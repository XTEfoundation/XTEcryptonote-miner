package com.xtefoundation.cryptonoteminer

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * HTTP/1.1 POST to one already-validated host, with no redirects and a fixed path.
 *
 * Used only when the platform network security config refuses cleartext for that host
 * (custom daemon hostnames and every IP address). [java.net.HttpURLConnection] is used
 * for hosts the config allows, so the platform policy still applies there.
 */
internal object CleartextJsonRpc {
    private const val MAX_HEADER_BYTES = 8 * 1024

    data class Parsed(val code: Int, val body: ByteArray)

    fun post(
        host: String,
        port: Int,
        path: String,
        body: ByteArray,
        maxBody: Int,
        connectMs: Int,
        readMs: Int
    ): ByteArray {
        if (!path.startsWith("/") || path.contains(' ') || path.contains('\r') || path.contains('\n')) {
            throw IOException("bad RPC path")
        }
        val socket = Socket()
        try {
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(host, port), connectMs)
            socket.soTimeout = readMs
            val hostHeader = if (host.contains(':')) "[$host]:$port" else "$host:$port"
            val head = (
                "POST $path HTTP/1.1\r\n" +
                    "Host: $hostHeader\r\n" +
                    "Content-Type: application/json\r\n" +
                    "Accept: application/json\r\n" +
                    "Content-Length: ${body.size}\r\n" +
                    "Connection: close\r\n" +
                    "\r\n"
                ).toByteArray(Charsets.US_ASCII)
            val out = socket.getOutputStream()
            out.write(head)
            out.write(body)
            out.flush()
            val raw = readCapped(socket.getInputStream(), maxBody + MAX_HEADER_BYTES)
            return bodyOrThrow(parseResponse(raw, maxBody))
        } finally {
            try {
                socket.close()
            } catch (_: Exception) {
            }
        }
    }

    fun bodyOrThrow(parsed: Parsed): ByteArray {
        if (parsed.code in 300..399) throw IOException("redirect refused")
        if (parsed.code !in 200..299) throw IOException("HTTP ${parsed.code}")
        return parsed.body
    }

    fun parseResponse(raw: ByteArray, maxBody: Int): Parsed {
        val sep = indexOfHeaderEnd(raw)
        if (sep < 0 || sep > MAX_HEADER_BYTES) throw IOException("truncated HTTP response")
        val headerText = String(raw, 0, sep, Charsets.ISO_8859_1)
        val lines = headerText.split("\r\n")
        if (lines.isEmpty()) throw IOException("bad HTTP status")
        val status = lines[0]
        if (!status.startsWith("HTTP/1.")) throw IOException("bad HTTP status")
        val codeToken = status.split(' ').getOrNull(1) ?: throw IOException("bad HTTP status")
        val code = codeToken.toIntOrNull() ?: throw IOException("bad HTTP status")
        var contentLength: Int? = null
        for (i in 1 until lines.size) {
            val line = lines[i]
            if (line.isEmpty()) continue
            val colon = line.indexOf(':')
            if (colon <= 0) throw IOException("bad HTTP header")
            val name = line.substring(0, colon).trim().lowercase()
            val value = line.substring(colon + 1).trim()
            when (name) {
                "content-length" -> {
                    val n = value.toLongOrNull() ?: throw IOException("bad content-length")
                    if (n < 0 || n > maxBody) throw IOException("RPC response too large")
                    contentLength = n.toInt()
                }
                "transfer-encoding" -> {
                    if (value.contains("chunked", ignoreCase = true)) {
                        throw IOException("chunked RPC response refused")
                    }
                }
            }
        }
        val bodyStart = sep + 4
        if (bodyStart > raw.size) throw IOException("truncated HTTP response")
        val available = raw.size - bodyStart
        if (contentLength != null) {
            if (available < contentLength) throw IOException("truncated HTTP body")
            return Parsed(code, raw.copyOfRange(bodyStart, bodyStart + contentLength))
        }
        if (available > maxBody) throw IOException("RPC response too large")
        return Parsed(code, raw.copyOfRange(bodyStart, raw.size))
    }

    private fun indexOfHeaderEnd(raw: ByteArray): Int {
        val limit = minOf(raw.size - 3, MAX_HEADER_BYTES + 4)
        var i = 0
        while (i < limit) {
            if (raw[i] == '\r'.code.toByte() &&
                raw[i + 1] == '\n'.code.toByte() &&
                raw[i + 2] == '\r'.code.toByte() &&
                raw[i + 3] == '\n'.code.toByte()
            ) {
                return i
            }
            i++
        }
        return -1
    }

    private fun readCapped(input: InputStream, max: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        var total = 0
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            if (n == 0) continue
            if (total.toLong() + n > max) throw IOException("RPC response too large")
            total += n
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }
}
