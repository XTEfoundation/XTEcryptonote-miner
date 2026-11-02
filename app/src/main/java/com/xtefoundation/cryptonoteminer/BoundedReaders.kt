package com.xtefoundation.cryptonoteminer

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.Reader

/** Size-capped readers so a hostile pool or daemon cannot force an unbounded allocation. */
internal object BoundedReaders {
    fun readLine(reader: Reader, maxChars: Int): String? {
        require(maxChars > 0)
        val sb = StringBuilder()
        while (true) {
            val c = reader.read()
            if (c == -1) return if (sb.isEmpty()) null else sb.toString()
            if (c == '\n'.code) return sb.toString()
            if (c == '\r'.code) continue
            if (sb.length >= maxChars) {
                while (true) {
                    val d = reader.read()
                    if (d == -1 || d == '\n'.code) break
                }
                throw IOException("line exceeds $maxChars characters")
            }
            sb.append(c.toChar())
        }
    }

    fun readStream(stream: InputStream, maxBytes: Int): ByteArray {
        require(maxBytes > 0)
        val out = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        var total = 0
        while (true) {
            val n = stream.read(buf)
            if (n < 0) break
            if (n == 0) continue
            if (total.toLong() + n > maxBytes) {
                throw IOException("response exceeds $maxBytes bytes")
            }
            total += n
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }
}
