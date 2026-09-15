package com.xtefoundation.cryptonoteminer

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * Solo / seednode mining against a Cryptonote daemon JSON-RPC
 * (`POST http://HOST:PORT/json_rpc`).
 *
 * Methods: [getblocktemplate], [submitblock] — matches traaitt
 * `RpcServer::on_getblocktemplate` / `on_submitblock`.
 */
class DaemonRpcClient(
    private val listener: Listener
) {
    interface Listener {
        fun onStatus(status: String)
        /** New template: mine [blobHex] with [target64]; [jobId] identifies the template. */
        fun onTemplate(jobId: String, blobHex: String, target64: Long, height: Long, difficulty: Long)
        fun onBlockAccepted()
        fun onBlockRejected(reason: String)
        fun onError(message: String)
    }

    private val running = AtomicBoolean(false)
    private val reqId = AtomicInteger(1)
    private val pollMs = AtomicLong(POLL_INTERVAL_MS)
    @Volatile private var host: String = ""
    @Volatile private var port: Int = 0
    @Volatile private var wallet: String = ""
    @Volatile private var currentBlobHex: String = ""
    @Volatile private var currentJobId: String = ""
    @Volatile private var lastHeight: Long = -1L
    @Volatile private var lastBlobHex: String = ""
    private var pollThread: Thread? = null

    fun connect(host: String, port: Int, wallet: String) {
        disconnect()
        this.host = host.trim()
        this.port = port
        this.wallet = wallet.trim()
        running.set(true)
        listener.onStatus("Connecting to seednode $host:$port…")
        pollThread = thread(name = "daemon-rpc-poll", isDaemon = true) {
            // DNS check first so UI gets a clear message when the host does not resolve
            try {
                listener.onStatus("Resolving $host…")
                InetAddress.getByName(host)
            } catch (e: Exception) {
                Log.e(TAG, "DNS failed for $host", e)
                listener.onError("DNS failed for $host: ${e.message}")
                listener.onStatus("Disconnected (DNS)")
                running.set(false)
                return@thread
            }
            listener.onStatus("Polling getblocktemplate…")
            var failures = 0
            while (running.get()) {
                try {
                    pollTemplate()
                    failures = 0
                } catch (e: Exception) {
                    failures++
                    Log.e(TAG, "poll failed", e)
                    val msg = e.message ?: e.javaClass.simpleName
                    listener.onError("RPC error: $msg")
                    if (failures == 1) {
                        listener.onStatus("Waiting for daemon…")
                    }
                }
                sleepInterruptible(pollMs.get())
            }
        }
    }

    /**
     * Rebuild the current blocktemplate with [nonce] (LE at Cryptonote offset 39)
     * and POST [submitblock] as a JSON array of one hex string.
     */
    fun submitBlock(jobId: String, nonce: Int) {
        if (jobId != currentJobId) {
            Log.w(TAG, "stale job $jobId (current=$currentJobId)")
            return
        }
        val blobHex = currentBlobHex
        if (blobHex.isEmpty()) {
            listener.onError("Submit failed: no active template")
            return
        }
        thread(name = "daemon-rpc-submit", isDaemon = true) {
            try {
                val blob = MiningEngine.hexToBytes(blobHex)
                if (blob.size < NONCE_OFFSET + 4) {
                    listener.onBlockRejected("blob too short for nonce")
                    return@thread
                }
                blob[NONCE_OFFSET] = (nonce and 0xff).toByte()
                blob[NONCE_OFFSET + 1] = ((nonce shr 8) and 0xff).toByte()
                blob[NONCE_OFFSET + 2] = ((nonce shr 16) and 0xff).toByte()
                blob[NONCE_OFFSET + 3] = ((nonce shr 24) and 0xff).toByte()
                val completedHex = MiningEngine.bytesToHex(blob)

                val id = reqId.getAndIncrement()
                val body = JSONObject()
                    .put("jsonrpc", "2.0")
                    .put("id", id)
                    .put("method", "submitblock")
                    .put("params", JSONArray().put(completedHex))

                val resp = postJsonRpc(body)
                if (resp.has("error") && !resp.isNull("error")) {
                    val err = resp.get("error")
                    val msg = when (err) {
                        is JSONObject -> err.optString("message", err.toString())
                        else -> err.toString()
                    }
                    listener.onBlockRejected(msg)
                    // Refresh template after reject
                    try { pollTemplate() } catch (_: Exception) {}
                    return@thread
                }
                val result = resp.opt("result")
                val status = when (result) {
                    is JSONObject -> result.optString("status", "")
                    is String -> result
                    else -> ""
                }
                if (status.equals("OK", true) || status.isEmpty() && result != null) {
                    listener.onBlockAccepted()
                    // Force new template after accepted block
                    lastHeight = -1L
                    lastBlobHex = ""
                    try { pollTemplate() } catch (_: Exception) {}
                } else {
                    listener.onBlockRejected(status.ifEmpty { "unexpected response" })
                }
            } catch (e: Exception) {
                Log.e(TAG, "submit failed", e)
                listener.onBlockRejected(e.message ?: "submit failed")
            }
        }
    }

    fun disconnect() {
        running.set(false)
        pollThread?.interrupt()
        pollThread = null
        currentBlobHex = ""
        currentJobId = ""
        lastHeight = -1L
        lastBlobHex = ""
        listener.onStatus("Disconnected")
    }

    private fun pollTemplate() {
        val id = reqId.getAndIncrement()
        val params = JSONObject()
            .put("reserve_size", RESERVE_SIZE)
            .put("wallet_address", wallet)
        val body = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", id)
            .put("method", "getblocktemplate")
            .put("params", params)

        val resp = postJsonRpc(body)
        if (resp.has("error") && !resp.isNull("error")) {
            val err = resp.get("error")
            val msg = when (err) {
                is JSONObject -> err.optString("message", err.toString())
                else -> err.toString()
            }
            throw RuntimeException(msg)
        }
        val result = resp.optJSONObject("result")
            ?: throw RuntimeException("empty getblocktemplate result")

        val status = result.optString("status", "OK")
        if (status.isNotEmpty() && !status.equals("OK", true)) {
            throw RuntimeException("getblocktemplate status=$status")
        }

        val blobHex = result.optString("blocktemplate_blob", "")
        if (blobHex.isEmpty()) throw RuntimeException("missing blocktemplate_blob")

        val height = parseUInt64(result, "height")
        val difficulty = parseUInt64(result, "difficulty")
        if (difficulty == 0L) throw RuntimeException("difficulty is 0")

        if (height == lastHeight && blobHex == lastBlobHex) {
            return // unchanged
        }

        val target64 = targetFromDifficulty(difficulty)
        if (target64 == 0L) throw RuntimeException("bad difficulty→target")

        val jobId = "h${height}_${blobHex.take(16)}"
        currentBlobHex = blobHex
        currentJobId = jobId
        lastHeight = height
        lastBlobHex = blobHex

        listener.onStatus("Seednode height=$height diff=$difficulty")
        listener.onTemplate(jobId, blobHex, target64, height, difficulty)
    }

    private fun postJsonRpc(body: JSONObject): JSONObject {
        val url = URL("http://$host:$port/json_rpc")
        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            doInput = true
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "application/json")
        }
        try {
            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { w ->
                w.write(body.toString())
                w.flush()
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).use { it.readText() }
            if (code !in 200..299) {
                throw RuntimeException("HTTP $code: ${text.take(200)}")
            }
            return JSONObject(text)
        } finally {
            conn.disconnect()
        }
    }

    private fun sleepInterruptible(ms: Long) {
        try {
            Thread.sleep(ms)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    companion object {
        private const val TAG = "DaemonRpcClient"
        private const val NONCE_OFFSET = 39
        private const val RESERVE_SIZE = 8
        private const val POLL_INTERVAL_MS = 4_000L
        private const val CONNECT_TIMEOUT_MS = 12_000
        private const val READ_TIMEOUT_MS = 20_000

        /**
         * xmrig Job::setDiff / toDiff: target64 = (2^64 − 1) / difficulty
         * (unsigned). Native hasher accepts shares where first 8 LE hash bytes < target64.
         */
        fun targetFromDifficulty(difficulty: Long): Long {
            if (difficulty == 0L) return 0L
            return java.lang.Long.divideUnsigned(-1L, difficulty)
        }

        fun parseUInt64(obj: JSONObject, key: String): Long {
            if (!obj.has(key) || obj.isNull(key)) return 0L
            return when (val v = obj.get(key)) {
                is String -> {
                    val s = v.trim()
                    if (s.startsWith("0x") || s.startsWith("0X")) {
                        java.lang.Long.parseUnsignedLong(s.substring(2), 16)
                    } else {
                        java.lang.Long.parseUnsignedLong(s)
                    }
                }
                is Number -> v.toLong()
                else -> 0L
            }
        }
    }
}
