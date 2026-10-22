package com.xtefoundation.cryptonoteminer

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URI
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/**
 * Solo / seednode mining against a Cryptonote daemon JSON-RPC
 * (`POST http://HOST:PORT/json_rpc`).
 *
 * Methods: [getblocktemplate], [submitblock] — matches traaitt
 * `RpcServer::on_getblocktemplate` / `on_submitblock`.
 *
 * The daemon protocol is cleartext HTTP. Responses are size-capped and redirects
 * are not followed. Polling waits at least one second between attempts (no hot loop).
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

    private data class Template(val jobId: String, val blobHex: String)

    private val running = AtomicBoolean(false)
    private val generation = AtomicInteger(0)
    private val reqId = AtomicInteger(1)
    private val pollMs = AtomicLong(POLL_INTERVAL_MS)
    private val current = AtomicReference<Template?>(null)
    @Volatile private var host: String = ""
    @Volatile private var port: Int = 0
    @Volatile private var wallet: String = ""
    @Volatile private var lastHeight: Long = -1L
    @Volatile private var lastBlobHex: String = ""
    private var pollThread: Thread? = null

    fun connect(host: String, port: Int, wallet: String) {
        val hostNorm = MinerValidation.normalizeHost(host)
        val walletNorm = wallet.trim()
        if (hostNorm == null || port !in 1..65535 || !MinerValidation.isWallet(walletNorm)) {
            listener.onError("Invalid seednode settings")
            listener.onStatus("Disconnected")
            return
        }

        val gen = generation.incrementAndGet()
        running.set(false)
        pollThread?.interrupt()
        this.host = hostNorm
        this.port = port
        this.wallet = walletNorm
        current.set(null)
        lastHeight = -1L
        lastBlobHex = ""
        running.set(true)
        listener.onStatus("Connecting to seednode $hostNorm:$port…")
        pollThread = thread(name = "daemon-rpc-poll", isDaemon = true) {
            try {
                listener.onStatus("Resolving $hostNorm…")
                InetAddress.getByName(hostNorm)
            } catch (e: Exception) {
                if (generation.get() != gen) return@thread
                Log.e(TAG, "DNS failed for $hostNorm (${e.javaClass.simpleName})")
                listener.onError("DNS failed for $hostNorm")
                listener.onStatus("Disconnected (DNS)")
                running.set(false)
                return@thread
            }
            if (generation.get() != gen || !running.get()) return@thread
            listener.onStatus("Polling getblocktemplate…")
            var failures = 0
            while (running.get() && generation.get() == gen) {
                try {
                    pollTemplate()
                    failures = 0
                } catch (e: Exception) {
                    if (generation.get() != gen) break
                    failures++
                    val safe = MinerValidation.clip(
                        MinerValidation.redact(e.message, listOf(walletNorm)),
                        160
                    )
                    Log.e(TAG, "poll failed: ${e.javaClass.simpleName}: $safe")
                    listener.onError("RPC error: $safe")
                    if (failures == 1) listener.onStatus("Waiting for daemon…")
                }
                if (!running.get() || generation.get() != gen) break
                sleepInterruptible(pollMs.get().coerceAtLeast(MIN_POLL_MS))
            }
        }
    }

    /**
     * Rebuild the current blocktemplate with [nonce] (LE at Cryptonote offset 39)
     * and POST [submitblock] as a JSON array of one hex string.
     */
    fun submitBlock(jobId: String, nonce: Int) {
        val gen = generation.get()
        val template = current.get()
        if (template == null) {
            listener.onError("Submit failed: no active template")
            return
        }
        if (jobId != template.jobId || !MinerValidation.isJobId(jobId)) {
            Log.w(TAG, "stale job")
            return
        }
        val blobHex = template.blobHex
        thread(name = "daemon-rpc-submit", isDaemon = true) {
            if (generation.get() != gen || !running.get()) return@thread
            try {
                MinerValidation.validateBlobHex(blobHex, MinerValidation.MAX_BLOCK_BLOB_BYTES)?.let {
                    listener.onBlockRejected("blob rejected")
                    return@thread
                }
                val blob = MinerValidation.hexToBytes(blobHex, MinerValidation.MAX_BLOCK_BLOB_BYTES)
                if (blob.size < MinerValidation.MIN_BLOB_BYTES) {
                    listener.onBlockRejected("blob too short for nonce")
                    return@thread
                }
                blob[MinerValidation.NONCE_OFFSET] = (nonce and 0xff).toByte()
                blob[MinerValidation.NONCE_OFFSET + 1] = ((nonce shr 8) and 0xff).toByte()
                blob[MinerValidation.NONCE_OFFSET + 2] = ((nonce shr 16) and 0xff).toByte()
                blob[MinerValidation.NONCE_OFFSET + 3] = ((nonce shr 24) and 0xff).toByte()
                val completedHex = MinerValidation.bytesToHex(blob)

                val id = reqId.getAndIncrement()
                val body = JSONObject()
                    .put("jsonrpc", "2.0")
                    .put("id", id)
                    .put("method", "submitblock")
                    .put("params", JSONArray().put(completedHex))

                if (generation.get() != gen || !running.get()) return@thread
                val resp = postJsonRpc(body)
                if (resp.has("error") && !resp.isNull("error")) {
                    val msg = errorText(resp.get("error"))
                    listener.onBlockRejected(msg)
                    try { pollTemplate() } catch (_: Exception) {}
                    return@thread
                }
                val result = resp.opt("result")
                val status = when (result) {
                    is JSONObject -> result.optString("status", "")
                    is String -> result
                    else -> ""
                }
                if (status.equals("OK", true) || (status.isEmpty() && result != null && result !== JSONObject.NULL)) {
                    listener.onBlockAccepted()
                    lastHeight = -1L
                    lastBlobHex = ""
                    try { pollTemplate() } catch (_: Exception) {}
                } else {
                    listener.onBlockRejected(MinerValidation.clip(status.ifEmpty { "unexpected response" }, 160))
                }
            } catch (e: Exception) {
                Log.e(TAG, "submit failed: ${e.javaClass.simpleName}")
                listener.onBlockRejected(MinerValidation.clip(MinerValidation.redact(e.message, listOf(wallet)), 160))
            }
        }
    }

    fun disconnect() {
        generation.incrementAndGet()
        running.set(false)
        pollThread?.interrupt()
        pollThread = null
        current.set(null)
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
            throw IOException(errorText(resp.get("error")))
        }
        val result = resp.optJSONObject("result")
            ?: throw IOException("empty getblocktemplate result")

        val status = result.optString("status", "OK")
        if (status.isNotEmpty() && !status.equals("OK", true)) {
            throw IOException("getblocktemplate status rejected")
        }

        val blobHex = result.optString("blocktemplate_blob", "").trim()
        MinerValidation.validateBlobHex(blobHex, MinerValidation.MAX_BLOCK_BLOB_BYTES)?.let {
            throw IOException("rejected block template")
        }

        val height = parseUInt64(result, "height")
        val difficulty = parseUInt64(result, "difficulty")
        if (difficulty == 0L) throw IOException("difficulty is 0")

        if (height == lastHeight && blobHex == lastBlobHex) return

        val target64 = MinerValidation.targetFromDifficulty(difficulty)
        if (target64 == 0L) throw IOException("bad difficulty")

        val jobId = "h${height}_${blobHex.take(16)}"
        if (!MinerValidation.isJobId(jobId)) throw IOException("bad template id")
        current.set(Template(jobId, blobHex))
        lastHeight = height
        lastBlobHex = blobHex

        listener.onStatus("Seednode height=$height diff=$difficulty")
        listener.onTemplate(jobId, blobHex, target64, height, difficulty)
    }

    private fun postJsonRpc(body: JSONObject): JSONObject {
        val uri = URI("http", null, host, port, "/json_rpc", null, null)
        val conn = (uri.toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            instanceFollowRedirects = false
            useCaches = false
            doInput = true
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty("Accept", "application/json")
        }
        try {
            val payload = body.toString().toByteArray(Charsets.UTF_8)
            conn.setFixedLengthStreamingMode(payload.size)
            conn.outputStream.use { it.write(payload) }
            val code = conn.responseCode
            if (code !in 200..299) throw IOException("HTTP $code")
            val announced = conn.contentLengthLong
            if (announced > MinerValidation.MAX_RPC_BYTES) throw IOException("RPC response too large")
            val stream = conn.inputStream ?: throw IOException("empty RPC body")
            val bytes = BoundedReaders.readStream(stream, MinerValidation.MAX_RPC_BYTES)
            val text = bytes.toString(Charsets.UTF_8).trim()
            if (!text.startsWith("{")) throw IOException("Malformed RPC JSON")
            return try {
                JSONObject(text)
            } catch (_: Exception) {
                throw IOException("Malformed RPC JSON")
            }
        } finally {
            conn.disconnect()
        }
    }

    private fun errorText(err: Any): String {
        val raw = when (err) {
            is JSONObject -> {
                val m = err.optString("message", "")
                if (m.isNotEmpty()) m else "error"
            }
            else -> err.toString()
        }
        return MinerValidation.clip(MinerValidation.redact(raw, listOf(wallet)), 160)
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
        private const val RESERVE_SIZE = 8
        private const val POLL_INTERVAL_MS = 4_000L
        private const val MIN_POLL_MS = 1_000L
        private const val CONNECT_TIMEOUT_MS = 12_000
        private const val READ_TIMEOUT_MS = 20_000

        fun targetFromDifficulty(difficulty: Long): Long = MinerValidation.targetFromDifficulty(difficulty)

        fun parseUInt64(obj: JSONObject, key: String): Long {
            if (!obj.has(key) || obj.isNull(key)) throw IllegalArgumentException("missing $key")
            return when (val v = obj.get(key)) {
                is String -> MinerValidation.parseUnsignedLongText(v)
                is Number -> MinerValidation.unsignedLongFromNumber(v)
                else -> throw IllegalArgumentException("bad $key")
            }
        }
    }
}
