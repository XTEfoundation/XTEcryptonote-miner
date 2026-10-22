package com.xtefoundation.cryptonoteminer

import android.security.NetworkSecurityPolicy
import android.util.Log
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URI
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
 *
 * The daemon protocol is cleartext HTTP. Responses are size-capped and redirects
 * are not followed. Hosts allowed by the network security config use
 * [HttpURLConnection]. Any other configured host is contacted with a direct
 * socket that only POSTs `/json_rpc` and does not follow redirects.
 *
 * This client does not hash `blocktemplate_blob`. traaitt's Chukwa hash is over
 * the parent-block hashing blob, and the nonce is not at offset 39 of the raw
 * template. See SECURITY.md.
 */
class DaemonRpcClient(
    private val listener: Listener
) {
    interface Listener {
        fun onStatus(status: String)
        /** Unused for hashing. Raw templates are not Chukwa inputs. See SECURITY.md. */
        fun onTemplate(jobId: String, blobHex: String, target64: Long, height: Long, difficulty: Long)
        fun onBlockAccepted()
        fun onBlockRejected(reason: String)
        fun onError(message: String)
    }

    private val running = AtomicBoolean(false)
    private val generation = AtomicInteger(0)
    private val reqId = AtomicInteger(1)
    private val pollMs = AtomicLong(POLL_INTERVAL_MS)
    @Volatile private var host: String = ""
    @Volatile private var port: Int = 0
    @Volatile private var wallet: String = ""
    @Volatile private var lastHeight: Long = -1L
    @Volatile private var lastDifficulty: Long = -1L
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
        lastHeight = -1L
        lastDifficulty = -1L
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
     * Solo submit is refused. `submitblock` expects the full block blob with the
     * nonce written inside the parent block, and Chukwa is computed over a
     * different hashing blob. Writing the nonce at offset 39 of the raw template
     * would submit a block the node cannot accept. See SECURITY.md.
     */
    fun submitBlock(jobId: String, nonce: Int) {
        Log.w(TAG, "solo submit refused job=${MinerValidation.isJobId(jobId)} nonceIgnored=$nonce")
        listener.onBlockRejected("solo submit disabled")
    }

    fun disconnect() {
        generation.incrementAndGet()
        running.set(false)
        pollThread?.interrupt()
        pollThread = null
        lastHeight = -1L
        lastDifficulty = -1L
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
        if (!isBoundedHex(blobHex, MinerValidation.MAX_BLOCK_BLOB_BYTES)) {
            throw IOException("rejected block template")
        }

        val height = parseUInt64(result, "height")
        val difficulty = parseUInt64(result, "difficulty")
        if (difficulty == 0L) throw IOException("difficulty is 0")
        if (MinerValidation.targetFromDifficulty(difficulty) == 0L) throw IOException("bad difficulty")

        if (height == lastHeight && difficulty == lastDifficulty) return
        lastHeight = height
        lastDifficulty = difficulty

        // The raw template is checked for size and then dropped. It is not a hashing blob.
        listener.onStatus("Seednode height=$height diff=$difficulty (not hashing)")
    }

    private fun isBoundedHex(hex: String, maxBytes: Int): Boolean {
        if (hex.isEmpty() || hex.length % 2 != 0) return false
        if (hex.length / 2 > maxBytes) return false
        return hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }
    }

    private fun postJsonRpc(body: JSONObject): JSONObject {
        val payload = body.toString().toByteArray(Charsets.UTF_8)
        if (payload.size > MAX_REQUEST_BYTES) throw IOException("RPC request too large")
        val bytes = if (platformCleartextAllowed(host)) {
            postViaPlatform(payload)
        } else {
            CleartextJsonRpc.post(
                host,
                port,
                "/json_rpc",
                payload,
                MinerValidation.MAX_RPC_BYTES,
                CONNECT_TIMEOUT_MS,
                READ_TIMEOUT_MS
            )
        }
        val text = bytes.toString(Charsets.UTF_8).trim()
        if (!text.startsWith("{")) throw IOException("Malformed RPC JSON")
        return try {
            JSONObject(text)
        } catch (_: Exception) {
            throw IOException("Malformed RPC JSON")
        }
    }

    /** True when network_security_config permits cleartext HTTP to [host]. */
    private fun platformCleartextAllowed(host: String): Boolean {
        return try {
            NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted(host)
        } catch (_: Throwable) {
            false
        }
    }

    private fun postViaPlatform(payload: ByteArray): ByteArray {
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
            conn.setFixedLengthStreamingMode(payload.size)
            conn.outputStream.use { it.write(payload) }
            val code = conn.responseCode
            if (code in 300..399) throw IOException("redirect refused")
            if (code !in 200..299) throw IOException("HTTP $code")
            val announced = conn.contentLengthLong
            if (announced > MinerValidation.MAX_RPC_BYTES) throw IOException("RPC response too large")
            val stream = conn.inputStream ?: throw IOException("empty RPC body")
            return BoundedReaders.readStream(stream, MinerValidation.MAX_RPC_BYTES)
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
        private const val MAX_REQUEST_BYTES = 8 * 1024

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
