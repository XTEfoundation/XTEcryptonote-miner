package com.xtefoundation.cryptonoteminer

import android.security.NetworkSecurityPolicy
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URI
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
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
 * Each template is parsed strictly by [CryptoNoteBlock] and turned into a [SoloJob]:
 * the merge-mining tag root is filled in exactly like traaitt's own solo miner
 * (`MinerManager::adjustMergeMiningTag`), and the Chukwa input is the parent-block
 * hashing blob (`CachedBlock::getParentBlockHashingBinaryArray(true)`), nonce at
 * offset 39. A found nonce is re-checked with the exact `check_hash` rule and
 * written into the full block, which is sent with `submitblock ["<hex>"]`.
 * A new job is issued when the height or previous block changes and every
 * [JOB_REFRESH_MS] (fresh timestamp); jobs for an old previous block are dropped.
 */
class DaemonRpcClient(
    private val listener: Listener,
    /** Recomputes Chukwa for a hashing blob (independent of the worker that found it). */
    private val powVerifier: ((ByteArray) -> ByteArray?)? = null
) {
    interface Listener {
        fun onStatus(status: String)
        /** A new solo job. Replaces any previous job; hash [SoloJob.hashingBlob]. */
        fun onSoloJob(job: SoloJob)
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
    @Volatile private var lastPrev: String = ""
    @Volatile private var lastJobAtMs: Long = 0L
    private var pollThread: Thread? = null
    private val jobCounter = AtomicLong(0)
    private val jobsLock = Any()
    private val jobs = LinkedHashMap<String, SoloJob>()
    private val submitted = HashSet<String>()
    private val forceRefresh = AtomicBoolean(false)
    private val accepted = AtomicLong(0)
    private val rejected = AtomicLong(0)
    @Volatile private var submitExecutor: ExecutorService = newSubmitExecutor()

    val acceptedBlocks: Long get() = accepted.get()
    val rejectedBlocks: Long get() = rejected.get()

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
        resetJobs()
        if (submitExecutor.isShutdown) submitExecutor = newSubmitExecutor()
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
                if (forceRefresh.getAndSet(false)) continue
                sleepInterruptible(pollMs.get().coerceAtLeast(MIN_POLL_MS))
            }
        }
    }

    /**
     * Called from the native worker thread with a nonce whose Chukwa hash passed the
     * 64-bit prefilter. The exact difficulty check, block assembly and network I/O run
     * on a single submit thread so the hashing threads are never blocked.
     */
    fun submitBlock(jobId: String, nonce: Int, hash: ByteArray) {
        if (!running.get()) return
        if (!MinerValidation.isJobId(jobId) || hash.size != 32) {
            listener.onBlockRejected("invalid share callback")
            return
        }
        val gen = generation.get()
        val hashCopy = hash.copyOf()
        try {
            submitExecutor.execute { doSubmit(gen, jobId, nonce, hashCopy) }
        } catch (_: RejectedExecutionException) {
            // Disconnected while the share was in flight.
        }
    }

    private fun doSubmit(gen: Int, jobId: String, nonce: Int, hash: ByteArray) {
        if (generation.get() != gen || !running.get()) return
        val job = synchronized(jobsLock) {
            val j = jobs[jobId]
            if (j != null && !submitted.add(jobId)) null else j
        }
        if (job == null) {
            Log.i(TAG, "dropping stale or duplicate solo share")
            return
        }
        val pow = powVerifier?.let { verify ->
            val again = verify(job.hashingBlobWithNonce(nonce))
            if (again == null || !again.contentEquals(hash)) {
                synchronized(jobsLock) { submitted.remove(jobId) }
                Log.e(TAG, "solo share failed PoW re-verification")
                listener.onError("Discarded a share that failed PoW re-check")
                return
            }
            again
        } ?: hash
        if (!CryptoNoteBlock.checkHash(pow, job.difficulty)) {
            // Prefilter hit that does not meet the full 256-bit difficulty.
            synchronized(jobsLock) { submitted.remove(jobId) }
            return
        }
        val blockHex = MinerValidation.bytesToHex(job.blockWithNonce(nonce))
        listener.onStatus("Block candidate at height ${job.height}, submitting…")
        try {
            val body = JSONObject()
                .put("jsonrpc", "2.0")
                .put("id", reqId.getAndIncrement())
                .put("method", "submitblock")
                .put("params", JSONArray().put(blockHex))
            val resp = postJsonRpc(body, MAX_SUBMIT_REQUEST_BYTES)
            if (generation.get() != gen) return
            if (resp.has("error") && !resp.isNull("error")) {
                rejected.incrementAndGet()
                listener.onBlockRejected(errorText(resp.get("error")))
            } else {
                val status = resp.optJSONObject("result")?.optString("status", "") ?: ""
                if (status.equals("OK", ignoreCase = true)) {
                    accepted.incrementAndGet()
                    Log.i(TAG, "block accepted height=${job.height}")
                    listener.onBlockAccepted()
                } else {
                    rejected.incrementAndGet()
                    listener.onBlockRejected("status ${MinerValidation.clip(status, 40)}")
                }
            }
        } catch (e: Exception) {
            if (generation.get() != gen) return
            rejected.incrementAndGet()
            val safe = MinerValidation.clip(MinerValidation.redact(e.message, listOf(wallet)), 160)
            Log.e(TAG, "submitblock failed: ${e.javaClass.simpleName}: $safe")
            listener.onBlockRejected("submit failed: $safe")
        }
        // Whatever happened, the chain tip has probably moved: fetch new work now.
        forceRefresh.set(true)
        pollThread?.interrupt()
    }

    fun disconnect() {
        generation.incrementAndGet()
        running.set(false)
        pollThread?.interrupt()
        pollThread = null
        resetJobs()
        submitExecutor.shutdownNow()
        listener.onStatus("Disconnected")
    }

    private fun resetJobs() {
        lastHeight = -1L
        lastDifficulty = -1L
        lastPrev = ""
        lastJobAtMs = 0L
        synchronized(jobsLock) {
            jobs.clear()
            submitted.clear()
        }
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

        val resp = postJsonRpc(body, MAX_REQUEST_BYTES)
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

        val template = MinerValidation.hexToBytes(blobHex, MinerValidation.MAX_BLOCK_BLOB_BYTES)
        val now = System.currentTimeMillis()
        val jobId = "solo-${jobCounter.incrementAndGet()}"
        val job = try {
            SoloJob.fromTemplate(jobId, template, height, difficulty)
        } catch (e: IllegalArgumentException) {
            throw IOException("unusable block template: ${MinerValidation.clip(e.message ?: "invalid", 80)}")
        }
        val prev = MinerValidation.bytesToHex(job.previousBlockHash)
        val tipChanged = height != lastHeight || prev != lastPrev
        val stale = now - lastJobAtMs >= JOB_REFRESH_MS
        if (!tipChanged && difficulty == lastDifficulty && !stale) return

        synchronized(jobsLock) {
            if (tipChanged) {
                // Work on the old tip can no longer produce an acceptable block.
                jobs.clear()
                submitted.clear()
            }
            jobs[jobId] = job
            while (jobs.size > MAX_LIVE_JOBS) jobs.remove(jobs.keys.first())
        }
        lastHeight = height
        lastDifficulty = difficulty
        lastPrev = prev
        lastJobAtMs = now
        listener.onSoloJob(job)
        listener.onStatus("Solo job height=$height diff=$difficulty")
    }

    private fun isBoundedHex(hex: String, maxBytes: Int): Boolean {
        if (hex.isEmpty() || hex.length % 2 != 0) return false
        if (hex.length / 2 > maxBytes) return false
        return hex.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }
    }

    private fun postJsonRpc(body: JSONObject, maxRequestBytes: Int): JSONObject {
        val payload = body.toString().toByteArray(Charsets.UTF_8)
        if (payload.size > maxRequestBytes) throw IOException("RPC request too large")
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
        private const val MAX_SUBMIT_REQUEST_BYTES = 2 * MinerValidation.MAX_BLOCK_BLOB_BYTES + 1024
        /** Re-issue work with a fresh template timestamp even if the tip is unchanged. */
        private const val JOB_REFRESH_MS = 30_000L
        /** Recent jobs on the current tip that may still receive in-flight results. */
        private const val MAX_LIVE_JOBS = 4

        private fun newSubmitExecutor(): ExecutorService = Executors.newSingleThreadExecutor { r ->
            Thread(r, "daemon-rpc-submit").apply { isDaemon = true }
        }

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
