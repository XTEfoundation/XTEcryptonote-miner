package com.xtefoundation.cryptonoteminer

import android.os.Handler
import android.os.Looper
import android.util.Log
import java.util.concurrent.atomic.AtomicLong

class MiningEngine(
    private val statsListener: StatsListener
) : StratumClient.Listener, DaemonRpcClient.Listener, ChukwaHasher.ShareListener {

    interface StatsListener {
        fun onStats(
            status: String,
            hashrate: Double,
            accepted: Long,
            rejected: Long,
            hashes: Long
        )
        fun onLog(line: String)
    }

    private val main = Handler(Looper.getMainLooper())
    @Volatile private var stratum: StratumClient? = null
    @Volatile private var daemon: DaemonRpcClient? = null
    @Volatile private var hasher: ChukwaHasher? = null
    private val accepted = AtomicLong(0)
    private val rejected = AtomicLong(0)
    private var lastHashes = 0L
    private var lastHashTime = 0L
    @Volatile private var hashrate = 0.0
    @Volatile private var statusText = "Idle"
    private var ticker: Runnable? = null
    @Volatile private var mining = false
    @Volatile private var mode: MiningMode = MiningMode.POOL
    @Volatile private var secretWallet = ""
    @Volatile private var secretPass = ""

    fun start(
        mode: MiningMode,
        host: String,
        port: Int,
        wallet: String,
        password: String,
        threads: Int,
        useTls: Boolean = MinerValidation.stratumUsesTls(port)
    ): Boolean {
        if (mining) return false
        val hostNorm = MinerValidation.normalizeHost(host)
        val walletNorm = wallet.trim()
        val poolMode = mode != MiningMode.SEEDNODE
        val passNorm = if (poolMode) {
            if (password.isEmpty()) MinerPrefs.DEFAULT_PASS else password
        } else {
            MinerPrefs.DEFAULT_PASS
        }
        val err = if (hostNorm == null) {
            MinerValidation.ERR_HOST
        } else {
            MinerValidation.validateConfig(poolMode, hostNorm, port, walletNorm, passNorm, threads)
        }
        if (err != null) {
            statusText = err
            pushStats()
            log(err)
            return false
        }
        val endpoint = hostNorm ?: return false

        mining = true
        this.mode = mode
        secretWallet = walletNorm
        secretPass = if (poolMode) passNorm else ""
        accepted.set(0)
        rejected.set(0)
        lastHashes = 0
        lastHashTime = System.currentTimeMillis()
        hashrate = 0.0
        statusText = "Starting…"
        pushStats()
        val modeLabel = if (mode == MiningMode.SEEDNODE) "seednode" else "pool"
        val tlsNote = if (poolMode && useTls) " tls" else ""
        log("Starting miner ($modeLabel): $endpoint:$port threads=$threads$tlsNote")

        if (mode == MiningMode.SEEDNODE) {
            log(
                "Solo mode polls height and difficulty only. traaitt hashes a parent-block " +
                    "blob (nonce at offset 39 of that blob, not of the raw template), so this " +
                    "build does not hash or submit solo blocks. See SECURITY.md."
            )
            daemon = DaemonRpcClient(this)
            daemon!!.connect(endpoint, port, walletNorm)
        } else {
            try {
                hasher = ChukwaHasher(this)
                hasher!!.start(threads)
            } catch (e: Exception) {
                Log.e(TAG, "hasher start failed: ${e.javaClass.simpleName}")
                mining = false
                hasher = null
                secretWallet = ""
                secretPass = ""
                statusText = "Failed to start miner"
                pushStats()
                log("Failed to start miner")
                return false
            }
            stratum = StratumClient(this)
            stratum!!.connect(endpoint, port, walletNorm, passNorm, useTls = useTls)
        }

        val tick = object : Runnable {
            override fun run() {
                if (!mining) return
                val h = hasher?.hashes() ?: 0L
                val now = System.currentTimeMillis()
                val dt = (now - lastHashTime).coerceAtLeast(1)
                hashrate = (h - lastHashes) * 1000.0 / dt
                lastHashes = h
                lastHashTime = now
                pushStats()
                main.postDelayed(this, 1000)
            }
        }
        ticker = tick
        main.postDelayed(tick, 1000)
        return true
    }

    fun stop() {
        if (!mining) return
        mining = false
        ticker?.let { main.removeCallbacks(it) }
        ticker = null
        try { hasher?.stop() } catch (_: Exception) {}
        try { hasher?.clearJob() } catch (_: Exception) {}
        hasher = null
        try { stratum?.disconnect() } catch (_: Exception) {}
        stratum = null
        try { daemon?.disconnect() } catch (_: Exception) {}
        daemon = null
        secretWallet = ""
        secretPass = ""
        statusText = "Stopped"
        hashrate = 0.0
        pushStats()
        log("Miner stopped")
    }

    fun isMining(): Boolean = mining

    override fun onStatus(status: String) {
        statusText = redact(status)
        pushStats()
        log(status)
    }

    override fun onError(message: String) {
        statusText = redact(message)
        pushStats()
        log(message)
    }

    override fun onJob(jobId: String, blobHex: String, targetHex: String, sessionId: String) {
        try {
            if (MinerValidation.validateStratumJob(jobId, blobHex, targetHex) != null) {
                log("Rejected job")
                return
            }
            val blob = MinerValidation.hexToBytes(blobHex, MinerValidation.MAX_JOB_BLOB_BYTES)
            val target64 = MinerValidation.parseTarget64(targetHex)
            if (target64 == 0L) {
                log("Rejected job")
                return
            }
            hasher?.setJob(blob, jobId, target64)
            log("New job $jobId target=$targetHex blob=${blob.size}B")
            statusText = "Mining"
            pushStats()
        } catch (e: Exception) {
            log("Bad job: ${e.javaClass.simpleName}")
        }
    }

    override fun onConnectionLost() {
        try {
            hasher?.clearJob()
        } catch (_: Exception) {
        }
    }

    override fun onShareAccepted() {
        accepted.incrementAndGet()
        pushStats()
        log("Share accepted")
    }

    override fun onShareRejected(reason: String) {
        rejected.incrementAndGet()
        pushStats()
        log("Share rejected: $reason")
    }

    override fun onTemplate(jobId: String, blobHex: String, target64: Long, height: Long, difficulty: Long) {
        // Defense in depth: never hash a raw blocktemplate_blob. Pool jobs use onJob.
        log("Solo template ignored (h=$height diff=$difficulty)")
        if (blobHex.length > MinerValidation.MAX_HASH_BLOB_BYTES * 2 || target64 == 0L ||
            !MinerValidation.isJobId(jobId)
        ) {
            return
        }
    }

    override fun onBlockAccepted() {
        accepted.incrementAndGet()
        pushStats()
        log("Block accepted")
    }

    override fun onBlockRejected(reason: String) {
        rejected.incrementAndGet()
        pushStats()
        log("Block rejected: $reason")
    }

    override fun onShareFound(jobId: String, nonce: Int, hash: ByteArray) {
        if (!MinerValidation.isJobId(jobId) || hash.size != MinerValidation.HASH_BYTES) return
        val nonceHex = String.format("%08x", nonce)
        val resultHex = MinerValidation.bytesToHex(hash)
        if (mode == MiningMode.SEEDNODE) {
            log("Block candidate nonce=$nonceHex")
            daemon?.submitBlock(jobId, nonce)
        } else {
            log("Share found nonce=$nonceHex")
            stratum?.submit(jobId, nonceHex, resultHex)
        }
    }

    private fun redact(line: String): String {
        return MinerValidation.redact(line, listOf(secretWallet, secretPass))
    }

    private fun pushStats() {
        val h = hasher?.hashes() ?: lastHashes
        val status = statusText
        val hr = hashrate
        val acc = accepted.get()
        val rej = rejected.get()
        main.post {
            statsListener.onStats(status, hr, acc, rej, h)
        }
    }

    private fun log(line: String) {
        val safe = redact(line)
        Log.i(TAG, safe)
        main.post { statsListener.onLog(safe) }
    }

    companion object {
        private const val TAG = "MiningEngine"

        fun hexToBytes(hex: String): ByteArray = MinerValidation.hexToBytes(hex)

        fun bytesToHex(bytes: ByteArray): String = MinerValidation.bytesToHex(bytes)

        fun parseTarget64(targetHex: String): Long = MinerValidation.parseTarget64(targetHex)
    }
}
