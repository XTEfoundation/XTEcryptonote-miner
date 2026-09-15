package com.xtefoundation.cryptonoteminer

import android.os.Handler
import android.os.Looper
import android.util.Log
import java.util.concurrent.atomic.AtomicLong

class MiningEngine(
    private val statsListener: StatsListener
) : StratumClient.Listener, ChukwaHasher.ShareListener {

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
    private var stratum: StratumClient? = null
    private var hasher: ChukwaHasher? = null
    private val accepted = AtomicLong(0)
    private val rejected = AtomicLong(0)
    private var lastHashes = 0L
    private var lastHashTime = 0L
    private var hashrate = 0.0
    private var statusText = "Idle"
    private var ticker: Runnable? = null
    @Volatile private var mining = false

    fun start(host: String, port: Int, wallet: String, password: String, threads: Int) {
        if (mining) return
        mining = true
        accepted.set(0)
        rejected.set(0)
        lastHashes = 0
        lastHashTime = System.currentTimeMillis()
        hashrate = 0.0
        statusText = "Starting…"
        pushStats()
        log("Starting miner: $host:$port threads=$threads")

        hasher = ChukwaHasher(this)
        hasher!!.start(threads)

        stratum = StratumClient(this)
        stratum!!.connect(host, port, wallet, password)

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
        statusText = "Stopped"
        hashrate = 0.0
        pushStats()
        log("Miner stopped")
    }

    fun isMining(): Boolean = mining

    override fun onStatus(status: String) {
        statusText = status
        pushStats()
        log(status)
    }

    override fun onJob(jobId: String, blobHex: String, targetHex: String, sessionId: String) {
        try {
            val blob = hexToBytes(blobHex)
            val target64 = parseTarget64(targetHex)
            hasher?.setJob(blob, jobId, target64)
            log("New job $jobId target=$targetHex tgt64=$target64 blob=${blob.size}B")
            statusText = "Mining"
            pushStats()
        } catch (e: Exception) {
            log("Bad job: ${e.message}")
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

    override fun onError(message: String) {
        log(message)
        statusText = message
        pushStats()
    }

    override fun onShareFound(jobId: String, nonce: Int, hash: ByteArray) {
        val nonceHex = String.format("%08x", nonce)
        val resultHex = bytesToHex(hash)
        log("Share found nonce=$nonceHex")
        stratum?.submit(jobId, nonceHex, resultHex)
    }

    private fun pushStats() {
        val h = hasher?.hashes() ?: lastHashes
        main.post {
            statsListener.onStats(statusText, hashrate, accepted.get(), rejected.get(), h)
        }
    }

    private fun log(line: String) {
        Log.i(TAG, line)
        main.post { statsListener.onLog(line) }
    }

    companion object {
        private const val TAG = "MiningEngine"

        fun hexToBytes(hex: String): ByteArray {
            val clean = if (hex.length % 2 != 0) "0$hex" else hex
            val out = ByteArray(clean.length / 2)
            var i = 0
            while (i < clean.length) {
                out[i / 2] = ((Character.digit(clean[i], 16) shl 4) + Character.digit(clean[i + 1], 16)).toByte()
                i += 2
            }
            return out
        }

        fun bytesToHex(bytes: ByteArray): String {
            val sb = StringBuilder(bytes.size * 2)
            for (b in bytes) sb.append(String.format("%02x", b))
            return sb.toString()
        }

        /**
         * Match xmrig Job::setTarget for 4-byte Cryptonote pool targets:
         * raw = fromHex(target); t32 = *(uint32_t*)raw;
         * target64 = 0xFFFFFFFFFFFFFFFF / (0xFFFFFFFF / t32)
         */
        fun parseTarget64(targetHex: String): Long {
            val bytes = hexToBytes(targetHex)
            if (bytes.size >= 8) {
                var v = 0L
                for (i in 0 until 8) {
                    v = v or ((bytes[i].toLong() and 0xffL) shl (8 * i))
                }
                return v
            }
            if (bytes.size < 4) return 0L
            var t32 = 0L
            for (i in 0 until 4) {
                t32 = t32 or ((bytes[i].toLong() and 0xffL) shl (8 * i))
            }
            if (t32 == 0L) return 0L
            // unsigned: 0xFFF..F / (0xFFFFFFFF / t32)  — matches xmrig
            val denom = java.lang.Long.divideUnsigned(0xffffffffL, t32)
            if (denom == 0L) return 0L
            return java.lang.Long.divideUnsigned(-1L, denom)
        }
    }
}
