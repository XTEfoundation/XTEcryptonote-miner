package com.xtefoundation.cryptonoteminer

import android.util.Log
import org.json.JSONObject
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.KeyStore
import java.security.SecureRandom
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import java.util.Collections
import java.util.HashSet
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * Cryptonote-nodejs-pool stratum (login / job / submit / keepalived).
 * XTE pool at xte.trrxitte.com uses this CN login protocol (not Bitcoin subscribe).
 *
 * TLS is optional. The UI defaults it on for port 9999 (the pool's documented SSL
 * port) and the user can turn it off. A dropped socket reconnects with backoff
 * until Stop, or until the pool rejects the login.
 */
class StratumClient(
    private val listener: Listener
) {
    interface Listener {
        fun onStatus(status: String)
        fun onJob(jobId: String, blobHex: String, targetHex: String, sessionId: String)
        fun onShareAccepted()
        fun onShareRejected(reason: String)
        fun onError(message: String)
        /** The socket is down and any current job must be dropped before reconnect. */
        fun onConnectionLost()
    }

    private data class Endpoint(
        val host: String,
        val port: Int,
        val wallet: String,
        val password: String,
        val agent: String,
        val useTls: Boolean
    )

    private val running = AtomicBoolean(false)
    private val wantConnection = AtomicBoolean(false)
    private val reconnecting = AtomicBoolean(false)
    private val generation = AtomicInteger(0)
    private val reconnectAttempt = AtomicInteger(0)
    private val reqId = AtomicInteger(1)
    private val ioLock = Any()
    private var socket: Socket? = null
    private var writer: BufferedWriter? = null
    private val pendingSubmits: MutableSet<Int> = Collections.synchronizedSet(HashSet())
    private val pendingLogins: MutableSet<Int> = Collections.synchronizedSet(HashSet())
    @Volatile private var endpoint: Endpoint? = null
    @Volatile var sessionId: String? = null
        private set

    fun connect(
        host: String,
        port: Int,
        wallet: String,
        password: String,
        agent: String = "XTE-Miner/1.1.0",
        useTls: Boolean = MinerValidation.stratumUsesTls(port)
    ) {
        val hostNorm = MinerValidation.normalizeHost(host)
        val walletNorm = wallet.trim()
        val passNorm = if (password.isEmpty()) "x" else password
        if (hostNorm == null || port !in 1..65535 ||
            !MinerValidation.isWallet(walletNorm) || !MinerValidation.isPassword(passNorm) ||
            agent.length !in 1..64 || agent.any { it.code !in 0x20..0x7E }
        ) {
            listener.onError("Invalid pool settings")
            listener.onStatus("Disconnected")
            return
        }

        endpoint = Endpoint(hostNorm, port, walletNorm, passNorm, agent, useTls)
        wantConnection.set(true)
        reconnectAttempt.set(0)
        val gen = openSession()
        beginConnect(gen)
    }

    fun submit(jobId: String, nonceHex: String, resultHex: String) {
        val sid = sessionId ?: return
        if (!running.get()) return
        if (!MinerValidation.isSessionId(sid) || !MinerValidation.isJobId(jobId) ||
            !isHex(nonceHex, 4) || !isHex(resultHex, 32)
        ) {
            listener.onError("Submit blocked")
            return
        }
        if (pendingSubmits.size >= MAX_IN_FLIGHT) {
            listener.onError("Too many in-flight submits")
            return
        }
        try {
            val id = reqId.getAndIncrement()
            pendingSubmits.add(id)
            send(
                JSONObject()
                    .put("id", id)
                    .put("jsonrpc", "2.0")
                    .put("method", "submit")
                    .put(
                        "params",
                        JSONObject()
                            .put("id", sid)
                            .put("job_id", jobId)
                            .put("nonce", nonceHex)
                            .put("result", resultHex)
                    )
            )
        } catch (e: Exception) {
            listener.onError("Submit failed: ${safeIoMessage(e)}")
        }
    }

    fun disconnect() {
        wantConnection.set(false)
        generation.incrementAndGet()
        running.set(false)
        pendingSubmits.clear()
        pendingLogins.clear()
        sessionId = null
        closeQuietly()
        listener.onStatus("Disconnected")
    }

    private fun beginConnect(gen: Int) {
        val ep = endpoint ?: return
        if (generation.get() != gen || !wantConnection.get()) return
        val tlsLabel = if (ep.useTls) " TLS" else ""
        listener.onStatus("Connecting to ${ep.host}:${ep.port}$tlsLabel…")
        thread(name = "stratum-connect", isDaemon = true) {
            if (generation.get() != gen || !wantConnection.get()) return@thread
            var opened: Socket? = null
            try {
                val s = openSocket(ep.host, ep.port, ep.useTls)
                opened = s
                if (generation.get() != gen || !running.get() || !wantConnection.get()) {
                    s.close()
                    return@thread
                }
                synchronized(ioLock) {
                    if (generation.get() != gen || !running.get() || !wantConnection.get()) {
                        s.close()
                        return@thread
                    }
                    socket = s
                    writer = BufferedWriter(OutputStreamWriter(s.getOutputStream(), Charsets.UTF_8))
                }
                listener.onStatus(
                    if (ep.useTls) "Connected (TLS) — logging in…" else "Connected — logging in…"
                )

                thread(name = "stratum-reader", isDaemon = true) { readLoop(gen) }
                thread(name = "stratum-keepalive", isDaemon = true) { keepaliveLoop(gen) }

                val id = reqId.getAndIncrement()
                pendingLogins.clear()
                pendingLogins.add(id)
                send(
                    JSONObject()
                        .put("id", id)
                        .put("jsonrpc", "2.0")
                        .put("method", "login")
                        .put(
                            "params",
                            JSONObject()
                                .put("login", ep.wallet)
                                .put("pass", ep.password)
                                .put("agent", ep.agent)
                        )
                )
            } catch (e: Exception) {
                Log.e(TAG, "connect failed: ${e.javaClass.simpleName}")
                try {
                    opened?.close()
                } catch (_: Exception) {
                }
                if (generation.get() == gen) {
                    listener.onError("Connect failed: ${safeIoMessage(e)}")
                    running.set(false)
                    closeQuietly()
                    if (!scheduleReconnect(gen)) listener.onStatus("Disconnected")
                }
            }
        }
    }

    private fun openSession(): Int {
        val gen = generation.incrementAndGet()
        running.set(false)
        pendingSubmits.clear()
        pendingLogins.clear()
        sessionId = null
        closeQuietly()
        running.set(true)
        return gen
    }

    /**
     * One reconnect per failed generation. Returns false when Stop was pressed
     * or the login was rejected, so the caller can show Disconnected.
     */
    private fun scheduleReconnect(failedGen: Int): Boolean {
        if (!wantConnection.get() || generation.get() != failedGen) return false
        if (!reconnecting.compareAndSet(false, true)) return true
        val attempt = reconnectAttempt.getAndIncrement()
        val delay = reconnectDelayMs(attempt)
        listener.onConnectionLost()
        listener.onStatus("Reconnecting in ${delay / 1000}s…")
        thread(name = "stratum-reconnect", isDaemon = true) {
            try {
                Thread.sleep(delay)
            } catch (_: InterruptedException) {
                reconnecting.set(false)
                return@thread
            }
            reconnecting.set(false)
            if (!wantConnection.get() || generation.get() != failedGen) return@thread
            val newGen = openSession()
            beginConnect(newGen)
        }
        return true
    }

    private fun closeQuietly() {
        val w: BufferedWriter?
        val s: Socket?
        synchronized(ioLock) {
            w = writer
            s = socket
            writer = null
            socket = null
        }
        try {
            w?.close()
        } catch (_: Exception) {
        }
        try {
            s?.close()
        } catch (_: Exception) {
        }
    }

    private fun send(obj: JSONObject) {
        val w = synchronized(ioLock) { writer } ?: throw java.io.IOException("not connected")
        synchronized(w) {
            w.write(obj.toString())
            w.write("\n")
            w.flush()
        }
    }

    private fun readLoop(gen: Int) {
        var lost = false
        var lossReason = "Connection lost"
        try {
            val input = synchronized(ioLock) { socket?.getInputStream() } ?: return
            val reader = InputStreamReader(input, Charsets.UTF_8)
            while (running.get() && generation.get() == gen && wantConnection.get()) {
                val line = try {
                    BoundedReaders.readLine(reader, MinerValidation.MAX_STRATUM_LINE_CHARS)
                } catch (e: SocketTimeoutException) {
                    lost = true
                    lossReason = "Read timed out"
                    break
                }
                if (line == null) {
                    lost = true
                    lossReason = "Connection lost"
                    break
                }
                if (line.isBlank()) continue
                if (generation.get() != gen) break
                handleLine(line)
                if (!wantConnection.get()) break
            }
        } catch (e: Exception) {
            if (running.get() && generation.get() == gen) {
                Log.e(TAG, "read error: ${e.javaClass.simpleName}")
                lost = true
                lossReason = if (e.message?.startsWith("line exceeds") == true) {
                    "Rejected oversized pool message"
                } else {
                    "Connection lost"
                }
            }
        } finally {
            if (generation.get() == gen) {
                running.set(false)
                closeQuietly()
                if (lost && wantConnection.get()) {
                    listener.onError(lossReason)
                    if (!scheduleReconnect(gen)) listener.onStatus("Disconnected")
                }
            }
        }
    }

    private fun keepaliveLoop(gen: Int) {
        while (running.get() && generation.get() == gen && wantConnection.get()) {
            try {
                Thread.sleep(KEEPALIVE_MS)
            } catch (_: InterruptedException) {
                break
            }
            if (!running.get() || generation.get() != gen || !wantConnection.get()) break
            val sid = sessionId ?: continue
            if (!MinerValidation.isSessionId(sid)) continue
            try {
                send(
                    JSONObject()
                        .put("id", reqId.getAndIncrement())
                        .put("jsonrpc", "2.0")
                        .put("method", "keepalived")
                        .put("params", JSONObject().put("id", sid))
                )
            } catch (e: Exception) {
                if (running.get() && generation.get() == gen && wantConnection.get()) {
                    Log.e(TAG, "keepalive failed: ${e.javaClass.simpleName}")
                    listener.onError("Connection lost")
                    running.set(false)
                    closeQuietly()
                    if (!scheduleReconnect(gen)) listener.onStatus("Disconnected")
                }
                break
            }
        }
    }

    internal fun handleLine(line: String) {
        try {
            val trimmed = line.trim()
            if (trimmed.length > MinerValidation.MAX_STRATUM_LINE_CHARS || !trimmed.startsWith("{")) {
                if (BuildConfig.DEBUG) {
                    Log.w(TAG, "rejected stratum line len=${trimmed.length}")
                }
                return
            }
            val obj = JSONObject(trimmed)
            val id = if (obj.has("id") && !obj.isNull("id")) obj.optInt("id", -1) else -1

            if (obj.has("method")) {
                when (obj.optString("method", "")) {
                    "job" -> {
                        val params = obj.optJSONObject("params") ?: return
                        dispatchJob(params)
                    }
                }
                return
            }

            val isSubmit = id >= 0 && pendingSubmits.remove(id)
            val isLogin = id >= 0 && pendingLogins.remove(id)

            if (obj.has("error") && !obj.isNull("error")) {
                val msg = errorText(obj.get("error"))
                if (isLogin || sessionId == null) {
                    // A rejected login is not a dead socket. Do not reconnect.
                    wantConnection.set(false)
                    listener.onError("Login error: $msg")
                    listener.onStatus("Login failed")
                } else if (isSubmit) {
                    listener.onShareRejected(msg)
                } else {
                    listener.onError(msg)
                }
                return
            }

            if (!obj.has("result") || obj.isNull("result")) return
            val result = obj.get("result")
            if (isLogin && result is JSONObject) {
                val sid = result.optString("id", "").trim()
                if (!MinerValidation.isSessionId(sid)) {
                    wantConnection.set(false)
                    listener.onError("Login failed")
                    listener.onStatus("Login failed")
                    return
                }
                sessionId = sid
                reconnectAttempt.set(0)
                listener.onStatus("Authorized — mining")
                val job = result.optJSONObject("job")
                if (job != null) dispatchJob(job)
                return
            }
            if (isSubmit) {
                val status = when (result) {
                    is JSONObject -> result.optString("status", "")
                    else -> result.toString()
                }
                if (status.equals("OK", ignoreCase = true)) {
                    listener.onShareAccepted()
                } else if (status.isNotEmpty()) {
                    listener.onShareRejected(MinerValidation.clip(status, 160))
                }
            }
        } catch (e: Exception) {
            if (BuildConfig.DEBUG) {
                Log.w(TAG, "rejected stratum message (${e.javaClass.simpleName}) len=${line.length}")
            }
        }
    }

    private fun dispatchJob(job: JSONObject) {
        val jobId = job.optString("job_id", "").trim()
        val blob = job.optString("blob", "").trim()
        val target = job.optString("target", "").trim()
        val sid = job.optString("id", "").trim()
        if (sid.isNotEmpty() && MinerValidation.isSessionId(sid)) sessionId = sid
        val problem = MinerValidation.validateStratumJob(jobId, blob, target)
        if (problem != null) {
            Log.w(TAG, "rejected job: $problem")
            listener.onError("Rejected job")
            return
        }
        listener.onJob(jobId, blob, target, sessionId ?: "")
    }

    companion object {
        private const val TAG = "StratumClient"
        private const val CONNECT_TIMEOUT_MS = 15_000
        private const val READ_TIMEOUT_MS = 120_000
        private const val KEEPALIVE_MS = 60_000L
        private const val MAX_IN_FLIGHT = 32

        /** First retry waits 2s, then 4, 8, 16, then 30s. */
        internal fun reconnectDelayMs(attempt: Int): Long {
            val shift = attempt.coerceIn(0, 4)
            return (2_000L shl shift).coerceAtMost(30_000L)
        }

        private fun isHex(s: String, nbytes: Int): Boolean {
            if (s.length != nbytes * 2) return false
            return s.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }
        }

        private fun errorText(err: Any): String {
            val raw = when (err) {
                is JSONObject -> {
                    val m = err.optString("message", "")
                    if (m.isNotEmpty()) m else "error"
                }
                else -> err.toString()
            }
            return MinerValidation.clip(raw, 160)
        }

        private fun safeIoMessage(e: Exception): String {
            val m = e.message ?: e.javaClass.simpleName
            if (m.contains("\n") || m.length > 120) return e.javaClass.simpleName
            return MinerValidation.clip(m, 120)
        }

        private fun cipherAllowed(name: String): Boolean {
            val u = name.uppercase()
            return !u.contains("NULL") && !u.contains("ANON") && !u.contains("EXPORT") &&
                !u.contains("RC4") && !u.contains("DES") && !u.contains("MD5")
        }

        private fun tlsFactory(): javax.net.ssl.SSLSocketFactory {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(null as KeyStore?)
            val context = SSLContext.getInstance("TLS")
            context.init(null, tmf.trustManagers, SecureRandom())
            return context.socketFactory
        }

        private fun openSocket(host: String, port: Int, useTls: Boolean): Socket {
            val plain = Socket()
            try {
                plain.tcpNoDelay = true
                plain.keepAlive = true
                plain.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
                plain.soTimeout = READ_TIMEOUT_MS
                if (!useTls) return plain
                val ssl = tlsFactory().createSocket(plain, host, port, true) as SSLSocket
                ssl.soTimeout = READ_TIMEOUT_MS
                ssl.tcpNoDelay = true
                ssl.keepAlive = true
                val protos = ssl.supportedProtocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }
                if (protos.isNotEmpty()) ssl.enabledProtocols = protos.toTypedArray()
                val ciphers = ssl.supportedCipherSuites.filter { cipherAllowed(it) }
                if (ciphers.isNotEmpty()) ssl.enabledCipherSuites = ciphers.toTypedArray()
                val params = ssl.sslParameters
                params.endpointIdentificationAlgorithm = "HTTPS"
                ssl.sslParameters = params
                ssl.startHandshake()
                return ssl
            } catch (e: Exception) {
                try {
                    plain.close()
                } catch (_: Exception) {
                }
                throw e
            }
        }
    }
}
