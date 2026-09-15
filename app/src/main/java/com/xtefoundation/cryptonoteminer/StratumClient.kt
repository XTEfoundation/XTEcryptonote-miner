package com.xtefoundation.cryptonoteminer

import android.util.Log
import org.json.JSONObject
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Collections
import java.util.HashSet
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * Cryptonote-nodejs-pool stratum (login / job / submit / keepalived).
 * XTE pool at xte.trrxitte.com uses this CN login protocol (not Bitcoin subscribe).
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
    }

    private val running = AtomicBoolean(false)
    private val reqId = AtomicInteger(1)
    private var socket: Socket? = null
    private var writer: BufferedWriter? = null
    private var readerThread: Thread? = null
    private var keepaliveThread: Thread? = null
    private val pendingSubmits: MutableSet<Int> = Collections.synchronizedSet(HashSet())
    private val pendingLogins: MutableSet<Int> = Collections.synchronizedSet(HashSet())
    @Volatile var sessionId: String? = null
        private set

    fun connect(host: String, port: Int, wallet: String, password: String, agent: String = "XTE-Miner/1.0.0") {
        disconnect()
        running.set(true)
        listener.onStatus("Connecting to $host:$port…")
        thread(name = "stratum-connect", isDaemon = true) {
            try {
                val s = Socket()
                s.tcpNoDelay = true
                s.keepAlive = true
                s.connect(InetSocketAddress(host, port), 15_000)
                s.soTimeout = 0
                socket = s
                writer = BufferedWriter(OutputStreamWriter(s.getOutputStream(), Charsets.UTF_8))
                listener.onStatus("Connected — logging in…")

                readerThread = thread(name = "stratum-reader", isDaemon = true) { readLoop() }
                keepaliveThread = thread(name = "stratum-keepalive", isDaemon = true) { keepaliveLoop() }

                val id = reqId.getAndIncrement()
                pendingLogins.add(id)
                send(
                    JSONObject()
                        .put("id", id)
                        .put("jsonrpc", "2.0")
                        .put("method", "login")
                        .put(
                            "params",
                            JSONObject()
                                .put("login", wallet)
                                .put("pass", password)
                                .put("agent", agent)
                        )
                )
            } catch (e: Exception) {
                Log.e(TAG, "connect failed", e)
                listener.onError("Connect failed: ${e.message}")
                listener.onStatus("Disconnected")
                running.set(false)
            }
        }
    }

    fun submit(jobId: String, nonceHex: String, resultHex: String) {
        val sid = sessionId ?: return
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
            listener.onError("Submit failed: ${e.message}")
        }
    }

    fun disconnect() {
        running.set(false)
        pendingSubmits.clear()
        pendingLogins.clear()
        try { writer?.close() } catch (_: Exception) {}
        try { socket?.close() } catch (_: Exception) {}
        writer = null
        socket = null
        sessionId = null
        listener.onStatus("Disconnected")
    }

    private fun send(obj: JSONObject) {
        val w = writer ?: return
        synchronized(w) {
            w.write(obj.toString())
            w.write("\n")
            w.flush()
        }
    }

    private fun readLoop() {
        try {
            val reader = BufferedReader(InputStreamReader(socket!!.getInputStream(), Charsets.UTF_8))
            while (running.get()) {
                val line = reader.readLine() ?: break
                if (line.isBlank()) continue
                handleLine(line)
            }
        } catch (e: Exception) {
            if (running.get()) {
                Log.e(TAG, "read error", e)
                listener.onError("Connection lost: ${e.message}")
                listener.onStatus("Disconnected")
            }
        } finally {
            running.set(false)
        }
    }

    private fun keepaliveLoop() {
        while (running.get()) {
            try {
                Thread.sleep(60_000)
                val sid = sessionId ?: continue
                send(
                    JSONObject()
                        .put("id", reqId.getAndIncrement())
                        .put("jsonrpc", "2.0")
                        .put("method", "keepalived")
                        .put("params", JSONObject().put("id", sid))
                )
            } catch (_: Exception) {
                break
            }
        }
    }

    private fun handleLine(line: String) {
        try {
            val obj = JSONObject(line)
            val id = if (obj.has("id") && !obj.isNull("id")) obj.optInt("id", -1) else -1

            if (obj.has("method")) {
                when (obj.getString("method")) {
                    "job" -> dispatchJob(obj.getJSONObject("params"))
                }
                return
            }

            val isSubmit = pendingSubmits.remove(id)
            val isLogin = pendingLogins.remove(id)

            if (obj.has("error") && !obj.isNull("error")) {
                val err = obj.get("error")
                val msg = when (err) {
                    is JSONObject -> err.optString("message", err.toString())
                    else -> err.toString()
                }
                if (isLogin || sessionId == null) {
                    listener.onError("Login error: $msg")
                    listener.onStatus("Login failed")
                } else if (isSubmit) {
                    listener.onShareRejected(msg)
                } else {
                    listener.onError(msg)
                }
                return
            }

            if (obj.has("result") && !obj.isNull("result")) {
                val result = obj.get("result")
                if (result is JSONObject) {
                    if (isLogin || (result.has("id") && result.has("job"))) {
                        sessionId = result.getString("id")
                        listener.onStatus("Authorized — mining")
                        if (result.has("job")) dispatchJob(result.getJSONObject("job"))
                    } else if (isSubmit && result.optString("status").equals("OK", true)) {
                        listener.onShareAccepted()
                    }
                } else if (isSubmit && result.toString().equals("OK", true)) {
                    listener.onShareAccepted()
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "bad line: $line", e)
        }
    }

    private fun dispatchJob(job: JSONObject) {
        val jobId = job.optString("job_id", "")
        val blob = job.optString("blob", "")
        val target = job.optString("target", "")
        val sid = job.optString("id", sessionId ?: "")
        if (sid.isNotEmpty()) sessionId = sid
        if (jobId.isEmpty() || blob.isEmpty() || target.isEmpty()) return
        listener.onJob(jobId, blob, target, sessionId ?: sid)
    }

    companion object {
        private const val TAG = "StratumClient"
    }
}
