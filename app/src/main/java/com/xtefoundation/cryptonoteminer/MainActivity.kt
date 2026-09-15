package com.xtefoundation.cryptonoteminer

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity(), MiningEngine.StatsListener {

    private lateinit var prefs: MinerPrefs
    private lateinit var engine: MiningEngine

    private lateinit var etHost: EditText
    private lateinit var etPort: EditText
    private lateinit var etWallet: EditText
    private lateinit var etPass: EditText
    private lateinit var etThreads: EditText
    private lateinit var btnStartStop: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvHashrate: TextView
    private lateinit var tvShares: TextView
    private lateinit var tvLog: TextView
    private lateinit var scrollLog: ScrollView

    private val logBuf = StringBuilder()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        prefs = MinerPrefs(this)
        engine = MiningEngine(this)

        etHost = findViewById(R.id.etHost)
        etPort = findViewById(R.id.etPort)
        etWallet = findViewById(R.id.etWallet)
        etPass = findViewById(R.id.etPass)
        etThreads = findViewById(R.id.etThreads)
        btnStartStop = findViewById(R.id.btnStartStop)
        tvStatus = findViewById(R.id.tvStatus)
        tvHashrate = findViewById(R.id.tvHashrate)
        tvShares = findViewById(R.id.tvShares)
        tvLog = findViewById(R.id.tvLog)
        scrollLog = findViewById(R.id.scrollLog)

        etHost.setText(prefs.poolHost)
        etPort.setText(prefs.poolPort.toString())
        etWallet.setText(prefs.wallet)
        etPass.setText(prefs.password)
        etThreads.setText(prefs.threads.toString())

        btnStartStop.setOnClickListener {
            if (engine.isMining()) {
                engine.stop()
                setFieldsEnabled(true)
                btnStartStop.text = getString(R.string.start)
            } else {
                savePrefs()
                val wallet = etWallet.text.toString().trim()
                if (wallet.length < 10) {
                    Toast.makeText(this, R.string.err_wallet, Toast.LENGTH_LONG).show()
                    return@setOnClickListener
                }
                val host = etHost.text.toString().trim().ifEmpty { MinerPrefs.DEFAULT_HOST }
                val port = etPort.text.toString().toIntOrNull() ?: MinerPrefs.DEFAULT_PORT
                val pass = etPass.text.toString().ifEmpty { MinerPrefs.DEFAULT_PASS }
                val threads = etThreads.text.toString().toIntOrNull()?.coerceIn(1, 16)
                    ?: Runtime.getRuntime().availableProcessors().coerceIn(1, 4)

                setFieldsEnabled(false)
                btnStartStop.text = getString(R.string.stop)
                engine.start(host, port, wallet, pass, threads)
            }
        }

        onStats("Idle", 0.0, 0, 0, 0)
        onLog("XTE Miner ready. Enter XT… wallet and tap Start. No mining until you start.")
        onLog("Algo: Chukwa (Argon2id t=3 m=512KiB p=1). Pool protocol: CN login/job/submit.")
        onLog("Default pool: ${MinerPrefs.DEFAULT_HOST}:${MinerPrefs.DEFAULT_PORT}")
    }

    private fun savePrefs() {
        prefs.poolHost = etHost.text.toString()
        prefs.poolPort = etPort.text.toString().toIntOrNull() ?: MinerPrefs.DEFAULT_PORT
        prefs.wallet = etWallet.text.toString()
        prefs.password = etPass.text.toString()
        prefs.threads = etThreads.text.toString().toIntOrNull() ?: prefs.threads
    }

    private fun setFieldsEnabled(enabled: Boolean) {
        etHost.isEnabled = enabled
        etPort.isEnabled = enabled
        etWallet.isEnabled = enabled
        etPass.isEnabled = enabled
        etThreads.isEnabled = enabled
    }

    override fun onStats(status: String, hashrate: Double, accepted: Long, rejected: Long, hashes: Long) {
        tvStatus.text = getString(R.string.status_fmt, status)
        tvHashrate.text = getString(R.string.hashrate_fmt, formatHs(hashrate), hashes)
        tvShares.text = getString(R.string.shares_fmt, accepted, rejected)
    }

    override fun onLog(line: String) {
        if (logBuf.length > 8000) logBuf.delete(0, logBuf.length - 4000)
        logBuf.append(line).append('\n')
        tvLog.text = logBuf.toString()
        scrollLog.post { scrollLog.fullScroll(ScrollView.FOCUS_DOWN) }
    }

    override fun onDestroy() {
        engine.stop()
        super.onDestroy()
    }

    private fun formatHs(hs: Double): String {
        return when {
            hs >= 1_000_000 -> String.format("%.2f MH/s", hs / 1_000_000)
            hs >= 1_000 -> String.format("%.2f kH/s", hs / 1_000)
            else -> String.format("%.2f H/s", hs)
        }
    }
}
