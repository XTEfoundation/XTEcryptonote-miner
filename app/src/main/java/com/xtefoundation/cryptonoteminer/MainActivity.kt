package com.xtefoundation.cryptonoteminer

import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.textfield.TextInputLayout

class MainActivity : AppCompatActivity(), MiningEngine.StatsListener {

    private lateinit var prefs: MinerPrefs
    private lateinit var engine: MiningEngine

    private lateinit var rgMode: RadioGroup
    private lateinit var rbPool: RadioButton
    private lateinit var rbSeednode: RadioButton
    private lateinit var tilHost: TextInputLayout
    private lateinit var tilPass: TextInputLayout
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
    private var applyingMode = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        prefs = MinerPrefs(this)
        engine = MiningEngine(this)

        rgMode = findViewById(R.id.rgMode)
        rbPool = findViewById(R.id.rbPool)
        rbSeednode = findViewById(R.id.rbSeednode)
        tilHost = findViewById(R.id.tilHost)
        tilPass = findViewById(R.id.tilPass)
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

        etWallet.setText(prefs.wallet)
        etPass.setText(prefs.password)
        etThreads.setText(prefs.threads.toString())

        applyingMode = true
        if (prefs.mode == MiningMode.SEEDNODE) {
            rbSeednode.isChecked = true
        } else {
            rbPool.isChecked = true
        }
        etHost.setText(prefs.poolHost)
        etPort.setText(prefs.poolPort.toString())
        applyModeUi(prefs.mode, fillPresets = false)
        applyingMode = false

        rgMode.setOnCheckedChangeListener { _, checkedId ->
            if (applyingMode) return@setOnCheckedChangeListener
            val mode = if (checkedId == R.id.rbSeednode) MiningMode.SEEDNODE else MiningMode.POOL
            applyModeUi(mode, fillPresets = true)
        }

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
                val mode = currentMode()
                val host = etHost.text.toString().trim()
                    .ifEmpty { MinerPrefs.defaultHostFor(mode) }
                val port = etPort.text.toString().toIntOrNull()
                    ?: MinerPrefs.defaultPortFor(mode)
                val pass = etPass.text.toString().ifEmpty { MinerPrefs.DEFAULT_PASS }
                val threads = etThreads.text.toString().toIntOrNull()?.coerceIn(1, 16)
                    ?: Runtime.getRuntime().availableProcessors().coerceIn(1, 4)

                setFieldsEnabled(false)
                btnStartStop.text = getString(R.string.stop)
                engine.start(mode, host, port, wallet, pass, threads)
            }
        }

        onStats("Idle", 0.0, 0, 0, 0)
        onLog("XTE Miner ready. Enter XT… wallet and tap Start. No mining until you start.")
        onLog("Algo: Chukwa (Argon2id t=3 m=512KiB p=1).")
        onLog("Pool: ${MinerPrefs.DEFAULT_HOST}:${MinerPrefs.DEFAULT_PORT} (CN login/job/submit)")
        onLog("Seednode: ${MinerPrefs.DEFAULT_SEED_HOST}:${MinerPrefs.DEFAULT_SEED_PORT} (daemon JSON-RPC)")
    }

    private fun currentMode(): MiningMode =
        if (rbSeednode.isChecked) MiningMode.SEEDNODE else MiningMode.POOL

    private fun applyModeUi(mode: MiningMode, fillPresets: Boolean) {
        val seed = mode == MiningMode.SEEDNODE
        tilPass.visibility = if (seed) View.GONE else View.VISIBLE
        tilHost.hint = if (seed) getString(R.string.pool_host) + " (daemon)" else getString(R.string.pool_host)
        if (fillPresets) {
            etHost.setText(MinerPrefs.defaultHostFor(mode))
            etPort.setText(MinerPrefs.defaultPortFor(mode).toString())
        }
    }

    private fun savePrefs() {
        prefs.mode = currentMode()
        prefs.poolHost = etHost.text.toString()
        prefs.poolPort = etPort.text.toString().toIntOrNull()
            ?: MinerPrefs.defaultPortFor(currentMode())
        prefs.wallet = etWallet.text.toString()
        prefs.password = etPass.text.toString()
        prefs.threads = etThreads.text.toString().toIntOrNull() ?: prefs.threads
    }

    private fun setFieldsEnabled(enabled: Boolean) {
        rbPool.isEnabled = enabled
        rbSeednode.isEnabled = enabled
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
