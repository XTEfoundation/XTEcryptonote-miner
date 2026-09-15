package com.xtefoundation.cryptonoteminer

import android.content.Context

class MinerPrefs(ctx: Context) {
    private val p = ctx.getSharedPreferences("xte_miner", Context.MODE_PRIVATE)

    var poolHost: String
        get() = p.getString(KEY_HOST, DEFAULT_HOST) ?: DEFAULT_HOST
        set(v) = p.edit().putString(KEY_HOST, v.trim()).apply()

    var poolPort: Int
        get() = p.getInt(KEY_PORT, DEFAULT_PORT)
        set(v) = p.edit().putInt(KEY_PORT, v).apply()

    var wallet: String
        get() = p.getString(KEY_WALLET, "") ?: ""
        set(v) = p.edit().putString(KEY_WALLET, v.trim()).apply()

    var password: String
        get() = p.getString(KEY_PASS, DEFAULT_PASS) ?: DEFAULT_PASS
        set(v) = p.edit().putString(KEY_PASS, v).apply()

    var threads: Int
        get() = p.getInt(KEY_THREADS, Runtime.getRuntime().availableProcessors().coerceIn(1, 4))
        set(v) = p.edit().putInt(KEY_THREADS, v.coerceIn(1, 16)).apply()

    companion object {
        const val DEFAULT_HOST = "xte.trrxitte.com"
        const val DEFAULT_PORT = 3333
        const val DEFAULT_PASS = "x"
        private const val KEY_HOST = "pool_host"
        private const val KEY_PORT = "pool_port"
        private const val KEY_WALLET = "wallet"
        private const val KEY_PASS = "password"
        private const val KEY_THREADS = "threads"
    }
}
