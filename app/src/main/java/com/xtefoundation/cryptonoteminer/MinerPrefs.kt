package com.xtefoundation.cryptonoteminer

import android.content.Context

enum class MiningMode {
    POOL,
    SEEDNODE;

    companion object {
        fun fromPrefs(value: String?): MiningMode =
            if (value.equals(SEEDNODE.name, ignoreCase = true)) SEEDNODE else POOL
    }
}

class MinerPrefs(ctx: Context) {
    private val p = ctx.getSharedPreferences("xte_miner", Context.MODE_PRIVATE)

    var mode: MiningMode
        get() = MiningMode.fromPrefs(p.getString(KEY_MODE, MiningMode.POOL.name))
        set(v) = p.edit().putString(KEY_MODE, v.name).apply()

    var poolHost: String
        get() = p.getString(KEY_HOST, defaultHostFor(mode)) ?: defaultHostFor(mode)
        set(v) = p.edit().putString(KEY_HOST, v.trim()).apply()

    var poolPort: Int
        get() {
            val v = p.getInt(KEY_PORT, defaultPortFor(mode))
            return if (v in 1..65535) v else defaultPortFor(mode)
        }
        set(v) {
            val stored = if (v in 1..65535) v else defaultPortFor(mode)
            p.edit().putInt(KEY_PORT, stored).apply()
        }

    var wallet: String
        get() = p.getString(KEY_WALLET, "") ?: ""
        set(v) = p.edit().putString(KEY_WALLET, v.trim()).apply()

    var password: String
        get() = p.getString(KEY_PASS, DEFAULT_PASS) ?: DEFAULT_PASS
        set(v) = p.edit().putString(KEY_PASS, v).apply()

    var threads: Int
        get() = p.getInt(KEY_THREADS, Runtime.getRuntime().availableProcessors().coerceIn(1, 4)).coerceIn(1, 16)
        set(v) = p.edit().putInt(KEY_THREADS, v.coerceIn(1, 16)).apply()

    /** True after the user or a previous Start has stored an explicit TLS choice. */
    fun isPoolTlsSet(): Boolean = p.contains(KEY_POOL_TLS)

    var poolTls: Boolean
        get() = p.getBoolean(KEY_POOL_TLS, false)
        set(v) = p.edit().putBoolean(KEY_POOL_TLS, v).apply()

    companion object {
        const val DEFAULT_HOST = "xte.trrxitte.com"
        const val DEFAULT_PORT = 3333
        const val DEFAULT_SEED_HOST = "eu-east.trrxitte.com"
        const val DEFAULT_SEED_PORT = 14485
        const val DEFAULT_PASS = "x"
        private const val KEY_MODE = "mining_mode"
        private const val KEY_HOST = "pool_host"
        private const val KEY_PORT = "pool_port"
        private const val KEY_WALLET = "wallet"
        private const val KEY_PASS = "password"
        private const val KEY_THREADS = "threads"
        private const val KEY_POOL_TLS = "pool_tls"

        fun defaultHostFor(mode: MiningMode): String =
            if (mode == MiningMode.SEEDNODE) DEFAULT_SEED_HOST else DEFAULT_HOST

        fun defaultPortFor(mode: MiningMode): Int =
            if (mode == MiningMode.SEEDNODE) DEFAULT_SEED_PORT else DEFAULT_PORT
    }
}
