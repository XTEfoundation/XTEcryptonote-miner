package com.xtefoundation.cryptonoteminer

/**
 * Pure input checks shared by the UI, the pool client, and the daemon client.
 * Messages are safe to show in the UI: they never echo the rejected value.
 */
object MinerValidation {
    const val NONCE_OFFSET = 39
    const val MIN_BLOB_BYTES = NONCE_OFFSET + 4
    /**
     * Stratum job blob. The pool sends the hashing blob (~76 bytes when the timestamp
     * varint is 5 bytes). 43 is the smallest buffer that can hold the nonce; 512 is
     * the peer cap from the hand-checked review.
     */
    const val MAX_JOB_BLOB_BYTES = 512
    /** Native hasher cap. Must match `MAX_BLOB` in native-lib.cpp. */
    const val MAX_HASH_BLOB_BYTES = 4096
    /**
     * Largest blocktemplate_blob accepted while parsing a seednode response.
     * The hex form plus JSON must fit in [MAX_RPC_BYTES]. It is not passed to the hasher.
     */
    const val MAX_BLOCK_BLOB_BYTES = 100_000
    const val HASH_BYTES = 32
    const val MAX_STRATUM_LINE_CHARS = 64 * 1024
    const val MAX_RPC_BYTES = 256 * 1024
    const val POOL_TLS_PORT = 9999

    const val ERR_WALLET = "Enter a valid XTE wallet address (starts with XT)."
    const val ERR_HOST = "Enter a valid host name or IP address."
    const val ERR_PORT = "Enter a port between 1 and 65535."
    const val ERR_THREADS = "Thread count must be between 1 and 16."
    const val ERR_PASSWORD = "Password must be 1–128 printable characters."

    /**
     * Standard address is 97 chars (2-byte prefix) or 95 (1-byte). Integrated forms are 106 and 108.
     * Pool login may append `+<payment id>` (16–64 hex) and/or `.<fixed difficulty>` (nodejs-pool separators).
     */
    private val WALLET = Regex(
        "^XT[1-9A-HJ-NP-Za-km-z]{93}" +
            "(?:[1-9A-HJ-NP-Za-km-z]{2}|[1-9A-HJ-NP-Za-km-z]{11}|[1-9A-HJ-NP-Za-km-z]{13})?" +
            "(?:\\+[0-9A-Fa-f]{16,64})?" +
            "(?:\\.\\d{1,18})?$"
    )
    private val HOSTNAME = Regex(
        "^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
    )
    private val IPV4 = Regex(
        "^(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$"
    )
    private val JOB_ID = Regex("^[A-Za-z0-9._:-]{1,128}$")

    fun isWallet(address: String): Boolean = WALLET.matches(address.trim())

    fun isPassword(password: String): Boolean {
        if (password.length !in 1..128) return false
        return password.all { it.code in 0x20..0x7E }
    }

    fun isJobId(id: String): Boolean = JOB_ID.matches(id)

    fun isSessionId(id: String): Boolean = JOB_ID.matches(id)

    /**
     * Default only. Port 9999 is the pool's documented SSL port, so the checkbox
     * starts checked. The user can turn TLS off; some pool configs ship that port
     * with `"ssl": false`.
     */
    fun stratumUsesTls(port: Int): Boolean = port == POOL_TLS_PORT

    /**
     * Accepts an ASCII hostname, IPv4, or IPv6 (optional brackets).
     * Returns the host form suitable for [java.net.InetSocketAddress] and `URI`, or null.
     */
    fun normalizeHost(raw: String?): String? {
        if (raw == null) return null
        var host = raw.trim()
        if (host.isEmpty() || host.length > 253) return null
        if (host.endsWith(".")) host = host.dropLast(1)
        if (host.isEmpty()) return null
        if (host.startsWith("[") && host.endsWith("]") && host.length >= 3) {
            val inner = host.substring(1, host.length - 1)
            return if (isIPv6(inner)) inner else null
        }
        if (isIPv4(host)) return host
        // Four numeric labels that are not a legal IPv4 address (for example 256.1.1.1)
        // must not fall through to the hostname check.
        if (host.count { it == '.' } == 3 && host.all { it.isDigit() || it == '.' }) return null
        if (HOSTNAME.matches(host)) return host
        if (isIPv6(host)) return host
        return null
    }

    fun isIPv4(host: String): Boolean = IPV4.matches(host)

    fun isIPv6(input: String): Boolean {
        if (input.isEmpty() || input.length > 45 || input.contains('%')) return false
        val first = input.indexOf("::")
        if (first != input.lastIndexOf("::")) return false
        val head: String
        val tail: String
        if (first >= 0) {
            head = input.substring(0, first)
            tail = input.substring(first + 2)
        } else {
            head = input
            tail = ""
        }
        val headGroups = splitV6(head) ?: return false
        val tailGroups = splitV6(tail) ?: return false
        val groups = headGroups + tailGroups
        if (groups.isEmpty() && first < 0) return false
        var v4 = false
        var hexCount = 0
        for (i in groups.indices) {
            val g = groups[i]
            if (i == groups.lastIndex && g.contains('.')) {
                if (!isIPv4(g)) return false
                v4 = true
            } else {
                if (g.length > 4 || g.any { it !in "0123456789abcdefABCDEF" }) return false
                hexCount++
            }
        }
        val count = hexCount + if (v4) 2 else 0
        return if (first >= 0) count < 8 else count == 8
    }

    fun validateConfig(
        poolMode: Boolean,
        host: String,
        port: Int,
        wallet: String,
        password: String,
        threads: Int
    ): String? {
        if (!isWallet(wallet.trim())) return ERR_WALLET
        if (normalizeHost(host) == null) return ERR_HOST
        if (port !in 1..65535) return ERR_PORT
        if (threads !in 1..16) return ERR_THREADS
        if (poolMode && !isPassword(password)) return ERR_PASSWORD
        return null
    }

    fun validateBlobHex(hex: String, maxBytes: Int): String? {
        val clean = hex.trim()
        if (clean.isEmpty()) return "empty blob"
        if (clean.length % 2 != 0) return "odd-length blob"
        val n = clean.length / 2
        if (n < MIN_BLOB_BYTES) return "blob shorter than nonce field"
        if (n > maxBytes) return "blob too large"
        if (!isHexChars(clean)) return "non-hex blob"
        return null
    }

    fun validateTargetHex(hex: String): String? {
        val clean = hex.trim()
        if (clean.length != 8 && clean.length != 16) return "target must be 4 or 8 bytes"
        if (!isHexChars(clean)) return "non-hex target"
        return null
    }

    fun validateStratumJob(jobId: String, blobHex: String, targetHex: String): String? {
        if (!isJobId(jobId)) return "bad job id"
        validateBlobHex(blobHex, MAX_JOB_BLOB_BYTES)?.let { return it }
        return validateTargetHex(targetHex)
    }

    fun hexToBytes(hex: String, maxBytes: Int = MAX_BLOCK_BLOB_BYTES): ByteArray {
        val clean = hex.trim()
        if (clean.isEmpty()) throw IllegalArgumentException("empty hex")
        if (clean.length % 2 != 0) throw IllegalArgumentException("odd-length hex")
        val n = clean.length / 2
        if (n > maxBytes) throw IllegalArgumentException("hex too long")
        val out = ByteArray(n)
        var i = 0
        while (i < clean.length) {
            val hi = Character.digit(clean[i], 16)
            val lo = Character.digit(clean[i + 1], 16)
            if (hi < 0 || lo < 0) throw IllegalArgumentException("non-hex character")
            out[i / 2] = ((hi shl 4) + lo).toByte()
            i += 2
        }
        return out
    }

    fun bytesToHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) sb.append(String.format("%02x", b.toInt() and 0xff))
        return sb.toString()
    }

    /**
     * xmrig `Job::setTarget`: 8-byte targets are a little-endian uint64.
     * 4-byte targets expand with `target64 = 2^64-1 / (2^32-1 / t32)`.
     */
    fun parseTarget64(targetHex: String): Long {
        validateTargetHex(targetHex)?.let { throw IllegalArgumentException(it) }
        val bytes = hexToBytes(targetHex, maxBytes = 8)
        if (bytes.size >= 8) return loadLe64(bytes)
        var t32 = 0L
        for (i in 0 until 4) {
            t32 = t32 or ((bytes[i].toLong() and 0xffL) shl (8 * i))
        }
        if (t32 == 0L) return 0L
        val denom = java.lang.Long.divideUnsigned(0xffffffffL, t32)
        if (denom == 0L) return 0L
        return java.lang.Long.divideUnsigned(-1L, denom)
    }

    /** xmrig `Job::setDiff`: `target64 = (2^64 − 1) / difficulty` (unsigned). */
    fun targetFromDifficulty(difficulty: Long): Long {
        if (difficulty == 0L) return 0L
        return java.lang.Long.divideUnsigned(-1L, difficulty)
    }

    fun parseUnsignedLongText(text: String): Long {
        val s = text.trim()
        if (s.isEmpty() || s[0] == '-' || s[0] == '+') {
            throw IllegalArgumentException("bad integer")
        }
        return if (s.startsWith("0x") || s.startsWith("0X")) {
            val body = s.substring(2)
            if (body.isEmpty()) throw IllegalArgumentException("bad integer")
            java.lang.Long.parseUnsignedLong(body, 16)
        } else {
            java.lang.Long.parseUnsignedLong(s, 10)
        }
    }

    fun unsignedLongFromNumber(v: Number): Long {
        when (v) {
            is Long -> {
                if (v < 0) throw IllegalArgumentException("negative integer")
                return v
            }
            is Int -> {
                if (v < 0) throw IllegalArgumentException("negative integer")
                return v.toLong()
            }
            is Short -> {
                if (v < 0) throw IllegalArgumentException("negative integer")
                return v.toLong()
            }
            is Byte -> {
                if (v < 0) throw IllegalArgumentException("negative integer")
                return v.toLong()
            }
        }
        val d = v.toDouble()
        if (!d.isFinite() || d < 0.0 || d > Long.MAX_VALUE.toDouble()) {
            throw IllegalArgumentException("bad integer")
        }
        val asLong = d.toLong()
        if (asLong.toDouble() != d) throw IllegalArgumentException("non-integral integer")
        return asLong
    }

    fun loadLe64(bytes: ByteArray, offset: Int = 0): Long {
        var v = 0L
        for (i in 0 until 8) {
            v = v or ((bytes[offset + i].toLong() and 0xffL) shl (8 * i))
        }
        return v
    }

    fun redact(message: String?, secrets: List<String> = emptyList(), maxLen: Int = 240): String {
        var s = message ?: ""
        for (secret in secrets) {
            if (secret.length >= 6) s = s.replace(secret, "•••")
        }
        s = WALLET_IN_TEXT.replace(s, "XT…")
        return clip(s, maxLen)
    }

    fun clip(s: String, maxLen: Int = 160): String {
        return if (s.length <= maxLen) s else s.take(maxLen) + "…"
    }

    private val WALLET_IN_TEXT = Regex("XT[1-9A-HJ-NP-Za-km-z]{20,}")

    private fun isHexChars(s: String): Boolean {
        return s.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }
    }

    private fun splitV6(s: String): List<String>? {
        if (s.isEmpty()) return emptyList()
        val g = s.split(':')
        if (g.any { it.isEmpty() }) return null
        return g
    }
}
