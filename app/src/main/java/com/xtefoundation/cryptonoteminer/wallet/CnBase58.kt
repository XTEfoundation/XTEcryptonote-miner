package com.xtefoundation.cryptonoteminer.wallet

import java.math.BigInteger

/**
 * CryptoNote block-wise Base58 (TRRXITTE/traaitt `src/common/Base58.cpp`): the input is cut
 * into 8-byte blocks, each encoded big-endian into 11 characters (a short last block uses
 * [ENCODED_BLOCK_SIZES]). This is not Bitcoin Base58.
 */
object CnBase58 {
    private const val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private const val FULL_BLOCK = 8
    private const val FULL_ENCODED = 11
    private val ENCODED_BLOCK_SIZES = intArrayOf(0, 2, 3, 5, 6, 7, 9, 10, 11)
    private val BASE = BigInteger.valueOf(58)

    fun encode(data: ByteArray): String {
        val sb = StringBuilder()
        var i = 0
        while (i < data.size) {
            val n = minOf(FULL_BLOCK, data.size - i)
            sb.append(encodeBlock(data.copyOfRange(i, i + n)))
            i += n
        }
        return sb.toString()
    }

    private fun encodeBlock(block: ByteArray): String {
        var num = BigInteger(1, block)
        val size = ENCODED_BLOCK_SIZES[block.size]
        val out = CharArray(size) { ALPHABET[0] }
        var pos = size - 1
        while (num.signum() > 0) {
            val qr = num.divideAndRemainder(BASE)
            out[pos--] = ALPHABET[qr[1].toInt()]
            num = qr[0]
        }
        return String(out)
    }

    /** Returns null for any malformed input (bad character, bad length, overflow). */
    fun decode(text: String): ByteArray? {
        val fullBlocks = text.length / FULL_ENCODED
        val lastLen = text.length % FULL_ENCODED
        val lastSize = ENCODED_BLOCK_SIZES.indexOf(lastLen)
        if (lastSize < 0) return null
        val out = ByteArray(fullBlocks * FULL_BLOCK + lastSize)
        var o = 0
        for (b in 0..fullBlocks) {
            val start = b * FULL_ENCODED
            val len = if (b < fullBlocks) FULL_ENCODED else lastLen
            if (len == 0) break
            val size = if (b < fullBlocks) FULL_BLOCK else lastSize
            var num = BigInteger.ZERO
            for (k in start until start + len) {
                val d = ALPHABET.indexOf(text[k])
                if (d < 0) return null
                num = num.multiply(BASE).add(BigInteger.valueOf(d.toLong()))
            }
            if (num.bitLength() > size * 8) return null
            val raw = num.toByteArray()
            val trimmed = if (raw.size > size) raw.copyOfRange(raw.size - size, raw.size) else raw
            System.arraycopy(trimmed, 0, out, o + size - trimmed.size, trimmed.size)
            o += size
        }
        return out
    }
}
