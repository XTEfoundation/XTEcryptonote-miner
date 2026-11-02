package com.xtefoundation.cryptonoteminer

/**
 * Keccak-256 with the original Keccak padding (0x01 … 0x80), i.e. CryptoNote
 * `cn_fast_hash`. This is NOT SHA3-256 (which pads with 0x06).
 *
 * Line-for-line Kotlin port of the public-domain baseline implementation
 * `keccak.c` by Markku-Juhani O. Saarinen (19-Nov-11), the same file the coin
 * ships as `src/crypto/keccak.c` in TRRXITTE/traaitt. `cn_fast_hash` there is
 * `keccak1600(in, len, state)` (rate 136 bytes) truncated to 32 bytes, which is
 * exactly Keccak-256.
 *
 * Only a handful of hashes are computed per block template (miner tx, tree
 * hash, merge-mining root), so a JVM implementation is fast enough and lets the
 * whole template pipeline run in plain JVM unit tests.
 */
object Keccak {
    private const val ROUNDS = 24
    private const val RATE = 136 // HASH_DATA_AREA in traaitt keccak.c
    const val HASH_BYTES = 32

    private val RNDC = longArrayOf(
        0x0000000000000001L, 0x0000000000008082L, -0x7fffffffffff7f76L, -0x7fffffff7fff8000L,
        0x000000000000808bL, 0x0000000080000001L, -0x7fffffff7fff7f7fL, -0x7fffffffffff7ff7L,
        0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, -0x7fffffffffffff75L, -0x7fffffffffff7f77L, -0x7fffffffffff7ffdL,
        -0x7fffffffffff7ffeL, -0x7fffffffffffff80L, 0x000000000000800aL, -0x7fffffff7ffffff6L,
        -0x7fffffff7fff7f7fL, -0x7fffffffffff7f80L, 0x0000000080000001L, -0x7fffffff7fff7ff8L
    )
    private val ROTC = intArrayOf(
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    )
    private val PILN = intArrayOf(
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    )

    private fun keccakf(st: LongArray) {
        val bc = LongArray(5)
        for (round in 0 until ROUNDS) {
            // Theta
            for (i in 0 until 5) {
                bc[i] = st[i] xor st[i + 5] xor st[i + 10] xor st[i + 15] xor st[i + 20]
            }
            for (i in 0 until 5) {
                val t = bc[(i + 4) % 5] xor java.lang.Long.rotateLeft(bc[(i + 1) % 5], 1)
                var j = 0
                while (j < 25) {
                    st[j + i] = st[j + i] xor t
                    j += 5
                }
            }
            // Rho Pi
            var t = st[1]
            for (i in 0 until 24) {
                val j = PILN[i]
                bc[0] = st[j]
                st[j] = java.lang.Long.rotateLeft(t, ROTC[i])
                t = bc[0]
            }
            // Chi
            var j = 0
            while (j < 25) {
                for (i in 0 until 5) bc[i] = st[j + i]
                for (i in 0 until 5) {
                    st[j + i] = st[j + i] xor (bc[(i + 1) % 5].inv() and bc[(i + 2) % 5])
                }
                j += 5
            }
            // Iota
            st[0] = st[0] xor RNDC[round]
        }
    }

    private fun absorbBlock(st: LongArray, block: ByteArray, off: Int) {
        for (w in 0 until RATE / 8) {
            st[w] = st[w] xor MinerValidation.loadLe64(block, off + 8 * w)
        }
        keccakf(st)
    }

    /** Keccak-256 (original padding) of [data][offset, offset+length). */
    fun keccak256(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): ByteArray {
        require(offset >= 0 && length >= 0 && offset <= data.size - length) { "bad range" }
        val st = LongArray(25)
        var pos = offset
        var remaining = length
        while (remaining >= RATE) {
            absorbBlock(st, data, pos)
            pos += RATE
            remaining -= RATE
        }
        // Last block and padding
        val temp = ByteArray(RATE)
        System.arraycopy(data, pos, temp, 0, remaining)
        temp[remaining] = 1
        temp[RATE - 1] = (temp[RATE - 1].toInt() or 0x80).toByte()
        absorbBlock(st, temp, 0)

        val out = ByteArray(HASH_BYTES)
        for (i in 0 until HASH_BYTES) {
            out[i] = (st[i / 8] ushr (8 * (i % 8))).toByte()
        }
        return out
    }

    /** CryptoNote `cn_fast_hash`. */
    fun cnFastHash(data: ByteArray): ByteArray = keccak256(data)
}
