package com.xtefoundation.cryptonoteminer.wallet

import java.util.zip.CRC32

/**
 * 25-word CryptoNote English seed, as in TRRXITTE/traaitt `src/mnemonics/Mnemonics.cpp`:
 * eight little-endian uint32 chunks of the private spend key, three words each, plus a
 * checksum word chosen by CRC32 over the first three letters of the 24 words.
 */
object Mnemonic {
    private val words = EnglishWordList.WORDS
    private val index: Map<String, Int> = words.withIndex().associate { it.value to it.index }
    private val n = words.size.toLong()

    sealed class Result {
        class Ok(val privateSpendKey: ByteArray) : Result()
        class Error(val message: String) : Result()
    }

    fun fromPrivateKey(key: ByteArray): List<String> {
        require(key.size == 32)
        val out = ArrayList<String>(25)
        for (i in 0 until 32 step 4) {
            val v = (key[i].toLong() and 0xFF) or ((key[i + 1].toLong() and 0xFF) shl 8) or
                ((key[i + 2].toLong() and 0xFF) shl 16) or ((key[i + 3].toLong() and 0xFF) shl 24)
            val w1 = v % n
            val w2 = ((v / n) + w1) % n
            val w3 = (((v / n) / n) + w2) % n
            out.add(words[w1.toInt()]); out.add(words[w2.toInt()]); out.add(words[w3.toInt()])
        }
        out.add(checksumWord(out))
        return out
    }

    fun checksumWord(first24: List<String>): String {
        val crc = CRC32()
        crc.update(first24.joinToString("") { it.take(3) }.toByteArray(Charsets.UTF_8))
        return first24[(crc.value % first24.size).toInt()]
    }

    fun toPrivateKey(phrase: String): Result {
        val list = phrase.trim().lowercase().split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (list.size != 25) return Result.Error("The seed must be 25 words, not ${list.size}.")
        val bad = list.indexOfFirst { it !in index }
        if (bad >= 0) return Result.Error("Word ${bad + 1} is not in the English word list.")
        if (checksumWord(list.subList(0, 24)) != list[24]) {
            return Result.Error("Checksum word does not match. Check the spelling and order.")
        }
        val key = ByteArray(32)
        for (c in 0 until 8) {
            val w1 = index.getValue(list[3 * c]).toLong()
            val w2 = index.getValue(list[3 * c + 1]).toLong()
            val w3 = index.getValue(list[3 * c + 2]).toLong()
            val v = w1 + n * (((n - w1) + w2) % n) + n * n * (((n - w2) + w3) % n)
            if (v % n != w1 || v > 0xFFFFFFFFL) return Result.Error("Invalid seed.")
            for (j in 0 until 4) key[4 * c + j] = (v shr (8 * j)).toByte()
        }
        return Result.Ok(key)
    }
}
