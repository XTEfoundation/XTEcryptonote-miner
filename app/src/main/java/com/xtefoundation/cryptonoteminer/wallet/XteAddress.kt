package com.xtefoundation.cryptonoteminer.wallet

import com.xtefoundation.cryptonoteminer.CryptoNoteBlock
import com.xtefoundation.cryptonoteminer.Keccak

/**
 * XTE standard address: CnBase58(varint(prefix) || publicSpendKey || publicViewKey ||
 * first 4 bytes of Keccak-256 of everything before)
 * (`Base58::encode_addr`, `getAccountAddressAsStr` in TRRXITTE/traaitt).
 */
object XteAddress {
    /** `CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX` in traaitt `src/config/CryptoNoteConfig.h`. */
    const val PREFIX: Long = 1334
    private const val CHECKSUM = 4

    data class Decoded(val prefix: Long, val publicSpendKey: ByteArray, val publicViewKey: ByteArray)

    fun encode(publicSpendKey: ByteArray, publicViewKey: ByteArray, prefix: Long = PREFIX): String {
        require(publicSpendKey.size == 32 && publicViewKey.size == 32)
        val body = CryptoNoteBlock.varint(prefix) + publicSpendKey + publicViewKey
        val check = Keccak.keccak256(body).copyOfRange(0, CHECKSUM)
        return CnBase58.encode(body + check)
    }

    /** Decodes and verifies the checksum. Returns null when malformed. Does not check the prefix. */
    fun decode(address: String): Decoded? {
        val raw = CnBase58.decode(address.trim()) ?: return null
        if (raw.size < 1 + 64 + CHECKSUM) return null
        var prefix = 0L
        var shift = 0
        var i = 0
        while (true) {
            if (i >= raw.size || shift > 56) return null
            val b = raw[i++].toInt() and 0xFF
            prefix = prefix or ((b and 0x7F).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
        }
        if (raw.size != i + 64 + CHECKSUM) return null
        val body = raw.copyOfRange(0, raw.size - CHECKSUM)
        val check = raw.copyOfRange(raw.size - CHECKSUM, raw.size)
        if (!Keccak.keccak256(body).copyOfRange(0, CHECKSUM).contentEquals(check)) return null
        return Decoded(prefix, raw.copyOfRange(i, i + 32), raw.copyOfRange(i + 32, i + 64))
    }

    /** Full XTE check: checksum, XTE prefix, and both keys are curve points. */
    fun isValidXte(address: String): Boolean {
        val d = decode(address) ?: return false
        return d.prefix == PREFIX && Ed25519Ops.isPoint(d.publicSpendKey) && Ed25519Ops.isPoint(d.publicViewKey)
    }
}
