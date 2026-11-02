package com.xtefoundation.cryptonoteminer.wallet

import com.xtefoundation.cryptonoteminer.Keccak
import java.security.SecureRandom

/**
 * A deterministic CryptoNote wallet, generated like traaitt's reference wallet
 * (`Crypto::generate_keys`, `generate_deterministic_keys`):
 * spend = sc_reduce32(random 32 bytes); view = sc_reduce32(Keccak-256(spend));
 * public = secret * G. Everything derives from the private spend key, which the
 * 25-word seed encodes.
 */
class XteKeys private constructor(
    private val spend: ByteArray,
    private val view: ByteArray,
    val publicSpendKey: ByteArray,
    val publicViewKey: ByteArray
) {
    val address: String = XteAddress.encode(publicSpendKey, publicViewKey)

    fun privateSpendKey(): ByteArray = spend.copyOf()
    fun privateViewKey(): ByteArray = view.copyOf()
    fun mnemonic(): List<String> = Mnemonic.fromPrivateKey(spend)

    /** Overwrites the private keys held by this object. */
    fun wipe() {
        spend.fill(0)
        view.fill(0)
    }

    companion object {
        fun generate(random: SecureRandom = SecureRandom()): XteKeys {
            val seed = ByteArray(32)
            random.nextBytes(seed)
            val spend = Ed25519Ops.scReduce32(seed)
            seed.fill(0)
            return fromSpendKey(spend).also { spend.fill(0) }
        }

        /** [spendKey] must be a reduced scalar (as every seed restored from words is checked to be). */
        fun fromSpendKey(spendKey: ByteArray): XteKeys {
            require(spendKey.size == 32) { "spend key must be 32 bytes" }
            require(Ed25519Ops.isReduced(spendKey)) { "spend key is not a valid scalar" }
            val spend = spendKey.copyOf()
            val h = Keccak.keccak256(spend)
            val view = Ed25519Ops.scReduce32(h)
            h.fill(0)
            return XteKeys(spend, view, Ed25519Ops.scalarMultBase(spend), Ed25519Ops.scalarMultBase(view))
        }

        /** Restores from a 25-word seed; returns an error message instead when it is invalid. */
        fun fromMnemonic(phrase: String): Pair<XteKeys?, String?> {
            return when (val r = Mnemonic.toPrivateKey(phrase)) {
                is Mnemonic.Result.Error -> null to r.message
                is Mnemonic.Result.Ok -> {
                    val k = r.privateSpendKey
                    try {
                        if (!Ed25519Ops.isReduced(k)) null to "Seed does not encode a valid key."
                        else fromSpendKey(k) to null
                    } finally {
                        k.fill(0)
                    }
                }
            }
        }
    }
}
