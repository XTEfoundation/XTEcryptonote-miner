package com.xtefoundation.cryptonoteminer.wallet

import net.i2p.crypto.eddsa.math.GroupElement
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable

/**
 * The two curve operations CryptoNote key generation needs, delegated to the
 * EdDSA-Java library (net.i2p.crypto:eddsa, a port of the ed25519 ref10 code that
 * CryptoNote's `crypto-ops.c` is also based on). No curve arithmetic is implemented here.
 *
 * - [scReduce32]: `sc_reduce32`, a 32-byte little-endian integer mod l.
 * - [scalarMultBase]: `ge_scalarmult_base` + `ge_p3_tobytes`, i.e. `secret_key_to_public_key`.
 */
object Ed25519Ops {
    private val spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519)
    private val base: GroupElement = spec.b

    fun scReduce32(s: ByteArray): ByteArray {
        require(s.size == 32) { "scalar must be 32 bytes" }
        val wide = ByteArray(64)
        System.arraycopy(s, 0, wide, 0, 32)
        val r = spec.scalarOps.reduce(wide)
        wide.fill(0)
        return r
    }

    /** True when [s] is already a canonical scalar (< l), like `sc_check`. */
    fun isReduced(s: ByteArray): Boolean = s.size == 32 && scReduce32(s).contentEquals(s)

    fun scalarMultBase(s: ByteArray): ByteArray {
        require(isReduced(s)) { "scalar is not reduced" }
        return base.scalarMultiply(s).toByteArray()
    }

    /** True when [p] decodes to a curve point (`check_key`). */
    fun isPoint(p: ByteArray): Boolean = try {
        p.size == 32 && GroupElement(spec.curve, p).isOnCurve
    } catch (_: Exception) {
        false
    }
}
