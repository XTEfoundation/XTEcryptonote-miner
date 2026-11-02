package com.xtefoundation.cryptonoteminer

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A real `getblocktemplate` response from https://main.trrxitte.com/json_rpc
 * (height 1788054, reserve_size 8, wallet = the public example address from
 * TRRXITTE/wallet-api-docs). Nothing from this template was ever submitted.
 */
class LiveTemplateTest {

    private fun hex(b: ByteArray) = MinerValidation.bytesToHex(b)

    private val json: String =
        javaClass.classLoader!!.getResourceAsStream("xte_live_template.json")!!.bufferedReader().readText()

    // The JVM unit-test android.jar stubs org.json, so read the flat fields with a regex.
    private fun field(name: String): String =
        Regex("\"$name\"\\s*:\\s*\"?([0-9A-Za-z]+)\"?").find(json)!!.groupValues[1]

    private fun chukwa(input: ByteArray): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(3).withMemoryAsKB(512).withParallelism(1)
            .withSalt(input.copyOfRange(0, 16)).build()
        val out = ByteArray(32)
        Argon2BytesGenerator().apply { init(params) }.generateBytes(input, out)
        return out
    }

    @Test
    fun liveTemplateParsesAndBuildsChukwaJob() {
        assertEquals("OK", field("status"))
        val tpl = MinerValidation.hexToBytes(field("blocktemplate_blob"))
        val height = field("height").toLong()
        val difficulty = field("difficulty").toLong()
        val reservedOffset = field("reserved_offset").toInt()
        assertEquals(1788054L, height)
        assertEquals(87238L, difficulty)
        assertEquals(457, tpl.size)

        val parsed = CryptoNoteBlock.parse(tpl)
        assertEquals(6, parsed.majorVersion)
        assertTrue(parsed.hasParentBlock)
        assertEquals(0, parsed.parentMmDepth)
        // Template arrives with an all-zero merge-mining root.
        val mm = parsed.parentMmRootOffset
        assertTrue(tpl.copyOfRange(mm, mm + 32).all { it == 0.toByte() })
        // Parsing does not copy or alter bytes.
        assertArrayEquals(tpl, parsed.raw)

        val job = SoloJob.fromTemplate("solo-1", tpl, height, difficulty)
        assertEquals(6, job.majorVersion)
        assertTrue(job.hashingBlob.size in MinerValidation.MIN_BLOB_BYTES..MinerValidation.MAX_JOB_BLOB_BYTES)
        assertArrayEquals(parsed.previousBlockHash, job.previousBlockHash)

        // Writing the template's own nonce back yields the template with only the mm root filled.
        val sameNonce = job.blockWithNonce(parsed.nonce)
        assertEquals(tpl.size, sameNonce.size)
        for (i in tpl.indices) {
            if (i in mm until mm + 32) continue
            assertEquals("byte $i", tpl[i], sameNonce[i])
        }
        assertArrayEquals(parsed.auxiliaryBlockHeaderHash(), sameNonce.copyOfRange(mm, mm + 32))
        assertFalse(sameNonce.copyOfRange(mm, mm + 32).all { it == 0.toByte() })

        // Round trip: re-parse the filled block and get exactly the same blob and hashing blob.
        val filled = CryptoNoteBlock.parse(sameNonce)
        assertArrayEquals(sameNonce, filled.raw)
        assertEquals(39, filled.powNonceOffset())
        assertArrayEquals(job.hashingBlob, filled.powHashingBlob())
        // The aux hash does not cover the nonce or parent, so filling the root keeps it stable.
        assertArrayEquals(parsed.auxiliaryBlockHeaderHash(), filled.auxiliaryBlockHeaderHash())

        // A mined nonce lands in the same place for the miner and for the daemon.
        val nonce = 0x5a17c0de
        val submitted = job.blockWithNonce(nonce)
        val reparsed = CryptoNoteBlock.parse(submitted)
        assertEquals(nonce, reparsed.nonce)
        assertArrayEquals(job.hashingBlobWithNonce(nonce), reparsed.powHashingBlob())
        var diffs = 0
        for (i in tpl.indices) if (tpl[i] != submitted[i]) diffs++
        assertTrue(diffs in 1..36)
        // Reserved extra-nonce space untouched.
        assertArrayEquals(tpl.copyOfRange(reservedOffset, reservedOffset + 8),
            submitted.copyOfRange(reservedOffset, reservedOffset + 8))

        // Chukwa pipeline runs on the exact bytes the native worker would hash.
        val pow = chukwa(job.hashingBlobWithNonce(nonce))
        assertEquals(32, pow.size)
        assertArrayEquals(pow, chukwa(reparsed.powHashingBlob()))
        println("live: height=$height diff=$difficulty blob=${tpl.size} hashing=${job.hashingBlob.size} " +
            "mmOffset=$mm aux=${hex(parsed.auxiliaryBlockHeaderHash())} hashingBlob=${hex(job.hashingBlob)} " +
            "blockHash=${hex(reparsed.blockHash())} pow=${hex(pow)} meets=${CryptoNoteBlock.checkHash(pow, difficulty)}")
    }
}
