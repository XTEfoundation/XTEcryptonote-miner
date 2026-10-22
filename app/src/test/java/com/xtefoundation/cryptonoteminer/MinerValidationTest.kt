package com.xtefoundation.cryptonoteminer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.StringReader

class MinerValidationTest {
    private val example =
        "XT2LD4w2FWZNcRCG4cYxfu8Bd1GjVziQ9Gv8MpK8NdXXg7uwJsbfXoYaGuJT2wqfMPapcjj4gmVasKvXLNnYxrDR1tVjhwwcP"

    @Test
    fun acceptsPublishedXteAddress() {
        assertEquals(97, example.length)
        assertTrue(MinerValidation.isWallet(example))
        assertTrue(MinerValidation.isWallet("$example.${"9".repeat(6)}"))
        assertTrue(MinerValidation.isWallet("$example+${"ab".repeat(32)}"))
        assertTrue(MinerValidation.isWallet("XT" + "1".repeat(93)))
        assertTrue(MinerValidation.isWallet("XT" + "1".repeat(104)))
        assertTrue(MinerValidation.isWallet("XT" + "1".repeat(106)))
    }

    @Test
    fun rejectsWalletInjectionAndShortPrefixes() {
        assertFalse(MinerValidation.isWallet("xte.trrxitte.com"))
        assertFalse(MinerValidation.isWallet("XT"))
        assertFalse(MinerValidation.isWallet("XT" + "1".repeat(10)))
        assertFalse(MinerValidation.isWallet("XT" + "0".repeat(93)))
        assertFalse(MinerValidation.isWallet("XT" + "O".repeat(93)))
        assertFalse(MinerValidation.isWallet("XT" + "I".repeat(93)))
        assertFalse(MinerValidation.isWallet("XT" + "l".repeat(93)))
        assertTrue(MinerValidation.isWallet("  $example\n"))
        assertFalse(MinerValidation.isWallet("$example\nextra"))
        assertFalse(MinerValidation.isWallet("$example+"))
        assertFalse(MinerValidation.isWallet("$example+1000"))
        assertFalse(MinerValidation.isWallet("$example.abc"))
        assertFalse(MinerValidation.isWallet("XT" + "1".repeat(94)))
    }

    @Test
    fun hostAndPortDefaults() {
        assertEquals("xte.trrxitte.com", MinerValidation.normalizeHost("xte.trrxitte.com"))
        assertEquals("eu-east.trrxitte.com", MinerValidation.normalizeHost("eu-east.trrxitte.com."))
        assertEquals("localhost", MinerValidation.normalizeHost("localhost"))
        assertEquals("127.0.0.1", MinerValidation.normalizeHost("127.0.0.1"))
        assertEquals("::1", MinerValidation.normalizeHost("[::1]"))
        assertEquals("2001:db8::1", MinerValidation.normalizeHost("2001:db8::1"))
        assertNull(MinerValidation.normalizeHost("xte.trrxitte.com:3333"))
        assertNull(MinerValidation.normalizeHost("http://xte.trrxitte.com"))
        assertNull(MinerValidation.normalizeHost("xte.trrxitte.com/json_rpc"))
        assertNull(MinerValidation.normalizeHost("user@xte.trrxitte.com"))
        assertNull(MinerValidation.normalizeHost("bad host"))
        assertNull(MinerValidation.normalizeHost("bad\nhost"))
        assertNull(MinerValidation.normalizeHost("-bad.com"))
        assertNull(MinerValidation.normalizeHost("256.1.1.1"))
        assertNull(MinerValidation.normalizeHost(""))
        assertNull(MinerValidation.normalizeHost("1::2::3"))

        val err = MinerValidation.validateConfig(
            poolMode = true,
            host = "xte.trrxitte.com",
            port = 3333,
            wallet = example,
            password = "x",
            threads = 2
        )
        assertNull(err)
        assertEquals(
            MinerValidation.ERR_PORT,
            MinerValidation.validateConfig(true, "xte.trrxitte.com", 0, example, "x", 2)
        )
        assertEquals(
            MinerValidation.ERR_THREADS,
            MinerValidation.validateConfig(true, "xte.trrxitte.com", 3333, example, "x", 0)
        )
        assertEquals(
            MinerValidation.ERR_THREADS,
            MinerValidation.validateConfig(false, "eu-east.trrxitte.com", 14485, example, "x", 17)
        )
        assertEquals(
            MinerValidation.ERR_PASSWORD,
            MinerValidation.validateConfig(true, "xte.trrxitte.com", 3333, example, "bad\npass", 2)
        )
        assertNull(
            MinerValidation.validateConfig(false, "eu-east.trrxitte.com", 14485, example, "bad\npass", 2)
        )
    }

    @Test
    fun tlsOnlyOnPoolSslPort() {
        assertTrue(MinerValidation.stratumUsesTls(9999))
        assertFalse(MinerValidation.stratumUsesTls(3333))
        assertFalse(MinerValidation.stratumUsesTls(14485))
    }

    @Test
    fun blobAndTargetBounds() {
        val blob = "ab".repeat(MinerValidation.MIN_BLOB_BYTES)
        assertNull(MinerValidation.validateBlobHex(blob, MinerValidation.MAX_JOB_BLOB_BYTES))
        assertEquals(
            "blob shorter than nonce field",
            MinerValidation.validateBlobHex("ab".repeat(42), MinerValidation.MAX_JOB_BLOB_BYTES)
        )
        assertEquals(
            "blob too large",
            MinerValidation.validateBlobHex("ab".repeat(MinerValidation.MAX_JOB_BLOB_BYTES + 1), MinerValidation.MAX_JOB_BLOB_BYTES)
        )
        assertEquals("odd-length blob", MinerValidation.validateBlobHex("abc", MinerValidation.MAX_JOB_BLOB_BYTES))
        assertEquals("non-hex blob", MinerValidation.validateBlobHex("zz".repeat(MinerValidation.MIN_BLOB_BYTES), MinerValidation.MAX_JOB_BLOB_BYTES))
        assertNull(MinerValidation.validateTargetHex("ffffffff"))
        assertNull(MinerValidation.validateTargetHex("0102030405060708"))
        assertEquals("target must be 4 or 8 bytes", MinerValidation.validateTargetHex("ffff"))
        assertEquals(
            "bad job id",
            MinerValidation.validateStratumJob("job id", blob, "ffffffff")
        )
        assertNull(MinerValidation.validateStratumJob("job-1", blob, "ffffffff"))
    }

    @Test
    fun targetAndDifficultyMatchXmrig() {
        assertEquals(4294967297L, MinerValidation.parseTarget64("01000000"))
        assertEquals(-1L, MinerValidation.parseTarget64("ffffffff"))
        assertEquals(0x0102030405060708L, MinerValidation.parseTarget64("0807060504030201"))
        assertEquals(0L, MinerValidation.parseTarget64("00000000"))
        assertEquals(-1L, MinerValidation.targetFromDifficulty(1))
        assertEquals(Long.MAX_VALUE, MinerValidation.targetFromDifficulty(2))
        assertEquals(0L, MinerValidation.targetFromDifficulty(0))
        assertEquals(
            MinerValidation.parseTarget64("ffffffff"),
            MiningEngine.parseTarget64("ffffffff")
        )
    }

    @Test
    fun hexRejectsMalformedInput() {
        val bytes = MinerValidation.hexToBytes("00ff")
        assertEquals(2, bytes.size)
        assertEquals(0, bytes[0].toInt())
        assertEquals(-1, bytes[1].toInt())
        assertEquals("00ff", MinerValidation.bytesToHex(bytes))
        assertFails("odd-length hex") { MinerValidation.hexToBytes("abc") }
        assertFails("non-hex character") { MinerValidation.hexToBytes("0g") }
        assertFails("empty hex") { MinerValidation.hexToBytes("  ") }
        assertFails("hex too long") { MinerValidation.hexToBytes("aa", maxBytes = 0) }
    }

    @Test
    fun unsignedParsingRejectsNegatives() {
        assertEquals(14485L, MinerValidation.parseUnsignedLongText("14485"))
        assertEquals(255L, MinerValidation.parseUnsignedLongText("0xff"))
        assertEquals(7L, MinerValidation.unsignedLongFromNumber(7))
        assertFails("bad integer") { MinerValidation.parseUnsignedLongText("-1") }
        assertFails("bad integer") { MinerValidation.parseUnsignedLongText("+1") }
        assertFails("negative integer") { MinerValidation.unsignedLongFromNumber(-5) }
        assertFails("non-integral integer") { MinerValidation.unsignedLongFromNumber(1.5) }
    }

    @Test
    fun redactWalletAndClip() {
        val masked = MinerValidation.redact("login failed for $example", emptyList())
        assertFalse(masked.contains(example))
        assertTrue(masked.contains("XT…"))
        val safe = MinerValidation.redact(
            "login failed for $example and worker-secret-name " + "y".repeat(400),
            listOf("worker-secret-name"),
            maxLen = 80
        )
        assertFalse(safe.contains("worker-secret-name"))
        assertFalse(safe.contains(example))
        assertTrue(safe.length <= 81)
        assertEquals("password x", MinerValidation.redact("password x", listOf("x")))
    }

    @Test
    fun boundedReadersStopOversizedInput() {
        assertEquals("abcd", BoundedReaders.readLine(StringReader("abcd\nnext"), 8))
        assertEquals("ab", BoundedReaders.readLine(StringReader("ab\r\n"), 8))
        assertEquals("ab", BoundedReaders.readLine(StringReader("ab"), 8))
        assertNull(BoundedReaders.readLine(StringReader(""), 8))

        val reader = StringReader("abcdefghij\nOK\n")
        try {
            BoundedReaders.readLine(reader, 4)
            throw AssertionError("expected cap")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("exceeds"))
        }
        assertEquals("OK", BoundedReaders.readLine(reader, 4))

        assertEquals(4, BoundedReaders.readStream(ByteArrayInputStream(byteArrayOf(1, 2, 3, 4)), 4).size)
        try {
            BoundedReaders.readStream(ByteArrayInputStream(byteArrayOf(1, 2, 3, 4, 5)), 4)
            throw AssertionError("expected cap")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("exceeds"))
        }
    }

    private fun assertFails(snippet: String, block: () -> Unit) {
        try {
            block()
            throw AssertionError("expected failure containing $snippet")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message ?: "", e.message!!.contains(snippet))
        }
    }
}
