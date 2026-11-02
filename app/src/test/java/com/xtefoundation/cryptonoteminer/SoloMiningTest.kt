package com.xtefoundation.cryptonoteminer

import org.bouncycastle.crypto.digests.KeccakDigest
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.math.BigInteger
import java.util.Random

class SoloMiningTest {

    private fun hex(s: String) = MinerValidation.hexToBytes(s)
    private fun hex(b: ByteArray) = MinerValidation.bytesToHex(b)

    private fun resource(name: String): List<String> =
        javaClass.classLoader!!.getResourceAsStream(name)!!.bufferedReader().readLines()
            .filter { it.isNotBlank() && !it.startsWith("#") }

    /** Chukwa = Argon2id v1.3, t=3, m=512 KiB, p=1, salt = first 16 bytes, 32-byte output. */
    private fun chukwa(input: ByteArray): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(3)
            .withMemoryAsKB(512)
            .withParallelism(1)
            .withSalt(input.copyOfRange(0, 16))
            .build()
        val gen = Argon2BytesGenerator()
        gen.init(params)
        val out = ByteArray(32)
        gen.generateBytes(input, out)
        return out
    }

    // ---------------------------------------------------------------- Keccak

    @Test
    fun keccak256KnownVectorsOriginalPadding() {
        // Keccak-256 (not SHA3-256) reference values.
        assertEquals(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            hex(Keccak.keccak256(ByteArray(0)))
        )
        assertEquals(
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
            hex(Keccak.keccak256("abc".toByteArray()))
        )
        // SHA3-256("") is a7ffc6f8…; make sure we are not computing that.
        assertNotEquals(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
            hex(Keccak.keccak256(ByteArray(0)))
        )
        // cn_fast_hash of a single zero byte: the constant used by getBaseTransactionHash (v2).
        assertEquals(
            "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a",
            hex(Keccak.cnFastHash(byteArrayOf(0)))
        )
    }

    @Test
    fun keccak256MatchesCoinKeccakAcrossBlockBoundaries() {
        // Expected values produced by TRRXITTE/traaitt src/crypto/keccak.c (keccak1600,
        // first 32 bytes) compiled on the host, and confirmed with pycryptodome keccak-256.
        // Input: bytes (i mod 251) for i in [0, n).
        val expected = mapOf(
            1 to "bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a",
            55 to "797f92d5e159d80a886c0a7802a255b475a1e8e473e8cf4345144824a2aee79c",
            135 to "cbdfd9dee5faad3818d6b06f95a219fd290b0e1706f6a82e5a595b9ce9faca62",
            136 to "7ce759f1ab7f9ce437719970c26b0a66ff11fe3e38e17df89cf5d29c7d7f807e",
            137 to "ac73d4fae68b8453f764007c1a20ce95994187861f0c3227a3a8e99a73a3b1db",
            200 to "bfb0aa97863e797943cf7c33bb7e880bb4543f3d2703c0923c6901c2af57b890",
            271 to "27eceb59ebc3dc8a04a5b135be641591a7278540e4556a2ba9f408194e666ec3",
            272 to "8e2476e65823b24d96ebe239f2c1534cdf763e689e2410c3b1cb0c74e6177bfc",
            273 to "3f02f134370e4debb95140ef49ddd3aed8c65ff1ed83a43f1b269421f179c5f9",
            500 to "d1346278c6b964973ca0d85063b4e9264739c7b84ff877c8018c865229f44835"
        )
        val input = ByteArray(600) { (it % 251).toByte() }
        for ((n, h) in expected) {
            assertEquals("len=$n", h, hex(Keccak.keccak256(input, 0, n)))
        }
    }

    @Test
    fun keccak256MatchesBouncyCastleKeccak() {
        val rnd = Random(42)
        for (len in 0..700 step 7) {
            val data = ByteArray(len).also { rnd.nextBytes(it) }
            val d = KeccakDigest(256)
            d.update(data, 0, data.size)
            val out = ByteArray(32)
            d.doFinal(out, 0)
            assertArrayEquals("len=$len", out, Keccak.keccak256(data))
        }
    }

    // ------------------------------------------------------- real block data

    @Test
    fun realBlocksReproduceBlockHashNonceAndParentLayout() {
        val lines = resource("turtlecoin_blocks.txt")
        assertEquals(13, lines.size)
        var v6 = 0
        for (line in lines) {
            val (hash, pow, nonce, blob) = line.split(" ")
            val block = CryptoNoteBlock.parse(hex(blob))
            assertEquals("hash v${block.majorVersion}", hash, hex(block.blockHash()))
            assertEquals("nonce v${block.majorVersion}", nonce.toLong(), block.nonce.toLong() and 0xffffffffL)
            if (block.majorVersion >= 2) {
                assertEquals(MinerValidation.NONCE_OFFSET, block.powNonceOffset())
                val hb = block.powHashingBlob()
                assertEquals(nonce.toLong(), CryptoNoteBlock.loadLe32(hb, 39).toLong() and 0xffffffffL)
            }
            if (block.majorVersion == CryptoNoteBlock.CHUKWA_MAJOR_VERSION) {
                // getBlockLongHash: Chukwa(getParentBlockHashingBinaryArray(true)).
                assertEquals("chukwa pow", pow, hex(chukwa(block.powHashingBlob())))
                v6++
            }
        }
        assertEquals(1, v6)
    }

    @Test
    fun realBlocksMergeMiningRootIsAuxHeaderHash() {
        // Currency::checkProofOfWorkV2: with depth 0 the mm root must equal the aux header hash.
        var checked = 0
        for (line in resource("turtlecoin_blocks.txt")) {
            val blob = hex(line.split(" ")[3])
            val block = CryptoNoteBlock.parse(blob)
            if (!block.hasParentBlock || block.parentMmDepth != 0) continue
            val root = blob.copyOfRange(block.parentMmRootOffset, block.parentMmRootOffset + 32)
            assertArrayEquals(root, block.auxiliaryBlockHeaderHash())
            checked++
        }
        // 13 vectors: 2 v1 (no parent block), 1 v5 with a real depth-1 merge-mining branch.
        assertEquals(10, checked)
    }

    private fun templateFields(): Map<String, String> =
        resource("turtlecoin_template.txt").associate { it.substringBefore('=') to it.substringAfter('=') }

    @Test
    fun realTemplateBuildsSubmittableJob() {
        val t = templateFields()
        val tpl = hex(t.getValue("blocktemplate"))
        val difficulty = t.getValue("difficulty").toLong()
        val parsed = CryptoNoteBlock.parse(tpl)
        assertEquals(5, parsed.majorVersion)
        assertEquals(0, parsed.parentMmDepth)
        // Template mm root is zero; the miner must fill it.
        assertTrue(tpl.copyOfRange(parsed.parentMmRootOffset, parsed.parentMmRootOffset + 32).all { it == 0.toByte() })
        assertEquals(t.getValue("mergedRoot"), hex(parsed.auxiliaryBlockHeaderHash()))

        // Production rejects non-Chukwa templates.
        try {
            SoloJob.fromTemplate("solo-1", tpl, 1457937, difficulty)
            fail("v5 template must be rejected for Chukwa mining")
        } catch (_: IllegalArgumentException) {
        }

        val job = SoloJob.fromTemplate("solo-1", tpl, 1457937, difficulty, requireChukwa = false)
        assertEquals(76, job.hashingBlob.size)
        val nonce = 0x1c64
        val submitted = job.blockWithNonce(nonce)
        assertEquals(tpl.size, submitted.size)

        // What the daemon recomputes from the submitted blob must equal what we hash.
        val reparsed = CryptoNoteBlock.parse(submitted)
        assertEquals(nonce, reparsed.nonce)
        assertArrayEquals(job.hashingBlobWithNonce(nonce), reparsed.powHashingBlob())
        assertArrayEquals(
            reparsed.auxiliaryBlockHeaderHash(),
            submitted.copyOfRange(reparsed.parentMmRootOffset, reparsed.parentMmRootOffset + 32)
        )
        // Only the mm root and the nonce differ from the template.
        var diffs = 0
        for (i in tpl.indices) if (tpl[i] != submitted[i]) diffs++
        assertTrue(diffs in 1..36)
        // Reserved space (extra nonce) left untouched.
        val ro = t.getValue("reservedOffset").toInt()
        assertArrayEquals(tpl.copyOfRange(ro, ro + 8), submitted.copyOfRange(ro, ro + 8))
    }

    @Test
    fun v6TemplateJobHashesLikeTheDaemon() {
        // Same real template relabelled as major 6 (first byte), to exercise the Chukwa path.
        val tpl = hex(templateFields().getValue("blocktemplate"))
        tpl[0] = 6
        val job = SoloJob.fromTemplate("solo-2", tpl, 1, 1000)
        assertEquals(6, job.majorVersion)
        val nonce = -0x21524111 // 0xdeadbeef
        val reparsed = CryptoNoteBlock.parse(job.blockWithNonce(nonce))
        assertArrayEquals(chukwa(job.hashingBlobWithNonce(nonce)), chukwa(reparsed.powHashingBlob()))
        assertEquals(39, reparsed.powNonceOffset())
    }

    // ------------------------------------------------------------ difficulty

    private fun bigCheck(hash: ByteArray, d: Long): Boolean =
        BigInteger(1, hash.reversedArray()).multiply(BigInteger(java.lang.Long.toUnsignedString(d))) <
            BigInteger.ONE.shiftLeft(256)

    @Test
    fun checkHashMatchesDefinition() {
        val pow = hex("ae6d9c3df0d2e9e4db7beeab3df4e2e14f63c472dcd9a9903f0b0c7900000000")
        assertTrue(CryptoNoteBlock.checkHash(pow, 1_000_000_000L))
        assertFalse(CryptoNoteBlock.checkHash(pow, 10_000_000_000L))
        assertFalse(CryptoNoteBlock.checkHash(pow, 0L))
        assertTrue(CryptoNoteBlock.checkHash(ByteArray(32) { -1 }, 1L))
        assertFalse(CryptoNoteBlock.checkHash(ByteArray(32) { -1 }, 2L))
        val rnd = Random(7)
        repeat(2000) {
            val h = ByteArray(32).also { rnd.nextBytes(it) }
            for (k in 24..31) if (rnd.nextInt(4) != 0) h[k] = 0
            val d = rnd.nextLong() ushr rnd.nextInt(64)
            if (d != 0L) assertEquals(bigCheck(h, d), CryptoNoteBlock.checkHash(h, d))
        }
    }

    @Test
    fun target64PrefilterNeverDropsValidBlock() {
        // Native workers prefilter with le64(hash[24..32]) < (2^64-1)/difficulty.
        val rnd = Random(9)
        repeat(5000) {
            val d = (rnd.nextLong() ushr (1 + rnd.nextInt(62))).coerceAtLeast(1)
            val h = ByteArray(32).also { rnd.nextBytes(it) }
            val top = java.lang.Long.divideUnsigned(MinerValidation.targetFromDifficulty(d), 1L + rnd.nextInt(3))
            for (k in 0 until 8) h[24 + k] = (top ushr (8 * k)).toByte()
            if (CryptoNoteBlock.checkHash(h, d)) {
                val top64 = MinerValidation.loadLe64(h, 24)
                assertTrue(java.lang.Long.compareUnsigned(top64, MinerValidation.targetFromDifficulty(d)) <= 0)
            }
        }
    }

    // ------------------------------------------------------------- strictness

    @Test
    fun parserRejectsMalformedBlobs() {
        val tpl = hex(templateFields().getValue("blocktemplate"))
        tpl[0] = 6
        val bad = listOf(
            tpl.copyOf(tpl.size - 1), // truncated
            tpl + byteArrayOf(0), // trailing byte
            tpl.copyOf().also { it[0] = 7 }, // unknown major version
            tpl.copyOf(40), // cut inside parent header
            byteArrayOf(0x06, 0x00), // header only
            ByteArray(0),
            byteArrayOf(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0x01), // varint overflow
            byteArrayOf(0x86.toByte(), 0x00) // non-canonical varint
        )
        for ((i, b) in bad.withIndex()) {
            try {
                CryptoNoteBlock.parse(b)
                fail("case $i should be rejected")
            } catch (_: IllegalArgumentException) {
            }
        }
        // Huge tx_hashes count must not allocate.
        val parsed = CryptoNoteBlock.parse(tpl)
        assertEquals(18, parsed.transactionHashes.size)
        val countOffset = tpl.size - 18 * 32 - 1
        assertEquals(18, tpl[countOffset].toInt())
        val hostile = tpl.copyOf(countOffset) + CryptoNoteBlock.varint(1L shl 40) + ByteArray(64)
        try {
            CryptoNoteBlock.parse(hostile)
            fail("hostile count")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun treeHashShapes() {
        val hs = List(5) { i -> Keccak.cnFastHash(byteArrayOf(i.toByte())) }
        assertArrayEquals(hs[0], CryptoNoteBlock.treeHash(hs.take(1)))
        assertArrayEquals(Keccak.cnFastHash(hs[0] + hs[1]), CryptoNoteBlock.treeHash(hs.take(2)))
        // count=3: cnt=2 -> ints=[h0, H(h1||h2)] -> H(ints0||ints1)
        assertArrayEquals(
            Keccak.cnFastHash(hs[0] + Keccak.cnFastHash(hs[1] + hs[2])),
            CryptoNoteBlock.treeHash(hs.take(3))
        )
        // count=5: cnt=4 -> ints=[h0,h1,h2,H(h3||h4)] -> [H(h0h1),H(h2,x)] -> root
        val x = Keccak.cnFastHash(hs[3] + hs[4])
        val l = Keccak.cnFastHash(hs[0] + hs[1])
        val r = Keccak.cnFastHash(hs[2] + x)
        assertArrayEquals(Keccak.cnFastHash(l + r), CryptoNoteBlock.treeHash(hs))
        assertEquals(0, CryptoNoteBlock.treeDepth(1))
        assertEquals(1, CryptoNoteBlock.treeDepth(2))
        assertEquals(1, CryptoNoteBlock.treeDepth(3))
        assertEquals(2, CryptoNoteBlock.treeDepth(4))
    }
}
