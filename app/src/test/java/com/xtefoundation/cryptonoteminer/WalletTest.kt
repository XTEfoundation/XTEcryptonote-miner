package com.xtefoundation.cryptonoteminer

import com.xtefoundation.cryptonoteminer.wallet.CnBase58
import com.xtefoundation.cryptonoteminer.wallet.Ed25519Ops
import com.xtefoundation.cryptonoteminer.wallet.EnglishWordList
import com.xtefoundation.cryptonoteminer.wallet.Mnemonic
import com.xtefoundation.cryptonoteminer.wallet.XteAddress
import com.xtefoundation.cryptonoteminer.wallet.XteKeys
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class WalletTest {
    private fun hex(s: String) = MinerValidation.hexToBytes(s)
    private fun hex(b: ByteArray) = MinerValidation.bytesToHex(b)

    // turtlecoin-utils README "Address" vector (TRTL prefix 3914525).
    private val seed = "517f0d3c5438416adad752557fdf001acfea189d35af8bba326c86928cc6100e"
    private val pubSpend = "0b5a6ed3fde5470fe13a6e817b5b4caf4ce014e65155ae2f6db66a3b9ad6e819"
    private val privView = "40cf3cdab84ef0c2c17c100ffb1ba3cb1c86e22f2c4bed766a465d466b210a0f"
    private val pubView = "1909af618bef1ecd30339fe12fb133bbaad05cc0ea365caf02254a5f3ae735df"
    private val trtlAddress =
        "TRTLuwmU3QWjU77wyHMvBiMdiQdKgj9qfEc3oiEhHfizSu8wZ6K8ZoWQQY57qNmDC48yg6UAHzyTugB9tMohMnUEArSCdrmeUdP"
    private val mnemonic = "lagoon much skirting goes okay afield royal cupcake lordship myriad necklace " +
        "pliers noodles laboratory axes useful poverty igloo diode ablaze nifty inline point ritual necklace"
    private val trtlPrefix = 3914525L

    // turtlecoin-utils README "Decoded Address" vector.
    private val rawAddress = "9df6ee01f71e440f9a5aab08dbdab0f4f36bba813660a0600f109b1371dc53be33f23c99" +
        "f0ba225065e1b9c2e43165b3e41f10fcb768853126dfa7e612a3df2deb332492cc073a66"

    // Public example address from TRRXITTE/wallet-api-docs (accepted by the live daemon).
    private val publishedXte =
        "XT2LD4w2FWZNcRCG4cYxfu8Bd1GjVziQ9Gv8MpK8NdXXg7uwJsbfXoYaGuJT2wqfMPapcjj4gmVasKvXLNnYxrDR1tVjhwwcP"

    @Test
    fun wordListIsTraaittEnglish() {
        val w = EnglishWordList.WORDS
        assertEquals(1626, w.size)
        assertEquals(1626, w.toSet().size)
        assertEquals("abbey", w.first())
        assertEquals("zoom", w.last())
    }

    @Test
    fun turtlecoinVectorKeysAddressAndMnemonic() {
        val keys = XteKeys.fromSpendKey(hex(seed))
        assertEquals(pubSpend, hex(keys.publicSpendKey))
        assertEquals(privView, hex(keys.privateViewKey()))
        assertEquals(pubView, hex(keys.publicViewKey))
        assertEquals(trtlAddress, XteAddress.encode(keys.publicSpendKey, keys.publicViewKey, trtlPrefix))
        // The README's 25th word ("necklace") disagrees with traaitt's Mnemonics.cpp:
        // CRC32 (standard table, checked against CRC32.h) of the 24 three-letter prefixes
        // selects word index 1, "much". The first 24 words match exactly.
        val words = keys.mnemonic()
        assertEquals(mnemonic.split(" ").subList(0, 24), words.subList(0, 24))
        assertEquals("much", words[24])

        val (restored, err) = XteKeys.fromMnemonic(words.joinToString(" ").uppercase() + "  ")
        assertNull(err)
        assertEquals(seed, hex(restored!!.privateSpendKey()))
        assertEquals(keys.address, restored.address)

        // Same keys under the XTE prefix 1334.
        assertTrue(keys.address.startsWith("XT"))
        assertTrue(XteAddress.isValidXte(keys.address))
        assertTrue(MinerValidation.isWallet(keys.address))
        println("xte-for-vector=${keys.address}")
        assertEquals(EXPECTED_XTE_FOR_VECTOR, keys.address)
    }

    @Test
    fun turtlecoinUtilsTestSuiteVectors() {
        // turtlecoin-utils tests/tests.js: seed <-> mnemonic (asserted both ways there).
        val tSeed = "dd0c02d3202634821b4d9d91b63d919725f5c3e97e803f3512e52fb0dc2aab0c"
        val tWords = "teeming taken piano ramped vegan jazz earth enjoy suture quick lied awkward ferry " +
            "python often exotic cube hexagon ionic joyous cage abnormal hull jigsaw lied"
        assertEquals(tWords, Mnemonic.fromPrivateKey(hex(tSeed)).joinToString(" "))
        val r = Mnemonic.toPrivateKey(tWords)
        assertTrue(r is Mnemonic.Result.Ok)
        assertEquals(tSeed, hex((r as Mnemonic.Result.Ok).privateSpendKey))
        // privateKeyToPublicKey.
        assertEquals(
            "7849297236cd7c0d6c69a3c8c179c038d3c1c434735741bb3c8995c3c9d6f2ac",
            hex(Ed25519Ops.scalarMultBase(hex("4a078e76cd41a3d3b534b83dc6f2ea2de500b653ca82273b7bfad8045d85a400")))
        )
        // encodeRawAddress / decodeAddress.
        val tAddr = "TRTLv3nzumGSpRsZWxkcbDhiVEfy9rAgX3X9b7z8XQAy9gwjB6cwr6BJ3P52a6TQUSfA4eXf3Avwz7W89J4doLuigLjUzQjvRqX"
        assertEquals(tAddr, CnBase58.encode(hex(rawAddress)))
        assertArrayEquals(hex(rawAddress), CnBase58.decode(tAddr))
    }

    @Test
    fun decodedAddressVectorAndBase58RoundTrip() {
        val raw = hex(rawAddress)
        val text = CnBase58.encode(raw)
        assertTrue(text.startsWith("TRTL"))
        assertArrayEquals(raw, CnBase58.decode(text))
        val d = XteAddress.decode(text)!!
        assertEquals(trtlPrefix, d.prefix)
        assertEquals("f71e440f9a5aab08dbdab0f4f36bba813660a0600f109b1371dc53be33f23c99", hex(d.publicSpendKey))
        assertEquals("f0ba225065e1b9c2e43165b3e41f10fcb768853126dfa7e612a3df2deb332492", hex(d.publicViewKey))
        assertFalse(XteAddress.isValidXte(text)) // wrong prefix for XTE
        val r = SecureRandom()
        for (len in 0..40) {
            val b = ByteArray(len).also { r.nextBytes(it) }
            assertArrayEquals(b, CnBase58.decode(CnBase58.encode(b)))
        }
    }

    @Test
    fun publishedXteAddressValidates() {
        val d = XteAddress.decode(publishedXte)!!
        assertEquals(1334L, d.prefix)
        assertTrue(XteAddress.isValidXte(publishedXte))
        assertEquals(publishedXte, XteAddress.encode(d.publicSpendKey, d.publicViewKey))
        // One changed character breaks the checksum.
        val bad = publishedXte.substring(0, 50) + (if (publishedXte[50] == 'a') 'b' else 'a') + publishedXte.substring(51)
        assertFalse(XteAddress.isValidXte(bad))
        assertNull(XteAddress.decode("XT"))
        assertNull(XteAddress.decode(publishedXte + "0"))
    }

    @Test
    fun generatedWalletsRoundTripThroughSeed() {
        repeat(20) {
            val k = XteKeys.generate()
            assertTrue(Ed25519Ops.isReduced(k.privateSpendKey()))
            assertEquals(97, k.address.length)
            assertTrue(XteAddress.isValidXte(k.address))
            assertTrue(MinerValidation.isWallet(k.address))
            val words = k.mnemonic()
            assertEquals(25, words.size)
            val (back, err) = XteKeys.fromMnemonic(words.joinToString(" "))
            assertNull(err)
            assertNotNull(back)
            assertEquals(k.address, back!!.address)
            assertArrayEquals(k.privateViewKey(), back.privateViewKey())
        }
    }

    @Test
    fun mnemonicErrors() {
        assertTrue(Mnemonic.toPrivateKey("abbey") is Mnemonic.Result.Error)
        val words = mnemonic.split(" ").toMutableList()
        words[3] = "notaword"
        assertTrue(Mnemonic.toPrivateKey(words.joinToString(" ")) is Mnemonic.Result.Error)
        val swapped = mnemonic.split(" ").toMutableList()
        swapped[24] = if (swapped[24] == "abbey") "zoom" else "abbey"
        assertTrue(Mnemonic.toPrivateKey(swapped.joinToString(" ")) is Mnemonic.Result.Error)
    }

    @Test
    fun scalarReduction() {
        val l = hex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
        assertEquals("0000000000000000000000000000000000000000000000000000000000000000", hex(Ed25519Ops.scReduce32(l)))
        assertFalse(Ed25519Ops.isReduced(l))
        assertTrue(Ed25519Ops.isReduced(hex(seed)))
        // 1 * G is the standard Ed25519 base point encoding.
        val one = ByteArray(32).also { it[0] = 1 }
        assertEquals("5866666666666666666666666666666666666666666666666666666666666666", hex(Ed25519Ops.scalarMultBase(one)))
    }

    companion object {
        const val EXPECTED_XTE_FOR_VECTOR = "XT1VzXW2nonCtPfMUnVrsLDpwRRzi11rCW8pHe7dLGLufpeDiBgpM4i69pAvp51isz9esndRTtJyBGW9YSYf35st1Tq1Jx9UU"
    }
}
