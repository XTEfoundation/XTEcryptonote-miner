package com.xtefoundation.cryptonoteminer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DefaultsTest {
    @Test
    fun soloSeednodeOverHttpsIsTheDefault() {
        assertEquals(MiningMode.SEEDNODE, MinerPrefs.DEFAULT_MODE)
        assertEquals(MiningMode.SEEDNODE, MiningMode.fromPrefs(null))
        assertEquals(MiningMode.SEEDNODE, MiningMode.fromPrefs("garbage"))
        assertEquals(MiningMode.SEEDNODE, MiningMode.fromPrefs("seednode"))
        assertEquals(MiningMode.POOL, MiningMode.fromPrefs("POOL"))
        assertEquals("main.trrxitte.com", MinerPrefs.defaultHostFor(MiningMode.SEEDNODE))
        assertEquals(443, MinerPrefs.defaultPortFor(MiningMode.SEEDNODE))
        assertTrue(MinerPrefs.defaultTlsFor(MiningMode.SEEDNODE, 443))
        assertFalse(MinerPrefs.defaultTlsFor(MiningMode.SEEDNODE, MinerPrefs.SEED_PLAIN_PORT))
    }

    @Test
    fun poolStaysTheAlternative() {
        assertEquals("main.trrxitte.com", MinerPrefs.defaultHostFor(MiningMode.POOL))
        assertEquals(3333, MinerPrefs.defaultPortFor(MiningMode.POOL))
        assertFalse(MinerPrefs.defaultTlsFor(MiningMode.POOL, 3333))
        assertTrue(MinerPrefs.defaultTlsFor(MiningMode.POOL, 9999))
    }
}
