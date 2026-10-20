package com.irnetfree.vpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The network watcher's judgement (NetWatch): which of Android's
 * default-network callbacks are a change worth asking the tunnel about, what a
 * change that has settled comes to, and how often the tunnel may be rebuilt.
 * The callbacks themselves need a device; what they are judged by does not.
 */
class NetWatchTest {
    private val wifi = setOf(NetWatch.WIFI)
    private val mobile = setOf(NetWatch.CELLULAR)

    @Test fun theNetworkTheWatchBeganOnIsNoChange() {
        // Registering delivers the current default at once: onAvailable, then
        // its capabilities — neither is a move.
        val t = NetWatch.Tracker()
        t.begin("100")
        assertFalse(t.available("100"))
        assertFalse("its transport named for the first time is learnt, not a move", t.capabilities("100", wifi))
        assertEquals(NetWatch.Settled.NOTHING, t.settle())
    }

    @Test fun withoutABaselineTheFirstNetworkNamedIsIt() {
        val t = NetWatch.Tracker()
        assertFalse(t.available("100"))
        assertFalse(t.capabilities("100", wifi))
        assertEquals(NetWatch.Settled.NOTHING, t.settle())
        assertTrue("the next one is a change", t.available("101"))
    }

    @Test fun wifiToMobileDataIsAskedAboutOnceItSettles() {
        val t = NetWatch.Tracker(); t.begin("100"); t.capabilities("100", wifi)
        assertTrue(t.available("101"))
        assertEquals("not told yet", emptySet<String>(), t.transports)
        assertFalse("the new network's transport, learnt", t.capabilities("101", mobile))
        assertEquals("mobile data", NetWatch.label(t.transports))
        assertEquals(NetWatch.Settled.ASK, t.settle())
        // judged: it is asked once, and the same network again is nothing more
        assertEquals(NetWatch.Settled.NOTHING, t.settle())
        assertFalse(t.available("101"))
    }

    @Test fun aNetworkThatGoesAndComesBackIsStillAskedAbout() {
        // Wi-Fi drops and comes back: the end looks like the start, but every
        // socket the core held died with the link (netWatcher.js tick).
        val t = NetWatch.Tracker(); t.begin("100")
        assertTrue(t.lost("100"))
        assertNull(t.id)
        assertTrue(t.available("100"))
        assertEquals(NetWatch.Settled.ASK, t.settle())
    }

    @Test fun noNetworkHoldsTheQuestionUntilOneComes() {
        // Nothing to rebuild onto: the tunnel is not asked (it cannot answer)
        // and the move is not forgotten either.
        val t = NetWatch.Tracker(); t.begin("100")
        assertTrue(t.lost("100"))
        assertEquals(NetWatch.Settled.NO_NETWORK, t.settle())
        assertTrue("still owed", t.moved)
        assertEquals(NetWatch.Settled.NO_NETWORK, t.settle())
        assertTrue(t.available("102"))
        assertEquals(NetWatch.Settled.ASK, t.settle())
        assertFalse(t.moved)
    }

    @Test fun aWatchBegunWithNoNetworkCountsTheFirstOne() {
        // The tunnel came up in a gap: the network that comes after is a change.
        val t = NetWatch.Tracker(); t.begin(null)
        assertTrue(t.available("100"))
        assertEquals(NetWatch.Settled.ASK, t.settle())
    }

    @Test fun onlyATransportChangeOfTheDefaultNetworkCounts() {
        val t = NetWatch.Tracker(); t.begin("100")
        assertFalse(t.capabilities("100", wifi))
        assertFalse("signal strength, validation: the same transports", t.capabilities("100", wifi))
        assertFalse("not the default network", t.capabilities("200", mobile))
        assertFalse("not the default network", t.lost("200"))
        assertEquals(NetWatch.Settled.NOTHING, t.settle())
        assertTrue(t.capabilities("100", setOf(NetWatch.WIFI, NetWatch.CELLULAR)))
        assertEquals(NetWatch.Settled.ASK, t.settle())
    }

    @Test fun atMostOneRebuildAMinute() {
        assertEquals("never rebuilt", 0L, NetWatch.rebuildWait(0L, 5_000L))
        val at = 1_000_000L
        assertEquals(50_000L, NetWatch.rebuildWait(at, at + 10_000L))
        assertEquals(1L, NetWatch.rebuildWait(at, at + 59_999L))
        assertEquals(0L, NetWatch.rebuildWait(at, at + 60_000L))
        assertEquals("a time from before this boot", 0L, NetWatch.rebuildWait(at, at - 1L))
    }

    @Test fun theNetworkIsNamedForTheLog() {
        assertEquals("Wi-Fi", NetWatch.label(wifi))
        assertEquals("mobile data", NetWatch.label(mobile))
        assertEquals("Ethernet", NetWatch.label(setOf(NetWatch.ETHERNET)))
        assertEquals("the new network", NetWatch.label(emptySet()))
        assertEquals("a network", NetWatch.label(setOf(NetWatch.OTHER)))
    }
}
