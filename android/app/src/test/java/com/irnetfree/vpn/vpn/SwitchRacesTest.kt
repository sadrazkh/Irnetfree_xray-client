package com.irnetfree.vpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Switching servers never mixes up the connection (XrayVpnService's class
 * comment): the rules that hold it, one race each. The service itself needs a
 * device; the generation it decides by does not.
 */
class SwitchRacesTest {

    @Test fun aConnectWhoseSelectionCannotBeBuiltStillOvertakesTheOneBeforeIt() {
        // Tap A (its prepare dials for certificate pins for seconds), then B, a
        // chain that has lost a member: B's buildPlan throws. The move used to
        // come after buildPlan, so A's prepare finished and A came up under
        // B's error. connect() moves first now.
        val g = Generation()
        val a = g.next { }
        val b = g.next { }                 // connect(B): the move, then buildPlan throws
        assertNotEquals("A's prepare stops at its check", a, g.get())
        // B's stop for what an older connect left up reaches A's tunnel…
        assertTrue(Generation.reaches(b, a))
    }

    @Test fun aStopSentLateNeverTakesDownATunnelANewerConnectBroughtUp() {
        // A is up (1). B (2) fails in prepare on its own thread and sends a
        // stop for what an older connect left up; before that stop is handled
        // C (3) connects and comes up. The stop must leave C alone: the last
        // thing asked for was C.
        val g = Generation()
        val a = g.next(); val b = g.next(); val c = g.next()
        assertTrue("had C not come, A goes", Generation.reaches(b, a))
        assertFalse("C stays", Generation.reaches(b, c))
        // A disconnect handled after the next connect's start, likewise.
        val d = g.stop(); val e = g.next()
        assertFalse(Generation.reaches(d, e))
        assertTrue(Generation.reaches(d, c))
        // nothing up: a stop has nothing to spare
        assertTrue(Generation.reaches(d, null))
        // the session's own generation: its core died for good (fail(l.gen))
        assertTrue(Generation.reaches(e, e))
    }

    @Test fun anOlderStartsConnectedNeverLandsAfterANewerConnectsConnecting() {
        // A's start holds the lock between its check and its "Connected"; B's
        // connect() waits for it and puts "Connecting…" up after. Whatever
        // the timing, the screen ends on the newer move — never A's Connected
        // over B's Connecting, the tap on B then looking ignored.
        val g = Generation()
        val a = g.next()
        val order = Collections.synchronizedList(ArrayList<String>())
        val inside = CountDownLatch(1); val release = CountDownLatch(1)
        val start = Thread { g.ifCurrent(a) { inside.countDown(); release.await(2, TimeUnit.SECONDS); order.add("A connected") } }
        start.start()
        assertTrue(inside.await(2, TimeUnit.SECONDS))
        val connect = Thread { g.next { order.add("B connecting") } }
        connect.start()
        connect.join(300)
        release.countDown()
        start.join(2000); connect.join(2000)
        assertEquals(listOf("A connected", "B connecting"), order.toList())
        // …and A's later writes are refused
        assertFalse(g.ifCurrent(a) { order.add("A late") })
        assertEquals(2, order.size)
    }

    @Test fun aStartOvertakenBetweenItsCheckAndItsConnectingShowsNothing() {
        // startTunnel checks its generation, tears the old session down, and
        // only then shows "Connecting…" — checked again there, under the lock.
        val g = Generation()
        val a = g.next()
        assertEquals(a, g.get())           // the first check passes
        g.next()                           // B tapped meanwhile
        var shown = false
        assertFalse(g.ifCurrent(a) { shown = true })
        assertFalse(shown)
    }

    @Test fun notConnectedGoesUpOnlyWhileTheDisconnectIsTheLatestMove() {
        val g = Generation()
        g.next(); g.stop()
        var off = 0
        assertTrue(g.ifStopped { off++ })
        g.next()                           // reconnect / ⚡ 0.6 s later
        assertFalse(g.ifStopped { off++ })
        assertEquals(1, off)
    }

    @Test fun aConnectAfterADisconnectCannotSlipBetweenItsCheckAndItsNotConnected() {
        val g = Generation()
        g.next(); g.stop()
        val order = Collections.synchronizedList(ArrayList<String>())
        val inside = CountDownLatch(1); val release = CountDownLatch(1)
        val teardown = Thread { g.ifStopped { inside.countDown(); release.await(2, TimeUnit.SECONDS); order.add("not connected") } }
        teardown.start()
        assertTrue(inside.await(2, TimeUnit.SECONDS))
        val connect = Thread { g.next { order.add("connecting") } }
        connect.start()
        connect.join(300)
        release.countDown()
        teardown.join(2000); connect.join(2000)
        // the connect asked for after the disconnect owns the screen at the end
        assertEquals(listOf("not connected", "connecting"), order.toList())
        assertFalse(g.stopLatest)
    }
}
