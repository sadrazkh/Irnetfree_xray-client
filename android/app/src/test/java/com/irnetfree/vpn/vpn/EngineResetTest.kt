package com.irnetfree.vpn.vpn

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The way out of a process whose tunnel engine will not let go (EngineReset):
 * a native call that never returns is waited for only so long, the process is
 * marked — and unmarked when the call returns after all — and the rules for
 * when it restarts itself. The natives need a device; the rules do not.
 */
class EngineResetTest {
    @After fun forget() { EngineReset.clear() }

    @Test fun aCallThatReturnsIsWaitedForAndMarksNothing() {
        assertTrue(EngineReset.bounded("a quick stop", 2000) { Thread.sleep(50) })
        assertNull(EngineReset.stuck)
        // one that throws returned all the same: the process is not stuck for it
        assertTrue(EngineReset.bounded("a stop that throws", 2000) { throw IllegalStateException("boom") })
        assertNull(EngineReset.stuck)
    }

    @Test fun aCallThatNeverReturnsMarksTheProcessStuckAndIsLeftBehind() {
        val release = CountDownLatch(1)
        val t0 = System.currentTimeMillis()
        assertFalse(EngineReset.bounded("the tunnel library's (hev) stop", 1000) { release.await(20, TimeUnit.SECONDS) })
        val took = System.currentTimeMillis() - t0
        assertTrue("waited about the timeout, not forever: $took ms", took in 900L..8000L)
        assertEquals("the tunnel library's (hev) stop did not return within 1 s", EngineReset.stuck)
        // the first reason is the one kept
        EngineReset.markStuck("something later")
        assertEquals("the tunnel library's (hev) stop did not return within 1 s", EngineReset.stuck)
        release.countDown()
    }

    @Test fun aCallThatReturnsLateClearsItsOwnMarkAndHasItsLateHandRun() {
        // a stop that takes 10.1 s where 10 are waited for: stuck for a moment, not for life
        val lateRan = AtomicBoolean(false)
        EngineReset.said = true
        assertFalse(EngineReset.bounded("the Xray core's stop", 200, onLate = { lateRan.set(true) }) { Thread.sleep(700) })
        assertEquals("the Xray core's stop did not return within 0 s", EngineReset.stuck)
        assertTrue("a connect waits a moment for exactly this", EngineReset.awaitClear(3000))
        assertNull(EngineReset.stuck)
        assertTrue("the orphan is stopped by the late hand", lateRan.get())
        assertFalse("nothing left to say again", EngineReset.said)
    }

    @Test fun aCallThatNeverReturnsKeepsItsMarkThroughTheWait() {
        val release = CountDownLatch(1)
        assertFalse(EngineReset.bounded("the tunnel library's (hev) stop", 100) { release.await(20, TimeUnit.SECONDS) })
        assertFalse(EngineReset.awaitClear(400))
        assertEquals("the tunnel library's (hev) stop did not return within 0 s", EngineReset.stuck)
        release.countDown()
    }

    @Test fun aWedgedMarkStaysWhenALateCallClearsItsOwn() {
        EngineReset.markStuck("the tunnel's worker has not finished its \"connect\" command in 130 s")
        assertFalse(EngineReset.bounded("the Xray core's stop", 100) { Thread.sleep(400) })
        assertEquals("the first remaining reason", "the tunnel's worker has not finished its \"connect\" command in 130 s", EngineReset.stuck)
        assertFalse(EngineReset.awaitClear(1500))
        assertEquals("the wedge is for the process", "the tunnel's worker has not finished its \"connect\" command in 130 s", EngineReset.stuck)
    }

    @Test fun aQuietCallMarksNothingEvenWhenItNeverReturns() {
        // a throwaway test core's controller is not the tunnel's
        val release = CountDownLatch(1)
        assertFalse(EngineReset.bounded("a test core's stop", 100, quiet = true) { release.await(20, TimeUnit.SECONDS) })
        assertNull(EngineReset.stuck)
        assertTrue(EngineReset.awaitClear(10))
        release.countDown()
    }

    @Test fun onlyOneRestartPerProcess() {
        assertTrue(EngineReset.beginRestart())
        assertFalse(EngineReset.beginRestart())
    }

    @Test fun theProcessRestartsItselfOnlyWithEveryScreenAwayAndNothingUp() {
        assertTrue(EngineReset.mayRestartInBackground(stuck = true, serviceAlive = false, state = ConnState.DISCONNECTED, uiAway = true))
        assertTrue(EngineReset.mayRestartInBackground(stuck = true, serviceAlive = false, state = ConnState.ERROR, uiAway = true))
        assertFalse("nothing is wrong", EngineReset.mayRestartInBackground(false, false, ConnState.DISCONNECTED, true))
        assertFalse("a screen of ours shows (or MainActivity is only stopped under the QR scanner)", EngineReset.mayRestartInBackground(true, false, ConnState.DISCONNECTED, false))
        assertFalse("the service lives", EngineReset.mayRestartInBackground(true, true, ConnState.DISCONNECTED, true))
        assertFalse("a connect is on its way", EngineReset.mayRestartInBackground(true, false, ConnState.CONNECTING, true))
        assertFalse(EngineReset.mayRestartInBackground(true, false, ConnState.CONNECTED, true))
    }

    @Test fun aRefusedConnectSaysItOnceThenRestarts() {
        assertEquals(EngineReset.Refused.SAY, EngineReset.onRefused(unattended = false, saidBefore = false))
        assertEquals(EngineReset.Refused.RESTART, EngineReset.onRefused(unattended = false, saidBefore = true))
        assertEquals("nobody to tell", EngineReset.Refused.RESTART, EngineReset.onRefused(unattended = true, saidBefore = false))
    }

    @Test fun aWorkerCommandIsWedgedOnlyPastTheLimit() {
        assertNull("idle", EngineReset.wedged(null, 0L, 100_000L))
        assertNull("a connect in its tenth second", EngineReset.wedged("connect", 1_000L, 11_000L))
        assertNull(EngineReset.wedged("disconnect", 1_000L, 1_000L + EngineReset.WEDGE_MS - 1))
        assertEquals("the tunnel's worker has not finished its \"disconnect\" command in 120 s", EngineReset.wedged("disconnect", 1_000L, 121_000L))
        assertEquals("the tunnel's worker has not finished its \"connect\" command in 73 s", EngineReset.wedged("connect", 1_000L, 74_000L, limitMs = 60_000L))
        // the bounded waits add up under the limit: hev 8 + core stop 10 + core start 30, plus the asset copy and a subprocess probe
        assertTrue(EngineReset.HEV_STOP_MS + EngineReset.CORE_STOP_MS + EngineReset.CORE_START_MS + 30_000L < EngineReset.WEDGE_MS)
    }

    @Test fun theRestartFlagIsTakenOnlyFresh() {
        val now = 1_700_000_000_000L
        assertEquals(EngineReset.RECONNECT to "hev stop", EngineReset.restartFlag(EngineReset.RECONNECT, "hev stop", now - 2_000L, now))
        assertEquals(EngineReset.STAY to "", EngineReset.restartFlag(EngineReset.STAY, null, now, now))
        // Android's restart delay grows fourfold per quick death: minutes later is still this kill's
        assertEquals(EngineReset.STAY to "x", EngineReset.restartFlag(EngineReset.STAY, "x", now - 5 * 60_000L, now))
        assertNull("none", EngineReset.restartFlag(null, null, now, now))
        assertNull("not a flag", EngineReset.restartFlag("later", "x", now, now))
        assertNull("stale: a crash's sticky restart weeks on must connect again", EngineReset.restartFlag(EngineReset.STAY, "x", now - 2 * EngineReset.FLAG_FRESH_MS, now))
        assertNull("a clock set back", EngineReset.restartFlag(EngineReset.STAY, "x", now + 2 * EngineReset.FLAG_FRESH_MS, now))
        assertNull("never written", EngineReset.restartFlag(EngineReset.STAY, "x", 0L, now))
    }

    @Test fun selfReconnectsHaveACeilingInTheWindow() {
        val now = 1_700_000_000_000L
        val min = 60_000L
        assertTrue("the first", EngineReset.mayReconnect(emptyList(), now))
        val one = EngineReset.reconnectsNoted(emptyList(), now - 3 * min)
        assertEquals(listOf(now - 3 * min), one)
        assertTrue("the second", EngineReset.mayReconnect(one, now - 1 * min))
        val two = EngineReset.reconnectsNoted(one, now - 1 * min)
        assertFalse("the third within ten minutes stays off", EngineReset.mayReconnect(two, now))
        // the window moves on: the first one is past it
        assertTrue(EngineReset.mayReconnect(two, now - 3 * min + EngineReset.RECONNECT_WINDOW_MS))
        assertEquals("what is stored is only what still counts", listOf(now - 1 * min, now + 8 * min), EngineReset.reconnectsNoted(two, now + 8 * min))
        // a clock set back: a future entry does not count against the user
        assertTrue(EngineReset.mayReconnect(listOf(now + 60 * min, now + 61 * min), now))
        // the prefs form
        assertEquals(two, EngineReset.parseTimes(EngineReset.joinTimes(two)))
        assertEquals(emptyList<Long>(), EngineReset.parseTimes(null))
        assertEquals(listOf(5L), EngineReset.parseTimes("x,5, ,"))
    }
}
