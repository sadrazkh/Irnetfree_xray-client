package com.irnetfree.vpn.vpn

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The way out of a process whose tunnel engine will not let go (EngineReset):
 * a native call that never returns is waited for only so long, the process is
 * marked, and the rules for when it restarts itself. The natives need a
 * device; the rules do not.
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

    @Test fun onlyOneRestartPerProcess() {
        assertTrue(EngineReset.beginRestart())
        assertFalse(EngineReset.beginRestart())
    }

    @Test fun theProcessRestartsItselfOnlyUnseenWithNothingUp() {
        assertTrue(EngineReset.mayRestartInBackground(stuck = true, serviceAlive = false, state = ConnState.DISCONNECTED, uiVisible = false))
        assertTrue(EngineReset.mayRestartInBackground(stuck = true, serviceAlive = false, state = ConnState.ERROR, uiVisible = false))
        assertFalse("nothing is wrong", EngineReset.mayRestartInBackground(false, false, ConnState.DISCONNECTED, false))
        assertFalse("the screen is on it", EngineReset.mayRestartInBackground(true, false, ConnState.DISCONNECTED, true))
        assertFalse("the service lives", EngineReset.mayRestartInBackground(true, true, ConnState.DISCONNECTED, false))
        assertFalse("a connect is on its way", EngineReset.mayRestartInBackground(true, false, ConnState.CONNECTING, false))
        assertFalse(EngineReset.mayRestartInBackground(true, false, ConnState.CONNECTED, false))
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
    }

    @Test fun theRestartFlagIsTakenOnlyFresh() {
        val now = 1_700_000_000_000L
        assertEquals(EngineReset.RECONNECT to "hev stop", EngineReset.restartFlag(EngineReset.RECONNECT, "hev stop", now - 2_000L, now))
        assertEquals(EngineReset.STAY to "", EngineReset.restartFlag(EngineReset.STAY, null, now, now))
        assertNull("none", EngineReset.restartFlag(null, null, now, now))
        assertNull("not a flag", EngineReset.restartFlag("later", "x", now, now))
        assertNull("stale: a crash's sticky restart weeks on must connect again", EngineReset.restartFlag(EngineReset.STAY, "x", now - 2 * EngineReset.FLAG_FRESH_MS, now))
        assertNull("a clock set back", EngineReset.restartFlag(EngineReset.STAY, "x", now + 2 * EngineReset.FLAG_FRESH_MS, now))
        assertNull("never written", EngineReset.restartFlag(EngineReset.STAY, "x", 0L, now))
    }
}
