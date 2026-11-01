package com.irnetfree.vpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The stall watchdog's judgement (StallWatch): which readings of hev's TUN
 * counters mean the tunnel carries, which mean it is to be asked, which mean
 * it is dead without asking, and how often a stall may rebuild it. The
 * counters come from a device; what they are judged by does not.
 */
class StallWatchTest {
    private val kb = 1024L
    private val t0 = 1_000_000L
    private val tick = StallWatch.TICK_MS

    /** A judge with its baseline taken: tx/rx at 1 MB each. */
    private fun based(): StallWatch.Judge {
        val j = StallWatch.Judge()
        assertEquals("the first reading is the baseline", StallWatch.Verdict.QUIET, j.tick(1024 * kb, 1024 * kb, t0))
        return j
    }

    /** The next tick: [inKb] more into the TUN, [outKb] more back, [n] ticks after the baseline. */
    private class Counters(var tx: Long = 1024 * 1024L, var rx: Long = 1024 * 1024L)
    private fun StallWatch.Judge.next(c: Counters, inKb: Long, outKb: Long, n: Int): StallWatch.Verdict {
        c.tx += inKb * 1024L; c.rx += outKb * 1024L
        return tick(c.tx, c.rx, t0 + n * tick)
    }

    @Test fun aPhoneNotUsingTheTunnelIsNeverAskedAbout() {
        // Under 8 KB in over a tick — the phone is not using the tunnel. Even
        // with nothing back, nothing to judge: no probe wakes the radio.
        val j = based(); val c = Counters()
        for (n in 1..20) assertEquals(StallWatch.Verdict.QUIET, j.next(c, 7, 0, n))
        assertEquals(0, j.suspect); assertEquals(0, j.dead)
    }

    @Test fun browsingAndDownloadsAreFine() {
        val j = based(); val c = Counters()
        assertEquals(StallWatch.Verdict.FINE, j.next(c, 50, 500, 1))
        assertEquals("exactly a quarter back is enough", StallWatch.Verdict.FINE, j.next(c, 100, 25, 2))
        // the last tick's figures are kept for the log
        assertEquals(100 * kb, j.inBytes); assertEquals(25 * kb, j.outBytes)
    }

    @Test fun aDeadFarEndIsAskedAboutAfterTwoTicks() {
        // The server is gone: every SYN still gets its SYN-ACK and a reset
        // from hev's own lwip, so a little comes back — never a quarter.
        val j = based(); val c = Counters()
        assertEquals(StallWatch.Verdict.SUSPECT, j.next(c, 20, 2, 1))
        assertEquals(StallWatch.Verdict.ASK, j.next(c, 20, 2, 2))
        assertEquals("an ask ends the streak", 0, j.suspect)
        // The asks failed and the service rebuilt (its own rate limit): had it
        // not, two suspect ticks more ask again.
        assertEquals(StallWatch.Verdict.SUSPECT, j.next(c, 20, 2, 3))
        assertEquals(StallWatch.Verdict.ASK, j.next(c, 20, 2, 4))
    }

    @Test fun aLongUploadIsAskedAboutOnceAMinuteAtMost() {
        // Uploading: tx far above rx (ACKs are a few per cent) — suspect every
        // tick, but the tunnel answered the ask, so no ask for a minute.
        val j = based(); val c = Counters()
        assertEquals(StallWatch.Verdict.SUSPECT, j.next(c, 1000, 20, 1))
        assertEquals(StallWatch.Verdict.ASK, j.next(c, 1000, 20, 2))
        j.answered(t0 + 2 * tick + 1_000L)
        // 45 s, 60 s: within the minute — suspect, never ASK
        assertEquals(StallWatch.Verdict.SUSPECT, j.next(c, 1000, 20, 3))
        assertEquals(StallWatch.Verdict.SUSPECT, j.next(c, 1000, 20, 4))
        assertEquals(StallWatch.Verdict.SUSPECT, j.next(c, 1000, 20, 5))
        // 90 s after the answer: asked again
        assertEquals(StallWatch.Verdict.ASK, j.next(c, 1000, 20, 8))
    }

    @Test fun nothingBackForThreeTicksIsDeadWithoutAsking() {
        // hev stopped writing to the TUN: data goes in, not a byte comes out.
        // TCP cannot run 45 s like that; a probe through the SOCKS port would
        // still answer (it never crosses the TUN), so asking proves nothing.
        val j = based(); val c = Counters()
        assertEquals(StallWatch.Verdict.SUSPECT, j.next(c, 20, 0, 1))
        assertEquals("two ticks: asked as any suspect", StallWatch.Verdict.ASK, j.next(c, 20, 0, 2))
        j.answered(t0 + 2 * tick + 500L)           // the core answered — hev is the dead part
        assertEquals(StallWatch.Verdict.DEAD, j.next(c, 20, 0, 3))
        assertEquals("the dead streak starts over after a rebuild was asked for", 0, j.dead)
        assertEquals(StallWatch.Verdict.SUSPECT, j.next(c, 20, 0, 4))
    }

    @Test fun aByteBackEndsTheDeadStreakButNotTheSuspicion() {
        val j = based(); val c = Counters()
        assertEquals(StallWatch.Verdict.SUSPECT, j.next(c, 20, 0, 1))
        assertEquals(1, j.dead)
        assertEquals(StallWatch.Verdict.ASK, j.next(c, 20, 1, 2))
        assertEquals("something came back: not dead", 0, j.dead)
    }

    @Test fun aQuietOrHealthyTickEndsTheStreak() {
        val j = based(); val c = Counters()
        assertEquals(StallWatch.Verdict.SUSPECT, j.next(c, 20, 2, 1))
        assertEquals(StallWatch.Verdict.QUIET, j.next(c, 1, 0, 2))
        assertEquals("one suspect tick again, not two", StallWatch.Verdict.SUSPECT, j.next(c, 20, 2, 3))
        assertEquals(StallWatch.Verdict.FINE, j.next(c, 20, 200, 4))
        assertEquals(StallWatch.Verdict.SUSPECT, j.next(c, 20, 2, 5))
        assertEquals(1, j.suspect)
    }

    @Test fun countersThatWentBackwardsAreANewBaseline() {
        // hev restarted under the session (its counters start at zero again):
        // the first reading after is a baseline, not 1 MB of nothing back.
        val j = based()
        assertEquals(StallWatch.Verdict.QUIET, j.tick(500L, 500L, t0 + tick))
        assertEquals(0, j.suspect)
        assertEquals("judged from the new baseline", StallWatch.Verdict.FINE, j.tick(500L + 20 * kb, 500L + 200 * kb, t0 + 2 * tick))
    }

    @Test fun aMissingReadingIsQuietAndKeepsTheBaseline() {
        val j = based(); val c = Counters()
        assertEquals(StallWatch.Verdict.QUIET, j.tick(-1L, -1L, t0 + tick))
        // the next real reading is judged against the baseline before the gap
        assertEquals(StallWatch.Verdict.SUSPECT, j.next(c, 20, 2, 2))
    }

    @Test fun stallRebuildsWaitLongerEachTime() {
        val at = 5_000_000L
        assertEquals("never rebuilt", 0L, StallWatch.rebuildWait(0L, 0, at))
        assertEquals("the first: the network watcher's minute", 30_000L, StallWatch.rebuildWait(at, 0, at + 30_000L))
        assertEquals(0L, StallWatch.rebuildWait(at, 0, at + 60_000L))
        assertEquals("the second waits two minutes", 60_000L, StallWatch.rebuildWait(at, 1, at + 60_000L))
        assertEquals("the third four", 180_000L, StallWatch.rebuildWait(at, 2, at + 60_000L))
        assertEquals("the fourth eight", 420_000L, StallWatch.rebuildWait(at, 3, at + 60_000L))
        assertEquals("then ten at most", 540_000L, StallWatch.rebuildWait(at, 4, at + 60_000L))
        assertEquals(540_000L, StallWatch.rebuildWait(at, 9, at + 60_000L))
        assertEquals("a time from before this boot", 0L, StallWatch.rebuildWait(at, 3, at - 1L))
        assertTrue(StallWatch.REBUILD_MAX_MS >= NetWatch.REBUILD_EVERY_MS)
    }

    @Test fun sizesForTheLog() {
        assertEquals("512 B", StallWatch.size(512L))
        assertEquals("20 KB", StallWatch.size(20 * kb))
        assertEquals("3.4 MB", StallWatch.size(3 * 1024 * kb + 410 * kb))
    }
}
