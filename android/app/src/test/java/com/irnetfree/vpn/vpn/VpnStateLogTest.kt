package com.irnetfree.vpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The log every thread writes to (VpnState.addLog): the worker, the connect
 * threads, the cores' output readers, the self-check, the network watcher.
 * Each line carries the time of day in front ("14:32:07 …").
 */
class VpnStateLogTest {

    /** A line without its "HH:mm:ss " stamp. */
    private fun bare(s: String): String = s.substring(9)

    @Test fun eachLineCarriesTheTimeOfDay() {
        VpnState.clearLog()
        VpnState.addLog("hello")
        val line = VpnState.log.value.single()
        assertTrue(line, Regex("""^\d\d:\d\d:\d\d hello$""").matches(line))
        VpnState.clearLog()
    }

    @Test fun linesWrittenFromManyThreadsAtOnceAreAllKept() {
        // A read-then-write lost one of two lines written at the same moment.
        VpnState.clearLog()
        val threads = 8
        val each = 30
        val go = CountDownLatch(1)
        val writers = (0 until threads).map { t: Int ->
            Thread { go.await(2, TimeUnit.SECONDS); for (i in 0 until each) VpnState.addLog("t$t-$i") }
        }
        writers.forEach { w: Thread -> w.start() }
        go.countDown()
        writers.forEach { w: Thread -> w.join(5_000) }
        val log = VpnState.log.value.map { s: String -> bare(s) }
        assertEquals(threads * each, log.size)
        assertEquals(threads * each, log.toSet().size)
        // and each thread's lines in the order it wrote them
        for (t in 0 until threads)
            assertEquals((0 until each).map { i: Int -> "t$t-$i" }, log.filter { s: String -> s.startsWith("t$t-") })
        VpnState.clearLog()
    }

    @Test fun theLogKeepsTheLast300Lines() {
        VpnState.clearLog()
        for (i in 1..350) VpnState.addLog("line $i")
        val log = VpnState.log.value.map { s: String -> bare(s) }
        assertEquals(300, log.size)
        assertEquals("line 51", log.first())
        assertEquals("line 350", log.last())
        VpnState.clearLog()
        assertTrue(VpnState.log.value.isEmpty())
    }
}
