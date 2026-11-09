package com.irnetfree.vpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * The log on disk (VpnState.attachLog): a run the system killed leaves its
 * lines in the file, and the next run opens the screen's log with them.
 */
class VpnStateLogFileTest {

    @Test fun theRunBeforeOpensTheLogAndNewLinesReachTheFile() {
        val dir: File = Files.createTempDirectory("irnf-log").toFile()
        // the run before: killed with these as its last lines
        File(dir, VpnState.LOG_FILE).writeText((1..200).joinToString(separator = "\n", postfix = "\n") { i: Int -> "10:00:00 old $i" })
        VpnState.clearLog()
        VpnState.attachLog(dir)

        val shown = VpnState.log.value
        assertTrue(shown.first().contains("before the app last stopped"))
        assertEquals("10:00:00 old 51", shown[1])                       // its last 150 lines
        assertEquals("10:00:00 old 200", shown[150])
        assertTrue(shown[151].contains("this run"))
        assertTrue("kept as the previous run's file", File(dir, VpnState.PREV_FILE).exists())

        VpnState.addLog("fresh line")
        val cur = File(dir, VpnState.LOG_FILE)
        // what the engine restart waits on before it ends the process: every line queued is in the file
        assertTrue("written out within the wait", VpnState.awaitLogFlushed(3000))
        assertTrue("the writer thread appended it", cur.readText().contains(" fresh line"))
        VpnState.clearLog()
    }

    @Test fun theTailIsBoundedAndStartsAtAWholeLine() {
        val f: File = File.createTempFile("irnf-tail", ".txt")
        f.writeText((1..1000).joinToString(separator = "\n", postfix = "\n") { i: Int -> "line $i" })
        val tail = String(VpnState.tailOf(f, 100), Charsets.UTF_8)
        assertTrue(tail, tail.length <= 100)
        assertTrue(tail, tail.startsWith("line "))
        assertTrue(tail, tail.endsWith("line 1000\n"))
        // shorter than the limit: all of it
        f.writeText("a\nb\n")
        assertEquals("a\nb\n", String(VpnState.tailOf(f, 100), Charsets.UTF_8))
        f.delete()
    }
}
