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
        val deadline = System.currentTimeMillis() + 3000
        while (System.currentTimeMillis() < deadline && !(cur.exists() && cur.readText().contains("fresh line"))) Thread.sleep(20)
        assertTrue("the writer thread appended it", cur.readText().contains(" fresh line"))
        VpnState.clearLog()
    }
}
