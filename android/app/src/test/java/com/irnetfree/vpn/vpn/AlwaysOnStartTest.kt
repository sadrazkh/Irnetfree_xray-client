package com.irnetfree.vpn.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * An always-on start that finds the service already up — or on its way up —
 * for the selection it would connect leaves it alone (AlwaysOnStart);
 * everything else is connected exactly as before.
 */
class AlwaysOnStartTest {

    @Test fun aTunnelUpOrComingUpForTheStoredSelectionIsLeftAlone() {
        assertTrue(AlwaysOnStart.leaveAlone(ConnState.CONNECTED, tunnelUp = true, askedIsLatest = true, asked = "srv-1", stored = "srv-1"))
        // still in prepare(): no tunnel yet — overtaking it only started it over
        assertTrue(AlwaysOnStart.leaveAlone(ConnState.CONNECTING, tunnelUp = false, askedIsLatest = true, asked = "chain:c1", stored = "chain:c1"))
    }

    @Test fun anythingElseIsConnectedAsBefore() {
        // another selection picked since the connect: always-on connects that one
        assertFalse(AlwaysOnStart.leaveAlone(ConnState.CONNECTED, tunnelUp = true, askedIsLatest = true, asked = "srv-1", stored = "srv-2"))
        // a disconnect (or another move) came after it
        assertFalse(AlwaysOnStart.leaveAlone(ConnState.CONNECTED, tunnelUp = true, askedIsLatest = false, asked = "srv-1", stored = "srv-1"))
        // "Connected" on screen, but no tunnel under it
        assertFalse(AlwaysOnStart.leaveAlone(ConnState.CONNECTED, tunnelUp = false, askedIsLatest = true, asked = "srv-1", stored = "srv-1"))
        // it failed, or nothing is up
        assertFalse(AlwaysOnStart.leaveAlone(ConnState.ERROR, tunnelUp = false, askedIsLatest = true, asked = "srv-1", stored = "srv-1"))
        assertFalse(AlwaysOnStart.leaveAlone(ConnState.DISCONNECTED, tunnelUp = false, askedIsLatest = true, asked = "srv-1", stored = "srv-1"))
        // nothing known to compare
        assertFalse(AlwaysOnStart.leaveAlone(ConnState.CONNECTED, tunnelUp = true, askedIsLatest = true, asked = null, stored = "srv-1"))
        assertFalse(AlwaysOnStart.leaveAlone(ConnState.CONNECTED, tunnelUp = true, askedIsLatest = true, asked = "srv-1", stored = null))
        assertFalse(AlwaysOnStart.leaveAlone(ConnState.CONNECTED, tunnelUp = true, askedIsLatest = true, asked = "", stored = ""))
    }
}
