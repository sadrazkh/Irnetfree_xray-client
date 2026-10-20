package com.irnetfree.vpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The Quick Settings tile (ConnectTile): what it shows for each state, and what a tap does. */
class ConnectTileTest {
    @Test fun litWhileConnectedOrOnItsWay() {
        assertEquals(TileLook.Look(true, "🇩🇪 Berlin"), TileLook.of(ConnState.CONNECTED, "🇩🇪 Berlin"))
        assertEquals(TileLook.Look(true, "Connected"), TileLook.of(ConnState.CONNECTED, ""))
        assertEquals(TileLook.Look(true, "Connecting…"), TileLook.of(ConnState.CONNECTING, "🇩🇪 Berlin"))
        assertEquals(TileLook.Look(false, "Off"), TileLook.of(ConnState.DISCONNECTED, "🇩🇪 Berlin"))
        assertEquals(TileLook.Look(false, "Not connected"), TileLook.of(ConnState.ERROR, ""))
    }

    @Test fun aTapDisconnectsWhatIsLitAndConnectsWhatIsNot() {
        // connecting: a tap cancels, as the app's ring does
        assertTrue(TileLook.tapDisconnects(ConnState.CONNECTED))
        assertTrue(TileLook.tapDisconnects(ConnState.CONNECTING))
        assertFalse(TileLook.tapDisconnects(ConnState.DISCONNECTED))
        assertFalse(TileLook.tapDisconnects(ConnState.ERROR))
    }
}
