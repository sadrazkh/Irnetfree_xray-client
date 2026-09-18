package com.irnetfree.vpn.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The names in these tests are the owner's own subscription, verbatim — that is
 * where the list's flags come from, since nothing in a share link carries a
 * country.
 */
class ServerLabelTest {

    @Test fun theFlagComesOutOfTheNameAndTakesItsSeparatorWithIt() {
        assertEquals("🇮🇹" to "CDN1", ServerLabel.split("🇮🇹-CDN1"))
        assertEquals("🇳🇱" to "CDN1", ServerLabel.split("🇳🇱-CDN1"))
        assertEquals("🇩🇪" to "TCP 12 Sadra|📊1.15TB", ServerLabel.split("TCP 12 🇩🇪-Sadra|📊1.15TB"))
        assertEquals("🇮🇹" to "Irancell", ServerLabel.split("Irancell 🇮🇹"))
    }

    @Test fun aNameWithNoFlagIsLeftExactlyAsItIs() {
        assertEquals(null to "cobra.tes.ca", ServerLabel.split("cobra.tes.ca"))
        assertEquals(null to "IR-Tehran-1", ServerLabel.split("IR-Tehran-1"))
        assertNull(ServerLabel.flagIn("no flag here"))
        // A single regional indicator is a letter, not a flag.
        assertNull(ServerLabel.flagIn("🇮 alone"))
    }

    @Test fun onlyTheSeparatorsTouchingTheFlagAreRemoved() {
        // The hyphens that are part of the name itself survive.
        assertEquals("🇩🇪" to "de-fra-01", ServerLabel.split("🇩🇪 de-fra-01"))
        assertEquals("🇬🇧" to "UK · London", ServerLabel.split("🇬🇧-UK · London"))
    }

    @Test fun aNameThatIsNothingButAFlagKeepsSomethingToShow() {
        // Stripping it would leave an empty row; the original stands.
        assertEquals("🇮🇹" to "🇮🇹", ServerLabel.split("🇮🇹"))
    }

    @Test fun theFirstFlagWins() {
        assertEquals("🇩🇪", ServerLabel.flagIn("🇩🇪 via 🇳🇱"))
    }
}
