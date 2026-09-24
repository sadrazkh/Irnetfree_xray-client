package com.irnetfree.vpn.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The rule behind "⚡ connect to the fastest". Every one of these is a shape the
 * owner's own subscription produces: thirteen CDN entries where several answer a
 * handshake in under a tenth of a second and only some of them carry anything.
 */
class FastestTest {

    private fun m(id: String, tcp: Long? = null, real: Long? = null) = Fastest.Measured(id, tcp, real)

    @Test fun aServerThatCarriedTrafficBeatsOneThatOnlyShookHands() {
        // This is the whole point: "a" answers a handshake seven times quicker
        // and carries nothing, which is the server auto-connect must not hand you.
        val best = Fastest.pick(listOf(m("a", tcp = 40), m("b", tcp = 280, real = 620)))
        assertEquals("b", best?.id)
    }

    @Test fun amongServersThatCarriedTrafficTheQuickestRoundTripWins() {
        val best = Fastest.pick(listOf(m("a", tcp = 40, real = 900), m("b", tcp = 280, real = 310), m("c", tcp = 90, real = 480)))
        assertEquals("b", best?.id)
    }

    @Test fun whenNothingCarriedTrafficTheQuickestHandshakeWins() {
        val best = Fastest.pick(listOf(m("a", tcp = 310), m("b", tcp = 88), m("c", tcp = 140)))
        assertEquals("b", best?.id)
    }

    @Test fun aServerThatNeverAnsweredIsNotACandidate() {
        // -1 is what Diagnostics.tcpPing/httpLatency return for "no answer", and
        // null is "never measured" — neither may be ranked as though it were 0.
        assertNull(Fastest.score(m("dead", tcp = -1)))
        assertNull(Fastest.score(m("untested")))
        assertNull(Fastest.score(m("dead", tcp = -1, real = -1)))
        val best = Fastest.pick(listOf(m("dead", tcp = -1), m("untested"), m("alive", tcp = 999)))
        assertEquals("alive", best?.id)
    }

    @Test fun nothingAnsweredMeansNoChoiceAtAll() {
        assertNull(Fastest.pick(listOf(m("a", tcp = -1), m("b"))))
        assertNull(Fastest.pick(emptyList()))
    }

    @Test fun aTieKeepsTheOneThatWasListedFirst() {
        // The list is in the user's own order, so an arbitrary tiebreak would make
        // two taps in a row connect to two different servers for no visible reason.
        assertEquals("a", Fastest.pick(listOf(m("a", tcp = 100), m("b", tcp = 100)))?.id)
        assertEquals("a", Fastest.pick(listOf(m("a", tcp = 900, real = 200), m("b", tcp = 30, real = 200)))?.id)
    }

    @Test fun onlyTheQuickestFewAreWorthAThrowawayCore() {
        val all = listOf(m("a", tcp = 300), m("b", tcp = 40), m("c", tcp = -1), m("d", tcp = 120), m("e", tcp = 90))
        // Three of them, in the order they answered, and never the one that did not.
        assertEquals(listOf("b", "e", "d"), Fastest.shortlist(all).map { it.id })
        assertEquals(listOf("b"), Fastest.shortlist(all, 1).map { it.id })
        assertEquals(emptyList<String>(), Fastest.shortlist(listOf(m("c", tcp = -1), m("f"))).map { it.id })
    }

    @Test fun measuringOnlyTheShortlistStillFindsTheRightWinner() {
        // What the UI actually hands pick(): three entries with a real round trip
        // and the rest with a handshake only. The slow-handshake server that was
        // never really tried must not beat a shortlisted one that carried traffic.
        val measured = listOf(
            m("a", tcp = 40, real = 700), m("b", tcp = 55, real = -1), m("c", tcp = 70, real = 350),
            m("d", tcp = 210), m("e", tcp = 260)
        )
        assertEquals("c", Fastest.pick(measured)?.id)
        // ...and when none of the shortlist carried anything, a server that was
        // never really tried is a better answer than one that was and failed.
        // (This used to pin "a": the best handshake won even though its real
        // round trip had just failed, so ⚡ connected to a server it had
        // measured as dead. The audit of 2026-09-24 changed the pin on purpose.)
        val noneCarried = listOf(m("a", tcp = 40, real = -1), m("b", tcp = 55, real = -1), m("d", tcp = 210))
        assertEquals("d", Fastest.pick(noneCarried)?.id)
    }

    @Test fun aMeasuredFailureDisqualifies() {
        // The handshake says the port is open; the round trip says it carries
        // nothing. The second measurement is the one that is true.
        assertNull(Fastest.score(m("a", tcp = 40, real = -1)))
        assertNull(Fastest.pick(listOf(m("a", tcp = 40, real = -1), m("b", tcp = 55, real = -1))))
    }
}
