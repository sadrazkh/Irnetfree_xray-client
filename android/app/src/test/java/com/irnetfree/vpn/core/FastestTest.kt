package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
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

    /** The UI's measuring, played back: `real` says which servers carry traffic. */
    private fun walk(all: List<Fastest.Measured>, real: Map<String, Long>): Pair<List<String>, String?> {
        val tried = Fastest.walk(all) { _, m -> real[m.id] ?: -1L }
        return tried.map { it.id } to Fastest.pick(tried)?.id
    }

    @Test fun theWalkTriesTheShortlistAndStopsWhenOneCarried() {
        val all = listOf(m("a", tcp = 40), m("b", tcp = 55), m("c", tcp = 70), m("d", tcp = 90), m("e", tcp = -1))
        val (tried, best) = walk(all, mapOf("a" to 700L, "b" to -1L, "c" to 350L, "d" to 100L))
        // the three quickest handshakes, as before; "d" is never spent a core on
        assertEquals(listOf("a", "b", "c"), tried)
        assertEquals("c", best)
    }

    @Test fun whenTheShortlistAllFailsTheWalkGoesOn() {
        // The shape that connected people to a dead server: the three quickest
        // handshakes all fail the real round trip. The next in line is tried
        // until one carries, and that one — never a failed one — is the answer.
        val all = listOf(m("a", tcp = 40), m("b", tcp = 55), m("c", tcp = 70), m("d", tcp = 90), m("f", tcp = 95), m("e", tcp = 300))
        val (tried, best) = walk(all, mapOf("d" to -1L, "f" to 480L, "e" to 120L))
        assertEquals(listOf("a", "b", "c", "d", "f"), tried)
        assertEquals("f", best)
    }

    @Test fun theWalkGivesUpAfterABoundedNumberOfTries() {
        val all = (1..10).map { m("s$it", tcp = 10L * it) }
        val (tried, best) = walk(all, emptyMap())
        assertEquals(Fastest.MAX_TRIES, tried.size)
        assertEquals(listOf("s1", "s2", "s3", "s4", "s5", "s6"), tried)
        assertNull(best)
        // nothing answered a handshake: nothing is tried at all
        assertEquals(emptyList<String>(), walk(listOf(m("x", tcp = -1), m("y")), emptyMap()).first)
    }

    @Test fun aMeasuredFailureDisqualifies() {
        // The handshake says the port is open; the round trip says it carries
        // nothing. The second measurement is the one that is true.
        assertNull(Fastest.score(m("a", tcp = 40, real = -1)))
        assertNull(Fastest.pick(listOf(m("a", tcp = 40, real = -1), m("b", tcp = 55, real = -1))))
    }

    /* ---------------- UDP-only servers: a real round trip in place of a handshake ---------------- */

    private fun rec(protocol: String, outbound: JSONObject) = ServerConfig("x", "x", protocol, "x.example", 443, outbound)
    private fun masque(vararg alpn: String): JSONObject {
        val tls = JSONObject()
        if (alpn.isNotEmpty()) tls.put("alpn", JSONArray(alpn.toList()))
        return JSONObject().put("protocol", "masque").put("streamSettings", JSONObject().put("tlsSettings", tls))
    }

    @Test fun udpOnly_asTheDesktopDecidesIt() {
        // latencyTest.js udpOnly: WireGuard and Hysteria2 have no TCP port at all
        assertTrue(Fastest.udpOnly(rec("wireguard", JSONObject().put("protocol", "wireguard"))))
        // a Hysteria2 record's outbound is "hysteria" (LinkParser); the outbound's protocol wins, the record's fills in
        assertTrue(Fastest.udpOnly(rec("hysteria2", JSONObject().put("protocol", "hysteria"))))
        assertTrue(Fastest.udpOnly(rec("hysteria2", JSONObject())))
        assertFalse(Fastest.udpOnly(rec("hysteria2", JSONObject().put("protocol", "vless"))))
        // MASQUE over HTTP/3 (no ALPN, or h3 named) is QUIC; over HTTP/2 alone it is TCP like any other
        assertTrue(Fastest.udpOnly(rec("masque", masque())))
        assertTrue(Fastest.udpOnly(rec("masque", masque("h2", "h3"))))
        assertFalse(Fastest.udpOnly(rec("masque", masque("h2"))))
        for (p in listOf("vless", "vmess", "trojan", "shadowsocks", "socks", "http"))
            assertFalse(p, Fastest.udpOnly(rec(p, JSONObject().put("protocol", p))))
    }

    @Test fun udpOnlyServersAreMeasuredInOrder_boundedInNumberAndTime() {
        var clock = 0L
        val ids = (1..10).map { n: Int -> "u$n" }
        // at most UDP_MAX throwaway cores, in the order given; a failure is kept as measured
        val out = Fastest.measureUdp(ids, now = { clock }) { _: Int, id: String -> clock += 1000; if (id == "u2") -1L else 400L }
        assertEquals(ids.take(Fastest.UDP_MAX), out.map { it.id })
        assertEquals(-1L, out[1].real)
        assertTrue(out.all { it.tcp == null })
        // none is started once the time is spent
        clock = 0L
        val slow = Fastest.measureUdp(ids, max = 100, budgetMs = 5000, now = { clock }) { _: Int, _: String -> clock += 2000; 300L }
        assertEquals(listOf("u1", "u2", "u3"), slow.map { it.id })
        assertEquals(emptyList<String>(), Fastest.measureUdp(emptyList(), now = { 0L }) { _: Int, _: String -> 1L }.map { it.id })
    }

    @Test fun aUdpOnlyServerThatCarriedCompetesWithTheTcpRoundTrips() {
        // what pickFastest hands pick(): the walk's TCP round trips and the UDP-only servers' together
        val tried = listOf(m("a", tcp = 40, real = 700), m("b", tcp = 55, real = -1))
        val udp = listOf(m("wg", real = 300), m("hy2", real = -1))
        assertEquals("wg", Fastest.pick(tried + udp)?.id)
        assertEquals("a", Fastest.pick(tried + listOf(m("wg", real = 900)))?.id)
        // nothing over TCP carried: the UDP-only one that did is the answer, never the one that failed
        assertEquals("wg", Fastest.pick(listOf(m("a", tcp = 40, real = -1)) + udp)?.id)
        assertNull(Fastest.pick(listOf(m("a", tcp = 40, real = -1), m("hy2", real = -1))))
        // it never shook hands, so the walk never spends a second core on it
        assertEquals(emptyList<String>(), Fastest.shortlist(udp).map { it.id })
    }
}
