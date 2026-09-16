package com.irnetfree.vpn.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** TrustedDns and CertPin, the pure parts, against the desktop's pins (tests/trustedDns.test.js). */
class TrustedDnsTest {
    private fun os(vararg ips: String): (String) -> List<String> = { ips.toList() }
    private fun doh(table: Map<String, List<String>>): (String, String, String) -> List<String> = { _, host, type -> table["$host/$type"] ?: emptyList() }

    @Test fun suspectRanges() {
        for (ip in listOf("198.18.175.48", "198.19.0.1", "192.168.10.1", "10.0.0.1", "172.16.5.5", "127.0.0.1", "0.0.0.0", "169.254.1.1", "100.64.0.1", "224.0.0.1", "192.0.2.1"))
            assertTrue(ip, TrustedDns.isSuspect(ip))
        for (ip in listOf("51.222.52.23", "3.11.139.9", "1.1.1.1", "198.17.255.255", "198.20.0.1", "8.8.8.8"))
            assertFalse(ip, TrustedDns.isSuspect(ip))
        for (ip in listOf("fc00::1a0:73dc:65f", "fd12::1", "fe80::1", "::1", "::", "2001:db8::1")) assertTrue(ip, TrustedDns.isSuspect(ip))
        for (ip in listOf("2606:4700::1111", "2a01:5ec0::1")) assertFalse(ip, TrustedDns.isSuspect(ip))
        assertTrue(TrustedDns.isSuspect("not-an-ip")); assertTrue(TrustedDns.isSuspect(""))
    }

    @Test fun literalAndSaneOsAnswers() {
        val lit = TrustedDns.resolveHost("51.222.52.23", lookup = { throw IllegalStateException("must not look up") }, query = { _, _, _ -> throw IllegalStateException() })
        assertEquals(listOf("51.222.52.23"), lit.ips); assertEquals("literal", lit.source)
        var dohAsked = 0
        val r = TrustedDns.resolveHost("cobra.tes.ca", lookup = os("51.222.52.23"), query = { _, _, _ -> dohAsked++; emptyList() })
        assertEquals(listOf("51.222.52.23"), r.ips); assertEquals("os", r.source); assertEquals(0, dohAsked)
    }

    @Test fun fakeIpNetworkFallsBackToDohAndReportsTheFake() {
        val r = TrustedDns.resolveHost("cobra.tes.ca", lookup = os("198.18.175.48"), query = doh(mapOf("cobra.tes.ca/A" to listOf("51.222.52.23"))))
        assertEquals(listOf("51.222.52.23"), r.ips); assertEquals("doh", r.source); assertEquals(listOf("198.18.175.48"), r.suspect)
    }

    @Test fun privateAnswerWithoutSecondOpinionIsKeptAndMarked() {
        val r = TrustedDns.resolveHost("wg.corp.lan", lookup = os("10.0.0.5"), query = doh(emptyMap()))
        assertEquals(listOf("10.0.0.5"), r.ips); assertEquals("os-suspect", r.source)
        val bad = TrustedDns.resolveHost("x.example", lookup = os("192.168.10.1"), query = doh(mapOf("x.example/A" to listOf("198.18.1.1"))))
        assertEquals("os-suspect", bad.source); assertEquals(listOf("192.168.10.1"), bad.ips)
    }

    @Test fun osFailureFallsThroughToDoh_nothingAnywhereIsNone() {
        val r = TrustedDns.resolveHost("cobra.tes.ca", lookup = { throw java.net.UnknownHostException() }, query = doh(mapOf("cobra.tes.ca/A" to listOf("51.222.52.23"))))
        assertEquals("doh", r.source); assertTrue(r.suspect.isEmpty())
        val none = TrustedDns.resolveHost("nowhere.invalid", lookup = os(), query = doh(emptyMap()))
        assertEquals("none", none.source); assertTrue(none.ips.isEmpty())
        assertEquals("none", TrustedDns.resolveHost("").source)
    }

    @Test fun dohServersInOrder_ipv6AddsAAAA_onlyHttpsLiteralsCount() {
        val asked = ArrayList<String>()
        val r = TrustedDns.resolveHost("cobra.tes.ca", ipv6 = true, lookup = os("198.18.175.48"),
            doh = listOf("https://1.1.1.1/dns-query", "tcp://1.0.0.1", "https://8.8.8.8/dns-query"),
            query = { url, _, type -> asked.add("$url $type"); if (url.contains("8.8.8.8")) listOf("51.222.52.23") else emptyList() })
        assertEquals("doh", r.source)
        assertEquals(listOf("https://1.1.1.1/dns-query A", "https://1.1.1.1/dns-query AAAA", "https://8.8.8.8/dns-query A", "https://8.8.8.8/dns-query AAAA"), asked)
        assertEquals(listOf("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"), TrustedDns.DEFAULT_DOH)
        // the real query refuses a URL whose host is a name, or a non-https one, without touching the network
        assertTrue(TrustedDns.dohQuery("https://dns.google/dns-query", "a.example", "A", 100).isEmpty())
        assertTrue(TrustedDns.dohQuery("http://1.1.1.1/dns-query", "a.example", "A", 100).isEmpty())
        assertTrue(TrustedDns.dohQuery("not a url", "a.example", "A", 100).isEmpty())
    }

    @Test fun certPinHelpers() {
        assertEquals("ab".repeat(32), CertPin.normalizePin("AB:".repeat(32).trimEnd(':')))
        assertEquals("", CertPin.normalizePin("zz")); assertEquals("", CertPin.normalizePin(null))
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", CertPin.pinOf(ByteArray(0)))
        val tls = org.json.JSONObject().put("network", "tcp").put("security", "tls").put("tlsSettings", org.json.JSONObject().put("allowInsecure", true))
        val ob = org.json.JSONObject().put("protocol", "vless").put("settings", org.json.JSONObject()).put("streamSettings", tls)
        val wants = ServerConfig("w", "w", "vless", "w.example", 443, ob)
        val pinned = wants.copy(certPin = "ab".repeat(32), certPinCheckedAt = 0L)
        assertTrue(CertPin.wantsPin(wants)); assertFalse(CertPin.wantsPin(wants.copy(outbound = org.json.JSONObject().put("streamSettings", org.json.JSONObject().put("security", "reality")))))
        val t = CertPin.pinTargets(ConnectionPlan.Single(wants))
        assertEquals(listOf("w"), t.probe.map { it.id }); assertTrue(t.behind.isEmpty())
        assertTrue(CertPin.pinTargets(ConnectionPlan.Single(pinned)).probe.isEmpty())
        val behind = CertPin.pinTargets(ConnectionPlan.Chain("c", listOf(pinned.copy(id = "hop"), wants)))
        assertTrue(behind.probe.isEmpty()); assertEquals(listOf("w"), behind.behind.map { it.id })
        assertTrue(CertPin.recheckDue(pinned, now = CertPin.RECHECK_AFTER_MS + 1))
        assertFalse(CertPin.recheckDue(pinned, now = 10L)); assertFalse(CertPin.recheckDue(wants, now = Long.MAX_VALUE / 2))
        assertEquals(listOf("w"), CertPin.directServers(ConnectionPlan.Advanced(listOf(RouteRule("ip", "10.0.0.0/8", "w")), "direct", mapOf("w" to wants), emptyMap())).map { it.id })
    }
}
