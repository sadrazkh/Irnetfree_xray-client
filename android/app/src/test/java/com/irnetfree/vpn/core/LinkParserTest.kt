package com.irnetfree.vpn.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The link parser against the desktop's pins (tests/parser.test.js), for the
 * shapes this phase touched: xhttp `extra`, the WireGuard `dns=` field and its
 * share link. (vmess/ss go through android.util.Base64, a stub off a device,
 * so they are not exercised here.)
 */
class LinkParserTest {
    @Test fun xhttpExtraReachesTheConfigAndTheShareLink() {
        val extra = """{"scMaxEachPostBytes":"1000000","uplinkHTTPMethod":"PUT","xPaddingBytes":"100-1000"}"""
        val s = LinkParser.parseLink("vless://u@x.example.com:443?type=xhttp&path=%2F&host=x.com&mode=auto&extra=" + java.net.URLEncoder.encode(extra, "UTF-8"))
        val xs = s.outbound.getJSONObject("streamSettings").getJSONObject("xhttpSettings")
        assertEquals("/", xs.getString("path")); assertEquals("x.com", xs.getString("host")); assertEquals("auto", xs.getString("mode"))
        assertEquals(Canon.of(JSONObject(extra)), Canon.of(xs.getJSONObject("extra")))
        val back = LinkParser.parseLink(LinkParser.buildShareLink(s))
        assertEquals(Canon.of(JSONObject(extra)), Canon.of(back.outbound.getJSONObject("streamSettings").getJSONObject("xhttpSettings").getJSONObject("extra")))
        // bad JSON is dropped, the link still imports
        val bad = LinkParser.parseLink("vless://u@x.example.com:443?type=xhttp&extra=not-json")
        assertFalse(bad.outbound.getJSONObject("streamSettings").getJSONObject("xhttpSettings").has("extra"))
        val plain = LinkParser.parseLink("vless://u@x.example.com:443?type=xhttp&path=%2Fx&host=x.com&mode=packet-up")
        assertFalse(LinkParser.buildShareLink(plain).contains("extra="))
    }

    @Test fun splitDnsField() {
        val (dns, domains) = LinkParser.splitDnsField("192.168.60.1, .Tes.Systems, 10.0.0.53:5353, [fd00::1]:53, corp.local")
        assertEquals(listOf("192.168.60.1", "10.0.0.53:5353", "[fd00::1]:53"), dns)
        assertEquals(listOf("tes.systems", "corp.local"), domains)
        assertEquals(emptyList<String>() to emptyList<String>(), LinkParser.splitDnsField(null))
        assertTrue(LinkParser.isResolverEntry("1.1.1.1")); assertTrue(LinkParser.isResolverEntry("[2a00::1]"))
        assertFalse(LinkParser.isResolverEntry("dns.google")); assertFalse(LinkParser.isResolverEntry("a.b:99999x"))
    }

    @Test fun wireguardLinkCarriesDnsAndWritesItBack() {
        val link = "wireguard://PRIV@cobra.example:42421?publickey=PUB&address=10.10.10.42%2F32&allowedips=192.168.0.0%2F16%2C10.0.0.0%2F8&mtu=1420&dns=192.168.60.1%2Ctes.systems#corp"
        val s = LinkParser.parseLink(link)
        assertEquals("wireguard", s.protocol); assertEquals("cobra.example", s.address); assertEquals(42421, s.port)
        assertEquals(listOf("192.168.60.1"), s.dns); assertEquals(listOf("tes.systems"), s.dnsDomains)
        val peer = s.outbound.getJSONObject("settings").getJSONArray("peers").getJSONObject(0)
        assertEquals("cobra.example:42421", peer.getString("endpoint"))
        assertEquals("""["192.168.0.0/16","10.0.0.0/8"]""", peer.getJSONArray("allowedIPs").toString())
        val out = LinkParser.buildShareLink(s)
        assertTrue(out.startsWith("wireguard://PRIV@cobra.example:42421?"))
        assertTrue(out.contains("publickey=PUB")); assertTrue(out.contains("dns=192.168.60.1%2Ctes.systems")); assertTrue(out.endsWith("#corp"))
        val again = LinkParser.parseLink(out)
        assertEquals(s.dns, again.dns); assertEquals(s.dnsDomains, again.dnsDomains)
        assertEquals(Canon.of(peer), Canon.of(again.outbound.getJSONObject("settings").getJSONArray("peers").getJSONObject(0)))
    }

    @Test fun manualWireGuardTakesTheDnsLine() {
        val s = LinkParser.makeWireguardServer("corp", "cobra.example:42421", "PRIV", "PUB", "10.10.10.42", "192.168.0.0/16", "", "1420", null, "192.168.60.1, tes.systems")
        assertEquals(listOf("192.168.60.1"), s.dns); assertEquals(listOf("tes.systems"), s.dnsDomains)
        val none = LinkParser.makeWireguardServer("w", "1.2.3.4:51820", "PRIV", "PUB", "10.0.0.2", "0.0.0.0/0", "", "1420", null)
        assertTrue(none.dns.isEmpty() && none.dnsDomains.isEmpty())
    }

    @Test fun storedRecordRoundTripsItsDnsAndPin() {
        val s = LinkParser.parseLink("wireguard://PRIV@cobra.example:42421?publickey=PUB&address=10.10.10.42&dns=192.168.60.1%2Ctes.systems")
            .copy(certPin = "ab".repeat(32), certPinAt = "now", certPinCheckedAt = 5L)
        val back = ServerConfig.fromJson(s.toJson())
        assertEquals(s.dns, back.dns); assertEquals(s.dnsDomains, back.dnsDomains)
        assertEquals("ab".repeat(32), back.certPin); assertEquals(5L, back.certPinCheckedAt)
        // a hand-edited store with the .conf line as a string
        val hand = ServerConfig.fromJson(JSONObject(s.toJson().toString()).put("dns", "10.0.0.53, corp.local").also { it.remove("dnsDomains") })
        assertEquals(listOf("10.0.0.53"), hand.dns); assertEquals(listOf("corp.local"), hand.dnsDomains)
    }

    @Test fun legacySettingsMigrateTheSingleDnsList() {
        val o = JSONObject().put("dns", org.json.JSONArray(listOf("1.1.1.1", "178.22.122.100", "9.9.9.9", "5.5.5.5")))
        val s = AppSettings.fromJson(o)
        assertEquals(listOf("https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query", "5.5.5.5"), s.dnsRemote)
        assertEquals(listOf("178.22.122.100"), s.dnsDirect)
        assertTrue(s.dnsManaged)
        val fresh = AppSettings.fromJson(JSONObject())
        assertEquals(DnsPlan.DEFAULT_REMOTE, fresh.dnsRemote); assertEquals(DnsPlan.DEFAULT_DIRECT_IR, fresh.dnsDirect)
        val round = AppSettings.fromJson(s.copy(advancedUseMode = true, dnsManaged = false).toJson())
        assertTrue(round.advancedUseMode); assertFalse(round.dnsManaged); assertEquals(s.dnsRemote, round.dnsRemote)
    }
}
