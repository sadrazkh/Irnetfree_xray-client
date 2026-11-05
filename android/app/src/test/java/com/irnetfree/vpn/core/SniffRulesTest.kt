package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The cases of tests/sniffRules.test.js: what a domain rule's text means, which addresses sniffing leaves alone, where the QUIC pair sits. */
class SniffRulesTest {
    @Test fun aDomainValueAsTheCoreMustReadIt() {
        val cases = listOf<Pair<String?, String?>>(
            "example.com" to "domain:example.com",
            "  Example.COM " to "domain:example.com",
            ".example.com" to "domain:example.com",
            "*.example.com" to "domain:example.com",
            "*..example.com" to "domain:example.com",
            "example.com." to "domain:example.com",
            "https://claude.ai/chat?x=1#y" to "domain:claude.ai",
            "HTTP://Claude.ai:8443/" to "domain:claude.ai",
            "claude.ai/new" to "domain:claude.ai",
            "*anthropic.com" to "regexp:^.*anthropic\\.com$",
            "*.example.*" to "regexp:^.*\\.example\\..*$",
            "api.*.example.com" to "regexp:^api\\..*\\.example\\.com$",
            "*" to "regexp:^.*$",
            "google" to "google",
            "localhost" to "localhost",
            "domain:Example.com" to "domain:Example.com",
            "Domain:example.com" to "domain:example.com",
            "full:www.example.com" to "full:www.example.com",
            "keyword:acme" to "keyword:acme",
            "Regexp:^a\\.b$" to "regexp:^a\\.b$",
            "geosite:category-ir" to "geosite:category-ir",
            "ext:my.dat:tag" to "ext:my.dat:tag",
            "dotless:corp" to "dotless:corp",
            "مثال.ir" to "domain:xn--mgbh0fb.ir",
            "" to null,
            "   " to null,
            "." to null,
            "https://" to null,
            null to null
        )
        for ((value, want) in cases) assertEquals("$value", want, SniffRules.normalizeDomain(value))
    }

    @Test fun theSameNameWrittenTwiceIsOneEntry() {
        assertEquals(listOf("domain:anthropic.com", "regexp:^.*anthropic\\.com$", "domain:claude.ai"),
            SniffRules.normalizeDomains(listOf("anthropic.com", "*anthropic.com", "claude.ai", "*.claude.ai", ".claude.ai", "")))
    }

    @Test fun sniffingLeavesAloneOnlyWhatTheCoreCanRead() {
        for (v in listOf("10.1.2.3", "192.168.0.0/16", "::1", "fc00::/7", "0.0.0.0/0", "::/0")) assertTrue(v, SniffRules.isIpLiteral(v))
        for (v in listOf("geoip:ir", "ext:x:y", "1.2.3.4-1.2.3.9", "1.2.3.4/33", "::1/129", "1.2.3.4/x", "1.2.3.4/8/8", "example.com", "", null)) {
            assertFalse("$v", SniffRules.isIpLiteral(v))
        }
        assertEquals(listOf("192.168.0.0/16", "172.16.0.0/12", "::1/128"),
            SniffRules.excludedIps(listOf("192.168.0.0/16", "geoip:ir", " 172.16.0.0/12 ", "192.168.0.0/16", "nonsense", "::1/128")))
    }

    private fun ipToLong(ip: String): Long = ip.split(".").fold(0L) { n: Long, x: String -> n * 256 + x.toLong() }
    private fun inside(ip: String, cidr: String): Boolean {
        val p = cidr.split("/")
        val shift = 32 - p[1].toInt()
        return (ipToLong(ip) shr shift) == (ipToLong(p[0]) shr shift)
    }

    @Test fun thePoisonAddressesStaySniffed() {
        val cut = SniffRules.excludedIps(listOf("10.0.0.0/8"))
        for (poison in listOf("10.10.34.34", "10.10.34.35", "10.10.34.36")) assertFalse(poison, cut.any { c: String -> inside(poison, c) })
        for (kept in listOf("10.0.0.1", "10.10.33.1", "10.10.34.31", "10.10.34.40", "10.10.35.1", "10.255.255.254", "10.128.0.1")) {
            assertEquals(kept, 1, cut.count { c: String -> inside(kept, c) })
        }
        assertEquals(21, cut.size)
        assertEquals(emptyList<String>(), SniffRules.excludedIps(listOf("0.0.0.0/0", "::/0", "128.0.0.0/1", "8.0.0.0/7", "2000::/3")))
        assertEquals(listOf("8.0.0.0/8", "fc00::/7"), SniffRules.excludedIps(listOf("8.0.0.0/8", "fc00::/7")))
        assertEquals(listOf("10.10.34.0/29"), SniffRules.excludedIps(listOf("10.10.34.0/29")))
        assertEquals(listOf("10.10.34.32/29", "10.10.34.34", "10.10.34.34/32"), SniffRules.excludedIps(listOf("10.10.34.32/29", "10.10.34.34", "10.10.34.34/32")))
        assertEquals(listOf("192.168.0.0/16"), SniffRules.excludedIps(listOf("192.168.0.0/16")))
    }

    private fun vless(id: String, host: String): ServerConfig {
        val user = JSONObject().put("id", "00000000-0000-0000-0000-000000000000").put("encryption", "none")
        val vnext = JSONObject().put("address", host).put("port", 443).put("users", JSONArray().put(user))
        val ob = JSONObject().put("protocol", "vless").put("settings", JSONObject().put("vnext", JSONArray().put(vnext)))
        return ServerConfig(id = id, name = id, protocol = "vless", address = host, port = 443, raw = "", outbound = ob)
    }
    private val server = vless("a", "a.example")
    private val other = vless("b", "b.example")
    private val settings = AppSettings(blockAds = false)
    private fun advanced(rules: List<RouteRule>, def: String = "a") =
        ConnectionPlan.Advanced(rules, def, mapOf("a" to server, "b" to other), emptyMap())
    private fun rulesOf(c: JSONObject): List<JSONObject> {
        val a = c.getJSONObject("routing").getJSONArray("rules")
        return (0 until a.length()).map { i: Int -> a.getJSONObject(i) }
    }
    private fun strs(a: JSONArray?): List<String> = if (a == null) emptyList() else (0 until a.length()).map { i: Int -> a.getString(i) }

    @Test fun aPlansSniffingLeavesAloneItsIpRulesAddressesAndThePrivateOnes() {
        val c = ConfigBuilder.build(advanced(listOf(RouteRule("ip", "203.0.113.0/24, geoip:de", "b"), RouteRule("domain", "a.example", "b"))), settings)
        val socks = (0 until c.getJSONArray("inbounds").length()).map { i: Int -> c.getJSONArray("inbounds").getJSONObject(i) }.first { o: JSONObject -> o.getString("tag") == "socks-in" }
        val kept = strs(socks.getJSONObject("sniffing").optJSONArray("ipsExcluded"))
        assertTrue(kept.contains("203.0.113.0/24"))
        assertTrue(kept.contains("172.16.0.0/12") && kept.contains("fe80::/10"))
        assertFalse(kept.any { k: String -> k.startsWith("geoip") })
    }

    @Test fun aRuleNotWrittenSaysNothing() {
        fun kept(c: JSONObject): List<String> {
            val all = c.getJSONArray("inbounds")
            val socks = (0 until all.length()).map { i: Int -> all.getJSONObject(i) }.first { o: JSONObject -> o.getString("tag") == "socks-in" }
            return strs(socks.getJSONObject("sniffing").optJSONArray("ipsExcluded"))
        }
        val gone = ConfigBuilder.build(advanced(listOf(RouteRule("ip", "203.0.113.0/24", "no-such-server"))), settings)
        assertFalse(kept(gone).contains("203.0.113.0/24"))
        val left = ConfigBuilder.build(advanced(listOf(RouteRule("domain", "a.example", "b"))), settings.copy(customRules = listOf(RouteRule("ip", "203.0.113.0/24", "direct"))))
        assertFalse(kept(left).contains("203.0.113.0/24"))
        val custom = ConfigBuilder.build(ConnectionPlan.Single(server), settings.copy(customRules = listOf(RouteRule("ip", "198.51.100.7", "direct"))))
        assertTrue(kept(custom).contains("198.51.100.7"))
    }

    @Test fun domainRulesAreWrittenAsTheCoreReadsThem() {
        val c = ConfigBuilder.build(advanced(listOf(RouteRule("domain", "x.com, *.y.example, geosite:netflix", "b"))), settings)
        assertEquals(listOf("domain:x.com", "domain:y.example", "geosite:netflix"), strs(rulesOf(c).first { r: JSONObject -> r.optString("outboundTag") == "out-b" }.optJSONArray("domain")))
        val nothing = ConfigBuilder.build(advanced(listOf(RouteRule("domain", ".", "b"))), settings)
        assertFalse("a rule with nothing left in it is no rule", rulesOf(nothing).any { r: JSONObject -> r.has("domain") && r.getJSONArray("domain").length() == 0 })
        val custom = ConfigBuilder.build(ConnectionPlan.Single(server), settings.copy(customRules = listOf(RouteRule("domain", "*.z.example", "direct"))))
        assertTrue(rulesOf(custom).any { r: JSONObject -> strs(r.optJSONArray("domain")).contains("domain:z.example") })
    }

    @Test fun theQuicPairOnlyWhenANameSendsSomethingAwayFromTheDefault() {
        fun pair(c: JSONObject) = rulesOf(c).filter { r: JSONObject -> r.optString("network") == "udp" && r.optString("port") == "443" }
        assertEquals(0, pair(ConfigBuilder.build(advanced(listOf(RouteRule("ip", "203.0.113.0/24", "b"))), settings)).size)
        assertEquals(0, pair(ConfigBuilder.build(advanced(listOf(RouteRule("domain", "a.example", "a"))), settings)).size)
        val c = ConfigBuilder.build(advanced(listOf(RouteRule("domain", "a.example", "b"))), settings)
        val tail = rulesOf(c).takeLast(3)
        assertEquals(listOf("out-a", "block", "out-a"), tail.map { r: JSONObject -> r.getString("outboundTag") })
        assertEquals(listOf("regexp:."), strs(tail[0].optJSONArray("domain")))
        assertEquals("0-65535", tail[2].getString("port"))
        val simple = ConfigBuilder.build(ConnectionPlan.Single(server), settings.copy(customRules = listOf(RouteRule("domain", "a.example", "direct"))))
        assertEquals(listOf("proxy", "block", "proxy"), rulesOf(simple).takeLast(3).map { r: JSONObject -> r.getString("outboundTag") })
        assertEquals(0, pair(ConfigBuilder.build(ConnectionPlan.Single(server), settings)).size)
    }
}
