package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * DnsPlan against the desktop's own pins (tests/dnsBuilder.test.js). Every
 * expected shape below is copied from a JS assertion, so the two clients keep
 * emitting the same resolver plan.
 */
class DnsPlanTest {
    private fun base(over: (AppSettings) -> AppSettings = { it }): AppSettings = over(AppSettings(
        dnsManaged = true,
        dnsRemote = listOf("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"),
        dnsDirect = listOf("178.22.122.100", "185.51.200.2"),
        ipv6 = false, routingMode = "global", advancedRouting = false, routeRules = emptyList()
    ))

    private fun j(s: String) = JSONObject(s).toString()
    private fun same(expected: String, actual: Any?) = assertEquals(Canon.of(JSONObject(expected)), Canon.of(actual))

    @Test fun globalRemoteDohOnlyHijackOn() {
        val p = DnsPlan.build(base(), geoAssets = true, exitTag = "proxy")
        same("""{"tag":"dns-internal","queryStrategy":"UseIPv4","servers":["https://1.1.1.1/dns-query","https://8.8.8.8/dns-query"]}""", p.dns)
        same("""{"tag":"dns-out","protocol":"dns","settings":{"rules":[{"action":"return","rCode":5,"qType":"0,2-27,29-65535"}]}}""", p.hijackOutbound)
        assertEquals(2, p.rules.size)
        same("""{"type":"field","inboundTag":["dns-internal"],"outboundTag":"proxy"}""", p.rules[0])
        same("""{"type":"field","port":"53","network":"tcp,udp","outboundTag":"dns-out"}""", p.rules[1])
        assertTrue(p.directResolverIps.isEmpty())
    }

    @Test fun ipv6SwitchesTheQueryStrategy() {
        assertEquals("UseIP", DnsPlan.build(base { it.copy(ipv6 = true) }, true, "proxy").dns.getString("queryStrategy"))
    }

    @Test fun bypassIrPinsTheDirectResolverToIranianDomains() {
        val p = DnsPlan.build(base { it.copy(routingMode = "bypass-ir") }, true, "proxy")
        val servers = p.dns.getJSONArray("servers")
        assertEquals(4, servers.length())
        same("""{"address":"178.22.122.100","domains":["geosite:category-ir","regexp:.*\\.ir$"],"expectedIPs":["geoip:ir"],"skipFallback":true}""", servers.get(0))
        same("""{"address":"185.51.200.2","domains":["geosite:category-ir","regexp:.*\\.ir$"],"expectedIPs":["geoip:ir"],"skipFallback":true}""", servers.get(1))
        assertEquals("https://1.1.1.1/dns-query", servers.getString(2))
        // the resolver's OWN queries to the in-country server go direct, on :53 only,
        // and are decided before the port-53 hijack
        same("""{"type":"field","inboundTag":["dns-internal"],"ip":["178.22.122.100","185.51.200.2"],"port":"53","outboundTag":"direct"}""", p.rules[0])
        same("""{"type":"field","inboundTag":["dns-internal"],"outboundTag":"proxy"}""", p.rules[1])
        assertEquals("dns-out", p.rules[2].getString("outboundTag"))
        assertEquals(listOf("178.22.122.100", "185.51.200.2"), p.directResolverIps)
    }

    @Test fun withoutGeoFilesThereIsNoInCountryResolverAtAll() {
        val p = DnsPlan.build(base { it.copy(routingMode = "bypass-ir") }, geoAssets = false, exitTag = "proxy")
        assertEquals(2, p.dns.getJSONArray("servers").length())
        assertTrue(p.directResolverIps.isEmpty())
        assertFalse(p.dns.toString().contains("geosite:"))
    }

    @Test fun bypassCnUsesTheChineseResolver() {
        val p = DnsPlan.build(base { it.copy(routingMode = "bypass-cn") }, true, "proxy")
        same("""{"address":"223.5.5.5","domains":["geosite:cn"],"expectedIPs":["geoip:cn"],"skipFallback":true}""", p.dns.getJSONArray("servers").get(0))
        assertEquals(listOf("223.5.5.5"), p.directResolverIps)
    }

    @Test fun emptyDirectListFallsBackToTheBuiltInResolver() {
        val p = DnsPlan.build(base { it.copy(routingMode = "bypass-ir", dnsDirect = emptyList()) }, true, "proxy")
        assertEquals(DnsPlan.DEFAULT_DIRECT_IR[0], p.dns.getJSONArray("servers").getJSONObject(0).getString("address"))
    }

    @Test fun advancedGeositeIrDirectRuleBringsTheIranianResolver() {
        val p = DnsPlan.build(base { it.copy(advancedRouting = true, routeRules = listOf(RouteRule("domain", "geosite:category-ir", "direct"))) }, true, "out-sv-a")
        assertEquals("178.22.122.100", p.dns.getJSONArray("servers").getJSONObject(0).getString("address"))
        val notDirect = DnsPlan.build(base { it.copy(advancedRouting = true, routeRules = listOf(RouteRule("domain", "geosite:category-ir", "out-sv-a"))) }, true, "x")
        assertTrue(notDirect.dns.getJSONArray("servers").get(0) is String)
    }

    @Test fun advancedUseModeFollowsTheRoutingMode() {
        val p = DnsPlan.build(base { it.copy(advancedRouting = true, advancedUseMode = true, routingMode = "bypass-ir", routeRules = listOf(RouteRule("ip", "10.20.0.0/16", "out-sv-a"))) }, true, "out-sv-a")
        assertEquals("178.22.122.100", p.dns.getJSONArray("servers").getJSONObject(0).getString("address"))
        val off = DnsPlan.build(base { it.copy(advancedRouting = true, advancedUseMode = false, routingMode = "bypass-ir", routeRules = listOf(RouteRule("ip", "10.20.0.0/16", "out-sv-a"))) }, true, "out-sv-a")
        assertTrue(off.dns.getJSONArray("servers").get(0) is String)
    }

    @Test fun unmanagedIsTheLegacyShape() {
        val p = DnsPlan.build(base { it.copy(dnsManaged = false, dnsRemote = listOf("1.1.1.1", "8.8.8.8:5353")) }, true, "proxy")
        same("""{"queryStrategy":"UseIPv4","servers":["1.1.1.1",{"address":"8.8.8.8","port":5353}]}""", p.dns)
        assertNull(p.hijackOutbound)
        assertTrue(p.rules.isEmpty())
    }

    @Test fun hostPortEntriesBecomeObjects() {
        val p = DnsPlan.build(base { it.copy(routingMode = "bypass-ir", dnsDirect = listOf("178.22.122.100"), dnsRemote = listOf("1.1.1.1:5353", "https://8.8.8.8/dns-query")) }, true, "proxy")
        same("""{"address":"1.1.1.1","port":5353}""", p.dns.getJSONArray("servers").get(1))
        assertEquals(listOf("178.22.122.100"), p.directResolverIps)
    }

    @Test fun privateRemoteResolverIsDialledDirect() {
        val p = DnsPlan.build(base { it.copy(dnsRemote = listOf("192.168.1.1", "https://1.1.1.1/dns-query")) }, true, "proxy")
        same("""{"type":"field","inboundTag":["dns-internal"],"ip":["192.168.1.1"],"port":"53","outboundTag":"direct"}""", p.rules[0])
        assertEquals(listOf("192.168.1.1"), p.directResolverIps)
        assertTrue(DnsPlan.build(base(), true, "proxy").directResolverIps.isEmpty())
    }

    @Test fun aPublicAddressInBothListsKeepsItsDohOnTheExit() {
        // the owner's store, verbatim: matched on ip alone, the direct rule also
        // caught the DoH connection to 1.1.1.1:443 and sent it off the tunnel
        val p = DnsPlan.build(base { it.copy(routingMode = "bypass-ir", dnsDirect = listOf("8.8.8.8", "1.1.1.1"), dnsRemote = listOf("https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query")) }, true, "proxy")
        same("""{"type":"field","inboundTag":["dns-internal"],"ip":["8.8.8.8","1.1.1.1"],"port":"53","outboundTag":"direct"}""", p.rules[0])
        assertEquals(3, p.rules.size)
    }

    @Test fun onePortOneRule() {
        val p = DnsPlan.build(base { it.copy(routingMode = "bypass-ir", dnsDirect = listOf("178.22.122.100", "185.51.200.2:5353"), dnsRemote = listOf("192.168.1.1", "https://192.168.1.2/dns-query")) }, true, "proxy")
        same("""{"type":"field","inboundTag":["dns-internal"],"ip":["178.22.122.100","192.168.1.1"],"port":"53","outboundTag":"direct"}""", p.rules[0])
        same("""{"type":"field","inboundTag":["dns-internal"],"ip":["185.51.200.2"],"port":"5353","outboundTag":"direct"}""", p.rules[1])
        same("""{"type":"field","inboundTag":["dns-internal"],"ip":["192.168.1.2"],"port":"443","outboundTag":"direct"}""", p.rules[2])
    }

    private val corp = DnsPlan.TargetResolver("192.168.60.1", "out-chain-c1", listOf("192.168.0.0/16", "10.0.0.0/8"), listOf("domain:tes.systems"))

    @Test fun targetResolverIsAppendedPinnedToItsSearchDomains() {
        val p = DnsPlan.build(base(), true, "proxy", listOf(corp))
        val servers = p.dns.getJSONArray("servers")
        assertEquals(3, servers.length())
        same("""{"address":"192.168.60.1","domains":["domain:tes.systems"],"expectedIPs":["192.168.0.0/16","10.0.0.0/8"],"skipFallback":true}""", servers.get(2))
        // without search domains it stays a fallback: there is nothing else to match it on
        val bare = DnsPlan.build(base(), true, "proxy", listOf(corp.copy(domains = emptyList())))
        same("""{"address":"192.168.60.1","expectedIPs":["192.168.0.0/16","10.0.0.0/8"]}""", bare.dns.getJSONArray("servers").get(2))
    }

    @Test fun targetResolverQueryLeavesThroughTheTargetAfterDirectBeforeExit() {
        val p = DnsPlan.build(base { it.copy(routingMode = "bypass-ir") }, true, "proxy", listOf(corp))
        assertEquals(4, p.rules.size)
        same("""{"type":"field","inboundTag":["dns-internal"],"ip":["178.22.122.100","185.51.200.2"],"port":"53","outboundTag":"direct"}""", p.rules[0])
        same("""{"type":"field","inboundTag":["dns-internal"],"ip":["192.168.60.1"],"outboundTag":"out-chain-c1"}""", p.rules[1])
        same("""{"type":"field","inboundTag":["dns-internal"],"outboundTag":"proxy"}""", p.rules[2])
    }

    @Test fun targetResolverIsNeverDialledDirectEvenWhenPrivateOrDuplicated() {
        val p = DnsPlan.build(base(), true, "proxy", listOf(corp))
        assertTrue(p.directResolverIps.isEmpty())
        assertFalse(p.rules.any { it.optString("outboundTag") == "direct" })
        val dup = DnsPlan.build(base { it.copy(dnsRemote = listOf(corp.address), dnsDirect = listOf(corp.address), routingMode = "bypass-ir") }, true, "proxy", listOf(corp))
        assertTrue(dup.directResolverIps.isEmpty())
        same("""{"type":"field","inboundTag":["dns-internal"],"ip":["192.168.60.1"],"outboundTag":"out-chain-c1"}""", dup.rules[0])
    }

    @Test fun v6ExpectedIpsAreDroppedWhileTheCoreAsksForARecordsOnly() {
        val t = corp.copy(expectedIPs = listOf("192.168.0.0/16", "fd00::/8"))
        val a = DnsPlan.build(base(), true, "proxy", listOf(t)).dns.getJSONArray("servers").getJSONObject(2)
        assertEquals("""["192.168.0.0/16"]""", a.getJSONArray("expectedIPs").toString())
        val b = DnsPlan.build(base { it.copy(ipv6 = true) }, true, "proxy", listOf(t)).dns.getJSONArray("servers").getJSONObject(2)
        assertEquals(2, b.getJSONArray("expectedIPs").length())
    }

    @Test fun helpers() {
        assertEquals("8.8.8.8", DnsPlan.resolverIp("8.8.8.8"))
        assertEquals("1.1.1.1", DnsPlan.resolverIp("1.1.1.1:5353"))
        assertEquals("1.1.1.1", DnsPlan.resolverIp("https://1.1.1.1/dns-query"))
        assertEquals("2a00:1450::1", DnsPlan.resolverIp("[2a00:1450::1]:5353"))
        assertNull(DnsPlan.resolverIp("https://dns.google/dns-query"))
        assertNull(DnsPlan.resolverIp("dns.example"))
        assertEquals(53, DnsPlan.resolverPort("8.8.8.8"))
        assertEquals(5353, DnsPlan.resolverPort("8.8.8.8:5353"))
        assertEquals(443, DnsPlan.resolverPort("https://1.1.1.1/dns-query"))
        assertEquals(8443, DnsPlan.resolverPort("https://1.1.1.1:8443/dns-query"))
        assertEquals(853, DnsPlan.resolverPort("quic+local://1.1.1.1"))
        assertTrue(DnsPlan.isPrivateIp("10.0.0.1")); assertTrue(DnsPlan.isPrivateIp("172.20.1.1")); assertTrue(DnsPlan.isPrivateIp("192.168.1.1"))
        assertTrue(DnsPlan.isPrivateIp("100.64.0.1")); assertTrue(DnsPlan.isPrivateIp("fd00::1")); assertTrue(DnsPlan.isPrivateIp("fe80::1"))
        assertFalse(DnsPlan.isPrivateIp("8.8.8.8")); assertFalse(DnsPlan.isPrivateIp("172.32.0.1")); assertFalse(DnsPlan.isPrivateIp("2606:4700::1111"))
        assertEquals(listOf("172.19.0.2"), DnsPlan.adapterDnsServers(base(), "172.19.0.2"))
        assertEquals(listOf("1.1.1.1", "8.8.8.8"), DnsPlan.adapterDnsServers(base { it.copy(dnsManaged = false) }, "172.19.0.2"))
        assertEquals(listOf("9.9.9.9"), DnsPlan.adapterDnsServers(base { it.copy(dnsManaged = false, dnsRemote = listOf("https://1.1.1.1/dns-query", "9.9.9.9")) }, "172.19.0.2"))
        assertEquals(JSONArray(listOf("a")).toString(), JSONArray().put("a").toString())
        assertEquals(Canon.of(JSONObject(j("""{"a":1}"""))), Canon.of(JSONObject("""{ "a": 1 }""")))
    }
}
