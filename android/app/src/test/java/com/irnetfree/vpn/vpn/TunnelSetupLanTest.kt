package com.irnetfree.vpn.vpn

import com.irnetfree.vpn.core.AppSettings
import com.irnetfree.vpn.core.Canon
import com.irnetfree.vpn.core.ConfigBuilder
import com.irnetfree.vpn.core.ConnectionPlan
import com.irnetfree.vpn.core.EngineChoice
import com.irnetfree.vpn.core.LanShare
import com.irnetfree.vpn.core.LocalAuth
import com.irnetfree.vpn.core.PoolEntry
import com.irnetfree.vpn.core.RouteRule
import com.irnetfree.vpn.core.ServerConfig
import com.irnetfree.vpn.core.SingboxConfig
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket

/**
 * LAN sharing on every core, and the pieces of it that do not need a device:
 * which config each engine gets, stripping sharing off a config whose port
 * turned out taken, the phone's LAN addresses and the URLs handed out.
 */
class TunnelSetupLanTest {
    private val session = LocalAuth("u1d2", "p9f8e7")
    private val share = LanShare(enabled = true, user = "irnf-ab12", pass = "k7p2m9x4q3w8")
    private fun vless(id: String): ServerConfig {
        val ob = JSONObject().put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(JSONObject().put("address", "$id.example").put("port", 443)
                .put("users", JSONArray().put(JSONObject().put("id", "u-$id").put("encryption", "none"))))))
            .put("streamSettings", JSONObject().put("network", "ws").put("security", "tls")
                .put("tlsSettings", JSONObject().put("serverName", "$id.example")))
        return ServerConfig(id, id, "vless", "$id.example", 443, ob)
    }
    private fun wg(): ServerConfig {
        val ob = JSONObject().put("protocol", "wireguard").put("settings", JSONObject()
            .put("secretKey", "k").put("address", JSONArray().put("10.13.13.2/32"))
            .put("peers", JSONArray().put(JSONObject().put("publicKey", "p").put("endpoint", "51.222.52.23:42421").put("allowedIPs", JSONArray().put("0.0.0.0/0")))))
        return ServerConfig("w", "w", "wireguard", "51.222.52.23", 42421, ob)
    }
    private val a = vless("a")
    private val b = vless("b")
    private val s = AppSettings(blockAds = false)
    private fun tags(c: JSONObject): List<String> { val arr = c.getJSONArray("inbounds"); return (0 until arr.length()).map { arr.getJSONObject(it).getString("tag") } }

    /* ---------------- every core ---------------- */

    @Test fun theInProcessCoreAndPattnCarryTheSameConfig_withTheLanInbounds() {
        val logs = ArrayList<String>()
        val x = TunnelSetup.coreConfig(EngineChoice.XRAY, ConnectionPlan.Single(a), s, true, emptyMap(), session, share) { l -> logs.add(l) }
        val p = TunnelSetup.coreConfig(EngineChoice.PATTN, ConnectionPlan.Single(a), s, true, emptyMap(), session, share) { l -> logs.add(l) }
        assertEquals(EngineChoice.XRAY, x.engine); assertEquals(EngineChoice.PATTN, p.engine)
        assertEquals(Canon.of(JSONObject(x.json)), Canon.of(JSONObject(p.json)))
        assertTrue(tags(JSONObject(p.json)).containsAll(listOf("socks-in", "http-in", "lan-socks", "lan-http")))
        // a chain on PattN, too (sing-box never runs one)
        val chain = TunnelSetup.coreConfig(EngineChoice.PATTN, ConnectionPlan.Chain("c", listOf(a, b)), s, true, emptyMap(), session, share) { l -> logs.add(l) }
        assertTrue(tags(JSONObject(chain.json)).containsAll(listOf("lan-socks", "lan-http")))
        assertTrue(logs.isEmpty())
    }

    @Test fun singBoxGetsItsOwnFormat_withTheLanInbounds() {
        val c = TunnelSetup.coreConfig(EngineChoice.SINGBOX, ConnectionPlan.Single(a), s, true, emptyMap(), session, share) { _ -> }
        assertEquals(EngineChoice.SINGBOX, c.engine)
        val j = JSONObject(c.json)
        assertTrue(j.getJSONObject("route").has("final"))
        assertEquals(listOf("socks-in", "http-in", "lan-socks", "lan-http"), tags(j))
    }

    @Test fun aServerSingBoxCannotExpressFallsBackToTheInProcessCore_stillSharing() {
        val logs = ArrayList<String>()
        val c = TunnelSetup.coreConfig(EngineChoice.SINGBOX, ConnectionPlan.Single(wg()), s, true, emptyMap(), session, share) { l -> logs.add(l) }
        assertEquals(EngineChoice.XRAY, c.engine)
        assertTrue(JSONObject(c.json).has("routing"))
        assertTrue(tags(JSONObject(c.json)).containsAll(listOf("lan-socks", "lan-http")))
        assertTrue(logs.joinToString(), logs.single().contains("using the in-process core"))
    }

    /* ---------------- a taken port: the same connection without sharing ---------------- */

    @Test fun strippingSharingGivesBackExactlyTheConfigWithoutIt_everyPlanBothFormats() {
        // Also the proof that LAN sharing changes nothing else: its inbounds,
        // its loopback guard, and its tags beside the tunnel's in a pool rule
        // are the whole difference.
        val plans = listOf<ConnectionPlan>(
            ConnectionPlan.Single(a),
            ConnectionPlan.Chain("c", listOf(a, b)),
            ConnectionPlan.Advanced(listOf(RouteRule("domain", "example.org", "b")), "a", mapOf("a" to a, "b" to b), emptyMap()),
            ConnectionPlan.Pool(listOf(PoolEntry("p1", "P", "b", 60001, 60002, true)), "a", mapOf("a" to a, "b" to b), emptyMap())
        )
        for (plan in plans) for (mode in listOf("global", "bypass-ir")) {
            val st = s.copy(routingMode = mode)
            val with = ConfigBuilder.build(plan, st, geoAssets = true, inboundAuth = session, lan = share)
            val without = ConfigBuilder.build(plan, st, geoAssets = true, inboundAuth = session)
            assertTrue(tags(with).contains("lan-socks"))
            assertEquals("$plan $mode", Canon.of(without), Canon.of(JSONObject(TunnelSetup.withoutLan(with.toString()))))
        }
        val sb = SingboxConfig.build(a, s, session, share)
        assertEquals(Canon.of(SingboxConfig.build(a, s, session)), Canon.of(JSONObject(TunnelSetup.withoutLan(sb.toString()))))
    }

    @Test fun aPortSomeoneHoldsOnAnyInterfaceIsNotFreeForSharing() {
        val taken = ServerSocket()
        taken.bind(InetSocketAddress(InetAddress.getByName(LocalPort.ANY), 0))
        val port = taken.localPort
        try {
            assertFalse(LocalPort.isFree(port, LocalPort.ANY))
            assertFalse(LocalPort.waitFree(port, 300, LocalPort.ANY))
        } finally { taken.close() }
        assertTrue(LocalPort.isFree(port, LocalPort.ANY))
    }

    @Test fun theLanPortProbeAsksBothAtOnceAndNeverWaitsForAPortToFree() {
        // It runs on the tunnel's one worker, where every Cancel queues: two
        // waitFree()s held a "Connecting…" up to four seconds.
        val free = ServerSocket().let { s -> s.bind(InetSocketAddress(InetAddress.getByName(LocalPort.ANY), 0)); val p = s.localPort; s.close(); p }
        val held = ServerSocket()
        held.bind(InetSocketAddress(InetAddress.getByName(LocalPort.ANY), 0))
        try {
            val t0 = System.nanoTime()
            assertEquals(listOf(held.localPort), LocalPort.takenNow(listOf(held.localPort, free, held.localPort), LocalPort.ANY))
            assertTrue("well under a second", (System.nanoTime() - t0) / 1_000_000 < 900)
            val t1 = System.nanoTime()
            assertEquals(listOf(held.localPort), LocalPort.takenNow(listOf(held.localPort), LocalPort.ANY, graceMs = 0L))
            assertEquals(emptyList<Int>(), LocalPort.takenNow(listOf(free), LocalPort.ANY))
            assertTrue("nothing held: no second look", (System.nanoTime() - t1) / 1_000_000 < 500)
        } finally { held.close() }
    }

    /* ---------------- where the other devices point their proxy ---------------- */

    @Test fun theLanAddressesAreWifiHotspotAndTethers_neverTheCarrierOrTheTunnel() {
        val found = listOf(
            "rmnet_data0" to "10.72.14.9",       // the carrier: nobody on a LAN reaches it
            "tun0" to "172.19.0.1",              // our own TUN
            "lo" to "127.0.0.1",
            "swlan0" to "192.168.43.1",          // Samsung's hotspot
            "wlan0" to "192.168.1.23",
            "wlan0" to "169.254.10.1",           // link-local
            "rndis0" to "192.168.42.129",
            "wlan0" to "fe80::1",                // not IPv4
            "ccmni1" to "10.1.2.3",
            "v4-rmnet_data0" to "192.0.0.4"      // 464xlat
        )
        val got = LanAddresses.pick(found)
        assertEquals(listOf("192.168.1.23", "192.168.43.1", "192.168.42.129"), got.map { it.ip })
        assertEquals(listOf("Wi-Fi", "Hotspot", "USB tethering"), got.map { it.kind })
        assertEquals("Hotspot", LanAddresses.kind("ap0"))
        assertEquals("Wi-Fi / hotspot", LanAddresses.kind("wlan1"))
        assertEquals("Bluetooth tethering", LanAddresses.kind("bt-pan"))
    }

    @Test fun theUrlsCarryTheCredentialsOnlyWhenAskedAndEncodeThem() {
        assertEquals("socks5://irnf-ab12:k7p2m9x4q3w8@192.168.1.23:10810", LanAddresses.socksUrl("192.168.1.23", share))
        assertEquals("http://192.168.1.23:10811", LanAddresses.httpUrl("192.168.1.23", share))
        assertEquals("socks5://192.168.1.23:10810", LanAddresses.socksUrl("192.168.1.23", share.copy(auth = false)))
        // a typed password with URL characters in it stays one password
        assertEquals("socks5://me:p%40ss%3Aw%2Frd%25@10.0.0.2:10810", LanAddresses.socksUrl("10.0.0.2", share.copy(user = "me", pass = "p@ss:w/rd%")))
        assertEquals("a-b.c_d~", LanAddresses.pct("a-b.c_d~"))
    }
}
