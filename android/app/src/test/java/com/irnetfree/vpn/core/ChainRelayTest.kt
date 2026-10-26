package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The chain relay (ConfigBuilder.relayHopDials, the desktop's tests/chainRelay.test.js):
 * a TCP dial through a hop rides a loopback SOCKS inbound locked with the
 * session's password, routed by account to the hop; a WireGuard keeps its
 * dialerProxy; no port or no password: the config of before.
 */
class ChainRelayTest {
    private fun vless(id: String, host: String, network: String = "ws"): ServerConfig {
        val ob = JSONObject().put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(JSONObject().put("address", host).put("port", 443)
                .put("users", JSONArray().put(JSONObject().put("id", "u-$id").put("encryption", "none"))))))
            .put("streamSettings", JSONObject().put("network", network).put("security", "tls")
                .put("tlsSettings", JSONObject().put("serverName", host)))
        return ServerConfig(id, id, "vless", host, 443, ob)
    }
    private fun wg(id: String): ServerConfig {
        val ob = JSONObject().put("protocol", "wireguard").put("settings", JSONObject()
            .put("secretKey", "k").put("address", JSONArray().put("10.13.13.2/32")).put("mtu", 1420)
            .put("peers", JSONArray().put(JSONObject().put("publicKey", "p").put("endpoint", "wg.example:51820").put("allowedIPs", JSONArray().put("0.0.0.0/0")))))
            .put("streamSettings", JSONObject().put("sockopt", JSONObject()))
        return ServerConfig(id, id, "wireguard", "wg.example", 51820, ob)
    }
    private val settings = AppSettings(blockAds = false, enableSniffing = false)
    private val auth = LocalAuth("u1d2", "p9f8e7")
    private fun outs(c: JSONObject): List<JSONObject> { val a = c.getJSONArray("outbounds"); return (0 until a.length()).map { i: Int -> a.getJSONObject(i) } }
    private fun tagged(c: JSONObject, tag: String): JSONObject? = outs(c).firstOrNull { o: JSONObject -> o.optString("tag") == tag }
    private fun via(o: JSONObject?): String = o?.optJSONObject("streamSettings")?.optJSONObject("sockopt")?.optString("dialerProxy") ?: ""
    private fun relayIn(c: JSONObject): JSONObject? {
        val a = c.getJSONArray("inbounds")
        return (0 until a.length()).map { i: Int -> a.getJSONObject(i) }.firstOrNull { ib: JSONObject -> ib.optString("tag") == ConfigBuilder.RELAY_IN }
    }

    private val h = vless("h", "cdn.example")
    private val x = vless("x", "de.example", network = "raw")

    @Test fun chain_exitRidesTheRelay_lockedWithTheSessionPassword_routedFirst() {
        val c = ConfigBuilder.build(ConnectionPlan.Chain("c", listOf(h, x)), settings, geoAssets = true, inboundAuth = auth, relayPort = 41600)
        assertEquals("chain-relay~proxy-h0", via(tagged(c, "proxy")))
        assertEquals("", via(tagged(c, "proxy-h0")))
        val relay = tagged(c, "chain-relay~proxy-h0")!!
        assertEquals("socks", relay.getString("protocol"))
        val server = relay.getJSONObject("settings").getJSONArray("servers").getJSONObject(0)
        assertEquals("127.0.0.1", server.getString("address")); assertEquals(41600, server.getInt("port"))
        val user = server.getJSONArray("users").getJSONObject(0)
        assertEquals("proxy-h0", user.getString("user")); assertEquals("p9f8e7", user.getString("pass"))
        val ib = relayIn(c)!!
        assertEquals("127.0.0.1", ib.getString("listen")); assertEquals(41600, ib.getInt("port"))
        val st = ib.getJSONObject("settings")
        assertEquals("password", st.getString("auth")); assertFalse(st.getBoolean("udp")); assertEquals(1, st.getInt("userLevel"))
        assertEquals("p9f8e7", st.getJSONArray("accounts").getJSONObject(0).getString("pass"))
        val first = c.getJSONObject("routing").getJSONArray("rules").getJSONObject(0)
        assertEquals(ConfigBuilder.RELAY_IN, first.getJSONArray("inboundTag").getString(0))
        assertEquals("proxy-h0", first.getJSONArray("user").getString(0))
        assertEquals("proxy-h0", first.getString("outboundTag"))
    }

    @Test fun wireGuardAfterAHop_keepsItsDialerProxy_andNoRelayOpens() {
        val c = ConfigBuilder.build(ConnectionPlan.Chain("c", listOf(h, wg("w"))), settings, geoAssets = true, inboundAuth = auth, relayPort = 41600)
        assertEquals("proxy-h0", via(tagged(c, "proxy")))
        assertNull(relayIn(c))
    }

    @Test fun noPortOrNoPassword_theConfigOfBefore() {
        val plan = ConnectionPlan.Chain("c", listOf(h, x))
        val before = ConfigBuilder.build(plan, settings, geoAssets = true, inboundAuth = auth)
        assertEquals("proxy-h0", via(tagged(before, "proxy")))
        assertNull(relayIn(before))
        val noAuth = ConfigBuilder.build(plan, settings, geoAssets = true, relayPort = 41600)
        assertNull(relayIn(noAuth))
        assertEquals("proxy-h0", via(tagged(noAuth, "proxy")))
        val single = ConfigBuilder.build(ConnectionPlan.Single(x), settings, geoAssets = true, inboundAuth = auth, relayPort = 41600)
        assertNull(relayIn(single))
        assertTrue(outs(single).none { o: JSONObject -> o.optString("tag").startsWith("chain-relay") })
    }

    @Test fun aPortTheConfigAlreadyListensOn_noRelay() {
        val c = ConfigBuilder.build(ConnectionPlan.Chain("c", listOf(h, x)), settings, geoAssets = true, inboundAuth = auth, relayPort = settings.socksPort)
        assertNull(relayIn(c))
        assertEquals("proxy-h0", via(tagged(c, "proxy")))
    }
}
