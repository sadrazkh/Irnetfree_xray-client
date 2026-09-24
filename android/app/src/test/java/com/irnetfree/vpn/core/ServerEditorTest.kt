package com.irnetfree.vpn.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The edit sheet saves every field it shows, every time — so whatever it does
 * not show must come through a save untouched. It used to rebuild the outbound
 * from the form alone: renaming a REALITY + Vision config wrote `flow: ""` and
 * killed it, a TCP + HTTP-header config became plain TCP, h2 lost its host and
 * path. The desktop's applyServerEdits patches a clone; so does this now.
 */
class ServerEditorTest {
    /** What the sheet does: read the fields, let the user change some, save. */
    private fun save(s: ServerConfig, edit: (ServerEditor.Fields) -> Unit = {}): ServerConfig {
        val f = ServerEditor.read(s); edit(f); return ServerEditor.apply(s, f)
    }
    private fun stream(s: ServerConfig) = s.outbound.getJSONObject("streamSettings")

    @Test fun renamingARealityVisionConfigKeepsItsFlow() {
        val s = LinkParser.parseLink("vless://uuid@h.example:443?security=reality&sni=www.google.com&fp=chrome&pbk=PBK&sid=ab12&type=tcp&flow=xtls-rprx-vision&spx=%2F#r")
        val before = Canon.of(s.outbound)
        val out = save(s) { it.name = "renamed" }
        assertEquals("renamed", out.name)
        assertEquals("xtls-rprx-vision", out.outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
            .getJSONArray("users").getJSONObject(0).getString("flow"))
        assertEquals(before, Canon.of(out.outbound))
        assertEquals("the stored record is never touched", before, Canon.of(s.outbound))
    }

    @Test fun renamingATcpHttpHeaderConfigKeepsTheHeader() {
        val s0 = LinkParser.parseLink("vless://u@h.example:80?type=tcp&headerType=http&host=example.com&path=%2Fx&security=none#h")
        // what a panel's config carries beyond what a link can say
        val ob = JSONObject(s0.outbound.toString())
        val req = ob.getJSONObject("streamSettings").getJSONObject("tcpSettings").getJSONObject("header").getJSONObject("request")
        req.put("method", "GET"); req.getJSONObject("headers").put("User-Agent", org.json.JSONArray().put("Mozilla/5.0"))
        val s = s0.copy(outbound = ob)
        val out = save(s) { it.name = "renamed" }
        assertEquals(Canon.of(s.outbound), Canon.of(out.outbound))
        // editing the path changes the path and nothing else in the header
        val moved = save(s) { it.path = "/y" }
        val h = stream(moved).getJSONObject("tcpSettings").getJSONObject("header")
        assertEquals("http", h.getString("type"))
        assertEquals("""["/y"]""", h.getJSONObject("request").getJSONArray("path").toString())
        assertEquals("GET", h.getJSONObject("request").getString("method"))
        assertEquals("""["example.com"]""", h.getJSONObject("request").getJSONObject("headers").getJSONArray("Host").toString())
    }

    @Test fun renamingAnH2ConfigKeepsHostAndPath() {
        val s = LinkParser.parseLink("trojan://p@h.example:443?type=h2&host=a.com,b.com&path=%2Fp&sni=a.com#h2")
        val out = save(s) { it.name = "renamed" }
        assertEquals(Canon.of(s.outbound), Canon.of(out.outbound))
        val hs = stream(out).getJSONObject("httpSettings")
        assertEquals("/p", hs.getString("path")); assertEquals("""["a.com","b.com"]""", hs.getJSONArray("host").toString())
    }

    @Test fun vmessKeepsItsAlterIdAndCipher() {
        val ob = JSONObject("""{"protocol":"vmess","settings":{"vnext":[{"address":"v.example","port":443,"users":[{"id":"U","alterId":64,"security":"aes-128-gcm"}]}]},
            "streamSettings":{"network":"ws","security":"tls","wsSettings":{"path":"/v","headers":{"Host":"v.example"}},
            "tlsSettings":{"serverName":"v.example","allowInsecure":false,"fingerprint":"chrome"}}}""")
        val s = ServerConfig("s-1", "vm", "vmess", "v.example", 443, ob)
        val out = save(s) { it.name = "renamed" }
        assertEquals(Canon.of(s.outbound), Canon.of(out.outbound))
        val moved = save(s) { it.address = "w.example"; it.port = "8443" }
        val vnext = moved.outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
        assertEquals("w.example", vnext.getString("address")); assertEquals(8443, vnext.getInt("port"))
        assertEquals(64, vnext.getJSONArray("users").getJSONObject(0).getInt("alterId"))
        assertEquals("w.example", moved.address); assertEquals(8443, moved.port)
    }

    @Test fun editingTheSniChangesOnlyTheSni() {
        val s0 = LinkParser.parseLink("vless://u@h.example:443?type=ws&path=%2Fws&host=cdn.example&security=tls&sni=cdn.example&fp=firefox&alpn=h2,http/1.1#w")
        val ob = JSONObject(s0.outbound.toString())
        ob.getJSONObject("streamSettings").getJSONObject("wsSettings").put("heartbeatPeriod", 30)
        ob.getJSONObject("streamSettings").put("sockopt", JSONObject().put("tcpFastOpen", true))
        val s = s0.copy(outbound = ob)
        val out = save(s) { it.sni = "other.example" }
        val tls = stream(out).getJSONObject("tlsSettings")
        assertEquals("other.example", tls.getString("serverName"))
        assertEquals("firefox", tls.getString("fingerprint"))
        assertEquals("""["h2","http/1.1"]""", tls.getJSONArray("alpn").toString())
        assertEquals(30, stream(out).getJSONObject("wsSettings").getInt("heartbeatPeriod"))
        assertTrue(stream(out).getJSONObject("sockopt").getBoolean("tcpFastOpen"))
    }

    @Test fun changingTheTransportReplacesItsSettings() {
        val s = LinkParser.parseLink("vless://u@h.example:443?type=ws&path=%2Fws&host=cdn.example&security=tls&sni=cdn.example#w")
        val out = save(s) { it.network = "grpc"; it.path = "svc" }
        assertEquals("grpc", stream(out).getString("network"))
        assertFalse(stream(out).has("wsSettings"))
        assertEquals("svc", stream(out).getJSONObject("grpcSettings").getString("serviceName"))
        assertEquals("cdn.example", stream(out).getJSONObject("tlsSettings").getString("serverName"))
    }

    @Test fun clearingTheFragmentRemovesIt() {
        val s = LinkParser.parseLink("vless://u@h.example:443?security=tls&sni=a.com&fragment=tlshello%2C100-200%2C10-20#f")
        assertEquals("tlshello,100-200,10-20", s.outbound.getString("_fragment"))
        assertEquals("tlshello,100-200,10-20", save(s) { it.name = "x" }.outbound.getString("_fragment"))
        assertFalse(save(s) { it.fragment = "" }.outbound.has("_fragment"))
    }

    /** The owner's corporate WireGuard: a hostname endpoint, split AllowedIPs, its own DNS. */
    @Test fun aWireGuardEditKeepsWhatTheFormDoesNotShow() {
        val s0 = LinkParser.parseLink("wireguard://PRIV@cobra.tes.ca:42421?publickey=PUB&address=10.10.10.42&allowedips=192.168.0.0%2F16%2C10.0.0.0%2F8&mtu=1420&dns=192.168.60.1%2Ctes.systems#corp")
        val ob = JSONObject(s0.outbound.toString())
        ob.getJSONObject("settings").put("workers", 2)
        ob.getJSONObject("settings").getJSONArray("peers").getJSONObject(0).put("keepAlive", 25)
        val s = s0.copy(outbound = ob)
        val renamed = save(s) { it.name = "Tes WG" }
        assertEquals(Canon.of(s.outbound), Canon.of(renamed.outbound))
        assertEquals(listOf("192.168.60.1"), renamed.dns); assertEquals(listOf("tes.systems"), renamed.dnsDomains)
        val mtu = save(s) { it.wgMtu = "1280" }
        val set = mtu.outbound.getJSONObject("settings")
        assertEquals(1280, set.getInt("mtu")); assertEquals(2, set.getInt("workers"))
        val peer = set.getJSONArray("peers").getJSONObject(0)
        assertEquals(25, peer.getInt("keepAlive")); assertEquals("cobra.tes.ca:42421", peer.getString("endpoint"))
        assertEquals("""["192.168.0.0/16","10.0.0.0/8"]""", peer.getJSONArray("allowedIPs").toString())
    }
}
