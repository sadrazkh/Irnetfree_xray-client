package com.irnetfree.vpn.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The newer link features in sing-box's terms, against the desktop's pins
 * (tests/singboxBuilder.test.js; every shape there passed `sing-box check`, 1.13.14),
 * and the pin merge of ConfigBuilder (tests/configBuilder.test.js).
 */
class SingboxNewFeaturesTest {
    private val s = AppSettings()
    private fun out(link: String): JSONObject = SingboxConfig.build(LinkParser.parseLink(link), s).getJSONArray("outbounds").getJSONObject(0)

    @Test fun echTheDnsFormAndBase64() {
        val o = out("vless://u@104.21.44.18:2087?type=ws&host=h.example&path=/&security=tls&fp=firefox&sni=h.example&ech=cloudflare-ech.com+udp://1.1.1.1#x")
        assertTrue(Canon.same("""{"enabled":true,"query_server_name":"cloudflare-ech.com"}""", o.getJSONObject("tls").getJSONObject("ech")))
        assertTrue(Canon.same("""{"enabled":true,"config":["-----BEGIN ECH CONFIGS-----","AEXX","-----END ECH CONFIGS-----"]}""",
            out("trojan://pw@a.example.com:443?ech=AEXX").getJSONObject("tls").getJSONObject("ech")))
        assertFalse(out("trojan://pw@a.example.com:443").getJSONObject("tls").has("ech"))
    }

    @Test fun pcsAndVcnSkipTheCheckOnSingbox() {
        assertTrue(out("trojan://pw@a.example.com:443?pcs=" + "ab".repeat(32)).getJSONObject("tls").getBoolean("insecure"))
        assertTrue(out("trojan://pw@a.example.com:443?vcn=real.example").getJSONObject("tls").getBoolean("insecure"))
        assertFalse(out("trojan://pw@a.example.com:443").getJSONObject("tls").has("insecure"))
    }

    @Test fun hysteria2() {
        val o = out("hysteria2://p%40ss@h.example.com:20000-30000/?sni=s.example&obfs=salamander&obfs-password=OB&insecure=1&up=50&down=100&mport=20000-30000,443")
        assertTrue(Canon.same("""{"type":"hysteria2","tag":"proxy","server":"h.example.com","password":"p@ss",
            "server_ports":["20000:30000","443:443"],"hop_interval":"30s","obfs":{"type":"salamander","password":"OB"},"up_mbps":50,"down_mbps":100,
            "tls":{"enabled":true,"server_name":"s.example","insecure":true}}""", o))
        assertTrue(Canon.same("""{"type":"hysteria2","tag":"proxy","server":"h.example.com","server_port":443,"password":"pw","tls":{"enabled":true,"server_name":"h.example.com"}}""",
            out("hy2://pw@h.example.com:443")))
    }

    @Test fun wsEarlyDataHttpupgradeFragmentAndSsPlugins() {
        assertTrue(Canon.same("""{"type":"ws","path":"/ws","max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol","headers":{"Host":"w.example.com"}}""",
            out("vless://u@w.example.com:443?type=ws&security=tls&path=%2Fws%3Fed%3D2048&host=w.example.com").getJSONObject("transport")))
        assertTrue(Canon.same("""{"type":"httpupgrade","host":"u.example.com","path":"/up"}""",
            out("vless://u@u.example.com:443?type=httpupgrade&security=tls&path=%2Fup&host=u.example.com").getJSONObject("transport")))
        assertTrue(out("vless://u@u.example.com:443?security=tls&fragment=tlshello,100-200,10-20").getJSONObject("tls").getBoolean("fragment"))
        val v2 = out("ss://aes-256-gcm:pw@v.example.com:443/?plugin=" + java.net.URLEncoder.encode("v2ray-plugin;tls;host=cdn.example.com;path=/ws", "UTF-8"))
        assertEquals("v2ray-plugin", v2.getString("plugin")); assertEquals("mode=websocket;tls;host=cdn.example.com;path=/ws;mux=0", v2.getString("plugin_opts"))
        assertFalse(v2.has("tls"))
        try { out("vless://u@a.example.com:443?type=tcp&headerType=http&host=x.example"); fail("tcp http header translated") }
        catch (e: SingboxConfig.Unsupported) { assertTrue((e.message ?: "").contains("HTTP header")) }
    }

    @Test fun aLatencyTestAsksForSocksAlone() {
        val c = SingboxConfig.build(LinkParser.parseLink("hy2://pw@h.example.com:443"), s.copy(socksPort = 20808, httpPort = 0))
        assertEquals(1, c.getJSONArray("inbounds").length())
        assertEquals(20808, c.getJSONArray("inbounds").getJSONObject(0).getInt("listen_port"))
    }

    @Test fun theLinksPinAndTheLearntOneAreEmittedTogether() {
        val PIN = "ab11bf7ac877baa539294f5a3c864b8ed43e6fe3a9a8230fc2db7fff85c27fde"
        val srv = LinkParser.parseLink("trojan://pw@a.example.com:443?pcs=" + "cd".repeat(32)).copy(certPin = PIN)
        val tls = ConfigBuilder.buildTestConfig(srv, 1080).getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings").getJSONObject("tlsSettings")
        assertEquals("cd".repeat(32) + "," + PIN, tls.getString("pinnedPeerCertSha256"))
        assertFalse(tls.has("allowInsecure"))
    }
}
