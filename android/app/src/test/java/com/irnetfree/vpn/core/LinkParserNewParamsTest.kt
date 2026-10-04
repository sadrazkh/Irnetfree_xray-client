package com.irnetfree.vpn.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * The newer link parameters and protocols against the desktop's pins
 * (tests/parser.test.js — "newer link parameters", "Shadowsocks plugins",
 * "Hysteria2"): ech, pcs, vcn, pqv, the hysteria spellings of insecure, gRPC
 * authority, mKCP mtu, vmess' second values, SIP002 plugins, hysteria2://.
 */
class LinkParserNewParamsTest {
    /** A well-formed ML-DSA-65 key: 1952 bytes as unpadded base64url. */
    private val PQV = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(1952) { 7 })
    private fun st(link: String): JSONObject = LinkParser.parseLink(link).outbound.getJSONObject("streamSettings")
    private fun tls(link: String): JSONObject = st(link).getJSONObject("tlsSettings")

    @Test fun echKeepsTheDnsFormVerbatim() {
        val s = LinkParser.parseLink("vless://cd5539e6-96b9-4daf-a09d-0d2a59804129@104.21.44.18:2087?encryption=none&type=ws&host=ircd-uk.irnetfree.xyz&path=/&security=tls&fp=firefox&sni=ircd-uk.irnetfree.xyz&ech=cloudflare-ech.com+udp://1.1.1.1#%F0%9F%87%AC%F0%9F%87%A7-1")
        val t = s.outbound.getJSONObject("streamSettings").getJSONObject("tlsSettings")
        assertEquals("cloudflare-ech.com+udp://1.1.1.1", t.getString("echConfigList"))
        assertEquals("ircd-uk.irnetfree.xyz", t.getString("serverName"))
        assertEquals("firefox", t.getString("fingerprint"))
        assertEquals("cloudflare-ech.com+https://1.1.1.1/dns-query",
            tls("vless://u@a.example.com:443?security=tls&ech=cloudflare-ech.com%2Bhttps%3A%2F%2F1.1.1.1%2Fdns-query").getString("echConfigList"))
        assertEquals("AEX+/==", tls("trojan://pw@a.example.com:443?ech=AEX%2B%2F%3D%3D").getString("echConfigList"))
        assertFalse(st("vless://u@a.example.com:443?security=reality&ech=x").has("tlsSettings"))
    }

    @Test fun pinsAreNormalisedAndMalformedOnesDropped() {
        val pin = "AB:CD:" + "ef".repeat(30)
        assertEquals("abcd" + "ef".repeat(30), tls("vless://u@a.example.com:443?security=tls&pcs=" + java.net.URLEncoder.encode(pin, "UTF-8")).getString("pinnedPeerCertSha256"))
        assertEquals("a".repeat(64) + "," + "b".repeat(64), tls("trojan://pw@a.example.com:443?pcs=${"a".repeat(64)},nothex,${"b".repeat(64)}").getString("pinnedPeerCertSha256"))
        assertFalse(tls("vless://u@a.example.com:443?security=tls&pcs=1234").has("pinnedPeerCertSha256"))
    }

    @Test fun vcnPqvAndTheInsecureSpellings() {
        assertEquals("real.example,b.example", tls("vless://u@a.example.com:443?security=tls&sni=front.example&vcn=real.example,b.example").getString("verifyPeerCertByName"))
        assertEquals(PQV, st("vless://u@1.2.3.4:443?security=reality&pbk=K&sid=1&pqv=$PQV").getJSONObject("realitySettings").getString("mldsa65Verify"))
        val std = java.util.Base64.getEncoder().encodeToString(ByteArray(1952) { 7 })
        assertEquals(PQV, st("vless://u@1.2.3.4:443?security=reality&pbk=K&sid=1&pqv=" + java.net.URLEncoder.encode(std, "UTF-8")).getJSONObject("realitySettings").getString("mldsa65Verify"))
        for (bad in listOf("abc", PQV.drop(1), PQV + "A")) assertFalse(st("vless://u@1.2.3.4:443?security=reality&pbk=K&sid=1&pqv=$bad").getJSONObject("realitySettings").has("mldsa65Verify"))
        assertTrue(tls("trojan://pw@a.example.com:443?insecure=1").getBoolean("allowInsecure"))
        assertTrue(tls("trojan://pw@a.example.com:443?allow_insecure=true").getBoolean("allowInsecure"))
        assertFalse(tls("trojan://pw@a.example.com:443?insecure=0").getBoolean("allowInsecure"))
    }

    @Test fun grpcAuthorityKcpMtuAndVmessSecondValues() {
        val g = st("vless://u@g.example.com:443?type=grpc&serviceName=svc&authority=cdn.example&mode=gun").getJSONObject("grpcSettings")
        assertTrue(Canon.same("""{"serviceName":"svc","multiMode":false,"authority":"cdn.example"}""", g))
        val k = st("vless://u@k.example.com:443?type=kcp&headerType=wechat-video&seed=S&mtu=1350").getJSONObject("kcpSettings")
        assertTrue(Canon.same("""{"header":{"type":"wechat-video"},"seed":"S","mtu":1350}""", k))

        fun vm(o: String) = LinkParser.vmessFromJson(JSONObject("""{"v":"2","ps":"M","add":"m.example.com","port":"443","id":"u",$o}"""), "vmess://x").outbound.getJSONObject("streamSettings")
        assertTrue(Canon.same("""{"serviceName":"svc","multiMode":true,"authority":"auth.example"}""",
            vm(""""net":"grpc","type":"multi","host":"auth.example","path":"svc","tls":"tls","sni":"s.example"""").getJSONObject("grpcSettings")))
        assertTrue(Canon.same("""{"header":{"type":"srtp"},"seed":"SEED"}""", vm(""""net":"kcp","type":"srtp","path":"SEED"""").getJSONObject("kcpSettings")))
        assertEquals("stream-one", vm(""""net":"xhttp","type":"stream-one","path":"/x","host":"h.example"""").getJSONObject("xhttpSettings").getString("mode"))
        val t = vm(""""net":"ws","tls":"tls","insecure":"1","ech":"e.example+udp://1.1.1.1","pcs":"${"c".repeat(64)}","vcn":"n.example"""").getJSONObject("tlsSettings")
        assertTrue(t.getBoolean("allowInsecure")); assertEquals("e.example+udp://1.1.1.1", t.getString("echConfigList"))
        assertEquals("c".repeat(64), t.getString("pinnedPeerCertSha256")); assertEquals("n.example", t.getString("verifyPeerCertByName"))
    }

    @Test fun shareLinkRoundTrip() {
        for (l in listOf(
            "vless://u@a.example.com:443?type=ws&security=tls&sni=s.example&host=h.example&path=%2F&ech=cloudflare-ech.com%2Budp%3A%2F%2F1.1.1.1&pcs=${"d".repeat(64)}&vcn=v.example#A",
            "vless://u@1.2.3.4:443?security=reality&sni=r.example&pbk=K&sid=ab&pqv=$PQV#B",
            "trojan://pw@g.example.com:443?type=grpc&serviceName=svc&authority=auth.example#C",
            "vless://u@k.example.com:443?type=kcp&headerType=srtp&seed=S&mtu=1350#D"
        )) {
            val a = LinkParser.parseLink(l)
            assertEquals(l, Canon.of(a.outbound), Canon.of(LinkParser.parseLink(LinkParser.buildShareLink(a)).outbound))
        }
    }

    @Test fun ssObfsAndV2rayPluginBecomeTransports() {
        val obfs = LinkParser.parseLink("ss://aes-256-gcm:pw@o.example.com:8388/?plugin=" + java.net.URLEncoder.encode("obfs-local;obfs=http;obfs-host=www.bing.com", "UTF-8").replace("+", "%20") + "#O")
        assertTrue(Canon.same("""{"network":"tcp","security":"none","tcpSettings":{"header":{"type":"http","request":{"path":["/"],"headers":{"Host":["www.bing.com"]}}}}}""",
            obfs.outbound.getJSONObject("streamSettings")))
        val v2 = LinkParser.parseLink("ss://aes-256-gcm:pw@v.example.com:443?plugin=" + java.net.URLEncoder.encode("v2ray-plugin;mode=websocket;tls;host=cdn.example.com;path=/ws\\;x", "UTF-8") + "#V")
        val s = v2.outbound.getJSONObject("streamSettings")
        assertEquals("ws", s.getString("network")); assertEquals("tls", s.getString("security"))
        assertEquals("/ws;x", s.getJSONObject("wsSettings").getString("path"))
        assertEquals("cdn.example.com", s.getJSONObject("tlsSettings").getString("serverName"))
        assertEquals("v2ray-plugin;mode=websocket;tls;host=cdn.example.com;path=/ws\\;x;mux=0", LinkParser.ssPluginOf(s))
        assertEquals("obfs-local;obfs=http;obfs-host=www.bing.com", LinkParser.ssPluginOf(obfs.outbound.getJSONObject("streamSettings")))
        assertTrue(Canon.same("""{"network":"tcp"}""", LinkParser.parseLink("ss://aes-256-gcm:pw@p.example.com:8388#P").outbound.getJSONObject("streamSettings")))
    }

    @Test fun ssPluginsTheCoreCannotCarryAreRefusedByName() {
        for ((plugin, word) in listOf("obfs-local;obfs=tls;obfs-host=x" to "obfs=tls", "v2ray-plugin;mode=quic" to "mode=quic",
                "v2ray-plugin;mux=4" to "mux", "shadow-tls" to "shadow-tls")) {
            try {
                LinkParser.parseLink("ss://aes-256-gcm:pw@a.example.com:8388/?plugin=" + java.net.URLEncoder.encode(plugin, "UTF-8") + "#A")
                fail("$plugin imported")
            } catch (e: IllegalArgumentException) { assertTrue("${e.message}", (e.message ?: "").contains(word)) }
        }
    }

    @Test fun hysteria2BecomesTheCoresHysteriaOutbound() {
        val s = LinkParser.parseLink("hysteria2://p%40ss@h.example.com:8443/?sni=s.example&insecure=1&obfs=salamander&obfs-password=OB&alpn=h3#%F0%9F%9A%80%20H")
        assertEquals("hysteria2", s.protocol); assertEquals("🚀 H", s.name); assertEquals("h.example.com", s.address); assertEquals(8443, s.port)
        assertTrue(Canon.same("""{"protocol":"hysteria","settings":{"version":2,"address":"h.example.com","port":8443},
            "streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"s.example","allowInsecure":true,"alpn":["h3"]},
            "hysteriaSettings":{"version":2,"auth":"p@ss"},"finalmask":{"udp":[{"type":"salamander","settings":{"password":"OB"}}]}}}""", s.outbound))
        val p = LinkParser.parseLink("hy2://pw@h.example.com:443?pinSHA256=" + "AB:".repeat(31) + "AB&ech=AEXX#H").outbound.getJSONObject("streamSettings").getJSONObject("tlsSettings")
        assertEquals("h.example.com", p.getString("serverName")); assertEquals("ab".repeat(32), p.getString("pinnedPeerCertSha256"))
        assertEquals("AEXX", p.getString("echConfigList")); assertFalse(p.has("fingerprint"))
        assertEquals("", LinkParser.parseLink("hy2://pw@1.2.3.4:443").outbound.getJSONObject("streamSettings").getJSONObject("tlsSettings").getString("serverName"))
    }

    @Test fun hysteria2PortHoppingAndBandwidth() {
        val a = LinkParser.parseLink("hysteria2://pw@h.example.com:20000-30000/?obfs=salamander&obfs-password=X#A")
        assertEquals(20000, a.port)
        assertTrue(Canon.same("""{"udp":[{"type":"salamander","settings":{"password":"X"}},
            {"type":"udphop","settings":{"mode":"intervalLocal,intervalRemote","interval":"30","remotePorts":"20000-30000"}}]}""",
            a.outbound.getJSONObject("streamSettings").getJSONObject("finalmask")))
        val b = LinkParser.parseLink("hysteria2://pw@h.example.com:443/?mport=443,5000:6000#B")
        assertEquals("443,5000-6000", b.outbound.getJSONObject("streamSettings").getJSONObject("finalmask").getJSONArray("udp").getJSONObject(0).getJSONObject("settings").getString("remotePorts"))
        val c = LinkParser.parseLink("hysteria2://pw@h.example.com:443/?up=50&down=200%20mbps#C")
        assertTrue(Canon.same("""{"quicParams":{"brutalUp":"50 mbps","brutalDown":"200 mbps"}}""", c.outbound.getJSONObject("streamSettings").getJSONObject("finalmask")))
        assertFalse(LinkParser.parseLink("hysteria2://pw@h.example.com:443/?mport=junk").outbound.getJSONObject("streamSettings").has("finalmask"))
    }

    @Test fun hysteria2ShareLinkRoundTripAndAnEdit() {
        val s = LinkParser.parseLink("hysteria2://pw@h.example.com:443/?sni=s.example&insecure=1&obfs=salamander&obfs-password=OB&mport=20000-30000&ech=e.example%2Budp%3A%2F%2F1.1.1.1&pinSHA256=" + "c".repeat(64) + "#H")
        assertEquals(Canon.of(s.outbound), Canon.of(LinkParser.parseLink(LinkParser.buildShareLink(s)).outbound))
        val f = ServerEditor.read(s)
        assertEquals(listOf("pw", "s.example", "OB", "20000-30000", "e.example+udp://1.1.1.1", "c".repeat(64)), listOf(f.cred, f.sni, f.hy2Obfs, f.hy2Ports, f.ech, f.pcs))
        assertTrue(f.allowInsecure)
        // nothing changed: nothing recorded, nothing rewritten
        val same = ServerEditor.apply(s, ServerEditor.read(s))
        assertEquals(Canon.of(s.outbound), Canon.of(same.outbound)); assertEquals(emptyList<String>(), same.edited)
        // a new address, password and obfs password; hopping and the pin cleared
        val g = ServerEditor.read(s).apply { address = "5.6.7.8"; port = "8443"; cred = "NEW"; hy2Obfs = "OB2"; hy2Ports = ""; pcs = "" }
        val ed = ServerEditor.apply(s, g)
        assertTrue(Canon.same("""{"version":2,"address":"5.6.7.8","port":8443}""", ed.outbound.getJSONObject("settings")))
        val es = ed.outbound.getJSONObject("streamSettings")
        assertEquals("NEW", es.getJSONObject("hysteriaSettings").getString("auth"))
        assertTrue(Canon.same("""{"udp":[{"type":"salamander","settings":{"password":"OB2"}}]}""", es.getJSONObject("finalmask")))
        assertFalse(es.getJSONObject("tlsSettings").has("pinnedPeerCertSha256"))
        assertEquals("e.example+udp://1.1.1.1", es.getJSONObject("tlsSettings").getString("echConfigList"))
        assertEquals(listOf("address", "cred", "hy2Obfs", "hy2Ports", "pcs", "port"), ed.edited.sorted())
    }

    @Test fun anEditKeepsTheNewTlsKnobsItDoesNotTouch() {
        val s = LinkParser.parseLink("vless://u@a.example.com:443?type=grpc&serviceName=svc&authority=auth.example&security=tls&sni=s.example&ech=e.example%2Budp%3A%2F%2F1.1.1.1&pcs=" + "a".repeat(64) + "&vcn=v.example#A")
        val f = ServerEditor.read(s)
        assertEquals("auth.example", f.host)
        assertEquals("e.example+udp://1.1.1.1", f.ech)
        val renamed = ServerEditor.apply(s, ServerEditor.read(s).apply { name = "B" })
        assertEquals(Canon.of(s.outbound), Canon.of(renamed.outbound))
        val other = ServerEditor.apply(s, ServerEditor.read(s).apply { sni = "other.example" }).outbound.getJSONObject("streamSettings")
        assertEquals("e.example+udp://1.1.1.1", other.getJSONObject("tlsSettings").getString("echConfigList"))
        assertEquals("auth.example", other.getJSONObject("grpcSettings").getString("authority"))
        val ech = ServerEditor.apply(s, ServerEditor.read(s).apply { this.ech = "AEXX"; pcs = "" })
        val t = ech.outbound.getJSONObject("streamSettings").getJSONObject("tlsSettings")
        assertEquals("AEXX", t.getString("echConfigList")); assertFalse(t.has("pinnedPeerCertSha256"))
        assertEquals(listOf("ech", "pcs"), ech.edited.sorted())
        val auth = ServerEditor.apply(s, ServerEditor.read(s).apply { host = "new.example" })
        assertEquals("new.example", auth.outbound.getJSONObject("streamSettings").getJSONObject("grpcSettings").getString("authority"))
        val r = LinkParser.parseLink("vless://u@1.2.3.4:443?security=reality&sni=r.example&pbk=K&sid=ab&pqv=$PQV#B")
        assertEquals(PQV, ServerEditor.apply(r, ServerEditor.read(r).apply { sni = "x.example" }).outbound.getJSONObject("streamSettings").getJSONObject("realitySettings").getString("mldsa65Verify"))
        assertNull(ServerEditor.apply(r, ServerEditor.read(r).apply { pqv = "" }).outbound.getJSONObject("streamSettings").getJSONObject("realitySettings").optString("mldsa65Verify").ifEmpty { null })
    }

    @Test fun pinsWantsPinAndTheInsecureCore() {
        assertTrue(CertPin.wantsPin(LinkParser.parseLink("trojan://pw@a.example.com:443?allowInsecure=1")))
        assertFalse(CertPin.wantsPin(LinkParser.parseLink("trojan://pw@a.example.com:443?allowInsecure=1&pcs=" + "ab".repeat(32))))
        assertFalse(CertPin.wantsPin(LinkParser.parseLink("trojan://pw@a.example.com:443?allowInsecure=1&vcn=real.example")))
        assertFalse(CertPin.wantsPin(LinkParser.parseLink("hysteria2://pw@h.example.com:443?insecure=1")))
        val hy = LinkParser.parseLink("hysteria2://pw@h.example.com:443?insecure=1")
        assertEquals(EngineChoice.SINGBOX, EngineChoice.chooseEngine(ConnectionPlan.Single(hy)))
        assertEquals(EngineChoice.PATTN, EngineChoice.chooseEngine(ConnectionPlan.Single(hy.copy(engine = EngineChoice.PATTN))))
        assertEquals(EngineChoice.XRAY, EngineChoice.chooseEngine(ConnectionPlan.Single(LinkParser.parseLink("hysteria2://pw@h.example.com:443?insecure=1&pinSHA256=" + "ab".repeat(32)))))
        assertEquals(EngineChoice.XRAY, EngineChoice.chooseEngine(ConnectionPlan.Single(hy.copy(certPin = "cd".repeat(32)))))
    }

    @Test fun reviewRound() {
        fun qp(q: String) = LinkParser.parseLink("hysteria2://pw@h.example.com:443/?$q").outbound.getJSONObject("streamSettings").optJSONObject("finalmask")?.optJSONObject("quicParams")
        assertNull(qp("up=100kbps&down=100ps"))
        assertTrue(Canon.same("""{"brutalDown":"600kbps"}""", qp("up=0.4&down=600kbps")))
        assertTrue(Canon.same("""{"brutalUp":"1gbps","brutalDown":"0.5 mbps"}""", qp("up=1gbps&down=0.5")))
        assertEquals("xray-pattn", LinkParser.parseLink("hysteria2://pw@h.example.com:443/?engine=xray-pattn").engine)
        val h = LinkParser.parseLink("hysteria2://pw@h.example.com:443/?mport=20000-30000&hopInterval=10-20#H")
        assertEquals(Canon.of(h.outbound), Canon.of(LinkParser.parseLink(LinkParser.buildShareLink(h)).outbound))
        assertFalse(LinkParser.buildShareLink(LinkParser.parseLink("hysteria2://pw@h.example.com:443/?mport=20000-30000#H")).contains("hopInterval"))
        val sb = SingboxConfig.build(h, AppSettings()).getJSONArray("outbounds").getJSONObject(0)
        assertEquals("10s", sb.getString("hop_interval"))
        val o = LinkParser.parseLink("ss://aes-256-gcm:pw@o.example.com:8388/?plugin=" + java.net.URLEncoder.encode("obfs-local;obfs=http;obfs-host=b.example;obfs-uri=/x", "UTF-8") + "#O")
        assertEquals("obfs-local;obfs=http;obfs-host=b.example;obfs-uri=/x", LinkParser.ssPluginOf(o.outbound.getJSONObject("streamSettings")))
    }
}
