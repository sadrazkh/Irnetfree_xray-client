package com.irnetfree.vpn.core

import com.irnetfree.vpn.vpn.TunnelSetup
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * TUIC and AnyTLS, which sing-box alone runs: their links and the Xray-shaped
 * record they make (the desktop's shape, field for field), the share link
 * read back, sing-box's outbounds, the core they always run on, the refusals
 * — a pin sing-box cannot keep, a place sing-box cannot go — no pin on first
 * use, the editor, and a sing-box JSON config's tuic / anytls outbounds.
 */
class TuicAnytlsTest {
    private val uuid = "00000000-0000-4000-8000-0000000000c4"
    private val tuicLink = "tuic://$uuid:p%3Aw%40x@q.example.com:8443?sni=s.example&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1&reduce_rtt=1&heartbeat=10#T%201"
    private val anyLink = "anytls://pa%20ss@a.example.com:443?sni=front.example&fp=firefox&alpn=h2,http/1.1&insecure=1#A"
    private val s = AppSettings()
    private fun sb(server: ServerConfig): JSONObject = SingboxConfig.build(server, s).getJSONArray("outbounds").getJSONObject(0)
    private fun server0(o: JSONObject): JSONObject = o.getJSONObject("settings").getJSONArray("servers").getJSONObject(0)
    private fun tls(o: JSONObject): JSONObject = o.getJSONObject("streamSettings").getJSONObject("tlsSettings")

    /* ------------------------------ links ------------------------------ */

    @Test fun aTuicLink_isAnXrayShapedRecord_itsUserinfoSplitAtTheFirstColon() {
        val t = LinkParser.parseLink(tuicLink)
        assertEquals("tuic", t.protocol); assertEquals("T 1", t.name)
        assertEquals("q.example.com", t.address); assertEquals(8443, t.port)
        assertNull(t.engine)
        assertTrue(Canon.of(t.outbound), Canon.same("""{"protocol":"tuic",
            "settings":{"servers":[{"address":"q.example.com","port":8443,"uuid":"$uuid","password":"p:w@x",
              "congestionControl":"bbr","udpRelayMode":"native","zeroRtt":true,"heartbeat":"10s"}]},
            "streamSettings":{"network":"udp","security":"tls","tlsSettings":{"serverName":"s.example","allowInsecure":true,"alpn":["h3"]}}}""", t.outbound))
        // the other spellings; a raw ':' in the password; an IPv6 host (no SNI for an address); nonsense values left empty
        val o = LinkParser.parseLink("tuic://$uuid:a:b@[2001:db8::1]:443?zero_rtt_handshake=1&insecure=1&disable_sni=1&congestion_control=new_reno&udp_relay_mode=x&heartbeat=0").outbound
        val srv = server0(o)
        assertEquals("a:b", srv.getString("password")); assertEquals("2001:db8::1", srv.getString("address"))
        assertEquals("new_reno", srv.getString("congestionControl")); assertEquals("", srv.getString("udpRelayMode"))
        assertEquals("", srv.getString("heartbeat")); assertTrue(srv.getBoolean("zeroRtt"))
        assertTrue(Canon.same("""{"serverName":"","allowInsecure":true,"disableSni":true}""", tls(o)))
        assertEquals("new_reno", server0(LinkParser.parseLink("tuic://$uuid:p@h.example:443?congestion_control=reno").outbound).getString("congestionControl"))
        assertEquals("", server0(LinkParser.parseLink("tuic://$uuid:p@h.example:443?congestion_control=vegas").outbound).getString("congestionControl"))
        // a userinfo encoded whole splits once decoded; no password at all is kept as none
        val whole = server0(LinkParser.parseLink("tuic://$uuid%3Ap%3Aw@h.example:443").outbound)
        assertEquals(uuid, whole.getString("uuid")); assertEquals("p:w", whole.getString("password"))
        assertEquals("", server0(LinkParser.parseLink("tuic://$uuid@h.example:443").outbound).getString("password"))
        // the TLS extras every kind takes — PattN's ECH outbound aside, an Xray outbound sing-box cannot dial through
        val pin = "ab".repeat(32)
        val x = tls(LinkParser.parseLink("tuic://$uuid:p@h.example:443?ech=AEXX&pcs=$pin&vcn=real.example&echOutbound=" +
            java.net.URLEncoder.encode("""{"protocol":"direct"}""", "UTF-8")).outbound)
        assertEquals("AEXX", x.getString("echConfigList")); assertEquals(pin, x.getString("pinnedPeerCertSha256")); assertEquals("real.example", x.getString("verifyPeerCertByName"))
        assertFalse(x.has("echOutbound")); assertEquals("h.example", x.getString("serverName"))
        // no UUID, one that is none (a v4 token), no address: said
        for ((bad, why) in listOf("tuic://token@h.example:443" to "TUIC: the uuid in the link is not a UUID", "tuic://h.example:443" to "TUIC: no uuid in the link",
                "tuic://:pw@h.example:443" to "TUIC: no uuid in the link", "tuic://$uuid:pw@:443" to "tuic: no server address in the link")) {
            try { LinkParser.parseLink(bad); fail(bad) } catch (e: IllegalArgumentException) { assertEquals(bad, why, e.message) }
        }
        assertTrue(LinkParser.isUuid(uuid.uppercase())); assertTrue(LinkParser.isUuid(uuid.replace("-", ""))); assertFalse(LinkParser.isUuid("u"))
        assertEquals("10s", LinkParser.tuicHeartbeat("10")); assertEquals("1m", LinkParser.tuicHeartbeat("1M")); assertEquals("1.5s", LinkParser.tuicHeartbeat("1.5s"))
        assertEquals("500ms", LinkParser.tuicHeartbeat("500ms")); assertEquals("", LinkParser.tuicHeartbeat("0")); assertEquals("", LinkParser.tuicHeartbeat(""))
        assertNull(LinkParser.tuicHeartbeat("soon"))
    }

    @Test fun anAnytlsLink_keepsAFingerprint_chromeUnlessNamed() {
        val a = LinkParser.parseLink(anyLink)
        assertEquals("anytls", a.protocol); assertEquals("A", a.name); assertEquals(443, a.port)
        assertTrue(Canon.of(a.outbound), Canon.same("""{"protocol":"anytls",
            "settings":{"servers":[{"address":"a.example.com","port":443,"password":"pa ss"}]},
            "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"front.example","allowInsecure":true,
              "alpn":["h2","http/1.1"],"fingerprint":"firefox"}}}""", a.outbound))
        // no SNI named: the address; any case of the scheme
        val plain = LinkParser.parseLink("ANYTLS://pw@b.example.com:8443")
        assertEquals("b.example.com", plain.name)
        assertTrue(Canon.same("""{"serverName":"b.example.com","allowInsecure":false,"fingerprint":"chrome"}""", tls(plain.outbound)))
        // the password is the userinfo whole — none is kept as none; no address is said
        assertEquals("", server0(LinkParser.parseLink("anytls://b.example.com:443").outbound).getString("password"))
        try { LinkParser.parseLink("anytls://pw@:443"); fail("no address") } catch (e: IllegalArgumentException) { assertEquals("anytls: no server address in the link", e.message) }
    }

    @Test fun theShareLink_readsBackAsTheSameServer() {
        for (link in listOf(tuicLink, anyLink, "tuic://$uuid:pw@q.example.com:443?disable_sni=1&ech=AEXX#B", "anytls://pw@[2001:db8::2]:8443#C",
                "tuic://$uuid:pw@q.example.com:443?pcs=${"cd".repeat(32)}&vcn=real.example#D", "tuic://$uuid@q.example.com:443#E")) {
            val a = LinkParser.parseLink(link)
            val b = LinkParser.parseLink(LinkParser.buildShareLink(a))
            assertEquals(link, Canon.of(a.outbound), Canon.of(b.outbound))
            assertEquals(link, a.name, b.name); assertEquals(a.protocol, b.protocol); assertEquals(a.address, b.address); assertEquals(a.port, b.port)
        }
        assertEquals("tuic://$uuid:p%3Aw%40x@q.example.com:8443?sni=s.example&alpn=h3&congestion_control=bbr&udp_relay_mode=native&reduce_rtt=1&heartbeat=10s&allow_insecure=1#T%201",
            LinkParser.buildShareLink(LinkParser.parseLink(tuicLink)))
        assertEquals("tuic://$uuid@q.example.com:443?sni=q.example.com#E", LinkParser.buildShareLink(LinkParser.parseLink("tuic://$uuid@q.example.com:443#E")))
        assertEquals("anytls://pw@b.example.com:443?sni=b.example.com&fp=chrome#b.example.com", LinkParser.buildShareLink(LinkParser.parseLink("anytls://pw@b.example.com:443")))
    }

    /* ------------------------------ sing-box ------------------------------ */

    @Test fun singBoxsOwnOutbounds() {
        assertTrue(Canon.same("""{"type":"tuic","tag":"proxy","server":"q.example.com","server_port":8443,"uuid":"$uuid","password":"p:w@x",
            "congestion_control":"bbr","udp_relay_mode":"native","zero_rtt_handshake":true,"heartbeat":"10s",
            "tls":{"enabled":true,"server_name":"s.example","insecure":true,"alpn":["h3"]}}""", sb(LinkParser.parseLink(tuicLink))))
        // nothing named: sing-box's own defaults (no keys); the address as the SNI; QUIC: no uTLS, the ALPN h3
        assertTrue(Canon.same("""{"type":"tuic","tag":"proxy","server":"q.example.com","server_port":443,"uuid":"$uuid","password":"pw",
            "tls":{"enabled":true,"server_name":"q.example.com","alpn":["h3"],"disable_sni":true}}""",
            sb(LinkParser.parseLink("tuic://$uuid:pw@q.example.com:443?disable_sni=1"))))
        // a record whose stream lost its security is still TLS (both speak nothing else)
        val bare = LinkParser.parseLink(anyLink).let { a: ServerConfig ->
            a.copy(outbound = JSONObject(a.outbound.toString()).also { o: JSONObject -> o.getJSONObject("streamSettings").remove("security") })
        }
        assertTrue(sb(bare).getJSONObject("tls").getBoolean("enabled"))
        assertTrue(Canon.same("""{"type":"anytls","tag":"proxy","server":"a.example.com","server_port":443,"password":"pa ss",
            "tls":{"enabled":true,"server_name":"front.example","insecure":true,"alpn":["h2","http/1.1"],"utls":{"enabled":true,"fingerprint":"firefox"}}}""",
            sb(LinkParser.parseLink(anyLink))))
        // ECH as for any server, the same PEM block
        assertTrue(Canon.same("""{"enabled":true,"config":["-----BEGIN ECH CONFIGS-----","AEXX","-----END ECH CONFIGS-----"]}""",
            sb(LinkParser.parseLink("anytls://pw@a.example.com:443?ech=AEXX")).getJSONObject("tls").getJSONObject("ech")))
        assertTrue(sb(LinkParser.parseLink("tuic://$uuid:p@q.example.com:443?ech=cloudflare-ech.com+udp://1.1.1.1")).getJSONObject("tls").getJSONObject("ech").has("query_server_name"))
        // anything but a duration is no heartbeat sing-box takes: left out
        val odd = LinkParser.parseLink(tuicLink).let { t: ServerConfig ->
            t.copy(outbound = JSONObject(t.outbound.toString()).also { o: JSONObject -> server0(o).put("heartbeat", "soon") })
        }
        assertFalse(sb(odd).has("heartbeat"))
    }

    @Test fun alwaysOnSingBox_whateverTheRecordOrTheDefaultSays() {
        val t = LinkParser.parseLink(tuicLink); val a = LinkParser.parseLink(anyLink)
        for (srv in listOf(t, a, t.copy(engine = "xray"), a.copy(engine = "xray-pattn"))) {
            assertTrue(EngineChoice.isSingboxOnly(srv))
            assertEquals(EngineChoice.SINGBOX, EngineChoice.chooseEngine(ConnectionPlan.Single(srv)))
            assertEquals(EngineChoice.SINGBOX, EngineChoice.chooseEngine(ConnectionPlan.Single(srv), EngineChoice.PATTN))
        }
        assertFalse(EngineChoice.isSingboxOnly(LinkParser.parseLink("trojan://pw@a.example.com:443")))
        assertEquals("TUIC", EngineChoice.protocolName(t)); assertEquals("AnyTLS", EngineChoice.protocolName(a))
        // the connect: sing-box's config, the TUIC outbound in it
        val c = TunnelSetup.coreConfig(EngineChoice.SINGBOX, ConnectionPlan.Single(t), s, false, emptyMap(), null, null, log = { _: String -> })
        assertEquals(EngineChoice.SINGBOX, c.engine)
        assertEquals("tuic", JSONObject(c.json).getJSONArray("outbounds").getJSONObject(0).getString("type"))
        // handed any other core, it is refused — never an Xray outbound the core rejects
        try {
            TunnelSetup.coreConfig(EngineChoice.XRAY, ConnectionPlan.Single(a), s, false, emptyMap(), null, null, log = { _: String -> })
            fail("an AnyTLS server built for Xray")
        } catch (e: IllegalStateException) { assertEquals("\"A\" is an AnyTLS server: it runs only on the sing-box core, and this connection is not on it.", e.message) }
        assertEquals("a TUIC server", EngineChoice.serverKind(t))
        // sing-box not bundled for the device: said by name (XrayVpnService.prepare), never handed to Xray
        assertEquals("\"T 1\" is a TUIC server: it runs only on the sing-box core, which is not bundled for this device (arm64 only).",
            EngineChoice.singboxOnlyError(t, EngineChoice.MISSING))
        // a TCP ping of TUIC (QUIC) reaches nothing; AnyTLS is TCP
        assertTrue(Fastest.udpOnly(t)); assertFalse(Fastest.udpOnly(a))
    }

    /* ------------------------------ refusals ------------------------------ */

    @Test fun aPinIsNeverInsecure_andWithNoXrayToFallBackOnTheConnectSaysSo() {
        val pin = "ab".repeat(32)
        for (link in listOf("tuic://$uuid:pw@q.example.com:443?pcs=$pin#P", "anytls://pw@a.example.com:443?vcn=real.example#P")) {
            val srv = LinkParser.parseLink(link)
            assertTrue(SingboxConfig.isPinned(srv))
            try { SingboxConfig.build(srv, s); fail(link) } catch (e: SingboxConfig.Unsupported) { assertTrue((e.message ?: "").contains("certificate is pinned")) }
            try {
                TunnelSetup.coreConfig(EngineChoice.SINGBOX, ConnectionPlan.Single(srv), s, false, emptyMap(), null, null, log = { _: String -> fail("fell back: $link") })
                fail("connected: $link")
            } catch (e: IllegalStateException) { assertEquals(EngineChoice.singboxOnlyError(srv, EngineChoice.PIN), e.message) }
        }
        assertEquals("\"P\" is a TUIC server with a pinned certificate (pcs, vcn or pinned on first use): sing-box, the only core it runs on, " +
            "could check it only by accepting any certificate — remove the pin in its edit sheet to connect.",
            EngineChoice.singboxOnlyError(LinkParser.parseLink("tuic://$uuid:pw@q.example.com:443?pcs=$pin#P"), EngineChoice.PIN))
        assertFalse(SingboxConfig.isPinned(LinkParser.parseLink(tuicLink)))
        // a pin learnt elsewhere (a hand-edited store): refused the same, not insecure
        val learnt = LinkParser.parseLink("tuic://$uuid:pw@q.example.com:443?allow_insecure=1").copy(certPin = "cd".repeat(32))
        try { SingboxConfig.build(learnt, s); fail("a learnt pin translated") } catch (e: SingboxConfig.Unsupported) { assertTrue((e.message ?: "").contains("pinned")) }
    }

    @Test fun inAChainGroupPoolOrProfile_theConfigPathRefusesNamingTheServer() {
        val t = LinkParser.parseLink(tuicLink).copy(id = "t")
        val v = LinkParser.parseLink("vless://$uuid@v.example.com:443?security=tls&sni=v.example.com#V").copy(id = "v")
        val byId = mapOf("t" to t, "v" to v)
        val group = Groups.groupRecord(GroupConfig("grp-1", "G", members = listOf(GroupMember("v"), GroupMember("t"))), byId) ?: throw AssertionError("no group record")
        val plans = listOf(
            ConnectionPlan.Chain("c", listOf(v, t)),
            ConnectionPlan.Single(group),
            ConnectionPlan.Pool(listOf(PoolEntry("e", "e", "t", 30810, 30811, true)), "t", byId, emptyMap()),
            ConnectionPlan.Advanced(listOf(RouteRule("domain", "example.com", "t")), "v", byId, emptyMap()))
        for (plan in plans) {
            assertEquals(plan.toString(), listOf("t"), EngineChoice.singboxOnlyInside(plan).map { x: ServerConfig -> x.id })
            assertEquals(EngineChoice.XRAY, EngineChoice.chooseEngine(plan))
            try {
                TunnelSetup.coreConfig(EngineChoice.chooseEngine(plan), plan, s, false, emptyMap(), null, null, log = { _: String -> })
                fail("built: $plan")
            } catch (e: IllegalStateException) {
                assertEquals("\"T 1\" is a TUIC server: it runs only on its own, on sing-box — not inside a chain, a group, the proxy pool or a routing profile.", e.message)
            }
        }
        // the builder itself never writes one either (a group's latency test goes through it)
        try { ConfigBuilder.build(ConnectionPlan.Chain("c", listOf(v, t)), s); fail("an Xray config with a TUIC hop") }
        catch (e: IllegalStateException) { assertEquals(EngineChoice.singboxOnlyError(t, EngineChoice.PLAN), e.message) }
        try { ConfigBuilder.buildTestConfig(group, 1080); fail("a test config with a TUIC member") }
        catch (e: IllegalStateException) { assertTrue((e.message ?: "").contains("\"T 1\"")) }
        // alone, or not in the plan at all: nothing to refuse
        assertTrue(EngineChoice.singboxOnlyInside(ConnectionPlan.Single(t)).isEmpty())
        assertTrue(EngineChoice.singboxOnlyInside(ConnectionPlan.Chain("c", listOf(v))).isEmpty())
    }

    /* ------------------------------ no first-use pin ------------------------------ */

    @Test fun noPinIsLearnt_theirAllowInsecureIsSingBoxsOwn() {
        val t = LinkParser.parseLink(tuicLink); val a = LinkParser.parseLink(anyLink)
        assertFalse(CertPin.wantsPin(t)); assertFalse(CertPin.wantsPin(a))
        // the TCP + TLS kind beside them still is
        assertTrue(CertPin.wantsPin(LinkParser.parseLink("trojan://pw@a.example.com:443?allowInsecure=1")))
        for (srv in listOf(t, a)) {
            assertTrue(CertPin.learn(ConnectionPlan.Single(srv), 1_000_000_000_000L, fetch = { fail("dialled"); "" }).isEmpty())
            assertFalse(CertPin.recheckDue(srv.copy(certPin = "ab".repeat(32)), now = 1_000_000_000_000L))
            // and sing-box takes it as insecure, on purpose
            assertTrue(sb(srv).getJSONObject("tls").getBoolean("insecure"))
        }
    }

    /* ------------------------------ the editor ------------------------------ */

    @Test fun theEditor_readsAndWritesTuic_andOffersSingBoxAlone() {
        val t = LinkParser.parseLink(tuicLink)
        val f = ServerEditor.read(t)
        assertEquals(uuid, f.cred); assertEquals("p:w@x", f.proxyPass); assertEquals("s.example", f.sni)
        assertTrue(f.allowInsecure); assertEquals("h3", f.alpn); assertEquals(EngineChoice.SINGBOX, f.engine)
        // nothing changed: the record exactly as it was
        assertEquals(Canon.of(t.outbound), Canon.of(ServerEditor.apply(t, ServerEditor.read(t)).outbound))
        // a new password, SNI and ALPN, insecure off: written; the rest kept; no core stored
        f.proxyPass = "n3w"; f.sni = "n.example"; f.alpn = "h3, h2"; f.allowInsecure = false
        val e = ServerEditor.apply(t, f)
        val srv = server0(e.outbound)
        assertEquals("n3w", srv.getString("password")); assertEquals(uuid, srv.getString("uuid")); assertEquals("bbr", srv.getString("congestionControl"))
        assertTrue(Canon.same("""{"serverName":"n.example","allowInsecure":false,"alpn":["h3","h2"]}""", tls(e.outbound)))
        assertEquals("udp", e.outbound.getJSONObject("streamSettings").getString("network"))
        assertNull(e.engine); assertEquals("", e.mux)
        assertTrue(e.edited.toString(), e.edited.containsAll(listOf("proxyPass", "sni", "allowInsecure")))
        // the Pro view's draft: the UUID and the password under the table's ids, TLS only, sing-box
        val d = ServerEditor.toDraft("tuic", ServerEditor.read(t))
        assertEquals(uuid, d["uuid"]); assertEquals("p:w@x", d["password"]); assertEquals("tls", d["security"]); assertEquals(EngineChoice.SINGBOX, d["engine"])
        assertEquals(Canon.of(t.outbound), Canon.of(ServerEditor.apply(t, ServerEditor.fromDraft("tuic", d, ServerEditor.read(t))).outbound))
        for (p in listOf("tuic", "anytls")) {
            assertEquals(listOf(EngineChoice.SINGBOX), ServerEditor.engineOptions(p))
            assertEquals(listOf("tls"), ServerFields.securitiesOf(p))
            assertTrue(ServerFields.tlsOnly(p)); assertFalse(ServerFields.hasTransport(p))
            assertTrue(p in ServerFields.PROTOCOLS)
            // no Xray noise on sing-box; a fragment only where there is a TCP ClientHello to split (AnyTLS)
            assertFalse(ServerEditor.shown(p, ServerEditor.newDraft(p), ServerFields.field("noise")!!))
            assertEquals(p == "anytls", ServerEditor.shown(p, ServerEditor.newDraft(p), ServerFields.field("fragment")!!))
        }
    }

    @Test fun aSave_refusesWhatSingBoxWould_andDropsWhatItHasNoUseFor() {
        val t = LinkParser.parseLink(tuicLink)
        // a UUID that is none: said at the save, not at a connect
        try { ServerEditor.apply(t, ServerEditor.read(t).also { x: ServerEditor.Fields -> x.cred = "not-a-uuid" }); fail("saved") }
        catch (e: IllegalArgumentException) { assertEquals("uuid: not a UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)", e.message) }
        // a heartbeat that is no duration; one that is, normalized with the rest
        val ob = JSONObject(t.outbound.toString())
        server0(ob).put("heartbeat", "soon")
        try { ServerEditor.checkSingboxOnly(ob, "tuic"); fail("checked") } catch (e: IllegalArgumentException) { assertEquals("tuicHeartbeat: a duration, like 10s", e.message) }
        server0(ob).put("heartbeat", "30").put("congestionControl", "Reno").remove("zeroRtt")
        ob.put("_noise", "random").put("_fragment", "tlshello,100-200,10-20")
        ServerEditor.checkSingboxOnly(ob, "tuic")
        assertEquals("30s", server0(ob).getString("heartbeat")); assertEquals("new_reno", server0(ob).getString("congestionControl"))
        assertFalse(server0(ob).getBoolean("zeroRtt"))
        assertFalse(ob.has("_noise")); assertFalse(ob.has("_fragment"))
        // AnyTLS keeps its fragment (sing-box's own ClientHello split), never Xray's noise
        val a = JSONObject(LinkParser.parseLink(anyLink).outbound.toString()).put("_noise", "random").put("_fragment", "tlshello,100-200,10-20")
        ServerEditor.checkSingboxOnly(a, "anytls")
        assertFalse(a.has("_noise")); assertEquals("tlshello,100-200,10-20", a.getString("_fragment"))
        assertTrue(sb(LinkParser.parseLink(anyLink).copy(outbound = a)).getJSONObject("tls").getBoolean("fragment"))
    }

    @Test fun theEditor_anytls_onePasswordAndAFingerprint() {
        val a = LinkParser.parseLink(anyLink)
        assertEquals("pa ss", ServerEditor.toDraft("anytls", ServerEditor.read(a))["password"])
        val f = ServerEditor.read(a).also { x: ServerEditor.Fields -> x.cred = "other"; x.fp = "safari" }
        val e = ServerEditor.apply(a, f)
        assertEquals("other", server0(e.outbound).getString("password"))
        assertEquals("safari", tls(e.outbound).getString("fingerprint"))
        assertEquals("tcp", e.outbound.getJSONObject("streamSettings").getString("network"))
        assertEquals(Canon.of(a.outbound), Canon.of(ServerEditor.apply(a, ServerEditor.read(a)).outbound))
    }

    @Test fun madeByHand_whatItLacksSaid_thenItsOwnLink() {
        val d = ServerEditor.newDraft("tuic").also { x: MutableMap<String, String> -> x["address"] = "q.example.com"; x["uuid"] = uuid }
        assertEquals(EngineChoice.SINGBOX, d["engine"])
        assertEquals(Triple("password", "protocol", "edit.err.required"), ServerEditor.problem("tuic", d, true, false))
        d["password"] = "pw"; d["sni"] = "s.example"
        assertNull(ServerEditor.problem("tuic", d, true, false))
        val t = ServerEditor.create("tuic", ServerEditor.fromDraft("tuic", d, ServerEditor.Fields()))
        assertEquals("tuic", t.protocol); assertNull(t.engine)
        assertEquals("pw", server0(t.outbound).getString("password")); assertEquals("s.example", tls(t.outbound).getString("serverName"))
        assertEquals(Canon.of(t.outbound), Canon.of(LinkParser.parseLink(t.raw).outbound))
        val ad = ServerEditor.newDraft("anytls").also { x: MutableMap<String, String> -> x["address"] = "a.example.com" }
        assertEquals(Triple("password", "protocol", "edit.err.required"), ServerEditor.problem("anytls", ad, true, false))
        ad["password"] = "pw"
        val a = ServerEditor.create("anytls", ServerEditor.fromDraft("anytls", ad, ServerEditor.Fields()))
        assertEquals("chrome", tls(a.outbound).getString("fingerprint"))
        assertEquals(Canon.of(a.outbound), Canon.of(LinkParser.parseLink(a.raw).outbound))
    }

    /* ------------------------------ a sing-box JSON config ------------------------------ */

    @Test fun aSingBoxConfigsTuicAndAnytls_importAsTheirLinksWouldBe() {
        val cfg = """{"outbounds":[
            {"type":"tuic","tag":"tq","server":"q.example.com","server_port":8443,"uuid":"$uuid","password":"p:w@x","congestion_control":"bbr",
             "udp_relay_mode":"native","zero_rtt_handshake":true,"heartbeat":"10s","tls":{"enabled":true,"server_name":"s.example","insecure":true,"alpn":["h3"]}},
            {"type":"anytls","tag":"an","server":"a.example.com","server_port":443,"password":"pa ss",
             "tls":{"enabled":true,"server_name":"front.example","insecure":true,"alpn":["h2","http/1.1"],"utls":{"enabled":true,"fingerprint":"firefox"}}},
            {"type":"anytls","tag":"ap","server":"p.example.com","server_port":8443,"password":"pw","tls":{"enabled":true,"utls":{"fingerprint":"safari"}}},
            {"type":"tuic","tag":"tv4","server":"v.example.com","server_port":443,"uuid":"token"},
            {"type":"direct","tag":"direct"}]}"""
        val r = JsonImport.importJson(cfg) ?: throw AssertionError("not read as JSON")
        assertEquals(listOf("tq", "an", "ap"), r.servers.map { x: ServerConfig -> x.name })
        // what a link of it would be refused for, said by its tag
        assertEquals(listOf(JsonImport.Problem("tv4", "TUIC: the uuid in the link is not a UUID")), r.errors)
        assertEquals(Canon.of(LinkParser.parseLink(tuicLink).outbound), Canon.of(r.servers[0].outbound))
        assertEquals(Canon.of(LinkParser.parseLink(anyLink).outbound), Canon.of(r.servers[1].outbound))
        // a uTLS block not switched off names the fingerprint; no SNI: the address
        assertTrue(Canon.same("""{"serverName":"p.example.com","allowInsecure":false,"fingerprint":"safari"}""", tls(r.servers[2].outbound)))
        assertTrue(r.servers.none { x: ServerConfig -> x.isJson })
    }
}
