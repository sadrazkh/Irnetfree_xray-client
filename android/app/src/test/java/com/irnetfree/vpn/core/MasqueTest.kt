package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * MASQUE as a native protocol on the phone (Masque, ServerEditor, LinkParser,
 * JsonImport) against the desktop's tests/masque.test.js: the record the
 * editor makes and edits, what the core would refuse said at the save, the
 * one-line share JSON and the JSON reader that makes it this server again;
 * then running it — never Mux, never sing-box, never allowInsecure, anti-DPI
 * by HTTP version, no certificate pin over QUIC.
 */
class MasqueTest {
    /** The WARP endpoint's public key (the same for every account today). */
    private val warpPub = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w=="
    private val pkcs8: ByteArray = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().private.encoded
    private val b64: String = Base64.getEncoder().encodeToString(pkcs8)
    private val pem: String = Masque.pem(pkcs8, "PRIVATE KEY")
    private val pin = "ab".repeat(32)

    /** A server made by hand, as the + Manual sheet makes one: the draft, then ServerEditor.create. */
    private fun plain(more: Map<String, String> = emptyMap()): ServerConfig {
        val d = ServerEditor.newDraft("masque")
        d["name"] = "M"; d["address"] = "m.example.com"; d["port"] = "443"
        d.putAll(more)
        return ServerEditor.create("masque", ServerEditor.fromDraft("masque", d, ServerEditor.Fields()))
    }

    private fun warp(more: Map<String, String> = emptyMap()): ServerConfig = plain(mapOf(
        "name" to "☁ WARP · H3", "address" to "162.159.198.1", "sni" to "consumer-masque.cloudflareclient.com",
        "warpPrivateKey" to pem, "warpPublicKey" to warpPub, "warpAddress" to "172.16.0.2, 2606:4700:110:8a36::2") + more)

    /** An edit of [s] as the sheet sends it: everything it read, [more] over it. */
    private fun edit(s: ServerConfig, more: Map<String, String>): ServerConfig {
        val d = ServerEditor.toDraft("masque", ServerEditor.read(s))
        d.putAll(more)
        return ServerEditor.apply(s, ServerEditor.fromDraft("masque", d, ServerEditor.read(s)))
    }

    private fun st(s: ServerConfig): JSONObject = s.outbound.getJSONObject("streamSettings")
    private fun ms(s: ServerConfig): JSONObject = st(s).getJSONObject("masqueSettings")
    private fun tls(s: ServerConfig): JSONObject = st(s).getJSONObject("tlsSettings")
    private fun strings(a: JSONArray?): List<String> = if (a == null) emptyList() else (0 until a.length()).map { i: Int -> a.getString(i) }
    private fun outs(c: JSONObject): List<JSONObject> { val a = c.getJSONArray("outbounds"); return (0 until a.length()).map { i: Int -> a.getJSONObject(i) } }
    private fun tagged(c: JSONObject, tag: String): JSONObject = outs(c).first { o: JSONObject -> o.optString("tag") == tag }
    private fun settings(): AppSettings = AppSettings(blockAds = false, enableSniffing = false)

    private fun refuses(more: Map<String, String>, message: String) {
        val e = assertThrows(more.toString(), IllegalArgumentException::class.java) { plain(more) }
        assertTrue("$more → ${e.message}", (e.message ?: "").contains(message))
    }

    /* ------------------------------ the record ------------------------------ */

    @Test fun aPlainServerOverHttp3_theCoresFlatSettings_masqueOverTls_noAlpn_readBack() {
        val s = plain(mapOf("masqueUser" to "ci", "masquePass" to "ci-pass", "sni" to "m.example.com", "pcs" to pin.uppercase()))
        assertEquals(listOf("masque", "m.example.com", "443", "M"), listOf(s.protocol, s.address, s.port.toString(), s.name))
        assertTrue(Canon.same("""{"protocol":"masque","settings":{"address":"m.example.com","port":443},
            "streamSettings":{"network":"masque","security":"tls","tlsSettings":{"serverName":"m.example.com","pinnedPeerCertSha256":"$pin"},
            "masqueSettings":{"user":"ci","pass":"ci-pass"}}}""", s.outbound))
        val f = ServerEditor.read(s)
        assertEquals(listOf("h3", "ci", "ci-pass", "m.example.com", pin, ""), listOf(f.masqueHttp, f.pro["masqueUser"], f.pro["masquePass"], f.sni, f.pcs, f.fp))
        assertFalse(ServerEditor.shown("masque", ServerEditor.toDraft("masque", f), ServerFields.field("allowInsecure")!!))
        assertEquals(ServerFields.Ctx("masque", "masque", "tls"), ServerFields.contextOf(s))
        assertTrue(s.edited.isEmpty())
        assertEquals(listOf("tls"), ServerFields.securitiesOf("masque"))
        assertFalse(ServerFields.hasTransport("masque"))
        assertTrue("masque" in ServerFields.PROTOCOLS)
    }

    @Test fun http2IsAlpnH2_backToHttp3DropsIt_anAlpnThatAlreadySaysTheVersionIsLeftAlone() {
        val h2 = plain(mapOf("masqueHttp" to "h2", "fp" to "firefox"))
        assertTrue(Canon.same("""{"fingerprint":"firefox","alpn":["h2"]}""", tls(h2)))
        assertEquals("h2", ServerEditor.read(h2).masqueHttp)
        val h3 = edit(h2, mapOf("masqueHttp" to "h3"))
        assertFalse(tls(h3).has("alpn"))
        assertEquals(listOf("masqueHttp"), h3.edited)
        // a JSON one's ["h3","h2"] is HTTP/3 already: a save that says h3 keeps it as written
        val both = Masque.serverFromOutbound(JSONObject("""{"protocol":"masque","settings":{"address":"b.example","port":443},
            "streamSettings":{"network":"masque","security":"tls","tlsSettings":{"alpn":["h3","h2"]}}}"""), "B")
        assertEquals(listOf("h3", "h2"), strings(tls(edit(both, mapOf("masqueHttp" to "h3"))).optJSONArray("alpn")))
        assertEquals("h2", Masque.httpOf(JSONObject("""{"alpn":["h2","http/1.1"]}""")))
        assertEquals("h3", Masque.httpOf(JSONObject("""{"alpn":"h3,h2"}""")))
        assertEquals("h3", Masque.httpOf(null))
    }

    @Test fun aWarpAccount_thePemMadeOneLineOfBase64_bareAddressesGetTheirPrefix_hostAndPathLeftToTheCore() {
        val s = warp()
        assertTrue(Canon.same("""{"warp":{"privateKey":"$b64","publicKey":"$warpPub","address":["172.16.0.2/32","2606:4700:110:8a36::2/128"]}}""", ms(s)))
        assertEquals("consumer-masque.cloudflareclient.com", tls(s).getString("serverName"))
        val f = ServerEditor.read(s)
        assertEquals(listOf(b64, warpPub, "172.16.0.2/32, 2606:4700:110:8a36::2/128"), listOf(f.pro["warpPrivateKey"], f.pro["warpPublicKey"], f.pro["warpAddress"]))
        // a PEM flattened onto one line by a text box, and a SEC1 key, are read as well
        assertEquals(b64, ms(edit(s, mapOf("warpPrivateKey" to pem.replace("\n", "")))).getJSONObject("warp").getString("privateKey"))
        val sec1 = Base64.getEncoder().encodeToString(Masque.sec1Of(pkcs8)!!)
        assertEquals(sec1, ms(edit(s, mapOf("warpPrivateKey" to sec1))).getJSONObject("warp").getString("privateKey"))
        // all three cleared: a plain server again, its user and password possible
        val off = edit(s, mapOf("warpPrivateKey" to "", "warpPublicKey" to "", "warpAddress" to "", "masqueUser" to "u", "masquePass" to "p"))
        assertTrue(Canon.same("""{"user":"u","pass":"p"}""", ms(off)))
        assertTrue(Masque.isWarp(s))
        assertFalse(Masque.isWarp(off))
    }

    @Test fun whatTheCoreWouldRefuse_isRefusedAtTheSave_namingTheField() {
        refuses(mapOf("warpPrivateKey" to pem), "warpPublicKey, warpAddress are empty")
        refuses(mapOf("warpPrivateKey" to pem, "warpPublicKey" to warpPub), "warpAddress is empty")
        refuses(mapOf("warpPrivateKey" to pem, "warpPublicKey" to warpPub, "warpAddress" to "172.16.0.2", "masqueUser" to "u"), "masqueUser: a WARP account takes no user and password")
        refuses(mapOf("warpPrivateKey" to "bm90IGEga2V5", "warpPublicKey" to warpPub, "warpAddress" to "172.16.0.2"), "warpPrivateKey: not a P-256 private key")
        val ed = Base64.getEncoder().encodeToString(KeyPairGenerator.getInstance("Ed25519").generateKeyPair().private.encoded)
        refuses(mapOf("warpPrivateKey" to ed, "warpPublicKey" to warpPub, "warpAddress" to "172.16.0.2"), "warpPrivateKey: not a P-256 private key")
        val p384 = Base64.getEncoder().encodeToString(KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }.generateKeyPair().private.encoded)
        refuses(mapOf("warpPrivateKey" to p384, "warpPublicKey" to warpPub, "warpAddress" to "172.16.0.2"), "warpPrivateKey: not a P-256 private key")
        refuses(mapOf("warpPrivateKey" to pem, "warpPublicKey" to "bm8=", "warpAddress" to "172.16.0.2"), "warpPublicKey: not a public key")
        refuses(mapOf("warpPrivateKey" to pem, "warpPublicKey" to warpPub, "warpAddress" to "172.16.0.2, 172.16.0.3"), "warpAddress: at most one IPv4 and one IPv6")
        refuses(mapOf("warpPrivateKey" to pem, "warpPublicKey" to warpPub, "warpAddress" to "warp.example"), "warpAddress: \"warp.example\" is not an IP address")
        refuses(mapOf("warpPrivateKey" to pem, "warpPublicKey" to warpPub, "warpAddress" to "172.16.0.2/33"), "is not an IP address")
        refuses(mapOf("masqueUser" to "a:b"), "masqueUser: a user name cannot contain \":\"")
        refuses(mapOf("masquePath" to "masque"), "masquePath: the path starts with /")
        refuses(mapOf("masqueHost" to "https://h.example/x"), "masqueHost: a host name only")
        refuses(mapOf("masqueHeaders" to """{"Host":"h.example"}"""), "masqueHeaders: Host is the core's own")
        refuses(mapOf("masqueHeaders" to """{"capsule-protocol":"?1"}"""), "masqueHeaders: capsule-protocol is the core's own")
        refuses(mapOf("masqueHeaders" to """{"X-N":1}"""), "masqueHeaders: the value of X-N is not text")
        refuses(mapOf("masqueHeaders" to """{"Authorization":"Bearer x"}""", "masqueUser" to "u"), "Authorization beside a user and password")
        refuses(mapOf("remoteDNS" to "1.1.1.1, dns.google"), "remoteDNS: IP addresses only")
        // what the core takes
        val ok = plain(mapOf("masqueHeaders" to """{"User-Agent":"chrome","Authorization":"Bearer x"}""",
            "masquePath" to "/.well-known/masque/ip/{target}/{ipproto}/", "masqueHost" to "m.example.com:8443", "remoteDNS" to "1.1.1.1, 2606:4700:4700::1111"))
        assertEquals(listOf("1.1.1.1", "2606:4700:4700::1111"), strings(ok.outbound.getJSONObject("settings").optJSONArray("remoteDNS")))
        // the record stays as it was when an edit is refused (apply works on a copy)
        val s = plain()
        assertThrows(IllegalArgumentException::class.java) { edit(s, mapOf("masqueUser" to "a:b")) }
        assertEquals(0, ms(s).length())
    }

    @Test fun neverAllowInsecureMuxOrSingbox_aFragmentOnlyOverHttp2_noiseOnlyOverHttp3() {
        val s = plain(mapOf("allowInsecure" to "true", "engine" to "sing-box", "mux" to "on", "fragment" to "tlshello,100-200,10-20", "noise" to "rand:50-100:0"))
        assertFalse(tls(s).has("allowInsecure"))
        assertNull("sing-box has no MASQUE", s.engine)
        assertEquals("the Mux field is not MASQUE's", "", s.mux)
        assertEquals(listOf("", "rand:50-100:0"), listOf(s.outbound.optString("_fragment"), s.outbound.optString("_noise")))
        val h2 = edit(s, mapOf("masqueHttp" to "h2", "fragment" to "tlshello,100-200,10-20"))
        assertEquals(listOf("tlshello,100-200,10-20", ""), listOf(h2.outbound.optString("_fragment"), h2.outbound.optString("_noise")))
        assertEquals("xray-pattn", edit(s, mapOf("engine" to "xray-pattn")).engine)
        // a JSON outbound with Mux on: the core would refuse it
        val j = Masque.serverFromOutbound(JSONObject("""{"protocol":"masque","mux":{"enabled":true},"settings":{"address":"j.example","port":443},
            "streamSettings":{"network":"masque","security":"tls"}}"""), "J")
        assertFalse(j.outbound.has("mux"))
        // the editor offers no sing-box for it, and its anti-DPI by HTTP version
        assertEquals(listOf("xray", "xray-pattn"), ServerEditor.engineOptions("masque"))
        val d3 = ServerEditor.newDraft("masque")
        assertTrue(ServerEditor.shown("masque", d3, ServerFields.field("noise")!!))
        assertFalse(ServerEditor.shown("masque", d3, ServerFields.field("fragment")!!))
        d3["masqueHttp"] = "h2"
        assertFalse(ServerEditor.shown("masque", d3, ServerFields.field("noise")!!))
        assertTrue(ServerEditor.shown("masque", d3, ServerFields.field("fragment")!!))
        for (id in listOf("mux", "alpn", "network", "security", "uuid", "password")) assertFalse(id, ServerEditor.shown("masque", d3, ServerFields.field(id)!!))
        for (id in listOf("masqueHttp", "masqueUser", "masquePass", "warpPrivateKey", "remoteDNS", "useSystemCA", "sni", "fp", "pcs", "vcn", "ech", "finalMask"))
            assertTrue(id, ServerEditor.shown("masque", d3, ServerFields.field(id)!!))
    }

    @Test fun aSaveWithNothingChanged_changesAndRecordsNothing_aChangedFieldIsRecorded() {
        for (s in listOf(plain(mapOf("masqueUser" to "u", "masquePass" to "p", "masqueHttp" to "h2", "fp" to "chrome", "remoteDNS" to "9.9.9.9", "useSystemCA" to "true")), warp(mapOf("noise" to "random")))) {
            val again = ServerEditor.apply(s, ServerEditor.read(s))
            assertTrue(again.edited.isEmpty())
            assertEquals(Canon.of(s.outbound), Canon.of(again.outbound))
        }
        val e = edit(warp(), mapOf("sni" to "www.example.com", "vcn" to "www.example.com"))
        assertEquals(listOf("sni", "vcn"), e.edited)
        assertEquals("www.example.com", tls(e).getString("verifyPeerCertByName"))
    }

    @Test fun aNewDraft_needsOnlyAnAddress() {
        val d = ServerEditor.newDraft("masque")
        d["address"] = "m.example.com"
        assertNull(ServerEditor.problem("masque", d, true, false))
        assertEquals(listOf("h3", "", "tls"), listOf(d["masqueHttp"], d["fp"], d["security"]))
        d["address"] = ""
        assertEquals("address", ServerEditor.problem("masque", d, true, false)?.first)
    }

    /* ------------------------------ sharing ------------------------------ */

    @Test fun theShareJson_oneLine_theRemarksAndTheOneOutbound_withoutWhatIsThisDevicesOwn() {
        val s = edit(warp(mapOf("noise" to "random", "engine" to "xray-pattn")), mapOf("remoteDNS" to "9.9.9.9", "useSystemCA" to "true",
            "echForceQuery" to "full", "minVersion" to "1.3", "curvePreferences" to "X25519", "pcs" to pin, "finalMask" to """{"quicParams":{"congestion":"reno"}}"""))
        val link = LinkParser.buildShareLink(s)
        assertFalse(link.contains("\n"))
        val made = warp()
        assertEquals("raw is the share JSON of the server as made", Canon.of(JSONObject(LinkParser.buildShareLink(made))), Canon.of(JSONObject(made.raw)))
        val j = JSONObject(link)
        assertEquals(setOf("remarks", "outbounds"), j.keySet())
        assertEquals("☁ WARP · H3", j.getString("remarks"))
        val ob = j.getJSONArray("outbounds").getJSONObject(0)
        assertTrue(Canon.same("""{"tag":"proxy","protocol":"masque","settings":{"address":"162.159.198.1","port":443},
            "streamSettings":{"network":"masque","security":"tls",
              "tlsSettings":{"serverName":"consumer-masque.cloudflareclient.com","pinnedPeerCertSha256":"$pin"},
              "masqueSettings":{"warp":{"privateKey":"$b64","publicKey":"$warpPub","address":["172.16.0.2/32","2606:4700:110:8a36::2/128"]}},
              "finalmask":{"quicParams":{"congestion":"reno"}}}}""", ob))
        // every local field of the table, and the device's anti-DPI and core, stay here
        for (f in ServerFields.PATH_FIELDS.filter { x: SfField -> x.local && !(x.path ?: "@").startsWith("@") }) assertNull(f.id, ServerFields.getPath(ob, f.path!!))
        assertFalse(Regex("_noise|_fragment|engine|xray-pattn").containsMatchIn(link))
        val p = plain(mapOf("masqueHeaders" to """{"User-Agent":"chrome"}""", "masqueUser" to "u", "masquePass" to "p"))
        assertTrue(Canon.same("""{"user":"u","pass":"p"}""", JSONObject(LinkParser.buildShareLink(p)).getJSONArray("outbounds").getJSONObject(0)
            .getJSONObject("streamSettings").getJSONObject("masqueSettings")))
    }

    @Test fun theShareJsonPastedIntoAnotherIrnetfree_isThisVeryServerAgain_everyFieldEditable() {
        for (s in listOf(warp(), plain(mapOf("masqueHttp" to "h2", "masqueUser" to "u", "masquePass" to "p", "masquePath" to "/m/", "masqueHost" to "h.example",
                "fp" to "safari", "ech" to "AEXX", "vcn" to "real.example")))) {
            val (servers, errors) = LinkParser.parseMany(LinkParser.buildShareLink(s))
            assertEquals(emptyList<String>(), errors)
            assertEquals(1, servers.size)
            val back = servers[0]
            assertEquals("", back.source)
            assertFalse(back.isJson)
            assertNotEquals(s.id, back.id)
            assertEquals(listOf(s.name, s.protocol, s.address, s.port.toString()), listOf(back.name, back.protocol, back.address, back.port.toString()))
            assertEquals(Canon.of(s.outbound), Canon.of(back.outbound))
            assertEquals(Canon.of(JSONObject(s.raw)), Canon.of(JSONObject(back.raw)))
            assertTrue(back.edited.isEmpty())
            // a routing link carries it the same way
            assertEquals("masque", RouteShare.parseServer(LinkParser.buildShareLink(s)).protocol)
        }
    }

    /* ------------------------------ the JSON reader ------------------------------ */

    private fun fixture(): String {
        val f = File("../../tests/fixtures/json/xray-masque.json")
        if (!f.isFile) fail("missing shared fixture ../../tests/fixtures/json/xray-masque.json (looked at ${f.absolutePath}) — the JVM tests run in android/app")
        return f.readText(Charsets.UTF_8)
    }

    @Test fun xrayMasqueJson_aWarpAndAnHttp2ServerAloneInTheirConfigAreNative_aPanelsFullConfigStaysJson() {
        val r = JsonImport.importJson(fixture()) ?: throw AssertionError("not read as JSON")
        assertTrue(r.errors.toString(), r.errors.isEmpty())
        assertEquals(listOf(
            listOf("☁ WARP · H3", "masque", "162.159.198.1", "443", "native"),
            listOf("Ⓜ MASQUE · H2", "masque", "masque.example.com", "8443", "native"),
            listOf("🏛 panel MASQUE", "masque", "panel.example.com", "443", "json")
        ), r.servers.map { s: ServerConfig -> listOf(s.name, s.protocol, s.address, s.port.toString(), s.source.ifEmpty { "native" }) })
        val w = r.servers[0]; val h2 = r.servers[1]; val panel = r.servers[2]
        val warp = ms(w).getJSONObject("warp")
        assertTrue("the PEM made one line", warp.getString("privateKey").startsWith("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg"))
        assertEquals(warpPub, warp.getString("publicKey"))
        assertEquals(listOf("172.16.0.2/32", "2606:4700:110:8a36:4d2e:7c3a:9f11:5b20/128"), strings(warp.getJSONArray("address")))
        assertFalse(w.outbound.has("tag"))
        assertEquals("h2", ServerEditor.read(h2).masqueHttp)
        assertEquals(listOf("1.1.1.1", "2606:4700:4700::1111"), strings(h2.outbound.getJSONObject("settings").getJSONArray("remoteDNS")))
        assertEquals(LinkParser.buildShareLink(h2), h2.raw)
        // the panel's config: run whole, its own routing kept
        assertEquals(JsonImport.MODE_FULL, panel.jsonMode)
        assertEquals("masque", panel.outbound.getString("protocol"))
        assertEquals(listOf("direct", "proxy"), panel.jsonInfo!!.rules.map { x: JsonRule -> x.to })
        assertTrue("a MASQUE JSON is never read as zero servers again", "masque" in JsonImport.PROXY_PROTOCOLS)
    }

    @Test fun onlyAConfigThatIsJustOneMasqueServerIsReadAsOne() {
        fun ob(stream: String = """{"network":"masque","security":"tls"}""", more: String = ""): String =
            """{"tag":"proxy","protocol":"masque","settings":{"address":"a.example","port":443},"streamSettings":$stream$more}"""
        fun one(cfg: String): ServerConfig = JsonImport.serversFromXray(JSONObject(cfg))[0]
        assertEquals("", one("""{"remarks":"r","outbounds":[${ob()}]}""").source)
        assertEquals("", one("""{"remarks":"r","outbounds":[${ob()},{"tag":"d","protocol":"freedom"},{"tag":"b","protocol":"blackhole"},{"tag":"dns-out","protocol":"dns"}]}""").source)
        assertEquals("no remarks: address:port, as for any JSON server", "a.example:443", one("""{"outbounds":[${ob()}]}""").name)
        // through a fragment dialer: that dialer would be lost
        val viaFrag = one("""{"outbounds":[${ob("""{"network":"masque","security":"tls","sockopt":{"dialerProxy":"frag"}}""")},
            {"tag":"frag","protocol":"freedom","settings":{"fragment":{"packets":"tlshello"}}}]}""")
        assertEquals("json", viaFrag.source)
        assertEquals(1, viaFrag.extraOutbounds.size)
        // a second proxy, a loopback, its own inbounds or routing
        assertEquals("json", one("""{"outbounds":[${ob()},{"tag":"v","protocol":"vless","settings":{"vnext":[{"address":"v.example","port":443,"users":[{"id":"u"}]}]}}]}""").source)
        assertEquals("json", one("""{"outbounds":[${ob()},{"tag":"l","protocol":"loopback"}]}""").source)
        assertEquals("json", one("""{"outbounds":[${ob()}],"routing":{"rules":[]}}""").source)
        assertEquals("json", one("""{"outbounds":[${ob()}],"inbounds":[]}""").source)
        // a WARP account missing its addresses: the core will say so; the import keeps the config
        val bad = one("""{"outbounds":[${ob("""{"network":"masque","security":"tls","masqueSettings":{"warp":{"privateKey":"$b64","publicKey":"$warpPub"}}}""")}]}""")
        assertEquals("json", bad.source)
        assertEquals("masque", bad.protocol)
    }

    /* ------------------------------ running it ------------------------------ */

    @Test fun theConfig_theMasqueOutboundAsTheProxy_dialledDirectly_neverMux() {
        val s = plain(mapOf("masqueUser" to "u", "masquePass" to "p")).copy(id = "mq", mux = "on")
        tls(s).put("allowInsecure", true)   // a hand-edited store
        val cfg = ConfigBuilder.build(ConnectionPlan.Single(s), settings(), muxIds = setOf("mq"))
        val proxy = tagged(cfg, "proxy")
        assertEquals("masque", proxy.getString("protocol"))
        assertFalse(proxy.has("mux"))
        assertFalse(proxy.getJSONObject("streamSettings").getJSONObject("tlsSettings").has("allowInsecure"))
        assertFalse(Mux.eligible(s.outbound))
        assertTrue(Mux.plan("on", listOf(s), emptyMap(), 1L).muxIds.isEmpty())
    }

    @Test fun antiDpiByHttpVersion_http2DialsThroughAFragment_http3ThroughNoise_neverTheOther() {
        fun dpi(c: JSONObject): List<JSONObject> = outs(c).filter { o: JSONObject -> o.optString("tag").startsWith("dpi-") }
        val h2 = plain(mapOf("masqueHttp" to "h2", "fragment" to "tlshello,100-200,10-20"))
        val c2 = ConfigBuilder.build(ConnectionPlan.Single(h2), settings())
        assertEquals("dpi-1", tagged(c2, "proxy").getJSONObject("streamSettings").getJSONObject("sockopt").getString("dialerProxy"))
        assertEquals(listOf(listOf("domainStrategy", "fragment")), dpi(c2).map { o: JSONObject -> o.getJSONObject("settings").keySet().sorted() })
        val h3 = warp(mapOf("noise" to "rand:50-100:0"))
        val c3 = ConfigBuilder.build(ConnectionPlan.Single(h3), settings())
        assertTrue(Canon.same("""{"n":[{"type":"rand","packet":"50-100","delay":"0"}]}""", JSONObject().put("n", dpi(c3)[0].getJSONObject("settings").getJSONArray("noises"))))
        assertFalse(dpi(c3)[0].getJSONObject("settings").has("fragment"))
        // a stored HTTP/3 record that still carries a fragment (hand-edited): no dialer at all
        val kept = plain()
        kept.outbound.put("_fragment", "tlshello,100-200,10-20")
        val ck = ConfigBuilder.build(ConnectionPlan.Single(kept), settings())
        assertTrue(dpi(ck).isEmpty())
        assertFalse(tagged(ck, "proxy").getJSONObject("streamSettings").optJSONObject("sockopt")?.has("dialerProxy") ?: false)
        assertFalse(ck.toString().contains("_fragment"))
        // the latency test's own config the same way
        assertEquals(listOf(true), dpi(ConfigBuilder.buildTestConfig(h3, 41000)).map { o: JSONObject -> o.getJSONObject("settings").has("noises") })
    }

    @Test fun theCore_XrayOrXrayPattnWhenChosen_neverSingbox_whichRefusesItOutright() {
        val s = plain()
        assertTrue(EngineChoice.isMasque(s))
        assertEquals(EngineChoice.XRAY, EngineChoice.chooseEngine(ConnectionPlan.Single(s.copy(engine = "sing-box"))))
        assertEquals(EngineChoice.PATTN, EngineChoice.chooseEngine(ConnectionPlan.Single(s.copy(engine = "xray-pattn"))))
        assertEquals(EngineChoice.PATTN, EngineChoice.chooseEngine(ConnectionPlan.Single(s), EngineChoice.PATTN))
        assertFalse(EngineChoice.needsInsecureCore(s))
        assertThrows(SingboxConfig.Unsupported::class.java) { SingboxConfig.build(s, AppSettings()) }
        assertEquals(EngineChoice.XRAY, EngineChoice.testEngineFor(s.copy(engine = "sing-box")))
        // a JSON server whose main outbound is MASQUE: the same
        val panel = JsonImport.importJson(fixture())!!.servers[2]
        assertEquals(EngineChoice.XRAY, EngineChoice.chooseEngine(ConnectionPlan.Single(panel.copy(engine = "sing-box"))))
    }

    @Test fun noCertificatePinLearntForMasque_andAQuicOnesPinIsNotReCheckedOverTcp() {
        val s = plain()
        tls(s).put("allowInsecure", true)
        assertFalse(CertPin.wantsPin(s))
        val h3 = plain().copy(id = "a", certPin = pin, certPinCheckedAt = 0)
        val h2 = plain(mapOf("masqueHttp" to "h2", "address" to "h2.example.com")).copy(id = "b", certPin = pin, certPinCheckedAt = 0)
        assertFalse(CertPin.recheckDue(h3, now = 10_000_000_000L))
        assertTrue(CertPin.recheckDue(h2, now = 10_000_000_000L))
        assertTrue(Masque.isQuic(h3))
        assertFalse(Masque.isQuic(h2))
    }

    @Test fun aSubscriptionKnowsOneByItsAccount_andARefreshOfTheSameJsonKeepsItsId() {
        val s = warp()
        val id = SubRefresh.identity(s).split("\u0001")
        assertEquals(listOf("masque", "162.159.198.1", "443", b64, "", "", "masque", "", ""), id)
        val p = SubRefresh.identity(plain(mapOf("masqueUser" to "u", "masquePass" to "p", "masquePath" to "/m/"))).split("\u0001")
        assertEquals(listOf("u", "p", "/m/"), listOf(p[4], p[5], p[7]))
        val old = s.copy(subId = "sub1")
        val fresh = LinkParser.parseMany(s.raw).first
        val m = SubRefresh.merge(listOf(old), fresh, "sub1")
        assertEquals(1, m.kept)
        assertEquals(old.id, m.servers[0].id)
    }

    @Test fun keysAndAddresses_asTheCoreTakesThem() {
        assertNotNull(Masque.p256Pkcs8(pkcs8))
        assertNotNull(Masque.p256Pkcs8(Masque.sec1Of(pkcs8)!!))
        assertNull(Masque.p256Pkcs8("not a key".toByteArray()))
        assertTrue(Masque.isSpki(Base64.getDecoder().decode(warpPub)))
        assertTrue(Masque.isP256Spki(Base64.getDecoder().decode(warpPub)))
        assertFalse(Masque.isSpki("no".toByteArray()))
        assertEquals(b64, Masque.keyBase64(pem))
        assertEquals(b64, Masque.keyBase64(pem.replace("\n", "")))
        assertNull(Masque.keyBase64("not-a-key"))
        assertEquals(listOf(4, 6, 6, 6, 0, 0, 0, 0), listOf("172.16.0.2", "2606:4700:103::1", "::ffff:1.2.3.4", "2606:4700:110:8a36:4d2e:7c3a:9f11:5b20",
            "999.1.1.1", "warp.example", "[]", "1:2:3:4:5:6:7:8:9").map { x: String -> Masque.ipFamily(x) })
        assertEquals(listOf("172.16.0.2/32", "2606:4700:110::2/128"), Masque.warpAddresses(JSONArray().put("172.16.0.2").put("2606:4700:110::2/128")))
    }
}
