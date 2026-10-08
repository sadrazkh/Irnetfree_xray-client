package com.irnetfree.vpn.core

import com.irnetfree.vpn.vpn.TunnelSetup
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/**
 * JSON configs (JsonImport, the builder's full and raw forms, the record, a
 * refresh) against the fixtures the desktop's tests read too:
 * tests/fixtures/json/ at the repository root — this test runs in android/app.
 * The expectations are the desktop's (tests/jsonImport.test.js).
 */
class JsonImportTest {
    private fun fixture(name: String): String {
        val f = File("../../tests/fixtures/json/$name")
        if (!f.isFile) fail("missing shared fixture ../../tests/fixtures/json/$name (looked at ${f.absolutePath}) — the JVM tests run in android/app")
        return f.readText(Charsets.UTF_8)
    }
    private fun imp(name: String): JsonImport.Result = JsonImport.importJson(fixture(name)) ?: throw AssertionError("$name was not read as JSON")
    private fun tags(list: List<JSONObject>): List<String> = list.map { o: JSONObject -> o.optString("tag") }
    private fun stream(o: JSONObject): JSONObject = o.getJSONObject("streamSettings")
    private fun dialer(o: JSONObject): String = o.optJSONObject("streamSettings")?.optJSONObject("sockopt")?.optString("dialerProxy") ?: ""
    private fun outs(c: JSONObject): List<JSONObject> { val a = c.getJSONArray("outbounds"); return (0 until a.length()).map { i: Int -> a.getJSONObject(i) } }
    private fun tagged(c: JSONObject, tag: String): JSONObject = outs(c).firstOrNull { o: JSONObject -> o.optString("tag") == tag } ?: throw AssertionError("no outbound $tag in ${tags(outs(c))}")
    private fun rules(c: JSONObject): List<JSONObject> { val a = c.getJSONObject("routing").getJSONArray("rules"); return (0 until a.length()).map { i: Int -> a.getJSONObject(i) } }
    private fun settings(): AppSettings = AppSettings(blockAds = false, enableSniffing = false)
    private fun byName(r: JsonImport.Result, name: String): ServerConfig = r.servers.firstOrNull { s: ServerConfig -> s.name == name } ?: throw AssertionError("no server $name in ${r.servers.map { s: ServerConfig -> s.name }}")
    private val subNames = listOf("🇩🇪 DE-1", "🇩🇪 DE-2", "🇳🇱 NL-1", "🇫🇮 FI-1", "🇺🇸 US-1")

    /* ------------------------------ import ------------------------------ */

    @Test fun subscription_fiveServers_theInfoRowsAreNoServers() {
        val r = imp("xray-subscription.json")
        assertTrue(r.errors.isEmpty())
        assertEquals(subNames, r.servers.map { s: ServerConfig -> s.name })
        for (s in r.servers) {
            assertEquals("vless", s.protocol)
            assertEquals("ws", stream(s.outbound).getString("network"))
            assertEquals("tls", stream(s.outbound).getString("security"))
            assertTrue(s.isJson); assertEquals("json", s.source); assertEquals(JsonImport.MODE_FULL, s.jsonMode)
            assertFalse(s.outbound.has("tag"))
            assertEquals(443, s.port)
            // raw: that one config, minified, remarks included
            assertEquals(JsonText.minify(s.json), s.raw)
            assertTrue(s.raw.contains("\"remarks\":\"${s.name}\""))
            assertFalse(s.raw.contains("\n"))
            assertEquals(3, s.jsonInfo!!.rules.size)
        }
        assertEquals(listOf("edge1.example.com", "edge2.example.com", "edge3.example.com", "edge4.example.com", "edge5.example.com"), r.servers.map { s: ServerConfig -> s.address })
    }

    @Test fun subscription_inBase64_givesTheSameServers() {
        val bytes = fixture("xray-subscription.json").toByteArray(Charsets.UTF_8)
        for (b64 in listOf(java.util.Base64.getEncoder().encodeToString(bytes), java.util.Base64.getMimeEncoder().encodeToString(bytes))) {
            val r = JsonImport.importJson(b64) ?: throw AssertionError("base64 JSON not read")
            assertEquals(subNames, r.servers.map { s: ServerConfig -> s.name })
            assertTrue(r.errors.isEmpty())
        }
    }

    @Test fun fragment_oneServer_itsDialerIsAHelper() {
        val r = imp("xray-fragment.json")
        val s = r.servers.single()
        assertEquals("🇩🇪 frag", s.name)
        assertEquals(listOf("fragment"), tags(s.extraOutbounds))
        assertEquals("freedom", s.extraOutbounds[0].getString("protocol"))
        assertEquals("fragment", dialer(s.outbound))
        val info = s.jsonInfo!!
        assertEquals(3, info.rules.size)
        assertTrue(info.dns)
        // the desktop's neutral tokens: `*` = no condition
        assertEquals(JsonRule("geosite:private", "direct"), info.rules[0])
        assertEquals(JsonRule("geoip:ir", "direct"), info.rules[1])
        assertEquals(JsonRule("*", "proxy"), info.rules[2])
        assertEquals(0, info.balancers); assertFalse(info.observatory)
    }

    @Test fun notAppliedSummary_putsTheTokensInWords() {
        assertEquals("everything else", JsonImport.matchInWords("*"))
        assertEquals("geoip:ir", JsonImport.matchInWords("geoip:ir"))
        assertEquals("—", JsonImport.matchInWords(""))
        assertEquals("balancer auto", JsonImport.targetInWords("balancer:auto"))
        assertEquals("direct", JsonImport.targetInWords("direct"))
        assertEquals("—", JsonImport.targetInWords(""))
        // a rule naming no outbound, the app's own catch-all port, several conditions
        val info = JsonImport.jsonInfo(JSONObject("{\"outbounds\":[],\"routing\":{\"rules\":[" +
            "{\"type\":\"field\",\"port\":\"0-65535\"}," +
            "{\"type\":\"field\",\"domain\":[\"a\",\"b\",\"c\",\"d\",\"e\"],\"port\":\"443\",\"network\":\"udp\",\"outboundTag\":\"x\"}]}}"))
        assertEquals(JsonRule("*", ""), info.rules[0])
        assertEquals(JsonRule("a, b, c +2 + port 443 + udp", "x"), info.rules[1])
    }

    @Test fun chain_theMainOutboundKeepsItsMux_helpersAreTheHops() {
        val s = imp("xray-chain.json").servers.single()
        assertEquals("vless", s.protocol)
        assertEquals("exit.example.com", s.address)
        assertEquals("reality", stream(s.outbound).getString("security"))
        assertTrue(s.outbound.getJSONObject("mux").getBoolean("enabled"))
        assertEquals(8, s.outbound.getJSONObject("mux").getInt("concurrency"))
        assertEquals("hop1", s.outbound.getJSONObject("proxySettings").getString("tag"))
        assertEquals(listOf("hop1", "frag"), tags(s.extraOutbounds))
    }

    @Test fun balancer_oneServerPerMember() {
        val r = imp("xray-balancer.json")
        assertEquals(listOf("⚖ auto · proxy-1", "⚖ auto · proxy-2"), r.servers.map { s: ServerConfig -> s.name })
        assertEquals(listOf("vless", "trojan"), r.servers.map { s: ServerConfig -> s.protocol })
        assertEquals(1, r.servers[0].jsonInfo!!.balancers)
        assertTrue(r.servers[0].jsonInfo!!.observatory)
        assertEquals(JsonRule("*", "balancer:auto"), r.servers[0].jsonInfo!!.rules[1])
        assertEquals(JsonImport.MainChoice(listOf("proxy-1", "proxy-2"), "auto"), JsonImport.mainOutboundTag(JSONObject(fixture("xray-balancer.json"))))
        assertEquals("proxy-2", JsonImport.mainTagOf(r.servers[1]))
    }

    @Test fun wireguard_anObjectWithNoRouting() {
        val s = imp("xray-wireguard.json").servers.single()
        assertEquals("wireguard", s.protocol)
        assertEquals("🛡 wg", s.name)
        assertEquals("wg.example.com", s.address); assertEquals(51820, s.port)
        assertTrue(s.extraOutbounds.isEmpty())
        assertTrue(s.jsonInfo!!.rules.isEmpty())
    }

    @Test fun singbox_ordinaryServers_asIfFromTheirLinks() {
        val r = imp("singbox.json")
        assertEquals(
            listOf("vless-reality", "vmess-ws", "trojan-grpc", "ss", "hy2", "wg", "socks-up", "http-up", "vless-detour (via trojan-grpc)"),
            r.servers.map { s: ServerConfig -> s.name })
        assertEquals(listOf("vless", "vmess", "trojan", "shadowsocks", "hysteria2", "wireguard", "socks", "http", "vless"), r.servers.map { s: ServerConfig -> s.protocol })
        assertEquals(listOf(JsonImport.Problem("tuic", "unsupported protocol: tuic")), r.errors)
        assertTrue(r.servers.none { s: ServerConfig -> s.isJson })
        assertTrue(r.servers.all { s: ServerConfig -> s.raw.isNotBlank() })
        fun same(link: String, name: String) =
            assertEquals(name, Canon.of(LinkParser.parseLink(link).outbound), Canon.of(byName(r, name).outbound))
        same("vless://00000000-0000-4000-8000-0000000000c1@r.example.com:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.example.net&fp=chrome&pbk=AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKK&sid=0a1b#vless-reality", "vless-reality")
        same("trojan://tpw@t.example.com:443?security=tls&sni=t.example.com&type=grpc&serviceName=tg#trojan-grpc", "trojan-grpc")
        same("ss://chacha20-ietf-poly1305:spw@s.example.com:8388#ss", "ss")
        same("hysteria2://hpw@h.example.com:443/?sni=h.example.com&obfs=salamander&obfs-password=ob&mport=20000-30000&up=50&down=100#hy2", "hy2")
        same("wireguard://SECRETKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D@w.example.com:51820?publickey=PUBKEYBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB%3D&address=10.8.0.2%2F32&mtu=1280#wg", "wg")
        same("socks://u:p@p.example.com:1080#socks-up", "socks-up")
        same("http://p.example.com:3128#http-up", "http-up")
        // vmess: its link is base64, which android.util.Base64 cannot decode off a device — the fields instead
        val vm = byName(r, "vmess-ws")
        assertEquals("v.example.com", vm.address); assertEquals(8443, vm.port)
        val vst = stream(vm.outbound)
        assertEquals("ws", vst.getString("network")); assertEquals("/vm", vst.getJSONObject("wsSettings").getString("path"))
        assertEquals("v.example.com", vst.getJSONObject("wsSettings").getJSONObject("headers").getString("Host"))
        assertEquals("v.example.com", vst.getJSONObject("tlsSettings").getString("serverName"))
        // a detour is said in the name, not chained
        val d = byName(r, "vless-detour (via trojan-grpc)")
        assertEquals("", dialer(d.outbound)); assertEquals("d.example.com", d.address)
    }

    @Test fun clashYaml_isRefusedWithAReason() {
        val r = JsonImport.importJson("proxies:\n  - name: a") ?: throw AssertionError("Clash YAML not recognised")
        assertTrue(r.servers.isEmpty())
        assertEquals("Clash YAML is not supported — use the subscription link", r.errors.single().error)
        assertEquals(listOf("Clash YAML is not supported — use the subscription link"), LinkParser.parseMany("proxies:\n  - name: a").second)
    }

    @Test fun notJson_isNull_soLinksReadAsBefore() {
        assertNull(JsonImport.importJson("vless://u@h.example:443?type=tcp&security=none#x"))
        assertNull(JsonImport.importJson("[Interface]\nPrivateKey = x\n[Peer]\nEndpoint = h.example:51820"))
        assertNull(JsonImport.importJson(""))
        assertFalse(JsonImport.looksLikeJson("[Interface]"))
        assertTrue(JsonImport.looksLikeJson("  [ {\"outbounds\": []} ]"))
        assertTrue(JsonImport.looksLikeJson("\uFEFF{\"remarks\": \"x\"}"))
        // only info rows: nothing, and no error
        val a = JSONArray(fixture("xray-subscription.json"))
        val info = JsonImport.importJson(JSONArray().put(a.get(0)).put(a.get(1)).toString()) ?: throw AssertionError("not read")
        assertTrue(info.servers.isEmpty()); assertTrue(info.errors.isEmpty())
        // a broken config says so
        val bad = JsonImport.importJson("{\"outbounds\": [ {\"protocol\": ") ?: throw AssertionError("not read")
        assertTrue(bad.errors.single().error.startsWith("Not valid JSON"))
    }

    @Test fun parseMany_readsEveryFixtureAsImportJsonDoes_andLinksAsBefore() {
        for (f in listOf("xray-subscription.json", "xray-fragment.json", "xray-chain.json", "xray-balancer.json", "xray-wireguard.json", "singbox.json")) {
            val text = fixture(f)
            val (servers, errors) = LinkParser.parseMany(text)
            val j = JsonImport.importJson(text) ?: throw AssertionError("$f not read")
            assertEquals(f, j.servers.map { s: ServerConfig -> s.name }, servers.map { s: ServerConfig -> s.name })
            assertEquals(f, j.servers.map { s: ServerConfig -> Canon.of(s.outbound) }, servers.map { s: ServerConfig -> Canon.of(s.outbound) })
            assertEquals(f, j.errors.map { p: JsonImport.Problem -> p.text() }, errors)
        }
        val l1 = "vless://u-1@a.example:443?type=ws&path=%2Fx&host=a.example&security=tls&sni=a.example#A"
        val l2 = "trojan://pw@b.example:443?security=tls&sni=b.example&type=grpc&serviceName=g#B"
        val (ls, le) = LinkParser.parseMany("$l1\n$l2\nnot a link\n")
        assertTrue(le.isEmpty())
        assertEquals(listOf("A", "B"), ls.map { s: ServerConfig -> s.name })
        assertEquals(Canon.of(LinkParser.parseLink(l1).outbound), Canon.of(ls[0].outbound))
        assertEquals(Canon.of(LinkParser.parseLink(l2).outbound), Canon.of(ls[1].outbound))
        assertEquals(listOf(l1, l2), ls.map { s: ServerConfig -> s.raw })
        assertTrue(ls.none { s: ServerConfig -> s.isJson || s.source.isNotEmpty() })
    }

    @Test fun jsonText_isJavaScriptsStringify() {
        val cfg = JSONObject(fixture("xray-fragment.json"))
        val min = JsonText.minify(cfg)
        assertFalse(min.contains("\\/")); assertTrue(min.contains("\"/ws\""))
        assertFalse(min.contains("\n")); assertFalse(min.contains(": "))
        assertTrue(min.contains("🇩🇪"))
        assertEquals(Canon.of(cfg), Canon.of(JSONObject(min)))
        val pretty = JsonText.pretty(cfg)
        assertTrue(pretty.startsWith("{\n  \"")); assertTrue(pretty.endsWith("\n}"))
        assertEquals(Canon.of(cfg), Canon.of(JSONObject(pretty)))
        assertEquals("{\n  \"c\": [\n    1,\n    \"x\\\"y\",\n    [],\n    {},\n    true,\n    null\n  ]\n}",
            JsonText.pretty(JSONObject().put("c", JSONArray().put(1).put("x\"y").put(JSONArray()).put(JSONObject()).put(true).put(JSONObject.NULL))))
        assertEquals("\"a\\u0001\\n\\t/\\\\\"", JsonText.minify("a\u0001\n\t/\\"))
        assertEquals("{\"a\":1,\"b\":{\"c\":2,\"d\":3}}", JsonText.canonical(JSONObject("{\"b\":{\"d\":3,\"c\":2},\"a\":1}")))
    }

    /* ------------------------------ the record ------------------------------ */

    @Test fun record_survivesTheStore_andOldRecordsLoad() {
        val s = imp("xray-chain.json").servers.single().copy(jsonMode = JsonImport.MODE_RAW)
        val back = ServerConfig.fromJson(JSONObject(s.toJson().toString()))
        assertTrue(back.isJson)
        assertEquals(JsonImport.MODE_RAW, back.jsonMode)
        assertEquals(Canon.of(s.json), Canon.of(back.json))
        assertEquals(s.extraOutbounds.map { o: JSONObject -> Canon.of(o) }, back.extraOutbounds.map { o: JSONObject -> Canon.of(o) })
        assertEquals(s.jsonInfo, back.jsonInfo)
        assertEquals(s.raw, back.raw)
        // a record written before JSON servers existed
        val old = ServerConfig.fromJson(JSONObject("{\"id\":\"s-1\",\"name\":\"a\",\"protocol\":\"vless\",\"address\":\"a.example\",\"port\":443,\"outbound\":{}}"))
        assertFalse(old.isJson); assertEquals("", old.source); assertEquals(JsonImport.MODE_FULL, old.jsonMode)
        assertNull(old.json); assertNull(old.jsonInfo); assertTrue(old.extraOutbounds.isEmpty())
        // a link server's record has none of the JSON keys
        val link = LinkParser.parseLink("trojan://pw@b.example:443?security=tls&sni=b.example#B").toJson()
        for (k in listOf("source", "json", "extraOutbounds", "jsonMode", "jsonInfo")) assertFalse(k, link.has(k))
        // the migration of old stores leaves a JSON server alone
        assertTrue(LinkParser.migrateStoredServer(s) === s)
    }

    @Test fun shareLink_ofAJsonServer_isItsConfigPretty() {
        val s = imp("xray-fragment.json").servers.single()
        val text = LinkParser.buildShareLink(s)
        assertTrue(text.startsWith("{\n  \""))
        assertEquals(Canon.of(s.json), Canon.of(JSONObject(text)))
    }

    @Test fun edits_reDeriveFromTheConfig_andRefuseWhatIsNoConfig() {
        val s = imp("xray-fragment.json").servers.single()
        val same = JsonImport.applyEdits(s, s.name, s.jsonMode, JsonText.pretty(s.json))
        assertTrue(same.edited.isEmpty())
        val e = JsonImport.applyEdits(s, " Mine ", JsonImport.MODE_RAW, JsonText.pretty(s.json).replace("edge1.example.com", "104.16.1.1"))
        assertEquals(s.id, e.id)
        assertEquals("Mine", e.name); assertEquals(JsonImport.MODE_RAW, e.jsonMode)
        assertEquals("104.16.1.1", e.address)
        assertEquals("104.16.1.1", e.outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address"))
        assertEquals(listOf("fragment"), tags(e.extraOutbounds))
        // raw stays the provider's own text: a refresh finds the server by it first
        assertEquals(s.raw, e.raw)
        assertTrue(e.raw.contains("edge1.example.com"))
        assertTrue(JsonText.minify(e.json).contains("104.16.1.1"))
        assertTrue(e.edited.containsAll(listOf("name", "jsonMode", "json")))
        try {
            JsonImport.applyEdits(s, "x", JsonImport.MODE_FULL, "{ not json")
            fail("bad JSON saved")
        } catch (ex: IllegalArgumentException) {
            assertTrue(ex.message ?: "", (ex.message ?: "").startsWith("Not valid JSON"))
        }
        try {
            JsonImport.applyEdits(s, "x", JsonImport.MODE_FULL, "{\"outbounds\":[{\"tag\":\"direct\",\"protocol\":\"freedom\"}]}")
            fail("a config with no proxy outbound saved")
        } catch (ex: IllegalArgumentException) {
            assertEquals(JsonImport.NO_PROXY, ex.message)
        }
        // a balancer's member stays the member it was
        val b = imp("xray-balancer.json").servers[1]
        val b2 = JsonImport.applyEdits(b, b.name, JsonImport.MODE_FULL, JsonText.pretty(b.json).replace("\"pw2\"", "\"pw3\""))
        assertEquals("trojan", b2.protocol); assertEquals("edge2.example.com", b2.address)
    }

    /* ------------------------------ full mode ------------------------------ */

    @Test fun full_single_helpersBesideTheMainOutbound_namespaced() {
        val s = imp("xray-fragment.json").servers.single()
        val c = ConfigBuilder.build(ConnectionPlan.Single(s), settings())
        assertEquals("proxy~fragment", dialer(tagged(c, "proxy")))
        val h = tagged(c, "proxy~fragment")
        assertEquals("freedom", h.getString("protocol"))
        assertEquals("tlshello", h.getJSONObject("settings").getJSONObject("fragment").getString("packets"))
        assertTrue(tags(outs(c)).none { t: String -> t == "fragment" })
        // its own routing is not the app's: the app's catch-all
        assertEquals("proxy", rules(c).last().getString("outboundTag")); assertEquals("0-65535", rules(c).last().getString("port"))
    }

    @Test fun full_chainFixture_everyReferenceRewritten() {
        val s = imp("xray-chain.json").servers.single()
        val c = ConfigBuilder.build(ConnectionPlan.Single(s), settings())
        val proxy = tagged(c, "proxy")
        // Xray 26 / PattN refuse proxySettings at load: the hop goes as the dialerProxy it was migrated to
        assertFalse(proxy.has("proxySettings"))
        assertEquals("proxy~hop1", dialer(proxy))
        assertEquals("hop1", s.outbound.getJSONObject("proxySettings").getString("tag"))
        assertTrue(outs(c).none { o: JSONObject -> o.has("proxySettings") })
        assertEquals(8, proxy.getJSONObject("mux").getInt("concurrency"))
        assertEquals("proxy~frag", dialer(tagged(c, "proxy~hop1")))
        assertEquals("freedom", tagged(c, "proxy~frag").getString("protocol"))
    }

    @Test fun full_advancedTargets_twoJsonServersNeverCollide() {
        val frag = imp("xray-fragment.json").servers.single()
        val chain = imp("xray-chain.json").servers.single()
        val plan = ConnectionPlan.Advanced(listOf(RouteRule("domain", "a.example", frag.id)), chain.id, mapOf(frag.id to frag, chain.id to chain), emptyMap())
        val c = ConfigBuilder.build(plan, settings())
        assertEquals("out-${frag.id}~fragment", dialer(tagged(c, "out-${frag.id}")))
        assertEquals("freedom", tagged(c, "out-${frag.id}~fragment").getString("protocol"))
        assertEquals("out-${chain.id}~hop1", dialer(tagged(c, "out-${chain.id}")))
        assertFalse(tagged(c, "out-${chain.id}").has("proxySettings"))
        assertEquals("out-${chain.id}~frag", dialer(tagged(c, "out-${chain.id}~hop1")))
        val all = tags(outs(c))
        assertEquals(all.size, all.toSet().size)
    }

    @Test fun full_chainHops_aJsonServerBehindAnotherDropsItsHelpers() {
        val frag = imp("xray-fragment.json").servers.single()
        val chainJson = imp("xray-chain.json").servers.single()
        val entry = LinkParser.parseLink("trojan://pw@entry.example:443?security=tls&sni=entry.example&type=tcp#entry")
        for (j in listOf(frag, chainJson)) {
            val c = ConfigBuilder.build(ConnectionPlan.Chain("c", listOf(entry, j)), settings())
            val exit = tagged(c, "proxy")
            assertEquals("proxy-h0", dialer(exit))
            assertFalse(exit.has("proxySettings"))
            assertTrue(tags(outs(c)).none { t: String -> t.contains("~") })
        }
        // the first hop keeps them
        val c = ConfigBuilder.build(ConnectionPlan.Chain("c", listOf(frag, entry)), settings())
        assertEquals("proxy-h0~fragment", dialer(tagged(c, "proxy-h0")))
        assertEquals("freedom", tagged(c, "proxy-h0~fragment").getString("protocol"))
        assertEquals("proxy-h0", dialer(tagged(c, "proxy")))
    }

    @Test fun full_theTestConfigCarriesTheHelpers_andAllowInsecureNeverReachesTheCore() {
        val frag = imp("xray-fragment.json").servers.single()
        val t = ConfigBuilder.buildTestConfig(frag, 20999)
        assertEquals("proxy~fragment", dialer(tagged(t, "proxy")))
        assertEquals("freedom", tagged(t, "proxy~fragment").getString("protocol"))
        val sub = imp("xray-subscription.json").servers[0]
        val c = ConfigBuilder.build(ConnectionPlan.Single(sub), settings())
        assertFalse(stream(tagged(c, "proxy")).getJSONObject("tlsSettings").has("allowInsecure"))
    }

    /* ------------------------------ raw mode ------------------------------ */

    @Test fun raw_theConfigAsWritten_withTheAppsInbounds() {
        val s = imp("xray-fragment.json").servers.single()
        val st = settings().copy(logLevel = "debug")
        val auth = LocalAuth("u", "p")
        val raw = ConfigBuilder.buildRawConfig(s, st, inboundAuth = auth)
        val full = ConfigBuilder.build(ConnectionPlan.Single(s), st, inboundAuth = auth)
        assertEquals(Canon.of(full.getJSONArray("inbounds")), Canon.of(raw.getJSONArray("inbounds")))
        assertEquals("debug", raw.getJSONObject("log").getString("loglevel"))
        val cfg = JSONObject(fixture("xray-fragment.json"))
        assertEquals(Canon.of(cfg.getJSONObject("routing")), Canon.of(raw.getJSONObject("routing")))
        assertEquals(Canon.of(cfg.getJSONObject("dns")), Canon.of(raw.getJSONObject("dns")))
        assertEquals(tags(outs(cfg)), tags(outs(raw)))
        assertEquals("fragment", dialer(tagged(raw, "proxy")))
        // a balancer runs as a balancer
        val b = imp("xray-balancer.json").servers[1]
        val rb = ConfigBuilder.buildRawConfig(b, st)
        val bcfg = JSONObject(fixture("xray-balancer.json"))
        assertEquals(Canon.of(bcfg.getJSONObject("routing")), Canon.of(rb.getJSONObject("routing")))
        assertEquals(Canon.of(bcfg.getJSONObject("observatory")), Canon.of(rb.getJSONObject("observatory")))
        // the cores refuse allowInsecure, so it goes; the rest of the TLS stays
        val sub = imp("xray-subscription.json").servers[0]
        val tls = stream(tagged(ConfigBuilder.buildRawConfig(sub, st), "proxy")).getJSONObject("tlsSettings")
        assertFalse(tls.has("allowInsecure")); assertEquals("chrome", tls.getString("fingerprint")); assertEquals("host1.example.org", tls.getString("serverName"))
        // a proxySettings hop, which Xray 26 refuses at load, goes as the dialerProxy it was migrated to — its own tag
        val chain = imp("xray-chain.json").servers.single()
        val rc = ConfigBuilder.buildRawConfig(chain, st)
        val cfx = JSONArray(fixture("xray-chain.json")).getJSONObject(0)
        val fxOuts = outs(cfx)
        assertFalse(tagged(rc, "proxy").has("proxySettings"))
        val wantStream = JSONObject(fxOuts[0].getJSONObject("streamSettings").toString()).put("sockopt", JSONObject().put("dialerProxy", "hop1"))
        assertEquals(Canon.of(wantStream), Canon.of(stream(tagged(rc, "proxy"))))
        assertEquals(fxOuts.drop(1).map { o: JSONObject -> Canon.of(o) }, outs(rc).drop(1).map { o: JSONObject -> Canon.of(o) })
        assertEquals(Canon.of(cfx.getJSONObject("routing")), Canon.of(rc.getJSONObject("routing")))
        // the stored record keeps its config as written
        assertEquals("hop1", outs(chain.json!!)[0].getJSONObject("proxySettings").getString("tag"))
    }

    @Test fun raw_lanSharing_hasItsInboundsAndItsLoopbackGuardFirst() {
        val s = imp("xray-fragment.json").servers.single()
        val lan = LanShare(enabled = true, user = "u1", pass = "p1")
        val c = ConfigBuilder.buildRawConfig(s, settings(), lan = lan)
        val inTags = (0 until c.getJSONArray("inbounds").length()).map { i: Int -> c.getJSONArray("inbounds").getJSONObject(i).getString("tag") }
        assertEquals(listOf("socks-in", "http-in", LanShare.SOCKS_TAG, LanShare.HTTP_TAG), inTags)
        val r = rules(c)
        assertEquals(ConfigBuilder.RAW_LAN_BLOCK, r[0].getString("outboundTag"))
        assertEquals(ConfigBuilder.RAW_LAN_BLOCK, r[1].getString("outboundTag"))
        assertEquals("blackhole", tagged(c, ConfigBuilder.RAW_LAN_BLOCK).getString("protocol"))
        assertEquals(5, r.size)
        // without LAN sharing (its port taken), the config's own three rules
        val without = JSONObject(TunnelSetup.withoutLan(c.toString()))
        assertEquals(3, rules(without).size)
    }

    @Test fun raw_runsOnlyForASingleConnect_elsewhereTheFullFormAndALogLine() {
        val s = imp("xray-fragment.json").servers.single().copy(jsonMode = JsonImport.MODE_RAW)
        val st = settings()
        val log = ArrayList<String>()
        val cc = TunnelSetup.coreConfig(EngineChoice.XRAY, ConnectionPlan.Single(s), st, false, emptyMap(), null, null) { l: String -> log.add(l) }
        assertTrue(cc.raw); assertEquals(EngineChoice.XRAY, cc.engine)
        assertEquals(Canon.of(JSONObject(fixture("xray-fragment.json")).getJSONObject("routing")), Canon.of(JSONObject(cc.json).getJSONObject("routing")))
        assertTrue(log.toString(), log.any { l: String -> l.startsWith("Running \"🇩🇪 frag\" exactly as written (raw JSON)") })
        // sing-box cannot run it: an Xray core all the same
        val sb = TunnelSetup.coreConfig(EngineChoice.SINGBOX, ConnectionPlan.Single(s), st, false, emptyMap(), null, null) { l: String -> log.add(l) }
        assertTrue(sb.raw); assertEquals(EngineChoice.XRAY, sb.engine)
        // in a chain: its full form, said once
        log.clear()
        val entry = LinkParser.parseLink("trojan://pw@entry.example:443?security=tls&sni=entry.example&type=tcp#entry")
        val ch = TunnelSetup.coreConfig(EngineChoice.XRAY, ConnectionPlan.Chain("c", listOf(s, entry)), st, false, emptyMap(), null, null) { l: String -> log.add(l) }
        assertFalse(ch.raw)
        assertEquals(1, log.count { l: String -> l == "\"🇩🇪 frag\" is set to run raw, but a chain/routing target uses its full form" })
        assertEquals("proxy-h0~fragment", dialer(tagged(JSONObject(ch.json), "proxy-h0")))
        // full mode is not raw
        assertFalse(TunnelSetup.coreConfig(EngineChoice.XRAY, ConnectionPlan.Single(s.copy(jsonMode = JsonImport.MODE_FULL)), st, false, emptyMap(), null, null) { _: String -> }.raw)
    }

    /* ------------------------------ a refresh ------------------------------ */

    @Test fun refresh_sameIds_theUsersChoicesKept() {
        val sub = Subscription("sub-j", "panel", "https://panel.example/sub")
        val first = imp("xray-subscription.json").servers.map { s: ServerConfig -> s.copy(subId = sub.id) }
        val old = first.toMutableList()
        old[0] = JsonImport.applyEdits(old[0], old[0].name, JsonImport.MODE_RAW, JsonText.pretty(old[0].json))
        old[1] = JsonImport.applyEdits(old[1], "Mine", old[1].jsonMode, JsonText.pretty(old[1].json))
        // the panel's next answer: one config's remarks changed
        val arr = JSONArray(fixture("xray-subscription.json"))
        arr.getJSONObject(2).put("remarks", "🇩🇪 DE-1 · 5 GB left")
        val fresh = JsonImport.importJson(arr.toString())?.servers ?: throw AssertionError("not read")
        val m = SubRefresh.merge(old, fresh, sub.id)
        assertEquals(old.map { s: ServerConfig -> s.id }, m.servers.map { s: ServerConfig -> s.id })
        assertEquals(5, m.kept); assertEquals(0, m.added); assertEquals(0, m.dropped)
        assertEquals("🇩🇪 DE-1 · 5 GB left", m.servers[0].name)
        assertEquals(JsonImport.MODE_RAW, m.servers[0].jsonMode)
        assertEquals("Mine", m.servers[1].name)
        assertTrue(m.servers.all { s: ServerConfig -> s.isJson && s.subId == sub.id })
        // a config the user edited stays theirs
        val mine = JsonImport.applyEdits(first[2], first[2].name, JsonImport.MODE_FULL, JsonText.pretty(first[2].json).replace("edge3.example.com", "104.16.1.1"))
        val carried = SubRefresh.carry(mine, fresh[2])
        assertEquals(mine.id, carried.id)
        assertEquals("104.16.1.1", carried.address)
        assertEquals(Canon.of(mine.json), Canon.of(carried.json))
        // ...through a whole refresh too: its raw is still the provider's text, so it is
        // found by it first — even with its address edited, the identity no longer the panel's
        val edited = first.toMutableList()
        edited[2] = mine
        val again = imp("xray-subscription.json").servers
        val m2 = SubRefresh.merge(edited, again, sub.id)
        assertEquals(edited.map { s: ServerConfig -> s.id }, m2.servers.map { s: ServerConfig -> s.id })
        assertEquals(5, m2.kept)
        val back = m2.servers[2]
        assertEquals("104.16.1.1", back.address)
        assertEquals("104.16.1.1", back.outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address"))
        assertEquals(Canon.of(mine.json), Canon.of(back.json))
        assertEquals(again[2].raw, back.raw)
        assertTrue(back.edited.contains("json"))
    }
}
