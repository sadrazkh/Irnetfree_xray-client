package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * PattN's ECH outbound (`echOutbound`): read from links into tlsSettings,
 * written back into share links with a tag, taken out by every builder as a
 * shared `ech-<n>` outbound that `echSockopt.dialerProxy` names, edited in the
 * server editor with its Example — the desktop's parser.js echOutboundOf /
 * echOutboundShare, configBuilder.js applyEchOutbounds and serverFields.js
 * echOutboundExample. (vmess:// links themselves need android.util.Base64,
 * a stub here: their JSON is read through vmessFromJson.)
 */
class EchOutboundTest {
    /** patterniha's, 2026-10-20 (PattN P34 / PattNG P67). */
    private val EO = """{"tag":"tls-repack-dns","protocol":"direct","settings":{"redirect":"1.1.1.1:443"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"www.microsoft.com","verifyPeerCertByName":"fromMitM,www.microsoft.com","alpn":["fromMitM"],"fingerprint":"chrome"}}}"""
    private val EO_BODY = """{"protocol":"direct","settings":{"redirect":"1.1.1.1:443"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"www.microsoft.com","verifyPeerCertByName":"fromMitM,www.microsoft.com","alpn":["fromMitM"],"fingerprint":"chrome"}}}"""
    private val OTHER = """{"protocol":"direct","settings":{"redirect":"8.8.8.8:443"}}"""
    private val H2C = "cloudflare-ech.com+h2c://1.1.1.1/dns-query"

    private fun enc(s: String) = java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20")
    private fun vless(eo: String, ech: String = H2C, host: String = "a.example.com"): ServerConfig =
        LinkParser.parseLink("vless://u@$host:443?type=ws&path=%2F&host=$host&security=tls&sni=$host&ech=${enc(ech)}&echOutbound=${enc(eo)}#$host")
    private fun tls(s: ServerConfig): JSONObject = s.outbound.getJSONObject("streamSettings").getJSONObject("tlsSettings")
    private fun outs(c: JSONObject): List<JSONObject> { val a = c.getJSONArray("outbounds"); return (0 until a.length()).map { i: Int -> a.getJSONObject(i) } }
    private fun tagged(c: JSONObject, tag: String): JSONObject = outs(c).first { o: JSONObject -> o.optString("tag") == tag }
    private fun echTags(c: JSONObject): List<String> = outs(c).map { o: JSONObject -> o.optString("tag") }.filter { t: String -> Regex("^ech-\\d+$").matches(t) }
    private fun tlsOut(c: JSONObject, tag: String): JSONObject = tagged(c, tag).getJSONObject("streamSettings").getJSONObject("tlsSettings")
    private val settings = AppSettings(blockAds = false, enableSniffing = false)

    /* ------------------------------ links ------------------------------ */

    @Test fun aLinkKeepsTheOutboundInTlsSettings() {
        val t = tls(vless(EO))
        assertEquals(H2C, t.getString("echConfigList"))
        assertTrue(Canon.same(EO, t.getJSONObject("echOutbound")))
        // trojan and hysteria2 read it the same way
        assertTrue(Canon.same(EO, tls(LinkParser.parseLink("trojan://pw@t.example.com:443?sni=t.example.com&ech=${enc(H2C)}&echOutbound=${enc(EO)}#t")).getJSONObject("echOutbound")))
        assertTrue(Canon.same(EO, tls(LinkParser.parseLink("hysteria2://pw@h.example.com:443/?sni=h.example.com&ech=${enc(H2C)}&echOutbound=${enc(EO)}#h")).getJSONObject("echOutbound")))
        // vmess JSON: a string of JSON, or the object itself
        fun vm(extra: String) = tls(LinkParser.vmessFromJson(JSONObject("""{"v":"2","ps":"M","add":"m.example.com","port":"443","id":"u","net":"ws","tls":"tls","ech":"$H2C",$extra}"""), "vmess://x"))
        assertTrue(Canon.same(EO, vm("\"echOutbound\":" + JSONObject.quote(EO)).getJSONObject("echOutbound")))
        assertTrue(Canon.same(EO, vm("\"echOutbound\":$EO").getJSONObject("echOutbound")))
        assertFalse(vm("\"echOutbound\":\"\"").has("echOutbound"))
    }

    @Test fun jsonWithCommentsAndTrailingCommasIsRead() {
        val text = "{\n  // PattN's own\n  \"protocol\": \"direct\", /* the resolver */\n  \"settings\": {\"redirect\": \"1.1.1.1:443\",},\n}"
        assertTrue(Canon.same("""{"protocol":"direct","settings":{"redirect":"1.1.1.1:443"}}""", LinkParser.echOutboundOf(text)))
        assertTrue(Canon.same("""{"protocol":"direct","settings":{"redirect":"1.1.1.1:443"}}""", tls(vless(text)).getJSONObject("echOutbound")))
        // a comment's characters inside a string are the string's
        assertEquals("{\"a\":\"x//y\", \n\"b\":[1,2]}", LinkParser.looseJson("{\"a\":\"x//y\", // c\n\"b\":[1,2,],}"))
        assertEquals("{\"a\":\"/*k*/\"}", LinkParser.looseJson("{\"a\":\"/*k*/\"/* gone */}"))
    }

    @Test fun anythingButAnObjectNamingAProtocolIsDropped() {
        for (bad in listOf("", "   ", "not json", "[1,2]", "{\"settings\":{}}", "{\"protocol\":\"\"}", "{\"protocol\":\"  \"}", "{\"protocol\":5}", "{\"protocol\": ")) {
            assertNull(bad, LinkParser.echOutboundOf(bad))
            assertFalse(bad, tls(vless(bad)).has("echOutbound"))
        }
        assertNull(LinkParser.echOutboundOf(null))
        assertNull(LinkParser.echOutboundOf(JSONArray().put(1)))
        // an object is copied, never shared
        val o = JSONObject(OTHER)
        val copy = LinkParser.echOutboundOf(o)!!
        copy.put("protocol", "freedom")
        assertEquals("direct", o.getString("protocol"))
    }

    @Test fun theShareLinkCarriesItWithATag() {
        assertTrue(Canon.same("""{"tag":"ech-out","protocol":"direct"}""", JSONObject(LinkParser.echOutboundShare(JSONObject("""{"protocol":"direct"}""")))))
        // an existing tag wins, and the line is one line
        val kept = LinkParser.echOutboundShare(JSONObject(EO))
        assertTrue(Canon.same(EO, JSONObject(kept))); assertFalse(kept.contains("\n"))
        for (eo in listOf(EO, OTHER)) {
            val want = if (eo == EO) EO else """{"tag":"ech-out","protocol":"direct","settings":{"redirect":"8.8.8.8:443"}}"""
            for (s in listOf(
                vless(eo),
                LinkParser.parseLink("trojan://pw@t.example.com:443?sni=t.example.com&ech=${enc(H2C)}&echOutbound=${enc(eo)}#t"),
                LinkParser.parseLink("hysteria2://pw@h.example.com:443/?sni=h.example.com&ech=${enc(H2C)}&echOutbound=${enc(eo)}#h")
            )) {
                val share = LinkParser.buildShareLink(s)
                assertTrue(share, share.contains("echOutbound="))
                val back = LinkParser.parseLink(share)
                assertTrue(share, Canon.same(want, tls(back).getJSONObject("echOutbound")))
                assertEquals(H2C, tls(back).getString("echConfigList"))
            }
        }
        // none: nothing written
        assertFalse(LinkParser.buildShareLink(LinkParser.parseLink("vless://u@a.example.com:443?security=tls&sni=a.example.com#n")).contains("echOutbound"))
    }

    /* ------------------------------ builders ------------------------------ */

    @Test fun aChainSharesOneEchOutbound_theKeyLeavesTlsSettings() {
        // the same outbound under two tags is one outbound: ours is the tag
        val a = vless(EO, host = "a.example.com")
        val b = vless(EO.replace("tls-repack-dns", "theirs"), host = "b.example.com")
        val c = ConfigBuilder.build(ConnectionPlan.Chain("c", listOf(a, b)), settings, geoAssets = true)
        assertEquals(listOf("ech-1"), echTags(c))
        assertTrue(Canon.same("""{"tag":"ech-1",${EO_BODY.substring(1)}""", tagged(c, "ech-1")))
        assertEquals("ech-1", outs(c).last().getString("tag"))
        for (tag in listOf("proxy-h0", "proxy")) {
            val t = tlsOut(c, tag)
            assertFalse(tag, t.has("echOutbound"))
            assertEquals(tag, "ech-1", t.getJSONObject("echSockopt").getString("dialerProxy"))
            assertEquals(H2C, t.getString("echConfigList"))
        }
        // the stored records are never touched
        assertTrue(tls(a).has("echOutbound")); assertFalse(tls(a).has("echSockopt"))
    }

    @Test fun aPoolShares_anotherOutboundIsEch2_andEchSockoptKeepsWhatItHad() {
        val a = vless(EO, host = "a.example.com")
        val b = vless(EO, host = "b.example.com")
        val pool = ConnectionPlan.Pool(listOf(PoolEntry("p1", "P", b.id, 60001, 60002, true)), a.id, mapOf(a.id to a, b.id to b), emptyMap())
        val p = ConfigBuilder.build(pool, settings, geoAssets = true)
        assertEquals(listOf("ech-1"), echTags(p))
        assertEquals("ech-1", tlsOut(p, "out-${a.id}").getJSONObject("echSockopt").getString("dialerProxy"))
        assertEquals("ech-1", tlsOut(p, "out-${b.id}").getJSONObject("echSockopt").getString("dialerProxy"))

        val ob = JSONObject(b.outbound.toString())
        ob.getJSONObject("streamSettings").getJSONObject("tlsSettings").put("echOutbound", JSONObject(OTHER))
            .put("echSockopt", JSONObject().put("domainStrategy", "UseIPv4"))
        val other = b.copy(outbound = ob)
        val c = ConfigBuilder.build(ConnectionPlan.Chain("c", listOf(a, other)), settings, geoAssets = true)
        assertEquals(listOf("ech-1", "ech-2"), echTags(c))
        assertTrue(Canon.same("""{"tag":"ech-2","protocol":"direct","settings":{"redirect":"8.8.8.8:443"}}""", tagged(c, "ech-2")))
        assertTrue(Canon.same("""{"domainStrategy":"UseIPv4","dialerProxy":"ech-2"}""", tlsOut(c, "proxy").getJSONObject("echSockopt")))
    }

    @Test fun withoutAListFetchedFromDnsItMeansNothing() {
        for (ech in listOf("AEX+/w==", "")) {
            val s = vless(EO, ech = ech)
            assertTrue(tls(s).has("echOutbound"))
            val c = ConfigBuilder.build(ConnectionPlan.Single(s), settings, geoAssets = true)
            assertEquals(emptyList<String>(), echTags(c))
            val t = tlsOut(c, "proxy")
            assertFalse(t.has("echOutbound")); assertFalse(t.has("echSockopt"))
        }
        assertTrue(ConfigBuilder.isEchQuery(H2C))
        assertTrue(ConfigBuilder.isEchQuery("udp://8.8.8.8"))
        assertTrue(ConfigBuilder.isEchQuery("x.example+https://[2606:4700::1111]/dns-query"))
        assertFalse(ConfigBuilder.isEchQuery("AEX+/w=="))
        assertFalse(ConfigBuilder.isEchQuery(""))
        assertFalse(ConfigBuilder.isEchQuery(null))
    }

    @Test fun theTestConfigGetsItToo() {
        val c = ConfigBuilder.buildTestConfig(vless(EO), 20000)
        assertEquals(listOf("proxy", "ech-1", "direct"), outs(c).map { o: JSONObject -> o.getString("tag") })
        val t = tlsOut(c, "proxy")
        assertFalse(t.has("echOutbound"))
        assertEquals("ech-1", t.getJSONObject("echSockopt").getString("dialerProxy"))
        assertTrue(Canon.same("""{"tag":"ech-1",${EO_BODY.substring(1)}""", tagged(c, "ech-1")))
    }

    @Test fun singBoxNeverSeesIt() {
        val c = SingboxConfig.build(vless(EO), AppSettings())
        assertFalse(c.toString().contains("echOutbound"))
        assertFalse(c.toString().contains("tls-repack-dns"))
        val o = c.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("cloudflare-ech.com", o.getJSONObject("tls").getJSONObject("ech").getString("query_server_name"))
    }

    /* ------------------------------ the editor ------------------------------ */

    private fun save(s: ServerConfig, edit: (ServerEditor.Fields) -> Unit = {}): ServerConfig {
        val f = ServerEditor.read(s); edit(f); return ServerEditor.apply(s, f)
    }

    @Test fun theEditorShowsItIndented_andWritesItBack() {
        val s = vless(EO)
        val f = ServerEditor.read(s)
        assertTrue(f.echOutbound, f.echOutbound.contains("\n  "))
        assertTrue(Canon.same(EO, JSONObject(f.echOutbound)))
        assertEquals("", ServerEditor.read(vless("")).echOutbound)
        // untouched: the record as it was, nothing recorded
        val same = save(s) { x: ServerEditor.Fields -> x.name = "renamed" }
        assertEquals(Canon.of(s.outbound), Canon.of(same.outbound)); assertEquals(listOf("name"), same.edited)
        // written as another text of the same object: no change either
        assertEquals(emptyList<String>(), save(s) { x: ServerEditor.Fields -> x.echOutbound = EO }.edited)
        // a new one, comments and all
        val e = save(s) { x: ServerEditor.Fields -> x.echOutbound = "{ // mine\n\"protocol\": \"direct\", \"settings\": {\"redirect\": \"8.8.8.8:443\"},\n}" }
        assertTrue(Canon.same(OTHER, tls(e).getJSONObject("echOutbound")))
        assertEquals(listOf("echOutbound"), e.edited)
        // emptied, or naming no protocol: the key goes
        assertFalse(tls(save(s) { x: ServerEditor.Fields -> x.echOutbound = "" }).has("echOutbound"))
        assertFalse(tls(save(s) { x: ServerEditor.Fields -> x.echOutbound = "{\"settings\":{}}" }).has("echOutbound"))
        // a new security writes it with the rest of TLS
        val plain = LinkParser.parseLink("vless://u@p.example.com:443?type=ws&path=%2F&security=none#p")
        val tlsNow = save(plain) { x: ServerEditor.Fields -> x.security = "tls"; x.sni = "p.example.com"; x.ech = H2C; x.echOutbound = OTHER }
        assertTrue(Canon.same(OTHER, tls(tlsNow).getJSONObject("echOutbound")))
    }

    @Test fun aHysteria2EditKeepsIt() {
        val s = LinkParser.parseLink("hysteria2://pw@h.example.com:443/?sni=h.example.com&ech=${enc(H2C)}&echOutbound=${enc(EO)}#h")
        val e = save(s) { x: ServerEditor.Fields -> x.sni = "other.example.com" }
        assertEquals("other.example.com", tls(e).getString("serverName"))
        assertTrue(Canon.same(EO, tls(e).getJSONObject("echOutbound")))
        assertFalse(tls(save(s) { x: ServerEditor.Fields -> x.echOutbound = "" }).has("echOutbound"))
    }

    @Test fun theProViewRefusesJsonItCannotRead_andItsExampleWritesThePair() {
        val s = vless(EO, ech = "cloudflare-ech.com+udp://1.1.1.1")
        val f = ServerEditor.read(s)
        val d = ServerEditor.toDraft("vless", f)
        assertTrue(Canon.same(EO, JSONObject(d.getValue("echOutbound"))))
        d["echOutbound"] = "{\"protocol\": "
        assertEquals(Triple("echOutbound", "security", "edit.err.json"), ServerEditor.problem("vless", d, false, false))
        // the Example, as its button writes it into the draft
        val ex = ServerEditor.echOutboundExample(d["ech"])
        d["ech"] = ex.ech; d["echOutbound"] = ex.echOutbound
        assertNull(ServerEditor.problem("vless", d, false, false))
        val e = ServerEditor.apply(s, ServerEditor.fromDraft("vless", d, f))
        assertEquals(H2C, tls(e).getString("echConfigList"))
        assertTrue(Canon.same(EO, tls(e).getJSONObject("echOutbound")))
    }

    @Test fun theExample() {
        assertEquals(H2C, ServerEditor.echOutboundExample("cloudflare-ech.com+udp://1.1.1.1").ech)
        assertEquals(H2C, ServerEditor.echOutboundExample("").ech)
        assertEquals(H2C, ServerEditor.echOutboundExample(null).ech)
        assertEquals("h2c://1.1.1.1/dns-query", ServerEditor.echOutboundExample("udp://8.8.8.8").ech)
        assertEquals(H2C, ServerEditor.echOutboundExample("AEX+/w==").ech)
        assertEquals("other.example+h2c://1.1.1.1/dns-query", ServerEditor.echOutboundExample(" other.example+https://dns.google/dns-query ").ech)
        val text = ServerEditor.echOutboundExample("").echOutbound
        assertTrue(Canon.same(EO, JSONObject(text)))
        assertTrue(text, text.contains("\n  \""))
        assertTrue(Canon.same(EO, JSONObject(ServerEditor.ECH_OUTBOUND_EXAMPLE)))
    }

    @Test fun theExampleButtonHasAWordInBothLanguages() {
        assertEquals("Example", I18n.word(I18n.EN, "sf.echOutbound.example"))
        assertEquals("نمونه", I18n.word(I18n.FA, "sf.echOutbound.example"))
        assertEquals("ECH outbound", I18n.word(I18n.EN, "sf.echOutbound"))
    }
}
