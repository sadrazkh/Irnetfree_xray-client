package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The cases of tests/helloCut.test.js: what gets a cut hello and what is left
 * alone, that an ordinary connection's config does not change by a byte, that a
 * config with its own fragment keeps it, and the check itself against a fake dial.
 */
class HelloCutTest {
    private fun out(over: JSONObject = JSONObject(), top: JSONObject = JSONObject()): JSONObject {
        val ss = JSONObject().put("network", "tcp").put("security", "tls")
        for (k in over.keys().asSequence().toList()) ss.put(k, over.get(k))
        val o = JSONObject().put("protocol", "vless").put("streamSettings", ss)
        for (k in top.keys().asSequence().toList()) o.put(k, top.get(k))
        return o
    }

    @Test fun aHelloOverTcpTakesTheCutWhatSaysHowItDialsDoesNot() {
        for (net in listOf("tcp", "raw", "ws", "grpc", "httpupgrade", "xhttp", "splithttp", "h2")) assertTrue(net, HelloCut.takesCut(out(JSONObject().put("network", net))))
        assertTrue(HelloCut.takesCut(out(JSONObject().put("security", "reality"))))
        assertTrue("no network written is tcp", HelloCut.takesCut(out(JSONObject().put("network", ""))))
        assertFalse("its own fragment", HelloCut.takesCut(out(top = JSONObject().put("_fragment", "tlshello,10-20,1-2"))))
        assertFalse("its own noise", HelloCut.takesCut(out(top = JSONObject().put("_noise", "random"))))
        assertFalse("a final mask", HelloCut.takesCut(out(JSONObject().put("finalmask", JSONObject().put("tcp", JSONArray())))))
        assertFalse("a dial mode", HelloCut.takesCut(out(JSONObject().put("sockopt", JSONObject().put("dialMode", "x")))))
        assertFalse("a hop in front of it", HelloCut.takesCut(out(JSONObject().put("sockopt", JSONObject().put("dialerProxy", "hop")))))
        assertFalse("ECH", HelloCut.takesCut(out(JSONObject().put("tlsSettings", JSONObject().put("echConfigList", "x")))))
        assertFalse("QUIC", HelloCut.takesCut(out(JSONObject().put("tlsSettings", JSONObject().put("alpn", JSONArray().put("h3"))))))
        assertTrue("h2 beside h3 is TCP too", HelloCut.takesCut(out(JSONObject().put("tlsSettings", JSONObject().put("alpn", JSONArray().put("h3").put("h2"))))))
        assertFalse("no TLS", HelloCut.takesCut(out(JSONObject().put("security", "none"))))
        for (net in listOf("kcp", "mkcp", "quic", "hysteria")) assertFalse(net, HelloCut.takesCut(out(JSONObject().put("network", net))))
        assertFalse(HelloCut.takesCut(JSONObject().put("protocol", "wireguard").put("settings", JSONObject())))
        assertFalse(HelloCut.takesCut(null))
        assertEquals("tlshello,100-200,0", HelloCut.HELLO_CUT)
    }

    @Test fun cutHellosMarksOnlyWhatTakesIt() {
        val plain = out()
        val own = out(top = JSONObject().put("_fragment", "1-3,5-9,20-30"))
        val wg = JSONObject().put("protocol", "wireguard").put("settings", JSONObject())
        HelloCut.cutHellos(JSONArray().put(plain).put(own).put(wg))
        assertEquals(HelloCut.HELLO_CUT, plain.getString("_fragment"))
        assertEquals("1-3,5-9,20-30", own.getString("_fragment"))
        assertFalse(wg.has("_fragment"))
    }

    /* ----------------------------- the config ----------------------------- */

    private fun vless(id: String, host: String, security: String = "tls", frag: String = ""): ServerConfig {
        val user = JSONObject().put("id", "00000000-0000-0000-0000-000000000000").put("encryption", "none")
        val vnext = JSONObject().put("address", host).put("port", 443).put("users", JSONArray().put(user))
        val ss = JSONObject().put("network", "tcp").put("security", security)
        if (security == "reality") ss.put("realitySettings", JSONObject().put("serverName", "cover.test").put("publicKey", "A".repeat(43)).put("shortId", "").put("fingerprint", "chrome"))
        else ss.put("tlsSettings", JSONObject().put("serverName", "cover.test").put("pinnedPeerCertSha256", "a".repeat(64)))
        val ob = JSONObject().put("protocol", "vless").put("settings", JSONObject().put("vnext", JSONArray().put(vnext))).put("streamSettings", ss)
        if (frag.isNotEmpty()) ob.put("_fragment", frag)
        return ServerConfig(id = id, name = id, protocol = "vless", address = host, port = 443, raw = "", outbound = ob)
    }
    private val pinned = vless("p", "p.example")
    private val reality = vless("r", "r.example", security = "reality")
    private val ownFrag = vless("f", "f.example", frag = "1-3,5-9,20-30")
    private val settings = AppSettings(blockAds = false, enableSniffing = true)
    private fun outs(c: JSONObject): List<JSONObject> { val a = c.getJSONArray("outbounds"); return (0 until a.length()).map { i: Int -> a.getJSONObject(i) } }
    private fun dialerOf(c: JSONObject, tag: String): JSONObject? {
        val o = outs(c).first { x: JSONObject -> x.getString("tag") == tag }
        val via = o.optJSONObject("streamSettings")?.optJSONObject("sockopt")?.optString("dialerProxy") ?: ""
        if (via.isEmpty()) return null
        return outs(c).first { x: JSONObject -> x.getString("tag") == via }
    }

    @Test fun offTheConfigIsWhatItAlwaysWasToTheByte() {
        for (s in listOf(pinned, reality, ownFrag)) {
            val plan = ConnectionPlan.Single(s)
            assertEquals(s.id, Canon.of(ConfigBuilder.build(plan, settings)), Canon.of(ConfigBuilder.build(plan, settings, cutHello = false)))
            assertEquals(s.id, Canon.of(ConfigBuilder.buildTestConfig(s, 9)), Canon.of(ConfigBuilder.buildTestConfig(s, 9, cutHello = false)))
        }
        val whole = ConfigBuilder.build(ConnectionPlan.Single(pinned), settings)
        assertFalse(outs(whole).any { o: JSONObject -> o.optJSONObject("settings")?.has("fragment") == true })
        assertNull(dialerOf(whole, "proxy"))
    }

    @Test fun onAServerDialsThroughADialerThatCutsIntoRecordsWithNoPause() {
        for (s in listOf(pinned, reality)) {
            val c = ConfigBuilder.build(ConnectionPlan.Single(s), settings, cutHello = true)
            val d = dialerOf(c, "proxy") ?: throw AssertionError("${s.id}: no dialer")
            assertEquals("freedom", d.getString("protocol"))
            assertEquals("""{"interval":"0-0","length":"100-200","packets":"tlshello"}""", Canon.of(d.getJSONObject("settings").getJSONObject("fragment")))
            assertFalse("the marker is not left for the core", outs(c).any { o: JSONObject -> o.has("_fragment") })
            val t = ConfigBuilder.buildTestConfig(s, 9, cutHello = true)
            assertEquals("a test measures what the live core would do", "0-0", dialerOf(t, "proxy")?.getJSONObject("settings")?.getJSONObject("fragment")?.getString("interval"))
        }
        // a config with a fragment of its own keeps its own
        val own = dialerOf(ConfigBuilder.build(ConnectionPlan.Single(ownFrag), settings, cutHello = true), "proxy") ?: throw AssertionError("no dialer")
        assertEquals("""{"interval":"20-30","length":"5-9","packets":"1-3"}""", Canon.of(own.getJSONObject("settings").getJSONObject("fragment")))
        assertFalse("the stored record is not touched", pinned.outbound.has("_fragment"))
    }

    @Test fun aChainCutsItsFirstHopAndTheNextRidesOnItAsItDid() {
        val c = ConfigBuilder.build(ConnectionPlan.Chain("c", listOf(pinned, reality)), settings, cutHello = true)
        val hops = outs(c).filter { o: JSONObject -> o.optString("protocol") == "vless" }
        assertEquals(2, hops.size)
        val dials = hops.map { h: JSONObject -> h.optJSONObject("streamSettings")?.optJSONObject("sockopt")?.optString("dialerProxy") ?: "" }
        assertEquals("one hop has the dialer", 1, dials.count { d: String -> d.startsWith("dpi-") })
        assertTrue("the other rides on a hop", dials.any { d: String -> d.isNotEmpty() && !d.startsWith("dpi-") && hops.any { h: JSONObject -> h.getString("tag") == d } })
    }

    /* ----------------------------- the check ----------------------------- */

    @Test fun aCertificateNamesASiteByItsExactNameOrOneWildcardLabel() {
        val c = listOf("DNS:*.google.com", "DNS:google.com", "IP Address:1.1.1.1")
        assertTrue(HelloCut.certNames(c, "www.google.com"))
        assertTrue(HelloCut.certNames(c, "google.com"))
        assertTrue(HelloCut.certNames(c, "WWW.GOOGLE.COM"))
        assertTrue("without the prefix too, as Java hands them over", HelloCut.certNames(listOf("*.google.com"), "www.google.com"))
        assertFalse(HelloCut.certNames(c, "a.b.google.com"))
        assertFalse(HelloCut.certNames(c, "www.googleXcom"))
        assertFalse(HelloCut.certNames(listOf("cloudflare-dns.com", "one.one.one.one"), "www.google.com"))
        assertFalse(HelloCut.certNames(emptyList(), "www.google.com"))
        assertFalse(HelloCut.certNames(c, ""))
    }

    private val asGoogle = listOf("*.google.com")
    private val asCloudflare = listOf("*.cloudflare.com")
    private val asItself = listOf("one.one.one.one")
    /** A dial that answers each address as told: a list of names, null for no answer, "hang" for never. */
    private fun fake(answers: Map<String, Any?>): (String, String) -> List<String>? = { ip: String, _: String ->
        val a = answers[ip]
        if (a == "hang") Thread.sleep(5000)
        if (a == "fail") throw IllegalStateException("reset")
        (a as? List<*>)?.map { x: Any? -> x.toString() }
    }

    @Test fun theCheckACertificateNamingTheSiteAskedForProvesItOneOfItsOwnProvesTheOpposite() {
        assertEquals(true, HelloCut.pathReadsHello(timeoutMs = 200, dial = fake(mapOf("1.1.1.1" to asGoogle, "8.8.8.8" to "hang"))))
        assertEquals(false, HelloCut.pathReadsHello(timeoutMs = 200, dial = fake(mapOf("1.1.1.1" to asItself, "8.8.8.8" to asItself))))
        assertEquals("one that reads is enough", true, HelloCut.pathReadsHello(timeoutMs = 200, dial = fake(mapOf("1.1.1.1" to asItself, "8.8.8.8" to asCloudflare))))
    }

    @Test fun theCheckWhenNothingAnswersNothingIsKnownAndItNeverWaitsPastItsLimit() {
        assertNull(HelloCut.pathReadsHello(timeoutMs = 200, dial = fake(mapOf("1.1.1.1" to "fail", "8.8.8.8" to "fail"))))
        val t0 = System.currentTimeMillis()
        assertNull(HelloCut.pathReadsHello(timeoutMs = 100, dial = fake(mapOf("1.1.1.1" to "hang", "8.8.8.8" to "hang"))))
        assertTrue(System.currentTimeMillis() - t0 < 1500)
        assertEquals("an address that answered as itself is an answer", false, HelloCut.pathReadsHello(timeoutMs = 100, dial = fake(mapOf("1.1.1.1" to asItself, "8.8.8.8" to "hang"))))
        assertNull(HelloCut.pathReadsHello(samples = emptyList(), timeoutMs = 100, dial = fake(emptyMap())))
    }
}
