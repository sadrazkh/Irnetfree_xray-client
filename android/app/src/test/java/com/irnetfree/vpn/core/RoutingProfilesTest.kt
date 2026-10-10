package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/**
 * Routing profiles and "via a base" (RoutingProfiles.kt, ConfigBuilder) against
 * the desktop's tests/routingProfiles.test.js and the via cases of
 * tests/configBuilder.test.js: migration, the mirror, selection ids,
 * effectiveVia, the builder's tags for every via case, the refusals.
 */
class RoutingProfilesTest {
    private fun vless(id: String, host: String): ServerConfig {
        val ob = JSONObject().put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(JSONObject().put("address", host).put("port", 443)
                .put("users", JSONArray().put(JSONObject().put("id", "u-$id").put("encryption", "none"))))))
            .put("streamSettings", JSONObject().put("network", "ws").put("security", "tls")
                .put("tlsSettings", JSONObject().put("serverName", host).put("fingerprint", "chrome"))
                .put("wsSettings", JSONObject().put("path", "/").put("headers", JSONObject().put("Host", host))))
        return ServerConfig(id, id, "vless", host, 443, ob)
    }
    private fun settings(over: (AppSettings) -> AppSettings = { s: AppSettings -> s }) = over(AppSettings(blockAds = false, enableSniffing = false))
    private fun build(p: ConnectionPlan, muxIds: Set<String> = emptySet()): JSONObject = ConfigBuilder.build(p, settings(), geoAssets = true, muxIds = muxIds)
    private fun outs(c: JSONObject): List<JSONObject> { val a = c.getJSONArray("outbounds"); return (0 until a.length()).map { i: Int -> a.getJSONObject(i) } }
    private fun tags(c: JSONObject): List<String> = outs(c).map { o: JSONObject -> o.optString("tag") }
    private fun tagged(c: JSONObject, tag: String): JSONObject = outs(c).firstOrNull { o: JSONObject -> o.optString("tag") == tag } ?: throw AssertionError("no outbound $tag in ${tags(c)}")
    private fun dialer(o: JSONObject): String = o.optJSONObject("streamSettings")?.optJSONObject("sockopt")?.optString("dialerProxy") ?: ""
    private fun rules(c: JSONObject): List<JSONObject> { val a = c.getJSONObject("routing").getJSONArray("rules"); return (0 until a.length()).map { i: Int -> a.getJSONObject(i) } }
    private fun domains(r: JSONObject): List<String> = r.optJSONArray("domain")?.let { a: JSONArray -> (0 until a.length()).map { i: Int -> a.getString(i) } } ?: emptyList()
    private fun ruleFor(c: JSONObject, domain: String): JSONObject = rules(c).firstOrNull { r: JSONObject -> domains(r).contains(domain) } ?: throw AssertionError("no rule for $domain")

    private val a = vless("a", "a.example")
    private val b = vless("b", "b.example")
    private val c = vless("c", "c.example")
    private val h1 = vless("h1", "h1.example")
    private val h2 = vless("h2", "h2.example")
    private val byId = listOf(a, b, c, h1, h2).associateBy { s: ServerConfig -> s.id }
    private val chains = mapOf("k1" to listOf(h1, h2), "base1" to listOf(a, b), "empty" to emptyList<ServerConfig>())

    private fun plan(rules: List<RouteRule>, def: String, defVia: String = RoutingProfiles.VIA_INHERIT, base: String? = null) =
        ConnectionPlan.Advanced(rules, def, byId, chains, defVia, base)

    /* ----------------------------- the model ----------------------------- */

    @Test fun migration_todaysSettingsBecomeRpDefault() {
        val s = AppSettings(routeRules = listOf(RouteRule("domain", "x.com", "a"), RouteRule("ip", "geoip:ir", "direct")), routeDefault = "b", advancedUseMode = true)
        val m = RoutingProfiles.migrate(null, s)
        assertTrue(m.changed)
        assertEquals(1, m.profiles.size)
        val p = m.profiles[0]
        assertEquals("rp-default", p.id)
        assertEquals("Advanced routing", p.name)
        assertEquals(s.routeRules, p.rules)
        assertEquals("b", p.def)
        assertTrue(p.useMode)
        assertNull(p.base)
        assertEquals("inherit", p.defVia)
        assertTrue(p.rules.all { r: RouteRule -> r.via.isEmpty() })
        // an emptied list is a first start too
        assertTrue(RoutingProfiles.migrate(emptyList(), s).changed)
        // stored and in step with the settings: nothing to do
        val again = RoutingProfiles.migrate(m.profiles, s)
        assertFalse(again.changed)
        assertEquals(m.profiles, again.profiles)
    }

    @Test fun mirror_bothWays() {
        val s = AppSettings(routeRules = listOf(RouteRule("domain", "x.com", "a")), routeDefault = "a")
        val p0 = RoutingProfiles.migrate(null, s).profiles
        val edited = listOf(
            p0[0].copy(rules = listOf(RouteRule("domain", "y.com", "b", "none")), def = "direct", useMode = true),
            RoutingProfile("rp-x", "Other", def = "c")
        )
        // the profile → the settings keys
        val mirrored = RoutingProfiles.mirrorToSettings(edited, s)
        assertEquals(edited[0].rules, mirrored.routeRules)
        assertEquals("direct", mirrored.routeDefault)
        assertTrue(mirrored.advancedUseMode)
        // the settings JSON keeps the via and reads it back
        assertEquals(edited[0].rules, AppSettings.fromJson(JSONObject(mirrored.toJson().toString())).routeRules)
        assertSame(mirrored, RoutingProfiles.mirrorToSettings(edited, mirrored))
        // the settings keys → the profile: an older app wrote them since
        val older = mirrored.copy(routeRules = listOf(RouteRule("port", "443", "a")), routeDefault = "a", advancedUseMode = false)
        val m = RoutingProfiles.migrate(edited, older)
        assertTrue(m.changed)
        assertEquals(older.routeRules, m.profiles[0].rules)
        assertEquals("a", m.profiles[0].def)
        assertFalse(m.profiles[0].useMode)
        assertEquals(edited[1], m.profiles[1])
        // no rp-default any more: the settings stay as they are
        assertSame(s, RoutingProfiles.mirrorToSettings(listOf(edited[1]), s))
    }

    @Test fun profileJson_roundTripsAndIsNormalized() {
        val p = RoutingProfile("rp-1", "Work", listOf(RouteRule("domain", "a.com", "a", "inherit"), RouteRule("ip", "1.2.3.4", "direct", "b")), "a", "none", true, "chain:k1")
        val back = RoutingProfile.fromJson(JSONObject(p.toJson().toString()))
        // direct never takes a via
        assertEquals(p.copy(rules = listOf(p.rules[0], p.rules[1].copy(via = ""))), back)
        // a rule without a via stores as before: no "via" key
        assertFalse(RouteRule("domain", "a.com", "a").toJson().has("via"))
        // junk comes back usable
        val n = RoutingProfile.fromJson(JSONObject().put("id", "bad id!").put("name", "  ").put("base", JSONObject.NULL).put("defVia", "direct"))
        assertTrue(RoutingProfiles.isValidId(n.id))
        assertTrue(n.id.startsWith("rp-"))
        assertEquals("Routing", n.name)
        assertNull(n.base)
        assertEquals("none", n.defVia)
        assertTrue(RoutingProfiles.isValidId(RoutingProfiles.newProfileId()))
        assertTrue(RoutingProfiles.newProfileId().startsWith("rp-"))
    }

    @Test fun selectionIds() {
        val ps = listOf(RoutingProfile("rp-a", "A"), RoutingProfile("rp-b", "B"))
        assertEquals("rp-a", RoutingProfiles.profileIdOf("__advanced__", ps))
        assertEquals("rp-b", RoutingProfiles.profileIdOf("__advanced__:rp-b", ps))
        assertNull(RoutingProfiles.profileIdOf("__advanced__:gone", ps))
        assertNull(RoutingProfiles.profileIdOf("a", ps))
        assertNull(RoutingProfiles.profileIdOf("__pool__", ps))
        assertNull(RoutingProfiles.profileIdOf("__advanced__", emptyList()))
        assertEquals("__advanced__:rp-b", Selection.forProfile("rp-b"))
        assertTrue(Selection.isAdvanced("__advanced__"))
        assertTrue(Selection.isAdvanced("__advanced__:rp-b"))
        assertFalse(Selection.isAdvanced("chain:x"))
        val pids = setOf("rp-a", "rp-b")
        assertTrue(Selection.resolves("__advanced__:rp-b", emptySet(), emptySet(), pids))
        assertFalse(Selection.resolves("__advanced__:gone", emptySet(), emptySet(), pids))
        assertTrue(Selection.resolves("__advanced__", emptySet(), emptySet(), pids))
        // a deleted profile's selection falls back like a deleted server's; a live one stays
        assertEquals("a", Selection.repair("__advanced__:gone", "a", listOf("a"), emptyList(), pids))
        assertEquals("__advanced__:rp-a", Selection.repair("__advanced__:rp-a", "a", listOf("a"), emptyList(), pids))
        assertEquals("__advanced__:rp-a", Selection.previousAfterPick("__advanced__:rp-a", "", "a", setOf("a"), emptySet(), pids))
    }

    @Test fun effectiveVia_inheritNoneExplicit() {
        val withBase = RoutingProfile("rp-1", "P", base = "b")
        val noBase = RoutingProfile("rp-2", "P")
        assertEquals("b", RoutingProfiles.effectiveVia(RouteRule("domain", "x", "a", "inherit"), withBase))
        assertEquals("b", RoutingProfiles.effectiveVia(RouteRule("domain", "x", "a"), withBase))
        assertNull(RoutingProfiles.effectiveVia(RouteRule("domain", "x", "a", "inherit"), noBase))
        assertNull(RoutingProfiles.effectiveVia(RouteRule("domain", "x", "a", "none"), withBase))
        assertEquals("chain:k1", RoutingProfiles.effectiveVia(RouteRule("domain", "x", "a", "chain:k1"), noBase))
        assertEquals("c", RoutingProfiles.effectiveVia(RouteRule("domain", "x", "a", "c"), withBase))
        // direct and block never take one; a target never rides on itself
        assertNull(RoutingProfiles.effectiveVia(RouteRule("domain", "x", "direct", "c"), withBase))
        assertNull(RoutingProfiles.effectiveVia(RouteRule("domain", "x", "block"), withBase))
        assertNull(RoutingProfiles.effectiveVia(RouteRule("domain", "x", "b"), withBase))
        // the default's
        assertEquals("b", RoutingProfiles.effectiveDefVia(withBase.copy(def = "a")))
        assertNull(RoutingProfiles.effectiveDefVia(withBase.copy(def = "a", defVia = "none")))
        assertNull(RoutingProfiles.effectiveDefVia(withBase.copy(def = "direct")))
    }

    /* ----------------------------- the builder ----------------------------- */

    @Test fun noVia_theConfigOfBefore() {
        val rs = listOf(RouteRule("domain", "x.com", "a"), RouteRule("ip", "10.0.0.0/8", "chain:k1"), RouteRule("port", "443", "direct"))
        val before = build(ConnectionPlan.Advanced(rs, "b", byId, chains))
        // a migrated profile: "inherit" everywhere, no base
        val migrated = build(plan(rs.map { r: RouteRule -> r.copy(via = if (RoutingProfiles.takesVia(r.target)) "inherit" else "") }, "b"))
        assertEquals(Canon.of(before), Canon.of(migrated))
        // a base nothing inherits changes nothing either
        val unused = build(plan(rs.map { r: RouteRule -> r.copy(via = if (RoutingProfiles.takesVia(r.target)) "none" else "") }, "b", "none", "c"))
        assertEquals(Canon.of(before), Canon.of(unused))
        assertTrue(tags(before).none { t: String -> t.contains("@") || t.startsWith("base-") })
        // the profile's useMode is the settings' advancedUseMode
        val withMode = ConfigBuilder.build(ConnectionPlan.Advanced(rs, "b", byId, chains, useMode = true), settings { s: AppSettings -> s.copy(routingMode = "bypass-ir") }, geoAssets = true)
        val viaSettings = ConfigBuilder.build(ConnectionPlan.Advanced(rs, "b", byId, chains), settings { s: AppSettings -> s.copy(routingMode = "bypass-ir", advancedUseMode = true) }, geoAssets = true)
        assertEquals(Canon.of(viaSettings), Canon.of(withMode))
    }

    @Test fun twoTargetsShareOneServerBase() {
        val cfg = build(plan(listOf(RouteRule("domain", "a.com", "a"), RouteRule("domain", "c.com", "c")), "direct", base = "b"))
        val t = tags(cfg)
        assertEquals(1, t.count { x: String -> x == "base-b" })
        assertEquals("base-b", dialer(tagged(cfg, "out-a@b")))
        assertEquals("base-b", dialer(tagged(cfg, "out-c@b")))
        assertFalse(t.contains("out-a"))
        assertFalse(t.contains("out-c"))
        assertEquals("", dialer(tagged(cfg, "base-b")))
        assertEquals("out-a@b", ruleFor(cfg, "a.com").getString("outboundTag"))
        assertEquals("out-c@b", ruleFor(cfg, "c.com").getString("outboundTag"))
    }

    @Test fun chainTargetThroughABase_itsFirstHopDialsTheBase() {
        val cfg = build(plan(listOf(RouteRule("port", "5060", "chain:k1", "a")), "direct"))
        assertEquals("base-a", dialer(tagged(cfg, "out-chain-k1@a-h0")))
        assertEquals("out-chain-k1@a-h0", dialer(tagged(cfg, "out-chain-k1@a")))
        assertEquals("out-chain-k1@a", rules(cfg).first { r: JSONObject -> r.optString("port") == "5060" }.getString("outboundTag"))
        assertFalse(tags(cfg).contains("out-chain-k1"))
    }

    @Test fun chainBase_hopsAndExit() {
        val cfg = build(plan(listOf(RouteRule("domain", "x.com", "c")), "direct", base = "chain:base1"))
        assertEquals("base-chain-base1-h0", dialer(tagged(cfg, "base-chain-base1")))
        assertEquals("", dialer(tagged(cfg, "base-chain-base1-h0")))
        assertEquals("base-chain-base1", dialer(tagged(cfg, "out-c@chain-base1")))
        assertEquals("out-c@chain-base1", ruleFor(cfg, "x.com").getString("outboundTag"))
        // a chain through a chain base
        val both = build(plan(listOf(RouteRule("domain", "y.com", "chain:k1")), "direct", base = "chain:base1"))
        assertEquals("base-chain-base1", dialer(tagged(both, "out-chain-k1@chain-base1-h0")))
    }

    @Test fun theDefaultThroughABase() {
        val cfg = build(plan(listOf(RouteRule("domain", "x.com", "direct")), "a", base = "b"))
        assertEquals("out-a@b", rules(cfg).last().getString("outboundTag"))
        assertEquals("base-b", dialer(tagged(cfg, "out-a@b")))
        // explicit none on the default: its own outbound
        val none = build(plan(listOf(RouteRule("domain", "x.com", "direct")), "a", "none", "b"))
        assertEquals("out-a", rules(none).last().getString("outboundTag"))
        assertFalse(tags(none).contains("base-b"))
    }

    @Test fun theSameServerWithAndWithoutAVia() {
        val cfg = build(plan(listOf(RouteRule("domain", "x.com", "a", "b"), RouteRule("domain", "y.com", "a", "none")), "direct"))
        assertTrue(tags(cfg).contains("out-a"))
        assertTrue(tags(cfg).contains("out-a@b"))
        assertEquals("", dialer(tagged(cfg, "out-a")))
        assertEquals("base-b", dialer(tagged(cfg, "out-a@b")))
    }

    @Test fun aJsonServerThroughABase_leavesItsHelpersOut() {
        val f = File("../../tests/fixtures/json/xray-fragment.json")
        if (!f.isFile) fail("missing shared fixture ${f.absolutePath} — the JVM tests run in android/app")
        val frag = (JsonImport.importJson(f.readText(Charsets.UTF_8)) ?: throw AssertionError("not read as JSON")).servers.single()
        val p = ConnectionPlan.Advanced(listOf(RouteRule("domain", "a.example", frag.id, "b")), "direct", byId + (frag.id to frag), chains)
        val cfg = build(p)
        val o = tagged(cfg, "out-${frag.id}@b")
        assertEquals("base-b", dialer(o))
        assertFalse(o.has("proxySettings"))
        assertTrue(tags(cfg).none { t: String -> t.contains("~") })
        // as a base it keeps its helpers: it dials by itself
        val asBase = build(ConnectionPlan.Advanced(listOf(RouteRule("domain", "a.example", "a")), "direct", byId + (frag.id to frag), chains, base = frag.id))
        assertEquals("base-${frag.id}", dialer(tagged(asBase, "out-a@${frag.id}")))
        assertTrue(tags(asBase).any { t: String -> t.startsWith("base-${frag.id}~") })
    }

    @Test fun muxNeverOnABaseNorOnAnythingThroughIt() {
        val p = plan(listOf(RouteRule("domain", "x.com", "a", "b"), RouteRule("domain", "y.com", "c")), "direct")
        val cfg = build(p, muxIds = setOf("a", "b", "c"))
        assertFalse(tagged(cfg, "out-a@b").has("mux"))
        assertFalse(tagged(cfg, "base-b").has("mux"))
        assertTrue(tagged(cfg, "out-c").has("mux"))
        assertTrue(tags(cfg).none { t: String -> (t.contains("@") || t.startsWith("base-")) && tagged(cfg, t).has("mux") })
        // the connect path's mux candidates leave them out too
        assertEquals(listOf("c"), Mux.targets(p).map { s: ServerConfig -> s.id })
    }

    private fun wg(id: String): ServerConfig {
        val ob = JSONObject().put("protocol", "wireguard")
            .put("settings", JSONObject().put("secretKey", "k-$id").put("address", JSONArray().put("10.10.10.42/32"))
                .put("peers", JSONArray().put(JSONObject().put("publicKey", "p-$id").put("endpoint", "wg.example:51820")
                    .put("allowedIPs", JSONArray().put("0.0.0.0/0")))))
        return ServerConfig(id, id, "wireguard", "wg.example", 51820, ob)
    }
    private fun wgTags(c: JSONObject): List<String> =
        outs(c).filter { o: JSONObject -> o.optString("protocol") == "wireguard" }.map { o: JSONObject -> o.optString("tag") }

    /** A WireGuard dialled twice is two sessions on one key — the peer keeps only the newest (scripts/probe-wg-base.js). */
    @Test fun aWireGuardBaseThatIsAlsoTheExit_isOneWireGuard() {
        val w = wg("w")
        val k = vless("k", "k.example")
        val ids = byId + (w.id to w) + (k.id to k)
        val chs = chains + ("tes" to listOf(k, w))
        // a rule at the base (resolved: the base itself, via none) and a target through it
        val cfg = build(ConnectionPlan.Advanced(listOf(RouteRule("ip", "192.168.0.0/16", "w", "none"), RouteRule("domain", "a.com", "a")), "direct", ids, chs, base = "w"))
        assertEquals(listOf("base-w"), wgTags(cfg))
        val exit = tagged(cfg, "out-w")
        assertEquals("freedom", exit.getString("protocol"))
        assertEquals("base-w", dialer(exit))
        assertEquals("base-w", dialer(tagged(cfg, "out-a@w")))
        assertEquals("out-w", rules(cfg).first { r: JSONObject -> r.optJSONArray("ip")?.optString(0) == "192.168.0.0/16" }.getString("outboundTag"))
        // the default at the base
        val def = build(ConnectionPlan.Advanced(listOf(RouteRule("domain", "a.com", "a")), "w", ids, chs, "none", "w"))
        assertEquals(listOf("base-w"), wgTags(def))
        assertEquals("base-w", dialer(tagged(def, "out-w")))
        // a chain base ending in it: that one chain, no second copy of its hops
        val chain = build(ConnectionPlan.Advanced(listOf(RouteRule("ip", "192.168.0.0/16", "chain:tes", "none"), RouteRule("domain", "a.com", "a")), "direct", ids, chs, base = "chain:tes"))
        assertEquals(listOf("base-chain-tes"), wgTags(chain))
        assertEquals("base-chain-tes", dialer(tagged(chain, "out-chain-tes")))
        assertFalse(tags(chain).contains("out-chain-tes-h0"))
        // a base of another kind keeps its own exit; a WireGuard nobody dials twice is as before
        val other = build(ConnectionPlan.Advanced(listOf(RouteRule("domain", "x.com", "b", "none"), RouteRule("domain", "a.com", "a")), "direct", ids, chs, base = "b"))
        assertEquals("vless", tagged(other, "out-b").getString("protocol"))
        val plain = build(ConnectionPlan.Advanced(listOf(RouteRule("ip", "192.168.0.0/16", "w")), "direct", ids, chs))
        assertEquals(listOf("out-w"), wgTags(plain))
    }

    @Test fun refusals_aGoneBaseOrDefault_andAGoneRuleTargetIsLeftOut() {
        val gone = assertThrows(IllegalStateException::class.java) { build(plan(listOf(RouteRule("domain", "x.com", "a", "zzz")), "direct")) }
        assertEquals(ConfigBuilder.MISSING_BASE, gone.message)
        val emptied = assertThrows(IllegalStateException::class.java) { build(plan(listOf(RouteRule("domain", "x.com", "a")), "direct", base = "chain:empty")) }
        assertEquals(ConfigBuilder.MISSING_BASE, emptied.message)
        val defBase = assertThrows(IllegalStateException::class.java) { build(plan(emptyList(), "a", "zzz")) }
        assertEquals(ConfigBuilder.MISSING_BASE, defBase.message)
        val def = assertThrows(IllegalStateException::class.java) { build(plan(emptyList(), "zzz")) }
        assertEquals(ConfigBuilder.MISSING_DEFAULT, def.message)
        assertThrows(IllegalStateException::class.java) { build(plan(emptyList(), "chain:empty")) }
        // a rule whose target is gone is left out — its traffic follows the default, never `direct`
        val cfg = build(plan(listOf(RouteRule("domain", "gone.com", "zzz"), RouteRule("domain", "x.com", "a")), "b"))
        assertTrue(rules(cfg).none { r: JSONObject -> domains(r).contains("gone.com") })
        assertEquals("out-a", ruleFor(cfg, "x.com").getString("outboundTag"))
        // a base nothing uses refuses nothing
        build(plan(listOf(RouteRule("domain", "x.com", "a", "none")), "direct", base = "zzz"))
    }

    @Test fun entriesAreTheBases_notTheTargetsThroughThem() {
        val p = plan(listOf(RouteRule("domain", "x.com", "a", "b"), RouteRule("domain", "y.com", "chain:k1")), "c")
        assertEquals(listOf("b", "chain:k1", "c"), RoutingProfiles.dialTargets(p))
        assertEquals(listOf("b"), RoutingProfiles.basesOf(p))
        val direct = CertPin.directServers(p).map { s: ServerConfig -> s.id }
        assertTrue(direct.containsAll(listOf("b", "h1", "c")))
        assertFalse(direct.contains("a"))
        assertTrue(CertPin.planServers(p).any { s: ServerConfig -> s.id == "a" })
        assertTrue(EngineChoice.planServers(p).any { s: ServerConfig -> s.id == "b" })
        // without vias: the rules' targets and the default, as before
        val plain = plan(listOf(RouteRule("domain", "x.com", "a")), "c")
        assertEquals(listOf("a", "c"), RoutingProfiles.dialTargets(plain))
        assertTrue(RoutingProfiles.basesOf(plain).isEmpty())
    }

    /* ----------------------------- exit at the base ----------------------------- */

    @Test fun exitAtTheBase_takesNoVia_andIsNeverABase() {
        assertEquals("base", RoutingProfiles.TARGET_BASE)
        assertFalse(RoutingProfiles.takesVia(RoutingProfiles.TARGET_BASE))
        val p = RoutingProfile("rp-1", "P", listOf(RouteRule("domain", "x.com", "base", "c")), def = "base", defVia = "c", base = "b")
        // it IS the base: it rides on nothing, whatever via it carries
        assertNull(RoutingProfiles.effectiveVia(p.rules[0], p))
        assertNull(RoutingProfiles.effectiveDefVia(p))
        val n = RoutingProfiles.normalize(p)
        assertEquals("base", n.rules[0].target)
        assertEquals("", n.rules[0].via)
        assertEquals("base", n.def)
        assertEquals("b", n.base)
        // a base of "base" is no base, stored or normalized
        assertNull(RoutingProfiles.normalize(p.copy(base = "base")).base)
        assertNull(RoutingProfiles.normalize(p.copy(base = " base ")).base)
        assertNull(RoutingProfile.fromJson(JSONObject().put("id", "rp-x").put("name", "X").put("base", "base")).base)
        // a via of "base" is the profile's base: inherit
        assertEquals("inherit", RoutingProfiles.normalize(p.copy(rules = listOf(RouteRule("domain", "x.com", "a", "base")))).rules[0].via)
        assertEquals("b", RoutingProfiles.effectiveVia("a", "base", "b"))
        // the flow marks it missing without a base, or with a base that is gone
        val exists = { t: String -> t in setOf("a", "b") }
        assertFalse(RoutingProfiles.lanes(p, exists)[0].targetMissing)
        assertNull(RoutingProfiles.lanes(p, exists)[0].via)
        assertTrue(RoutingProfiles.lanes(p.copy(base = null), exists)[0].targetMissing)
        assertTrue(RoutingProfiles.lanes(p.copy(base = null), exists).last().targetMissing)
        assertTrue(RoutingProfiles.lanes(p.copy(base = "zzz"), exists)[0].targetMissing)
    }

    @Test fun resolveBaseTargets_withABase_withoutOne_andNothingToResolve() {
        val rs = listOf(RouteRule("domain", "x.com", "base"), RouteRule("domain", "y.com", "a", "inherit"), RouteRule("ip", "1.1.1.1", "direct"))
        val r = RoutingProfiles.resolveBaseTargets(rs, "base", "inherit", "chain:base1")
        assertEquals(RouteRule("domain", "x.com", "chain:base1", "none"), r.rules[0])
        assertSame(rs[1], r.rules[1])
        assertSame(rs[2], r.rules[2])
        assertEquals("chain:base1", r.def)
        assertEquals("none", r.defVia)
        // only the rules at the base: the default keeps its own target and via
        val ruleOnly = RoutingProfiles.resolveBaseTargets(rs, "c", "inherit", "b")
        assertEquals(RouteRule("domain", "x.com", "b", "none"), ruleOnly.rules[0])
        assertEquals("c", ruleOnly.def)
        assertEquals("inherit", ruleOnly.defVia)
        // without a base: as it is — the rule names nothing (left out), the default is refused
        val none = RoutingProfiles.resolveBaseTargets(rs, "base", "inherit", null)
        assertSame(rs, none.rules)
        assertEquals("base", none.def)
        assertEquals("inherit", none.defVia)
        assertSame(rs, RoutingProfiles.resolveBaseTargets(rs, "base", "inherit", "base").rules)
        // nothing at the base: the very same list and values
        val plain = listOf(RouteRule("domain", "y.com", "a"))
        val same = RoutingProfiles.resolveBaseTargets(plain, "c", "none", "b")
        assertSame(plain, same.rules)
        assertEquals("c", same.def)
        assertEquals("none", same.defVia)
    }

    @Test fun planRoutes_theDefaultAtTheBaseWithoutOneIsRefused() {
        val p = RoutingProfile("rp-1", "P", listOf(RouteRule("domain", "x.com", "base")), def = "base", base = "b")
        val r = RoutingProfiles.planRoutes(p, "a")
        assertEquals("b", r.def)
        assertEquals("b", r.rules[0].target)
        val e = assertThrows(IllegalStateException::class.java) { RoutingProfiles.planRoutes(p.copy(base = null), "a") }
        assertEquals(RoutingProfiles.NO_BASE, e.message)
        // a rule at the base without one is no refusal: the builder leaves it out
        val ruleOnly = RoutingProfiles.planRoutes(p.copy(def = "c", base = null), "a")
        assertEquals("base", ruleOnly.rules[0].target)
        // an empty default is the fallback, as before
        assertEquals("a", RoutingProfiles.planRoutes(RoutingProfile("rp-2", "Q", def = ""), "a").def)
    }

    /** As the desktop (main.js buildPlan): left out, the rule's traffic would follow the default — perhaps direct. */
    @Test fun planRoutes_anythingAtABaseThatIsGoneIsRefused() {
        val gone = { t: String -> t != "b" }
        val rule = RoutingProfile("rp-1", "P", listOf(RouteRule("ip", "192.168.0.0/16", "base"), RouteRule("domain", "y.com", "a")), def = "direct", base = "b")
        val e = assertThrows(IllegalStateException::class.java) { RoutingProfiles.planRoutes(rule, "a", gone) }
        assertEquals(RoutingProfiles.GONE_BASE, e.message)
        val def = RoutingProfile("rp-2", "Q", listOf(RouteRule("domain", "y.com", "a", "none")), def = "base", base = "chain:k9")
        assertEquals(RoutingProfiles.GONE_BASE, assertThrows(IllegalStateException::class.java) { RoutingProfiles.planRoutes(def, "a") { t: String -> t != "chain:k9" } }.message)
        // the base there: as before; nothing at the base: no refusal here (a target through a gone base is the builder's MISSING_BASE)
        assertEquals("b", RoutingProfiles.planRoutes(rule, "a") { _: String -> true }.rules[0].target)
        val through = RoutingProfile("rp-3", "R", listOf(RouteRule("domain", "y.com", "a")), def = "direct", base = "b")
        assertEquals("a", RoutingProfiles.planRoutes(through, "a", gone).rules[0].target)
    }

    @Test fun exitAtTheBase_inTheConfig_theBaseDialledDirectly() {
        val p = RoutingProfile("rp-1", "P", listOf(RouteRule("domain", "x.com", "base"), RouteRule("domain", "y.com", "a")), def = "base", base = "b")
        val r = RoutingProfiles.planRoutes(p, "a")
        val resolved = plan(r.rules, r.def, r.defVia, p.base)
        val cfg = build(resolved)
        // at the base: the base's own outbound, dialling by itself
        assertEquals("out-b", ruleFor(cfg, "x.com").getString("outboundTag"))
        assertEquals("", dialer(tagged(cfg, "out-b")))
        assertEquals("out-b", rules(cfg).last().getString("outboundTag"))
        // through the base: as before
        assertEquals("out-a@b", ruleFor(cfg, "y.com").getString("outboundTag"))
        assertEquals("base-b", dialer(tagged(cfg, "out-a@b")))
        // the phone dials the base for both
        assertEquals(listOf("b", "b", "b"), RoutingProfiles.dialTargets(resolved))
        assertTrue(CertPin.directServers(resolved).any { s: ServerConfig -> s.id == "b" })
        assertFalse(CertPin.directServers(resolved).any { s: ServerConfig -> s.id == "a" })
        // without a base a rule at the base is left out — its traffic follows the default
        val noBase = build(plan(listOf(RouteRule("domain", "x.com", "base"), RouteRule("domain", "y.com", "a")), "c"))
        assertTrue(rules(noBase).none { x: JSONObject -> domains(x).contains("x.com") })
        assertEquals("out-a", ruleFor(noBase, "y.com").getString("outboundTag"))
        // a profile with nothing at the base: the config of before, byte for byte
        val rs = listOf(RouteRule("domain", "x.com", "a"), RouteRule("ip", "10.0.0.0/8", "chain:k1", "none"))
        val plainP = RoutingProfile("rp-2", "Q", rs, def = "c", base = "b")
        val pr = RoutingProfiles.planRoutes(plainP, "a")
        assertEquals(Canon.of(build(plan(rs, "c", "inherit", "b"))), Canon.of(build(plan(pr.rules, pr.def, pr.defVia, plainP.base))))
    }

    /* ----------------------------- the flow list ----------------------------- */

    @Test fun flowLanes_groupedRulesTargetsBasesAndWhatIsMissing() {
        val p = RoutingProfile("rp-1", "P", listOf(
            RouteRule("domain", "a.com", "a"), RouteRule("domain", "b.com", "a"),
            RouteRule("ip", "1.1.1.1", "direct"),
            RouteRule("domain", "c.com", "gone"),
            RouteRule("domain", "d.com", "c", "zzz")
        ), def = "c", base = "b")
        val exists = { t: String -> t in setOf("a", "b", "c", "direct") }
        val lanes = RoutingProfiles.lanes(p, exists)
        assertEquals(5, lanes.size)
        assertEquals(listOf(0, 1), lanes[0].rules)
        assertEquals("b", lanes[0].via)
        assertNull(lanes[1].via)
        assertTrue(lanes[2].targetMissing)
        assertFalse(lanes[2].viaMissing)
        assertTrue(lanes[3].viaMissing)
        assertTrue(lanes[4].isDefault)
        assertEquals("b", lanes[4].via)
        val byBase = RoutingProfiles.lanesByBase(lanes)
        assertEquals(listOf("b", "zzz"), byBase.map { e: Pair<String, List<RoutingProfiles.Lane>> -> e.first })
        assertEquals(3, byBase[0].second.size)
    }
}
