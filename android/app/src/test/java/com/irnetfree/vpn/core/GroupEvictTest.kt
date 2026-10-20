package com.irnetfree.vpn.core

import com.irnetfree.vpn.vpn.TunnelSetup
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.ServerSocket
import java.net.Socket

/**
 * A group's member that stays dead leaves the running config and the app tests
 * it instead (GroupEvict.kt) — the desktop's tests/groupEvict.test.js and the
 * evictor half of tests/groupLive.test.js, then what the phone adds: the live
 * map and the skip in the builder, the group's own fallback (tests/groups.test.js),
 * the metrics listener only with a group, and reading /debug/vars.
 */
class GroupEvictTest {
    private val uuid = "7d2f0c3b-1e4a-4b6d-9c8e-0a1b2c3d4e5f"
    private fun srv(id: String, address: String, port: Int): ServerConfig {
        val ob = JSONObject().put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(JSONObject().put("address", address).put("port", port)
                .put("users", JSONArray().put(JSONObject().put("id", uuid).put("encryption", "none"))))))
            .put("streamSettings", JSONObject().put("network", "tcp").put("security", "none"))
        return ServerConfig(id, id.uppercase(), "vless", address, port, ob)
    }
    private val a = srv("a", "a.example.net", 443)
    private val b = srv("b", "b.example.net", 443)
    private val c = srv("c", "c.example.net", 443)
    private val byId: Map<String, ServerConfig> = mapOf("a" to a, "b" to b, "c" to c)
    private fun groupOf(json: String, servers: Map<String, ServerConfig> = byId): ServerConfig =
        Groups.groupRecord(Groups.normalizeGroup(JSONObject(json))!!, servers)!!
    private val grp = groupOf("""{"id":"grp-x","name":"X","members":[{"id":"a"},{"id":"b"},{"id":"c","address":"104.16.1.1","port":2053}]}""")
    private val settings = AppSettings(blockAds = false, enableSniffing = false)
    private fun key(id: String, address: String, port: Int): String = GroupEvict.memberKey("grp-x", id, address, port)
    private val kb = key("b", "b.example.net", 443)
    private val kc = key("c", "104.16.1.1", 2053)

    private fun built(plan: ConnectionPlan, skip: Set<String> = emptySet()): ConfigBuilder.Built =
        ConfigBuilder.buildWithGroups(plan, settings, groupSkip = skip)

    /** The live map the service reads for the plan's config, with these verdicts. */
    private fun payload(b0: ConfigBuilder.Built, alive: List<Boolean?>): List<GroupEvict.Group> = b0.groups.map { g: GroupEvict.Group ->
        g.copy(members = g.members.mapIndexed { i: Int, m: GroupEvict.Member -> m.copy(alive = alive[i]) })
    }

    private fun outs(cfg: JSONObject): List<JSONObject> { val arr = cfg.getJSONArray("outbounds"); return (0 until arr.length()).map { i: Int -> arr.getJSONObject(i) } }
    private fun find(cfg: JSONObject, tag: String): JSONObject? = outs(cfg).firstOrNull { o: JSONObject -> o.optString("tag") == tag }
    private fun dialer(o: JSONObject?): String = o?.optJSONObject("streamSettings")?.optJSONObject("sockopt")?.optString("dialerProxy") ?: ""
    private fun strs(arr: JSONArray?): List<String> = if (arr == null) emptyList() else (0 until arr.length()).map { i: Int -> arr.getString(i) }

    @Test fun theBuilderLeavesASetAsideMemberOut_neverTheWholeGroup_andTheLiveMapSaysWhoTheAppMayTest() {
        val full = built(ConnectionPlan.Single(grp))
        assertEquals(listOf(Pair("a", true), Pair("b", true), Pair("c", true)), full.groups[0].members.map { m: GroupEvict.Member -> Pair(m.id, m.direct) })
        val less = built(ConnectionPlan.Single(grp), setOf(kb))
        assertEquals(listOf("a", "c"), less.groups[0].members.map { m: GroupEvict.Member -> m.id })
        assertEquals(listOf("a.example.net", "104.16.1.1"), outs(less.config).filter { o: JSONObject -> Regex("~gm\\d$").containsMatchIn(o.optString("tag")) }
            .map { o: JSONObject -> o.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address") })
        assertEquals("proxy~gm0", less.config.getJSONObject("routing").getJSONArray("balancers").getJSONObject(0).getString("fallbackTag"))
        val all = setOf(key("a", "a.example.net", 443), kb, kc)
        assertEquals("all of them: none left out", listOf("a", "b", "c"), built(ConnectionPlan.Single(grp), all).groups[0].members.map { m: GroupEvict.Member -> m.id })
        // a group behind a hop: the app cannot test its members as the core dials them
        val behind = built(ConnectionPlan.Chain("c", listOf(a, grp)))
        assertTrue(behind.groups[0].members.all { m: GroupEvict.Member -> !m.direct })
        assertEquals(listOf("a", "b", "c"), behind.groups[0].members.map { m: GroupEvict.Member -> m.id })
        assertEquals("grp-x", behind.groups[0].groupId)
        // the key, as configBuilder.js groupMemberKey writes it
        assertEquals("grp-x|c|104.16.1.1|2053", kc)
        assertEquals("|||0", GroupEvict.memberKey(null, null, null, null))
        // the live map travels in the service's Intent and comes back the same
        assertEquals(full.groups, GroupEvict.mapFromJson(GroupEvict.mapToJson(full.groups)))
        assertEquals(emptyList<GroupEvict.Group>(), GroupEvict.mapFromJson("not json"))
        assertEquals(emptyList<GroupEvict.Group>(), GroupEvict.mapFromJson(null))
        // no group: no map
        assertTrue(built(ConnectionPlan.Single(a)).groups.isEmpty())
    }

    @Test fun deadFor90sWhileAnotherAnswers_setAside_said_aReloadWanted_neverTheLastThatMightAnswer_neverOneBehindAHop() {
        var now = 1_000_000L
        val e = GroupEvict.Evictor(now = { now })
        e.reset(ConnectionPlan.Single(grp))
        assertEquals(listOf("grp-x"), GroupEvict.groupRecordsOf(ConnectionPlan.Single(grp)).map { s: ServerConfig -> s.id })
        val cfg = built(ConnectionPlan.Single(grp))
        assertEquals("first seen dead: a streak starts", emptyList<GroupEvict.Line>(), e.update(payload(cfg, listOf(true, false, null))))
        now += 60_000
        assertEquals(emptyList<GroupEvict.Line>(), e.update(payload(cfg, listOf(true, false, null))))
        assertFalse(e.takeReload())
        now += 31_000
        val lines = e.update(payload(cfg, listOf(true, false, null)))
        assertEquals(1, lines.size)
        assertTrue(lines[0].line, lines[0].line.startsWith("Group X: B (b.example.net:443) has not answered for 90 s — taken out of the running config"))
        assertEquals("warn", lines[0].level)
        assertEquals(listOf(kb), e.skip())
        assertTrue(e.takeReload())
        assertFalse("taken once", e.takeReload())
        // still dead in the running config until the reload lands: said once, not again every 90 s
        now += 95_000
        assertEquals(emptyList<GroupEvict.Line>(), e.update(payload(cfg, listOf(true, false, null))))
        assertEquals(listOf(kb), e.skip())
        // a member that comes back alive before 90 s: its streak ends
        val f = GroupEvict.Evictor(now = { now })
        f.reset(ConnectionPlan.Single(grp))
        f.update(payload(cfg, listOf(true, false, true)))
        now += 50_000; f.update(payload(cfg, listOf(true, true, true)))
        now += 50_000
        assertEquals("a new streak, not 100 s of one", emptyList<GroupEvict.Line>(), f.update(payload(cfg, listOf(true, false, true))))
        // nobody answers: nothing is set aside (the core's fallback stays)
        val g = GroupEvict.Evictor(now = { now })
        g.reset(ConnectionPlan.Single(grp))
        g.update(payload(cfg, listOf(false, false, false)))
        now += 200_000
        assertEquals(emptyList<GroupEvict.Line>(), g.update(payload(cfg, listOf(false, false, false))))
        assertEquals(emptyList<String>(), g.skip())
        // behind a hop: left to the core
        val behind = built(ConnectionPlan.Chain("c", listOf(a, grp)))
        val h = GroupEvict.Evictor(now = { now })
        h.reset(ConnectionPlan.Chain("c", listOf(a, grp)))
        h.update(payload(behind, listOf(true, false, true)))
        now += 200_000
        assertEquals(emptyList<GroupEvict.Line>(), h.update(payload(behind, listOf(true, false, true))))
    }

    @Test fun aSetAsideMember_testedAfter3min_doublingTo24min_backOnlyAfterTwoAnswers_reloads60sApart_aFailedOneAskedAgain() {
        var now = 5_000_000L
        val e = GroupEvict.Evictor(now = { now })
        e.reset(ConnectionPlan.Single(grp))
        val cfg = built(ConnectionPlan.Single(grp))
        e.update(payload(cfg, listOf(true, false, false)))
        now += 91_000
        assertEquals(2, e.update(payload(cfg, listOf(true, false, false))).size)
        assertEquals("said once", 0, e.update(payload(cfg, listOf(true, false, false))).size)
        assertTrue(e.takeReload())
        assertEquals("not before 3 min", 0, e.due().size)
        now += 180_000
        val due = e.due()
        assertEquals("each with the record a test dials — a clean-IP member at its own address",
            listOf(Triple(kb, "b.example.net", "B (b.example.net:443)"), Triple(kc, "104.16.1.1", "C (104.16.1.1:2053)")),
            due.map { d: GroupEvict.Due -> Triple(d.key, d.record.address, d.label) })
        // b misses: 6 min to its next test, then 12, 24, 24
        assertEquals(emptyList<GroupEvict.Line>(), e.tested(due[0].key, false, null))
        // c answers once: not back yet — once more in 30 s
        assertEquals(emptyList<GroupEvict.Line>(), e.tested(due[1].key, true, 120))
        assertEquals(listOf(kb, kc), e.skip())
        assertFalse(e.wantsReload())
        now += 30_000
        assertEquals(listOf(kc), e.due().map { d: GroupEvict.Due -> d.key })
        val back = e.tested(kc, true, 110)
        assertEquals(listOf(GroupEvict.Line("Group X: C (104.16.1.1:2053) answers again (110 ms) — back in the running config", "info")), back)
        assertEquals(listOf(kb), e.skip())
        assertTrue("the last reload was 3.5 min ago", e.takeReload())
        // the reload did not happen (a connect came first, or the start failed): asked again, still 60 s apart
        e.reloadFailed()
        assertTrue(e.wantsReload())
        now += 30_000
        assertFalse("30 s after the last: not yet", e.takeReload())
        now += 31_000
        assertTrue(e.takeReload())
        // b's backoff: 6 min after its miss, not 3
        val bSince = now
        assertEquals("91 s after its miss: not due", 0, e.due().size)
        now = bSince - 91_000 + 360_000
        assertEquals("due 6 min after the miss", listOf(kb), e.due().map { d: GroupEvict.Due -> d.key })
        e.tested(kb, false, null)
        now += 6 * 60_000
        assertEquals("12 min now", 0, e.due().size)
        now += 6 * 60_000
        assertEquals(listOf(kb), e.due().map { d: GroupEvict.Due -> d.key })
        e.tested(kb, false, null)
        e.tested(kb, false, null)
        e.tested(kb, false, null)
        now += 24 * 60_000
        assertEquals("capped at 24 min", listOf(kb), e.due().map { d: GroupEvict.Due -> d.key })
        assertEquals(emptyList<GroupEvict.Line>(), e.tested("nobody", true, null))
        assertEquals("what the window shows", listOf(Pair("grp-x", "B (b.example.net:443)")), e.list().map { x: GroupEvict.SetAside -> Pair(x.groupId, x.label) })
    }

    @Test fun theWholeGroupDeadAtOnceIsTheLine_noStreakRuns_theFirstToAnswerAgainDoesNotTakeTheOthersOut() {
        var now = 9_000_000L
        val e = GroupEvict.Evictor(now = { now })
        e.reset(ConnectionPlan.Single(grp))
        val cfg = built(ConnectionPlan.Single(grp))
        e.update(payload(cfg, listOf(false, false, false)))
        now += 120_000
        e.update(payload(cfg, listOf(false, false, false)))
        now += 5_000
        assertEquals("a answers again: b and c start their streaks now, not 2 min ago", emptyList<GroupEvict.Line>(), e.update(payload(cfg, listOf(true, false, false))))
        now += 60_000
        assertEquals(emptyList<GroupEvict.Line>(), e.update(payload(cfg, listOf(true, true, false))))
        now += 31_000
        assertEquals("c, dead 91 s while others answered", listOf("C (104.16.1.1"),
            e.update(payload(cfg, listOf(true, true, false))).map { l: GroupEvict.Line -> l.line.split(":")[1].trim() })
    }

    @Test fun aReconnectOfTheSamePlanKeepsWhatIsSetAside_30minSinceItsLastTest_anotherPlanOrAStaleOneForgetsIt() {
        var now = 12_000_000L
        val e = GroupEvict.Evictor(now = { now })
        val plan = ConnectionPlan.Single(grp)
        e.reset(plan)
        val cfg = built(plan)
        e.update(payload(cfg, listOf(true, false, true)))
        now += 91_000
        e.update(payload(cfg, listOf(true, false, true)))
        assertEquals(listOf(kb), e.skip())
        // a network change: the connect asks skip() before it builds, then follows its plan
        val again = built(plan, e.skip().toSet())
        assertEquals(listOf("a", "c"), again.groups[0].members.map { m: GroupEvict.Member -> m.id })
        e.reset(plan)
        assertEquals("still out", listOf(kb), e.skip())
        assertFalse("the connect built without it: nothing to reload", e.takeReload())
        // another plan without that group: forgotten
        e.reset(ConnectionPlan.Single(a))
        assertEquals(emptyList<String>(), e.skip())
        // stale (no test for over 30 min): forgotten too
        val f = GroupEvict.Evictor(now = { now })
        f.reset(plan)
        f.update(payload(cfg, listOf(true, false, true)))
        now += 91_000
        f.update(payload(cfg, listOf(true, false, true)))
        now += 31 * 60_000
        f.reset(plan)
        assertEquals(emptyList<String>(), f.skip())
    }

    @Test fun theEvictorHandsOverWhatChangedSinceTheLastAsk_doneLiveNoReloadIsWantedForIt() {
        var now = 1_000_000L
        val e = GroupEvict.Evictor(now = { now })
        val two = groupOf("""{"id":"grp-x","name":"X","members":[{"id":"a"},{"id":"b"}]}""")
        e.reset(ConnectionPlan.Single(two))
        val cfg = built(ConnectionPlan.Single(two))
        e.update(payload(cfg, listOf(true, false)))
        now += 91_000
        e.update(payload(cfg, listOf(true, false)))
        assertEquals(GroupEvict.Changes(listOf(kb), emptyList()), e.takeChanges())
        assertEquals("taken once", GroupEvict.Changes(emptyList(), emptyList()), e.takeChanges())
        assertTrue(e.wantsReload())
        e.liveApplied()
        assertFalse(e.wantsReload())
        assertEquals("still out for the next config built", listOf(kb), e.skip())
        now += 180_000; e.tested(kb, true, 90)
        now += 30_000; e.tested(kb, true, 80)
        assertEquals(GroupEvict.Changes(emptyList(), listOf(kb)), e.takeChanges())
    }

    @Test fun onThePhoneAReloadIsAConnect_itsResetKeepsCountingTheGapBetweenReloads_aUsersConnectDoesNot() {
        var now = 20_000_000L
        val e = GroupEvict.Evictor(now = { now })
        val plan = ConnectionPlan.Single(grp)
        e.reset(plan)
        val cfg = built(plan)
        e.update(payload(cfg, listOf(true, false, true)))
        now += 91_000
        e.update(payload(cfg, listOf(true, false, true)))
        assertTrue(e.takeReload())
        // the reload's own connect
        e.reset(plan, reload = true)
        assertEquals(listOf(kb), e.skip())
        e.reloadFailed()
        now += 30_000
        assertFalse("30 s after the last reload", e.takeReload())
        now += 31_000
        assertTrue(e.takeReload())
        // the user's connect starts the clock afresh
        e.reset(plan)
        e.reloadFailed()
        assertTrue(e.takeReload())
    }

    @Test fun theCoresHealthCheck_byMemberTag_aDelayOnlyForALiveOne_onTheMapByIndex() {
        val vars = JSONObject("""{"observatory":{"proxy~gm0":{"alive":true,"delay":120,"outbound_tag":"proxy~gm0"},"proxy~gm1":{"alive":false,"delay":99999999},"x":3},"stats":{}}""")
        val h = GroupEvict.healthOf(vars)
        assertEquals(GroupEvict.Health(true, 120L), h["proxy~gm0"])
        assertEquals(GroupEvict.Health(false, null), h["proxy~gm1"])
        assertNull(h["x"])
        assertTrue(GroupEvict.healthOf(JSONObject()).isEmpty())
        assertTrue(GroupEvict.healthOf(null).isEmpty())
        val live = GroupEvict.liveOf(built(ConnectionPlan.Single(grp)).groups, h)
        assertEquals(listOf<Boolean?>(true, false, null), live[0].members.map { m: GroupEvict.Member -> m.alive })
        assertEquals(listOf<Long?>(120L, null, null), live[0].members.map { m: GroupEvict.Member -> m.delay })
    }

    @Test fun debugVars_readOverAPlainLoopbackSocket_only200JsonCounts() {
        val body = """{"observatory":{"proxy~gm0":{"alive":true,"delay":42}}}"""
        assertNotNull(GroupEvict.parseVars("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n$body".toByteArray()))
        assertNull(GroupEvict.parseVars("HTTP/1.0 404 Not Found\r\n\r\n$body".toByteArray()))
        assertNull(GroupEvict.parseVars("HTTP/1.1 200 OK\r\n\r\nnot json".toByteArray()))
        assertNull(GroupEvict.parseVars("garbage".toByteArray()))
        val server = ServerSocket(0)
        val asked = StringBuilder()
        val t = Thread {
            try {
                server.accept().use { s: Socket ->
                    val r = s.getInputStream().bufferedReader()
                    asked.append(r.readLine())
                    while (true) { val line = r.readLine() ?: break; if (line.isEmpty()) break }
                    s.getOutputStream().write("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n$body".toByteArray())
                    s.getOutputStream().flush()
                }
            } catch (e: Exception) {
                // the test fails below
            }
        }
        t.start()
        val vars = GroupEvict.readVars(server.localPort)
        t.join(3000)
        server.close()
        assertEquals("GET /debug/vars HTTP/1.0", asked.toString())
        assertEquals(GroupEvict.Health(true, 42L), GroupEvict.healthOf(vars)["proxy~gm0"])
        assertNull(GroupEvict.readVars(0))
        // nothing listening there any more
        assertNull(GroupEvict.readVars(server.localPort, timeoutMs = 500))
    }

    /* ------------------------------ the group's own fallback ------------------------------ */

    private fun wg(id: String, endpoint: String): ServerConfig {
        val ob = JSONObject().put("protocol", "wireguard").put("settings", JSONObject()
            .put("secretKey", "k").put("address", JSONArray().put("172.16.0.2/32")).put("mtu", 1280)
            .put("peers", JSONArray().put(JSONObject().put("publicKey", "p").put("endpoint", endpoint)
                .put("allowedIPs", JSONArray().put("0.0.0.0/0")))))
        return ServerConfig(id, id.uppercase(), "wireguard", endpoint.substringBeforeLast(':'), endpoint.substringAfterLast(':').toInt(), ob)
    }

    @Test fun aGroupsFallback_keptAsAServerId_dialledAsTfbOutsideTheMembersPrefix_theBalancersFallbackTag_neverProbed() {
        val warp = wg("warp", "engage.example.com:2408")
        val all = byId + ("warp" to warp)
        // stored: a server id only — a group's id, or nothing, leaves no field
        assertEquals("warp", Groups.normalizeGroup(JSONObject("""{"id":"grp-f","name":"F","members":["a"],"fallback":" warp "}"""))!!.fallback)
        assertEquals("", Groups.normalizeGroup(JSONObject("""{"id":"grp-f","name":"F","members":["a"],"fallback":"grp-x"}"""))!!.fallback)
        assertEquals("", Groups.normalizeGroup(JSONObject("""{"id":"grp-f","name":"F","members":["a"]}"""))!!.fallback)
        assertEquals("", Groups.normalizeGroup(JSONObject("""{"id":"grp-f","members":["a"],"fallback":null}"""))!!.fallback)
        assertEquals("not among the saved servers", "", Groups.normalizeGroup(JSONObject("""{"id":"grp-f","members":["a"],"fallback":"gone"}"""), known = setOf("a", "warp"))!!.fallback)
        val gc = Groups.normalizeGroup(JSONObject("""{"id":"grp-f","name":"F","members":["a","b"],"fallback":"warp"}"""))!!
        assertEquals(gc, GroupConfig.fromJson(JSONObject(gc.toJson().toString())))
        assertFalse("not written when there is none", gc.copy(fallback = "").toJson().has("fallback"))
        // the record carries the server; it is dialled too (endpoints, pins, the engine see it)
        val g = Groups.groupRecord(gc, all)!!
        assertEquals("warp", Groups.fallbackOf(g.outbound.getJSONObject(Groups.MARK))!!.id)
        assertEquals(listOf("a", "b", "warp"), Groups.serversOf(g).map { s: ServerConfig -> s.id })
        assertEquals(2, Groups.sizeOf(g))
        assertTrue(ConfigBuilder.wgEndpointHosts(ConnectionPlan.Single(g)).contains("engage.example.com"))
        assertNull("a fallback deleted since: none", Groups.fallbackOf(Groups.groupRecord(gc, byId)!!.outbound.getJSONObject(Groups.MARK)))
        // the config: T~fb, the balancer's fallbackTag; the selector and the health check stay on T~gm
        val bt = built(ConnectionPlan.Single(g))
        val cfg = bt.config
        val bal = cfg.getJSONObject("routing").getJSONArray("balancers").getJSONObject(0)
        assertEquals("proxy~fb", bal.getString("fallbackTag"))
        assertEquals(listOf("proxy~gm"), strs(bal.getJSONArray("selector")))
        assertEquals("never probed", listOf("proxy~gm"), strs(cfg.getJSONObject("observatory").getJSONArray("subjectSelector")))
        assertEquals("wireguard", find(cfg, "proxy~fb")!!.getString("protocol"))
        assertEquals(GroupEvict.Fallback("warp", "WARP"), bt.groups[0].fallback)
        assertEquals("the members only", listOf("a", "b"), bt.groups[0].members.map { m: GroupEvict.Member -> m.id })
        // its endpoint name takes the address it was resolved to, like a member's
        val resolved = ConfigBuilder.build(ConnectionPlan.Single(g), settings, wgEndpointIps = mapOf("engage.example.com" to "162.159.192.1"))
        assertEquals("162.159.192.1:2408", find(resolved, "proxy~fb")!!.getJSONObject("settings").getJSONArray("peers").getJSONObject(0).getString("endpoint"))
        // without one: the first member, as before
        val plain = ConfigBuilder.build(ConnectionPlan.Single(Groups.groupRecord(gc.copy(fallback = ""), all)!!), settings)
        assertEquals("proxy~gm0", plain.getJSONObject("routing").getJSONArray("balancers").getJSONObject(0).getString("fallbackTag"))
        assertNull(find(plain, "proxy~fb"))
        // a group of chain variants takes none: they fall back to the first
        val chained = built(ConnectionPlan.Chain("c", listOf(g, c)))
        assertEquals("proxy~gm0", chained.config.getJSONObject("routing").getJSONArray("balancers").getJSONObject(0).getString("fallbackTag"))
        assertTrue(outs(chained.config).none { o: JSONObject -> o.optString("tag").endsWith("~fb") })
        assertNull(chained.groups[0].fallback)
        // a group behind a base: its fallback rides the same base, never straight out
        val adv = ConnectionPlan.Advanced(listOf(RouteRule("domain", "example.org", "grp-f", via = "c")), "direct", all + ("grp-f" to g), emptyMap())
        val viaBase = ConfigBuilder.build(adv, settings)
        assertEquals("base-c", dialer(find(viaBase, "out-grp-f@c~fb")))
        assertEquals("out-grp-f@c~fb", viaBase.getJSONObject("routing").getJSONArray("balancers").getJSONObject(0).getString("fallbackTag"))
        assertEquals("every outbound has a tag of its own", outs(viaBase).size, outs(viaBase).map { o: JSONObject -> o.optString("tag") }.toSet().size)
    }

    @Test fun aJsonFallbacksHelpersAreNamedOutsideTheBalancersPrefix() {
        val main = JSONObject().put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(JSONObject().put("address", "j.example.net").put("port", 443)
                .put("users", JSONArray().put(JSONObject().put("id", uuid).put("encryption", "none"))))))
            .put("streamSettings", JSONObject().put("network", "tcp").put("sockopt", JSONObject().put("dialerProxy", "frag")))
        val frag = JSONObject().put("tag", "frag").put("protocol", "freedom")
            .put("settings", JSONObject().put("fragment", JSONObject().put("packets", "tlshello").put("length", "100-200").put("interval", "10-20")))
        val json = ServerConfig("j", "J", "vless", "j.example.net", 443, main, source = JsonImport.SOURCE,
            json = JSONObject().put("outbounds", JSONArray().put(JSONObject(main.toString()).put("tag", "proxy")).put(frag)), extraOutbounds = listOf(frag))
        val g = groupOf("""{"id":"grp-j","name":"J","members":["a","b"],"fallback":"j"}""", byId + ("j" to json))
        val cfg = ConfigBuilder.build(ConnectionPlan.Single(g), settings)
        assertEquals("proxy~fh~frag", dialer(find(cfg, "proxy~fb")))
        assertNotNull(find(cfg, "proxy~fh~frag"))
        assertEquals("the prefix holds the two members only", 2, outs(cfg).count { o: JSONObject -> o.optString("tag").startsWith("proxy~gm") })
    }

    /* ------------------------------ the metrics listener ------------------------------ */

    @Test fun theMetricsListener_onLoopback_onlyWhenTheConfigRunsAGroup_andTheConnectHandsTheMapOn() {
        val withGroup = ConfigBuilder.build(ConnectionPlan.Single(grp), settings, metricsPort = 41555)
        assertTrue(Canon.same("""{"tag":"metrics","listen":"127.0.0.1:41555"}""", withGroup.getJSONObject("metrics")))
        assertFalse("no group: none", ConfigBuilder.build(ConnectionPlan.Single(a), settings, metricsPort = 41555).has("metrics"))
        assertFalse("no port: none", ConfigBuilder.build(ConnectionPlan.Single(grp), settings).has("metrics"))
        // a group among an advanced plan's targets opens it too
        val adv = ConnectionPlan.Advanced(listOf(RouteRule("domain", "example.org", "grp-x")), "direct", byId + ("grp-x" to grp), emptyMap())
        assertTrue(ConfigBuilder.build(adv, settings, metricsPort = 41556).has("metrics"))
        // what the connect builds: the config and its groups
        val cc = TunnelSetup.coreConfig(EngineChoice.XRAY, ConnectionPlan.Single(grp), settings, false, emptyMap(), null, null,
            groupSkip = setOf(kb), metricsPort = 41557) { _: String -> }
        assertTrue(JSONObject(cc.json).has("metrics"))
        assertEquals(listOf("a", "c"), cc.groups[0].members.map { m: GroupEvict.Member -> m.id })
        val single = TunnelSetup.coreConfig(EngineChoice.XRAY, ConnectionPlan.Single(a), settings, false, emptyMap(), null, null, metricsPort = 41558) { _: String -> }
        assertTrue(single.groups.isEmpty())
        assertFalse(JSONObject(single.json).has("metrics"))
    }
}
