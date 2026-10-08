package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.Deflater

/**
 * Share links (RouteShare.kt) against the desktop's tests/routeShare.test.js and
 * the shared fixtures in tests/fixtures/routing/ — the link the desktop made
 * decodes here to the very payload, and what this side makes decodes back.
 */
class RouteShareTest {
    private fun fixture(name: String): String {
        val f = File("../../tests/fixtures/routing/$name")
        if (!f.isFile) fail("missing shared fixture ../../tests/fixtures/routing/$name (looked at ${f.absolutePath}) — the JVM tests run in android/app")
        return f.readText(Charsets.UTF_8)
    }
    private val link: String get() = fixture("profile-link.txt").trim()
    private val payload: JSONObject get() = JSONObject(fixture("profile-payload.json"))

    /** The fixture's servers as this phone would hold them, by id. */
    private fun fixtureServers(): Map<String, String> {
        val a = payload.getJSONArray("servers")
        return (0 until a.length()).associate { i: Int -> a.getJSONObject(i).getString("key") to a.getJSONObject(i).getString("link") }
    }
    private fun parse(l: String): ServerConfig = RouteShare.parseServer(l)
    private val identity: (ServerConfig) -> String = { s: ServerConfig -> SubRefresh.strictIdentity(s) }
    private var seq = 0
    private val newId: (String) -> String = { p: String -> "$p-t${++seq}" }

    /** A raw-deflate + base64url link around any text — the hostile cases. */
    private fun wrap(text: String): String {
        val d = Deflater(Deflater.DEFAULT_COMPRESSION, true)
        d.setInput(text.toByteArray(Charsets.UTF_8)); d.finish()
        val out = ByteArrayOutputStream(); val buf = ByteArray(4096)
        while (!d.finished()) { val n = d.deflate(buf); out.write(buf, 0, n) }
        d.end()
        return RouteShare.PREFIX + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(out.toByteArray())
    }

    @Test fun theDesktopsLinkDecodesToThePayload() {
        assertEquals(Canon.of(payload), Canon.of(RouteShare.decode(link)))
        assertTrue(RouteShare.looksLikeShare("  " + link))
        assertFalse(RouteShare.looksLikeShare("vless://x@y:1"))
    }

    @Test fun encodeDecode_roundTrip() {
        val text = RouteShare.encode(payload)
        assertTrue(text.startsWith("irnetfree://routing/"))
        assertFalse(text.substring(RouteShare.PREFIX.length).any { ch: Char -> ch == '=' || ch == '+' || ch == '/' })
        assertEquals(Canon.of(payload), Canon.of(RouteShare.decode(text)))
        // and once more through itself
        assertEquals(Canon.of(payload), Canon.of(RouteShare.decode(RouteShare.encode(RouteShare.decode(text)))))
    }

    @Test fun profilePayload_keysTargetsAndOnlyWhatItNames() {
        val links = fixtureServers()
        fun srv(id: String, name: String, key: String) = parse(links.getValue(key)).copy(id = id, name = name)
        val servers = listOf(
            srv("other", "Unrelated", "s4").copy(id = "other"),
            srv("base", "🇩🇪 Base DE", "s1"), srv("wg", "Corp WG", "s2"), srv("us", "Netflix US", "s3"), srv("nl", "Hop NL", "s4")
        )
        val chains = listOf(ChainConfig("ch-unused", "Spare", listOf("wg", "nl")), ChainConfig("ch1", "NL→US", listOf("nl", "us")))
        val profile = RoutingProfile("rp-work", "Work", listOf(
            RouteRule("domain", "corp.example,intranet.example", "wg"),
            RouteRule("domain", "geosite:netflix", "us", "inherit"),
            RouteRule("domain", "geosite:category-ir", "direct"),
            RouteRule("ip", "geoip:ir", "direct"),
            RouteRule("port", "5060", "chain:ch1", "none")
        ), def = "base", defVia = "none", useMode = true, base = "base")
        val linkOf = { s: ServerConfig -> if (s.id == "other") "vless://unused" else links.getValue(mapOf("base" to "s1", "wg" to "s2", "us" to "s3", "nl" to "s4").getValue(s.id)) }
        val out = RouteShare.profilePayload(profile, servers, chains, linkOf)
        assertEquals(Canon.of(payload), Canon.of(out))
        // nothing of the sender's ids travels
        val text = out.toString()
        assertFalse(text.contains("rp-work") || text.contains("\"ch1\"") || text.contains("\"base\":\"base\""))
        // a target that no longer exists refuses the share
        assertThrows(IllegalArgumentException::class.java) { RouteShare.profilePayload(profile.copy(def = "gone"), servers, chains, linkOf) }
        // Android's legacy "proxy" target travels as the first server
        val proxied = RouteShare.profilePayload(RoutingProfile("rp-p", "P", def = "proxy"), servers, chains, linkOf)
        assertEquals("s1", proxied.getJSONObject("profile").getString("def"))
        assertEquals("other", servers.first().id)
    }

    @Test fun chainPayload_theChainAndItsServers() {
        val s = listOf(ServerConfig("x", "X", "vless", "x.example", 443, JSONObject().put("protocol", "vless")),
            ServerConfig("y", "Y", "vless", "y.example", 443, JSONObject().put("protocol", "vless")),
            ServerConfig("z", "Z", "vless", "z.example", 443, JSONObject().put("protocol", "vless")))
        val out = RouteShare.chainPayload(ChainConfig("c-9", "Y→X", listOf("y", "x", "gone")), s) { srv: ServerConfig -> "vless://u@${srv.address}:443#${srv.name}" }
        assertEquals(1, out.getInt("v"))
        assertEquals("chain", out.getString("kind"))
        assertFalse(out.has("profile"))
        assertEquals(Canon.of(JSONObject().put("key", "c1").put("name", "Y→X").put("members", JSONArray().put("s1").put("s2"))), Canon.of(out.getJSONArray("chains").getJSONObject(0)))
        assertEquals(listOf("Y", "X"), (0 until out.getJSONArray("servers").length()).map { i: Int -> out.getJSONArray("servers").getJSONObject(i).getString("name") })
        // it decodes as a chain link
        assertEquals("chain", RouteShare.decode(RouteShare.encode(out)).getString("kind"))
    }

    @Test fun preview_intoAnEmptyStore_andAPopulatedOne() {
        val p = RouteShare.decode(link)
        val empty = RouteShare.previewImport(p, emptyList(), emptyList(), emptyList(), { l: String -> parse(l) }, identity)
        assertEquals("profile", empty.kind)
        assertEquals("Work", empty.name)
        assertEquals(5, empty.rules)
        assertEquals(1, empty.chains)
        assertEquals(4, empty.serversNew)
        assertEquals(0, empty.serversExisting)
        assertTrue(empty.unreadable.isEmpty())
        // already holding s1 and s3 (the same servers, under other names and ids)
        val links = fixtureServers()
        val held = listOf(parse(links.getValue("s1")).copy(id = "mine-1", name = "my DE"), parse(links.getValue("s3")).copy(id = "mine-3", name = "my US"))
        val some = RouteShare.previewImport(p, held, emptyList(), emptyList(), { l: String -> parse(l) }, identity)
        assertEquals(2, some.serversExisting)
        assertEquals(2, some.serversNew)
    }

    @Test fun import_intoAnEmptyStore() {
        val r = RouteShare.applyImport(RouteShare.decode(link), emptyList(), emptyList(), emptyList(), { l: String -> parse(l) }, identity, newId)
        assertEquals(4, r.addedServers)
        assertEquals(1, r.addedChains)
        assertEquals(1, r.addedProfiles)
        assertNull(r.chainId)
        val prof = r.profiles.single()
        assertEquals(r.profileId, prof.id)
        assertEquals("Work", prof.name)
        assertTrue(prof.useMode)
        val byName = r.servers.associateBy { s: ServerConfig -> s.name }
        val base = byName.getValue("🇩🇪 Base DE").id
        assertEquals(base, prof.base)
        assertEquals(base, prof.def)
        assertEquals("none", prof.defVia)
        assertEquals(byName.getValue("Corp WG").id, prof.rules[0].target)
        assertEquals("inherit", prof.rules[0].via)
        assertEquals("direct", prof.rules[2].target)
        assertEquals("", prof.rules[2].via)
        val chain = r.chains.single()
        assertEquals("NL→US", chain.name)
        assertEquals(listOf(byName.getValue("Hop NL").id, byName.getValue("Netflix US").id), chain.members)
        assertEquals("chain:${chain.id}", prof.rules[4].target)
        assertEquals("none", prof.rules[4].via)
        // added by hand: no subscription
        assertTrue(r.servers.all { s: ServerConfig -> s.subId == null })
        assertEquals(4, r.servers.map { s: ServerConfig -> s.id }.toSet().size)
    }

    @Test fun import_intoAPopulatedStore_reusesAndSuffixesTheName() {
        val links = fixtureServers()
        val held = listOf(parse(links.getValue("s1")).copy(id = "mine-1", name = "my DE"), parse(links.getValue("s3")).copy(id = "mine-3", name = "my US"))
        val heldChains = listOf(ChainConfig("mine-c", "Other", listOf("mine-1")))
        val heldProfiles = listOf(RoutingProfile("rp-default", "Advanced routing"), RoutingProfile("rp-w", "Work"))
        val r = RouteShare.applyImport(RouteShare.decode(link), held, heldChains, heldProfiles, { l: String -> parse(l) }, identity, newId)
        assertEquals(2, r.addedServers)
        assertEquals(4, r.servers.size)
        assertEquals("my DE", r.servers[0].name)   // kept as it was
        val prof = r.profiles.last()
        assertEquals("Work (2)", prof.name)
        assertEquals(3, r.profiles.size)
        assertEquals("mine-1", prof.base)
        assertEquals("mine-1", prof.def)
        assertEquals("mine-3", prof.rules[1].target)
        // the chain names the reused server
        val chain = r.chains.first { c: ChainConfig -> c.name == "NL→US" }
        assertEquals("mine-3", chain.members[1])
        // importing the same link again reuses the chain and every server; the profile is new again
        val again = RouteShare.applyImport(RouteShare.decode(link), r.servers, r.chains, r.profiles, { l: String -> parse(l) }, identity, newId)
        assertEquals(0, again.addedServers)
        assertEquals(0, again.addedChains)
        assertEquals(1, again.addedProfiles)
        assertEquals("Work (3)", again.profiles.last().name)
        assertEquals("Work (2)", RoutingProfiles.uniqueName("Work", listOf("Work")))
        assertEquals("Fresh", RoutingProfiles.uniqueName("Fresh", listOf("Work")))
    }

    @Test fun import_aChainLink_bringsItsChainAndServersOnly() {
        val links = fixtureServers()
        val servers = listOf(parse(links.getValue("s4")).copy(id = "nl"), parse(links.getValue("s3")).copy(id = "us"))
        val text = RouteShare.encode(RouteShare.chainPayload(ChainConfig("c-x", "NL→US", listOf("nl", "us")), servers) { s: ServerConfig -> links.getValue(if (s.id == "nl") "s4" else "s3") })
        val r = RouteShare.applyImport(RouteShare.decode(text), emptyList(), emptyList(), listOf(RoutingProfile("rp-default", "A")), { l: String -> parse(l) }, identity, newId)
        assertEquals(2, r.addedServers)
        assertEquals(1, r.addedChains)
        assertEquals(0, r.addedProfiles)
        assertNull(r.profileId)
        assertEquals(r.chains.single().id, r.chainId)
        assertEquals(1, r.profiles.size)
        val pv = RouteShare.previewImport(RouteShare.decode(text), emptyList(), emptyList(), emptyList(), { l: String -> parse(l) }, identity)
        assertEquals("chain", pv.kind)
        assertEquals("NL→US", pv.name)
        assertEquals(0, pv.rules)
    }

    @Test fun anUnreadableServerIsListed_andLeftDangling() {
        val p = RouteShare.decode(link)
        p.getJSONArray("servers").getJSONObject(1).put("link", "nonsense://what")
        val pv = RouteShare.previewImport(p, emptyList(), emptyList(), emptyList(), { l: String -> parse(l) }, identity)
        assertEquals(1, pv.unreadable.size)
        assertTrue(pv.unreadable[0].startsWith("Corp WG: "))
        assertEquals(3, pv.serversNew)
        val r = RouteShare.applyImport(p, emptyList(), emptyList(), emptyList(), { l: String -> parse(l) }, identity, newId)
        assertEquals(3, r.addedServers)
        // the rule keeps naming something that is not there — Routing marks it, connecting leaves it out
        assertTrue(r.profiles.single().rules[0].target.startsWith(RouteShare.UNREADABLE_PREFIX))
    }

    @Test fun hostileText_isRefusedWithAReason() {
        fun refused(text: String): String {
            val e = assertThrows(IllegalArgumentException::class.java) { RouteShare.decode(text) }
            assertNotNull(e.message)
            return e.message ?: ""
        }
        refused("vless://not-a-routing-link")
        refused(RouteShare.PREFIX)
        refused(RouteShare.PREFIX + "%%%not*base64%%%")
        // truncated: half the line
        val l = link
        refused(l.substring(0, RouteShare.PREFIX.length + (l.length - RouteShare.PREFIX.length) / 2))
        // not deflate at all
        refused(RouteShare.PREFIX + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("hello world, plainly".toByteArray()))
        // more than 64 KB once unpacked (it packs into a few hundred bytes)
        val huge = JSONObject(payload.toString()).put("pad", "x".repeat(70_000))
        assertTrue(refused(wrap(huge.toString())).contains("64 KB"))
        assertThrows(IllegalArgumentException::class.java) { RouteShare.encode(huge) }
        // not JSON
        refused(wrap("not json"))
        // a wrong version, an unknown kind
        assertTrue(refused(wrap(JSONObject(payload.toString()).put("v", 2).toString())).contains("newer"))
        refused(wrap(JSONObject(payload.toString()).put("v", "1").toString()))
        refused(wrap(JSONObject(payload.toString()).put("kind", "everything").toString()))
        // a target, a via, a base or a member naming a key it does not carry
        val badTarget = JSONObject(payload.toString()); badTarget.getJSONObject("profile").getJSONArray("rules").getJSONObject(0).put("target", "s9")
        refused(wrap(badTarget.toString()))
        val badVia = JSONObject(payload.toString()); badVia.getJSONObject("profile").getJSONArray("rules").getJSONObject(0).put("via", "chain:c7")
        refused(wrap(badVia.toString()))
        val badBase = JSONObject(payload.toString()); badBase.getJSONObject("profile").put("base", "s5")
        refused(wrap(badBase.toString()))
        val badMember = JSONObject(payload.toString()); badMember.getJSONArray("chains").getJSONObject(0).put("members", JSONArray().put("s4").put("s8"))
        refused(wrap(badMember.toString()))
        // and an import of a refused payload writes nothing: it throws before building anything
        assertThrows(IllegalArgumentException::class.java) {
            RouteShare.applyImport(badTarget, emptyList(), emptyList(), emptyList(), { x: String -> parse(x) }, identity, newId)
        }
    }

    @Test fun theQrDecision() {
        assertTrue(RouteShare.fitsQr("x".repeat(1700)))
        assertFalse(RouteShare.fitsQr("x".repeat(1701)))
        // bytes, not characters
        assertFalse(RouteShare.fitsQr("→".repeat(600)))
        assertTrue(RouteShare.fitsQr(link))
    }
}
