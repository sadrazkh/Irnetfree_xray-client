package com.irnetfree.vpn.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A subscription refresh against the servers it already gave you (SubRefresh).
 * The shapes are the owner's: a chain whose first hop is an xhttp + REALITY
 * server from a subscription, and a panel that sometimes answers with nothing.
 */
class SubRefreshTest {
    private val sub = Subscription("sub-1", "panel", "https://panel.example/sub")
    private fun link(host: String, name: String, uuid: String = "u-$host", path: String = "/x", sni: String = "www.google.com") =
        "vless://$uuid@$host:443?type=xhttp&path=${path.replace("/", "%2F")}&host=$host&mode=auto&security=reality&sni=$sni&pbk=K&sid=ab#$name"
    private fun parse(l: String) = LinkParser.parseLink(l).copy(subId = sub.id)
    /** What the edit sheet does: read, change, save. */
    private fun edited(s: ServerConfig, edit: (ServerEditor.Fields) -> Unit): ServerConfig {
        val f = ServerEditor.read(s); edit(f); return ServerEditor.apply(s, f)
    }
    private fun realitySni(s: ServerConfig) = s.outbound.getJSONObject("streamSettings").getJSONObject("realitySettings").getString("serverName")
    private fun vnextAddress(s: ServerConfig) = s.outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getString("address")

    /*
     * What the user edited on a subscription server — above all a clean
     * Cloudflare IP in place of the panel's address, which is how half of Iran
     * gets through — is the user's, and a refresh must not revert it. What the
     * panel changed where the user edited nothing is the panel's. The test for
     * "the user's" is the same as for fragment/noise/core: it differs from
     * what the old server's own link gives.
     */
    @Test fun whatTheUserEditedOnTheConnectionSurvivesARefresh() {
        val orig = parse(link("a.example", "A · 12 GB left"))
        val mine = edited(orig) { it.address = "104.16.1.1"; it.path = "/mine"; it.sni = "www.speedtest.net" }
        assertEquals("104.16.1.1", mine.address)
        // the panel renames it (so its link changed) and changes nothing else
        val out = SubRefresh.merge(listOf(mine), listOf(LinkParser.parseLink(link("a.example", "A · 11 GB left"))), sub.id).servers[0]
        assertEquals(mine.id, out.id)
        assertEquals("104.16.1.1", out.address); assertEquals("104.16.1.1", vnextAddress(out))
        assertEquals("/mine", out.outbound.getJSONObject("streamSettings").getJSONObject("xhttpSettings").getString("path"))
        assertEquals("www.speedtest.net", realitySni(out))
        assertEquals("A · 11 GB left", out.name)   // the name was never the user's: the panel's
        // ...and the user's own name, when they gave one, is theirs too
        val named = edited(orig) { it.name = "Work" }
        assertEquals("Work", SubRefresh.merge(listOf(named), listOf(LinkParser.parseLink(link("a.example", "A · 11 GB left"))), sub.id).servers[0].name)
    }

    @Test fun whatThePanelChangedWinsWhereTheUserEditedNothing() {
        val old = parse(link("a.example", "A"))
        // a new SNI from the panel: still the same server (same address, key, transport), the panel's SNI
        val out = SubRefresh.merge(listOf(old), listOf(LinkParser.parseLink(link("a.example", "A", sni = "www.apple.com"))), sub.id).servers[0]
        assertEquals(old.id, out.id); assertEquals("www.apple.com", realitySni(out))
        // a new address from the panel: the panel's address (a new server by X1's identity)
        val moved = SubRefresh.merge(listOf(old), listOf(LinkParser.parseLink(link("b.example", "A", uuid = "u-a.example"))), sub.id).servers[0]
        assertEquals("b.example", moved.address); assertEquals("b.example", vnextAddress(moved))
        // the user edited only the SNI: the panel's new address is still the panel's
        val sniOnly = edited(old) { it.sni = "www.speedtest.net" }
        val both = SubRefresh.merge(listOf(sniOnly), listOf(LinkParser.parseLink(link("a.example", "A", sni = "www.apple.com", path = "/x"))), sub.id).servers[0]
        assertEquals(old.id, both.id); assertEquals("www.speedtest.net", realitySni(both)); assertEquals("a.example", both.address)
    }

    /*
     * What an OLDER PARSER got wrong is not an edit. WireGuard subscription
     * servers were always stored with their link, and the parser before this
     * update read a WARP key's '+' as a space and `host:2408/` as no port
     * (51820). Today's parser reads the same link right; the stored record still
     * differs from it — and must be replaced by it, not "kept as the user's".
     */
    @Test fun anOldParsersMistakeIsNotAnEdit() {
        val priv = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
        val pub = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
        val raw = "wireguard://$priv@engage.cloudflareclient.com:2408/?publickey=$pub&address=172.16.0.2/32&mtu=1280#warp"
        val legacy = ServerConfig("s-warp", "warp", "wireguard", "engage.cloudflareclient.com", 51820,
            LinkParser.buildWireguardOutbound(priv.replace('+', ' '), pub.replace('+', ' '), "engage.cloudflareclient.com:51820",
                "172.16.0.2/32", "", "1280", null, null),
            raw, subId = sub.id)
        val out = SubRefresh.merge(listOf(legacy), listOf(LinkParser.parseLink(raw)), sub.id).servers[0]
        assertEquals("s-warp", out.id)
        assertEquals(2408, out.port)
        val set = out.outbound.getJSONObject("settings")
        assertEquals(priv, set.getString("secretKey"))
        val peer = set.getJSONArray("peers").getJSONObject(0)
        assertEquals(pub, peer.getString("publicKey")); assertEquals("engage.cloudflareclient.com:2408", peer.getString("endpoint"))
    }

    /* A new handshake from the panel takes the user's address, never their SNI or keys for the old one. */
    @Test fun aNewHandshakeFromThePanelTakesNothingOfTheOldOne() {
        val mine = edited(parse(link("a.example", "A"))) { it.address = "104.16.1.1"; it.sni = "www.speedtest.net"; it.pbk = "MINE" }
        // the panel moves the same server (same address, uuid, transport) from REALITY to TLS
        val tls = "vless://u-a.example@a.example:443?type=xhttp&path=%2Fx&host=a.example&mode=auto&security=tls&sni=cdn.example&fp=chrome#A"
        val out = SubRefresh.merge(listOf(mine), listOf(LinkParser.parseLink(tls)), sub.id).servers[0]
        assertEquals(mine.id, out.id)
        assertEquals("104.16.1.1", out.address); assertEquals("104.16.1.1", vnextAddress(out))
        val st = out.outbound.getJSONObject("streamSettings")
        assertEquals("tls", st.getString("security")); assertFalse(st.has("realitySettings"))
        assertEquals("cdn.example", st.getJSONObject("tlsSettings").getString("serverName"))
    }

    @Test fun theSheetsOwnNoiseSpellingIsNotAnEdit() {
        // noise=fakehello in the link; the sheet writes it back as "faketls" on any save
        val raw = "vless://u-a@a.example:443?type=tcp&security=tls&sni=a.example&noise=fakehello#A"
        val saved = edited(parse(raw)) { it.noise = "faketls" }
        assertEquals("faketls", saved.outbound.getString("_noise"))
        // the panel moves the SNI and the noise: both are the panel's
        val fresh = LinkParser.parseLink("vless://u-a@a.example:443?type=tcp&security=tls&sni=b.example&noise=random#A2")
        val out = SubRefresh.merge(listOf(saved), listOf(fresh), sub.id).servers[0]
        assertEquals(saved.id, out.id)
        assertEquals("random", out.outbound.getString("_noise"))
        assertEquals("b.example", out.outbound.getJSONObject("streamSettings").getJSONObject("tlsSettings").getString("serverName"))
        assertEquals("A2", out.name); assertEquals("a.example", out.address)
    }

    @Test fun anUnchangedServerKeepsItsId() {
        val old = listOf(parse(link("a.example", "A")), parse(link("b.example", "B")))
        val fresh = listOf(LinkParser.parseLink(link("a.example", "A")), LinkParser.parseLink(link("b.example", "B")))
        assertNotEquals(old[0].id, fresh[0].id)   // the parser always hands out a new one
        val m = SubRefresh.merge(old, fresh, sub.id)
        assertEquals(old.map { it.id }, m.servers.map { it.id })
        assertTrue(m.servers.all { it.subId == sub.id })
        assertEquals(2, m.kept); assertEquals(0, m.added); assertEquals(0, m.dropped)
    }

    @Test fun aRenamedServerIsStillTheSameServer() {
        // a new name changes the link, not the server: matched by identity
        val old = listOf(parse(link("a.example", "A · 12 GB left")))
        val m = SubRefresh.merge(old, listOf(LinkParser.parseLink(link("a.example", "A · 11 GB left"))), sub.id)
        assertEquals(old[0].id, m.servers[0].id)
        assertEquals("A · 11 GB left", m.servers[0].name)
        // a store from before links were kept (raw "") is matched the same way
        val legacy = listOf(parse(link("a.example", "A")).copy(raw = ""))
        assertEquals(legacy[0].id, SubRefresh.merge(legacy, listOf(LinkParser.parseLink(link("a.example", "A"))), sub.id).servers[0].id)
    }

    @Test fun aDifferentServerIsNotMatched() {
        val old = listOf(parse(link("a.example", "A")))
        // same address, another uuid / another path: another server
        for (l in listOf(link("a.example", "A", uuid = "other"), link("a.example", "A", path = "/y"), link("c.example", "A"))) {
            val m = SubRefresh.merge(old, listOf(LinkParser.parseLink(l)), sub.id)
            assertNotEquals(old[0].id, m.servers[0].id)
            assertEquals(1, m.added); assertEquals(1, m.dropped)
        }
    }

    @Test fun duplicatesDoNotBothClaimOneOldServer() {
        val old = listOf(parse(link("a.example", "A")))
        val twice = listOf(LinkParser.parseLink(link("a.example", "A")), LinkParser.parseLink(link("a.example", "A")))
        val m = SubRefresh.merge(old, twice, sub.id)
        assertEquals(old[0].id, m.servers[0].id)
        assertNotEquals(old[0].id, m.servers[1].id)
        assertEquals(2, m.servers.map { it.id }.toSet().size)
        // two old copies and two fresh: each keeps one
        val oldTwice = listOf(parse(link("a.example", "A")), parse(link("a.example", "A")))
        assertEquals(oldTwice.map { it.id }, SubRefresh.merge(oldTwice, twice, sub.id).servers.map { it.id })
    }

    @Test fun whatTheUserSetOnAServerSurvivesARefresh() {
        val base = parse(link("a.example", "A"))
        val ob = org.json.JSONObject(base.outbound.toString()).put("_fragment", "tlshello,100-200,10-20").put("_noise", "random")
        val old = base.copy(outbound = ob, engine = "sing-box", certPin = "ab".repeat(32), certPinAt = "then", certPinCheckedAt = 42L)
        val out = SubRefresh.merge(listOf(old), listOf(LinkParser.parseLink(link("a.example", "A"))), sub.id).servers[0]
        assertEquals(old.id, out.id); assertEquals("sing-box", out.engine)
        assertEquals("ab".repeat(32), out.certPin); assertEquals("then", out.certPinAt); assertEquals(42L, out.certPinCheckedAt)
        assertEquals("tlshello,100-200,10-20", out.outbound.getString("_fragment")); assertEquals("random", out.outbound.getString("_noise"))
    }

    /*
     * `fragment=`, `noise=` and `engine=` come FROM THE LINK as well, and they
     * are what a panel retunes when the DPI changes. Only a value the user set
     * themselves — one that differs from what the old server's own link gives —
     * may outlive a refresh.
     */
    private fun tuned(host: String, name: String, frag: String?, engine: String? = null) =
        "vless://u-$host@$host:443?type=tcp&security=tls&sni=$host" +
            (frag?.let { "&fragment=" + it.replace(",", "%2C") } ?: "") + (engine?.let { "&engine=$it" } ?: "") + "#$name"

    @Test fun aPanelThatRetunesTheFragmentIsFollowed() {
        val old = parse(tuned("a.example", "A", "tlshello,100-200,10-20"))
        val out = SubRefresh.merge(listOf(old), listOf(LinkParser.parseLink(tuned("a.example", "A", "tlshello,1-3,1-2"))), sub.id).servers[0]
        assertEquals(old.id, out.id)
        assertEquals("tlshello,1-3,1-2", out.outbound.getString("_fragment"))
        // a panel that drops it is followed too
        val gone = SubRefresh.merge(listOf(old), listOf(LinkParser.parseLink(tuned("a.example", "A", null))), sub.id).servers[0]
        assertEquals(old.id, gone.id)
        assertFalse(gone.outbound.has("_fragment"))
    }

    @Test fun aFragmentTheUserSetWinsOverThePanels() {
        val base = parse(tuned("a.example", "A", "tlshello,100-200,10-20"))
        val mine = base.copy(outbound = org.json.JSONObject(base.outbound.toString()).put("_fragment", "1-3,5-10,1-1"))
        val fresh = listOf(LinkParser.parseLink(tuned("a.example", "A", "tlshello,1-3,1-2")))
        assertEquals("1-3,5-10,1-1", SubRefresh.merge(listOf(mine), fresh, sub.id).servers[0].outbound.getString("_fragment"))
        // cleared by the user: it stays cleared
        val cleared = base.copy(outbound = org.json.JSONObject(base.outbound.toString()).also { it.remove("_fragment") })
        assertFalse(SubRefresh.merge(listOf(cleared), fresh, sub.id).servers[0].outbound.has("_fragment"))
    }

    @Test fun theCoreFollowsTheSameRule() {
        val old = parse(tuned("a.example", "A", null, engine = "xray-pattn"))
        fun refreshTo(o: ServerConfig, engine: String?) = SubRefresh.merge(listOf(o), listOf(LinkParser.parseLink(tuned("a.example", "A", null, engine))), sub.id).servers[0]
        assertEquals("sing-box", refreshTo(old, "sing-box").engine)          // the panel changed it
        assertNull(refreshTo(old, null).engine)                              // the panel dropped it
        assertEquals("sing-box", refreshTo(old.copy(engine = "sing-box"), "xray-pattn").engine)   // the user chose it
        assertNull(refreshTo(old.copy(engine = null), "xray-pattn").engine)  // the user chose the default
    }

    @Test fun aServerStoredWithoutItsLinkKeepsWhatItHas() {
        // an older store kept no link, so nothing can tell a user's value from the panel's: keep it
        val old = parse(tuned("a.example", "A", "tlshello,100-200,10-20", engine = "sing-box")).copy(raw = "")
        val out = SubRefresh.merge(listOf(old), listOf(LinkParser.parseLink(tuned("a.example", "A", "tlshello,1-3,1-2"))), sub.id).servers[0]
        assertEquals(old.id, out.id)
        assertEquals("tlshello,100-200,10-20", out.outbound.getString("_fragment")); assertEquals("sing-box", out.engine)
    }

    @Test fun variantsOfOneServerKeepTheirOwnIds() {
        // One server offered with two SNIs (or two fingerprints), which a panel
        // reorders and renames: every link differs and the loose identity is the
        // same for both, so only the tighter one keeps each id with its variant.
        fun v(sni: String, fp: String, name: String) = "vless://u-a@a.example:443?type=tcp&security=tls&sni=$sni&fp=$fp#$name"
        val old = listOf(parse(v("x.example", "chrome", "A1")), parse(v("y.example", "chrome", "A2")), parse(v("x.example", "firefox", "A3")))
        val fresh = listOf(v("x.example", "firefox", "A3 · new"), v("y.example", "chrome", "A2 · new"), v("x.example", "chrome", "A1 · new")).map { LinkParser.parseLink(it) }
        assertEquals(listOf(old[2].id, old[1].id, old[0].id), SubRefresh.merge(old, fresh, sub.id).servers.map { it.id })
    }

    @Test fun theChainStillHasItsMembersAfterARefresh() {
        // the owner's corporate chain: [subscription xhttp server] → [WireGuard added by hand]
        val xhttp = parse(link("edge.example", "Edge"))
        val wg = LinkParser.parseLink("wireguard://PRIV@cobra.tes.ca:42421?publickey=PUB&address=10.10.10.42&allowedips=192.168.0.0%2F16%2C10.0.0.0%2F8&dns=192.168.60.1%2Ctes.systems#Tes")
        val chain = ChainConfig("chain-1", "Tes Chain", listOf(xhttp.id, wg.id))
        val all = listOf(wg, xhttp)
        val applied = SubRefresh.applyFetch(all, sub, listOf(LinkParser.parseLink(link("edge.example", "Edge (renamed)"))), null, emptyList(), 1000L)
        val ids = applied.servers!!.map { it.id }.toSet()
        assertTrue(chain.members.all { it in ids })
        assertEquals(listOf(wg.id, xhttp.id), applied.servers!!.map { it.id })   // the place in the list is kept too
    }

    @Test fun aResponseWithNoServersChangesNothing() {
        val old = parse(link("a.example", "A"))
        val before = sub.copy(serverCount = 1, lastUpdated = 500L)
        val applied = SubRefresh.applyFetch(listOf(old), before, emptyList(), null, listOf("vless://… : bad port"), 9000L)
        assertNull(applied.servers)
        assertEquals(500L, applied.sub.lastUpdated)          // not "updated"
        assertEquals(9000L, applied.sub.lastTried)           // but tried
        assertEquals(1, applied.sub.serverCount)
        assertTrue(applied.sub.lastError.startsWith("no servers in the response"))
        // a good one clears the error and moves both clocks
        val good = SubRefresh.applyFetch(listOf(old), applied.sub, listOf(LinkParser.parseLink(link("a.example", "A"))),
            Subscriptions.Usage(1, 2, 10, 99), emptyList(), 12000L)
        assertEquals(12000L, good.sub.lastUpdated); assertEquals(12000L, good.sub.lastTried)
        assertEquals("", good.sub.lastError); assertEquals(10L, good.sub.total)
        assertEquals(listOf(old.id), good.servers!!.map { it.id })
    }

    @Test fun replaceKeepsTheSubscriptionsPlace() {
        val a = parse(link("a.example", "A")).copy(subId = null)
        val s1 = parse(link("s1.example", "S1")); val s2 = parse(link("s2.example", "S2"))
        val b = parse(link("b.example", "B")).copy(subId = "other")
        val n = parse(link("n.example", "N"))
        assertEquals(listOf(a.id, n.id, b.id), SubRefresh.replace(listOf(a, s1, s2, b), sub.id, listOf(n)).map { it.id })
        // a subscription with no servers yet goes at the end
        assertEquals(listOf(a.id, b.id, n.id), SubRefresh.replace(listOf(a, b), sub.id, listOf(n)).map { it.id })
    }

    @Test fun aFailedAttemptWaitsOutTheIntervalToo() {
        val hour = 3_600_000L
        val never = sub
        assertTrue(SubRefresh.due(never, 10 * hour, hour))
        // it failed a minute ago: not again yet, although it has never succeeded
        val failed = SubRefresh.failed(never, "HTTP 403", 10 * hour - 60_000L)
        assertFalse(SubRefresh.due(failed, 10 * hour, hour))
        assertTrue(SubRefresh.due(failed, 11 * hour, hour))
        assertEquals("HTTP 403", failed.lastError)
        // the record carries both through the store
        val back = Subscription.fromJson(failed.toJson())
        assertEquals(failed.lastTried, back.lastTried); assertEquals("HTTP 403", back.lastError)
        assertEquals("", Subscription.fromJson(sub.toJson()).lastError)
    }
}
