package com.irnetfree.vpn.ui

import com.irnetfree.vpn.core.ServerConfig
import com.irnetfree.vpn.core.Subscription
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The Servers list as collapsible groups (ServerGroups). */
class ServerGroupsTest {
    private fun srv(id: String, name: String, subId: String? = null, address: String = "$id.example") =
        ServerConfig(id, name, "vless", address, 443, JSONObject(), subId = subId)

    private val panel = Subscription("p", "Panel", "https://panel.example/sub")
    private val work = Subscription("w", "Work", "https://work.example/sub")
    private val empty = Subscription("e", "", "https://new.example/sub")
    private val servers = listOf(
        srv("m1", "Home router"),
        srv("p1", "🇩🇪-Sadra", "p"), srv("p2", "🇮🇹-CDN1", "p"),
        srv("w1", "Office", "w"),
        srv("o1", "Old one", "removed-sub"),
        srv("m2", "My VPS", address = "203.0.113.7")
    )

    private fun keys(groups: List<ServerGroups.Group>) = groups.map { it.key }

    @Test fun manualFirstThenEachSubscriptionThenTheOrphans() {
        val g = ServerGroups.build(servers, listOf(panel, work, empty), "", emptySet(), "")
        assertEquals(listOf("manual", "sub:p", "sub:w", "sub:e", "orphan"), keys(g))
        assertEquals(listOf("Manual", "Panel", "Work", "Subscription", "From a removed subscription"), g.map { it.title })
        assertEquals(listOf(2, 2, 1, 0, 1), g.map { it.total })
        assertEquals(listOf("m1", "m2"), g[0].servers.map { it.id })
        assertTrue(g.all { it.open })
        // a subscription with nothing yet keeps its header (its refresh button lives there)...
        assertEquals(panel, g[1].sub); assertEquals(0, g[3].servers.size)
        // ...and says so in the list, rather than showing nothing
        val e = ServerGroups.entries(g, searching = false)
        assertTrue(e.any { it is ServerGroups.ListEntry.Empty && it.group.key == "sub:e" })
        // no manual servers and no orphans: no such headers
        val onlySub = ServerGroups.build(listOf(srv("p1", "x", "p")), listOf(panel), "", emptySet(), "")
        assertEquals(listOf("sub:p"), keys(onlySub))
    }

    @Test fun aFoldedGroupShowsOnlyItsHeaderAndSaysItHoldsTheSelection() {
        var folded = ServerGroups.toggle(emptySet(), "sub:p")
        assertEquals(setOf("sub:p"), folded)
        val g = ServerGroups.build(servers, listOf(panel, work), "", folded, "p2")
        val p = g.first { it.key == "sub:p" }
        assertFalse(p.open); assertTrue(p.hasSelected)
        val e = ServerGroups.entries(g, searching = false)
        assertFalse(e.any { it is ServerGroups.ListEntry.Item && it.group.key == "sub:p" })
        assertTrue(e.any { it is ServerGroups.ListEntry.Head && it.group.key == "sub:p" })
        folded = ServerGroups.toggle(folded, "sub:p")
        assertEquals(emptySet<String>(), folded)
    }

    @Test fun aSearchMatchesNameOrAddressOpensFoldedGroupsAndHidesTheRest() {
        val folded = setOf("manual", "sub:p")
        val byName = ServerGroups.build(servers, listOf(panel, work, empty), "cdn", folded, "")
        assertEquals(listOf("sub:p"), keys(byName))
        assertTrue(byName[0].open)
        assertEquals(listOf("p2"), byName[0].servers.map { it.id })
        assertEquals(2, byName[0].total)
        val byAddress = ServerGroups.build(servers, listOf(panel, work, empty), " 203.0.113 ", folded, "")
        assertEquals(listOf("m2"), byAddress.flatMap { g -> g.servers.map { it.id } })
        // nothing matches: no groups, and no "empty" lines either
        val none = ServerGroups.build(servers, listOf(panel, work, empty), "zzz", folded, "")
        assertTrue(none.isEmpty())
        assertTrue(ServerGroups.entries(none, searching = true).isEmpty())
    }

    @Test fun aGroupHoldsAllOfItsServersWhateverTheSearchShows() {
        // 📶 and ⚡ on a header act on the whole group, not on what a search left of it
        val searched = ServerGroups.build(servers, listOf(panel, work), "cdn", emptySet(), "")
        val p = searched.first { it.key == "sub:p" }
        assertEquals(listOf("p2"), p.servers.map { it.id })
        assertEquals(listOf("p1", "p2"), p.all.map { it.id })
        assertEquals(p.total, p.all.size)
        // a folded group holds them too
        val folded = ServerGroups.build(servers, listOf(panel, work), "", setOf("manual"), "")
        assertEquals(listOf("m1", "m2"), folded.first { it.key == "manual" }.all.map { it.id })
        // no search: the two lists are the same, group by group
        val plain = ServerGroups.build(servers, listOf(panel, work), "", emptySet(), "")
        assertEquals(plain.map { g -> g.servers.map { it.id } }, plain.map { g -> g.all.map { it.id } })
        assertEquals(listOf("o1"), plain.first { it.key == "orphan" }.all.map { it.id })
    }

    @Test fun everyLineHasAUniqueKeyEvenWhenAnIdRepeats() {
        val twice = listOf(srv("x", "one"), srv("x", "two"), srv("x", "three", "p"), srv("y", "four", "p"))
        // the same subscription listed twice is shown once
        val g = ServerGroups.build(twice, listOf(panel, panel), "", emptySet(), "")
        assertEquals(listOf("manual", "sub:p"), keys(g))
        val e = ServerGroups.entries(g, searching = false)
        val k = e.map { it.key }
        assertEquals(k.size, k.toSet().size)
        assertEquals(listOf("g:manual", "s:x", "s:x#2", "g:sub:p", "s:x#3", "s:y"), k)
    }

    @Test fun theListOpensAtTheSelectedServerOrItsFoldedGroup() {
        val open = ServerGroups.entries(ServerGroups.build(servers, listOf(panel, work), "", emptySet(), "w1"), false)
        val i = ServerGroups.scrollTarget(open, "w1")
        assertEquals("s:w1", open[i].key)
        val shut = ServerGroups.entries(ServerGroups.build(servers, listOf(panel, work), "", setOf("sub:w"), "w1"), false)
        assertEquals("g:sub:w", shut[ServerGroups.scrollTarget(shut, "w1")].key)
        assertEquals(-1, ServerGroups.scrollTarget(open, ""))
        assertEquals(-1, ServerGroups.scrollTarget(open, "chain:c1"))
    }

    @Test fun foldedKeysOfDeletedSubscriptionsAreForgotten() {
        val kept = ServerGroups.prune(setOf("manual", "orphan", "sub:p", "sub:gone"), listOf(panel))
        assertEquals(setOf("manual", "orphan", "sub:p"), kept)
    }

    @Test fun theLineUnderASubscriptionHeader() {
        val now = 1_800_000_000_000L
        val gb = 1024L * 1024 * 1024
        // usage and expiry the panel reported, and when it was updated
        val fine = ServerGroups.summary(panel.copy(download = 2 * gb, total = 10 * gb, expire = now / 1000 + 12 * 86_400, lastUpdated = now - 5 * 60_000), now)
        assertEquals("${fmtBytes(2 * gb)} / ${fmtBytes(10 * gb)} · 12 days left · updated 5 min ago", fine.text)
        assertEquals(ServerGroups.LEVEL_OK, fine.level)
        // nearly used up, and a few days left: a warning; used up or expired: bad
        assertEquals(ServerGroups.LEVEL_WARN, ServerGroups.summary(panel.copy(download = 7 * gb, total = 10 * gb, lastUpdated = now), now).level)
        assertEquals(ServerGroups.LEVEL_WARN, ServerGroups.summary(panel.copy(expire = now / 1000 + 2 * 86_400, lastUpdated = now), now).level)
        assertEquals(ServerGroups.LEVEL_BAD, ServerGroups.summary(panel.copy(download = 95 * gb, total = 100 * gb, lastUpdated = now), now).level)
        val expired = ServerGroups.summary(panel.copy(expire = now / 1000 - 60, lastUpdated = now), now)
        assertTrue(expired.text.startsWith("expired")); assertEquals(ServerGroups.LEVEL_BAD, expired.level)
        // the last try failed: said, as a warning (its servers are the ones it had)
        val failed = ServerGroups.summary(panel.copy(lastUpdated = now - 86_400_000, lastTried = now - 60_000, lastError = "timeout"), now)
        assertEquals("last try failed 1 min ago", failed.text); assertEquals(ServerGroups.LEVEL_WARN, failed.level)
        // nothing known yet
        assertEquals("never updated", ServerGroups.summary(empty, now).text)
    }
}
