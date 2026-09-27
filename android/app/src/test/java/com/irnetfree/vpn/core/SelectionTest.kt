package com.irnetfree.vpn.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The selection survives a restart, a subscription refresh and a delete
 * (Selection, used by Store on start and after every delete or refresh).
 */
class SelectionTest {
    private val sub = Subscription("sub-1", "panel", "https://panel.example/sub")
    // the shape SubRefreshTest uses: the owner's xhttp + REALITY subscription servers
    private fun link(host: String, name: String) =
        "vless://u-$host@$host:443?type=xhttp&path=%2Fx&host=$host&mode=auto&security=reality&sni=www.google.com&pbk=K&sid=ab#$name"
    private fun parse(l: String) = LinkParser.parseLink(l).copy(subId = sub.id)
    private fun ids(vararg s: String) = s.toSet()

    @Test fun whatResolvesAndWhatDoesNot() {
        val servers = ids("a", "b"); val chains = ids("c1")
        assertTrue(Selection.resolves("a", servers, chains))
        assertTrue(Selection.resolves("chain:c1", servers, chains))
        assertTrue(Selection.resolves(Selection.POOL, servers, chains))
        assertTrue(Selection.resolves(Selection.ADVANCED, servers, chains))
        assertFalse(Selection.resolves("", servers, chains))
        assertFalse(Selection.resolves("gone", servers, chains))
        assertFalse(Selection.resolves("chain:gone", servers, chains))
        // Store's own names for the two modes are these very strings
        assertEquals("__pool__", Selection.POOL); assertEquals("__advanced__", Selection.ADVANCED)
    }

    @Test fun aSelectionThatStillResolvesIsNeverMoved() {
        assertEquals("b", Selection.repair("b", "a", listOf("a", "b"), emptyList()))
        assertEquals("chain:c1", Selection.repair("chain:c1", "a", listOf("a"), listOf("c1")))
        assertEquals(Selection.POOL, Selection.repair(Selection.POOL, "", emptyList(), emptyList()))
        assertEquals(Selection.ADVANCED, Selection.repair(Selection.ADVANCED, "a", listOf("a"), emptyList()))
    }

    @Test fun aDeletedSelectionFallsBackToTheChoiceBeforeItThenTheFirstServer() {
        // the selected server was deleted: the one picked before it
        assertEquals("b", Selection.repair("gone", "b", listOf("a", "b", "c"), emptyList()))
        // ...a deleted chain the same way
        assertEquals("a", Selection.repair("chain:gone", "a", listOf("a", "b"), listOf("c2")))
        // the choice before is gone too: the first server
        assertEquals("a", Selection.repair("gone", "also-gone", listOf("a", "b"), emptyList()))
        // never chosen at all (an empty selection with servers): the first server
        assertEquals("a", Selection.repair("", "", listOf("a", "b"), emptyList()))
        // nothing left to point at: nothing, and no crash
        assertEquals("", Selection.repair("gone", "b", emptyList(), emptyList()))
        assertEquals("", Selection.repair("", "", emptyList(), emptyList()))
    }

    @Test fun theChoiceBeforeIsWhatWasReallyReplaced() {
        val servers = ids("a", "b", "c"); val chains = ids("c1")
        assertEquals("a", Selection.previousAfterPick("a", "", "b", servers, chains))
        assertEquals("chain:c1", Selection.previousAfterPick("chain:c1", "a", "b", servers, chains))
        // picking the same one again keeps the one before it
        assertEquals("a", Selection.previousAfterPick("b", "a", "b", servers, chains))
        // a dangling current is never remembered as a fallback
        assertEquals("a", Selection.previousAfterPick("gone", "a", "b", servers, chains))
        assertEquals("", Selection.previousAfterPick("", "", "b", servers, chains))
    }

    /*
     * The owner's case: a subscription server is selected and the subscription
     * is refreshed. Since v1.14.0 the refresh keeps the ids (SubRefresh.merge),
     * so the selection stays exactly where it was; a refresh that drops that
     * server falls back to the choice before, not to "—" and not to the top.
     */
    @Test fun theSelectionSurvivesASubscriptionRefresh() {
        val a = parse(link("a.example", "A")); val b = parse(link("b.example", "B")); val c = parse(link("c.example", "C"))
        val old = listOf(a, b, c)
        val selected = b.id
        // the panel renames everything and reorders it: same servers, same ids
        val fresh = listOf(link("c.example", "C · 9 GB"), link("b.example", "B · 9 GB"), link("a.example", "A · 9 GB")).map { LinkParser.parseLink(it) }
        val merged = SubRefresh.merge(old, fresh, sub.id).servers
        assertEquals(selected, Selection.repair(selected, a.id, merged.map { it.id }, emptyList()))
        // the panel drops the selected server: back to the one chosen before it
        val dropped = SubRefresh.merge(old, listOf(link("a.example", "A"), link("c.example", "C")).map { LinkParser.parseLink(it) }, sub.id).servers
        assertFalse(dropped.any { it.id == selected })
        assertEquals(a.id, Selection.repair(selected, a.id, dropped.map { it.id }, emptyList()))
        // ...or, with nothing chosen before it, to the first server there is
        assertEquals(dropped.first().id, Selection.repair(selected, "", dropped.map { it.id }, emptyList()))
    }

    @Test fun deletingAnotherServerLeavesTheSelectionAlone() {
        val left = listOf("a", "c")   // "b" deleted, "c" selected
        assertEquals("c", Selection.repair("c", "a", left, emptyList()))
    }
}
