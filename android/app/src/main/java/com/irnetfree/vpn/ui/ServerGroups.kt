package com.irnetfree.vpn.ui

import com.irnetfree.vpn.core.ServerConfig
import com.irnetfree.vpn.core.Subscription

/**
 * The Servers list as groups: what the user added by hand ("Manual"), then one
 * group per subscription in the order they were added, then servers whose
 * subscription was deleted. Each group folds away under its header, and what
 * is folded is remembered across restarts (Store.collapsedGroups).
 *
 * Pure — no Compose, no Android — so the grouping, the folding, the keys the
 * lazy list is given and the line under a header are tested off a device. The
 * screen only draws [ListEntry]s, in order.
 */
object ServerGroups {
    const val MANUAL = "manual"
    const val ORPHAN = "orphan"
    fun subKey(id: String) = "sub:$id"

    /**
     * One group. [servers] is what the search left; [total] what the group
     * holds. [open]: its servers are listed — a folded group is opened while a
     * search is running, or its matches would be hidden behind a header.
     * [hasSelected]: the selected server is in it (the header says so when folded).
     */
    class Group(
        val key: String,
        val title: String,
        val sub: Subscription?,
        val servers: List<ServerConfig>,
        val total: Int,
        val open: Boolean,
        val hasSelected: Boolean
    )

    /**
     * The groups to show. A subscription with no servers yet (a first fetch
     * that failed) still gets its header — that is where its refresh button
     * is — except during a search, which shows only groups with matches.
     */
    fun build(servers: List<ServerConfig>, subs: List<Subscription>, query: String, collapsed: Set<String>, selectedId: String): List<Group> {
        val q = query.trim()
        val searching = q.isNotEmpty()
        val bySub = servers.groupBy { it.subId }
        val subIds = subs.mapTo(HashSet()) { it.id }
        val out = ArrayList<Group>()
        val seen = HashSet<String>()
        fun add(key: String, title: String, sub: Subscription?, all: List<ServerConfig>, showEmpty: Boolean) {
            if (!seen.add(key)) return            // a subscription listed twice: its servers are already shown
            val shown = if (searching) all.filter { s -> s.name.contains(q, true) || s.address.contains(q, true) } else all
            if (shown.isEmpty() && (searching || !showEmpty)) return
            out.add(Group(key, title, sub, shown, all.size, searching || key !in collapsed, all.any { s -> s.id == selectedId }))
        }
        add(MANUAL, "Manual", null, bySub[null] ?: emptyList(), false)
        for (sub in subs) add(subKey(sub.id), sub.name.ifBlank { "Subscription" }, sub, bySub[sub.id] ?: emptyList(), true)
        val orphans = servers.filter { s -> val id = s.subId; id != null && id !in subIds }
        add(ORPHAN, "From a removed subscription", null, orphans, false)
        return out
    }

    /** One line of the lazy list. [key] is unique in the list — Compose throws on a repeated key. */
    sealed class ListEntry(val key: String) {
        class Head(val group: Group) : ListEntry("g:" + group.key)
        class Item(val group: Group, val server: ServerConfig, key: String) : ListEntry(key)
        class Empty(val group: Group) : ListEntry("e:" + group.key)
    }

    /**
     * The groups flattened into list lines. A server id seen twice (a store
     * restored by hand can hold that) gets a suffixed key rather than taking
     * the whole screen down.
     */
    fun entries(groups: List<Group>, searching: Boolean): List<ListEntry> {
        val out = ArrayList<ListEntry>()
        val used = HashSet<String>()
        for (g in groups) {
            out.add(ListEntry.Head(g))
            if (!g.open) continue
            if (g.servers.isEmpty()) {
                if (!searching) out.add(ListEntry.Empty(g))
                continue
            }
            for (s in g.servers) {
                var k = "s:" + s.id
                var n = 1
                while (!used.add(k)) { n++; k = "s:" + s.id + "#" + n }
                out.add(ListEntry.Item(g, s, k))
            }
        }
        return out
    }

    /**
     * Where the list opens: the selected server's row, or the header of its
     * group when that group is folded; -1 = the top.
     */
    fun scrollTarget(entries: List<ListEntry>, selectedId: String): Int {
        if (selectedId.isEmpty()) return -1
        val row = entries.indexOfFirst { it is ListEntry.Item && it.server.id == selectedId }
        if (row >= 0) return row
        // a folded group lists nothing, but still holds all of its servers
        return entries.indexOfFirst { e -> e is ListEntry.Head && !e.group.open && e.group.servers.any { s -> s.id == selectedId } }
    }

    fun toggle(collapsed: Set<String>, key: String): Set<String> = if (key in collapsed) collapsed - key else collapsed + key

    /** Folded keys whose subscription is gone are forgotten. */
    fun prune(collapsed: Set<String>, subs: List<Subscription>): Set<String> {
        val live = subs.mapTo(HashSet()) { subKey(it.id) }
        return collapsed.filterTo(HashSet()) { it == MANUAL || it == ORPHAN || it in live }
    }

    /** The line under a subscription's header, and how worried it looks: [LEVEL_OK], [LEVEL_WARN] or [LEVEL_BAD]. */
    class Summary(val text: String, val level: Int)
    const val LEVEL_OK = 0
    const val LEVEL_WARN = 1
    const val LEVEL_BAD = 2

    /**
     * Usage (when the panel reports it), expiry (likewise), and when it was
     * last updated — or that the last try failed, in which case its servers are
     * the ones it had before (SubRefresh keeps them).
     */
    fun summary(sub: Subscription, now: Long): Summary {
        val parts = ArrayList<String>()
        var level = LEVEL_OK
        if (sub.total > 0) {
            val used = sub.upload + sub.download
            val pct = (used.toDouble() / sub.total * 100).toInt().coerceIn(0, 100)
            parts.add("${fmtBytes(used)} / ${fmtBytes(sub.total)}")
            level = maxOf(level, if (pct >= 90) LEVEL_BAD else if (pct >= 70) LEVEL_WARN else LEVEL_OK)
        }
        if (sub.expire > 0) {
            val msLeft = sub.expire * 1000L - now
            if (msLeft < 0) {
                parts.add("expired")
                level = LEVEL_BAD
            } else {
                val days = msLeft / 86_400_000L
                parts.add(if (days == 1L) "1 day left" else "$days days left")
                if (days <= 3) level = maxOf(level, LEVEL_WARN)
            }
        }
        if (sub.lastError.isNotEmpty() && sub.lastTried > 0) {
            parts.add("last try failed ${fmtAgo(now - sub.lastTried)}")
            level = maxOf(level, LEVEL_WARN)
        } else {
            parts.add(if (sub.lastUpdated > 0) "updated ${fmtAgo(now - sub.lastUpdated)}" else "never updated")
        }
        return Summary(parts.joinToString(" · "), level)
    }
}
