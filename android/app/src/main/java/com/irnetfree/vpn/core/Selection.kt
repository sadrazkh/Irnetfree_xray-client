package com.irnetfree.vpn.core

/**
 * What the app is pointed at, and what becomes of that when the thing it names
 * goes away. Pure — Store holds the two values and writes them — so the rule is
 * tested off a device.
 *
 * A selection is "<serverId>" | "chain:<id>" | "__pool__" | "__advanced__".
 * The pool and advanced routing are modes of the app, not records anybody can
 * delete, so they always resolve. A chain resolves while it exists: one that has
 * lost members is still the user's chain, and connecting says what it lacks —
 * quietly swapping a route the user built for some single server would be worse.
 *
 * The owner's complaint was the selection "jumping back to the start". The
 * selection itself was stored; what it named was not always there any more —
 * before v1.14.0 every subscription refresh handed out new ids, and a server
 * deleted (or dropped by its panel) left the selection naming nothing, so the
 * screen showed "—" and Connect said "Select a server first". Now a selection
 * that names nothing falls back to the choice before it, then to the first
 * server, and says so; one that still resolves is never touched.
 */
object Selection {
    const val POOL = "__pool__"
    const val ADVANCED = "__advanced__"
    private const val CHAIN = "chain:"

    /** Does [sel] name something that exists? "" never does. */
    fun resolves(sel: String, serverIds: Set<String>, chainIds: Set<String>): Boolean = when {
        sel.isEmpty() -> false
        sel == POOL || sel == ADVANCED -> true
        sel.startsWith(CHAIN) -> sel.substring(CHAIN.length) in chainIds
        else -> sel in serverIds
    }

    /**
     * What the selection should be now: [current] while it resolves; else the
     * choice before it; else the first server; else nothing ("").
     */
    fun repair(current: String, previous: String, serverIds: List<String>, chainIds: Collection<String>): String {
        val servers = serverIds.toHashSet()
        val chains = chainIds.toHashSet()
        return when {
            resolves(current, servers, chains) -> current
            resolves(previous, servers, chains) -> previous
            else -> serverIds.firstOrNull() ?: ""
        }
    }

    /**
     * The "choice before" to keep when [next] is picked over [current]: the
     * current one when it is really being replaced and still resolves, else
     * whatever was kept already — a dangling id is never remembered as a
     * fallback, and picking the same thing twice does not erase the one before.
     */
    fun previousAfterPick(current: String, previous: String, next: String, serverIds: Set<String>, chainIds: Set<String>): String =
        if (next != current && resolves(current, serverIds, chainIds)) current else previous
}
