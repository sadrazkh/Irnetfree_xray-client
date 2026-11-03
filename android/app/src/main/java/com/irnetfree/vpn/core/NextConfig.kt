package com.irnetfree.vpn.core

/**
 * Which config to try after a failed connect — Home's "Try the next config"
 * — and the one order by measured speed it shares with the Servers list's
 * sort (ServerGroups). Pure, so both run off a device.
 *
 * The order, in every list it sorts: a real round trip that succeeded, quickest
 * first; then a handshake that succeeded, quickest first; then what was never
 * measured, in the list's own order; then what was measured and failed. A
 * negative figure is a failure (the app's -1), null is "not measured".
 */
object NextConfig {
    /** A server's last test as the order reads it: the two figures of the UI's TestState, in ms. */
    data class Test(val tcp: Long? = null, val down: Long? = null)

    /** 0 a real round trip, 1 a handshake only, 2 nothing measured, 3 measured and failed. */
    fun tier(t: Test?): Int = when {
        t == null -> 2
        (t.down ?: -1L) >= 0L -> 0
        (t.tcp ?: -1L) >= 0L -> 1
        t.down == null && t.tcp == null -> 2
        else -> 3
    }

    /** The figure a server is sorted on inside its tier (0 where the tier has none). */
    private fun figure(t: Test?): Long = when (tier(t)) {
        0 -> t?.down ?: 0L
        1 -> t?.tcp ?: 0L
        else -> 0L
    }

    /** The order above, as a comparator over servers by id; a stable sort keeps the list's order inside a tier. */
    fun byPing(tests: Map<String, Test>): Comparator<ServerConfig> =
        compareBy<ServerConfig>({ s: ServerConfig -> tier(tests[s.id]) }, { s: ServerConfig -> figure(tests[s.id]) })

    /** [servers] in that order. */
    fun sorted(servers: List<ServerConfig>, tests: Map<String, Test>): List<ServerConfig> = servers.sortedWith(byPing(tests))

    /**
     * The next config to try after [currentId] failed: every server but the
     * current one and the [tried] ones, those of the current server's own
     * subscription first (by hand = the other by-hand ones), each in the order
     * above — "never measured" starting after the current server and wrapping
     * round. Null when nothing is left.
     */
    fun pick(servers: List<ServerConfig>, currentId: String, tried: Set<String>, tests: Map<String, Test>): ServerConfig? {
        val at = servers.indexOfFirst { s: ServerConfig -> s.id == currentId }
        val current = if (at < 0) null else servers[at]
        val rotated = if (at < 0) servers else servers.subList(at + 1, servers.size) + servers.subList(0, at)
        val candidates = rotated.filter { s: ServerConfig -> s.id != currentId && s.id !in tried }
        if (candidates.isEmpty()) return null
        val (same, other) = candidates.partition { s: ServerConfig -> current != null && s.subId == current.subId }
        return (sorted(same, tests) + sorted(other, tests)).firstOrNull()
    }
}
