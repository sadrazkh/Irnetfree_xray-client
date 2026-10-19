package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import java.security.SecureRandom

/**
 * Groups (v1.27.0, the desktop's src/main/groups.js): several saved servers
 * used together as one config. Each new connection goes out through one
 * member — round-robin by default — and a member that stops answering is left
 * out until it answers again (Xray's balancer and observatory, written by
 * ConfigBuilder.expandGroups). A group is used wherever a server is: selected,
 * a routing target, a routing profile's base, a pool entry, any hop of a chain.
 *
 * Stored under `groups` ([GroupConfig]):
 *   { id: 'grp-…', name, strategy: 'roundRobin' | 'leastPing' | 'random',
 *     members: [{ id: '<serverId>', address?: '<ip or host>', port?: <n> }] }
 * A member is a server, dialled as it is or at an address of its own (a clean
 * CDN IP — AddressSwap.withTarget keeps its SNI and Host on the original name).
 *
 * The plan carries a group as a RECORD beside the servers ([groupRecord]): a
 * ServerConfig whose outbound is a `loopback` marked `_group` with its member
 * records, which ConfigBuilder expands at the end into the members, the
 * balancer, its routing rule and the health check.
 *
 * Pure: Store keeps the list, the JVM tests run it.
 */
object Groups {
    const val ROUND_ROBIN = "roundRobin"
    const val LEAST_PING = "leastPing"
    const val RANDOM = "random"
    val STRATEGIES: List<String> = listOf(ROUND_ROBIN, LEAST_PING, RANDOM)
    const val DEFAULT_STRATEGY = ROUND_ROBIN
    /** The store key (SharedPreferences "irnetfree"). */
    const val STORE_KEY = "groups"
    /** The marker on a group record's loopback outbound (configBuilder.js reads `_group`). */
    const val MARK = "_group"
    /** A group record's protocol. */
    const val PROTOCOL = "group"

    private val ID = Regex("^grp-[\\w-]+$")
    private val rng = SecureRandom()

    /** [o]'s [key] as trimmed text, "" when absent or a JSON null (Android's org.json hands back "null" for one). */
    private fun str(o: JSONObject, key: String): String = if (o.isNull(key)) "" else o.opt(key).toString().trim()

    /** A new group id: `grp-<base36 time><4 hex>`. */
    fun newGroupId(now: () -> Long = { System.currentTimeMillis() }): String {
        val b = ByteArray(2)
        rng.nextBytes(b)
        return "grp-" + now().toString(36) + b.joinToString("") { x: Byte -> "%02x".format(x.toInt() and 0xFF) }
    }

    /** Is this id a group's? */
    fun isGroupId(id: String?): Boolean = id != null && ID.matches(id)

    /** A member as stored: `{ id, address?, port? }`; null when it names no server (a group never is one). */
    fun normalizeMember(m: Any?): GroupMember? {
        val src: JSONObject = when (m) {
            is String -> JSONObject().put("id", m)
            is GroupMember -> m.toJson()
            is JSONObject -> m
            else -> return null
        }
        val id = str(src, "id")
        if (id.isEmpty() || isGroupId(id)) return null
        val address = str(src, "address").replace(Regex("^\\[(.*)\\]$"), "$1")
        val keepAddress = address.isNotEmpty() && !Regex("[\\s/@]").containsMatchIn(address)
        val port = AddressSwap.toPort(if (src.isNull("port")) null else src.opt("port"))
        return GroupMember(id, if (keepAddress) address else null, port)
    }

    /** A group with only its own fields, each of its type; an id that is not `grp-…` a new one; not an object → null. */
    fun normalizeGroup(g: Any?, now: () -> Long = { System.currentTimeMillis() }): GroupConfig? {
        val src: JSONObject = when (g) {
            is GroupConfig -> g.toJson()
            is JSONObject -> g
            else -> return null
        }
        val st = src.opt("strategy")
        val strategy = if (st is String && st in STRATEGIES) st else DEFAULT_STRATEGY
        val rawId = src.opt("id")
        val id = if (rawId is String && isGroupId(rawId)) rawId else newGroupId(now)
        val list = src.optJSONArray("members")
        val members = ArrayList<GroupMember>()
        if (list != null) for (i in 0 until list.length()) normalizeMember(list.opt(i))?.let { x: GroupMember -> members.add(x) }
        return GroupConfig(id, str(src, "name").ifEmpty { "Group" }, strategy, members)
    }

    /** The list as it is saved: each normalized, a repeated id dropped. [list]: a JSONArray or a List. */
    fun normalizeGroups(list: Any?, now: () -> Long = { System.currentTimeMillis() }): List<GroupConfig> {
        val items: List<Any?> = when (list) {
            is JSONArray -> (0 until list.length()).map { i: Int -> list.opt(i) }
            is List<*> -> list
            else -> emptyList()
        }
        val seen = HashSet<String>()
        val out = ArrayList<GroupConfig>()
        for (g in items) {
            val n = normalizeGroup(g, now) ?: continue
            if (!seen.add(n.id)) continue
            out.add(n)
        }
        return out
    }

    /** A member's server record: the saved server, or a copy dialling the member's own address (its id kept). */
    private fun memberRecord(server: ServerConfig, m: GroupMember): ServerConfig? {
        if (m.address == null && m.port == null) return server
        return try {
            AddressSwap.withTarget(server, m.address, m.port)
        } catch (e: IllegalArgumentException) {
            null   // a shape that cannot take another address: left out, as a server that is gone
        }
    }

    /**
     * The record a group is in a plan — null when none of its members is left:
     * a ServerConfig { id, name, protocol "group", address "", port 0 } whose
     * outbound is `{ protocol: loopback, settings: {}, _group: { strategy,
     * members: [server records] } }`. [serversById]: the saved servers (never
     * other groups — a group never holds a group).
     */
    fun groupRecord(group: GroupConfig, serversById: Map<String, ServerConfig>): ServerConfig? {
        val g = normalizeGroup(group) ?: return null
        val members = ArrayList<ServerConfig>()
        for (m in g.members) {
            val s = serversById[m.id] ?: continue
            if (s.outbound.length() == 0 || s.protocol == PROTOCOL || isGroupRecord(s)) continue
            val rec = memberRecord(s, m) ?: continue
            members.add(rec)
        }
        if (members.isEmpty()) return null
        // copies: the record shares nothing with the stored servers
        val arr = JSONArray()
        for (rec in members) arr.put(JSONObject(rec.toJson().toString()))
        val outbound = JSONObject().put("protocol", "loopback").put("settings", JSONObject())
            .put(MARK, JSONObject().put("strategy", g.strategy).put("members", arr))
        return ServerConfig(id = g.id, name = g.name, protocol = PROTOCOL, address = "", port = 0, outbound = outbound)
    }

    /** Every group as a record, keyed by id (one with no member left is not there) — what a plan's serversById takes beside the servers. */
    fun groupRecordsById(groups: List<GroupConfig>, serversById: Map<String, ServerConfig>): Map<String, ServerConfig> {
        val out = LinkedHashMap<String, ServerConfig>()
        for (g in groups) {
            val rec = groupRecord(g, serversById) ?: continue
            out[rec.id] = rec
        }
        return out
    }

    /** Is this record a group's ([groupRecord])? */
    fun isGroupRecord(s: ServerConfig?): Boolean =
        s != null && s.outbound.optString("protocol") == "loopback" && s.outbound.optJSONObject(MARK) != null

    /** The member records a `_group` marker carries. */
    fun membersOf(mark: JSONObject?): List<ServerConfig> {
        val a = mark?.optJSONArray("members") ?: return emptyList()
        val out = ArrayList<ServerConfig>()
        for (i in 0 until a.length()) {
            val o = a.optJSONObject(i) ?: continue
            val s = ServerConfig.fromJson(o)
            if (s.outbound.length() > 0) out.add(s)
        }
        return out
    }

    /**
     * One member a `_group` marker carries, as ConfigBuilder.expandGroups
     * reads it: a server ([server]), or a whole chain ([chain]) — a chain
     * through a group becomes a group of chains (ConfigBuilder.groupOfChains),
     * one variant per member in the group's place.
     */
    class Member(val server: ServerConfig?, val chain: List<ServerConfig>?)

    /** Every member a `_group` marker carries — servers and chain variants — in order; nothing else. */
    fun entriesOf(mark: JSONObject?): List<Member> {
        val a = mark?.optJSONArray("members") ?: return emptyList()
        val out = ArrayList<Member>()
        for (i in 0 until a.length()) {
            val o = a.optJSONObject(i) ?: continue
            val c = o.optJSONArray("chain")
            if (c != null) {
                val hops = ArrayList<ServerConfig>()
                for (j in 0 until c.length()) {
                    val h = c.optJSONObject(j) ?: continue
                    hops.add(ServerConfig.fromJson(h))
                }
                out.add(Member(null, hops))
                continue
            }
            val s = ServerConfig.fromJson(o)
            if (s.outbound.length() > 0) out.add(Member(s, null))
        }
        return out
    }

    /** The strategy a `_group` marker names; anything else is round-robin. */
    fun strategyOf(mark: JSONObject?): String {
        val st = mark?.opt("strategy")
        return if (st is String && st in STRATEGIES) st else DEFAULT_STRATEGY
    }

    /** The servers a record stands for: a group's members, else the record itself. */
    fun serversOf(s: ServerConfig?): List<ServerConfig> {
        if (s == null) return emptyList()
        return if (isGroupRecord(s)) membersOf(s.outbound.optJSONObject(MARK)) else listOf(s)
    }

    /** How many members a group record carries (0 for anything else). */
    fun sizeOf(s: ServerConfig?): Int {
        if (s == null || !isGroupRecord(s)) return 0
        return s.outbound.optJSONObject(MARK)?.optJSONArray("members")?.length() ?: 0
    }

    /* ----------------------------- for the editor ----------------------------- */

    /** The strategy in words, for a card. */
    fun strategyLabel(strategy: String): String = when (strategy) {
        LEAST_PING -> "Fastest"
        RANDOM -> "Random"
        else -> "Round-robin"
    }

    /** What the strategy does, one line, for the editor. */
    fun strategyHelp(strategy: String): String = when (strategy) {
        LEAST_PING -> "all through the lowest-latency live member, the rest as spares"
        RANDOM -> "every new connection through a live member picked at random"
        else -> "every new connection through the next live member — more total speed"
    }

    /** What "+ clean IPs" made of the pasted text: one address per good line, and the numbers (from 1) of the bad ones. */
    data class CleanIps(val targets: List<Pair<String, Int?>>, val bad: List<Int>)

    /**
     * The pasted list of "+ clean IPs": one per line — `ip`, `ip:port`,
     * `[v6]:port`, a bare v6, or a host name — blank lines skipped. A line
     * that is none of those, or names a port outside 1–65535, is reported by
     * its number and left out.
     */
    fun parseCleanIps(text: String): CleanIps {
        val out = ArrayList<Pair<String, Int?>>()
        val bad = ArrayList<Int>()
        text.split('\n').forEachIndexed { i: Int, raw: String ->
            val line = raw.trim()
            if (line.isEmpty()) return@forEachIndexed
            val t = cleanTarget(line)
            if (t == null) bad.add(i + 1) else out.add(t)
        }
        return CleanIps(out, bad)
    }

    /**
     * Why "+ clean IPs" cannot add [r] for [server] — no server picked, a bad
     * line (by number), nothing pasted, or a config that cannot be dialled at
     * another address (AddressSwap) — or null: it can.
     */
    fun cleanIpProblem(server: ServerConfig?, r: CleanIps): String? {
        if (server == null) return "Pick the server these addresses are for"
        if (r.bad.isNotEmpty()) return (if (r.bad.size == 1) "Line " else "Lines ") + r.bad.joinToString(", ") + ": not an address — one per line: ip, ip:port or [v6]:port"
        if (r.targets.isEmpty()) return "Paste at least one address"
        val first = r.targets.first()
        return try {
            AddressSwap.withTarget(server, first.first, first.second)
            null
        } catch (e: IllegalArgumentException) {
            "${server.name} can't be dialled at another address (${e.message})"
        }
    }

    /** A member's own address in words: "104.16.1.1:2053", "port 2053", or "" when it dials the server's own. */
    fun memberAddress(m: GroupMember): String {
        val a = m.address
        val p = m.port
        return when {
            a != null -> AddressSwap.addrPort(a, p)
            p != null -> "port $p"
            else -> ""
        }
    }

    private val HOST = Regex("^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$")

    /** One line of "+ clean IPs" as an address and a port (null = the server's own), or null when it is neither. */
    private fun cleanTarget(line: String): Pair<String, Int?>? {
        val v6 = Regex("^\\[([0-9A-Fa-f:.]+)\\](?::(\\d+))?$").find(line)
        if (v6 != null) {
            val host = v6.groupValues[1]
            if (!DnsPlan.isIpv6(host)) return null
            val p = v6.groupValues[2]
            if (p.isEmpty()) return Pair(host, null)
            val port = AddressSwap.toPort(p) ?: return null
            return Pair(host, port)
        }
        if (DnsPlan.isIpv6(line)) return Pair(line, null)
        val colon = line.lastIndexOf(':')
        val host = if (colon == -1) line else line.substring(0, colon)
        var port: Int? = null
        if (colon != -1) {
            val p = line.substring(colon + 1)
            if (!Regex("^\\d+$").matches(p)) return null
            port = AddressSwap.toPort(p) ?: return null
        }
        if (host.isEmpty() || host.contains(':')) return null
        if (DnsPlan.isIpv4(host)) return Pair(host, port)
        // four dotted numbers that are not an address (999.1.1.1) are a typo, not a host name
        if (Regex("^[\\d.]+$").matches(host)) return null
        return if (HOST.matches(host)) Pair(host, port) else null
    }
}
