package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * A group's member that stays dead is taken out of the running config and the
 * app tests it instead (the desktop's src/main/groupEvict.js, v1.28.3).
 *
 * The core's own health check (the observatory) keeps probing a dead member
 * for as long as the core runs, and on both suggested cores a probe whose TLS
 * handshake fails leaves its socket and goroutines behind: against a member
 * that accepts and never answers, one established connection more per probe,
 * forever. So after [EVICT_AFTER_MS] of "dead" — while another member of its
 * group answers — the member is set aside: the core is reloaded without it,
 * and the app asks it itself through a throwaway core (which exits, and its
 * sockets with it): after [RETEST_MS], then twice as long after each miss (up
 * to [RETEST_MAX_MS]), so a member that stays dead costs ever less. It is put
 * back only after TWO answers in a row ([PASS_AGAIN_MS] apart): one lucky
 * answer from a member that is filtered on and off would otherwise cost a
 * reload — every connection — every few minutes. Reloads are at least
 * [RELOAD_GAP_MS] apart, and a reload that did not happen is asked for again
 * ([Evictor.reloadFailed]).
 *
 * A whole group dead at once (the line itself down) is no member's fault: no
 * dead streak runs while no member of the group answers, so the members do not
 * all go the moment the first one answers again.
 *
 * What is set aside outlives a reconnect of the same plan (a network change, a
 * wake from sleep) for [KEEP_MS]: the connect builds without it
 * ([Evictor.skip]) instead of probing it for 90 s more and reloading once again.
 *
 * Only members the app can test as the core dials them: not a group dialled
 * through a hop, not a chain variant (`direct = false` in the live map).
 *
 * On the phone a reload is a connect of the stored selection onto the live
 * tunnel (XrayVpnService — a switch, without a gap), and the core's health
 * check is read from its metrics listener every [TICK_MS], only while a group
 * runs. Pure apart from [readVars] (a loopback socket): the JVM tests run it.
 */
object GroupEvict {
    const val EVICT_AFTER_MS = 90_000L
    const val RETEST_MS = 3 * 60_000L
    const val RETEST_MAX_MS = 24 * 60_000L
    const val PASS_AGAIN_MS = 30_000L
    const val RELOAD_GAP_MS = 60_000L
    const val KEEP_MS = 30 * 60_000L

    /** How often the service reads the core's health check while a group runs (its observatory probes every 30 s here — ConfigBuilder). */
    const val TICK_MS = 30_000L

    /** At most this many set-aside members are tested in one tick, one at a time; the rest wait for the next. */
    const val TESTS_PER_TICK = 3

    /** The most of /debug/vars read: it carries the runtime's counters too, never this much. */
    private const val VARS_MAX_BYTES = 8 * 1024 * 1024

    /**
     * A member of a running group as ConfigBuilder.expandGroups names it — the
     * server it dials ([id], [name], [address], [port]; a chain variant by the
     * group member it takes) — and whether the app can test it as the core
     * dials it ([direct]). [alive] / [delay]: the core's verdict, once read
     * ([liveOf]); null = not probed yet.
     */
    data class Member(
        val id: String, val name: String, val address: String, val port: Int,
        val direct: Boolean = true, val alive: Boolean? = null, val delay: Long? = null
    ) {
        fun toJson(): JSONObject = JSONObject().put("id", id).put("name", name).put("address", address).put("port", port).put("direct", direct)
        companion object {
            fun fromJson(o: JSONObject): Member = Member(
                str(o, "id"), str(o, "name"), str(o, "address"), o.optInt("port", 0), o.optBoolean("direct", true))
        }
    }

    /** The server a group falls back to when no member answers (its `T~fb`), by id and name. */
    data class Fallback(val id: String, val name: String)

    /**
     * A group the config runs: its outbound tag T (member i is `T~gm<i>`), its
     * id and name, its strategy, whether it is dialled straight ([direct]),
     * and its own fallback (null: the first member is the balancer's).
     */
    data class Group(
        val tag: String, val groupId: String, val name: String, val strategy: String,
        val direct: Boolean, val members: List<Member>, val fallback: Fallback? = null
    ) {
        fun toJson(): JSONObject {
            val o = JSONObject().put("tag", tag).put("groupId", groupId).put("name", name)
                .put("strategy", strategy).put("direct", direct)
                .put("members", JSONArray().apply { members.forEach { m: Member -> put(m.toJson()) } })
            val fb = fallback
            if (fb != null) o.put("fallback", JSONObject().put("id", fb.id).put("name", fb.name))
            return o
        }
        companion object {
            fun fromJson(o: JSONObject): Group {
                val a = o.optJSONArray("members")
                val ms = ArrayList<Member>()
                if (a != null) for (i in 0 until a.length()) a.optJSONObject(i)?.let { m: JSONObject -> ms.add(Member.fromJson(m)) }
                val f = o.optJSONObject("fallback")
                val fb: Fallback? = if (f == null) null else Fallback(str(f, "id"), str(f, "name"))
                return Group(str(o, "tag"), str(o, "groupId"), str(o, "name"), str(o, "strategy"), o.optBoolean("direct", true), ms, fb)
            }
        }
    }

    /** The members set aside ([out]) and put back ([back]) since the last ask, by key ([Evictor.takeChanges]). */
    data class Changes(val out: List<String>, val back: List<String>)

    /** One log line and its level ("warn" | "info"), as the desktop sends them. */
    data class Line(val line: String, val level: String)

    /** A set-aside member whose test is due: its key, the record a test dials, how the log names it and its group. */
    class Due(val key: String, val record: ServerConfig, val label: String, val group: String)

    /** What is set aside, for a screen: its key, its group (id and name), how it is named, since and next test. */
    data class SetAside(val key: String, val groupId: String, val group: String, val label: String, val since: Long, val nextTest: Long)

    /** The core's verdict on one member: alive, and its delay when it is. */
    data class Health(val alive: Boolean, val delay: Long?)

    /** [o]'s [key] as text, "" when absent or a JSON null (Android's org.json hands back "null" for one). */
    private fun str(o: JSONObject, key: String): String = if (o.isNull(key)) "" else o.optString(key, "")

    /** A group member as the app names it to set it aside: its group, the server dialled and the address it dials (configBuilder.js groupMemberKey). */
    fun memberKey(groupId: String?, id: String?, address: String?, port: Int?): String =
        listOf(groupId ?: "", id ?: "", address ?: "", (port ?: 0).toString()).joinToString("|")

    fun memberKey(groupId: String?, m: Member): String = memberKey(groupId, m.id, m.address, m.port)

    /** Every group record a plan can dial: a single selection, a chain's hops, the targets of advanced routing and the pool. */
    fun groupRecordsOf(plan: ConnectionPlan?): List<ServerConfig> {
        if (plan == null) return emptyList()
        val out = ArrayList<ServerConfig>()
        fun add(r: ServerConfig?) { if (r != null && Groups.isGroupRecord(r) && out.none { x: ServerConfig -> x.id == r.id }) out.add(r) }
        when (plan) {
            is ConnectionPlan.Single -> add(plan.server)
            is ConnectionPlan.Chain -> plan.members.forEach { r: ServerConfig -> add(r) }
            is ConnectionPlan.Pool -> {
                plan.serversById.values.forEach { r: ServerConfig -> add(r) }
                plan.chainsById.values.forEach { l: List<ServerConfig> -> l.forEach { r: ServerConfig -> add(r) } }
            }
            is ConnectionPlan.Advanced -> {
                plan.serversById.values.forEach { r: ServerConfig -> add(r) }
                plan.chainsById.values.forEach { l: List<ServerConfig> -> l.forEach { r: ServerConfig -> add(r) } }
            }
        }
        return out
    }

    /** The live map as the service's Intent carries it. */
    fun mapToJson(map: List<Group>): String = JSONArray().apply { map.forEach { g: Group -> put(g.toJson()) } }.toString()

    /** ...and read back; nothing usable → empty. */
    fun mapFromJson(s: String?): List<Group> {
        if (s.isNullOrBlank()) return emptyList()
        return try {
            val a = JSONArray(s)
            (0 until a.length()).mapNotNull { i: Int -> a.optJSONObject(i) }.map { o: JSONObject -> Group.fromJson(o) }
        } catch (e: Exception) {
            emptyList()
        }
    }

    /**
     * What the core's health check (the observatory a group runs) says of each
     * member it probed, by outbound tag — a delay only for a live one (a dead
     * one reads 99999999). (stats.js healthOf)
     */
    fun healthOf(vars: JSONObject?): Map<String, Health> {
        val obs = vars?.optJSONObject("observatory") ?: return emptyMap()
        val res = LinkedHashMap<String, Health>()
        val keys = obs.keys()
        while (keys.hasNext()) {
            val tag = keys.next()
            val o = obs.optJSONObject(tag) ?: continue
            val alive = o.opt("alive") == true
            val d = o.opt("delay")
            val delay: Long? = if (alive && d is Number) d.toLong() else null
            res[tag] = Health(alive, delay)
        }
        return res
    }

    /** The running groups with the core's verdicts on their members — member i is `<tag>~gm<i>` (stats.js groupsLive, without the bytes). */
    fun liveOf(map: List<Group>, health: Map<String, Health>): List<Group> = map.map { g: Group ->
        g.copy(members = g.members.mapIndexed { i: Int, m: Member ->
            val h = health["${g.tag}~gm$i"]
            m.copy(alive = h?.alive, delay = h?.delay)
        })
    }

    /** The JSON body of an HTTP/1.x response to GET /debug/vars, or null: not a 200, or not JSON. */
    fun parseVars(raw: ByteArray): JSONObject? {
        val text = String(raw, Charsets.UTF_8)
        val end = text.indexOf("\r\n\r\n")
        if (end < 0) return null
        val status = text.substring(0, text.indexOf("\r\n").coerceAtLeast(0))
        if (!Regex("^HTTP/1\\.[01] 200\\b").containsMatchIn(status)) return null
        return try { JSONObject(text.substring(end + 4)) } catch (e: Exception) { null }
    }

    /**
     * GET /debug/vars from the core's metrics listener on 127.0.0.1:[port] —
     * a plain socket (Android refuses cleartext HTTP through its URL stack),
     * HTTP/1.0 so the answer is never chunked. Bounded in time ([timeoutMs] in
     * all, a dripping answer included) and size. Blocking; null on any failure.
     */
    fun readVars(port: Int, timeoutMs: Int = 3000): JSONObject? {
        if (port <= 0 || port > 65535) return null
        val deadline = System.currentTimeMillis() + timeoutMs
        return try {
            Socket().use { s: Socket ->
                s.connect(InetSocketAddress("127.0.0.1", port), timeoutMs)
                s.soTimeout = timeoutMs
                s.getOutputStream().write("GET /debug/vars HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                s.getOutputStream().flush()
                val input = s.getInputStream()
                val buf = ByteArray(16 * 1024)
                val out = ByteArrayOutputStream()
                while (true) {
                    if (System.currentTimeMillis() > deadline) return null
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    if (out.size() > VARS_MAX_BYTES) return null
                }
                parseVars(out.toByteArray())
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun who(m: Member): String =
        m.name.ifEmpty { m.id.ifEmpty { "a member" } } + (if (m.address.isNotEmpty()) " (${m.address}${if (m.port != 0) ":${m.port}" else ""})" else "")

    private fun mins(ms: Long): String = if (ms % 60_000L == 0L) "${ms / 60_000L} min" else "${Math.round(ms / 1000.0)} s"

    /**
     *   reset(plan)        at connect: the plan's group members, by key; what is set
     *                      aside and still in this plan, kept (KEEP_MS); the rest forgotten
     *   update(groups)     each tick → log lines; marks a reload when one goes
     *   due()              the set-aside members whose test is due
     *   tested(key, ok, ms) → log lines; a member that answered twice is back (a reload)
     *   wantsReload()      is a reload asked for?
     *   takeReload()       a reload wanted and allowed now? (then it is taken)
     *   reloadFailed()     the reload taken did not happen: ask for it again
     *   skip()             the keys the next config leaves out (ConfigBuilder's groupSkip)
     *   takeChanges()      the members set aside / put back since the last ask
     *                      (the desktop does them in the running core, groupLive.js)
     *   liveApplied()      they were done there: no reload is needed for them
     *   list()             what is set aside
     *
     * The phone has no way into its running core (no `xray api` CLI beside the
     * in-process core): every change is a reload there, and takeChanges() only
     * drains what the desktop would have done live.
     *
     * Process-wide on the phone (the connect's prepare reads skip(), the
     * service's tick feeds it), so every call takes the instance's lock.
     */
    class Evictor(
        private val now: () -> Long = { System.currentTimeMillis() },
        private val evictAfter: Long = EVICT_AFTER_MS,
        private val retest: Long = RETEST_MS,
        private val retestMax: Long = RETEST_MAX_MS,
        private val passAgain: Long = PASS_AGAIN_MS,
        private val reloadGap: Long = RELOAD_GAP_MS,
        private val keep: Long = KEEP_MS
    ) {
        private class Out(
            val groupId: String, val group: String, val label: String, val since: Long,
            var nextTest: Long, var misses: Int, var passes: Int, var touched: Long
        )

        /** key → the member's record (what a test dials) */
        private var records: Map<String, ServerConfig> = emptyMap()
        private val deadSince = HashMap<String, Long>()
        private val out = LinkedHashMap<String, Out>()
        private var wantReload = false
        private var lastReload = 0L
        private val changedOut = ArrayList<String>()
        private val changedBack = ArrayList<String>()

        /**
         * [reload]: a reload of the app's own — on the phone a connect like any
         * other — keeps counting the gap since the last one ([reloadGap]).
         */
        @Synchronized fun reset(plan: ConnectionPlan?, reload: Boolean = false) {
            val t = now()
            val recs = LinkedHashMap<String, ServerConfig>()
            for (g in groupRecordsOf(plan)) {
                val mark = g.outbound.optJSONObject(Groups.MARK) ?: continue
                val gid = if (mark.isNull("id")) "" else mark.optString("id", "")
                for (m in Groups.membersOf(mark)) recs[memberKey(gid, m.id, m.address, m.port)] = m
            }
            records = recs
            // set aside lately, and a member of this plan still: it stays out (the connect built without it)
            val iter = out.entries.iterator()
            while (iter.hasNext()) {
                val e = iter.next()
                if (!recs.containsKey(e.key) || t - e.value.touched > keep) iter.remove()
            }
            deadSince.clear()
            wantReload = false
            if (!reload) lastReload = 0L
            changedOut.clear()
            changedBack.clear()
        }

        @Synchronized fun skip(): List<String> = out.keys.toList()

        @Synchronized fun list(): List<SetAside> {
            val res = ArrayList<SetAside>()
            for ((key, e) in out) res.add(SetAside(key, e.groupId, e.group, e.label, e.since, e.nextTest))
            return res
        }

        @Synchronized fun update(groups: List<Group>): List<Line> {
            val t = now()
            val lines = ArrayList<Line>()
            val seen = HashSet<String>()
            for (g in groups) {
                if (!g.direct) continue
                val alive = g.members.count { m: Member -> m.alive == true }
                for (m in g.members) {
                    if (!m.direct) continue
                    val key = memberKey(g.groupId, m)
                    seen.add(key)
                    // already set aside, still in the running config until the reload: once is enough;
                    // and nobody in the group answering is the line, not this member: no streak runs
                    if (m.alive != false || out.containsKey(key) || alive == 0) { deadSince.remove(key); continue }
                    val since = deadSince.getOrPut(key) { t }
                    // only one the app can test
                    if (!records.containsKey(key) || t - since < evictAfter) continue
                    deadSince.remove(key)
                    val group = g.name.ifEmpty { g.groupId }
                    out[key] = Out(g.groupId, group, who(m), t, t + retest, 0, 0, t)
                    wantReload = true
                    changedOut.add(key)
                    lines.add(Line("Group $group: ${who(m)} has not answered for ${mins(evictAfter)} — taken out of the running config (the core's own check would keep knocking on it); tested again in ${mins(retest)}", "warn"))
                }
            }
            // a member no longer in any running group (a reload left it out, the plan changed) has no dead streak
            deadSince.keys.retainAll(seen)
            return lines
        }

        @Synchronized fun due(): List<Due> {
            val t = now()
            val res = ArrayList<Due>()
            for ((key, e) in out) {
                val rec = records[key] ?: continue
                if (e.nextTest <= t) res.add(Due(key, rec, e.label, e.group))
            }
            return res
        }

        @Synchronized fun tested(key: String, ok: Boolean, ms: Long?): List<Line> {
            val e = out[key] ?: return emptyList()
            val t = now()
            e.touched = t
            if (!ok) {
                // each miss doubles the wait, up to the cap
                e.misses += 1
                e.passes = 0
                val wait = retest * (1L shl e.misses.coerceAtMost(30))
                e.nextTest = t + minOf(retestMax, wait)
                return emptyList()
            }
            if (e.passes < 1) {
                // one answer is not yet a member back: once more, shortly
                e.passes = 1
                e.nextTest = t + passAgain
                return emptyList()
            }
            out.remove(key)
            wantReload = true
            changedBack.add(key)
            return listOf(Line("Group ${e.group}: ${e.label} answers again${if (ms != null) " ($ms ms)" else ""} — back in the running config", "info"))
        }

        @Synchronized fun wantsReload(): Boolean = wantReload

        @Synchronized fun takeChanges(): Changes {
            val c = Changes(changedOut.toList(), changedBack.toList())
            changedOut.clear()
            changedBack.clear()
            return c
        }

        @Synchronized fun liveApplied() { wantReload = false }

        @Synchronized fun takeReload(): Boolean {
            val t = now()
            if (!wantReload || (lastReload != 0L && t - lastReload < reloadGap)) return false
            wantReload = false
            lastReload = t
            return true
        }

        @Synchronized fun reloadFailed() { wantReload = true }
    }
}
