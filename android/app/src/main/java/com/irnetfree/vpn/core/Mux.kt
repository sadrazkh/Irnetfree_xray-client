package com.irnetfree.vpn.core

import org.json.JSONObject
import java.security.MessageDigest

/**
 * Xray's mux, decided per server by a test — spec §4 of
 * docs/superpowers/specs/2026-10-05-v1180-final-design.md, the same rules as the
 * desktop's and the router's src/main/mux.js.
 *
 * Why: every connection an app opens through a WebSocket/HTTPUpgrade server is
 * its own TLS (+ECH) + WS handshake. On the owner's line one took 0.6–3.7 s,
 * and with mux the same server answered each new connection in about 150 ms,
 * over a handful of real connections — fewer handshakes, less CPU and battery.
 * Not every server accepts it, so in Settings → Mux "auto" a
 * server is tested once before the connect that needs it, and the verdict is
 * kept: "ok" for 7 days, "unsupported" for 1 — per server FINGERPRINT, so an
 * edited server, or a subscription refresh with new parameters, is tested
 * again. "on" muxes every eligible server untested; "off" — the default, the
 * owner's choice — writes the configs of before, byte for byte.
 *
 * After the review (the same rules as the desktop's): a test without a clear
 * answer on a line that works (mux ran out of time, the control answered)
 * never replaces a verdict — it keeps the one there was (expired, or marked
 * for a recheck) and is not repeated for an hour (`retryAfter`); with none,
 * it is kept as an unknown for that hour. A test where nothing answered at
 * all (the phone offline, the server down) keeps nothing: the next connect
 * tests again. A muxed connection that drops
 * keeps its servers' ok, marked `recheck`: the user's (or the boot's) next
 * connect tests them again; a reconnect of the service's own never tests — it
 * uses what is kept, a recheck counting as ok.
 *
 * Everything here is pure — the cores, the store and the log are handed in —
 * so the rules are tested off a device (MuxTest). The real test runs through
 * XrayTester.probeMux; the connect path is XrayVpnService.prepare.
 */
object Mux {
    /** Settings → Mux. */
    const val AUTO = "auto"
    const val ON = "on"
    const val OFF = "off"

    /**
     * A test's verdict: mux carried both requests / mux definitively failed
     * and the control without it answered / mux ran out of time while the
     * control answered — the line works, mux was only slow: kept as unknown,
     * never replacing a verdict, retried in an hour ([record]). [OK] is also
     * the mux attempt's outcome when it worked.
     */
    const val OK = "ok"
    const val UNSUPPORTED = "unsupported"
    const val UNKNOWN = "unknown"

    /**
     * A test that learnt nothing: the control did not answer either (the
     * phone offline, the server down), or the test was cut short. Nothing is
     * kept — no retry, any verdict untouched — so the next connect that may
     * test, tests again.
     */
    const val UNREACHABLE = "unreachable"

    /**
     * The mux attempt's other outcomes: it did not answer before its time ran
     * out (or the budget did) — a slow moment, which says nothing — or it
     * definitively failed: refused, reset or closed before its time, or its
     * test core could not start.
     */
    const val TIMEOUT = "timeout"
    const val FAILED = "failed"

    const val DAY_MS: Long = 24L * 3600 * 1000
    /** How long a verdict holds. */
    const val OK_TTL_MS: Long = 7 * DAY_MS
    const val UNSUPPORTED_TTL_MS: Long = 1 * DAY_MS
    /** After a test without a clear answer, the server is not tested again for this long. */
    const val RETRY_MS: Long = 3600L * 1000

    /** One server's whole test, from the first core started to the last one stopped. */
    const val PROBE_BUDGET_MS: Long = 8_000
    /** The most one request is given: a server that does not answer holds the connect up 5 s, not the whole budget. */
    const val REQUEST_MS: Long = 5_000
    /** A request that failed this close to the end of its time ran out of it: a timeout, not a refusal. */
    const val TIMEOUT_SLACK_MS: Long = 150
    /** Less left than this and no further core is started. */
    const val MIN_START_MS: Long = 1_500
    /** Less left than this and no further request is made. */
    const val MIN_REQUEST_MS: Long = 500

    /** The stored verdicts are capped at this many, the oldest dropped first. */
    const val MAX_PROBES = 500

    /**
     * The mux object an eligible outbound gets. UDP to port 443 (QUIC) keeps
     * its own way. A fresh copy every time it is read: an outbound owns the one
     * it is given.
     */
    val MUX: JSONObject
        get() = JSONObject().put("enabled", true).put("concurrency", 8).put("xudpConcurrency", 16).put("xudpProxyUDP443", "skip")

    /**
     * Settings → Mux when nothing (or nothing readable) is stored: off — the
     * owner's choice (he has run mux on no client yet); Auto and On are a tap
     * away in Settings.
     */
    const val DEFAULT_MODE = OFF

    /** Settings → Mux as stored: "auto" and "on" as they are, anything else [DEFAULT_MODE] (off). */
    fun modeOf(raw: String?): String = when (raw?.trim()?.lowercase()) {
        AUTO -> AUTO
        ON -> ON
        else -> DEFAULT_MODE
    }

    /**
     * May this outbound carry mux? VLESS without a `flow`, VMess and Trojan,
     * over `ws` (or `websocket`, the core's other name for it) or
     * `httpupgrade`. gRPC, XHTTP and H2 multiplex already; Vision, REALITY on
     * raw, mKCP, Hysteria, WireGuard and Shadowsocks are never touched.
     */
    fun eligible(outbound: JSONObject?): Boolean {
        if (outbound == null) return false
        val network = str(outbound.optJSONObject("streamSettings"), "network").lowercase()
        if (network != "ws" && network != "websocket" && network != "httpupgrade") return false
        return when (str(outbound, "protocol").lowercase()) {
            "vmess", "trojan" -> true
            "vless" -> noFlow(outbound.optJSONObject("settings"))
            else -> false
        }
    }

    /** No user of this VLESS outbound names a flow — in `vnext`, or in the flat form's own settings. */
    private fun noFlow(settings: JSONObject?): Boolean {
        if (settings == null) return true
        if (str(settings, "flow").isNotEmpty()) return false
        val vnext = settings.optJSONArray("vnext") ?: return true
        for (i in 0 until vnext.length()) {
            val users = vnext.optJSONObject(i)?.optJSONArray("users") ?: continue
            for (j in 0 until users.length()) if (str(users.optJSONObject(j), "flow").isNotEmpty()) return false
        }
        return true
    }

    /**
     * What a server is recognised by from one connect to the next: a hash of
     * its protocol, address, port, id/password, network, the ws/httpupgrade
     * path and host, security and SNI — what decides whether mux works, and
     * nothing else (not the name, not the record's id: a subscription refresh
     * that hands out new ids keeps a server's verdict).
     */
    fun fingerprint(server: ServerConfig): String {
        val o = server.outbound
        val settings = o.optJSONObject("settings")
        // the server entry: vnext[0] (VLESS, VMess), servers[0] (Trojan), else the flat form
        val entry = settings?.optJSONArray("vnext")?.optJSONObject(0) ?: settings?.optJSONArray("servers")?.optJSONObject(0) ?: settings
        val user = entry?.optJSONArray("users")?.optJSONObject(0)
        val address = str(entry, "address").ifEmpty { server.address }
        val port = (entry?.optInt("port", 0) ?: 0).takeIf { p: Int -> p > 0 } ?: server.port
        val credential = str(user, "id").ifEmpty { str(entry, "password") }.ifEmpty { str(entry, "id") }
        val ss = o.optJSONObject("streamSettings")
        val network = str(ss, "network").lowercase()
        val path: String
        val host: String
        when (network) {
            "ws", "websocket" -> {
                val w = ss?.optJSONObject("wsSettings")
                path = str(w, "path")
                host = str(w?.optJSONObject("headers"), "Host").ifEmpty { str(w, "host") }
            }
            "httpupgrade" -> {
                val h = ss?.optJSONObject("httpupgradeSettings")
                path = str(h, "path")
                host = str(h, "host")
            }
            else -> { path = ""; host = "" }
        }
        val security = str(ss, "security").lowercase()
        val sni = str(ss?.optJSONObject("tlsSettings"), "serverName").ifEmpty { str(ss?.optJSONObject("realitySettings"), "serverName") }
        val protocol = str(o, "protocol").lowercase().ifEmpty { server.protocol.lowercase() }
        val fields = listOf(protocol, address.lowercase(), port.toString(), credential, network, path, host.lowercase(), security, sni.lowercase())
        // length-prefixed, so no two different field lists ever read the same
        val text = fields.joinToString("") { f: String -> "${f.length}:$f;" }
        val digest = MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
        return digest.take(16).joinToString("") { b: Byte -> "%02x".format(b.toInt() and 0xFF) }
    }

    /**
     * What is kept about a server, stored as {ok, at, recheck?, retryAfter?}:
     * [ok] true / false — the verdict "ok" / "unsupported", reached at [at]
     * (epoch ms) — or null: no verdict, only a test without a clear answer at
     * [at]. [recheck]: a muxed connection through it dropped since — still ok,
     * to be tested again by the next connect that may test. [retryAfter]: a
     * test without a clear answer was made; none again before this.
     */
    data class Probe(val ok: Boolean?, val at: Long, val recheck: Boolean = false, val retryAfter: Long = 0L)

    /** "ok" / "unsupported" while [entry]'s verdict still holds by its age (7 days / 1 day), else null. */
    fun freshVerdict(entry: Probe?, now: Long): String? {
        if (entry == null || entry.ok == null || entry.at <= 0L) return null
        val age = now - entry.at
        if (age < 0L) return null              // stamped by a clock that has since gone back
        return if (entry.ok) (if (age < OK_TTL_MS) OK else null) else (if (age < UNSUPPORTED_TTL_MS) UNSUPPORTED else null)
    }

    /**
     * Mux on without a test now: an ok within its 7 days (marked for a recheck
     * or not), or an ok a test without a clear answer kept, before its retry.
     */
    private fun usable(e: Probe?, now: Long): Boolean =
        e != null && e.ok == true && (freshVerdict(e, now) == OK || e.retryAfter > now)

    /**
     * Tested by a connect that may test (the user's, the boot's): nothing
     * known, a verdict past its age, or an ok marked for a recheck — never
     * before its retryAfter.
     */
    private fun needsTest(e: Probe?, now: Long): Boolean {
        if (e == null) return true
        if (e.retryAfter > now) return false
        return freshVerdict(e, now) == null || e.recheck
    }

    /**
     * What a connect does: the server ids that get mux with no further test,
     * and the servers a connect that may test should test first (a server may
     * be in both: an ok marked for a recheck stays on until its test says
     * otherwise).
     */
    data class Plan(val muxIds: Set<String>, val toProbe: List<ServerConfig>)

    /**
     * off → nothing. on → every eligible id, no test. auto → the ids that may
     * have mux without a test (usable), and the eligible servers to test (one
     * per fingerprint): nothing known, past its age, or marked for a recheck,
     * and not before its retryAfter. [recovery]: a reconnect of the service's
     * own — never a test; the kept verdict whatever its age, a recheck as ok.
     */
    fun plan(mode: String, servers: List<ServerConfig>, cache: Map<String, Probe>, now: Long, recovery: Boolean = false): Plan {
        val m = modeOf(mode)
        if (m == OFF) return Plan(emptySet(), emptyList())
        val ids = LinkedHashSet<String>()
        val toProbe = ArrayList<ServerConfig>()
        val queued = HashSet<String>()
        for (s in servers) {
            if (!eligible(s.outbound)) continue
            if (m == ON) { ids.add(s.id); continue }
            val fp = fingerprint(s)
            val e = cache[fp]
            if (recovery) {
                if (e?.ok == true) ids.add(s.id)
                continue
            }
            if (usable(e, now)) ids.add(s.id)
            if (needsTest(e, now) && queued.add(fp)) toProbe.add(s)
        }
        return Plan(ids, toProbe)
    }

    /**
     * What a test's [verdict] leaves kept for a server whose entry was
     * [previous]: "ok" / "unsupported" replace it (no recheck, no retry); an
     * unknown (mux out of time on a line that works) never does — it keeps the
     * verdict there was (past its age, or marked for a recheck, included) and
     * stamps a retry an hour on; with no verdict, it is kept as an unknown with
     * that retry. "unreachable" learnt nothing: [previous] as it was (null
     * stays null) — the caller writes nothing.
     */
    fun record(previous: Probe?, verdict: String, now: Long): Probe? = when (verdict) {
        OK -> Probe(true, now)
        UNSUPPORTED -> Probe(false, now)
        UNKNOWN -> if (previous != null && previous.ok != null) previous.copy(retryAfter = now + RETRY_MS) else Probe(null, now, retryAfter = now + RETRY_MS)
        else -> previous
    }

    /** A muxed connection dropped: the ok verdicts of its servers ([fingerprints]) are kept, marked for a recheck. */
    fun markRecheck(probes: Map<String, Probe>, fingerprints: Collection<String>): Map<String, Probe> {
        val out = HashMap(probes)
        for (fp in fingerprints) {
            val e = out[fp] ?: continue
            if (e.ok == true && !e.recheck) out[fp] = e.copy(recheck = true)
        }
        return out
    }

    /**
     * The test's verdict, from the mux attempt's outcome — [OK] | [TIMEOUT] |
     * [FAILED] — and the control's (null = not run): mux ok → "ok"; the
     * control did not answer (or never ran) → "unreachable", nothing learnt;
     * mux failed and the control answered → "unsupported"; mux ran out of time
     * and the control answered → "unknown" — the line works, mux was only slow.
     */
    fun verdict(mux: String, plainOk: Boolean?): String = when {
        mux == OK -> OK
        plainOk != true -> UNREACHABLE
        mux == FAILED -> UNSUPPORTED
        else -> UNKNOWN
    }

    /**
     * The test (spec §4), with the cores handed in: a throwaway core whose
     * proxy outbound carries [MUX] ([start] true) makes two requests, one after
     * the other — both must answer. That attempt is [OK]; a [TIMEOUT] when a
     * request did not answer before its time ran out, or the budget did; or
     * [FAILED] when a request failed before its time (refused, reset, closed)
     * or the core could not start. After a TIMEOUT or a FAILED, one request
     * goes through a core without mux ([start] false), the control: it tells a
     * server that refuses mux ("unsupported", only after a FAILED) and a line
     * that works while mux was only slow ("unknown", after a TIMEOUT — a slow
     * moment is not a refusal: the router's field case had been remembered as
     * "unsupported" for three days) from nothing reachable at all
     * ("unreachable": the phone offline, the server down — nothing is kept).
     *
     * Every core started is stopped, and the whole test stays within
     * [budgetMs]: each request gets at most what is left ([REQUEST_MS] at the
     * most), and nothing more is started once too little is. [request] makes
     * one request through a core within the ms it is given: its round trip, or
     * a negative number when it did not answer. [wanted]: false once the
     * connect this is for has been overtaken — nothing more starts, and nothing
     * was learnt: "unreachable".
     */
    fun <H : Any> probe(
        start: (Boolean) -> H?,
        request: (H, Int) -> Long,
        stop: (H) -> Unit,
        now: () -> Long,
        wanted: () -> Boolean = { true },
        budgetMs: Long = PROBE_BUDGET_MS
    ): String {
        val deadline = now() + budgetMs
        // One core, with mux or without, asked [times] requests that must all
        // answer: OK, TIMEOUT or FAILED as above; null when the connect was overtaken.
        fun attempt(mux: Boolean, times: Int): String? {
            if (!wanted()) return null
            if (deadline - now() < MIN_START_MS) return TIMEOUT
            val h: H = (try { start(mux) } catch (e: Exception) { null }) ?: return FAILED
            try {
                for (i in 0 until times) {
                    if (!wanted()) return null
                    val left = deadline - now()
                    if (left < MIN_REQUEST_MS) return TIMEOUT
                    val given = minOf(left, REQUEST_MS)
                    val t0 = now()
                    val ms = try { request(h, given.toInt()) } catch (e: Exception) { -1L }
                    // The round trip (Diagnostics, through XrayTester) is -1 for a refusal and for a
                    // timeout alike; the time it took tells them apart: within TIMEOUT_SLACK_MS of the
                    // time it was given, it ran out of time; earlier, it was refused, reset or closed.
                    if (ms < 0L) return if (now() - t0 >= given - TIMEOUT_SLACK_MS) TIMEOUT else FAILED
                }
                return OK
            } finally {
                try { stop(h) } catch (e: Exception) { }
            }
        }
        val muxOutcome = attempt(true, 2) ?: return UNREACHABLE
        if (muxOutcome == OK) return OK
        // refused or out of time: the control tells the server, the line or nothing at all
        val plain = attempt(false, 1)
        return verdict(muxOutcome, if (plain == null) null else plain == OK)
    }

    /**
     * The servers a plan dials as non-chain targets — the only outbounds mux is
     * ever put on (ConfigBuilder): the single server; a pool's and an advanced
     * plan's server targets, a literal "proxy" being the first server. A
     * chain's hops: none.
     */
    fun targets(connection: ConnectionPlan): List<ServerConfig> {
        val out = LinkedHashMap<String, ServerConfig>()
        fun keep(s: ServerConfig?) {
            if (s != null && s.outbound.length() > 0 && !out.containsKey(s.id)) out[s.id] = s
        }
        fun fromTargets(list: List<String>, byId: Map<String, ServerConfig>) {
            for (t in list) {
                if (t.isEmpty() || t == "direct" || t == "block" || t.startsWith("chain:")) continue
                keep(if (t == "proxy") byId.values.firstOrNull { s: ServerConfig -> s.outbound.length() > 0 } else byId[t])
            }
        }
        when (connection) {
            is ConnectionPlan.Single -> keep(connection.server)
            is ConnectionPlan.Chain -> {}
            is ConnectionPlan.Pool -> fromTargets(listOf(connection.primary) + connection.entries.map { e: PoolEntry -> e.target }, connection.serversById)
            // a target through a base never carries mux (spec §2), nor does the base
            is ConnectionPlan.Advanced -> fromTargets(
                connection.rules.filter { r: RouteRule -> r.value.isNotBlank() && RoutingProfiles.effectiveVia(r.target, r.via, connection.base) == null }
                    .map { r: RouteRule -> r.target } +
                    listOfNotNull(connection.def.takeIf { d: String -> RoutingProfiles.effectiveVia(d, connection.defVia, connection.base) == null }),
                connection.serversById)
        }
        return out.values.toList()
    }

    /**
     * A connect's mux: the server ids whose outbounds get it, and (auto) the
     * fingerprints a drop of this connection marks for a recheck.
     */
    data class Pick(val ids: Set<String>, val onDrop: List<String>) {
        companion object {
            val NONE = Pick(emptySet(), emptyList())
        }
    }

    /**
     * The connect path's decision, with the test, the store and the log handed
     * in. In auto the SELECTED server — a single-server plan's — is tested
     * ([test]) when [plan] says so: nothing known, a verdict past its age, or
     * an ok marked for a recheck, and not before its retryAfter. What a test
     * says is kept through [record] ([remember] stores it) — nothing at all
     * when it says "unreachable". A pool's or an
     * advanced plan's servers are not tested on a phone, one throwaway core per
     * server before every connect: they use what is kept. [recovery]: a
     * reconnect of the service's own — no test at all. One log line per server
     * decided. [wanted] false (the connect was overtaken): nothing is decided.
     */
    fun choose(
        mode: String,
        connection: ConnectionPlan,
        cache: Map<String, Probe>,
        now: () -> Long,
        test: (ServerConfig) -> String,
        remember: (String, Probe) -> Unit,
        log: (String) -> Unit,
        wanted: () -> Boolean = { true },
        recovery: Boolean = false
    ): Pick {
        val m = modeOf(mode)
        if (m == OFF) return Pick.NONE
        val servers = targets(connection).filter { s: ServerConfig -> eligible(s.outbound) }
        if (servers.isEmpty()) return Pick.NONE
        val first = plan(m, servers, cache, now(), recovery)
        if (m == ON) {
            for (s in servers) if (s.id in first.muxIds) log("Mux on for ${s.name} (Settings → Mux: On)")
            return Pick(first.muxIds, emptyList())
        }
        val known = HashMap(cache)
        val testedNow = HashMap<String, String>()
        val selected = (connection as? ConnectionPlan.Single)?.server
        for (s in first.toProbe) {
            if (selected == null || s.id != selected.id || !wanted()) continue
            val fp = fingerprint(s)
            val v = test(s)
            testedNow[fp] = v
            // nothing reachable (or the test cut short): nothing is written — the next connect tests again
            if (v != OK && v != UNSUPPORTED && v != UNKNOWN) continue
            val p = record(known[fp], v, now()) ?: continue
            known[fp] = p
            remember(fp, p)
        }
        if (!wanted()) return Pick.NONE
        val t = now()
        val second = plan(m, servers, known, t, recovery)
        for (s in servers) {
            val fp = fingerprint(s)
            log(line(s.name, s.id in second.muxIds, testedNow[fp], known[fp], t, recovery))
        }
        val onDrop = servers.filter { s: ServerConfig -> s.id in second.muxIds }.map { s: ServerConfig -> fingerprint(s) }.distinct()
        return Pick(second.muxIds, onDrop)
    }

    /**
     * One server's decision in the log: [on] what was decided, [testedNow]
     * what this connect's test said (null: none ran), [e] what is kept now,
     * [recovery] a reconnect of the service's own.
     */
    private fun line(name: String, on: Boolean, testedNow: String?, e: Probe?, now: Long, recovery: Boolean): String {
        val state = if (on) "on" else "off"
        if (testedNow == OK) return "Mux on for $name (tested: works)"
        if (testedNow == UNSUPPORTED) return "Mux off for $name (this server does not accept it)"
        if (testedNow == UNKNOWN) {
            if (e?.ok == null) return "Mux off for $name (no clear answer — mux ran out of time, the server answered without it; tested again in an hour)"
            return "Mux $state for $name (no clear answer this time — keeping the earlier result, tested again in an hour)"
        }
        if (testedNow != null) {
            // unreachable: nothing was kept, whatever was there stands
            if (on) return "Mux on for $name (no answer either way this time — the earlier result stands)"
            return "Mux: $name did not answer either way — connecting without it"
        }
        val earlier = when (e?.ok) {
            true -> "tested earlier: works"
            false -> "tested earlier: this server does not accept it"
            else -> "not tested yet"
        }
        if (recovery) return "Mux $state for $name (reconnecting, no test — $earlier)"
        if (e != null && e.retryAfter > now) {
            if (e.ok == null) return "Mux off for $name (the last test had no clear answer — tested again within the hour)"
            return "Mux $state for $name ($earlier; the last test had no clear answer)"
        }
        if (e == null || e.ok == null) return "Mux off for $name (not tested yet — it is tested when you connect to it on its own)"
        if (freshVerdict(e, now) == null) return "Mux off for $name (tested too long ago — it is tested when you connect to it on its own)"
        if (on && e.recheck) return "Mux on for $name ($earlier; tested again when you connect to it on its own)"
        return "Mux $state for $name ($earlier)"
    }

    /* ------ the kept verdicts: {fingerprint: {ok, at, recheck?, retryAfter?}} (Store.muxProbes) ------ */

    fun probesFromJson(text: String?): Map<String, Probe> {
        if (text.isNullOrBlank()) return emptyMap()
        val o = try { JSONObject(text) } catch (e: Exception) { return emptyMap() }
        val out = HashMap<String, Probe>()
        for (k in o.keys().asSequence()) {
            val e = o.optJSONObject(k) ?: continue
            val ok: Boolean? = if (e.has("ok") && !e.isNull("ok")) e.optBoolean("ok", false) else null
            val at = e.optLong("at", 0L)
            val retryAfter = e.optLong("retryAfter", 0L)
            // a verdict with its time, or an unknown waiting out its retry; anything else is no entry
            if ((ok != null && at > 0L) || retryAfter > 0L) out[k] = Probe(ok, at, e.optBoolean("recheck", false), retryAfter)
        }
        return out
    }

    fun probesToJson(probes: Map<String, Probe>): String {
        val o = JSONObject()
        for ((k, p) in probes) {
            val e = JSONObject().put("at", p.at)
            val ok = p.ok
            if (ok != null) e.put("ok", ok)
            if (p.recheck) e.put("recheck", true)
            if (p.retryAfter > 0L) e.put("retryAfter", p.retryAfter)
            o.put(k, e)
        }
        return o.toString()
    }

    /** At most [max] verdicts: the newest are kept. */
    fun capped(probes: Map<String, Probe>, max: Int = MAX_PROBES): Map<String, Probe> {
        if (probes.size <= max) return probes
        return probes.entries.sortedByDescending { e: Map.Entry<String, Probe> -> e.value.at }
            .take(max).associate { e: Map.Entry<String, Probe> -> Pair(e.key, e.value) }
    }

    /** A JSON string value, trimmed; "" when absent or null. */
    private fun str(o: JSONObject?, key: String): String = if (o == null || o.isNull(key)) "" else o.optString(key).trim()
}
