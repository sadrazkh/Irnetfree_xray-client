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
 * Not every server accepts it, so in Settings → Mux "auto" (the default) a
 * server is tested once before the connect that needs it, and the verdict is
 * kept: "ok" for 7 days, "unsupported" for 3 — per server FINGERPRINT, so an
 * edited server, or a subscription refresh with new parameters, is tested
 * again. "on" muxes every eligible server untested; "off" writes the configs of
 * before, byte for byte.
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
     * and plain worked / nothing definite — a timeout, or no answer either way
     * (never remembered). [OK] is also the mux attempt's outcome when it worked.
     */
    const val OK = "ok"
    const val UNSUPPORTED = "unsupported"
    const val UNKNOWN = "unknown"

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
    const val UNSUPPORTED_TTL_MS: Long = 3 * DAY_MS

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

    /** Settings → Mux as stored: anything but "on" / "off" is "auto", the default. */
    fun modeOf(raw: String?): String = when (raw?.trim()?.lowercase()) {
        ON -> ON
        OFF -> OFF
        else -> AUTO
    }

    /**
     * May this outbound carry mux? VLESS without a `flow`, VMess and Trojan,
     * over `ws` or `httpupgrade`. gRPC, XHTTP and H2 multiplex already; Vision,
     * REALITY on raw, mKCP, Hysteria, WireGuard and Shadowsocks are never touched.
     */
    fun eligible(outbound: JSONObject?): Boolean {
        if (outbound == null) return false
        val network = str(outbound.optJSONObject("streamSettings"), "network").lowercase()
        if (network != "ws" && network != "httpupgrade") return false
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
            "ws" -> {
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

    /** A remembered verdict: mux worked (or the server did not accept it), [at] epoch ms. Stored as {ok, at}. */
    data class Probe(val ok: Boolean, val at: Long)

    /** "ok" / "unsupported" while [entry] still holds (7 / 3 days), else null: test again. */
    fun freshVerdict(entry: Probe?, now: Long): String? {
        if (entry == null || entry.at <= 0L) return null
        val age = now - entry.at
        if (age < 0L) return null              // stamped by a clock that has since gone back
        return if (entry.ok) (if (age < OK_TTL_MS) OK else null) else (if (age < UNSUPPORTED_TTL_MS) UNSUPPORTED else null)
    }

    /** What a connect does: the server ids that get mux, and the servers that have no fresh verdict yet. */
    data class Plan(val muxIds: Set<String>, val toProbe: List<ServerConfig>)

    /**
     * off → nothing. on → every eligible id, no test. auto → the ids with a
     * fresh "ok", and the eligible servers with no fresh verdict to test (one
     * per fingerprint). A fresh "unsupported" is neither.
     */
    fun plan(mode: String, servers: List<ServerConfig>, cache: Map<String, Probe>, now: Long): Plan {
        val m = modeOf(mode)
        if (m == OFF) return Plan(emptySet(), emptyList())
        val ids = LinkedHashSet<String>()
        val toProbe = ArrayList<ServerConfig>()
        val queued = HashSet<String>()
        for (s in servers) {
            if (!eligible(s.outbound)) continue
            if (m == ON) { ids.add(s.id); continue }
            val fp = fingerprint(s)
            val v = freshVerdict(cache[fp], now)
            if (v == OK) ids.add(s.id)
            else if (v == null && queued.add(fp)) toProbe.add(s)
        }
        return Plan(ids, toProbe)
    }

    /**
     * The test's verdict, from the mux attempt's outcome — [OK] | [TIMEOUT] |
     * [FAILED] — and the control's (null = not run): mux ok → "ok"; mux failed
     * and the control answered → "unsupported"; a mux timeout, whatever the
     * control says, or a control that did not answer → "unknown".
     */
    fun verdict(mux: String, plainOk: Boolean?): String = when {
        mux == OK -> OK
        mux == FAILED && plainOk == true -> UNSUPPORTED
        else -> UNKNOWN
    }

    /**
     * The test (spec §4), with the cores handed in: a throwaway core whose
     * proxy outbound carries [MUX] ([start] true) makes two requests, one after
     * the other — both must answer. That attempt is [OK]; a [TIMEOUT] when a
     * request did not answer before its time ran out, or the budget did; or
     * [FAILED] when a request failed before its time (refused, reset, closed)
     * or the core could not start. Only after FAILED does one request go
     * through a core without mux ([start] false), and only then can a server be
     * "unsupported". A slow moment is not a refusal: a mux attempt that ran out
     * of time says nothing whatever a control would say (the router's field
     * case — a timeout, then an answering control, was remembered as
     * "unsupported" for three days), so after a TIMEOUT no control is run.
     *
     * Every core started is stopped, and the whole test stays within
     * [budgetMs]: each request gets at most what is left ([REQUEST_MS] at the
     * most), and nothing more is started once too little is. [request] makes
     * one request through a core within the ms it is given: its round trip, or
     * a negative number when it did not answer. [wanted]: false once the
     * connect this is for has been overtaken — nothing more starts, "unknown".
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
        val muxOutcome = attempt(true, 2) ?: return UNKNOWN
        if (muxOutcome != FAILED) return verdict(muxOutcome, null)
        val plain = attempt(false, 1)
        return verdict(FAILED, if (plain == null) null else plain == OK)
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
            is ConnectionPlan.Advanced -> fromTargets(
                connection.rules.filter { r: RouteRule -> r.value.isNotBlank() }.map { r: RouteRule -> r.target } + connection.def,
                connection.serversById)
        }
        return out.values.toList()
    }

    /** A connect's mux: the server ids whose outbounds get it, and (auto) the fingerprints a drop forgets. */
    data class Pick(val ids: Set<String>, val forget: List<String>) {
        companion object {
            val NONE = Pick(emptySet(), emptyList())
        }
    }

    /**
     * The connect path's decision, with the test, the store and the log handed
     * in. In auto the SELECTED server — a single-server plan's — is tested once
     * ([test]) when it has no fresh verdict; "ok" and "unsupported" are
     * remembered, "unknown" is not (connect as today, test again next time). A
     * pool's or an advanced plan's servers are not tested on a phone, one
     * throwaway core per server before every connect: they use what their own
     * connects found. One log line per server decided. [wanted] false (the
     * connect was overtaken): nothing is decided.
     */
    fun choose(
        mode: String,
        connection: ConnectionPlan,
        cache: Map<String, Probe>,
        now: () -> Long,
        test: (ServerConfig) -> String,
        remember: (String, Probe) -> Unit,
        log: (String) -> Unit,
        wanted: () -> Boolean = { true }
    ): Pick {
        val m = modeOf(mode)
        if (m == OFF) return Pick.NONE
        val servers = targets(connection).filter { s: ServerConfig -> eligible(s.outbound) }
        if (servers.isEmpty()) return Pick.NONE
        val first = plan(m, servers, cache, now())
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
            if (v == OK || v == UNSUPPORTED) {
                val p = Probe(v == OK, now())
                known[fp] = p
                remember(fp, p)
            }
        }
        if (!wanted()) return Pick.NONE
        val t = now()
        val second = plan(m, servers, known, t)
        for (s in servers) {
            val fp = fingerprint(s)
            log(line(s.name, testedNow[fp], freshVerdict(known[fp], t)))
        }
        val forget = servers.filter { s: ServerConfig -> s.id in second.muxIds }.map { s: ServerConfig -> fingerprint(s) }.distinct()
        return Pick(second.muxIds, forget)
    }

    /** One server's decision in the log: [testedNow] what this connect's test said, else [remembered]. */
    private fun line(name: String, testedNow: String?, remembered: String?): String = when {
        testedNow == OK -> "Mux on for $name (tested: works)"
        testedNow == UNSUPPORTED -> "Mux off for $name (this server does not accept it)"
        testedNow != null -> "Mux: $name did not answer either way — connecting without it"
        remembered == OK -> "Mux on for $name (tested earlier: works)"
        remembered == UNSUPPORTED -> "Mux off for $name (tested earlier: this server does not accept it)"
        else -> "Mux off for $name (not tested yet — it is tested when you connect to it on its own)"
    }

    /* ---------------- the stored verdicts: {fingerprint: {ok, at}} (Store.muxProbes) ---------------- */

    fun probesFromJson(text: String?): Map<String, Probe> {
        if (text.isNullOrBlank()) return emptyMap()
        val o = try { JSONObject(text) } catch (e: Exception) { return emptyMap() }
        val out = HashMap<String, Probe>()
        for (k in o.keys().asSequence()) {
            val e = o.optJSONObject(k) ?: continue
            val at = e.optLong("at", 0L)
            if (at > 0L) out[k] = Probe(e.optBoolean("ok", false), at)
        }
        return out
    }

    fun probesToJson(probes: Map<String, Probe>): String {
        val o = JSONObject()
        for ((k, p) in probes) o.put(k, JSONObject().put("ok", p.ok).put("at", p.at))
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
