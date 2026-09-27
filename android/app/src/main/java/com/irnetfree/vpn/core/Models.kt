package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * A single proxy config (mirrors the desktop `server` object): a normalized
 * record plus a ready-to-use Xray outbound (without a tag; the builder adds it).
 * `subId` links it to the subscription it came from (null = added manually).
 */
data class ServerConfig(
    val id: String,
    val name: String,
    val protocol: String,
    val address: String,
    val port: Int,
    val outbound: JSONObject,
    val raw: String = "",
    val subId: String? = null,
    // Per-config core (EngineChoice.kt): null = follow the app-wide default,
    // "xray" the in-process core, "xray-pattn" the bundled patterniha binary,
    // "sing-box" the bundled sing-box binary (single configs only).
    val engine: String? = null,
    // A WireGuard's own resolvers and search domains (`DNS = 10.0.0.53, corp.local`
    // in its .conf, `dns=` in its link): asked THROUGH that tunnel for the names
    // inside it. See DnsPlan.TargetResolver / configBuilder.js wgResolvers.
    val dns: List<String> = emptyList(),
    val dnsDomains: List<String> = emptyList(),
    // Certificate pinned on first use (CertPin.kt): the SHA-256 (hex) of the leaf
    // certificate a TLS server presented, when its link asked for allowInsecure.
    val certPin: String = "",
    val certPinAt: String = "",
    val certPinCheckedAt: Long = 0,
    // The edit-sheet fields the USER has changed on this server (ServerEditor
    // field names, accumulated over every save). A subscription refresh keeps
    // these and nothing else of the old record's connection (SubRefresh.carry):
    // what the user did is recorded when they do it, never inferred afterwards.
    val edited: List<String> = emptyList()
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id); put("name", name); put("protocol", protocol)
        put("address", address); put("port", port); put("outbound", outbound)
        put("raw", raw); if (subId != null) put("subId", subId)
        if (engine != null) put("engine", engine)
        if (dns.isNotEmpty()) put("dns", JSONArray(dns))
        if (dnsDomains.isNotEmpty()) put("dnsDomains", JSONArray(dnsDomains))
        if (certPin.isNotEmpty()) { put("certPin", certPin); put("certPinAt", certPinAt); put("certPinCheckedAt", certPinCheckedAt) }
        if (edited.isNotEmpty()) put("edited", JSONArray(edited))
    }

    companion object {
        fun fromJson(o: JSONObject): ServerConfig {
            // `dns` may be a list, or (a hand-edited store, an older record) the
            // .conf's own comma-separated line — the desktop's repairWgDnsFields.
            var dns = strList(o.optJSONArray("dns"))
            var domains = strList(o.optJSONArray("dnsDomains"))
            val dnsRaw = o.opt("dns")
            if (dnsRaw is String && dnsRaw.isNotBlank()) {
                val (d, dd) = LinkParser.splitDnsField(dnsRaw)
                dns = d; if (domains.isEmpty()) domains = dd
            }
            return ServerConfig(
                id = o.optString("id", newId("s")),
                name = o.optString("name"),
                protocol = o.optString("protocol"),
                address = o.optString("address"),
                port = o.optInt("port"),
                outbound = o.optJSONObject("outbound") ?: JSONObject(),
                raw = o.optString("raw"),
                subId = if (o.has("subId") && !o.isNull("subId")) o.optString("subId") else null,
                engine = if (o.has("engine") && !o.isNull("engine")) o.optString("engine") else null,
                dns = dns,
                dnsDomains = domains,
                certPin = CertPin.normalizePin(o.optString("certPin")),
                certPinAt = o.optString("certPinAt"),
                certPinCheckedAt = o.optLong("certPinCheckedAt", 0),
                edited = strList(o.optJSONArray("edited"))
            )
        }

        fun strList(a: JSONArray?): List<String> =
            if (a == null) emptyList() else (0 until a.length()).mapNotNull { a.opt(it) as? String }.map { it.trim() }.filter { it.isNotEmpty() }
    }
}

/** A named chain: ordered server ids (first hop -> exit). */
data class ChainConfig(val id: String, val name: String, val members: List<String>) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id); put("name", name)
        put("members", JSONArray().apply { members.forEach { put(it) } })
    }
    companion object {
        fun fromJson(o: JSONObject): ChainConfig {
            val arr = o.optJSONArray("members") ?: JSONArray()
            return ChainConfig(o.optString("id"), o.optString("name", "Chain"),
                (0 until arr.length()).map { arr.getString(it) })
        }
    }
}

/** A proxy-pool entry: an exit exposed on its own local SOCKS/HTTP port. */
data class PoolEntry(
    val id: String, val name: String, val target: String,
    val socksPort: Int, val httpPort: Int, val enabled: Boolean
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id); put("name", name); put("target", target)
        put("socksPort", socksPort); put("httpPort", httpPort); put("enabled", enabled)
    }
    companion object {
        fun fromJson(o: JSONObject) = PoolEntry(
            o.optString("id"), o.optString("name", "Proxy"), o.optString("target"),
            o.optInt("socksPort"), o.optInt("httpPort"), o.optBoolean("enabled", true))
    }
}

/**
 * A subscription source + its last-known usage (from Subscription-Userinfo).
 * `lastUpdated` is the last refresh that brought servers; `lastTried` the last
 * attempt of any outcome, so a failing one waits out the auto-update interval
 * like a good one instead of being fetched again on every visit (SubRefresh.due);
 * `lastError` is what that attempt said when it failed ("" = it did not).
 */
data class Subscription(
    val id: String,
    val name: String,
    val url: String,
    val serverCount: Int = 0,
    val lastUpdated: Long = 0,
    val autoUpdate: Boolean = true,
    val upload: Long = 0, val download: Long = 0, val total: Long = 0, val expire: Long = 0,
    val lastTried: Long = 0,
    val lastError: String = ""
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id); put("name", name); put("url", url)
        put("serverCount", serverCount); put("lastUpdated", lastUpdated); put("autoUpdate", autoUpdate)
        put("upload", upload); put("download", download); put("total", total); put("expire", expire)
        put("lastTried", lastTried); if (lastError.isNotEmpty()) put("lastError", lastError)
    }
    companion object {
        fun fromJson(o: JSONObject) = Subscription(
            o.optString("id"), o.optString("name", "Sub"), o.optString("url"),
            o.optInt("serverCount"), o.optLong("lastUpdated"), o.optBoolean("autoUpdate", true),
            o.optLong("upload"), o.optLong("download"), o.optLong("total"), o.optLong("expire"),
            o.optLong("lastTried"), o.optString("lastError"))
    }
}

/** One advanced-routing rule: match a kind/value and send it to a target. */
data class RouteRule(val type: String, val value: String, val target: String) {
    fun toJson(): JSONObject = JSONObject().apply { put("type", type); put("value", value); put("target", target) }
    companion object {
        fun fromJson(o: JSONObject) = RouteRule(o.optString("type", "domain"), o.optString("value"), o.optString("target", "proxy"))
    }
}

/** App settings (superset the Android client needs). */
data class AppSettings(
    val socksPort: Int = 10808,
    val httpPort: Int = 10809,
    val apiPort: Int = 10085,
    // Name resolution (see DnsPlan.kt / desktop dnsBuilder.js): remote over DoH
    // through the tunnel, an in-country resolver for bypass modes, every
    // port-53 packet answered by the core. `dnsManaged:false` restores the old
    // "use these servers" behaviour.
    val dnsManaged: Boolean = true,
    val dnsRemote: List<String> = DnsPlan.DEFAULT_REMOTE,
    val dnsDirect: List<String> = DnsPlan.DEFAULT_DIRECT_IR,
    val routingMode: String = "global",   // global | bypass-ir | bypass-cn | direct
    val blockAds: Boolean = true,
    val enableSniffing: Boolean = true,
    val logLevel: String = "warning",
    val advancedRouting: Boolean = false,
    // apply routingMode (bypass Iran/China…) UNDER the advanced rules as well
    val advancedUseMode: Boolean = false,
    // The core a config runs on when it does not name one of its own.
    // "xray" = libv2ray in-process; "xray-pattn" = the bundled patterniha
    // fork as a subprocess (EngineChoice.kt, the desktop's engineChoice.js).
    val defaultEngine: String = EngineChoice.XRAY,
    // Simple or advanced, the badge in the header. Advanced shows the chain,
    // pool, routing and log screens behind More; simple hides them and leaves
    // Connect one decision. Default true so an upgrade never hides work the
    // owner already set up.
    val advancedMode: Boolean = true,
    val routeRules: List<RouteRule> = emptyList(),
    val routeDefault: String = "proxy",
    val customRules: List<RouteRule> = emptyList(),
    // per-app routing: mode 'off' | 'allow' (only these apps) | 'disallow' (all but these)
    val perAppMode: String = "off",
    val perApps: List<String> = emptyList(),
    val ipv6: Boolean = false,
    // Connect to the selected config when the app is opened. Off by default:
    // like the desktop (main.js autoConnect), starting a tunnel by itself is a
    // thing the user turns on deliberately.
    val autoConnect: Boolean = false,
    val autoUpdateSubs: Boolean = true,
    val autoUpdateInterval: Int = 60,
    val lang: String = "fa"
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("socksPort", socksPort); put("httpPort", httpPort); put("apiPort", apiPort)
        put("dnsManaged", dnsManaged); put("dnsRemote", JSONArray(dnsRemote)); put("dnsDirect", JSONArray(dnsDirect))
        put("routingMode", routingMode)
        put("blockAds", blockAds); put("enableSniffing", enableSniffing); put("logLevel", logLevel)
        put("advancedRouting", advancedRouting); put("advancedUseMode", advancedUseMode)
        put("defaultEngine", defaultEngine)
        put("advancedMode", advancedMode)
        put("routeRules", JSONArray(routeRules.map { it.toJson() }))
        put("routeDefault", routeDefault)
        put("customRules", JSONArray(customRules.map { it.toJson() }))
        put("perAppMode", perAppMode); put("perApps", JSONArray(perApps))
        put("ipv6", ipv6); put("autoConnect", autoConnect); put("autoUpdateSubs", autoUpdateSubs); put("autoUpdateInterval", autoUpdateInterval)
        put("lang", lang)
    }
    companion object {
        /** The DoH endpoint of a public resolver the old store may have listed as a plain address. */
        private val DOH_FOR = mapOf(
            "1.1.1.1" to "https://1.1.1.1/dns-query", "1.0.0.1" to "https://1.0.0.1/dns-query",
            "8.8.8.8" to "https://8.8.8.8/dns-query", "8.8.4.4" to "https://8.8.4.4/dns-query",
            "9.9.9.9" to "https://9.9.9.9/dns-query", "149.112.112.112" to "https://149.112.112.112/dns-query",
            "94.140.14.14" to "https://94.140.14.14/dns-query", "94.140.15.15" to "https://94.140.15.15/dns-query",
            "208.67.222.222" to "https://208.67.222.222/dns-query", "208.67.220.220" to "https://208.67.220.220/dns-query"
        )
        /** Resolvers that only make sense as the in-country (direct) server. */
        private val IRANIAN = setOf(
            "178.22.122.100", "185.51.200.2",      // Shecan
            "78.157.42.100", "78.157.42.101",      // Electro
            "10.202.10.202", "10.202.10.102",      // Begzar
            "10.202.10.10", "10.202.10.11"         // 403.online
        )

        fun fromJson(o: JSONObject): AppSettings {
            fun strList(a: JSONArray?): List<String> = ServerConfig.strList(a)
            fun ruleList(a: JSONArray?): List<RouteRule> = if (a == null) emptyList() else (0 until a.length()).map { RouteRule.fromJson(a.getJSONObject(it)) }
            // A store from before the managed plan held one `dns` list of plain
            // resolvers. Its known public ones become their DoH endpoints, the
            // Iranian ones the in-country list, anything else is kept as is —
            // the desktop's settingsMigrate.js, applied on read.
            var remote = strList(o.optJSONArray("dnsRemote"))
            var direct = strList(o.optJSONArray("dnsDirect"))
            if (remote.isEmpty() && o.has("dns")) {
                val old = strList(o.optJSONArray("dns"))
                val r = ArrayList<String>(); val d = ArrayList<String>()
                for (ip in old) { if (ip in IRANIAN) d.add(ip) else r.add(DOH_FOR[ip] ?: ip) }
                remote = r
                if (direct.isEmpty() && d.isNotEmpty()) direct = d
            }
            return AppSettings(
                socksPort = o.optInt("socksPort", 10808),
                httpPort = o.optInt("httpPort", 10809),
                apiPort = o.optInt("apiPort", 10085),
                dnsManaged = o.optBoolean("dnsManaged", true),
                dnsRemote = remote.ifEmpty { DnsPlan.DEFAULT_REMOTE },
                dnsDirect = direct.ifEmpty { DnsPlan.DEFAULT_DIRECT_IR },
                routingMode = o.optString("routingMode", "global"),
                blockAds = o.optBoolean("blockAds", true),
                enableSniffing = o.optBoolean("enableSniffing", true),
                logLevel = o.optString("logLevel", "warning"),
                advancedRouting = o.optBoolean("advancedRouting", false),
                advancedUseMode = o.optBoolean("advancedUseMode", false),
                defaultEngine = o.optString("defaultEngine", EngineChoice.XRAY).ifBlank { EngineChoice.XRAY },
                advancedMode = o.optBoolean("advancedMode", true),
                routeRules = ruleList(o.optJSONArray("routeRules")),
                routeDefault = o.optString("routeDefault", "proxy"),
                customRules = ruleList(o.optJSONArray("customRules")),
                perAppMode = o.optString("perAppMode", "off"),
                perApps = strList(o.optJSONArray("perApps")),
                ipv6 = o.optBoolean("ipv6", false),
                autoConnect = o.optBoolean("autoConnect", false),
                autoUpdateSubs = o.optBoolean("autoUpdateSubs", true),
                autoUpdateInterval = o.optInt("autoUpdateInterval", 60),
                lang = o.optString("lang", "fa")
            )
        }
    }
}

/**
 * LAN sharing: while connected, the other devices on the phone's Wi-Fi or on
 * its hotspot use the phone as a proxy — a SOCKS5 and an HTTP inbound of their
 * own, on every interface, routed exactly like the tunnel's traffic (the same
 * rules, the same DNS plan) on whichever core runs (ConfigBuilder,
 * SingboxConfig). The tunnel's own socks-in/http-in stay on 127.0.0.1 with
 * their per-session credentials (LocalAuth.kt); these are separate inbounds.
 *
 * Off by default. Password on by default, with a generated username and
 * password the user can read, copy and change; off, anyone on the network can
 * use the connection. Stored under a key of its own (LanShareStore), not inside
 * AppSettings: the Settings screen writes AppSettings back whole from the copy
 * it opened with, and a change made in this section meanwhile was lost with it.
 */
data class LanShare(
    val enabled: Boolean = false,
    val socksPort: Int = DEFAULT_SOCKS,
    val httpPort: Int = DEFAULT_HTTP,
    val auth: Boolean = true,
    val user: String = "",
    val pass: String = ""
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("enabled", enabled); put("socksPort", socksPort); put("httpPort", httpPort)
        put("auth", auth); put("user", user); put("pass", pass)
    }

    /**
     * Why this share cannot open beside [s]'s own inbounds and the pool's, in
     * words for the user; null = it can. Checked by the Settings section as it
     * is typed and again at connect, where a share that no longer fits (the
     * tunnel's port was changed onto it since) is left out of that connection.
     */
    fun problem(s: AppSettings, pool: List<PoolEntry>): String? {
        for ((name, p) in listOf("SOCKS" to socksPort, "HTTP" to httpPort)) {
            if (p < MIN_PORT || p > MAX_PORT) return "The LAN $name port must be between $MIN_PORT and $MAX_PORT"
        }
        if (socksPort == httpPort) return "The LAN SOCKS and HTTP ports must differ"
        for (p in listOf(socksPort, httpPort)) {
            if (p == s.socksPort) return "Port $p is the tunnel's own SOCKS port"
            if (p == s.httpPort) return "Port $p is the tunnel's own HTTP port"
            if (p == s.apiPort) return "Port $p is reserved for the core's API port"
            val e = pool.firstOrNull { it.socksPort == p || it.httpPort == p }
            if (e != null) return "Port $p belongs to the proxy pool (${e.name})"
        }
        if (auth) credentialProblem(user, pass)?.let { m -> return m }
        return null
    }

    /** Blank credentials filled in with generated ones; set ones are kept. */
    fun withCredentials(): LanShare =
        if (user.isNotEmpty() && pass.isNotEmpty()) this
        else copy(user = user.ifEmpty { newUser() }, pass = pass.ifEmpty { newPass() })

    companion object {
        const val DEFAULT_SOCKS = 10810
        const val DEFAULT_HTTP = 10811
        const val MIN_PORT = 1024
        const val MAX_PORT = 65535
        /** The inbound tags, in both config formats: TunnelSetup.withoutLan finds them by these. */
        const val SOCKS_TAG = "lan-socks"
        const val HTTP_TAG = "lan-http"
        /** Every interface: the phone's Wi-Fi address and its hotspot's alike. */
        const val LISTEN = "0.0.0.0"

        // No 0/O, 1/l/i: these get typed on a TV or a laptop by hand.
        private const val ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
        private val rng = java.security.SecureRandom()
        private fun pick(n: Int): String = buildString { repeat(n) { append(ALPHABET[rng.nextInt(ALPHABET.length)]) } }
        fun newUser(): String = "irnf-" + pick(4)
        fun newPass(): String = pick(12)

        fun fromJson(o: JSONObject): LanShare = LanShare(
            enabled = o.optBoolean("enabled", false),
            socksPort = o.optInt("socksPort", DEFAULT_SOCKS),
            httpPort = o.optInt("httpPort", DEFAULT_HTTP),
            auth = o.optBoolean("auth", true),
            user = o.optString("user", ""),
            pass = o.optString("pass", "")
        )

        /**
         * Printable ASCII only (no spaces): SOCKS5 sends them as bytes, and a
         * person types them on another device. The username carries no ":" —
         * HTTP's Basic auth splits the pair on the first one.
         */
        fun credentialProblem(user: String, pass: String): String? {
            fun bad(v: String) = v.any { c -> c.code < 33 || c.code > 126 }
            return when {
                user.isEmpty() -> "Enter a username, or turn the password off"
                pass.isEmpty() -> "Enter a password, or turn the password off"
                user.length > 64 || pass.length > 64 -> "The username and the password take at most 64 characters each"
                bad(user) || bad(pass) -> "Letters, digits and plain symbols only — no spaces"
                user.contains(':') -> "The username cannot contain \":\""
                else -> null
            }
        }

        /**
         * Do [a] and [b] open the same share — the same ports and, with a
         * password, the same credentials? Off (or null) on both sides is the
         * same too. What the running tunnel opened (VpnState.lanShared) against
         * what Settings holds now: different means "applies on the next connect".
         */
        fun same(a: LanShare?, b: LanShare?): Boolean {
            val x = a?.takeIf { it.enabled }
            val y = b?.takeIf { it.enabled }
            if (x == null || y == null) return x == null && y == null
            return x.socksPort == y.socksPort && x.httpPort == y.httpPort && x.auth == y.auth &&
                (!x.auth || (x.user == y.user && x.pass == y.pass))
        }
    }
}

/** What to connect through. single / chain / pool / advanced. */
sealed class ConnectionPlan {
    data class Single(val server: ServerConfig) : ConnectionPlan()
    data class Chain(val name: String, val members: List<ServerConfig>) : ConnectionPlan()
    data class Pool(
        val entries: List<PoolEntry>, val primary: String,
        val serversById: Map<String, ServerConfig>, val chainsById: Map<String, List<ServerConfig>>
    ) : ConnectionPlan()
    data class Advanced(
        val rules: List<RouteRule>, val def: String,
        val serversById: Map<String, ServerConfig>, val chainsById: Map<String, List<ServerConfig>>
    ) : ConnectionPlan()

    /**
     * The same plan — the same servers, chain, pool or rules — with each
     * record replaced by [fresh]'s record of that id (one [fresh] no longer
     * has is kept as it was). How a connect picks up the certificate pins it
     * has just learnt: rebuilding the plan from the store's CURRENT selection
     * instead connected whatever had been selected meanwhile, under the label
     * and notification of the server that was asked for.
     */
    fun withRecords(fresh: (String) -> ServerConfig?): ConnectionPlan {
        fun f(s: ServerConfig): ServerConfig = fresh(s.id) ?: s
        fun servers(m: Map<String, ServerConfig>): Map<String, ServerConfig> = m.mapValues { e: Map.Entry<String, ServerConfig> -> f(e.value) }
        fun chains(m: Map<String, List<ServerConfig>>): Map<String, List<ServerConfig>> =
            m.mapValues { e: Map.Entry<String, List<ServerConfig>> -> e.value.map { s: ServerConfig -> f(s) } }
        val p: ConnectionPlan = this
        return when (p) {
            is Single -> Single(f(p.server))
            is Chain -> Chain(p.name, p.members.map { s: ServerConfig -> f(s) })
            is Pool -> p.copy(serversById = servers(p.serversById), chainsById = chains(p.chainsById))
            is Advanced -> p.copy(serversById = servers(p.serversById), chainsById = chains(p.chainsById))
        }
    }
}

fun newId(prefix: String): String =
    prefix + "-" + System.currentTimeMillis().toString(36) + UUID.randomUUID().toString().replace("-", "").take(4)
