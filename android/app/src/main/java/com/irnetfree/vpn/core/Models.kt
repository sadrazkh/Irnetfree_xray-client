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
    val certPinCheckedAt: Long = 0
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id); put("name", name); put("protocol", protocol)
        put("address", address); put("port", port); put("outbound", outbound)
        put("raw", raw); if (subId != null) put("subId", subId)
        if (engine != null) put("engine", engine)
        if (dns.isNotEmpty()) put("dns", JSONArray(dns))
        if (dnsDomains.isNotEmpty()) put("dnsDomains", JSONArray(dnsDomains))
        if (certPin.isNotEmpty()) { put("certPin", certPin); put("certPinAt", certPinAt); put("certPinCheckedAt", certPinCheckedAt) }
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
                certPinCheckedAt = o.optLong("certPinCheckedAt", 0)
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

/** A subscription source + its last-known usage (from Subscription-Userinfo). */
data class Subscription(
    val id: String,
    val name: String,
    val url: String,
    val serverCount: Int = 0,
    val lastUpdated: Long = 0,
    val autoUpdate: Boolean = true,
    val upload: Long = 0, val download: Long = 0, val total: Long = 0, val expire: Long = 0
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id); put("name", name); put("url", url)
        put("serverCount", serverCount); put("lastUpdated", lastUpdated); put("autoUpdate", autoUpdate)
        put("upload", upload); put("download", download); put("total", total); put("expire", expire)
    }
    companion object {
        fun fromJson(o: JSONObject) = Subscription(
            o.optString("id"), o.optString("name", "Sub"), o.optString("url"),
            o.optInt("serverCount"), o.optLong("lastUpdated"), o.optBoolean("autoUpdate", true),
            o.optLong("upload"), o.optLong("download"), o.optLong("total"), o.optLong("expire"))
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
        put("ipv6", ipv6); put("autoUpdateSubs", autoUpdateSubs); put("autoUpdateInterval", autoUpdateInterval)
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
                autoUpdateSubs = o.optBoolean("autoUpdateSubs", true),
                autoUpdateInterval = o.optInt("autoUpdateInterval", 60),
                lang = o.optString("lang", "fa")
            )
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
}

fun newId(prefix: String): String =
    prefix + "-" + System.currentTimeMillis().toString(36) + UUID.randomUUID().toString().replace("-", "").take(4)
