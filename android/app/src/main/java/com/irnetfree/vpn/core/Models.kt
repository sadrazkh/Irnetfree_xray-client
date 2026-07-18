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
    val subId: String? = null
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id); put("name", name); put("protocol", protocol)
        put("address", address); put("port", port); put("outbound", outbound)
        put("raw", raw); if (subId != null) put("subId", subId)
    }

    companion object {
        fun fromJson(o: JSONObject): ServerConfig = ServerConfig(
            id = o.optString("id", newId("s")),
            name = o.optString("name"),
            protocol = o.optString("protocol"),
            address = o.optString("address"),
            port = o.optInt("port"),
            outbound = o.optJSONObject("outbound") ?: JSONObject(),
            raw = o.optString("raw"),
            subId = if (o.has("subId") && !o.isNull("subId")) o.optString("subId") else null
        )
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
    val dns: List<String> = listOf("1.1.1.1", "8.8.8.8"),
    val routingMode: String = "global",   // global | bypass-ir | bypass-cn | direct
    val blockAds: Boolean = true,
    val enableSniffing: Boolean = true,
    val logLevel: String = "warning",
    val advancedRouting: Boolean = false,
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
        put("dns", JSONArray(dns)); put("routingMode", routingMode)
        put("blockAds", blockAds); put("enableSniffing", enableSniffing); put("logLevel", logLevel)
        put("advancedRouting", advancedRouting)
        put("routeRules", JSONArray(routeRules.map { it.toJson() }))
        put("routeDefault", routeDefault)
        put("customRules", JSONArray(customRules.map { it.toJson() }))
        put("perAppMode", perAppMode); put("perApps", JSONArray(perApps))
        put("ipv6", ipv6); put("autoUpdateSubs", autoUpdateSubs); put("autoUpdateInterval", autoUpdateInterval)
        put("lang", lang)
    }
    companion object {
        fun fromJson(o: JSONObject): AppSettings {
            fun strList(a: JSONArray?): List<String> = if (a == null) emptyList() else (0 until a.length()).map { a.getString(it) }
            fun ruleList(a: JSONArray?): List<RouteRule> = if (a == null) emptyList() else (0 until a.length()).map { RouteRule.fromJson(a.getJSONObject(it)) }
            val d = strList(o.optJSONArray("dns")).ifEmpty { listOf("1.1.1.1", "8.8.8.8") }
            return AppSettings(
                socksPort = o.optInt("socksPort", 10808),
                httpPort = o.optInt("httpPort", 10809),
                apiPort = o.optInt("apiPort", 10085),
                dns = d,
                routingMode = o.optString("routingMode", "global"),
                blockAds = o.optBoolean("blockAds", true),
                enableSniffing = o.optBoolean("enableSniffing", true),
                logLevel = o.optString("logLevel", "warning"),
                advancedRouting = o.optBoolean("advancedRouting", false),
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
