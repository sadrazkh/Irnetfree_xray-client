package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * A single proxy config (mirrors the desktop `server` object): a normalized
 * record plus a ready-to-use Xray outbound (without a tag; the builder adds it).
 */
data class ServerConfig(
    val id: String,
    val name: String,
    val protocol: String,
    val address: String,
    val port: Int,
    val outbound: JSONObject
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id); put("name", name); put("protocol", protocol)
        put("address", address); put("port", port); put("outbound", outbound)
    }

    companion object {
        fun fromJson(o: JSONObject): ServerConfig = ServerConfig(
            id = o.optString("id", UUID.randomUUID().toString().replace("-", "").take(16)),
            name = o.optString("name"),
            protocol = o.optString("protocol"),
            address = o.optString("address"),
            port = o.optInt("port"),
            outbound = o.optJSONObject("outbound") ?: JSONObject()
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
            val m = (0 until arr.length()).map { arr.getString(it) }
            return ChainConfig(o.optString("id"), o.optString("name", "Chain"), m)
        }
    }
}

/**
 * A proxy-pool entry: a target exit exposed on its own local SOCKS/HTTP port.
 * `target` is a server id or "chain:<chainId>".
 */
data class PoolEntry(
    val id: String,
    val name: String,
    val target: String,
    val socksPort: Int,
    val httpPort: Int,
    val enabled: Boolean
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id); put("name", name); put("target", target)
        put("socksPort", socksPort); put("httpPort", httpPort); put("enabled", enabled)
    }

    companion object {
        fun fromJson(o: JSONObject): PoolEntry = PoolEntry(
            id = o.optString("id"),
            name = o.optString("name", "Proxy"),
            target = o.optString("target"),
            socksPort = o.optInt("socksPort"),
            httpPort = o.optInt("httpPort"),
            enabled = o.optBoolean("enabled", true)
        )
    }
}

/** App settings (subset of the desktop settings that matter on Android). */
data class AppSettings(
    val socksPort: Int = 10808,
    val httpPort: Int = 10809,
    val apiPort: Int = 10085,
    val dns: List<String> = listOf("1.1.1.1", "8.8.8.8"),
    val routingMode: String = "global",   // global | bypass-ir | bypass-cn | direct
    val blockAds: Boolean = true,
    val enableSniffing: Boolean = true,
    val logLevel: String = "warning",
    val perApp: Boolean = false            // reserved for per-app routing
)

/**
 * What to connect through. Mirrors the desktop "plan": single / chain / pool.
 * For the pool, `entries` are the enabled entries and `primary` is the exit used
 * by the TUN (the whole-device tunnel) while the extra ports stay available.
 */
sealed class ConnectionPlan {
    data class Single(val server: ServerConfig) : ConnectionPlan()
    data class Chain(val name: String, val members: List<ServerConfig>) : ConnectionPlan()
    data class Pool(
        val entries: List<PoolEntry>,
        val primary: String,
        val serversById: Map<String, ServerConfig>,
        val chainsById: Map<String, List<ServerConfig>>
    ) : ConnectionPlan()
}

fun newId(prefix: String): String =
    prefix + "-" + System.currentTimeMillis().toString(36) +
        UUID.randomUUID().toString().replace("-", "").take(4)
