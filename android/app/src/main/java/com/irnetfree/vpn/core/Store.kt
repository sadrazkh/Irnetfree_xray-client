package com.irnetfree.vpn.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Local JSON store (SharedPreferences) for servers, chains, pool and settings.
 * Also resolves a UI "selection" into a concrete ConnectionPlan for the VPN.
 *
 * Selection ids:
 *   "<serverId>"     a single config
 *   "chain:<id>"     a named chain
 *   "__pool__"       the proxy pool (all enabled entries at once)
 */
class Store(context: Context) {
    private val prefs = context.getSharedPreferences("irnetfree", Context.MODE_PRIVATE)

    var servers: MutableList<ServerConfig> = loadServers()
        private set
    var chains: MutableList<ChainConfig> = loadChains()
        private set
    var pool: MutableList<PoolEntry> = loadPool()
        private set
    var settings: AppSettings = loadSettings()
        private set
    var selection: String = prefs.getString("selection", "") ?: ""

    /* ------------- persistence ------------- */

    fun saveServers() { prefs.edit().putString("servers", JSONArray(servers.map { it.toJson() }).toString()).apply() }
    fun saveChains() { prefs.edit().putString("chains", JSONArray(chains.map { it.toJson() }).toString()).apply() }
    fun savePool() { prefs.edit().putString("pool", JSONArray(pool.map { it.toJson() }).toString()).apply() }
    fun saveSelection(sel: String) { selection = sel; prefs.edit().putString("selection", sel).apply() }

    fun saveSettings(s: AppSettings) {
        settings = s
        prefs.edit().putString("settings", JSONObject()
            .put("socksPort", s.socksPort).put("httpPort", s.httpPort).put("apiPort", s.apiPort)
            .put("dns", JSONArray(s.dns)).put("routingMode", s.routingMode)
            .put("blockAds", s.blockAds).put("enableSniffing", s.enableSniffing)
            .put("logLevel", s.logLevel).put("perApp", s.perApp).toString()).apply()
    }

    private fun loadServers(): MutableList<ServerConfig> = readArray("servers") { ServerConfig.fromJson(it) }
    private fun loadChains(): MutableList<ChainConfig> = readArray("chains") { ChainConfig.fromJson(it) }
    private fun loadPool(): MutableList<PoolEntry> = readArray("pool") { PoolEntry.fromJson(it) }

    private fun <T> readArray(key: String, map: (JSONObject) -> T): MutableList<T> {
        val out = ArrayList<T>()
        try {
            val arr = JSONArray(prefs.getString(key, "[]"))
            for (i in 0 until arr.length()) out.add(map(arr.getJSONObject(i)))
        } catch (_: Exception) {}
        return out
    }

    private fun loadSettings(): AppSettings {
        return try {
            val o = JSONObject(prefs.getString("settings", "{}"))
            val dnsArr = o.optJSONArray("dns")
            val dns = if (dnsArr != null) (0 until dnsArr.length()).map { dnsArr.getString(it) } else listOf("1.1.1.1", "8.8.8.8")
            AppSettings(
                socksPort = o.optInt("socksPort", 10808),
                httpPort = o.optInt("httpPort", 10809),
                apiPort = o.optInt("apiPort", 10085),
                dns = dns,
                routingMode = o.optString("routingMode", "global"),
                blockAds = o.optBoolean("blockAds", true),
                enableSniffing = o.optBoolean("enableSniffing", true),
                logLevel = o.optString("logLevel", "warning"),
                perApp = o.optBoolean("perApp", false)
            )
        } catch (_: Exception) { AppSettings() }
    }

    /* ------------- helpers ------------- */

    fun serverById(id: String): ServerConfig? = servers.firstOrNull { it.id == id }
    fun chainById(id: String): ChainConfig? = chains.firstOrNull { it.id == id }
    fun chainMembers(c: ChainConfig): List<ServerConfig> = c.members.mapNotNull { serverById(it) }
    fun chainReady(c: ChainConfig): Boolean = chainMembers(c).size >= 2

    fun poolTargetValid(target: String): Boolean = when {
        target.isEmpty() -> false
        target.startsWith("chain:") -> chainById(target.substring(6))?.let { chainReady(it) } == true
        else -> serverById(target) != null
    }
    fun poolEnabledValid(): List<PoolEntry> = pool.filter { it.enabled && it.socksPort > 0 && poolTargetValid(it.target) }

    /** Human label for the current selection (for the connect screen). */
    fun selectionLabel(): String = when {
        selection == POOL_ID -> "🧩 Proxy Pool (${poolEnabledValid().size})"
        selection.startsWith("chain:") -> "⛓ " + (chainById(selection.substring(6))?.name ?: "—")
        else -> serverById(selection)?.name ?: "—"
    }

    /**
     * Build the ConnectionPlan for the current selection, or throw with a clear
     * message when it isn't connectable.
     */
    fun buildPlan(): ConnectionPlan {
        val sel = selection
        if (sel == POOL_ID) {
            val entries = poolEnabledValid()
            if (entries.isEmpty()) throw IllegalStateException("Enable at least one valid proxy in the pool")
            val serversById = servers.associateBy { it.id }
            val chainsById = chains.associate { it.id to chainMembers(it) }
            return ConnectionPlan.Pool(entries, entries.first().target, serversById, chainsById)
        }
        if (sel.startsWith("chain:")) {
            val c = chainById(sel.substring(6)) ?: throw IllegalStateException("Chain not found")
            val members = chainMembers(c)
            if (members.size < 2) throw IllegalStateException("This chain needs at least 2 servers")
            return ConnectionPlan.Chain(c.name, members)
        }
        val server = serverById(sel) ?: throw IllegalStateException("Select a server first")
        return ConnectionPlan.Single(server)
    }

    /** Server addresses the device must dial DIRECTLY (bypass in the TUN). */
    fun entryAddresses(plan: ConnectionPlan): List<String> = when (plan) {
        is ConnectionPlan.Single -> listOf(plan.server.address)
        is ConnectionPlan.Chain -> plan.members.firstOrNull()?.let { listOf(it.address) } ?: emptyList()
        is ConnectionPlan.Pool -> plan.entries.mapNotNull { e ->
            when {
                e.target.startsWith("chain:") -> plan.chainsById[e.target.substring(6)]?.firstOrNull()?.address
                else -> plan.serversById[e.target]?.address
            }
        }.distinct()
    }

    companion object {
        const val POOL_ID = "__pool__"
    }
}
