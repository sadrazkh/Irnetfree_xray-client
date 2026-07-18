package com.irnetfree.vpn.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Local JSON store (SharedPreferences) for servers, chains, pool, subscriptions
 * and settings. Also resolves a UI "selection" into a concrete ConnectionPlan.
 *
 * Selection ids:  "<serverId>" | "chain:<id>" | "__pool__" | "__advanced__"
 */
class Store(context: Context) {
    private val prefs = context.getSharedPreferences("irnetfree", Context.MODE_PRIVATE)

    val servers: MutableList<ServerConfig> = read("servers") { ServerConfig.fromJson(it) }
    val chains: MutableList<ChainConfig> = read("chains") { ChainConfig.fromJson(it) }
    val pool: MutableList<PoolEntry> = read("pool") { PoolEntry.fromJson(it) }
    val subs: MutableList<Subscription> = read("subs") { Subscription.fromJson(it) }
    var settings: AppSettings = loadSettings()
    var selection: String = prefs.getString("selection", "") ?: ""

    fun saveServers() = prefs.edit().putString("servers", JSONArray(servers.map { it.toJson() }).toString()).apply()
    fun saveChains() = prefs.edit().putString("chains", JSONArray(chains.map { it.toJson() }).toString()).apply()
    fun savePool() = prefs.edit().putString("pool", JSONArray(pool.map { it.toJson() }).toString()).apply()
    fun saveSubs() = prefs.edit().putString("subs", JSONArray(subs.map { it.toJson() }).toString()).apply()
    fun saveSelection(sel: String) { selection = sel; prefs.edit().putString("selection", sel).apply() }
    fun saveSettings(sNew: AppSettings) { settings = sNew; prefs.edit().putString("settings", sNew.toJson().toString()).apply() }

    private fun <T> read(key: String, map: (JSONObject) -> T): MutableList<T> {
        val out = ArrayList<T>()
        try { val a = JSONArray(prefs.getString(key, "[]")); for (i in 0 until a.length()) out.add(map(a.getJSONObject(i))) } catch (_: Exception) {}
        return out
    }
    private fun loadSettings(): AppSettings =
        try { AppSettings.fromJson(JSONObject(prefs.getString("settings", "{}"))) } catch (_: Exception) { AppSettings() }

    /* ------------- helpers ------------- */
    fun serverById(id: String) = servers.firstOrNull { it.id == id }
    fun chainById(id: String) = chains.firstOrNull { it.id == id }
    fun chainMembers(c: ChainConfig) = c.members.mapNotNull { serverById(it) }
    fun chainReady(c: ChainConfig) = chainMembers(c).size >= 2

    fun poolTargetValid(t: String): Boolean = when {
        t.isEmpty() -> false
        t.startsWith("chain:") -> chainById(t.substring(6))?.let { chainReady(it) } == true
        else -> serverById(t) != null
    }
    fun poolEnabledValid() = pool.filter { it.enabled && it.socksPort > 0 && poolTargetValid(it.target) }
    fun advancedReady() = settings.advancedRouting && (settings.routeRules.isNotEmpty() || settings.routeDefault.isNotEmpty())

    /** Delete a server and prune it from chains/pool. */
    fun deleteServer(id: String) {
        servers.removeAll { it.id == id }; saveServers()
        var changed = false
        for (i in chains.indices) if (chains[i].members.contains(id)) { chains[i] = chains[i].copy(members = chains[i].members.filter { it != id }); changed = true }
        if (changed) saveChains()
    }

    fun selectionLabel(): String = when {
        selection == POOL_ID -> "🧩 Proxy Pool (${poolEnabledValid().size})"
        selection == ADV_ID -> "🧭 Advanced routing"
        selection.startsWith("chain:") -> "⛓ " + (chainById(selection.substring(6))?.name ?: "—")
        else -> serverById(selection)?.name ?: "—"
    }

    fun buildPlan(): ConnectionPlan {
        val sel = selection
        val serversById = servers.associateBy { it.id }
        val chainsById = chains.associate { it.id to chainMembers(it) }
        return when {
            sel == POOL_ID -> {
                val entries = poolEnabledValid()
                if (entries.isEmpty()) throw IllegalStateException("Enable at least one valid proxy in the pool")
                ConnectionPlan.Pool(entries, entries.first().target, serversById, chainsById)
            }
            sel == ADV_ID -> {
                if (settings.routeRules.isEmpty() && settings.routeDefault.isBlank()) throw IllegalStateException("Add at least one routing rule")
                ConnectionPlan.Advanced(settings.routeRules, settings.routeDefault.ifBlank { servers.firstOrNull()?.id ?: "direct" }, serversById, chainsById)
            }
            sel.startsWith("chain:") -> {
                val c = chainById(sel.substring(6)) ?: throw IllegalStateException("Chain not found")
                val members = chainMembers(c)
                if (members.size < 2) throw IllegalStateException("This chain needs at least 2 servers")
                ConnectionPlan.Chain(c.name, members)
            }
            else -> ConnectionPlan.Single(serverById(sel) ?: throw IllegalStateException("Select a server first"))
        }
    }

    /** Server addresses to bypass in the TUN (avoid loop). */
    fun entryAddresses(plan: ConnectionPlan): List<String> = when (plan) {
        is ConnectionPlan.Single -> listOf(plan.server.address)
        is ConnectionPlan.Chain -> plan.members.firstOrNull()?.let { listOf(it.address) } ?: emptyList()
        is ConnectionPlan.Pool -> plan.entries.mapNotNull { entryAddr(it.target, plan.serversById, plan.chainsById) }.distinct()
        is ConnectionPlan.Advanced -> {
            val ts = (plan.rules.map { it.target } + plan.def).toSet()
            ts.mapNotNull { entryAddr(it, plan.serversById, plan.chainsById) }.distinct()
        }
    }
    private fun entryAddr(t: String, sById: Map<String, ServerConfig>, cById: Map<String, List<ServerConfig>>): String? = when {
        t.startsWith("chain:") -> cById[t.substring(6)]?.firstOrNull()?.address
        t == "direct" || t == "block" || t == "proxy" -> null
        else -> sById[t]?.address
    }

    companion object {
        const val POOL_ID = "__pool__"
        const val ADV_ID = "__advanced__"
    }
}
