package com.irnetfree.vpn.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Local JSON store (SharedPreferences) for servers, chains, pool, subscriptions
 * and settings. Also resolves a UI "selection" into a concrete ConnectionPlan.
 *
 * Selection ids:  "<serverId>" | "chain:<id>" | "__pool__" | "__advanced__" | "__advanced__:<profileId>"
 */
class Store(context: Context) {
    private val prefs = context.getSharedPreferences("irnetfree", Context.MODE_PRIVATE)

    val servers: MutableList<ServerConfig> = read("servers") { ServerConfig.fromJson(it) }
    val chains: MutableList<ChainConfig> = read("chains") { ChainConfig.fromJson(it) }
    val pool: MutableList<PoolEntry> = read("pool") { PoolEntry.fromJson(it) }
    val subs: MutableList<Subscription> = read("subs") { Subscription.fromJson(it) }
    var settings: AppSettings = loadSettings()
    /** The routing profiles (RoutingProfiles.kt); never empty once the store is open. */
    val profiles: MutableList<RoutingProfile> = ArrayList()
    var selection: String = prefs.getString("selection", "") ?: ""
    /** The choice before [selection]: where a selection whose server is gone falls back to (Selection.repair). */
    var previousSelection: String = prefs.getString("selectionPrev", "") ?: ""
        private set

    // The selection is checked on every start as well: one saved before ids
    // were stable, or naming a server removed while the app was not running,
    // comes back as the choice before it (or the first server), not as "—".
    init { migrateServers(); migrateProfiles(); repairSelection() }

    /**
     * The routing profiles at start (RoutingProfiles.migrate): the first start
     * of this version turns today's settings into `rp-default`; a store whose
     * settings were changed since by an older app takes them back into
     * `rp-default`. Then `rp-default` is mirrored into the settings keys.
     */
    private fun migrateProfiles() {
        val stored: List<RoutingProfile>? = if (!prefs.contains(RoutingProfiles.STORE_KEY)) null
            else read(RoutingProfiles.STORE_KEY) { o: JSONObject -> RoutingProfile.fromJson(o) }
        val m = RoutingProfiles.migrate(stored, settings)
        profiles.clear(); profiles.addAll(m.profiles)
        if (m.changed) writeProfiles()
        val mirrored = RoutingProfiles.mirrorToSettings(profiles, settings)
        if (mirrored != settings) saveSettings(mirrored)
    }

    /**
     * One-time upgrade of the saved servers to the shape the current parser and
     * config builder expect (see LinkParser.migrateStoredServer). Runs once, when
     * the store is created, and writes back — so it costs one pass over the list
     * per launch at most, and every later read sees the migrated records.
     */
    private fun migrateServers() {
        if (servers.isEmpty()) return
        var changed = false
        for (i in servers.indices) {
            val m = LinkParser.migrateStoredServer(servers[i])
            // migrateStoredServer hands back the very same object when there is
            // nothing to do, so this stays false on every launch after the first.
            if (m !== servers[i]) { servers[i] = m; changed = true }
        }
        if (changed) saveServers()
    }

    fun saveServers() = prefs.edit().putString("servers", JSONArray(servers.map { it.toJson() }).toString()).apply()
    fun saveChains() = prefs.edit().putString("chains", JSONArray(chains.map { it.toJson() }).toString()).apply()
    fun savePool() = prefs.edit().putString("pool", JSONArray(pool.map { it.toJson() }).toString()).apply()
    fun saveSubs() = prefs.edit().putString("subs", JSONArray(subs.map { it.toJson() }).toString()).apply()
    fun saveSelection(sel: String) {
        previousSelection = Selection.previousAfterPick(selection, previousSelection, sel, serverIds(), chainIds(), profileIds())
        selection = sel
        writeSelection()
    }
    /**
     * The settings, with `rp-default` mirrored into routeRules / routeDefault /
     * advancedUseMode whatever copy the caller held: a screen writes back the
     * whole AppSettings it opened with, and an older copy must not put old
     * rules back under the profile's name.
     */
    fun saveSettings(sNew: AppSettings) {
        val s = RoutingProfiles.mirrorToSettings(profiles, sNew)
        settings = s; prefs.edit().putString("settings", s.toJson().toString()).apply()
    }

    /** Write the routing profiles, and `rp-default` into the settings keys (an older app and an old backup read those). */
    fun saveProfiles() {
        writeProfiles()
        val mirrored = RoutingProfiles.mirrorToSettings(profiles, settings)
        if (mirrored != settings) saveSettings(mirrored)
    }
    private fun writeProfiles() = prefs.edit().putString(RoutingProfiles.STORE_KEY, JSONArray(profiles.map { p: RoutingProfile -> p.toJson() }).toString()).apply()

    private fun writeSelection() = prefs.edit().putString("selection", selection).putString("selectionPrev", previousSelection).apply()
    private fun serverIds(): Set<String> = servers.mapTo(HashSet()) { it.id }
    private fun chainIds(): Set<String> = chains.mapTo(HashSet()) { it.id }
    private fun profileIds(): Set<String> = profiles.mapTo(HashSet()) { p: RoutingProfile -> p.id }

    /** Does the selection name something that exists (a server, a chain, the pool, a routing profile)? */
    fun selectionResolves(): Boolean = Selection.resolves(selection, serverIds(), chainIds(), profileIds())

    /**
     * Point the selection at something that exists — after a server or chain
     * is deleted, a subscription refresh has dropped the selected server, and
     * on every start. A selection that still resolves is left exactly as it is.
     * True when it moved (the caller says so).
     */
    fun repairSelection(): Boolean {
        val next = Selection.repair(selection, previousSelection, servers.map { it.id }, chains.map { it.id }, profiles.map { p: RoutingProfile -> p.id })
        if (next == selection) return false
        selection = next
        previousSelection = ""   // what it fell back from is gone, and what it fell back to is now current
        writeSelection()
        return true
    }

    /** Whether the app has asked for POST_NOTIFICATIONS yet (Android 13+; asked once, before a first connect). */
    var notifAsked: Boolean
        get() = prefs.getBoolean("notifAsked", false)
        set(v) { prefs.edit().putBoolean("notifAsked", v).apply() }

    /** The Servers screen's folded groups (ServerGroups keys), kept across restarts. */
    var collapsedGroups: Set<String>
        get() = try { ServerConfig.strList(JSONArray(prefs.getString("collapsedGroups", "[]"))).toSet() } catch (_: Exception) { emptySet() }
        set(v) { prefs.edit().putString("collapsedGroups", JSONArray(v.toList()).toString()).apply() }

    /*
     * The update notice (UpdateCheck): when GitHub last answered (0 = never),
     * the newest release it named ("v1.18.1") and that release's APK (or its
     * page), and the version "Later" was tapped on — not mentioned again.
     */
    var updateCheckedAt: Long
        get() = prefs.getLong("updateCheckedAt", 0L)
        set(v) { prefs.edit().putLong("updateCheckedAt", v).apply() }
    var updateLatest: String
        get() = prefs.getString("updateLatest", "") ?: ""
        set(v) { prefs.edit().putString("updateLatest", v).apply() }
    var updateUrl: String
        get() = prefs.getString("updateUrl", "") ?: ""
        set(v) { prefs.edit().putString("updateUrl", v).apply() }
    var updateDismissed: String
        get() = prefs.getString("updateDismissed", "") ?: ""
        set(v) { prefs.edit().putString("updateDismissed", v).apply() }

    /*
     * Mux (Mux.kt, spec §4). Kept under keys of their own, not inside
     * AppSettings: the Settings screen writes AppSettings back whole from the
     * copy it opened with, and the connect path writes verdicts meanwhile.
     */

    /** Settings → Mux: "off" (the default — also for an install that never set it) | "auto" | "on". */
    var muxMode: String
        get() = Mux.modeOf(prefs.getString("muxMode", null))
        set(v) { prefs.edit().putString("muxMode", Mux.modeOf(v)).apply() }

    /**
     * What the mux tests found, by server fingerprint (Mux.fingerprint) →
     * {ok, at, recheck?, retryAfter?} (Mux.Probe); at most 500, the oldest dropped.
     */
    var muxProbes: Map<String, Mux.Probe>
        get() = Mux.probesFromJson(prefs.getString("muxProbes", null))
        set(v) { prefs.edit().putString("muxProbes", Mux.probesToJson(Mux.capped(v))).apply() }

    /** What a test left for a server (Mux.record: ok 7 days, unsupported 1, an unclear one retried in an hour). Any thread. */
    fun rememberMux(fingerprint: String, probe: Mux.Probe) {
        synchronized(MUX_LOCK) { muxProbes = muxProbes + Pair(fingerprint, probe) }
    }

    /**
     * A muxed connection dropped: these servers' ok verdicts are kept and
     * marked for a recheck — the next connect that may test, tests them again
     * (Mux.markRecheck). Any thread.
     */
    fun markMuxRecheck(fingerprints: Collection<String>) {
        if (fingerprints.isEmpty()) return
        synchronized(MUX_LOCK) { muxProbes = Mux.markRecheck(muxProbes, fingerprints) }
    }

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
    /**
     * A chain's servers. One imported with a member this phone could not read (RouteShare's
     * `unreadable-…`) has none: a shorter chain would dial the rest straight from here.
     */
    fun chainMembers(c: ChainConfig): List<ServerConfig> =
        if (c.members.any { m: String -> m.startsWith(RouteShare.UNREADABLE_PREFIX) }) emptyList()
        else c.members.mapNotNull { serverById(it) }
    fun chainReady(c: ChainConfig) = chainMembers(c).size >= 2

    fun poolTargetValid(t: String): Boolean = when {
        t.isEmpty() -> false
        t.startsWith("chain:") -> chainById(t.substring(6))?.let { chainReady(it) } == true
        else -> serverById(t) != null
    }
    fun poolEnabledValid() = pool.filter { it.enabled && it.socksPort > 0 && poolTargetValid(it.target) }
    /** A profile the home picker offers: advanced routing is on, and it has rules or a default. */
    fun profileReady(p: RoutingProfile) = settings.advancedRouting && (p.rules.isNotEmpty() || p.def.isNotEmpty())
    fun advancedReady() = profiles.any { p: RoutingProfile -> profileReady(p) }
    fun profileById(id: String) = profiles.firstOrNull { p: RoutingProfile -> p.id == id }
    /** The profile the selection connects (`__advanced__` = the first one), or null when it names none. */
    fun selectedProfile(): RoutingProfile? = RoutingProfiles.profileIdOf(selection, profiles)?.let { id: String -> profileById(id) }

    /**
     * Does a routing target still name something the builder can dial — a
     * server, or a chain with at least one server left? direct, block, "" and
     * the legacy 'proxy' always do (ConfigBuilder's Registry.exists).
     */
    fun targetExists(t: String): Boolean = when {
        t.isEmpty() || t == "direct" || t == "block" || t == "proxy" -> true
        t.startsWith("chain:") -> chainById(t.substring(6))?.let { c: ChainConfig -> chainMembers(c).isNotEmpty() } == true
        else -> serverById(t) != null
    }

    /** A routing target in words: a server's name, "⛓ chain", Direct, Block, "⚓ Exit at the base", or what is missing. */
    fun targetLabel(t: String): String = when {
        t.isEmpty() -> "first server"
        t == "direct" -> "Direct"
        t == "block" -> "Block"
        t == "proxy" -> "Proxy (first server)"
        t == RoutingProfiles.TARGET_BASE -> "⚓ Exit at the base"
        t.startsWith("chain:") -> chainById(t.substring(6))?.let { c: ChainConfig -> "⛓ ${c.name}" } ?: "missing chain"
        else -> serverById(t)?.name ?: "missing server"
    }

    /** [t] as a target of [p]: "exit at the base" is there while [p]'s base is (no base: it is not). */
    fun targetExists(t: String, p: RoutingProfile): Boolean =
        if (t == RoutingProfiles.TARGET_BASE) p.base?.let { b: String -> targetExists(b) } == true else targetExists(t)

    /** [t] as a target of [p] in words: "exit at the base" names the base it stands for. */
    fun targetLabel(t: String, p: RoutingProfile): String {
        if (t != RoutingProfiles.TARGET_BASE) return targetLabel(t)
        val b = p.base ?: return "⚓ Exit at the base (no base)"
        return "⚓ Exit at the base (${targetLabel(b)})"
    }

    /** Replace the lists with what an import made of them (RouteShare.applyImport), and write them. */
    fun applyImported(r: RouteShare.Imported) {
        servers.clear(); servers.addAll(r.servers); saveServers()
        chains.clear(); chains.addAll(r.chains); saveChains()
        profiles.clear(); profiles.addAll(r.profiles); saveProfiles()
    }

    /** Delete a server and prune it from chains/pool; a selection that named it falls back (repairSelection). */
    fun deleteServer(id: String) {
        servers.removeAll { it.id == id }; saveServers()
        var changed = false
        for (i in chains.indices) if (chains[i].members.contains(id)) { chains[i] = chains[i].copy(members = chains[i].members.filter { it != id }); changed = true }
        if (changed) saveChains()
        repairSelection()
    }

    /** Delete a subscription with the servers it brought; a selection among them falls back. */
    fun deleteSubscription(id: String) {
        servers.removeAll { it.subId == id }; saveServers()
        subs.removeAll { it.id == id }; saveSubs()
        repairSelection()
    }

    /** Delete a chain; a selection that named it falls back. */
    fun deleteChain(id: String) {
        chains.removeAll { it.id == id }; saveChains()
        repairSelection()
    }

    fun selectionLabel(): String = when {
        selection == POOL_ID -> "🧩 Proxy Pool (${poolEnabledValid().size})"
        Selection.isAdvanced(selection) -> "🧭 " + (selectedProfile()?.name ?: "—")
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
            Selection.isAdvanced(sel) -> {
                val p = selectedProfile() ?: throw IllegalStateException("This routing profile no longer exists — pick another one")
                if (p.rules.isEmpty() && p.def.isBlank()) throw IllegalStateException("Add at least one routing rule")
                // "exit at the base" is the base itself from here on; a default there without a base,
                // or anything there when the base is gone, refuses
                val r = RoutingProfiles.planRoutes(p, servers.firstOrNull()?.id ?: "direct") { t: String -> targetExists(t) }
                ConnectionPlan.Advanced(r.rules, r.def, serversById, chainsById,
                    defVia = r.defVia, base = p.base, useMode = p.useMode, profileId = p.id)
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
        // a target through a base is not an entry; its base is (RoutingProfiles.dialTargets)
        is ConnectionPlan.Advanced -> {
            val ts = RoutingProfiles.dialTargets(plan).toSet()
            ts.mapNotNull { entryAddr(it, plan.serversById, plan.chainsById) }.distinct()
        }
    }
    private fun entryAddr(t: String, sById: Map<String, ServerConfig>, cById: Map<String, List<ServerConfig>>): String? = when {
        t.startsWith("chain:") -> cById[t.substring(6)]?.firstOrNull()?.address
        t == "direct" || t == "block" || t == "proxy" -> null
        else -> sById[t]?.address
    }

    companion object {
        const val POOL_ID = Selection.POOL
        const val ADV_ID = Selection.ADVANCED

        /** The mux verdicts' read-modify-write: the connect thread remembers, the service forgets. */
        private val MUX_LOCK = Any()

        @Volatile private var shared: Store? = null

        /**
         * The process's one store, for the UI. Work that outlives a screen — a
         * subscription fetch, ⚡ fastest — writes into the lists it started
         * with; an activity recreated meanwhile must be showing those same
         * lists, not a second copy read from disk that the next save of either
         * would overwrite.
         */
        fun get(ctx: Context): Store =
            shared ?: synchronized(this) { shared ?: Store(ctx.applicationContext).also { shared = it } }
    }
}
