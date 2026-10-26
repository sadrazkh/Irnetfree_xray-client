package com.irnetfree.vpn.core

import org.json.JSONObject

/**
 * Extensions (افزونه‌ها) — the desktop's src/renderer/modules.js on Android.
 *
 * The advanced features are built into the app and stay OFF until they are
 * installed on More → Extensions; nothing is downloaded. Off means HIDDEN:
 * every screen, menu row, picker entry and editor field of the feature goes,
 * while what it already made keeps working exactly as before — a chain, a
 * group, a pool entry, a routing profile, a WARP or MASQUE server, a server's
 * ECH outbound or fragment, the LAN share that is on. Nothing here is read at
 * connect time. And the config that is SELECTED stays in the picker whatever
 * its extension, so a connection never changes by itself.
 *
 * The same ids as the desktop's registry, the ones it lists for `android`
 * (multi-internet, the router's relay and LAN users are not on a phone). The
 * installed set is kept in the store under a key of its own ([STORE_KEY]:
 * id → true); a store from before extensions existed is migrated once
 * ([migrate]): what it uses is installed, the rest is not — a fresh install
 * uses nothing, so it starts with all of them off. Pure: no android.* here.
 */
object Modules {
    const val CHAINS = "chains"
    const val GROUPS = "groups"
    const val ADVANCED_ROUTING = "advancedRouting"
    const val POOL = "pool"
    const val WARP = "warp"
    const val ECH_OUTBOUND = "echOutbound"
    const val ANTI_DPI = "antiDpi"
    const val LAN_SHARE = "lanShare"

    /** This registry's platform in the desktop's terms (its `platforms` lists). */
    const val PLATFORM = "android"

    /** Where the installed set is kept (Store's preferences file), and the mark that the one-time migration ran. */
    const val STORE_KEY = "modules"
    const val MIGRATED_KEY = "modulesMigrated"

    /** The Extensions screen's sections, in order (the desktop's categories). */
    val CATEGORIES: List<String> = listOf("connection", "routing", "network", "security")

    /**
     * One extension: its id, its icon (one emoji), its section, and the
     * extensions it needs installed first. Its words are I18nWords'
     * `mod.<id>.name`, `mod.<id>.desc` and `mod.<id>.hides` (what removing it hides).
     */
    class Module(val id: String, val icon: String, val category: String, val requires: List<String> = emptyList()) {
        val nameKey: String get() = "mod.$id.name"
        val descKey: String get() = "mod.$id.desc"
        val hidesKey: String get() = "mod.$id.hides"
    }

    val MODULES: List<Module> = listOf(
        Module(CHAINS, "⛓", "connection"),
        Module(GROUPS, "⧉", "connection"),
        Module(WARP, "☁", "connection"),
        Module(ADVANCED_ROUTING, "🧭", "routing"),
        Module(POOL, "🧩", "routing"),
        Module(LAN_SHARE, "📡", "network"),
        Module(ECH_OUTBOUND, "🔐", "security"),
        Module(ANTI_DPI, "🛡", "security")
    )

    val IDS: List<String> = MODULES.map { m: Module -> m.id }

    fun byId(id: String, registry: List<Module> = MODULES): Module? = registry.firstOrNull { m: Module -> m.id == id }

    /** Is [id] an extension of this app (the desktop's `available(id, 'android')`)? */
    fun available(id: String): Boolean = byId(id) != null

    /** The i18n key of an extension's name ("mod.<id>.name"). */
    fun nameKey(id: String): String = "mod.$id.name"

    /** Is [id] installed? Only `true` is: a store without the key, or with anything else, has it off. */
    fun isOn(modules: Map<String, Boolean>, id: String): Boolean = modules[id] == true

    /* ------------- what the store uses ------------- */

    /** What [inUseOf] counts: the store's lists, its settings, the selection and whether LAN sharing is on. */
    class Data(
        val servers: List<ServerConfig> = emptyList(),
        val groups: List<GroupConfig> = emptyList(),
        val chains: List<ChainConfig> = emptyList(),
        val pool: List<PoolEntry> = emptyList(),
        val profiles: List<RoutingProfile> = emptyList(),
        val settings: AppSettings = AppSettings(),
        val selection: String = "",
        val lanShareEnabled: Boolean = false
    )

    /**
     * How much of the store each extension holds (the desktop's inUseOf):
     * groups, chains and pool entries by number; advanced routing by its
     * profiles once it is in use at all (switched on, a profile selected, or a
     * profile besides `rp-default`); WARP by its servers (a WARP account's,
     * MASQUE's); ECH outbound by the servers whose TLS has one; anti-DPI by the
     * servers with a fragment, noise, finalmask or cipherSuites; LAN sharing 1
     * while it is on. The Extensions card says "in use: N", and a remove asks first.
     */
    fun inUseOf(d: Data): Map<String, Int> {
        val out = LinkedHashMap<String, Int>()
        out[CHAINS] = d.chains.size
        out[GROUPS] = d.groups.size
        out[ADVANCED_ROUTING] = advancedRoutingInUse(d)
        out[POOL] = d.pool.size
        out[WARP] = d.servers.count { s: ServerConfig -> isWarpServer(s) }
        out[ECH_OUTBOUND] = d.servers.count { s: ServerConfig -> hasEchOutbound(s) }
        out[ANTI_DPI] = d.servers.count { s: ServerConfig -> hasAntiDpi(s) }
        out[LAN_SHARE] = if (d.lanShareEnabled) 1 else 0
        return out
    }

    private fun advancedRoutingInUse(d: Data): Int {
        val used = d.settings.advancedRouting || Selection.isAdvanced(d.selection) ||
            d.profiles.any { p: RoutingProfile -> p.id != RoutingProfiles.DEFAULT_ID }
        return if (used) maxOf(1, d.profiles.size) else 0
    }

    /** A WARP account's server (made or imported on + WARP), or a MASQUE one — a JSON one too. */
    fun isWarpServer(s: ServerConfig): Boolean = s.warp != null || Masque.isMasque(s)

    private fun tlsOf(s: ServerConfig): JSONObject? = s.outbound.optJSONObject("streamSettings")?.optJSONObject("tlsSettings")

    /** Does the server's TLS carry PattN's ECH outbound (tlsSettings.echOutbound)? */
    fun hasEchOutbound(s: ServerConfig): Boolean {
        val tls = tlsOf(s) ?: return false
        return tls.has("echOutbound") && !tls.isNull("echOutbound")
    }

    /**
     * Does the server carry an anti-DPI value: a fragment or noise (the
     * outbound's `_fragment` / `_noise`), a finalmask, or cipherSuites?
     * Hysteria2's finalmask is its obfuscation and port hopping, which have
     * fields of their own — not this extension's.
     */
    fun hasAntiDpi(s: ServerConfig): Boolean {
        val ob = s.outbound
        if (ob.optString("_fragment", "").isNotBlank() || ob.optString("_noise", "").isNotBlank()) return true
        val hy2 = s.protocol == "hysteria2" || ob.optString("protocol") == "hysteria2"
        val fm = ob.optJSONObject("streamSettings")?.optJSONObject("finalmask")
        if (!hy2 && fm != null && fm.length() > 0) return true
        return (tlsOf(s)?.optString("cipherSuites", "") ?: "").isNotBlank()
    }

    /* ------------- installing and removing ------------- */

    /**
     * The answer to an install or a remove: the installed set after it, the
     * extensions it also installed (what [id] needs), and — for a remove that
     * is refused — the installed extensions that need it.
     */
    class SetResult(val modules: Map<String, Boolean>, val added: List<String>, val blockedBy: List<String>)

    /**
     * Install [id] (with everything it needs, in turn) or remove it. A remove
     * is refused while another installed extension needs it ([SetResult.blockedBy]);
     * one that is in use is allowed once the screen has asked — its data is
     * kept, only hidden. An id this app does not have changes nothing.
     */
    fun set(current: Map<String, Boolean>, id: String, on: Boolean, registry: List<Module> = MODULES): SetResult {
        if (byId(id, registry) == null) return SetResult(current, emptyList(), emptyList())
        if (!on) {
            val blockers = registry.filter { m: Module -> m.id != id && isOn(current, m.id) && m.requires.contains(id) }.map { m: Module -> m.id }
            if (blockers.isNotEmpty()) return SetResult(current, emptyList(), blockers)
            val out = LinkedHashMap<String, Boolean>()
            for ((k, v) in current) if (k != id && v) out[k] = true
            return SetResult(out, emptyList(), emptyList())
        }
        val out = LinkedHashMap<String, Boolean>()
        for ((k, v) in current) if (v) out[k] = true
        val added = ArrayList<String>()
        // what [id] needs, and what that needs, each once (a loop in the table cannot run away)
        val todo = ArrayList<String>()
        todo.add(id)
        val seen = HashSet<String>()
        while (todo.isNotEmpty()) {
            val x = todo.removeAt(todo.size - 1)
            if (!seen.add(x)) continue
            val m = byId(x, registry) ?: continue
            if (out[x] != true) {
                out[x] = true
                if (x != id) added.add(x)
            }
            todo.addAll(m.requires)
        }
        return SetResult(out, added, emptyList())
    }

    /**
     * The installed set a store from before extensions gets, once: every
     * extension it uses ([inUse] above zero), with what each needs; the rest off.
     */
    fun migrate(inUse: Map<String, Int>, registry: List<Module> = MODULES): Map<String, Boolean> {
        var m: Map<String, Boolean> = emptyMap()
        for (mod in registry) {
            if ((inUse[mod.id] ?: 0) > 0) m = set(m, mod.id, true, registry).modules
        }
        return m
    }

    /** The stored set read back: only this app's ids, only `true`; anything unreadable is none. */
    fun fromJson(text: String?): Map<String, Boolean> {
        val out = LinkedHashMap<String, Boolean>()
        if (text.isNullOrBlank()) return out
        try {
            val o = JSONObject(text)
            for (id in IDS) {
                if (o.optBoolean(id, false)) out[id] = true
            }
        } catch (e: Exception) {
            return LinkedHashMap()
        }
        return out
    }

    /** The set as stored: `{ "<id>": true, … }`, installed ones only. */
    fun toJson(modules: Map<String, Boolean>): String {
        val o = JSONObject()
        for ((k, v) in modules) if (v) o.put(k, true)
        return o.toString()
    }

    /* ------------- what is hidden ------------- */

    /**
     * The extension a server editor field belongs to, by the field's id (the
     * desktop's serverFields.js `module`; the Android table is generated and
     * carries none): the ECH outbound, and the anti-DPI fields. null = core.
     */
    fun fieldModule(fieldId: String): String? = when (fieldId) {
        "echOutbound" -> ECH_OUTBOUND
        "fragment", "noise", "cipherSuites", "finalMask" -> ANTI_DPI
        else -> null
    }

    /** Does the editor show field [fieldId]? A core field always; an extension's while it is installed. */
    fun fieldShown(modules: Map<String, Boolean>, fieldId: String): Boolean {
        val m = fieldModule(fieldId) ?: return true
        return isOn(modules, m)
    }

    /** The extension a selection belongs to — the pool, a routing profile, a chain, a group — or null for a server. */
    fun moduleOfSelection(sel: String): String? = when {
        sel == Selection.POOL -> POOL
        Selection.isAdvanced(sel) -> ADVANCED_ROUTING
        sel.startsWith("chain:") -> CHAINS
        Groups.isGroupId(sel) -> GROUPS
        else -> null
    }

    /**
     * Does a picker show [entry], an entry of extension [module]? While it is
     * installed — and the one [selected] always: the config in use never
     * vanishes from under the person using it.
     */
    fun pickerShows(modules: Map<String, Boolean>, module: String, entry: String, selected: String): Boolean =
        isOn(modules, module) || (entry.isNotEmpty() && entry == selected)

    /** The extensions [id] needs that are not installed: the card says "needs …". */
    fun missingRequires(modules: Map<String, Boolean>, id: String, registry: List<Module> = MODULES): List<String> =
        (byId(id, registry)?.requires ?: emptyList()).filter { r: String -> !isOn(modules, r) }
}
