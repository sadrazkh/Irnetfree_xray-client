package com.irnetfree.vpn.core

/**
 * Routing profiles and "via a base" — the desktop's src/main/routingProfiles.js
 * (docs/superpowers/specs/2026-10-09-routing-profiles-design.md §1–§3). Pure:
 * Store keeps the list, ConfigBuilder builds what it says, the JVM tests run it.
 *
 *  - A profile is one advanced routing: `{ id, name, rules, def, defVia,
 *    useMode, base }`, stored under `routingProfiles`.
 *  - The settings' routeRules / routeDefault / advancedUseMode are profile
 *    `rp-default`, both ways: an older app on the same store and an old backup
 *    still read and write them ([mirrorToSettings], [migrate]).
 *  - `__advanced__:<id>` connects that profile; plain `__advanced__` (an old
 *    selection) is the first one ([profileIdOf]).
 *  - A rule's `via` and the profile's `defVia` are "inherit" (the profile's
 *    base, when it has one), "none" (dial the target directly) or a target
 *    (a server id or `chain:<id>`) the target rides on. `direct` and `block`
 *    never take one ([effectiveVia]).
 */
object RoutingProfiles {
    const val VIA_INHERIT = "inherit"
    const val VIA_NONE = "none"
    /** The profile today's settings became, and that they keep mirroring. */
    const val DEFAULT_ID = "rp-default"
    const val DEFAULT_NAME = "Advanced routing"
    /** The store key (SharedPreferences "irnetfree"). */
    const val STORE_KEY = "routingProfiles"

    private val ID_RE = Regex("^[\\w-]+$")

    /** `rp-<base36 time><rand>`, matching `^[\w-]+$`. */
    fun newProfileId(): String = newId("rp")

    fun isValidId(id: String): Boolean = ID_RE.matches(id)

    /** A target that can ride on a base: anything but direct, block and "not routed anywhere". */
    fun takesVia(target: String): Boolean = target.isNotBlank() && target != "direct" && target != "block"

    /** A via as stored: "inherit" | "none" | a target. direct/block/proxy are no base at all. */
    private fun normalizeVia(v: String, emptyAs: String): String {
        val t = v.trim()
        return when {
            t.isEmpty() -> emptyAs
            t == VIA_INHERIT || t == VIA_NONE -> t
            t == "direct" || t == "block" || t == "proxy" -> VIA_NONE
            else -> t
        }
    }

    /**
     * A profile in the shape the rest relies on: a usable id, a name, rule
     * vias only where the target can take one (a rule's unset via stays ""),
     * defVia never empty, base null or a real target.
     */
    fun normalize(p: RoutingProfile): RoutingProfile {
        val rules = p.rules.map { r: RouteRule ->
            val target = r.target.trim()
            r.copy(
                type = r.type.trim().ifEmpty { "domain" },
                target = target,
                via = if (takesVia(target)) normalizeVia(r.via, "") else ""
            )
        }
        val b = (p.base ?: "").trim()
        val base = if (b.isEmpty() || b == "direct" || b == "block" || b == "proxy" || b == VIA_NONE || b == VIA_INHERIT) null else b
        return p.copy(
            id = p.id.trim().takeIf { id: String -> isValidId(id) } ?: newProfileId(),
            name = p.name.trim().ifEmpty { "Routing" },
            rules = rules,
            def = p.def.trim(),
            defVia = normalizeVia(p.defVia, VIA_INHERIT),
            base = base
        )
    }

    /** Today's settings as profile `rp-default`: the same rules, default and mode, no vias, no base. */
    fun profileFromSettings(s: AppSettings): RoutingProfile = normalize(RoutingProfile(
        id = DEFAULT_ID, name = DEFAULT_NAME, rules = s.routeRules, def = s.routeDefault,
        defVia = VIA_INHERIT, useMode = s.advancedUseMode, base = null
    ))

    /** What [migrate] made of the store: the profiles, and whether they need writing back. */
    data class Migration(val profiles: List<RoutingProfile>, val changed: Boolean)

    /**
     * The profiles at start. None stored yet (the first start of this version,
     * or a list emptied by hand): today's settings become `rp-default`. Stored,
     * and the settings say something else than `rp-default` — written since by
     * an older app on this store, or a restored backup — the settings win:
     * every save of this version mirrors them ([mirrorToSettings]), so a
     * difference is always somebody else's newer word.
     */
    fun migrate(stored: List<RoutingProfile>?, settings: AppSettings): Migration {
        if (stored.isNullOrEmpty()) return Migration(listOf(profileFromSettings(settings)), true)
        val i = stored.indexOfFirst { p: RoutingProfile -> p.id == DEFAULT_ID }
        if (i < 0) return Migration(stored, false)
        val p = stored[i]
        if (p.rules == settings.routeRules && p.def == settings.routeDefault && p.useMode == settings.advancedUseMode) return Migration(stored, false)
        val next = stored.toMutableList()
        next[i] = normalize(p.copy(rules = settings.routeRules, def = settings.routeDefault, useMode = settings.advancedUseMode))
        return Migration(next, true)
    }

    /** [s] with `rp-default` written into routeRules / routeDefault / advancedUseMode (unchanged when they already say it, or there is none). */
    fun mirrorToSettings(profiles: List<RoutingProfile>, s: AppSettings): AppSettings {
        val p = profiles.firstOrNull { x: RoutingProfile -> x.id == DEFAULT_ID } ?: return s
        if (s.routeRules == p.rules && s.routeDefault == p.def && s.advancedUseMode == p.useMode) return s
        return s.copy(routeRules = p.rules, routeDefault = p.def, advancedUseMode = p.useMode)
    }

    /**
     * The profile a selection connects: `__advanced__` → the first one,
     * `__advanced__:<id>` → that one while it exists; anything else → null.
     */
    fun profileIdOf(sel: String, profiles: List<RoutingProfile>): String? = when {
        sel == Selection.ADVANCED -> profiles.firstOrNull()?.id
        sel.startsWith(Selection.ADVANCED_PREFIX) -> sel.substring(Selection.ADVANCED_PREFIX.length).takeIf { id: String -> profiles.any { p: RoutingProfile -> p.id == id } }
        else -> null
    }

    /**
     * The base [target] rides on, given its [via] and the profile's [base]:
     * "inherit" (or unset) → the base when there is one; "none" → nothing; a
     * target → that. direct/block never ride on anything, and a target never
     * rides on itself. null = it dials by itself.
     */
    fun effectiveVia(target: String, via: String, base: String?): String? {
        if (!takesVia(target)) return null
        val v = via.trim()
        val eff = when {
            v.isEmpty() || v == VIA_INHERIT -> base?.trim()?.takeIf { b: String -> b.isNotEmpty() }
            v == VIA_NONE || v == "direct" || v == "block" || v == "proxy" -> null
            else -> v
        }
        return if (eff == null || eff == target) null else eff
    }

    fun effectiveVia(rule: RouteRule, p: RoutingProfile): String? = effectiveVia(rule.target, rule.via, p.base)
    /** The default's base. */
    fun effectiveDefVia(p: RoutingProfile): String? = effectiveVia(p.def, p.defVia, p.base)

    /** Every target of an advanced plan with the base it rides on (null = none): the rules in order, then the default. */
    fun routes(plan: ConnectionPlan.Advanced): List<Pair<String, String?>> =
        plan.rules.map { r: RouteRule -> Pair(r.target, effectiveVia(r.target, r.via, plan.base)) } +
            Pair(plan.def, effectiveVia(plan.def, plan.defVia, plan.base))

    /**
     * What an advanced plan dials from the phone itself, in order: a target
     * without a base, and the base of one with — a target through a base is
     * not an entry, its base is. Without vias: the rules' targets and the
     * default, exactly as before.
     */
    fun dialTargets(plan: ConnectionPlan.Advanced): List<String> = routes(plan).map { p: Pair<String, String?> -> p.second ?: p.first }

    /** The bases an advanced plan uses, each once (none without vias). */
    fun basesOf(plan: ConnectionPlan.Advanced): List<String> = routes(plan).mapNotNull { p: Pair<String, String?> -> p.second }.distinct()

    /** [name], or "name (2)", "name (3)"… — the first one [taken] does not hold. */
    fun uniqueName(name: String, taken: Collection<String>): String {
        val base = name.trim().ifEmpty { "Routing" }
        if (base !in taken) return base
        var n = 2
        while ("$base ($n)" in taken) n++
        return "$base ($n)"
    }

    /* ----------------------------- the flow list ----------------------------- */

    /**
     * One step of the flow (spec §3, Android's vertical list): consecutive
     * rules that go to the same target through the same base, where they go,
     * and what that rides on. [rules] are indexes into the profile's rules;
     * none = the default, "everything else". A missing target or base is
     * flagged with what connecting does about it.
     */
    data class Lane(
        val rules: List<Int>,
        val target: String,
        val via: String?,
        val targetMissing: Boolean,
        val viaMissing: Boolean
    ) {
        val isDefault: Boolean get() = rules.isEmpty()
    }

    /** The profile as lanes; [exists] says whether a target (server id or `chain:<id>`) is still there. */
    fun lanes(p: RoutingProfile, exists: (String) -> Boolean): List<Lane> {
        val out = ArrayList<Lane>()
        p.rules.forEachIndexed { i: Int, r: RouteRule ->
            val via = effectiveVia(r, p)
            val last = out.lastOrNull()
            if (last != null && last.target == r.target && last.via == via) {
                out[out.size - 1] = last.copy(rules = last.rules + i)
            } else {
                out.add(Lane(listOf(i), r.target, via, !exists(r.target), via != null && !exists(via)))
            }
        }
        val dv = effectiveDefVia(p)
        out.add(Lane(emptyList(), p.def, dv, !exists(p.def), dv != null && !exists(dv)))
        return out
    }

    /** Each base once, with the lanes that ride on it, in the order they first appear. */
    fun lanesByBase(lanes: List<Lane>): List<Pair<String, List<Lane>>> {
        val out = LinkedHashMap<String, MutableList<Lane>>()
        for (l in lanes) { val v = l.via ?: continue; out.getOrPut(v) { ArrayList() }.add(l) }
        return out.entries.map { e: Map.Entry<String, MutableList<Lane>> -> Pair(e.key, e.value.toList()) }
    }
}
