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
 *  - A rule or default target "base" ([TARGET_BASE]) is the profile's own
 *    base: the traffic leaves from the base itself, and follows it when the
 *    base changes. It takes no via; a connect resolves it to the base
 *    ([resolveBaseTargets], [planRoutes]).
 */
object RoutingProfiles {
    const val VIA_INHERIT = "inherit"
    const val VIA_NONE = "none"
    /** A target that is the profile's own base — "exit at the base": traffic leaves from it, and it follows the base. */
    const val TARGET_BASE = "base"
    /** The profile today's settings became, and that they keep mirroring. */
    const val DEFAULT_ID = "rp-default"
    const val DEFAULT_NAME = "Advanced routing"
    /** The store key (SharedPreferences "irnetfree"). */
    const val STORE_KEY = "routingProfiles"
    /** A default at the base in a profile without one: there is nowhere to send everything else (main.js buildPlan). */
    const val NO_BASE = "This routing sends everything else out through its base, but it has no base — choose one under Routing."

    private val ID_RE = Regex("^[\\w-]+$")

    /** `rp-<base36 time><rand>`, matching `^[\w-]+$`. */
    fun newProfileId(): String = newId("rp")

    fun isValidId(id: String): Boolean = ID_RE.matches(id)

    /** A target that can ride on a base: anything but direct, block, "exit at the base" (it IS the base) and "not routed anywhere". */
    fun takesVia(target: String): Boolean = target.isNotBlank() && target != "direct" && target != "block" && target != TARGET_BASE

    /** A via as stored: "inherit" | "none" | a target. direct/block/proxy are no base at all; "base" is the profile's base, i.e. inherit. */
    private fun normalizeVia(v: String, emptyAs: String): String {
        val t = v.trim()
        return when {
            t.isEmpty() -> emptyAs
            t == VIA_INHERIT || t == VIA_NONE -> t
            t == TARGET_BASE -> VIA_INHERIT
            t == "direct" || t == "block" || t == "proxy" -> VIA_NONE
            else -> t
        }
    }

    /** [b] as a base: a server or a chain — never direct/block/proxy, a via word or "exit at the base" itself (null then). */
    private fun baseOrNull(b: String?): String? {
        val t = (b ?: "").trim()
        return if (t.isEmpty() || t == "direct" || t == "block" || t == "proxy" || t == VIA_NONE || t == VIA_INHERIT || t == TARGET_BASE) null else t
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
        return p.copy(
            id = p.id.trim().takeIf { id: String -> isValidId(id) } ?: newProfileId(),
            name = p.name.trim().ifEmpty { "Routing" },
            rules = rules,
            def = p.def.trim(),
            defVia = normalizeVia(p.defVia, VIA_INHERIT),
            base = baseOrNull(p.base)
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
     * target → that. direct/block never ride on anything, "exit at the base"
     * IS the base, and a target never rides on itself. null = it dials by itself.
     */
    fun effectiveVia(target: String, via: String, base: String?): String? {
        if (!takesVia(target)) return null
        val v = via.trim()
        val eff = when {
            v.isEmpty() || v == VIA_INHERIT || v == TARGET_BASE -> base?.trim()?.takeIf { b: String -> b.isNotEmpty() }
            v == VIA_NONE || v == "direct" || v == "block" || v == "proxy" -> null
            else -> v
        }
        return if (eff == null || eff == target) null else eff
    }

    fun effectiveVia(rule: RouteRule, p: RoutingProfile): String? = effectiveVia(rule.target, rule.via, p.base)
    /** The default's base. */
    fun effectiveDefVia(p: RoutingProfile): String? = effectiveVia(p.def, p.defVia, p.base)

    /** A profile's rules, default and default's via as a connect routes them ([resolveBaseTargets]). */
    data class Routes(val rules: List<RouteRule>, val def: String, val defVia: String)

    /**
     * [rules], [def] and [defVia] with "exit at the base" ([TARGET_BASE]) as
     * the [base] it stands for — the server or chain the builder, the bypass
     * and the certificate pins then see, dialled directly (via "none": it is
     * the base). Without a base they stay as they are: a target that names
     * nothing, which the builder leaves out (a rule) and [planRoutes] refuses
     * (the default). Nothing at the base → the very same list and values
     * (routingProfiles.js resolveBaseTargets).
     */
    fun resolveBaseTargets(rules: List<RouteRule>, def: String, defVia: String, base: String?): Routes {
        val b = baseOrNull(base) ?: return Routes(rules, def, defVia)
        val atBase = rules.any { r: RouteRule -> r.target == TARGET_BASE }
        val rs = if (!atBase) rules else rules.map { r: RouteRule -> if (r.target == TARGET_BASE) r.copy(target = b, via = VIA_NONE) else r }
        return if (def == TARGET_BASE) Routes(rs, b, VIA_NONE) else Routes(rs, def, defVia)
    }

    /**
     * What a connect on [p] routes (Store.buildPlan): its rules and default
     * (an empty default: [fallbackDef]) with "exit at the base" resolved. A
     * default at the base in a profile without one is refused ([NO_BASE]).
     */
    fun planRoutes(p: RoutingProfile, fallbackDef: String): Routes {
        val r = resolveBaseTargets(p.rules, p.def.ifBlank { fallbackDef }, p.defVia, p.base)
        if (r.def == TARGET_BASE) throw IllegalStateException(NO_BASE)
        return r
    }

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

    /**
     * The profile as lanes; [exists] says whether a target (server id or
     * `chain:<id>`) is still there. "Exit at the base" is there while the
     * profile has a base that is: no base, or one that is gone, marks it missing.
     */
    fun lanes(p: RoutingProfile, exists: (String) -> Boolean): List<Lane> {
        val there = { t: String -> if (t == TARGET_BASE) p.base?.let { b: String -> exists(b) } == true else exists(t) }
        val out = ArrayList<Lane>()
        p.rules.forEachIndexed { i: Int, r: RouteRule ->
            val via = effectiveVia(r, p)
            val last = out.lastOrNull()
            if (last != null && last.target == r.target && last.via == via) {
                out[out.size - 1] = last.copy(rules = last.rules + i)
            } else {
                out.add(Lane(listOf(i), r.target, via, !there(r.target), via != null && !exists(via)))
            }
        }
        val dv = effectiveDefVia(p)
        out.add(Lane(emptyList(), p.def, dv, !there(p.def), dv != null && !exists(dv)))
        return out
    }

    /** Each base once, with the lanes that ride on it, in the order they first appear. */
    fun lanesByBase(lanes: List<Lane>): List<Pair<String, List<Lane>>> {
        val out = LinkedHashMap<String, MutableList<Lane>>()
        for (l in lanes) { val v = l.via ?: continue; out.getOrPut(v) { ArrayList() }.add(l) }
        return out.entries.map { e: Map.Entry<String, MutableList<Lane>> -> Pair(e.key, e.value.toList()) }
    }
}
