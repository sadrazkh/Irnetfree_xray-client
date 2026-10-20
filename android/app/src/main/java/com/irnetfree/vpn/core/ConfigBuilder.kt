package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Builds a complete Xray config.json for Android. Ported from the desktop
 * configBuilder.js so both clients behave identically. Supports single / chain /
 * pool / advanced plans, simple routing modes, custom rules, WireGuard, the
 * managed DNS plan (DnsPlan.kt), certificate pins (CertPin.kt), groups
 * (Groups.kt — a record wherever a server goes, expanded by [expandGroups] into
 * its members, a balancer and one health check) and an optional geo-asset
 * flag (geo rules are skipped when the .dat files are absent).
 *
 * The VpnService points tun2socks at the SOCKS inbound (settings.socksPort).
 * That inbound and http-in carry the session's credentials when the caller
 * hands them in (`inboundAuth`, LocalAuth.kt): loopback is shared by every app.
 */
object ConfigBuilder {

    /**
     * Rule values separate on either `,` or `|` (the settings page writes
     * `domain, a.com|b.com, proxy`). Neither character is legal inside a domain,
     * an IP/CIDR or a port range. Kept identical to `SEPARATORS` in
     * src/main/configBuilder.js — advanced AND custom rules use it on both sides.
     */
    private val SEPARATORS = Regex("[|,]")

    private val PRIVATE_IPS = listOf(
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
        "::1/128", "fc00::/7", "fe80::/10"
    )

    /**
     * Every WireGuard peer endpoint in a plan that is a NAME rather than an
     * address, with the resolved address the caller found for it — see
     * `wgEndpointHosts`. Handed in through the settings-like `wgEndpointIps` map
     * (the desktop's `settings.wgEndpointIps`).
     *
     * `inboundAuth`: the session's username/password for socks-in and http-in
     * (the pool's own ps-/ph- ports stay open — exposing them is that feature).
     *
     * `lan`: LAN sharing (LanShare) — when enabled, two more inbounds on every
     * interface, routed by the very rules the tunnel's traffic takes; the only
     * rule of their own keeps them off the phone's loopback (lanGuardRules).
     *
     * `muxIds`: the servers whose outbounds carry Xray's mux (Mux.kt — Settings
     * → Mux, and in auto each server's own test, decided by the connect path).
     * Only a non-chain target's outbound, and only one that can carry it
     * (Mux.eligible); a chain's hops never. Empty: the config of before, byte
     * for byte.
     *
     * `groupSkip`: the group members the app has set aside for not answering
     * (GroupEvict.Evictor.skip — GroupEvict.memberKey each), left out of their
     * group unless that would leave it empty. `metricsPort`: when the config
     * runs a group, the core's metrics listener on 127.0.0.1 at this port —
     * where the app reads the groups' health check (GroupEvict.readVars); 0,
     * or no group: none.
     */
    fun build(plan: ConnectionPlan, s: AppSettings, geoAssets: Boolean = false, wgEndpointIps: Map<String, String> = emptyMap(), inboundAuth: LocalAuth? = null, lan: LanShare? = null, muxIds: Set<String> = emptySet(), groupSkip: Set<String> = emptySet(), metricsPort: Int = 0): JSONObject =
        buildWithGroups(plan, s, geoAssets, wgEndpointIps, inboundAuth, lan, muxIds, groupSkip, metricsPort).config

    /** A config, and the groups it runs ([GroupEvict.Group] — member i of group T is `T~gm<i>`; empty: none). */
    class Built(val config: JSONObject, val groups: List<GroupEvict.Group>)

    /** [build], with the groups the config runs beside it (configBuilder.js `groupTags`). */
    fun buildWithGroups(plan: ConnectionPlan, s: AppSettings, geoAssets: Boolean = false, wgEndpointIps: Map<String, String> = emptyMap(), inboundAuth: LocalAuth? = null, lan: LanShare? = null, muxIds: Set<String> = emptySet(), groupSkip: Set<String> = emptySet(), metricsPort: Int = 0): Built {
        val listen = "127.0.0.1"
        val sniffing = sniffingFor(s)
        val share = lan?.takeIf { it.enabled }

        if (plan is ConnectionPlan.Pool) return buildPool(plan, s, listen, sniffing, geoAssets, wgEndpointIps, inboundAuth, share, muxIds, groupSkip, metricsPort)
        if (plan is ConnectionPlan.Advanced) return buildAdvanced(plan, s, listen, sniffing, geoAssets, wgEndpointIps, inboundAuth, share, muxIds, groupSkip, metricsPort)

        val outbounds = JSONArray()
        // Every target the plan routes to, with its outbound tag — the resolver a
        // corporate WireGuard carries must be asked through THAT outbound.
        val targets = ArrayList<Pair<Any?, String>>()
        when (plan) {
            is ConnectionPlan.Chain -> { buildChainOutbounds(plan.members, "proxy").forEach { outbounds.put(it) }; targets.add(plan.members to "proxy") }
            is ConnectionPlan.Single -> {
                withHelpers(withMux(cloneOut(plan.server.outbound, "proxy", plan.server), plan.server, muxIds), plan.server, "proxy").forEach { o: JSONObject -> outbounds.put(o) }
                targets.add(plan.server to "proxy")
            }
            else -> {}
        }
        outbounds.put(freedom(s)).put(blackhole())

        // RULE ORDER IS LOAD-BEARING — xray applies the FIRST rule that matches.
        // The order below is exactly the one src/main/configBuilder.js builds
        // (buildRoutingRules() -> pop the catch-all -> append the custom rules ->
        // re-append the catch-all):
        //   ad-block, private-IP bypass, the routingMode geo rules, the CUSTOM
        //   rules, then the catch-all.
        // Do NOT hoist the custom rules above the geo rules: with
        // routingMode 'bypass-ir' a custom `domain, mysite.ir, proxy` MUST lose to
        // `geosite:category-ir -> direct` — that is what the desktop does, and the
        // two clients have to route the same account the same way.
        val rules = JSONArray()
        if (s.blockAds && geoAssets) rules.put(fieldRule().put("domain", JSONArray().put("geosite:category-ads-all")).put("outboundTag", "block"))
        rules.put(fieldRule().put("ip", JSONArray(PRIVATE_IPS)).put("outboundTag", "direct"))
        var catchAllTag = "proxy"
        when (s.routingMode) {
            "bypass-ir" -> if (geoAssets) modeBypassRules("bypass-ir").forEach { rules.put(it) }
            "bypass-cn" -> if (geoAssets) modeBypassRules("bypass-cn").forEach { rules.put(it) }
            "direct" -> { catchAllTag = "direct" }
        }
        addCustomRules(rules, s.customRules, geoAssets)
        rules.put(fieldRule().put("port", "0-65535").put("outboundTag", catchAllTag))
        // The resolver's exit follows the catch-all; a chain / single plan never
        // applies advanced rules, so the DNS plan sees `advancedRouting: false`.
        val dnsSettings = s.copy(advancedRouting = false)
        val inbounds = standardInbounds(s, listen, sniffing, inboundAuth)
        val lanTags = addLanInbounds(inbounds, share, sniffing, setOf(s.socksPort, s.httpPort))
        return assemble(s, inbounds, outbounds, rules,
            geoAssets, catchAllTag, dnsSettings, targetResolversFor(targets), wgEndpointIps, lanTags,
            groupSkip = groupSkip, metricsPort = metricsPort)
    }

    /**
     * The country-bypass part of a simple routing mode, on its own: what sits
     * between the private-range bypass and the catch-all. `global` and `direct`
     * contribute nothing (configBuilder.js modeBypassRules).
     */
    private fun modeBypassRules(mode: String): List<JSONObject> = when (mode) {
        "bypass-ir" -> listOf(
            fieldRule().put("domain", JSONArray().put("geosite:category-ir").put("regexp:.*\\.ir$")).put("outboundTag", "direct"),
            fieldRule().put("ip", JSONArray().put("geoip:ir")).put("outboundTag", "direct"))
        "bypass-cn" -> listOf(
            fieldRule().put("domain", JSONArray().put("geosite:cn")).put("outboundTag", "direct"),
            fieldRule().put("ip", JSONArray().put("geoip:cn")).put("outboundTag", "direct"))
        else -> emptyList()
    }

    /* ----------------------------- advanced ----------------------------- */

    /** The default carries everything no rule claims: gone, there is nothing honest to send it to (configBuilder.js). */
    const val MISSING_DEFAULT = "Advanced routing: the default target no longer exists (it was removed, or replaced by a subscription update) — choose a new default under Routing."
    /** A base a target rides on is gone: connecting through nothing would leave in the clear. */
    const val MISSING_BASE = "Advanced routing: a base this profile goes through no longer exists (a server removed or replaced by a subscription update, or a chain left empty) — choose another base under Routing."

    /**
     * A routing profile's config ("via a base", RoutingProfiles.kt). A target
     * with a via gets an outbound of its own, `out-<id>@<baseKey>` (a chain:
     * `out-chain-<cid>@<baseKey>` and its hops), whose self-dialing outbound
     * dials the base's exit; each base is one outbound group (`base-<id>`, or
     * `base-chain-<cid>` with hops `base-chain-<cid>-h<i>`), shared by every
     * target through it. Mux stays on direct server targets only. Without a
     * via anywhere, the config of before, byte for byte.
     *
     * Refuses (IllegalStateException, said to the user as it is) a default
     * that no longer exists and a base that no longer exists. A rule whose
     * target is gone is left out — its traffic follows the default, as on the
     * desktop; Android used to send it `direct` without a word.
     */
    private fun buildAdvanced(plan: ConnectionPlan.Advanced, s0: AppSettings, listen: String, sniffing: JSONObject, geo: Boolean, wgEndpointIps: Map<String, String>, auth: LocalAuth?, lan: LanShare?, muxIds: Set<String>, groupSkip: Set<String>, metricsPort: Int): Built {
        // the profile's own "routing mode under these rules"; a plan without one uses the settings'
        val um = plan.useMode
        val s = if (um != null && um != s0.advancedUseMode) s0.copy(advancedUseMode = um) else s0
        val reg = Registry(plan.serversById, plan.chainsById, muxIds, RoutingProfiles.basesOf(plan).toSet())
        if (!reg.exists(plan.def)) throw IllegalStateException(MISSING_DEFAULT)
        val defVia = RoutingProfiles.effectiveVia(plan.def, plan.defVia, plan.base)
        if (defVia != null && !reg.exists(defVia)) throw IllegalStateException(ConfigBuilder.MISSING_BASE)
        val advRules = JSONArray()
        val targets = ArrayList<Pair<Any?, String>>()
        for (r in plan.rules) {
            if (r.value.isBlank()) continue
            var vals = r.value.split(SEPARATORS).map { it.trim() }.filter { it.isNotEmpty() }
            if (vals.isEmpty()) continue

            val ruleField: String
            val ruleValue: Any
            when (r.type) {
                "ip" -> {
                    if (!geo) vals = vals.filter { !it.startsWith("geoip:", true) }
                    if (vals.isEmpty()) continue
                    ruleField = "ip"; ruleValue = JSONArray(vals)
                }
                "domain" -> {
                    if (!geo) vals = vals.filter { !it.startsWith("geosite:", true) }
                    if (vals.isEmpty()) continue
                    ruleField = "domain"; ruleValue = JSONArray(vals)
                }
                "port" -> { ruleField = "port"; ruleValue = vals.joinToString(",") }
                else -> continue
            }

            // A rule to a target that no longer exists is left out: its traffic
            // then follows the default like everything else no rule claims.
            if (!reg.exists(r.target)) continue
            // ...but a base that is gone refuses the connect: the target would
            // otherwise be dialled from here, which is what the base was for.
            val via = RoutingProfiles.effectiveVia(r.target, r.via, plan.base)
            if (via != null && !reg.exists(via)) throw IllegalStateException(ConfigBuilder.MISSING_BASE)

            // Resolve the target only once the rule is known to survive: tagFor()
            // REGISTERS the outbound(s), so doing it earlier leaves a dead outbound
            // behind for every dropped rule — writing an unused server's address and
            // credentials into the config (and materializing a whole chain for a
            // "chain:" target). Mirrors configBuilder.js.
            val tag = if (via == null) reg.tagFor(r.target) else reg.tagVia(r.target, via)
            advRules.put(fieldRule().put("outboundTag", tag).put(ruleField, ruleValue))
            targets.add(targetServer(r.target, plan) to tag)
        }
        val defTag = if (defVia == null) reg.tagFor(plan.def) else reg.tagVia(plan.def, defVia)
        targets.add(targetServer(plan.def, plan) to defTag)
        // The resolver's exit. A `block` default is a legitimate allow-list, but
        // the blackhole can never answer a DoH query: use the first proxy the
        // rules name whose tunnel can carry it — a split-tunnel WireGuard drops
        // anything outside its AllowedIPs, so DoH to 1.1.1.1 would die inside it
        // — else direct.
        val carrier = targets.firstOrNull { (srv, tag) -> tag != "direct" && tag != "block" && !isSplitTunnelWg(srv as? ServerConfig) }
        val exitTag = if (defTag != "block") defTag else (carrier?.second ?: "direct")
        reg.add(freedom(s)); reg.add(blackhole())

        // NOTE: user rules come BEFORE the private-IP bypass on purpose. This is
        // "special routing" — explicit rules must win, otherwise a database on an
        // internal range (e.g. 10.20.0.0/16) would be caught by the private bypass
        // and go direct instead of through the chosen config/chain (e.g. WireGuard).
        // `advancedUseMode`: the simple routing mode UNDER the user's rules — an
        // explicit corporate rule must still win over a country bypass.
        val rules = JSONArray()
        if (s.blockAds && geo) rules.put(fieldRule().put("domain", JSONArray().put("geosite:category-ads-all")).put("outboundTag", "block"))
        for (i in 0 until advRules.length()) rules.put(advRules.getJSONObject(i))
        rules.put(fieldRule().put("ip", JSONArray(PRIVATE_IPS)).put("outboundTag", "direct"))
        if (s.advancedUseMode && geo) modeBypassRules(s.routingMode).forEach { rules.put(it) }
        rules.put(fieldRule().put("port", "0-65535").put("outboundTag", defTag))

        val dnsSettings = s.copy(advancedRouting = true, routeRules = plan.rules)
        val inbounds = standardInbounds(s, listen, sniffing, auth)
        val lanTags = addLanInbounds(inbounds, lan, sniffing, setOf(s.socksPort, s.httpPort))
        return assemble(s, inbounds, JSONArray(reg.outs), rules,
            geo, exitTag, dnsSettings, targetResolversFor(targets), wgEndpointIps, lanTags,
            groupSkip = groupSkip, metricsPort = metricsPort)
    }

    /* ----------------------------- pool ----------------------------- */

    private fun buildPool(plan: ConnectionPlan.Pool, s: AppSettings, listen: String, sniffing: JSONObject, geo: Boolean, wgEndpointIps: Map<String, String>, auth: LocalAuth?, lan: LanShare?, muxIds: Set<String>, groupSkip: Set<String>, metricsPort: Int): Built {
        val reg = Registry(plan.serversById, plan.chainsById, muxIds)
        val inbounds = JSONArray()
        // apiPort stays reserved although this config no longer opens the
        // metrics listener on it: the settings screen still counts it as taken,
        // and the desktop's buildPoolConfig() keeps a pool entry off it too.
        val used = HashSet<Int>()
        used.add(s.apiPort)
        val perInbound = JSONArray()
        val targets = ArrayList<Pair<Any?, String>>()

        fun addInbound(tag: String, port: Int, http: Boolean, a: LocalAuth? = null): Boolean {
            if (port <= 0 || port > 65535 || !used.add(port)) return false
            inbounds.put(if (http) httpInbound(tag, port, listen, sniffing, a) else socksInbound(tag, port, listen, sniffing, a))
            return true
        }

        val primaryTag = reg.tagFor(plan.primary)
        targets.add(targetServer(plan.primary, plan) to primaryTag)
        val stdTags = ArrayList<String>()
        if (addInbound("socks-in", s.socksPort, false, auth)) stdTags.add("socks-in")
        if (addInbound("http-in", s.httpPort, true, auth)) stdTags.add("http-in")
        // LAN sharing goes where the tunnel's own traffic goes: the primary exit.
        // Its ports are claimed after the tunnel's and before the entries', so a
        // pool entry sitting on one loses it (LanShare.problem keeps them apart).
        val lanTags = addLanInbounds(inbounds, lan, sniffing, used)
        used.addAll(lanPorts(lan, lanTags))
        stdTags.addAll(lanTags)
        if (stdTags.isNotEmpty()) perInbound.put(rule(stdTags, primaryTag))

        for (e in plan.entries) {
            val tag = reg.tagFor(e.target)
            targets.add(targetServer(e.target, plan) to tag)
            val inTags = ArrayList<String>()
            if (addInbound("ps-" + e.id, e.socksPort, false)) inTags.add("ps-" + e.id)
            if (e.httpPort > 0 && addInbound("ph-" + e.id, e.httpPort, true)) inTags.add("ph-" + e.id)
            if (inTags.isNotEmpty()) perInbound.put(rule(inTags, tag))
        }

        reg.add(freedom(s)); reg.add(blackhole())
        // Private/LAN bypass first, THEN the per-inbound routing, THEN a catch-all
        // to the primary exit so nothing is ever left unrouted (configBuilder.js).
        val rules = JSONArray()
        rules.put(fieldRule().put("ip", JSONArray(PRIVATE_IPS)).put("outboundTag", "direct"))
        for (i in 0 until perInbound.length()) rules.put(perInbound.getJSONObject(i))
        rules.put(fieldRule().put("port", "0-65535").put("outboundTag", primaryTag))

        // Pool emits no bypass rules, so an in-country resolver would only hand
        // the primary exit an Iranian IP to dial from abroad — routingMode is not its.
        val dnsSettings = s.copy(advancedRouting = false, routingMode = "global")
        // IPIfNonMatch on purpose, managed DNS or not (configBuilder.js): the pool
        // has no user ip rule (only the private bypass), and on demand every
        // entry's hostname connections would wait on the PRIMARY's DoH — a dead
        // primary costing the other entries ~8 s per new name.
        return assemble(s, inbounds, JSONArray(reg.outs), rules, geo, primaryTag, dnsSettings, targetResolversFor(targets), wgEndpointIps, lanTags,
            domainStrategy = "IPIfNonMatch", groupSkip = groupSkip, metricsPort = metricsPort)
    }

    /* ----------------------------- chain / registry ----------------------------- */

    /**
     * [firstVia]: the tag the first hop dials through (a chain riding on a
     * base) — it then loses its own dialer and helpers like any later hop.
     * null: the first hop dials by itself, as always. [hopBase]: what the hops
     * are named after when not the exit (`<hopBase>-h<i>`; a group's chain
     * variants name theirs outside the group's member prefix — expandGroups);
     * null: after [exitTag].
     *
     * A chain with a group in it, in segments (configBuilder.js): the hops
     * before the group are built once and every member dials through them;
     * from the group up to (not including) the next WireGuard the chain is a
     * group of whole chains ([groupOfChains]) — one variant per member, in
     * that hop's place — a loopback tagged at the stretch's last position; a
     * WireGuard after a group is built ONCE and dials through that group's
     * loopback. Copied per variant it would be one session per copy on one
     * key, and the peer keeps only the newest handshake — every copy would cut
     * the others off. A TCP hop never dials through a group.
     */
    private fun buildChainOutbounds(members: List<ServerConfig>, exitTag: String, firstVia: String? = null, hopBase: String? = null): List<JSONObject> {
        val list = members.filter { it.outbound.length() > 0 }
        val hops = hopBase ?: exitTag
        val last = list.size - 1
        fun tagAt(i: Int): String = if (i == last) exitTag else "$hops-h$i"
        val outs = ArrayList<JSONObject>()
        var prev: String? = firstVia
        var i = 0
        while (i <= last) {
            if (last > 0 && Groups.isGroupRecord(list[i])) {
                var end = i + 1
                while (end <= last && !isWgServer(list[end])) end++
                val at = tagAt(end - 1)
                outs.add(groupOfChains(list.subList(i, end), at, prev))
                prev = at
                i = end
                continue
            }
            val tag = tagAt(i)
            val dialVia = prev
            if (dialVia != null) {
                // A server behind another hop dials through that hop; a JSON
                // server's own way to its helpers (proxySettings, its
                // dialerProxy) goes, and so do the helpers — nothing else uses them.
                outs.add(throughBase(list[i], tag, dialVia))
            } else {
                outs.addAll(withHelpers(cloneOut(list[i].outbound, tag, list[i]), list[i], tag))
            }
            prev = tag
            i++
        }
        return outs
    }

    /** At most this many variants for a chain through groups (one per combination of their members). */
    const val MAX_CHAIN_VARIANTS = 64

    /**
     * A stretch of a chain that starts with a group, as a group of whole chains
     * (configBuilder.js groupOfChains): one variant per member, the member in
     * the group's place — [G(m1, m2) → B] is G'([m1 → B], [m2 → B]), each
     * variant's first hop dialling [viaTag] (the hops before the group, or the
     * base the chain rides); two groups make every combination (at most
     * [MAX_CHAIN_VARIANTS]). A TCP hop never dials THROUGH a group: aimed at a
     * group's loopback, the next hop's dialerProxy lost the end of a response
     * now and then on both cores (the desktop's probe-group.js, 2026-10-19),
     * while a loopback as a route's target never did. Only a WireGuard does
     * ([buildChainOutbounds]), its UDP never ending with a response. The
     * variants take the first group's strategy, id and name; each is known by
     * the hops it takes from the group(s) (`at`). A group's fallback is not
     * carried into its chain variants: they fall back to the first.
     */
    private fun groupOfChains(list: List<ServerConfig>, exitTag: String, viaTag: String?): JSONObject {
        var variants: List<List<ServerConfig>> = listOf(emptyList())
        for (s in list) {
            val opts: List<ServerConfig> = if (Groups.isGroupRecord(s)) Groups.membersOf(s.outbound.optJSONObject(Groups.MARK)) else listOf(s)
            variants = variants.flatMap { v: List<ServerConfig> -> opts.map { o: ServerConfig -> v + o } }.take(MAX_CHAIN_VARIANTS)
        }
        val first = list.first { s: ServerConfig -> Groups.isGroupRecord(s) }
        val firstMark = first.outbound.optJSONObject(Groups.MARK)
        val at = JSONArray(list.indices.filter { i: Int -> Groups.isGroupRecord(list[i]) })
        val members = JSONArray()
        for (v in variants) {
            val chain = JSONArray()
            for (hop in v) chain.put(JSONObject(hop.toJson().toString()))
            members.put(JSONObject().put("chain", chain).put("at", at))
        }
        val mark = JSONObject().put("id", firstMark?.optString("id", "") ?: "").put("name", firstMark?.optString("name", "") ?: "")
            .put("strategy", Groups.strategyOf(firstMark)).put("members", members)
        val o = JSONObject().put("tag", exitTag).put("protocol", "loopback").put("settings", JSONObject())
            .put(Groups.MARK, mark)
        if (viaTag != null) o.put("streamSettings", JSONObject().put("sockopt", JSONObject().put("dialerProxy", viaTag)))
        return o
    }

    /**
     * [server]'s outbound tagged [tag], dialling through [via] (a base's exit):
     * a JSON server's own helper dialer is replaced and its helpers left out,
     * as for a chain's later hop. Never mux.
     */
    private fun throughBase(server: ServerConfig, tag: String, via: String): JSONObject {
        val ob = cloneOut(server.outbound, tag, server)
        if (server.isJson) ob.remove("proxySettings")
        dialThrough(ob, via)
        return ob
    }

    /**
     * The outbounds a pool / advanced plan routes to, each once; [muxIds] as in
     * build(). [bases]: what the plan rides on (RoutingProfiles.basesOf) — a
     * target among them that carries a WireGuard is a freedom through the
     * base's exit ([exitAtBase]): two outbounds would be two sessions on one
     * key, and the peer keeps only the newest. (configBuilder.js makeRegistry)
     */
    private class Registry(
        val serversById: Map<String, ServerConfig>,
        val chainsById: Map<String, List<ServerConfig>>,
        val muxIds: Set<String> = emptySet(),
        val bases: Set<String> = emptySet()
    ) {
        val outs = ArrayList<JSONObject>()
        private val seen = HashSet<String>()
        fun add(o: JSONObject) { val t = o.optString("tag"); if (t.isNotEmpty() && seen.add(t)) outs.add(o) }

        /** The servers [target] dials: a server, a chain's members. */
        private fun members(target: String): List<ServerConfig> {
            if (target.startsWith("chain:")) return chainsById[target.substring(6)] ?: emptyList()
            val s = serversById[target]
            return if (s == null) emptyList() else listOf(s)
        }

        /**
         * A base with a group in it (a group, or a chain with one) has no
         * outbound of its own to share ([groupBaseHops]), so a target that is
         * also such a base is built as itself.
         */
        private fun sharesBase(target: String): Boolean =
            bases.contains(target) && groupBaseHops(target) == null &&
                members(target).any { m: ServerConfig -> m.outbound.length() > 0 && ConfigBuilder.isWgServer(m) }

        /**
         * The hops of a base [via] that holds a group — a group, or a chain
         * with one in it — or null for an ordinary base. Such a base registers
         * nothing: nothing may dial through a group, so each target through it
         * is a chain [base hops → target] of its own, a group of whole chains
         * (configBuilder.js baseOf → `{ group }`, tagThrough).
         */
        private fun groupBaseHops(via: String): List<ServerConfig>? {
            val hops = if (via.startsWith("chain:")) (chainsById[via.substring(6)] ?: emptyList()) else listOfNotNull(serversById[via])
            val list = hops.filter { s: ServerConfig -> s.outbound.length() > 0 }
            return if (list.any { s: ServerConfig -> Groups.isGroupRecord(s) }) list else null
        }

        /** [target] is its own base's WireGuard: a freedom out through the base's exit, its own [tag] kept. */
        private fun exitAtBase(target: String, tag: String): String {
            val exit = baseTag(target)
            if (!seen.contains(tag)) {
                add(JSONObject().put("tag", tag).put("protocol", "freedom").put("settings", JSONObject())
                    .put("streamSettings", JSONObject().put("sockopt", JSONObject().put("dialerProxy", exit))))
            }
            return tag
        }

        private fun chainTag(list: List<ServerConfig>?, tag: String): String {
            val arr = list?.filter { it.outbound.length() > 0 } ?: emptyList()
            return when {
                arr.size >= 2 -> { ConfigBuilder.buildChainOutbounds(arr, tag).forEach { add(it) }; tag }
                arr.size == 1 -> { ConfigBuilder.withHelpers(ConfigBuilder.cloneOut(arr[0].outbound, tag, arr[0]), arr[0], tag).forEach { o: JSONObject -> add(o) }; tag }
                else -> "direct"
            }
        }

        fun tagFor(target: String?): String {
            if (target.isNullOrEmpty() || target == "direct") return "direct"
            if (target == "proxy") return proxyFallback()
            if (target == "block") return "block"
            if (target.startsWith("chain:")) {
                val tag = "out-chain-" + target.substring(6)
                return if (sharesBase(target)) exitAtBase(target, tag) else chainTag(chainsById[target.substring(6)], tag)
            }
            val s = serversById[target]
            if (s != null && s.outbound.length() > 0 && sharesBase(target)) return exitAtBase(target, "out-$target")
            if (s != null && s.outbound.length() > 0) {
                val tag = "out-$target"
                ConfigBuilder.withHelpers(ConfigBuilder.withMux(ConfigBuilder.cloneOut(s.outbound, tag, s), s, muxIds), s, tag).forEach { o: JSONObject -> add(o) }
                return tag
            }
            return "direct"
        }

        // in advanced/custom rules a literal 'proxy' target uses the first server
        private fun proxyFallback(): String {
            val first = serversById.values.firstOrNull { it.outbound.length() > 0 } ?: return "direct"
            val tag = "out-proxy"
            if (!seen.contains(tag)) {
                ConfigBuilder.withHelpers(ConfigBuilder.withMux(ConfigBuilder.cloneOut(first.outbound, tag, first), first, muxIds), first, tag).forEach { o: JSONObject -> add(o) }
            }
            return tag
        }

        /**
         * Does the target still name something? A server deleted (or replaced
         * by a subscription refresh), a chain removed or left with no members:
         * tagFor() would send that `direct`. An empty target is the user's own
         * "not routed anywhere"; a literal 'proxy' is whichever server is first
         * (direct with none at all, as it always was). (configBuilder.js exists)
         */
        fun exists(target: String?): Boolean {
            if (target.isNullOrEmpty() || target == "direct" || target == "block" || target == "proxy") return true
            if (target.startsWith("chain:")) return (chainsById[target.substring(6)]?.count { it.outbound.length() > 0 } ?: 0) > 0
            val s = serversById[target]
            return s != null && s.outbound.length() > 0
        }

        /** `<baseKey>`: the base's server id, or `chain-<cid>`. */
        private fun baseKey(via: String): String = if (via.startsWith("chain:")) "chain-" + via.substring(6) else via

        /**
         * The base [via]'s outbound group, registered once and shared by every
         * target through it; its exit tag. A server: `base-<id>` (a JSON
         * server with its helpers). A chain: hops `base-chain-<cid>-h<i>`, exit
         * `base-chain-<cid>`. Never mux. A base that is gone refuses.
         */
        fun baseTag(via: String): String {
            if (via.startsWith("chain:")) {
                val cid = via.substring(6)
                val tag = "base-chain-$cid"
                val arr = chainsById[cid]?.filter { it.outbound.length() > 0 } ?: emptyList()
                if (arr.isEmpty()) throw IllegalStateException(ConfigBuilder.MISSING_BASE)
                if (!seen.contains(tag)) ConfigBuilder.buildChainOutbounds(arr, tag).forEach { o: JSONObject -> add(o) }
                return tag
            }
            val s = serversById[via]
            if (s == null || s.outbound.length() == 0) throw IllegalStateException(ConfigBuilder.MISSING_BASE)
            val tag = "base-$via"
            if (!seen.contains(tag)) ConfigBuilder.withHelpers(ConfigBuilder.cloneOut(s.outbound, tag, s), s, tag).forEach { o: JSONObject -> add(o) }
            return tag
        }

        /**
         * [target] riding on the base [via]: `out-<id>@<baseKey>` (a chain:
         * `out-chain-<cid>@<baseKey>` with hops `…-h<i>`), its self-dialing
         * outbound — the server's own, the chain's first hop — dialling the
         * base's exit. The same target without a via keeps its own `out-<id>`.
         * A base with a group in it registers nothing ([groupBaseHops]): the
         * target is the chain [base hops → target], `out-<id>@<baseKey>` (a
         * chain: `out-chain-<cid>@<baseKey>`) — a group of whole chains.
         */
        fun tagVia(target: String, via: String): String {
            val key = baseKey(via)
            val groupHops = groupBaseHops(via)
            if (groupHops != null) {
                val name = if (target.startsWith("chain:")) "out-chain-" + target.substring(6) else "out-$target"
                val rest: List<ServerConfig> = if (target == "proxy") listOfNotNull(serversById.values.firstOrNull { s: ServerConfig -> s.outbound.length() > 0 }) else members(target)
                return chainTag(groupHops + rest, "$name@$key")
            }
            val exit = baseTag(via)
            if (target.startsWith("chain:")) {
                val cid = target.substring(6)
                val arr = chainsById[cid]?.filter { it.outbound.length() > 0 } ?: emptyList()
                if (arr.isEmpty()) return "direct"   // exists() has said otherwise already
                val tag = "out-chain-$cid@$key"
                if (!seen.contains(tag)) ConfigBuilder.buildChainOutbounds(arr, tag, exit).forEach { o: JSONObject -> add(o) }
                return tag
            }
            val s = if (target == "proxy") serversById.values.firstOrNull { it.outbound.length() > 0 } else serversById[target]
            if (s == null || s.outbound.length() == 0) return "direct"
            val tag = "out-$target@$key"
            if (!seen.contains(tag)) add(ConfigBuilder.throughBase(s, tag, exit))
            return tag
        }
    }

    /* ----------------------------- WireGuard targets ----------------------------- */

    /** Is this record a WireGuard config? The OUTBOUND is the truth (configBuilder.isWgServer). */
    fun isWgServer(server: ServerConfig?): Boolean =
        server != null && (server.protocol == "wireguard" || server.outbound.optString("protocol") == "wireguard")

    /** A WireGuard whose AllowedIPs is not the whole internet: it carries only those ranges. */
    fun isSplitTunnelWg(server: ServerConfig?): Boolean {
        if (!isWgServer(server)) return false
        val peer = server!!.outbound.optJSONObject("settings")?.optJSONArray("peers")?.optJSONObject(0)
        val allowed = jarr(peer?.optJSONArray("allowedIPs")).map { it.trim() }.filter { it.isNotEmpty() }
        return allowed.isNotEmpty() && allowed.none { it.endsWith("/0") }
    }

    /**
     * Resolvers a routing target brings with it. A WireGuard server that names a
     * DNS in its config (a corporate VPN) can resolve names nobody else knows —
     * but only when asked THROUGH that tunnel. A chain contributes its last hop.
     */
    fun wgResolvers(server: ServerConfig?, outboundTag: String): List<DnsPlan.TargetResolver> {
        if (!isWgServer(server) || server!!.dns.isEmpty()) return emptyList()
        val peer = server.outbound.optJSONObject("settings")?.optJSONArray("peers")?.optJSONObject(0)
        // AllowedIPs minus the full-tunnel entries; empty → any answer is acceptable
        val expectedIPs = jarr(peer?.optJSONArray("allowedIPs")).map { it.trim() }.filter { it.isNotEmpty() && !it.endsWith("/0") }
        val domains = server.dnsDomains.map { it.trim().trimStart('.') }.filter { it.isNotEmpty() }.map { "domain:$it" }
        return server.dns.take(2).map { DnsPlan.TargetResolver(it, outboundTag, expectedIPs, domains) }
    }

    /**
     * The server a routing target ends at: a chain's last hop, a server looked up
     * by id, or the server object / member list itself. `direct`, `block` and an
     * unknown target end nowhere.
     */
    private fun targetServer(target: String?, plan: ConnectionPlan): ServerConfig? {
        fun last(list: List<ServerConfig>?) = list?.lastOrNull { it.outbound.length() > 0 }
        if (target.isNullOrEmpty() || target == "direct" || target == "block") return null
        val sById: Map<String, ServerConfig>; val cById: Map<String, List<ServerConfig>>
        when (plan) {
            is ConnectionPlan.Advanced -> { sById = plan.serversById; cById = plan.chainsById }
            is ConnectionPlan.Pool -> { sById = plan.serversById; cById = plan.chainsById }
            else -> return null
        }
        if (target.startsWith("chain:")) return last(cById[target.substring(6)])
        // a literal 'proxy' target is the first server (Registry.proxyFallback)
        if (target == "proxy") return sById.values.firstOrNull { it.outbound.length() > 0 }
        return sById[target]
    }

    /**
     * The target resolvers for `targets` = [(server or member list, tag)]: every
     * outbound the plan routes to, with the tag its outbound already got.
     * Deduplicated by resolver address: first entry wins, except that a chain to
     * the resolver beats a direct dial (configBuilder.targetResolversFor).
     */
    private fun targetResolversFor(targets: List<Pair<Any?, String>>): List<DnsPlan.TargetResolver> {
        val out = ArrayList<DnsPlan.TargetResolver>()
        val at = HashMap<String, Int>()
        fun viaChain(tag: String) = tag.startsWith("out-chain")
        for ((who, tag) in targets) {
            val server: ServerConfig? = when (who) {
                is ServerConfig -> who
                is List<*> -> who.filterIsInstance<ServerConfig>().lastOrNull { it.outbound.length() > 0 }
                else -> null
            }
            for (r in wgResolvers(server, tag)) {
                val i = at[r.address]
                if (i == null) { at[r.address] = out.size; out.add(r); continue }
                if (viaChain(r.outboundTag) && !viaChain(out[i].outboundTag)) out[i] = r
            }
        }
        // A single/chain plan carries its members as the list; `plan` is only
        // needed for the target-string forms above.
        return out
    }

    /**
     * The WireGuard peer endpoints in a plan that are names rather than
     * addresses. They have to be resolved before the config is written: a core
     * that has to resolve the endpoint itself and fails takes the whole process
     * down with it (`close of closed channel` in proxy/wireguard — the desktop's
     * v1.7.3). The VpnService resolves them through TrustedDns and hands the map
     * to build() as `wgEndpointIps`.
     */
    fun wgEndpointHosts(plan: ConnectionPlan): List<String> {
        val out = ArrayList<String>()
        fun visitOut(o: JSONObject) {
            if (o.optString("protocol") != "wireguard") return
            val peers = o.optJSONObject("settings")?.optJSONArray("peers") ?: return
            for (i in 0 until peers.length()) {
                val ep = splitEndpoint(peers.optJSONObject(i)?.optString("endpoint")) ?: continue
                if (!DnsPlan.isIp(ep.first) && ep.first !in out) out.add(ep.first)
            }
        }
        // a JSON server's helpers dial too (a WireGuard hop of its own); a group stands for its members
        fun visit(rec: ServerConfig?) {
            for (s in Groups.serversOf(rec)) {
                visitOut(s.outbound)
                if (s.isJson) s.extraOutbounds.forEach { h: JSONObject -> visitOut(h) }
            }
        }
        when (plan) {
            is ConnectionPlan.Single -> visit(plan.server)
            is ConnectionPlan.Chain -> plan.members.forEach { visit(it) }
            is ConnectionPlan.Pool -> { plan.serversById.values.forEach { visit(it) }; plan.chainsById.values.forEach { l -> l.forEach { visit(it) } } }
            is ConnectionPlan.Advanced -> { plan.serversById.values.forEach { visit(it) }; plan.chainsById.values.forEach { l -> l.forEach { visit(it) } } }
        }
        return out
    }

    /**
     * Every resolver the WireGuard servers in a plan bring with them, whether or
     * not this config ends up using them — what the connect path names when
     * managed DNS is off and these are silently absent.
     */
    fun wgResolverAddresses(plan: ConnectionPlan): List<String> {
        val out = ArrayList<String>()
        // a group stands for its members
        fun visit(rec: ServerConfig?) {
            for (s in Groups.serversOf(rec)) if (isWgServer(s)) for (d in s.dns) if (d.isNotBlank() && d !in out) out.add(d)
        }
        when (plan) {
            is ConnectionPlan.Single -> visit(plan.server)
            is ConnectionPlan.Chain -> plan.members.forEach { visit(it) }
            is ConnectionPlan.Pool -> { plan.serversById.values.forEach { visit(it) }; plan.chainsById.values.forEach { l -> l.forEach { visit(it) } } }
            is ConnectionPlan.Advanced -> { plan.serversById.values.forEach { visit(it) }; plan.chainsById.values.forEach { l -> l.forEach { visit(it) } } }
        }
        return out
    }

    /** "host:port" / "[v6]:port" → host to port; anything else → null. */
    private fun splitEndpoint(ep: String?): Pair<String, String>? {
        val e = (ep ?: "").trim()
        Regex("^\\[([^\\]]+)\\]:(\\d{1,5})$").find(e)?.let { return it.groupValues[1] to it.groupValues[2] }
        Regex("^([^:]+):(\\d{1,5})$").find(e)?.let { return it.groupValues[1] to it.groupValues[2] }
        return null
    }

    /** Put the resolved address in the peer's endpoint, keeping its port. */
    private fun applyWgEndpointIps(o: JSONObject, map: Map<String, String>) {
        if (o.optString("protocol") != "wireguard" || map.isEmpty()) return
        val peers = o.optJSONObject("settings")?.optJSONArray("peers") ?: return
        for (i in 0 until peers.length()) {
            val p = peers.optJSONObject(i) ?: continue
            val ep = splitEndpoint(p.optString("endpoint")) ?: continue
            val ip = map[ep.first] ?: continue
            p.put("endpoint", (if (ip.contains(":")) "[$ip]" else ip) + ":" + ep.second)
        }
    }

    /* ----------------------------- shared bits ----------------------------- */

    private fun addCustomRules(rules: JSONArray, custom: List<RouteRule>, geo: Boolean) {
        for (r in custom) {
            if (r.value.isBlank() || r.target.isBlank()) continue
            var vals = r.value.split(SEPARATORS).map { it.trim() }.filter { it.isNotEmpty() }
            val rule = fieldRule().put("outboundTag", r.target)
            when (r.type) {
                "domain" -> { if (!geo) vals = vals.filter { !it.startsWith("geosite:", true) }; if (vals.isEmpty()) continue; rule.put("domain", JSONArray(vals)) }
                "ip" -> { if (!geo) vals = vals.filter { !it.startsWith("geoip:", true) }; if (vals.isEmpty()) continue; rule.put("ip", JSONArray(vals)) }
                "port" -> rule.put("port", vals.joinToString(","))
                else -> continue
            }
            rules.put(rule)
        }
    }

    private fun standardInbounds(s: AppSettings, listen: String, sniffing: JSONObject, auth: LocalAuth?): JSONArray = JSONArray()
        .put(socksInbound("socks-in", s.socksPort, listen, sniffing, auth))
        .put(httpInbound("http-in", s.httpPort, listen, sniffing, auth))

    /** A local SOCKS inbound; with [auth], only for whoever presents it (hev, the app's own clients). */
    private fun socksInbound(tag: String, port: Int, listen: String, sniffing: JSONObject, auth: LocalAuth?): JSONObject {
        val settings = if (auth == null) JSONObject().put("auth", "noauth")
            else JSONObject().put("auth", "password").put("accounts", JSONArray().put(JSONObject().put("user", auth.user).put("pass", auth.pass)))
        return JSONObject().put("tag", tag).put("port", port).put("listen", listen)
            .put("protocol", "socks").put("settings", settings.put("udp", true)).put("sniffing", sniffing)
    }

    private fun httpInbound(tag: String, port: Int, listen: String, sniffing: JSONObject, auth: LocalAuth?): JSONObject {
        val settings = JSONObject()
        if (auth != null) settings.put("accounts", JSONArray().put(JSONObject().put("user", auth.user).put("pass", auth.pass)))
        return JSONObject().put("tag", tag).put("port", port).put("listen", listen)
            .put("protocol", "http").put("settings", settings).put("sniffing", sniffing)
    }

    /**
     * LAN sharing's two inbounds (LanShare): on every interface, with the
     * share's own credentials when it asks for them, sniffing like the tunnel's.
     * A port already [taken] by this config is skipped rather than written
     * twice — a config the core would refuse whole. The tags that went in.
     */
    private fun addLanInbounds(inbounds: JSONArray, lan: LanShare?, sniffing: JSONObject, taken: Set<Int>): List<String> {
        if (lan == null || !lan.enabled) return emptyList()
        val a = if (lan.auth) LocalAuth(lan.user, lan.pass) else null
        val tags = ArrayList<String>()
        if (lan.socksPort !in taken) { inbounds.put(socksInbound(LanShare.SOCKS_TAG, lan.socksPort, LanShare.LISTEN, sniffing, a)); tags.add(LanShare.SOCKS_TAG) }
        if (lan.httpPort !in taken && lan.httpPort != lan.socksPort) { inbounds.put(httpInbound(LanShare.HTTP_TAG, lan.httpPort, LanShare.LISTEN, sniffing, a)); tags.add(LanShare.HTTP_TAG) }
        return tags
    }

    private fun lanPorts(lan: LanShare?, tags: List<String>): List<Int> = if (lan == null) emptyList() else buildList {
        if (LanShare.SOCKS_TAG in tags) add(lan.socksPort)
        if (LanShare.HTTP_TAG in tags) add(lan.httpPort)
    }

    /** The phone's own loopback, as a destination. */
    val LOOPBACK = listOf("127.0.0.0/8", "0.0.0.0/8", "::1/128")

    /**
     * The one routing difference LAN sharing has from the tunnel: nothing that
     * comes in from the network reaches the PHONE's own loopback — the tunnel's
     * inbounds, the pool's open ports, other apps' local servers. The tunnel's
     * traffic cannot get there either (loopback never enters the TUN); through
     * the proxy it would, since private ranges go direct. First of all rules.
     */
    private fun lanGuardRules(tags: List<String>): List<JSONObject> = if (tags.isEmpty()) emptyList() else listOf(
        fieldRule().put("inboundTag", JSONArray(tags)).put("ip", JSONArray(LOOPBACK)).put("outboundTag", "block"),
        fieldRule().put("inboundTag", JSONArray(tags)).put("domain", JSONArray().put("domain:localhost")).put("outboundTag", "block"))

    // No metrics listener (the desktop's GET /debug/vars on apiPort) for the
    // traffic figures — they come from hev — since it answers any app on
    // 127.0.0.1 with this tunnel's outbound tags and byte counts. Only a config
    // that runs a group opens one ([assemble]'s metricsPort, a port picked free
    // at connect): the groups' health check is read there (GroupEvict).

    /**
     * What a WireGuard peer in the CONFIG may carry: everything. `allowedIPs` is
     * not a firewall, it only says what this outbound may carry, and what reaches
     * it is decided by the routing rules — which are built from the very same
     * ranges. The stored record keeps them, so the resolver's expectedIPs and the
     * split-tunnel check are unaffected. (configBuilder.widenWgAllowedIps)
     */
    private fun widenWgAllowedIps(o: JSONObject) {
        if (o.optString("protocol") != "wireguard") return
        val peers = o.optJSONObject("settings")?.optJSONArray("peers") ?: return
        for (i in 0 until peers.length()) peers.optJSONObject(i)?.put("allowedIPs", JSONArray().put("0.0.0.0/0").put("::/0"))
    }

    /** Fix any WireGuard interface address that isn't /32 (/128). */
    private fun sanitizeWgAddress(o: JSONObject) {
        if (o.optString("protocol") != "wireguard") return
        val settings = o.optJSONObject("settings") ?: return
        val addr = settings.optJSONArray("address") ?: return
        val fixed = JSONArray()
        for (j in 0 until addr.length()) {
            val a = addr.getString(j).trim()
            if (a.isEmpty()) continue
            val v6 = a.contains(":")
            val host = if (a.indexOf('/') == -1) a else a.substring(0, a.indexOf('/'))
            fixed.put(host + if (v6) "/128" else "/32")
        }
        settings.put("address", fixed)
    }

    /**
     * allowInsecure is gone from the core (it rejects the key at config load,
     * true or false is irrelevant — the value `true` is what every share link
     * carries): never emit it. A record that learnt its server's certificate on
     * first use (CertPin.kt) pins it instead — the core then accepts that
     * certificate and no other; without a pin it verifies the chain as usual and
     * its own error is the user's signal. (configBuilder.applyCertPin)
     */
    private fun applyCertPin(o: JSONObject, server: ServerConfig?) {
        val tls = o.optJSONObject("streamSettings")?.optJSONObject("tlsSettings") ?: return
        tls.remove("allowInsecure")
        // The link's own pins (`pcs`) and the one learnt on first use, together:
        // the core accepts a certificate that matches any of them.
        val pins = (tls.optString("pinnedPeerCertSha256").split(",") + listOf(server?.certPin ?: ""))
            .map { CertPin.normalizePin(it) }.filter { it.isNotEmpty() }.distinct()
        if (pins.isNotEmpty()) tls.put("pinnedPeerCertSha256", pins.joinToString(",")) else tls.remove("pinnedPeerCertSha256")
    }

    /**
     * [domainStrategy]: the router's; null = IPOnDemand under managed DNS, IPIfNonMatch without it (a pool always sets its own).
     * [groupSkip], [metricsPort]: as in [build].
     */
    private fun assemble(
        s: AppSettings, inbounds: JSONArray, outboundsIn: JSONArray, rules: JSONArray,
        geoAssets: Boolean, exitTag: String, dnsSettings: AppSettings,
        targetResolvers: List<DnsPlan.TargetResolver>, wgEndpointIps: Map<String, String>,
        lanTags: List<String> = emptyList(), domainStrategy: String? = null,
        groupSkip: Set<String> = emptySet(), metricsPort: Int = 0
    ): Built {
        // Name resolution (see DnsPlan.kt). Its rules go FIRST: the port-53 hijack
        // must beat the private-IP bypass, or a query to the tunnel resolver would
        // be sent "direct" into nowhere instead of being answered. Only LAN
        // sharing's loopback guard comes before them (it matches nothing else).
        val plan = DnsPlan.build(dnsSettings, geoAssets, exitTag, targetResolvers)
        plan.hijackOutbound?.let { outboundsIn.put(it) }
        // Groups (Groups.kt): their members, balancers, rules and health check —
        // expanded here, before every pass below, so the members get them all
        // (configBuilder.js expandGroups). A group's rule comes FIRST of all:
        // what loops back must meet its balancer before any other rule. A
        // member the app has set aside for not answering stays out (GroupEvict).
        val grp = expandGroups(outboundsIn, groupSkip)
        val allRules = JSONArray()
        grp.rules.forEach { r: JSONObject -> allRules.put(r) }
        lanGuardRules(lanTags).forEach { allRules.put(it) }
        plan.rules.forEach { allRules.put(it) }
        for (i in 0 until rules.length()) allRules.put(rules.getJSONObject(i))

        for (i in 0 until grp.outbounds.length()) {
            val o = grp.outbounds.getJSONObject(i)
            widenWgAllowedIps(o); sanitizeWgAddress(o); applyWgEndpointIps(o, wgEndpointIps)
        }
        val outbounds = applyEchOutbounds(applyFragments(grp.outbounds))
        // xray resolves a hostname destination under IPIfNonMatch only when NO
        // rule matched on the first pass — and every plan ends with a catch-all
        // that always matches — so an `ip:` rule never fires for a name. With
        // managed DNS the router asks the plan's own resolver on demand — except
        // in a pool, which has no ip rule of the user's to serve (buildPool).
        val routing = JSONObject().put("domainStrategy", domainStrategy ?: if (s.dnsManaged) "IPOnDemand" else "IPIfNonMatch").put("rules", allRules)
        if (grp.balancers.length() > 0) routing.put("balancers", grp.balancers)

        // No `bufferSize: 0` for a chained WireGuard any more (Xray-core #2850):
        // level 0 is every connection of the config, and a pipe allowed to hold
        // nothing made the whole plan run lock-stepped. Both cores carry the
        // chained WireGuard with the default buffer now (desktop v1.7.2).
        val level0 = JSONObject().put("statsUserUplink", true).put("statsUserDownlink", true)
        val config = JSONObject()
            .put("log", JSONObject().put("loglevel", s.logLevel))
            // stats + policy: the core's own counters, the desktop's shape. Nothing on
            // Android reads them now — the traffic figures come from hev
            // (TProxyGetStats), and XrayCore.queryTraffic, which could, is never called.
            .put("stats", JSONObject())
            .put("policy", JSONObject()
                .put("levels", JSONObject().put("0", level0))
                .put("system", JSONObject().put("statsInboundUplink", true).put("statsInboundDownlink", true)
                    .put("statsOutboundUplink", true).put("statsOutboundDownlink", true)))
            .put("dns", plan.dns)
            .put("inbounds", inbounds)
            .put("outbounds", outbounds)
            .put("routing", routing)
        // one health check for every group's members; none without a group
        grp.observatory?.let { ob: JSONObject -> config.put("observatory", ob) }
        // ...and where the app reads it (GET /debug/vars): only with a group, on loopback
        if (grp.balancers.length() > 0 && metricsPort in 1..65535)
            config.put("metrics", JSONObject().put("tag", "metrics").put("listen", "127.0.0.1:$metricsPort"))
        return Built(config, grp.map)
    }

    /* ----------------------------- groups ----------------------------- */

    /** How a group's health check asks: the page every ping here asks, every 30 s, all members at once. */
    private const val GROUP_PROBE_URL = "http://cp.cloudflare.com/"
    private const val GROUP_PROBE_INTERVAL = "30s"

    /**
     * What [expandGroups] made of an outbound list. [observatory]: null when
     * there is no group. [map]: each group in the config — who `T~gm<i>` is,
     * and which members the app could test on its own (GroupEvict.Group).
     */
    class GroupParts(val outbounds: JSONArray, val rules: List<JSONObject>, val balancers: JSONArray, val observatory: JSONObject?, val map: List<GroupEvict.Group> = emptyList())

    /**
     * Groups (Groups.kt): every outbound a group record became — a `loopback`
     * marked `_group`, tagged T wherever the plan put it (the selection, a
     * rule's target, a base, a chain's hop) — expanded into what the core runs
     * (configBuilder.js expandGroups):
     *  - its members `T~gm<i>`, each dialling through T's own dialerProxy when
     *    the group rides one (a target through a server base) — the loopback
     *    itself dials nothing; a JSON member's helpers are `T~gh<i>~<tag>`,
     *    outside the balancer's prefix; a chain variant ([groupOfChains]) has
     *    its exit as `T~gm<i>` and its hops `T~gh<i>-h<j>`, its first hop
     *    dialling T's via;
     *  - its fallback, when the group names one (Groups.fallbackOf), as `T~fb`
     *    (its helpers `T~fh~<tag>`), dialling like a member — outside the
     *    prefix, so never probed and never picked while a member answers;
     *  - T itself: `{ protocol: loopback, settings: { inboundTag: 'T~in' } }` —
     *    what is routed to T comes back in on T~in;
     *  - the balancer `T~bal` over the `T~gm` prefix, its fallback `T~fb` or
     *    else the first member: Xray's roundRobin and random leave out a member
     *    the health check found dead only when a fallback is set;
     *  - the rule T~in → T~bal, which the caller puts FIRST in routing: what
     *    loops back must meet its balancer before any other rule — a hop to a
     *    bridge in Iran, say, before `geoip:ir → direct`;
     *  - one observatory over every group's members.
     * [skip]: the member keys (GroupEvict.memberKey) the app has set aside —
     * left out, unless that would leave the group empty.
     * Without a group: the very same list, no rule, no balancer, no observatory.
     */
    internal fun expandGroups(outbounds: JSONArray, skip: Set<String> = emptySet()): GroupParts {
        val out = JSONArray()
        val rules = ArrayList<JSONObject>()
        val balancers = JSONArray()
        val subjects = JSONArray()
        val map = ArrayList<GroupEvict.Group>()
        for (i in 0 until outbounds.length()) {
            val o = outbounds.optJSONObject(i) ?: continue
            val mark: JSONObject? = if (o.optString("protocol") == "loopback") o.optJSONObject(Groups.MARK) else null
            if (mark == null) { out.put(o); continue }
            val t = o.optString("tag")
            val via = o.optJSONObject("streamSettings")?.optJSONObject("sockopt")?.let { so: JSONObject ->
                if (so.isNull("dialerProxy")) "" else so.opt("dialerProxy").toString()
            } ?: ""
            val gid = if (mark.isNull("id")) "" else mark.optString("id", "")
            out.put(JSONObject().put("tag", t).put("protocol", "loopback").put("settings", JSONObject().put("inboundTag", "$t~in")))
            val all = Groups.entriesOf(mark)
            val kept = if (skip.isEmpty()) all else all.filter { m: Groups.Member -> GroupEvict.memberKey(gid, whoOf(m)) !in skip }
            val members = if (kept.isNotEmpty()) kept else all
            for ((idx, m) in members.withIndex()) {
                val tag = "$t~gm$idx"
                // a chain variant (groupOfChains): its exit is the member, its hops `T~gh<i>-h<j>`,
                // its first hop dialling T's via when the group rides one
                val chain = m.chain
                if (chain != null) {
                    val firstVia: String? = if (via.isEmpty()) null else via
                    for (x in buildChainOutbounds(chain, tag, firstVia, "$t~gh$idx")) out.put(x)
                    continue
                }
                val srv = m.server ?: continue
                if (via.isNotEmpty()) {
                    out.put(throughBase(srv, tag, via))
                    continue
                }
                for (x in withHelpers(cloneOut(srv.outbound, tag, srv), srv, "$t~gh$idx")) out.put(x)
            }
            if (members.isEmpty()) continue
            // Where the group's traffic goes when no member answers: its own fallback
            // (a WARP, say) as `T~fb`, outside the members' prefix — never probed, never
            // picked while a member answers — else the first member. Not for a group
            // of chain variants (each would need its own chain).
            var fallbackTag = "$t~gm0"
            val fb: ServerConfig? = if (members.any { m: Groups.Member -> m.chain != null }) null else Groups.fallbackOf(mark)
            if (fb != null) {
                fallbackTag = "$t~fb"
                if (via.isNotEmpty()) {
                    out.put(throughBase(fb, fallbackTag, via))
                } else {
                    for (x in withHelpers(cloneOut(fb.outbound, fallbackTag, fb), fb, "$t~fh")) out.put(x)
                }
            }
            val strategy = Groups.strategyOf(mark)
            balancers.put(JSONObject().put("tag", "$t~bal").put("selector", JSONArray().put("$t~gm"))
                .put("strategy", JSONObject().put("type", strategy))
                .put("fallbackTag", fallbackTag))
            rules.add(fieldRule().put("inboundTag", JSONArray().put("$t~in")).put("balancerTag", "$t~bal"))
            subjects.put("$t~gm")
            // who `T~gm<i>` is, and whether the app can test it as the core dials it:
            // not through a hop, not a chain variant
            val name = if (mark.isNull("name")) "" else mark.optString("name", "")
            map.add(GroupEvict.Group(t, gid, name, strategy, via.isEmpty(),
                members.map { m: Groups.Member -> whoOf(m).copy(direct = via.isEmpty() && m.chain == null) },
                if (fb == null) null else GroupEvict.Fallback(fb.id, fb.name)))
        }
        val observatory = if (subjects.length() == 0) null else JSONObject()
            .put("subjectSelector", subjects).put("probeUrl", GROUP_PROBE_URL)
            .put("probeInterval", GROUP_PROBE_INTERVAL).put("enableConcurrency", true)
        return GroupParts(out, rules, balancers, observatory, map)
    }

    /**
     * A group member as the live map names it (configBuilder.js expandGroups'
     * `who`): the server dialled — a chain variant by the hop(s) it takes from
     * the group(s), their names joined.
     */
    private fun whoOf(m: Groups.Member): GroupEvict.Member {
        val chain = m.chain
        val recs: List<ServerConfig> = if (chain != null) m.at.mapNotNull { k: Int -> chain.getOrNull(k) } else listOfNotNull(m.server)
        val r = recs.firstOrNull()
        val name = recs.map { s: ServerConfig -> s.name }.filter { n: String -> n.isNotEmpty() }.joinToString(" + ")
        return GroupEvict.Member(r?.id ?: "", name, r?.address ?: "", r?.port ?: 0)
    }

    /**
     * A minimal test config: one socks inbound -> the given server (with
     * fragment and pin as stored). A WireGuard endpoint that is a name takes the
     * address the tester resolved (`wgEndpointIps`, XrayTester.testEndpoints):
     * the throwaway core shares the live tunnel's process, and one that has to
     * resolve the name itself and fails can panic it (`close of closed channel`).
     *
     * `mux`: the proxy outbound carries Mux.MUX (when it can) — only the mux
     * test asks for it (XrayTester.probeMux); latency tests stay without.
     */
    fun buildTestConfig(server: ServerConfig, socksPort: Int, wgEndpointIps: Map<String, String> = emptyMap(), mux: Boolean = false): JSONObject {
        val proxy = cloneOut(server.outbound, "proxy", server)
        if (mux && Mux.eligible(proxy)) proxy.put("mux", Mux.MUX)
        // a JSON server is measured in its full form: its helpers come along
        val first = JSONArray()
        for (o in withHelpers(proxy, server, "proxy")) first.put(o)
        // a group (Groups.kt): its members and balancer, no health check — a ping
        // is over before one would answer (configBuilder.js buildTestConfig)
        val grp = expandGroups(first)
        val all = JSONArray()
        for (i in 0 until grp.outbounds.length()) {
            val o = grp.outbounds.getJSONObject(i)
            widenWgAllowedIps(o); sanitizeWgAddress(o); applyWgEndpointIps(o, wgEndpointIps)
            all.put(o)
        }
        // a server's own ECH outbound too: without it the test would ask for the key directly and fail where the connect works
        val outs = applyEchOutbounds(applyFragments(all))
        outs.put(JSONObject().put("tag", "direct").put("protocol", "freedom"))
        val config = JSONObject()
            .put("log", JSONObject().put("loglevel", "none"))
            .put("inbounds", JSONArray().put(JSONObject().put("tag", "socks-in").put("port", socksPort)
                .put("listen", "127.0.0.1").put("protocol", "socks").put("settings", JSONObject().put("auth", "noauth").put("udp", false))))
            .put("outbounds", outs)
        // Unrouted traffic goes to the FIRST outbound — a group's loopback, whose
        // traffic must meet its balancer: the rule for that first, then the inbound
        // to the group. Without a group, the config of before (no routing at all).
        if (grp.balancers.length() > 0) {
            val rules = JSONArray()
            grp.rules.forEach { r: JSONObject -> rules.put(r) }
            rules.put(fieldRule().put("inboundTag", JSONArray().put("socks-in")).put("outboundTag", "proxy"))
            config.put("routing", JSONObject().put("rules", rules).put("balancers", grp.balancers))
        }
        return config
    }

    /** DPI-evasion dialer: outbounds marked with `_fragment` (TLS fragmentation)
     *  and/or `_noise` (fake ClientHello / decoy packet injection) dial through a
     *  freedom outbound carrying the matching settings (skipping chain inner hops
     *  that already dial-through).
     *
     *  MASQUE dials TCP for HTTP/2 and QUIC (UDP) for HTTP/3: a fragment cuts
     *  only the first, noise goes only before the second, so the one that would
     *  do nothing is dropped (the editor drops it from the record too) — a record
     *  left with neither dials directly (configBuilder.js applyFragments). */
    private fun applyFragments(outbounds: JSONArray): JSONArray {
        val byKey = HashMap<String, String>()
        val extra = JSONArray()
        for (i in 0 until outbounds.length()) {
            val o = outbounds.getJSONObject(i)
            var frag = o.optString("_fragment", "")
            var noise = o.optString("_noise", "")
            if (frag.isEmpty() && noise.isEmpty()) continue
            o.remove("_fragment"); o.remove("_noise")
            if (o.optString("protocol") == Masque.PROTOCOL) {
                if (Masque.httpOf(o.optJSONObject("streamSettings")?.optJSONObject("tlsSettings")) == "h2") noise = "" else frag = ""
                if (frag.isEmpty() && noise.isEmpty()) continue
            }
            val ss = o.optJSONObject("streamSettings") ?: JSONObject().also { o.put("streamSettings", it) }
            val sockopt = ss.optJSONObject("sockopt") ?: JSONObject().also { ss.put("sockopt", it) }
            if (sockopt.has("dialerProxy")) continue
            val key = "$frag|$noise"
            var tag = byKey[key]
            if (tag == null) { tag = "dpi-" + (byKey.size + 1); byKey[key] = tag; extra.put(makeFragmentOutbound(tag, frag, noise)) }
            sockopt.put("dialerProxy", tag)
        }
        for (i in 0 until extra.length()) outbounds.put(extra.getJSONObject(i))
        return outbounds
    }

    /**
     * A server's own ECH outbound (PattN's `echOutbound`, the link's
     * `echOutbound=`): the outbound the core dials its ECH config query through —
     * `echSockopt.dialerProxy` (configBuilder.js applyEchOutbounds). What it is
     * for (patterniha, 2026-10-20): the plain-DNS answer no longer carries the
     * key and DoH to 1.1.1.1 is reset on its SNI, so the query goes
     * `h2c://1.1.1.1/dns-query` through a `direct` outbound that redirects to
     * 1.1.1.1:443 under TLS with another name (`www.microsoft.com`) and checks
     * the certificate against the resolver's own (`fromMitM`; the core hands the
     * query's host over from 26.10.10).
     *
     * The record keeps it in tlsSettings (`echOutbound`, never a core key): taken
     * out here, given a tag of ours — `ech-<n>`, one per distinct outbound (by
     * its canonical JSON without its tag), so twenty servers with the same one
     * share it and the user's own tag can clash with nothing — and appended
     * after everything else. Without a list fetched from DNS (a base64 one is not
     * fetched) it means nothing and is dropped. Every builder runs it, the
     * tests' too, right after [applyFragments].
     */
    internal fun applyEchOutbounds(outbounds: JSONArray): JSONArray {
        val byKey = HashMap<String, String>()
        val extra = ArrayList<JSONObject>()
        for (i in 0 until outbounds.length()) {
            val tls = outbounds.optJSONObject(i)?.optJSONObject("streamSettings")?.optJSONObject("tlsSettings") ?: continue
            if (!tls.has("echOutbound")) continue
            val ob = tls.opt("echOutbound")
            tls.remove("echOutbound")
            if (ob !is JSONObject || !isEchQuery(tls.optString("echConfigList"))) continue
            val protocol = ob.opt("protocol")
            if (protocol !is String || protocol.isEmpty()) continue
            val body = JSONObject(ob.toString())
            body.remove("tag")
            val key = JsonText.canonical(body)
            var tag = byKey[key]
            if (tag == null) {
                tag = "ech-" + (byKey.size + 1)
                byKey[key] = tag
                val o = JSONObject().put("tag", tag)
                for (k in body.keys().asSequence().toList()) o.put(k, body.get(k))
                extra.add(o)
            }
            val so = tls.optJSONObject("echSockopt")?.let { x: JSONObject -> JSONObject(x.toString()) } ?: JSONObject()
            tls.put("echSockopt", so.put("dialerProxy", tag))
        }
        for (o in extra) outbounds.put(o)
        return outbounds
    }

    private val ECH_QUERY = Regex("^([a-z0-9]+)://(\\[[^\\]]+\\]|[^/:?#]+)(?::(\\d+))?", RegexOption.IGNORE_CASE)

    /**
     * Is this echConfigList fetched from DNS — `[name+]scheme://server[:port]…`
     * — rather than given as a base64 list? (configBuilder.js echQueryOf is not null)
     */
    internal fun isEchQuery(list: String?): Boolean {
        val s = (list ?: "").trim()
        val sep = s.indexOf("://")
        if (sep == -1) return false
        val plus = s.indexOf('+')
        val server = if (plus > -1 && plus < sep) s.substring(plus + 1) else s
        return ECH_QUERY.containsMatchIn(server)
    }

    private fun makeFragmentOutbound(tag: String, fragStr: String, noiseStr: String): JSONObject {
        val settings = JSONObject().put("domainStrategy", "AsIs")
        if (fragStr.isNotEmpty()) {
            val p = fragStr.split(",").map { it.trim() }
            settings.put("fragment", JSONObject()   // xray rejects LengthMin=0 -> clamp length min to >=1
                .put("packets", p.getOrNull(0)?.takeIf { it.isNotEmpty() } ?: "tlshello")
                .put("length", fragRange(p.getOrNull(1), "100-200", 1))
                .put("interval", fragRange(p.getOrNull(2), "10-20", 0)))
        }
        val noises = if (noiseStr.isNotEmpty()) parseNoises(noiseStr) else JSONArray()
        if (noises.length() > 0) settings.put("noises", noises)
        return JSONObject().put("tag", tag).put("protocol", "freedom").put("settings", settings)
    }
    // Named presets (also accepted from the link's &noise= value).
    private val noisePresets = mapOf(
        "random" to "rand:50-100:0",
        "faketls" to "rand:100-200:0;rand:40-80:10-20",
        "fakehello" to "rand:100-200:0;rand:40-80:10-20"
    )
    /** Parse a noise spec (`type:packet:delay;…`, or a preset keyword) into xray `noises`. */
    private fun parseNoises(spec: String): JSONArray {
        var s = spec.trim()
        if (s.isEmpty()) return JSONArray()
        noisePresets[s.lowercase()]?.let { s = it }
        val out = JSONArray()
        for (entry in s.split(";")) {
            val e = entry.trim()
            if (e.isEmpty()) continue
            val parts = e.split(":")
            val type = parts.getOrNull(0)?.trim()?.lowercase() ?: ""
            val packet = parts.getOrNull(1)?.trim() ?: ""
            val delay = parts.getOrNull(2)?.trim()?.takeIf { it.isNotEmpty() } ?: "0"
            if (type !in listOf("rand", "str", "base64", "hex") || packet.isEmpty()) continue
            out.put(JSONObject().put("type", type).put("packet", packet).put("delay", delay))
        }
        return out
    }
    private fun fragRange(v: String?, def: String, floor: Int): String {
        if (v.isNullOrEmpty()) return def
        val parts = v.split("-")
        var min = parts.getOrNull(0)?.toIntOrNull() ?: return def
        var max = parts.getOrNull(1)?.toIntOrNull() ?: min
        if (min < floor) min = floor
        if (max < min) max = min
        return "$min-$max"
    }

    /* ----------------------------- JSON servers ----------------------------- */

    /**
     * [main] — a server's outbound, already tagged [tag] — with a JSON server's
     * helper outbounds beside it (full mode): each helper's tag becomes
     * `<tag>~<helper>`, and every dialerProxy / proxySettings.tag that named a
     * helper is rewritten to match, so two JSON servers in one config never
     * collide — a proxySettings as the dialerProxy the cores now take
     * (proxySettingsToDialer). Like any outbound, a helper loses
     * `allowInsecure`, which the cores refuse. Any other server: [main] alone,
     * untouched. (configBuilder.js helpersFor)
     */
    private fun withHelpers(main: JSONObject, server: ServerConfig, tag: String): List<JSONObject> {
        if (!server.isJson) return listOf(main)
        proxySettingsToDialer(main)
        if (server.extraOutbounds.isEmpty()) return listOf(main)
        val names = server.extraOutbounds.map { h: JSONObject -> h.optString("tag") }.filter { t: String -> t.isNotEmpty() }.toSet()
        val out = arrayListOf(main)
        for (h0 in server.extraOutbounds) {
            val own = h0.optString("tag")
            if (own.isEmpty()) continue
            val h = JSONObject(h0.toString()).put("tag", "$tag~$own")
            applyCertPin(h, null)
            proxySettingsToDialer(h)
            out.add(h)
        }
        for (o in out) {
            val so = o.optJSONObject("streamSettings")?.optJSONObject("sockopt")
            val dialer = so?.optString("dialerProxy") ?: ""
            if (so != null && dialer in names) so.put("dialerProxy", "$tag~$dialer")
        }
        return out
    }

    /**
     * `proxySettings.tag` → `streamSettings.sockopt.dialerProxy`, in place. The
     * 2026 cores (and PattN) refuse proxySettings at config load — "has been
     * removed and migrated to streamSettings.sockopt.dialerProxy" — and a JSON
     * config written for an older one still carries it (a chain's hop). A
     * dialerProxy the outbound has already wins. Only a JSON server's outbounds
     * ever carry it; the stored record keeps its config as written.
     * (configBuilder.js proxySettingsToDialer)
     */
    private fun proxySettingsToDialer(o: JSONObject): JSONObject {
        val ps = o.optJSONObject("proxySettings") ?: return o
        val via = ps.optString("tag")
        o.remove("proxySettings")
        if (via.isNotEmpty()) {
            val ss = o.optJSONObject("streamSettings") ?: JSONObject().also { o.put("streamSettings", it) }
            val so = ss.optJSONObject("sockopt") ?: JSONObject().also { ss.put("sockopt", it) }
            if (so.optString("dialerProxy").isEmpty()) so.put("dialerProxy", via)
        }
        return o
    }

    /** The local inbounds' sniffing, as Settings asks for it. */
    private fun sniffingFor(s: AppSettings): JSONObject = if (s.enableSniffing)
        JSONObject().put("enabled", true).put("destOverride", JSONArray().put("http").put("tls").put("quic")).put("routeOnly", false)
    else JSONObject().put("enabled", false)

    private fun jarr(a: JSONArray?): List<String> = if (a == null) emptyList() else (0 until a.length()).map { a.optString(it) }
    /** A server's outbound as the config will carry it: a deep copy, tagged, its certificate pin applied. */
    private fun cloneOut(outbound: JSONObject, tag: String, server: ServerConfig?): JSONObject {
        val o = JSONObject(outbound.toString()).put("tag", tag)
        applyCertPin(o, server)
        return o
    }
    /**
     * Xray's mux on [o], the outbound of [server] as a NON-CHAIN target, when the
     * connect chose it for that server and the outbound can carry it (Mux.kt).
     * No ids, no change. A chain's hops never come through here.
     */
    private fun withMux(o: JSONObject, server: ServerConfig, muxIds: Set<String>): JSONObject {
        if (server.id in muxIds && Mux.eligible(o)) {
            // the server's own numbers (the editor's Mux fields), where it has them
            val m = JSONObject(Mux.MUX.toString())
            server.muxConcurrency?.let { n: Int -> m.put("concurrency", n) }
            server.xudpConcurrency?.let { n: Int -> m.put("xudpConcurrency", n) }
            o.put("mux", m)
        }
        return o
    }
    private fun dialThrough(outbound: JSONObject, viaTag: String) {
        val stream = outbound.optJSONObject("streamSettings") ?: JSONObject().also { outbound.put("streamSettings", it) }
        val sockopt = stream.optJSONObject("sockopt") ?: JSONObject().also { stream.put("sockopt", it) }
        sockopt.put("dialerProxy", viaTag)
    }
    /**
     * The direct outbound. IPv4-only unless the user turned IPv6 on: with no v6
     * route in the tunnel, an AAAA answer would just make the app try an address
     * it cannot reach. (configBuilder.freedom)
     */
    private fun freedom(s: AppSettings) = JSONObject().put("tag", "direct").put("protocol", "freedom").put("settings", JSONObject().put("domainStrategy", if (s.ipv6) "UseIP" else "UseIPv4"))
    private fun blackhole() = JSONObject().put("tag", "block").put("protocol", "blackhole").put("settings", JSONObject().put("response", JSONObject().put("type", "http")))
    private fun fieldRule() = JSONObject().put("type", "field")
    private fun rule(inbound: List<String>, out: String) = fieldRule().put("inboundTag", JSONArray(inbound)).put("outboundTag", out)
}
