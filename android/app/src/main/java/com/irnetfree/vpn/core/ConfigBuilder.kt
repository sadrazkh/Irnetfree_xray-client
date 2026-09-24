package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Builds a complete Xray config.json for Android. Ported from the desktop
 * configBuilder.js so both clients behave identically. Supports single / chain /
 * pool / advanced plans, simple routing modes, custom rules, WireGuard, the
 * managed DNS plan (DnsPlan.kt), certificate pins (CertPin.kt) and an optional
 * geo-asset flag (geo rules are skipped when the .dat files are absent).
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
     */
    fun build(plan: ConnectionPlan, s: AppSettings, geoAssets: Boolean = false, wgEndpointIps: Map<String, String> = emptyMap(), inboundAuth: LocalAuth? = null): JSONObject {
        val listen = "127.0.0.1"
        val sniffing = if (s.enableSniffing)
            JSONObject().put("enabled", true).put("destOverride", JSONArray().put("http").put("tls").put("quic")).put("routeOnly", false)
        else JSONObject().put("enabled", false)

        if (plan is ConnectionPlan.Pool) return buildPool(plan, s, listen, sniffing, geoAssets, wgEndpointIps, inboundAuth)
        if (plan is ConnectionPlan.Advanced) return buildAdvanced(plan, s, listen, sniffing, geoAssets, wgEndpointIps, inboundAuth)

        val outbounds = JSONArray()
        // Every target the plan routes to, with its outbound tag — the resolver a
        // corporate WireGuard carries must be asked through THAT outbound.
        val targets = ArrayList<Pair<Any?, String>>()
        when (plan) {
            is ConnectionPlan.Chain -> { buildChainOutbounds(plan.members, "proxy").forEach { outbounds.put(it) }; targets.add(plan.members to "proxy") }
            is ConnectionPlan.Single -> { outbounds.put(cloneOut(plan.server.outbound, "proxy", plan.server)); targets.add(plan.server to "proxy") }
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
        return assemble(s, standardInbounds(s, listen, sniffing, inboundAuth), outbounds, rules,
            geoAssets, catchAllTag, dnsSettings, targetResolversFor(targets), wgEndpointIps)
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

    private fun buildAdvanced(plan: ConnectionPlan.Advanced, s: AppSettings, listen: String, sniffing: JSONObject, geo: Boolean, wgEndpointIps: Map<String, String>, auth: LocalAuth?): JSONObject {
        val reg = Registry(plan.serversById, plan.chainsById)
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

            // Resolve the target only once the rule is known to survive: tagFor()
            // REGISTERS the outbound(s), so doing it earlier leaves a dead outbound
            // behind for every dropped rule — writing an unused server's address and
            // credentials into the config (and materializing a whole chain for a
            // "chain:" target). Mirrors configBuilder.js.
            val tag = reg.tagFor(r.target)
            advRules.put(fieldRule().put("outboundTag", tag).put(ruleField, ruleValue))
            targets.add(targetServer(r.target, plan) to tag)
        }
        val defTag = reg.tagFor(plan.def)
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
        return assemble(s, standardInbounds(s, listen, sniffing, auth), JSONArray(reg.outs), rules,
            geo, exitTag, dnsSettings, targetResolversFor(targets), wgEndpointIps)
    }

    /* ----------------------------- pool ----------------------------- */

    private fun buildPool(plan: ConnectionPlan.Pool, s: AppSettings, listen: String, sniffing: JSONObject, geo: Boolean, wgEndpointIps: Map<String, String>, auth: LocalAuth?): JSONObject {
        val reg = Registry(plan.serversById, plan.chainsById)
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
        return assemble(s, inbounds, JSONArray(reg.outs), rules, geo, primaryTag, dnsSettings, targetResolversFor(targets), wgEndpointIps)
    }

    /* ----------------------------- chain / registry ----------------------------- */

    private fun buildChainOutbounds(members: List<ServerConfig>, exitTag: String): List<JSONObject> {
        val list = members.filter { it.outbound.length() > 0 }
        val last = list.size - 1
        val outs = ArrayList<JSONObject>()
        for (i in 0..last) {
            val tag = if (i == last) exitTag else "$exitTag-h$i"
            val ob = cloneOut(list[i].outbound, tag, list[i])
            if (i > 0) dialThrough(ob, "$exitTag-h${i - 1}")
            outs.add(ob)
        }
        return outs
    }

    private class Registry(
        val serversById: Map<String, ServerConfig>,
        val chainsById: Map<String, List<ServerConfig>>
    ) {
        val outs = ArrayList<JSONObject>()
        private val seen = HashSet<String>()
        fun add(o: JSONObject) { val t = o.optString("tag"); if (t.isNotEmpty() && seen.add(t)) outs.add(o) }

        private fun chainTag(list: List<ServerConfig>?, tag: String): String {
            val arr = list?.filter { it.outbound.length() > 0 } ?: emptyList()
            return when {
                arr.size >= 2 -> { ConfigBuilder.buildChainOutbounds(arr, tag).forEach { add(it) }; tag }
                arr.size == 1 -> { add(ConfigBuilder.cloneOut(arr[0].outbound, tag, arr[0])); tag }
                else -> "direct"
            }
        }

        fun tagFor(target: String?): String {
            if (target.isNullOrEmpty() || target == "direct") return "direct"
            if (target == "proxy") return proxyFallback()
            if (target == "block") return "block"
            if (target.startsWith("chain:")) return chainTag(chainsById[target.substring(6)], "out-chain-" + target.substring(6))
            val s = serversById[target]
            if (s != null && s.outbound.length() > 0) { val tag = "out-$target"; add(ConfigBuilder.cloneOut(s.outbound, tag, s)); return tag }
            return "direct"
        }

        // in advanced/custom rules a literal 'proxy' target uses the first server
        private fun proxyFallback(): String {
            val first = serversById.values.firstOrNull { it.outbound.length() > 0 } ?: return "direct"
            val tag = "out-proxy"
            if (!seen.contains(tag)) add(ConfigBuilder.cloneOut(first.outbound, tag, first))
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
        fun visit(s: ServerConfig?) {
            if (s == null || s.outbound.optString("protocol") != "wireguard") return
            val peers = s.outbound.optJSONObject("settings")?.optJSONArray("peers") ?: return
            for (i in 0 until peers.length()) {
                val ep = splitEndpoint(peers.optJSONObject(i)?.optString("endpoint")) ?: continue
                if (!DnsPlan.isIp(ep.first) && ep.first !in out) out.add(ep.first)
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
        fun visit(s: ServerConfig?) { if (isWgServer(s)) for (d in s!!.dns) if (d.isNotBlank() && d !in out) out.add(d) }
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

    // No metrics listener (the desktop's GET /debug/vars on apiPort): nothing on
    // Android reads it — the traffic figures come from hev — and it answered any
    // app on 127.0.0.1 with this tunnel's outbound tags and byte counts.

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
        val pin = CertPin.normalizePin(server?.certPin)
        if (pin.isNotEmpty()) tls.put("pinnedPeerCertSha256", pin)
    }

    private fun assemble(
        s: AppSettings, inbounds: JSONArray, outboundsIn: JSONArray, rules: JSONArray,
        geoAssets: Boolean, exitTag: String, dnsSettings: AppSettings,
        targetResolvers: List<DnsPlan.TargetResolver>, wgEndpointIps: Map<String, String>
    ): JSONObject {
        // Name resolution (see DnsPlan.kt). Its rules go FIRST: the port-53 hijack
        // must beat the private-IP bypass, or a query to the tunnel resolver would
        // be sent "direct" into nowhere instead of being answered.
        val plan = DnsPlan.build(dnsSettings, geoAssets, exitTag, targetResolvers)
        plan.hijackOutbound?.let { outboundsIn.put(it) }
        val allRules = JSONArray()
        plan.rules.forEach { allRules.put(it) }
        for (i in 0 until rules.length()) allRules.put(rules.getJSONObject(i))

        for (i in 0 until outboundsIn.length()) {
            val o = outboundsIn.getJSONObject(i)
            widenWgAllowedIps(o); sanitizeWgAddress(o); applyWgEndpointIps(o, wgEndpointIps)
        }
        val outbounds = applyFragments(outboundsIn)

        // No `bufferSize: 0` for a chained WireGuard any more (Xray-core #2850):
        // level 0 is every connection of the config, and a pipe allowed to hold
        // nothing made the whole plan run lock-stepped. Both cores carry the
        // chained WireGuard with the default buffer now (desktop v1.7.2).
        val level0 = JSONObject().put("statsUserUplink", true).put("statsUserDownlink", true)
        return JSONObject()
            .put("log", JSONObject().put("loglevel", s.logLevel))
            // stats + policy stay: the core's own counters (XrayCore.queryTraffic) live on them
            .put("stats", JSONObject())
            .put("policy", JSONObject()
                .put("levels", JSONObject().put("0", level0))
                .put("system", JSONObject().put("statsInboundUplink", true).put("statsInboundDownlink", true)
                    .put("statsOutboundUplink", true).put("statsOutboundDownlink", true)))
            .put("dns", plan.dns)
            .put("inbounds", inbounds)
            .put("outbounds", outbounds)
            // xray resolves a hostname destination under IPIfNonMatch only when NO
            // rule matched on the first pass — and every plan ends with a catch-all
            // that always matches — so an `ip:` rule never fires for a name. With
            // managed DNS the router asks the plan's own resolver on demand.
            .put("routing", JSONObject().put("domainStrategy", if (s.dnsManaged) "IPOnDemand" else "IPIfNonMatch").put("rules", allRules))
    }

    /**
     * A minimal test config: one socks inbound -> the given server (with
     * fragment and pin as stored). A WireGuard endpoint that is a name takes the
     * address the tester resolved (`wgEndpointIps`, XrayTester.testEndpoints):
     * the throwaway core shares the live tunnel's process, and one that has to
     * resolve the name itself and fails can panic it (`close of closed channel`).
     */
    fun buildTestConfig(server: ServerConfig, socksPort: Int, wgEndpointIps: Map<String, String> = emptyMap()): JSONObject {
        val proxy = cloneOut(server.outbound, "proxy", server)
        widenWgAllowedIps(proxy); sanitizeWgAddress(proxy); applyWgEndpointIps(proxy, wgEndpointIps)
        val outs = applyFragments(JSONArray().put(proxy))
        outs.put(JSONObject().put("tag", "direct").put("protocol", "freedom"))
        return JSONObject()
            .put("log", JSONObject().put("loglevel", "none"))
            .put("inbounds", JSONArray().put(JSONObject().put("tag", "socks-in").put("port", socksPort)
                .put("listen", "127.0.0.1").put("protocol", "socks").put("settings", JSONObject().put("auth", "noauth").put("udp", false))))
            .put("outbounds", outs)
    }

    /** DPI-evasion dialer: outbounds marked with `_fragment` (TLS fragmentation)
     *  and/or `_noise` (fake ClientHello / decoy packet injection) dial through a
     *  freedom outbound carrying the matching settings (skipping chain inner hops
     *  that already dial-through). */
    private fun applyFragments(outbounds: JSONArray): JSONArray {
        val byKey = HashMap<String, String>()
        val extra = JSONArray()
        for (i in 0 until outbounds.length()) {
            val o = outbounds.getJSONObject(i)
            val frag = o.optString("_fragment", "")
            val noise = o.optString("_noise", "")
            if (frag.isEmpty() && noise.isEmpty()) continue
            o.remove("_fragment"); o.remove("_noise")
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

    private fun jarr(a: JSONArray?): List<String> = if (a == null) emptyList() else (0 until a.length()).map { a.optString(it) }
    /** A server's outbound as the config will carry it: a deep copy, tagged, its certificate pin applied. */
    private fun cloneOut(outbound: JSONObject, tag: String, server: ServerConfig?): JSONObject {
        val o = JSONObject(outbound.toString()).put("tag", tag)
        applyCertPin(o, server)
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
