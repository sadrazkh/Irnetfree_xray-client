package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Builds a complete Xray config.json for Android. Ported from the desktop
 * configBuilder.js so both clients behave identically. Supports single / chain /
 * pool / advanced plans, simple routing modes, custom rules, WireGuard, and an
 * optional geo-asset flag (geo rules are skipped when the .dat files are absent).
 *
 * The VpnService points tun2socks at the SOCKS inbound (settings.socksPort).
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

    fun build(plan: ConnectionPlan, s: AppSettings, geoAssets: Boolean = false): JSONObject {
        val listen = "127.0.0.1"
        val sniffing = if (s.enableSniffing)
            JSONObject().put("enabled", true).put("destOverride", JSONArray().put("http").put("tls").put("quic")).put("routeOnly", false)
        else JSONObject().put("enabled", false)

        if (plan is ConnectionPlan.Pool) return buildPool(plan, s, listen, sniffing)
        if (plan is ConnectionPlan.Advanced) return buildAdvanced(plan, s, listen, sniffing, geoAssets)

        val outbounds = JSONArray()
        val proxyOuts = when (plan) {
            is ConnectionPlan.Chain -> buildChainOutbounds(plan.members, "proxy")
            is ConnectionPlan.Single -> listOf(cloneOut(plan.server.outbound, "proxy"))
            else -> emptyList()
        }
        proxyOuts.forEach { outbounds.put(it) }
        outbounds.put(freedom()).put(blackhole())

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
        // Pinned by tests/configBuilder.test.js ("custom rules sit before the
        // catch-all", which asserts a custom rule is the LAST rule before it).
        val rules = JSONArray()
        if (s.blockAds && geoAssets) rules.put(fieldRule().put("domain", JSONArray().put("geosite:category-ads-all")).put("outboundTag", "block"))
        rules.put(fieldRule().put("ip", JSONArray(PRIVATE_IPS)).put("outboundTag", "direct"))
        var catchAllTag = "proxy"
        when (s.routingMode) {
            "bypass-ir" -> if (geoAssets) {
                rules.put(fieldRule().put("domain", JSONArray().put("geosite:category-ir").put("regexp:.*\\.ir$")).put("outboundTag", "direct"))
                rules.put(fieldRule().put("ip", JSONArray().put("geoip:ir")).put("outboundTag", "direct"))
            }
            "bypass-cn" -> if (geoAssets) {
                rules.put(fieldRule().put("domain", JSONArray().put("geosite:cn")).put("outboundTag", "direct"))
                rules.put(fieldRule().put("ip", JSONArray().put("geoip:cn")).put("outboundTag", "direct"))
            }
            "direct" -> { catchAllTag = "direct" }
        }
        addCustomRules(rules, s.customRules, geoAssets)
        rules.put(fieldRule().put("port", "0-65535").put("outboundTag", catchAllTag))
        return assemble(s, standardInbounds(s, listen, sniffing), finalizeOutbounds(outbounds), rules)
    }

    /* ----------------------------- advanced ----------------------------- */

    private fun buildAdvanced(plan: ConnectionPlan.Advanced, s: AppSettings, listen: String, sniffing: JSONObject, geo: Boolean): JSONObject {
        val reg = Registry(plan.serversById, plan.chainsById)
        val advRules = JSONArray()
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
            advRules.put(fieldRule().put("outboundTag", reg.tagFor(r.target)).put(ruleField, ruleValue))
        }
        val defTag = reg.tagFor(plan.def)
        reg.add(freedom()); reg.add(blackhole())

        val rules = JSONArray()
        if (s.blockAds && geo) rules.put(fieldRule().put("domain", JSONArray().put("geosite:category-ads-all")).put("outboundTag", "block"))
        for (i in 0 until advRules.length()) rules.put(advRules.getJSONObject(i))
        rules.put(fieldRule().put("ip", JSONArray(PRIVATE_IPS)).put("outboundTag", "direct"))
        rules.put(fieldRule().put("port", "0-65535").put("outboundTag", defTag))

        return assemble(s, standardInbounds(s, listen, sniffing), finalizeOutbounds(JSONArray(reg.outs)), rules)
    }

    /* ----------------------------- pool ----------------------------- */

    private fun buildPool(plan: ConnectionPlan.Pool, s: AppSettings, listen: String, sniffing: JSONObject): JSONObject {
        val reg = Registry(plan.serversById, plan.chainsById)
        val inbounds = JSONArray()
        // The metrics listener binds apiPort itself, outside the inbound list, so
        // reserve it up front: a pool entry must never take it (xray refuses to
        // start on a duplicate bind). Mirrors buildPoolConfig() in configBuilder.js.
        val used = HashSet<Int>()
        used.add(s.apiPort)
        val perInbound = JSONArray()

        fun addInbound(tag: String, port: Int, http: Boolean): Boolean {
            if (port <= 0 || port > 65535 || !used.add(port)) return false
            inbounds.put(if (http)
                JSONObject().put("tag", tag).put("port", port).put("listen", listen).put("protocol", "http").put("settings", JSONObject()).put("sniffing", sniffing)
            else
                JSONObject().put("tag", tag).put("port", port).put("listen", listen).put("protocol", "socks").put("settings", JSONObject().put("auth", "noauth").put("udp", true)).put("sniffing", sniffing))
            return true
        }

        val primaryTag = reg.tagFor(plan.primary)
        val stdTags = ArrayList<String>()
        if (addInbound("socks-in", s.socksPort, false)) stdTags.add("socks-in")
        if (addInbound("http-in", s.httpPort, true)) stdTags.add("http-in")
        if (stdTags.isNotEmpty()) perInbound.put(rule(stdTags, primaryTag))

        for (e in plan.entries) {
            val tag = reg.tagFor(e.target)
            val inTags = ArrayList<String>()
            if (addInbound("ps-" + e.id, e.socksPort, false)) inTags.add("ps-" + e.id)
            if (e.httpPort > 0 && addInbound("ph-" + e.id, e.httpPort, true)) inTags.add("ph-" + e.id)
            if (inTags.isNotEmpty()) perInbound.put(rule(inTags, tag))
        }

        reg.add(freedom()); reg.add(blackhole())
        // Private/LAN bypass first, THEN the per-inbound routing, THEN a catch-all
        // to the primary exit so nothing is ever left unrouted (configBuilder.js).
        val rules = JSONArray()
        rules.put(fieldRule().put("ip", JSONArray(PRIVATE_IPS)).put("outboundTag", "direct"))
        for (i in 0 until perInbound.length()) rules.put(perInbound.getJSONObject(i))
        rules.put(fieldRule().put("port", "0-65535").put("outboundTag", primaryTag))

        return assemble(s, inbounds, finalizeOutbounds(JSONArray(reg.outs)), rules)
    }

    /* ----------------------------- chain / registry ----------------------------- */

    private fun buildChainOutbounds(members: List<ServerConfig>, exitTag: String): List<JSONObject> {
        val list = members.filter { it.outbound.length() > 0 }
        val last = list.size - 1
        val outs = ArrayList<JSONObject>()
        for (i in 0..last) {
            val tag = if (i == last) exitTag else "$exitTag-h$i"
            val ob = cloneOut(list[i].outbound, tag)
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
                arr.size == 1 -> { add(ConfigBuilder.cloneOut(arr[0].outbound, tag)); tag }
                else -> "direct"
            }
        }

        fun tagFor(target: String?): String {
            if (target.isNullOrEmpty() || target == "direct" || target == "proxy") {
                // 'proxy' means the primary server exit isn't defined here; treat as direct fallback
                if (target == "proxy") return proxyFallback()
                return if (target == "direct") "direct" else "direct"
            }
            if (target == "block") return "block"
            if (target.startsWith("chain:")) return chainTag(chainsById[target.substring(6)], "out-chain-" + target.substring(6))
            val s = serversById[target]
            if (s != null && s.outbound.length() > 0) { val tag = "out-$target"; add(ConfigBuilder.cloneOut(s.outbound, tag)); return tag }
            return "direct"
        }

        // in advanced/custom rules a literal 'proxy' target uses the first server
        private fun proxyFallback(): String {
            val first = serversById.values.firstOrNull { it.outbound.length() > 0 } ?: return "direct"
            val tag = "out-proxy"
            if (!seen.contains(tag)) add(ConfigBuilder.cloneOut(first.outbound, tag))
            return tag
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

    private fun standardInbounds(s: AppSettings, listen: String, sniffing: JSONObject): JSONArray = JSONArray()
        .put(JSONObject().put("tag", "socks-in").put("port", s.socksPort).put("listen", listen)
            .put("protocol", "socks").put("settings", JSONObject().put("auth", "noauth").put("udp", true)).put("sniffing", sniffing))
        .put(JSONObject().put("tag", "http-in").put("port", s.httpPort).put("listen", listen)
            .put("protocol", "http").put("settings", JSONObject()).put("sniffing", sniffing))

    /**
     * Live traffic counters over HTTP (GET /debug/vars) instead of the gRPC-only
     * StatsService. It is a top-level listener, NOT an inbound, so no inbound and
     * no `inboundTag: ["api"]` routing rule exists any more — nothing can collide
     * with it and it reports EVERY outbound tag (pool/advanced plans have no
     * outbound called 'proxy'). Kept on 127.0.0.1 even when allowLan is on.
     */
    private fun metricsListener(s: AppSettings): JSONObject = JSONObject()
        .put("tag", "metrics").put("listen", "127.0.0.1:${s.apiPort}")

    /** Fix any WireGuard interface address that isn't /32 (/128); return outbounds. */
    private fun finalizeOutbounds(outbounds: JSONArray): JSONArray {
        for (i in 0 until outbounds.length()) {
            val o = outbounds.getJSONObject(i)
            if (o.optString("protocol") == "wireguard") {
                val settings = o.optJSONObject("settings") ?: continue
                val addr = settings.optJSONArray("address") ?: continue
                val fixed = JSONArray()
                for (j in 0 until addr.length()) {
                    val a = addr.getString(j).trim()
                    val v6 = a.contains(":")
                    val host = if (a.indexOf('/') == -1) a else a.substring(0, a.indexOf('/'))
                    fixed.put(host + if (v6) "/128" else "/32")
                }
                settings.put("address", fixed)
            }
        }
        return outbounds
    }

    private fun assemble(s: AppSettings, inbounds: JSONArray, outboundsIn: JSONArray, rules: JSONArray): JSONObject {
        val outbounds = applyFragments(outboundsIn)
        // WireGuard dialed THROUGH another outbound needs bufferSize 0 (see Xray #2850)
        var wgChained = false
        for (i in 0 until outbounds.length()) {
            val o = outbounds.getJSONObject(i)
            if (o.optString("protocol") == "wireguard") {
                val so = o.optJSONObject("streamSettings")?.optJSONObject("sockopt")
                if (so != null && so.has("dialerProxy")) wgChained = true
            }
        }
        val level0 = JSONObject().put("statsUserUplink", true).put("statsUserDownlink", true)
        if (wgChained) level0.put("bufferSize", 0)
        return JSONObject()
            .put("log", JSONObject().put("loglevel", s.logLevel))
            .put("metrics", metricsListener(s))
            // stats + policy stay: the counters metrics reports only exist because of them
            .put("stats", JSONObject())
            .put("policy", JSONObject()
                .put("levels", JSONObject().put("0", level0))
                .put("system", JSONObject().put("statsInboundUplink", true).put("statsInboundDownlink", true)
                    .put("statsOutboundUplink", true).put("statsOutboundDownlink", true)))
            .put("dns", JSONObject().put("servers", JSONArray(s.dns)).put("queryStrategy", if (s.ipv6) "UseIP" else "UseIPv4"))
            .put("inbounds", inbounds)
            .put("outbounds", outbounds)
            .put("routing", JSONObject().put("domainStrategy", "IPIfNonMatch").put("rules", rules))
    }

    /** A minimal test config: one socks inbound -> the given server (with fragment). */
    fun buildTestConfig(server: ServerConfig, socksPort: Int): JSONObject {
        val outs = applyFragments(finalizeOutbounds(JSONArray().put(cloneOut(server.outbound, "proxy"))))
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

    private fun cloneOut(outbound: JSONObject, tag: String): JSONObject = JSONObject(outbound.toString()).put("tag", tag)
    private fun dialThrough(outbound: JSONObject, viaTag: String) {
        val stream = outbound.optJSONObject("streamSettings") ?: JSONObject().also { outbound.put("streamSettings", it) }
        val sockopt = stream.optJSONObject("sockopt") ?: JSONObject().also { stream.put("sockopt", it) }
        sockopt.put("dialerProxy", viaTag)
    }
    private fun freedom() = JSONObject().put("tag", "direct").put("protocol", "freedom").put("settings", JSONObject().put("domainStrategy", "UseIP"))
    private fun blackhole() = JSONObject().put("tag", "block").put("protocol", "blackhole").put("settings", JSONObject().put("response", JSONObject().put("type", "http")))
    private fun fieldRule() = JSONObject().put("type", "field")
    private fun rule(inbound: List<String>, out: String) = fieldRule().put("inboundTag", JSONArray(inbound)).put("outboundTag", out)
}
