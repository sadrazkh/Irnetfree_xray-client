package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Builds a complete Xray config.json for Android. Ported from the desktop
 * configBuilder.js so both clients behave identically. Supports:
 *   - Single(server)
 *   - Chain(members)   client -> s0 -> s1 -> ... -> exit
 *   - Pool(entries)    many local SOCKS/HTTP inbounds, each -> its own exit
 *
 * The VpnService points tun2socks at the SOCKS inbound (settings.socksPort).
 */
object ConfigBuilder {

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

        val outbounds = JSONArray()
        val proxyOuts = when (plan) {
            is ConnectionPlan.Chain -> buildChainOutbounds(plan.members, "proxy")
            is ConnectionPlan.Single -> listOf(cloneOut(plan.server.outbound, "proxy"))
            else -> emptyList()
        }
        proxyOuts.forEach { outbounds.put(it) }
        outbounds.put(freedom()).put(blackhole())

        val rules = JSONArray()
        rules.put(rule(inbound = listOf("api"), out = "api"))
        if (s.blockAds && geoAssets) rules.put(JSONObject().put("type", "field")
            .put("domain", JSONArray().put("geosite:category-ads-all")).put("outboundTag", "block"))
        rules.put(JSONObject().put("type", "field").put("ip", JSONArray(PRIVATE_IPS)).put("outboundTag", "direct"))
        // simple routing modes (geo-based ones need geo dat files)
        when (s.routingMode) {
            "bypass-ir" -> if (geoAssets) {
                rules.put(JSONObject().put("type", "field").put("domain", JSONArray().put("geosite:category-ir")).put("outboundTag", "direct"))
                rules.put(JSONObject().put("type", "field").put("ip", JSONArray().put("geoip:ir")).put("outboundTag", "direct"))
            }
            "bypass-cn" -> if (geoAssets) {
                rules.put(JSONObject().put("type", "field").put("domain", JSONArray().put("geosite:cn")).put("outboundTag", "direct"))
                rules.put(JSONObject().put("type", "field").put("ip", JSONArray().put("geoip:cn")).put("outboundTag", "direct"))
            }
            "direct" -> rules.put(JSONObject().put("type", "field").put("port", "0-65535").put("outboundTag", "direct"))
        }
        if (s.routingMode != "direct") rules.put(JSONObject().put("type", "field").put("port", "0-65535").put("outboundTag", "proxy"))

        return assemble(s, listen, sniffing, standardInbounds(s, listen, sniffing), outbounds, rules)
    }

    /* ----------------------------- pool ----------------------------- */

    private fun buildPool(plan: ConnectionPlan.Pool, s: AppSettings, listen: String, sniffing: JSONObject): JSONObject {
        val reg = Registry(plan.serversById, plan.chainsById)
        val inbounds = JSONArray()
        val used = HashSet<Int>()
        val perInbound = JSONArray()

        fun addInbound(tag: String, port: Int, http: Boolean): Boolean {
            if (port <= 0 || port > 65535 || !used.add(port)) return false
            inbounds.put(if (http)
                JSONObject().put("tag", tag).put("port", port).put("listen", listen)
                    .put("protocol", "http").put("settings", JSONObject()).put("sniffing", sniffing)
            else
                JSONObject().put("tag", tag).put("port", port).put("listen", listen)
                    .put("protocol", "socks").put("settings", JSONObject().put("auth", "noauth").put("udp", true))
                    .put("sniffing", sniffing))
            return true
        }

        val primaryTag = reg.tagFor(plan.primary)
        val stdTags = ArrayList<String>()
        if (addInbound("socks-in", s.socksPort, false)) stdTags.add("socks-in")
        if (addInbound("http-in", s.httpPort, true)) stdTags.add("http-in")
        if (stdTags.isNotEmpty()) perInbound.put(rule(inbound = stdTags, out = primaryTag))

        for (e in plan.entries) {
            val tag = reg.tagFor(e.target)
            val inTags = ArrayList<String>()
            if (addInbound("ps-" + e.id, e.socksPort, false)) inTags.add("ps-" + e.id)
            if (e.httpPort > 0 && addInbound("ph-" + e.id, e.httpPort, true)) inTags.add("ph-" + e.id)
            if (inTags.isNotEmpty()) perInbound.put(rule(inbound = inTags, out = tag))
        }

        inbounds.put(apiInbound(s))

        val outbounds = JSONArray()
        reg.outs.forEach { outbounds.put(it) }
        outbounds.put(freedom()).put(blackhole())

        val rules = JSONArray()
        rules.put(rule(inbound = listOf("api"), out = "api"))
        rules.put(JSONObject().put("type", "field").put("ip", JSONArray(PRIVATE_IPS)).put("outboundTag", "direct"))
        for (i in 0 until perInbound.length()) rules.put(perInbound.getJSONObject(i))
        rules.put(JSONObject().put("type", "field").put("port", "0-65535").put("outboundTag", primaryTag))

        return assemble(s, listen, sniffing, inbounds, outbounds, rules)
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

    /** Turns a routing "target" into an outbound tag, lazily creating outbounds. */
    private class Registry(
        val serversById: Map<String, ServerConfig>,
        val chainsById: Map<String, List<ServerConfig>>
    ) {
        val outs = ArrayList<JSONObject>()
        private val seen = HashSet<String>()
        private fun add(o: JSONObject) { val t = o.optString("tag"); if (t.isNotEmpty() && seen.add(t)) outs.add(o) }

        private fun chainTag(list: List<ServerConfig>?, tag: String): String {
            val arr = list?.filter { it.outbound.length() > 0 } ?: emptyList()
            return when {
                arr.size >= 2 -> { buildChainOutboundsStatic(arr, tag).forEach { add(it) }; tag }
                arr.size == 1 -> { add(cloneOut(arr[0].outbound, tag)); tag }
                else -> "direct"
            }
        }

        fun tagFor(target: String?): String {
            if (target.isNullOrEmpty() || target == "direct") return "direct"
            if (target == "block") return "block"
            if (target.startsWith("chain:")) return chainTag(chainsById[target.substring(6)], "out-chain-" + target.substring(6))
            val s = serversById[target]
            if (s != null && s.outbound.length() > 0) { val tag = "out-$target"; add(cloneOut(s.outbound, tag)); return tag }
            return "direct"
        }
    }

    /* ----------------------------- shared bits ----------------------------- */

    private fun standardInbounds(s: AppSettings, listen: String, sniffing: JSONObject): JSONArray = JSONArray()
        .put(JSONObject().put("tag", "socks-in").put("port", s.socksPort).put("listen", listen)
            .put("protocol", "socks").put("settings", JSONObject().put("auth", "noauth").put("udp", true)).put("sniffing", sniffing))
        .put(JSONObject().put("tag", "http-in").put("port", s.httpPort).put("listen", listen)
            .put("protocol", "http").put("settings", JSONObject()).put("sniffing", sniffing))
        .put(apiInbound(s))

    private fun apiInbound(s: AppSettings): JSONObject = JSONObject()
        .put("tag", "api").put("port", s.apiPort).put("listen", "127.0.0.1")
        .put("protocol", "dokodemo-door").put("settings", JSONObject().put("address", "127.0.0.1"))

    private fun assemble(s: AppSettings, listen: String, sniffing: JSONObject,
                         inbounds: JSONArray, outbounds: JSONArray, rules: JSONArray): JSONObject {
        val wgChained = false // WireGuard outbounds aren't produced on Android yet
        val level0 = JSONObject().put("statsUserUplink", true).put("statsUserDownlink", true)
        if (wgChained) level0.put("bufferSize", 0)
        return JSONObject()
            .put("log", JSONObject().put("loglevel", s.logLevel))
            .put("api", JSONObject().put("tag", "api").put("services", JSONArray().put("StatsService")))
            .put("stats", JSONObject())
            .put("policy", JSONObject()
                .put("levels", JSONObject().put("0", level0))
                .put("system", JSONObject().put("statsInboundUplink", true).put("statsInboundDownlink", true)
                    .put("statsOutboundUplink", true).put("statsOutboundDownlink", true)))
            .put("dns", JSONObject().put("servers", JSONArray(s.dns)).put("queryStrategy", "UseIP"))
            .put("inbounds", inbounds)
            .put("outbounds", outbounds)
            .put("routing", JSONObject().put("domainStrategy", "IPIfNonMatch").put("rules", rules))
    }

    private fun cloneOut(outbound: JSONObject, tag: String): JSONObject =
        JSONObject(outbound.toString()).put("tag", tag)

    private fun dialThrough(outbound: JSONObject, viaTag: String) {
        val stream = outbound.optJSONObject("streamSettings") ?: JSONObject().also { outbound.put("streamSettings", it) }
        val sockopt = stream.optJSONObject("sockopt") ?: JSONObject().also { stream.put("sockopt", it) }
        sockopt.put("dialerProxy", viaTag)
    }

    private fun freedom(): JSONObject = JSONObject().put("tag", "direct").put("protocol", "freedom")
        .put("settings", JSONObject().put("domainStrategy", "UseIP"))

    private fun blackhole(): JSONObject = JSONObject().put("tag", "block").put("protocol", "blackhole")
        .put("settings", JSONObject().put("response", JSONObject().put("type", "http")))

    private fun rule(inbound: List<String>, out: String): JSONObject =
        JSONObject().put("type", "field").put("inboundTag", JSONArray(inbound)).put("outboundTag", out)

    // static helper so Registry (nested) can reuse chain building
    private fun buildChainOutboundsStatic(members: List<ServerConfig>, exitTag: String): List<JSONObject> =
        buildChainOutbounds(members, exitTag)
}
