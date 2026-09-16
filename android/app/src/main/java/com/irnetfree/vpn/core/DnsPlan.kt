package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Port of src/main/dnsBuilder.js — the resolver plan and the routing rules that
 * make it safe. Function for function; tests/dnsBuilder.test.js is the
 * specification and DnsPlanTest mirrors its pins.
 *
 * Why this exists (from the desktop): the old config listed plain UDP resolvers
 * and let them ride through the proxy. When the server dropped UDP — common —
 * every lookup failed, `geoip:ir` never matched, and "bypass Iran" silently
 * became "everything through the proxy"; under the VPN the whole phone's DNS
 * took the same doomed path. The plan: remote lookups over DoH (TCP/443) routed
 * to the tunnel exit; in bypass modes an in-country UDP resolver pinned to
 * domestic domains, reached direct; a `dns` outbound answering ANY port-53
 * packet that enters the core; and a resolver that belongs to a routing target
 * (a corporate WireGuard's DNS) asked through that target's own outbound.
 */
object DnsPlan {
    const val DNS_TAG = "dns-internal"
    const val HIJACK_TAG = "dns-out"
    val DEFAULT_REMOTE = listOf("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query")
    /** Shecan — the usual in-country resolver; a user can pick another. */
    val DEFAULT_DIRECT_IR = listOf("178.22.122.100", "185.51.200.2")
    /** AliDNS for the China bypass — not user-configurable. */
    val DEFAULT_DIRECT_CN = listOf("223.5.5.5")

    private val URL_SCHEME = Regex("^[a-z+]+://", RegexOption.IGNORE_CASE)
    private val URL_HOST = Regex("^([a-z+]+)://(\\[[^\\]]+\\]|[^/:?#]+)(?::(\\d{1,5}))?", RegexOption.IGNORE_CASE)
    private val IPV4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private val IPV6_CHARS = Regex("^[0-9a-fA-F:.]+$")

    /** A resolver a routing target brings with it (configBuilder.wgResolvers). */
    data class TargetResolver(
        val address: String,
        val outboundTag: String,
        val expectedIPs: List<String> = emptyList(),
        val domains: List<String> = emptyList()
    )

    class Result(
        val dns: JSONObject,
        val hijackOutbound: JSONObject?,
        val rules: List<JSONObject>,
        val directResolverIps: List<String>
    )

    fun isDohUrl(s: String?): Boolean = Regex("^https(\\+local)?://", RegexOption.IGNORE_CASE).containsMatchIn((s ?: "").trim())

    /** "host:port" / "[v6]:port" → host to port; anything else keeps port null. */
    fun splitHostPort(e: String): Pair<String, Int?> {
        Regex("^\\[([^\\]]+)\\]:(\\d{1,5})$").find(e)?.let { return it.groupValues[1] to it.groupValues[2].toInt() }
        Regex("^([^:/]+):(\\d{1,5})$").find(e)?.let { return it.groupValues[1] to it.groupValues[2].toInt() }
        return e to null
    }

    fun isIp(h: String): Boolean = isIpv4(h) || isIpv6(h)
    fun isIpv4(h: String): Boolean = IPV4.matches(h) && h.split(".").all { it.toInt() <= 255 }
    fun isIpv6(h: String): Boolean = h.contains(":") && IPV6_CHARS.matches(h) && h.count { it == ':' } >= 2

    /**
     * The address the core will dial for an entry, if it is a literal IP:
     * "8.8.8.8" → "8.8.8.8"; "1.1.1.1:5353" → "1.1.1.1"; "https://1.1.1.1/dns-query"
     * → "1.1.1.1"; a hostname (bare or in a URL) → null.
     */
    fun resolverIp(entry: String?): String? {
        val e = (entry ?: "").trim()
        val m = URL_HOST.find(e)
        val host = if (m != null) m.groupValues[2].removePrefix("[").removeSuffix("]") else splitHostPort(e).first
        return if (isIp(host)) host else null
    }

    /**
     * The port the core dials for an entry: the URL's or the host:port's own,
     * else the scheme's default — 443 for DoH, 853 for DNS over QUIC, 53 for
     * everything plain.
     */
    fun resolverPort(entry: String?): Int {
        val e = (entry ?: "").trim()
        val m = URL_HOST.find(e)
        if (m != null) {
            m.groupValues[3].takeIf { it.isNotEmpty() }?.let { return it.toInt() }
            val scheme = m.groupValues[1].lowercase()
            if (scheme.startsWith("https")) return 443
            if (scheme.startsWith("quic")) return 853
            return 53
        }
        return splitHostPort(e).second ?: 53
    }

    /** RFC1918 / loopback / link-local / CGNAT v4, ULA / link-local / loopback v6. */
    fun isPrivateIp(ip: String): Boolean {
        if (isIpv4(ip)) {
            val p = ip.split(".").map { it.toInt() }
            val a = p[0]; val b = p[1]
            return a == 10 || a == 127 || (a == 172 && b in 16..31) || (a == 192 && b == 168) ||
                (a == 169 && b == 254) || (a == 100 && b in 64..127)
        }
        return Regex("^(fc|fd|fe80:|::1$)", RegexOption.IGNORE_CASE).containsMatchIn(ip)
    }

    /**
     * A resolver entry in the shape the core accepts. A URL or a bare address is
     * a string; "host:port" must become { address, port }.
     */
    fun serverEntry(entry: String): Any {
        val e = entry.trim()
        if (URL_SCHEME.containsMatchIn(e)) return e
        val (host, port) = splitHostPort(e)
        return if (port != null) JSONObject().put("address", host).put("port", port) else e
    }

    /** A CIDR that only an AAAA answer could ever fall in. */
    private fun isV6Range(c: String): Boolean = c.contains(":") && !c.lowercase().startsWith("geoip:")

    fun cleanList(list: List<String>?): List<String> {
        val out = ArrayList<String>()
        for (raw in list ?: emptyList()) { val v = raw.trim(); if (v.isNotEmpty() && v !in out) out.add(v) }
        return out
    }

    /**
     * Which in-country resolver set a plan needs, if any: "ir" | "cn" | null.
     * Simple modes follow routingMode; advanced routing needs one only when a
     * domain rule sends the matching geosite list DIRECT, or when the plan
     * applies a simple mode on top (`advancedUseMode`). `geoAssets` is the veto:
     * without the geo files the router emits no bypass at all, and a domestic
     * resolver kept anyway would hand an Iranian server, in cleartext UDP off
     * the tunnel, exactly the names the traffic then hides.
     */
    fun directRegion(s: AppSettings, geoAssets: Boolean): String? {
        if (!geoAssets) return null
        if (s.advancedRouting) {
            var region: String? = null
            for (r in s.routeRules) {
                if (r.type != "domain" || r.target != "direct") continue
                val v = r.value.lowercase()
                if (v.contains("geosite:category-ir")) return "ir"
                if (v.contains("geosite:cn")) region = region ?: "cn"
            }
            if (region != null || !s.advancedUseMode) return region
            // else fall through to the routing mode the plan also applies
        }
        return when (s.routingMode) { "bypass-ir" -> "ir"; "bypass-cn" -> "cn"; else -> null }
    }

    private fun fieldRule() = JSONObject().put("type", "field")

    /**
     * @param s               dnsManaged, dnsRemote, dnsDirect, ipv6, routingMode, advancedRouting, routeRules, advancedUseMode
     * @param geoAssets       are geoip.dat / geosite.dat readable by the core
     * @param exitTag         where the resolver's own queries leave
     * @param targetResolvers resolvers that belong to a routing target (configBuilder.targetResolversFor)
     */
    fun build(s: AppSettings, geoAssets: Boolean, exitTag: String, targetResolvers: List<TargetResolver> = emptyList()): Result {
        val queryStrategy = if (s.ipv6) "UseIP" else "UseIPv4"
        var remote = cleanList(s.dnsRemote)
        if (remote.isEmpty()) remote = DEFAULT_REMOTE

        if (!s.dnsManaged) {
            // Legacy behaviour: the user's servers as given, nothing intercepted.
            val servers = JSONArray(); remote.forEach { servers.put(serverEntry(it)) }
            return Result(JSONObject().put("queryStrategy", queryStrategy).put("servers", servers), null, emptyList(), emptyList())
        }

        val servers = JSONArray()
        val directResolverIps = ArrayList<String>()
        // { ip, port } per resolver the core dials off the tunnel. The direct rule
        // matches BOTH, so a public address that is also a remote DoH server keeps
        // its DoH on the exit: only the plain :53 query to it goes direct.
        val directResolvers = ArrayList<Pair<String, Int>>()
        fun addDirect(entry: String) {
            val ip = resolverIp(entry) ?: return
            val port = resolverPort(entry)
            if (directResolvers.none { it.first == ip && it.second == port }) directResolvers.add(ip to port)
            if (ip !in directResolverIps) directResolverIps.add(ip)
        }

        val region = directRegion(s, geoAssets)
        if (region != null) {
            var direct = if (region == "cn") DEFAULT_DIRECT_CN else cleanList(s.dnsDirect)
            if (direct.isEmpty()) direct = if (region == "cn") DEFAULT_DIRECT_CN else DEFAULT_DIRECT_IR
            val domains = if (region == "ir") listOf("geosite:category-ir", "regexp:.*\\.ir$") else listOf("geosite:cn")
            val expected = if (region == "ir") listOf("geoip:ir") else listOf("geoip:cn")
            for (address in direct.take(2)) {
                val ent = serverEntry(address)
                val srv = if (ent is JSONObject) ent else JSONObject().put("address", ent)
                srv.put("domains", JSONArray(domains))
                srv.put("expectedIPs", JSONArray(expected))
                srv.put("skipFallback", true)   // never ask the domestic resolver about the rest of the world
                servers.put(srv)
                addDirect(address)
            }
        }

        for (r in remote) {
            servers.put(serverEntry(r))
            // A LAN / private-range resolver (a router, a corporate DNS) is only
            // reachable off the tunnel; the exit rule below would send it nowhere.
            val ip = resolverIp(r)
            if (ip != null && isPrivateIp(ip)) addDirect(r)
        }

        // Resolvers that belong to a routing target. They go LAST: the public
        // resolver answers everything it knows and only its NXDOMAIN falls
        // through to the target's server. `domains` (the search domains) hands
        // those names to the target's server FIRST, and with search domains
        // `skipFallback` too — a resolver reachable only THROUGH the tunnel must
        // never be the fallback for the names the tunnel itself needs. Their
        // queries must leave through the target — never `direct`.
        val targetRules = ArrayList<JSONObject>()
        for (t in targetResolvers) {
            if (t.address.isBlank() || t.outboundTag.isBlank()) continue
            val ent = serverEntry(t.address)
            val srv = if (ent is JSONObject) ent else JSONObject().put("address", ent)
            if (t.domains.isNotEmpty()) {
                srv.put("domains", JSONArray(t.domains))
                srv.put("skipFallback", true)
            }
            if (t.expectedIPs.isNotEmpty()) {
                val exp = if (s.ipv6) t.expectedIPs else t.expectedIPs.filter { !isV6Range(it) }
                if (exp.isNotEmpty()) srv.put("expectedIPs", JSONArray(exp))
            }
            servers.put(srv)
            val ip = resolverIp(t.address)
            if (ip != null && targetRules.none { it.getJSONArray("ip").getString(0) == ip }) {
                targetRules.add(fieldRule().put("inboundTag", JSONArray().put(DNS_TAG)).put("ip", JSONArray().put(ip)).put("outboundTag", t.outboundTag))
            }
        }

        // Rule order matters: the resolver's own traffic must be decided BEFORE
        // the port-53 hijack. Direct resolvers → target resolvers → everything
        // else to the exit → the hijack. A resolver imported from a routing target
        // can also occur in the user's lists: its explicit target owns that IP.
        val targetIps = targetRules.map { it.getJSONArray("ip").getString(0) }.toSet()
        directResolverIps.removeAll { it in targetIps }
        val rules = ArrayList<JSONObject>()
        val byPort = LinkedHashMap<Int, ArrayList<String>>()
        for ((ip, port) in directResolvers) {
            if (ip in targetIps) continue
            byPort.getOrPut(port) { ArrayList() }.add(ip)
        }
        for ((port, ips) in byPort) {
            rules.add(fieldRule().put("inboundTag", JSONArray().put(DNS_TAG)).put("ip", JSONArray(ips)).put("port", port.toString()).put("outboundTag", "direct"))
        }
        rules.addAll(targetRules)
        rules.add(fieldRule().put("inboundTag", JSONArray().put(DNS_TAG)).put("outboundTag", exitTag))
        rules.add(fieldRule().put("port", "53").put("network", "tcp,udp").put("outboundTag", HIJACK_TAG))

        // Every non-A/AAAA query (PTR/SRV/TXT/HTTPS…) is answered REFUSED (rCode 5)
        // instead of being forwarded to its original destination through a direct
        // dial — under the VPN that is the tunnel itself, so it would loop.
        val hijack = JSONObject().put("tag", HIJACK_TAG).put("protocol", "dns").put("settings", JSONObject().put("rules",
            JSONArray().put(JSONObject().put("action", "return").put("rCode", 5).put("qType", "0,2-27,29-65535"))))
        return Result(JSONObject().put("tag", DNS_TAG).put("queryStrategy", queryStrategy).put("servers", servers), hijack, rules, directResolverIps)
    }

    /**
     * What the VPN's TUN should hand the OS as its resolver. Managed: the tunnel's
     * own address — every query then enters the TUN and is hijacked by dns-out.
     * Otherwise the plain-IP entries of the remote list, falling back to public
     * resolvers the proxy can reach. (dnsBuilder.adapterDnsServers)
     */
    fun adapterDnsServers(s: AppSettings, tunnelPeer: String?): List<String> {
        if (s.dnsManaged && !tunnelPeer.isNullOrBlank()) return listOf(tunnelPeer)
        val ips = cleanList(s.dnsRemote).filter { IPV4.matches(it) }
        return if (ips.isNotEmpty()) ips.take(2) else listOf("1.1.1.1", "8.8.8.8")
    }
}
