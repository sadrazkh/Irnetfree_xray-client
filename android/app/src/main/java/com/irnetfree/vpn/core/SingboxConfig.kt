package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Android counterpart of the desktop `singboxBuilder.js`: translate one server
 * (our Xray-shaped model) into a sing-box config, used only for configs whose
 * per-config engine is 'sing-box'.
 *
 * sing-box runs as a subprocess with the SAME local socks/http inbounds on the
 * SAME ports the Xray core would use, so the VpnService TUN + hev tun2socks +
 * traffic stats keep working unchanged (only the core process differs). uTLS is
 * the realistic ("fake") ClientHello — sing-box's anti-DPI edge.
 *
 * Supports vless/vmess/trojan/shadowsocks/socks/http and hysteria2 over
 * tcp/ws/grpc/http/httpupgrade with tls/reality (and ECH). WireGuard, kcp and
 * xhttp throw so the caller falls back to Xray.
 */
object SingboxConfig {

    class Unsupported(msg: String) : Exception(msg)

    /**
     * [auth]: the session's credentials for both inbounds (LocalAuth.kt), as ConfigBuilder puts them on Xray's.
     * [lan]: LAN sharing (LanShare) — two more inbounds on every interface. Nothing
     * here routes by inbound, so they take the tunnel's route as they are; the
     * only rules of their own keep them off loopback, as on Xray.
     */
    fun build(server: ServerConfig, s: AppSettings, auth: LocalAuth? = null, lan: LanShare? = null): JSONObject {
        val listen = "127.0.0.1"
        val socks = JSONObject().put("type", "socks").put("tag", "socks-in").put("listen", listen).put("listen_port", s.socksPort)
        val http = JSONObject().put("type", "http").put("tag", "http-in").put("listen", listen).put("listen_port", s.httpPort)
        if (auth != null) {
            socks.put("users", JSONArray().put(JSONObject().put("username", auth.user).put("password", auth.pass)))
            http.put("users", JSONArray().put(JSONObject().put("username", auth.user).put("password", auth.pass)))
        }
        // a latency test asks for SOCKS alone (httpPort 0): the HTTP port is the live connection's
        val inbounds = JSONArray().put(socks)
        if (s.httpPort > 0) inbounds.put(http)
        val lanTags = ArrayList<String>()
        if (lan != null && lan.enabled) {
            val taken = setOf(s.socksPort, s.httpPort)
            fun users(): JSONArray = JSONArray().put(JSONObject().put("username", lan.user).put("password", lan.pass))
            if (lan.socksPort !in taken) {
                val o = JSONObject().put("type", "socks").put("tag", LanShare.SOCKS_TAG).put("listen", LanShare.LISTEN).put("listen_port", lan.socksPort)
                if (lan.auth) o.put("users", users())
                inbounds.put(o); lanTags.add(LanShare.SOCKS_TAG)
            }
            if (lan.httpPort !in taken && lan.httpPort != lan.socksPort) {
                val o = JSONObject().put("type", "http").put("tag", LanShare.HTTP_TAG).put("listen", LanShare.LISTEN).put("listen_port", lan.httpPort)
                if (lan.auth) o.put("users", users())
                inbounds.put(o); lanTags.add(LanShare.HTTP_TAG)
            }
        }

        val outbounds = JSONArray()
            .put(translateOutbound(server))
            .put(JSONObject().put("type", "direct").put("tag", "direct"))

        // Explicit DNS via `direct`. sing-box is a Go binary and on Android can't
        // read the system resolver, so without this the server domain never
        // resolves and nothing connects. (This is the usual "works on Xray, not on
        // sing-box" cause.) Resolving via `direct` also keeps it off the tunnel.
        // A plain address the sing-box `udp` server can take: the first literal
        // resolver in the remote list (a DoH URL gives its address), else 1.1.1.1.
        val dnsServer = s.dnsRemote.mapNotNull { DnsPlan.resolverIp(it) }.firstOrNull() ?: "1.1.1.1"
        val dns = JSONObject()
            .put("servers", JSONArray().put(JSONObject()
                .put("type", "udp").put("tag", "dns-direct").put("server", dnsServer)))
            .put("final", "dns-direct")

        // resolve outbound server domains via dns-direct (no resolve→proxy loop)
        val route = JSONObject().put("final", "proxy").put("default_domain_resolver", "dns-direct")
        if (lanTags.isNotEmpty()) route.put("rules", JSONArray()
            .put(JSONObject().put("inbound", JSONArray(lanTags)).put("ip_cidr", JSONArray(ConfigBuilder.LOOPBACK)).put("action", "reject"))
            .put(JSONObject().put("inbound", JSONArray(lanTags)).put("domain_suffix", JSONArray().put("localhost")).put("action", "reject")))
        return JSONObject()
            .put("log", JSONObject().put("level", logLevel(s.logLevel)).put("timestamp", false))
            .put("dns", dns)
            .put("inbounds", inbounds)
            .put("outbounds", outbounds)
            .put("route", route)
    }

    private fun logLevel(x: String): String {
        val v = x.lowercase()
        if (v == "warning") return "warn"
        return if (v in listOf("trace", "debug", "info", "warn", "error", "fatal", "panic")) v else "warn"
    }

    private fun translateOutbound(server: ServerConfig): JSONObject {
        val ob = server.outbound
        val proto = server.protocol
        val ss = ob.optJSONObject("streamSettings") ?: JSONObject()
        val out = JSONObject().put("tag", "proxy").put("server", server.address).put("server_port", server.port)

        when (proto) {
            "vless" -> {
                val u = vnextUser(ob)
                out.put("type", "vless").put("uuid", u.optString("id"))
                val flow = u.optString("flow"); if (flow.isNotBlank()) out.put("flow", flow)
                out.put("packet_encoding", "xudp")
            }
            "vmess" -> {
                val u = vnextUser(ob)
                out.put("type", "vmess").put("uuid", u.optString("id"))
                    .put("security", u.optString("security", "auto")).put("alter_id", u.optInt("alterId", 0))
            }
            "trojan" -> out.put("type", "trojan").put("password", serverObj(ob).optString("password"))
            "shadowsocks" -> {
                val srv = serverObj(ob)
                out.put("type", "shadowsocks").put("method", srv.optString("method")).put("password", srv.optString("password"))
                // A plugin's transport (LinkParser.ssStream) goes back to being the
                // plugin: sing-box runs obfs-local and v2ray-plugin itself, and its
                // Shadowsocks takes no transport or TLS of its own.
                val plugin = LinkParser.ssPluginOf(ss)
                if (plugin.isNotEmpty()) {
                    val i = plugin.indexOf(';')
                    out.put("plugin", if (i == -1) plugin else plugin.substring(0, i))
                    if (i != -1) out.put("plugin_opts", plugin.substring(i + 1))
                } else {
                    val n = ss.optString("network", "tcp").lowercase(); val sec = ss.optString("security", "none")
                    if ((n.isNotEmpty() && n != "tcp" && n != "raw") || (sec.isNotEmpty() && sec != "none"))
                        throw Unsupported("sing-box: Shadowsocks over '$n'/$sec is not supported (use Xray)")
                }
                return out
            }
            "hysteria2" -> return translateHysteria2(server)
            "socks" -> {
                out.put("type", "socks").put("version", "5")
                serverObj(ob).optJSONArray("users")?.optJSONObject(0)?.let {
                    if (it.optString("user").isNotBlank()) out.put("username", it.optString("user")).put("password", it.optString("pass"))
                }
            }
            "http" -> {
                out.put("type", "http")
                serverObj(ob).optJSONArray("users")?.optJSONObject(0)?.let {
                    if (it.optString("user").isNotBlank()) out.put("username", it.optString("user")).put("password", it.optString("pass"))
                }
            }
            else -> throw Unsupported("sing-box: protocol '$proto' not supported (use Xray)")
        }

        translateTls(ss, server.address)?.let {
            // sing-box (1.12+) splits the ClientHello itself: the link's fragment
            // setting asks for exactly that (its sizes and delays are Xray's knobs).
            if (ob.optString("_fragment").isNotBlank()) it.put("fragment", true)
            out.put("tls", it)
        }
        // Reject transports sing-box can't express so the caller falls back to Xray
        // instead of silently dialing plain TCP (which would just fail to connect).
        val net = ss.optString("network", "tcp").lowercase()
        if (net !in listOf("tcp", "raw", "ws", "grpc", "http", "h2", "httpupgrade")) {
            throw Unsupported("sing-box: '$net' transport not supported (use Xray)")
        }
        // RAW's HTTP header obfuscation has no sing-box counterpart
        if ((net == "tcp" || net == "raw") && ss.optJSONObject("tcpSettings")?.optJSONObject("header")?.optString("type") == "http") {
            throw Unsupported("sing-box: the TCP HTTP header is not supported (use Xray)")
        }
        translateTransport(ss)?.let { out.put("transport", it) }
        return out
    }

    /**
     * Hysteria2 (singboxBuilder.js translateHysteria2) — the record keeps it in
     * the Xray core's shape (LinkParser); this is sing-box's: the password, the
     * salamander obfuscation, port hopping as `from:to` ranges, Mbps.
     */
    private fun translateHysteria2(server: ServerConfig): JSONObject {
        val ss = server.outbound.optJSONObject("streamSettings") ?: JSONObject()
        val h = LinkParser.hy2Values(server.outbound)
        val out = JSONObject().put("type", "hysteria2").put("tag", "proxy").put("server", server.address)
            .put("server_port", server.port).put("password", h["auth"] ?: "")
        val ports = (h["mport"] ?: "").split(",").map { it.trim() }.filter { it.isNotEmpty() }
        if (ports.isNotEmpty()) {
            out.remove("server_port")
            out.put("server_ports", JSONArray(ports.map { if (it.contains('-')) it.replace('-', ':') else "$it:$it" }))
            // "10-20" (the core's range): its first number, as the desktop's parseInt reads it
            Regex("^\\d+").find(h["hopInterval"] ?: "")?.value?.toIntOrNull()?.takeIf { it > 0 }?.let { out.put("hop_interval", "${it}s") }
        }
        (h["obfs-password"] ?: "").takeIf { it.isNotEmpty() }?.let { out.put("obfs", JSONObject().put("type", "salamander").put("password", it)) }
        fun mbps(v: String?): Int = Regex("^(\\d+(?:\\.\\d+)?)\\s*m", RegexOption.IGNORE_CASE).find(v ?: "")?.groupValues?.get(1)?.toDouble()?.let { Math.round(it).toInt() } ?: 0
        mbps(h["up"]).takeIf { it > 0 }?.let { out.put("up_mbps", it) }
        mbps(h["down"]).takeIf { it > 0 }?.let { out.put("down_mbps", it) }
        val tls = translateTls(ss, server.address) ?: JSONObject().put("enabled", true).put("server_name", server.address)
        tls.remove("utls")   // QUIC: no uTLS fingerprint
        out.put("tls", tls)
        return out
    }

    private fun translateTls(ss: JSONObject, addr: String): JSONObject? {
        val security = ss.optString("security", "none").lowercase()
        if (security != "tls" && security != "reality") return null
        val t = ss.optJSONObject("tlsSettings") ?: ss.optJSONObject("realitySettings") ?: JSONObject()
        val tls = JSONObject().put("enabled", true)
        tls.put("server_name", t.optString("serverName").ifBlank { addr })
        // sing-box can pin neither a certificate's hash (`pcs`: it pins a public
        // key) nor verify it against another name (`vcn`): a link that carries one
        // has a certificate the usual check refuses, so — as allowInsecure did —
        // the check is skipped. The Xray cores keep both checks.
        if (t.optBoolean("allowInsecure") || (security == "tls" && (t.optString("pinnedPeerCertSha256").isNotBlank() || t.optString("verifyPeerCertByName").isNotBlank()))) tls.put("insecure", true)
        val alpn = normalizeAlpn(t.opt("alpn"))
        if (alpn.length() > 0) tls.put("alpn", alpn)
        tls.put("utls", JSONObject().put("enabled", true).put("fingerprint", t.optString("fingerprint", "chrome")))
        if (security == "reality") {
            val r = ss.optJSONObject("realitySettings") ?: JSONObject()
            tls.put("reality", JSONObject().put("enabled", true).put("public_key", r.optString("publicKey")).put("short_id", r.optString("shortId")))
        }
        if (security == "tls") ech(t.optString("echConfigList"))?.let { tls.put("ech", it) }
        return tls
    }

    /**
     * Encrypted Client Hello in sing-box's terms (singboxBuilder.js singboxEch):
     * a base64 ECHConfigList as the PEM block sing-box reads; the DNS form
     * (`name+udp://1.1.1.1`) has sing-box look the record up itself — of `name`,
     * through this config's own resolver (it cannot name one per outbound).
     */
    private fun ech(list: String?): JSONObject? {
        val s = (list ?: "").trim()
        if (s.isEmpty()) return null
        val sep = s.indexOf("://")
        if (sep == -1) return JSONObject().put("enabled", true).put("config", JSONArray().put("-----BEGIN ECH CONFIGS-----").put(s).put("-----END ECH CONFIGS-----"))
        val plus = s.indexOf('+')
        val o = JSONObject().put("enabled", true)
        if (plus in 1 until sep) o.put("query_server_name", s.substring(0, plus))
        return o
    }

    private fun translateTransport(ss: JSONObject): JSONObject? {
        return when (ss.optString("network", "tcp").lowercase()) {
            "ws" -> {
                val w = ss.optJSONObject("wsSettings") ?: JSONObject()
                val tr = JSONObject().put("type", "ws")
                // `/path?ed=2048` is Xray's early data: sing-box wants it spelt out
                var p = w.optString("path")
                Regex("[?&]ed=(\\d+)").find(p)?.let { m ->
                    p = p.replace(Regex("([?&])ed=\\d+&?"), "$1").replace(Regex("[?&]$"), "")
                    tr.put("max_early_data", m.groupValues[1].toInt()).put("early_data_header_name", "Sec-WebSocket-Protocol")
                }
                if (p.isNotBlank()) tr.put("path", p)
                val host = w.optString("host").ifBlank { w.optJSONObject("headers")?.optString("Host") ?: "" }
                if (host.isNotBlank()) tr.put("headers", JSONObject().put("Host", host))
                tr
            }
            "httpupgrade" -> {
                val h = ss.optJSONObject("httpupgradeSettings") ?: JSONObject()
                val tr = JSONObject().put("type", "httpupgrade")
                if (h.optString("host").isNotBlank()) tr.put("host", h.optString("host"))
                if (h.optString("path").isNotBlank()) tr.put("path", h.optString("path"))
                tr
            }
            "grpc" -> JSONObject().put("type", "grpc").put("service_name", (ss.optJSONObject("grpcSettings") ?: JSONObject()).optString("serviceName"))
            "http", "h2" -> {
                val h = ss.optJSONObject("httpSettings") ?: JSONObject()
                val tr = JSONObject().put("type", "http")
                if (h.optString("path").isNotBlank()) tr.put("path", h.optString("path"))
                tr
            }
            else -> null
        }
    }

    private fun vnextUser(ob: JSONObject): JSONObject =
        ob.optJSONObject("settings")?.optJSONArray("vnext")?.optJSONObject(0)?.optJSONArray("users")?.optJSONObject(0) ?: JSONObject()
    private fun serverObj(ob: JSONObject): JSONObject =
        ob.optJSONObject("settings")?.optJSONArray("servers")?.optJSONObject(0) ?: JSONObject()
    private fun normalizeAlpn(v: Any?): JSONArray {
        val out = JSONArray()
        when (v) {
            is JSONArray -> for (i in 0 until v.length()) v.optString(i).trim().takeIf { it.isNotEmpty() }?.let { out.put(it) }
            is String -> v.split(",").map { it.trim() }.filter { it.isNotEmpty() }.forEach { out.put(it) }
        }
        return out
    }
}
