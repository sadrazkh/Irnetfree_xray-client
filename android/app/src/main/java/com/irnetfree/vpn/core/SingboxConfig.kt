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
 * Supports vless/vmess/trojan/shadowsocks/socks/http over tcp/ws/grpc with
 * tls/reality. WireGuard and anything else throws so the caller falls back to
 * Xray. Fragment is Xray-only (mainline sing-box has no tls_fragment).
 */
object SingboxConfig {

    class Unsupported(msg: String) : Exception(msg)

    fun build(server: ServerConfig, s: AppSettings): JSONObject {
        val listen = "127.0.0.1"
        val inbounds = JSONArray()
            .put(JSONObject().put("type", "socks").put("tag", "socks-in").put("listen", listen).put("listen_port", s.socksPort))
            .put(JSONObject().put("type", "http").put("tag", "http-in").put("listen", listen).put("listen_port", s.httpPort))

        val outbounds = JSONArray()
            .put(translateOutbound(server))
            .put(JSONObject().put("type", "direct").put("tag", "direct"))

        // Explicit DNS via `direct`. sing-box is a Go binary and on Android can't
        // read the system resolver, so without this the server domain never
        // resolves and nothing connects. (This is the usual "works on Xray, not on
        // sing-box" cause.) Resolving via `direct` also keeps it off the tunnel.
        val dnsServer = s.dns.firstOrNull()?.takeIf { it.isNotBlank() } ?: "1.1.1.1"
        val dns = JSONObject()
            .put("servers", JSONArray().put(JSONObject()
                .put("type", "udp").put("tag", "dns-direct").put("server", dnsServer)))
            .put("final", "dns-direct")

        return JSONObject()
            .put("log", JSONObject().put("level", logLevel(s.logLevel)).put("timestamp", false))
            .put("dns", dns)
            .put("inbounds", inbounds)
            .put("outbounds", outbounds)
            // resolve outbound server domains via dns-direct (no resolve→proxy loop)
            .put("route", JSONObject().put("final", "proxy").put("default_domain_resolver", "dns-direct"))
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
            }
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

        translateTls(ss, server.address)?.let { out.put("tls", it) }
        // Reject transports sing-box can't express so the caller falls back to Xray
        // instead of silently dialing plain TCP (which would just fail to connect).
        val net = ss.optString("network", "tcp").lowercase()
        if (net !in listOf("tcp", "raw", "ws", "grpc", "http", "h2")) {
            throw Unsupported("sing-box: '$net' transport not supported (use Xray)")
        }
        translateTransport(ss)?.let { out.put("transport", it) }
        // NOTE: fragment (`_fragment`) is intentionally ignored — mainline sing-box
        // has no TLS-fragment option; uTLS covers the fake-ClientHello need.
        return out
    }

    private fun translateTls(ss: JSONObject, addr: String): JSONObject? {
        val security = ss.optString("security", "none").lowercase()
        if (security != "tls" && security != "reality") return null
        val t = ss.optJSONObject("tlsSettings") ?: ss.optJSONObject("realitySettings") ?: JSONObject()
        val tls = JSONObject().put("enabled", true)
        tls.put("server_name", t.optString("serverName").ifBlank { addr })
        if (t.optBoolean("allowInsecure")) tls.put("insecure", true)
        val alpn = normalizeAlpn(t.opt("alpn"))
        if (alpn.length() > 0) tls.put("alpn", alpn)
        tls.put("utls", JSONObject().put("enabled", true).put("fingerprint", t.optString("fingerprint", "chrome")))
        if (security == "reality") {
            val r = ss.optJSONObject("realitySettings") ?: JSONObject()
            tls.put("reality", JSONObject().put("enabled", true).put("public_key", r.optString("publicKey")).put("short_id", r.optString("shortId")))
        }
        return tls
    }

    private fun translateTransport(ss: JSONObject): JSONObject? {
        return when (ss.optString("network", "tcp").lowercase()) {
            "ws" -> {
                val w = ss.optJSONObject("wsSettings") ?: JSONObject()
                val tr = JSONObject().put("type", "ws")
                if (w.optString("path").isNotBlank()) tr.put("path", w.optString("path"))
                val host = w.optJSONObject("headers")?.optString("Host")
                if (!host.isNullOrBlank()) tr.put("headers", JSONObject().put("Host", host))
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
