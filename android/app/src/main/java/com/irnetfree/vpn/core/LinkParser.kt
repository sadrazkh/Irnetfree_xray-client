package com.irnetfree.vpn.core

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLDecoder

/**
 * Share-link parser: converts vless:// vmess:// trojan:// ss:// socks:// links
 * into Xray outbound JSON (+ a normalized ServerConfig). Ported from the desktop
 * parser.js so both clients produce identical outbounds.
 */
object LinkParser {

    private val SCHEME_RE = Regex("^(vless|vmess|trojan|ss|socks|socks5|wireguard|wg)://", RegexOption.IGNORE_CASE)

    fun parseMany(text: String): Pair<List<ServerConfig>, List<String>> {
        var body = text.trim()
        if (!SCHEME_RE.containsMatchIn(body)) {
            val decoded = b64(body)
            if (SCHEME_RE.containsMatchIn(decoded)) body = decoded
        }
        val out = ArrayList<ServerConfig>()
        val errors = ArrayList<String>()
        for (raw in body.split(Regex("\\r?\\n"))) {
            val line = raw.trim()
            if (line.isEmpty() || !SCHEME_RE.containsMatchIn(line)) continue
            try {
                out.add(parseLink(line))
            } catch (e: Exception) {
                errors.add(line.take(24) + "… : " + (e.message ?: "error"))
            }
        }
        return out to errors
    }

    fun parseLink(link: String): ServerConfig {
        val l = link.trim()
        return when {
            l.startsWith("vless://", true) -> parseVless(l)
            l.startsWith("vmess://", true) -> parseVmess(l)
            l.startsWith("trojan://", true) -> parseTrojan(l)
            l.startsWith("ss://", true) -> parseShadowsocks(l)
            l.startsWith("socks://", true) || l.startsWith("socks5://", true) -> parseSocks(l)
            l.startsWith("wireguard://", true) || l.startsWith("wg://", true) -> parseWireguard(l)
            else -> throw IllegalArgumentException("Unsupported link")
        }
    }

    /** Build a SOCKS/HTTP proxy outbound (mirrors parser.js buildProxyOutbound). */
    fun proxyOutbound(proto: String, address: String, port: Int, user: String, pass: String): JSONObject {
        val server = JSONObject().put("address", address).put("port", port)
        if (user.isNotEmpty() || pass.isNotEmpty()) {
            server.put("users", JSONArray().put(JSONObject().put("user", user).put("pass", pass)))
        }
        return JSONObject()
            .put("protocol", if (proto == "http") "http" else "socks")
            .put("settings", JSONObject().put("servers", JSONArray().put(server)))
            .put("streamSettings", JSONObject().put("network", "tcp"))
    }

    fun makeProxyServer(type: String, name: String, address: String, port: Int, user: String, pass: String): ServerConfig {
        val t = if (type == "http") "http" else "socks"
        val ob = proxyOutbound(t, address, port, user, pass)
        return ServerConfig(newId("px"), name.ifBlank { address }, t, address, port, ob)
    }

    /* ------------------------- protocol parsers ------------------------- */

    private fun parseVless(link: String): ServerConfig {
        val body = link.substring("vless://".length)
        val (main, name) = splitHash(body)
        val (beforeQ, q) = splitQuery(main)
        val at = beforeQ.lastIndexOf('@')
        val uuid = beforeQ.substring(0, at)
        val (address, portStr) = splitHostPort(beforeQ.substring(at + 1))
        val port = portStr.toIntOrNull() ?: 443
        val users = JSONObject()
            .put("id", uuid)
            .put("encryption", q["encryption"] ?: "none")
            .put("flow", q["flow"] ?: "")
        val ob = JSONObject()
            .put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(
                JSONObject().put("address", address).put("port", port)
                    .put("users", JSONArray().put(users)))))
            .put("streamSettings", buildStream(q))
        q["fragment"]?.let { ob.put("_fragment", it) }   // TLS fragmentation from the link
        return ServerConfig(newId("s"), name.ifBlank { address }, "vless", address, port, ob)
    }

    private fun parseVmess(link: String): ServerConfig {
        val json = b64(link.substring("vmess://".length))
        val v = JSONObject(json)
        val address = v.optString("add")
        val port = v.optString("port").toIntOrNull() ?: 443
        val net = v.optString("net", "tcp").lowercase()
        val tls = v.optString("tls").lowercase()
        val q = hashMapOf(
            "type" to net,
            "security" to if (tls == "tls") "tls" else "none",
            "path" to v.optString("path", "/"),
            "host" to v.optString("host"),
            "sni" to v.optString("sni", v.optString("host")),
            "fp" to v.optString("fp", "chrome"),
            "alpn" to v.optString("alpn"),
            "serviceName" to v.optString("path"),
            "headerType" to v.optString("type", "none")
        )
        val user = JSONObject()
            .put("id", v.optString("id"))
            .put("alterId", v.optString("aid").toIntOrNull() ?: 0)
            .put("security", v.optString("scy", "auto"))
        val ob = JSONObject()
            .put("protocol", "vmess")
            .put("settings", JSONObject().put("vnext", JSONArray().put(
                JSONObject().put("address", address).put("port", port)
                    .put("users", JSONArray().put(user)))))
            .put("streamSettings", buildStream(q))
        if (v.has("fragment")) ob.put("_fragment", v.optString("fragment"))
        return ServerConfig(newId("s"), v.optString("ps", address), "vmess", address, port, ob)
    }

    private fun parseTrojan(link: String): ServerConfig {
        val body = link.substring("trojan://".length)
        val (main, name) = splitHash(body)
        val (beforeQ, q0) = splitQuery(main)
        val q = HashMap(q0)
        if (q["security"] == null) q["security"] = "tls"
        val at = beforeQ.lastIndexOf('@')
        val password = dec(beforeQ.substring(0, at))
        val (address, portStr) = splitHostPort(beforeQ.substring(at + 1))
        val port = portStr.toIntOrNull() ?: 443
        val ob = JSONObject()
            .put("protocol", "trojan")
            .put("settings", JSONObject().put("servers", JSONArray().put(
                JSONObject().put("address", address).put("port", port).put("password", password))))
            .put("streamSettings", buildStream(q))
        q["fragment"]?.let { ob.put("_fragment", it) }
        return ServerConfig(newId("s"), name.ifBlank { address }, "trojan", address, port, ob)
    }

    private fun parseShadowsocks(link: String): ServerConfig {
        val body = link.substring("ss://".length)
        val (mainWithHash, name) = splitHash(body)
        var main = mainWithHash
        val qi = main.indexOf('?')
        if (qi != -1) main = main.substring(0, qi)

        val method: String; val password: String; val address: String; var portStr: String
        if (main.contains("@")) {
            val at = main.lastIndexOf('@')
            val userInfo = main.substring(0, at)
            val decoded = b64(userInfo).ifEmpty { dec(userInfo) }
            val ci = decoded.indexOf(':')
            method = decoded.substring(0, ci); password = decoded.substring(ci + 1)
            val hp = splitHostPort(main.substring(at + 1)); address = hp.first; portStr = hp.second
        } else {
            val decoded = b64(main)
            val at = decoded.lastIndexOf('@')
            val userInfo = decoded.substring(0, at)
            val ci = userInfo.indexOf(':')
            method = userInfo.substring(0, ci); password = userInfo.substring(ci + 1)
            val hp = splitHostPort(decoded.substring(at + 1)); address = hp.first; portStr = hp.second
        }
        val port = portStr.toIntOrNull() ?: 443
        val ob = JSONObject()
            .put("protocol", "shadowsocks")
            .put("settings", JSONObject().put("servers", JSONArray().put(
                JSONObject().put("address", address).put("port", port)
                    .put("method", method).put("password", password).put("uot", true))))
            .put("streamSettings", JSONObject().put("network", "tcp"))
        return ServerConfig(newId("s"), name.ifBlank { address }, "shadowsocks", address, port, ob)
    }

    private fun parseSocks(link: String): ServerConfig {
        val scheme = if (link.startsWith("socks5://", true)) "socks5://" else "socks://"
        val body = link.substring(scheme.length)
        val (mainWithHash, name) = splitHash(body)
        var main = mainWithHash
        val qi = main.indexOf('?'); if (qi != -1) main = main.substring(0, qi)

        var user = ""; var pass = ""; val address: String; var portStr: String
        fun creds(raw: String) {
            val ci = raw.indexOf(':')
            if (ci == -1) user = raw else { user = raw.substring(0, ci); pass = raw.substring(ci + 1) }
        }
        if (main.contains("@")) {
            val at = main.lastIndexOf('@')
            val userInfo = main.substring(0, at)
            val decoded = if (userInfo.contains(":")) userInfo else b64(userInfo).ifEmpty { userInfo }
            creds(decoded)
            val hp = splitHostPort(main.substring(at + 1)); address = hp.first; portStr = hp.second
        } else {
            val decoded = b64(main)
            if (decoded.contains("@")) {
                val at = decoded.lastIndexOf('@')
                creds(decoded.substring(0, at))
                val hp = splitHostPort(decoded.substring(at + 1)); address = hp.first; portStr = hp.second
            } else {
                val hp = splitHostPort(main); address = hp.first; portStr = hp.second
            }
        }
        val port = portStr.toIntOrNull() ?: 1080
        val ob = proxyOutbound("socks", address, port, dec(user), dec(pass))
        return ServerConfig(newId("s"), name.ifBlank { address }, "socks", address, port, ob)
    }

    /* ------------------------- WireGuard ------------------------- */

    private fun splitCommas(v: String?): List<String> =
        (v ?: "").split(Regex("[,\\s]+")).map { it.trim() }.filter { it.isNotEmpty() }

    /** Xray requires the interface address to be /32 (IPv4) or /128 (IPv6). */
    private fun normalizeWgAddresses(list: List<String>): List<String> = list
        .map { it.trim() }.filter { it.isNotEmpty() }
        .map { a ->
            val v6 = a.contains(":")
            val host = if (a.indexOf('/') == -1) a else a.substring(0, a.indexOf('/'))
            host + (if (v6) "/128" else "/32")
        }

    fun buildWireguardOutbound(
        privateKey: String, publicKey: String, endpoint: String,
        address: String, presharedKey: String, mtu: String?, reserved: String?, allowedIPs: String?
    ): JSONObject {
        var localAddrs = normalizeWgAddresses(splitCommas(address))
        if (localAddrs.isEmpty()) localAddrs = listOf("10.0.0.2/32")
        val allowed = splitCommas(allowedIPs).ifEmpty { listOf("0.0.0.0/0", "::/0") }
        val peer = JSONObject()
            .put("publicKey", publicKey.trim())
            .put("endpoint", endpoint.trim())
            .put("allowedIPs", JSONArray(allowed))
        if (presharedKey.isNotBlank()) peer.put("preSharedKey", presharedKey.trim())
        val settings = JSONObject()
            .put("secretKey", privateKey.trim())
            .put("address", JSONArray(localAddrs))
            .put("peers", JSONArray().put(peer))
            .put("mtu", mtu?.toIntOrNull() ?: 1420)
        val res = splitCommas(reserved).mapNotNull { it.toIntOrNull() }
        if (res.isNotEmpty()) settings.put("reserved", JSONArray(res))
        return JSONObject().put("protocol", "wireguard").put("settings", settings)
            .put("streamSettings", JSONObject().put("sockopt", JSONObject()))
    }

    private fun parseWireguard(link: String): ServerConfig {
        val scheme = if (link.startsWith("wireguard://", true)) "wireguard://" else "wg://"
        val body = link.substring(scheme.length)
        val (main, name) = splitHash(body)
        val (beforeQ, q) = splitQuery(main)
        val at = beforeQ.lastIndexOf('@')
        val privateKey = dec(if (at == -1) "" else beforeQ.substring(0, at))
        val (address, portStr) = splitHostPort(if (at == -1) beforeQ else beforeQ.substring(at + 1))
        val port = portStr.toIntOrNull() ?: 51820
        val ob = buildWireguardOutbound(
            privateKey = privateKey,
            publicKey = q["publickey"] ?: q["publicKey"] ?: q["peer"] ?: "",
            endpoint = "$address:$port",
            address = q["address"] ?: q["ip"] ?: "",
            presharedKey = q["presharedkey"] ?: q["presharedKey"] ?: q["psk"] ?: "",
            mtu = q["mtu"], reserved = q["reserved"], allowedIPs = q["allowedips"] ?: q["allowedIPs"]
        )
        return ServerConfig(newId("s"), name.ifBlank { address }, "wireguard", address, port, ob, link)
    }

    /** Manual WireGuard from a form. `endpoint` is host:port of the public server. */
    fun makeWireguardServer(
        name: String, endpoint: String, privateKey: String, publicKey: String,
        address: String, allowedIPs: String, presharedKey: String, mtu: String?, reserved: String?
    ): ServerConfig {
        val (host, portStr) = splitHostPort(endpoint)
        val port = portStr.toIntOrNull() ?: 51820
        val ep = if (endpoint.contains(":")) endpoint else "$host:$port"
        val ob = buildWireguardOutbound(privateKey, publicKey, ep, address, presharedKey, mtu, reserved, allowedIPs)
        return ServerConfig(newId("s"), name.ifBlank { host.ifBlank { "WireGuard" } }, "wireguard", host, port, ob, "wireguard://$host:$port")
    }

    /* ------------------------- shared stream builder ------------------------- */

    internal fun buildStream(q: Map<String, String?>): JSONObject {
        val net = (q["type"] ?: q["network"] ?: "tcp").lowercase()
        val security = (q["security"] ?: "none").lowercase()
        val stream = JSONObject().put("network", net).put("security", security)

        when (net) {
            "ws" -> stream.put("wsSettings", JSONObject()
                .put("path", q["path"] ?: "/")
                .put("headers", JSONObject().apply { q["host"]?.takeIf { it.isNotEmpty() }?.let { put("Host", it) } }))
            "grpc" -> stream.put("grpcSettings", JSONObject()
                .put("serviceName", q["serviceName"] ?: q["path"] ?: "")
                .put("multiMode", q["mode"] == "multi"))
            "h2", "http" -> {
                stream.put("network", "h2")
                stream.put("httpSettings", JSONObject()
                    .put("path", q["path"] ?: "/")
                    .put("host", JSONArray().apply { q["host"]?.split(",")?.forEach { put(it) } }))
            }
            "xhttp", "splithttp" -> {
                stream.put("network", "xhttp")
                stream.put("xhttpSettings", JSONObject()
                    .put("path", q["path"] ?: "/").put("host", q["host"] ?: "").put("mode", q["mode"] ?: "auto"))
            }
            "kcp", "mkcp" -> {
                stream.put("network", "kcp")
                stream.put("kcpSettings", JSONObject()
                    .put("header", JSONObject().put("type", q["headerType"] ?: "none")).put("seed", q["seed"] ?: ""))
            }
            "tcp" -> if (q["headerType"] == "http") {
                stream.put("tcpSettings", JSONObject().put("header", JSONObject()
                    .put("type", "http")
                    .put("request", JSONObject()
                        .put("path", JSONArray().put(q["path"] ?: "/"))
                        .put("headers", JSONObject().apply {
                            q["host"]?.takeIf { it.isNotEmpty() }?.let { put("Host", JSONArray().put(it)) }
                        }))))
            }
        }

        if (security == "tls") {
            val tls = JSONObject()
                .put("serverName", q["sni"] ?: q["host"] ?: "")
                .put("allowInsecure", q["allowInsecure"] == "1" || q["allowInsecure"] == "true")
                .put("fingerprint", q["fp"] ?: "chrome")
            q["alpn"]?.takeIf { it.isNotEmpty() }?.let { tls.put("alpn", JSONArray().apply { it.split(",").forEach { a -> put(a) } }) }
            stream.put("tlsSettings", tls)
        } else if (security == "reality") {
            stream.put("realitySettings", JSONObject()
                .put("serverName", q["sni"] ?: "")
                .put("fingerprint", q["fp"] ?: "chrome")
                .put("publicKey", q["pbk"] ?: "")
                .put("shortId", q["sid"] ?: "")
                .put("spiderX", q["spx"] ?: ""))
        }
        return stream
    }

    /* ------------------------- helpers ------------------------- */

    private fun splitHash(body: String): Pair<String, String> {
        val h = body.indexOf('#')
        return if (h == -1) body to "" else body.substring(0, h) to dec(body.substring(h + 1))
    }

    private fun splitQuery(main: String): Pair<String, Map<String, String>> {
        val qi = main.indexOf('?')
        if (qi == -1) return main to emptyMap()
        return main.substring(0, qi) to parseQuery(main.substring(qi + 1))
    }

    private fun parseQuery(qs: String): Map<String, String> {
        val out = HashMap<String, String>()
        for (pair in qs.split("&")) {
            if (pair.isEmpty()) continue
            val i = pair.indexOf('=')
            val k = if (i == -1) pair else pair.substring(0, i)
            val v = if (i == -1) "" else pair.substring(i + 1)
            out[dec(k)] = dec(v)
        }
        return out
    }

    private fun splitHostPort(hp: String): Pair<String, String> {
        if (hp.startsWith("[")) {
            val close = hp.indexOf(']')
            return hp.substring(1, close) to hp.substring(close + 2)
        }
        val i = hp.lastIndexOf(':')
        return if (i == -1) hp to "" else hp.substring(0, i) to hp.substring(i + 1)
    }

    private fun dec(s: String): String = try { URLDecoder.decode(s, "UTF-8") } catch (e: Exception) { s }

    private fun b64(s: String?): String {
        if (s.isNullOrBlank()) return ""
        var t = s.trim().replace('-', '+').replace('_', '/')
        while (t.length % 4 != 0) t += "="
        return try { String(Base64.decode(t, Base64.DEFAULT), Charsets.UTF_8) } catch (e: Exception) { "" }
    }
}
