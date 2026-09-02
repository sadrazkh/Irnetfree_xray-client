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

    /**
     * v2rayN shares an HTTP proxy exactly like a SOCKS one —
     * `http://[b64(user:pass)@]host:port#name` — which is also the shape of a plain
     * subscription URL's origin. A proxy link therefore has NO path and NO query.
     * The userinfo is either a standard-alphabet base64 blob (which may contain '/')
     * or a plain `user:pass`; the host never contains a '/', so a subscription URL
     * with an '@' in its path still fails to match.
     * (Kept byte-identical to HTTP_PROXY_LINK in src/main/parser.js.)
     */
    private val HTTP_PROXY_LINK = Regex(
        "^http://(?:(?:[A-Za-z0-9+/=]+|[^/?#\\s@]+)@)?[^/?#\\s@]+:\\d{1,5}(?:#\\S*)?\$",
        RegexOption.IGNORE_CASE)

    fun isHttpProxyLink(s: String?): Boolean = HTTP_PROXY_LINK.matches((s ?: "").trim())

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
            if (line.isEmpty() || (!SCHEME_RE.containsMatchIn(line) && !isHttpProxyLink(line))) continue
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
            l.startsWith("socks://", true) || l.startsWith("socks5://", true) -> parseProxyLink(l, "socks")
            l.startsWith("wireguard://", true) || l.startsWith("wg://", true) -> parseWireguard(l)
            // case-insensitive to match HTTP_PROXY_LINK (and parseMany's line filter),
            // so an uppercase scheme imports instead of being reported as an error
            l.startsWith("http://", true) && isHttpProxyLink(l) -> parseProxyLink(l, "http")
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
        q["noise"]?.let { ob.put("_noise", it) }         // anti-DPI / fake ClientHello injection
        return ServerConfig(newId("s"), name.ifBlank { address }, "vless", address, port, ob,
            engine = q["engine"]?.takeIf { it.isNotBlank() && it != "xray" })
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
            "headerType" to v.optString("type", "none"),
            // `cs` / `fm` are the standard short keys; the long ones are the form we used to emit
            "cipherSuites" to v.optString("cs").ifBlank { v.optString("cipherSuites") },
            "finalMask" to v.optString("fm").ifBlank { v.optString("finalMask").ifBlank { v.optString("finalmask") } }
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
        if (v.has("noise")) ob.put("_noise", v.optString("noise"))
        return ServerConfig(newId("s"), v.optString("ps", address), "vmess", address, port, ob,
            engine = v.optString("engine").takeIf { it.isNotBlank() && it != "xray" })
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
        q["noise"]?.let { ob.put("_noise", it) }
        return ServerConfig(newId("s"), name.ifBlank { address }, "trojan", address, port, ob,
            engine = q["engine"]?.takeIf { it.isNotBlank() && it != "xray" })
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

    /**
     * A socks:// / socks5:// / http:// proxy link (mirrors parser.js parseProxyLink).
     * Tolerant of `host:port`, `user:pass@host:port`, `base64(user:pass)@host:port`
     * and a fully base64 `base64(user:pass@host:port)` body.
     */
    private fun parseProxyLink(link: String, proto: String): ServerConfig {
        val body = link.substring(link.indexOf("://") + 3)
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
        val port = portStr.toIntOrNull() ?: (if (proto == "http") 8080 else 1080)
        val ob = proxyOutbound(proto, address, port, dec(user), dec(pass))
        return ServerConfig(newId("s"), name.ifBlank { address }, proto, address, port, ob)
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
            // patterniha custom TLS: `unsafe` fingerprint + pinned cipherSuites.
            // `cs` is the standard share-link name, `cipherSuites` the long legacy one.
            val cs = q["cs"]?.takeIf { it.isNotBlank() } ?: q["cipherSuites"]
            cs?.takeIf { it.isNotBlank() }?.let { tls.put("cipherSuites", it.trim()) }
            stream.put("tlsSettings", tls)
        } else if (security == "reality") {
            stream.put("realitySettings", JSONObject()
                .put("serverName", q["sni"] ?: "")
                .put("fingerprint", q["fp"] ?: "chrome")
                .put("publicKey", q["pbk"] ?: "")
                .put("shortId", q["sid"] ?: "")
                .put("spiderX", q["spx"] ?: ""))
        }
        // finalMask (transport-level masking: fragment, noise, header-custom, …).
        // Stored VERBATIM: the core takes the plural `lengths`/`delays` arrays, and an
        // earlier version of this code rewrote them into the singular form, which the
        // current core rejects. `fm` is the standard share-link name; `finalMask` is
        // the long form we used to emit.
        val fmRaw = q["fm"]?.takeIf { it.isNotBlank() } ?: q["finalMask"]
        fmRaw?.takeIf { it.isNotBlank() }?.let { raw -> parseFinalMask(raw)?.let { fm -> stream.put("finalmask", fm) } }
        return stream
    }

    /** Parse a finalMask JSON string, untouched. Returns null when it is unusable. */
    fun parseFinalMask(raw: String): JSONObject? =
        try { JSONObject(raw) } catch (e: Exception) { null }

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

    /* ------------------- build share link (carries ALL settings) ------------------- */
    private fun enc(s: String) = java.net.URLEncoder.encode(s, "UTF-8")
    private fun jarr(a: JSONArray?): List<String> = if (a == null) emptyList() else (0 until a.length()).map { a.optString(it) }
    private fun b64e(s: String) = Base64.encodeToString(s.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
    private fun qstr(m: Map<String, String>) = m.filterValues { it.isNotBlank() }.entries.joinToString("&") { "${it.key}=${enc(it.value)}" }

    /** streamSettings -> flat query params (inverse of buildStream). */
    private fun streamToQuery(st: JSONObject, q: MutableMap<String, String>) {
        val net = st.optString("network", "tcp"); q["type"] = net; q["security"] = st.optString("security", "none")
        when (net) {
            "ws" -> st.optJSONObject("wsSettings")?.let { q["path"] = it.optString("path"); it.optJSONObject("headers")?.optString("Host")?.takeIf { h -> h.isNotBlank() }?.let { h -> q["host"] = h } }
            "grpc" -> st.optJSONObject("grpcSettings")?.let { q["serviceName"] = it.optString("serviceName"); if (it.optBoolean("multiMode")) q["mode"] = "multi" }
            "h2", "http" -> st.optJSONObject("httpSettings")?.let { q["path"] = it.optString("path"); q["host"] = jarr(it.optJSONArray("host")).joinToString(",") }
            "xhttp" -> st.optJSONObject("xhttpSettings")?.let { q["path"] = it.optString("path"); q["host"] = it.optString("host"); it.optString("mode").takeIf { m -> m.isNotBlank() }?.let { m -> q["mode"] = m } }
            "kcp" -> st.optJSONObject("kcpSettings")?.let { q["headerType"] = it.optJSONObject("header")?.optString("type") ?: "none"; it.optString("seed").takeIf { sd -> sd.isNotBlank() }?.let { sd -> q["seed"] = sd } }
            "tcp" -> st.optJSONObject("tcpSettings")?.optJSONObject("header")?.takeIf { it.optString("type") == "http" }?.let { h -> q["headerType"] = "http"; val rq = h.optJSONObject("request"); q["path"] = rq?.optJSONArray("path")?.optString(0) ?: ""; q["host"] = rq?.optJSONObject("headers")?.optJSONArray("Host")?.optString(0) ?: "" }
        }
        st.optJSONObject("tlsSettings")?.let { q["sni"] = it.optString("serverName"); q["fp"] = it.optString("fingerprint"); if (it.optBoolean("allowInsecure")) q["allowInsecure"] = "1"; jarr(it.optJSONArray("alpn")).joinToString(",").takeIf { a -> a.isNotBlank() }?.let { a -> q["alpn"] = a }; it.optString("cipherSuites").takeIf { c -> c.isNotBlank() }?.let { c -> q["cs"] = c } }
        st.optJSONObject("realitySettings")?.let { q["sni"] = it.optString("serverName"); q["fp"] = it.optString("fingerprint"); q["pbk"] = it.optString("publicKey"); q["sid"] = it.optString("shortId"); it.optString("spiderX").takeIf { x -> x.isNotBlank() }?.let { x -> q["spx"] = x } }
        st.optJSONObject("finalmask")?.let { q["fm"] = it.toString() }
    }

    private fun srv0(ob: JSONObject) = ob.optJSONObject("settings")?.optJSONArray("servers")?.optJSONObject(0) ?: JSONObject()
    private fun user0(ob: JSONObject) = ob.optJSONObject("settings")?.optJSONArray("vnext")?.optJSONObject(0)?.optJSONArray("users")?.optJSONObject(0) ?: JSONObject()

    /** Serialize a server (with ALL its settings) back into a shareable link. */
    fun buildShareLink(s: ServerConfig): String {
        val ob = s.outbound
        val name = if (s.name.isNotBlank()) "#" + enc(s.name) else ""
        val st = ob.optJSONObject("streamSettings") ?: JSONObject()
        val extras = LinkedHashMap<String, String>()
        ob.optString("_fragment").takeIf { it.isNotBlank() }?.let { extras["fragment"] = it }
        ob.optString("_noise").takeIf { it.isNotBlank() }?.let { extras["noise"] = it }
        s.engine?.takeIf { it.isNotBlank() && it != "xray" }?.let { extras["engine"] = it }
        return when (s.protocol) {
            "vless" -> {
                val u = user0(ob); val q = LinkedHashMap<String, String>()
                q["encryption"] = u.optString("encryption", "none"); u.optString("flow").takeIf { it.isNotBlank() }?.let { q["flow"] = it }
                streamToQuery(st, q); q.putAll(extras)
                "vless://${u.optString("id")}@${s.address}:${s.port}?${qstr(q)}$name"
            }
            "trojan" -> {
                val srv = srv0(ob); val q = LinkedHashMap<String, String>(); streamToQuery(st, q); q.putAll(extras)
                "trojan://${enc(srv.optString("password"))}@${s.address}:${s.port}?${qstr(q)}$name"
            }
            "vmess" -> {
                val u = user0(ob); val p = LinkedHashMap<String, String>(); streamToQuery(st, p)
                val v = JSONObject().put("v", "2").put("ps", s.name).put("add", s.address).put("port", s.port.toString())
                    .put("id", u.optString("id")).put("aid", u.optInt("alterId", 0).toString()).put("scy", u.optString("security", "auto"))
                    .put("net", p["type"] ?: "tcp").put("type", p["headerType"] ?: "none").put("host", p["host"] ?: "")
                    .put("path", p["path"] ?: (p["serviceName"] ?: "")).put("tls", if (p["security"] == "tls") "tls" else "")
                    .put("sni", p["sni"] ?: "").put("fp", p["fp"] ?: "").put("alpn", p["alpn"] ?: "")
                p["cs"]?.let { v.put("cs", it) }; p["fm"]?.let { v.put("fm", it) }
                extras["fragment"]?.let { v.put("fragment", it) }; extras["noise"]?.let { v.put("noise", it) }
                extras["engine"]?.let { v.put("engine", it) }
                "vmess://" + b64e(v.toString())
            }
            "shadowsocks" -> { val srv = srv0(ob); "ss://${b64e("${srv.optString("method")}:${srv.optString("password")}")}@${s.address}:${s.port}$name" }
            "socks", "http" -> {
                val srv = srv0(ob); val c = srv.optJSONArray("users")?.optJSONObject(0)
                val auth = if (c != null) b64e("${c.optString("user")}:${c.optString("pass")}") + "@" else ""
                "${s.protocol}://$auth${s.address}:${s.port}$name"
            }
            else -> s.raw   // wireguard / unknown -> imported link
        }
    }

    /* ================ migrating servers from an older store ================ */

    /**
     * A singular finalmask value as the single element of its plural array.
     * Anything we never wrote (an object, a boolean, an empty string) gives null,
     * so the caller leaves that entry alone rather than inventing one.
     */
    private fun pluralValue(v: Any?): String? = when (v) {
        is String -> if (v.isEmpty()) null else v
        is Number -> v.toString()
        else -> null
    }

    /**
     * Rewrite the singular `length`/`delay` keys of a finalmask into the plural
     * `lengths`/`delays` arrays the current core wants, IN PLACE — the caller owns
     * `fm`. Returns true when anything actually changed. A `lengths` array that is
     * already there means the entry was never collapsed, so it is left whole; a
     * mask carrying both forms (never written by either parser) keeps the plural.
     */
    private fun pluralizeFinalMask(fm: JSONObject): Boolean {
        var changed = false
        for (key in listOf("tcp", "udp")) {
            val list = fm.optJSONArray(key) ?: continue
            for (i in 0 until list.length()) {
                val s = list.optJSONObject(i)?.optJSONObject("settings") ?: continue
                if (s.optJSONArray("lengths") == null) {
                    val lv = pluralValue(s.opt("length"))
                    if (lv != null) { s.put("lengths", JSONArray().put(lv)); s.remove("length"); changed = true }
                }
                if (s.optJSONArray("delays") == null) {
                    val dv = pluralValue(s.opt("delay"))
                    if (dv != null) { s.put("delays", JSONArray().put(dv)); s.remove("delay"); changed = true }
                }
            }
        }
        return changed
    }

    /**
     * Bring a server saved by an older version up to the shape the current code
     * expects. Pure: the input is never mutated, and when there is nothing to do
     * the very same object comes back, so a caller can skip the store write.
     *
     * Two shapes the previous parser wrote are still sitting in users' stores:
     *  - `outbound._fakesni`, the fake-ClientHello decoy marker. It was built out of
     *    the freedom outbound's `noises`, which are UDP-only, so it never did
     *    anything on a TLS/TCP connection — it is dead weight in config.json now.
     *  - a finalmask fragment collapsed to the SINGULAR `length`/`delay` form. The
     *    current core takes only the plural arrays. (Only the collapse direction is
     *    reversible — `length: "3-8"` becomes `lengths: ["3-8"]`, one fragment
     *    covering the whole range.)
     *
     * The store is a plain file a user can hand-edit, so every step is shape-checked
     * and nothing throws.
     */
    fun migrateStoredServer(s: ServerConfig): ServerConfig {
        val dropFakeSni = s.outbound.has("_fakesni")
        val hasMask = s.outbound.optJSONObject("streamSettings")?.optJSONObject("finalmask") != null
        if (!dropFakeSni && !hasMask) return s
        // work on a deep copy, so the stored outbound is never touched
        val outbound = try { JSONObject(s.outbound.toString()) } catch (e: Exception) { return s }
        var changed = dropFakeSni
        if (dropFakeSni) outbound.remove("_fakesni")
        val fm = outbound.optJSONObject("streamSettings")?.optJSONObject("finalmask")
        if (fm != null && pluralizeFinalMask(fm)) changed = true
        return if (changed) s.copy(outbound = outbound) else s
    }
}
