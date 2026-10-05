package com.irnetfree.vpn.core

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * Share-link parser: converts vless:// vmess:// trojan:// ss:// socks:// links
 * into Xray outbound JSON (+ a normalized ServerConfig). Ported from the desktop
 * parser.js so both clients produce identical outbounds.
 */
object LinkParser {

    private val SCHEME_RE = Regex("^(vless|vmess|trojan|ss|socks|socks5|wireguard|wg|hysteria2|hy2)://", RegexOption.IGNORE_CASE)

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

    /**
     * A line smart import fetches as a subscription: an http(s) URL that is not
     * an HTTP proxy link (renderer/app.js isSubUrl). `http://user@host:port#name`
     * is a proxy to import, not a panel to download.
     */
    fun isSubUrl(s: String): Boolean {
        val t = s.trim()
        return (t.startsWith("http://", true) || t.startsWith("https://", true)) && !isHttpProxyLink(t)
    }

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
            l.startsWith("hysteria2://", true) || l.startsWith("hy2://", true) -> parseHysteria2(l)
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
        val port = portOf(portStr, 443)
        val users = JSONObject()
            .put("id", uuid)
            .put("encryption", q.given("encryption") ?: "none")
            .put("flow", q.given("flow") ?: "")
        val ob = JSONObject()
            .put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(
                JSONObject().put("address", address).put("port", port)
                    .put("users", JSONArray().put(users)))))
            .put("streamSettings", buildStream(q))
        q.given("fragment")?.let { ob.put("_fragment", it) }   // TLS fragmentation from the link
        q.given("noise")?.let { ob.put("_noise", it) }         // anti-DPI / fake ClientHello injection
        return ServerConfig(newId("s"), name.ifBlank { address }, "vless", address, port, ob, link,
            engine = q["engine"]?.takeIf { it.isNotBlank() && it != "xray" })
    }

    private fun parseVmess(link: String): ServerConfig =
        vmessFromJson(JSONObject(b64(link.substring("vmess://".length))), link)

    /**
     * The vmess JSON, already out of its base64, as a server. Every field is read
     * the desktop's way, `v.x || default`: v2rayN writes `"sni": ""` and `"fp": ""`,
     * and an empty value is a missing one — not an empty SNI and no uTLS.
     */
    internal fun vmessFromJson(v: JSONObject, link: String): ServerConfig {
        val address = v.optString("add")
        val port = portOf(v.optString("port"), 443)
        val net = v.optString("net").ifBlank { "tcp" }.lowercase()
        val tls = v.optString("tls").lowercase()
        // VMess JSON puts a transport's second value in `type` and `host`, as
        // v2rayN writes them: the mode of grpc and xhttp, the :authority of
        // grpc; mKCP carries its seed in `path` (parser.js parseVmess).
        val isKcp = net == "kcp" || net == "mkcp"
        val isXhttp = net == "xhttp" || net == "splithttp"
        val type = v.optString("type").trim()
        val q = hashMapOf(
            "type" to net,
            "security" to if (tls == "tls") "tls" else "none",
            "path" to v.optString("path").ifBlank { "/" },
            "host" to v.optString("host"),
            "sni" to v.optString("sni").ifBlank { v.optString("host") },
            "fp" to v.optString("fp").ifBlank { "chrome" },
            "alpn" to v.optString("alpn"),
            "serviceName" to v.optString("path"),
            "headerType" to if (net == "grpc" || isXhttp) "none" else type.ifBlank { "none" },
            "mode" to v.optString("mode").ifBlank { if ((net == "grpc" || isXhttp) && type.isNotEmpty() && type != "none") type else "" },
            "authority" to if (net == "grpc") v.optString("authority").ifBlank { v.optString("host") } else "",
            "seed" to if (isKcp) v.optString("seed").ifBlank { v.optString("path").takeIf { it.isNotBlank() && it != "/" } ?: "" } else "",
            "extra" to if (isXhttp) (v.opt("extra")?.toString() ?: "") else "",
            "allowInsecure" to v.optString("allowInsecure").ifBlank { v.optString("insecure") },
            "ech" to v.optString("ech"),
            "pcs" to v.optString("pcs"),
            "vcn" to v.optString("vcn"),
            // `cs` / `fm` are the standard short keys; the long ones are the form we used to emit
            "cipherSuites" to v.optString("cs").ifBlank { v.optString("cipherSuites") },
            "finalMask" to v.optString("fm").ifBlank { v.optString("finalMask").ifBlank { v.optString("finalmask") } }
        )
        val user = JSONObject()
            .put("id", v.optString("id"))
            .put("alterId", v.optString("aid").toIntOrNull() ?: 0)
            .put("security", v.optString("scy").ifBlank { "auto" })
        val ob = JSONObject()
            .put("protocol", "vmess")
            .put("settings", JSONObject().put("vnext", JSONArray().put(
                JSONObject().put("address", address).put("port", port)
                    .put("users", JSONArray().put(user)))))
            .put("streamSettings", buildStream(q))
        v.optString("fragment").takeIf { it.isNotBlank() }?.let { ob.put("_fragment", it) }
        v.optString("noise").takeIf { it.isNotBlank() }?.let { ob.put("_noise", it) }
        return ServerConfig(newId("s"), v.optString("ps").ifBlank { address }, "vmess", address, port, ob, link,
            engine = v.optString("engine").takeIf { it.isNotBlank() && it != "xray" })
    }

    private fun parseTrojan(link: String): ServerConfig {
        val body = link.substring("trojan://".length)
        val (main, name) = splitHash(body)
        val (beforeQ, q0) = splitQuery(main)
        val q = HashMap(q0)
        if (q.given("security") == null) q["security"] = "tls"   // trojan defaults to tls — an empty value too
        val at = beforeQ.lastIndexOf('@')
        val password = dec(beforeQ.substring(0, at))
        val (address, portStr) = splitHostPort(beforeQ.substring(at + 1))
        val port = portOf(portStr, 443)
        val ob = JSONObject()
            .put("protocol", "trojan")
            .put("settings", JSONObject().put("servers", JSONArray().put(
                JSONObject().put("address", address).put("port", port).put("password", password))))
            .put("streamSettings", buildStream(q))
        q.given("fragment")?.let { ob.put("_fragment", it) }
        q.given("noise")?.let { ob.put("_noise", it) }
        return ServerConfig(newId("s"), name.ifBlank { address }, "trojan", address, port, ob, link,
            engine = q["engine"]?.takeIf { it.isNotBlank() && it != "xray" })
    }

    private fun parseShadowsocks(link: String): ServerConfig {
        val body = link.substring("ss://".length)
        val (mainWithHash, name) = splitHash(body)
        var main = mainWithHash
        // SIP002 puts a plugin in the query (`/?plugin=…`)
        val qi = main.indexOf('?')
        val q = if (qi == -1) emptyMap() else parseQuery(main.substring(qi + 1))
        if (qi != -1) main = main.substring(0, qi)
        main = main.trimEnd('/')

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
        val port = portOf(portStr, 443)
        val ob = JSONObject()
            .put("protocol", "shadowsocks")
            .put("settings", JSONObject().put("servers", JSONArray().put(
                JSONObject().put("address", address).put("port", port)
                    .put("method", method).put("password", password).put("uot", true))))
            .put("streamSettings", ssStream(q, address))
        return ServerConfig(newId("s"), name.ifBlank { address }, "shadowsocks", address, port, ob, link)
    }

    /**
     * The transport a Shadowsocks link asks for (parser.js ssStream). A SIP002
     * `plugin` the core can stand in for becomes its transport, as v2rayN does
     * it: obfs-local's `obfs=http` is RAW with an HTTP header, v2ray-plugin's
     * websocket (with or without `tls`) is WebSocket. Any other plugin is refused
     * BY NAME — imported, the server would never connect, the plugin missing.
     * Without a plugin: what an Xray panel's `type`/`security` say, else TCP.
     */
    internal fun ssStream(q: Map<String, String>, address: String): JSONObject {
        val plugin = (q["plugin"] ?: "").trim()
        if (plugin.isNotEmpty()) {
            // `;` separates options; `\;`, `\=`, `\,` and `\\` are escapes inside a value
            val parts = plugin.split(Regex("(?<!\\\\);")).map { it.trim() }.filter { it.isNotEmpty() }
            fun unesc(x: String) = x.replace(Regex("\\\\([;=,\\\\])"), "$1")
            val opt = HashMap<String, String>(); val flags = HashSet<String>()
            for (p in parts.drop(1)) {
                val eq = Regex("(?<!\\\\)=").find(p)?.range?.first ?: -1
                if (eq == -1) flags.add(unesc(p).lowercase()) else opt[unesc(p.substring(0, eq)).lowercase()] = unesc(p.substring(eq + 1))
            }
            val name = parts[0].lowercase()
            if (name == "obfs-local" || name == "simple-obfs") {
                val mode = (opt["obfs"] ?: "http").lowercase()
                if (mode != "http") throw IllegalArgumentException("Shadowsocks: the $name plugin with obfs=$mode is not supported (obfs=http is)")
                return buildStream(mapOf("type" to "tcp", "headerType" to "http", "host" to (opt["obfs-host"]?.takeIf { it.isNotBlank() } ?: address), "path" to (opt["obfs-uri"]?.takeIf { it.isNotBlank() } ?: "/")))
            }
            if (name == "v2ray-plugin") {
                val mode = (opt["mode"] ?: "websocket").lowercase()
                if (mode != "websocket") throw IllegalArgumentException("Shadowsocks: v2ray-plugin mode=$mode is not supported (websocket is)")
                if ((opt["mux"]?.toIntOrNull() ?: 0) > 0) throw IllegalArgumentException("Shadowsocks: v2ray-plugin with mux is not supported — ask for a link with mux=0")
                val host = opt["host"] ?: ""
                val tls = "tls" in flags || isTrue(opt["tls"])
                return buildStream(mapOf("type" to "ws", "host" to host, "path" to (opt["path"]?.takeIf { it.isNotBlank() } ?: "/"), "security" to if (tls) "tls" else "none", "sni" to host))
            }
            throw IllegalArgumentException("Shadowsocks: plugin ${parts[0]} is not supported")
        }
        val net = (q["type"] ?: q["network"] ?: "").lowercase()
        val sec = (q["security"] ?: "").lowercase()
        if ((net.isNotEmpty() && net != "tcp" && net != "raw") || (sec.isNotEmpty() && sec != "none") || q["headerType"] == "http") return buildStream(q)
        return JSONObject().put("network", "tcp")
    }

    /** The SIP002 plugin a Shadowsocks stream stands for (ssStream's inverse); "" for plain TCP. */
    fun ssPluginOf(st: JSONObject?): String {
        if (st == null) return ""
        fun esc(x: String) = x.replace(Regex("[\\\\;=,]")) { "\\" + it.value }
        val net = st.optString("network")
        if (net == "ws" && st.has("wsSettings")) {
            val w = st.optJSONObject("wsSettings") ?: JSONObject()
            val host = w.optJSONObject("headers")?.let { it.optString("Host").ifBlank { it.optString("host") } } ?: ""
            val parts = arrayListOf("v2ray-plugin", "mode=websocket")
            if (st.optString("security") == "tls") parts.add("tls")
            if (host.isNotBlank()) parts.add("host=" + esc(host))
            parts.add("path=" + esc(w.optString("path").ifBlank { "/" })); parts.add("mux=0")
            return parts.joinToString(";")
        }
        val h = st.optJSONObject("tcpSettings")?.optJSONObject("header")
        if ((net.isEmpty() || net == "tcp" || net == "raw") && h != null && h.optString("type") == "http") {
            val rq = h.optJSONObject("request")
            val host = rq?.optJSONObject("headers")?.optJSONArray("Host")?.optString(0) ?: ""
            val uri = rq?.optJSONArray("path")?.optString(0)?.ifBlank { "/" } ?: "/"
            return "obfs-local;obfs=http" + (if (host.isNotBlank()) ";obfs-host=" + esc(host) else "") + (if (uri != "/") ";obfs-uri=" + esc(uri) else "")
        }
        return ""
    }

    /* ------------------------- Hysteria2 ------------------------- */

    private const val HOP_INTERVAL = "30"

    /**
     * hysteria2://auth@host:port/?sni=…&insecure=1&obfs=salamander&obfs-password=…&pinSHA256=…&mport=…#name
     * (or hy2://) — parser.js parseHysteria2. Both cores speak it natively since
     * 26.1: outbound `hysteria` (version 2) over the `hysteria` transport, the
     * obfuscation and the port hopping as finalmask, stored here in the newest
     * core's form (CoreCompat writes an older core's). A port list or range in
     * the host part ("443,8443-8500") is port hopping: the first port is dialled.
     */
    private fun parseHysteria2(link: String): ServerConfig {
        val scheme = if (link.startsWith("hy2://", true)) "hy2://" else "hysteria2://"
        val (main, name) = splitHash(link.substring(scheme.length))
        val (beforeQ0, q) = splitQuery(main)
        val beforeQ = beforeQ0.trimEnd('/')
        val at = beforeQ.lastIndexOf('@')
        val auth = if (at == -1) (q["auth"] ?: "") else dec(beforeQ.substring(0, at))
        val hostPart = if (at == -1) beforeQ else beforeQ.substring(at + 1)
        // the port's text is kept whole: "443,8443-8500" is a hopping list
        val (address, spec) = splitHostPort(hostPart)
        val port = portOf(spec, 443)
        val hop = hopPorts(q.given("mport") ?: q.given("ports") ?: if (spec.contains(',') || spec.contains('-')) spec else "")
        val f = HashMap<String, String>(q); f["address"] = address; f["port"] = port.toString(); f["auth"] = auth; f["mport"] = hop
        return ServerConfig(newId("s"), name.ifBlank { address }, "hysteria2", address, port, buildHysteria2Outbound(f), link,
            engine = q["engine"]?.takeIf { it.isNotBlank() && it != "xray" })
    }

    /** A port-hopping list as the core takes it ("20000-30000,443"); "" when it names no port. */
    internal fun hopPorts(v: String?): String {
        val s = (v ?: "").replace(Regex("\\s+"), "").replace(':', '-')
        return if (s.isNotEmpty() && Regex("^\\d+(-\\d+)?(,\\d+(-\\d+)?)*$").matches(s)) s else ""
    }

    /**
     * A bandwidth for the core ("100 mbps"); a bare number is Mbps, as hysteria's
     * links mean it. The core counts bits per second in powers of 1024 and refuses
     * the whole config below 65536 bytes a second (0.5 mbps): under that, or in a
     * unit it does not know, "" (parser.js bandwidth).
     */
    private fun bandwidth(v: String?): String {
        val s = (v ?: "").trim().lowercase()
        val m = Regex("^(\\d+(?:\\.\\d+)?)\\s*(|b|bps|k|kb|kbps|m|mb|mbps|g|gb|gbps|t|tb|tbps)$").find(s) ?: return ""
        val unit = m.groupValues[2].ifEmpty { "mbps" }
        val mul = Math.pow(1024.0, " kmgt".indexOf(if (unit[0] == 'b') ' ' else unit[0]).toDouble())
        if ((m.groupValues[1].toDoubleOrNull() ?: 0.0) * mul < 524288.0) return ""
        return if (m.groupValues[2].isNotEmpty()) s else "$s mbps"
    }

    /**
     * The hysteria outbound from a link's (or the edit sheet's) values: `address`,
     * `port`, `auth`, `sni`, `insecure`, `alpn`, `ech`, `pcs`/`pinSHA256`, `vcn`,
     * `obfs` + `obfs-password`, `mport` (+ `hopInterval`), `up`/`down`.
     */
    fun buildHysteria2Outbound(f: Map<String, String?>): JSONObject {
        val address = (f["address"] ?: "").trim()
        val tls = JSONObject()
            .put("serverName", (f["sni"] ?: f["peer"] ?: "").trim().ifBlank { if (DnsPlan.isIp(address)) "" else address })
            .put("allowInsecure", isTrue(f["insecure"]) || isTrue(f["allowInsecure"]) || isTrue(f["allow_insecure"]))
        f["alpn"]?.takeIf { it.isNotBlank() }?.let { a -> tls.put("alpn", JSONArray(a.split(",").map { it.trim() }.filter { it.isNotEmpty() })) }
        tlsExtras(tls, f)
        val stream = JSONObject().put("network", "hysteria").put("security", "tls").put("tlsSettings", tls)
            .put("hysteriaSettings", JSONObject().put("version", 2).put("auth", f["auth"] ?: ""))
        val udp = JSONArray()
        val obfs = (f["obfs"] ?: "").trim().lowercase()
        val obfsPassword = f["obfs-password"] ?: f["obfsPassword"] ?: ""
        if ((obfs == "salamander" || (obfs.isEmpty() && obfsPassword.isNotEmpty())) && obfsPassword.isNotEmpty()) {
            udp.put(JSONObject().put("type", "salamander").put("settings", JSONObject().put("password", obfsPassword)))
        }
        val hop = hopPorts(f["mport"])
        if (hop.isNotEmpty()) {
            val iv = (f["hopInterval"] ?: f["hop_interval"] ?: "").trim().removeSuffix("s").removeSuffix("S").trim()
            udp.put(JSONObject().put("type", "udphop").put("settings", JSONObject()
                .put("mode", "intervalLocal,intervalRemote")
                .put("interval", if (Regex("^\\d+(-\\d+)?$").matches(iv)) iv else HOP_INTERVAL)
                .put("remotePorts", hop)))
        }
        val fm = JSONObject()
        if (udp.length() > 0) fm.put("udp", udp)
        val up = bandwidth(f["up"] ?: f["upmbps"]); val down = bandwidth(f["down"] ?: f["downmbps"])
        if (up.isNotEmpty() || down.isNotEmpty()) {
            val qp = JSONObject()
            if (up.isNotEmpty()) qp.put("brutalUp", up)
            if (down.isNotEmpty()) qp.put("brutalDown", down)
            fm.put("quicParams", qp)
        }
        if (fm.length() > 0) stream.put("finalmask", fm)
        return JSONObject().put("protocol", "hysteria")
            .put("settings", JSONObject().put("version", 2).put("address", address).put("port", portOf(f["port"] ?: "", 443)))
            .put("streamSettings", stream)
    }

    /**
     * A hysteria outbound's values in buildHysteria2Outbound's terms (parser.js
     * hy2Values) — so an edit rebuilds it from everything it had.
     */
    fun hy2Values(ob: JSONObject): HashMap<String, String> {
        val st = ob.optJSONObject("streamSettings") ?: JSONObject()
        val tls = st.optJSONObject("tlsSettings") ?: JSONObject()
        val set = ob.optJSONObject("settings") ?: JSONObject()
        val fm = st.optJSONObject("finalmask") ?: JSONObject()
        val masks = fm.optJSONArray("udp") ?: JSONArray()
        var sal: JSONObject? = null; var hop: JSONObject? = null
        for (i in 0 until masks.length()) {
            val m = masks.optJSONObject(i) ?: continue
            if (sal == null && m.optString("type") == "salamander") sal = m
            if (hop == null && m.optString("type") == "udphop") hop = m
        }
        val qp = fm.optJSONObject("quicParams") ?: JSONObject()
        return hashMapOf(
            "address" to set.optString("address"), "port" to set.optInt("port", 443).toString(),
            "auth" to (st.optJSONObject("hysteriaSettings")?.optString("auth") ?: ""),
            "sni" to tls.optString("serverName"), "insecure" to if (tls.optBoolean("allowInsecure")) "1" else "",
            "alpn" to jarr(tls.optJSONArray("alpn")).joinToString(","),
            "ech" to tls.optString("echConfigList"), "pcs" to tls.optString("pinnedPeerCertSha256"), "vcn" to tls.optString("verifyPeerCertByName"),
            "obfs" to if (sal != null) "salamander" else "",
            "obfs-password" to (sal?.optJSONObject("settings")?.optString("password") ?: ""),
            "mport" to (hop?.optJSONObject("settings")?.opt("remotePorts")?.toString() ?: ""),
            "hopInterval" to (hop?.optJSONObject("settings")?.opt("interval")?.toString() ?: ""),
            "up" to qp.optString("brutalUp"), "down" to qp.optString("brutalDown")
        )
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
        val port = portOf(portStr, if (proto == "http") 8080 else 1080)
        val ob = proxyOutbound(proto, address, port, dec(user), dec(pass))
        return ServerConfig(newId("s"), name.ifBlank { address }, proto, address, port, ob, link)
    }

    /* ------------------------- WireGuard ------------------------- */

    internal fun splitCommas(v: String?): List<String> =
        (v ?: "").split(Regex("[,\\s]+")).map { it.trim() }.filter { it.isNotEmpty() }

    /** Xray requires the interface address to be /32 (IPv4) or /128 (IPv6). */
    internal fun normalizeWgAddresses(list: List<String>): List<String> = list
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
        val port = portOf(portStr, 51820)
        val ob = buildWireguardOutbound(
            privateKey = privateKey,
            publicKey = q.given("publickey") ?: q.given("publicKey") ?: q.given("peer") ?: "",
            endpoint = "$address:$port",
            address = q.given("address") ?: q.given("ip") ?: "",
            presharedKey = q.given("presharedkey") ?: q.given("presharedKey") ?: q.given("psk") ?: "",
            mtu = q["mtu"], reserved = q["reserved"], allowedIPs = q.given("allowedips") ?: q.given("allowedIPs")
        )
        val (dns, dnsDomains) = splitDnsField(q["dns"])
        return ServerConfig(newId("s"), name.ifBlank { address }, "wireguard", address, port, ob, link, dns = dns, dnsDomains = dnsDomains)
    }

    /** Manual WireGuard from a form. `endpoint` is host:port of the public server. */
    fun makeWireguardServer(
        name: String, endpoint: String, privateKey: String, publicKey: String,
        address: String, allowedIPs: String, presharedKey: String, mtu: String?, reserved: String?,
        dnsField: String? = null
    ): ServerConfig {
        val (host, portStr) = splitHostPort(endpoint)
        val port = portOf(portStr, 51820)
        val ep = if (endpoint.contains(":")) endpoint else "$host:$port"
        val ob = buildWireguardOutbound(privateKey, publicKey, ep, address, presharedKey, mtu, reserved, allowedIPs)
        val (dns, dnsDomains) = splitDnsField(dnsField)
        return ServerConfig(newId("s"), name.ifBlank { host.ifBlank { "WireGuard" } }, "wireguard", host, port, ob, "wireguard://$host:$port", dns = dns, dnsDomains = dnsDomains)
    }

    /* ------------------------- shared stream builder ------------------------- */

    /**
     * `pqv` — an ML-DSA-65 public key: 1952 bytes as unpadded base64url, the only
     * form the core reads (a malformed one makes it refuse the WHOLE config).
     * The standard alphabet and padding are mapped to it; anything else is "".
     * parser.js mldsaKey.
     */
    internal fun mldsaKey(v: String?): String {
        val s = (v ?: "").trim().replace('+', '-').replace('/', '_').trimEnd('=')
        if (s.length != 2603 || !Regex("^[A-Za-z0-9_-]+$").matches(s)) return ""
        return try { if (java.util.Base64.getUrlDecoder().decode(s).size == 1952) s else "" } catch (e: Exception) { "" }
    }

    /** A link's boolean flag: `1` / `true`, any case. */
    internal fun isTrue(v: String?): Boolean { val s = (v ?: "").trim().lowercase(); return s == "1" || s == "true" }

    /**
     * `pcs` — the certificate hash(es) to accept, comma separated: SHA-256 of the
     * certificate's DER as hex, colons allowed. The core refuses the WHOLE config
     * over one malformed entry, so only well-formed ones are kept, in one form.
     */
    internal fun pinList(v: String?): String {
        val out = ArrayList<String>()
        for (part in (v ?: "").split(",")) {
            val hex = part.replace(Regex("[\\s:]"), "").lowercase()
            if (Regex("^[0-9a-f]{64}$").matches(hex) && hex !in out) out.add(hex)
        }
        return out.joinToString(",")
    }

    /**
     * What newer links carry for TLS (v2rayN's names; the core's in brackets):
     * `ech` (echConfigList) — a base64 ECHConfigList or where to fetch one,
     * `cloudflare-ech.com+udp://1.1.1.1`, kept verbatim (the `+` is no space);
     * `pcs` (pinnedPeerCertSha256) — the certificate to accept; `vcn`
     * (verifyPeerCertByName) — the name(s) to check it against. parser.js tlsExtras.
     */
    internal fun tlsExtras(tls: JSONObject, q: Map<String, String?>): JSONObject {
        val ech = (q["ech"]?.takeIf { it.isNotBlank() } ?: q["echConfigList"] ?: "").trim()
        if (ech.isNotEmpty()) tls.put("echConfigList", ech)
        val pcs = pinList(q["pcs"]?.takeIf { it.isNotBlank() } ?: q["pinnedPeerCertSha256"]?.takeIf { it.isNotBlank() } ?: q["pinSHA256"])
        if (pcs.isNotEmpty()) tls.put("pinnedPeerCertSha256", pcs)
        val vcn = (q["vcn"]?.takeIf { it.isNotBlank() } ?: q["verifyPeerCertByName"] ?: "").split(",").map { it.trim() }.filter { it.isNotEmpty() }.joinToString(",")
        if (vcn.isNotEmpty()) tls.put("verifyPeerCertByName", vcn)
        return tls
    }

    /** The xhttp `extra` query value as an object; null when absent or not one. */
    fun parseXhttpExtra(raw: String?): JSONObject? {
        val s = raw?.trim() ?: return null
        if (s.isEmpty()) return null
        return try { JSONObject(s) } catch (e: Exception) { null }
    }

    /** An IP, "ip:port" or "[v6]:port" — the forms DnsPlan takes as a resolver (parser.js isResolverEntry). */
    fun isResolverEntry(v: String): Boolean {
        if (DnsPlan.isIp(v)) return true
        Regex("^\\[([^\\]]+)\\](?::\\d{1,5})?$").find(v)?.let { return DnsPlan.isIpv6(it.groupValues[1]) }
        Regex("^([^:/]+):\\d{1,5}$").find(v)?.let { return DnsPlan.isIpv4(it.groupValues[1]) }
        return false
    }

    /**
     * `DNS = 10.0.0.53, corp.local` → resolvers and search domains. Mirrors
     * parser.js splitDnsField: every entry that is not an address is a search
     * domain, lower-cased, without a leading dot.
     */
    fun splitDnsField(value: String?): Pair<List<String>, List<String>> {
        val dns = ArrayList<String>(); val domains = ArrayList<String>()
        for (v in splitCommas(value)) { if (isResolverEntry(v)) dns.add(v) else domains.add(v.trimStart('.').lowercase()) }
        return dns to domains
    }

    /**
     * A link value, or null when it is absent OR empty — the desktop's `q.x || …`.
     * v2rayN exports every key it knows, empty ones included: `type=` read as a
     * value became network "" (which xray refuses), `sni=` an empty SNI.
     */
    private fun Map<String, String?>.given(k: String): String? = this[k]?.takeIf { it.isNotBlank() }

    internal fun buildStream(q: Map<String, String?>): JSONObject {
        val net = (q.given("type") ?: q.given("network") ?: "tcp").lowercase()
        val security = (q.given("security") ?: "none").lowercase()
        val stream = JSONObject().put("network", net).put("security", security)

        when (net) {
            "ws" -> stream.put("wsSettings", JSONObject()
                .put("path", q.given("path") ?: "/")
                .put("headers", JSONObject().apply { q.given("host")?.let { put("Host", it) } }))
            "grpc" -> stream.put("grpcSettings", JSONObject()
                .put("serviceName", q.given("serviceName") ?: q.given("path") ?: "")
                .put("multiMode", q["mode"] == "multi")
                // the :authority the gRPC stream announces — what a CDN routes by
                .apply { q.given("authority")?.let { put("authority", it.trim()) } })
            "h2", "http" -> {
                stream.put("network", "h2")
                stream.put("httpSettings", JSONObject()
                    .put("path", q.given("path") ?: "/")
                    .put("host", JSONArray().apply { q.given("host")?.split(",")?.forEach { put(it) } }))
            }
            // Without its own settings the core dials `/` with Host = the address —
            // a 404 from every CDN-fronted httpupgrade server (parser.js).
            "httpupgrade" -> stream.put("httpupgradeSettings", JSONObject()
                .put("path", q.given("path") ?: "/").put("host", q.given("host") ?: ""))
            "xhttp", "splithttp" -> {
                stream.put("network", "xhttp")
                val xs = JSONObject().put("path", q.given("path") ?: "/").put("host", q.given("host") ?: "").put("mode", q.given("mode") ?: "auto")
                // `extra`: the link's JSON of everything else xhttp takes — xmux,
                // padding, scMaxEachPostBytes, the uplink method — as v2rayN and the
                // panels emit it. The core reads it leniently (unknown keys ignored)
                // and its own host / path / mode win over anything inside it.
                parseXhttpExtra(q["extra"])?.let { xs.put("extra", it) }
                stream.put("xhttpSettings", xs)
            }
            "kcp", "mkcp" -> {
                stream.put("network", "kcp")
                // Stored in the link's own terms; CoreCompat writes the masks the
                // running core takes (the 2026 cores refuse header/seed here).
                stream.put("kcpSettings", JSONObject()
                    .put("header", JSONObject().put("type", q.given("headerType") ?: "none")).put("seed", q.given("seed") ?: "")
                    .apply { q["mtu"]?.trim()?.toIntOrNull()?.takeIf { it > 0 }?.let { put("mtu", it) } })
            }
            "tcp" -> if (q["headerType"] == "http") {
                stream.put("tcpSettings", JSONObject().put("header", JSONObject()
                    .put("type", "http")
                    .put("request", JSONObject()
                        .put("path", JSONArray().put(q.given("path") ?: "/"))
                        .put("headers", JSONObject().apply {
                            q.given("host")?.let { put("Host", JSONArray().put(it)) }
                        }))))
            }
        }

        if (security == "tls") {
            val tls = JSONObject()
                .put("serverName", q.given("sni") ?: q.given("host") ?: "")
                // `insecure` / `allow_insecure`: hysteria2's, anytls' and tuic's spelling
                .put("allowInsecure", isTrue(q["allowInsecure"]) || isTrue(q["insecure"]) || isTrue(q["allow_insecure"]))
                .put("fingerprint", q.given("fp") ?: "chrome")
            q["alpn"]?.takeIf { it.isNotEmpty() }?.let { tls.put("alpn", JSONArray().apply { it.split(",").forEach { a -> put(a) } }) }
            // patterniha custom TLS: `unsafe` fingerprint + pinned cipherSuites.
            // `cs` is the standard share-link name, `cipherSuites` the long legacy one.
            val cs = q["cs"]?.takeIf { it.isNotBlank() } ?: q["cipherSuites"]
            cs?.takeIf { it.isNotBlank() }?.let { tls.put("cipherSuites", it.trim()) }
            tlsExtras(tls, q)
            stream.put("tlsSettings", tls)
        } else if (security == "reality") {
            stream.put("realitySettings", JSONObject()
                .put("serverName", q.given("sni") ?: "")
                .put("fingerprint", q.given("fp") ?: "chrome")
                .put("publicKey", q.given("pbk") ?: "")
                .put("shortId", q.given("sid") ?: "")
                .put("spiderX", q.given("spx") ?: "")
                // `pqv`: the server's ML-DSA-65 public key — REALITY's post-quantum check
                .apply { mldsaKey(q.given("pqv") ?: q.given("mldsa65Verify")).takeIf { it.isNotEmpty() }?.let { put("mldsa65Verify", it) } })
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

    /**
     * `host:port`, `[v6]:port` or `[v6]` → the host and the port's text ("" =
     * none, the caller's default). A `/` ends the authority: `host:2053/?type=ws`
     * leaves "host:2053/" in front of the query, and the slash is no part of the
     * port. `[v6]` without a port used to throw.
     */
    private fun splitHostPort(hp0: String): Pair<String, String> {
        val hp = hp0.substringBefore('/')
        if (hp.startsWith("[")) {
            val close = hp.indexOf(']')
            if (close == -1) return hp.substring(1) to ""
            val rest = hp.substring(close + 1)
            return hp.substring(1, close) to (if (rest.startsWith(":")) rest.substring(1) else "")
        }
        val i = hp.lastIndexOf(':')
        return if (i == -1) hp to "" else hp.substring(0, i) to hp.substring(i + 1)
    }

    /** The port a link names — its leading digits, as parseInt reads "2053/" — else [def]. */
    internal fun portOf(s: String, def: Int): Int =
        Regex("^\\s*(\\d+)").find(s)?.groupValues?.get(1)?.toIntOrNull()?.takeIf { it > 0 } ?: def

    private fun dec(s: String): String = pctDecode(s)

    /**
     * `%XX` → the byte it names, read as UTF-8, and nothing else: a `+` stays a
     * `+`. URLDecoder is FORM decoding and made it a space, which broke every
     * standard-base64 key (WARP's public keys carry '+') and any password with
     * one in it. This is decodeURIComponent, which the desktop uses — and as the
     * desktop's safeDecodeURIComponent does, a malformed escape gives the text
     * back as it was.
     */
    internal fun pctDecode(s: String): String {
        if (s.indexOf('%') < 0) return s
        val bytes = ByteArrayOutputStream(s.length)
        var i = 0
        while (i < s.length) {
            if (s[i] == '%') {
                if (i + 2 >= s.length) return s
                val hi = hexDigit(s[i + 1])
                val lo = hexDigit(s[i + 2])
                if (hi < 0 || lo < 0) return s
                bytes.write(hi * 16 + lo)
                i += 3
            } else {
                val cp = s.codePointAt(i)
                val b = String(Character.toChars(cp)).toByteArray(Charsets.UTF_8)
                bytes.write(b, 0, b.size)
                i += Character.charCount(cp)
            }
        }
        return try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes.toByteArray())).toString()
        } catch (e: CharacterCodingException) { s }
    }

    /**
     * An ASCII hex digit's value, else -1. Not Character.digit, which also takes
     * every other script's digits — "%۵۰" (Persian five, zero) decoded to "P".
     */
    private fun hexDigit(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }

    private fun b64(s: String?): String {
        if (s.isNullOrBlank()) return ""
        return try { String(Base64.decode(b64Normalize(s), Base64.DEFAULT), Charsets.UTF_8) } catch (e: Exception) { "" }
    }

    /**
     * Base64 text the way the decoder takes it: no whitespace anywhere, the
     * URL-safe alphabet mapped back, padded to a multiple of four. A panel's
     * subscription body is often wrapped at 76 columns, and the padding used to
     * be counted with the newlines in — android.util.Base64 refuses the extra
     * '=' that made, so the whole subscription decoded to nothing. (Node's
     * Buffer ignores both, which is why the desktop never saw it.)
     */
    internal fun b64Normalize(s: String): String {
        val t = StringBuilder(s.length + 3)
        for (c in s) {
            if (c.isWhitespace()) continue
            t.append(if (c == '-') '+' else if (c == '_') '/' else c)
        }
        while (t.length % 4 != 0) t.append('=')
        return t.toString()
    }

    /* ------------------- build share link (carries ALL settings) ------------------- */
    // encodeURIComponent's space, %20: URLEncoder writes '+', which a reader that
    // keeps '+' as '+' (the desktop, and this parser now) hands back as a '+'.
    private fun enc(s: String) = java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20")
    private fun jarr(a: JSONArray?): List<String> = if (a == null) emptyList() else (0 until a.length()).map { a.optString(it) }
    private fun b64e(s: String) = Base64.encodeToString(s.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
    private fun qstr(m: Map<String, String>) = m.filterValues { it.isNotBlank() }.entries.joinToString("&") { "${it.key}=${enc(it.value)}" }

    /** streamSettings -> flat query params (inverse of buildStream). */
    private fun streamToQuery(st: JSONObject, q: MutableMap<String, String>) {
        val net = st.optString("network", "tcp"); q["type"] = net; q["security"] = st.optString("security", "none")
        when (net) {
            "ws" -> st.optJSONObject("wsSettings")?.let { q["path"] = it.optString("path"); it.optJSONObject("headers")?.optString("Host")?.takeIf { h -> h.isNotBlank() }?.let { h -> q["host"] = h } }
            "grpc" -> st.optJSONObject("grpcSettings")?.let { q["serviceName"] = it.optString("serviceName"); if (it.optBoolean("multiMode")) q["mode"] = "multi"; it.optString("authority").takeIf { a -> a.isNotBlank() }?.let { a -> q["authority"] = a } }
            "h2", "http" -> st.optJSONObject("httpSettings")?.let { q["path"] = it.optString("path"); q["host"] = jarr(it.optJSONArray("host")).joinToString(",") }
            "httpupgrade" -> st.optJSONObject("httpupgradeSettings")?.let { q["path"] = it.optString("path"); it.optString("host").takeIf { h -> h.isNotBlank() }?.let { h -> q["host"] = h } }
            "xhttp" -> st.optJSONObject("xhttpSettings")?.let { q["path"] = it.optString("path"); q["host"] = it.optString("host"); it.optString("mode").takeIf { m -> m.isNotBlank() }?.let { m -> q["mode"] = m }; it.optJSONObject("extra")?.takeIf { x -> x.length() > 0 }?.let { x -> q["extra"] = x.toString() } }
            "kcp" -> st.optJSONObject("kcpSettings")?.let { q["headerType"] = it.optJSONObject("header")?.optString("type") ?: "none"; it.optString("seed").takeIf { sd -> sd.isNotBlank() }?.let { sd -> q["seed"] = sd }; it.optInt("mtu", 0).takeIf { m -> m > 0 }?.let { m -> q["mtu"] = m.toString() } }
            "tcp" -> st.optJSONObject("tcpSettings")?.optJSONObject("header")?.takeIf { it.optString("type") == "http" }?.let { h -> q["headerType"] = "http"; val rq = h.optJSONObject("request"); q["path"] = rq?.optJSONArray("path")?.optString(0) ?: ""; q["host"] = rq?.optJSONObject("headers")?.optJSONArray("Host")?.optString(0) ?: "" }
        }
        st.optJSONObject("tlsSettings")?.let {
            q["sni"] = it.optString("serverName"); q["fp"] = it.optString("fingerprint"); if (it.optBoolean("allowInsecure")) q["allowInsecure"] = "1"
            jarr(it.optJSONArray("alpn")).joinToString(",").takeIf { a -> a.isNotBlank() }?.let { a -> q["alpn"] = a }
            it.optString("cipherSuites").takeIf { c -> c.isNotBlank() }?.let { c -> q["cs"] = c }
            it.optString("echConfigList").takeIf { x -> x.isNotBlank() }?.let { x -> q["ech"] = x }
            it.optString("pinnedPeerCertSha256").takeIf { x -> x.isNotBlank() }?.let { x -> q["pcs"] = x }
            it.optString("verifyPeerCertByName").takeIf { x -> x.isNotBlank() }?.let { x -> q["vcn"] = x }
        }
        st.optJSONObject("realitySettings")?.let {
            q["sni"] = it.optString("serverName"); q["fp"] = it.optString("fingerprint"); q["pbk"] = it.optString("publicKey"); q["sid"] = it.optString("shortId")
            it.optString("spiderX").takeIf { x -> x.isNotBlank() }?.let { x -> q["spx"] = x }
            it.optString("mldsa65Verify").takeIf { x -> x.isNotBlank() }?.let { x -> q["pqv"] = x }
        }
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
                // the second value of a transport, where vmessFromJson reads it back (v2rayN's places)
                when (p["type"]) {
                    "grpc" -> { v.put("host", p["authority"] ?: ""); p["mode"]?.let { v.put("type", it) } }
                    "xhttp" -> { p["mode"]?.let { v.put("type", it) }; p["extra"]?.let { v.put("extra", it) } }
                    "kcp" -> p["seed"]?.let { v.put("path", it) }
                }
                if (p["allowInsecure"] == "1") v.put("insecure", "1")
                p["ech"]?.let { v.put("ech", it) }; p["pcs"]?.let { v.put("pcs", it) }; p["vcn"]?.let { v.put("vcn", it) }
                p["cs"]?.let { v.put("cs", it) }; p["fm"]?.let { v.put("fm", it) }
                extras["fragment"]?.let { v.put("fragment", it) }; extras["noise"]?.let { v.put("noise", it) }
                extras["engine"]?.let { v.put("engine", it) }
                "vmess://" + b64e(v.toString())
            }
            "shadowsocks" -> {
                val srv = srv0(ob)
                val plugin = ssPluginOf(st)
                val query = if (plugin.isNotEmpty()) "/?plugin=" + enc(plugin) else ""
                "ss://${b64e("${srv.optString("method")}:${srv.optString("password")}")}@${s.address}:${s.port}$query$name"
            }
            "hysteria2" -> {
                val h = hy2Values(ob)
                val q = LinkedHashMap<String, String>()
                q["sni"] = h["sni"] ?: ""; q["insecure"] = h["insecure"] ?: ""; q["alpn"] = h["alpn"] ?: ""
                q["pinSHA256"] = h["pcs"] ?: ""; q["ech"] = h["ech"] ?: ""; q["vcn"] = h["vcn"] ?: ""
                q["obfs"] = h["obfs"] ?: ""; q["obfs-password"] = h["obfs-password"] ?: ""; q["mport"] = h["mport"] ?: ""
                q["hopInterval"] = (h["hopInterval"] ?: "").takeIf { it.isNotEmpty() && (h["mport"] ?: "").isNotEmpty() && it != HOP_INTERVAL } ?: ""
                q["up"] = (h["up"] ?: "").replace(Regex("\\s*mbps$", RegexOption.IGNORE_CASE), "")
                q["down"] = (h["down"] ?: "").replace(Regex("\\s*mbps$", RegexOption.IGNORE_CASE), "")
                extras["engine"]?.let { q["engine"] = it }
                "hysteria2://${enc(h["auth"] ?: "")}@${s.address}:${s.port}/?${qstr(q)}$name"
            }
            "socks", "http" -> {
                val srv = srv0(ob); val c = srv.optJSONArray("users")?.optJSONObject(0)
                val auth = if (c != null) b64e("${c.optString("user")}:${c.optString("pass")}") + "@" else ""
                "${s.protocol}://$auth${s.address}:${s.port}$name"
            }
            "wireguard" -> {
                val set = ob.optJSONObject("settings") ?: JSONObject()
                val peer = set.optJSONArray("peers")?.optJSONObject(0) ?: JSONObject()
                val q = LinkedHashMap<String, String>()
                q["publickey"] = peer.optString("publicKey")
                q["address"] = jarr(set.optJSONArray("address")).joinToString(",")
                q["allowedips"] = jarr(peer.optJSONArray("allowedIPs")).joinToString(",")
                q["presharedkey"] = peer.optString("preSharedKey")
                q["mtu"] = if (set.has("mtu")) set.optInt("mtu").toString() else ""
                q["reserved"] = jarr(set.optJSONArray("reserved")).joinToString(",")
                q["dns"] = (s.dns + s.dnsDomains).joinToString(",")
                "wireguard://${enc(set.optString("secretKey"))}@${s.address}:${s.port}?${qstr(q)}$name"
            }
            else -> s.raw   // unknown -> imported link
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
