package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import java.util.Collections
import java.util.IdentityHashMap

/**
 * A saved server dialled at another address — a clean CDN IP, another port —
 * as a group member asks for it (v1.27.0, Groups.kt). The desktop's
 * src/main/addressSwap.js, itself ported from IRNetFree Plus's scanner
 * (scan/substitute.js `applyTarget`), less the SNI. Pure: the stored record is
 * never touched, a deep copy comes back.
 *
 * The address goes where the protocol keeps it: `vnext[0]` (vless, vmess),
 * `servers[0]` (trojan, shadowsocks), the flat `settings.address/port`
 * (hysteria, MASQUE, and any flat shape a JSON config uses), a WireGuard
 * peer's `endpoint`. The names the server hides behind — TLS SNI, the
 * WebSocket / HTTPUpgrade / XHTTP / h2 Host, the gRPC authority — stay on the
 * original host name, and are filled from it when the link left them empty:
 * the Cloudflare-fronting trick, any edge IP works as long as the handshake
 * still names the site. REALITY's serverName is the camouflage site, not
 * ours, so it is never touched.
 *
 *   withTarget(server, address, port) → the copy | throws [SwapError] (.code: unsupported | json-chain | invalid)
 *   dialOf(server) → what it dials today
 */
object AddressSwap {
    /** What a JSON server's helper is when it dials as a proxy of its own (the desktop's list, written out). */
    private val PROXY_PROTOCOLS = setOf("vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard", "hysteria", "masque")
    val SUPPORTED_PROTOCOLS: List<String> = listOf("vless", "vmess", "trojan", "shadowsocks", "hysteria2", "masque", "wireguard")

    /** Why a server cannot take another address: [code] unsupported | json-chain | invalid. */
    class SwapError(val code: String, message: String) : IllegalArgumentException(message)

    /** What a server dials: its address (a host or an IP) and port (null when none). */
    data class Dial(val addr: String, val port: Int?)

    /** [o]'s [key] as text, "" when absent or a JSON null (Android's org.json hands back "null" for one). */
    private fun str(o: JSONObject?, key: String): String =
        if (o == null || o.isNull(key)) "" else o.opt(key).toString()

    /** JavaScript's falsy for a field: absent, null, "", false or 0. */
    private fun falsy(o: JSONObject, key: String): Boolean {
        if (o.isNull(key)) return true
        val v = o.opt(key)
        return when (v) {
            is String -> v.isEmpty()
            is Boolean -> !v
            is Number -> v.toDouble() == 0.0
            else -> false
        }
    }

    /** 1–65535, or null: a whole number, or text that reads as one. */
    fun toPort(v: Any?): Int? {
        val d: Double = when (v) {
            null -> return null
            is Number -> v.toDouble()
            is String -> v.trim().toDoubleOrNull() ?: return null
            else -> return null
        }
        if (d.isNaN() || d != Math.floor(d) || d < 1.0 || d > 65535.0) return null
        return d.toInt()
    }

    /** `host:port`, a v6 host bracketed; [port] null → the host alone. */
    fun addrPort(addr: String, port: Int?): String {
        if (port == null) return addr
        return (if (addr.contains(':') && !addr.startsWith("[")) "[$addr]" else addr) + ":" + port
    }

    /** The record's protocol in its own terms ("hysteria2" for a hysteria outbound); the outbound's protocol wins. */
    fun protocolOf(server: ServerConfig): String {
        val p = str(server.outbound, "protocol").ifEmpty { server.protocol }
        return if (p == "hysteria") "hysteria2" else p
    }

    /** The node that carries the dial address, or null for a shape this cannot rewrite. WireGuard: [wgPeer]. */
    private fun dialNode(ob: JSONObject, proto: String): JSONObject? {
        val st = ob.optJSONObject("settings") ?: return null
        val flat: JSONObject? = if (st.opt("address") is String && st.optString("address").trim().isNotEmpty()) st else null
        return when (proto) {
            "vless", "vmess" -> st.optJSONArray("vnext")?.optJSONObject(0) ?: flat
            "trojan", "shadowsocks" -> st.optJSONArray("servers")?.optJSONObject(0) ?: flat
            "hysteria2", "masque" -> flat
            else -> null
        }
    }

    private fun wgPeer(ob: JSONObject): JSONObject? = ob.optJSONObject("settings")?.optJSONArray("peers")?.optJSONObject(0)

    /** 'host:port' / '[v6]:port' → host to port (port "" when none). */
    private fun splitEndpoint(ep: String): Pair<String, String> {
        val e = ep.trim()
        val m6 = Regex("^\\[([^\\]]+)\\](?::(\\d*))?$").find(e)
        if (m6 != null) return Pair(m6.groupValues[1], m6.groupValues[2])
        val i = e.lastIndexOf(':')
        if (i == -1 || e.indexOf(':') != i) return Pair(e, "")
        return Pair(e.substring(0, i), e.substring(i + 1))
    }

    /** The server address and port the config dials today (port null when none). */
    fun dialOf(server: ServerConfig): Dial {
        val proto = protocolOf(server)
        val ob = server.outbound
        var addr = ""
        var port: Int? = null
        if (proto == "wireguard") {
            val ep = splitEndpoint(str(wgPeer(ob), "endpoint"))
            addr = ep.first
            port = toPort(ep.second)
        } else {
            val node = dialNode(ob, proto)
            if (node != null) { addr = str(node, "address").trim(); port = toPort(node.opt("port")) }
        }
        if (addr.isEmpty()) addr = server.address.trim()
        if (port == null) port = toPort(server.port)
        return Dial(addr, port)
    }

    /** Fill the fronting names a link may have left empty. Only existing blocks are touched; REALITY never. */
    private fun fillHostNames(stream: JSONObject, name: String) {
        val tls = stream.optJSONObject("tlsSettings")
        if (tls != null && falsy(tls, "serverName")) tls.put("serverName", name)
        val ws = stream.optJSONObject("wsSettings")
        if (ws != null && falsy(ws, "host")) {
            val existing: JSONObject? = ws.optJSONObject("headers")
            val headers: JSONObject = existing ?: JSONObject()
            if (existing == null) ws.put("headers", headers)
            if (falsy(headers, "Host") && falsy(headers, "host")) headers.put("Host", name)
        }
        val hu = stream.optJSONObject("httpupgradeSettings")
        if (hu != null && falsy(hu, "host")) hu.put("host", name)
        val xh = stream.optJSONObject("xhttpSettings")
        if (xh != null && falsy(xh, "host")) xh.put("host", name)
        val h2 = stream.optJSONObject("httpSettings")
        if (h2 != null) {
            val cur = h2.opt("host")
            val list = JSONArray()
            if (cur is JSONArray) {
                for (i in 0 until cur.length()) list.put(cur.opt(i))
            } else if (!falsy(h2, "host")) {
                list.put(cur.toString())
            }
            if (list.length() == 0) list.put(name)
            h2.put("host", list)
        }
        val grpc = stream.optJSONObject("grpcSettings")
        if (grpc != null && falsy(grpc, "authority")) grpc.put("authority", name)
    }

    /** The tags an outbound dials through: its dialerProxy and its proxySettings.tag. */
    private fun refsOf(o: JSONObject): List<String> {
        val so = o.optJSONObject("streamSettings")?.optJSONObject("sockopt")
        val out = ArrayList<String>()
        val d = so?.opt("dialerProxy")
        if (d is String && d.isNotEmpty()) out.add(d)
        val t = o.optJSONObject("proxySettings")?.opt("tag")
        if (t is String && t.isNotEmpty()) out.add(t)
        return out
    }

    /**
     * Does a JSON server's main outbound reach its server through another proxy
     * (a chain)? Through a freedom helper (a fragment or noise dialer) it still
     * dials the address itself, so the walk goes on through those.
     */
    private fun dialsThroughProxy(server: ServerConfig): Boolean {
        val byTag = HashMap<String, JSONObject>()
        for (h in server.extraOutbounds) { val t = str(h, "tag"); if (t.isNotEmpty() && t !in byTag) byTag[t] = h }
        val visited: MutableSet<JSONObject> = Collections.newSetFromMap(IdentityHashMap<JSONObject, Boolean>())
        val queue = ArrayDeque<JSONObject>()
        queue.add(server.outbound)
        while (queue.isNotEmpty()) {
            val o = queue.removeFirst()
            if (!visited.add(o)) continue
            for (t in refsOf(o)) {
                val h = byTag[t] ?: continue
                if (str(h, "protocol") in PROXY_PROTOCOLS) return true
                queue.add(h)
            }
        }
        return false
    }

    /** Key order aside, the same JSON. */
    private fun canon(v: Any?): String = when (v) {
        null, JSONObject.NULL -> "null"
        is JSONObject -> v.keys().asSequence().toList().sorted().joinToString(",", "{", "}") { k: String -> JSONObject.quote(k) + ":" + canon(v.opt(k)) }
        is JSONArray -> (0 until v.length()).joinToString(",", "[", "]") { i: Int -> canon(v.opt(i)) }
        is String -> JSONObject.quote(v)
        else -> v.toString()
    }

    /** A JSON server's config gets the same outbound, so the record stays one config. */
    private fun mirrorIntoJson(json: JSONObject, outbound: JSONObject, original: JSONObject) {
        val list = json.optJSONArray("outbounds") ?: return
        val want = canon(original)
        for (i in 0 until list.length()) {
            val o = list.optJSONObject(i) ?: continue
            val c = JSONObject(o.toString())
            c.remove("tag")
            if (canon(c) != want) continue
            val copy = JSONObject(outbound.toString())
            if (o.has("tag")) copy.put("tag", o.opt("tag"))
            list.put(i, copy)
            return
        }
    }

    /** A deep copy of [s]: its outbound, its config and its helpers copied, nothing shared with the stored record. */
    private fun deepCopy(s: ServerConfig): ServerConfig = s.copy(
        outbound = JSONObject(s.outbound.toString()),
        json = s.json?.let { j: JSONObject -> JSONObject(j.toString()) },
        extraOutbounds = s.extraOutbounds.map { h: JSONObject -> JSONObject(h.toString()) }
    )

    /**
     * A deep copy of [server] that dials [address]:[port], its fronting names
     * kept on the original host. An absent field (null or blank) keeps the
     * config's own. Throws [SwapError]: "unsupported" (a protocol or record
     * shape this cannot rewrite), "json-chain" (a JSON server that reaches its
     * server through another proxy), "invalid" (a port outside 1–65535). `raw`
     * is left as it was.
     */
    fun withTarget(server: ServerConfig, address: String?, port: Any?): ServerConfig {
        val proto = protocolOf(server)
        if (server.outbound.length() == 0 || proto !in SUPPORTED_PROTOCOLS) {
            throw SwapError("unsupported", "unsupported protocol" + (if (proto.isNotEmpty()) ": $proto" else ""))
        }
        val shapeOk = if (proto == "wireguard") wgPeer(server.outbound) != null else dialNode(server.outbound, proto) != null
        if (!shapeOk) throw SwapError("unsupported", "this $proto config names no server to dial")
        if (server.source == JsonImport.SOURCE && dialsThroughProxy(server)) {
            throw SwapError("json-chain", "this JSON config dials its server through another proxy (a chain)")
        }
        val newAddr: String? = address?.trim()?.takeIf { a: String -> a.isNotEmpty() }?.replace(Regex("^\\[(.*)\\]$"), "$1")
        var newPort: Int? = null
        if (port != null && !(port is String && port.isEmpty())) {
            newPort = toPort(port) ?: throw SwapError("invalid", "invalid port: $port")
        }

        val origin = dialOf(server).addr
        val out = deepCopy(server)
        val ob = out.outbound
        if (proto == "wireguard") {
            val peer = wgPeer(ob)!!
            val ep = splitEndpoint(str(peer, "endpoint"))
            val host = newAddr ?: ep.first
            val p = newPort ?: (toPort(ep.second) ?: toPort(server.port))
            peer.put("endpoint", addrPort(host, p))
        } else {
            val node = dialNode(ob, proto)!!
            if (newAddr != null) node.put("address", newAddr)
            if (newPort != null) node.put("port", newPort)
        }
        val st = ob.optJSONObject("streamSettings")
        if (st != null && newAddr != null && origin.isNotEmpty() && !DnsPlan.isIp(origin)) fillHostNames(st, origin)
        val json = out.json
        if (out.source == JsonImport.SOURCE && json != null) mirrorIntoJson(json, ob, server.outbound)
        return out.copy(address = newAddr ?: out.address, port = newPort ?: out.port)
    }
}
