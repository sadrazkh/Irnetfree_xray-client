package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Reads editable fields out of a ServerConfig's outbound and rebuilds the
 * outbound from edited fields — the Android counterpart of the desktop
 * parser.js `applyServerEdits`. Includes the `fragment` marker.
 */
object ServerEditor {

    data class Fields(
        var name: String = "", var address: String = "", var port: String = "",
        var cred: String = "",                 // uuid / password / wg private key
        var network: String = "tcp", var security: String = "none",
        var sni: String = "", var host: String = "", var path: String = "", var fp: String = "chrome",
        var pbk: String = "", var sid: String = "", var allowInsecure: Boolean = false, var alpn: String = "",
        var method: String = "",               // shadowsocks method
        var proxyUser: String = "", var proxyPass: String = "",
        var wgPub: String = "", var wgAddr: String = "", var wgPsk: String = "",
        var wgMtu: String = "1420", var wgReserved: String = "", var wgAllowed: String = "0.0.0.0/0, ::/0",
        var fragment: String = "", var noise: String = ""
    )

    fun read(s: ServerConfig): Fields {
        val f = Fields(name = s.name, address = s.address, port = s.port.toString())
        val ob = s.outbound
        val st = ob.optJSONObject("streamSettings") ?: JSONObject()
        f.network = st.optString("network", "tcp"); f.security = st.optString("security", "none")
        f.fragment = ob.optString("_fragment", "")
        f.noise = ob.optString("_noise", "")

        when (s.protocol) {
            "vless", "vmess" -> vnextUser(ob)?.let { f.cred = it.optString("id") }
            "trojan" -> serverObj(ob)?.let { f.cred = it.optString("password") }
            "shadowsocks" -> serverObj(ob)?.let { f.cred = it.optString("password"); f.method = it.optString("method") }
            "socks", "http" -> serverObj(ob)?.optJSONArray("users")?.optJSONObject(0)?.let { f.proxyUser = it.optString("user"); f.proxyPass = it.optString("pass") }
            "wireguard" -> {
                val set = ob.optJSONObject("settings") ?: JSONObject()
                f.cred = set.optString("secretKey")
                f.wgAddr = arr(set.optJSONArray("address")).joinToString(",")
                f.wgMtu = set.optInt("mtu", 1420).toString()
                f.wgReserved = arr(set.optJSONArray("reserved")).joinToString(",")
                set.optJSONArray("peers")?.optJSONObject(0)?.let { p ->
                    f.wgPub = p.optString("publicKey"); f.wgPsk = p.optString("preSharedKey")
                    f.wgAllowed = arr(p.optJSONArray("allowedIPs")).joinToString(", ")
                }
            }
        }
        // transport / tls details
        st.optJSONObject("wsSettings")?.let { f.path = it.optString("path"); f.host = it.optJSONObject("headers")?.optString("Host") ?: "" }
        st.optJSONObject("grpcSettings")?.let { f.path = it.optString("serviceName") }
        st.optJSONObject("tlsSettings")?.let { f.sni = it.optString("serverName"); f.allowInsecure = it.optBoolean("allowInsecure"); f.fp = it.optString("fingerprint", "chrome"); f.alpn = arr(it.optJSONArray("alpn")).joinToString(",") }
        st.optJSONObject("realitySettings")?.let { f.sni = it.optString("serverName"); f.fp = it.optString("fingerprint", "chrome"); f.pbk = it.optString("publicKey"); f.sid = it.optString("shortId") }
        return f
    }

    fun apply(s: ServerConfig, f: Fields): ServerConfig {
        val addr = f.address.trim().ifEmpty { s.address }
        val port = f.port.toIntOrNull() ?: s.port
        val ob: JSONObject = when (s.protocol) {
            "vless" -> JSONObject().put("protocol", "vless")
                .put("settings", JSONObject().put("vnext", JSONArray().put(JSONObject().put("address", addr).put("port", port)
                    .put("users", JSONArray().put(JSONObject().put("id", f.cred.trim()).put("encryption", "none").put("flow", ""))))))
                .put("streamSettings", LinkParser.buildStream(streamQ(f)))
            "vmess" -> JSONObject().put("protocol", "vmess")
                .put("settings", JSONObject().put("vnext", JSONArray().put(JSONObject().put("address", addr).put("port", port)
                    .put("users", JSONArray().put(JSONObject().put("id", f.cred.trim()).put("alterId", 0).put("security", "auto"))))))
                .put("streamSettings", LinkParser.buildStream(streamQ(f)))
            "trojan" -> JSONObject().put("protocol", "trojan")
                .put("settings", JSONObject().put("servers", JSONArray().put(JSONObject().put("address", addr).put("port", port).put("password", f.cred.trim()))))
                .put("streamSettings", LinkParser.buildStream(streamQ(f)))
            "shadowsocks" -> JSONObject().put("protocol", "shadowsocks")
                .put("settings", JSONObject().put("servers", JSONArray().put(JSONObject().put("address", addr).put("port", port).put("method", f.method.trim()).put("password", f.cred.trim()).put("uot", true))))
                .put("streamSettings", JSONObject().put("network", "tcp"))
            "socks", "http" -> LinkParser.proxyOutbound(s.protocol, addr, port, f.proxyUser.trim(), f.proxyPass.trim())
            "wireguard" -> LinkParser.buildWireguardOutbound(f.cred.trim(), f.wgPub.trim(), "$addr:$port", f.wgAddr.trim(), f.wgPsk.trim(), f.wgMtu, f.wgReserved, f.wgAllowed)
            else -> s.outbound
        }
        if (f.fragment.isNotBlank()) ob.put("_fragment", f.fragment.trim())
        if (f.noise.isNotBlank()) ob.put("_noise", f.noise.trim())
        return s.copy(name = f.name.trim().ifEmpty { s.name }, address = addr, port = port, outbound = ob)
    }

    private fun streamQ(f: Fields): Map<String, String?> = mapOf(
        "type" to f.network, "security" to f.security, "sni" to f.sni, "host" to f.host,
        "path" to f.path, "serviceName" to f.path, "fp" to f.fp, "pbk" to f.pbk, "sid" to f.sid,
        "alpn" to f.alpn, "allowInsecure" to if (f.allowInsecure) "1" else "0")

    private fun vnextUser(ob: JSONObject) = ob.optJSONObject("settings")?.optJSONArray("vnext")?.optJSONObject(0)?.optJSONArray("users")?.optJSONObject(0)
    private fun serverObj(ob: JSONObject) = ob.optJSONObject("settings")?.optJSONArray("servers")?.optJSONObject(0)
    private fun arr(a: JSONArray?): List<String> = if (a == null) emptyList() else (0 until a.length()).map { a.optString(it) }
}
