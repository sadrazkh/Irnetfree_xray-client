package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import kotlin.reflect.KMutableProperty1

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
        var wgDns: String = "",                // `DNS = 10.0.0.53, corp.local`: resolvers + search domains
        var fragment: String = "", var noise: String = "",
        var cipherSuites: String = "", var finalMask: String = "",   // patterniha
        // newer TLS / REALITY knobs: Encrypted Client Hello, a certificate pin, the
        // name to verify it against, REALITY's ML-DSA-65 key (parser.js tlsExtras)
        var ech: String = "", var pcs: String = "", var vcn: String = "", var pqv: String = "",
        // Hysteria2: the salamander password and the hopping ports
        var hy2Obfs: String = "", var hy2Ports: String = "",
        var engine: String = "xray",                // 'xray' (default) | 'sing-box'
        // preserved passthroughs the edit form doesn't expose (so editing anything
        // doesn't silently drop them): reality spiderX, xhttp mode/extra, kcp bits.
        var spx: String = "", var xmode: String = "", var seed: String = "",
        var headerType: String = "", var xhttpExtra: JSONObject? = null
    )

    fun read(s: ServerConfig): Fields {
        val f = Fields(name = s.name, address = s.address, port = s.port.toString())
        val ob = s.outbound
        val st = ob.optJSONObject("streamSettings") ?: JSONObject()
        f.network = st.optString("network", "tcp"); f.security = st.optString("security", "none")
        f.fragment = ob.optString("_fragment", "")
        f.noise = ob.optString("_noise", "")
        f.engine = s.engine ?: "xray"

        when (s.protocol) {
            "vless", "vmess" -> vnextUser(ob)?.let { f.cred = it.optString("id") }
            "trojan" -> serverObj(ob)?.let { f.cred = it.optString("password") }
            "shadowsocks" -> serverObj(ob)?.let { f.cred = it.optString("password"); f.method = it.optString("method") }
            "socks", "http" -> serverObj(ob)?.optJSONArray("users")?.optJSONObject(0)?.let { f.proxyUser = it.optString("user"); f.proxyPass = it.optString("pass") }
            "hysteria2" -> {
                val h = LinkParser.hy2Values(ob)
                f.cred = h["auth"] ?: ""; f.hy2Obfs = h["obfs-password"] ?: ""; f.hy2Ports = h["mport"] ?: ""
            }
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
                f.wgDns = (s.dns + s.dnsDomains).joinToString(", ")
            }
        }
        // transport / tls details
        st.optJSONObject("wsSettings")?.let { f.path = it.optString("path"); f.host = it.optJSONObject("headers")?.optString("Host") ?: "" }
        // gRPC's :authority is what the sheet's Host field shows for it
        st.optJSONObject("grpcSettings")?.let { f.path = it.optString("serviceName"); f.host = it.optString("authority"); if (it.optBoolean("multiMode")) f.xmode = "multi" }
        if (f.network == "h2" || f.network == "http") st.optJSONObject("httpSettings")?.let { f.path = it.optString("path"); f.host = arr(it.optJSONArray("host")).joinToString(",") }
        if (f.network == "tcp" || f.network == "raw") httpHeaderRequest(st)?.let { rq ->
            f.path = arr(rq.optJSONArray("path")).joinToString(",")
            f.host = arr(rq.optJSONObject("headers")?.optJSONArray("Host")).joinToString(",")
        }
        st.optJSONObject("xhttpSettings")?.let { f.path = it.optString("path"); f.host = it.optString("host"); f.xmode = it.optString("mode"); f.xhttpExtra = it.optJSONObject("extra") }
        st.optJSONObject("httpupgradeSettings")?.let { f.path = it.optString("path"); f.host = it.optString("host") }
        st.optJSONObject("kcpSettings")?.let { f.seed = it.optString("seed"); f.headerType = it.optJSONObject("header")?.optString("type") ?: "" }
        st.optJSONObject("tlsSettings")?.let { f.sni = it.optString("serverName"); f.allowInsecure = it.optBoolean("allowInsecure"); f.fp = it.optString("fingerprint", "chrome"); f.alpn = arr(it.optJSONArray("alpn")).joinToString(",") }
        st.optJSONObject("realitySettings")?.let { f.sni = it.optString("serverName"); f.fp = it.optString("fingerprint", "chrome"); f.pbk = it.optString("publicKey"); f.sid = it.optString("shortId"); f.spx = it.optString("spiderX") }
        st.optJSONObject("tlsSettings")?.optString("cipherSuites")?.takeIf { it.isNotBlank() }?.let { f.cipherSuites = it }
        st.optJSONObject("tlsSettings")?.let { f.ech = it.optString("echConfigList"); f.pcs = it.optString("pinnedPeerCertSha256"); f.vcn = it.optString("verifyPeerCertByName") }
        st.optJSONObject("realitySettings")?.let { f.pqv = it.optString("mldsa65Verify") }
        // Hysteria2's masks are its obfs and hopping fields (hy2Obfs / hy2Ports), not text to edit
        if (s.protocol != "hysteria2") st.optJSONObject("finalmask")?.let { f.finalMask = it.toString() }
        return f
    }

    /**
     * The edited server: a CLONE of its outbound with only what the user changed
     * written into it — the desktop's applyServerEdits.
     *
     * The sheet hands back every field it shows, changed or not, so "changed" is
     * measured against [read] of the same server: a field still holding what the
     * sheet opened with is left exactly as stored. Everything the form has no
     * field for — VLESS `flow` and `encryption`, vmess alterId and cipher, a TCP
     * HTTP header's method and headers, h2's host list, ws heartbeat, sockopt, a
     * WireGuard's keepAlive — survives any edit. The form used to be rebuilt from
     * scratch instead: renaming a REALITY + Vision config wrote `flow: ""` and
     * killed it, a TCP + HTTP-header config came back as plain TCP.
     *
     * A record too broken to patch (no vnext, no server, no peer) is rebuilt from
     * the form, as before.
     */
    fun apply(s: ServerConfig, f: Fields): ServerConfig {
        val was = read(s)
        val addr = f.address.trim().ifEmpty { s.address }
        val port = f.port.toIntOrNull() ?: s.port
        val moved = addr != s.address || port != s.port
        val ob = try { JSONObject(s.outbound.toString()) } catch (e: Exception) { JSONObject() }
        val patched: Boolean = when (s.protocol) {
            "vless", "vmess" -> {
                val vnext = ob.optJSONObject("settings")?.optJSONArray("vnext")?.optJSONObject(0)
                val user = vnext?.optJSONArray("users")?.optJSONObject(0)
                if (vnext == null || user == null) false else {
                    if (moved) vnext.put("address", addr).put("port", port)
                    if (f.cred != was.cred && f.cred.isNotBlank()) user.put("id", f.cred.trim())
                    patchStream(ob, was, f)
                    true
                }
            }
            "trojan", "shadowsocks", "socks", "http" -> {
                val srv = serverObj(ob)
                if (srv == null) false else {
                    if (moved) srv.put("address", addr).put("port", port)
                    if (s.protocol == "trojan" || s.protocol == "shadowsocks") {
                        if (f.cred != was.cred && f.cred.isNotBlank()) srv.put("password", f.cred.trim())
                    }
                    if (s.protocol == "shadowsocks" && f.method != was.method && f.method.isNotBlank()) srv.put("method", f.method.trim())
                    if ((s.protocol == "socks" || s.protocol == "http") && (f.proxyUser != was.proxyUser || f.proxyPass != was.proxyPass)) {
                        val u = f.proxyUser.trim(); val p = f.proxyPass.trim()
                        if (u.isEmpty() && p.isEmpty()) srv.remove("users")
                        else srv.put("users", JSONArray().put(JSONObject().put("user", u).put("pass", p)))
                    }
                    if (s.protocol == "trojan") patchStream(ob, was, f)
                    true
                }
            }
            "wireguard" -> patchWireguard(ob, was, f, if (moved) "$addr:$port" else null)
            "hysteria2" -> { patchHysteria2(ob, was, f, addr, port, moved); true }
            else -> true
        }
        val out = if (patched) ob else rebuilt(s, f, addr, port)
        // TLS fragmentation / noise: an emptied field clears it.
        if (!patched || f.fragment != was.fragment) { if (f.fragment.isBlank()) out.remove("_fragment") else out.put("_fragment", f.fragment.trim()) }
        if (!patched || f.noise != was.noise) { if (f.noise.isBlank()) out.remove("_noise") else out.put("_noise", f.noise.trim()) }
        val engine = f.engine.trim().takeIf { it.isNotBlank() && it != "xray" }
        val (dns, dnsDomains) = if (s.protocol == "wireguard") LinkParser.splitDnsField(f.wgDns) else (s.dns to s.dnsDomains)
        val saved = s.copy(name = f.name.trim().ifEmpty { s.name }, address = addr, port = port, outbound = out, engine = engine, dns = dns, dnsDomains = dnsDomains)
        return saved.copy(edited = record(s, was, read(saved)))
    }

    /**
     * The new [ServerConfig.edited]: the old record plus every field this save
     * REALLY changed — [read] of the saved server against [read] of the one
     * before, so a value apply did not take (" 8443", a non-numeric MTU, a padded
     * SNI trimmed back to what it was) is no edit — minus every field that now
     * holds exactly what the server's own link gives: saving the link's value
     * releases the field, and it follows the panel again.
     */
    private fun record(s: ServerConfig, before: Fields, after: Fields): List<String> {
        val changed = RECORDABLE.filter { valueOf(it, before) != valueOf(it, after) }
        val linked = SubRefresh.linkedForm(s)?.let { read(it) }
        return (s.edited + changed).distinct().filter { linked == null || valueOf(it, after) != valueOf(it, linked) }
    }

    /**
     * The sheet's text fields other than fragment / noise / core, by the name
     * [ServerConfig.edited] records them under. SubRefresh carries exactly the
     * recorded ones onto a refreshed subscription server.
     */
    internal val EDITABLE: List<Pair<String, KMutableProperty1<Fields, String>>> = listOf(
        "name" to Fields::name, "address" to Fields::address, "port" to Fields::port, "cred" to Fields::cred,
        "network" to Fields::network, "security" to Fields::security, "sni" to Fields::sni, "host" to Fields::host,
        "path" to Fields::path, "fp" to Fields::fp, "pbk" to Fields::pbk, "sid" to Fields::sid,
        "method" to Fields::method, "proxyUser" to Fields::proxyUser, "proxyPass" to Fields::proxyPass,
        "wgPub" to Fields::wgPub, "wgAddr" to Fields::wgAddr, "wgPsk" to Fields::wgPsk, "wgMtu" to Fields::wgMtu,
        "wgReserved" to Fields::wgReserved, "wgAllowed" to Fields::wgAllowed, "wgDns" to Fields::wgDns,
        "cipherSuites" to Fields::cipherSuites, "finalMask" to Fields::finalMask,
        "ech" to Fields::ech, "pcs" to Fields::pcs, "vcn" to Fields::vcn, "pqv" to Fields::pqv,
        "hy2Obfs" to Fields::hy2Obfs, "hy2Ports" to Fields::hy2Ports
    )

    /** Everything [ServerConfig.edited] can name: the text fields, then the switch, the fragment, the noise, the core. */
    private val RECORDABLE: List<String> = EDITABLE.map { it.first } + listOf("allowInsecure", "fragment", "noise", "engine")

    /** One recordable field of [f], in the form a save writes it (so two spellings of one value compare equal). */
    private fun valueOf(name: String, f: Fields): String = when (name) {
        "allowInsecure" -> f.allowInsecure.toString()
        "fragment" -> f.fragment.trim()
        "noise" -> noiseKey(f.noise)
        "engine" -> f.engine.trim().takeIf { it.isNotBlank() && it != "xray" } ?: ""
        else -> EDITABLE.firstOrNull { it.first == name }?.second?.get(f)?.trim() ?: ""
    }

    /**
     * A noise value as the sheet writes it back: its presets lower-cased and
     * "fakehello" as "faketls". Saving a link's `noise=fakehello` rewrites it as
     * "faketls" — the sheet's spelling, not a change the user made.
     */
    internal fun noiseKey(v: String): String {
        val t = v.trim()
        return when (val l = t.lowercase()) {
            "fakehello" -> "faketls"
            "random", "faketls" -> l
            else -> t
        }
    }

    /** Stream keys that belong to one transport; a change of transport drops them all. */
    private val TRANSPORT_KEYS = listOf("tcpSettings", "rawSettings", "wsSettings", "grpcSettings", "httpSettings",
        "xhttpSettings", "splithttpSettings", "kcpSettings", "httpupgradeSettings", "quicSettings")

    /** What buildStream calls a network: h2 for http, xhttp for splithttp, kcp for mkcp. */
    internal fun normNet(n: String): String = when (val l = n.lowercase()) {
        "http" -> "h2"; "splithttp" -> "xhttp"; "mkcp" -> "kcp"; else -> l
    }

    /** A child object, created when it is not there yet. */
    private fun child(parent: JSONObject, key: String): JSONObject =
        parent.optJSONObject(key) ?: JSONObject().also { parent.put(key, it) }

    private fun list(v: String): List<String> = v.split(",").map { it.trim() }.filter { it.isNotEmpty() }

    /** The request of a TCP (raw) HTTP-header obfuscation, when the stream has one. */
    private fun httpHeaderRequest(st: JSONObject): JSONObject? =
        (st.optJSONObject("tcpSettings") ?: st.optJSONObject("rawSettings"))?.optJSONObject("header")
            ?.takeIf { it.optString("type") == "http" }?.optJSONObject("request")

    /**
     * Write the stream fields the user changed into [ob]'s own streamSettings.
     * A new transport or a new security replaces that part whole (built the way
     * a link would be); the same one is patched field by field.
     */
    private fun patchStream(ob: JSONObject, was: Fields, f: Fields) {
        val changed = f.network != was.network || f.security != was.security || f.sni != was.sni || f.host != was.host ||
            f.path != was.path || f.fp != was.fp || f.pbk != was.pbk || f.sid != was.sid ||
            f.allowInsecure != was.allowInsecure || f.cipherSuites != was.cipherSuites || f.finalMask != was.finalMask ||
            f.ech != was.ech || f.pcs != was.pcs || f.vcn != was.vcn || f.pqv != was.pqv
        if (!changed) return
        // What the form says, built as a link would be — the old transport's
        // passthroughs (mode, seed, header type) mean nothing to a new one.
        val fresh = LinkParser.buildStream(streamQ(f, passthroughs = false))
        val cur = ob.optJSONObject("streamSettings")
        if (cur == null) { ob.put("streamSettings", fresh); return }

        val netNow = fresh.optString("network")
        val netWas = normNet(cur.optString("network", "tcp"))
        if (netNow != netWas) {
            TRANSPORT_KEYS.forEach { cur.remove(it) }
            cur.put("network", netNow)
            TRANSPORT_KEYS.forEach { k -> fresh.optJSONObject(k)?.let { cur.put(k, it) } }
        } else if (f.path != was.path || f.host != was.host) {
            patchTransport(cur, netWas, was, f)
        }

        val secNow = fresh.optString("security")
        val secWas = cur.optString("security", "none").lowercase()
        if (secNow != secWas) {
            cur.remove("tlsSettings"); cur.remove("realitySettings")
            cur.put("security", secNow)
            fresh.optJSONObject("tlsSettings")?.let { cur.put("tlsSettings", it) }
            fresh.optJSONObject("realitySettings")?.let { cur.put("realitySettings", it) }
        } else if (secWas == "tls") {
            if (f.sni != was.sni || f.fp != was.fp || f.allowInsecure != was.allowInsecure || f.cipherSuites != was.cipherSuites ||
                f.ech != was.ech || f.pcs != was.pcs || f.vcn != was.vcn) {
                val tls = child(cur, "tlsSettings")
                if (f.sni != was.sni) tls.put("serverName", f.sni.trim().ifEmpty { f.host.trim() })
                if (f.fp != was.fp) tls.put("fingerprint", f.fp.trim().ifEmpty { "chrome" })
                if (f.allowInsecure != was.allowInsecure) tls.put("allowInsecure", f.allowInsecure)
                if (f.cipherSuites != was.cipherSuites) { if (f.cipherSuites.isBlank()) tls.remove("cipherSuites") else tls.put("cipherSuites", f.cipherSuites.trim()) }
                patchTlsExtras(tls, was, f)
            }
        } else if (secWas == "reality") {
            if (f.sni != was.sni || f.fp != was.fp || f.pbk != was.pbk || f.sid != was.sid || f.pqv != was.pqv) {
                val rs = child(cur, "realitySettings")
                if (f.sni != was.sni) rs.put("serverName", f.sni.trim())
                if (f.fp != was.fp) rs.put("fingerprint", f.fp.trim().ifEmpty { "chrome" })
                if (f.pbk != was.pbk) rs.put("publicKey", f.pbk.trim())
                if (f.sid != was.sid) rs.put("shortId", f.sid.trim())
                if (f.pqv != was.pqv) { if (f.pqv.isBlank()) rs.remove("mldsa65Verify") else rs.put("mldsa65Verify", f.pqv.trim()) }
            }
        }

        if (f.finalMask != was.finalMask) {
            val fm = fresh.optJSONObject("finalmask")
            if (fm != null) cur.put("finalmask", fm) else cur.remove("finalmask")
        }
    }

    /** ECH, the pin and the verify-name the sheet changed, in the core's own fields (an emptied one clears). */
    private fun patchTlsExtras(tls: JSONObject, was: Fields, f: Fields) {
        if (f.ech != was.ech) { val v = f.ech.trim(); if (v.isEmpty()) tls.remove("echConfigList") else tls.put("echConfigList", v) }
        if (f.pcs != was.pcs) { val v = LinkParser.pinList(f.pcs); if (v.isEmpty()) tls.remove("pinnedPeerCertSha256") else tls.put("pinnedPeerCertSha256", v) }
        if (f.vcn != was.vcn) { val v = list(f.vcn).joinToString(","); if (v.isEmpty()) tls.remove("verifyPeerCertByName") else tls.put("verifyPeerCertByName", v) }
    }

    /**
     * Hysteria2: rebuilt (LinkParser.buildHysteria2Outbound) from everything it
     * had, with what the sheet changed over it; masks and QUIC knobs the sheet
     * does not model stay as they were (parser.js applyServerEdits).
     */
    private fun patchHysteria2(ob: JSONObject, was: Fields, f: Fields, addr: String, port: Int, moved: Boolean) {
        val touched = moved || f.cred != was.cred || f.sni != was.sni || f.allowInsecure != was.allowInsecure ||
            f.ech != was.ech || f.pcs != was.pcs || f.vcn != was.vcn || f.hy2Obfs != was.hy2Obfs || f.hy2Ports != was.hy2Ports
        if (!touched) return
        val h = LinkParser.hy2Values(ob)
        h["address"] = addr; h["port"] = port.toString()
        if (f.cred != was.cred && f.cred.isNotBlank()) h["auth"] = f.cred.trim()
        if (f.sni != was.sni) h["sni"] = f.sni.trim()
        if (f.allowInsecure != was.allowInsecure) h["insecure"] = if (f.allowInsecure) "1" else ""
        if (f.ech != was.ech) h["ech"] = f.ech.trim()
        if (f.pcs != was.pcs) h["pcs"] = f.pcs.trim()
        if (f.vcn != was.vcn) h["vcn"] = f.vcn.trim()
        if (f.hy2Obfs != was.hy2Obfs) h["obfs-password"] = f.hy2Obfs.trim()
        if (f.hy2Ports != was.hy2Ports) h["mport"] = f.hy2Ports.trim()
        h["obfs"] = ""
        val rebuilt = LinkParser.buildHysteria2Outbound(h)
        val st = ob.optJSONObject("streamSettings") ?: JSONObject().also { ob.put("streamSettings", it) }
        val fmWas = st.optJSONObject("finalmask") ?: JSONObject()
        val rs = rebuilt.getJSONObject("streamSettings")
        val keep = JSONArray()
        fmWas.optJSONArray("udp")?.let { a -> for (i in 0 until a.length()) a.optJSONObject(i)?.takeIf { it.optString("type") != "salamander" && it.optString("type") != "udphop" }?.let { keep.put(it) } }
        val qpWas = fmWas.optJSONObject("quicParams")
        if (keep.length() > 0 || (qpWas != null && qpWas.length() > 0)) {
            val fm = rs.optJSONObject("finalmask") ?: JSONObject().also { rs.put("finalmask", it) }
            if (keep.length() > 0) { val u = fm.optJSONArray("udp"); if (u != null) for (i in 0 until u.length()) keep.put(u.get(i)); fm.put("udp", keep) }
            if (qpWas != null) { val merged = JSONObject(qpWas.toString()); fm.optJSONObject("quicParams")?.let { q -> q.keys().forEach { k -> merged.put(k, q.get(k)) } }; fm.put("quicParams", merged) }
        }
        ob.put("settings", rebuilt.getJSONObject("settings"))
        for (k in listOf("network", "security", "tlsSettings", "hysteriaSettings")) st.put(k, rs.get(k))
        if (rs.has("finalmask")) st.put("finalmask", rs.getJSONObject("finalmask")) else st.remove("finalmask")
    }

    /** The same transport, a new path and/or Host. */
    private fun patchTransport(cur: JSONObject, net: String, was: Fields, f: Fields) {
        val path = f.path.trim(); val host = f.host.trim()
        val pathChanged = f.path != was.path; val hostChanged = f.host != was.host
        when (net) {
            "ws" -> {
                val ws = child(cur, "wsSettings")
                if (pathChanged) ws.put("path", path.ifEmpty { "/" })
                if (hostChanged) { val h = child(ws, "headers"); if (host.isEmpty()) h.remove("Host") else h.put("Host", host) }
            }
            "grpc" -> {
                val gs = child(cur, "grpcSettings")
                if (pathChanged) gs.put("serviceName", path)
                if (hostChanged) { if (host.isEmpty()) gs.remove("authority") else gs.put("authority", host) }
            }
            "h2" -> {
                val hs = child(cur, "httpSettings")
                if (pathChanged) hs.put("path", path.ifEmpty { "/" })
                if (hostChanged) hs.put("host", JSONArray(list(host)))
            }
            "xhttp" -> {
                val xs = child(cur, "xhttpSettings")
                if (pathChanged) xs.put("path", path.ifEmpty { "/" })
                if (hostChanged) xs.put("host", host)
            }
            "httpupgrade" -> {
                val hs = child(cur, "httpupgradeSettings")
                if (pathChanged) hs.put("path", path.ifEmpty { "/" })
                if (hostChanged) hs.put("host", host)
            }
            "tcp", "raw" -> {
                val rq = httpHeaderRequest(cur)
                if (rq != null) {
                    if (pathChanged) rq.put("path", JSONArray(list(path).ifEmpty { listOf("/") }))
                    if (hostChanged) {
                        val h = child(rq, "headers")
                        if (list(host).isEmpty()) h.remove("Host") else h.put("Host", JSONArray(list(host)))
                    }
                }
            }
            else -> {}
        }
    }

    /**
     * The WireGuard fields the user changed, into a clone of its settings. False
     * when the record has no settings/peer to patch (then it is rebuilt).
     * `endpoint` is the new host:port, or null when the address did not move.
     */
    private fun patchWireguard(ob: JSONObject, was: Fields, f: Fields, endpoint: String?): Boolean {
        val set = ob.optJSONObject("settings") ?: return false
        val peer = set.optJSONArray("peers")?.optJSONObject(0) ?: return false
        if (endpoint != null) peer.put("endpoint", endpoint)
        if (f.cred != was.cred && f.cred.isNotBlank()) set.put("secretKey", f.cred.trim())
        if (f.wgPub != was.wgPub && f.wgPub.isNotBlank()) peer.put("publicKey", f.wgPub.trim())
        if (f.wgPsk != was.wgPsk) { if (f.wgPsk.isBlank()) peer.remove("preSharedKey") else peer.put("preSharedKey", f.wgPsk.trim()) }
        if (f.wgAllowed != was.wgAllowed) peer.put("allowedIPs", JSONArray(LinkParser.splitCommas(f.wgAllowed).ifEmpty { listOf("0.0.0.0/0", "::/0") }))
        if (f.wgAddr != was.wgAddr) set.put("address", JSONArray(LinkParser.normalizeWgAddresses(LinkParser.splitCommas(f.wgAddr)).ifEmpty { listOf("10.0.0.2/32") }))
        if (f.wgMtu != was.wgMtu) set.put("mtu", f.wgMtu.trim().toIntOrNull() ?: set.optInt("mtu", 1420))
        if (f.wgReserved != was.wgReserved) {
            val r = LinkParser.splitCommas(f.wgReserved).mapNotNull { it.toIntOrNull() }
            if (r.isEmpty()) set.remove("reserved") else set.put("reserved", JSONArray(r))
        }
        return true
    }

    /** The outbound built from the form alone — only for a record too broken to patch. */
    private fun rebuilt(s: ServerConfig, f: Fields, addr: String, port: Int): JSONObject {
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
            else -> JSONObject(s.outbound.toString())
        }
        // carry over xhttp `extra` (padding / post-bytes / method) the builder doesn't model
        f.xhttpExtra?.let { ob.optJSONObject("streamSettings")?.optJSONObject("xhttpSettings")?.put("extra", it) }
        return ob
    }

    /** The form as link parameters. `passthroughs` = the transport extras the form only carries (see Fields). */
    private fun streamQ(f: Fields, passthroughs: Boolean = true): Map<String, String?> = mapOf(
        "type" to f.network, "security" to f.security, "sni" to f.sni, "host" to f.host,
        "path" to f.path, "serviceName" to f.path, "fp" to f.fp, "pbk" to f.pbk, "sid" to f.sid,
        "alpn" to f.alpn, "allowInsecure" to if (f.allowInsecure) "1" else "0",
        "cipherSuites" to f.cipherSuites, "finalMask" to f.finalMask,
        "ech" to f.ech, "pcs" to f.pcs, "vcn" to f.vcn, "pqv" to f.pqv,
        "authority" to if (normNet(f.network) == "grpc") f.host else "",
        // preserved passthroughs (see Fields)
        "spx" to f.spx,
        "mode" to if (passthroughs) f.xmode else "", "seed" to if (passthroughs) f.seed else "",
        "headerType" to if (passthroughs) f.headerType else "")

    private fun vnextUser(ob: JSONObject) = ob.optJSONObject("settings")?.optJSONArray("vnext")?.optJSONObject(0)?.optJSONArray("users")?.optJSONObject(0)
    private fun serverObj(ob: JSONObject) = ob.optJSONObject("settings")?.optJSONArray("servers")?.optJSONObject(0)
    private fun arr(a: JSONArray?): List<String> = if (a == null) emptyList() else (0 until a.length()).map { a.optString(it) }
}
