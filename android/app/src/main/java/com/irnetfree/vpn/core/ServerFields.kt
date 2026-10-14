package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * One field of the server editor (ServerFieldsTable, generated from the
 * desktop's src/renderer/serverFields.js — see that file for what each part
 * means). `path` is a dotted path into the outbound, or `@name` into the record.
 */
data class SfField(
    val id: String, val tab: String, val kind: String, val path: String?, val special: Boolean, val key: String,
    val protocols: List<String>?, val networks: List<String>?, val securities: List<String>?,
    val local: Boolean, val simple: Boolean, val span2: Boolean, val group: String?,
    val options: List<String>, val optionLabels: String, val emptyAs: Any?, val hint: Boolean, val placeholder: String
)

/**
 * The server editor's table and its generic read / write — serverFields.js on
 * the phone. ServerEditor reads and writes the path fields through it; the edit
 * sheet's Pro view draws the fields from it.
 */
object ServerFields {
    val FIELDS: List<SfField> get() = ServerFieldsTable.FIELDS
    val PATH_FIELDS: List<SfField> by lazy { ServerFieldsTable.FIELDS.filter { f: SfField -> f.path != null } }
    val TABS = listOf("basics", "protocol", "transport", "security", "advanced")
    val PROTOCOLS = listOf("vless", "vmess", "trojan", "shadowsocks", "hysteria2", "masque", "wireguard", "socks", "http")
    val NETWORKS = listOf("tcp", "ws", "grpc", "httpupgrade", "xhttp", "kcp")
    val SS_METHODS = listOf("2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
        "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "none")
    private val STREAM = listOf("vless", "vmess", "trojan", "shadowsocks")

    fun field(id: String): SfField? = ServerFieldsTable.FIELDS.firstOrNull { f: SfField -> f.id == id }

    /** An English string of the editor, by its i18n key (the key itself when there is none). */
    fun str(key: String): String = ServerFieldsTable.STRINGS[key] ?: key

    fun hasTransport(protocol: String): Boolean = protocol in STREAM

    fun securitiesOf(protocol: String): List<String> = when (protocol) {
        "vless", "trojan" -> listOf("none", "tls", "reality")
        "vmess", "shadowsocks" -> listOf("none", "tls")
        "hysteria2", "masque" -> listOf("tls")
        else -> emptyList()
    }

    /** Hysteria2 and MASQUE speak TLS and nothing else, whatever a hand-written stream says. */
    fun tlsOnly(protocol: String): Boolean = protocol == "hysteria2" || protocol == "masque"

    /** The HTTP version a MASQUE outbound dials (serverFields.js masqueHttpOf): "h2" or "h3". */
    fun masqueHttpOf(tls: JSONObject?): String = Masque.httpOf(tls)

    data class Ctx(val protocol: String, val network: String, val security: String)

    /** A protocol and an outbound's stream, in the table's terms. */
    fun contextOf(protocol: String, outbound: JSONObject): Ctx {
        val st = outbound.optJSONObject("streamSettings") ?: JSONObject()
        val n0 = when (val n = st.optString("network", "tcp").lowercase().ifEmpty { "tcp" }) { "raw" -> "tcp"; "splithttp" -> "xhttp"; "mkcp" -> "kcp"; else -> n }
        // MASQUE's transport is its own, whatever a hand-written stream says
        val net = if (protocol == "masque") "masque" else n0
        val p = if (protocol == "hysteria") "hysteria2" else protocol
        return Ctx(p, net, st.optString("security", "none").lowercase().ifEmpty { "none" })
    }

    fun contextOf(s: ServerConfig): Ctx = contextOf(s.protocol, s.outbound)

    /** Does the field belong to this protocol / transport / security? */
    fun applies(f: SfField, c: Ctx): Boolean {
        val ps = f.protocols
        if (ps != null && c.protocol !in ps) return false
        val ns = f.networks
        if (ns != null && !(hasTransport(c.protocol) && c.network in ns)) return false
        val ss = f.securities
        if (ss != null) {
            val sec = if (tlsOnly(c.protocol)) "tls" else c.security
            if (sec !in ss) return false
        }
        return true
    }

    private fun step(k: String): Int? = if (k.all { ch: Char -> ch.isDigit() }) k.toInt() else null

    /** The value at a dotted path of an outbound (numbers index arrays); null when it is not there. */
    fun getPath(outbound: JSONObject, path: String): Any? {
        var cur: Any? = outbound
        for (k in path.split(".")) {
            val i = step(k)
            cur = when {
                cur is JSONArray && i != null -> if (i < cur.length()) cur.opt(i) else null
                cur is JSONObject && i == null -> if (cur.has(k) && !cur.isNull(k)) cur.opt(k) else null
                else -> null
            }
            if (cur == null) return null
        }
        return cur
    }

    /** The record-level ones (`@mux` …): [ServerConfig]'s own fields. */
    fun getRecord(s: ServerConfig, name: String): Any? = when (name) {
        "mux" -> s.mux.ifEmpty { null }
        "muxConcurrency" -> s.muxConcurrency
        "xudpConcurrency" -> s.xudpConcurrency
        else -> null
    }

    /** A field's stored value: from the outbound, or from the record for `@` paths. */
    fun get(s: ServerConfig, f: SfField): Any? {
        val p = f.path ?: return null
        return if (p.startsWith("@")) getRecord(s, p.substring(1)) else getPath(s.outbound, p)
    }

    /**
     * Write [value] at a dotted path of [outbound], making the objects (and the
     * arrays, for a numeric step) on the way; null deletes the key, and an object
     * it leaves empty three or more steps down goes too (serverFields.js setPath).
     */
    fun setPath(outbound: JSONObject, path: String, value: Any?) {
        val ks = path.split(".")
        val trail = ArrayList<Any>()
        trail.add(outbound)
        var cur: Any = outbound
        for (n in 0 until ks.size - 1) {
            val k = ks[n]
            val nextIsIndex = step(ks[n + 1]) != null
            val i = step(k)
            val next: Any? = when {
                cur is JSONObject && i == null -> cur.opt(k)
                cur is JSONArray && i != null -> if (i < cur.length()) cur.opt(i) else null
                else -> return
            }
            val child: Any = when (next) {
                is JSONObject -> next
                is JSONArray -> next
                else -> {
                    if (value == null) return
                    val made: Any = if (nextIsIndex) JSONArray() else JSONObject()
                    val parent = cur
                    if (parent is JSONObject) parent.put(k, made)
                    if (parent is JSONArray && i != null) parent.put(i, made)
                    made
                }
            }
            cur = child
            trail.add(cur)
        }
        val leaf = ks[ks.size - 1]
        val li = step(leaf)
        if (value != null) {
            if (cur is JSONObject && li == null) cur.put(leaf, value) else if (cur is JSONArray && li != null) cur.put(li, value)
            return
        }
        if (cur is JSONObject && li == null) cur.remove(leaf) else if (cur is JSONArray && li != null && li < cur.length()) cur.remove(li)
        var n = trail.size - 1
        while (n >= 3) {
            val node = trail[n]
            if (node is JSONObject && node.length() == 0) {
                val parent = trail[n - 1]
                if (parent is JSONObject) parent.remove(ks[n - 1])
                n--
            } else break
        }
    }

    /** A stored value as the form shows it: text, "true" / "" for a switch. */
    fun toForm(f: SfField, raw: Any?): String {
        if (f.kind == "switch") return if (raw == true || raw == "true") "true" else ""
        if (raw == null) return ""
        if (f.kind == "list" || f.kind == "chips") return if (raw is JSONArray) (0 until raw.length()).joinToString(", ") { i: Int -> raw.optString(i) } else raw.toString()
        return raw.toString()
    }

    /** What the form's text is written as; null deletes the key (or [SfField.emptyAs]). */
    fun fromForm(f: SfField, v: String): Any? {
        if (f.kind == "switch") return if (v == "true") true else null
        val s = v.trim()
        if (s.isEmpty()) return f.emptyAs
        return when (f.kind) {
            "number" -> s.toLongOrNull()?.let { n: Long -> if (n <= Int.MAX_VALUE.toLong() && n >= Int.MIN_VALUE.toLong()) n.toInt() else n } ?: s
            "range" -> if (s.all { ch: Char -> ch.isDigit() }) s.toInt() else s
            "json" -> try { JSONObject(s) } catch (e: Exception) { s }
            "list", "chips" -> {
                val a = s.split(Regex("[,\\s]+")).map { x: String -> x.trim() }.filter { x: String -> x.isNotEmpty() }
                if (a.isEmpty()) f.emptyAs else JSONArray(a)
            }
            else -> s
        }
    }

    /** Why the form's text cannot be written (an i18n key), or null. */
    fun validate(f: SfField, v: String): String? {
        if (f.kind == "switch") return null
        val s = v.trim()
        if (s.isEmpty()) return null
        if (f.kind == "number" && !Regex("^\\d+$").matches(s)) return "edit.err.number"
        if (f.kind == "range" && !Regex("^\\d+(-\\d+)?$").matches(s)) return "edit.err.range"
        if (f.kind == "json") {
            val ok = try { JSONObject(s); true } catch (e: Exception) { false }
            if (!ok) return "edit.err.json"
        }
        if (f.kind == "encryption") { val r = readEncryption(s); if (r != null && r.bad != null) return r.bad }
        return null
    }

    /** VLESS Encryption read back (serverFields.js readEncryption): its auth, mode and RTT — or why it is not one. */
    data class Enc(val auth: String = "", val mode: String = "", val rtt: String = "", val padded: Boolean = false, val bad: String? = null)

    fun readEncryption(v: String): Enc? {
        val s = v.trim()
        if (s.isEmpty() || s == "none") return null
        val p = s.split(".")
        if (p[0] != "mlkem768x25519plus") return Enc(bad = "edit.err.encPrefix")
        if (p.size < 2 || p[1] !in listOf("native", "xorpub", "random")) return Enc(bad = "edit.err.encMode")
        if (p.size < 3 || p[2] !in listOf("0rtt", "1rtt")) return Enc(bad = "edit.err.encRtt")
        val rest = p.drop(3)
        val key = rest.lastOrNull() ?: ""
        val part = Regex("^[A-Za-z0-9_-]+$")
        if (!Regex("^[A-Za-z0-9_-]{40,}$").matches(key) || rest.any { x: String -> !part.matches(x) }) return Enc(bad = "edit.err.encKey")
        return Enc(auth = if (key.length > 200) "ML-KEM-768" else "X25519", mode = p[1], rtt = p[2], padded = rest.size > 1)
    }
}
