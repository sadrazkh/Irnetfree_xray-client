package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyFactory
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * MASQUE (Xray 26.9.30+, XTLS/Xray-core #6807 #6810): IP over HTTP/3, or over
 * HTTP/2 when the ALPN says h2 — the Android side of the desktop's MASQUE
 * section of parser.js, serverFields.js masqueHttpOf and jsonImport.js
 * lonelyMasque. The record is the core's own outbound — `settings` { address,
 * port, remoteDNS }, the stream `network: "masque"` over TLS with
 * `masqueSettings` { host, path, user, pass, headers, warp } — so the editor
 * (ServerEditor) writes it field by field. A WARP account (26.10.10+) is
 * `warp` { privateKey, publicKey, address }: the device's P-256 key, the
 * endpoint's public key, the tunnel's addresses — both keys kept as one line
 * of base64 (their DER), as the desktop keeps them.
 *
 * There is no share link for it anywhere: a MASQUE server is shared as the
 * Xray JSON it is ([shareJson]), which JsonImport reads back as this very
 * server ([serverFromOutbound]). Never allowInsecure (the core refuses it with
 * MASQUE), never Mux, never sing-box (EngineChoice). Pure: no android.* here.
 */
object Masque {
    const val PROTOCOL = "masque"

    /**
     * The HTTP version a MASQUE outbound dials, by the core's own rule: HTTP/2
     * over TCP when its ALPN names h2 and not h3, HTTP/3 over QUIC otherwise
     * (no ALPN at all included). [tls] is its tlsSettings.
     */
    fun httpOf(tls: JSONObject?): String {
        val parts = ArrayList<String>()
        when (val raw = tls?.opt("alpn")) {
            is JSONArray -> for (i in 0 until raw.length()) parts.addAll(raw.optString(i).split(","))
            is String -> parts.addAll(raw.split(","))
            else -> {}
        }
        val alpn = parts.map { p: String -> p.trim().lowercase() }
        return if ("h2" in alpn && "h3" !in alpn) "h2" else "h3"
    }

    /** A MASQUE server, a JSON one too (engineChoice.js isMasque). */
    fun isMasque(s: ServerConfig?): Boolean =
        s != null && (s.protocol == PROTOCOL || s.outbound.optString("protocol") == PROTOCOL)

    /** A MASQUE server over HTTP/3: QUIC, no TCP port to probe a certificate on. */
    fun isQuic(s: ServerConfig?): Boolean {
        if (s == null) return false
        if (s.outbound.optString("protocol") != PROTOCOL) return false
        return httpOf(s.outbound.optJSONObject("streamSettings")?.optJSONObject("tlsSettings")) == "h3"
    }

    /** Is it a WARP account (its `masqueSettings.warp`)? The card says so. */
    fun isWarp(s: ServerConfig?): Boolean =
        s?.outbound?.optJSONObject("streamSettings")?.optJSONObject("masqueSettings")?.optJSONObject("warp") != null

    /** The bare outbound a new MASQUE server starts from (parser.js createServer). */
    fun bareOutbound(address: String, port: Int): JSONObject = JSONObject()
        .put("protocol", PROTOCOL)
        .put("settings", JSONObject().put("address", address).put("port", port))
        .put("streamSettings", JSONObject().put("network", PROTOCOL).put("security", "tls")
            .put("tlsSettings", JSONObject()).put("masqueSettings", JSONObject()))

    /** A value as text: absent and JSON null are "" (org.json's optString differs here between the JVM and Android). */
    internal fun text(o: JSONObject?, k: String): String {
        val v = o?.opt(k)
        return if (v == null || v == JSONObject.NULL) "" else v.toString()
    }

    /** `host:port`, an IPv6 host in brackets. */
    internal fun hostPort(host: String, port: Int): String = if (host.contains(':')) "[$host]:$port" else "$host:$port"

    /* ------------------------------ sharing ------------------------------ */

    /**
     * The one-line JSON a MASQUE server is shared as (parser.js buildShareLink):
     * its remarks and its one outbound, tagged `proxy` — without what is this
     * device's own (the table's `local` fields; anti-DPI and the core are the
     * device's choice too). JsonImport reads it back as this very server.
     */
    fun shareJson(s: ServerConfig): String {
        val ob = JSONObject(s.outbound.toString())
        for (fld in ServerFields.PATH_FIELDS) {
            val p = fld.path ?: continue
            if (fld.local && !p.startsWith("@")) ServerFields.setPath(ob, p, null)
        }
        ob.remove("_fragment"); ob.remove("_noise"); ob.remove("tag")
        val out = JSONObject().put("tag", "proxy")
        for (k in ob.keys().asSequence().toList()) out.put(k, ob.get(k))
        return JsonText.minify(JSONObject().put("remarks", s.name).put("outbounds", JSONArray().put(out)))
    }

    /**
     * A MASQUE server from an Xray outbound — a pasted share JSON (JsonImport):
     * the outbound as written, its tag aside, in the record's shape and checked
     * as an edit checks it (parser.js masqueServer). Throws
     * IllegalArgumentException, saying why, when the editor could not hold it.
     */
    fun serverFromOutbound(outbound: JSONObject, name: String): ServerConfig {
        val ob = JSONObject(outbound.toString())
        ob.remove("tag")
        if (ob.optJSONObject("settings") == null) ob.put("settings", JSONObject())
        if (ob.optJSONObject("streamSettings") == null) ob.put("streamSettings", JSONObject())
        val set = ob.getJSONObject("settings")
        val address = text(set, "address").trim()
        val port = text(set, "port").trim().takeWhile { c: Char -> c.isDigit() }.take(6).toIntOrNull() ?: 0
        require(address.isNotEmpty()) { "MASQUE: the server address is empty" }
        require(port in 1..65535) { "MASQUE: the port must be between 1 and 65535" }
        val bare = ServerConfig(id = newId("s"), name = name.trim().ifEmpty { hostPort(address, port) }, protocol = PROTOCOL,
            address = address, port = port, outbound = ob)
        val made = ServerEditor.apply(bare, ServerEditor.read(bare)).copy(edited = emptyList())
        return made.copy(raw = LinkParser.buildShareLink(made))
    }

    /* ------------------------------ what the core refuses ------------------------------ */

    private fun bad(why: String): IllegalArgumentException = IllegalArgumentException(why)

    /** Empty as the desktop's String(v).trim() sees it: absent, null, "", an empty list. */
    private fun blank(v: Any?): Boolean = when (v) {
        null, JSONObject.NULL -> true
        is JSONArray -> v.length() == 0
        else -> v.toString().trim().isEmpty()
    }

    /**
     * Bring a MASQUE outbound to the shape the core takes, or throw saying
     * which field it refuses — what the core would refuse the whole config for,
     * said at the save instead of at a connect (parser.js checkMasque; infra/conf
     * MasqueConfig.Build): a WARP account is all three of its fields or none,
     * and no Basic user and password beside it; a user name has no `:`; the path
     * starts with `/`; the host is a name only; the headers are text, never Host
     * or Capsule-Protocol (nor Authorization beside a user and password);
     * remoteDNS holds IPs. Never allowInsecure, never Mux — and the anti-DPI
     * dialer only where it does anything: a fragment cuts TCP (HTTP/2), noise
     * goes before UDP (HTTP/3). [ob] is changed in place.
     */
    fun check(ob: JSONObject) {
        val st = ob.optJSONObject("streamSettings") ?: JSONObject().also { x: JSONObject -> ob.put("streamSettings", x) }
        val ms = st.optJSONObject("masqueSettings") ?: JSONObject().also { x: JSONObject -> st.put("masqueSettings", x) }
        val tls = st.optJSONObject("tlsSettings") ?: JSONObject().also { x: JSONObject -> st.put("tlsSettings", x) }
        tls.remove("allowInsecure")
        val mux = ob.optJSONObject("mux")
        if (mux != null && mux.optBoolean("enabled")) ob.remove("mux")   // the core refuses the outbound with it
        if (httpOf(tls) == "h2") ob.remove("_noise") else ob.remove("_fragment")

        val warpRaw = ms.opt("warp")
        if (warpRaw != null && warpRaw != JSONObject.NULL) {
            val warp = warpRaw as? JSONObject ?: throw bad("warp: not a WARP account")
            val missing = listOf("privateKey" to "warpPrivateKey", "publicKey" to "warpPublicKey", "address" to "warpAddress")
                .filter { p: Pair<String, String> -> blank(warp.opt(p.first)) }.map { p: Pair<String, String> -> p.second }
            if (missing.isNotEmpty()) {
                throw bad("${missing.joinToString(", ")} ${if (missing.size > 1) "are" else "is"} empty: a WARP account needs its private key, the public key and its addresses together")
            }
            if (text(ms, "user").isNotEmpty() || text(ms, "pass").isNotEmpty()) throw bad("masqueUser: a WARP account takes no user and password")
            val notPrivate = "warpPrivateKey: not a P-256 private key (PEM or base64, PKCS#8 or SEC1)"
            val priv = keyBase64(warp.opt("privateKey")) ?: throw bad(notPrivate)
            if (p256Pkcs8(Base64.getDecoder().decode(priv)) == null) throw bad(notPrivate)
            val notPublic = "warpPublicKey: not a public key (PEM or base64)"
            val pub = keyBase64(warp.opt("publicKey")) ?: throw bad(notPublic)
            if (!isSpki(Base64.getDecoder().decode(pub))) throw bad(notPublic)
            warp.put("privateKey", priv)
            warp.put("publicKey", pub)
            warp.put("address", JSONArray(warpAddresses(warp.opt("address"))))
        }
        if (text(ms, "user").contains(':')) throw bad("masqueUser: a user name cannot contain \":\"")
        val path = text(ms, "path")
        if (path.isNotEmpty() && !path.startsWith("/")) throw bad("masquePath: the path starts with /")
        if (Regex("[\\s/?#@]").containsMatchIn(text(ms, "host"))) throw bad("masqueHost: a host name only (no scheme or path)")
        val headers = ms.opt("headers")
        if (headers != null && headers != JSONObject.NULL) {
            if (headers !is JSONObject) throw bad("masqueHeaders: a JSON object of headers")
            for (k in headers.keys().asSequence().toList()) {
                if (headers.opt(k) !is String) throw bad("masqueHeaders: the value of $k is not text")
                val n = k.lowercase()
                if (n == "host" || n == "capsule-protocol") throw bad("masqueHeaders: $k is the core's own")
                if (n == "authorization" && (text(ms, "user").isNotEmpty() || text(ms, "pass").isNotEmpty())) throw bad("masqueHeaders: Authorization beside a user and password")
            }
        }
        val dns = ob.optJSONObject("settings")?.opt("remoteDNS")
        if (dns != null && dns != JSONObject.NULL) {
            if (dns !is JSONArray) throw bad("remoteDNS: IP addresses only")
            for (i in 0 until dns.length()) if (ipFamily(dns.opt(i)?.toString() ?: "") == 0) throw bad("remoteDNS: IP addresses only")
        }
    }

    /**
     * WARP's tunnel addresses as the core takes them: at most one IPv4 and one
     * IPv6, a bare address made a /32 or /128. Throws naming what it refuses.
     */
    fun warpAddresses(v: Any?): List<String> {
        val items: List<String> = when (v) {
            null, JSONObject.NULL -> emptyList()
            is JSONArray -> (0 until v.length()).map { i: Int -> v.opt(i)?.toString() ?: "" }
            else -> listOf(v.toString())
        }
        val out = ArrayList<String>()
        var v4 = false
        var v6 = false
        for (a in items.map { x: String -> x.trim() }.filter { x: String -> x.isNotEmpty() }) {
            val slash = a.indexOf('/')
            val host = if (slash == -1) a else a.substring(0, slash)
            val fam = ipFamily(host)
            val max = if (fam == 6) 128 else 32
            val suffix = if (slash == -1) "" else a.substring(slash + 1)
            val bits = if (slash == -1) max else (if (Regex("^\\d{1,3}$").matches(suffix)) suffix.toInt() else -1)
            if (fam == 0 || bits < 0 || bits > max) throw bad("warpAddress: \"$a\" is not an IP address")
            if ((fam == 4 && v4) || (fam == 6 && v6)) throw bad("warpAddress: at most one IPv4 and one IPv6 address")
            if (fam == 4) v4 = true else v6 = true
            out.add("$host/$bits")
        }
        return out
    }

    /* ------------------------------ addresses ------------------------------ */

    private val V4 = Regex("^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$")
    private val HEX4 = Regex("^[0-9A-Fa-f]{1,4}$")

    /** 4 for an IPv4 address, 6 for an IPv6 one, 0 for anything else (Node's net.isIP) — never a lookup. */
    fun ipFamily(s: String): Int = when {
        V4.matches(s) -> 4
        isIpv6(s) -> 6
        else -> 0
    }

    private fun isIpv6(s0: String): Boolean {
        if (s0.length < 2 || !s0.contains(':')) return false
        var s = s0
        val lastColon = s.lastIndexOf(':')
        if (s.indexOf('.', lastColon) >= 0) {
            // an IPv4 tail: two groups' worth
            if (!V4.matches(s.substring(lastColon + 1))) return false
            s = s.substring(0, lastColon + 1) + "0:0"
        }
        val dbl = s.indexOf("::")
        if (dbl != s.lastIndexOf("::")) return false
        if (dbl >= 0) {
            val left = s.substring(0, dbl)
            val right = s.substring(dbl + 2)
            val l = if (left.isEmpty()) emptyList() else left.split(":")
            val r = if (right.isEmpty()) emptyList() else right.split(":")
            return (l + r).all { g: String -> HEX4.matches(g) } && l.size + r.size <= 7
        }
        val g = s.split(":")
        return g.size == 8 && g.all { x: String -> HEX4.matches(x) }
    }

    /* ------------------------------ keys ------------------------------ */

    /** P-256's group order: a key on any other curve has another. */
    private val P256_N = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    /** 1.2.840.10045.3.1.7 (prime256v1), as a DER OID. */
    private val P256_OID = byteArrayOf(0x06, 0x08, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x03, 0x01, 0x07)
    /** 1.2.840.10045.2.1 (id-ecPublicKey), as a DER OID. */
    private val EC_OID = byteArrayOf(0x06, 0x07, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x02, 0x01)

    /**
     * A key as the core takes it and a one-line text box keeps it: the base64
     * of its DER. A PEM block — its BEGIN / END lines, perhaps flattened onto
     * one line by an input — and base64 broken over lines both become that.
     * null when it is neither.
     */
    fun keyBase64(v: Any?): String? {
        val s = if (v == null || v == JSONObject.NULL) "" else v.toString()
        val body = s.replace(Regex("-----(BEGIN|END)[^-]*-----"), "").replace(Regex("\\s+"), "")
        if (body.isEmpty() || !Regex("^[A-Za-z0-9+/]+={0,2}$").matches(body)) return null
        val der = try { Base64.getDecoder().decode(body) } catch (e: IllegalArgumentException) { null } ?: return null
        if (der.isEmpty()) return null
        return Base64.getEncoder().encodeToString(der)
    }

    /** `der` as PEM: its label's BEGIN / END lines around base64 in lines of 64. */
    fun pem(der: ByteArray, label: String): String =
        "-----BEGIN $label-----\n" + Base64.getEncoder().encodeToString(der).chunked(64).joinToString("\n") + "\n-----END $label-----\n"

    private fun isP256(params: ECParameterSpec?): Boolean =
        params != null && params.order == P256_N && params.curve.field.fieldSize == 256

    /**
     * The device key as PKCS#8 DER when [der] is a P-256 private key — PKCS#8
     * (as it is) or SEC1 (wrapped into PKCS#8) — the only ones the core reads;
     * null otherwise (another curve, Ed25519 / X25519, not a key at all).
     */
    fun p256Pkcs8(der: ByteArray): ByteArray? {
        try {
            val k = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(der))
            return if (k is ECPrivateKey && isP256(k.params)) der else null
        } catch (e: Exception) {
            // not PKCS#8 of an EC key: SEC1, below
        }
        if (!isSec1P256(der)) return null
        val wrapped = seq(derInt0(), seq(EC_OID, P256_OID), tlv(0x04, der))
        return try {
            val k = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(wrapped))
            if (k is ECPrivateKey && isP256(k.params)) wrapped else null
        } catch (e: Exception) {
            null
        }
    }

    /** The public half of a P-256 key as SPKI DER, when [der] is one (KeyFactory EC). */
    fun isP256Spki(der: ByteArray): Boolean = try {
        val k = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der))
        k is ECPublicKey && isP256(k.params)
    } catch (e: Exception) {
        false
    }

    /**
     * Any public key in PKIX (SPKI) form, as the core checks the endpoint's:
     * SEQUENCE { SEQUENCE { OID … }, BIT STRING }, nothing after it.
     */
    fun isSpki(der: ByteArray): Boolean {
        val outer = readTlv(der, 0, der.size) ?: return false
        if (outer.tag != 0x30 || outer.next != der.size) return false
        val alg = readTlv(der, outer.start, outer.end) ?: return false
        if (alg.tag != 0x30) return false
        val oid = readTlv(der, alg.start, alg.end) ?: return false
        if (oid.tag != 0x06 || oid.end == oid.start) return false
        val bits = readTlv(der, alg.next, outer.end) ?: return false
        return bits.tag == 0x03 && bits.next == outer.end && bits.end - bits.start >= 2
    }

    /**
     * A SEC1 ECPrivateKey of P-256: version 1, a scalar of at most 32 bytes in
     * range, and — when it names its curve — prime256v1.
     */
    private fun isSec1P256(der: ByteArray): Boolean {
        val seq = readTlv(der, 0, der.size) ?: return false
        if (seq.tag != 0x30 || seq.next != der.size) return false
        val ver = readTlv(der, seq.start, seq.end) ?: return false
        if (ver.tag != 0x02 || ver.end - ver.start != 1 || der[ver.start].toInt() != 1) return false
        val key = readTlv(der, ver.next, seq.end) ?: return false
        if (key.tag != 0x04 || key.end - key.start !in 1..32) return false
        var at = key.next
        while (at < seq.end) {
            val t = readTlv(der, at, seq.end) ?: return false
            if (t.tag == 0xA0 && !der.copyOfRange(t.start, t.end).contentEquals(P256_OID)) return false
            at = t.next
        }
        val d = BigInteger(1, der.copyOfRange(key.start, key.end))
        return d.signum() > 0 && d < P256_N
    }

    /** The SEC1 ECPrivateKey inside a PKCS#8 one (its OCTET STRING), or null. For scrubbing a key out of text. */
    internal fun sec1Of(pkcs8: ByteArray): ByteArray? {
        val seq = readTlv(pkcs8, 0, pkcs8.size) ?: return null
        if (seq.tag != 0x30) return null
        val ver = readTlv(pkcs8, seq.start, seq.end) ?: return null
        val alg = readTlv(pkcs8, ver.next, seq.end) ?: return null
        val inner = readTlv(pkcs8, alg.next, seq.end) ?: return null
        return if (inner.tag == 0x04) pkcs8.copyOfRange(inner.start, inner.end) else null
    }

    /* ------------------------------ a little DER ------------------------------ */

    /** One DER element: its tag, its contents [start, end), and where the next one starts. */
    internal class Tlv(val tag: Int, val start: Int, val end: Int) { val next: Int get() = end }

    /** The element at [at], within [limit]; null when it is not a whole one (definite lengths only). */
    internal fun readTlv(b: ByteArray, at: Int, limit: Int): Tlv? {
        if (at < 0 || at + 2 > limit || limit > b.size) return null
        val tag = b[at].toInt() and 0xFF
        val first = b[at + 1].toInt() and 0xFF
        var pos = at + 2
        val len: Int
        if (first < 0x80) {
            len = first
        } else {
            val n = first and 0x7F
            if (n == 0 || n > 3 || pos + n > limit) return null
            var l = 0
            for (i in 0 until n) l = (l shl 8) or (b[pos + i].toInt() and 0xFF)
            pos += n
            len = l
        }
        if (len < 0 || pos + len > limit) return null
        return Tlv(tag, pos, pos + len)
    }

    private fun tlv(tag: Int, body: ByteArray): ByteArray {
        val n = body.size
        val len: ByteArray = when {
            n < 0x80 -> byteArrayOf(n.toByte())
            n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
            else -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
        }
        return byteArrayOf(tag.toByte()) + len + body
    }

    private fun seq(vararg parts: ByteArray): ByteArray {
        var body = ByteArray(0)
        for (p in parts) body += p
        return tlv(0x30, body)
    }

    private fun derInt0(): ByteArray = byteArrayOf(0x02, 0x01, 0x00)
}
