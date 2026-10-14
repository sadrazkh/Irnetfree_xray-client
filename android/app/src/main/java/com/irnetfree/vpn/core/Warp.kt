package com.irnetfree.vpn.core

import okhttp3.ConnectionSpec
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.TlsVersion
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.InterruptedIOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.SocketTimeoutException
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Cloudflare WARP on MASQUE — the Android side of the desktop's
 * src/main/warp.js, step for step: a WARP device registered from the app, or
 * one brought in from usque's config.json or a pasted Xray WARP outbound, and
 * one MASQUE server per HTTP version (ServerEditor.create).
 *
 *   registerWarp(request, license, now, log)  → Reg
 *   importWarp(text)                          → Reg
 *   warpServers(reg, options)                 → the editor's fields, one map per server (pure)
 *   addWarpOnce(args, deps)                   → the WARP sheet's whole job, one at a time
 *
 * The device key is made HERE (P-256) and never leaves the phone except to the
 * core; Cloudflare gets its public half. The API token is used for the calls of
 * one registration and then dropped. Neither is ever logged, nor put in an
 * error: whatever Cloudflare says back is scrubbed of both ([scrub]).
 *
 * The transport is injectable ([Req] → [Res]); the real one is OkHttp with the
 * ClientHello below ([okHttpTransport]) — straight out, or through the
 * running tunnel's own SOCKS inbound (its port and per-session credentials,
 * which java.net's SOCKS client gets from LocalProxyAuth, as SubFetch's
 * subscription fetch does). The app's own package is outside the VPN, so
 * "direct" really is the phone's own network even while connected.
 */
object Warp {
    /* --------------------------------- the API --------------------------------- */
    // The API as the official Android client 6.38.9 speaks it — wgcf 2.3.0's
    // values, the release that got past the 429s on POST /reg: that refusal
    // follows the TLS ClientHello (wgcf #613/#626), and a TLS 1.2 hello with
    // ALPN http/1.1 is the shape that got through. One place, so the next
    // client version is one edit (warp.js API).
    const val HOST = "api.cloudflareclient.com"
    const val API_VERSION = "v0a5641"
    const val CLIENT_VERSION = "a-6.38.9-5641"
    const val USER_AGENT = "1.1.1.1/6.38.9-5641 (Android 16.0.0)"
    const val CONTENT_TYPE = "application/json; charset=UTF-8"
    const val TIMEOUT_MS = 20_000L
    const val MAX_ANSWER = 512 * 1024

    /** Cloudflare's MASQUE edges when a record names none: H3 from the record, H2 the fixed .2 pair (.1 is a plain CDN edge on TCP). */
    val DEFAULT_ENDPOINTS: Map<String, String> = linkedMapOf(
        "h3v4" to "162.159.198.1", "h3v6" to "2606:4700:103::1", "h2v4" to "162.159.198.2", "h2v6" to "2606:4700:103::2")
    /** The name the official client sends; a cover domain replaces it. */
    const val WARP_SNI = "consumer-masque.cloudflareclient.com"
    /** Anti-DPI per HTTP version: the lightest noise preset for QUIC, the app's Hide-SNI fragment for TCP. */
    const val ANTI_DPI_NOISE = "random"
    const val ANTI_DPI_FRAGMENT = "tlshello,100-200,10-20"
    /** A WARP+ key: three groups of eight. */
    private val LICENSE_RE = Regex("^[A-Za-z0-9]{8}-[A-Za-z0-9]{8}-[A-Za-z0-9]{8}$")
    /** A domain name with a dot and a non-numeric last label (so no IP passes for one). */
    private val HOST_RE = Regex("^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$", RegexOption.IGNORE_CASE)

    /** The codes a refusal carries (the desktop's warp.err.*). */
    val ERROR_CODES = listOf("rateLimited", "blocked", "rejected", "notConnected", "badLicense", "badAnswer", "badImport",
        "badCover", "badAddress", "busy", "createFailed", "failed")
    val WARNING_CODES = listOf("warpNotEnabled", "licenseFailed")

    /** What the sheet says for each code — the desktop's English (i18n.js warp.err.* / warp.warn.*); {msg} is the detail. */
    private val MESSAGES: Map<String, String> = mapOf(
        "rateLimited" to "Cloudflare is not taking new sign-ups right now (429, too many requests). Try again in a few minutes, or choose “Through the app’s connection”.",
        "blocked" to "Could not reach the WARP sign-up server (api.cloudflareclient.com) — it is probably blocked on this network ({msg}). Connect to a server first and choose “Through the app’s connection”.",
        "rejected" to "Cloudflare refused the request: {msg}",
        "notConnected" to "To sign up through the app’s connection, connect to a server first.",
        "badLicense" to "That is not a WARP+ key — it looks like xxxxxxxx-xxxxxxxx-xxxxxxxx.",
        "badAnswer" to "Cloudflare’s answer could not be used ({msg}). Try again a little later.",
        "badImport" to "This is not a WARP account ({msg}). Paste usque’s config.json or an Xray WARP outbound.",
        "badCover" to "The cover domain must be just a domain name, like www.example.com.",
        "badAddress" to "The endpoint IP or domain could not be read — like 162.159.198.2 or 162.159.198.2:443.",
        "busy" to "A WARP sign-up is already running; wait for it to finish.",
        "createFailed" to "The account is ready but the servers could not be made: {msg}",
        "failed" to "WARP could not be added: {msg}",
        "warn.warpNotEnabled" to "Cloudflare did not switch WARP on for this device. If the servers do not connect (“access denied”), make a new account.",
        "warn.licenseFailed" to "The WARP+ key was not applied ({msg}); a free account was made."
    )

    /** A refusal in the sheet's words. */
    fun messageFor(code: String, detail: String): String = (MESSAGES[code] ?: MESSAGES.getValue("failed")).replace("{msg}", detail)

    /** A warning in the sheet's words. */
    fun warningText(w: Warning): String = (MESSAGES["warn." + w.code] ?: w.message).replace("{msg}", w.message)

    /** A refusal: its [code] (one of [ERROR_CODES]) and, in [detail], Cloudflare's own words, already scrubbed. */
    class WarpError(val code: String, message: String, val detail: String? = null) : Exception(message)

    /** One API request. Its text never shows the headers (the token is one). */
    class Req(val method: String, val path: String, val headers: Map<String, String>, val body: String?) {
        override fun toString(): String = "$method $path"
    }

    class Res(val status: Int, val body: String)

    data class Account(val id: String, val type: String, val warpPlus: Boolean)

    data class Warning(val code: String, val message: String, val cause: String? = null)

    /**
     * A WARP device: its P-256 key (PKCS#8 PEM), the edge's key (PEM), its
     * addresses [v4/32, v6/128], the edges (h3v4, h3v6, h2v4, h2v6), the
     * account and any warnings. Its text never shows the private key.
     */
    class Reg(
        val privateKey: String, val publicKey: String, val address: List<String>,
        val endpoints: Map<String, String>, val account: Account, val warnings: List<Warning>
    ) {
        override fun toString(): String = "Reg(address=$address, endpoints=$endpoints, account=$account)"
    }

    /* --------------------------------- helpers --------------------------------- */

    private fun str(v: Any?): String = if (v == null || v == JSONObject.NULL) "" else v.toString().trim()

    private fun pemBody(pem: String): String = pem.replace(Regex("-----[^-]+-----"), "").replace(Regex("\\s+"), "")

    /** [text] with every secret cut out (an answer that repeats the token, say). */
    fun scrub(text: String?, secrets: List<String>): String {
        var s = text ?: ""
        for (secret in secrets) {
            val v = secret.trim()
            if (v.length < 8) continue
            s = s.replace(v, "…")
        }
        return s
    }

    /** A failure on the way to the API, in the sheet's terms. */
    private fun netError(e: Throwable): WarpError {
        if (e is WarpError) return e
        val why = e.message?.takeIf { m: String -> m.isNotBlank() } ?: e.javaClass.simpleName
        return WarpError("blocked", "Could not reach $HOST: $why", why)
    }

    private val ISO: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC)
    private val rng = SecureRandom()

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { b: Byte -> "%02x".format(b.toInt() and 0xFF) }

    /**
     * usque's registration body: a throwaway key — 32 random bytes, which is
     * all an X25519 public key is on the wire, and the MASQUE key replaces it
     * at once —, `tos` the moment the user accepted the terms (pressing Create
     * is that), a random 16-hex serial.
     */
    internal fun regBody(now: Long): JSONObject {
        val key = ByteArray(32).also { b: ByteArray -> rng.nextBytes(b) }
        val serial = ByteArray(8).also { b: ByteArray -> rng.nextBytes(b) }
        return JSONObject()
            .put("key", Base64.getEncoder().encodeToString(key))
            .put("install_id", "")
            .put("fcm_token", "")
            .put("tos", ISO.format(Instant.ofEpochMilli(now)))
            .put("model", "PC")
            .put("serial_number", hex(serial))
            .put("os_version", "")
            .put("key_type", "curve25519")
            .put("tunnel_type", "wireguard")
            .put("locale", "en_US")
    }

    /** encodeURIComponent. */
    private fun uriComponent(s: String): String {
        val sb = StringBuilder()
        for (b in s.toByteArray(Charsets.UTF_8)) {
            val c = b.toInt() and 0xFF
            val ch = c.toChar()
            val plain = (ch in 'A'..'Z') || (ch in 'a'..'z') || (ch in '0'..'9') || "-_.!~*'()".indexOf(ch) >= 0
            if (plain) sb.append(ch) else sb.append('%').append("%02X".format(c))
        }
        return sb.toString()
    }

    /** What Cloudflare said in a refusal: its `errors[].message`, else a short line of plain text (an HTML page says nothing useful). */
    private fun cfMessage(json: JSONObject?, text: String): String {
        if (json != null) {
            val errs = json.optJSONArray("errors")
            if (errs != null && errs.length() > 0) {
                val parts = ArrayList<String>()
                for (i in 0 until errs.length()) {
                    val e = errs.opt(i)
                    val m = if (e is JSONObject) str(e.opt("message")) else str(e)
                    if (m.isNotEmpty()) parts.add(m)
                }
                if (parts.isNotEmpty()) return parts.joinToString("; ").take(300)
            }
            val msg = json.opt("message")
            if (msg is String && msg.isNotBlank()) return msg.trim().take(300)
            val err = json.opt("error")
            if (err is String && err.isNotBlank()) return err.trim().take(300)
            if (err is JSONObject && str(err.opt("message")).isNotEmpty()) return str(err.opt("message")).take(300)
        }
        val t = text.trim()
        if (t.isEmpty() || t.startsWith("<")) return ""
        return t.replace(Regex("\\s+"), " ").take(200)
    }

    /** One API call: the headers, the version prefix, the status mapped. The answer's JSON object. */
    private fun call(request: (Req) -> Res, method: String, path: String, token: String?, body: JSONObject?, step: String, secrets: List<String>): JSONObject {
        val headers = LinkedHashMap<String, String>()
        headers["User-Agent"] = USER_AGENT
        headers["CF-Client-Version"] = CLIENT_VERSION
        headers["Accept"] = "application/json"
        headers["Accept-Encoding"] = "identity"
        if (body != null) headers["Content-Type"] = CONTENT_TYPE
        if (token != null) headers["Authorization"] = "Bearer $token"
        val res: Res = try {
            request(Req(method, "/$API_VERSION$path", headers, body?.let { b: JSONObject -> JsonText.minify(b) }))
        } catch (e: Exception) {
            val err = netError(e)
            throw WarpError(err.code, scrub(err.message, secrets), err.detail?.let { d: String -> scrub(d, secrets) })
        }
        val status = res.status
        val text = res.body
        val json: JSONObject? = try { JSONTokener(text).nextValue() as? JSONObject } catch (e: Exception) { null }
        if (status == 429) throw WarpError("rateLimited", "Cloudflare answered 429 (too many requests) to the $step")
        if (status < 200 || status > 299) {
            val detail = scrub(cfMessage(json, text), secrets)
            val shown = if (status == 0) "no status" else status.toString()
            throw WarpError("rejected", "Cloudflare refused the $step ($shown)" + (if (detail.isNotEmpty()) ": $detail" else ""), detail.ifEmpty { null })
        }
        return json ?: throw WarpError("badAnswer", "Cloudflare's answer to the $step is not JSON")
    }

    /* ------------------------------ keys, addresses, endpoints ------------------------------ */

    /** A P-256 private key (PEM or base64, PKCS#8 or SEC1) as PKCS#8 PEM; null when it is not one. */
    private fun privatePem(v: Any?): String? {
        val b64 = Masque.keyBase64(v) ?: return null
        val der = Masque.p256Pkcs8(Base64.getDecoder().decode(b64)) ?: return null
        return Masque.pem(der, "PRIVATE KEY")
    }

    /** The edge's P-256 public key (PEM or base64 SPKI) as PEM; null when it is not one. */
    private fun publicPem(v: Any?): String? {
        val b64 = Masque.keyBase64(v) ?: return null
        val der = Base64.getDecoder().decode(b64)
        return if (Masque.isP256Spki(der)) Masque.pem(der, "PUBLIC KEY") else null
    }

    /** The device's addresses: at most one v4 (/32 unless given) and one v6 (/128); null when one is not an address. */
    private fun addressList(values: List<Any?>): List<String>? {
        var v4: String? = null
        var v6: String? = null
        for (v in values) {
            val s = str(v)
            if (s.isEmpty()) continue
            val parts = s.split("/")
            val ip = parts[0]
            val prefix = parts.getOrNull(1)
            val fam = Masque.ipFamily(ip)
            if (fam == 0) return null
            val max = if (fam == 4) 32 else 128
            if (prefix != null && !(Regex("^\\d{1,3}$").matches(prefix) && prefix.toInt() <= max)) return null
            val a = "$ip/${prefix ?: max}"
            if (fam == 4 && v4 == null) v4 = a
            if (fam == 6 && v6 == null) v6 = a
        }
        return listOfNotNull(v4, v6)
    }

    /** `162.159.198.1:0`, `[2606:4700:103::1]:0` or a bare IP → the IP, when it is of [family]; else "". */
    private fun hostOf(value: Any?, family: Int): String {
        var s = str(value)
        if (s.isEmpty()) return ""
        if (s.startsWith("[")) {
            val end = s.indexOf(']')
            s = if (end > 0) s.substring(1, end) else ""
        } else if (Masque.ipFamily(s) != 6) {
            val i = s.lastIndexOf(':')
            if (i > -1 && s.indexOf(':') == i) s = s.substring(0, i)
        }
        return if (Masque.ipFamily(s) == family) s else ""
    }

    private class Mapped(val publicKey: String, val address: List<String>, val endpoints: Map<String, String>)

    /** A device record (the enroll, activation or GET answer) → the registration's key, addresses, endpoints. */
    private fun fromRecord(rec: JSONObject): Mapped {
        val cfg = rec.optJSONObject("config") ?: JSONObject()
        val peer = cfg.optJSONArray("peers")?.optJSONObject(0)
            ?: throw WarpError("badAnswer", "Cloudflare's device record has no endpoint (config.peers is empty)")
        val publicKey = publicPem(peer.opt("public_key"))
            ?: throw WarpError("badAnswer", "Cloudflare's device record has no readable endpoint key (config.peers[0].public_key)")
        val a = cfg.optJSONObject("interface")?.optJSONObject("addresses") ?: JSONObject()
        val address = addressList(listOf(a.opt("v4"), a.opt("v6")))?.takeIf { x: List<String> -> x.isNotEmpty() }
            ?: throw WarpError("badAnswer", "Cloudflare's device record has no usable address (config.interface.addresses)")
        val ep = peer.optJSONObject("endpoint") ?: JSONObject()
        val endpoints = linkedMapOf(
            "h3v4" to hostOf(ep.opt("v4"), 4).ifEmpty { DEFAULT_ENDPOINTS.getValue("h3v4") },
            "h3v6" to hostOf(ep.opt("v6"), 6).ifEmpty { DEFAULT_ENDPOINTS.getValue("h3v6") },
            "h2v4" to DEFAULT_ENDPOINTS.getValue("h2v4"),
            "h2v6" to DEFAULT_ENDPOINTS.getValue("h2v6"))
        return Mapped(publicKey, address, endpoints)
    }

    private fun peersOf(rec: JSONObject): Int = rec.optJSONObject("config")?.optJSONArray("peers")?.length() ?: 0

    /* --------------------------------- registering --------------------------------- */

    /**
     * A new WARP device for MASQUE (design §5, warp.js registerWarp):
     *   1. a P-256 key pair, made here;
     *   2. POST /reg (usque's body) → the device id and its token;
     *   3. PATCH /reg/{id} { key: base64 SPKI, key_type secp256r1, tunnel_type masque };
     *   4. when the answer does not say warp_enabled: PATCH { warp_enabled: true }, and
     *      check it — a device left off is refused by the edge ("tls: access denied");
     *      an answer without peers is no failure (the key IS enrolled): GET the record;
     *   5. with a WARP+ license: PUT /reg/{id}/account { license };
     *   6. the record → the edge key, the addresses, the endpoints.
     * A device that stays off and a license Cloudflare refuses are warnings: the
     * device exists by then, and a free account beats none (another try costs a
     * registration, and those are rate-limited). Blocking — run it off the main thread.
     */
    fun registerWarp(
        request: (Req) -> Res,
        license: String = "",
        now: () -> Long = { System.currentTimeMillis() },
        log: (String, String) -> Unit = { _: String, _: String -> }
    ): Reg {
        val lic = license.trim()
        if (lic.isNotEmpty() && !LICENSE_RE.matches(lic)) throw WarpError("badLicense", "A WARP+ license looks like xxxxxxxx-xxxxxxxx-xxxxxxxx")
        val secrets = ArrayList<String>()
        fun say(line: String, level: String) {
            try { log(scrub(line, secrets), level) } catch (e: Exception) { /* a log never fails a sign-up */ }
        }

        val gen = KeyPairGenerator.getInstance("EC")
        gen.initialize(ECGenParameterSpec("secp256r1"))
        val pair = gen.generateKeyPair()
        val pkcs8 = pair.private.encoded
        val privateKey = Masque.pem(pkcs8, "PRIVATE KEY")
        secrets.add(privateKey)
        secrets.add(Base64.getEncoder().encodeToString(pkcs8))
        Masque.sec1Of(pkcs8)?.let { b: ByteArray -> secrets.add(Base64.getEncoder().encodeToString(b)) }
        val enrollKey = Base64.getEncoder().encodeToString(pair.public.encoded)

        say("WARP: registering a new device with Cloudflare…", "info")
        val made = call(request, "POST", "/reg", null, regBody(now()), "registration", secrets)
        val id = str(made.opt("id"))
        val token = str(made.opt("token"))
        if (id.isEmpty() || token.isEmpty()) throw WarpError("badAnswer", "Cloudflare's registration answer has no device id or token")
        secrets.add(token)
        val dev = "/reg/" + uriComponent(id)
        say("WARP: device $id registered", "info")

        val enroll = JSONObject().put("key", enrollKey).put("key_type", "secp256r1").put("tunnel_type", "masque")
        var rec = call(request, "PATCH", dev, token, enroll, "MASQUE key enrollment", secrets)
        say("WARP: the device's MASQUE key (secp256r1) is enrolled", "info")

        val warnings = ArrayList<Warning>()
        if (rec.opt("warp_enabled") != true) {
            val on = call(request, "PATCH", dev, token, JSONObject().put("warp_enabled", true), "activation (warp_enabled)", secrets)
            if (on.opt("warp_enabled") == true) {
                rec = if (peersOf(on) > 0) on else JSONObject(rec.toString()).put("warp_enabled", true)
                say("WARP: switched on for the device (warp_enabled)", "info")
            } else {
                warnings.add(Warning("warpNotEnabled", "Cloudflare still reports warp_enabled: false for this device; the edge may answer \"access denied\""))
                say("WARP: Cloudflare did not switch the device on (warp_enabled stays false) — the edge may refuse it", "warn")
            }
        }
        if (peersOf(rec) == 0) {
            say("WARP: the answer names no endpoint — reading the device record", "info")
            val got = call(request, "GET", dev, token, null, "device record", secrets)
            val enabled = rec.opt("warp_enabled") == true || got.opt("warp_enabled") == true
            rec = JSONObject(got.toString()).put("warp_enabled", enabled)
        }

        var account: JSONObject = rec.optJSONObject("account") ?: made.optJSONObject("account") ?: JSONObject()
        if (lic.isNotEmpty()) {
            try {
                val acc = call(request, "PUT", "$dev/account", token, JSONObject().put("license", lic), "WARP+ license", secrets)
                val merged = JSONObject(account.toString())
                for (k in acc.keys().asSequence().toList()) merged.put(k, acc.get(k))
                account = merged
                say("WARP: the WARP+ license is applied (account ${str(acc.opt("account_type")).ifEmpty { "updated" }})", "info")
            } catch (e: WarpError) {
                val why = scrub(e.detail?.takeIf { d: String -> d.isNotEmpty() } ?: e.message, secrets)
                warnings.add(Warning("licenseFailed", why, e.code))
                say("WARP: the WARP+ license was not applied — $why", "warn")
            }
        }

        val mapped = fromRecord(rec)
        say("WARP: the device's addresses ${mapped.address.joinToString(", ")}; HTTP/3 edge ${mapped.endpoints["h3v4"]}", "info")
        return Reg(privateKey, mapped.publicKey, mapped.address, mapped.endpoints,
            Account(id, str(account.opt("account_type")), account.opt("warp_plus") == true), warnings)
    }

    /* ---------------------------------- importing ---------------------------------- */

    private fun badImport(why: String): WarpError = WarpError("badImport", why)

    private fun items(a: JSONArray?): List<Any?> = if (a == null) emptyList() else (0 until a.length()).map { i: Int -> a.opt(i) }

    /** usque's config.json (or the same keys pasted alone; mihomo's dashed spellings too). Its token is not carried. */
    private fun fromUsque(j: JSONObject): Reg {
        val pk = if (j.has("private_key") && !j.isNull("private_key")) j.opt("private_key") else j.opt("private-key")
        val privateKey = privatePem(pk) ?: throw badImport("private_key is not a P-256 (secp256r1) private key")
        val pub = listOf("endpoint_pub_key", "public_key", "public-key").map { k: String -> str(j.opt(k)) }.firstOrNull { x: String -> x.isNotEmpty() } ?: ""
        val publicKey = publicPem(pub) ?: throw badImport("endpoint_pub_key is missing or not a P-256 public key")
        val v4 = str(j.opt("ipv4")).ifEmpty { str(j.opt("ip")) }
        val address = addressList(listOf(v4, str(j.opt("ipv6"))))?.takeIf { x: List<String> -> x.isNotEmpty() }
            ?: throw badImport("ipv4 / ipv6 are missing or not addresses")
        val endpoints = linkedMapOf(
            "h3v4" to hostOf(j.opt("endpoint_v4"), 4).ifEmpty { DEFAULT_ENDPOINTS.getValue("h3v4") },
            "h3v6" to hostOf(j.opt("endpoint_v6"), 6).ifEmpty { DEFAULT_ENDPOINTS.getValue("h3v6") },
            "h2v4" to hostOf(j.opt("endpoint_h2_v4"), 4).ifEmpty { DEFAULT_ENDPOINTS.getValue("h2v4") },
            "h2v6" to hostOf(j.opt("endpoint_h2_v6"), 6).ifEmpty { DEFAULT_ENDPOINTS.getValue("h2v6") })
        return Reg(privateKey, publicKey, address, endpoints, Account(str(j.opt("id")), "", false), emptyList())
    }

    /** A masque outbound's WARP account (its masqueSettings.warp), or null. */
    private fun warpOf(o: Any?): JSONObject? {
        val ob = o as? JSONObject ?: return null
        if (ob.optString("protocol") != Masque.PROTOCOL) return null
        return ob.optJSONObject("streamSettings")?.optJSONObject("masqueSettings")?.optJSONObject("warp")
    }

    /**
     * An Xray WARP outbound — alone, in a list, in a whole config (an IRNetFree
     * share JSON is one) — or the warp object by itself, or 3x-ui's registration
     * answer { privateKey, publicKey, address, endpoint }. Each masque outbound of
     * the same device names an endpoint for its HTTP version and address family.
     */
    private fun fromXray(j: Any): Reg {
        var list: List<Any?> = emptyList()
        var warp: JSONObject? = null
        var endpoint = ""
        val arr = j as? JSONArray
        val obj = j as? JSONObject
        when {
            arr != null -> list = items(arr)
            obj != null && obj.optJSONArray("outbounds") != null -> list = items(obj.optJSONArray("outbounds"))
            obj != null && str(obj.opt("protocol")).isNotEmpty() -> list = listOf(obj)
            obj != null && obj.optJSONObject("warp") != null -> warp = obj.optJSONObject("warp")
            obj != null && str(obj.opt("privateKey")).isNotEmpty() && str(obj.opt("publicKey")).isNotEmpty() -> {
                warp = obj
                endpoint = str(obj.opt("endpoint"))
            }
            else -> {}
        }
        val outs = list.mapNotNull { o: Any? -> if (warpOf(o) != null) o as JSONObject else null }
        if (outs.isNotEmpty()) warp = warpOf(outs[0])
        val w = warp ?: throw badImport("No WARP account in it: neither usque's private_key nor a masque outbound with masqueSettings.warp")

        val privateKey = privatePem(w.opt("privateKey")) ?: throw badImport("warp.privateKey is not a P-256 (secp256r1) private key")
        val publicKey = publicPem(w.opt("publicKey")) ?: throw badImport("warp.publicKey is missing or not a P-256 public key")
        val addrs: List<Any?> = when (val raw = w.opt("address")) {
            null, JSONObject.NULL -> emptyList()
            is JSONArray -> items(raw)
            else -> listOf(raw)
        }
        val address = addressList(addrs)?.takeIf { x: List<String> -> x.isNotEmpty() } ?: throw badImport("warp.address is missing or not addresses")

        val endpoints = LinkedHashMap<String, String>()
        val h3 = hostOf(endpoint, 4)
        if (h3.isNotEmpty()) endpoints["h3v4"] = h3
        for (o in outs) {
            if (str(warpOf(o)?.opt("privateKey")) != str(w.opt("privateKey"))) continue   // another device's
            val addr = str(o.optJSONObject("settings")?.opt("address"))
            val fam = when {
                Masque.ipFamily(addr) == 6 -> 6
                Masque.ipFamily(addr) == 4 || HOST_RE.matches(addr) -> 4
                else -> 0
            }
            if (fam == 0) continue
            val slot = Masque.httpOf(o.optJSONObject("streamSettings")?.optJSONObject("tlsSettings")) + (if (fam == 6) "v6" else "v4")
            if (!endpoints.containsKey(slot)) endpoints[slot] = addr
        }
        val all = LinkedHashMap(DEFAULT_ENDPOINTS)
        all.putAll(endpoints)
        return Reg(privateKey, publicKey, address, all, Account("", "", false), emptyList())
    }

    /** A WARP account pasted in the sheet's Import: usque's config.json, or Xray's WARP outbound / config. */
    fun importWarp(text: String?): Reg {
        val s = (text ?: "").trim()
        if (s.isEmpty()) throw badImport("Nothing was pasted")
        if (JsonImport.nestingDepth(s) > JsonImport.MAX_DEPTH) throw badImport("It is nested too deeply to be a WARP account")
        val notJson = "It is not JSON: paste usque's config.json or an Xray WARP outbound"
        val j: Any = (try { JSONTokener(s).nextValue() } catch (e: Exception) { null }) ?: throw badImport(notJson)
        if (j !is JSONObject && j !is JSONArray) throw badImport(notJson)
        if (j is JSONObject) {
            val usque = (j.has("private_key") && !j.isNull("private_key")) || (j.has("private-key") && !j.isNull("private-key"))
            if (usque) return fromUsque(j)
        }
        return fromXray(j)
    }

    /* ---------------------------------- the servers ---------------------------------- */

    /** The sheet's step 2: HTTP version, endpoint, cover domain, anti-DPI, a name. */
    class Options(
        val http: String = "both", val endpoint: String = "auto", val address: String = "",
        val cover: String = "", val antiDpi: Boolean = true, val name: String = ""
    )

    /** [Options], checked. */
    internal class Checked(val http: String, val endpoint: String, val custom: Pair<String, Int>?, val cover: String, val antiDpi: Boolean, val name: String)

    /** `ip`, `ip:port`, `[v6]:port`, a bare v6 or a domain → (host, port); null when it is none of them. */
    internal fun parseEndpoint(v: String): Pair<String, Int>? {
        val s = v.trim()
        if (s.isEmpty() || Regex("[\\s/@]").containsMatchIn(s)) return null
        val host: String
        var port = 443
        if (s.startsWith("[")) {
            val m = Regex("^\\[([^\\]]+)\\](?::(\\d+))?$").find(s) ?: return null
            if (Masque.ipFamily(m.groupValues[1]) != 6) return null
            host = m.groupValues[1]
            if (m.groupValues[2].isNotEmpty()) port = m.groupValues[2].toIntOrNull() ?: return null
        } else if (Masque.ipFamily(s) == 6) {
            host = s
        } else {
            val m = Regex("^([^:]+)(?::(\\d+))?$").find(s) ?: return null
            val h = m.groupValues[1]
            if (!(Masque.ipFamily(h) == 4 || HOST_RE.matches(h))) return null
            host = h.lowercase()
            if (m.groupValues[2].isNotEmpty()) port = m.groupValues[2].toIntOrNull() ?: return null
        }
        return if (port in 1..65535) host to port else null
    }

    /** A cover domain as typed (a URL is forgiven) → the bare name, "" for none; badCover when it is no domain. */
    internal fun coverOf(v: String): String {
        var s = v.trim().lowercase()
        if (s.isEmpty()) return ""
        s = s.replace(Regex("^https?://"), "").replace(Regex("/.*$"), "").replace(Regex("\\.$"), "")
        if (!HOST_RE.matches(s)) throw WarpError("badCover", "The cover domain must be a domain name, like www.example.com")
        return s
    }

    /** The sheet's step 2, checked — before a registration, so a typo costs no device. */
    internal fun warpOptions(o: Options): Checked {
        val h = o.http.trim().lowercase()
        val e = o.endpoint.trim().lowercase()
        val endpoint = if (e in listOf("auto", "v6", "custom")) e else "auto"
        val custom = if (endpoint == "custom") (parseEndpoint(o.address)
            ?: throw WarpError("badAddress", "The endpoint must be an IP or a domain, with an optional port")) else null
        return Checked(
            http = if (h in listOf("h3", "h2", "both")) h else "both",
            endpoint = endpoint, custom = custom, cover = coverOf(o.cover), antiDpi = o.antiDpi, name = o.name.trim())
    }

    /**
     * The editor's fields, one server per HTTP version (H3 first): «☁ WARP · H3»
     * on the record's H3 edge, «☁ WARP · H2» on the .2 edge — or both on the
     * IPv6 pair, or on the user's own clean IP. The edge's certificate is pinned
     * by the WARP key, so the SNI is free: the official client's name, or a
     * cover domain — then serverName AND verifyPeerCertByName are that name (the
     * edge serves that site's real certificate, checked against the core's
     * roots). Host and path stay unset: the core's WARP defaults. Anti-DPI goes
     * per HTTP version: noise for QUIC, the Hide-SNI fragment for TCP.
     */
    fun warpServers(reg: Reg, opts: Options): List<Map<String, String>> {
        val o = warpOptions(opts)
        if (reg.privateKey.isBlank() || reg.publicKey.isBlank() || reg.address.isEmpty()) {
            throw WarpError("badAnswer", "The WARP account lacks its keys or its addresses")
        }
        val ep = LinkedHashMap(DEFAULT_ENDPOINTS)
        for (entry in reg.endpoints.entries) if (entry.value.isNotBlank() && ep.containsKey(entry.key)) ep[entry.key] = entry.value.trim()
        val base = o.name.ifEmpty { "☁ WARP" }
        val versions = if (o.http == "both") listOf("h3", "h2") else listOf(o.http)
        return versions.map { ver: String ->
            val f = LinkedHashMap<String, String>()
            val custom = o.custom
            f["protocol"] = Masque.PROTOCOL
            f["name"] = "$base · ${ver.uppercase()}"
            f["address"] = custom?.first ?: (ep[ver + (if (o.endpoint == "v6") "v6" else "v4")] ?: "")
            f["port"] = (custom?.second ?: 443).toString()
            f["masqueHttp"] = ver
            f["warpPrivateKey"] = reg.privateKey
            f["warpPublicKey"] = reg.publicKey
            f["warpAddress"] = reg.address.joinToString(", ")
            f["sni"] = o.cover.ifEmpty { WARP_SNI }
            if (o.cover.isNotEmpty()) f["vcn"] = o.cover
            if (o.antiDpi) { if (ver == "h3") f["noise"] = ANTI_DPI_NOISE else f["fragment"] = ANTI_DPI_FRAGMENT }
            f
        }
    }

    /** One server of [warpServers] made — ServerEditor.create, as the editor's + Manual makes one. */
    fun createServer(m: Map<String, String>): ServerConfig {
        val f = ServerEditor.Fields(
            name = m["name"] ?: "", address = m["address"] ?: "", port = m["port"] ?: "443", fp = "",
            masqueHttp = m["masqueHttp"] ?: "h3", sni = m["sni"] ?: "", vcn = m["vcn"] ?: "",
            fragment = m["fragment"] ?: "", noise = m["noise"] ?: "")
        for (id in listOf("warpPrivateKey", "warpPublicKey", "warpAddress")) m[id]?.let { x: String -> f.pro[id] = x }
        return ServerEditor.create(Masque.PROTOCOL, f)
    }

    /* -------------------------------- the whole sign-up -------------------------------- */

    /** The sheet's choices: a new account (direct / through the connection, a license) or an import, and step 2. */
    class AddArgs(
        val mode: String = "new", val license: String = "", val via: String = "direct",
        val importText: String = "", val options: Options = Options()
    )

    /** `ok` with the servers made (not saved yet), the account and any warnings; or a [code] with the message and its detail. */
    class AddResult(
        val ok: Boolean, val added: List<ServerConfig> = emptyList(), val account: Account? = null,
        val warnings: List<Warning> = emptyList(), val code: String = "", val error: String = "", val detail: String = ""
    )

    /**
     * What the sign-up needs from the app: is it connected, the live SOCKS port,
     * the transport for a route, how a server is made, the clock and the log.
     * [request] replaces the transport (tests).
     */
    class Deps(
        val connected: () -> Boolean = { false },
        val socksPort: () -> Int = { 0 },
        val request: ((Req) -> Res)? = null,
        val transport: (String, Int) -> ((Req) -> Res) = { via: String, port: Int -> Warp.okHttpTransport(via, port) },
        val createServer: (Map<String, String>) -> ServerConfig = { m: Map<String, String> -> Warp.createServer(m) },
        val now: () -> Long = { System.currentTimeMillis() },
        val log: (String, String) -> Unit = { _: String, _: String -> }
    )

    private fun secretsOf(r: Reg): List<String> = listOf(r.privateKey, pemBody(r.privateKey))

    /**
     * Register (or import), the fields, one server each (warp.js addWarp). The
     * options are checked before anything is sent, so a typo costs no device;
     * "through the connection" needs one. Nothing is saved here — the caller
     * adds [AddResult.added] to the store. Blocking — run it off the main thread.
     */
    fun addWarp(a: AddArgs, deps: Deps = Deps()): AddResult {
        var reg: Reg? = null
        try {
            warpOptions(a.options)
            val r: Reg = if (a.mode == "import") {
                val imported = importWarp(a.importText)
                deps.log("WARP: an existing account was imported", "info")
                imported
            } else {
                val license = a.license.trim()
                if (license.isNotEmpty() && !LICENSE_RE.matches(license)) throw WarpError("badLicense", "A WARP+ license looks like xxxxxxxx-xxxxxxxx-xxxxxxxx")
                val via = if (a.via == "proxy") "proxy" else "direct"
                if (via == "proxy" && !deps.connected()) {
                    throw WarpError("notConnected", "Registering through the app's connection needs one: connect to a server first")
                }
                val request = deps.request ?: deps.transport(via, if (via == "proxy") deps.socksPort() else 0)
                deps.log("WARP: signing up " + (if (via == "proxy") "through the app's connection" else "directly"), "info")
                registerWarp(request, license, deps.now, deps.log)
            }
            reg = r
            val fields = warpServers(r, a.options)
            val added = ArrayList<ServerConfig>()
            try {
                for (m in fields) added.add(deps.createServer(m))
            } catch (e: Exception) {
                val why = scrub(e.message ?: e.toString(), secretsOf(r))
                throw WarpError("createFailed", "The servers could not be made: $why", why)
            }
            deps.log("WARP: " + (if (added.size == 1) "one server" else "${added.size} servers") + " added (" + added.joinToString(", ") { s: ServerConfig -> s.name } + ")", "info")
            return AddResult(true, added, r.account, r.warnings)
        } catch (e: Exception) {
            val err = e as? WarpError ?: WarpError("failed", e.message ?: e.toString())
            val held = reg
            val secrets = if (held != null) secretsOf(held) else emptyList()
            val message = scrub(err.message, secrets)
            try { deps.log("WARP: $message", "warn") } catch (x: Exception) { /* never fails the answer */ }
            val detail = err.detail?.takeIf { d: String -> d.isNotEmpty() }?.let { d: String -> scrub(d, secrets) } ?: message
            return AddResult(false, code = err.code, error = message, detail = detail)
        }
    }

    private val running = AtomicBoolean(false)

    /** [addWarp], one at a time: a second tap meanwhile would register a second device (and spend a rate limit). */
    fun addWarpOnce(a: AddArgs, deps: Deps = Deps()): AddResult {
        if (!running.compareAndSet(false, true)) {
            return AddResult(false, code = "busy", error = "A WARP sign-up is already running", detail = "A WARP sign-up is already running")
        }
        try {
            return addWarp(a, deps)
        } finally {
            running.set(false)
        }
    }

    /* --------------------------------- the transport --------------------------------- */

    /**
     * The client for one sign-up: TLS 1.2 only and ALPN http/1.1 only (the
     * ClientHello that avoided 429s), no retries, no redirects, and either no
     * proxy at all or the tunnel's own SOCKS inbound on 127.0.0.1 — through
     * which OkHttp hands the name to the proxy unresolved, so nothing is looked
     * up on the phone's network.
     */
    internal fun client(via: String, socksPort: Int, timeoutMs: Long = TIMEOUT_MS): OkHttpClient {
        val spec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS).tlsVersions(TlsVersion.TLS_1_2).build()
        val proxy = if (via == "proxy") Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort)) else Proxy.NO_PROXY
        return OkHttpClient.Builder()
            .connectTimeout(timeoutMs, TimeUnit.MILLISECONDS)
            .readTimeout(timeoutMs, TimeUnit.MILLISECONDS)
            .writeTimeout(timeoutMs, TimeUnit.MILLISECONDS)
            .callTimeout(timeoutMs, TimeUnit.MILLISECONDS)
            .connectionSpecs(listOf(spec))
            .protocols(listOf(Protocol.HTTP_1_1))
            .retryOnConnectionFailure(false)
            .followRedirects(false)
            .followSslRedirects(false)
            .proxy(proxy)
            .build()
    }

    /**
     * A failure of the real transport in the sheet's terms: no answer in time
     * is `blocked` (timed out); through the connection, nothing listening on
     * the local port is `notConnected`; everything else on the way — refused,
     * reset, a certificate that is not the API's — is `blocked`.
     */
    internal fun transportError(e: IOException, via: String, socksPort: Int, timeoutMs: Long = TIMEOUT_MS): WarpError {
        val after = if (timeoutMs >= 1000) "${Math.round(timeoutMs / 1000.0)} s" else "$timeoutMs ms"
        val timedOut = e is SocketTimeoutException || (e is InterruptedIOException && (e.message ?: "").contains("timeout", ignoreCase = true))
        if (timedOut) return WarpError("blocked", "No answer from $HOST: timed out after $after", "timed out after $after")
        var c: Throwable? = e
        var refused = false
        var depth = 0
        while (c != null && depth < 8) {
            if (c is ConnectException) refused = true
            c = c.cause
            depth++
        }
        if (via == "proxy" && refused) return WarpError("notConnected", "Nothing answers on the app's proxy port $socksPort: the app is not connected")
        val why = e.message?.takeIf { m: String -> m.isNotBlank() } ?: e.javaClass.simpleName
        return WarpError("blocked", "Could not reach $HOST: $why", why)
    }

    private fun readCapped(input: InputStream?): String {
        if (input == null) return ""
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            if (out.size() + n > MAX_ANSWER) throw WarpError("badAnswer", "Cloudflare's answer is too large")
            out.write(buf, 0, n)
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }

    /**
     * The real request: HTTPS to the API with [client]'s ClientHello, straight
     * out (`via` "direct") or through the tunnel's SOCKS inbound (`via` "proxy",
     * [socksPort] — LocalProxyAuth answers its credentials). The certificate is
     * checked as any HTTPS client checks it.
     */
    fun okHttpTransport(via: String, socksPort: Int, timeoutMs: Long = TIMEOUT_MS): (Req) -> Res {
        if (via == "proxy" && socksPort !in 1..65535) {
            return { _: Req -> throw WarpError("notConnected", "The app has no local proxy port to register through") }
        }
        val http = client(via, socksPort, timeoutMs)
        return { r: Req ->
            val body = r.body?.toRequestBody(CONTENT_TYPE.toMediaType())
            val rb = Request.Builder().url("https://$HOST${r.path}").method(r.method, body)
            for (h in r.headers.entries) if (!h.key.equals("Content-Type", ignoreCase = true)) rb.header(h.key, h.value)
            rb.header("Connection", "close")
            try {
                http.newCall(rb.build()).execute().use { resp: Response -> Res(resp.code, readCapped(resp.body?.byteStream())) }
            } catch (e: IOException) {
                throw transportError(e, via, socksPort, timeoutMs)
            }
        }
    }
}
