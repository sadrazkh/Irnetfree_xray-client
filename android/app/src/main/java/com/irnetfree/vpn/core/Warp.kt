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
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Cloudflare WARP — the Android side of the desktop's src/main/warp.js, step
 * for step (v1.25.0 MASQUE, v1.26.0 WireGuard): a WARP device registered from
 * the app — or one brought in (usque's config.json or a pasted Xray WARP
 * outbound for MASQUE; a WireGuard .conf or wireguard:// link) — and its
 * servers (ServerEditor.create): one MASQUE server per HTTP version, or one
 * WireGuard server, alone or as the exit of a chain over a config the user
 * already has. Several accounts in one go, each with a WARP+ key or none, and
 * what Cloudflare says of each account kept on its servers ([AccountInfo],
 * `ServerConfig.warp`). .superpowers/sdd/warp-wg/design.md (git-ignored).
 *
 *   registerWarp(request, license, now, log)    → Reg (MASQUE)
 *   registerWarpWg(request, license, now, log)  → Reg (WireGuard)
 *   importWarp(text)                            → Reg (MASQUE)
 *   importWg(text)                              → a WireGuard server
 *   warpServers(reg, options)                   → the editor's fields, one map per server (pure)
 *   wgServerFields(reg, options, name)          → the editor's fields of a WireGuard WARP (pure)
 *   addWarpOnce(args, deps)                     → the WARP sheet's whole job, one at a time
 *
 * The device key is made HERE (P-256 for MASQUE, X25519 for WireGuard) and
 * never leaves the phone except to the core; Cloudflare gets its public half.
 * The API token is used for the calls of one registration and then dropped.
 * Neither is ever logged, nor put in an error, nor is a WARP+ key: whatever
 * Cloudflare says back is scrubbed of all three ([scrub]).
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

    /** The two kinds of WARP device: MASQUE (every caller before v1.26) and WireGuard. */
    const val KIND_MASQUE = "masque"
    const val KIND_WIREGUARD = "wireguard"
    /** Cloudflare's WireGuard edge when a record names none, and its port (2408; 500, 1701, 4500 answer too). */
    val WG_ENDPOINTS: Map<String, String> = linkedMapOf("v4" to "162.159.192.1", "v6" to "2606:4700:d0::a29f:c001")
    const val WG_PORT = 2408
    /** WARP's own MTU — and room for the hop a chained WARP rides inside. */
    const val WG_MTU = 1280
    /** Accounts in one go, and the pause between two sign-ups (they are rate-limited). */
    const val MAX_ACCOUNTS = 10
    const val PAUSE_MS = 2000L
    val ACCOUNT_TYPES = listOf("free", "limited", "unlimited", "team")
    const val BASE_NAME = "☁ WARP"

    /** The codes a refusal carries (the desktop's warp.err.*). */
    val ERROR_CODES = listOf("rateLimited", "blocked", "rejected", "notConnected", "badLicense", "badAnswer", "badImport",
        "badCover", "badAddress", "busy", "createFailed", "failed", "badHop", "badConf")
    val WARNING_CODES = listOf("warpNotEnabled", "licenseFailed", "accountUnread")

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
        "badHop" to "WARP cannot go through that config: {msg}",
        "badConf" to "Not imported: {msg}. A WireGuard .conf has an [Interface] and a [Peer]; a link starts with wireguard://.",
        "warn.warpNotEnabled" to "Cloudflare did not switch WARP on for this device. If the servers do not connect (“access denied”), make a new account.",
        "warn.licenseFailed" to "The WARP+ key was not applied ({msg}); a free account was made.",
        "warn.accountUnread" to "The account’s details could not be read ({msg}); its servers work all the same."
    )

    /**
     * A refusal in the sheet's words. A bad key of several is named by its
     * number (licensePlan's "Key 2 …"), never shown; too many keys says so.
     */
    fun messageFor(code: String, detail: String): String {
        if (code == "badLicense") {
            val m = Regex("^Key (\\d+) ").find(detail)
            if (m != null) return "Key ${m.groupValues[1]}: " + MESSAGES.getValue("badLicense")
            if (detail.startsWith("At most")) return detail
        }
        return (MESSAGES[code] ?: MESSAGES.getValue("failed")).replace("{msg}", detail)
    }

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

    /** A warning: its [code] (one of [WARNING_CODES]), the words, and — in a batch's flattened list — the account's [name]. */
    data class Warning(val code: String, val message: String, val cause: String? = null, val name: String = "")

    /**
     * What the sheet and the server's card show of an account (the desktop's
     * AccountInfo, `server.warp`): Cloudflare's account object read as it is —
     * premium_data, quota and usage in bytes under their own names (their
     * meaning is not documented: never "remaining") — plus how the WARP+ key
     * went and the devices it is on. Never the key itself: its last four
     * characters ([licenseTail]) say which one it was. An imported account
     * knows none of it ([imported]). Written on a server only when there is one.
     */
    data class AccountInfo(
        val kind: String,
        val imported: Boolean = false,
        val deviceId: String = "",
        /** account_type: free | limited | unlimited | team | "" */
        val type: String = "",
        val warpPlus: Boolean = false,
        val premiumData: Long? = null,
        val quota: Long? = null,
        val usage: Long? = null,
        /** parent | child | "" */
        val role: String = "",
        val referralCount: Long? = null,
        /** GET …/account/devices: how many devices are on this account (license) */
        val devices: Long? = null,
        /** none | applied | refused */
        val license: String = "none",
        val licenseTail: String = "",
        /** license "refused": Cloudflare's words, scrubbed */
        val licenseError: String = "",
        val checkedAt: String = ""
    ) {
        fun toJson(): JSONObject {
            val o = JSONObject().put("kind", kind)
            if (imported) return o.put("imported", true)
            o.put("deviceId", deviceId).put("type", type).put("warpPlus", warpPlus)
            o.put("premiumData", premiumData ?: JSONObject.NULL)
            o.put("quota", quota ?: JSONObject.NULL)
            o.put("usage", usage ?: JSONObject.NULL)
            o.put("role", role)
            o.put("referralCount", referralCount ?: JSONObject.NULL)
            o.put("devices", devices ?: JSONObject.NULL)
            o.put("license", license).put("licenseTail", licenseTail).put("licenseError", licenseError).put("checkedAt", checkedAt)
            return o
        }

        companion object {
            /** A stored `warp` object; null when there is none. Unknown values read as the defaults. */
            fun fromJson(stored: JSONObject?): AccountInfo? {
                val o: JSONObject = stored ?: return null
                // isNull first: Android's org.json hands back "null" for a JSON null
                fun text(k: String): String = if (o.isNull(k)) "" else o.optString(k, "").trim()
                val kind = if (text("kind") == Warp.KIND_WIREGUARD) Warp.KIND_WIREGUARD else Warp.KIND_MASQUE
                if (o.optBoolean("imported", false)) return AccountInfo(kind = kind, imported = true)
                val type = text("type").lowercase()
                val role = text("role").lowercase()
                val license = text("license")
                return AccountInfo(
                    kind = kind,
                    deviceId = text("deviceId"),
                    type = if (type in Warp.ACCOUNT_TYPES) type else "",
                    warpPlus = o.opt("warpPlus") == true,
                    premiumData = Warp.numberOf(o.opt("premiumData")),
                    quota = Warp.numberOf(o.opt("quota")),
                    usage = Warp.numberOf(o.opt("usage")),
                    role = if (role == "parent" || role == "child") role else "",
                    referralCount = Warp.numberOf(o.opt("referralCount")),
                    devices = Warp.numberOf(o.opt("devices")),
                    license = if (license == "applied" || license == "refused") license else "none",
                    licenseTail = text("licenseTail"),
                    licenseError = text("licenseError"),
                    checkedAt = text("checkedAt"))
            }
        }
    }

    /**
     * A WARP device: its key (MASQUE: P-256, PKCS#8 PEM; WireGuard: X25519,
     * base64 of the raw 32 bytes), the edge's key (MASQUE: PEM; WireGuard: the
     * peer's base64 key), its addresses [v4/32, v6/128], the edges (MASQUE:
     * h3v4, h3v6, h2v4, h2v6; WireGuard: v4, v6), the account and any warnings;
     * what Cloudflare says of the account ([info], null for an import) and
     * WireGuard's `reserved` (the client id's bytes). Its text never shows the
     * private key.
     */
    class Reg(
        val privateKey: String, val publicKey: String, val address: List<String>,
        val endpoints: Map<String, String>, val account: Account, val warnings: List<Warning>,
        val info: AccountInfo? = null, val reserved: List<Int> = emptyList(), val kind: String = Warp.KIND_MASQUE
    ) {
        override fun toString(): String = "Reg(kind=$kind, address=$address, endpoints=$endpoints, account=$account)"
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
     * usque's registration body: an X25519 key — for MASQUE a throwaway one,
     * 32 random bytes (all an X25519 public key is on the wire; the MASQUE key
     * replaces it at once), for WireGuard the device's own ([key]) —, `tos`
     * the moment the user accepted the terms (pressing Create is that), a
     * random 16-hex serial.
     */
    internal fun regBody(now: Long, key: String? = null): JSONObject {
        val throwaway = ByteArray(32).also { b: ByteArray -> rng.nextBytes(b) }
        val serial = ByteArray(8).also { b: ByteArray -> rng.nextBytes(b) }
        return JSONObject()
            .put("key", key ?: Base64.getEncoder().encodeToString(throwaway))
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

    /**
     * One API call: the headers, the version prefix, the status mapped. The
     * answer's JSON object — `{}` for an empty one when [empty] allows it
     * (PUT …/account may answer 204).
     */
    private fun call(request: (Req) -> Res, method: String, path: String, token: String?, body: JSONObject?, step: String,
                     secrets: List<String>, empty: Boolean = false): JSONObject {
        val res = send(request, method, path, token, body, step, secrets)
        if (empty && (res.status == 204 || res.body.isBlank())) return JSONObject()
        val json: JSONObject? = try { JSONTokener(res.body).nextValue() as? JSONObject } catch (e: Exception) { null }
        return json ?: throw WarpError("badAnswer", "Cloudflare's answer to the $step is not JSON")
    }

    /** One API call whose answer is a JSON list (GET …/account/devices). */
    private fun callList(request: (Req) -> Res, method: String, path: String, token: String?, step: String, secrets: List<String>): JSONArray {
        val res = send(request, method, path, token, null, step, secrets)
        val list: JSONArray? = try { JSONTokener(res.body).nextValue() as? JSONArray } catch (e: Exception) { null }
        return list ?: throw WarpError("badAnswer", "Cloudflare's answer to the $step is not a list")
    }

    /** One request sent, its status mapped: a 2xx answer comes back, anything else is thrown in the sheet's terms. */
    private fun send(request: (Req) -> Res, method: String, path: String, token: String?, body: JSONObject?, step: String, secrets: List<String>): Res {
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
        return res
    }

    /* ---------------------------------- the account ---------------------------------- */

    private val DIGITS = Regex("^\\d{1,20}$")

    /** A byte count as Cloudflare writes it — a number or a string of digits, never negative — else null. A fraction is cut to its whole bytes. */
    internal fun numberOf(v: Any?): Long? {
        if (v is String) {
            val s = v.trim()
            return if (DIGITS.matches(s)) s.toLongOrNull() else null
        }
        if (v !is Number) return null
        if (v is Int || v is Long || v is Short || v is Byte) return v.toLong().takeIf { n: Long -> n >= 0 }
        if (v is java.math.BigInteger) return if (v.signum() >= 0 && v.bitLength() < 64) v.toLong() else null
        val d = v.toDouble()
        return if (d.isFinite() && d >= 0) Math.floor(d).toLong() else null
    }

    /** [a] with every key of [b] over it (Object.assign({}, a, b)). */
    private fun merged(a: JSONObject, b: JSONObject): JSONObject {
        val out = JSONObject(a.toString())
        for (k in b.keys().asSequence().toList()) out.put(k, b.get(k))
        return out
    }

    /** Cloudflare's account object as [AccountInfo] (warp.js accountInfo): read as it is, odd values as null / "". */
    fun accountInfo(
        kind: String, deviceId: String, acc: JSONObject?, now: Long,
        license: String = "none", licenseTail: String = "", licenseError: String = "", devices: Long? = null
    ): AccountInfo {
        val a = acc ?: JSONObject()
        val type = str(a.opt("account_type")).lowercase()
        val role = str(a.opt("role")).lowercase()
        return AccountInfo(
            kind = kind,
            deviceId = deviceId.trim(),
            type = if (type in ACCOUNT_TYPES) type else "",
            warpPlus = a.opt("warp_plus") == true,
            premiumData = numberOf(a.opt("premium_data")),
            quota = numberOf(a.opt("quota")),
            usage = numberOf(a.opt("usage")),
            role = if (role == "parent" || role == "child") role else "",
            referralCount = numberOf(a.opt("referral_count")),
            devices = devices,
            license = license,
            licenseTail = licenseTail,
            licenseError = licenseError,
            checkedAt = ISO.format(Instant.ofEpochMilli(now)))
    }

    /** What went wrong, in words fit to show: Cloudflare's own, else the message — scrubbed. */
    private fun whyOf(e: Exception, secrets: List<String>): String {
        val detail = (e as? WarpError)?.detail?.takeIf { d: String -> d.isNotEmpty() }
        return scrub(detail ?: e.message ?: e.toString(), secrets)
    }

    /**
     * A registered device's account, both kinds (warp.js accountStep): the
     * WARP+ key when there is one (PUT …/account, which may answer 204; a
     * refusal is a warning — the device exists by then, and a free account
     * beats none), then the account and its devices read back. A read that
     * fails is a warning too (accountUnread): the servers work without it.
     */
    private fun accountStep(
        request: (Req) -> Res, dev: String, token: String, license: String, secrets: List<String>,
        say: (String, String) -> Unit, warnings: MutableList<Warning>, base: JSONObject?, kind: String, id: String, now: () -> Long
    ): AccountInfo {
        var acc: JSONObject = if (base != null) JSONObject(base.toString()) else JSONObject()
        var applied = "none"
        var tail = ""
        var refusedWhy = ""
        if (license.isNotEmpty()) {
            tail = license.takeLast(4)
            try {
                val put = call(request, "PUT", "$dev/account", token, JSONObject().put("license", license), "WARP+ license", secrets, empty = true)
                acc = merged(acc, put)
                applied = "applied"
                say("WARP: the WARP+ key …$tail is applied", "info")
            } catch (e: Exception) {
                val why = whyOf(e, secrets)
                applied = "refused"
                refusedWhy = why
                warnings.add(Warning("licenseFailed", why, (e as? WarpError)?.code ?: "failed"))
                say("WARP: the WARP+ key …$tail was not applied — $why", "warn")
            }
        }
        val unread = ArrayList<String>()
        try {
            acc = merged(acc, call(request, "GET", "$dev/account", token, null, "account", secrets))
        } catch (e: Exception) {
            unread.add(whyOf(e, secrets))
        }
        var devices: Long? = null
        try {
            devices = callList(request, "GET", "$dev/account/devices", token, "account devices", secrets).length().toLong()
        } catch (e: Exception) {
            unread.add(whyOf(e, secrets))
        }
        if (unread.isNotEmpty()) {
            warnings.add(Warning("accountUnread", unread.joinToString("; ")))
            say("WARP: the account could not be read in full — " + unread.joinToString("; "), "warn")
        }
        val info = accountInfo(kind, id, acc, now(), applied, tail, refusedWhy, devices)
        say("WARP: the account is " + info.type.ifEmpty { "of an unknown type" } + (if (info.warpPlus) " (WARP+)" else ""), "info")
        return info
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
     *   5. the WARP+ key when there is one, the account and its devices read back ([accountStep]);
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
        if (lic.isNotEmpty()) secrets.add(lic)
        val say: (String, String) -> Unit = { line: String, level: String ->
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

        val base: JSONObject? = rec.optJSONObject("account") ?: made.optJSONObject("account")
        val info = accountStep(request, dev, token, lic, secrets, say, warnings, base, KIND_MASQUE, id, now)

        val mapped = fromRecord(rec)
        say("WARP: the device's addresses ${mapped.address.joinToString(", ")}; HTTP/3 edge ${mapped.endpoints["h3v4"]}", "info")
        return Reg(privateKey, mapped.publicKey, mapped.address, mapped.endpoints,
            Account(id, info.type, info.warpPlus), warnings, info = info, kind = KIND_MASQUE)
    }

    /* ------------------------------ WireGuard (v1.26.0) ------------------------------ */

    /** A WireGuard key: 32 bytes, base64. */
    private val WG_KEY = Regex("^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")

    internal fun isWgKey(v: String?): Boolean = WG_KEY.matches((v ?: "").trim())

    private val CLIENT_ID = Regex("^[A-Za-z0-9+/_-]+={0,2}$")

    /** `config.client_id` (base64) → its bytes: Xray's `reserved`, the three Cloudflare reads off each packet. */
    internal fun clientIdBytes(v: Any?): List<Int> {
        val s = str(v)
        if (s.isEmpty() || !CLIENT_ID.matches(s)) return emptyList()
        val b: ByteArray = try { Base64.getDecoder().decode(s.replace('-', '+').replace('_', '/')) } catch (e: IllegalArgumentException) { return emptyList() }
        return if (b.size in 1..8) b.map { x: Byte -> x.toInt() and 0xFF } else emptyList()
    }

    /**
     * An X25519 key pair for a WireGuard device: (private, public), each the
     * raw 32 bytes in base64 as `wg genkey` / `wg pubkey` write them. Made by
     * the platform's KeyPairGenerator — on the phone Conscrypt's (IRApp puts
     * the bundled Conscrypt 2.7.0 first; it registers X25519 on every Android
     * version), on the JVM the JDK's — whose encodings (PKCS#8 / X.509) end in
     * the raw key. The private key is clamped as `wg genkey` writes it: X25519
     * clamps it anyway, so its public half is the same.
     */
    internal fun wgKeyPair(): Pair<String, String> {
        val pair = try {
            KeyPairGenerator.getInstance("X25519").generateKeyPair()
        } catch (e: Exception) {
            throw WarpError("failed", "This phone could not make an X25519 key for a WireGuard device (${e.javaClass.simpleName})")
        }
        val priv: ByteArray? = pair.private?.encoded
        val pub: ByteArray? = pair.public?.encoded
        if (priv == null || pub == null || priv.size < 32 || pub.size < 32) {
            throw WarpError("failed", "This phone made an X25519 key in a form that cannot be read")
        }
        val raw = priv.copyOfRange(priv.size - 32, priv.size)
        raw[0] = (raw[0].toInt() and 248).toByte()
        raw[31] = ((raw[31].toInt() and 127) or 64).toByte()
        val enc = Base64.getEncoder()
        return enc.encodeToString(raw) to enc.encodeToString(pub.copyOfRange(pub.size - 32, pub.size))
    }

    /** A WireGuard device record → the peer's key, the addresses, the endpoints (v4, v6), `reserved`. */
    private class WgMapped(val publicKey: String, val address: List<String>, val endpoints: Map<String, String>, val reserved: List<Int>)

    private fun fromWgRecord(rec: JSONObject): WgMapped {
        val cfg = rec.optJSONObject("config") ?: JSONObject()
        val peer = cfg.optJSONArray("peers")?.optJSONObject(0)
            ?: throw WarpError("badAnswer", "Cloudflare's device record has no endpoint (config.peers is empty)")
        val publicKey = str(peer.opt("public_key"))
        if (!isWgKey(publicKey)) throw WarpError("badAnswer", "Cloudflare's device record has no WireGuard key (config.peers[0].public_key)")
        val a = cfg.optJSONObject("interface")?.optJSONObject("addresses") ?: JSONObject()
        val address = addressList(listOf(a.opt("v4"), a.opt("v6")))?.takeIf { x: List<String> -> x.isNotEmpty() }
            ?: throw WarpError("badAnswer", "Cloudflare's device record has no usable address (config.interface.addresses)")
        val ep = peer.optJSONObject("endpoint") ?: JSONObject()
        val endpoints = linkedMapOf(
            "v4" to hostOf(ep.opt("v4"), 4).ifEmpty { WG_ENDPOINTS.getValue("v4") },
            "v6" to hostOf(ep.opt("v6"), 6).ifEmpty { WG_ENDPOINTS.getValue("v6") })
        return WgMapped(publicKey, address, endpoints, clientIdBytes(cfg.opt("client_id")))
    }

    /**
     * A new WARP device for WireGuard (wgcf's way, warp.js registerWarpWg):
     *   1. an X25519 key pair, made here;
     *   2. POST /reg with its public half (key_type curve25519, tunnel_type wireguard);
     *   3. warp_enabled switched on when the answer does not say it is — as for MASQUE;
     *      an answer without peers: GET the record;
     *   4. the WARP+ key, the account and its devices ([accountStep]);
     *   5. the record → the peer's key, the addresses, the endpoints, `reserved`.
     * Blocking — run it off the main thread.
     */
    fun registerWarpWg(
        request: (Req) -> Res,
        license: String = "",
        now: () -> Long = { System.currentTimeMillis() },
        log: (String, String) -> Unit = { _: String, _: String -> }
    ): Reg {
        val lic = license.trim()
        if (lic.isNotEmpty() && !LICENSE_RE.matches(lic)) throw WarpError("badLicense", "A WARP+ license looks like xxxxxxxx-xxxxxxxx-xxxxxxxx")
        val secrets = ArrayList<String>()
        if (lic.isNotEmpty()) secrets.add(lic)
        val say: (String, String) -> Unit = { line: String, level: String ->
            try { log(scrub(line, secrets), level) } catch (e: Exception) { /* a log never fails a sign-up */ }
        }

        val keys = wgKeyPair()
        val privateKey = keys.first
        secrets.add(privateKey)
        val ownKey = keys.second

        say("WARP: registering a new WireGuard device with Cloudflare…", "info")
        val made = call(request, "POST", "/reg", null, regBody(now(), ownKey), "registration", secrets)
        val id = str(made.opt("id"))
        val token = str(made.opt("token"))
        if (id.isEmpty() || token.isEmpty()) throw WarpError("badAnswer", "Cloudflare's registration answer has no device id or token")
        secrets.add(token)
        val dev = "/reg/" + uriComponent(id)
        say("WARP: device $id registered (WireGuard)", "info")

        val warnings = ArrayList<Warning>()
        var rec = made
        if (rec.opt("warp_enabled") != true) {
            val on = call(request, "PATCH", dev, token, JSONObject().put("warp_enabled", true), "activation (warp_enabled)", secrets)
            if (on.opt("warp_enabled") == true) {
                rec = if (peersOf(on) > 0) on else JSONObject(rec.toString()).put("warp_enabled", true)
                say("WARP: switched on for the device (warp_enabled)", "info")
            } else {
                warnings.add(Warning("warpNotEnabled", "Cloudflare still reports warp_enabled: false for this device; the edge may not answer"))
                say("WARP: Cloudflare did not switch the device on (warp_enabled stays false) — the edge may not answer", "warn")
            }
        }
        if (peersOf(rec) == 0) {
            say("WARP: the answer names no endpoint — reading the device record", "info")
            val got = call(request, "GET", dev, token, null, "device record", secrets)
            val enabled = rec.opt("warp_enabled") == true || got.opt("warp_enabled") == true
            rec = JSONObject(got.toString()).put("warp_enabled", enabled)
        }

        val base: JSONObject? = rec.optJSONObject("account") ?: made.optJSONObject("account")
        val info = accountStep(request, dev, token, lic, secrets, say, warnings, base, KIND_WIREGUARD, id, now)

        val mapped = fromWgRecord(rec)
        say("WARP: the device's addresses ${mapped.address.joinToString(", ")}; edge ${mapped.endpoints["v4"]}:$WG_PORT", "info")
        return Reg(privateKey, mapped.publicKey, mapped.address, mapped.endpoints,
            Account(id, info.type, info.warpPlus), warnings, info = info, reserved = mapped.reserved, kind = KIND_WIREGUARD)
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

    private val WG_LINK = Regex("^(wireguard|wg)://", RegexOption.IGNORE_CASE)
    /** Something that may be a key: a message carrying one is not repeated. */
    private val KEYISH = Regex("[A-Za-z0-9+/]{20,}")

    /**
     * A WireGuard .conf or a wireguard:// link pasted in the sheet's Import →
     * its server, as + WireGuard makes it (LinkParser; warp.js importWg).
     * Anything else is badConf.
     */
    fun importWg(text: String?): ServerConfig {
        val s = (text ?: "").trim()
        if (s.isEmpty()) throw WarpError("badConf", "Nothing was pasted")
        val made: ServerConfig? = try {
            when {
                LinkParser.isWireguardConf(s) -> LinkParser.parseWireguardConf(s)
                WG_LINK.containsMatchIn(s) -> LinkParser.parseLink(s)
                else -> null
            }
        } catch (e: Exception) {
            // the parser's own words say which line is missing; a message quoting a key is not repeated
            val why = e.message ?: ""
            throw WarpError("badConf", "The WireGuard config could not be read" + (if (why.isNotEmpty() && !KEYISH.containsMatchIn(why)) ": $why" else ""))
        }
        if (made == null || made.protocol != KIND_WIREGUARD) {
            throw WarpError("badConf", "Paste a WireGuard .conf ([Interface] and [Peer]) or a wireguard:// link")
        }
        return made
    }

    /* ---------------------------------- the servers ---------------------------------- */

    /** The sheet's step 2: HTTP version, endpoint, cover domain, anti-DPI, a name. */
    class Options(
        val http: String = "both", val endpoint: String = "auto", val address: String = "",
        val cover: String = "", val antiDpi: Boolean = true, val name: String = ""
    )

    /** [Options], checked. */
    internal class Checked(val http: String, val endpoint: String, val custom: Pair<String, Int>?, val cover: String, val antiDpi: Boolean, val name: String)

    /** `ip`, `ip:port`, `[v6]:port`, a bare v6 or a domain → (host, port — [defaultPort] when none is given); null when it is none of them. */
    internal fun parseEndpoint(v: String, defaultPort: Int = 443): Pair<String, Int>? {
        val s = v.trim()
        if (s.isEmpty() || Regex("[\\s/@]").containsMatchIn(s)) return null
        val host: String
        var port = defaultPort
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

    /* ------------------------------ WireGuard servers ------------------------------ */

    /**
     * The sheet's WireGuard choices: chained over a config of the user's
     * ([use] "chain", [chainWith] a server id or `chain:<id>`) — the default —
     * or dialled from here ([use] "direct": [endpoint] auto / v6 / custom with
     * [address], and [antiDpi] the noise preset), a base [name].
     */
    class WgOptions(
        val use: String = "chain", val chainWith: String = "", val endpoint: String = "auto",
        val address: String = "", val antiDpi: Boolean = true, val name: String = ""
    )

    /** [WgOptions], checked. */
    internal class WgChecked(val use: String, val chainWith: String, val endpoint: String, val custom: Pair<String, Int>?, val antiDpi: Boolean, val name: String)

    /** The sheet's WireGuard choices, checked — before a registration, so a typo costs no device. */
    internal fun wgOptions(o: WgOptions): WgChecked {
        val use = if (o.use.trim().lowercase() == "direct") "direct" else "chain"
        val e = o.endpoint.trim().lowercase()
        // a chained WARP is dialled from the hop's server: Cloudflare's own edge, no clean IP, no noise
        val endpoint = if (use == "direct" && e in listOf("auto", "v6", "custom")) e else "auto"
        val custom = if (endpoint == "custom") (parseEndpoint(o.address, WG_PORT)
            ?: throw WarpError("badAddress", "The endpoint must be an IP or a domain, with an optional port")) else null
        return WgChecked(use, o.chainWith.trim(), endpoint, custom, use == "direct" && o.antiDpi, o.name.trim())
    }

    /**
     * A WireGuard WARP device as the editor's fields (warp.js wgServerFields):
     * Cloudflare's edge (the record's v4, or its v6, or the user's clean IP) on
     * 2408, the device's own key, the peer's, the tunnel's addresses,
     * `reserved` from the client id, MTU 1280, everything through it. Noise
     * only for a WARP dialled from here; a chained one rides its hop.
     */
    fun wgServerFields(reg: Reg, opts: WgOptions, name: String = ""): Map<String, String> {
        val o = wgOptions(opts)
        if (!isWgKey(reg.privateKey) || !isWgKey(reg.publicKey) || reg.address.isEmpty()) {
            throw WarpError("badAnswer", "The WARP account lacks its keys or its addresses")
        }
        val ep = LinkedHashMap(WG_ENDPOINTS)
        for (k in listOf("v4", "v6")) {
            val v = (reg.endpoints[k] ?: "").trim()
            if (v.isNotEmpty()) ep[k] = v
        }
        val custom = o.custom
        val f = LinkedHashMap<String, String>()
        f["protocol"] = KIND_WIREGUARD
        f["name"] = name.trim().ifEmpty { o.name.ifEmpty { BASE_NAME } }
        f["address"] = custom?.first ?: (ep[if (o.endpoint == "v6") "v6" else "v4"] ?: "")
        f["port"] = (custom?.second ?: WG_PORT).toString()
        f["privateKey"] = reg.privateKey
        f["publicKey"] = reg.publicKey
        f["localAddress"] = reg.address.joinToString(", ")
        f["mtu"] = WG_MTU.toString()
        f["allowedIPs"] = "0.0.0.0/0, ::/0"
        if (reg.reserved.isNotEmpty()) f["reserved"] = reg.reserved.joinToString(",")
        if (o.antiDpi) f["noise"] = ANTI_DPI_NOISE
        return f
    }

    /** A WireGuard WARP of [wgServerFields] made — ServerEditor.create, as the editor's + Manual makes one. */
    private fun createWgServer(m: Map<String, String>): ServerConfig {
        val f = ServerEditor.Fields(
            name = m["name"] ?: "", address = m["address"] ?: "", port = m["port"] ?: WG_PORT.toString(),
            cred = m["privateKey"] ?: "", wgPub = m["publicKey"] ?: "", wgAddr = m["localAddress"] ?: "",
            wgMtu = m["mtu"] ?: WG_MTU.toString(), wgReserved = m["reserved"] ?: "",
            wgAllowed = m["allowedIPs"] ?: "0.0.0.0/0, ::/0", noise = m["noise"] ?: "")
        val s = ServerEditor.create(KIND_WIREGUARD, f)
        // an IPv6 edge in brackets, the way the core reads an endpoint (and ConfigBuilder writes a resolved one)
        if (Masque.ipFamily(s.address) == 6) {
            val peer = s.outbound.optJSONObject("settings")?.optJSONArray("peers")?.optJSONObject(0)
            peer?.put("endpoint", "[${s.address}]:${s.port}")
        }
        return s
    }

    /** One server of [warpServers] or [wgServerFields] made — ServerEditor.create, as the editor's + Manual makes one. */
    fun createServer(m: Map<String, String>): ServerConfig {
        if (m["protocol"] == KIND_WIREGUARD) return createWgServer(m)
        val f = ServerEditor.Fields(
            name = m["name"] ?: "", address = m["address"] ?: "", port = m["port"] ?: "443", fp = "",
            masqueHttp = m["masqueHttp"] ?: "h3", sni = m["sni"] ?: "", vcn = m["vcn"] ?: "",
            fragment = m["fragment"] ?: "", noise = m["noise"] ?: "")
        for (id in listOf("warpPrivateKey", "warpPublicKey", "warpAddress")) m[id]?.let { x: String -> f.pro[id] = x }
        return ServerEditor.create(Masque.PROTOCOL, f)
    }

    /* ------------------------------ names, keys, the chain ------------------------------ */

    /**
     * Each account's label (warp.js accountLabels): the base alone for one
     * account no server uses yet («☁ WARP», MASQUE «☁ WARP · H3»), else the
     * next free numbers — «☁ WARP 2» when the bare base is there already,
     * «☁ WARP 1» … for a batch. A label is taken by a server of that name, or
     * of that name + « · …».
     */
    fun accountLabels(n: Int, base: String, names: List<String>): List<String> {
        val all = names.map { x: String -> x.trim() }
        fun taken(label: String): Boolean = all.any { x: String -> x == label || x.startsWith("$label · ") }
        if (n == 1 && !taken(base)) return listOf(base)
        val out = ArrayList<String>()
        var k = if (taken(base)) 2 else 1
        while (out.size < n) {
            val label = "$base $k"
            if (!taken(label)) out.add(label)
            k++
        }
        return out
    }

    /** How many accounts, and each one's WARP+ key ("" = a free account). */
    class Plan(val count: Int, val keys: List<String>)

    /**
     * The WARP+ keys and how many accounts (warp.js licensePlan): one key goes
     * on every account, several one each in order (the accounts past them
     * free), more keys than accounts raise the count — at most [MAX_ACCOUNTS].
     * Every key is checked here: the message names the key's number, never the key.
     */
    fun licensePlan(licenses: List<String>, license: String = "", count: Int = 1): Plan {
        val raw = if (licenses.isNotEmpty()) licenses else listOf(license)
        val keys = raw.map { k: String -> k.trim() }.filter { k: String -> k.isNotEmpty() }
        if (keys.size > MAX_ACCOUNTS) throw WarpError("badLicense", "At most $MAX_ACCOUNTS WARP+ keys at once")
        for (i in keys.indices) {
            if (!LICENSE_RE.matches(keys[i])) {
                throw WarpError("badLicense", (if (keys.size > 1) "Key ${i + 1} is not a WARP+ key: " else "") + "a WARP+ license looks like xxxxxxxx-xxxxxxxx-xxxxxxxx")
            }
        }
        val n = minOf(MAX_ACCOUNTS, maxOf(1, count, keys.size))
        val each = ArrayList<String>()
        for (i in 0 until n) each.add(if (keys.size == 1) keys[0] else keys.getOrElse(i) { _: Int -> "" })
        return Plan(n, each)
    }

    /** The WARP+ keys box read back as it is typed: what Create would make ([ok]), or which key is not one — never the key. */
    class ReadBack(val ok: Boolean, val text: String)

    /** «3 accounts: 2 with WARP+, 1 free» — or «Key 2 (line 3) is not a WARP+ key …» — for the keys box and the count. */
    fun licenseReadBack(text: String, count: Int): ReadBack {
        val lines = text.split(Regex("\\r?\\n"))
        val keys = ArrayList<Pair<Int, String>>()   // (line number, key)
        for (i in lines.indices) {
            val k = lines[i].trim()
            if (k.isNotEmpty()) keys.add(Pair(i + 1, k))
        }
        if (keys.size > MAX_ACCOUNTS) return ReadBack(false, "At most $MAX_ACCOUNTS WARP+ keys at once — this has ${keys.size}")
        val bad = ArrayList<String>()
        for (j in keys.indices) {
            if (!LICENSE_RE.matches(keys[j].second)) bad.add(if (j + 1 == keys[j].first) "Key ${j + 1}" else "Key ${j + 1} (line ${keys[j].first})")
        }
        if (bad.isNotEmpty()) {
            return ReadBack(false, bad.joinToString(", ") + (if (bad.size == 1) " is not a WARP+ key" else " are not WARP+ keys") +
                " — a key looks like xxxxxxxx-xxxxxxxx-xxxxxxxx")
        }
        val n = minOf(MAX_ACCOUNTS, maxOf(1, count, keys.size))
        val plus = if (keys.size == 1) n else minOf(keys.size, n)
        val free = n - plus
        val parts = ArrayList<String>()
        if (plus > 0) parts.add("$plus with WARP+")
        if (free > 0) parts.add("$free free")
        return ReadBack(true, "$n " + (if (n == 1) "account" else "accounts") + ": " + parts.joinToString(", "))
    }

    /** What a chained WARP rides: the hop's members, in order, and its name for the chain's. */
    class Hop(val members: List<String>, val name: String)

    /**
     * What a chained WARP rides (warp.js resolveHop): a server (`<id>`) or a
     * chain (`chain:<id>`, its members) — each still there, and none an HTTP
     * proxy, which carries no UDP. Otherwise badHop.
     */
    fun resolveHop(chainWith: String, servers: List<ServerConfig>, chains: List<ChainConfig>): Hop {
        val v = chainWith.trim()
        if (v.isEmpty()) throw WarpError("badHop", "Choose the config WARP goes through")
        val byId = servers.associateBy { s: ServerConfig -> s.id }
        val members: List<String>
        val name: String
        if (v.startsWith("chain:")) {
            val wanted = v.substring(6)
            val c = chains.firstOrNull { x: ChainConfig -> x.id == wanted } ?: throw WarpError("badHop", "That chain is no longer there")
            members = c.members.filter { m: String -> m.isNotEmpty() }
            name = c.name.trim().ifEmpty { "Chain" }
        } else {
            val s = byId[v] ?: throw WarpError("badHop", "That config is no longer there")
            members = listOf(v)
            name = s.name.trim().ifEmpty { v }
        }
        if (members.isEmpty()) throw WarpError("badHop", "That chain has no servers")
        for (id in members) {
            if (byId[id] == null) throw WarpError("badHop", "A server of that chain is no longer there")
        }
        // WireGuard's UDP goes through the last hop; the hops before it only carry that hop's stream
        val last = byId.getValue(members.last())
        if (last.protocol == "http") {
            throw WarpError("badHop", last.name.trim().ifEmpty { last.id } + " is an HTTP proxy: it carries no UDP, so WireGuard cannot ride it")
        }
        return Hop(members, name)
    }

    /** A new chain id, of the app's own form (newId): `chain-<base36 time><4 hex>`. */
    private fun chainId(now: () -> Long): String =
        "chain-" + now().toString(36) + hex(ByteArray(2).also { b: ByteArray -> rng.nextBytes(b) })

    /* ------------------------------ an account in words ------------------------------ */

    /** Cloudflare's account_type in the sheet's words. */
    fun typeLabel(type: String): String = when (type) {
        "free" -> "Free"
        "limited" -> "WARP+ (data)"
        "unlimited" -> "WARP+ Unlimited"
        "team" -> "Team (Zero Trust)"
        else -> "Unknown"
    }

    /** A byte count for people: 1024-based, one decimal, up to EB (Cloudflare's "unlimited" is about 25 PB). */
    fun humanBytes(n: Long): String {
        val units = listOf("B", "KB", "MB", "GB", "TB", "PB", "EB")
        var v = n.toDouble()
        var i = 0
        while (v >= 1024 && i < units.size - 1) {
            v /= 1024
            i++
        }
        return (if (i == 0) n.toString() else "%.1f".format(Locale.US, v)) + " " + units[i]
    }

    /**
     * An account in the sheet's words (the desktop's account box): its type,
     * how the WARP+ key went (its last four only), Cloudflare's premium_data /
     * quota / usage under their own names — their meaning is not documented,
     * so never "remaining" — and the devices on it. [size] shows a byte count.
     */
    fun accountLines(info: AccountInfo, size: (Long) -> String = { n: Long -> humanBytes(n) }): List<String> {
        if (info.imported) return listOf("Imported — Cloudflare’s account details are not known for it")
        val out = ArrayList<String>()
        out.add("Type: " + typeLabel(info.type))
        val tail = if (info.licenseTail.isNotEmpty()) " …${info.licenseTail}" else ""
        if (info.license == "applied") {
            out.add("WARP+ key$tail: applied")
            if (info.type == "free") out.add("The key was accepted, but the account is still free")
        } else if (info.license == "refused") {
            out.add("WARP+ key$tail: refused" + (if (info.licenseError.isNotEmpty()) " — ${info.licenseError}" else ""))
        } else {
            out.add("No WARP+ key")
        }
        val shown = listOf("premium_data" to info.premiumData, "quota" to info.quota, "usage" to info.usage)
            .joinToString(" · ") { p: Pair<String, Long?> -> p.first + " " + (p.second?.let { v: Long -> size(v) } ?: "—") }
        out.add(shown)
        val d = info.devices
        if (d != null) out.add("Devices on this account: $d")
        return out
    }

    /* -------------------------------- the whole sign-up -------------------------------- */

    /**
     * The sheet's choices: the [kind] (MASQUE when absent, as every caller
     * before v1.26), a new account — direct / through the connection, [count]
     * accounts with [licenses] (or the older single [license]) — or an import,
     * and step 2: MASQUE's [options] or WireGuard's [wg].
     */
    class AddArgs(
        val mode: String = "new", val license: String = "", val via: String = "direct",
        val importText: String = "", val options: Options = Options(),
        val kind: String = Warp.KIND_MASQUE, val count: Int = 1, val licenses: List<String> = emptyList(),
        val wg: WgOptions = WgOptions()
    )

    /** One account of a sign-up: its label, its servers' ids, its chain (a WireGuard WARP over a hop), what Cloudflare says of it, its warnings. */
    class AccountResult(
        val name: String, val serverIds: List<String>, val chainId: String?, val chainName: String?,
        val info: AccountInfo, val warnings: List<Warning>
    )

    /** A batch Cloudflare stopped part-way: why ([code], [error], [detail]) and how far it got ([made] of [wanted]). */
    class Stopped(val code: String, val error: String, val detail: String, val made: Int, val wanted: Int)

    /**
     * `ok` with the servers made (not saved yet) and the chains (not saved
     * either), each account, the first account (as before v1.26), every
     * account's warnings with its name, and [stopped] when a batch stopped
     * early; or a [code] with the message and its detail — nothing made.
     */
    class AddResult(
        val ok: Boolean, val added: List<ServerConfig> = emptyList(), val account: Account? = null,
        val warnings: List<Warning> = emptyList(), val code: String = "", val error: String = "", val detail: String = "",
        val accounts: List<AccountResult> = emptyList(), val addedChains: List<ChainConfig> = emptyList(), val stopped: Stopped? = null
    )

    /**
     * What the sign-up needs from the app: is it connected, the live SOCKS port,
     * the transport for a route, how a server is made, the clock and the log,
     * the servers and chains there are (names, hops), the pause between two
     * accounts. [request] replaces the transport, [pause] the wait (tests).
     */
    class Deps(
        val connected: () -> Boolean = { false },
        val socksPort: () -> Int = { 0 },
        val request: ((Req) -> Res)? = null,
        val transport: (String, Int) -> ((Req) -> Res) = { via: String, port: Int -> Warp.okHttpTransport(via, port) },
        val createServer: (Map<String, String>) -> ServerConfig = { m: Map<String, String> -> Warp.createServer(m) },
        val now: () -> Long = { System.currentTimeMillis() },
        val log: (String, String) -> Unit = { _: String, _: String -> },
        val getServers: () -> List<ServerConfig> = { emptyList<ServerConfig>() },
        val getChains: () -> List<ChainConfig> = { emptyList<ChainConfig>() },
        val pause: (Long) -> Unit = { ms: Long -> Thread.sleep(ms) }
    )

    private fun secretsOf(r: Reg): List<String> = listOf(r.privateKey, pemBody(r.privateKey))

    /** One account made: its label, its servers, its chain, what Cloudflare says of it. */
    private class Built(
        val name: String, val added: List<ServerConfig>, val chain: ChainConfig?,
        val info: AccountInfo, val warnings: List<Warning>, val account: Account
    )

    /**
     * The whole sign-up (warp.js addWarp, warp-wg/design.md §1-2): every
     * choice checked before the first registration (a typo costs no device);
     * "through the connection" needs one. The accounts are made one after
     * another, a pause between; the first failing fails the call, a later one
     * stops the batch and keeps what was made ([AddResult.stopped]). Each
     * account's servers carry what Cloudflare said of it (`warp`); a chained
     * WireGuard WARP gets its chain. Nothing is saved here — the caller adds
     * [AddResult.added] and [AddResult.addedChains] to the store. Blocking —
     * run it off the main thread.
     */
    fun addWarp(a: AddArgs, deps: Deps = Deps()): AddResult {
        val kind = if (a.kind.trim().lowercase() == KIND_WIREGUARD) KIND_WIREGUARD else KIND_MASQUE
        val secrets = ArrayList<String>()
        val accounts = ArrayList<Built>()
        var stopped: Stopped? = null
        var last: Reg? = null

        // one account's servers (and its chain): createServer for each, the account kept on them
        fun build(reg: Reg, label: String, hop: Hop?): Built {
            val o = a.options
            val fields: List<Map<String, String>> = if (kind == KIND_WIREGUARD) {
                listOf(wgServerFields(reg, a.wg, label))
            } else {
                warpServers(reg, Options(http = o.http, endpoint = o.endpoint, address = o.address, cover = o.cover, antiDpi = o.antiDpi, name = label))
            }
            val made = ArrayList<ServerConfig>()
            try {
                for (m in fields) made.add(deps.createServer(m))
            } catch (e: Exception) {
                val why = scrub(e.message ?: e.toString(), secrets + secretsOf(reg))
                throw WarpError("createFailed", "The servers could not be made: $why", why)
            }
            val info = reg.info ?: AccountInfo(kind = kind, imported = true)
            val added = made.map { s: ServerConfig -> s.copy(warp = info) }
            val chain: ChainConfig? = if (hop != null) ChainConfig(chainId(deps.now), "${hop.name} → $label", hop.members + added[0].id) else null
            val chained = if (chain != null) "; chain ${chain.name}" else ""
            deps.log("WARP: " + (if (added.size == 1) "one server" else "${added.size} servers") + " added (" +
                added.joinToString(", ") { s: ServerConfig -> s.name } + ")" + chained, "info")
            return Built(label, added, chain, info, reg.warnings, reg.account)
        }

        try {
            val servers = deps.getServers()
            val chains = deps.getChains()
            // checked first, so a typo costs no device; warpServers / wgServerFields check the same options again
            val wg: WgChecked? = if (kind == KIND_WIREGUARD) wgOptions(a.wg) else null
            val masque: Checked? = if (kind == KIND_MASQUE) warpOptions(a.options) else null
            val hop: Hop? = if (wg != null && wg.use == "chain") resolveHop(wg.chainWith, servers, chains) else null
            val base = (wg?.name ?: masque?.name ?: "").ifEmpty { BASE_NAME }
            val names = servers.map { s: ServerConfig -> s.name }
            if (a.mode == "import") {
                val label = accountLabels(1, base, names)[0]
                if (kind == KIND_WIREGUARD) {
                    val info = AccountInfo(kind = KIND_WIREGUARD, imported = true)
                    val server = importWg(a.importText).copy(name = label, warp = info)
                    val chain: ChainConfig? = if (hop != null) ChainConfig(chainId(deps.now), "${hop.name} → $label", hop.members + server.id) else null
                    val chained = if (chain != null) "; chain ${chain.name}" else ""
                    deps.log("WARP: a WireGuard account was imported ($label)$chained", "info")
                    accounts.add(Built(label, listOf(server), chain, info, emptyList(), Account("", "", false)))
                } else {
                    val reg = importWarp(a.importText)
                    last = reg
                    deps.log("WARP: an existing account was imported", "info")
                    accounts.add(build(reg, label, null))
                }
            } else {
                val plan = licensePlan(a.licenses, a.license, a.count)
                for (k in plan.keys) {
                    if (k.isNotEmpty() && !secrets.contains(k)) secrets.add(k)
                }
                val via = if (a.via == "proxy") "proxy" else "direct"
                if (via == "proxy" && !deps.connected()) {
                    throw WarpError("notConnected", "Registering through the app's connection needs one: connect to a server first")
                }
                val request = deps.request ?: deps.transport(via, if (via == "proxy") deps.socksPort() else 0)
                val labels = accountLabels(plan.count, base, names)
                val what = if (plan.count == 1) "one account" else "${plan.count} accounts"
                val how = if (kind == KIND_WIREGUARD) "WireGuard" else "MASQUE"
                deps.log("WARP: signing up $what ($how) " + (if (via == "proxy") "through the app's connection" else "directly"), "info")
                for (i in 0 until plan.count) {
                    if (i > 0) deps.pause(PAUSE_MS)
                    if (plan.count > 1) deps.log("WARP: account ${i + 1} of ${plan.count}", "info")
                    var reg: Reg? = null
                    try {
                        val r: Reg = if (kind == KIND_WIREGUARD) registerWarpWg(request, plan.keys[i], deps.now, deps.log) else registerWarp(request, plan.keys[i], deps.now, deps.log)
                        reg = r
                        last = r
                        accounts.add(build(r, labels[i], hop))
                    } catch (e: Exception) {
                        if (accounts.isEmpty()) throw e
                        val err = e as? WarpError ?: WarpError("failed", e.message ?: e.toString())
                        val held = reg
                        val hidden: List<String> = if (held != null) secrets + secretsOf(held) else secrets.toList()
                        val message = scrub(err.message, hidden)
                        val detail = err.detail?.takeIf { d: String -> d.isNotEmpty() }?.let { d: String -> scrub(d, hidden) } ?: message
                        stopped = Stopped(err.code, message, detail, accounts.size, plan.count)
                        deps.log("WARP: stopped after ${accounts.size} of ${plan.count} accounts — $message", "warn")
                        break
                    }
                }
            }
            val first = accounts.firstOrNull() ?: throw WarpError("failed", "No account was made")
            val results = accounts.map { x: Built ->
                AccountResult(x.name, x.added.map { s: ServerConfig -> s.id }, x.chain?.id, x.chain?.name, x.info, x.warnings)
            }
            // every account's warnings, each with its account's name
            val flat = accounts.flatMap { x: Built -> x.warnings.map { w: Warning -> w.copy(name = x.name) } }
            return AddResult(true, added = accounts.flatMap { x: Built -> x.added }, account = first.account, warnings = flat,
                accounts = results, addedChains = accounts.mapNotNull { x: Built -> x.chain }, stopped = stopped)
        } catch (e: Exception) {
            val err = e as? WarpError ?: WarpError("failed", e.message ?: e.toString())
            val held = last
            val hidden: List<String> = if (held != null) secrets + secretsOf(held) else secrets.toList()
            val message = scrub(err.message, hidden)
            try { deps.log("WARP: $message", "warn") } catch (x: Exception) { /* never fails the answer */ }
            val detail = err.detail?.takeIf { d: String -> d.isNotEmpty() }?.let { d: String -> scrub(d, hidden) } ?: message
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
