package com.irnetfree.vpn.core

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * What a link the app was opened with, or a text shared to it, asks for — and
 * nothing more: the caller shows it and asks before anything is added, and
 * nothing here ever connects. Pure, so the rules run off a device; the desktop's
 * src/main/deepLink.js has the same rules and the same test cases.
 *
 *   irnetfree://routing/<…>                    the routing preview (RouteShare), the link as it is
 *   irnetfree://import/<percent-encoded text>  a subscription URL or a config link, decoded
 *   irnetfree://import?url=<encoded>[&name=…]  the same, with a name for a subscription
 *   vless://… https://…                        a bare link, opened with the app
 *
 * A payload is one line: an http(s) URL with a host that LinkParser.isSubUrl
 * calls a subscription ([SUB], with its host — never its path, which is the
 * secret), or a link of a scheme this app imports ([CONFIG]). Anything else —
 * file:, javascript:, intent:, content:, nothing, several lines, over
 * [MAX_LEN] characters, a control character, any other irnetfree:// path — is
 * null. No android.net.Uri here: the percent-decoding is the JavaScript
 * decodeURIComponent's (a `+` stays a `+`, as a base64 vmess body needs), so
 * both clients read one link the same way.
 */
object DeepLink {
    const val SUB = "sub"
    const val CONFIG = "config"
    const val ROUTING = "routing"

    /** The most a payload may be; a shared text keeps at most this many lines. */
    const val MAX_LEN = 8192
    const val MAX_SHARED = 50

    const val SCHEME = "irnetfree://"
    private const val IMPORT = "import"
    private const val ROUTING_PREFIX = 20   // irnetfree://routing/
    private val NAME_CONTROLS = Regex("[\\u0000-\\u001f\\u007f\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]")
    private val NAME_SPACES = Regex("\\s+")
    private val CONFIG_LINK = Regex("^(vless|vmess|trojan|ss|socks|socks5|wireguard|wg|tuic|anytls|hysteria2|hy2)://\\S", RegexOption.IGNORE_CASE)

    /** One thing asked for: its [kind], the text to import ([ROUTING]: the whole link), a subscription's [host], and a [name] when the link gave one. */
    data class Item(val kind: String, val text: String, val host: String = "", val name: String = "")

    /** A link the app was opened with (ACTION_VIEW): an irnetfree:// link by its rules, any other by [classify]. */
    fun parse(link: String): Item? {
        val l = link.trim()
        if (!l.startsWith(SCHEME, ignoreCase = true)) return classify(l)
        if (RouteShare.looksLikeShare(l)) return if (singleLine(l) && l.length > ROUTING_PREFIX) Item(ROUTING, l) else null
        val rest = l.substring(SCHEME.length)
        var end = rest.indexOfFirst { c: Char -> c == '/' || c == '?' || c == '#' }
        if (end < 0) end = rest.length
        if (!rest.substring(0, end).equals(IMPORT, ignoreCase = true)) return null
        var tail = rest.substring(end)
        if (tail.startsWith("/")) tail = tail.substring(1)
        if (tail.isEmpty() || tail.startsWith("#")) return null
        if (tail.startsWith("?")) {
            // the query form: a fragment is not part of it (a browser drops one the same way)
            val q = query(tail.substring(1).substringBefore('#')) ?: return null
            val item = classify(q["url"] ?: return null) ?: return null
            val name = cleanName(q["name"] ?: "")
            return if (name.isEmpty()) item else Item(item.kind, item.text, item.host, name)
        }
        // the path form: everything after import/ is the payload, so a `?` or `#` the
        // sender left unencoded still belongs to the link inside
        return classify(pctDecode(tail) ?: return null)
    }

    /**
     * What one payload is — [SUB], [CONFIG] — or null. A sub URL that is an HTTP
     * proxy link (LinkParser.isHttpProxyLink) is neither here: `http` is not a
     * scheme the contract imports as a config, and it is not a subscription.
     */
    fun classify(payload: String): Item? {
        val s = payload.trim()
        if (s.isEmpty() || s.length > MAX_LEN || !singleLine(s)) return null
        if (s.startsWith("http://", ignoreCase = true) || s.startsWith("https://", ignoreCase = true)) {
            // a backslash ends the host for some parsers and not for others, so the host shown might not be the host fetched
            if (!LinkParser.isSubUrl(s) || s.contains('\\')) return null
            val host = hostOf(s) ?: return null
            return Item(SUB, s, host)
        }
        return if (CONFIG_LINK.containsMatchIn(s)) Item(CONFIG, s) else null
    }

    /**
     * Text shared to the app (ACTION_SEND): the lines that classify, at most
     * [MAX_SHARED] of them, in order; null when none does. One irnetfree:// link
     * shared whole is read as if it had been opened — a routing link included.
     */
    fun fromShared(text: String): List<Item>? {
        val t = text.trim()
        if (t.isEmpty()) return null
        if (t.startsWith(SCHEME, ignoreCase = true) && singleLine(t)) return parse(t)?.let { i: Item -> listOf(i) }
        val out = ArrayList<Item>()
        for (line in t.split(Regex("[\\r\\n]+"))) {
            val item = classify(line) ?: continue
            out.add(item)
            if (out.size >= MAX_SHARED) break
        }
        return if (out.isEmpty()) null else out
    }

    /**
     * A name a link brought, as the question may show it: one line, with no bidi
     * control. Otherwise a page could write lines of its own under the question,
     * or turn the rest of the line around.
     */
    internal fun cleanName(name: String): String = name.replace(NAME_CONTROLS, " ").replace(NAME_SPACES, " ").trim().take(60)

    /** No control character — which rules out a second line, a tab, a NUL. */
    private fun singleLine(s: String): Boolean = s.none { c: Char -> c < ' ' || c == '\u007f' }

    /** The host of an http(s) URL, lowercased, without its login or port; null when there is none (or it holds a space). */
    internal fun hostOf(url: String): String? {
        val at = url.indexOf("://")
        if (at < 0) return null
        val rest = url.substring(at + 3)
        var end = rest.indexOfFirst { c: Char -> c == '/' || c == '?' || c == '#' }
        if (end < 0) end = rest.length
        var auth = rest.substring(0, end)
        auth = auth.substring(auth.lastIndexOf('@') + 1)
        val host = if (auth.startsWith("[")) {
            val close = auth.indexOf(']')
            if (close < 0) return null
            auth.substring(0, close + 1)
        } else auth.substringBefore(':')
        if (host.isEmpty() || host.any { c: Char -> c.isWhitespace() }) return null
        if (host.startsWith("[")) return host.lowercase()
        // what is shown is what will be dialled: a look-alike in another alphabet comes out as xn--
        return try { java.net.IDN.toASCII(host).lowercase() } catch (e: IllegalArgumentException) { null }
    }

    /** `k=v&k=v`, each side percent-decoded; null when any of it is malformed. The first value of a repeated key wins. */
    private fun query(q: String): Map<String, String>? {
        val out = LinkedHashMap<String, String>()
        for (pair in q.split('&')) {
            if (pair.isEmpty()) continue
            val eq = pair.indexOf('=')
            val k = pctDecode(if (eq < 0) pair else pair.substring(0, eq)) ?: return null
            val v = pctDecode(if (eq < 0) "" else pair.substring(eq + 1)) ?: return null
            if (k !in out) out[k] = v
        }
        return out
    }

    /**
     * decodeURIComponent: every %XX is a byte, the bytes are UTF-8, and a `+` is
     * a `+`. A lone `%`, a non-hex digit or bytes that are not UTF-8 → null, as
     * the JavaScript throws.
     */
    internal fun pctDecode(s: String): String? {
        if (s.indexOf('%') < 0) return s
        val bytes = ByteArrayOutputStream()
        val run = StringBuilder()
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c != '%') { run.append(c); i++; continue }
            if (i + 2 >= s.length) return null
            val hi = Character.digit(s[i + 1], 16)
            val lo = Character.digit(s[i + 2], 16)
            if (hi < 0 || lo < 0) return null
            if (run.isNotEmpty()) { bytes.write(run.toString().toByteArray(Charsets.UTF_8)); run.setLength(0) }
            bytes.write(hi * 16 + lo)
            i += 3
        }
        if (run.isNotEmpty()) bytes.write(run.toString().toByteArray(Charsets.UTF_8))
        return try {
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes.toByteArray())).toString()
        } catch (e: CharacterCodingException) {
            null
        }
    }
}
