package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import java.net.IDN

/**
 * What the core may read from a connection, and what a domain rule's text means:
 * src/main/sniffRules.js, whose header says why. SniffRulesTest.kt and
 * tests/sniffRules.test.js hold the same cases.
 */
object SniffRules {
    /** Iran's DNS poison answers with these private addresses: a connection to one stays sniffed. */
    private const val POISON = "10.10.34.32"
    private const val POISON_BITS = 29

    private val V4 = Regex("""^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$""")
    private val V6_CHARS = Regex("""^[0-9a-fA-F:.]+$""")
    private val MASK = Regex("""^\d{1,3}$""")
    private val CORE_PREFIX = Regex("""^(domain|full|keyword|regexp|geosite|ext|dotless):""", RegexOption.IGNORE_CASE)
    private val SCHEME = Regex("""^[a-zA-Z][a-zA-Z0-9+.-]*://""")
    private val STAR_DOT = Regex("""^\*\.+[^*]+$""")

    private fun isV4(s: String): Boolean {
        val m = V4.find(s) ?: return false
        return m.groupValues.drop(1).all { p: String -> p.toInt() <= 255 && (p.length == 1 || !p.startsWith("0")) }
    }

    private fun isV6(s: String): Boolean {
        if (!s.contains(":") || !V6_CHARS.matches(s)) return false
        return try {
            // a literal with a colon is parsed, never looked up
            java.net.InetAddress.getByName(s) != null
        } catch (e: Exception) {
            false
        }
    }

    /** Is this an address or a CIDR the core can read: a geoip: name, a range `a-b` or a typo is not? */
    fun isIpLiteral(value: String?): Boolean {
        val parts = (value ?: "").trim().split("/")
        if (parts.size > 2) return false
        val v4 = isV4(parts[0])
        if (!v4 && !isV6(parts[0])) return false
        if (parts.size == 1) return true
        return MASK.matches(parts[1]) && parts[1].toInt() <= (if (v4) 32 else 128)
    }

    private fun v4ToLong(ip: String): Long = ip.split(".").fold(0L) { n: Long, x: String -> n * 256 + x.toLong() }
    private fun longToV4(n: Long): String = listOf(24, 16, 8, 0).joinToString(".") { s: Int -> ((n shr s) and 255).toString() }

    /** Wider than this is the internet, not a host: an IP rule for 0.0.0.0/0 must not stop every name being read. */
    private fun tooWide(cidr: String): Boolean {
        val parts = cidr.split("/")
        if (parts.size != 2) return false
        return parts[1].toInt() < (if (isV4(parts[0])) 8 else 7)
    }

    /** A v4 CIDR around the poison addresses, as the CIDRs that cover the rest of it. Anything else stays as it is. */
    private fun withoutPoison(cidr: String): List<String> {
        val parts = cidr.split("/")
        if (parts.size != 2 || !isV4(parts[0])) return listOf(cidr)
        val bits = parts[1].toInt()
        if (bits >= POISON_BITS) return listOf(cidr)
        val hostBits = 32 - bits
        val target = v4ToLong(POISON)
        if ((v4ToLong(parts[0]) shr hostBits) != (target shr hostBits)) return listOf(cidr)
        val out = ArrayList<String>()
        for (b in (bits + 1)..POISON_BITS) {
            val shift = 32 - b
            val sibling = ((target shr shift) xor 1L) shl shift
            out.add("${longToV4(sibling)}/$b")
        }
        return out
    }

    /** `sniffing.ipsExcluded` for these addresses: the ones a core can read and that are not the whole internet, once each, with the poison addresses cut out of any range around them. */
    fun excludedIps(values: List<String>): List<String> {
        val out = LinkedHashSet<String>()
        for (v in values) {
            val s = v.trim()
            if (!isIpLiteral(s) || tooWide(s)) continue
            out.addAll(withoutPoison(s))
        }
        return out.toList()
    }

    private fun escapeRegexp(s: String): String {
        val b = StringBuilder()
        for (c in s) {
            if (".+?^\${}()|[]\\".indexOf(c) >= 0) b.append('\\')
            b.append(c)
        }
        return b.toString()
    }

    private fun toAscii(name: String): String {
        if (name.all { c: Char -> c.code < 128 }) return name
        return try {
            IDN.toASCII(name)
        } catch (e: Exception) {
            name
        }
    }

    /**
     * One value of a domain rule as the core must read it. To the core a bare
     * string is a substring and a `*` an ordinary character. A prefix the core
     * knows stays as written. Otherwise: an address pasted whole is its host;
     * `example.com`, `.example.com` and `*.example.com` are that name and
     * everything under it; any other `*` is a wildcard over the whole name; a word
     * with no dot is the core's own substring.
     */
    fun normalizeDomain(value: String?): String? {
        val raw = (value ?: "").trim()
        if (raw.isEmpty()) return null
        val prefix = CORE_PREFIX.find(raw)
        if (prefix != null) return prefix.groupValues[1].lowercase() + raw.substring(prefix.groupValues[1].length)
        var v = raw.replaceFirst(SCHEME, "")
        val cut = v.indexOfFirst { c: Char -> c == '/' || c == '?' || c == '#' }
        if (cut >= 0) v = v.substring(0, cut)
        v = v.replaceFirst(Regex(""":\d+$"""), "").trimEnd('.').lowercase()
        if (v.isEmpty()) return null
        if (STAR_DOT.matches(v)) {
            v = v.substring(1).trimStart('.')
        } else if (v.contains("*")) {
            return "regexp:^" + v.split("*").joinToString(".*") { p: String -> escapeRegexp(p) } + "$"
        }
        v = v.trimStart('.')
        if (v.isEmpty()) return null
        v = toAscii(v)
        return if (v.contains(".")) "domain:$v" else v
    }

    /** A domain rule's values for the core, once each. */
    fun normalizeDomains(values: List<String>): List<String> {
        val out = LinkedHashSet<String>()
        for (v in values) {
            val n = normalizeDomain(v)
            if (n != null) out.add(n)
        }
        return out.toList()
    }

    /** Does a name, in these rules from [from] on, send something away from where it would go anyway? */
    fun namesDecide(rules: JSONArray, from: Int, defaultTag: String): Boolean {
        for (i in from until rules.length()) {
            val r = rules.getJSONObject(i)
            if (r.has("domain") && r.optString("outboundTag") != defaultTag) return true
        }
        return false
    }

    /**
     * The two rules right before the catch-all when a name decides: a QUIC with a
     * name goes on as usual, one whose name could not be read is refused, and a
     * browser falls back to TCP, where the name is always read.
     */
    fun quicFallbackRules(defaultTag: String): List<JSONObject> = listOf(
        JSONObject().put("type", "field").put("network", "udp").put("port", "443")
            .put("domain", JSONArray().put("regexp:.")).put("outboundTag", defaultTag),
        JSONObject().put("type", "field").put("network", "udp").put("port", "443").put("outboundTag", "block")
    )
}
