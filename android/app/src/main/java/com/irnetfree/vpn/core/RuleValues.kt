package com.irnetfree.vpn.core

/**
 * What a core can read of a routing rule's IP and port values (ConfigBuilder:
 * advanced routing's rules and the custom rules).
 *
 * Domain values were cleaned (SniffRules.normalizeDomains); IP and port values
 * went into the config as typed. One the core cannot read — `google.com` in an
 * IP rule (the rule editor keeps the value when its type changes from domain
 * to IP), `1.2.3.4/33`, `80-` — and Xray refuses the WHOLE config ("invalid
 * IP", "invalid port range"): the tunnel did not come up at all over one rule.
 * Such a value is left out now, and a connect says which (TunnelSetup.routingNotes).
 */
object RuleValues {
    /** An IP rule's value a core reads: an address or a CIDR (IPv4 /0–32, IPv6 /0–128), or a `geoip:` / `ext:` reference. */
    fun isIp(v0: String): Boolean {
        val v = v0.trim()
        if (v.startsWith("geoip:", ignoreCase = true) || v.startsWith("ext:", ignoreCase = true) || v.startsWith("ext-ip:", ignoreCase = true))
            return v.substringAfter(':').isNotBlank()
        val slash = v.indexOf('/')
        val host = if (slash >= 0) v.substring(0, slash) else v
        val prefix: Int? = if (slash >= 0) (v.substring(slash + 1).takeIf { p: String -> p.isNotEmpty() && p.all { c: Char -> c.isDigit() } }?.toIntOrNull() ?: return false) else null
        return when (Masque.ipFamily(host)) {
            4 -> prefix == null || prefix in 0..32
            6 -> prefix == null || prefix in 0..128
            else -> false
        }
    }

    /** A port rule's value a core reads: `443`, or a range `1000-2000` (0–65535, low ≤ high). */
    fun isPort(v0: String): Boolean {
        val parts = v0.trim().split('-')
        fun num(s: String): Int? = s.trim().takeIf { t: String -> t.isNotEmpty() && t.length <= 5 && t.all { c: Char -> c.isDigit() } }?.toInt()?.takeIf { n: Int -> n in 0..65535 }
        return when (parts.size) {
            1 -> num(parts[0]) != null
            2 -> { val a = num(parts[0]); val b = num(parts[1]); a != null && b != null && a <= b }
            else -> false
        }
    }

    /** The values of a rule of [type] a core reads; a domain rule's are another's to clean (SniffRules). */
    fun usable(type: String, vals: List<String>): List<String> = when (type) {
        "ip" -> vals.filter { v: String -> isIp(v) }
        "port" -> vals.filter { v: String -> isPort(v) }
        else -> vals
    }

    /** The values of a rule of [type] that would be left out ([usable]'s complement), as typed. */
    fun unusable(type: String, vals: List<String>): List<String> = when (type) {
        "ip" -> vals.filter { v: String -> !isIp(v) }
        "port" -> vals.filter { v: String -> !isPort(v) }
        else -> emptyList()
    }
}
