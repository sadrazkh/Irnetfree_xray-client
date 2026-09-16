package com.irnetfree.vpn.core

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.net.URLEncoder

/**
 * Port of src/main/trustedDns.js — resolving a name without believing the
 * network.
 *
 * The phone's own resolver is the one thing this app cannot trust: a fake-IP
 * gateway answers EVERY name from 198.18.0.0/15, a filtered carrier answers
 * with its block page. Neither is a lookup failure the caller can see — it is a
 * plausible address that connects to the wrong machine. So: ask the OS first
 * (instant, and on a sane network right), and when every answer falls in a
 * range no public server can be in, ask a DoH resolver over HTTPS instead. The
 * DoH URL must name a literal IP (resolving the resolver would need the
 * resolver we do not trust) and its certificate is verified by the platform, so
 * the middlebox that rewrites DNS cannot answer for it either.
 *
 * Every call blocks — run it off the main thread.
 */
object TrustedDns {
    val DEFAULT_DOH = listOf("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query")

    /** Result of a lookup: the addresses, where they came from, and what the OS said if it was unusable. */
    class Result(val ips: List<String>, val source: String, val suspect: List<String>)

    /** [base, prefix bits]: ranges no public server's A record can legitimately be in. */
    private val SUSPECT4 = listOf(
        "0.0.0.0" to 8, "10.0.0.0" to 8, "100.64.0.0" to 10, "127.0.0.0" to 8,
        "169.254.0.0" to 16, "172.16.0.0" to 12, "192.0.2.0" to 24, "192.168.0.0" to 16,
        // 198.18.0.0/15 is the benchmarking range every fake-IP gateway hands out.
        "198.18.0.0" to 15, "198.51.100.0" to 24, "203.0.113.0" to 24,
        "224.0.0.0" to 4, "240.0.0.0" to 4
    )

    private fun v4num(ip: String): Long? {
        val p = ip.split(".")
        if (p.size != 4) return null
        var n = 0L
        for (part in p) {
            val b = part.toIntOrNull() ?: return null
            if (part.length !in 1..3 || b > 255) return null
            n = n * 256 + b
        }
        return n
    }

    /** True when an address cannot be a public server. A LAN address is in here too, so this is only ever a reason to ask a second resolver. */
    fun isSuspect(ip: String?): Boolean {
        val s = (ip ?: "").trim()
        if (DnsPlan.isIpv4(s)) {
            val n = v4num(s) ?: return true
            return SUSPECT4.any { (base, bits) ->
                val mask = if (bits == 0) 0L else ((0xFFFFFFFFL shl (32 - bits)) and 0xFFFFFFFFL)
                (n and mask) == ((v4num(base) ?: 0L) and mask)
            }
        }
        if (DnsPlan.isIpv6(s)) {
            val low = s.lowercase()
            return low == "::" || low == "::1" || low.startsWith("fc") || low.startsWith("fd") ||
                Regex("^fe[89ab]").containsMatchIn(low) || low.startsWith("2001:db8:")
        }
        return true
    }

    /** One DoH question over the JSON API (Cloudflare, Google, Quad9, AdGuard). Empty on any failure. */
    fun dohQuery(url: String, host: String, type: String, timeoutMs: Int = 2500): List<String> {
        val u = try { URL(url) } catch (e: Exception) { return emptyList() }
        val urlHost = u.host.removePrefix("[").removeSuffix("]")
        // No bootstrap: a DoH server named by hostname would have to be resolved
        // by the resolver we are trying not to trust.
        if (u.protocol != "https" || !DnsPlan.isIp(urlHost)) return emptyList()
        val sep = if (u.query.isNullOrEmpty()) "?" else "&"
        val full = "$url${sep}name=${URLEncoder.encode(host, "UTF-8")}&type=$type"
        var c: HttpURLConnection? = null
        return try {
            c = URL(full).openConnection() as HttpURLConnection
            c.connectTimeout = timeoutMs; c.readTimeout = timeoutMs
            c.setRequestProperty("accept", "application/dns-json")
            c.setRequestProperty("User-Agent", "IRNetFree/Android")
            if (c.responseCode != 200) return emptyList()
            val body = c.inputStream.bufferedReader().use { it.readText() }
            val want = if (type == "AAAA") 28 else 1
            val answers = JSONObject(body).optJSONArray("Answer") ?: return emptyList()
            val out = ArrayList<String>()
            for (i in 0 until answers.length()) {
                val a = answers.optJSONObject(i) ?: continue
                val data = a.optString("data")
                if (a.optInt("type") == want && DnsPlan.isIp(data) && data !in out) out.add(data)
            }
            out
        } catch (e: Exception) { emptyList() } finally { runCatching { c?.disconnect() } }
    }

    private fun dohLookup(host: String, ipv6: Boolean, doh: List<String>, timeoutMs: Int, query: (String, String, String) -> List<String>): List<String> {
        val types = if (ipv6) listOf("A", "AAAA") else listOf("A")
        for (url in doh) {
            val out = ArrayList<String>()
            for (type in types) for (ip in query(url, host, type)) if (ip !in out) out.add(ip)
            if (out.isNotEmpty()) return out
        }
        return emptyList()
    }

    /**
     * @param host    a hostname, or a literal address (returned as is)
     * @param ipv6    also ask for AAAA
     * @param doh     DoH URLs to fall back to (only https:// with a literal host count)
     * @param lookup  the OS lookup (injectable for tests); throws or returns [] on failure
     * @param query   the DoH question (injectable for tests)
     * @return source: "literal" | "os" | "doh" (the OS answer was unusable) | "os-suspect" (no second opinion) | "none"
     */
    fun resolveHost(
        host: String?, ipv6: Boolean = false, doh: List<String>? = null, timeoutMs: Int = 2500,
        lookup: ((String) -> List<String>)? = null,
        query: ((String, String, String) -> List<String>)? = null
    ): Result {
        val h = (host ?: "").trim()
        if (h.isEmpty()) return Result(emptyList(), "none", emptyList())
        if (DnsPlan.isIp(h)) return Result(listOf(h), "literal", emptyList())
        val servers = (if (doh.isNullOrEmpty()) DEFAULT_DOH else doh).filter { it.lowercase().startsWith("https://") }
        val os: (String) -> List<String> = lookup ?: { name: String ->
            InetAddress.getAllByName(name).mapNotNull { it.hostAddress }
                .filter { ipv6 || DnsPlan.isIpv4(it) }
                .map { it.substringBefore('%') }
        }
        val q: (String, String, String) -> List<String> = query ?: { url: String, name: String, type: String -> dohQuery(url, name, type, timeoutMs) }

        val osIps = try { os(h) } catch (e: Exception) { emptyList() }
        val clean = osIps.filter { !isSuspect(it) }
        if (clean.isNotEmpty()) return Result(clean, "os", emptyList())

        val fromDoh = dohLookup(h, ipv6, servers, timeoutMs, q)
        val cleanDoh = fromDoh.filter { !isSuspect(it) }
        if (cleanDoh.isNotEmpty()) return Result(cleanDoh, "doh", osIps)
        if (osIps.isNotEmpty()) return Result(osIps, "os-suspect", osIps)
        return Result(fromDoh, if (fromDoh.isNotEmpty()) "doh" else "none", emptyList())
    }
}
