package com.irnetfree.vpn.core

import okhttp3.ConnectionSpec
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException

/**
 * Fetches a subscription URL and parses it into servers + usage info.
 *
 * Two things make this harder on a phone than on the desktop, and both caused
 * the same symptom — a TLS handshake that fails while the very same URL loads
 * on Windows:
 *
 *  1. THE TUNNEL. Our own package is excluded from the VPN (XrayVpnService
 *     applyPerApp) so the core's own sockets can leave the device; that
 *     exclusion applies to every socket this app opens, including this one. So
 *     a subscription fetch goes out over the raw ISP network even while the
 *     tunnel is up — where the desktop, whose whole system is inside the TUN,
 *     fetches the same URL through it. A middlebox that answers a censored
 *     panel's handshake then breaks the phone and not the laptop. When the
 *     tunnel is up we now dial through the core's own SOCKS inbound, which is
 *     what the desktop effectively does. Diagnostics.kt has had this note for
 *     the IP check since the beginning; the subscription fetch never got it.
 *
 *  2. THE RESOLVER. Off the tunnel, the name is resolved by the phone — and on
 *     a fake-IP network every name answers from 198.18.0.0/15, so the handshake
 *     goes to a machine that was never the panel. TrustedDns is asked instead:
 *     the OS first, a DoH server over HTTPS when every OS answer is in a range
 *     no public server can be in. (Through the SOCKS proxy this does not apply:
 *     OkHttp leaves the name unresolved for a SOCKS route on purpose, so the
 *     core resolves it at the far end, which is better still.)
 *
 * TLS stays permissive (MODERN + COMPATIBLE + CLEARTEXT) because many panels
 * are old. A v2rayNG-style User-Agent makes them return the base64 config list
 * AND the Subscription-Userinfo usage header.
 */
object Subscriptions {

    data class Usage(val upload: Long, val download: Long, val total: Long, val expire: Long)
    data class Result(val servers: List<ServerConfig>, val usage: Usage?, val errors: List<String>)

    /**
     * DoH first, the platform second — the opposite of TrustedDns's own order,
     * and deliberately so.
     *
     * TrustedDns believes the OS unless every answer lands in a range no public
     * server can be in (198.18/15 and friends). That catches a fake-IP gateway.
     * It does not catch what a subscription host actually gets, which is a
     * PUBLIC address belonging to the censor: perfectly routable, not suspect by
     * any test of the number itself, and the TLS handshake then fails because
     * the machine it reaches was never the panel. A subscription URL is exactly
     * the name worth spending one extra round trip on, so it is asked of a DoH
     * resolver over HTTPS — whose own certificate the platform verifies, so the
     * middlebox cannot answer for it either — and the OS is the fallback, not
     * the default.
     */
    internal object TrustedResolver : Dns {
        /** The last address set handed out, per host — for the failure report. */
        val lastSeen = HashMap<String, String>()

        override fun lookup(hostname: String): List<InetAddress> {
            val doh = dohAddresses(hostname)
            val chosen = if (doh.isNotEmpty()) doh else TrustedDns.resolveHost(hostname, ipv6 = true).ips
            val ips = chosen.mapNotNull { runCatching { InetAddress.getByName(it) }.getOrNull() }
            val via = if (doh.isNotEmpty()) "doh" else "os"
            // Nothing usable: the platform lookup, so this can only ever add
            // answers and never remove ones that already worked.
            if (ips.isEmpty()) return Dns.SYSTEM.lookup(hostname)
            synchronized(lastSeen) { lastSeen[hostname] = ips.joinToString(", ") { it.hostAddress ?: "?" } + " ($via)" }
            return ips
        }

        private fun dohAddresses(hostname: String): List<String> {
            if (DnsPlan.isIp(hostname)) return listOf(hostname)
            for (url in TrustedDns.DEFAULT_DOH) {
                val out = ArrayList<String>()
                for (type in listOf("A", "AAAA")) {
                    for (ip in TrustedDns.dohQuery(url, hostname, type, 4000)) if (ip !in out) out.add(ip)
                }
                if (out.isNotEmpty()) return out
            }
            return emptyList()
        }
    }

    private fun clientFor(socksPort: Int?): OkHttpClient {
        val b = OkHttpClient.Builder()
            .connectTimeout(20, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .callTimeout(35, TimeUnit.SECONDS)
            .followRedirects(true).followSslRedirects(true)
            .retryOnConnectionFailure(true)
            .connectionSpecs(listOf(ConnectionSpec.MODERN_TLS, ConnectionSpec.COMPATIBLE_TLS, ConnectionSpec.CLEARTEXT))
        if (socksPort != null && socksPort > 0) {
            b.proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort)))
        } else {
            b.dns(TrustedResolver)
        }
        return b.build()
    }

    // One client per shape, so connections and the pool are reused across refreshes.
    private val direct: OkHttpClient by lazy { clientFor(null) }
    private var tunnelled: Pair<Int, OkHttpClient>? = null
    @Synchronized private fun client(socksPort: Int?): OkHttpClient {
        if (socksPort == null || socksPort <= 0) return direct
        tunnelled?.let { (port, c) -> if (port == socksPort) return c }
        val c = clientFor(socksPort)
        tunnelled = socksPort to c
        return c
    }

    /**
     * Blocking network call — run on Dispatchers.IO.
     *
     * Through the tunnel first when there is one, then directly. Both are worth
     * trying and neither is always right: a censored panel is only reachable
     * through the tunnel, while a panel that only serves domestic addresses is
     * only reachable off it. Whichever answers, answers; the error reported is
     * the one from the attempt that had the better chance.
     *
     * @param socksPort the core's local SOCKS inbound when the tunnel is up;
     *   null fetches directly and is then the only attempt.
     * @param call     the single request, injectable so the order above can be
     *   tested without a network.
     */
    fun fetch(url: String, socksPort: Int? = null, call: (String, Int?) -> Result = ::attempt): Result {
        val viaTunnel = socksPort != null && socksPort > 0
        if (!viaTunnel) {
            try { return call(url, null) } catch (e: Exception) { throw RuntimeException(explain(e, null) + whoAnswered(url, e), e) }
        }
        return try {
            call(url, socksPort)
        } catch (tunnelFailure: Exception) {
            try {
                call(url, null)
            } catch (directFailure: Exception) {
                // Say both, in the order the user should act on them.
                throw RuntimeException(
                    explain(tunnelFailure, socksPort) + "  Off the tunnel: " + explain(directFailure, null) + whoAnswered(url, directFailure),
                    tunnelFailure
                )
            }
        }
    }

    private fun attempt(url: String, socksPort: Int?): Result {
        val req = Request.Builder()
            .url(url.trim())
            .header("User-Agent", "v2rayNG/1.9.5")
            .header("Accept", "*/*")
            .build()
        client(socksPort).newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw RuntimeException("HTTP ${resp.code}")
            val body = resp.body?.string() ?: ""
            if (body.isBlank()) throw RuntimeException("empty response")
            val (servers, errors) = LinkParser.parseMany(body)
            // OkHttp header lookup is case-insensitive.
            val usage = parseUserInfo(resp.header("subscription-userinfo"))
            return Result(servers, usage, errors)
        }
    }

    /**
     * Turn a transport failure into the sentence that tells the user what to do.
     * "Handshake failed" on its own is what sent this bug round in circles: it
     * reads like a broken panel when it is the network in front of it.
     */
    internal fun explain(e: Exception, socksPort: Int?): String {
        val tunnelled = socksPort != null && socksPort > 0
        val hint = if (tunnelled) "Through the tunnel — try another server, or open the link in a browser to check the panel itself."
                   else "Over your normal network — connect first, or the panel may be blocked by your ISP."
        return when (e) {
            is SSLHandshakeException, is SSLException ->
                "TLS handshake failed — something answered for the panel and it was not the panel. $hint (${e.message ?: e.javaClass.simpleName})"
            is UnknownHostException ->
                "Could not resolve the subscription host. $hint"
            is SocketTimeoutException ->
                "Timed out reaching the subscription. $hint"
            is IOException ->
                "${e.message ?: "network error"} — $hint"
            else -> e.message ?: e.toString()
        }
    }

    /**
     * After a TLS failure, dial the host again with verification off and report
     * the certificate that came back. "Handshake failed" cannot distinguish a
     * censored panel from a broken one; the name on the certificate can. Also
     * reports the address we resolved to, since a poisoned answer is the other
     * half of the same story.
     */
    private fun whoAnswered(url: String, e: Exception): String {
        if (e !is SSLException) return ""
        val u = runCatching { java.net.URI(url.trim()) }.getOrNull() ?: return ""
        val host = u.host ?: return ""
        val port = if (u.port > 0) u.port else if (u.scheme.equals("http", true)) 80 else 443
        val resolved = synchronized(TrustedResolver.lastSeen) { TrustedResolver.lastSeen[host] }
        val cert = CertPin.describeLeaf(host, port, host)
        return "  [$host" + (if (resolved != null) " -> $resolved" else "") + "; $cert]"
    }

    // "upload=1234; download=5678; total=100000; expire=1699999999"
    private fun parseUserInfo(h: String?): Usage? {
        if (h.isNullOrBlank()) return null
        val m = HashMap<String, Long>()
        for (part in h.split(";")) {
            val kv = part.split("=")
            if (kv.size == 2) kv[0].trim().lowercase().let { k -> kv[1].trim().toLongOrNull()?.let { m[k] = it } }
        }
        if (m.isEmpty()) return null
        return Usage(m["upload"] ?: 0, m["download"] ?: 0, m["total"] ?: 0, m["expire"] ?: 0)
    }
}
