package com.irnetfree.vpn.net

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URL

/**
 * Ping / latency / egress-IP checks. All calls block — run on Dispatchers.IO.
 *
 * IMPORTANT: our own app is excluded from the VPN (so xray's sockets can bypass
 * the tunnel), which means a DIRECT request from us shows the real IP, not the
 * exit. To see the tunnel's exit we must go THROUGH the local SOCKS inbound — so
 * the IP/latency checks take a `socksPort` and dial via 127.0.0.1:socksPort when
 * connected.
 */
object Diagnostics {

    data class IpInfo(val ok: Boolean, val ip: String = "", val country: String = "", val countryCode: String = "", val isp: String = "", val error: String = "")

    /** TCP handshake time to host:port in ms, or -1 on failure. */
    fun tcpPing(host: String, port: Int, timeout: Int = 4000): Long {
        return try {
            val t0 = System.nanoTime()
            Socket().use { it.connect(InetSocketAddress(host, port), timeout) }
            (System.nanoTime() - t0) / 1_000_000
        } catch (e: Exception) { -1 }
    }

    /** Real HTTP round-trip. When `socksPort` is set, it goes through the tunnel. */
    fun httpLatency(socksPort: Int? = null, url: String = "https://cp.cloudflare.com/generate_204", timeout: Int = 9000): Long {
        return try {
            val t0 = System.nanoTime()
            val c = open(url, timeout, proxyFor(socksPort)); c.requestMethod = "GET"
            c.responseCode; c.disconnect()
            (System.nanoTime() - t0) / 1_000_000
        } catch (e: Exception) { -1 }
    }

    /**
     * Upload latency: time (ms) to POST `sizeBytes` THROUGH the given SOCKS port,
     * or -1 on failure. Lower = faster upload. Used to compare configs (upload is
     * often the slow/broken side even when download latency looks fine).
     */
    fun uploadTest(socksPort: Int, sizeBytes: Int = 800_000, timeout: Int = 15000): Long {
        val proxy = proxyFor(socksPort) ?: return -1
        return try {
            val c = open("https://speed.cloudflare.com/__up", timeout, proxy)
            c.requestMethod = "POST"; c.doOutput = true; c.setFixedLengthStreamingMode(sizeBytes)
            c.setRequestProperty("Content-Type", "application/octet-stream")
            val t0 = System.nanoTime()
            val buf = ByteArray(16384)
            c.outputStream.use { os -> var sent = 0; while (sent < sizeBytes) { val n = minOf(buf.size, sizeBytes - sent); os.write(buf, 0, n); sent += n }; os.flush() }
            c.responseCode
            c.disconnect()
            (System.nanoTime() - t0) / 1_000_000
        } catch (e: Exception) { -1 }
    }

    /** Egress IP + geo. Pass the SOCKS port when connected to see the exit IP. */
    fun ipInfo(socksPort: Int? = null): IpInfo {
        val p = proxyFor(socksPort)
        ipwhois(p)?.let { if (it.ok) return it }
        ipapiCo(p)?.let { if (it.ok) return it }
        return IpInfo(false, error = "all IP providers failed")
    }

    private fun ipwhois(proxy: Proxy?): IpInfo? = try {
        val o = JSONObject(httpGet("https://ipwho.is/", proxy = proxy))
        if (!o.optBoolean("success", true)) IpInfo(false, error = o.optString("message", "failed"))
        else IpInfo(true, o.optString("ip"), o.optString("country"), o.optString("country_code"),
            o.optJSONObject("connection")?.optString("isp") ?: "")
    } catch (e: Exception) { null }

    private fun ipapiCo(proxy: Proxy?): IpInfo? = try {
        val o = JSONObject(httpGet("https://ipapi.co/json/", proxy = proxy))
        IpInfo(true, o.optString("ip"), o.optString("country_name"), o.optString("country_code"), o.optString("org"))
    } catch (e: Exception) { null }

    private fun proxyFor(socksPort: Int?): Proxy? =
        socksPort?.takeIf { it > 0 }?.let { Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", it)) }

    private fun open(url: String, timeout: Int, proxy: Proxy?): HttpURLConnection {
        val u = URL(url)
        val c = (if (proxy != null) u.openConnection(proxy) else u.openConnection()) as HttpURLConnection
        c.connectTimeout = timeout; c.readTimeout = timeout; c.instanceFollowRedirects = true
        c.setRequestProperty("User-Agent", "IRNetFree/Android"); c.setRequestProperty("Accept", "application/json")
        return c
    }

    private fun httpGet(url: String, timeout: Int = 9000, proxy: Proxy? = null): String {
        val c = open(url, timeout, proxy)
        try { return c.inputStream.bufferedReader().use { it.readText() } } finally { c.disconnect() }
    }
}
