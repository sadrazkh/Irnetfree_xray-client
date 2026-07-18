package com.irnetfree.vpn.net

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL

/** Ping / latency / egress-IP checks. All calls block — run on Dispatchers.IO. */
object Diagnostics {

    data class IpInfo(val ok: Boolean, val ip: String = "", val country: String = "", val countryCode: String = "", val isp: String = "", val error: String = "")

    /** TCP handshake time to host:port in ms, or -1 on failure. */
    fun tcpPing(host: String, port: Int, timeout: Int = 4000): Long {
        return try {
            val t0 = System.nanoTime()
            Socket().use { s -> s.connect(InetSocketAddress(host, port), timeout) }
            (System.nanoTime() - t0) / 1_000_000
        } catch (e: Exception) { -1 }
    }

    /** Time a real HTTP round-trip (through the active tunnel when connected), ms or -1. */
    fun httpLatency(url: String = "https://cp.cloudflare.com/generate_204", timeout: Int = 8000): Long {
        return try {
            val t0 = System.nanoTime()
            val c = (URL(url).openConnection() as HttpURLConnection).apply { connectTimeout = timeout; readTimeout = timeout; requestMethod = "GET" }
            c.responseCode
            c.disconnect()
            (System.nanoTime() - t0) / 1_000_000
        } catch (e: Exception) { -1 }
    }

    /**
     * Egress IP + geo. When the VPN is up this reflects the exit (whole-device
     * tunnel). Uses HTTPS providers (HTTP is blocked by default on Android 9+),
     * with a fallback so a single provider being down doesn't break the check.
     */
    fun ipInfo(): IpInfo {
        ipwhois()?.let { if (it.ok) return it }
        ipapiCo()?.let { if (it.ok) return it }
        return IpInfo(false, error = "all IP providers failed")
    }

    private fun ipwhois(): IpInfo? = try {
        val o = JSONObject(httpGet("https://ipwho.is/"))
        if (!o.optBoolean("success", true)) IpInfo(false, error = o.optString("message", "failed"))
        else IpInfo(true, o.optString("ip"), o.optString("country"), o.optString("country_code"),
            o.optJSONObject("connection")?.optString("isp") ?: "")
    } catch (e: Exception) { null }

    private fun ipapiCo(): IpInfo? = try {
        val o = JSONObject(httpGet("https://ipapi.co/json/"))
        IpInfo(true, o.optString("ip"), o.optString("country_name"), o.optString("country_code"), o.optString("org"))
    } catch (e: Exception) { null }

    private fun httpGet(url: String, timeout: Int = 8000): String {
        val c = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = timeout; readTimeout = timeout; instanceFollowRedirects = true
            setRequestProperty("User-Agent", "IRNetFree/Android"); setRequestProperty("Accept", "application/json")
        }
        try { return c.inputStream.bufferedReader().use { it.readText() } } finally { c.disconnect() }
    }
}
