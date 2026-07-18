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

    /** Egress IP + geo. When the VPN is up this reflects the exit (whole-device tunnel). */
    fun ipInfo(): IpInfo {
        return try {
            val c = (URL("http://ip-api.com/json/?fields=status,message,country,countryCode,isp,query").openConnection() as HttpURLConnection).apply {
                connectTimeout = 8000; readTimeout = 8000; setRequestProperty("User-Agent", "IRNetFree/Android")
            }
            val body = c.inputStream.bufferedReader().use { it.readText() }
            c.disconnect()
            val o = JSONObject(body)
            if (o.optString("status") != "success") return IpInfo(false, error = o.optString("message", "failed"))
            IpInfo(true, o.optString("query"), o.optString("country"), o.optString("countryCode"), o.optString("isp"))
        } catch (e: Exception) { IpInfo(false, error = e.message ?: "error") }
    }
}
