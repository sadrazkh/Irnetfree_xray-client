package com.irnetfree.vpn.core

import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/**
 * Fetches a subscription URL and parses it into servers + usage info.
 *
 * Uses OkHttp with permissive TLS (MODERN + COMPATIBLE + CLEARTEXT) because
 * Android's default HttpURLConnection fails the TLS handshake with many sub
 * panels (older ciphers / TLS quirks). A v2rayNG-style User-Agent makes panels
 * return the base64 config list AND the Subscription-Userinfo usage header.
 */
object Subscriptions {

    data class Usage(val upload: Long, val download: Long, val total: Long, val expire: Long)
    data class Result(val servers: List<ServerConfig>, val usage: Usage?, val errors: List<String>)

    private val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(20, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .callTimeout(35, TimeUnit.SECONDS)
            .followRedirects(true).followSslRedirects(true)
            .retryOnConnectionFailure(true)
            .connectionSpecs(listOf(ConnectionSpec.MODERN_TLS, ConnectionSpec.COMPATIBLE_TLS, ConnectionSpec.CLEARTEXT))
            .build()
    }

    /** Blocking network call — run on Dispatchers.IO. */
    fun fetch(url: String): Result {
        val req = Request.Builder()
            .url(url.trim())
            .header("User-Agent", "v2rayNG/1.9.5")
            .header("Accept", "*/*")
            .build()
        client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw RuntimeException("HTTP ${resp.code}")
            val body = resp.body?.string() ?: ""
            if (body.isBlank()) throw RuntimeException("empty response")
            val (servers, errors) = LinkParser.parseMany(body)
            // OkHttp header lookup is case-insensitive.
            val usage = parseUserInfo(resp.header("subscription-userinfo"))
            return Result(servers, usage, errors)
        }
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
