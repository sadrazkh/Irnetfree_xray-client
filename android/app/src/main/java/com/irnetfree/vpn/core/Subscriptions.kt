package com.irnetfree.vpn.core

import java.net.HttpURLConnection
import java.net.URL

/** Fetches a subscription URL and parses it into servers + usage info. */
object Subscriptions {

    data class Usage(val upload: Long, val download: Long, val total: Long, val expire: Long)
    data class Result(val servers: List<ServerConfig>, val usage: Usage?, val errors: List<String>)

    /** Blocking network call — run on Dispatchers.IO. */
    fun fetch(url: String): Result {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15000; readTimeout = 15000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "IRNetFree/Android")
            setRequestProperty("Accept", "*/*")
        }
        try {
            val code = conn.responseCode
            if (code !in 200..299) throw RuntimeException("HTTP $code")
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            val (servers, errors) = LinkParser.parseMany(body)
            val usage = parseUserInfo(conn.getHeaderField("Subscription-Userinfo") ?: conn.getHeaderField("subscription-userinfo"))
            return Result(servers, usage, errors)
        } finally { conn.disconnect() }
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
