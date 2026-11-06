package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import java.net.InetSocketAddress
import java.security.cert.X509Certificate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReferenceArray
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Port of src/main/helloCut.js, whose header says why: a server that sniffs
 * without Route Only reads the name in a TLS hello and dials that name instead
 * of the address it was asked for — the far end of a VPN router's tunnel, say —
 * so a Reality or pinned config behind it reaches the real site its name stands
 * for and dies. Xray's sniffer wants the whole hello in one TLS record: cut into
 * several (`tlshello,100-200,0`: interval 0 writes them in one go) it reads
 * nothing, and the TLS stack on the far side takes the records as usual.
 *
 * Only on evidence ([pathReadsHello], asked by the connect), and only for a
 * config that says nothing itself about how it dials ([takesCut]): one with its
 * own fragment or noise, a final mask, a dial mode, ECH or a hop in front of it
 * keeps what it has. With the cut off a config is what it always was, byte for
 * byte (HelloCutTest).
 */
object HelloCut {
    const val HELLO_CUT = "tlshello,100-200,0"

    /** A hello over TCP; QUIC, mKCP and the like have no such thing for a sniffer to read here. */
    private val TCP_TRANSPORTS = setOf("tcp", "raw", "ws", "grpc", "httpupgrade", "xhttp", "splithttp", "h2", "http")

    /** JavaScript's truthiness for a JSON value: absent, null, "", 0 and false are nothing. */
    private fun set(v: Any?): Boolean = when (v) {
        null, JSONObject.NULL -> false
        is String -> v.isNotEmpty()
        is Boolean -> v
        is Number -> v.toDouble() != 0.0
        else -> true
    }

    /**
     * helloCut.js masksHello: a final mask that fragments over TCP is the config's own way to hand over its hello and is
     * left alone; any other mask stays as it is and the cut goes under it. A shape not known here is left alone.
     */
    fun masksHello(fm: Any?): Boolean {
        if (fm == null || fm == JSONObject.NULL) return false
        if (fm is String) return fm.isNotEmpty()
        if (fm !is JSONObject) return true
        val tcp = fm.opt("tcp")
        if (tcp == null || tcp == JSONObject.NULL) return false
        if (tcp !is JSONArray) return true
        for (i in 0 until tcp.length()) {
            val m = tcp.opt(i)
            if (m !is JSONObject) return true
            if (m.optString("type").lowercase() == "fragment") return true
        }
        return false
    }

    /** Does this Xray outbound take the cut (helloCut.js takesCut)? */
    fun takesCut(o: JSONObject?): Boolean {
        if (o == null) return false
        if (set(o.opt("_fragment")) || set(o.opt("_noise"))) return false
        val ss = o.optJSONObject("streamSettings") ?: return false
        val security = ss.optString("security")
        if (security != "tls" && security != "reality") return false
        val network = ss.optString("network").ifEmpty { "tcp" }
        if (network !in TCP_TRANSPORTS) return false
        if (masksHello(ss.opt("finalmask")) || masksHello(ss.opt("finalMask"))) return false
        val so = ss.optJSONObject("sockopt")
        if (so != null && (set(so.opt("dialerProxy")) || set(so.opt("dialMode")))) return false
        val t = ss.optJSONObject("tlsSettings")
        if (t != null) {
            if (set(t.opt("echOutbound")) || set(t.opt("echConfigList")) || set(t.opt("echServerKeys"))) return false
            val alpn = t.optJSONArray("alpn")
            if (alpn != null && alpn.length() > 0 && (0 until alpn.length()).all { i: Int -> alpn.optString(i) == "h3" }) return false
        }
        return true
    }

    /** Marks what takes the cut; ConfigBuilder.applyFragments writes the dialer. Runs on a config's own copies. */
    fun cutHellos(outbounds: JSONArray): JSONArray {
        for (i in 0 until outbounds.length()) {
            val o = outbounds.optJSONObject(i) ?: continue
            if (takesCut(o)) o.put("_fragment", HELLO_CUT)
        }
        return outbounds
    }

    /** A public address asked for another's name (helloCut.js SAMPLES). */
    class Sample(val ip: String, val name: String)
    val SAMPLES: List<Sample> = listOf(Sample("1.1.1.1", "www.google.com"), Sample("8.8.8.8", "www.cloudflare.com"))

    /**
     * Does a certificate's DNS names (`DNS:` prefix or not) name the site asked
     * for — exactly, or by one wildcard label (helloCut.js certNames)?
     */
    fun certNames(dnsNames: List<String>, name: String): Boolean {
        val want = name.trim().lowercase()
        if (want.isEmpty()) return false
        for (raw in dnsNames) {
            val d = raw.trim().lowercase().removePrefix("dns:")
            if (d == want) return true
            if (d.startsWith("*.")) {
                val suffix = d.substring(1)
                if (want.length > suffix.length && want.endsWith(suffix) && !want.substring(0, want.length - suffix.length).contains(".")) return true
            }
        }
        return false
    }

    /**
     * Does the way out read names? true: proved — an address asked for another's
     * name answered with a certificate naming that site, which can only have
     * come from the site, so something on the way dialled the name. false: an
     * address answered as itself. null: nothing answered, so nothing is known
     * and the last answer stands. Asked without a tunnel of ours up: through one
     * it would be about our own server.
     *
     * Blocks the calling thread for [timeoutMs] at most (never the main one):
     * every dial runs on a daemon thread of its own, with the same limit, and the
     * first proof ends the wait. [dial] answers a sample with the DNS names of
     * the certificate it got, or null for no answer; the device's is [dialSans].
     */
    fun pathReadsHello(
        samples: List<Sample> = SAMPLES,
        timeoutMs: Long = 2000,
        dial: (String, String) -> List<String>? = { ip: String, name: String -> dialSans(ip, name, timeoutMs.toInt()) }
    ): Boolean? {
        if (samples.isEmpty()) return null
        val answers = AtomicReferenceArray<Boolean?>(samples.size)
        val latch = CountDownLatch(samples.size)
        for ((i, s) in samples.withIndex()) {
            val t = Thread {
                val names = try { dial(s.ip, s.name) } catch (e: Throwable) { null }
                answers.set(i, if (names == null) null else certNames(names, s.name))
                latch.countDown()
            }
            t.isDaemon = true
            t.name = "irnf-hello-check"
            t.start()
        }
        val deadline = System.currentTimeMillis() + timeoutMs
        while (true) {
            var proved = false
            var kept = false
            for (i in 0 until samples.size) {
                val a = answers.get(i)
                if (a == true) proved = true
                if (a == false) kept = true
            }
            if (proved) return true
            val left = deadline - System.currentTimeMillis()
            if (latch.count == 0L || left <= 0) return if (kept) false else null
            latch.await(if (left < 50L) left else 50L, TimeUnit.MILLISECONDS)
        }
    }

    /**
     * One trust-all TLS dial to [ip]:443 naming [name]: the DNS names of the
     * certificate it presents. Verification is off on purpose — the certificate
     * is read, nothing trusts it (CertPin.withLeaf does the same for a pin).
     * Throws when nothing completes a handshake within [timeoutMs].
     */
    fun dialSans(ip: String, name: String, timeoutMs: Int): List<String> {
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, trustAll, null)
        val sock = ctx.socketFactory.createSocket() as SSLSocket
        try {
            sock.soTimeout = timeoutMs
            sock.connect(InetSocketAddress(ip, 443), timeoutMs)
            val params = sock.getSSLParameters()
            params.setServerNames(listOf(SNIHostName(name)))
            sock.setSSLParameters(params)
            sock.startHandshake()
            val certs = sock.session.peerCertificates
            if (certs.isEmpty()) throw IllegalStateException("no certificate")
            val leaf = certs[0] as? X509Certificate ?: throw IllegalStateException("not an X.509 certificate")
            val out = ArrayList<String>()
            val sans = leaf.subjectAlternativeNames
            if (sans != null) {
                for (entry in sans) {
                    // each entry: [type, value]; type 2 is a dNSName
                    if (entry.size >= 2 && entry[0] == 2) {
                        val v = entry[1]
                        if (v is String) out.add(v)
                    }
                }
            }
            return out
        } finally { runCatching { sock.close() } }
    }

    /** The last answer (helloCut.js pathCut): the configs are cut from here on. False until a path is proved to read. */
    @Volatile var pathCut: Boolean = false

    /**
     * Ask the path once and remember what it said (a null keeps the last answer),
     * saying in [log] when the answer changed. Blocks for the check's limit at
     * most — the connect thread, never the main one. Returns [pathCut].
     */
    fun refresh(log: (String) -> Unit): Boolean {
        val reads = pathReadsHello()
        if (reads != null && reads != pathCut) {
            pathCut = reads
            log(if (reads) "This network reads the names in TLS hellos on the way out, so a config could reach the real site instead of its own server: hellos are cut from here on"
                else "This network no longer reads names on the way out: TLS hellos go whole again")
        }
        return pathCut
    }
}
