package com.irnetfree.vpn.core

import java.net.InetSocketAddress
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Port of src/main/certPin.js — certificate pinning on first use, what stands
 * in for `allowInsecure` now.
 *
 * Both cores (Xray 26.3.27, PattN 26.9.1, and the libv2ray this app bundles)
 * refuse `tlsSettings.allowInsecure: true` at config load: "removed and
 * migrated to pinnedPeerCertSha256". That key is the SHA-256 of the leaf
 * certificate's DER, as hex. Iranian share links carry allowInsecure=1
 * constantly, so the first time such a server is dialled the app reads the
 * certificate it presents, stores the hash on the server record (`certPin`,
 * `certPinAt`), and ConfigBuilder emits it as pinnedPeerCertSha256 from then
 * on — the core then accepts that certificate and no other, which is strictly
 * more than allowInsecure ever checked.
 *
 * Every probe blocks — run it off the main thread.
 */
object CertPin {
    /** A pin is re-verified against the live server at most this often. */
    const val RECHECK_AFTER_MS = 6L * 3600L * 1000L

    /** SHA-256 (hex, lowercase) of a certificate's DER. */
    fun pinOf(der: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(der).joinToString("") { "%02x".format(it) }

    /** The core accepts the hash in any case, with or without `:` separators; the record keeps one canonical form. */
    fun normalizePin(s: String?): String {
        val hex = (s ?: "").replace(Regex("[\\s:]"), "").lowercase()
        return if (Regex("^[0-9a-f]{64}$").matches(hex)) hex else ""
    }

    /**
     * The pin of the leaf certificate a TLS server presents. Verification is off
     * on purpose: this is the trust-on-first-use step, and the hash learnt here
     * is what the core will insist on from now on. Throws when the server does
     * not complete a handshake (a uTLS-only server may refuse a plain one) — the
     * caller then leaves verification to the core.
     */
    fun fetchLeafPin(host: String, port: Int, servername: String?, timeoutMs: Int = 5000): String =
        withLeaf(host, port, servername, timeoutMs) { leaf, _ -> pinOf(leaf.encoded) }

    /**
     * Who is actually answering for this name, in one line.
     *
     * When a TLS handshake fails there is no way to tell a censored panel from
     * a broken one without looking at the certificate the other end sent, and
     * the JSSE exception never carries it. This dials again with verification
     * off and reports what came back: the address it reached, the name on the
     * certificate and who issued it. On the owner's network a middlebox answers
     * every name with its own certificate, and this is what makes that visible
     * rather than a guess.
     *
     * Diagnostics only — nothing trusts the result.
     */
    fun describeLeaf(host: String, port: Int, servername: String? = host, timeoutMs: Int = 5000): String = try {
        withLeaf(host, port, servername, timeoutMs) { leaf, peer ->
            val subject = shortName(leaf.subjectX500Principal?.name)
            val issuer = shortName(leaf.issuerX500Principal?.name)
            "$peer presented \"$subject\" issued by \"$issuer\""
        }
    } catch (t: Throwable) {
        "could not read the certificate (${t.message ?: t.javaClass.simpleName})"
    }

    /** CN if there is one, else the whole DN — an X.500 name is unreadable in a toast. */
    private fun shortName(dn: String?): String {
        val s = dn ?: return "?"
        return Regex("CN=([^,]+)").find(s)?.groupValues?.get(1)?.trim() ?: s
    }

    /** One trust-all handshake; [use] gets the leaf certificate and the address reached. */
    private fun <T> withLeaf(host: String, port: Int, servername: String?, timeoutMs: Int, use: (X509Certificate, String) -> T): T {
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
            sock.connect(InetSocketAddress(host, port), timeoutMs)
            // SNI carries host names only (RFC 6066), never an address
            val sni = servername?.trim()?.takeIf { it.isNotEmpty() && !DnsPlan.isIp(it) }
            if (sni != null) {
                val params = sock.getSSLParameters()
                params.setServerNames(listOf(SNIHostName(sni)))
                sock.setSSLParameters(params)
            }
            sock.startHandshake()
            val certs = sock.session.peerCertificates
            if (certs.isEmpty()) throw IllegalStateException("the server presented no certificate")
            val leaf = certs[0] as? X509Certificate ?: throw IllegalStateException("not an X.509 certificate")
            val peer = sock.inetAddress?.hostAddress ?: host
            return use(leaf, peer)
        } finally { runCatching { sock.close() } }
    }

    /* ----------------------------- which servers a plan dials itself ----------------------------- */

    private fun firstHop(list: List<ServerConfig>?): ServerConfig? = list?.firstOrNull { it.outbound.length() > 0 }

    /**
     * The servers the phone dials directly: a single server, a chain's first
     * hop, and for advanced / pool plans each target's server or chain first hop.
     * Only these can be probed from here — a later hop is reached through the
     * previous one.
     */
    fun directServers(plan: ConnectionPlan): List<ServerConfig> {
        val out = ArrayList<ServerConfig>()
        fun add(s: ServerConfig?) { if (s != null && s.outbound.length() > 0 && out.none { it.id == s.id }) out.add(s) }
        fun target(tg: String?, sById: Map<String, ServerConfig>, cById: Map<String, List<ServerConfig>>) {
            if (tg.isNullOrEmpty() || tg == "direct" || tg == "block") return
            if (tg.startsWith("chain:")) { add(firstHop(cById[tg.substring(6)])); return }
            add(sById[tg])
        }
        when (plan) {
            is ConnectionPlan.Single -> add(plan.server)
            is ConnectionPlan.Chain -> add(firstHop(plan.members))
            is ConnectionPlan.Pool -> for (e in plan.entries) target(e.target, plan.serversById, plan.chainsById)
            is ConnectionPlan.Advanced -> { for (r in plan.rules) target(r.target, plan.serversById, plan.chainsById); target(plan.def, plan.serversById, plan.chainsById) }
        }
        return out
    }

    /** Every server a plan names, in any position (engineChoice.planServers). */
    fun planServers(plan: ConnectionPlan): List<ServerConfig> {
        val out = ArrayList<ServerConfig>()
        fun add(s: ServerConfig?) { if (s != null && out.none { it.id == s.id }) out.add(s) }
        fun target(tg: String?, sById: Map<String, ServerConfig>, cById: Map<String, List<ServerConfig>>) {
            if (tg.isNullOrEmpty() || tg == "direct" || tg == "block") return
            if (tg.startsWith("chain:")) { cById[tg.substring(6)]?.forEach { add(it) }; return }
            add(sById[tg])
        }
        when (plan) {
            is ConnectionPlan.Single -> add(plan.server)
            is ConnectionPlan.Chain -> plan.members.forEach { add(it) }
            is ConnectionPlan.Pool -> for (e in plan.entries) target(e.target, plan.serversById, plan.chainsById)
            is ConnectionPlan.Advanced -> { for (r in plan.rules) target(r.target, plan.serversById, plan.chainsById); target(plan.def, plan.serversById, plan.chainsById) }
        }
        return out
    }

    /** The record asked for "allow insecure" (allowInsecure=1 in its link) over plain TLS. REALITY verifies its own way. */
    fun wantsPin(server: ServerConfig?): Boolean {
        val st = server?.outbound?.optJSONObject("streamSettings") ?: return false
        return st.optString("security") == "tls" && (st.optJSONObject("tlsSettings")?.optBoolean("allowInsecure") == true)
    }

    class Targets(val probe: List<ServerConfig>, val behind: List<ServerConfig>)

    /**
     * Who needs a pin before this plan can run: `probe` = dialled directly, asked
     * for allowInsecure, no pin yet; `behind` = the same, but only reachable
     * through another hop — those the user pins by connecting to them directly once.
     */
    fun pinTargets(plan: ConnectionPlan): Targets {
        val direct = directServers(plan)
        fun needs(s: ServerConfig) = wantsPin(s) && normalizePin(s.certPin).isEmpty()
        val probe = direct.filter { needs(it) }
        val behind = planServers(plan).filter { s -> direct.none { it.id == s.id } && needs(s) }
        return Targets(probe, behind)
    }

    /** Should this record's pin be checked against the server now? No pin, nothing to re-check. */
    fun recheckDue(server: ServerConfig, now: Long = System.currentTimeMillis(), maxAgeMs: Long = RECHECK_AFTER_MS): Boolean {
        if (normalizePin(server.certPin).isEmpty()) return false
        return now - server.certPinCheckedAt >= maxAgeMs
    }

    /* ----------------------------- one connect's pins, applied by id ----------------------------- */

    /**
     * What one connect learnt about the certificate of the record [id]: when
     * it was checked, and — unless [pin] is null — the pin itself ("" = the old
     * one is gone). [address], [port] and [sni] are where it was learnt; a
     * record that dials somewhere else by the time it is applied does not take it.
     */
    data class PinUpdate(val id: String, val address: String, val port: Int, val sni: String, val checkedAt: Long, val pin: String? = null, val pinAt: String = "")

    /** The name the probe presents: the record's serverName, else its address. */
    fun sniOf(s: ServerConfig): String =
        s.outbound.optJSONObject("streamSettings")?.optJSONObject("tlsSettings")?.optString("serverName")?.takeIf { it.isNotBlank() } ?: s.address

    /**
     * The pins this plan needs, learnt from the live servers — and written
     * nowhere: the caller applies them by id (applyPins) where the store's
     * lists are written, the main thread. [fetch] is fetchLeafPin on the
     * device and throws when a server completes no handshake. Blocks.
     *
     *  - a pin due for its re-check (RECHECK_AFTER_MS: a rotated certificate
     *    makes the core refuse every dial, and it says so only at log level
     *    info) is compared with what the server presents now — the same, only
     *    the time of the check moves; different, the old pin goes and the one
     *    presented now is pinned; unreachable is not a verdict;
     *  - a server the phone dials itself that asked for allowInsecure and has
     *    no pin yet is pinned on first use.
     */
    fun learn(plan: ConnectionPlan, now: Long, fetch: (ServerConfig) -> String, log: (String) -> Unit = {}): List<PinUpdate> {
        val targets = pinTargets(plan)
        for (b in targets.behind) log("${b.name} sits behind a proxy; its certificate cannot be pinned automatically — connect to it directly once to pin it")
        val out = LinkedHashMap<String, PinUpdate>()
        fun update(s: ServerConfig, pin: String?, pinAt: String = "") = PinUpdate(s.id, s.address, s.port, sniOf(s), now, pin, pinAt)
        val probe = ArrayList(targets.probe)
        for (srv in directServers(plan).filter { recheckDue(it, now) }) {
            val live = normalizePin(runCatching { fetch(srv) }.getOrNull())
            if (live.isNotEmpty() && live != normalizePin(srv.certPin)) {
                out[srv.id] = update(srv, "")
                log("Certificate changed for ${srv.name} — the old pin is gone; the one it presents now will be pinned instead")
                if (probe.none { it.id == srv.id }) probe.add(srv)
            } else {
                out[srv.id] = update(srv, null)
            }
        }
        for (srv in probe) {
            try {
                val pin = fetch(srv)
                out[srv.id] = update(srv, pin, java.util.Date(now).toString())
                log("Certificate pinned on first use for ${srv.name}: $pin")
            } catch (e: Exception) {
                log("Could not read the certificate of ${srv.name} to pin it (${e.message}) — the core will verify it itself")
            }
        }
        return ArrayList(out.values)
    }

    /**
     * Write [updates] into [servers] by id, onto the record that holds the id
     * NOW: a subscription refresh may have rebuilt the list since they were
     * learnt (another order, records replaced by the panel's fresh copies,
     * some gone). Only the pin fields move. A record gone, or one that dials
     * another address, port or name by now, is left alone. True when anything
     * changed. Call it where the list is written — the main thread.
     */
    fun applyPins(servers: MutableList<ServerConfig>, updates: List<PinUpdate>): Boolean {
        var changed = false
        for (u in updates) {
            val i = servers.indexOfFirst { it.id == u.id }
            if (i < 0) continue
            val s = servers[i]
            if (s.address != u.address || s.port != u.port || sniOf(s) != u.sni) continue
            val pin = u.pin
            servers[i] = if (pin == null) s.copy(certPinCheckedAt = u.checkedAt)
                else s.copy(certPin = pin, certPinAt = u.pinAt, certPinCheckedAt = u.checkedAt)
            changed = true
        }
        return changed
    }
}
