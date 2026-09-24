package com.irnetfree.vpn.core

import java.net.Authenticator
import java.net.PasswordAuthentication
import java.security.SecureRandom

/**
 * The per-session credentials of the tunnel's own local inbounds.
 *
 * socks-in and http-in listen on fixed ports of 127.0.0.1 — and loopback is
 * shared by every app on the phone. Open, they let any installed app (the state
 * apps users must keep included) ask them for the VPN's exit address and so
 * detect the VPN: the 2025 "localhost SOCKS" class. Each connect therefore puts
 * a fresh random username/password on both (ConfigBuilder, SingboxConfig); hev
 * presents it (XrayVpnService.writeTun2socksConfig) and so does every client of
 * the app's own that goes through the tunnel (LocalProxyAuth below). Hex only:
 * the values go into hev's YAML in single quotes and into JSON untouched.
 */
data class LocalAuth(val user: String, val pass: String) {
    companion object {
        private val rng = SecureRandom()
        private fun hex(bytes: Int): String {
            val b = ByteArray(bytes); rng.nextBytes(b)
            return b.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
        }
        fun random(): LocalAuth = LocalAuth(hex(8), hex(16))
    }
}

/**
 * Answers java.net's SOCKS client with the tunnel's credentials — for
 * 127.0.0.1 and the tunnel's own port, and for nothing else.
 *
 * OkHttp (Subscriptions via SubFetch) and HttpURLConnection (Diagnostics: the
 * self-check, the Home screen's latency and exit-IP checks) both hand a SOCKS
 * proxy to the platform's own `Socket(Proxy)`, whose RFC 1929 step asks the
 * process-wide Authenticator. A throwaway test core on another port stays open
 * and is never answered for; an HTTP 401/407 is not either.
 */
object LocalProxyAuth : Authenticator() {
    @Volatile private var port = 0
    @Volatile private var auth: LocalAuth? = null

    /** The tunnel's SOCKS port while its credentials are set. */
    val activePort: Int? get() = if (auth != null && port > 0) port else null

    /** The tunnel is up on [port] with [auth]. Installs this as the default Authenticator. */
    @Synchronized fun set(port: Int, auth: LocalAuth) {
        this.port = port; this.auth = auth
        Authenticator.setDefault(this)
    }

    /** Forget [auth] — unless a newer session has already replaced it. */
    @Synchronized fun release(auth: LocalAuth?) {
        if (auth != null && auth == this.auth) { this.auth = null; this.port = 0 }
    }

    override fun getPasswordAuthentication(): PasswordAuthentication? {
        val a = auth ?: return null
        if (requestingProtocol?.startsWith("SOCKS", ignoreCase = true) != true) return null
        if (requestingPort != port) return null
        val site = requestingSite
        val loopback = if (site != null) site.isLoopbackAddress else requestingHost == "127.0.0.1"
        if (!loopback) return null
        return PasswordAuthentication(a.user, a.pass.toCharArray())
    }
}
