package com.irnetfree.vpn.vpn

import com.irnetfree.vpn.core.LocalAuth
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket

/**
 * The pure parts of bringing the tunnel up, kept out of the VpnService so the
 * JVM tests reach them: which apps the TUN takes, and what hev is told.
 */
object TunnelSetup {
    /** What the VpnService.Builder is told. The two lists are never both used (the builder refuses a mix). */
    data class PerApp(val allowed: List<String>, val disallowed: List<String>)

    /**
     * Our own package is never inside the TUN: the core's sockets would loop
     * back into it. "Only these apps" simply leaves it out of the list — and if
     * that leaves nothing, the whole device goes through, minus us.
     */
    fun perApp(mode: String, apps: List<String>, self: String): PerApp {
        val others = apps.filter { it.isNotBlank() && it != self }.distinct()
        return when {
            mode == "allow" && others.isNotEmpty() -> PerApp(others, emptyList())
            mode == "disallow" -> PerApp(emptyList(), others + self)
            else -> PerApp(emptyList(), listOf(self))
        }
    }

    /**
     * hev-socks5-tunnel's config: the TUN → the core's local SOCKS inbound, with
     * the session's credentials when the inbound asks for them (LocalAuth.kt).
     */
    fun tun2socksYaml(socksPort: Int, auth: LocalAuth?, mtu: Int, ipv4: String, ipv6: String?): String = buildString {
        append("tunnel:\n  mtu: $mtu\n  ipv4: $ipv4\n")
        if (ipv6 != null) append("  ipv6: '$ipv6'\n")
        append("socks5:\n  port: $socksPort\n  address: 127.0.0.1\n  udp: 'udp'\n")
        if (auth != null) append("  username: '${auth.user}'\n  password: '${auth.pass}'\n")
        append("misc:\n  task-stack-size: 20480\n  connect-timeout: 5000\n  read-write-timeout: 60000\n  log-level: warn\n")
    }
}

object StickyRestart {
    const val WINDOW_MS = 120_000L

    class Next(val streak: Int, val waitMs: Long, val attemptAt: Long)

    fun next(lastAttemptAt: Long, streak: Int, now: Long): Next = Next(0, 0L, now)
}

/**
 * Is a loopback port free for a core to bind? A subprocess core's "ready" is
 * "the port answers" — which another app, or an orphan of ours, satisfies just
 * as well — so the port is checked BEFORE the launch, bound exactly as the core
 * will bind it.
 */
object LocalPort {
    fun isFree(port: Int): Boolean = try {
        ServerSocket().use { it.reuseAddress = true; it.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port)) }
        true
    } catch (e: Exception) { false }

    /** Wait a moment for a port to come free: the core just stopped may still be letting go of it. */
    fun waitFree(port: Int, timeoutMs: Long = 3000): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (!isFree(port)) {
            if (System.currentTimeMillis() >= deadline) return false
            try { Thread.sleep(100) } catch (e: InterruptedException) { return false }
        }
        return true
    }
}
