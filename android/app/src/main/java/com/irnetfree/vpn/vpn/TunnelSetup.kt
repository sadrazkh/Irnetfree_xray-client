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
     * They are single-quoted, so a quote inside is doubled — LocalAuth.random()
     * never makes one, but nothing else here stops a caller that does.
     */
    fun tun2socksYaml(socksPort: Int, auth: LocalAuth?, mtu: Int, ipv4: String, ipv6: String?): String = buildString {
        fun q(s: String) = s.replace("'", "''")
        append("tunnel:\n  mtu: $mtu\n  ipv4: $ipv4\n")
        if (ipv6 != null) append("  ipv6: '$ipv6'\n")
        append("socks5:\n  port: $socksPort\n  address: 127.0.0.1\n  udp: 'udp'\n")
        if (auth != null) append("  username: '${q(auth.user)}'\n  password: '${q(auth.pass)}'\n")
        append("misc:\n  task-stack-size: 20480\n  connect-timeout: 5000\n  read-write-timeout: 60000\n  log-level: warn\n")
    }
}

/**
 * When a START_STICKY restart (the process was killed under a live tunnel)
 * connects by itself again. At once — unless the previous attempt was under
 * two minutes ago: that is a crash loop (a config that takes the core down as
 * it starts, a native crash IRApp's handler never sees), and connecting at
 * once only repeats it. It then waits 30 s, 60 s, then 120 s each time, and
 * keeps trying: giving up left a phone under lockdown with no internet until
 * somebody opened the app.
 */
object StickyRestart {
    /** A restart this soon after the previous attempt is the same crash again. */
    const val WINDOW_MS = 120_000L

    /** [attemptAt]: when this restart connects — what the next one measures from. */
    class Next(val streak: Int, val waitMs: Long, val attemptAt: Long)

    /**
     * [lastAttemptAt]/[streak]: what the previous restart stored (0 = none).
     * A restart before that attempt was even due — killed while it waited —
     * counts as the same loop; one from a clock set far back does not.
     */
    fun next(lastAttemptAt: Long, streak: Int, now: Long): Next {
        val gap = now - lastAttemptAt
        val s = if (lastAttemptAt > 0L && gap >= -WINDOW_MS && gap < WINDOW_MS) (streak + 1).coerceAtMost(100) else 0
        val wait = when {
            s <= 0 -> 0L
            s == 1 -> 30_000L
            s == 2 -> 60_000L
            else -> 120_000L
        }
        return Next(s, wait, now + wait)
    }
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
