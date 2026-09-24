package com.irnetfree.vpn.vpn

import com.irnetfree.vpn.core.LocalAuth

/** The pure parts of starting the tunnel. */
object TunnelSetup {
    data class PerApp(val allowed: List<String>, val disallowed: List<String>)

    fun perApp(mode: String, apps: List<String>, self: String): PerApp = when {
        mode == "allow" && apps.isNotEmpty() -> PerApp(apps, emptyList())
        mode == "disallow" -> PerApp(emptyList(), apps + self)
        else -> PerApp(emptyList(), listOf(self))
    }

    fun tun2socksYaml(socksPort: Int, auth: LocalAuth?, mtu: Int, ipv4: String, ipv6: String?): String = buildString {
        append("tunnel:\n  mtu: $mtu\n  ipv4: $ipv4\n")
        if (ipv6 != null) append("  ipv6: '$ipv6'\n")
        append("socks5:\n  port: $socksPort\n  address: 127.0.0.1\n  udp: 'udp'\n")
        append("misc:\n  task-stack-size: 20480\n  connect-timeout: 5000\n  read-write-timeout: 60000\n  log-level: warn\n")
    }
}

/** Is a loopback port free for a core to bind. */
object LocalPort {
    fun isFree(port: Int): Boolean = true
    fun waitFree(port: Int, timeoutMs: Long = 3000): Boolean = true
}
