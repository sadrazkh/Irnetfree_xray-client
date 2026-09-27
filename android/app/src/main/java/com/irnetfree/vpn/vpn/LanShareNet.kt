package com.irnetfree.vpn.vpn

import android.content.Context
import com.irnetfree.vpn.core.DnsPlan
import com.irnetfree.vpn.core.LanShare
import org.json.JSONObject
import java.net.Inet4Address
import java.net.NetworkInterface

/**
 * Where LAN sharing (LanShare) is kept: the store's own preferences file, under
 * a key of its own. Not inside AppSettings — the Settings screen saves those
 * back whole from the copy it opened with, and a change made in the LAN
 * section meanwhile went with them. A share without credentials gets
 * generated ones here, the first time anything reads it, and keeps them.
 */
object LanShareStore {
    private const val PREFS = "irnetfree"
    private const val KEY = "lanShare"

    fun load(ctx: Context): LanShare {
        val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val stored = try { LanShare.fromJson(JSONObject(p.getString(KEY, null) ?: "{}")) } catch (e: Exception) { LanShare() }
        val v = stored.withCredentials()
        if (v != stored) save(ctx, v)
        return v
    }

    fun save(ctx: Context, v: LanShare) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY, v.toJson().toString()).apply()
    }
}

/**
 * The addresses other devices reach this phone at — on its Wi-Fi, its hotspot,
 * a USB or Bluetooth tether — and the proxy URLs to hand them. The mobile
 * network (a carrier address nobody on a LAN can reach), the VPN's own TUN and
 * loopback are left out.
 */
object LanAddresses {
    /** [kind]: what the user knows the interface as ("Wi-Fi", "Hotspot", …). */
    data class Addr(val iface: String, val ip: String, val kind: String)

    /** Interface-name prefixes that are never a LAN: loopback, the VPN's TUN, the carrier's, tunnels. */
    private val NOT_LAN = listOf(
        "lo", "tun", "rmnet", "r_rmnet", "rev_rmnet", "ccmni", "clat", "v4-", "dummy", "ppp", "pdp",
        "ifb", "ip6", "sit", "seth", "wwan", "ipsec", "radio", "gre", "ip_vti", "umts", "mif", "ims"
    )

    /** What [iface] is to the user; null = not a network another device can be on. */
    fun kind(iface: String): String? {
        val n = iface.lowercase()
        if (NOT_LAN.any { p -> n.startsWith(p) }) return null
        return when {
            n.startsWith("ap") || n.startsWith("swlan") || n.startsWith("softap") -> "Hotspot"
            n == "wlan0" -> "Wi-Fi"
            // a second Wi-Fi interface is usually the hotspot, but not on every phone
            n.startsWith("wlan") -> "Wi-Fi / hotspot"
            n.startsWith("p2p") -> "Wi-Fi Direct"
            n.startsWith("rndis") || n.startsWith("usb") || n.startsWith("ncm") -> "USB tethering"
            n.startsWith("bt") -> "Bluetooth tethering"
            n.startsWith("eth") -> "Ethernet"
            else -> iface
        }
    }

    private fun rank(kind: String): Int = when (kind) {
        "Wi-Fi" -> 0; "Hotspot" -> 1; "Wi-Fi / hotspot" -> 2; "USB tethering" -> 3; "Ethernet" -> 4
        else -> 5
    }

    /** From (interface, IPv4 address) pairs: the ones a device on a LAN can reach, Wi-Fi first. */
    fun pick(found: List<Pair<String, String>>): List<Addr> {
        val out = ArrayList<Addr>()
        for ((iface, ip) in found) {
            if (!DnsPlan.isIpv4(ip)) continue
            if (ip.startsWith("127.") || ip.startsWith("169.254.") || ip.startsWith("0.")) continue
            val k = kind(iface) ?: continue
            if (out.none { a -> a.ip == ip }) out.add(Addr(iface, ip, k))
        }
        return out.sortedBy { a -> rank(a.kind) }
    }

    /** What the phone has right now. Cheap enough to ask every few seconds. */
    fun current(): List<Addr> {
        val found = ArrayList<Pair<String, String>>()
        try {
            val all = NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()
            for (ni in all) {
                if (!ni.isUp || ni.isLoopback) continue
                for (a in ni.inetAddresses.toList()) {
                    if (a !is Inet4Address) continue
                    val host: String = a.hostAddress ?: continue
                    found.add(ni.name to host)
                }
            }
        } catch (e: Exception) { /* no interfaces to show */ }
        return pick(found)
    }

    /** `socks5://user:pass@ip:port` — without the credentials when the share asks for none. */
    fun socksUrl(ip: String, lan: LanShare): String =
        "socks5://" + (if (lan.auth) pct(lan.user) + ":" + pct(lan.pass) + "@" else "") + "$ip:${lan.socksPort}"

    fun httpUrl(ip: String, lan: LanShare): String = "http://$ip:${lan.httpPort}"

    /** Percent-encoding for the userinfo part of a URL: everything but the unreserved characters. */
    fun pct(s: String): String = buildString {
        for (b in s.toByteArray(Charsets.UTF_8)) {
            val c = b.toInt() and 0xFF
            val ch = c.toChar()
            if (ch in 'A'..'Z' || ch in 'a'..'z' || ch in '0'..'9' || ch == '-' || ch == '.' || ch == '_' || ch == '~') append(ch)
            else append('%').append(String.format("%02X", c))
        }
    }
}
