package com.irnetfree.vpn.vpn

import com.irnetfree.vpn.core.LocalAuth
import com.irnetfree.vpn.core.ServerConfig
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket

/**
 * The parts of bringing the tunnel up that do not need a device: which apps
 * the TUN takes, what hev is told, whether a throwaway test core may start,
 * whether the port a subprocess core wants is really its own, and the state the
 * screen is left in.
 */
class TunnelSetupTest {
    private val self = "com.irnetfree.vpn"

    @Test fun onlyTheseAppsNeverIncludesUs() {
        // Our own package inside the TUN routes the core's own sockets back
        // into it — a loop that carries nothing.
        assertEquals(TunnelSetup.PerApp(listOf("org.telegram.messenger"), emptyList()),
            TunnelSetup.perApp("allow", listOf("org.telegram.messenger", self), self))
        // Nothing left to allow: the whole device, minus us.
        assertEquals(TunnelSetup.PerApp(emptyList(), listOf(self)), TunnelSetup.perApp("allow", listOf(self), self))
        assertEquals(TunnelSetup.PerApp(emptyList(), listOf(self)), TunnelSetup.perApp("allow", emptyList(), self))
    }

    @Test fun allButTheseAndOffKeepUsOutside() {
        assertEquals(TunnelSetup.PerApp(emptyList(), listOf("a.b", self)), TunnelSetup.perApp("disallow", listOf("a.b"), self))
        assertEquals(TunnelSetup.PerApp(emptyList(), listOf(self)), TunnelSetup.perApp("off", listOf("a.b"), self))
    }

    @Test fun hevPresentsTheSessionsCredentials() {
        val y = TunnelSetup.tun2socksYaml(10808, LocalAuth("u1d2", "p9f8e7"), mtu = 1500, ipv4 = "172.19.0.1", ipv6 = null)
        assertTrue(y, y.contains("socks5:\n  port: 10808\n  address: 127.0.0.1\n  udp: 'udp'\n  username: 'u1d2'\n  password: 'p9f8e7'\n"))
        assertTrue(y, y.startsWith("tunnel:\n  mtu: 1500\n  ipv4: 172.19.0.1\n"))
        val v6 = TunnelSetup.tun2socksYaml(10808, null, mtu = 1500, ipv4 = "172.19.0.1", ipv6 = "fdfe:dcba:9876::1")
        assertTrue(v6, v6.contains("  ipv6: 'fdfe:dcba:9876::1'\n"))
        assertFalse(v6, v6.contains("username"))
    }

    @Test fun hevsYamlQuotesTheCredentials() {
        // A single-quoted YAML scalar ends at the first lone ' — doubled, it is one quote.
        val y = TunnelSetup.tun2socksYaml(10808, LocalAuth("it's", "p'w''"), mtu = 1500, ipv4 = "172.19.0.1", ipv6 = null)
        assertTrue(y, y.contains("  username: 'it''s'\n  password: 'p''w'''''\n"))
    }

    @Test fun aCrashLoopBacksOffAndKeepsTrying() {
        val t0 = 1_000_000_000_000L
        // The first restart after a kill, or one long after the last attempt: at once.
        val first = StickyRestart.next(0L, 0, t0)
        assertEquals(0, first.streak); assertEquals(0L, first.waitMs); assertEquals(t0, first.attemptAt)
        assertEquals(0L, StickyRestart.next(t0 - 10 * 60_000L, 3, t0).waitMs)

        // A config that takes the process down five seconds into every attempt:
        // 30 s, 60 s, then 120 s each time — never a stop, which under lockdown
        // was a phone with no internet until somebody opened the app.
        var at = 0L; var streak = 0; var now = t0
        val waits = ArrayList<Long>()
        repeat(7) {
            val n = StickyRestart.next(at, streak, now)
            waits.add(n.waitMs); at = n.attemptAt; streak = n.streak
            now = n.attemptAt + 5_000L
        }
        assertEquals(listOf(0L, 30_000L, 60_000L, 120_000L, 120_000L, 120_000L, 120_000L), waits)

        // Killed again while it waited (the planned attempt is still ahead): the same loop.
        assertEquals(60_000L, StickyRestart.next(t0 + 30_000L, 1, t0).waitMs)
        // A clock set far back does not make every restart look like a loop.
        assertEquals(0L, StickyRestart.next(t0 + 3_600_000L, 4, t0).waitMs)
    }

    private fun wg(endpoint: String): ServerConfig {
        val ob = JSONObject().put("protocol", "wireguard").put("settings", JSONObject()
            .put("secretKey", "k").put("address", JSONArray().put("10.13.13.2/32"))
            .put("peers", JSONArray().put(JSONObject().put("publicKey", "p").put("endpoint", endpoint).put("allowedIPs", JSONArray().put("10.0.0.0/8")))))
        return ServerConfig("w", "corp", "wireguard", endpoint.substringBeforeLast(':'), 42421, ob)
    }

    @Test fun aTestOfAWireGuardByNameStartsOnlyWithTheNameResolved() {
        val corp = wg("cobra.example:42421")
        assertEquals(mapOf("cobra.example" to "51.222.52.23"), XrayTester.testEndpoints(corp) { "51.222.52.23" })
        // Unresolved: the core is not started at all (it would resolve the name
        // itself, and a failure there has panicked the whole process).
        assertNull(XrayTester.testEndpoints(corp) { null })
        // An address, or not WireGuard: nothing to resolve.
        assertEquals(emptyMap<String, String>(), XrayTester.testEndpoints(wg("51.222.52.23:42421")) { fail("asked"); null })
        val vless = ServerConfig("v", "v", "vless", "a.example", 443, JSONObject().put("protocol", "vless"))
        assertEquals(emptyMap<String, String>(), XrayTester.testEndpoints(vless) { fail("asked"); null })
    }

    @Test fun aPortSomeoneElseListensOnIsNotFree() {
        val taken = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val port = taken.localPort
        try {
            // A subprocess core's "ready" is "the port answers" — which another
            // app, or an orphan of ours, would satisfy as well.
            assertFalse(LocalPort.isFree(port))
            assertFalse(LocalPort.waitFree(port, 300))
        } finally { taken.close() }
        assertTrue(LocalPort.isFree(port))
        assertTrue(LocalPort.waitFree(port, 300))
    }

    @Test fun anErrorOutlivesTheTeardownAndEndsTheSessionClock() {
        VpnState.set(ConnState.CONNECTED, "x")
        VpnState.setTraffic(Traffic(1, 2, 3, 4))
        VpnState.setHealth(true, "Working")
        assertTrue(VpnState.connectedSince.value > 0)
        VpnState.set(ConnState.ERROR, error = "sing-box core stopped")
        assertEquals(ConnState.ERROR, VpnState.state.value)
        assertEquals("sing-box core stopped", VpnState.lastError.value)
        // the tunnel is down: no uptime, no speed, no verdict left from before
        assertEquals(0L, VpnState.connectedSince.value)
        assertEquals(Traffic(), VpnState.traffic.value)
        assertNull(VpnState.health.value)
        VpnState.set(ConnState.DISCONNECTED, "")
    }
}
