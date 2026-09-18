package com.irnetfree.vpn.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLHandshakeException

/**
 * Which path a subscription fetch takes, and what it says when both fail.
 *
 * The bug this pins: our own package is excluded from the VPN, so a fetch left
 * over the raw ISP network even while the tunnel was up, and a middlebox
 * answered the panel's TLS handshake. The desktop, whose whole system is inside
 * the TUN, fetched the same URL through the tunnel and worked — so "it works on
 * Windows" was true and told us nothing.
 *
 * The network itself is not testable off a device; the ORDER is, which is why
 * `fetch` takes its single request as a parameter.
 */
class SubscriptionsTest {
    private val ok = Subscriptions.Result(emptyList(), null, emptyList())

    /** Records each (url, socksPort) attempt and fails the ones named. */
    private class Calls(private val failOn: (Int?) -> Exception?) {
        val ports = ArrayList<Int?>()
        val urls = ArrayList<String>()
        fun call(url: String, port: Int?): Subscriptions.Result {
            ports.add(port); urls.add(url)
            failOn(port)?.let { throw it }
            return Subscriptions.Result(emptyList(), null, emptyList())
        }
    }

    @Test fun withNoTunnelThereIsExactlyOneDirectAttempt() {
        val c = Calls { null }
        Subscriptions.fetch("https://sub.example/x", null, c::call)
        assertEquals(listOf<Int?>(null), c.ports)
        assertEquals(listOf("https://sub.example/x"), c.urls)
        // 0 is "no port", not a port
        val c2 = Calls { null }
        Subscriptions.fetch("https://sub.example/x", 0, c2::call)
        assertEquals(listOf<Int?>(null), c2.ports)
    }

    @Test fun withATunnelItGoesThroughItFirst() {
        val c = Calls { null }
        Subscriptions.fetch("https://sub.example/x", 10808, c::call)
        assertEquals(listOf<Int?>(10808), c.ports)
    }

    @Test fun aTunnelFailureFallsBackToDirect() {
        // A panel that only serves domestic addresses refuses the exit; before
        // the tunnel was ever used this worked, and it must keep working.
        val c = Calls { port -> if (port != null) SSLHandshakeException("handshake") else null }
        Subscriptions.fetch("https://sub.example/x", 10808, c::call)
        assertEquals(listOf<Int?>(10808, null), c.ports)
    }

    @Test fun bothFailingReportsBothAndNamesThePathsApart() {
        val c = Calls { port ->
            if (port != null) SSLHandshakeException("Chain validation failed")
            else UnknownHostException("sub.example")
        }
        val e = runCatching { Subscriptions.fetch("https://sub.example/x", 10808, c::call) }.exceptionOrNull()
        assertEquals(listOf<Int?>(10808, null), c.ports)
        val msg = e?.message ?: ""
        assertTrue("says the handshake failed: $msg", msg.contains("TLS handshake failed"))
        assertTrue("keeps the core's own words: $msg", msg.contains("Chain validation failed"))
        assertTrue("reports the direct attempt too: $msg", msg.contains("Off the tunnel"))
        assertTrue("and what went wrong there: $msg", msg.contains("Could not resolve"))
    }

    @Test fun everyFailureTellsTheUserWhichNetworkItWasOn() {
        val viaTunnel = Subscriptions.explain(SSLHandshakeException("x"), 10808)
        val direct = Subscriptions.explain(SSLHandshakeException("x"), null)
        assertTrue(viaTunnel.contains("Through the tunnel"))
        assertTrue(direct.contains("Over your normal network"))
        // A timeout and a name failure are different problems and read differently.
        assertTrue(Subscriptions.explain(SocketTimeoutException(), null).contains("Timed out"))
        assertTrue(Subscriptions.explain(UnknownHostException("h"), null).contains("resolve"))
        // Anything we do not recognise still reaches the user unedited.
        assertEquals("HTTP 403", Subscriptions.explain(RuntimeException("HTTP 403"), null))
    }

    /*
     * The resolver order. TrustedDns believes the OS unless every answer is in a
     * range no public server can be in; a censor that answers with a PUBLIC
     * address of its own passes that test, and the handshake then fails against
     * a machine that was never the panel — which is what the owner hit. For a
     * subscription host the DoH answer wins, and the OS is only the fallback.
     */
    @Test fun aLiteralAddressIsNotLookedUpAtAll() {
        val ips = Subscriptions.TrustedResolver.lookup("93.184.216.34")
        assertEquals(listOf("93.184.216.34"), ips.map { it.hostAddress })
    }

    @Test fun theAddressUsedIsRememberedForTheFailureReport() {
        Subscriptions.TrustedResolver.lookup("93.184.216.34")
        val seen = synchronized(Subscriptions.TrustedResolver.lastSeen) {
            Subscriptions.TrustedResolver.lastSeen["93.184.216.34"]
        }
        assertTrue("records what it handed out: $seen", seen != null && seen.contains("93.184.216.34"))
    }
}
