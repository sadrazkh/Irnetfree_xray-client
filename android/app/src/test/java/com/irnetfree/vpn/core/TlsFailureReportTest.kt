package com.irnetfree.vpn.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLProtocolException

/**
 * What a TLS failure report has to carry.
 *
 * The owner's subscription failed with "Handshake failed" for five releases.
 * The platform wraps the real reason — a TLS alert number, an OpenSSL error
 * string — one level down in the cause, and the message printed only the top.
 * The actual cause was `alert protocol version`: the panel's Cloudflare zone
 * accepts nothing below TLS 1.3 and the phone's platform TLS had nothing above
 * 1.2. Both halves of that are now in every report, so the next one ends on the
 * first log line.
 */
class TlsFailureReportTest {

    @Test fun theCauseChainIsPrintedNotJustTheTop() {
        // Exactly the shape Conscrypt throws: a generic top, the reason beneath.
        val inner = SSLProtocolException("SSL handshake aborted: ssl=0x7b: Failure in SSL library, usually a protocol error\nerror:1000042e:SSL routines:OPENSSL_internal:TLSV1_ALERT_PROTOCOL_VERSION")
        val top = SSLHandshakeException("Handshake failed").apply { initCause(inner) }
        val chain = Subscriptions.causeChain(top)
        assertTrue("keeps the top: $chain", chain.startsWith("Handshake failed"))
        assertTrue("and the alert beneath it: $chain", chain.contains("TLSV1_ALERT_PROTOCOL_VERSION"))
        assertTrue("on one line: $chain", !chain.contains("\n"))
    }

    @Test fun aRepeatedMessageIsNotRepeated() {
        val inner = RuntimeException("same")
        val top = RuntimeException("same", inner)
        assertEquals("same", Subscriptions.causeChain(top))
    }

    @Test fun theDeviceSideOfTheHandshakeIsNamed() {
        val here = Subscriptions.tlsHere()
        // On the JVM this is the JDK's JSSE; on a phone, Conscrypt. Either way
        // the report says which protocols exist and which provider answers.
        assertTrue("names the protocols: $here", here.contains("TLS "))
        assertTrue("names the provider: $here", here.contains(" via "))
        assertTrue("names the Android API: $here", here.contains("Android API"))
    }

    @Test fun anSslFailureReportCarriesBothSides() {
        val inner = SSLProtocolException("error:1000042e:SSL routines:OPENSSL_internal:TLSV1_ALERT_PROTOCOL_VERSION")
        val top = SSLHandshakeException("Handshake failed").apply { initCause(inner) }
        val msg = Subscriptions.explain(top, null)
        assertTrue(msg.startsWith("TLS handshake failed"))
        assertTrue("the alert: $msg", msg.contains("TLSV1_ALERT_PROTOCOL_VERSION"))
        assertTrue("the device: $msg", msg.contains("this device: TLS"))
    }
}
