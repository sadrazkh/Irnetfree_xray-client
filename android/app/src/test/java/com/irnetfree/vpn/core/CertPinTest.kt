package com.irnetfree.vpn.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException

/**
 * Certificate pins learnt on a connect, and how they reach the store.
 *
 * XrayVpnService.connect learns them on its own thread, while a subscription
 * refresh may rebuild the very list on the main thread (clear + addAll). The
 * connect thread used to write `store.servers[i]` by an index it had looked up
 * earlier — a stale copy onto whatever sat there by then. Now it only learns
 * (CertPin.learn, no store at all) and the result is applied by id, on the
 * main thread, onto the record that holds the id at that moment (applyPins).
 */
class CertPinTest {
    private val now = 1_000_000_000_000L
    private val pinA = "aa".repeat(32)
    private val pinB = "bb".repeat(32)

    /** A TLS server whose link asked for allowInsecure: the kind that gets pinned. */
    private fun tls(id: String, host: String = "$id.example", sni: String? = null): ServerConfig {
        val t = JSONObject().put("allowInsecure", true)
        if (sni != null) t.put("serverName", sni)
        val ob = JSONObject().put("protocol", "vless").put("settings", JSONObject())
            .put("streamSettings", JSONObject().put("network", "tcp").put("security", "tls").put("tlsSettings", t))
        return ServerConfig(id, id, "vless", host, 443, ob)
    }

    @Test fun aFirstUsePinIsLearntWithoutTouchingAStore() {
        val asked = ArrayList<String>()
        val ups = CertPin.learn(ConnectionPlan.Single(tls("w", sni = "front.example")), now, fetch = { s ->
            asked.add("${s.address}:${s.port} ${CertPin.sniOf(s)}"); pinA
        })
        assertEquals(listOf("w.example:443 front.example"), asked)
        assertEquals(1, ups.size)
        val u = ups[0]
        assertEquals("w", u.id); assertEquals(pinA, u.pin); assertEquals(now, u.checkedAt)
        assertEquals("w.example", u.address); assertEquals(443, u.port); assertEquals("front.example", u.sni)
        assertTrue(u.pinAt.isNotEmpty())
        // no serverName: the SNI is the address, as the probe dials it
        assertEquals("w.example", CertPin.sniOf(tls("w")))
    }

    @Test fun aDuePinIsCheckedAgainstWhatTheServerPresentsNow() {
        val p = tls("p", sni = "front.example").copy(certPin = pinA, certPinAt = "then", certPinCheckedAt = now - CertPin.RECHECK_AFTER_MS)
        val plan = ConnectionPlan.Single(p)
        val checked = CertPin.PinUpdate("p", "p.example", 443, "front.example", now, null, "")
        // the same certificate: only the time of the check moves
        assertEquals(listOf(checked), CertPin.learn(plan, now, fetch = { pinA.uppercase() }))
        // unreachable is not a verdict: the pin stays, the check is done
        assertEquals(listOf(checked), CertPin.learn(plan, now, fetch = { throw IOException("timeout") }))
        // a rotated certificate: the one it presents now replaces the old pin
        val rotated = CertPin.learn(plan, now, fetch = { pinB })
        assertEquals(1, rotated.size); assertEquals(pinB, rotated[0].pin); assertEquals(now, rotated[0].checkedAt)
        // rotated, and the second dial fails: the old pin is dropped all the same
        var n = 0
        val half = CertPin.learn(plan, now, fetch = { if (n++ == 0) pinB else throw IOException("reset") })
        assertEquals("", half.single().pin)
        // not due yet: nothing is dialled at all
        assertTrue(CertPin.learn(ConnectionPlan.Single(p.copy(certPinCheckedAt = now)), now, fetch = { fail("dialled"); pinA }).isEmpty())
    }

    @Test fun pinsLandByIdOnTheRecordThereNowNotByPosition() {
        val w = tls("w"); val x = tls("x"); val gone = tls("gone")
        val plan = ConnectionPlan.Advanced(
            listOf(RouteRule("ip", "10.0.0.0/8", "w"), RouteRule("ip", "192.168.0.0/16", "gone")), "x",
            mapOf("w" to w, "x" to x, "gone" to gone), emptyMap())
        val ups = CertPin.learn(plan, now, fetch = { s -> if (s.id == "w") pinA else pinB })
        assertEquals(setOf("w", "x", "gone"), ups.map { it.id }.toSet())

        // Meanwhile a refresh rebuilt the list: another order, w replaced by
        // the panel's fresh copy under a new name, one server gone, one new.
        val list = mutableListOf(tls("new"), x, w.copy(name = "w · 12 GB left"))
        assertTrue(CertPin.applyPins(list, ups))
        assertEquals(listOf("new", "x", "w"), list.map { it.id })
        assertEquals("", list[0].certPin)                         // nobody learnt a pin for it
        assertEquals(pinB, list[1].certPin)
        assertEquals(pinA, list[2].certPin); assertEquals(now, list[2].certPinCheckedAt)
        assertEquals("w · 12 GB left", list[2].name)              // the record there now, not the copy the connect started from
    }

    @Test fun aRecordThatDialsSomewhereElseByNowDoesNotTakeThePin() {
        val w = tls("w")
        val ups = CertPin.learn(ConnectionPlan.Single(w), now, fetch = { pinA })
        // edited while the connect ran: another address, or another SNI
        val moved = mutableListOf(w.copy(address = "104.16.1.1"))
        assertFalse(CertPin.applyPins(moved, ups)); assertEquals("", moved[0].certPin)
        val renamed = mutableListOf(tls("w", sni = "other.example"))
        assertFalse(CertPin.applyPins(renamed, ups)); assertEquals("", renamed[0].certPin)
        // gone altogether, or nothing learnt: nothing changes
        assertFalse(CertPin.applyPins(mutableListOf(tls("x")), ups))
        assertFalse(CertPin.applyPins(mutableListOf(w), emptyList()))
    }
}
