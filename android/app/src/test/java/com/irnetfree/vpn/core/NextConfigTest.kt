package com.irnetfree.vpn.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The order by measured speed, and the next config to try after a failed connect (NextConfig.kt). */
class NextConfigTest {
    private fun srv(id: String, subId: String? = "p") = ServerConfig(id, id, "vless", "$id.example", 443, JSONObject(), subId = subId)
    // a panel's five, two by hand, one of another panel — in the list's order
    private val list = listOf(srv("a"), srv("b"), srv("c"), srv("d"), srv("e"), srv("m1", null), srv("m2", null), srv("w1", "w"))
    private val tests = mapOf(
        "a" to NextConfig.Test(tcp = 40, down = -1),      // a handshake, and a round trip that failed: a handshake
        "b" to NextConfig.Test(tcp = 120, down = 300),
        "c" to NextConfig.Test(tcp = 90),
        "d" to NextConfig.Test(tcp = -1),                 // failed
        "e" to NextConfig.Test(down = 150),               // UDP-only: a round trip, no handshake
        "m1" to NextConfig.Test(tcp = -1, down = -1),
        "w1" to NextConfig.Test(tcp = 30)
    )                                                     // m2: never measured
    private fun ids(l: List<ServerConfig>) = l.map { it.id }

    @Test fun theOrderARealRoundTripThenAHandshakeThenUntestedThenFailed() {
        assertEquals(listOf("e", "b", "w1", "a", "c", "m2", "d", "m1"), ids(NextConfig.sorted(list, tests)))
        // nothing measured: the list as it is
        assertEquals(ids(list), ids(NextConfig.sorted(list, emptyMap())))
        // the input is not touched
        assertEquals(listOf("a", "b", "c", "d", "e", "m1", "m2", "w1"), ids(list))
        assertEquals(2, NextConfig.tier(null))
        assertEquals(2, NextConfig.tier(NextConfig.Test()))
        assertEquals(0, NextConfig.tier(NextConfig.Test(tcp = -1, down = 10)))
        assertEquals(1, NextConfig.tier(NextConfig.Test(tcp = 10, down = -1)))
        assertEquals(1, NextConfig.tier(NextConfig.Test(tcp = 10)))
        assertEquals(3, NextConfig.tier(NextConfig.Test(tcp = -1)))
        assertEquals(3, NextConfig.tier(NextConfig.Test(down = -1)))
    }

    @Test fun theNextConfigComesFromTheSameSubscriptionFirstInThatOrder() {
        // c failed: of its own panel, e (a round trip) comes before b (slower), then a (a handshake), then d (failed) —
        // and d, a failure of the same panel, still before another panel's good one
        assertEquals("e", NextConfig.pick(list, "c", emptySet(), tests)?.id)
        assertEquals("b", NextConfig.pick(list, "c", setOf("e"), tests)?.id)
        assertEquals("a", NextConfig.pick(list, "c", setOf("e", "b"), tests)?.id)
        assertEquals("d", NextConfig.pick(list, "c", setOf("e", "b", "a"), tests)?.id)
        // the panel exhausted: the others, in the same order — w1 (a handshake), m2 (untested), m1 (failed)
        assertEquals("w1", NextConfig.pick(list, "c", setOf("e", "b", "a", "d"), tests)?.id)
        assertEquals("m2", NextConfig.pick(list, "c", setOf("e", "b", "a", "d", "w1"), tests)?.id)
        assertEquals("m1", NextConfig.pick(list, "c", setOf("e", "b", "a", "d", "w1", "m2"), tests)?.id)
        assertNull(NextConfig.pick(list, "c", setOf("e", "b", "a", "d", "w1", "m2", "m1"), tests))
        // the current one is never the answer, tried or not
        assertNull(NextConfig.pick(listOf(srv("a")), "a", emptySet(), tests))
        assertNull(NextConfig.pick(emptyList(), "a", emptySet(), tests))
    }

    @Test fun untestedOnesAreTakenInListOrderAfterTheCurrentOneWrappingRound() {
        assertEquals("d", NextConfig.pick(list, "c", emptySet(), emptyMap())?.id)
        // after e, its panel's list wraps round to a
        assertEquals("a", NextConfig.pick(list, "e", emptySet(), emptyMap())?.id)
        assertEquals("d", NextConfig.pick(list, "e", setOf("a", "b", "c"), emptyMap())?.id)
        // its panel exhausted: the others in list order after it
        assertEquals("m1", NextConfig.pick(list, "e", setOf("a", "b", "c", "d"), emptyMap())?.id)
        // alone in its subscription: the others, from the one after it round to the top
        assertEquals("a", NextConfig.pick(list, "w1", emptySet(), emptyMap())?.id)
        // the by-hand servers are one another's "same subscription"
        assertEquals("m2", NextConfig.pick(list, "m1", emptySet(), emptyMap())?.id)
        assertEquals("w1", NextConfig.pick(list, "m1", setOf("m2"), emptyMap())?.id)
        // a current that is not in the list any more (deleted meanwhile): a pick from the top
        assertEquals("a", NextConfig.pick(list, "zz", emptySet(), emptyMap())?.id)
    }
}
