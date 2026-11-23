package com.irnetfree.vpn.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** newId: a big subscription parsed many to the millisecond came out with two servers under one id. */
class NewIdTest {
    @Test fun idsMadeInABurstAreAllDifferent() {
        val ids = (1..50_000).map { newId("s") }
        assertEquals(ids.size, ids.toSet().size)
    }

    @Test fun anIdKeepsItsPrefix() {
        val id = newId("s")
        assertTrue(id, Regex("^s-[0-9a-z]+$").matches(id))
    }
}
