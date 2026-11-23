package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JSON from links and imports (JsonSafe). Android's org.json lets a NaN into an
 * array and then cannot write it; the org.json the JVM tests run on refuses one
 * outright, so that half is checked on the values themselves, and on a device.
 */
class JsonSafeTest {
    @Test fun nonFiniteNumbersAreSeenWherePresent() {
        assertFalse(JsonSafe.finite(Double.NaN))
        assertFalse(JsonSafe.finite(Double.POSITIVE_INFINITY))
        assertFalse(JsonSafe.finite(Float.NEGATIVE_INFINITY))
        assertTrue(JsonSafe.finite(1.5))
        assertTrue(JsonSafe.finite(JSONObject().put("a", JSONArray().put(1).put("x").put(JSONObject().put("b", 2.5)))))
        assertTrue(JsonSafe.finite(null))
    }

    @Test fun anObjectIsReadAndAnythingElseIsNot() {
        assertEquals(2, JsonSafe.objectOf("""{"tcp":[{"type":"fragment"}],"n":1}""")?.length())
        assertNull(JsonSafe.objectOf("[1,2]"))
        assertNull(JsonSafe.objectOf("not json"))
        assertNull(JsonSafe.objectOf(""))
    }

    @Test fun aLinkParameterNestedThousandsDeepIsRefusedNotAStackOverflow() {
        val deep = "{\"a\":" + "[".repeat(20_000) + "]".repeat(20_000) + "}"
        assertNull(JsonSafe.objectOf(deep))
        assertNull(LinkParser.parseFinalMask(deep))
        assertNull(LinkParser.parseXhttpExtra(deep))
        // just under the limit still reads
        val ok = "{\"a\":" + "[".repeat(JsonImport.MAX_DEPTH - 2) + "]".repeat(JsonImport.MAX_DEPTH - 2) + "}"
        assertNotNull(JsonSafe.objectOf(ok))
    }

    @Test fun aWritableObjectHasItsText() {
        assertEquals("{}", JsonSafe.text(JSONObject()))
        assertEquals("[1]", JsonSafe.text(JSONArray().put(1)))
    }

    @Test fun aDeepJsonParameterLeavesTheLinkWithoutItNotTheAppWithoutAStack() {
        // (a vmess body goes through android.util.Base64, which the JVM tests do not have: its
        // depth check is JsonSafe.objectOf's, checked above)
        val deep = "{\"a\":" + "[".repeat(20_000) + "]".repeat(20_000) + "}"
        val enc = java.net.URLEncoder.encode(deep, "UTF-8")
        val s = LinkParser.parseLink("vless://u@a.example.com:443?type=tcp&security=tls&sni=a.example.com&fm=$enc&echOutbound=$enc#a")
        assertEquals("a.example.com", s.address)
        val stream = s.outbound.getJSONObject("streamSettings")
        assertFalse(stream.has("finalmask"))
        assertFalse(stream.optJSONObject("tlsSettings")?.has("echOutbound") ?: false)
        assertNull(LinkParser.echOutboundOf(deep))
    }
}
