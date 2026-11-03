package com.irnetfree.vpn.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Links the app is opened with and texts shared to it (DeepLink.kt) — the same
 * rules and cases as the desktop's src/main/deepLink.js: what is read, what is
 * refused, and that nothing here is ever more than a description of what to ask.
 */
class DeepLinkTest {
    private val vless = "vless://9dfa1529-8427-41f3-ac27-b0efeb338b22@203.0.113.9:443?type=ws&path=%2Fws&security=tls&sni=cdn.example#%F0%9F%87%A9%F0%9F%87%AA%20Berlin"
    private val sub = "https://panel.example:8443/sub/SECRET-TOKEN?token=abc"
    private val routing = "irnetfree://routing/eJxLTEwEAA"

    /** encodeURIComponent: unreserved characters as they are, every other byte as %XX. */
    private fun enc(s: String): String {
        val sb = StringBuilder()
        for (b in s.toByteArray(Charsets.UTF_8)) {
            val c = b.toInt() and 0xff
            val ch = c.toChar()
            if ((c < 128 && ch.isLetterOrDigit()) || ch == '-' || ch == '.' || ch == '_' || ch == '~') sb.append(ch)
            else sb.append('%').append(String.format("%02X", c))
        }
        return sb.toString()
    }

    @Test fun aRoutingLinkGoesToThePreviewAsItIs() {
        assertEquals(DeepLink.Item(DeepLink.ROUTING, routing), DeepLink.parse(routing))
        // the host is read whatever its case, and the text is still the link as given
        val upper = "irnetfree://ROUTING/eJxLTEwEAA"
        assertEquals(DeepLink.Item(DeepLink.ROUTING, upper), DeepLink.parse(" $upper "))
    }

    @Test fun anImportLinkCarriesAConfigOrASubscription() {
        // the path form: the text, percent-encoded
        assertEquals(DeepLink.Item(DeepLink.CONFIG, vless), DeepLink.parse("irnetfree://import/" + enc(vless)))
        assertEquals(DeepLink.Item(DeepLink.SUB, sub, "panel.example"), DeepLink.parse("irnetfree://IMPORT/" + enc(sub)))
        // the query form, with a name for the subscription
        assertEquals(DeepLink.Item(DeepLink.SUB, sub, "panel.example"), DeepLink.parse("irnetfree://import?url=" + enc(sub)))
        assertEquals(DeepLink.Item(DeepLink.SUB, sub, "panel.example", "My Panel"), DeepLink.parse("irnetfree://import?url=" + enc(sub) + "&name=" + enc("My Panel")))
        assertEquals("My Panel", DeepLink.parse("irnetfree://import?name=" + enc("My Panel") + "&url=" + enc(sub))?.name)
        // a slash before the query, a fragment after it: neither is part of the payload
        assertEquals(DeepLink.Item(DeepLink.CONFIG, vless), DeepLink.parse("irnetfree://import/?url=" + enc(vless)))
        assertEquals(DeepLink.Item(DeepLink.CONFIG, vless), DeepLink.parse("irnetfree://import?url=" + enc(vless) + "#opened"))
        // a name is carried for a config too (the screen uses it for subscriptions)
        assertEquals("x", DeepLink.parse("irnetfree://import?url=" + enc(vless) + "&name=x")?.name)
        // a bare link opened with the app is read as a payload
        assertEquals(DeepLink.Item(DeepLink.CONFIG, vless), DeepLink.parse(vless))
        assertEquals(DeepLink.Item(DeepLink.SUB, sub, "panel.example"), DeepLink.parse(sub))
    }

    @Test fun otherIrnetfreePathsAndBadEncodingsAreNothing() {
        for (l in listOf(
            "irnetfree://import", "irnetfree://import/", "irnetfree://import?", "irnetfree://import?name=x", "irnetfree://import/#x",
            "irnetfree://", "irnetfree://settings/x", "irnetfree://importer/" + enc(vless),
            // a lone %, a non-hex digit, bytes that are not UTF-8
            "irnetfree://import/%", "irnetfree://import/%zz", "irnetfree://import/" + enc(vless) + "%4", "irnetfree://import/%ff%fe",
            "irnetfree://import?url=%zz",
            // a payload that is not one
            "irnetfree://import/" + enc("file:///etc/passwd"), "irnetfree://import?url=" + enc("javascript:alert(1)"),
            "irnetfree://import/" + enc("$vless\n$sub")
        )) assertNull(l, DeepLink.parse(l))
    }

    @Test fun aPayloadIsASubscriptionWithItsHostOrAConfigLink() {
        assertEquals(DeepLink.Item(DeepLink.SUB, sub, "panel.example"), DeepLink.classify(sub))
        // the host: lowercased, without the login or the port — and never the path
        assertEquals("panel.example", DeepLink.classify("HTTP://User:pw@Panel.Example/sub/x")?.host)
        assertEquals("[2001:db8::1]", DeepLink.classify("https://[2001:db8::1]:8443/sub")?.host)
        assertEquals("panel.example", DeepLink.classify("https://panel.example")?.host)
        for (scheme in listOf("vless", "vmess", "trojan", "ss", "socks", "socks5", "wireguard", "wg", "tuic", "anytls", "hysteria2", "hy2"))
            assertEquals(scheme, DeepLink.CONFIG, DeepLink.classify("$scheme://x@h:1#n")?.kind)
        assertEquals(DeepLink.CONFIG, DeepLink.classify("VLESS://x@h:1")?.kind)
        // trimmed, and the text kept is the trimmed one
        assertEquals(vless, DeepLink.classify("  $vless \n")?.text)
        // the length limit is on the payload
        assertEquals(DeepLink.CONFIG, DeepLink.classify("vless://" + "a".repeat(DeepLink.MAX_LEN - 8))?.kind)
        assertNull(DeepLink.classify("vless://" + "a".repeat(DeepLink.MAX_LEN - 7)))
    }

    @Test fun whatIsNotAPayload() {
        for (p in listOf(
            "", "   ",
            // an HTTP proxy link is not a subscription, and http is not a config scheme
            "http://user@host:1080#name",
            // no host, or not a host
            "http:///nohost", "https://", "http://a b.example/x", "https://[2001:db8::1/x",
            "file:///etc/hosts", "javascript:alert(1)", "intent://x#Intent;end", "content://media/1", "ftp://h/x", "mailto:a@b",
            // nothing after the scheme; two lines; a control character
            "vless://", "vless:// ", "$vless\n$sub", "$vless\r\n$sub", "vless://x\u0000y", "vless://x\ty",
            // not a link at all
            "my server", "9dfa1529-8427-41f3-ac27-b0efeb338b22"
        )) assertNull(p, DeepLink.classify(p))
    }

    @Test fun aSharedTextKeepsTheLinesThatClassify() {
        val text = "My configs:\n$vless\n\n$sub\r\nhttp://user@h:1080#proxy\nfile:///x\n  ss://a@b:1#c  \nbye"
        assertEquals(
            listOf(DeepLink.Item(DeepLink.CONFIG, vless), DeepLink.Item(DeepLink.SUB, sub, "panel.example"), DeepLink.Item(DeepLink.CONFIG, "ss://a@b:1#c")),
            DeepLink.fromShared(text)
        )
        assertNull(DeepLink.fromShared("hello"))
        assertNull(DeepLink.fromShared(""))
        assertNull(DeepLink.fromShared("\n\n"))
        // at most 50
        val many = (1..60).joinToString("\n") { i: Int -> "vless://u@h$i:443#n$i" }
        assertEquals(DeepLink.MAX_SHARED, DeepLink.fromShared(many)?.size)
        assertEquals("vless://u@h1:443#n1", DeepLink.fromShared(many)?.first()?.text)
        // one irnetfree:// link shared whole is read as if it had been opened — a routing link too
        assertEquals(listOf(DeepLink.Item(DeepLink.ROUTING, routing)), DeepLink.fromShared(" $routing\n"))
        assertEquals(listOf(DeepLink.Item(DeepLink.SUB, sub, "panel.example", "P")), DeepLink.fromShared("irnetfree://import?url=" + enc(sub) + "&name=P"))
        assertNull(DeepLink.fromShared("irnetfree://nothing/here"))
        // several irnetfree:// lines are not read one by one: none is a payload
        assertNull(DeepLink.fromShared("$routing\n$routing"))
    }

    @Test fun percentDecodingIsTheBrowsersDecodeURIComponent() {
        assertEquals("plain", DeepLink.pctDecode("plain"))
        assertEquals("a b", DeepLink.pctDecode("a%20b"))
        // a + is a +, as a base64 vmess body needs
        assertEquals("a+b", DeepLink.pctDecode("a+b"))
        assertEquals("س", DeepLink.pctDecode("%D8%B3"))
        assertEquals("🇩🇪 x", DeepLink.pctDecode("%F0%9F%87%A9%F0%9F%87%AA%20x"))
        assertEquals("%", DeepLink.pctDecode("%25"))
        assertNull(DeepLink.pctDecode("%zz"))
        assertNull(DeepLink.pctDecode("abc%"))
        assertNull(DeepLink.pctDecode("%4"))
        assertNull(DeepLink.pctDecode("%ff"))
        assertNull(DeepLink.pctDecode("%C3%28"))
        // the host of an http(s) URL, as the dialog names it
        assertEquals("h.example", DeepLink.hostOf("https://u:p@h.example:443/x?y#z"))
        assertNull(DeepLink.hostOf("https:///x"))
        assertNull(DeepLink.hostOf("nohost"))
    }
}
