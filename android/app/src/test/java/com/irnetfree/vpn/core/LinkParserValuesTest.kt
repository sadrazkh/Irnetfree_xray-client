package com.irnetfree.vpn.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * How a link's VALUES are read — the three places the port read them differently
 * from src/main/parser.js, each pinned against what the desktop gives for the
 * very same link (node -e "require('./src/main/parser.js').parseLink(…)").
 */
class LinkParserValuesTest {
    private fun stream(s: ServerConfig) = s.outbound.getJSONObject("streamSettings")
    private fun vnextUser(s: ServerConfig) = s.outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0)
    private fun server0(s: ServerConfig) = s.outbound.getJSONObject("settings").getJSONArray("servers").getJSONObject(0)
    private fun peer0(s: ServerConfig) = s.outbound.getJSONObject("settings").getJSONArray("peers").getJSONObject(0)

    /*
     * A present-but-empty field is a missing one. v2rayN exports every key it
     * knows, empty ones included: `type=` became network "" (which xray refuses
     * outright), `sni=` an empty SNI instead of the Host, `fp=` no uTLS at all.
     * The desktop reads all of them with `||`.
     */
    @Test fun anEmptyFieldIsAMissingOne() {
        val s = LinkParser.parseLink("vless://u@h.example:443?type=&security=tls&sni=&host=cdn.example&fp=&encryption=&flow=&fragment=&noise=#x")
        assertEquals("tcp", stream(s).getString("network"))
        val tls = stream(s).getJSONObject("tlsSettings")
        assertEquals("cdn.example", tls.getString("serverName"))
        assertEquals("chrome", tls.getString("fingerprint"))
        assertEquals("none", vnextUser(s).getString("encryption"))
        assertEquals("", vnextUser(s).getString("flow"))
        assertFalse(s.outbound.has("_fragment")); assertFalse(s.outbound.has("_noise"))

        val r = LinkParser.parseLink("vless://u@h.example:443?security=reality&sni=www.google.com&fp=&pbk=K&sid=&flow=xtls-rprx-vision#r")
        val rs = stream(r).getJSONObject("realitySettings")
        assertEquals("chrome", rs.getString("fingerprint")); assertEquals("", rs.getString("shortId"))
        assertEquals("tcp", stream(r).getString("network"))

        val w = LinkParser.parseLink("vless://u@h.example:443?type=ws&path=&host=&security=none#w")
        val ws = stream(w).getJSONObject("wsSettings")
        assertEquals("/", ws.getString("path")); assertFalse(ws.getJSONObject("headers").has("Host"))

        // trojan's own default (tls) applies to an empty `security=` too
        val t = LinkParser.parseLink("trojan://p@h.example:443?security=&sni=a.com#t")
        assertEquals("tls", stream(t).getString("security"))
        assertEquals("a.com", stream(t).getJSONObject("tlsSettings").getString("serverName"))
    }

    /*
     * `host:port/?…` — the slash before the query is part of the link, and
     * "2053/" is not a number, so every such link fell back to port 443.
     * parseInt("2053/") is 2053 on the desktop.
     */
    @Test fun aPortFollowedByASlashIsStillThePort() {
        val v = LinkParser.parseLink("vless://u@h.example:2053/?type=ws&path=%2Fws&host=a.com&security=tls#x")
        assertEquals("h.example", v.address); assertEquals(2053, v.port)
        assertEquals(2053, v.outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getInt("port"))

        val t = LinkParser.parseLink("trojan://p@[2001:db8::1]:8443/?sni=a.com#n")
        assertEquals("2001:db8::1", t.address); assertEquals(8443, t.port)

        val socks = LinkParser.parseLink("socks://user:pass@1.2.3.4:9050/#s")
        assertEquals("1.2.3.4", socks.address); assertEquals(9050, socks.port)

        val wg = LinkParser.parseLink("wireguard://PRIV@cobra.example:42421/?publickey=PUB#w")
        assertEquals(42421, wg.port); assertEquals("cobra.example:42421", peer0(wg).getString("endpoint"))
    }

    /* `[v6]` with no port threw StringIndexOutOfBounds; the desktop gives the default. */
    @Test fun aBracketedAddressWithoutAPortTakesTheDefault() {
        val t = LinkParser.parseLink("trojan://p@[2001:db8::1]?sni=a.com#n")
        assertEquals("2001:db8::1", t.address); assertEquals(443, t.port)
        val w = LinkParser.parseLink("wireguard://PRIV@[2001:db8::2]?publickey=PUB#w")
        assertEquals("2001:db8::2", w.address); assertEquals(51820, w.port)
    }

    /*
     * A `+` is a `+`. URLDecoder (form decoding) turned it into a space, which
     * corrupts every standard-base64 key — Cloudflare WARP's public keys carry
     * '+' — and any trojan password with one. The desktop's decodeURIComponent
     * only decodes %XX.
     */
    @Test fun aPlusInAKeyOrPasswordIsAPlus() {
        val priv = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
        val pub = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
        val warp = "wireguard://$priv@engage.cloudflareclient.com:2408?publickey=$pub" +
            "&address=172.16.0.2/32,2606:4700:110:8a36::1/128&reserved=1,2,3&mtu=1280#warp"
        val s = LinkParser.parseLink(warp)
        assertEquals(priv, s.outbound.getJSONObject("settings").getString("secretKey"))
        assertEquals(pub, peer0(s).getString("publicKey"))
        assertEquals("""[1,2,3]""", s.outbound.getJSONObject("settings").getJSONArray("reserved").toString())

        // the same keys escaped (%2B, %2F, %3D) decode to the same thing
        val esc = LinkParser.parseLink("wireguard://yAnz5TF%2BlXXJte14tji3zlMNq%2Bhd2rYUIgJBgB3fBmk%3D@engage.cloudflareclient.com:2408" +
            "?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D#warp")
        assertEquals(priv, esc.outbound.getJSONObject("settings").getString("secretKey"))
        assertEquals(pub, peer0(esc).getString("publicKey"))

        // ...and they survive the app's own share link
        val again = LinkParser.parseLink(LinkParser.buildShareLink(s))
        assertEquals(priv, again.outbound.getJSONObject("settings").getString("secretKey"))
        assertEquals(pub, peer0(again).getString("publicKey"))

        val t = LinkParser.parseLink("trojan://pa+ss%2Fw@h.example:443?sni=a.com#n")
        assertEquals("pa+ss/w", server0(t).getString("password"))
        assertEquals("pa+ss/w", server0(LinkParser.parseLink(LinkParser.buildShareLink(t))).getString("password"))
    }

    /*
     * vmess goes through android.util.Base64, a stub off a device, so its JSON
     * half is tested on its own: v2rayN writes `"sni": ""`, `"fp": ""`, `"net": ""`.
     */
    @Test fun vmessReadsEmptyFieldsAsMissing() {
        val v = JSONObject("""{"v":"2","ps":"","add":"v.example","port":"2083","id":"U","aid":"0","scy":"","net":"",
            "type":"","host":"cdn.example","path":"","tls":"tls","sni":"","fp":"","alpn":"","fragment":"","noise":""}""")
        val s = LinkParser.vmessFromJson(v, "vmess://x")
        assertEquals("v.example", s.name); assertEquals(2083, s.port); assertEquals("vmess://x", s.raw)
        assertEquals("tcp", stream(s).getString("network"))
        val tls = stream(s).getJSONObject("tlsSettings")
        assertEquals("cdn.example", tls.getString("serverName")); assertEquals("chrome", tls.getString("fingerprint"))
        assertEquals("auto", vnextUser(s).getString("security"))
        assertFalse(s.outbound.has("_fragment")); assertFalse(s.outbound.has("_noise"))
        val ws = LinkParser.vmessFromJson(JSONObject("""{"add":"v.example","port":443,"id":"U","net":"ws","host":"h.example","path":"","tls":"tls","sni":"s.example"}"""), "")
        assertEquals("/", stream(ws).getJSONObject("wsSettings").getString("path"))
        assertEquals("s.example", stream(ws).getJSONObject("tlsSettings").getString("serverName"))
        assertEquals(443, ws.port)
    }

    /*
     * A panel's base64 wrapped at 76 columns: the padding was counted with the
     * newlines in, and android.util.Base64 refuses the extra '='. (The decoder
     * is a stub here, so the normalisation is checked against java.util.Base64.)
     */
    @Test fun wrappedBase64IsNormalisedBeforeDecoding() {
        val body = "vless://u@a.example:443?security=none#A\nvless://u@b.example:443?security=none#B\n"
        val enc = java.util.Base64.getEncoder().encodeToString(body.toByteArray())
        val wrapped = enc.chunked(76).joinToString("\r\n") + "\n"
        val norm = LinkParser.b64Normalize(wrapped)
        assertEquals(enc, norm)
        assertEquals(body, String(java.util.Base64.getDecoder().decode(norm)))
        // unpadded, URL-safe, wrapped
        val url = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(byteArrayOf(-5, -1, -2, 0x3e, 0x3f))
        assertEquals(0, LinkParser.b64Normalize(url.chunked(3).joinToString("\n")).length % 4)
        assertEquals(listOf(-5, -1, -2, 0x3e, 0x3f), java.util.Base64.getDecoder().decode(LinkParser.b64Normalize(url.chunked(3).joinToString("\n"))).map { it.toInt() })
    }

    @Test fun portOfReadsLeadingDigits() {
        assertEquals(2053, LinkParser.portOf("2053/", 443)); assertEquals(8443, LinkParser.portOf("8443", 443))
        assertEquals(443, LinkParser.portOf("", 443)); assertEquals(443, LinkParser.portOf("x", 443)); assertEquals(443, LinkParser.portOf("0", 443))
    }

    @Test fun pctDecodeIsDecodeUriComponent() {
        assertEquals("a+b c/é", LinkParser.pctDecode("a+b%20c%2F%C3%A9"))
        assertEquals("%zz", LinkParser.pctDecode("%zz")); assertEquals("%C3", LinkParser.pctDecode("%C3"))
        assertEquals("سرور", LinkParser.pctDecode("سرور"))
    }

    /* renderer/app.js isSubUrl: an http proxy link is a server, not a subscription. */
    @Test fun anHttpProxyLinkIsNotASubscriptionUrl() {
        assertTrue(LinkParser.isSubUrl("https://sub.example.com/abc?token=1"))
        assertTrue(LinkParser.isSubUrl("http://sub.example.com/path"))
        assertFalse(LinkParser.isSubUrl("http://user:pass@1.2.3.4:8080#office"))
        assertFalse(LinkParser.isSubUrl("http://1.2.3.4:3128"))
        assertFalse(LinkParser.isSubUrl("vless://u@h:443"))
    }

    /* A name with a space goes out as %20 — a '+' would now come back as a '+'. */
    @Test fun aNameWithASpaceRoundTrips() {
        val named = LinkParser.parseLink("vless://u@h.example:443?security=none#My%20Server")
        assertEquals("My Server", named.name)
        assertEquals("My Server", LinkParser.parseLink(LinkParser.buildShareLink(named)).name)
        // the desktop keeps a literal '+' in a name, so this port does too
        assertEquals("My+Server", LinkParser.parseLink("vless://u@h.example:443?security=none#My+Server").name)
        // a malformed escape leaves the text as it was, as decodeURIComponent's caller does
        assertEquals("100%", LinkParser.parseLink("vless://u@h.example:443?security=none#100%").name)
        assertEquals(Canon.of(JSONObject("""{"network":"tcp","security":"none"}""")), Canon.of(stream(named)))
    }
}
