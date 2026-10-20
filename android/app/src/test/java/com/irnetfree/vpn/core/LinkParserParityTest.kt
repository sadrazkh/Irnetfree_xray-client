package com.irnetfree.vpn.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Where the phone read a share link differently from the desktop
 * (src/main/parser.js), each pinned to what the desktop gives. android.util.Base64
 * is a stub off a device, so the base64 halves are checked through the pure
 * helpers (linkText, b64Data, vmessData) with java.util.Base64 doing the decoding.
 */
class LinkParserParityTest {
    private fun stream(s: ServerConfig) = s.outbound.getJSONObject("streamSettings")
    private fun server0(s: ServerConfig) = s.outbound.getJSONObject("settings").getJSONArray("servers").getJSONObject(0)
    private fun peer0(s: ServerConfig) = s.outbound.getJSONObject("settings").getJSONArray("peers").getJSONObject(0)
    private fun b64(s: String): String = java.util.Base64.getEncoder().encodeToString(s.toByteArray(Charsets.UTF_8))
    /** LinkParser's own decoding, with the JVM's decoder in android.util.Base64's place. */
    private fun jvmB64(s: String): String =
        String(java.util.Base64.getDecoder().decode(LinkParser.b64Normalize(LinkParser.b64Data(s))), Charsets.UTF_8)
    /** The reasons parseMany gives, without the line each is about. */
    private fun why(errors: List<String>): List<String> = errors.map { e: String -> e.substringAfter("… : ") }

    /*
     * A base64 subscription is recognised by a link at the start of ANY line of
     * what it decodes to (parser.js SCHEME_LINE). Only the first character was
     * looked at: a body opening with `#profile-title:` or a blank line imported 0.
     */
    @Test fun aSubscriptionIsFoundByALinkOnAnyLine() {
        val vless = "vless://u@a.example:443?security=none#A"
        for (body in listOf("#profile-title: base64:SVJOZXRGcmVl\n#profile-update-interval: 1\n$vless\n", "\n$vless\n", "$vless\n")) {
            assertEquals(body, LinkParser.linkText(b64(body)) { s: String -> jvmB64(s) })
        }
        // a text with a link on a line of its own is read as it is, never decoded
        val plain = "#profile-title: x\n\n$vless"
        assertEquals(plain, LinkParser.linkText(plain) { _: String -> throw AssertionError("decoded") })
        // nothing that decodes to a link: the text itself
        assertEquals("hello", LinkParser.linkText("hello") { _: String -> "" })
        // ...and read line by line, the comment and the blank line skipped
        val (servers, errors) = LinkParser.parseMany(plain)
        assertEquals(listOf("A"), servers.map { s: ServerConfig -> s.name })
        assertTrue(errors.toString(), errors.isEmpty())
    }

    /* tuic / anytls lines are said (parser.js parseMany), not dropped; http(s) lines and comments stay skipped. */
    @Test fun aLinkOfAProtocolThisAppDoesNotSpeakIsSaidNotSkipped() {
        val text = "vless://u@a.example:443?security=none#A\ntuic://uuid:pw@t.example:443#T\nANYTLS://pw@n.example:443#N\n" +
            "https://t.me/channel\nhttp://sub.example/path\n# a comment\nnot a link"
        val (servers, errors) = LinkParser.parseMany(text)
        assertEquals(listOf("A"), servers.map { s: ServerConfig -> s.name })
        assertEquals(listOf("unsupported protocol: tuic", "unsupported protocol: anytls"), why(errors))
        assertEquals("tuic://uuid:pw@t.example… : unsupported protocol: tuic", errors[0])
    }

    /* `raw` is tcp (parser.js buildStreamSettings): its HTTP header was dropped. */
    @Test fun rawIsTcpAndKeepsItsHttpHeader() {
        val v = LinkParser.parseLink("vless://u@h.example:443?type=raw&headerType=http&host=cdn.example&path=%2Fp&security=none#v")
        val st = stream(v)
        assertEquals("tcp", st.getString("network"))
        val rq = st.getJSONObject("tcpSettings").getJSONObject("header").getJSONObject("request")
        assertEquals("""["/p"]""", rq.getJSONArray("path").toString())
        assertEquals("""["cdn.example"]""", rq.getJSONObject("headers").getJSONArray("Host").toString())
        // ...and the share link carries it
        assertEquals(Canon.of(st), Canon.of(stream(LinkParser.parseLink(LinkParser.buildShareLink(v)))))
        assertEquals("tcp", stream(LinkParser.parseLink("vless://u@h.example:443?type=raw&security=none")).getString("network"))

        val t = LinkParser.parseLink("trojan://pw@h.example:443?type=raw&headerType=http&host=cdn.example&security=none#t")
        assertEquals("http", stream(t).getJSONObject("tcpSettings").getJSONObject("header").getString("type"))

        val vm = LinkParser.vmessFromJson(JSONObject("""{"add":"v.example","port":443,"id":"U","net":"raw","type":"http","host":"cdn.example","path":"/p"}"""), "")
        assertEquals("tcp", stream(vm).getString("network"))
        assertEquals("http", stream(vm).getJSONObject("tcpSettings").getJSONObject("header").getString("type"))

        val ss = LinkParser.parseLink("ss://aes-128-gcm:pw@h.example:8388?type=raw&headerType=http&host=cdn.example#s")
        assertEquals("tcp", stream(ss).getString("network"))
        assertEquals("http", stream(ss).getJSONObject("tcpSettings").getJSONObject("header").getString("type"))
    }

    /*
     * An IPv6 host is bracketed wherever a host and a port are joined (parser.js
     * joinHostPort): `2606:…:c001:2408` is an endpoint nothing can split.
     */
    @Test fun anIpv6HostIsBracketedInEveryEndpointAndShareLink() {
        assertEquals("[2606:4700:d0::a29f:c001]:2408", LinkParser.joinHostPort("2606:4700:d0::a29f:c001", 2408))
        assertEquals("162.159.192.1:2408", LinkParser.joinHostPort("162.159.192.1", 2408))
        assertEquals("engage.example.com:2408", LinkParser.joinHostPort("engage.example.com", 2408))
        assertEquals("[2606:4700::1]:2408", LinkParser.joinHostPort("[2606:4700::1]", 2408))   // never twice

        val wg = LinkParser.parseLink("wireguard://PRIV@[2606:4700:d0::a29f:c001]:2408?publickey=PUB&address=172.16.0.2%2F32#w")
        assertEquals("2606:4700:d0::a29f:c001", wg.address); assertEquals(2408, wg.port)
        assertEquals("[2606:4700:d0::a29f:c001]:2408", peer0(wg).getString("endpoint"))
        assertEquals(AddressSwap.Dial("2606:4700:d0::a29f:c001", 2408), AddressSwap.dialOf(wg))
        val wgLink = LinkParser.buildShareLink(wg)
        assertTrue(wgLink, wgLink.startsWith("wireguard://PRIV@[2606:4700:d0::a29f:c001]:2408?"))
        val wgBack = LinkParser.parseLink(wgLink)
        assertEquals("2606:4700:d0::a29f:c001", wgBack.address); assertEquals(2408, wgBack.port)
        assertEquals(Canon.of(peer0(wg)), Canon.of(peer0(wgBack)))

        val manual = LinkParser.makeWireguardServer("m", "[2001:db8::2]:51821", "PRIV", "PUB", "10.0.0.2", "", "", "1420", null)
        assertEquals("[2001:db8::2]:51821", peer0(manual).getString("endpoint"))
        assertEquals("wireguard://[2001:db8::2]:51821", manual.raw)
        assertEquals("2001:db8::2", manual.address); assertEquals(51821, manual.port)

        val made = ServerEditor.create("wireguard", ServerEditor.Fields(address = "2001:db8::3", port = "2408", cred = "PRIV", wgPub = "PUB"))
        assertEquals("[2001:db8::3]:2408", peer0(made).getString("endpoint"))
        assertTrue(made.raw, made.raw.startsWith("wireguard://PRIV@[2001:db8::3]:2408?"))
        val moved = ServerEditor.apply(made, ServerEditor.read(made).copy(address = "2001:db8::4"))
        assertEquals("[2001:db8::4]:2408", peer0(moved).getString("endpoint"))

        // a sing-box WireGuard is written as its link and parsed (JsonImport): bracketed too
        val sb = JsonImport.serversFromSingbox(JSONObject("""{"outbounds":[{"type":"wireguard","tag":"wg6","server":"2606:4700:d0::a29f:c001",
            "server_port":2408,"private_key":"PRIV","peer_public_key":"PUB","local_address":["172.16.0.2/32"]}]}"""))
        assertTrue(sb.errors.toString(), sb.errors.isEmpty())
        assertEquals("[2606:4700:d0::a29f:c001]:2408", peer0(sb.servers.single()).getString("endpoint"))

        for (link in listOf(
            "vless://u@[2001:db8::1]:443?security=none#v",
            "trojan://pw@[2001:db8::1]:443?security=tls&sni=a.example#t",
            "socks://[2001:db8::1]:1080#s",
            "hysteria2://pw@[2001:db8::1]:443/?sni=a.example#h")) {
            val s = LinkParser.parseLink(link)
            assertEquals(link, "2001:db8::1", s.address)
            val out = LinkParser.buildShareLink(s)
            assertTrue(out, out.contains("[2001:db8::1]:" + s.port))
            val back = LinkParser.parseLink(out)
            assertEquals(out, "2001:db8::1", back.address); assertEquals(out, s.port, back.port)
        }
        // Shadowsocks too (its userinfo goes out as base64, a stub here: only the host part is looked at)
        val ss = LinkParser.parseLink("ss://aes-128-gcm:pw@[2001:db8::1]:8388#s")
        assertTrue(LinkParser.buildShareLink(ss).contains("@[2001:db8::1]:8388"))
    }

    /*
     * Node's Buffer stops at the first '=' and ignores what follows the padding:
     * `vmess://<b64>==#name` imports on the desktop and failed here.
     */
    @Test fun vmessIgnoresWhatFollowsItsBase64() {
        val enc = b64("""{"v":"2","ps":"VM","add":"v.example","port":"443","id":"U","net":"ws","path":"/w"}""")
        assertTrue("the fixture carries padding", enc.endsWith("=="))
        val bare = enc.trimEnd('=')
        for (link in listOf("vmess://$enc", "vmess://$enc#My%20name", "vmess://${enc}trailing", "vmess://$bare#name", "vmess://$bare")) {
            assertEquals(link, "v.example", JSONObject(jvmB64(LinkParser.vmessData(link))).getString("add"))
        }
        assertEquals("YQ", LinkParser.b64Data("YQ==YQ=="))
        assertEquals("YWJj", LinkParser.b64Data("YWJj"))
        // what does not decode is said as the desktop says it
        assertEquals(listOf("VMess: invalid base64/JSON"), why(LinkParser.parseMany("vmess://not-base64-json").second))
    }

    /*
     * Shadowsocks userinfo: plain `method:password` (percent-encoded — SS-2022
     * keys carry %2B and %3D%3D) is read before base64 is tried (parser.js).
     */
    @Test fun shadowsocksReadsAPlainMethodPasswordFirst() {
        val s22 = LinkParser.parseLink("ss://2022-blake3-aes-128-gcm:YWJjZGVmZ2hpamtsbW5vcA%3D%3D@h.example:8388#s22")
        assertEquals("2022-blake3-aes-128-gcm", server0(s22).getString("method"))
        assertEquals("YWJjZGVmZ2hpamtsbW5vcA==", server0(s22).getString("password"))
        val plus = LinkParser.parseLink("ss://2022-blake3-aes-256-gcm:a%2Bb%2Fc%3D%3A1@h.example:8388#p")
        assertEquals("2022-blake3-aes-256-gcm", server0(plus).getString("method"))
        assertEquals("a+b/c=:1", server0(plus).getString("password"))
        val whole = LinkParser.parseLink("ss://aes-256-gcm%3Apass@h.example:8388#w")
        assertEquals("aes-256-gcm", server0(whole).getString("method")); assertEquals("pass", server0(whole).getString("password"))
    }

    /* JavaScript's `||` falls through an empty value; Kotlin's `?:` kept it. */
    @Test fun anEmptyValueFallsThroughToTheNextSpelling() {
        val h = LinkParser.parseLink("hysteria2://pw@h.example:443/?sni=&peer=p.example&obfs=salamander&obfs-password=&obfsPassword=secret" +
            "&up=&upmbps=50&down=&downmbps=100#h")
        assertEquals("p.example", stream(h).getJSONObject("tlsSettings").getString("serverName"))
        val fm = stream(h).getJSONObject("finalmask")
        assertEquals("secret", fm.getJSONArray("udp").getJSONObject(0).getJSONObject("settings").getString("password"))
        assertEquals("50 mbps", fm.getJSONObject("quicParams").getString("brutalUp"))
        assertEquals("100 mbps", fm.getJSONObject("quicParams").getString("brutalDown"))

        val ss = LinkParser.parseLink("ss://aes-128-gcm:pw@h.example:8388?type=&network=ws&path=%2Fw&host=cdn.example#s")
        assertEquals("ws", stream(ss).getString("network"))
        assertEquals("/w", stream(ss).getJSONObject("wsSettings").getString("path"))

        fun insecure(json: String): Boolean =
            stream(LinkParser.vmessFromJson(JSONObject(json), "")).getJSONObject("tlsSettings").getBoolean("allowInsecure")
        assertTrue(insecure("""{"add":"v.example","port":443,"id":"U","tls":"tls","allowInsecure":false,"insecure":"1"}"""))
        assertTrue(insecure("""{"add":"v.example","port":443,"id":"U","tls":"tls","allowInsecure":0,"insecure":true}"""))
        assertTrue(insecure("""{"add":"v.example","port":443,"id":"U","tls":"tls","allowInsecure":true}"""))
        // "0" is a value to `||` (a non-empty string): no fall-through, and not insecure
        assertFalse(insecure("""{"add":"v.example","port":443,"id":"U","tls":"tls","allowInsecure":"0","insecure":"1"}"""))
        assertFalse(insecure("""{"add":"v.example","port":443,"id":"U","tls":"tls"}"""))

        // `parseInt(n) || 0` per reserved byte, `parseInt(mtu) || 1420`
        val wg = LinkParser.parseLink("wireguard://PRIV@w.example:51820?publickey=PUB&reserved=1,2,x&mtu=0#w")
        val set = wg.outbound.getJSONObject("settings")
        assertEquals("[1,2,0]", set.getJSONArray("reserved").toString())
        assertEquals(1420, set.getInt("mtu"))
        assertEquals(listOf(1, 2, 0), LinkParser.wgReserved("1, 2, x"))
        assertEquals(listOf(12, -1), LinkParser.wgReserved("12abc,-1"))
        assertTrue(LinkParser.wgReserved("").isEmpty())
    }

    /* What crashed with an index out of bounds now says what is missing. */
    @Test fun aLinkMissingItsCredentialSaysSo() {
        val text = listOf(
            "vless://h.example:443?security=none#v",
            "trojan://h.example:443#t",
            "ss://aes-128-gcm-without-a-password@h.example:8388#s",
            "ss://aes-128-gcm:pw@h.example:8388/?plugin=%3B#p").joinToString("\n")
        val (servers, errors) = LinkParser.parseMany(text)
        assertTrue(servers.isEmpty())
        assertEquals(listOf("VLESS: the user id is missing (uuid@host:port)", "Trojan: the password is missing (password@host:port)",
            "Shadowsocks: cannot read method:password from the link", "Shadowsocks: the plugin option names no plugin"), why(errors))
    }

    /* A pasted .conf is one server (parser.js parseMany), not lines skipped one by one. */
    @Test fun aPastedWireguardConfIsOneServer() {
        val conf = "[Interface]\r\nPrivateKey = PRIV\r\nAddress = 172.16.0.2/32\r\nDNS = 1.1.1.1, corp.local\r\nMTU = 1280\r\n\r\n" +
            "[Peer]\r\nPublicKey = PUB\r\nAllowedIPs = 0.0.0.0/0, ::/0\r\nEndpoint = [2606:4700:d0::a29f:c001]:2408\r\n"
        val (servers, errors) = LinkParser.parseMany(conf)
        assertTrue(errors.toString(), errors.isEmpty())
        val s = servers.single()
        assertEquals("wireguard", s.protocol); assertEquals("2606:4700:d0::a29f:c001", s.address); assertEquals(2408, s.port)
        assertEquals("[2606:4700:d0::a29f:c001]:2408", peer0(s).getString("endpoint"))
        assertEquals("PRIV", s.outbound.getJSONObject("settings").getString("secretKey"))
        assertEquals(1280, s.outbound.getJSONObject("settings").getInt("mtu"))
        assertEquals(listOf("1.1.1.1"), s.dns); assertEquals(listOf("corp.local"), s.dnsDomains)
        val noKey = "[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = PUB\nEndpoint = h.example:51820\n"
        assertEquals(listOf("[Interface]… : WireGuard config: PrivateKey is missing"), LinkParser.parseMany(noKey).second)
    }
}
