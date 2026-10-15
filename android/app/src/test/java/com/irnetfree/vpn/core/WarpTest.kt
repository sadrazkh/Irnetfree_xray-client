package com.irnetfree.vpn.core

import okhttp3.Protocol
import okhttp3.TlsVersion
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.SocketTimeoutException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLHandshakeException

/**
 * WARP on MASQUE (Warp.kt) against the desktop's tests/warp.test.js: a device
 * registered with Cloudflare's API — always a FAKE of it here (FakeApi below,
 * the desktop's warpFakes.js); the real api.cloudflareclient.com is never
 * dialled — or brought in from usque / a pasted Xray outbound, the editor's
 * fields for one server per HTTP version, and the whole sign-up.
 */
class WarpTest {
    private val token = "tok-3f9a1c0e-SECRET-5b7d2e48a1"
    private val deviceId = "dev-0a1b2c3d"
    private val license = "A1b2C3d4-E5f6G7h8-I9j0K1l2"
    private val now = 1_791_970_215_123L   // 2026-10-14T09:30:15.123Z

    private fun p256(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val b64e = Base64.getEncoder()
    /** The MASQUE edge's key, as Cloudflare hands it out: base64 SPKI DER (a key made here). */
    private val edgePub: String = b64e.encodeToString(p256().public.encoded)

    private fun der(pem: String): ByteArray = Base64.getDecoder().decode(pem.replace(Regex("-----[^-]+-----"), "").replace(Regex("\\s+"), ""))

    /** Does this PKCS#8 PEM sign what [pub] verifies — are they one key pair? */
    private fun pairs(privatePem: String, pub: PublicKey): Boolean {
        val priv = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(der(privatePem)))
        val sig = Signature.getInstance("SHA256withECDSA").apply { initSign(priv); update("warp".toByteArray()) }.sign()
        return Signature.getInstance("SHA256withECDSA").apply { initVerify(pub); update("warp".toByteArray()) }.verify(sig)
    }
    private fun spkiKey(b64: String): PublicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(b64)))

    /* ------------------------------ the fake API ------------------------------ */

    private fun config(peer: JSONObject = JSONObject().put("public_key", edgePub)
        .put("endpoint", JSONObject().put("v4", "162.159.198.1:0").put("v6", "[2606:4700:103::1]:0").put("host", "engage.cloudflareclient.com:2408")),
                       addresses: JSONObject = JSONObject().put("v4", "172.16.0.2").put("v6", "2606:4700:110:8a36:9c1:2b3:4d5:6e7f")): JSONObject =
        JSONObject().put("client_id", "AAAA").put("peers", JSONArray().put(peer))
            .put("interface", JSONObject().put("addresses", addresses)).put("services", JSONObject().put("http_proxy", "172.16.0.1:2480"))

    /** A device record as the API answers it (usque's AccountData shape). */
    private fun device(warpEnabled: Boolean = true, cfg: JSONObject = config()): JSONObject = JSONObject()
        .put("id", deviceId).put("type", "a").put("model", "PC").put("name", "").put("key", "").put("key_type", "secp256r1").put("tunnel_type", "masque")
        .put("account", JSONObject().put("id", "acc-77").put("account_type", "free").put("warp_plus", false).put("premium_data", 0).put("quota", 0).put("license", "xyz"))
        .put("config", cfg).put("warp_enabled", warpEnabled).put("waitlist_enabled", false).put("enabled", true).put("locale", "en_US")

    class Call(val method: String, val path: String, val headers: Map<String, String>, val body: JSONObject?)

    /**
     * The API, step by step as Cloudflare answers it: [enrolled] the PATCH key
     * answer (default: a fresh device, warp_enabled false), [activated] the
     * PATCH warp_enabled answer, [fetched] the GET answer, [licensed] the PUT
     * answer, [status] a status (and [errorBody]) instead of an answer, by route.
     */
    inner class FakeApi(
        val enrolled: JSONObject? = null, val activated: JSONObject? = null, val fetched: JSONObject? = null,
        val licensed: JSONObject? = null, val status: Map<String, Int> = emptyMap(), val errorBody: String? = null
    ) {
        val calls = ArrayList<Call>()
        private fun ok(o: JSONObject): Warp.Res = Warp.Res(200, o.toString())
        private val unauth = Warp.Res(401, """{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}""")

        fun call(r: Warp.Req): Warp.Res {
            val body: JSONObject? = r.body?.takeIf { x: String -> x.isNotEmpty() }?.let { x: String -> JSONObject(x) }
            calls.add(Call(r.method, r.path, HashMap(r.headers), body))
            val route = r.method + " " + r.path.removePrefix("/v0a5641").replace(deviceId, "{id}")
            val st = status[route]
            if (st != null) return Warp.Res(st, errorBody ?: """{"success":false,"errors":[{"code":1000,"message":"Refused by the fake"}]}""")
            val authed = r.headers["Authorization"] == "Bearer $token"
            return when (route) {
                "POST /reg" -> ok(device(false).put("token", token).put("key_type", "curve25519").put("tunnel_type", "wireguard"))
                "PATCH /reg/{id}" -> when {
                    !authed -> unauth
                    body?.opt("warp_enabled") == true -> ok(activated ?: device())
                    else -> ok(enrolled ?: device(false))
                }
                "GET /reg/{id}" -> if (!authed) unauth else ok(fetched ?: device())
                "PUT /reg/{id}/account" -> if (!authed) unauth else ok(licensed ?: JSONObject().put("id", "acc-77").put("account_type", "unlimited")
                    .put("warp_plus", true).put("premium_data", 1).put("license", body?.optString("license") ?: ""))
                else -> Warp.Res(404, """{"success":false,"errors":[{"code":404,"message":"no route $route"}]}""")
            }
        }
    }

    private class Registered(val reg: Warp.Reg, val api: WarpTest.FakeApi, val lines: List<String>)

    private fun register(api: FakeApi = FakeApi(), lic: String = ""): Registered {
        val lines = ArrayList<String>()
        val reg = Warp.registerWarp({ r: Warp.Req -> api.call(r) }, lic, { now }, { line: String, _: String -> lines.add(line) })
        return Registered(reg, api, lines)
    }

    private fun refusal(code: String, body: () -> Unit): Warp.WarpError {
        try {
            body()
        } catch (e: Warp.WarpError) {
            assertEquals(e.message, code, e.code)
            return e
        }
        fail("no $code")
        throw AssertionError()
    }

    private fun route(c: Call): String = c.method + " " + c.path.removePrefix("/v0a5641")

    /* -------------------------------- the requests -------------------------------- */

    @Test fun post_usquesBody_aThrowaway32ByteKey_tosNow_a16HexSerial_andWgcfsHeaders_noToken() {
        val post = register().api.calls[0]
        assertEquals("POST", post.method)
        assertEquals("/v0a5641/reg", post.path)
        assertEquals("1.1.1.1/6.38.9-5641 (Android 16.0.0)", post.headers["User-Agent"])
        assertEquals("a-6.38.9-5641", post.headers["CF-Client-Version"])
        assertEquals("application/json; charset=UTF-8", post.headers["Content-Type"])
        assertEquals("identity", post.headers["Accept-Encoding"])
        assertFalse(post.headers.containsKey("Authorization"))
        val b = post.body!!
        assertEquals(listOf("fcm_token", "install_id", "key", "key_type", "locale", "model", "os_version", "serial_number", "tos", "tunnel_type"), b.keySet().sorted())
        assertEquals("2026-10-14T09:30:15.123Z", b.getString("tos"))
        assertEquals(listOf("curve25519", "wireguard", "PC", "en_US", "", "", ""),
            listOf("key_type", "tunnel_type", "model", "locale", "install_id", "fcm_token", "os_version").map { k: String -> b.getString(k) })
        assertTrue(Regex("^[0-9a-f]{16}$").matches(b.getString("serial_number")))
        assertEquals(32, Base64.getDecoder().decode(b.getString("key")).size)
    }

    @Test fun patch_withTheBearerToken_andExactlyOurP256KeysSpki_secp256r1_masque() {
        val r = register()
        val patch = r.api.calls[1]
        assertEquals("PATCH", patch.method)
        assertEquals("/v0a5641/reg/$deviceId", patch.path)
        assertEquals("Bearer $token", patch.headers["Authorization"])
        assertEquals("a-6.38.9-5641", patch.headers["CF-Client-Version"])
        assertEquals(listOf("key", "key_type", "tunnel_type"), patch.body!!.keySet().sorted())
        assertEquals("secp256r1", patch.body.getString("key_type"))
        assertEquals("masque", patch.body.getString("tunnel_type"))
        // the key enrolled is the public half of the private key handed back
        assertTrue(pairs(r.reg.privateKey, spkiKey(patch.body.getString("key"))))
        assertNotNull(Masque.p256Pkcs8(der(r.reg.privateKey)))
        assertTrue("PKCS#8 PEM", Regex("^-----BEGIN PRIVATE KEY-----\\n[\\s\\S]+\\n-----END PRIVATE KEY-----\\n?$").matches(r.reg.privateKey))
    }

    @Test fun warpEnabled_switchedOnOnlyWhenTheAnswerSaysItIsNot_checked_aDeviceThatStaysOffIsAWarning() {
        // a fresh device answers warp_enabled:false → PATCH { warp_enabled: true }
        var r = register()
        assertEquals(listOf("POST /reg", "PATCH /reg/$deviceId", "PATCH /reg/$deviceId"), r.api.calls.map { c: Call -> route(c) })
        assertTrue(Canon.same("""{"warp_enabled":true}""", r.api.calls[2].body))
        assertEquals("Bearer $token", r.api.calls[2].headers["Authorization"])
        assertTrue(r.reg.warnings.isEmpty())
        // already on → no second PATCH
        r = register(FakeApi(enrolled = device(true)))
        assertEquals(2, r.api.calls.size)
        assertTrue(r.reg.warnings.isEmpty())
        // still off after the PATCH → said, and the servers are still made from the record
        r = register(FakeApi(activated = device(false)))
        assertEquals(3, r.api.calls.size)
        assertEquals(listOf("warpNotEnabled"), r.reg.warnings.map { w: Warp.Warning -> w.code })
        assertEquals(2, r.reg.address.size)
    }

    @Test fun aWarpPlusLicense_putAfterTheKey_theAccountReadFromItsAnswer_noneWithoutOne() {
        var r = register(lic = "  $license ")
        val put = r.api.calls.last()
        assertEquals("PUT", put.method)
        assertEquals("/v0a5641/reg/$deviceId/account", put.path)
        assertEquals("Bearer $token", put.headers["Authorization"])
        assertTrue(Canon.same("""{"license":"$license"}""", put.body))
        assertEquals(Warp.Account(deviceId, "unlimited", true), r.reg.account)
        r = register()
        assertFalse(r.api.calls.any { c: Call -> c.method == "PUT" })
        assertEquals(Warp.Account(deviceId, "free", false), r.reg.account)
    }

    @Test fun aLicenseThatIsNotOne_isRefusedBeforeAnythingIsSent_oneCloudflareRefuses_leavesAFreeAccountAndAWarning() {
        val api = FakeApi()
        refusal("badLicense") { Warp.registerWarp({ r: Warp.Req -> api.call(r) }, "not-a-license", { now }) }
        assertEquals("no device was registered for nothing", 0, api.calls.size)
        val r = register(FakeApi(status = mapOf("PUT /reg/{id}/account" to 403),
            errorBody = """{"success":false,"errors":[{"code":1300,"message":"Too many connected devices."}]}"""), license)
        assertEquals(listOf("licenseFailed"), r.reg.warnings.map { w: Warp.Warning -> w.code })
        assertTrue(r.reg.warnings[0].message.contains("Too many connected devices"))
        assertFalse(r.reg.account.warpPlus)
        assertTrue(r.reg.privateKey.isNotEmpty() && r.reg.publicKey.isNotEmpty())
    }

    /* ------------------------------ the answer, mapped ------------------------------ */

    @Test fun theRecordMapped_theEdgeKeyAsPem_v4And_v6_h3EndpointsFromThePeer_h2TheFixedPair() {
        val reg = register().reg
        assertTrue(reg.publicKey.startsWith("-----BEGIN PUBLIC KEY-----\n"))
        assertEquals(edgePub, b64e.encodeToString(der(reg.publicKey)))
        assertEquals(listOf("172.16.0.2/32", "2606:4700:110:8a36:9c1:2b3:4d5:6e7f/128"), reg.address)
        assertEquals(mapOf("h3v4" to "162.159.198.1", "h3v6" to "2606:4700:103::1", "h2v4" to "162.159.198.2", "h2v6" to "2606:4700:103::2"), reg.endpoints)
        assertFalse("its text never shows the key", reg.toString().contains(b64e.encodeToString(der(reg.privateKey)).take(40)))
    }

    @Test fun endpointsFallBackToCloudflaresDefaults_anotherPortIsDropped_prefixesKept() {
        fun cfg(endpoint: JSONObject, addresses: JSONObject) = device(true, config(JSONObject().put("public_key", edgePub).put("endpoint", endpoint), addresses))
        var reg = register(FakeApi(enrolled = cfg(JSONObject(), JSONObject().put("v4", "172.16.0.2/32").put("v6", "2606:4700:110::2/128")))).reg
        assertEquals(Warp.DEFAULT_ENDPOINTS, reg.endpoints)
        assertEquals(listOf("172.16.0.2/32", "2606:4700:110::2/128"), reg.address)
        reg = register(FakeApi(enrolled = cfg(JSONObject().put("v4", "162.159.199.1:443").put("v6", "2606:4700:104::1"), JSONObject().put("v4", "172.16.0.9")))).reg
        assertEquals("162.159.199.1", reg.endpoints["h3v4"])
        assertEquals("2606:4700:104::1", reg.endpoints["h3v6"])
        assertEquals("no v6 given, none made up", listOf("172.16.0.9/32"), reg.address)
        // garbage in an endpoint → the default, not a broken address
        reg = register(FakeApi(enrolled = cfg(JSONObject().put("v4", "not an ip:0").put("v6", "[]:0"), JSONObject().put("v4", "172.16.0.2")))).reg
        assertEquals("162.159.198.1", reg.endpoints["h3v4"])
        assertEquals("2606:4700:103::1", reg.endpoints["h3v6"])
    }

    @Test fun anEnrollAnswerWithoutPeers_isNoFailure_theRecordIsReadBack() {
        val bare = device(true, JSONObject().put("peers", JSONArray()).put("interface", JSONObject().put("addresses", JSONObject())))
        val r = register(FakeApi(enrolled = bare))
        assertEquals(listOf("POST", "PATCH", "GET"), r.api.calls.map { c: Call -> c.method })
        assertEquals("Bearer $token", r.api.calls[2].headers["Authorization"])
        assertNull(r.api.calls[2].body)
        assertEquals(edgePub, b64e.encodeToString(der(r.reg.publicKey)))
        // and with no peers even then: an answer that cannot be used
        refusal("badAnswer") { register(FakeApi(enrolled = bare, fetched = bare)) }
    }

    /* ----------------------------------- errors ----------------------------------- */

    @Test fun errors_429RateLimited_a4xxRejectedWithCloudflaresWords_5xx_unreadable_andTheNetwork() {
        assertTrue(refusal("rateLimited") { register(FakeApi(status = mapOf("POST /reg" to 429))) }.message!!.contains("429"))
        val e = refusal("rejected") { register(FakeApi(status = mapOf("POST /reg" to 400), errorBody = """{"success":false,"errors":[{"code":1002,"message":"Invalid public key"}]}""")) }
        assertTrue(e.message!!.contains("400") && e.message!!.contains("Invalid public key"))
        assertEquals("Invalid public key", e.detail)
        assertTrue(refusal("rejected") { register(FakeApi(status = mapOf("PATCH /reg/{id}" to 403))) }.message!!.contains("Refused by the fake"))
        assertTrue(refusal("rejected") { register(FakeApi(status = mapOf("POST /reg" to 503), errorBody = "<html>upstream</html>")) }.message!!.contains("503"))
        refusal("badAnswer") { Warp.registerWarp({ _: Warp.Req -> Warp.Res(200, "<html>a captive portal</html>") }, "", { now }) }
        refusal("badAnswer") { Warp.registerWarp({ _: Warp.Req -> Warp.Res(200, """{"id":"x"}""") }, "", { now }) }
        // a transport that fails says why; anything else on the way is "blocked"
        val down = refusal("blocked") { Warp.registerWarp({ _: Warp.Req -> throw IOException("read ECONNRESET") }, "", { now }) }
        assertTrue(down.message!!.contains("ECONNRESET"))
    }

    @Test fun theTokenAndThePrivateKeyAreNeverLogged_norInAnError_notEvenWhenCloudflareRepeatsThem() {
        val lines = ArrayList<String>()
        val echo = FakeApi(status = mapOf("PUT /reg/{id}/account" to 400), errorBody = """{"success":false,"errors":[{"code":1,"message":"bad token $token"}]}""")
        val reg = Warp.registerWarp({ r: Warp.Req -> echo.call(r) }, license, { now }, { line: String, _: String -> lines.add(line) })
        val keyBody = b64e.encodeToString(der(reg.privateKey))
        val secrets = listOf(token, keyBody, keyBody.take(40), keyBody.takeLast(40))
        val text = lines.joinToString("\n") + "\n" + reg.warnings.joinToString("\n") { w: Warp.Warning -> w.message } + "\n" + reg.toString()
        assertTrue("the steps are logged", lines.size >= 3)
        for (s in secrets) assertFalse("a secret reached the log", text.contains(s))
        assertTrue(reg.warnings[0].message.contains("bad token …"))
        // a refusal that repeats the token, thrown
        val thrown = FakeApi(status = mapOf("PATCH /reg/{id}" to 400), errorBody = """{"errors":[{"message":"token $token unknown"}]}""")
        val lines2 = ArrayList<String>()
        val e = refusal("rejected") { Warp.registerWarp({ r: Warp.Req -> thrown.call(r) }, "", { now }, { line: String, _: String -> lines2.add(line) }) }
        assertFalse(e.message!!.contains(token))
        assertFalse((e.detail ?: "").contains(token))
        assertFalse(e.stackTraceToString().contains(token))
        assertFalse(lines2.joinToString("\n").contains(token))
        // a request's own text never shows its headers
        assertFalse(Warp.Req("PATCH", "/x", mapOf("Authorization" to "Bearer $token"), null).toString().contains(token))
    }

    /* ------------------------------ the real transport, off the network ------------------------------ */

    @Test fun theRealTransport_tls12AndAlpnHttp11Only_noRetries_directOrTheTunnelsSocksPort() {
        assertEquals("api.cloudflareclient.com", Warp.HOST)
        assertEquals("v0a5641", Warp.API_VERSION)
        val direct = Warp.client("direct", 0)
        assertEquals(listOf(TlsVersion.TLS_1_2), direct.connectionSpecs.single().tlsVersions)
        assertEquals(listOf(Protocol.HTTP_1_1), direct.protocols)
        assertEquals(Proxy.NO_PROXY, direct.proxy)
        assertFalse(direct.retryOnConnectionFailure)
        assertFalse(direct.followRedirects)
        val viaTunnel = Warp.client("proxy", 10808)
        assertEquals(Proxy.Type.SOCKS, viaTunnel.proxy!!.type())
        val at = viaTunnel.proxy!!.address() as InetSocketAddress
        assertEquals("127.0.0.1" to 10808, at.address.hostAddress to at.port)
        // no port to go through: refused without a dial
        val e = refusal("notConnected") { Warp.okHttpTransport("proxy", 0)(Warp.Req("POST", "/v0a5641/reg", emptyMap(), "{}")) }
        assertTrue(e.message!!.contains("no local proxy port"))
    }

    @Test fun whatABlockLooksLike_timeout_refusedLocalPort_aCertificateThatIsNotTheApis() {
        val t = Warp.transportError(SocketTimeoutException("Read timed out"), "direct", 0)
        assertEquals("blocked", t.code)
        assertTrue(t.message!!.contains("timed out after 20 s"))
        assertEquals("notConnected", Warp.transportError(ConnectException("Failed to connect to /127.0.0.1:10808"), "proxy", 10808).code)
        assertEquals("blocked", Warp.transportError(ConnectException("Failed to connect"), "direct", 0).code)
        val wrapped = IOException("outer", ConnectException("Connection refused"))
        assertEquals("notConnected", Warp.transportError(wrapped, "proxy", 10808).code)
        val mitm = Warp.transportError(SSLHandshakeException("PKIX path building failed"), "direct", 0)
        assertEquals("blocked", mitm.code)
        assertEquals("PKIX path building failed", mitm.detail)
        assertEquals("blocked", Warp.transportError(java.io.InterruptedIOException("timeout"), "proxy", 10808).code)
    }

    /* ----------------------------------- the fields ----------------------------------- */

    private val reg0 = Warp.Reg(
        "-----BEGIN PRIVATE KEY-----\nMIGHAgEA\n-----END PRIVATE KEY-----\n", "-----BEGIN PUBLIC KEY-----\nMFkwEwYH\n-----END PUBLIC KEY-----\n",
        listOf("172.16.0.2/32", "2606:4700:110::2/128"),
        mapOf("h3v4" to "162.159.198.1", "h3v6" to "2606:4700:103::1", "h2v4" to "162.159.198.2", "h2v6" to "2606:4700:103::2"),
        Warp.Account("d", "free", false), emptyList())

    @Test fun warpServers_bothByDefault_h3ThenH2OnTheirOwnEdges_theWarpFields_theWarpSni_antiDpiPerVersion() {
        val out = Warp.warpServers(reg0, Warp.Options())
        val common = mapOf("protocol" to "masque", "port" to "443", "warpPrivateKey" to reg0.privateKey, "warpPublicKey" to reg0.publicKey,
            "warpAddress" to "172.16.0.2/32, 2606:4700:110::2/128", "sni" to "consumer-masque.cloudflareclient.com")
        assertEquals(listOf(
            common + mapOf("name" to "☁ WARP · H3", "address" to "162.159.198.1", "masqueHttp" to "h3", "noise" to "random"),
            common + mapOf("name" to "☁ WARP · H2", "address" to "162.159.198.2", "masqueHttp" to "h2", "fragment" to "tlshello,100-200,10-20")
        ), out)
        assertEquals(out, Warp.warpServers(reg0, Warp.Options(http = "both", endpoint = "auto", antiDpi = true)))
    }

    @Test fun warpServers_oneVersion_ipv6Edges_myOwnCleanIp_aNameOfMyOwn() {
        fun of(o: Warp.Options, vararg keys: String): List<List<String>> = Warp.warpServers(reg0, o).map { f: Map<String, String> -> keys.map { k: String -> f[k] ?: "" } }
        assertEquals(listOf(listOf("☁ WARP · H3", "162.159.198.1", "h3")), of(Warp.Options(http = "h3"), "name", "address", "masqueHttp"))
        assertEquals(listOf(listOf("2606:4700:103::2", "443", "h2")), of(Warp.Options(http = "h2", endpoint = "v6"), "address", "port", "masqueHttp"))
        assertEquals(listOf(listOf("2606:4700:103::1"), listOf("2606:4700:103::2")), of(Warp.Options(endpoint = "v6"), "address"))
        assertEquals(listOf(listOf("Home · H3", "162.159.198.10", "443"), listOf("Home · H2", "162.159.198.10", "443")),
            of(Warp.Options(endpoint = "custom", address = " 162.159.198.10 ", name = "Home"), "name", "address", "port"))
        assertEquals(listOf(listOf("162.159.198.2", "8443")), of(Warp.Options(endpoint = "custom", address = "162.159.198.2:8443", http = "h2"), "address", "port"))
        assertEquals(listOf(listOf("2606:4700:103::2", "4443")), of(Warp.Options(endpoint = "custom", address = "[2606:4700:103::2]:4443", http = "h2"), "address", "port"))
        assertEquals(listOf(listOf("2606:4700:103::2", "443")), of(Warp.Options(endpoint = "custom", address = "2606:4700:103::2", http = "h2"), "address", "port"))
        assertEquals(listOf(listOf("warp.example.net"), listOf("warp.example.net")), of(Warp.Options(endpoint = "custom", address = "warp.example.net"), "address"))
        for (bad in listOf("", "   ", "https://162.159.198.2/", "1.2.3.4:0", "1.2.3.4:70000", "a b")) {
            refusal("badAddress") { Warp.warpServers(reg0, Warp.Options(endpoint = "custom", address = bad)) }
        }
    }

    @Test fun warpServers_aCoverDomain_serverNameAndVerifyNameBothThatName_antiDpiOffWritesNone() {
        for (f in Warp.warpServers(reg0, Warp.Options(cover = "  WWW.Example.COM ", antiDpi = false))) {
            assertEquals("www.example.com", f["sni"])
            assertEquals("www.example.com", f["vcn"])
            assertFalse(f.containsKey("noise"))
            assertFalse(f.containsKey("fragment"))
        }
        assertEquals("cdn.example.org", Warp.warpServers(reg0, Warp.Options(cover = "https://cdn.example.org/"))[0]["sni"])
        assertFalse("no cover: the WARP key pins the edge", Warp.warpServers(reg0, Warp.Options())[0].containsKey("vcn"))
        for (bad in listOf("1.2.3.4", "localhost", "a b.com", "ex ample", "-x.com", "x..com")) {
            refusal("badCover") { Warp.warpServers(reg0, Warp.Options(cover = bad)) }
        }
    }

    @Test fun warpServers_aRegistrationWithoutItsKeysOrAddresses_makesNoServer() {
        refusal("badAnswer") { Warp.warpServers(Warp.Reg("", reg0.publicKey, reg0.address, reg0.endpoints, reg0.account, emptyList()), Warp.Options()) }
        refusal("badAnswer") { Warp.warpServers(Warp.Reg(reg0.privateKey, "", reg0.address, reg0.endpoints, reg0.account, emptyList()), Warp.Options()) }
        refusal("badAnswer") { Warp.warpServers(Warp.Reg(reg0.privateKey, reg0.publicKey, emptyList(), reg0.endpoints, reg0.account, emptyList()), Warp.Options()) }
    }

    /* ----------------------------------- importing ----------------------------------- */

    private fun pemOf(der: ByteArray, label: String) = Masque.pem(der, label)

    private fun usque(k: KeyPair): JSONObject = JSONObject()
        .put("private_key", b64e.encodeToString(Masque.sec1Of(k.private.encoded)!!))
        .put("endpoint_v4", "162.159.198.1").put("endpoint_v6", "2606:4700:103::1")
        .put("endpoint_h2_v4", "162.159.198.2").put("endpoint_h2_v6", "2606:4700:103::2")
        .put("endpoint_pub_key", pemOf(Base64.getDecoder().decode(edgePub), "PUBLIC KEY"))
        .put("license", "xyz").put("id", "usque-dev-1").put("access_token", "usque-SECRET-token").put("ipv4", "172.16.0.2").put("ipv6", "2606:4700:110:8a36::2")

    @Test fun importWarp_usquesConfigJson_theSec1KeyAsPkcs8Pem_itsFourEndpoints_noToken() {
        val k = p256()
        val json = usque(k)
        val reg = Warp.importWarp(json.toString(2))
        assertTrue(reg.privateKey.startsWith("-----BEGIN PRIVATE KEY-----\n"))
        assertTrue(pairs(reg.privateKey, k.public))
        assertEquals(edgePub, b64e.encodeToString(der(reg.publicKey)))
        assertEquals(listOf("172.16.0.2/32", "2606:4700:110:8a36::2/128"), reg.address)
        assertEquals(Warp.DEFAULT_ENDPOINTS, reg.endpoints)
        assertEquals(Warp.Account("usque-dev-1", "", false), reg.account)
        assertFalse(reg.toString().contains("usque-SECRET-token"))
        // the fields go straight to warpServers
        assertEquals(2, Warp.warpServers(reg, Warp.Options()).size)
        // the keys alone: endpoints default
        val bare = Warp.importWarp(JSONObject().put("private_key", json.getString("private_key")).put("endpoint_pub_key", json.getString("endpoint_pub_key")).put("ipv4", "172.16.0.3/32").toString())
        assertEquals(Warp.DEFAULT_ENDPOINTS, bare.endpoints)
        assertEquals(listOf("172.16.0.3/32"), bare.address)
    }

    @Test fun importWarp_aPastedXrayWarpOutbound_aWholeConfig_anOutboundList_orTheWarpObjectAlone() {
        val k = p256()
        val warp = JSONObject().put("privateKey", b64e.encodeToString(k.private.encoded)).put("publicKey", edgePub)
            .put("address", JSONArray().put("172.16.0.2/32").put("2606:4700:110::2"))
        val h2 = JSONObject().put("protocol", "masque").put("settings", JSONObject().put("address", "162.159.198.10").put("port", 443)).put("tag", "warp-masque")
            .put("streamSettings", JSONObject().put("method", "masque").put("masqueSettings", JSONObject().put("warp", warp)).put("security", "tls")
                .put("tlsSettings", JSONObject().put("serverName", "consumer-masque.cloudflareclient.com").put("alpn", JSONArray().put("h2"))))
        val h3 = JSONObject().put("protocol", "masque").put("settings", JSONObject().put("address", "2606:4700:103::7").put("port", 443))
            .put("streamSettings", JSONObject().put("network", "masque").put("masqueSettings", JSONObject().put("warp", warp)).put("security", "tls").put("tlsSettings", JSONObject()))
        var reg = Warp.importWarp(h2.toString())
        assertTrue(pairs(reg.privateKey, k.public))
        assertEquals(edgePub, b64e.encodeToString(der(reg.publicKey)))
        assertEquals(listOf("172.16.0.2/32", "2606:4700:110::2/128"), reg.address)
        assertEquals(mapOf("h3v4" to "162.159.198.1", "h3v6" to "2606:4700:103::1", "h2v4" to "162.159.198.10", "h2v6" to "2606:4700:103::2"), reg.endpoints)
        reg = Warp.importWarp(JSONObject().put("remarks", "x").put("outbounds", JSONArray().put(JSONObject().put("protocol", "freedom").put("tag", "direct")).put(h2).put(h3)).toString())
        assertEquals("162.159.198.10", reg.endpoints["h2v4"])
        assertEquals("2606:4700:103::7", reg.endpoints["h3v6"])
        reg = Warp.importWarp(JSONArray().put(h3).toString())
        assertEquals("2606:4700:103::7", reg.endpoints["h3v6"])
        val sec1Pem = pemOf(Masque.sec1Of(k.private.encoded)!!, "EC PRIVATE KEY")
        reg = Warp.importWarp(JSONObject().put("warp", JSONObject(warp.toString()).put("privateKey", sec1Pem)).toString())
        assertTrue(pairs(reg.privateKey, k.public))
        // 3x-ui's registration answer: { privateKey, publicKey, address, endpoint }
        reg = Warp.importWarp(JSONObject().put("privateKey", pemOf(k.private.encoded, "PRIVATE KEY")).put("publicKey", edgePub)
            .put("address", JSONArray().put("172.16.0.2/32")).put("endpoint", "162.159.198.1").toString())
        assertEquals("162.159.198.1", reg.endpoints["h3v4"])
        assertEquals(Warp.Account("", "", false), reg.account)
    }

    @Test fun importWarp_whatIsNotAWarpAccountIsSaid_withoutRepeatingTheKey() {
        val x = b64e.encodeToString(KeyPairGenerator.getInstance("X25519").generateKeyPair().private.encoded)
        val p384 = b64e.encodeToString(KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }.generateKeyPair().private.encoded)
        val json = usque(p256())
        fun alt(k: String, v: String): String = JSONObject(json.toString()).put(k, v).toString()
        val cases = listOf(
            "", "   ", "vless://x@y:443", """{"a":""", "[]", """{"outbounds":[{"protocol":"vless"}]}""",
            """{"protocol":"masque","settings":{"address":"1.2.3.4","port":443},"streamSettings":{"masqueSettings":{"user":"u","pass":"p"}}}""",
            alt("private_key", x), alt("private_key", p384), alt("private_key", "bm90IGEga2V5"),
            alt("endpoint_pub_key", ""), alt("endpoint_pub_key", "not-a-key"),
            JSONObject(json.toString()).put("ipv4", "").put("ipv6", "").toString(), alt("ipv4", "999.1.1.1"))
        for (c in cases) {
            val e = refusal("badImport") { Warp.importWarp(c) }
            assertFalse(c, e.message!!.contains(json.getString("private_key").substring(8, 40)))
            assertFalse(c, e.message!!.contains(x.substring(8, 40)))
        }
    }

    /* --------------------------------- the whole sign-up --------------------------------- */

    private class Made(val result: Warp.AddResult, val made: List<Map<String, String>>, val logs: List<String>)

    private fun add(args: Warp.AddArgs, api: FakeApi? = FakeApi(), connected: Boolean = false, port: Int = 10808,
                    createServer: ((Map<String, String>) -> ServerConfig)? = null): Made {
        val made = ArrayList<Map<String, String>>()
        val logs = ArrayList<String>()
        val deps = Warp.Deps(
            connected = { connected }, socksPort = { port },
            request = if (api == null) null else ({ r: Warp.Req -> api.call(r) }),
            createServer = { m: Map<String, String> -> made.add(m); if (createServer != null) createServer(m) else Warp.createServer(m) },
            now = { now }, log = { line: String, level: String -> logs.add("$level $line") })
        return Made(Warp.addWarp(args, deps), made, logs)
    }

    @Test fun addWarp_aNewAccount_registered_oneMasqueServerPerHttpVersion_madeAsTheEditorMakesThem() {
        val api = FakeApi()
        val m = add(Warp.AddArgs(mode = "new", via = "direct"), api)
        assertTrue(m.result.error, m.result.ok)
        assertEquals(listOf("☁ WARP · H3", "☁ WARP · H2"), m.result.added.map { s: ServerConfig -> s.name })
        assertEquals(Warp.Account(deviceId, "free", false), m.result.account)
        assertTrue(m.result.warnings.isEmpty())
        val (h3, h2) = m.result.added
        assertEquals(listOf("masque", "162.159.198.1", "443"), listOf(h3.protocol, h3.address, h3.port.toString()))
        assertEquals("162.159.198.2", h2.address)
        assertEquals("h2", ServerEditor.read(h2).masqueHttp)
        assertEquals("random", h3.outbound.optString("_noise"))
        assertEquals("tlshello,100-200,10-20", h2.outbound.optString("_fragment"))
        val warp = h3.outbound.getJSONObject("streamSettings").getJSONObject("masqueSettings").getJSONObject("warp")
        assertEquals("the WARP key kept as one line of base64", b64e.encodeToString(der(m.made[0]["warpPrivateKey"]!!)), warp.getString("privateKey"))
        assertEquals(edgePub, warp.getString("publicKey"))
        assertEquals("consumer-masque.cloudflareclient.com", h3.outbound.getJSONObject("streamSettings").getJSONObject("tlsSettings").getString("serverName"))
        assertTrue(h3.raw.startsWith("{"))
        val text = m.logs.joinToString("\n")
        assertTrue(text.contains("WARP"))
        assertFalse(text.contains(token))
        assertFalse(text.contains(warp.getString("privateKey").take(40)))
    }

    @Test fun addWarp_throughTheConnectionOnlyWhenConnected_otherwiseNotConnectedAndNothingIsSent() {
        val api = FakeApi()
        val m = add(Warp.AddArgs(mode = "new", via = "proxy"), api, connected = false)
        assertEquals(listOf("false", "notConnected"), listOf(m.result.ok.toString(), m.result.code))
        assertEquals(0, api.calls.size)
        assertTrue(m.result.added.isEmpty())
        // connected: the transport is built for the tunnel's own SOCKS port
        var asked: Pair<String, Int>? = null
        val deps = Warp.Deps(connected = { true }, socksPort = { 47808 },
            transport = { via: String, port: Int ->
                asked = via to port
                val t: (Warp.Req) -> Warp.Res = { r: Warp.Req -> api.call(r) }
                t
            })
        assertTrue(Warp.addWarp(Warp.AddArgs(mode = "new", via = "proxy"), deps).ok)
        assertEquals("proxy" to 47808, asked)
    }

    @Test fun addWarp_importNeedsNoNetwork_badOptionsRefusedBeforeARegistration_createServerRefusingIsSaid() {
        val api = FakeApi()
        val json = usque(p256()).toString()
        var m = add(Warp.AddArgs(mode = "import", importText = json, options = Warp.Options(http = "h2", cover = "www.example.com")), api)
        assertTrue(m.result.error, m.result.ok)
        assertEquals(listOf("☁ WARP · H2"), m.result.added.map { s: ServerConfig -> s.name })
        assertEquals("www.example.com", m.made[0]["vcn"])
        assertEquals("www.example.com", m.result.added[0].outbound.getJSONObject("streamSettings").getJSONObject("tlsSettings").getString("verifyPeerCertByName"))
        assertEquals(0, api.calls.size)
        m = add(Warp.AddArgs(mode = "import", importText = "{}"), api)
        assertEquals("badImport", m.result.code)
        // my own clean IP, through the whole sign-up
        m = add(Warp.AddArgs(mode = "import", importText = json, options = Warp.Options(endpoint = "custom", address = "162.159.198.10:8443")), api)
        assertTrue(m.result.error, m.result.ok)
        assertEquals(listOf("162.159.198.10:8443", "162.159.198.10:8443"), m.result.added.map { s: ServerConfig -> "${s.address}:${s.port}" })
        for ((args, code) in listOf(
            Warp.AddArgs(options = Warp.Options(cover = "1.2.3.4")) to "badCover",
            Warp.AddArgs(options = Warp.Options(endpoint = "custom", address = "")) to "badAddress",
            Warp.AddArgs(license = "nope") to "badLicense")) {
            assertEquals(code, add(args, api).result.code)
        }
        assertEquals("no device was registered for a typo", 0, api.calls.size)
        // createServer refusing
        m = add(Warp.AddArgs(), FakeApi(), createServer = { _: Map<String, String> -> throw IllegalArgumentException("Unknown protocol: masque") })
        assertEquals("createFailed", m.result.code)
        assertTrue(m.result.error.contains("Unknown protocol"))
        assertEquals("the sheet puts the detail in its own sentence", "Unknown protocol: masque", m.result.detail)
    }

    @Test fun addWarp_everyRefusalCarriesADetail_cloudflaresWords_theNetworkError_theReason() {
        assertEquals("Invalid locale" to "rejected", add(Warp.AddArgs(), FakeApi(status = mapOf("POST /reg" to 400),
            errorBody = """{"errors":[{"message":"Invalid locale"}]}""")).result.let { r: Warp.AddResult -> r.detail to r.code })
        val down = Warp.addWarp(Warp.AddArgs(), Warp.Deps(request = { _: Warp.Req -> throw IOException("ECONNRESET") }))
        assertEquals("blocked" to "ECONNRESET", down.code to down.detail)
        val limited = add(Warp.AddArgs(), FakeApi(status = mapOf("POST /reg" to 429))).result
        assertEquals("rateLimited", limited.code)
        assertTrue(limited.detail.contains("429"))
        val imp = add(Warp.AddArgs(mode = "import", importText = "[]")).result
        assertEquals("badImport", imp.code)
        assertTrue(imp.detail.contains("No WARP account"))
        // in the sheet's words
        assertEquals("Cloudflare refused the request: Invalid locale", Warp.messageFor("rejected", "Invalid locale"))
        assertTrue(Warp.warningText(Warp.Warning("licenseFailed", "x")).contains("(x)"))
        for (code in Warp.ERROR_CODES) assertFalse(code, Warp.messageFor(code, "d").isBlank())
    }

    @Test fun addWarpOnce_aSecondSignUpWhileOneRuns_isBusy_andRegistersNothing() {
        val api = FakeApi()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val slow = Warp.Deps(request = { r: Warp.Req ->
            entered.countDown()
            release.await(10, TimeUnit.SECONDS)
            api.call(r)
        })
        var first: Warp.AddResult? = null
        val t = Thread { first = Warp.addWarpOnce(Warp.AddArgs(), slow) }
        t.start()
        assertTrue(entered.await(10, TimeUnit.SECONDS))
        val second = Warp.addWarpOnce(Warp.AddArgs(), Warp.Deps(request = { r: Warp.Req -> api.call(r) }))
        assertEquals("busy", second.code)
        release.countDown()
        t.join(20_000)
        assertTrue(first?.ok == true)
        assertEquals("one device, not two", 1, api.calls.count { c: Call -> c.method == "POST" })
        assertTrue("free again once the first one finished", Warp.addWarpOnce(Warp.AddArgs(mode = "import", importText = usque(p256()).toString()), Warp.Deps()).ok)
    }
}
