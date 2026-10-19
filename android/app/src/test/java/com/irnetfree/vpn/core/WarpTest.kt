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
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.KeyAgreement
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

    /** Cloudflare's WireGuard peer key (the same for every WARP device). */
    private val wgPeer = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

    /** A WireGuard device's config: the WireGuard peer and its edges. */
    private fun wgConfig(): JSONObject = config(JSONObject().put("public_key", wgPeer)
        .put("endpoint", JSONObject().put("v4", "162.159.192.1:0").put("v6", "[2606:4700:d0::a29f:c001]:0").put("host", "engage.cloudflareclient.com:2408")))

    /** A WireGuard device record (the desktop's warpFakes.wgDevice). */
    private fun wgDevice(warpEnabled: Boolean = true, cfg: JSONObject = wgConfig()): JSONObject =
        device(warpEnabled, cfg).put("key_type", "curve25519").put("tunnel_type", "wireguard")

    class Call(val method: String, val path: String, val headers: Map<String, String>, val body: JSONObject?)

    /**
     * The API, step by step as Cloudflare answers it: [registered] the POST
     * answer (default: a fresh WireGuard device, warp_enabled false, its
     * token), [enrolled] the PATCH key answer (default: a fresh device,
     * warp_enabled false), [activated] the PATCH warp_enabled answer,
     * [fetched] the GET answer, [licensed] the PUT answer ([license204]: none,
     * as the API may answer), [account] the GET …/account answer (default: the
     * device's account as the key left it), [devices] the GET …/devices
     * answer (default: this one device), [status] a status (and [errorBody])
     * instead of an answer, by route.
     */
    inner class FakeApi(
        val enrolled: JSONObject? = null, val activated: JSONObject? = null, val fetched: JSONObject? = null,
        val licensed: JSONObject? = null, val status: Map<String, Int> = emptyMap(), val errorBody: String? = null,
        val registered: JSONObject? = null, val license204: Boolean = false, val account: JSONObject? = null, val devices: JSONArray? = null
    ) {
        val calls = ArrayList<Call>()
        /** What a PUT …/account made of the account. */
        private var licensedNow: JSONObject? = null
        /** What the device is: WireGuard as registered, MASQUE once its key is enrolled. */
        private var tunnel = ""
        private fun ok(o: JSONObject): Warp.Res = Warp.Res(200, o.toString())
        private fun okList(a: JSONArray): Warp.Res = Warp.Res(200, a.toString())
        private val unauth = Warp.Res(401, """{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}""")
        private fun plusAccount(): JSONObject = JSONObject().put("id", "acc-77").put("account_type", "unlimited").put("warp_plus", true).put("premium_data", 1)
        private fun current(): JSONObject = if (tunnel == "wireguard") wgDevice() else device()

        fun call(r: Warp.Req): Warp.Res {
            val body: JSONObject? = r.body?.takeIf { x: String -> x.isNotEmpty() }?.let { x: String -> JSONObject(x) }
            calls.add(Call(r.method, r.path, HashMap(r.headers), body))
            val route = r.method + " " + r.path.removePrefix("/v0a5641").replace(deviceId, "{id}")
            val st = status[route]
            if (st != null) return Warp.Res(st, errorBody ?: """{"success":false,"errors":[{"code":1000,"message":"Refused by the fake"}]}""")
            val authed = r.headers["Authorization"] == "Bearer $token"
            return when (route) {
                "POST /reg" -> {
                    tunnel = "wireguard"   // a new device: its own account
                    licensedNow = null
                    ok(registered ?: wgDevice(false).put("token", token))
                }
                "PATCH /reg/{id}" -> when {
                    !authed -> unauth
                    body?.opt("warp_enabled") == true -> ok(activated ?: current())
                    else -> {
                        tunnel = "masque"
                        ok(enrolled ?: device(false))
                    }
                }
                "GET /reg/{id}" -> if (!authed) unauth else ok(fetched ?: current())
                "PUT /reg/{id}/account" -> when {
                    !authed -> unauth
                    license204 -> {
                        licensedNow = plusAccount()
                        Warp.Res(204, "")
                    }
                    else -> {
                        val made = licensed ?: plusAccount().put("license", body?.optString("license") ?: "")
                        licensedNow = made
                        ok(made)
                    }
                }
                "GET /reg/{id}/account" -> {
                    if (!authed) unauth else {
                        val acc = JSONObject(device().getJSONObject("account").toString())
                        val lic = licensedNow
                        if (lic != null) for (k in lic.keySet()) acc.put(k, lic.get(k))
                        ok(account ?: acc)
                    }
                }
                "GET /reg/{id}/account/devices" -> if (!authed) unauth else okList(devices ?: JSONArray().put(JSONObject()
                    .put("id", deviceId).put("type", "Android").put("model", "PC").put("name", "").put("active", true).put("role", "child")))
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
        // then the account and its devices read back (accountStep), every time
        assertEquals(listOf("POST /reg", "PATCH /reg/$deviceId", "PATCH /reg/$deviceId", "GET /reg/$deviceId/account", "GET /reg/$deviceId/account/devices"),
            r.api.calls.map { c: Call -> route(c) })
        assertTrue(Canon.same("""{"warp_enabled":true}""", r.api.calls[2].body))
        assertEquals("Bearer $token", r.api.calls[2].headers["Authorization"])
        assertTrue(r.reg.warnings.isEmpty())
        // already on → no second PATCH
        r = register(FakeApi(enrolled = device(true)))
        assertEquals(1, r.api.calls.count { c: Call -> c.method == "PATCH" })
        assertTrue(r.reg.warnings.isEmpty())
        // still off after the PATCH → said, and the servers are still made from the record
        r = register(FakeApi(activated = device(false)))
        assertEquals(2, r.api.calls.count { c: Call -> c.method == "PATCH" })
        assertEquals(listOf("warpNotEnabled"), r.reg.warnings.map { w: Warp.Warning -> w.code })
        assertEquals(2, r.reg.address.size)
    }

    @Test fun aWarpPlusLicense_putAfterTheKey_theAccountReadFromItsAnswer_noneWithoutOne() {
        var r = register(lic = "  $license ")
        val put = r.api.calls.first { c: Call -> c.method == "PUT" }
        // the key, then the account read back
        assertEquals(listOf("PUT /account", "GET /account", "GET /account/devices"),
            r.api.calls.takeLast(3).map { c: Call -> c.method + " " + c.path.removePrefix("/v0a5641/reg/$deviceId") })
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
        assertEquals(listOf("POST", "PATCH", "GET", "GET", "GET"), r.api.calls.map { c: Call -> c.method })
        assertEquals("/v0a5641/reg/$deviceId", r.api.calls[2].path)
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
        val secrets = listOf(token, keyBody, keyBody.take(40), keyBody.takeLast(40), license)
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

    /* ============================ WireGuard WARP, many accounts (v1.26.0) ============================ */
    // the desktop's tests/warpWg.test.js, case for case where it makes sense on the JVM

    private val key2 = "Z9y8X7w6-V5u4T3s2-R1q0P9o8"
    private val key3 = "M1n2B3v4-C5x6Z7l8-K9j0H1g2"

    private fun hexBytes(h: String): ByteArray = ByteArray(h.length / 2) { i: Int -> h.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    /** RFC 8410's X25519 encodings: what comes before the raw 32 bytes. */
    private val x25519Pkcs8 = hexBytes("302e020100300506032b656e04220420")
    private val x25519Spki = hexBytes("302a300506032b656e032100")

    /** Are these (raw, base64) one X25519 key pair? Each agrees with a third key on the same secret. */
    private fun x25519Pairs(privateB64: String, publicB64: String): Boolean {
        val kf = KeyFactory.getInstance("XDH")
        val priv: PrivateKey = kf.generatePrivate(PKCS8EncodedKeySpec(x25519Pkcs8 + Base64.getDecoder().decode(privateB64)))
        val pub: PublicKey = kf.generatePublic(X509EncodedKeySpec(x25519Spki + Base64.getDecoder().decode(publicB64)))
        val other = KeyPairGenerator.getInstance("X25519").generateKeyPair()
        fun agree(k: PrivateKey, p: PublicKey): ByteArray {
            val ka = KeyAgreement.getInstance("XDH")
            ka.init(k)
            ka.doPhase(p, true)
            return ka.generateSecret()
        }
        return agree(priv, other.public).contentEquals(agree(other.private, pub))
    }

    private fun registerWg(api: FakeApi = FakeApi(), lic: String = ""): Registered {
        val lines = ArrayList<String>()
        val reg = Warp.registerWarpWg({ r: Warp.Req -> api.call(r) }, lic, { now }, { line: String, _: String -> lines.add(line) })
        return Registered(reg, api, lines)
    }

    private fun wgRoute(c: Call): String = c.method + " " + c.path.removePrefix("/v0a5641").replace(deviceId, "{id}")

    /* ------------------------------ the registration ------------------------------ */

    @Test fun wg_postCarriesOurX25519Key_curve25519Wireguard_noMasqueEnrollment_thenWarpEnabled_theAccountAndItsDevices() {
        val r = registerWg()
        assertEquals(listOf("POST /reg", "PATCH /reg/{id}", "GET /reg/{id}/account", "GET /reg/{id}/account/devices"), r.api.calls.map { c: Call -> wgRoute(c) })
        val post = r.api.calls[0]
        val b = post.body!!
        assertEquals("curve25519", b.getString("key_type"))
        assertEquals("wireguard", b.getString("tunnel_type"))
        assertEquals("2026-10-14T09:30:15.123Z", b.getString("tos"))
        assertFalse(post.headers.containsKey("Authorization"))
        // the key sent is the public half of the private key kept, both wg's raw base64
        assertTrue(r.reg.privateKey, Regex("^[A-Za-z0-9+/]{43}=$").matches(r.reg.privateKey))
        assertTrue(x25519Pairs(r.reg.privateKey, b.getString("key")))
        assertTrue(Canon.same("""{"warp_enabled":true}""", r.api.calls[1].body))
        for (c in r.api.calls.drop(1)) assertEquals("Bearer $token", c.headers["Authorization"])
        // clamped as wg genkey writes it; each device its own
        val raw = Base64.getDecoder().decode(r.reg.privateKey)
        assertEquals(0, raw[0].toInt() and 7)
        assertEquals(64, raw[31].toInt() and 0xC0)
        assertFalse(registerWg().reg.privateKey == r.reg.privateKey)
        // already on → no PATCH at all
        val on = registerWg(FakeApi(registered = wgDevice(true).put("token", token)))
        assertEquals(0, on.api.calls.count { c: Call -> c.method == "PATCH" })
        assertTrue(on.reg.warnings.isEmpty())
    }

    @Test fun wg_theRecordMapped_thePeersKey_v4And_v6_theEdgesWithoutPort0_reservedFromTheClientId() {
        val reg = registerWg().reg
        assertEquals("wireguard", reg.kind)
        assertEquals(wgPeer, reg.publicKey)
        assertEquals(listOf("172.16.0.2/32", "2606:4700:110:8a36:9c1:2b3:4d5:6e7f/128"), reg.address)
        assertEquals(mapOf("v4" to "162.159.192.1", "v6" to "2606:4700:d0::a29f:c001"), reg.endpoints)
        assertEquals("client_id AAAA is three zero bytes", listOf(0, 0, 0), reg.reserved)
        // another client id; an answer without peers is read back with GET /reg/{id}
        val bare = JSONObject().put("peers", JSONArray()).put("interface", JSONObject().put("addresses", JSONObject()))
        val fetched = wgDevice(true, JSONObject().put("client_id", "qbs5")
            .put("peers", JSONArray().put(JSONObject().put("public_key", wgPeer).put("endpoint", JSONObject().put("v4", "162.159.192.7:0"))))
            .put("interface", JSONObject().put("addresses", JSONObject().put("v4", "172.16.0.2"))))
        val r2 = registerWg(FakeApi(registered = wgDevice(true, bare).put("token", token), fetched = fetched))
        assertEquals(listOf(169, 187, 57), r2.reg.reserved)
        assertEquals("162.159.192.7", r2.reg.endpoints["v4"])
        assertEquals("none given → Cloudflare’s default", "2606:4700:d0::a29f:c001", r2.reg.endpoints["v6"])
        assertEquals(listOf("172.16.0.2/32"), r2.reg.address)
        assertEquals("GET /reg/{id}", wgRoute(r2.api.calls[1]))
        // a peer key that is not a WireGuard key (the MASQUE edge's P-256 one) → badAnswer
        refusal("badAnswer") { registerWg(FakeApi(registered = wgDevice(true, config()).put("token", token))) }
        assertEquals(listOf(1, 2, 3), Warp.clientIdBytes("AQID"))
        assertEquals(emptyList<Int>(), Warp.clientIdBytes(""))
        assertEquals(emptyList<Int>(), Warp.clientIdBytes("not base64!"))
    }

    /* ------------------------------ the account ------------------------------ */

    @Test fun wg_theAccount_aWarpPlusKeyApplied_itsTypeAndFigures_theDevices_whichKey_when() {
        val account = JSONObject().put("id", "acc-9").put("account_type", "limited").put("warp_plus", true).put("premium_data", 27670000000000000L)
            .put("quota", "27670000000000000").put("usage", 0).put("role", "child").put("referral_count", 3).put("license", license)
        val devices = JSONArray().put(JSONObject().put("id", "a")).put(JSONObject().put("id", "b")).put(JSONObject().put("id", deviceId))
        val r = registerWg(FakeApi(account = account, devices = devices), license)
        assertEquals(listOf("PUT /reg/{id}/account", "GET /reg/{id}/account", "GET /reg/{id}/account/devices"), r.api.calls.takeLast(3).map { c: Call -> wgRoute(c) })
        assertTrue(Canon.same("""{"license":"$license"}""", r.api.calls[r.api.calls.size - 3].body))
        val expected = Warp.AccountInfo(kind = "wireguard", deviceId = deviceId, type = "limited", warpPlus = true,
            premiumData = 27670000000000000L, quota = 27670000000000000L, usage = 0L, role = "child", referralCount = 3L, devices = 3L,
            license = "applied", licenseTail = license.takeLast(4), licenseError = "", checkedAt = "2026-10-14T09:30:15.123Z")
        assertEquals(expected, r.reg.info)
        assertEquals(Warp.Account(deviceId, "limited", true), r.reg.account)
        assertTrue(r.reg.warnings.isEmpty())
        val info = r.reg.info!!
        assertFalse("the key itself is not kept", info.toString().contains(license))
        assertFalse(info.toJson().toString().contains(license))
    }

    @Test fun wg_theAccount_put204WithNoBody_isApplied_theAccountReadBackSaysWhatItBecame_masqueToo() {
        val r = registerWg(FakeApi(license204 = true), license)
        val info = r.reg.info!!
        assertEquals("applied", info.license)
        assertEquals("unlimited", info.type)
        assertTrue(info.warpPlus)
        assertTrue(r.reg.warnings.isEmpty())
        val m = register(FakeApi(license204 = true), license).reg.info!!
        assertEquals("masque", m.kind)
        assertEquals("applied", m.license)
        assertEquals("unlimited", m.type)
    }

    @Test fun wg_theAccount_aKeyCloudflareRefuses_refusedWithItsWords_aWarning_stillFree_withoutAKey_none() {
        val r = registerWg(FakeApi(status = mapOf("PUT /reg/{id}/account" to 403),
            errorBody = """{"success":false,"errors":[{"code":1300,"message":"Too many connected devices."}]}"""), license)
        val info = r.reg.info!!
        assertEquals("refused", info.license)
        assertTrue(info.licenseError.contains("Too many connected devices"))
        assertEquals("free", info.type)
        assertFalse(info.warpPlus)
        assertEquals(listOf("licenseFailed"), r.reg.warnings.map { w: Warp.Warning -> w.code })
        val none = registerWg()
        val ni = none.reg.info!!
        assertEquals("none", ni.license)
        assertEquals("", ni.licenseTail)
        assertEquals(1L, ni.devices)
        assertFalse(none.api.calls.any { c: Call -> c.method == "PUT" })
    }

    @Test fun wg_theAccount_unread_isAWarning_theRegistrationsOwnAccountKept_oddValuesReadAsNullOrEmpty() {
        val r = registerWg(FakeApi(status = mapOf("GET /reg/{id}/account" to 500, "GET /reg/{id}/account/devices" to 429)))
        assertEquals(listOf("accountUnread"), r.reg.warnings.map { w: Warp.Warning -> w.code })
        val info = r.reg.info!!
        assertEquals("the activation answer’s account", "free", info.type)
        assertNull(info.devices)
        assertTrue("the servers can still be made", r.reg.address.isNotEmpty())
        val odd = Warp.accountInfo("wireguard", "d", JSONObject().put("account_type", "Platinum").put("warp_plus", "yes").put("premium_data", -5)
            .put("quota", "12x").put("usage", 1.5).put("role", "admin"), now)
        assertEquals("", odd.type)
        assertFalse(odd.warpPlus)
        assertNull(odd.premiumData)
        assertNull(odd.quota)
        assertEquals("a fraction is cut to whole bytes", 1L, odd.usage)
        assertEquals("", odd.role)
        assertEquals(27670000000000000L, Warp.numberOf("27670000000000000"))
        assertNull(Warp.numberOf(true))
    }

    @Test fun wg_theKeyTheTokenAndThePrivateKeyAreNeverLogged_norInAWarning_notEvenWhenCloudflareRepeatsTheKey() {
        val r = registerWg(FakeApi(status = mapOf("PUT /reg/{id}/account" to 400), errorBody = """{"errors":[{"message":"License $license is invalid"}]}"""), license)
        val text = r.lines.joinToString("\n") + "\n" + r.reg.warnings.joinToString("\n") { w: Warp.Warning -> w.message } + "\n" + r.reg.info.toString() + "\n" + r.reg.toString()
        for (s in listOf(license, token, r.reg.privateKey)) assertFalse("a secret reached the log", text.contains(s))
        assertTrue(r.reg.info!!.licenseError.contains("License … is invalid"))
        assertTrue("which key it was: its last four", r.lines.joinToString("\n").contains("…" + license.takeLast(4)))
    }

    /* ------------------------------ the server ------------------------------ */

    @Test fun wgServerFields_chainedByDefault_cloudflaresV4EdgeOn2408_mtu1280_reserved_everythingThroughIt_noNoise_madeAsTheEditorMakesIt() {
        val reg = registerWg().reg
        val f = Warp.wgServerFields(reg, Warp.WgOptions(use = "chain", antiDpi = true), "☁ WARP")
        assertEquals(mapOf("protocol" to "wireguard", "name" to "☁ WARP", "address" to "162.159.192.1", "port" to "2408",
            "privateKey" to reg.privateKey, "publicKey" to wgPeer, "localAddress" to "172.16.0.2/32, 2606:4700:110:8a36:9c1:2b3:4d5:6e7f/128",
            "mtu" to "1280", "allowedIPs" to "0.0.0.0/0, ::/0", "reserved" to "0,0,0"), f)
        val s = Warp.createServer(f)
        assertEquals(listOf("wireguard", "162.159.192.1", "2408"), listOf(s.protocol, s.address, s.port.toString()))
        val st = s.outbound.getJSONObject("settings")
        assertEquals(reg.privateKey, st.getString("secretKey"))
        assertEquals(1280, st.getInt("mtu"))
        assertTrue(Canon.same("""{"a":[0,0,0]}""", JSONObject().put("a", st.getJSONArray("reserved"))))
        assertTrue(Canon.same("""{"a":["172.16.0.2/32","2606:4700:110:8a36:9c1:2b3:4d5:6e7f/128"]}""", JSONObject().put("a", st.getJSONArray("address"))))
        val peer = st.getJSONArray("peers").getJSONObject(0)
        assertEquals(wgPeer, peer.getString("publicKey"))
        assertEquals("162.159.192.1:2408", peer.getString("endpoint"))
        assertTrue(Canon.same("""{"a":["0.0.0.0/0","::/0"]}""", JSONObject().put("a", peer.getJSONArray("allowedIPs"))))
        assertFalse(s.outbound.has("_noise"))
    }

    @Test fun wgServerFields_direct_antiDpiNoise_theV6Edge_myOwnCleanIp_aBadOneIsBadAddress_aChainedOneTakesNoEndpoint() {
        val reg = registerWg().reg
        assertEquals("random", Warp.wgServerFields(reg, Warp.WgOptions(use = "direct"))["noise"])
        assertEquals("random", Warp.createServer(Warp.wgServerFields(reg, Warp.WgOptions(use = "direct"))).outbound.optString("_noise"))
        assertFalse(Warp.wgServerFields(reg, Warp.WgOptions(use = "direct", antiDpi = false)).containsKey("noise"))
        val v6 = Warp.wgServerFields(reg, Warp.WgOptions(use = "direct", endpoint = "v6"))
        assertEquals("2606:4700:d0::a29f:c001", v6["address"])
        assertEquals("[2606:4700:d0::a29f:c001]:2408",
            Warp.createServer(v6).outbound.getJSONObject("settings").getJSONArray("peers").getJSONObject(0).getString("endpoint"))
        fun at(address: String): Pair<String?, String?> =
            Warp.wgServerFields(reg, Warp.WgOptions(use = "direct", endpoint = "custom", address = address)).let { m: Map<String, String> -> m["address"] to m["port"] }
        assertEquals(Pair<String?, String?>("188.114.97.3", "2408"), at("188.114.97.3"))
        assertEquals(Pair<String?, String?>("2606:4700::1", "4500"), at("[2606:4700::1]:4500"))
        refusal("badAddress") { Warp.wgServerFields(reg, Warp.WgOptions(use = "direct", endpoint = "custom", address = "not an ip/x")) }
        // a chained WARP takes no endpoint choice: the hop's server dials Cloudflare's own edge
        assertEquals("162.159.192.1", Warp.wgServerFields(reg, Warp.WgOptions(use = "chain", endpoint = "custom", address = "188.114.97.3"))["address"])
        refusal("badAnswer") {
            Warp.wgServerFields(Warp.Reg("x", wgPeer, listOf("1.2.3.4/32"), emptyMap(), Warp.Account("", "", false), emptyList()), Warp.WgOptions())
        }
    }

    /* ------------------------------ names, keys, the hop ------------------------------ */

    @Test fun accountLabels_theBareBaseForOneAccountNobodyUses_numbersOtherwise_pastTheOnesTaken() {
        assertEquals(listOf("☁ WARP"), Warp.accountLabels(1, "☁ WARP", emptyList()))
        assertEquals(listOf("☁ WARP 1", "☁ WARP 2", "☁ WARP 3"), Warp.accountLabels(3, "☁ WARP", emptyList()))
        assertEquals(listOf("☁ WARP 2"), Warp.accountLabels(1, "☁ WARP", listOf("☁ WARP · H3")))
        assertEquals(listOf("☁ WARP 2", "☁ WARP 4"), Warp.accountLabels(2, "☁ WARP", listOf("☁ WARP", "☁ WARP 3", "☁ WARP 10 · H2")))
        assertEquals("a longer name is not this one", listOf("Home"), Warp.accountLabels(1, "Home", listOf("Home office")))
    }

    @Test fun licensePlan_oneKeyOnEveryAccount_severalOneEach_theRestFree_moreKeysRaiseTheCount_atMost10_aBadOneNamedNeverShown() {
        fun plan(licenses: List<String>, count: Int = 1, single: String = ""): Pair<Int, List<String>> =
            Warp.licensePlan(licenses, single, count).let { p: Warp.Plan -> p.count to p.keys }
        assertEquals(3 to listOf(license, license, license), plan(listOf(license), 3))
        assertEquals(3 to listOf(license, key2, ""), plan(listOf(license, " ", key2), 3))
        assertEquals(3 to listOf(license, key2, key3), plan(listOf(license, key2, key3), 1))
        assertEquals("the pre-1.26 single key", 1 to listOf(license), plan(emptyList(), 1, license))
        assertEquals(1 to listOf(""), plan(emptyList(), 0))
        assertEquals(10, plan(emptyList(), 99).first)
        refusal("badLicense") { Warp.licensePlan(List(11) { _: Int -> license }) }
        val e = refusal("badLicense") { Warp.licensePlan(listOf(license, "Q1w2E3r4-T5y6U7i8")) }
        val msg = e.message ?: ""
        assertTrue(msg, msg.startsWith("Key 2 "))
        assertFalse(msg.contains("Q1w2E3r4"))
        assertEquals("Key 2: That is not a WARP+ key — it looks like xxxxxxxx-xxxxxxxx-xxxxxxxx.", Warp.messageFor("badLicense", msg))
    }

    @Test fun licenseReadBack_whatCreateWouldMake_orWhichKeyIsNotOne_neverTheKey() {
        assertEquals("3 accounts: 2 with WARP+, 1 free", Warp.licenseReadBack("$license\n$key2", 3).text)
        assertEquals("2 accounts: 2 with WARP+", Warp.licenseReadBack(license, 2).text)
        assertEquals("1 account: 1 free", Warp.licenseReadBack("", 1).text)
        assertEquals("more keys than the count raise it", "3 accounts: 3 with WARP+", Warp.licenseReadBack("$license\n$key2\n$key3", 1).text)
        val bad = Warp.licenseReadBack("$license\n\nQ1w2E3r4-T5y6U7i8", 1)
        assertFalse(bad.ok)
        assertTrue(bad.text, bad.text.startsWith("Key 2 (line 3) is not a WARP+ key"))
        assertFalse(bad.text.contains("Q1w2E3r4"))
        assertTrue(Warp.licenseReadBack("$license\r\n$key2", 0).ok)
        assertFalse(Warp.licenseReadBack(List(11) { _: Int -> license }.joinToString("\n"), 1).ok)
    }

    private fun srv(id: String, name: String, protocol: String): ServerConfig =
        ServerConfig(id = id, name = name, protocol = protocol, address = "198.51.100.7", port = 443, outbound = JSONObject())

    @Test fun resolveHop_aServerOrAChainsMembers_eachStillThere_theLastNotAnHttpProxy_otherwiseBadHop() {
        val servers = listOf(srv("s1", "UK xhttp", "vless"), srv("s2", "hy2", "hysteria2"), srv("p", "office proxy", "http"))
        val chains = listOf(ChainConfig("c1", "Two hops", listOf("s1", "s2")), ChainConfig("c2", "empty", emptyList()),
            ChainConfig("c3", "via proxy", listOf("p", "s1")), ChainConfig("c4", "gone", listOf("s1", "zz")),
            ChainConfig("c5", "ends on proxy", listOf("s1", "p")))
        val one = Warp.resolveHop("s1", servers, chains)
        assertEquals(listOf("s1") to "UK xhttp", one.members to one.name)
        val two = Warp.resolveHop("chain:c1", servers, chains)
        assertEquals(listOf("s1", "s2") to "Two hops", two.members to two.name)
        // an HTTP proxy FIRST only carries the VLESS stream: allowed
        val three = Warp.resolveHop("chain:c3", servers, chains)
        assertEquals(listOf("p", "s1") to "via proxy", three.members to three.name)
        for (v in listOf("", "nope", "chain:nope", "chain:c2", "chain:c4", "chain:c5", "p")) {
            refusal("badHop") { Warp.resolveHop(v, servers, chains) }
        }
        assertTrue((refusal("badHop") { Warp.resolveHop("p", servers, chains) }.message ?: "").contains("HTTP proxy"))
    }

    /* ------------------------------ the whole sign-up ------------------------------ */

    private class Batch(val result: Warp.AddResult, val pauses: List<Long>, val logs: List<String>)

    private val hopServers: List<ServerConfig> = listOf(srv("hop", "UK xhttp", "vless"), srv("px", "office proxy", "http"))
    private val oldChains: List<ChainConfig> = listOf(ChainConfig("old-chain", "Old", listOf("hop")))

    /** addWarp over the fake API, the store's servers and chains above, no pause (the pauses recorded). */
    private fun batch(args: Warp.AddArgs, request: (Warp.Req) -> Warp.Res): Batch {
        val pauses = ArrayList<Long>()
        val logs = ArrayList<String>()
        val deps = Warp.Deps(
            request = request, now = { now },
            getServers = { hopServers }, getChains = { oldChains },
            pause = { ms: Long -> pauses.add(ms) }, log = { line: String, level: String -> logs.add("$level $line") })
        return Batch(Warp.addWarp(args, deps), pauses, logs)
    }

    @Test fun addWarp_wireguard_threeAccountsFromTwoKeys_oneAfterAnother_numbered_eachWithItsAccount_eachChainedOverTheConfigIPicked() {
        val api = FakeApi()
        val b = batch(Warp.AddArgs(kind = "wireguard", mode = "new", via = "direct", count = 3, licenses = listOf(license, key2),
            wg = Warp.WgOptions(use = "chain", chainWith = "hop"))) { r: Warp.Req -> api.call(r) }
        val res = b.result
        assertTrue(res.error, res.ok)
        assertEquals(3, api.calls.count { c: Call -> c.method == "POST" })
        assertEquals("the third account is free", listOf(license, key2),
            api.calls.filter { c: Call -> c.method == "PUT" }.map { c: Call -> c.body?.optString("license") ?: "" })
        assertEquals(listOf(2000L, 2000L), b.pauses)
        assertEquals(listOf("☁ WARP 1", "☁ WARP 2", "☁ WARP 3").map { n: String -> listOf(n, "wireguard", "162.159.192.1", "2408") },
            res.added.map { s: ServerConfig -> listOf(s.name, s.protocol, s.address, s.port.toString()) })
        assertEquals("each account its own device key", 3,
            res.added.map { s: ServerConfig -> s.outbound.getJSONObject("settings").getString("secretKey") }.toSet().size)
        assertEquals(listOf("applied", "applied", "none"), res.added.map { s: ServerConfig -> s.warp?.license })
        assertEquals(listOf("unlimited", "unlimited", "free"), res.added.map { s: ServerConfig -> s.warp?.type })
        // the chains: the hop, then the account's WARP
        assertEquals(res.added.map { s: ServerConfig -> "UK xhttp → ${s.name}" to listOf("hop", s.id) },
            res.addedChains.map { c: ChainConfig -> c.name to c.members })
        for (c in res.addedChains) assertTrue(c.id, Regex("^chain-[0-9a-z]+[0-9a-f]{4}$").matches(c.id))
        assertEquals(res.added.mapIndexed { i: Int, s: ServerConfig -> listOf(s.name, listOf(s.id), res.addedChains[i].id, res.addedChains[i].name, s.warp?.license) },
            res.accounts.map { x: Warp.AccountResult -> listOf(x.name, x.serverIds, x.chainId, x.chainName, x.info.license) })
        assertTrue(res.warnings.isEmpty())
        assertNull(res.stopped)
        assertEquals(Warp.Account(deviceId, "unlimited", true), res.account)
        val text = b.logs.joinToString("\n") + res.accounts.joinToString("\n") { x: Warp.AccountResult -> x.info.toString() }
        for (k in listOf(license, key2, token)) assertFalse("a secret reached the log", text.contains(k))
        // what each server keeps of its account comes back from the store as it went in
        for (s in res.added) assertEquals(s.warp, ServerConfig.fromJson(JSONObject(s.toJson().toString())).warp)
    }

    @Test fun addWarp_wireguard_aChainAsTheHop_direct_aHopGoneOrAnHttpProxyIsRefusedBeforeAnyDeviceIsMade() {
        val a1 = FakeApi()
        val r1 = batch(Warp.AddArgs(kind = "wireguard", wg = Warp.WgOptions(use = "chain", chainWith = "chain:old-chain"))) { r: Warp.Req -> a1.call(r) }.result
        assertTrue(r1.error, r1.ok)
        assertEquals(listOf("Old → ☁ WARP" to listOf("hop", r1.added[0].id)), r1.addedChains.map { c: ChainConfig -> c.name to c.members })

        val a2 = FakeApi()
        val r2 = batch(Warp.AddArgs(kind = "wireguard", wg = Warp.WgOptions(use = "direct", antiDpi = true))) { r: Warp.Req -> a2.call(r) }.result
        assertTrue(r2.error, r2.ok)
        assertTrue(r2.addedChains.isEmpty())
        assertEquals("random", r2.added[0].outbound.optString("_noise"))
        assertNull(r2.accounts[0].chainId)

        for (chainWith in listOf("", "gone", "px", "chain:nope")) {
            val a = FakeApi()
            val res = batch(Warp.AddArgs(kind = "wireguard", licenses = listOf(license), wg = Warp.WgOptions(use = "chain", chainWith = chainWith))) { q: Warp.Req -> a.call(q) }.result
            assertFalse(chainWith, res.ok)
            assertEquals(chainWith, "badHop", res.code)
            assertEquals("no device registered for nothing", 0, a.calls.size)
        }
        // a bad key too, before anything
        val a3 = FakeApi()
        val r3 = batch(Warp.AddArgs(kind = "wireguard", licenses = listOf(license, "nope"), wg = Warp.WgOptions(chainWith = "hop"))) { r: Warp.Req -> a3.call(r) }.result
        assertEquals("badLicense", r3.code)
        assertEquals(0, a3.calls.size)
        assertTrue(Warp.messageFor(r3.code, r3.detail).startsWith("Key 2: "))
    }

    @Test fun addWarp_aBatchStoppedByCloudflare_keepsWhatWasMade_andSaysWhy_theFirstOneFailingFailsTheCall() {
        val api = FakeApi()
        var posts = 0
        val limited: (Warp.Req) -> Warp.Res = { r: Warp.Req ->
            if (r.method == "POST") posts++
            if (r.method == "POST" && posts >= 3) Warp.Res(429, "{}") else api.call(r)
        }
        val res = batch(Warp.AddArgs(kind = "wireguard", count = 4, wg = Warp.WgOptions(chainWith = "hop")), limited).result
        assertTrue(res.error, res.ok)
        assertEquals(2, res.added.size)
        assertEquals(2, res.addedChains.size)
        val st = res.stopped
        assertNotNull(st)
        assertEquals(listOf("rateLimited", "2", "4"), listOf(st?.code, st?.made.toString(), st?.wanted.toString()))
        assertTrue((st?.detail ?: "").contains("429"))

        val none = batch(Warp.AddArgs(kind = "wireguard", count = 3, wg = Warp.WgOptions(chainWith = "hop"))) { _: Warp.Req -> Warp.Res(429, "{}") }.result
        assertFalse(none.ok)
        assertEquals("rateLimited", none.code)
        assertTrue(none.added.isEmpty())
        assertTrue(none.addedChains.isEmpty())
    }

    @Test fun addWarp_masque_twoAccounts_numberedNames_everyServerKeepsItsAccount_warningsCarryTheAccountsName() {
        val api = FakeApi(status = mapOf("PUT /reg/{id}/account" to 403))
        val res = batch(Warp.AddArgs(mode = "new", count = 2, licenses = listOf(license), options = Warp.Options(http = "both"))) { r: Warp.Req -> api.call(r) }.result
        assertTrue(res.error, res.ok)
        assertEquals(listOf("☁ WARP 1 · H3", "☁ WARP 1 · H2", "☁ WARP 2 · H3", "☁ WARP 2 · H2"), res.added.map { s: ServerConfig -> s.name })
        assertEquals(listOf(listOf("☁ WARP 1", 2, null, "masque", "refused"), listOf("☁ WARP 2", 2, null, "masque", "refused")),
            res.accounts.map { x: Warp.AccountResult -> listOf(x.name, x.serverIds.size, x.chainId, x.info.kind, x.info.license) })
        for (s in res.added) assertEquals("masque", s.warp?.kind)
        assertEquals(listOf("licenseFailed" to "☁ WARP 1", "licenseFailed" to "☁ WARP 2"), res.warnings.map { w: Warp.Warning -> w.code to w.name })
        assertTrue(res.addedChains.isEmpty())
    }

    @Test fun addWarp_wireguardImport_aConfOrAWireguardLink_noNetwork_markedImported_chainedWhenAsked_anythingElseIsBadConf() {
        val priv = b64e.encodeToString(ByteArray(32).also { b: ByteArray -> java.security.SecureRandom().nextBytes(b) })
        val conf = "[Interface]\nPrivateKey = $priv\nAddress = 172.16.0.2/32, 2606:4700:110:8a36::2/128\nMTU = 1280\n\n" +
            "[Peer]\nPublicKey = $wgPeer\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = engage.cloudflareclient.com:2408\n"
        val offline: (Warp.Req) -> Warp.Res = { _: Warp.Req -> throw IOException("no network for an import") }
        val res = batch(Warp.AddArgs(kind = "wireguard", mode = "import", importText = conf, wg = Warp.WgOptions(use = "chain", chainWith = "hop")), offline).result
        assertTrue(res.error, res.ok)
        val s = res.added[0]
        assertEquals(listOf("☁ WARP", "wireguard", "2408", "engage.cloudflareclient.com"), listOf(s.name, s.protocol, s.port.toString(), s.address))
        assertEquals(Warp.AccountInfo(kind = "wireguard", imported = true), s.warp)
        assertTrue(Canon.same("""{"kind":"wireguard","imported":true}""", s.warp?.toJson()))
        assertEquals(listOf("hop", s.id), res.addedChains[0].members)
        assertEquals(Warp.AccountInfo(kind = "wireguard", imported = true), res.accounts[0].info)
        val set = s.outbound.getJSONObject("settings")
        assertEquals(priv, set.getString("secretKey"))
        assertEquals(1280, set.getInt("mtu"))

        val link = "wireguard://" + java.net.URLEncoder.encode(priv, "UTF-8") + "@162.159.192.1:2408?publickey=" +
            java.net.URLEncoder.encode(wgPeer, "UTF-8") + "&address=172.16.0.2%2F32&reserved=1,2,3#w"
        val viaLink = batch(Warp.AddArgs(kind = "wireguard", mode = "import", importText = link, wg = Warp.WgOptions(use = "direct")), offline).result
        assertTrue(viaLink.error, viaLink.ok)
        assertTrue(Canon.same("""{"a":[1,2,3]}""", JSONObject().put("a", viaLink.added[0].outbound.getJSONObject("settings").getJSONArray("reserved"))))
        assertEquals("☁ WARP", viaLink.added[0].name)
        assertTrue(viaLink.addedChains.isEmpty())

        val noKey = "[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = $wgPeer\nEndpoint = h.example:51820\n"
        for (bad in listOf("", "{\"private_key\":\"x\"}", "vless://u@h:1", "[Interface]\nAddress = 10.0.0.2/32\n", noKey)) {
            val r = batch(Warp.AddArgs(kind = "wireguard", mode = "import", importText = bad, wg = Warp.WgOptions(use = "direct")), offline).result
            assertFalse(bad, r.ok)
            assertEquals(bad, "badConf", r.code)
        }
        assertTrue("the parser's words say which line", batch(Warp.AddArgs(kind = "wireguard", mode = "import", importText = noKey,
            wg = Warp.WgOptions(use = "direct")), offline).result.error.contains("PrivateKey is missing"))
    }

    /* ------------------------------ the account, kept and in words ------------------------------ */

    @Test fun accountInfo_keptOnTheServer_roundTripsThroughTheStore_writtenOnlyWhenThere() {
        val info = Warp.AccountInfo(kind = "wireguard", deviceId = "d-1", type = "limited", warpPlus = true, premiumData = 27670000000000000L,
            quota = null, usage = 5L, role = "parent", referralCount = 2L, devices = 4L, license = "applied", licenseTail = "K1l2",
            checkedAt = "2026-10-14T09:30:15.123Z")
        assertEquals(info, Warp.AccountInfo.fromJson(JSONObject(info.toJson().toString())))
        assertTrue(info.toJson().isNull("quota"))
        val plain = ServerConfig(id = "s", name = "n", protocol = "vless", address = "a", port = 1, outbound = JSONObject())
        assertFalse("a server without one is stored as before", plain.toJson().has("warp"))
        assertNull(ServerConfig.fromJson(plain.toJson()).warp)
        val kept = plain.copy(warp = info)
        assertEquals(info, ServerConfig.fromJson(JSONObject(kept.toJson().toString())).warp)
        // odd stored values read as the defaults
        val odd = Warp.AccountInfo.fromJson(JSONObject().put("kind", "other").put("type", "gold").put("license", "maybe").put("premiumData", "x"))
        assertNotNull(odd)
        assertEquals(listOf("masque", "", "none"), listOf(odd?.kind, odd?.type, odd?.license))
        assertNull(odd?.premiumData)
        assertNull(Warp.AccountInfo.fromJson(null))
    }

    @Test fun theNewCodes_inTheSheetsWords_andAnAccountInWords_underCloudflaresOwnNames() {
        for (code in listOf("badHop", "badConf")) {
            assertTrue(code, Warp.ERROR_CODES.contains(code))
            assertTrue(code, Warp.messageFor(code, "why").contains("why"))
        }
        assertTrue(Warp.WARNING_CODES.contains("accountUnread"))
        assertTrue(Warp.warningText(Warp.Warning("accountUnread", "500")).contains("(500)"))
        assertEquals("At most 10 WARP+ keys at once", Warp.messageFor("badLicense", "At most 10 WARP+ keys at once"))
        assertEquals(listOf("Free", "WARP+ (data)", "WARP+ Unlimited", "Team (Zero Trust)", "Unknown"),
            listOf("free", "limited", "unlimited", "team", "").map { t: String -> Warp.typeLabel(t) })
        val lines = Warp.accountLines(Warp.AccountInfo(kind = "wireguard", type = "free", license = "applied", licenseTail = "K1l2",
            premiumData = 0L, quota = 1073741824L, usage = null, devices = 2L))
        assertEquals(listOf("Type: Free", "WARP+ key …K1l2: applied", "The key was accepted, but the account is still free",
            "premium_data 0 B · quota 1.0 GB · usage —", "Devices on this account: 2"), lines)
        assertFalse("never called “remaining”", lines.joinToString(" ").contains("remaining", ignoreCase = true))
        assertEquals("WARP+ key …K1l2: refused — Too many connected devices.", Warp.accountLines(Warp.AccountInfo(kind = "masque", license = "refused",
            licenseTail = "K1l2", licenseError = "Too many connected devices."))[1])
        assertEquals("No WARP+ key", Warp.accountLines(Warp.AccountInfo(kind = "masque"))[1])
        assertEquals(1, Warp.accountLines(Warp.AccountInfo(kind = "wireguard", imported = true)).size)
        assertEquals("24.6 PB", Warp.humanBytes(27670000000000000L))
    }
}
