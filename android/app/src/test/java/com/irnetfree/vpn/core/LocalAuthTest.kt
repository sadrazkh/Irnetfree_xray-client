package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.DataInputStream
import java.io.OutputStream
import java.net.Authenticator
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections

/**
 * The tunnel's own local proxies are not open to every app on the phone.
 *
 * socks-in (10808) and http-in (10809) used to take anyone: an installed app
 * could ask them for the VPN's exit address and so detect the VPN (the 2025
 * "localhost SOCKS" class). Each session now puts a random username/password on
 * both, hev and the app's own clients present it, and the metrics listener —
 * which nothing on Android reads — is gone. The pool's own ports stay open:
 * exposing them is what that feature is for.
 */
class LocalAuthTest {
    private val auth = LocalAuth("u1d2", "p9f8e7")

    @After fun forget() { LocalProxyAuth.release(auth) }

    private fun vless(id: String): ServerConfig {
        val ob = JSONObject().put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(JSONObject().put("address", "a.example").put("port", 443)
                .put("users", JSONArray().put(JSONObject().put("id", "u-$id").put("encryption", "none"))))))
            .put("streamSettings", JSONObject().put("network", "ws").put("security", "tls")
                .put("tlsSettings", JSONObject().put("serverName", "a.example")))
        return ServerConfig(id, id, "vless", "a.example", 443, ob)
    }
    private val a = vless("a")
    private fun settings() = AppSettings(blockAds = false, enableSniffing = false)
    private fun inbound(c: JSONObject, tag: String): JSONObject {
        val arr = c.getJSONArray("inbounds")
        return (0 until arr.length()).map { arr.getJSONObject(it) }.first { it.getString("tag") == tag }
    }

    @Test fun theTunnelsSocksAndHttpInboundsAskForTheSessionsCredentials() {
        val c = ConfigBuilder.build(ConnectionPlan.Single(a), settings(), geoAssets = true, inboundAuth = auth)
        val socks = inbound(c, "socks-in").getJSONObject("settings")
        assertEquals("password", socks.getString("auth"))
        assertEquals("""[{"pass":"p9f8e7","user":"u1d2"}]""", Canon.of(socks.getJSONArray("accounts")))
        assertTrue("hev relays UDP through it", socks.getBoolean("udp"))
        val http = inbound(c, "http-in").getJSONObject("settings")
        assertEquals("""[{"pass":"p9f8e7","user":"u1d2"}]""", Canon.of(http.getJSONArray("accounts")))
        // Nothing on Android reads the metrics listener (the traffic figures
        // come from hev), and it answered anyone on 127.0.0.1:10085.
        assertFalse(c.has("metrics"))
    }

    @Test fun aPoolLocksItsTunnelInboundsAndLeavesItsOwnPortsOpen() {
        val plan = ConnectionPlan.Pool(listOf(PoolEntry("p1", "P", "a", 60001, 60002, true)), "a", mapOf("a" to a), emptyMap())
        val c = ConfigBuilder.build(plan, settings(), geoAssets = true, inboundAuth = auth)
        assertEquals("password", inbound(c, "socks-in").getJSONObject("settings").getString("auth"))
        assertTrue(inbound(c, "http-in").getJSONObject("settings").has("accounts"))
        assertEquals("noauth", inbound(c, "ps-p1").getJSONObject("settings").getString("auth"))
        assertFalse(inbound(c, "ps-p1").getJSONObject("settings").has("accounts"))
        assertFalse(inbound(c, "ph-p1").getJSONObject("settings").has("accounts"))
        assertFalse(c.has("metrics"))
    }

    @Test fun withoutCredentialsTheShapeIsUnchanged() {
        val c = ConfigBuilder.build(ConnectionPlan.Single(a), settings(), geoAssets = true)
        assertEquals("noauth", inbound(c, "socks-in").getJSONObject("settings").getString("auth"))
        assertFalse(inbound(c, "http-in").getJSONObject("settings").has("accounts"))
    }

    @Test fun singBoxTakesTheSameCredentialsInItsOwnShape() {
        val c = SingboxConfig.build(a, settings(), auth)
        assertEquals("""[{"password":"p9f8e7","username":"u1d2"}]""", Canon.of(inbound(c, "socks-in").getJSONArray("users")))
        assertEquals("""[{"password":"p9f8e7","username":"u1d2"}]""", Canon.of(inbound(c, "http-in").getJSONArray("users")))
        assertFalse(inbound(SingboxConfig.build(a, settings()), "socks-in").has("users"))
    }

    @Test fun everySessionGetsFreshCredentialsThatNeedNoQuoting() {
        val x = LocalAuth.random(); val y = LocalAuth.random()
        assertNotEquals(x, y)
        // They go into hev's YAML in single quotes and into JSON: hex only.
        for (v in listOf(x.user, x.pass, y.user, y.pass)) assertTrue(v, Regex("^[0-9a-f]{16,}$").matches(v))
    }

    /* ---------- the app's own clients: java.net's SOCKS asks the Authenticator ---------- */

    @Test fun theAuthenticatorAnswersOnlyForTheTunnelsOwnPort() {
        LocalProxyAuth.set(40001, auth)
        assertEquals(40001, LocalProxyAuth.activePort)
        val lo = InetAddress.getByName("127.0.0.1")
        val pa = Authenticator.requestPasswordAuthentication("127.0.0.1", lo, 40001, "SOCKS5", "SOCKS authentication", null)
        assertNotNull(pa)
        assertEquals("u1d2", pa!!.userName); assertEquals("p9f8e7", String(pa.password))
        // a throwaway test core on another port, a remote proxy, an HTTP 401: never
        assertNull(Authenticator.requestPasswordAuthentication("127.0.0.1", lo, 40002, "SOCKS5", "SOCKS authentication", null))
        assertNull(Authenticator.requestPasswordAuthentication("10.0.0.5", InetAddress.getByName("10.0.0.5"), 40001, "SOCKS5", "SOCKS authentication", null))
        assertNull(Authenticator.requestPasswordAuthentication("127.0.0.1", lo, 40001, "http", "realm", "basic"))
        // 127.0.0.1 itself, where the tunnel listens — not the rest of loopback
        assertNull(Authenticator.requestPasswordAuthentication("127.0.0.2", InetAddress.getByName("127.0.0.2"), 40001, "SOCKS5", "SOCKS authentication", null))
        assertNull(Authenticator.requestPasswordAuthentication("::1", InetAddress.getByName("::1"), 40001, "SOCKS5", "SOCKS authentication", null))
        assertNull(Authenticator.requestPasswordAuthentication("localhost", null, 40001, "SOCKS5", "SOCKS authentication", null))
        // a newer session's credentials are not dropped by an older teardown
        LocalProxyAuth.release(LocalAuth("old", "old"))
        assertNotNull(Authenticator.requestPasswordAuthentication("127.0.0.1", lo, 40001, "SOCKS5", "SOCKS authentication", null))
        LocalProxyAuth.release(auth)
        assertNull(Authenticator.requestPasswordAuthentication("127.0.0.1", lo, 40001, "SOCKS5", "SOCKS authentication", null))
        assertNull(LocalProxyAuth.activePort)
    }

    @Test fun aJavaSocksSocketPresentsTheCredentials() {
        FakeSocks(auth).use { fake ->
            LocalProxyAuth.set(fake.port, auth)
            Socket(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", fake.port))).use { s ->
                s.connect(InetSocketAddress.createUnresolved("panel.example.invalid", 443), 5000)
            }
            assertEquals(listOf("u1d2:p9f8e7"), fake.seen.toList())
            assertEquals(listOf("panel.example.invalid:443"), fake.targets.toList())
        }
    }

    @Test fun aSubscriptionFetchThroughTheTunnelGetsThrough() {
        // OkHttp hands a SOCKS proxy to java.net's own client, so this is the
        // path SubFetch takes while connected — end to end over loopback.
        FakeSocks(auth, body = "vless://00000000-0000-0000-0000-000000000001@1.2.3.4:443?security=none&type=tcp#one").use { fake ->
            LocalProxyAuth.set(fake.port, auth)
            Subscriptions.fetch("http://sub.example.invalid/s", fake.port)
            assertTrue(fake.seen.toList().toString(), fake.seen.contains("u1d2:p9f8e7"))
            assertTrue(fake.targets.toList().toString(), fake.targets.contains("sub.example.invalid:80"))
        }
    }

    /**
     * A SOCKS5 server on loopback that insists on username/password (RFC 1929),
     * records what it was given, and answers each CONNECT as a tiny HTTP server.
     */
    private class FakeSocks(private val want: LocalAuth, private val body: String = "ok") : AutoCloseable {
        private val server = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val port: Int get() = server.localPort
        val seen: MutableList<String> = Collections.synchronizedList(ArrayList())
        val targets: MutableList<String> = Collections.synchronizedList(ArrayList())

        init {
            Thread {
                while (!server.isClosed) {
                    val s = try { server.accept() } catch (e: Exception) { break }
                    Thread { runCatching { s.use { handle(it) } } }.also { it.isDaemon = true }.start()
                }
            }.also { it.isDaemon = true }.start()
        }

        private fun handle(s: Socket) {
            s.soTimeout = 5000
            val i = DataInputStream(s.getInputStream()); val o = s.getOutputStream()
            if (i.readUnsignedByte() != 5) return
            val methods = ByteArray(i.readUnsignedByte()).also { i.readFully(it) }
            if (methods.none { it.toInt() == 2 }) { o.write(byteArrayOf(5, -1)); o.flush(); return }
            o.write(byteArrayOf(5, 2)); o.flush()
            if (i.readUnsignedByte() != 1) return
            val u = String(ByteArray(i.readUnsignedByte()).also { i.readFully(it) })
            val p = String(ByteArray(i.readUnsignedByte()).also { i.readFully(it) })
            seen.add("$u:$p")
            val ok = u == want.user && p == want.pass
            o.write(byteArrayOf(1, (if (ok) 0 else 1).toByte())); o.flush()
            if (!ok) return
            i.readUnsignedByte(); i.readUnsignedByte(); i.readUnsignedByte()   // ver, cmd, rsv
            val host = when (i.readUnsignedByte()) {
                1 -> ByteArray(4).also { i.readFully(it) }.joinToString(".") { (it.toInt() and 0xFF).toString() }
                3 -> String(ByteArray(i.readUnsignedByte()).also { i.readFully(it) })
                else -> return
            }
            targets.add("$host:${i.readUnsignedShort()}")
            o.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 0, 0)); o.flush()
            // The HTTP request, up to its blank line; then one answer.
            var line = StringBuilder(); var blank = 0
            while (blank < 1) {
                val b = i.read(); if (b < 0) return
                if (b == '\n'.code) { if (line.toString().trimEnd('\r').isEmpty()) blank++; line = StringBuilder() } else line.append(b.toChar())
            }
            respond(o)
        }

        private fun respond(o: OutputStream) {
            val bytes = body.toByteArray()
            o.write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${bytes.size}\r\nConnection: close\r\n\r\n".toByteArray())
            o.write(bytes); o.flush()
        }

        override fun close() { runCatching { server.close() } }
    }
}
