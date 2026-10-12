package com.irnetfree.vpn.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The full server editor on the phone (ServerFields, ServerEditor) against the
 * desktop's tests/serverFields.test.js and tests/serverEditor.test.js: the
 * table, its generic read / write, a Pro value kept by a Simple-view save, a
 * transport change, a server made by hand, what a save refuses, Mux for one
 * server and the sing-box engine with VLESS Encryption.
 */
class ServerFieldsTest {
    private val uuid = "2c0f0d9a-6b3a-4f0e-9a1f-8c2b4d6e7a10"
    private val enc = "mlkem768x25519plus.native.0rtt.p7sTtcQlhzr21By6QMbFOEFjtHJa8dquXhK7pboK9GE"
    private fun wsTls(): ServerConfig = LinkParser.parseLink(
        "vless://$uuid@de.example.com:443?encryption=none&type=ws&path=%2Fw&host=h.example&security=tls&sni=h.example#DE")

    @Test fun table_uniqueIds_aPathOrSpecial_andTheAppsOwnSockoptNeverWritten() {
        val ids = ServerFields.FIELDS.map { f: SfField -> f.id }
        assertEquals(ids.size, ids.toSet().size)
        for (f in ServerFields.FIELDS) {
            assertTrue(f.id, (f.path != null) != f.special)
            assertTrue(f.id, f.tab in ServerFields.TABS)
        }
        for (f in ServerFields.PATH_FIELDS) assertFalse(f.id, Regex("sockopt\\.(interface|mark|domainStrategy|dialerProxy)$").containsMatchIn(f.path ?: ""))
        assertEquals("Mux for this server", ServerFields.str("sf.mux"))
    }

    @Test fun readEncryption_authByKeyLength_modeRtt_orWhyNot() {
        assertNull(ServerFields.readEncryption("none"))
        val x = ServerFields.readEncryption(enc)!!
        assertEquals("X25519", x.auth); assertEquals("native", x.mode); assertEquals("0rtt", x.rtt); assertNull(x.bad)
        assertEquals("ML-KEM-768", ServerFields.readEncryption("mlkem768x25519plus.native.1rtt." + "A".repeat(1579))!!.auth)
        assertEquals("edit.err.encMode", ServerFields.readEncryption("mlkem768x25519plus.plain.0rtt." + "k".repeat(43))!!.bad)
        assertEquals("edit.err.encPrefix", ServerFields.readEncryption("aes.native.0rtt." + "k".repeat(43))!!.bad)
    }

    @Test fun setPath_makesAndPrunes_likeTheDesktop() {
        val ob = JSONObject().put("streamSettings", JSONObject().put("sockopt", JSONObject()))
        ServerFields.setPath(ob, "streamSettings.xhttpSettings.extra.xmux.maxConcurrency", "16-32")
        assertEquals("16-32", ServerFields.getPath(ob, "streamSettings.xhttpSettings.extra.xmux.maxConcurrency"))
        ServerFields.setPath(ob, "streamSettings.xhttpSettings.extra.xmux.maxConcurrency", null)
        assertEquals(0, ob.getJSONObject("streamSettings").getJSONObject("xhttpSettings").length())
        ServerFields.setPath(ob, "settings.vnext.0.users.0.flow", "xtls-rprx-vision")
        assertEquals("xtls-rprx-vision", ServerFields.getPath(ob, "settings.vnext.0.users.0.flow"))
    }

    @Test fun anEdit_writesTheProFields_aSimpleSave_keepsThem_aTransportChange_dropsTheOldOnes() {
        val s = wsTls()
        val f = ServerEditor.read(s)
        assertEquals("none", f.pro["encryption"])
        f.pro["encryption"] = enc; f.pro["wsHeartbeat"] = "30"; f.pro["tcpFastOpen"] = "true"; f.pro["mux"] = "off"
        val e = ServerEditor.apply(s, f)
        val st = e.outbound.getJSONObject("streamSettings")
        assertEquals(enc, e.outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0).getString("encryption"))
        assertEquals(30, st.getJSONObject("wsSettings").getInt("heartbeatPeriod"))
        assertTrue(st.getJSONObject("sockopt").getBoolean("tcpFastOpen"))
        assertEquals("off", e.mux)
        assertTrue(e.edited.containsAll(listOf("encryption", "wsHeartbeat", "tcpFastOpen", "mux")))
        // a Simple-view save: its own fields, a new name — every Pro value stays
        val simple = ServerEditor.read(e).also { x: ServerEditor.Fields -> x.name = "renamed" }
        val r = ServerEditor.apply(e, simple)
        assertEquals("renamed", r.name)
        assertEquals(30, r.outbound.getJSONObject("streamSettings").getJSONObject("wsSettings").getInt("heartbeatPeriod"))
        assertEquals("off", r.mux)
        // to gRPC: the ws heartbeat goes, the socket options stay, gRPC's own fields are written
        val g = ServerEditor.read(r).also { x: ServerEditor.Fields -> x.network = "grpc"; x.path = "svc"; x.xmode = "multi"; x.pro["grpcIdleTimeout"] = "60" }
        val gr = ServerEditor.apply(r, g)
        val gst = gr.outbound.getJSONObject("streamSettings")
        assertFalse(gst.has("wsSettings"))
        assertEquals(true, gst.getJSONObject("grpcSettings").getBoolean("multiMode"))
        assertEquals(60, gst.getJSONObject("grpcSettings").getInt("idle_timeout"))
        assertTrue(gst.getJSONObject("sockopt").getBoolean("tcpFastOpen"))
    }

    @Test fun theDraft_roundTrips_andTheSameTransportUnderAnotherNameIsNoChange() {
        val s = wsTls()
        val f = ServerEditor.read(s)
        val d = ServerEditor.toDraft("vless", f)
        assertEquals("ws", d["network"]); assertEquals(uuid, d["uuid"]); assertEquals("none", d["encryption"])
        val back = ServerEditor.fromDraft("vless", d, f)
        assertEquals(Canon.of(s.outbound), Canon.of(ServerEditor.apply(s, back).outbound))
        // the draft edited: Encryption on, a new SNI
        d["encryption"] = enc; d["sni"] = "x.example"
        val e = ServerEditor.apply(s, ServerEditor.fromDraft("vless", d, f))
        assertEquals("x.example", e.outbound.getJSONObject("streamSettings").getJSONObject("tlsSettings").getString("serverName"))
        assertEquals(enc, ServerEditor.read(e).pro["encryption"])
    }

    @Test fun aSaveRefuses_namingTheFieldAndItsTab() {
        val d = ServerEditor.newDraft("vless").also { x: MutableMap<String, String> -> x["address"] = "a.example"; x["uuid"] = uuid }
        assertNull(ServerEditor.problem("vless", d, true, false))
        d["network"] = "xhttp"; d["xmuxMaxConcurrency"] = "16 to 32"
        assertEquals(Triple("xmuxMaxConcurrency", "transport", "edit.err.range"), ServerEditor.problem("vless", d, true, false))
        d["xmuxMaxConcurrency"] = "16-32"
        d["encryption"] = ""   // Encryption turned on, its value not pasted yet
        assertEquals("encryption", ServerEditor.problem("vless", d, true, true)?.first)
        val t = ServerEditor.newDraft("trojan").also { x: MutableMap<String, String> -> x["address"] = "t.example" }
        assertEquals(Triple("password", "protocol", "edit.err.required"), ServerEditor.problem("trojan", t, true, false))
        assertEquals("“Password” is empty", ServerEditor.problemText("trojan", Triple("password", "protocol", "edit.err.required")))
    }

    @Test fun create_everyProtocol_withItsOwnLink_andWhatItLacksSaid() {
        for (p in ServerFields.PROTOCOLS) {
            val d = ServerEditor.newDraft(p)
            d["name"] = "T"; d["address"] = "de.example.com"
            when (p) {
                "vless", "vmess" -> d["uuid"] = uuid
                "trojan", "shadowsocks", "hysteria2" -> d["password"] = "secret-1"
                "wireguard" -> { d["privateKey"] = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGtleSAzMiBi"; d["publicKey"] = "cGVlciBrZXkgdGhpcyBpcyBhIGtleSAzMiBieXRlcw==" }
                else -> {}
            }
            if (p == "vless") { d["network"] = "xhttp"; d["security"] = "tls"; d["sni"] = "de.example.com"; d["path"] = "/x"; d["xPaddingBytes"] = "100-1000" }
            val s = ServerEditor.create(p, ServerEditor.fromDraft(p, d, ServerEditor.Fields()))
            assertEquals(p, s.protocol)
            assertEquals("de.example.com", s.address)
            assertTrue(p, s.raw.isNotBlank())
            assertTrue(p, s.edited.isEmpty())
            if (p == "vless") {
                val xs = s.outbound.getJSONObject("streamSettings").getJSONObject("xhttpSettings")
                assertEquals("/x", xs.getString("path"))
                assertEquals("100-1000", xs.getJSONObject("extra").getString("xPaddingBytes"))
            }
        }
        assertThrows(IllegalArgumentException::class.java) { ServerEditor.create("vless", ServerEditor.Fields(address = "a.example", port = "443")) }
        assertThrows(IllegalArgumentException::class.java) { ServerEditor.create("tuic", ServerEditor.Fields(address = "a.example", port = "443")) }
    }

    @Test fun mux_aServersOwnSetting_beforeTheApps() {
        val on = wsTls().copy(id = "a", mux = "on")
        val off = wsTls().copy(id = "b", mux = "off")
        val plain = wsTls().copy(id = "c")
        assertEquals(setOf("a"), Mux.plan("off", listOf(on, off, plain), emptyMap(), 1L).muxIds)
        assertEquals(setOf("a", "c"), Mux.plan("on", listOf(on, off, plain), emptyMap(), 1L).muxIds)
        val auto = Mux.plan("auto", listOf(on, off, plain), emptyMap(), 1L)
        assertEquals(setOf("a"), auto.muxIds)
        assertEquals(listOf("c"), auto.toProbe.map { s: ServerConfig -> s.id })
        // its own numbers survive the store
        val stored = ServerConfig.fromJson(on.copy(muxConcurrency = 4, xudpConcurrency = 32).toJson())
        assertEquals("on", stored.mux); assertEquals(4, stored.muxConcurrency); assertEquals(32, stored.xudpConcurrency)
    }

    @Test fun singBox_refusesVlessEncryption_soTheConnectRunsItOnXray() {
        val f = ServerEditor.read(wsTls()).also { x: ServerEditor.Fields -> x.pro["encryption"] = enc }
        val s = ServerEditor.apply(wsTls(), f)
        assertThrows(SingboxConfig.Unsupported::class.java) { SingboxConfig.build(s, AppSettings()) }
        assertNotNull(SingboxConfig.build(wsTls(), AppSettings()))
    }
}
