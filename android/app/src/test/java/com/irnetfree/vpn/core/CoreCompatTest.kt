package com.irnetfree.vpn.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** CoreCompat against the desktop's pins (tests/coreCompat.test.js). */
class CoreCompatTest {
    private fun cfg(stream: String, protocol: String = "vless") =
        JSONObject("""{"log":{"loglevel":"warning"},"outbounds":[{"tag":"proxy","protocol":"$protocol","settings":{},"streamSettings":$stream},{"tag":"direct","protocol":"freedom"}]}""")
    private fun ss(c: JSONObject) = c.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings")
    private val KCP = """{"network":"kcp","security":"none","kcpSettings":{"header":{"type":"srtp"},"seed":"SEED","mtu":1350}}"""

    @Test fun nothingToAdaptIsTheSameObject() {
        val c = cfg("""{"network":"ws","security":"tls","wsSettings":{"path":"/"}}""")
        assertFalse(CoreCompat.needsCoreVersion(c)); assertSame(c, CoreCompat.adaptForCore(c, "26.3.27"))
        assertTrue(CoreCompat.needsCoreVersion(cfg(KCP)))
        val old = cfg(KCP); assertSame(old, CoreCompat.adaptForCore(old, "26.1.23"))
    }

    @Test fun kcpMasksBetween26_1_31And26_6() {
        val out = ss(CoreCompat.adaptForCore(cfg(KCP), "26.3.27"))
        assertTrue(Canon.same("""{"network":"kcp","security":"none","kcpSettings":{"mtu":1350},
            "finalmask":{"udp":[{"type":"mkcp-aes128gcm","settings":{"password":"SEED"}},{"type":"header-srtp"}]}}""", out))
        assertTrue(Canon.same("""{"udp":[{"type":"mkcp-original"},{"type":"header-wechat"}]}""",
            ss(CoreCompat.adaptForCore(cfg("""{"network":"kcp","kcpSettings":{"header":{"type":"wechat-video"},"seed":""}}"""), "26.5.9")).getJSONObject("finalmask")))
    }

    @Test fun kcpLegacyMaskFrom26_6_1AndTheLibv2rayVersionString() {
        for (v in listOf("26.6.1", "26.9.30", "Lib v36, Xray-core v26.7.11", "")) {
            val out = ss(CoreCompat.adaptForCore(cfg(KCP), v))
            assertTrue(v, Canon.same("""{"udp":[{"type":"mkcp-legacy","settings":{"value":"SEED"}},{"type":"mkcp-legacy","settings":{"header":"srtp"}}]}""", out.getJSONObject("finalmask")))
            assertTrue(v, Canon.same("""{"mtu":1350}""", out.getJSONObject("kcpSettings")))
        }
        val back = ss(CoreCompat.adaptForCore(cfg("""{"network":"kcp","kcpSettings":{},"finalmask":{"udp":[{"type":"mkcp-original"},{"type":"header-dns","settings":{"domain":"d.example"}}]}}"""), "26.1.23"))
        assertTrue(Canon.same("""{"header":{"type":"dns","domain":"d.example"}}""", back.getJSONObject("kcpSettings")))
        assertFalse(back.has("finalmask"))
    }

    private val HOP = """{"type":"udphop","settings":{"mode":"intervalLocal,intervalRemote","interval":"30","remotePorts":"20000-30000"}}"""
    private val SAL = """{"type":"salamander","settings":{"password":"OB"}}"""
    private fun hy(fm: String) = cfg("""{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"h.example"},"hysteriaSettings":{"version":2,"auth":"pw"},"finalmask":$fm}""", "hysteria")

    @Test fun hysteriaHoppingPerVersion() {
        val now = hy("""{"udp":[$SAL,$HOP]}""")
        assertSame(now, CoreCompat.adaptForCore(now, "26.9.9"))
        for (v in listOf("26.3.27", "Lib v35, Xray-core v26.7.11", "26.9.8")) {
            assertTrue(v, Canon.same("""{"udp":[$SAL],"quicParams":{"brutalDown":"100 mbps","udpHop":{"ports":"20000-30000","interval":"30"}}}""",
                ss(CoreCompat.adaptForCore(hy("""{"udp":[$SAL,$HOP],"quicParams":{"brutalDown":"100 mbps"}}"""), v)).getJSONObject("finalmask")))
        }
        val old = ss(CoreCompat.adaptForCore(hy("""{"udp":[$SAL,$HOP],"quicParams":{"brutalUp":"10 mbps","brutalDown":"20 mbps"}}"""), "26.2.6"))
        assertTrue(Canon.same("""{"version":2,"auth":"pw","udphop":{"ports":"20000-30000","interval":"30"},"up":"10 mbps","down":"20 mbps"}""", old.getJSONObject("hysteriaSettings")))
        assertTrue(Canon.same("""{"udp":[$SAL]}""", old.getJSONObject("finalmask")))
        val moved = ss(CoreCompat.adaptForCore(hy("""{"udp":[$SAL],"quicParams":{"brutalUp":"50 mbps","udpHop":{"ports":"1000-2000","interval":"20"}}}"""), "26.9.30"))
        assertTrue(Canon.same("""{"udp":[$SAL,{"type":"udphop","settings":{"mode":"intervalLocal,intervalRemote","interval":"20","remotePorts":"1000-2000"}}],"quicParams":{"brutalUp":"50 mbps"}}""", moved.getJSONObject("finalmask")))
    }

    private val XDNS_OLD = """{"type":"xdns","settings":{"domains":[{"name":"t.example.com","types":[16]}],"resolvers":[{"type":"udp","settings":{"addr":"1.1.1.1:53"}},{"type":"tcp","settings":{"addr":"8.8.8.8:53"}}],"extraPoll":0}}"""
    private val XDNS_NEW = """{"type":"xdns","settings":{"domains":[{"names":["a.example","b.example"],"edns0":1232}],"resolvers":[{"addrs":["1.1.1.1","tcp://8.8.8.8","[2606:4700::1111]:5353","2606:4700::1001"]}]}}"""

    @Test fun xdnsNamesAndAddrsFrom26_10_5() {
        val c = cfg("""{"network":"xhttp","security":"tls","finalmask":{"udp":[$XDNS_OLD]}}""")
        assertTrue(CoreCompat.needsCoreVersion(c))
        for (v in listOf("26.10.10", "Lib v37, Xray-core v26.10.10", "")) {
            assertTrue(v, Canon.same("""{"udp":[{"type":"xdns","settings":{"domains":[{"types":[16],"names":["t.example.com"]}],
                "resolvers":[{"addrs":["udp://1.1.1.1:53"]},{"addrs":["tcp://8.8.8.8:53"]}],"extraPoll":0}}]}""",
                ss(CoreCompat.adaptForCore(c, v)).getJSONObject("finalmask")))
        }
        val fresh = cfg("""{"network":"xhttp","finalmask":{"udp":[$XDNS_NEW]}}""")
        assertSame(fresh, CoreCompat.adaptForCore(fresh, "26.10.10"))
    }

    @Test fun xdnsNameAndTypedResolversUpTo26_10_3() {
        for (v in listOf("26.9.30", "26.10.3")) {
            assertTrue(v, Canon.same("""{"udp":[{"type":"xdns","settings":{
                "domains":[{"name":"a.example","edns0":1232},{"name":"b.example","edns0":1232}],
                "resolvers":[{"type":"udp","settings":{"addr":"1.1.1.1:53"}},{"type":"tcp","settings":{"addr":"8.8.8.8:53"}},
                  {"type":"udp","settings":{"addr":"[2606:4700::1111]:5353"}},{"type":"udp","settings":{"addr":"[2606:4700::1001]:53"}}]}}]}""",
                ss(CoreCompat.adaptForCore(cfg("""{"network":"kcp","finalmask":{"udp":[$XDNS_NEW]}}"""), v)).getJSONObject("finalmask")))
        }
        val old = cfg("""{"network":"kcp","finalmask":{"udp":[$XDNS_OLD]}}""")
        assertSame(old, CoreCompat.adaptForCore(old, "26.9.30"))
    }

    @Test fun neverChangesItsInput() {
        val c = cfg(KCP); val before = c.toString()
        CoreCompat.adaptForCore(c, "26.9.30"); CoreCompat.adaptForCore(c, "26.3.27")
        assertEquals(before, c.toString())
    }
}
