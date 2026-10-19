package com.irnetfree.vpn.vpn

import com.irnetfree.vpn.core.AppSettings
import com.irnetfree.vpn.core.ConnectionPlan
import com.irnetfree.vpn.core.EngineChoice
import com.irnetfree.vpn.core.RouteRule
import com.irnetfree.vpn.core.ServerConfig
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What a connect says about its routing (TunnelSetup.routingNotes): the mode it
 * really runs, and each thing the screen shows that the connection cannot do —
 * a sing-box server's missing routing, Windows app rules, a Private DNS that
 * goes around the app's resolver.
 */
class RoutingNotesTest {
    private val srv = ServerConfig(id = "s1", name = "UK", protocol = "vless", address = "uk.example.com", port = 443, raw = "", outbound = JSONObject().put("protocol", "vless"))
    private val single = ConnectionPlan.Single(srv)
    private val bypass = AppSettings(routingMode = "bypass-ir")

    @Test fun theSimpleModeItRuns() {
        val n = TunnelSetup.routingNotes(single, bypass, EngineChoice.XRAY, geo = true, privateDns = null)
        assertEquals(1, n.size)
        assertTrue(n[0], n[0].startsWith("Routing: Bypass Iran — Iranian sites go direct, by name (sniffing on) and by address"))
        val off = TunnelSetup.routingNotes(single, bypass.copy(enableSniffing = false), EngineChoice.XRAY, geo = true, privateDns = null)
        assertTrue(off[0], off[0].contains("sniffing OFF"))
        val noGeo = TunnelSetup.routingNotes(single, bypass, EngineChoice.XRAY, geo = false, privateDns = null)
        assertTrue(noGeo[0], noGeo[0].contains("not applied: no geo data"))
        assertEquals(listOf("Routing: Global"), TunnelSetup.routingNotes(single, AppSettings(), EngineChoice.PATTN, geo = true, privateDns = null))
    }

    @Test fun aSingboxServerCarriesNoneOfIt() {
        val n = TunnelSetup.routingNotes(single, bypass, EngineChoice.SINGBOX, geo = true, privateDns = "dns.google")
        assertEquals(1, n.size)
        assertTrue(n[0], n[0].startsWith("⚠ This server runs on sing-box") && n[0].contains("Bypass Iran"))
        assertEquals(emptyList<String>(), TunnelSetup.routingNotes(single, AppSettings(), EngineChoice.SINGBOX, geo = true, privateDns = null))
    }

    @Test fun windowsAppRulesAreSaidLeftOut() {
        val adv = ConnectionPlan.Advanced(
            rules = listOf(RouteRule("domain", "example.com", "s1"), RouteRule("process", "Telegram.exe", "s1"), RouteRule("process", "chrome.exe", "direct")),
            def = "s1", serversById = mapOf("s1" to srv), chainsById = emptyMap(), useMode = true)
        val n = TunnelSetup.routingNotes(adv, bypass, EngineChoice.XRAY, geo = true, privateDns = null)
        assertEquals("Routing: the profile's 1 rule(s), then Bypass Iran under them, the rest to its default", n[0])
        assertTrue(n[1], n[1].startsWith("⚠ 2 app rules of this profile came from Windows and are left out"))
        val noMode = TunnelSetup.routingNotes(adv.copy(useMode = false), bypass, EngineChoice.XRAY, geo = true, privateDns = null)
        assertEquals("Routing: the profile's 1 rule(s), the rest to its default", noMode[0])
    }

    @Test fun aPrivateDnsHostIsNamedOnlyWhenABypassRuns() {
        val n = TunnelSetup.routingNotes(single, bypass, EngineChoice.XRAY, geo = true, privateDns = "dns.google")
        assertEquals(2, n.size)
        assertTrue(n[1], n[1].startsWith("⚠ Android's Private DNS is set to dns.google"))
        assertEquals(1, TunnelSetup.routingNotes(single, AppSettings(), EngineChoice.XRAY, geo = true, privateDns = "dns.google").size)
    }
}
