package com.irnetfree.vpn.core

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * A change the running connection does not carry is named (the desktop's
 * settingsMeta.js): the routing mode and the per-app list above all — the two
 * the owner saw "not work" on Android because they waited, unsaid, for the
 * next connect.
 */
class SettingsApplyTest {
    private val base = AppSettings()
    private val prof = RoutingProfile("rp-1", "Work", rules = listOf(RouteRule("domain", "example.com", "direct")), def = "s1")

    @Test fun nothingAppliedNothingPending() {
        assertEquals(emptyList<String>(), SettingsApply.pending(null, base.copy(routingMode = "bypass-ir"), null))
    }

    @Test fun theSameSettingsNothingPending() {
        assertEquals(emptyList<String>(), SettingsApply.pending(SettingsApply.Applied(base, null), base.copy(), null))
    }

    @Test fun routingModeAndPerAppAreNamed() {
        val applied = SettingsApply.Applied(base, null)
        assertEquals(listOf("Routing mode"), SettingsApply.pending(applied, base.copy(routingMode = "bypass-ir"), null))
        assertEquals(listOf("Per-app routing"), SettingsApply.pending(applied, base.copy(perAppMode = "disallow", perApps = listOf("org.telegram.messenger")), null))
        assertEquals(listOf("Routing mode", "Sniffing", "DNS"),
            SettingsApply.pending(applied, base.copy(routingMode = "bypass-ir", enableSniffing = false, dnsRemote = listOf("https://dns.google/dns-query")), null))
    }

    @Test fun perAppListOrderAndAnOffModeDoNotCount() {
        val on = base.copy(perAppMode = "allow", perApps = listOf("a.b", "c.d"))
        assertEquals(emptyList<String>(), SettingsApply.pending(SettingsApply.Applied(on, null), on.copy(perApps = listOf("c.d", "a.b")), null))
        val off = base.copy(perAppMode = "off", perApps = listOf("a.b"))
        assertEquals(emptyList<String>(), SettingsApply.pending(SettingsApply.Applied(off, null), off.copy(perApps = listOf("x.y")), null))
    }

    @Test fun theProfileInUseEditedOrDeleted() {
        val applied = SettingsApply.Applied(base, prof)
        assertEquals(emptyList<String>(), SettingsApply.pending(applied, base, prof.copy()))
        assertEquals(listOf("Routing profile “Work”"), SettingsApply.pending(applied, base, prof.copy(def = "direct")))
        assertEquals(listOf("Routing profile (deleted)"), SettingsApply.pending(applied, base, null))
    }

    @Test fun whatNoConnectionReadsIsNotNamed() {
        val applied = SettingsApply.Applied(base, null)
        assertEquals(emptyList<String>(), SettingsApply.pending(applied, base.copy(autoConnect = true, autoUpdateInterval = 5, lang = "en", advancedMode = false), null))
    }
}
