package com.irnetfree.vpn.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Extensions (Modules.kt) against the shared contract's Android set: the
 * registry, what is installed by default, what the store is counted as using,
 * the one-time migration, install/remove with what one needs, the editor's
 * fields by id, the picker keeping the selected one, and the words of every
 * extension in both languages.
 */
class ModulesTest {
    private val androidSet = setOf("chains", "groups", "advancedRouting", "pool", "warp", "echOutbound", "antiDpi", "lanShare")

    private fun ob(protocol: String = "vless"): JSONObject = JSONObject().put("protocol", protocol)
    private fun srv(id: String, outbound: JSONObject, protocol: String = outbound.optString("protocol"), warp: Warp.AccountInfo? = null): ServerConfig =
        ServerConfig(id, id, protocol, "$id.example.com", 443, outbound, warp = warp)
    private fun tls(o: JSONObject, tlsSettings: JSONObject): JSONObject =
        o.put("streamSettings", JSONObject().put("security", "tls").put("tlsSettings", tlsSettings))

    private val plain = srv("plain", tls(ob(), JSONObject().put("serverName", "plain.example.com")))
    private val fragment = srv("frag", ob().put("_fragment", "tlshello,100-200,10-20"))
    private val noise = srv("noise", ob("wireguard").put("_noise", "random"))
    private val finalmask = srv("fm", ob().put("streamSettings", JSONObject().put("finalmask", JSONObject().put("udp", "x"))))
    private val hy2Mask = srv("hy2", ob("hysteria2").put("streamSettings", JSONObject().put("finalmask", JSONObject().put("udp", "salamander"))))
    private val ciphers = srv("cs", tls(ob(), JSONObject().put("cipherSuites", "TLS_AES_128_GCM_SHA256")))
    private val ech = srv("ech", tls(ob(), JSONObject().put("echOutbound", JSONObject().put("protocol", "freedom"))))
    private val echNull = srv("echNull", tls(ob(), JSONObject().put("echOutbound", JSONObject.NULL)))
    private val masque = srv("masque", ob("masque"))
    private val warpWg = srv("warpwg", ob("wireguard"), warp = Warp.AccountInfo(kind = Warp.KIND_WIREGUARD, type = "free"))

    private fun counts(d: Modules.Data): Map<String, Int> = Modules.inUseOf(d)

    @Test fun theRegistryIsTheContractsAndroidSet() {
        assertEquals(androidSet, Modules.IDS.toSet())
        assertEquals("no id twice", Modules.IDS.size, Modules.IDS.toSet().size)
        assertEquals("android", Modules.PLATFORM)
        assertEquals(listOf("connection", "routing", "network", "security"), Modules.CATEGORIES)
        for (m in Modules.MODULES) {
            assertTrue("${m.id}'s category", m.category in Modules.CATEGORIES)
            assertTrue("${m.id}'s icon", m.icon.isNotBlank())
            for (r in m.requires) assertTrue("${m.id} needs an extension this app has: $r", Modules.available(r) && r != m.id)
            assertEquals("mod.${m.id}.name", m.nameKey)
            assertEquals(m.nameKey, Modules.nameKey(m.id))
        }
        // the desktop's and the router's own are not on a phone
        for (id in listOf("multiWan", "remoteRelay", "lanUsers", "nope")) assertFalse(id, Modules.available(id))
        assertEquals(Modules.CHAINS, Modules.byId("chains")?.id)
        assertNull(Modules.byId("multiWan"))
    }

    @Test fun nothingIsInstalledUntilItIs() {
        for (id in Modules.IDS) assertFalse(id, Modules.isOn(emptyMap(), id))
        assertFalse(Modules.isOn(mapOf("chains" to false), "chains"))
        assertTrue(Modules.isOn(mapOf("chains" to true), "chains"))
        // what the store holds read back: only this app's ids, only true; anything unreadable is none
        assertEquals(emptyMap<String, Boolean>(), Modules.fromJson(null))
        assertEquals(emptyMap<String, Boolean>(), Modules.fromJson(""))
        assertEquals(emptyMap<String, Boolean>(), Modules.fromJson("not json"))
        assertEquals(emptyMap<String, Boolean>(), Modules.fromJson("[]"))
        assertEquals(mapOf("chains" to true, "lanShare" to true),
            Modules.fromJson("{\"chains\":true,\"groups\":false,\"multiWan\":true,\"lanShare\":true}"))
        val m = mapOf("warp" to true, "pool" to true, "groups" to false)
        assertEquals(mapOf("warp" to true, "pool" to true), Modules.fromJson(Modules.toJson(m)))
        assertEquals("{}", Modules.toJson(emptyMap()))
    }

    @Test fun whatAStoreUsesIsCounted() {
        // a fresh store uses nothing
        val none = counts(Modules.Data())
        assertEquals(androidSet, none.keys)
        for ((id, n) in none) assertEquals(id, 0, n)

        val d = Modules.Data(
            servers = listOf(plain, fragment, noise, finalmask, hy2Mask, ciphers, ech, echNull, masque, warpWg),
            groups = listOf(GroupConfig("grp-a", "A", members = listOf(GroupMember("plain"))), GroupConfig("grp-b", "B")),
            chains = listOf(ChainConfig("c1", "C", listOf("plain", "ech"))),
            pool = listOf(PoolEntry("p1", "P1", "plain", 60001, 60002, true), PoolEntry("p2", "P2", "ech", 60003, 60004, false), PoolEntry("p3", "P3", "", 0, 0, true)),
            lanShareEnabled = true
        )
        val c = counts(d)
        assertEquals(1, c["chains"])
        assertEquals(2, c["groups"])
        assertEquals("every pool entry, on or off", 3, c["pool"])
        assertEquals("a WARP account's server and MASQUE", 2, c["warp"])
        assertEquals("tlsSettings.echOutbound; a JSON null is none", 1, c["echOutbound"])
        // fragment, noise, finalmask, cipherSuites — not Hysteria2's finalmask (its obfs and hopping)
        assertEquals(4, c["antiDpi"])
        assertEquals(1, c["lanShare"])
        assertEquals(0, c["advancedRouting"])

        assertTrue(Modules.isWarpServer(masque)); assertTrue(Modules.isWarpServer(warpWg)); assertFalse(Modules.isWarpServer(plain))
        assertTrue(Modules.hasEchOutbound(ech)); assertFalse(Modules.hasEchOutbound(echNull)); assertFalse(Modules.hasEchOutbound(plain))
        for (s in listOf(fragment, noise, finalmask, ciphers)) assertTrue(s.id, Modules.hasAntiDpi(s))
        for (s in listOf(plain, hy2Mask, ech, masque)) assertFalse(s.id, Modules.hasAntiDpi(s))
    }

    @Test fun advancedRoutingIsInUseOnceItIsUsedAtAll() {
        val def = RoutingProfile(RoutingProfiles.DEFAULT_ID, "Advanced routing", rules = listOf(RouteRule("domain", "example.com", "direct")))
        val other = RoutingProfile("rp-work", "Work")
        // only rp-default, switched off, not selected: rules typed long ago and left off are not a use
        assertEquals(0, counts(Modules.Data(profiles = listOf(def), selection = "plain"))["advancedRouting"])
        // switched on
        assertEquals(1, counts(Modules.Data(profiles = listOf(def), settings = AppSettings(advancedRouting = true)))["advancedRouting"])
        // a profile besides rp-default: every profile is counted
        assertEquals(2, counts(Modules.Data(profiles = listOf(def, other)))["advancedRouting"])
        // a profile selected for Connect
        assertEquals(1, counts(Modules.Data(profiles = listOf(def), selection = Selection.forProfile(def.id)))["advancedRouting"])
        assertEquals(1, counts(Modules.Data(profiles = listOf(def), selection = Selection.ADVANCED))["advancedRouting"])
        // in use with no profile list at hand still counts one
        assertEquals(1, counts(Modules.Data(settings = AppSettings(advancedRouting = true)))["advancedRouting"])
    }

    @Test fun aStoreFromBeforeGetsWhatItUsesAndAFreshOneNothing() {
        // a fresh install: everything off
        assertEquals(emptyMap<String, Boolean>(), Modules.migrate(counts(Modules.Data())))

        // an upgrade: what it uses is installed, the rest is not
        val used = Modules.Data(
            servers = listOf(plain, fragment, masque),
            chains = listOf(ChainConfig("c1", "C", listOf("plain", "frag"))),
            pool = listOf(PoolEntry("p1", "P1", "plain", 60001, 60002, true)),
            settings = AppSettings(advancedRouting = true)
        )
        assertEquals(setOf("chains", "pool", "warp", "antiDpi", "advancedRouting"), Modules.migrate(counts(used)).keys)
        assertTrue(Modules.migrate(counts(used)).values.all { v: Boolean -> v })

        // groups, ECH outbound and LAN sharing alone
        val other = Modules.Data(
            servers = listOf(ech),
            groups = listOf(GroupConfig("grp-a", "A", members = listOf(GroupMember("ech")))),
            lanShareEnabled = true
        )
        assertEquals(setOf("groups", "echOutbound", "lanShare"), Modules.migrate(counts(other)).keys)

        // only servers, nothing advanced: nothing installed
        assertEquals(emptyMap<String, Boolean>(), Modules.migrate(counts(Modules.Data(servers = listOf(plain, hy2Mask)))))

        // what an extension in use needs comes with it
        val reg = listOf(Modules.Module("a", "A", "connection"), Modules.Module("b", "B", "connection", listOf("a")), Modules.Module("c", "C", "routing"))
        assertEquals(mapOf("b" to true, "a" to true), Modules.migrate(mapOf("b" to 1, "c" to 0), reg))
    }

    @Test fun installBringsWhatItNeedsAndRemoveIsRefusedWhileNeeded() {
        val reg = listOf(
            Modules.Module("a", "A", "connection"),
            Modules.Module("b", "B", "connection", listOf("a")),
            Modules.Module("c", "C", "routing", listOf("b")),
            Modules.Module("x", "X", "network", listOf("y")),
            Modules.Module("y", "Y", "network", listOf("x"))   // a loop in the table
        )
        // c needs b, which needs a: all three, and the two it brought are said
        val c = Modules.set(emptyMap(), "c", true, reg)
        assertEquals(setOf("a", "b", "c"), c.modules.keys)
        assertEquals(setOf("a", "b"), c.added.toSet())
        assertTrue(c.blockedBy.isEmpty())
        // installing what is there brings nothing more
        assertTrue(Modules.set(c.modules, "a", true, reg).added.isEmpty())
        // a is needed by b (installed): refused, unchanged, by name
        val refused = Modules.set(c.modules, "a", false, reg)
        assertEquals(listOf("b"), refused.blockedBy)
        assertEquals(c.modules, refused.modules)
        // c needs b, but nothing needs c: removed, the rest kept
        val noC = Modules.set(c.modules, "c", false, reg)
        assertTrue(noC.blockedBy.isEmpty())
        assertEquals(setOf("a", "b"), noC.modules.keys)
        // then b, then a
        val noB = Modules.set(noC.modules, "b", false, reg)
        assertEquals(setOf("a"), noB.modules.keys)
        assertEquals(emptyMap<String, Boolean>(), Modules.set(noB.modules, "a", false, reg).modules)
        // a loop installs both and stops
        assertEquals(setOf("x", "y"), Modules.set(emptyMap(), "x", true, reg).modules.keys)
        // an id the table does not have changes nothing
        val unknown = Modules.set(mapOf("a" to true), "zzz", true, reg)
        assertEquals(mapOf("a" to true), unknown.modules)
        assertTrue(unknown.added.isEmpty() && unknown.blockedBy.isEmpty())
        // a stored false is not carried along as an entry
        assertEquals(mapOf("a" to true), Modules.set(mapOf("b" to false), "a", true, reg).modules)
        assertEquals(listOf("a"), Modules.missingRequires(emptyMap(), "b", reg))
        assertTrue(Modules.missingRequires(mapOf("a" to true), "b", reg).isEmpty())

        // this app's own table: installing and removing each on its own
        for (id in Modules.IDS) {
            val on = Modules.set(emptyMap(), id, true)
            assertTrue(id, Modules.isOn(on.modules, id))
            for (r in Modules.byId(id)?.requires ?: emptyList()) assertTrue("$id brings $r", Modules.isOn(on.modules, r))
            val off = Modules.set(mapOf(id to true), id, false)
            assertFalse(id, Modules.isOn(off.modules, id))
        }
    }

    @Test fun theEditorsFieldsAreFoundByTheirIds() {
        assertEquals(Modules.ECH_OUTBOUND, Modules.fieldModule("echOutbound"))
        for (id in listOf("fragment", "noise", "cipherSuites", "finalMask")) assertEquals(id, Modules.ANTI_DPI, Modules.fieldModule(id))
        for (id in listOf("sni", "ech", "echForceQuery", "address", "engine", "mux")) assertNull(id, Modules.fieldModule(id))
        // the generated table (ServerFieldsTable) has every field the ids name …
        val ids = ServerFields.FIELDS.map { f: SfField -> f.id }.toSet()
        for (id in listOf("echOutbound", "fragment", "noise", "cipherSuites", "finalMask")) assertTrue("$id in the field table", id in ids)
        // … and every field of its anti-DPI and patterniha groups is anti-DPI's
        for (f in ServerFields.FIELDS.filter { f: SfField -> f.group == "dpi" || f.group == "pattn" }) assertEquals(f.id, Modules.ANTI_DPI, Modules.fieldModule(f.id))

        assertTrue(Modules.fieldShown(emptyMap(), "sni"))
        assertFalse(Modules.fieldShown(emptyMap(), "fragment"))
        assertFalse(Modules.fieldShown(emptyMap(), "echOutbound"))
        assertTrue(Modules.fieldShown(mapOf("antiDpi" to true), "fragment"))
        assertFalse(Modules.fieldShown(mapOf("antiDpi" to true), "echOutbound"))
        assertTrue(Modules.fieldShown(mapOf("echOutbound" to true), "echOutbound"))
    }

    @Test fun thePickerKeepsTheSelectedOne() {
        assertEquals(Modules.POOL, Modules.moduleOfSelection(Selection.POOL))
        assertEquals(Modules.ADVANCED_ROUTING, Modules.moduleOfSelection(Selection.ADVANCED))
        assertEquals(Modules.ADVANCED_ROUTING, Modules.moduleOfSelection(Selection.forProfile("rp-x")))
        assertEquals(Modules.CHAINS, Modules.moduleOfSelection("chain:c1"))
        assertEquals(Modules.GROUPS, Modules.moduleOfSelection("grp-ab12"))
        assertNull(Modules.moduleOfSelection("s-123"))
        assertNull(Modules.moduleOfSelection(""))

        // not installed: no row — except the one selected
        assertFalse(Modules.pickerShows(emptyMap(), Modules.CHAINS, "chain:c1", "plain"))
        assertTrue(Modules.pickerShows(emptyMap(), Modules.CHAINS, "chain:c1", "chain:c1"))
        assertTrue(Modules.pickerShows(mapOf("chains" to true), Modules.CHAINS, "chain:c2", "chain:c1"))
        // nothing selected never shows a hidden row
        assertFalse(Modules.pickerShows(emptyMap(), Modules.GROUPS, "", ""))
    }

    @Test fun everyExtensionHasItsWordsInBothLanguages() {
        val keys = ArrayList<String>()
        for (m in Modules.MODULES) { keys.add(m.nameKey); keys.add(m.descKey); keys.add(m.hidesKey) }
        for (c in Modules.CATEGORIES) keys.add("mod.cat.$c")
        keys.addAll(listOf(
            "mod.title", "mod.intro", "mod.moreSub", "mod.settingsLine", "mod.installed", "mod.install", "mod.remove",
            "mod.inUse", "mod.needs", "mod.installedSnack", "mod.alsoInstalled", "mod.removedSnack", "mod.blocked",
            "mod.removeTitle", "mod.removeAsk", "mod.offHint", "mod.importHidden", "mod.warpChain"
        ))
        for (k in keys) {
            assertTrue("English for $k", I18n.en[k]?.isNotBlank() == true)
            assertTrue("Persian for $k", I18n.fa[k]?.isNotBlank() == true)
            assertEquals("placeholders of $k", I18n.placeholders(I18n.en.getValue(k)), I18n.placeholders(I18n.fa.getValue(k)))
        }
        // the Persian is Persian, not the English carried over
        for (m in Modules.MODULES) assertNotEquals(m.descKey, I18n.en.getValue(m.descKey), I18n.fa.getValue(m.descKey))
        assertEquals("Extensions", I18n.word(I18n.EN, "mod.title"))
        assertEquals("افزونه‌ها", I18n.word(I18n.FA, "mod.title"))
    }
}
