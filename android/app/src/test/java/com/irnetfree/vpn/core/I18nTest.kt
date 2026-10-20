package com.irnetfree.vpn.core

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The app's two languages (I18n, I18nWords) and the server editor's Persian (ServerFieldsTable.STRINGS_FA). */
class I18nTest {
    private val fsi = "⁨"
    private val pdi = "⁩"

    @After fun backToTheDefault() { I18n.setLang(I18n.FA) }

    @Test fun everyKeyIsInBothLanguagesOnceWithAWord() {
        assertEquals(0, I18nWords.FA.size % 2)
        assertEquals(0, I18nWords.EN.size % 2)
        assertEquals(emptyList<String>(), I18n.duplicateKeys(I18nWords.FA))
        assertEquals(emptyList<String>(), I18n.duplicateKeys(I18nWords.EN))
        assertEquals(I18n.en.keys, I18n.fa.keys)
        assertTrue(I18n.en.size > 500)
        for ((k, v) in I18n.en) assertTrue("empty English for $k", v.isNotBlank())
        for ((k, v) in I18n.fa) assertTrue("empty Persian for $k", v.isNotBlank())
        for (k in I18n.en.keys) assertTrue("not a dotted key: $k", Regex("[a-z][A-Za-z0-9]*(\\.[A-Za-z0-9_]+)+").matches(k))
    }

    @Test fun persianNamesTheSamePlaceholdersAsEnglish() {
        for ((k, en) in I18n.en) {
            assertEquals("placeholders of $k", I18n.placeholders(en), I18n.placeholders(I18n.fa.getValue(k)))
        }
        // Persian quotes are «», never the English ones
        for ((k, v) in I18n.fa) assertFalse("English quotes in the Persian of $k", v.contains('“') || v.contains('”') || v.contains('"'))
    }

    @Test fun theServerEditorTableHasTheDesktopsPersianForEveryKey() {
        assertEquals(ServerFieldsTable.STRINGS.keys, ServerFieldsTable.STRINGS_FA.keys)
        for ((k, en) in ServerFieldsTable.STRINGS) {
            val fa = ServerFieldsTable.STRINGS_FA.getValue(k)
            assertTrue("empty Persian for $k", fa.isNotBlank())
            assertEquals("placeholders of $k", I18n.placeholders(en), I18n.placeholders(fa))
        }
        // the app's own keys never shadow the table's
        for (k in I18n.en.keys) assertFalse("$k is also the server editor's", ServerFieldsTable.STRINGS.containsKey(k))
        assertEquals("Mux for this server", I18n.word(I18n.EN, "sf.mux"))
        assertEquals(ServerFieldsTable.STRINGS_FA.getValue("sf.mux"), I18n.word(I18n.FA, "sf.mux"))
        assertTrue(I18n.has("sf.mux"))
    }

    @Test fun aKeyNobodyKnowsShowsAsItself() {
        assertEquals("no.such.key", I18n.word(I18n.FA, "no.such.key"))
        assertEquals("no.such.key", I18n.word(I18n.EN, "no.such.key"))
        assertFalse(I18n.has("no.such.key"))
        assertTrue(I18n.has("power.connect"))
    }

    @Test fun theLanguageIsPersianUnlessItIsEnglish() {
        assertEquals("fa", I18n.norm(null))
        assertEquals("fa", I18n.norm(""))
        assertEquals("fa", I18n.norm("de"))
        assertEquals("en", I18n.norm("en"))
        assertEquals("fa", AppSettings().lang)
        I18n.setLang("en")
        assertEquals("en", I18n.lang); assertFalse(I18n.rtl)
        assertEquals("Connect", t("power.connect"))
        I18n.setLang("xx")
        assertEquals("fa", I18n.lang); assertTrue(I18n.rtl)
        assertEquals("اتصال", t("power.connect"))
    }

    @Test fun tfFillsEveryPlaceholder() {
        I18n.setLang("en")
        assertEquals("Deleted Home", tf("srv.deleted", "name" to "Home"))
        assertEquals("Deleted Home — now using ⛓ Work", tf("srv.deletedNow", "name" to "Home", "now" to "⛓ Work"))
        assertEquals("3 of 5 subscriptions failed — their servers are kept", tf("subs.failedN", "failed" to 3, "n" to 5))
        // the same placeholder twice, a null, one the word does not have, one left unfilled
        assertEquals("1 · 1", I18n.fill("{n} · {n}", arrayOf("n" to 1), false))
        assertEquals("a  b", I18n.fill("a {x} b", arrayOf("x" to null), false))
        assertEquals("a b", I18n.fill("a b", arrayOf("x" to 1), false))
        assertEquals("a {y}", I18n.fill("a {y}", arrayOf("x" to 1), false))
        assertEquals(setOf("name", "now"), I18n.placeholders("Deleted {name} — now using {now}"))
    }

    @Test fun inPersianAFilledValueKeepsItsOwnDirection() {
        I18n.setLang("fa")
        // an English name or an address inside a right-to-left sentence: isolated, so it does not reorder it
        assertEquals("${fsi}Home$pdi حذف شد", tf("srv.deleted", "name" to "Home"))
        assertEquals("a ${fsi}1.2.3.4:443$pdi", I18n.fill("a {ip}", arrayOf("ip" to "1.2.3.4:443"), true))
        assertEquals("⁦vless://x⁩", I18n.ltrIn(true, "vless://x"))
        assertEquals("vless://x", I18n.ltrIn(false, "vless://x"))
    }

    @Test fun theFlowArrowPointsTheWayThePageReads() {
        assertEquals("→", I18n.arrow(false))
        assertEquals("←", I18n.arrow(true))
        I18n.setLang("en")
        assertEquals("→", flowArrow())
        assertEquals("a → b → c", I18n.flow(listOf("a", "b", "c")))
        I18n.setLang("fa")
        assertEquals("←", flowArrow())
        // one right-to-left run, each hop's name in its own direction
        assertEquals("⁧${fsi}a$pdi ← ${fsi}b$pdi⁩", I18n.flow(listOf("a", "b")))
        assertEquals("a → b", I18n.flowIn(false, listOf("a", "b")))
        assertEquals("", I18n.flowIn(false, emptyList()))
    }
}
