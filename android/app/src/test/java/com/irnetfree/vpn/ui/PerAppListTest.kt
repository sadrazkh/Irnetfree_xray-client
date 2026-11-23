package com.irnetfree.vpn.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.text.Collator
import java.util.Locale

/** Settings → Per-app routing's list (PerAppList). */
class PerAppListTest {
    private fun apps(n: Int): List<Pair<String, String>> = (1..n).map { i -> "pkg.app$i" to "App %04d".format(i) }

    @Test fun lowercaseLabelsAreNotSortedAfterEveryCapital() {
        // a plain String sort put "apple" after "Zebra"
        val sorted = PerAppList.byLabel(listOf("z" to "Zebra", "a" to "apple", "b" to "Banana"), Collator.getInstance(Locale.ENGLISH))
        assertEquals(listOf("a", "b", "z"), sorted.map { it.first })
    }

    @Test fun equalLabelsKeepOneOrder() {
        val sorted = PerAppList.byLabel(listOf("p.two" to "Mail", "p.one" to "mail"), Collator.getInstance(Locale.ENGLISH))
        assertEquals(listOf("p.one", "p.two"), sorted.map { it.first })
    }

    @Test fun pastOnePageTheListSaysHowManyMoreThereAre() {
        val all = apps(PerAppList.PAGE + 40)
        val one = PerAppList.view(all, emptyList(), "", pages = 1, known = true)
        assertEquals(PerAppList.PAGE, one.rest.size)
        assertEquals(40, one.hidden)
        val two = PerAppList.view(all, emptyList(), "", pages = 2, known = true)
        assertEquals(PerAppList.PAGE + 40, two.rest.size)
        assertEquals(0, two.hidden)
    }

    @Test fun aSearchShowsEveryMatch() {
        val all = apps(PerAppList.PAGE * 3)
        val v = PerAppList.view(all, emptyList(), "app", pages = 1, known = true)
        assertEquals(all.size, v.rest.size)
        assertEquals(0, v.hidden)
        assertEquals(listOf("pkg.app7"), PerAppList.view(all, emptyList(), "0007", pages = 1, known = true).rest.map { it.pkg })
    }

    @Test fun tickedAppsComeFirstEvenPastTheFirstPage() {
        val all = apps(PerAppList.PAGE + 40)
        val last = all.last().first
        val v = PerAppList.view(all, listOf(last), "", pages = 1, known = true)
        assertEquals(listOf(last), v.ticked.map { it.pkg })
        assertFalse(v.rest.any { it.pkg == last })
        assertFalse(v.ticked.single().missing)
    }

    @Test fun aTickedAppNoLongerOnThePhoneCanStillBeUnticked() {
        val v = PerAppList.view(apps(3), listOf("gone.app", "pkg.app2"), "", pages = 1, known = true)
        assertEquals(listOf("pkg.app2", "gone.app"), v.ticked.map { it.pkg })
        val gone = v.ticked.last()
        assertTrue(gone.missing)
        assertEquals("gone.app", gone.label)
        // before the phone's list is read, nothing is called missing
        assertFalse(PerAppList.view(emptyList(), listOf("gone.app"), "", pages = 1, known = false).ticked.single().missing)
    }

    @Test fun duplicatesAndBlanksInTheSavedListShowOnce() {
        val v = PerAppList.view(apps(2), listOf("pkg.app1", "pkg.app1", " ", ""), "", pages = 1, known = true)
        assertEquals(listOf("pkg.app1"), v.ticked.map { it.pkg })
        assertEquals(listOf("pkg.app2"), v.rest.map { it.pkg })
    }
}
