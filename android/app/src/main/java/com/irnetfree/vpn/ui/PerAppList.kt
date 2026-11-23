package com.irnetfree.vpn.ui

import java.text.Collator

/**
 * The per-app list as Settings → Per-app routing shows it (MainActivity's
 * AppPicker) — pure, so the JVM tests reach it.
 *
 * What it fixes (v1.47.5): the list stopped at 150 apps without a word, sorted
 * by plain string order — every lowercase and every Persian label after all
 * the Latin capitals, so the Iranian banks and messengers people most want to
 * leave out were exactly the ones past the cut. And a ticked app that was no
 * longer on the phone was never listed, so its tick could not be taken off,
 * while Home still counted it.
 */
internal object PerAppList {
    /** How many unticked apps one page shows; "show more" adds another. */
    const val PAGE = 150

    /** One row. [missing]: ticked, but not among the phone's apps (uninstalled, or not visible to this app). */
    data class Row(val pkg: String, val label: String, val missing: Boolean = false)

    /** [ticked]: always shown first; [rest]: the unticked shown; [hidden]: unticked ones that match, past the pages shown. */
    data class View(val ticked: List<Row>, val rest: List<Row>, val hidden: Int)

    /**
     * [apps] (package to label) in the order a person reads them: [collator]'s
     * order for the labels' language, case and accents aside — then by
     * package, so equal labels keep one order.
     */
    fun byLabel(apps: List<Pair<String, String>>, collator: Collator = Collator.getInstance()): List<Pair<String, String>> {
        val c = (collator.clone() as Collator).apply { strength = Collator.SECONDARY }
        return apps.sortedWith { a: Pair<String, String>, b: Pair<String, String> ->
            val r = c.compare(a.second, b.second)
            if (r != 0) r else a.first.compareTo(b.first)
        }
    }

    /**
     * What the list shows. [apps]: the phone's (in byLabel order); [selected]:
     * the ticked packages; [query]: the search box, matched against label and
     * package; [pages]: how many pages of the unticked to show (a search shows
     * every match); [known]: [apps] is the phone's real list — only then is a
     * ticked package that is not in it called missing.
     */
    fun view(apps: List<Pair<String, String>>, selected: List<String>, query: String, pages: Int, known: Boolean): View {
        val labels: Map<String, String> = apps.toMap()
        val order: Map<String, Int> = apps.withIndex().associate { (i, a) -> a.first to i }
        val q = query.trim()
        fun hit(pkg: String, label: String): Boolean = q.isEmpty() || label.contains(q, ignoreCase = true) || pkg.contains(q, ignoreCase = true)
        val chosen = selected.filter { p: String -> p.isNotBlank() }.distinct()
        val ticked = chosen.map { p: String -> Row(p, labels[p] ?: p, missing = known && p !in labels) }
            .filter { r: Row -> hit(r.pkg, r.label) }
            .sortedBy { r: Row -> order[r.pkg] ?: Int.MAX_VALUE }
        val taken = chosen.toSet()
        val rest = apps.filter { (p, l) -> p !in taken && hit(p, l) }.map { (p, l) -> Row(p, l) }
        val limit = if (q.isNotEmpty()) rest.size else minOf(rest.size.toLong(), pages.coerceAtLeast(1).toLong() * PAGE).toInt()
        return View(ticked, rest.take(limit), rest.size - limit)
    }
}
