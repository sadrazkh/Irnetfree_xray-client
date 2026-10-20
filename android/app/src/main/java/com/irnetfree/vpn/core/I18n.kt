package com.irnetfree.vpn.core

import androidx.compose.runtime.mutableStateOf

/**
 * The app's language — Persian (the default, right to left) or English — and
 * its words: the desktop's i18n.js on Android.
 *
 * Every word on screen is t("power.connect"), or tf("srv.deleted", "name" to
 * s.name) for one with {name} in it. The words are in I18nWords (one table per language, by
 * the same keys); the server editor's field labels are the desktop's own,
 * generated into ServerFieldsTable in both languages. A key Persian lacks
 * falls back to English, and a key nobody knows shows as itself.
 *
 * The language is a Compose state: a screen that read a word is redrawn the
 * moment it changes, so Settings → Language applies at once. Store sets it
 * from AppSettings.lang when it opens and on every save (the VPN service's
 * notification reads it too). The log stays English: it is what the owner
 * sends to the developer.
 *
 * In Persian a filled-in value is wrapped in a first-strong isolate (U+2068 …
 * U+2069), so an address, a port or an English server name keeps its own
 * direction inside a right-to-left sentence instead of reordering it.
 */
object I18n {
    const val FA = "fa"
    const val EN = "en"

    private const val FSI = "⁨"   // first-strong isolate: a value's own direction
    private const val RLI = "⁧"   // right-to-left isolate: a flow read in Persian
    private const val LRI = "⁦"   // left-to-right isolate: an address, a key, a link
    private const val PDI = "⁩"   // the end of an isolate

    /** The language every t() reads ("fa" or "en"). */
    private val current = mutableStateOf(FA)

    /** The words, by key. */
    val fa: Map<String, String> = words(I18nWords.FA)
    val en: Map<String, String> = words(I18nWords.EN)

    val lang: String get() = current.value

    /** Persian reads right to left. */
    val rtl: Boolean get() = current.value == FA

    /** Switch the language (anything but "en" is Persian, the default); a no-op when it is already that one. */
    fun setLang(lang: String?) {
        val n = norm(lang)
        if (current.value != n) current.value = n
    }

    /** AppSettings.lang as a language this app has: "en", else "fa". */
    fun norm(lang: String?): String = if (lang == EN) EN else FA

    /** [key] in [lang]: Persian falls back to English, English to the key itself. */
    fun word(lang: String, key: String): String {
        val persian = if (lang == FA) (fa[key] ?: ServerFieldsTable.STRINGS_FA[key]) else null
        return persian ?: en[key] ?: ServerFieldsTable.STRINGS[key] ?: key
    }

    /** Is [key] a word of the app's (a key built from a code is asked this before t()). */
    fun has(key: String): Boolean = en.containsKey(key) || ServerFieldsTable.STRINGS.containsKey(key)

    /**
     * [template] with each {name} of [pairs] filled in; [isolate] (Persian) wraps
     * every value in a first-strong isolate so its direction is its own.
     */
    fun fill(template: String, pairs: Array<out Pair<String, Any?>>, isolate: Boolean): String {
        var out = template
        for ((name, value) in pairs) {
            val v = value?.toString() ?: ""
            out = out.replace("{$name}", if (isolate) FSI + v + PDI else v)
        }
        return out
    }

    /** The {names} a word fills in. */
    fun placeholders(s: String): Set<String> =
        Regex("\\{([A-Za-z]+)\\}").findAll(s).map { m: MatchResult -> m.groupValues[1] }.toSet()

    /** The arrow of a flow, the way the page reads: → left to right, ← right to left (the desktop's flowArrow). */
    fun arrow(rtl: Boolean): String = if (rtl) "←" else "→"

    /**
     * Hops in reading order, joined by the arrow: "a → b" in English; in Persian
     * "a ← b" as one right-to-left run, each name keeping its own direction.
     */
    fun flowIn(rtl: Boolean, parts: List<String>): String =
        if (!rtl) parts.joinToString(" → ")
        else RLI + parts.joinToString(" ← ") { p: String -> FSI + p + PDI } + PDI

    /** [flowIn] in the app's language. */
    fun flow(parts: List<String>): String = flowIn(rtl, parts)

    /** [s] kept left to right inside a right-to-left line (an address, a key, a link); as it is in English. */
    fun ltrIn(rtl: Boolean, s: String): String = if (rtl) LRI + s + PDI else s

    /** Keys a table lists more than once (I18nTest): key, word, key, word … */
    internal fun duplicateKeys(kv: Array<String>): List<String> {
        val seen = HashSet<String>()
        val out = ArrayList<String>()
        var i = 0
        while (i < kv.size) {
            if (!seen.add(kv[i])) out.add(kv[i])
            i += 2
        }
        return out
    }

    private fun words(kv: Array<String>): Map<String, String> {
        val m = LinkedHashMap<String, String>(kv.size)
        var i = 0
        while (i + 1 < kv.size) {
            m[kv[i]] = kv[i + 1]
            i += 2
        }
        return m
    }
}

/** The word for [key] in the app's language. */
fun t(key: String): String = I18n.word(I18n.lang, key)

/** The word for [key] with its {placeholders} filled from [pairs]: tf("srv.deleted", "name" to s.name). */
fun tf(key: String, vararg pairs: Pair<String, Any?>): String = I18n.fill(t(key), pairs, I18n.rtl)

/** The arrow between the hops of a flow in the app's language: → in English, ← in Persian. */
fun flowArrow(): String = I18n.arrow(I18n.rtl)

/** [s] kept left to right inside the app's sentences (an address, a key, a link). */
fun ltr(s: String): String = I18n.ltrIn(I18n.rtl, s)
