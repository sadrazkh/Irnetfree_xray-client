package com.irnetfree.vpn.core

import java.util.concurrent.ConcurrentHashMap

/**
 * How a config is written in the list: its flag, and its name without it.
 *
 * A config record has no country of its own — nothing in a share link carries
 * one. What it does carry, because panels write them there, is a flag emoji in
 * the name: the owner's own subscription hands out `TCP 12 🇩🇪-Sadra|📊1.15TB`
 * and `🇮🇹-CDN1`. The list shows that flag on the left, as the design does, and
 * the name without it — which also stops the flag being counted twice when the
 * row is already showing it.
 */
object ServerLabel {

    /** The first flag: two Regional Indicator code points in a row, or null. */
    fun flagIn(name: String): String? {
        var i = 0
        while (i < name.length) {
            val cp = name.codePointAt(i)
            val w = Character.charCount(cp)
            if (cp in 0x1F1E6..0x1F1FF && i + w < name.length) {
                val next = name.codePointAt(i + w)
                if (next in 0x1F1E6..0x1F1FF) return name.substring(i, i + w + Character.charCount(next))
            }
            i += w
        }
        return null
    }

    /**
     * The name with [flag] taken out, along with the separator that was holding
     * it on — `🇮🇹-CDN1` is "CDN1", not "-CDN1". Only the separators touching the
     * flag are removed, so a name that is genuinely hyphenated keeps its hyphens.
     */
    fun withoutFlag(name: String, flag: String): String {
        val cut = name.replaceFirst(Regex("\\s*[-—·|]?\\s*" + Regex.escape(flag) + "\\s*[-—·|]?\\s*"), " ").trim()
        return cut.ifEmpty { name }
    }

    /** [split]'s answers for flagged names: every row asks on every draw, and [withoutFlag] compiles a Regex each time. */
    private val splitCache = ConcurrentHashMap<String, Pair<String?, String>>()
    private const val SPLIT_CACHE_MAX = 2000

    /** Flag (or null) and the name to print beside it. */
    fun split(name: String): Pair<String?, String> {
        val hit = splitCache[name]
        if (hit != null) return hit
        val f = flagIn(name) ?: return null to name
        val out: Pair<String?, String> = f to withoutFlag(name, f)
        if (splitCache.size >= SPLIT_CACHE_MAX) splitCache.clear()
        splitCache[name] = out
        return out
    }
}
