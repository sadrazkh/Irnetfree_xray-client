package com.irnetfree.vpn.core

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

    /** Flag (or null) and the name to print beside it. */
    fun split(name: String): Pair<String?, String> {
        val f = flagIn(name) ?: return null to name
        return f to withoutFlag(name, f)
    }
}
