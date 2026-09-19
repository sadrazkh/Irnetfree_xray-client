package com.irnetfree.vpn.core

/**
 * "Auto (fastest)": which config the app connects to when the user asks it to
 * choose. Port of the desktop picker's bestServerId (src/renderer/app.js), which
 * is what the ⚡ row in the Windows picker runs.
 *
 * Only the arithmetic lives here — no sockets, no Android — so the rule that
 * decides which server wins can be tested off a device, which is the only way it
 * gets tested at all (see docs: CI is the compile gate, there is no phone in it).
 *
 * The measuring itself is the caller's job, because a phone cannot afford the
 * desktop's version of it: Windows measures a real round trip through every
 * server at once, while here each one costs a throwaway core. So the UI measures
 * the handshake to all of them in parallel and a real round trip through only
 * the few that answered fastest, and hands both numbers to [pick].
 */
object Fastest {
    /** How many of the quickest-to-answer servers are then really tried. */
    const val SHORTLIST = 3

    /**
     * One server's measurements, in milliseconds. `tcp` is the handshake to the
     * server's own address; `real` is an HTTP round trip THROUGH it. Either may
     * be null (never measured) or negative (measured, did not answer).
     */
    data class Measured(val id: String, val tcp: Long? = null, val real: Long? = null)

    /**
     * What a server is ranked by — lower wins, null means it is not a candidate
     * at all because nothing about it ever answered.
     *
     * A REAL round trip beats a handshake however slow it is. A dead exit will
     * still complete a TCP handshake in 40 ms and then carry nothing, and that is
     * precisely the server this feature must not hand somebody. The desktop
     * writes that rule as a band: everything that only managed a handshake is
     * scored 100000 + ms, above every server that actually carried a request.
     */
    fun score(m: Measured): Long? {
        val real = m.real?.takeIf { it >= 0 }
        if (real != null) return real
        val tcp = m.tcp?.takeIf { it >= 0 } ?: return null
        return 100_000 + tcp
    }

    /** The winner, or null when nothing answered. A tie keeps the earlier one. */
    fun pick(all: List<Measured>): Measured? =
        all.mapNotNull { m -> score(m)?.let { m to it } }.minByOrNull { it.second }?.first

    /**
     * The servers worth spending a throwaway core on: the [n] quickest
     * handshakes. Ones that never answered are dropped — a real round trip
     * through a server whose port is closed only buys the same answer slower.
     */
    fun shortlist(all: List<Measured>, n: Int = SHORTLIST): List<Measured> =
        all.filter { (it.tcp ?: -1) >= 0 }.sortedBy { it.tcp }.take(n)
}
