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
 * the few that answered fastest, and hands both numbers to [pick]. A server
 * with no TCP port to time ([udpOnly]) gets a real round trip straight away
 * ([measureUdp]) — a handshake would rule every one of them out.
 */
object Fastest {
    /** How many of the quickest-to-answer servers are then really tried. */
    const val SHORTLIST = 3

    /**
     * When none of the shortlist carried anything, the next handshakes in line
     * are tried as well — up to this many real round trips in all, each of them
     * a throwaway core, before ⚡ gives up and says so.
     */
    const val MAX_TRIES = 6

    /**
     * A UDP-only server ([udpOnly]) has no handshake to time, so its first
     * measurement is already a real round trip through a throwaway core
     * ([measureUdp]) — one core at a time, like every test here. Bounded like
     * the handshake batch: each round trip is given [UDP_TIMEOUT_MS] (the
     * batch's handshake timeout), at most [UDP_MAX] of them are run, and none
     * is started once [UDP_BUDGET_MS] has gone by.
     */
    const val UDP_MAX = 6
    const val UDP_TIMEOUT_MS = 3000
    const val UDP_BUDGET_MS = 15_000L

    /**
     * A server a TCP connect says nothing about (the desktop's latencyTest.js
     * udpOnly): WireGuard and Hysteria2 listen on UDP only — a TCP ping of them
     * fails for every one — and MASQUE over HTTP/3 (QUIC); MASQUE over HTTP/2
     * is TCP like any other. The outbound's protocol wins over the record's
     * (a Hysteria2 server's outbound is "hysteria").
     */
    fun udpOnly(server: ServerConfig): Boolean {
        val ob = server.outbound
        val p = ob.optString("protocol").ifEmpty { server.protocol }.lowercase()
        if (p == Masque.PROTOCOL) return Masque.httpOf(ob.optJSONObject("streamSettings")?.optJSONObject("tlsSettings")) != "h2"
        return p == "wireguard" || p == "hysteria" || p == "hysteria2"
    }

    /**
     * One server's measurements, in milliseconds. `tcp` is the handshake to the
     * server's own address; `real` is an HTTP round trip THROUGH it. Either may
     * be null (never measured) or negative (measured, did not answer).
     */
    data class Measured(val id: String, val tcp: Long? = null, val real: Long? = null)

    /**
     * What a server is ranked by — lower wins, null means it is not a candidate:
     * nothing about it ever answered, or its real round trip was tried and failed.
     *
     * A REAL round trip beats a handshake however slow it is. A dead exit will
     * still complete a TCP handshake in 40 ms and then carry nothing, and that is
     * precisely the server this feature must not hand somebody. The desktop
     * writes that rule as a band: everything that only managed a handshake is
     * scored 100000 + ms, above every server that actually carried a request.
     *
     * And a round trip that was MEASURED as failing disqualifies outright. It
     * used to fall back into the handshake band, so when all three of the
     * shortlist failed, the quickest handshake — one of the three that had just
     * failed — won, and ⚡ connected to a server it had measured as dead.
     */
    fun score(m: Measured): Long? {
        val real = m.real
        if (real != null) return real.takeIf { it >= 0 }
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
        all.filter { (it.tcp ?: -1L) >= 0L }.sortedBy { it.tcp }.take(n)

    /**
     * The real round trips, in handshake order: the [want] quickest handshakes
     * first, as always; if not one of them carried anything, the next ones in
     * line, one at a time, until one does — never more than [maxTries] in all.
     * Returns every server it TRIED, with its `real` filled in (a failure is
     * negative), so [pick] over the result can only ever name a server that
     * really carried a request, and null means none of them did.
     *
     * `real` measures one server; inline, so the caller's measuring may suspend.
     */
    inline fun walk(all: List<Measured>, want: Int = SHORTLIST, maxTries: Int = MAX_TRIES, real: (index: Int, m: Measured) -> Long): List<Measured> {
        val tried = ArrayList<Measured>()
        var carried = 0
        for (m in shortlist(all, Int.MAX_VALUE)) {
            if (tried.size >= maxTries || (tried.size >= want && carried > 0)) break
            val ms = real(tried.size, m)
            tried.add(m.copy(real = ms))
            if (ms >= 0) carried++
        }
        return tried
    }

    /**
     * The UDP-only servers' first stage ([udpOnly]): a real round trip through
     * each of [ids], in the order given — at most [max] of them, and none
     * started once [budgetMs] has gone by since the first ([now], in ms).
     * Returns every server it MEASURED with its `real` filled in (a failure
     * negative), ranked by [pick] beside the TCP servers' round trips; one left
     * unmeasured is not in it, and so is never a candidate.
     *
     * `real` measures one server; inline, so the caller's measuring may suspend.
     */
    inline fun measureUdp(ids: List<String>, max: Int = UDP_MAX, budgetMs: Long = UDP_BUDGET_MS, now: () -> Long, real: (index: Int, id: String) -> Long): List<Measured> {
        val out = ArrayList<Measured>()
        val start = now()
        for (id in ids) {
            if (out.size >= max || now() - start >= budgetMs) break
            val ms = real(out.size, id)
            out.add(Measured(id, real = ms))
        }
        return out
    }
}
