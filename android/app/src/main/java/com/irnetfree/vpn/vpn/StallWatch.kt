package com.irnetfree.vpn.vpn

/**
 * The stall watchdog's judgement — the pure part of XrayVpnService.watchStall,
 * kept here so the JVM tests reach it.
 *
 * Why it exists: a session can die with no network change at all — the server
 * goes away, the ISP cuts the connection half-way, the core's outbound hangs,
 * hev stops carrying between the TUN and the core — and nothing in the app
 * noticed. The network watcher (NetWatch) acts only on Android's
 * default-network callbacks, the self-check runs once, twelve seconds after
 * the connect, and the stats loop only draws figures. The phone sat at
 * "Connected" carrying nothing until somebody reconnected by hand — and a
 * reconnect by hand onto the same dead server was no better.
 *
 * What it judges by: hev's own TUN counters, the ones the stats loop draws
 * (TProxyGetStats: tx = what the apps sent INTO the TUN, rx = what came back
 * OUT to them), read once a tick — one JNI call, no network, nothing per
 * second. Judged a tick at a time and over the last [WINDOW_TICKS] together:
 *  - a tick with at least [MIN_TX_BYTES] in and a quarter of it back
 *    ([RX_SHARE]), or a window that adds up to that: the tunnel carries — a
 *    page, a download, a call all answer far more than that;
 *  - a tick with that much in and less back, or a window of that much in and
 *    less back: suspect. A dead core still answers every SYN with a SYN-ACK
 *    and a reset (hev's lwip does that by itself), so a little always comes
 *    back from a tunnel whose far end is gone — as from a long upload, whose
 *    ACKs are a few per cent of what goes up. The two are told apart by
 *    asking: [SUSPECT_TICKS] suspect ticks and the tunnel is asked through
 *    its own SOCKS port, twice, as the network watcher asks; an answer keeps
 *    it (and no ask for [PROBE_EVERY_MS], however long the upload), no answer
 *    twice rebuilds it. The window is for light use: a phone trying a few
 *    sites on a dead tunnel sends its ClientHellos in one tick and little in
 *    the next, and judged a tick at a time that was never asked about. The
 *    single tick stays beside it: a busy tunnel that dies has megabytes of
 *    good answers in its window for a minute after;
 *  - NOTHING came back for [DEAD_TICKS] ticks in a row of at least
 *    [MIN_TX_BYTES] in: rebuilt without asking. TCP cannot send for that long
 *    without a byte back, so this is hev no longer writing to the TUN at all
 *    — the core would still answer a probe, which never crosses the TUN.
 * A window with less than [MIN_TX_BYTES] in is quiet, and so is a tick with
 * nothing in at all: the phone is not using the tunnel, there is nothing to
 * judge, and no probe wakes the radio.
 *
 * A rebuild is the network watcher's (a connect onto the live tunnel, as a
 * switch) and shares its budget — at most one a minute
 * between the two — and a stall that comes back after each rebuild waits
 * twice as long each time ([rebuildWait]): a tunnel rebuilt every minute for
 * a stall the rebuild never cures is seconds without a tunnel, every minute.
 */
object StallWatch {
    /** How often the counters are read while connected (not per second: battery; the self-check already covers the first twelve). */
    const val TICK_MS = 15_000L

    /** Less than this into the TUN over the window is a phone not using the tunnel: nothing to judge. */
    const val MIN_TX_BYTES = 8 * 1024L

    /** How many ticks suspicion adds up over. */
    const val WINDOW_TICKS = 4

    /** The tunnel carries when at least 1/RX_SHARE of what went in came back. */
    const val RX_SHARE = 4L

    /** Suspect ticks in a row before the tunnel is asked. */
    const val SUSPECT_TICKS = 2

    /** Ticks in a row with traffic in and nothing at all back before the tunnel is rebuilt unasked. */
    const val DEAD_TICKS = 3

    /** After an ask the tunnel answered, no ask for this long — a long upload is suspect every tick. */
    const val PROBE_EVERY_MS = 60_000L

    /** The two asks: as the network watcher makes them (and NetWatch.probeTimeout, NetWatch.SECOND_PROBE_URL). */
    const val PROBE_GAP_MS = NetWatch.PROBE_GAP_MS

    /** The wait between stall rebuilds doubles with each ([rebuildWait]) up to this. */
    const val REBUILD_MAX_MS = 10 * 60_000L

    /** Doublings counted (2^4 minutes is past [REBUILD_MAX_MS] already). */
    const val BACKOFF_MAX = 4

    /** What one tick's reading comes to. */
    enum class Verdict {
        /** Nothing to judge: no reading, the first reading, the counters reset, or the phone sent next to nothing. */
        QUIET,
        /** Traffic in and enough back: the tunnel carries. */
        FINE,
        /** Traffic in and little back — not for long enough yet, or asked about less than a minute ago. */
        SUSPECT,
        /** Little back for [SUSPECT_TICKS] ticks: ask the tunnel through its SOCKS port. */
        ASK,
        /** Nothing at all back for [DEAD_TICKS] ticks of traffic in: rebuild without asking. */
        DEAD
    }

    /** One session's judge: the counters as last read, and the streaks. Used on one thread (the watchdog's). */
    class Judge {
        private var lastTx = -1L
        private var lastRx = -1L

        /** The last tick's bytes into the TUN and back out, for the log (0 before the first judgement). */
        var inBytes = 0L
            private set
        var outBytes = 0L
            private set

        /** Suspect ticks since the streak began (ended by an ASK, a FINE, or a window with next to nothing in it). */
        var suspect = 0
            private set

        /** Ticks in a row with traffic in and nothing back. */
        var dead = 0
            private set

        /** When an ask last got an answer (elapsed real time; 0 = never). */
        private var answeredAt = 0L

        /** The last [WINDOW_TICKS] ticks' bytes in and back; [slot] is overwritten next. */
        private val txWindow = LongArray(WINDOW_TICKS)
        private val rxWindow = LongArray(WINDOW_TICKS)
        private var slot = 0

        private fun remember(dTx: Long, dRx: Long) {
            txWindow[slot] = dTx; rxWindow[slot] = dRx
            slot = (slot + 1) % WINDOW_TICKS
        }

        private fun forget() { txWindow.fill(0L); rxWindow.fill(0L) }

        /**
         * The counters as read now ([tx] into the TUN, [rx] back out; a negative
         * one = no reading), at [now] (elapsed real time). The first reading is
         * the baseline; a counter that went backwards (hev restarted under the
         * session) is a new baseline too.
         */
        fun tick(tx: Long, rx: Long, now: Long): Verdict {
            if (tx < 0L || rx < 0L) return Verdict.QUIET
            val based = lastTx >= 0L
            val dTx = tx - lastTx
            val dRx = rx - lastRx
            lastTx = tx; lastRx = rx
            if (!based || dTx < 0L || dRx < 0L) { inBytes = 0L; outBytes = 0L; suspect = 0; dead = 0; forget(); return Verdict.QUIET }
            inBytes = dTx; outBytes = dRx
            val busy = dTx >= MIN_TX_BYTES
            // A tick that carried: what the window held before it says nothing about the tunnel now.
            if (busy && dRx * RX_SHARE >= dTx) { forget(); remember(dTx, dRx); suspect = 0; dead = 0; return Verdict.FINE }
            remember(dTx, dRx)
            val sumTx = txWindow.sum()
            val sumRx = rxWindow.sum()
            if (sumTx < MIN_TX_BYTES) { suspect = 0; dead = 0; return Verdict.QUIET }
            // Nothing in at all this tick: never asked about, whatever the window
            // holds — but a dead tunnel's next little bit picks the streak up again.
            if (dTx == 0L) { dead = 0; return Verdict.QUIET }
            if (!busy && sumRx * RX_SHARE >= sumTx) { suspect = 0; dead = 0; return Verdict.FINE }
            suspect++
            dead = if (busy && dRx == 0L) dead + 1 else 0
            if (dead >= DEAD_TICKS) { dead = 0; suspect = 0; return Verdict.DEAD }
            if (suspect >= SUSPECT_TICKS && (answeredAt == 0L || now - answeredAt >= PROBE_EVERY_MS)) { suspect = 0; return Verdict.ASK }
            return Verdict.SUSPECT
        }

        /** The ask got an answer at [now]: no ask for [PROBE_EVERY_MS]. */
        fun answered(now: Long) { answeredAt = now }
    }

    /**
     * How long until a stall rebuild may run (0 = now), given when the tunnel
     * was last rebuilt by either watcher ([lastAt], elapsed real time; 0 =
     * never) and how many stall rebuilds in a row cured nothing ([streak]):
     * a minute, then two, four, eight, ten at most.
     */
    fun rebuildWait(lastAt: Long, streak: Int, now: Long): Long {
        if (lastAt <= 0L || now < lastAt) return 0L
        val every = minOf(NetWatch.REBUILD_EVERY_MS shl streak.coerceIn(0, BACKOFF_MAX), REBUILD_MAX_MS)
        val since = now - lastAt
        return if (since >= every) 0L else every - since
    }

    /** Bytes for the log: "0 B", "12 KB", "3.4 MB". */
    fun size(bytes: Long): String = when {
        bytes < 1024L -> "$bytes B"
        bytes < 1024L * 1024L -> "${bytes / 1024L} KB"
        else -> String.format(java.util.Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0))
    }
}
