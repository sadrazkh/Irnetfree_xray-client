package com.irnetfree.vpn.vpn

import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The way out of a process whose tunnel engine will not let go — the state
 * that used to take a Force Stop, and only a Force Stop.
 *
 * How it came about: every start and stop of the tunnel runs on the service's
 * one worker thread, one after another (XrayVpnService.onWorker), and the
 * calls there that matter are native and cannot be interrupted. hev's stop
 * joins its thread — and after a start whose init failed it never returns at
 * all (TProxyService: the 2.16.0 stop polls for an event fd that will never
 * exist). The in-process core's StopLoop closes the whole Xray instance in
 * this process and its StartLoop builds one; either can block in Go. A
 * command that never returned froze every command queued behind it: the
 * Disconnect, the Cancel, the next connect. The screen kept saying Connected
 * (or Connecting…), the notification stayed, the TUN stayed open — every app
 * routed into it, nothing carrying — and nothing in the app answered. Force
 * Stop kills the process, which is the only thing that ends a native call.
 *
 * What is done instead:
 *  1. Every such call runs under [bounded]: on a thread of its own, waited for
 *     at most its timeout. One that does not come back is one log line and the
 *     process is marked ([stuck]). The teardown then finishes without it — the
 *     TUN closed, Not connected up, the service stopped — so a Disconnect
 *     always ends in a usable screen with nothing of the old session left
 *     that the app still holds. A call that returns late after all clears its
 *     own mark (a slow stop on a server switch is not a stuck engine), and a
 *     start that returns late has the core nobody references stopped.
 *  2. A process marked stuck runs no tunnel again: hev ignores a start while
 *     its flag stands (and the stop that never came back holds its mutex), a
 *     core still closing holds its port; a tunnel brought up here now would
 *     carry nothing. A connect is refused there (XrayVpnService.refuseStuck)
 *     — after a brief wait for a late stop to clear its mark ([awaitClear]) —
 *     and the process restarts itself — as Android restarts any app in the
 *     background — at a moment nothing is lost ([mayRestartInBackground]: the
 *     service gone, every screen of ours away, the log written out). The next
 *     open is a fresh process with a clean engine.
 *  3. A connect nobody tapped (always-on, the watchdog's rebuild, a sticky
 *     restart), or the second tap on Connect once the refusal has been said,
 *     restarts at once with the service still started: Android's START_STICKY
 *     brings it back in a fresh process and it connects by itself
 *     ([RECONNECT]) — at most [RECONNECT_MAX] times in [RECONNECT_WINDOW_MS]
 *     ([mayReconnect]): a config that hangs the start every time would
 *     otherwise kill and reconnect for ever. A restart that follows the
 *     user's Disconnect says [STAY]: the sticky start that may follow stops quietly.
 *  4. Anything else that holds the worker ([wedged]: a command running for
 *     longer than anything the service does) is caught by the service's own
 *     tick and by the user's Disconnect — said once, with what to do, and the
 *     process restarts when nobody is looking or on the next Disconnect. That
 *     mark stays for the process.
 *
 * The real fix for hev's part is upstream: hev 2.17.0+ exposes TProxyIsRunning
 * and returns a Boolean from start and stop — but its JNI table changes in
 * lockstep with TProxyService.kt and cannot be tried without a device, so the
 * bump is not part of this.
 *
 * The rules live here so the JVM tests reach them; the kill itself is the
 * service's (XrayVpnService.restartProcess).
 */
object EngineReset {
    /** hev's stop: it joins a thread that ends within milliseconds — or never (TProxyService). */
    const val HEV_STOP_MS = 8_000L

    /** The in-process core's StopLoop: every handler closed, a WireGuard device among them. */
    const val CORE_STOP_MS = 10_000L

    /** The in-process core's StartLoop: under ten seconds with the geo files on a healthy phone; thirty leaves an Android 8 phone its time. A slow one is not fatal: a start that returns late is stopped and its mark cleared. */
    const val CORE_START_MS = 30_000L

    /** A stop still finishing late clears its mark the moment it returns: how long a connect waits for that before it refuses (XrayVpnService.startTunnel). */
    const val STUCK_GRACE_MS = 5_000L

    /** A worker command still running after this long is wedged — the bounded waits add up to 48 s at the very worst (hev 8 + core stop 10 + core start 30), plus the first run's asset copy and a subprocess core's probes (~10 s). */
    const val WEDGE_MS = 120_000L

    /** How often the service looks for a wedged command while it lives. */
    const val WEDGE_TICK_MS = 30_000L

    /** The background restart waits this long after the service's end. */
    const val GRACE_MS = 3_000L

    /** …and this long after every screen of ours went away: a share sheet over the app is back within that. */
    const val UI_GONE_GRACE_MS = 15_000L

    /** A restart flag older than this is not for the start that finds it. Android's restart delay grows fourfold per quick death, so a sticky restart can come minutes after the kill. */
    const val FLAG_FRESH_MS = 10 * 60_000L

    /** Self-reconnects ([RECONNECT]) allowed within [RECONNECT_WINDOW_MS]; the one after stays off and says so. */
    const val RECONNECT_MAX = 2
    const val RECONNECT_WINDOW_MS = 10 * 60_000L

    /** What the sticky restart after the kill does: connect the stored selection again, or stay off. */
    const val RECONNECT = "reconnect"
    const val STAY = "stay"

    /** Why this process can run no tunnel any more; null = it can. The first remaining reason (marks). */
    @Volatile var stuck: String? = null
        private set

    /** The user has been told once what to do about it: the next tap restarts (onRefused; the wedged Disconnect). Reset when nothing is stuck any more. */
    @Volatile var said = false

    /**
     * Every screen of ours is hidden (Application.onTrimMemory UI_HIDDEN →
     * XrayVpnService.uiHidden; back with MainActivity.onStart → uiShown) —
     * true until the first screen ever shows. An Activity's own onStop is not
     * this: the QR scanner, a picker or a sheet over the app stop MainActivity
     * while the app is very much in use.
     */
    @Volatile var uiGone = true

    /** The reasons the process is stuck, in the order they came (guarded by itself). */
    private val marks = ArrayList<String>()

    private val restarting = AtomicBoolean(false)

    /** A mark for the rest of the process — the wedged worker: nothing ever clears it. */
    fun markStuck(why: String) { synchronized(marks) { marks.add(why); recompute() } }

    /** A bounded call's own mark, cleared when that call returned after all. */
    private fun unmark(why: String) { synchronized(marks) { marks.remove(why); recompute() } }

    /** Under the lock: the first remaining reason; nothing left — nothing to say again. */
    private fun recompute() {
        stuck = marks.firstOrNull()
        if (marks.isEmpty()) said = false
    }

    /** Tests only — a process forgets nothing. */
    fun clear() { synchronized(marks) { marks.clear(); recompute() }; restarting.set(false); uiGone = true }

    /** The one restart of this process: true for the caller that gets to make it. */
    fun beginRestart(): Boolean = restarting.compareAndSet(false, true)

    /**
     * Run [block] — a native call that may never return — on a thread of its
     * own and wait at most [timeoutMs]. True when it returned, whatever it
     * did; false when it did not: the process is marked stuck with [what]
     * (unless [quiet]: a throwaway test core's call says nothing about the
     * tunnel's — AndroidLibXrayLite's mutex is per controller) and the thread
     * is left where it is (a daemon: it never keeps the process alive). Should
     * it return after all, [onLate] runs on it — a start's orphan core stopped
     * — and the mark it earned is cleared. An exception inside is the block's
     * own affair — caught, one logcat line — and counts as returned.
     */
    fun bounded(what: String, timeoutMs: Long, quiet: Boolean = false, onLate: (() -> Unit)? = null, block: () -> Unit): Boolean {
        val mark = "$what did not return within ${timeoutMs / 1000} s"
        val lock = Any()
        var done = false
        var timedOut = false
        val t = Thread({
            try { block() } catch (e: Throwable) { Log.w(TAG, "$what threw: ${e.message}") }
            val late = synchronized(lock) { done = true; timedOut }
            if (late) {
                Log.w(TAG, "$what returned late")
                try { onLate?.invoke() } catch (e: Throwable) { Log.w(TAG, "$what: the late hand failed: ${e.message}") }
                if (!quiet) unmark(mark)
            }
        }, "irnf-bounded")
        t.isDaemon = true
        t.start()
        try { t.join(timeoutMs) } catch (e: InterruptedException) { Thread.currentThread().interrupt() }
        // Marked under the same lock the thread reads timedOut under: a return
        // in the very moment after the join still sees its mark to clear.
        val expired = synchronized(lock) {
            if (done) false else { timedOut = true; if (!quiet) markStuck(mark); true }
        }
        if (!expired) return true
        Log.w(TAG, mark)
        return false
    }

    /** Wait at most [timeoutMs] for every mark to clear — a stop finishing late — polling; true when nothing is stuck. */
    fun awaitClear(timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (stuck != null) {
            if (System.currentTimeMillis() >= deadline) return false
            try { Thread.sleep(100) } catch (e: InterruptedException) { return false }
        }
        return true
    }

    /**
     * May the process restart itself now, unasked? Only a stuck one, with the
     * service gone ([serviceAlive] false: nothing of a tunnel is left and no
     * command runs), nothing on its way (a connect still in prepare() is
     * CONNECTING) and every screen of ours away ([uiAway]: [uiGone] and
     * MainActivity stopped): a background app Android kills is recreated when
     * it is next opened, as after any reclaim for memory — a visible one simply
     * vanishes from the screen.
     */
    fun mayRestartInBackground(stuck: Boolean, serviceAlive: Boolean, state: ConnState, uiAway: Boolean): Boolean =
        stuck && !serviceAlive && uiAway && (state == ConnState.DISCONNECTED || state == ConnState.ERROR)

    /** What a connect refused for a stuck engine does. */
    enum class Refused { SAY, RESTART }

    /**
     * A connect nobody tapped restarts at once — there is nobody to tell, and
     * the sticky restart connects again. The user's first is told why and
     * what to do ([saidBefore] false); the next restarts.
     */
    fun onRefused(unattended: Boolean, saidBefore: Boolean): Refused =
        if (unattended || saidBefore) Refused.RESTART else Refused.SAY

    /**
     * The worker command running now ([command], since [since]; null = idle)
     * has run longer than [limitMs]: what to say, or null while it is within
     * its time. Uptime, not elapsed real time: the worker's own waits — a
     * join, a socket timeout — stand still while the phone sleeps, and a
     * connect caught by a two-minute sleep is not wedged on waking.
     */
    fun wedged(command: String?, since: Long, now: Long, limitMs: Long = WEDGE_MS): String? {
        if (command == null) return null
        val ran = now - since
        if (ran < limitMs) return null
        return "the tunnel's worker has not finished its \"$command\" command in ${ran / 1000} s"
    }

    /**
     * The flag a restart left for the start that follows it
     * (XrayVpnService.restartProcess): its value and reason, or null when
     * there is none or it is stale ([at] more than [FLAG_FRESH_MS] from
     * [now], either way): a flag no sticky start came for must not turn a
     * crash's restart, weeks later, into a stay.
     */
    fun restartFlag(flag: String?, why: String?, at: Long, now: Long): Pair<String, String>? {
        val f = flag ?: return null
        if (f != RECONNECT && f != STAY) return null
        if (at <= 0L || now - at > FLAG_FRESH_MS || at - now > FLAG_FRESH_MS) return null
        return f to (why ?: "")
    }

    /** The self-reconnects noted so far that still count ([history], epoch ms) with [now] among them: what to store. */
    fun reconnectsNoted(history: List<Long>, now: Long): List<Long> =
        history.filter { t: Long -> t <= now && now - t < RECONNECT_WINDOW_MS } + now

    /** May a restart connect again by itself, given the self-reconnects noted before it? Not once [RECONNECT_MAX] are within the window. */
    fun mayReconnect(history: List<Long>, now: Long): Boolean =
        history.count { t: Long -> t <= now && now - t < RECONNECT_WINDOW_MS } < RECONNECT_MAX

    /** The history as the prefs hold it: epoch ms, comma-separated. */
    fun parseTimes(s: String?): List<Long> = s?.split(",")?.mapNotNull { p: String -> p.trim().toLongOrNull() } ?: emptyList()
    fun joinTimes(times: List<Long>): String = times.joinToString(",")

    private const val TAG = "EngineReset"
}
