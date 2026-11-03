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
 *     process is marked [stuck]. The teardown then finishes without it — the
 *     TUN closed, Not connected up, the service stopped — so a Disconnect
 *     always ends in a usable screen with nothing of the old session left
 *     that the app still holds.
 *  2. A process marked stuck runs no tunnel again: hev ignores a start while
 *     its flag stands (and the stop that never came back holds its mutex), a
 *     core still closing holds its port; a tunnel brought up here now would
 *     carry nothing. A connect is refused there (XrayVpnService.refuseStuck)
 *     and the process restarts itself — as Android restarts any app in the
 *     background — at a moment nothing is lost ([mayRestartInBackground]: the
 *     service gone, the screen away, the log written out). The next open is a
 *     fresh process with a clean engine.
 *  3. A connect nobody tapped (always-on, the watchdog's rebuild, a sticky
 *     restart), or the second tap on Connect once the refusal has been said,
 *     restarts at once with the service still started: Android's START_STICKY
 *     brings it back in a fresh process and it connects by itself
 *     ([RECONNECT]). A restart that follows the user's Disconnect says [STAY]:
 *     the sticky start that may follow stops quietly.
 *  4. Anything else that holds the worker ([wedged]: a command running for
 *     longer than anything the service does) is caught by the service's own
 *     tick and by the user's Disconnect — said once, with what to do, and the
 *     process restarts when nobody is looking or on the next Disconnect.
 *
 * The rules live here so the JVM tests reach them; the kill itself is the
 * service's (XrayVpnService.restartProcess).
 */
object EngineReset {
    /** hev's stop: it joins a thread that ends within milliseconds — or never (TProxyService). */
    const val HEV_STOP_MS = 8_000L

    /** The in-process core's StopLoop: every handler closed, a WireGuard device among them. */
    const val CORE_STOP_MS = 10_000L

    /** The in-process core's StartLoop: the handlers built, the ports bound, an endpoint resolved at most. */
    const val CORE_START_MS = 45_000L

    /** A worker command still running after this long is wedged — the bounded waits above add up to about a minute at the very worst. */
    const val WEDGE_MS = 120_000L

    /** How often the service looks for a wedged command while it lives. */
    const val WEDGE_TICK_MS = 30_000L

    /** The background restart waits this long after the service's end or the screen's going. */
    const val GRACE_MS = 3_000L

    /** A restart flag older than this is not for the start that finds it: a sticky restart follows the kill within seconds. */
    const val FLAG_FRESH_MS = 60_000L

    /** What the sticky restart after the kill does: connect the stored selection again, or stay off. */
    const val RECONNECT = "reconnect"
    const val STAY = "stay"

    /** Why this process can run no tunnel any more; null = it can. The first reason is kept for the process. */
    @Volatile var stuck: String? = null
        private set

    /** The user has been told once what to do about it: the next tap restarts (onRefused; the wedged Disconnect). */
    @Volatile var said = false

    private val restarting = AtomicBoolean(false)

    fun markStuck(why: String) { if (stuck == null) stuck = why }

    /** Tests only — a process forgets nothing. */
    fun clear() { stuck = null; said = false; restarting.set(false) }

    /** The one restart of this process: true for the caller that gets to make it. */
    fun beginRestart(): Boolean = restarting.compareAndSet(false, true)

    /**
     * Run [block] — a native call that may never return — on a thread of its
     * own and wait at most [timeoutMs]. True when it returned, whatever it
     * did; false when it did not: the process is marked stuck with [what] and
     * the thread is left where it is (a daemon: it never keeps the process
     * alive). An exception inside is the block's own affair — caught, one
     * logcat line — and counts as returned.
     */
    fun bounded(what: String, timeoutMs: Long, block: () -> Unit): Boolean {
        val t = Thread({
            try { block() } catch (e: Throwable) { Log.w(TAG, "$what threw: ${e.message}") }
        }, "irnf-bounded")
        t.isDaemon = true
        t.start()
        try { t.join(timeoutMs) } catch (e: InterruptedException) { Thread.currentThread().interrupt() }
        if (!t.isAlive) return true
        markStuck("$what did not return within ${timeoutMs / 1000} s")
        return false
    }

    /**
     * May the process restart itself now, unasked? Only a stuck one, with the
     * service gone ([serviceAlive] false: nothing of a tunnel is left and no
     * command runs), nothing on its way (a connect still in prepare() is
     * CONNECTING) and nobody looking ([uiVisible] false): a background app
     * Android kills is recreated when it is next opened, as after any reclaim
     * for memory — a visible one simply vanishes from the screen.
     */
    fun mayRestartInBackground(stuck: Boolean, serviceAlive: Boolean, state: ConnState, uiVisible: Boolean): Boolean =
        stuck && !serviceAlive && !uiVisible && (state == ConnState.DISCONNECTED || state == ConnState.ERROR)

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
     * The worker command running now ([command], since [since] in elapsed
     * real time; null = idle) has run longer than [limitMs]: what to say, or
     * null while it is within its time.
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

    private const val TAG = "EngineReset"
}
