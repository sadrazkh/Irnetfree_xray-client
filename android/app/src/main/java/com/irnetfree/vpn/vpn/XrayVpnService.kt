package com.irnetfree.vpn.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import com.irnetfree.vpn.core.AppSettings
import com.irnetfree.vpn.core.CertPin
import com.irnetfree.vpn.core.ChainConfig
import com.irnetfree.vpn.core.ConfigBuilder
import com.irnetfree.vpn.core.ConnectionPlan
import com.irnetfree.vpn.core.DnsPlan
import com.irnetfree.vpn.core.EngineChoice
import com.irnetfree.vpn.core.GroupEvict
import com.irnetfree.vpn.core.HelloCut
import com.irnetfree.vpn.core.LanShare
import com.irnetfree.vpn.core.LocalAuth
import com.irnetfree.vpn.core.LocalProxyAuth
import com.irnetfree.vpn.core.Mux
import com.irnetfree.vpn.core.PoolEntry
import com.irnetfree.vpn.core.RoutingProfile
import com.irnetfree.vpn.core.SettingsApply
import com.irnetfree.vpn.core.ServerConfig
import com.irnetfree.vpn.core.TrustedDns
import com.irnetfree.vpn.core.t
import com.irnetfree.vpn.core.tf
import com.irnetfree.vpn.net.Diagnostics
import com.irnetfree.vpn.core.Store
import com.irnetfree.vpn.ui.MainActivity
import hev.htproxy.TProxyService
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File
import java.net.ServerSocket
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.FutureTask
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Whole-device tunnel:
 *   1. A proxy core runs with a local SOCKS inbound and no internal tun. Which
 *      core is EngineChoice's answer: Xray in-process (libv2ray, tunFd=0), or
 *      one of the two bundled binaries as a subprocess — Xray-PattN, which
 *      takes the very same config, or sing-box, which has its own format.
 *   2. VpnService establishes a TUN; our own app package is EXCLUDED from the VPN
 *      so the core's outbound sockets bypass the tunnel (no protect needed).
 *   3. hev-socks5-tunnel reads the TUN fd and forwards all packets to that SOCKS
 *      port — which is also how a subprocess core, with no handle on the TUN fd,
 *      still carries the whole device.
 *
 * Starting and stopping never happen on the main thread (asset copies, a core
 * start of up to seven seconds, joins — an ANR waiting to happen): the service
 * goes foreground at once in onStartCommand, then the work runs on ONE
 * process-wide worker thread, one command after another. A connect carries a
 * generation number, and one that a disconnect or a newer connect overtook
 * while its prepare() ran never starts.
 *
 * Switching (tapping one server, then another; ⚡; reconnect; disconnect then
 * connect) ends on the LAST thing asked for, with one tunnel, on screen and in
 * the notification under that server's name. What holds it:
 *  - every move (connect, disconnect) takes a generation, and the latest move
 *    always ends in a command to this service — its CONNECT, its DISCONNECT,
 *    or, for a connect that failed before it got here, a stop for whatever an
 *    older connect left up (connect → stopOlder);
 *  - Connecting / Connected / an error go on screen only under the generation
 *    lock and only while their move is still the latest (Generation.ifCurrent,
 *    next(show)), so an older start never writes over a newer one's state;
 *  - a stop never reaches a tunnel a newer connect brought up
 *    (Generation.reaches), whatever order it arrives in;
 *  - a connect builds the plan it was asked for, never whatever is selected
 *    by the time its certificate pins are learnt (ConnectionPlan.withRecords);
 *  - a switch never leaves the phone outside the VPN: the old TUN is held,
 *    carrying nothing, until the new one is established (startTunnel).
 *
 * While a session is up, the phone's own network is watched (NetWatcher): a
 * change that left the tunnel dead is rebuilt — a connect like any other. And
 * a session that stops carrying with no network change at all — the server
 * gone, the core's outbound hung, hev wedged — is caught by the stall watchdog
 * (StallWatch, watchStall): asked through its own SOCKS port, then rebuilt the
 * same way, instead of sitting at "Connected" with nothing behind it. A
 * rebuild that fails is tried again on the crash loop's wait (retryRebuild);
 * it never moves the tunnel to a selection or settings nobody connected
 * (rebuildStays).
 *
 * Nothing that runs for a session may end the process: a coroutine or a worker
 * command that throws what nobody expected is one log line (unexpected,
 * onWorker). On Android an uncaught exception on ANY thread kills the process,
 * tunnel and all — and the sticky restart then took it for a crash loop.
 *
 * And nothing may hold the worker for good: the native stops and the
 * in-process core's start are waited for only so long (EngineReset.bounded),
 * a Disconnect always ends with the TUN closed and Not connected up, and a
 * process whose engine did not let go — hev's stop that never returns, a
 * core that will not close — runs no tunnel again: a connect there is
 * refused (refuseStuck) and the process restarts itself (restartProcess),
 * which is what a Force Stop did by hand. EngineReset has the why.
 */
class XrayVpnService : VpnService() {

    // Written on the worker; @Volatile for the stats loop and the checks that
    // look from other threads.
    @Volatile private var tun: ParcelFileDescriptor? = null
    /**
     * The previous session's TUN during a switch: kept open — carrying nothing,
     * hev and its core already stopped — until the new interface is
     * established, so no app goes out around the VPN meanwhile; closed then,
     * or by any teardown. Only ever set inside one startTunnel run.
     */
    @Volatile private var heldTun: ParcelFileDescriptor? = null
    @Volatile private var xray: XrayCore? = null
    @Volatile private var singbox: SingboxCore? = null
    @Volatile private var pattn: XrayPattnCore? = null
    @Volatile private var tunnelRunning = false
    /** What the running tunnel was started with, to restart a subprocess core that died under it. */
    @Volatile private var running: Launch? = null
    /** The credentials this instance handed LocalProxyAuth; released at teardown. */
    @Volatile private var auth: LocalAuth? = null
    private var coreRestartedAt = 0L
    /**
     * The session's own checks run here — the stats loop, the self-check, the
     * group watch, the stall watchdog, the network watcher's asks. One that
     * throws what nothing expected is one log line (unexpected), never the end
     * of the process: without the handler a coroutine's exception goes to its
     * thread's own, and on Android that kills the process, tunnel and all.
     */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + CoroutineExceptionHandler { _, e -> unexpected("a session check", e) })
    private var statsJob: Job? = null
    /** The running session's self-check; cancelled with it, so a verdict never lands on the next one. */
    private var checkJob: Job? = null
    /** The running session's group watch (watchGroups) — only while its config runs a group; cancelled with it. */
    private var groupJob: Job? = null
    /** The running session's stall watchdog (watchStall); cancelled with it. */
    private var stallJob: Job? = null
    /**
     * Stall rebuilds in a row that cured nothing (rebuildForStall): each waits
     * longer than the last (StallWatch.rebuildWait); the first tick that carries
     * both ways resets it. Written on the main thread, read by the watchdog.
     */
    @Volatile private var stallRebuilds = 0
    /** What went into the TUN in the watchdog's last tick (StallWatch.Judge.inBytes): how long an ask may take (NetWatch.probeTimeout). */
    @Volatile private var tickIn = 0L
    /**
     * Held from a change of network until it has been dealt with: the settle
     * and the asks run on a Handler's uptime and a socket's timeouts, and with
     * the screen off the phone sleeps through them — a tunnel left dead by a
     * move was then found only when something else woke the phone. Not
     * reference counted, and it lets go by itself after NetWatch.WAKE_MS.
     */
    private val netWake: PowerManager.WakeLock? by lazy<PowerManager.WakeLock?> {
        try {
            (getSystemService(Context.POWER_SERVICE) as PowerManager).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "irnetfree:network").apply { setReferenceCounted(false) }
        } catch (e: Throwable) {
            Log.w(TAG, "no wake lock: ${e.message}")
            null
        }
    }
    private val main = Handler(Looper.getMainLooper())
    /** The newest start id: a teardown for an older command must not stop what a newer one started. */
    @Volatile private var lastStartId = 0
    /**
     * The newest start id Android delivered, [lastStartId] or an always-on
     * start left alone after it (AlwaysOnStart): that one owns nothing, so it
     * is not what a session's end is measured against — but stopSelf() stops
     * nothing with an id older than the newest delivered (finish).
     */
    @Volatile private var newestStartId = 0
    /** The running session's network watcher (NetWatcher); null = none. */
    @Volatile private var netWatcher: NetWatcher? = null
    /** When the network watcher last rebuilt the tunnel (elapsed real time, 0 = never): at most once a minute. Main thread. */
    private var netRebuiltAt = 0L
    /** A crash loop's delayed reconnect, or a failed rebuild's next try (main thread only); dropped with the service. */
    private var pendingAutoStart: Runnable? = null
    /** The rebuild under way, until its tunnel is up: a failure of its generation is tried again instead of ending the service (fail). Set on the main thread. */
    @Volatile private var rebuilding: Rebuild? = null
    /** What the notification says now: a CONNECT that was overtaken before it arrived posts this again, not its own server. */
    @Volatile private var shown = Shown("IRNetFree", false, null)

    /**
     * [gen]: the connect this session came from — a newer one, or a disconnect, overtakes it. [startId]: its start command.
     * [lan]: the LAN share its config opens (null = none), for VpnState.lanShared.
     * [muxTested]: the fingerprints of the servers auto mode put mux on by their verdict (Mux.Pick.onDrop) —
     * marked for a recheck when this session drops (markMuxRecheck), so the next connect that may test, tests
     * them again; their ok is kept meanwhile.
     * [metricsPort] / [groups]: a config that runs a group — where its core's health check is read, and who
     * each `T~gm<i>` is (GroupEvict); 0 / empty: no group, nothing watched.
     * [intent]: the start it came from, whole — what a rebuild replays when the stored selection is no longer this session (rebuildStays).
     */
    private class Launch(
        val engine: String, val config: String, val socksPort: Int, val gen: Long, val startId: Int, val lan: LanShare?,
        val muxTested: List<String> = emptyList(), val metricsPort: Int = 0, val groups: List<GroupEvict.Group> = emptyList(),
        val intent: Intent
    ) {
        /** Its mux verdicts have been marked: one drop, one log line. */
        val muxMarked = AtomicBoolean(false)
    }

    /**
     * A rebuild of a session that was really running — the network watcher's,
     * the stall watchdog's, a group reload — from the move [gen] until it is
     * up (rebuildSession). [session]: that session's Launch.intent;
     * [selection]: what it was asked for (null: not known, replayed).
     * [why]: for the log. [streak]: attempts that failed so far (StickyRestart).
     */
    private class Rebuild(val gen: Long, val why: String, val groupReload: Boolean, val session: Intent, val selection: String?) {
        var streak = 0
    }

    private class Shown(val text: String, val connected: Boolean, val action: String?)

    /** A connect move: its generation, and the selection (Store.selection) it connects (the companion's [asked]). */
    private class Asked(val gen: Long, val selection: String)

    override fun onCreate() {
        super.onCreate()
        alive = true
        main.postDelayed(wedgeWatch, EngineReset.WEDGE_TICK_MS)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        newestStartId = startId
        // The process before this one ended itself for a fresh engine
        // (restartProcess) and left what the sticky restart should do: stay
        // off, or connect again (below). Taken on every start, so a flag no
        // sticky start came for is gone by the next.
        val engineFlag: Pair<String, String>? = takeEngineRestartFlag()
        if (intent == null && engineFlag != null && engineFlag.first == EngineReset.STAY) {
            VpnState.addLog("Android started the service again after IRNetFree reset its engine (${engineFlag.second}) — staying disconnected, as asked")
            stopSelf(startId)
            return START_NOT_STICKY
        }
        // Always-on VPN asking again while this is already up — or on its way
        // up — for the very selection it would connect (AlwaysOnStart): left
        // alone. Rebuilding it was seconds of a tunnel torn down and built
        // again for nothing, and a connect still being prepared started over.
        // This start owns nothing, so it does not become lastStartId either:
        // the session's own end still stops the service (finish).
        if ((intent == null || intent.action == VpnService.SERVICE_INTERFACE) && servesStoredSelection()) {
            val s = shown
            goForeground(s.text, s.action, s.connected)   // what is up, again: a start may oblige a startForeground()
            val what = if (VpnState.state.value == ConnState.CONNECTED) "connected" else "connecting"
            VpnState.addLog("Always-on VPN asked to connect — already $what to ${VpnState.label.value}; left as it is")
            return START_STICKY
        }
        lastStartId = startId
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                // The worker has not finished a command in all the time the
                // service ever takes (EngineReset.wedged): this stop would
                // queue behind it for good, as every command did. Said once —
                // the log, the notification, Home's health line (sayWedged) —
                // and the next Disconnect restarts the process, which stays
                // off: Android then has no service to bring back (NOT_STICKY),
                // and a start of ours that still follows finds STAY.
                val wedged = EngineReset.wedged(workerCommand, workerSince, SystemClock.uptimeMillis())
                if (wedged != null) {
                    EngineReset.markStuck(wedged)
                    if (EngineReset.said) { restartProcess(this, EngineReset.STAY, wedged); return START_NOT_STICKY }
                    sayWedged(wedged)
                } else if (live()) {
                    // Said at once where it was asked: a stop queued behind a start
                    // still running can take its time, and a notification that kept
                    // saying Connected meanwhile looked like a button that did nothing.
                    goForeground(t("state.disconnecting"))
                }
                // disconnect() moved the generation on when it was asked
                // (EXTRA_GEN). Moving it again whenever this command arrives
                // cancelled a connect asked for AFTER the disconnect: a Connect
                // tapped a moment later (Reconnect used to be exactly that, 0.6 s
                // on), and a busy main thread can deliver this later than that.
                // The notification's Disconnect (and its Cancel while
                // connecting) carries no generation and moves it here. A
                // connect that failed before it reached the
                // service sends this too, with ITS generation (stopOlder).
                val gen = if (intent.hasExtra(EXTRA_GEN)) intent.getLongExtra(EXTRA_GEN, 0L) else generation.stop()
                onWorker("disconnect") { stopFor(gen, startId) }
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                val gen = if (intent.hasExtra(EXTRA_GEN)) intent.getLongExtra(EXTRA_GEN, 0L) else generation.next()
                // startForegroundService() obliges a startForeground() here either
                // way. A connect overtaken before it even arrived posts what is up
                // again instead of naming its own server over the one carrying
                // the traffic (its start below is dropped).
                val s = shown
                if (gen == generation.get()) goForeground(intent.getStringExtra(EXTRA_LABEL) ?: "IRNetFree", action = "Cancel")
                else goForeground(s.text, s.action, s.connected)
                onWorker("connect") { startTunnel(intent, gen, startId, unattended = false) }
            }
            // Always-on VPN / "Block connections without VPN" (the system starts
            // us with android.net.VpnService, at boot too), or a START_STICKY
            // restart after the process was killed (no intent at all). Nobody
            // tapped Connect and nobody may be looking: the stored selection is
            // connected exactly as the button would, and a failure says so in a
            // notification — with lockdown on, silence here is a phone with no
            // internet and no reason given.
            null, VpnService.SERVICE_INTERFACE -> {
                val gen = generation.next()
                // After restartProcess(RECONNECT) — the engine was stuck and the
                // process ended itself for a fresh one — the tunnel the user had
                // comes back here; no crash-loop wait for it, this was no crash.
                val reset: String? = if (intent == null) engineFlag?.second else null
                val why = when {
                    reset != null -> "IRNetFree restarted its engine — $reset"
                    intent == null -> "restarted after the app was stopped"
                    else -> "always-on VPN"
                }
                // A START_STICKY restart is this service's own reconnect after the
                // tunnel went down with the process: it never runs a mux test
                // (Mux.choose recovery). Always-on starts — at boot too — may.
                val recovery = intent == null
                val wait = if (intent == null && reset == null) stickyRestartWait() else 0L
                if (wait <= 0L) {
                    goForeground("IRNetFree")
                    autoStart(gen, startId, why, recovery)
                } else {
                    // A crash loop (StickyRestart): try again later, and say when
                    // — on screen and in the notification, whose Stop ends it. A
                    // connect or a disconnect meanwhile moves the generation on
                    // and this attempt is dropped.
                    val msg = "IRNetFree stopped unexpectedly again — it reconnects by itself in ${wait / 1000} s"
                    goForeground(tf("notif.restartIn", "s" to wait / 1000), action = "Stop")
                    VpnState.set(ConnState.ERROR, error = msg)
                    afterWait(gen, wait) { autoStart(gen, startId, why, recovery) }
                }
            }
        }
        return START_STICKY
    }

    /**
     * Run [attempt] once [wait] has passed, while the move [gen] is still the
     * latest: a connect or a disconnect meanwhile drops it. Counted in elapsed
     * real time, deep sleep included, and looked at every few seconds
     * (StickyRestart.tick): a postDelayed of the whole wait runs on uptime,
     * which stops while the phone sleeps, so the wait stretched with every
     * minute asleep. Main thread.
     */
    private fun afterWait(gen: Long, wait: Long, attempt: () -> Unit) {
        val due = SystemClock.elapsedRealtime() + wait
        pendingRestart = true
        val r = object : Runnable {
            override fun run() {
                if (gen != generation.get()) { pendingRestart = false; return }
                val next = StickyRestart.tick(due, SystemClock.elapsedRealtime())
                if (next > 0L) { main.postDelayed(this, next); return }
                pendingRestart = false
                goForeground("IRNetFree")      // the countdown and its Stop are over
                attempt()
            }
        }
        pendingAutoStart = r
        main.postDelayed(r, StickyRestart.tick(due, SystemClock.elapsedRealtime()))
    }

    /**
     * How long this START_STICKY restart waits before it connects
     * (StickyRestart: at once, or 30 s, 60 s, 120 s in a crash loop — never a
     * stop, which under lockdown left the phone with no internet until
     * somebody opened the app). Stored with commit(): the next crash can come
     * before an apply() reaches the disk, and a loop nobody counted never
     * backs off.
     */
    private fun stickyRestartWait(): Long {
        val p = getSharedPreferences("irnf-service", Context.MODE_PRIVATE)
        val n = StickyRestart.next(p.getLong("stickyRestartAt", 0L), p.getInt("stickyStreak", 0), System.currentTimeMillis())
        p.edit().putLong("stickyRestartAt", n.attemptAt).putInt("stickyStreak", n.streak).commit()
        return n.waitMs
    }

    /**
     * The flag restartProcess() wrote for the start after its kill
     * (EngineReset.restartFlag), taken once; null when there is none, or it is
     * stale. The same prefs, on the main thread, as stickyRestartWait reads.
     */
    private fun takeEngineRestartFlag(): Pair<String, String>? {
        val p = getSharedPreferences("irnf-service", Context.MODE_PRIVATE)
        val flag = p.getString(KEY_ENGINE_RESTART, null) ?: return null
        val why = p.getString(KEY_ENGINE_WHY, null)
        val at = p.getLong(KEY_ENGINE_AT, 0L)
        p.edit().remove(KEY_ENGINE_RESTART).remove(KEY_ENGINE_WHY).remove(KEY_ENGINE_AT).commit()
        return EngineReset.restartFlag(flag, why, at, System.currentTimeMillis())
    }

    /**
     * Every EngineReset.WEDGE_TICK_MS while this instance lives: a worker
     * command that has run for longer than anything the service does is
     * wedged — a native call that never came back past every bounded wait, or
     * one nothing bounds (wedgedUnasked). Main thread; let go in onDestroy.
     */
    private val wedgeWatch = object : Runnable {
        override fun run() {
            val w = EngineReset.wedged(workerCommand, workerSince, SystemClock.uptimeMillis())
            if (w != null) wedgedUnasked(w)
            main.postDelayed(this, EngineReset.WEDGE_TICK_MS)
        }
    }

    /**
     * The worker is wedged and nobody has asked for anything (the tick): the
     * process restarts itself as soon as every screen of ours is away —
     * connecting again by itself, unless the latest move was a disconnect,
     * which it then honours (STAY) — and says what to do while one is on it.
     * Main thread.
     */
    private fun wedgedUnasked(w: String) {
        EngineReset.markStuck(w)
        if (uiAway()) {
            restartProcess(this, if (generation.stopLatest) EngineReset.STAY else EngineReset.RECONNECT, w)
            return
        }
        sayWedged(w)
    }

    /**
     * Once: the worker is wedged and the next Disconnect restarts the process
     * — in the log, on Home's health line (the ring's verdict) and in the
     * notification, whose Disconnect is that next tap. Main thread.
     */
    private fun sayWedged(w: String) {
        if (EngineReset.said) return
        EngineReset.said = true
        VpnState.addLog("⚠ $w — tap Disconnect again and IRNetFree restarts its engine (the app closes; open it again)")
        VpnState.setHealth(false, t("engine.tapAgain"))
        val s = shown
        goForeground(t("engine.tapAgain"), action = "Disconnect", connected = s.connected)
    }

    /**
     * Is the latest move a connect of the stored selection that is up, or on
     * its way up (AlwaysOnStart)? Main thread — where the store's selection is
     * written. The store is asked only when such a connect exists, so it is
     * already open then: nothing is read from disk here.
     */
    private fun servesStoredSelection(): Boolean {
        val a = asked ?: return false
        if (a.gen != generation.get()) return false
        val stored = runCatching { Store.get(this).selection }.getOrNull()
        return AlwaysOnStart.leaveAlone(VpnState.state.value, live(), askedIsLatest = true, asked = a.selection, stored = stored)
    }

    /**
     * The stored selection, through the same prepare() as the Connect button — off the main thread.
     * [recovery]: a reconnect of the service's own (a START_STICKY restart, the network watcher's
     * rebuild, a group reload) — no mux test. [groupReload]: the reload a group's set-aside asked
     * for (watchGroups).
     */
    private fun autoStart(gen: Long, startId: Int, why: String, recovery: Boolean, groupReload: Boolean = false) {
        Thread {
            val intent = try {
                // The process's one Store, the screens' own (Store.get): a second
                // instance saved its copy of the lists (prepare's pins end in
                // saveServers) over whatever the UI had saved since, and the UI
                // never saw the pins. Its lists are read on the main thread,
                // where the screens write them.
                val store = Store.get(this@XrayVpnService)
                val (plan, label, sel) = onMain { Triple(store.buildPlan(), store.selectionLabel(), store.selection) }   // throws when nothing usable is selected
                asked = Asked(gen, sel)
                // Overtaken already — a disconnect, or a connect: no "Connecting…"
                // that nothing would clear (checked and set under one lock, Generation).
                if (!generation.ifCurrent(gen) { VpnState.set(ConnState.CONNECTING, label) }) { onWorker("connect") { finishIfIdle(startId) }; return@Thread }
                VpnState.addLog("Connecting by itself ($why): $label")
                prepare(this@XrayVpnService, store, plan, label, wanted = { gen == generation.get() }, recovery = recovery, groupReload = groupReload)
            } catch (e: Throwable) {
                Log.e(TAG, "auto start failed", e)
                val msg = "Could not connect by itself ($why): ${e.message ?: "nothing to connect to"}"
                onWorker("connect") { fail(gen, startId, msg, notify = true) }
                return@Thread
            }
            onWorker("connect") { startTunnel(intent, gen, startId, unattended = true) }
        }.also { it.isDaemon = true; it.name = "irnf-autostart" }.start()
    }

    /** Runs on the worker. [unattended]: nobody tapped Connect, so a failure is also a notification. */
    private fun startTunnel(intent: Intent, gen: Long, startId: Int, unattended: Boolean) {
        // Overtaken while prepare() ran: a disconnect, or a newer connect.
        if (gen != generation.get()) { VpnState.addLog("Connect superseded — not started"); finishIfIdle(startId); return }
        // Everything from here ends in fail() when it goes wrong — the expected
        // failures and any exception at all, reading the extras and taking the
        // session before down included (they ran outside the try once: a throw
        // there left "Connecting…" up for good, and ended the process besides).
        var awake = false
        try {
            val config0 = intent.getStringExtra(EXTRA_CONFIG) ?: return fail(gen, startId, "empty config", unattended)
            val socksPort = intent.getIntExtra(EXTRA_SOCKS, 30808)
            val dns = intent.getStringArrayListExtra(EXTRA_DNS) ?: arrayListOf("1.1.1.1", "8.8.8.8")
            val label = intent.getStringExtra(EXTRA_LABEL) ?: "IRNetFree"
            val ipv6 = intent.getBooleanExtra(EXTRA_IPV6, false)
            val perAppMode = intent.getStringExtra(EXTRA_PERAPP_MODE) ?: "off"
            val perApps = intent.getStringArrayListExtra(EXTRA_PERAPPS) ?: arrayListOf()
            val engine = intent.getStringExtra(EXTRA_ENGINE) ?: "xray"
            val user = intent.getStringExtra(EXTRA_SOCKS_USER)
            val pass = intent.getStringExtra(EXTRA_SOCKS_PASS)
            val sessionAuth = if (!user.isNullOrEmpty() && !pass.isNullOrEmpty()) LocalAuth(user, pass) else null
            val lan0: LanShare? = intent.getStringExtra(EXTRA_LAN)?.let { j -> runCatching { LanShare.fromJson(JSONObject(j)) }.getOrNull() }
            val muxTested: List<String> = intent.getStringArrayListExtra(EXTRA_MUX)?.toList() ?: emptyList()
            val metricsPort = intent.getIntExtra(EXTRA_METRICS, 0)
            val groups: List<GroupEvict.Group> = GroupEvict.mapFromJson(intent.getStringExtra(EXTRA_GROUPS))
            val groupReload = intent.getBooleanExtra(EXTRA_GROUP_RELOAD, false)

            // A connect onto a live service: the old core and hev go first.
            // Otherwise the new core cannot bind the port, hev ignores a second
            // start and keeps the dead session, and the screen says Connected.
            // The old TUN does NOT go yet: closed here, every app went out directly
            // over the ISP for the seconds the new core took to start — a switch,
            // a ⚡, a Reconnect each leaked. It is held open (carrying nothing, hev
            // is stopped) until the new interface is established below, which
            // Android hands over in place (VpnService.Builder.establish: the old
            // interface is deactivated as the new one is created); closed then.
            // Every way out before that closes it with the rest (teardown), so
            // nothing is left half up — the very same end as before.
            teardown(keepTun = true)
            // The teardown let the network watcher's wake lock go; a rebuild
            // nobody may be looking at holds it until the tunnel is up or has failed.
            if (rebuilding?.gen == gen) { awake = true; keepAwake() }
            coreRestartedAt = 0L
            cancelErrorNotification()
            // An engine this process can run no more (EngineReset.stuck — a stop
            // that never came back, this teardown's or an earlier one): a tunnel
            // started here would carry nothing. A stop merely slow — a server
            // switch's hev or core taking a moment longer than its wait — clears
            // its mark the moment it returns: waited for, briefly, before the
            // refusal; then refused, and the process restarts itself.
            if (EngineReset.stuck != null) EngineReset.awaitClear(EngineReset.STUCK_GRACE_MS)
            EngineReset.stuck?.let { why: String -> return refuseStuck(gen, startId, why, unattended) }

            // "Connecting…" only while this connect is still the latest move, checked
            // and written under one lock: overtaken between the check above and here,
            // it wrote its own server's name over the newer connect's. (The held TUN
            // goes too: the command that overtook it starts from nothing, as before.)
            if (!generation.ifCurrent(gen) { VpnState.set(ConnState.CONNECTING, label) }) {
                VpnState.addLog("Connect superseded — not started"); teardown(); finishIfIdle(startId); return
            }
            VpnState.addLog("Connecting: $label")

            if (!TProxyService.available) return fail(gen, startId, "Tunnel core (libhev-socks5-tunnel.so) missing.", unattended)
            // The app's own clients through this tunnel (the self-check, the
            // latency and exit checks, a subscription fetch) present these.
            if (sessionAuth != null) { LocalProxyAuth.set(socksPort, sessionAuth); auth = sessionAuth }

            // LAN sharing binds its two ports on every interface, and one that
            // another app already holds takes the WHOLE core down ("address in
            // use") — a connect that fails over a convenience. Asked here, after
            // the old session let go of them, both at once and without waiting
            // (LocalPort.takenNow — this is the worker every Cancel queues on):
            // taken, this connection goes without sharing and says why.
            val taken: List<Int> = if (lan0 == null) emptyList()
                else LocalPort.takenNow(listOf(lan0.socksPort, lan0.httpPort), LocalPort.ANY)
            val lan: LanShare? = if (taken.isEmpty()) lan0 else null
            val config: String = if (taken.isEmpty()) config0 else TunnelSetup.withoutLan(config0)
            if (taken.isNotEmpty()) VpnState.addLog("⚠ LAN sharing skipped: port ${taken.joinToString(" and ")} is in use by another app — connecting without it; choose other ports under Settings → LAN sharing")

            // 1) Proxy core with a local SOCKS inbound (no internal tun).
            //    EngineChoice already decided which, and prepare() already checked
            //    it is bundled for this ABI; anything else here is a real failure.
            val first = Launch(engine, config, socksPort, gen, startId, lan, muxTested, metricsPort, groups, intent)
            val firstErr = startCore(first)
            val launch: Launch
            if (firstErr != null && lan != null && gen == generation.get() && EngineReset.stuck == null) {
                // The check above is check-then-bind: another app can still take
                // a LAN port before the core binds it, and a core that cannot bind
                // one does not start at all. Sharing is a convenience, the tunnel
                // is not — once more at once, without it (a failed start leaves
                // nothing running to stop first). Not after a start that never
                // came back (stuck): that one holds the port.
                val held = LocalPort.takenNow(listOf(lan.socksPort, lan.httpPort), LocalPort.ANY, graceMs = 0L)
                val why = if (held.isNotEmpty()) "port ${held.joinToString(" and ")} is in use by another app" else "the core would not start with it ($firstErr)"
                VpnState.addLog("⚠ LAN sharing skipped: $why — connecting without it; choose other ports under Settings → LAN sharing")
                launch = Launch(engine, TunnelSetup.withoutLan(config), socksPort, gen, startId, null, muxTested, metricsPort, groups, intent)
                startCore(launch)?.let { err: String -> return failOrStuck(gen, startId, err, unattended) }
            } else {
                launch = first
                if (firstErr != null) return failOrStuck(gen, startId, firstErr, unattended)
            }
            if (gen != generation.get()) { VpnState.addLog("Connect cancelled while the core started"); teardown(); finishIfIdle(startId); return }

            // 2) TUN — exclude our own app so xray's sockets bypass the tunnel
            val builder = Builder()
                .setSession(label)
                .setMtu(TUN_MTU)
                .addAddress(TUN_ADDR4, 30)
                .addRoute("0.0.0.0", 0)
            if (ipv6) { builder.addAddress(TUN_ADDR6, 126); builder.addRoute("::", 0) }
            // Managed DNS: the resolver handed to the OS is the tunnel PEER — an
            // address inside the TUN's own route and not the device's, so every
            // query enters the TUN, reaches the SOCKS inbound and is answered by
            // dns-out (DnsPlan). The address itself no longer matters; with the
            // plan off it is the user's own public resolvers, through the tunnel.
            dns.forEach { runCatching { builder.addDnsServer(it) } }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
            applyPerApp(builder, perAppMode, perApps)

            // null: the VPN permission was revoked, or another app holds it —
            // and the core just started must not be left running (fail tears
            // it down, the held TUN of the session before with it).
            val fd = builder.establish() ?: return fail(gen, startId, "Android refused the VPN interface — VPN permission missing, or another VPN app holds it", unattended)
            tun = fd
            VpnState.addLog("TUN up (fd=${fd.fd}) · resolver ${dns.joinToString(", ")}")
            // The routes are on the new interface now; the old one, which
            // Android has just deactivated, is closed — before hev starts on the new.
            val old = heldTun
            if (old != null) {
                heldTun = null
                runCatching { old.close() }
                VpnState.addLog("Switched in place: the previous TUN is closed — no app went around the VPN meanwhile")
            }
            // "Block connections without VPN" leaves an app per-app routing keeps
            // out of the tunnel with no internet at all — it never goes direct.
            var lockdown = false
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) lockdown = try { isLockdownEnabled } catch (e: Throwable) { false }
            VpnState.setLockdown(lockdown)
            if (lockdown && perAppMode != "off")
                VpnState.addLog("⚠ Android's “Block connections without VPN” is on: the apps per-app routing leaves out of the VPN have no internet at all instead of going direct — turn it off under Android Settings → VPN → IRNetFree (⚙) to let them go direct.")

            // 3) hev tun2socks: TUN fd -> local SOCKS, with the session's credentials
            val cfgPath = writeTun2socksConfig(socksPort, ipv6, sessionAuth)
            TProxyService.TProxyStartService(cfgPath, fd.fd)   // JNI runs on its own thread
            tunnelRunning = true
            tunnelUp = true
            running = launch
            VpnState.addLog("tun2socks started")

            // Up. "Connected" goes on screen only while this connect is still the
            // latest move: overtaken after the check above (a tap on another
            // server, a disconnect), it put its own server up as Connected over
            // the newer one's Connecting — or over the error of a newer connect
            // that failed. The tunnel stays up meanwhile: the command queued
            // behind this one replaces it or stops it (see the class comment).
            if (!generation.ifCurrent(gen) { VpnState.set(ConnState.CONNECTED, label); VpnState.setLanShared(launch.lan) }) {
                VpnState.addLog("Up, but a disconnect or another connect has been asked for since — that comes next")
                return
            }
            VpnState.addLog("Connected")
            if (rebuilding?.gen == gen) rebuilding = null   // up: a later failure is not this rebuild's to retry
            if (groupReload) VpnState.addLog("Groups: the core reloaded with the members that answer")
            updateNotification(label, true)
            launch.lan?.let { l: LanShare -> logLan(l) }
            startStatsLoop()
            selfCheck(launch)
            watchNetwork(launch)
            watchStall(launch)
            watchGroups(launch)
            Log.i(TAG, "tunnel up: $label")
        } catch (e: Throwable) {
            Log.e(TAG, "startTunnel failed", e)
            fail(gen, startId, e.message ?: "connect failed", unattended)
        } finally {
            if (awake) letSleep()
        }
    }

    /**
     * A connect onto a process whose engine is stuck (EngineReset.stuck): hev
     * ignores a start while its old flag stands — and the stop that never came
     * back holds its mutex — a core still closing holds its port; a tunnel
     * brought up here now would carry nothing. So nothing is started: the
     * session before is down (teardown), and the process restarts itself.
     * Nobody tapped this one (always-on, a rebuild, a sticky restart), or the
     * refusal has been said already: at once, the service left started, so
     * Android's START_STICKY brings it back in a fresh process and it connects
     * by itself (EngineReset.RECONNECT). The user's first tap is told why and
     * what to do — ERROR on screen, through fail, and a notification when no
     * screen of ours shows (the tile) — and the restart then waits for the
     * screens to go (scheduleEngineRestart). Overtaken meanwhile — a Cancel
     * during the start that hung, a tap on another server — nothing of that:
     * the command queued behind this one is the user's last word, and a
     * RECONNECT here would have reversed their Disconnect. A newer connect is
     * refused on its own turn; a disconnect ends in stopAll, and the
     * background restart follows the service's end. Runs on the worker.
     */
    private fun refuseStuck(gen: Long, startId: Int, why: String, unattended: Boolean) {
        teardown()
        if (gen != generation.get()) {
            VpnState.addLog("Not connecting: $why — a disconnect or another connect has been asked for since; that comes next")
            finishIfIdle(startId)
            return
        }
        when (EngineReset.onRefused(unattended, EngineReset.said)) {
            EngineReset.Refused.RESTART -> {
                VpnState.addLog("Not connecting: $why — IRNetFree restarts its engine now and connects again by itself")
                restartProcess(this, EngineReset.RECONNECT, why)
            }
            EngineReset.Refused.SAY -> {
                EngineReset.said = true
                fail(gen, startId, tf("engine.stuck", "why" to why), notify = !VpnState.uiVisible.value)
            }
        }
    }

    /**
     * fail() — unless the start left the engine stuck (EngineReset): then the
     * refusal's way out. A start that returns late after all clears its mark
     * (its orphan stopped): waited for, briefly, so that a slow start ends in
     * a plain error the next tap gets past, not a refusal.
     */
    private fun failOrStuck(gen: Long, startId: Int, error: String, unattended: Boolean) {
        if (EngineReset.stuck != null) EngineReset.awaitClear(EngineReset.STUCK_GRACE_MS)
        val why = EngineReset.stuck
        if (why != null) refuseStuck(gen, startId, why, unattended) else fail(gen, startId, error, unattended)
    }

    /**
     * A muxed session that broke — its core exited by itself, it carried
     * nothing, or it stalled: the ok verdicts that put mux on it are kept and
     * marked for a recheck (Mux.markRecheck) — the user's next connect tests
     * them again; a reconnect of the service's own uses them as they are. Only
     * auto's (Launch.muxTested), once per session. Prefs only — any thread.
     */
    private fun markMuxRecheck(l: Launch, why: String) {
        if (l.muxTested.isEmpty() || l.muxMarked.getAndSet(true)) return
        runCatching { Store.get(this).markMuxRecheck(l.muxTested) }
            .onFailure { e -> Log.w(TAG, "could not mark the mux verdicts: ${e.message}") }
        VpnState.addLog("Mux: $why while muxed — mux stays on; the server is tested again on your next connect")
    }

    /** Where the other devices point their proxy settings — never the password (logs get shared). */
    private fun logLan(lan: LanShare) {
        val ips = LanAddresses.current().map { a -> a.ip }
        val at = if (ips.isEmpty()) "no Wi-Fi or hotspot address yet" else ips.joinToString(", ")
        VpnState.addLog("LAN sharing on: SOCKS5 port ${lan.socksPort}, HTTP port ${lan.httpPort} at $at" +
            if (lan.auth) " — username and password required (Settings → LAN sharing)" else " — open to anyone on this network")
    }

    /**
     * Start the plan's core with its local SOCKS inbound. Null when it runs,
     * else what went wrong, for the user. A subprocess core that dies later is
     * handed to onCoreExit.
     */
    private fun startCore(l: Launch): String? {
        when (l.engine) {
            EngineChoice.SINGBOX -> {
                if (!SingboxCore.available(this)) return "sing-box core is not bundled for this device."
                val sb = SingboxCore()
                if (!sb.start(this, l.config, l.socksPort, onLog = { s -> VpnState.addLog(s) }, onExit = { code -> onCoreExit(sb, code) }))
                    return "sing-box core failed to start — see logs (More → Logs)."
                singbox = sb
                VpnState.addLog("✓ Running on sing-box core (socks=${l.socksPort})")
            }
            EngineChoice.PATTN -> {
                if (!XrayPattnCore.available(this)) return "Xray-PattN is not bundled for this device."
                // Same geo files as the in-process core, in the same place —
                // the subprocess is pointed at them with XRAY_LOCATION_ASSET.
                XrayCore.prepareAssets(this) { s -> VpnState.addLog(s) }
                val pn = XrayPattnCore()
                if (!pn.start(this, l.config, l.socksPort, onLog = { s -> VpnState.addLog(s) }, onExit = { code -> onCoreExit(pn, code) }))
                    return "Xray-PattN failed to start — see logs (More → Logs)."
                pattn = pn
                VpnState.addLog("✓ Running on Xray-PattN core (socks=${l.socksPort})")
            }
            else -> {
                if (!XrayCore.available) return "Xray core (libv2ray) is not bundled."
                // The geo files the routing rules and the in-country resolver need,
                // handed to the core before it starts (see XrayCore.prepareAssets).
                XrayCore.prepareAssets(this) { s -> VpnState.addLog(s) }
                val x = XrayCore(onStatus = { _, s -> if (!s.isNullOrBlank()) VpnState.addLog(s) })
                // StartLoop builds and starts the whole instance in this process,
                // waited for only so long (EngineReset.bounded): one that never
                // came back held the worker — "Connecting…" and its Cancel — for
                // good. One that comes back late is a core nobody references,
                // bound to the SOCKS port: stopped there and then (onLate).
                val started = AtomicBoolean(false)
                if (!EngineReset.bounded("the Xray core's start", EngineReset.CORE_START_MS, onLate = { runCatching { x.stop() } }) { started.set(x.start(l.config, 0)) })
                    return "The Xray core did not start within ${EngineReset.CORE_START_MS / 1000} s"
                if (!started.get()) { runCatching { x.stop() }; return "Xray core failed to start — see logs (More → Logs)." }
                xray = x
                // startLoop() returning true only means the core booted; confirm it
                // is really listening. NEVER abort on this — it is a diagnostic, and
                // a probe that is wrong (as it was) must not take the tunnel down.
                if (waitForPort(l.socksPort)) VpnState.addLog("✓ Running on Xray core (socks=${l.socksPort} ready)")
                else VpnState.addLog("⚠ Xray is up but SOCKS ${l.socksPort} didn't answer the probe — continuing anyway.")
            }
        }
        return null
    }

    /**
     * A subprocess core exited on its own under a live tunnel. It is restarted
     * once, on the same port with the same config: the TUN and hev stay up
     * meanwhile, so nothing leaves the phone outside the tunnel. A second death
     * within a minute ends the session with the error on screen and in a
     * notification — never a silent "Connected" that carries nothing.
     *
     * Not when a disconnect or a newer connect has been asked for since the
     * session started (its generation moved on): that command is queued behind
     * this one, and a restart — up to ten seconds — would only hold it up, for
     * a core it stops anyway. The session goes at once instead (dropOvertaken).
     */
    private fun onCoreExit(core: Any, code: Int) {
        onWorker("core restart") {
            if (core !== singbox && core !== pattn) return@onWorker     // stopped or replaced meanwhile
            val l = running ?: return@onWorker
            val name = if (core === singbox) "sing-box" else "Xray-PattN"
            if (core === singbox) { singbox = null } else { pattn = null }
            VpnState.addLog("⚠ The $name core exited by itself (code $code)")
            markMuxRecheck(l, "the connection dropped")
            if (l.gen != generation.get()) { dropOvertaken(l, "Not restarting it — a disconnect or a new connect is next"); return@onWorker }
            val now = SystemClock.elapsedRealtime()
            if (coreRestartedAt != 0L && now - coreRestartedAt < 60_000) {
                fail(l.gen, lastStartId, "The $name core stopped again (exit code $code) — reconnect, or see More → Logs", notify = true)
                return@onWorker
            }
            coreRestartedAt = now
            VpnState.addLog("Restarting the $name core — the tunnel stays up meanwhile")
            val err = startCore(l)
            // Overtaken while it restarted: a core that came back carries the
            // tunnel until the command queued behind this replaces it; one that
            // did not leaves nothing worth keeping up.
            if (l.gen != generation.get()) {
                if (err != null) dropOvertaken(l, "The $name core did not come back — $err")
                return@onWorker
            }
            if (err == null) VpnState.addLog("✓ The $name core is back")
            else fail(l.gen, lastStartId, "The $name core stopped (exit code $code) and did not come back — $err", notify = true)
        }
    }

    /**
     * A session a disconnect or a newer connect has overtaken, whose core is
     * dead: the tunnel goes now. Left up over the dead core, a newer connect
     * that then failed in prepare() (it never reaches the service) kept a TUN
     * that let nothing through under "Not connected" — and live() stayed true.
     * The service stops by this session's own start id, so a start command
     * that has arrived since keeps it (stopSelf(id) ignores an older id).
     * Runs on the worker.
     */
    private fun dropOvertaken(l: Launch, why: String) {
        VpnState.addLog("$why — the tunnel is down until then")
        teardown()
        finishIfIdle(l.startId)
    }

    private fun applyPerApp(b: Builder, mode: String, apps: List<String>) {
        val rules = TunnelSetup.perApp(mode, apps, packageName)
        var allowed = 0
        for (p in rules.allowed) if (runCatching { b.addAllowedApplication(p) }.isSuccess) allowed++
        if (rules.allowed.isNotEmpty() && allowed == 0) {
            // Every app on the list is gone: the whole device then — never us.
            VpnState.addLog("⚠ None of the apps under “Only these apps” is installed — the whole device goes through the VPN")
            runCatching { b.addDisallowedApplication(packageName) }
            return
        }
        for (p in rules.disallowed) runCatching { b.addDisallowedApplication(p) }
    }

    private fun writeTun2socksConfig(socksPort: Int, ipv6: Boolean, auth: LocalAuth?): String {
        val yaml = TunnelSetup.tun2socksYaml(socksPort, auth, TUN_MTU, TUN_ADDR4, if (ipv6) TUN_ADDR6 else null)
        val f = File(filesDir, "tun2socks.yml"); f.writeText(yaml); return f.absolutePath
    }

    /**
     * Block until 127.0.0.1:port accepts a connection (or we give up).
     *
     * The probe MUST run off the main thread: startTunnel() used to be called
     * from onStartCommand(), and Android throws NetworkOnMainThreadException for
     * any socket there — even to loopback — so probing inline always "failed"
     * and made a perfectly healthy core look dead. (It runs on the worker now;
     * the probe keeps its own thread all the same.)
     */
    private fun waitForPort(port: Int, timeoutMs: Long = 5000): Boolean {
        val ok = java.util.concurrent.atomic.AtomicBoolean(false)
        val t = Thread {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                try {
                    java.net.Socket().use { it.connect(java.net.InetSocketAddress("127.0.0.1", port), 300) }
                    ok.set(true); return@Thread
                } catch (e: Exception) {
                    try { Thread.sleep(150) } catch (i: InterruptedException) { return@Thread }
                }
            }
        }
        t.start()
        runCatching { t.join(timeoutMs + 1500) }
        return ok.get()
    }

    /**
     * After connecting, say IN THE LOG where a failure actually is — this app is
     * excluded from its own VPN, so it can't test the tunnel directly, but it can
     * split the problem: reach the internet THROUGH the core's SOCKS port, then
     * report whether the tunnel is carrying any packets at all.
     *   core fails      -> the config/server is at fault
     *   core OK, tx = 0 -> nothing is entering the TUN (VPN/route/per-app problem)
     *   core OK, tx > 0 but rx = 0 -> packets enter but nothing comes back
     *
     * About [l] only: switched meanwhile (the check takes seconds, then waits
     * twelve), its verdict — "Server unreachable" from the core being stopped
     * under it — landed on the server switched to.
     */
    private fun selfCheck(l: Launch) {
        val socksPort = l.socksPort
        checkJob?.cancel()
        checkJob = scope.launch {
            val ms = Diagnostics.httpLatency(socksPort)
            if (running !== l) return@launch
            if (ms < 0) {
                VpnState.addLog("✗ Self-check: the core could NOT reach the internet — the server/config is the problem (not the tunnel).")
                VpnState.setHealth(false, t("health.unreachable"))
                markMuxRecheck(l, "the connection carried nothing")
                return@launch
            }
            val ip = runCatching { Diagnostics.ipInfo(socksPort) }.getOrNull()
            if (running !== l) return@launch
            val where = ip?.takeIf { it.ok }?.let { " · exit ${it.ip} ${it.country}" } ?: ""
            VpnState.addLog("✓ Self-check: core reaches the internet (${ms}ms)$where")
            VpnState.setHealth(true, t("health.working") + "${if (where.isBlank()) "" else " ·"} ${ip?.takeIf { it.ok }?.let { "${it.country} ${it.ip}" } ?: "${ms}ms"}")
            delay(12_000)
            if (!tunnelRunning || running !== l) return@launch
            val st = runCatching { TProxyService.TProxyGetStats() }.getOrNull()
            val tx = if (st != null && st.size >= 4) st[1] else -1
            val rx = if (st != null && st.size >= 4) st[3] else -1
            when {
                tx < 0 -> VpnState.addLog("? Tunnel stats unavailable (tun2socks may not be running).")
                tx == 0L -> { VpnState.addLog("✗ Tunnel: no packets entered the TUN in 12s — other apps aren't being routed into the VPN."); VpnState.setHealth(false, t("health.noApps")) }
                rx == 0L -> { VpnState.addLog("✗ Tunnel: sent $tx B but received 0 — packets enter the TUN but nothing returns."); VpnState.setHealth(false, t("health.stalled")); markMuxRecheck(l, "the connection stalled") }
                else -> VpnState.addLog("✓ Tunnel carrying traffic (↑$tx B ↓$rx B).")
            }
        }
    }

    private fun startStatsLoop() {
        statsJob?.cancel()
        statsJob = scope.launch {
            var lastTx = 0L; var lastRx = 0L; var lastAt = 0L
            while (isActive && tunnelRunning) {
                // The figures are only drawn: with the app off screen nothing is
                // read at all — no wake-up every second — until it is seen again
                // (VpnState.uiVisible); the totals then catch up in one read.
                if (!VpnState.uiVisible.value) { VpnState.uiVisible.first { v: Boolean -> v }; lastAt = 0L; continue }
                val st = runCatching { TProxyService.TProxyGetStats() }.getOrNull()
                if (st != null && st.size >= 4) {
                    val tx = st[1]; val rx = st[3]   // [tx_pkts, tx_bytes, rx_pkts, rx_bytes]
                    val now = SystemClock.elapsedRealtime()
                    // per second of the time that really passed (the first read after a pause has none)
                    val ms = if (lastAt == 0L) 0L else (now - lastAt).coerceAtLeast(1L)
                    val txSpeed = if (ms == 0L) 0L else (tx - lastTx).coerceAtLeast(0L) * 1000L / ms
                    val rxSpeed = if (ms == 0L) 0L else (rx - lastRx).coerceAtLeast(0L) * 1000L / ms
                    lastTx = tx; lastRx = rx; lastAt = now
                    VpnState.setTraffic(Traffic(tx, rx, txSpeed, rxSpeed))
                }
                delay(1000)
            }
        }
    }

    /**
     * A group's member that stays dead, set aside (GroupEvict; the desktop's
     * main.js groupEvictTick). While this session's config runs a group — and
     * only then (battery: one loopback read every GroupEvict.TICK_MS, nothing
     * per second, screen on or off) — the core's own health check is read from
     * its metrics listener and fed to the evictor. The set-aside members whose
     * test is due are asked through a throwaway core, one at a time and at most
     * GroupEvict.TESTS_PER_TICK a tick, and only when no test of the screens
     * holds the one test core (XrayTester.coreLock). A reload the evictor wants
     * is a connect of the stored selection onto this live tunnel (a switch,
     * without a gap), without a mux test, the set-aside members left out by
     * prepare(). Nothing happens while a connect or a disconnect is on its way
     * (the generation); no reload while a setting waits for Apply or another
     * selection was made since — said once. Runs on IO; cancelled with the session.
     */
    private fun watchGroups(l: Launch) {
        groupJob?.cancel(); groupJob = null
        if (l.metricsPort <= 0 || l.groups.isEmpty()) return
        VpnState.addLog("Groups: the core's health check is read every ${GroupEvict.TICK_MS / 1000} s — a member that stays dead ${GroupEvict.EVICT_AFTER_MS / 1000} s while another answers is set aside and tested by the app")
        groupJob = scope.launch {
            var waitSaid = false
            var unread = 0
            while (isActive && running === l) {
                delay(GroupEvict.TICK_MS)
                if (!groupQuiet(l)) continue
                val vars = GroupEvict.readVars(l.metricsPort)
                if (vars == null) {
                    unread++
                    if (unread == 3) VpnState.addLog("⚠ Groups: the core's health check could not be read (127.0.0.1:${l.metricsPort}) — a member that stops answering is left to the core's own check")
                    continue
                }
                unread = 0
                if (!groupQuiet(l)) continue
                for (x in groupEvict.update(GroupEvict.liveOf(l.groups, GroupEvict.healthOf(vars)))) logGroup(x)
                var tested = 0
                for (d in groupEvict.due()) {
                    if (tested >= GroupEvict.TESTS_PER_TICK || !groupQuiet(l)) break
                    // the one test core is busy (a test or ⚡ on screen): the next tick
                    if (!XrayTester.coreLock.tryLock()) break
                    val ms: Long = try { XrayTester.realDelay(this@XrayVpnService, d.record) } finally { XrayTester.coreLock.unlock() }
                    tested++
                    for (x in groupEvict.tested(d.key, ms >= 0, if (ms >= 0) ms else null)) logGroup(x)
                }
                if (!groupQuiet(l)) continue
                // The desktop takes these out of (and back into) its running core
                // without a restart (groupLive.js, `xray api rmo|ado`); the phone's
                // in-process core has no such way in, so each is a reload here.
                groupEvict.takeChanges()
                if (!groupEvict.wantsReload()) continue
                // a change waiting for Apply would go live with the reload, as would another selection
                val wait = groupReloadWait(l)
                if (wait != null) {
                    if (!waitSaid) { waitSaid = true; VpnState.addLog(wait) }
                    continue
                }
                waitSaid = false
                if (!groupEvict.takeReload()) continue
                main.post { reloadForGroups(l) }
            }
        }
    }

    /** This session is the one up, and no connect or disconnect has been asked for since. Any thread. */
    private fun groupQuiet(l: Launch): Boolean = running === l && tunnelRunning && l.gen == generation.get()

    /** One of the evictor's lines, a warning marked as every warning here. */
    private fun logGroup(x: GroupEvict.Line) { VpnState.addLog(if (x.level == "warn") "⚠ ${x.line}" else x.line) }

    /**
     * Why a group reload has to wait (said once), or null: it may go now. It
     * is a connect of the stored selection, so it waits while that is no
     * longer this session's (another was picked since), and while a setting
     * waits for Apply (SettingsApply) — the reload would apply it unasked.
     * Blocking: the store is read on the main thread. Never on the main thread.
     */
    private fun groupReloadWait(l: Launch): String? = try {
        onMain {
            val store = Store.get(this@XrayVpnService)
            val a = asked
            when {
                a == null || a.gen != l.gen || a.selection != store.selection ->
                    "Groups: a member to set aside or bring back waits — another selection was made since this connection; connect it (or reconnect) and the core reloads"
                pendingApply(store).isNotEmpty() ->
                    "Groups: a member to set aside or bring back waits for your pending settings — apply them (or reconnect) and the core reloads"
                else -> null
            }
        }
    } catch (e: Throwable) {
        "Groups: a member to set aside or bring back waits — ${e.message ?: "the selection could not be read"}"
    }

    /** The settings the running tunnel does not carry yet (SettingsApply, the screens' "not applied" bar). Main thread. */
    private fun pendingApply(store: Store): List<String> {
        val applied = VpnState.applied.value
        return SettingsApply.pending(applied, store.settings, applied?.profile?.let { p: RoutingProfile -> store.profileById(p.id) }, store.muxMode) { id: String ->
            store.chainById(id)?.let { c: ChainConfig -> SettingsApply.ChainNow(c.name, store.chainMembers(c).map { m: ServerConfig -> m.id }) }
        }
    }

    /**
     * The reload the evictor took: the stored selection connected onto this
     * live tunnel — a switch, so no app goes around the VPN meanwhile — with
     * the set-aside members left out (prepare) and no mux test. Overtaken by a
     * connect or a disconnect before it got here: asked for again (that
     * connect starts the evictor afresh anyway). Main thread.
     */
    private fun reloadForGroups(l: Launch) {
        if (!groupQuiet(l)) { groupEvict.reloadFailed(); return }
        rebuildSession(l, "Groups: a member was set aside or answers again — the core reloads with the members that answer", groupReload = true)
    }

    /**
     * The session [l] rebuilt by the service itself — a move like any connect,
     * so a Disconnect or a tap meanwhile overtakes it. A session that was
     * really running: when an attempt fails it is tried again (retryRebuild)
     * instead of leaving the phone off the VPN until somebody opens the app.
     * Main thread.
     */
    private fun rebuildSession(l: Launch, why: String, groupReload: Boolean = false) {
        val gen = generation.next()
        val r = Rebuild(gen, why, groupReload, Intent(l.intent).apply { removeExtra(EXTRA_GROUP_RELOAD) }, asked?.takeIf { a: Asked -> a.gen == l.gen }?.selection)
        rebuilding = r
        attemptRebuild(r, lastStartId)
    }

    /**
     * One attempt at the rebuild [r]: the stored selection through prepare()
     * — a panel changes a server's address on every fetch, so the fresh record
     * is what connects — or, when that is not the session the rebuild is of,
     * the session's own Intent again (rebuildStays). Asked again on every
     * attempt: a row tapped during a retry's wait counts too. Main thread.
     */
    private fun attemptRebuild(r: Rebuild, startId: Int) {
        val stays = rebuildStays(r)
        if (stays == null) {
            autoStart(r.gen, startId, r.why, recovery = true, groupReload = r.groupReload)
            return
        }
        asked = Asked(r.gen, r.selection ?: "")
        VpnState.addLog("Connecting by itself (${r.why}): the running connection again — $stays")
        onWorker("connect") { startTunnel(r.session, r.gen, startId, unattended = true) }
    }

    /**
     * Why the rebuild [r] must not connect the stored selection, or null: it
     * may. Tapping a row only saves a selection, and a changed setting waits
     * for Apply: connected to A and looking at B, a change of network must not
     * move the tunnel to B or apply what nobody applied. Main thread.
     */
    private fun rebuildStays(r: Rebuild): String? = try {
        val store = Store.get(this)
        when {
            r.selection == null || r.selection != store.selection -> "another selection was made since it was connected; connect that one to move to it"
            pendingApply(store).isNotEmpty() -> "settings are waiting for Apply, and a rebuild does not apply them"
            else -> null
        }
    } catch (e: Throwable) {
        "the selection could not be read (${e.message ?: e.javaClass.simpleName})"
    }

    /**
     * Watch the phone's own network under the session [l] now Connected
     * (NetWatch has the why): Android's default-network callback, delivered on
     * the main thread — nothing is polled. Let go with the session (teardown).
     * Runs on the worker.
     */
    private fun watchNetwork(l: Launch) {
        unwatchNetwork()
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val w = NetWatcher(l)
        // What the phone is on right now, so that a network coming only after
        // this is a change too. A VPN here is not the phone's own network
        // (this app is outside its own tunnel, so it should never be): then
        // the first network the callback names is the baseline instead.
        try {
            val n: Network? = cm.activeNetwork
            val vpn = n != null && cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            if (!vpn) { w.track.begin(n?.toString()); w.current = n }
        } catch (e: Exception) {
            Log.w(TAG, "active network unknown: ${e.message}")
        }
        netWatcher = w
        try {
            cm.registerDefaultNetworkCallback(w, main)
        } catch (e: Throwable) {
            netWatcher = null
            VpnState.addLog("⚠ Network changes cannot be watched on this phone (${e.message ?: e.javaClass.simpleName}) — after a switch between Wi-Fi and mobile data, reconnect by hand if nothing loads")
        }
    }

    /** Stay awake (netWake), for NetWatch.WAKE_MS from now at most. A wake lock that fails is never worth the tunnel. Any thread. */
    private fun keepAwake() {
        try {
            netWake?.acquire(NetWatch.WAKE_MS)
        } catch (e: Throwable) {
            Log.w(TAG, "wake lock: ${e.message}")
        }
    }

    /** May sleep again. Any thread. */
    private fun letSleep() {
        val w: PowerManager.WakeLock = netWake ?: return
        try {
            if (w.isHeld) w.release()
        } catch (e: Throwable) {
            Log.w(TAG, "wake lock: ${e.message}")
        }
    }

    /** The network watcher let go: unregistered, and nothing it scheduled runs any more. Any thread. */
    private fun unwatchNetwork() {
        val w = netWatcher ?: return
        netWatcher = null
        w.stop()
        runCatching { (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).unregisterNetworkCallback(w) }
    }

    /**
     * The phone's default network under one session [l]. A change — another
     * network, the network gone, its transport changed — waits for the network
     * to hold still (NetWatch.SETTLE_MS from the last change), then the tunnel
     * is asked through its own SOCKS port, with the session's credentials
     * (LocalProxyAuth), twice NetWatch.PROBE_GAP_MS apart; only when neither
     * answered is it rebuilt — a connect onto the live tunnel, which the switch
     * makes without a gap (rebuildSession) — at most once a minute.
     * As the router judges (wanWatch.js): a tunnel that survived the change is
     * never rebuilt for it. The one change rebuilt without asking: off a
     * network still there but without internet (lostItsInternet). Every step
     * is one log line.
     *
     * Its state lives on the main thread, where the callbacks arrive; one that
     * arrives after the watcher was let go, or once a newer connect or a
     * disconnect has been asked for (the session is going anyway), does nothing.
     */
    private inner class NetWatcher(private val l: Launch) : ConnectivityManager.NetworkCallback() {
        val track = NetWatch.Tracker()
        /** The default network now, a handle Android can be asked about (track keeps only its id). */
        var current: Network? = null
        /** What the default network last moved off, until that change has settled (onSettled). */
        private var movedOff: Network? = null
        /** A change is waiting out its settle (one log line per wait, however many events). */
        private var settling = false
        /** The two asks in flight — dropped when the network moves again: they were about the one left behind. */
        @Volatile private var asking: Job? = null
        private val settle = Runnable { onSettled() }
        private val askAgain = Runnable {
            if (mine()) {
                VpnState.addLog("Network: a minute since the last rebuild — asking the tunnel again")
                keepAwake()
                ask()
            }
        }

        private fun mine(): Boolean = netWatcher === this && running === l && l.gen == generation.get()

        /** This change has been dealt with: the phone may sleep — unless another is already waiting out its settle, or this watcher was let go (stop, and the lock may be a rebuild's by now). Main thread. */
        private fun dealtWith() { if (netWatcher === this && !settling) letSleep() }

        override fun onAvailable(network: Network) {
            if (!mine()) return
            val before: Network? = current
            current = network
            if (track.available(network.toString())) { movedOff = before; changed("the phone switched networks") }
        }

        override fun onLost(network: Network) {
            if (mine() && track.lost(network.toString())) { current = null; changed("the phone's network went away") }
        }

        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
            if (!mine() || networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
            val was = track.transports
            if (track.capabilities(network.toString(), transportsOf(networkCapabilities)))
                changed("the phone's network moved from ${NetWatch.label(was)} to ${NetWatch.label(track.transports)}")
        }

        private fun changed(what: String) {
            keepAwake()
            main.removeCallbacks(settle); main.removeCallbacks(askAgain)
            asking?.cancel(); asking = null
            if (!settling) VpnState.addLog("Network: $what — the tunnel is checked once it settles")
            settling = true
            main.postDelayed(settle, NetWatch.SETTLE_MS)
        }

        /**
         * [left] is still there but no longer has internet (Wi-Fi associated, its
         * internet gone). An answer through the tunnel would prove only that NEW
         * connections work: every one the tunnel held went into that network and
         * hangs there. A network that still has internet — mobile data lingering
         * a moment after Wi-Fi joins, the commonest move — says nothing of the
         * kind, and one that has gone (no capabilities) took its sockets with it.
         */
        private fun lostItsInternet(left: Network?): Boolean {
            if (left == null) return false
            return try {
                val caps: NetworkCapabilities? = (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).getNetworkCapabilities(left)
                caps != null && !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            } catch (e: Throwable) {
                false
            }
        }

        private fun onSettled() {
            settling = false
            val left: Network? = movedOff
            movedOff = null
            if (!mine()) { dealtWith(); return }
            when (track.settle()) {
                NetWatch.Settled.NOTHING -> dealtWith()
                NetWatch.Settled.NO_NETWORK -> {
                    VpnState.addLog("Network: none at the moment — the tunnel is checked when one comes")
                    dealtWith()
                }
                NetWatch.Settled.ASK -> {
                    if (lostItsInternet(left)) {
                        rebuild("the phone moved off a network that lost its internet")
                    } else {
                        VpnState.addLog("Network: settled on ${NetWatch.label(track.transports)} — asking the tunnel whether it still carries")
                        ask()
                    }
                }
            }
        }

        private fun ask() {
            val port = l.socksPort
            val timeout = NetWatch.probeTimeout(tickIn)
            asking?.cancel()
            asking = scope.launch {
                val first = Diagnostics.httpLatency(port, timeout = timeout, fresh = true)
                if (!isActive) return@launch
                if (first >= 0) {
                    main.post {
                        if (mine()) VpnState.addLog("✓ Network: the tunnel still carries (${first}ms) — kept as it is")
                        dealtWith()
                    }
                    return@launch
                }
                VpnState.addLog("Network: the tunnel did not answer — asked once more in ${NetWatch.PROBE_GAP_MS / 1000} s")
                delay(NetWatch.PROBE_GAP_MS)
                val second = Diagnostics.httpLatency(port, url = NetWatch.SECOND_PROBE_URL, timeout = timeout, fresh = true)
                if (!isActive) return@launch
                main.post {
                    if (!mine()) { dealtWith(); return@post }
                    if (second >= 0) {
                        VpnState.addLog("✓ Network: the tunnel answered the second time (${second}ms) — kept as it is")
                        dealtWith()
                    } else {
                        rebuild("the tunnel did not answer twice")
                    }
                }
            }
        }

        /** Neither ask answered, or what the tunnel held died with the network left behind ([why], for the log). Main thread. */
        private fun rebuild(why: String) {
            val now = SystemClock.elapsedRealtime()
            val wait = NetWatch.rebuildWait(netRebuiltAt, now)
            if (wait > 0L) {
                VpnState.addLog("✗ Network: $why, but the tunnel was rebuilt less than a minute ago — asked again in ${(wait + 999) / 1000} s")
                main.removeCallbacks(askAgain)
                main.postDelayed(askAgain, wait)
                dealtWith()
                return
            }
            netRebuiltAt = now
            VpnState.addLog("✗ Network: $why — rebuilding the tunnel on this network")
            // The lock stays: the rebuild's teardown lets go of this watcher (stop).
            rebuildSession(l, "the network changed and the tunnel stopped carrying")
        }

        /** Let go (teardown, any thread). */
        fun stop() {
            main.removeCallbacks(settle); main.removeCallbacks(askAgain)
            asking?.cancel(); asking = null
            letSleep()
        }
    }

    /**
     * The stall watchdog under the session [l] now Connected (StallWatch has the
     * why and the judgement). Every StallWatch.TICK_MS hev's TUN counters are read
     * — the ones the stats loop draws; one JNI call, no network — and judged.
     * Suspect for StallWatch.SUSPECT_TICKS ticks (traffic in, little back), the
     * tunnel is asked through its own SOCKS port with the session's credentials
     * (LocalProxyAuth), twice StallWatch.PROBE_GAP_MS apart, exactly as the
     * network watcher asks; neither answered, it is rebuilt (rebuildForStall).
     * Traffic in and nothing at all back for StallWatch.DEAD_TICKS ticks is
     * rebuilt unasked: the core answers a probe while hev, between the TUN and
     * it, carries nothing. Every step is one log line.
     *
     * Battery: one counter read a tick, screen on or off (the per-second stats
     * loop waits for the screen; this cannot — the session nobody is looking at
     * is the one that needs healing); no probe while the phone sends nothing;
     * on a tunnel that only uploads (suspect every tick) a probe at most once a
     * minute. Runs on IO; cancelled with the session (teardown), and a tick
     * after a connect or a disconnect has been asked for does nothing.
     */
    private fun watchStall(l: Launch) {
        stallJob?.cancel()
        tickIn = 0L
        stallJob = scope.launch {
            val judge = StallWatch.Judge()
            while (isActive && running === l && tunnelRunning) {
                delay(StallWatch.TICK_MS)
                if (!groupQuiet(l)) continue
                val st = runCatching { TProxyService.TProxyGetStats() }.getOrNull()
                val tx = if (st != null && st.size >= 4) st[1] else -1L
                val rx = if (st != null && st.size >= 4) st[3] else -1L
                val v = judge.tick(tx, rx, SystemClock.elapsedRealtime())
                tickIn = judge.inBytes
                if (v == StallWatch.Verdict.FINE) {
                    if (stallRebuilds != 0) main.post { stallRebuilds = 0 }
                } else if (v == StallWatch.Verdict.DEAD) {
                    main.post { rebuildForStall(l, "${StallWatch.size(judge.inBytes)} went into the tunnel in the last ${StallWatch.TICK_MS / 1000} s and nothing at all came back, for ${StallWatch.DEAD_TICKS * StallWatch.TICK_MS / 1000} s now") }
                } else if (v == StallWatch.Verdict.ASK) {
                    VpnState.addLog("Watchdog: ${StallWatch.size(judge.inBytes)} went into the tunnel in ${StallWatch.TICK_MS / 1000} s and ${StallWatch.size(judge.outBytes)} came back — asking the tunnel whether it still carries")
                    val timeout = NetWatch.probeTimeout(judge.inBytes)
                    val first = Diagnostics.httpLatency(l.socksPort, timeout = timeout, fresh = true)
                    if (!isActive || !groupQuiet(l)) continue
                    if (first >= 0) {
                        judge.answered(SystemClock.elapsedRealtime())
                        VpnState.addLog("✓ Watchdog: the tunnel answers (${first}ms) — kept as it is; not asked again for a minute")
                        continue
                    }
                    VpnState.addLog("Watchdog: the tunnel did not answer — asked once more in ${StallWatch.PROBE_GAP_MS / 1000} s")
                    delay(StallWatch.PROBE_GAP_MS)
                    val second = Diagnostics.httpLatency(l.socksPort, url = NetWatch.SECOND_PROBE_URL, timeout = timeout, fresh = true)
                    if (!isActive || !groupQuiet(l)) continue
                    if (second >= 0) {
                        judge.answered(SystemClock.elapsedRealtime())
                        VpnState.addLog("✓ Watchdog: the tunnel answered the second time (${second}ms) — kept as it is")
                    } else {
                        main.post { rebuildForStall(l, "the tunnel stopped carrying and did not answer twice") }
                    }
                }
            }
        }
    }

    /**
     * The stall watchdog's rebuild (watchStall): a connect onto this live
     * tunnel — a switch, so no app goes around the VPN meanwhile — without a
     * mux test, as the network watcher rebuilds (rebuildSession, NetWatcher.rebuild)
     * and on the same budget: at most one rebuild a minute between the two
     * (netRebuiltAt). A stall that comes straight back after each rebuild waits
     * twice as long each time (StallWatch.rebuildWait, stallRebuilds — reset by
     * the first tick that carries both ways): a stall no rebuild cures — a
     * server that answers the probe and drops the rest, a phone whose own
     * uplink is gone — must not cost a tunnel every minute. The health line
     * says stalled meanwhile, and a muxed session's verdicts are marked for a
     * recheck, as the self-check marks them. Main thread.
     */
    private fun rebuildForStall(l: Launch, why: String) {
        if (!groupQuiet(l)) return                  // going anyway: a connect or a disconnect is on its way
        // No network at all: nothing to rebuild onto, and the budget is kept for
        // when one comes (the network watcher asks the tunnel then). Only with a
        // watcher to say so: where none could be registered, no network is known.
        val watcher = netWatcher
        if (watcher != null && watcher.track.id == null) {
            VpnState.addLog("Watchdog: $why — but the phone has no network at the moment; the tunnel is checked when one comes")
            return
        }
        val now = SystemClock.elapsedRealtime()
        val wait = StallWatch.rebuildWait(netRebuiltAt, stallRebuilds, now)
        if (wait > 0L) {
            VpnState.addLog("✗ Watchdog: $why — but the tunnel was rebuilt ${(now - netRebuiltAt) / 1000} s ago; rebuilt again in ${(wait + 999) / 1000} s at the earliest if it still carries nothing")
            return
        }
        netRebuiltAt = now
        stallRebuilds++
        VpnState.setHealth(false, t("health.stalled"))
        markMuxRecheck(l, "the connection stalled")
        VpnState.addLog("✗ Watchdog: $why — rebuilding the tunnel" + (if (stallRebuilds > 1) " (stall rebuild $stallRebuilds in a row — the next waits longer)" else ""))
        rebuildSession(l, "the tunnel stopped carrying")
    }

    /** The transports of the phone's network, as NetWatch names them. */
    private fun transportsOf(caps: NetworkCapabilities): Set<String> {
        val out = HashSet<String>()
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) out.add(NetWatch.WIFI)
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) out.add(NetWatch.CELLULAR)
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) out.add(NetWatch.ETHERNET)
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) out.add(NetWatch.BLUETOOTH)
        if (out.isEmpty()) out.add(NetWatch.OTHER)
        return out
    }

    /**
     * Core, hev, TUN and credentials down, and the network watcher. Runs on the
     * worker; the service and the screen are left alone. [keepTun]: a switch —
     * the TUN is held open instead (heldTun) until the next one is established
     * (startTunnel); without it, a TUN held so far is closed as well.
     */
    private fun teardown(keepTun: Boolean = false) {
        unwatchNetwork()
        statsJob?.cancel(); statsJob = null
        checkJob?.cancel(); checkJob = null
        groupJob?.cancel(); groupJob = null
        stallJob?.cancel(); stallJob = null
        running = null
        VpnState.setLanShared(null)
        if (tunnelRunning) {
            tunnelRunning = false
            tunnelUp = false
            // hev's stop joins its thread, which ends within milliseconds — or
            // never, after a start whose init failed (TProxyService). Waited for
            // only so long (EngineReset.bounded): past that the process is
            // marked stuck and this teardown goes on without it — the TUN
            // closed, Not connected up, the service stopped — instead of
            // freezing every command behind it until a Force Stop.
            if (!EngineReset.bounded("the tunnel library's (hev) stop", EngineReset.HEV_STOP_MS) { TProxyService.TProxyStopService() })
                VpnState.addLog("⚠ The tunnel library (hev) did not stop within ${EngineReset.HEV_STOP_MS / 1000} s — this process can run no tunnel any more; IRNetFree restarts itself for a fresh one")
        }
        // The in-process core's StopLoop closes the whole instance here; the same bounded wait.
        val x = xray
        xray = null
        if (x != null && !EngineReset.bounded("the Xray core's stop", EngineReset.CORE_STOP_MS) { x.stop() })
            VpnState.addLog("⚠ The Xray core did not stop within ${EngineReset.CORE_STOP_MS / 1000} s — it still holds its port; IRNetFree restarts itself for a fresh engine")
        runCatching { singbox?.stop() }; singbox = null
        runCatching { pattn?.stop() }; pattn = null
        val t = tun
        tun = null
        if (keepTun && t != null) {
            runCatching { heldTun?.close() }          // never two held: the older one is no use to anyone
            heldTun = t
        } else if (!keepTun) {
            runCatching { t?.close() }
            runCatching { heldTun?.close() }; heldTun = null
        }
        LocalProxyAuth.release(auth); auth = null
    }

    private fun live() = tunnelRunning || tun != null || heldTun != null || xray != null || singbox != null || pattn != null

    /**
     * The teardown a disconnect asked for: the tunnel down and the service
     * stopped. Its Not connected goes up only while that disconnect is still
     * the latest move (checked and written under the generation lock):
     * a Connect tapped a moment after it (Reconnect used to be exactly that,
     * 0.6 s on), and a teardown landing later than that put "Not protected"
     * over the new connect's CONNECTING (a tap then started yet another
     * connect) or erased its prepare's ERROR.
     */
    private fun stopAll(startId: Int) {
        teardown()
        generation.ifStopped { VpnState.set(ConnState.DISCONNECTED, "") }
        finish(startId)
    }

    /**
     * A stop of generation [gen] — a disconnect, or a connect that failed
     * before it reached the service (stopOlder) — for whatever is up. Never a
     * tunnel a NEWER connect brought up (Generation.reaches): such a stop,
     * sent from another thread, can arrive after that connect's start, and
     * taking its tunnel down would leave the earlier request standing over the
     * later one. Nothing is finished then either — this start id is newer than
     * that session's, and finishing by it stopped the service under it.
     */
    private fun stopFor(gen: Long, startId: Int) {
        if (!Generation.reaches(gen, running?.gen)) {
            VpnState.addLog("A stop asked for before the connection now up arrived after it — the connection stays")
            return
        }
        stopAll(startId)
    }

    /**
     * A connect of generation [gen] that could not come up (or a session whose
     * core died for good). While it is still the latest move: the tunnel down,
     * ERROR and its message on screen — kept through the teardown; DISCONNECTED
     * used to overwrite them, so every failure reached the user as "Not
     * protected" — plus a notification with [notify], for when nobody is
     * looking. Overtaken, it goes quietly: its error over a newer connect's
     * Connecting was a failure the user no longer asked about, and a tunnel a
     * newer connect already brought up is not its to touch. A rebuild of a
     * session that was really running does not end here (retryRebuild).
     */
    private fun fail(gen: Long, startId: Int, error: String, notify: Boolean) {
        if (retryRebuild(gen, startId, error)) return
        val newer = !Generation.reaches(gen, running?.gen)
        if (!newer) teardown()
        if (generation.ifCurrent(gen) { VpnState.set(ConnState.ERROR, error = error) }) {
            if (notify) notifyError(this, error)
            finish(startId)
        } else {
            VpnState.addLog("⚠ $error — a disconnect or another connect has been asked for since")
            if (!newer) finishIfIdle(startId)
        }
    }

    /**
     * The rebuild of generation [gen] could not come up, and it was the latest
     * move: the session goes down as any failure's does, but the service
     * stays and tries again in 30 s, then 60 s, then every 120 s
     * (StickyRestart) — on screen and in the notification, whose Stop ends it.
     * A Disconnect or a connect meanwhile moves the generation on and drops
     * the try (afterWait). False when this is no such rebuild, or it was
     * overtaken: fail() goes on as for any connect. Runs on the worker.
     */
    private fun retryRebuild(gen: Long, startId: Int, error: String): Boolean {
        val r = rebuilding?.takeIf { x: Rebuild -> x.gen == gen } ?: return false
        if (gen != generation.get()) return false
        teardown()
        val now = SystemClock.elapsedRealtime()
        val n = StickyRestart.next(now, r.streak, now)      // measured from now: every failure of this rebuild is the next step
        r.streak = n.streak
        val wait = n.waitMs
        if (!generation.ifCurrent(gen) { VpnState.set(ConnState.ERROR, error = "$error — it tries again by itself in ${wait / 1000} s") }) return false
        main.post {
            if (gen != generation.get()) return@post
            goForeground(tf("notif.restartIn", "s" to wait / 1000), action = "Stop")
            afterWait(gen, wait) {
                netRebuiltAt = SystemClock.elapsedRealtime()      // a rebuild like the first: the shared budget counts from it
                attemptRebuild(r, startId)
            }
        }
        return true
    }

    /**
     * Leave the foreground and stop — unless a start command newer than
     * [startId] has arrived since: a plain stopSelf() from a late teardown
     * used to stop the service a reconnect had just started.
     */
    private fun finish(startId: Int) {
        main.post {
            if (startId != lastStartId) return@post
            stopForegroundCompat()
            // By the newest id delivered: an always-on start left alone since
            // (onStartCommand) is newer than [startId], and stopSelf() with an
            // id older than the newest one stops nothing.
            stopSelf(newestStartId)
        }
    }

    /**
     * An overtaken connect: stop only if nothing is running here (the command
     * that overtook it owns the rest). When what overtook it was a disconnect
     * and no connect has been asked for since, a "Connecting…" still on screen
     * is nobody's any more — Not connected. (A newer connect's own CONNECTING
     * is left alone.)
     */
    private fun finishIfIdle(startId: Int) {
        if (live()) return
        generation.ifStopped { if (VpnState.state.value == ConnState.CONNECTING) VpnState.set(ConnState.DISCONNECTED, "") }
        finish(startId)
    }

    override fun onRevoke() {
        // Another VPN took over, or the user switched this one off in Android's
        // settings. (VpnService's own onRevoke is a bare stopSelf(); finish() does it here.)
        generation.stop()
        val id = lastStartId
        onWorker("revoke") { stopAll(id) }
    }

    override fun onDestroy() {
        alive = false
        main.removeCallbacks(wedgeWatch)
        pendingAutoStart?.let { main.removeCallbacks(it) }; pendingAutoStart = null; pendingRestart = false
        runCatching { scope.cancel() }
        // Normally everything is already down (stopAll ran first). Stopped some
        // other way, the tunnel still goes — on the worker, after whatever it is
        // doing, and without touching a state a newer start may already own.
        onWorker("destroy") {
            if (live()) {
                val g = running?.gen
                teardown()
                if (g != null) generation.ifCurrent(g) { VpnState.set(ConnState.DISCONNECTED, "") }
            }
        }
        // A process whose engine is stuck restarts itself once nothing is left
        // of the service and nobody is looking (EngineReset); nothing otherwise.
        scheduleEngineRestart(applicationContext, EngineReset.GRACE_MS)
        super.onDestroy()
    }

    /* ----------------------------- notification ----------------------------- */
    /**
     * [action]: a button on it that sends ACTION_DISCONNECT (a crash loop's wait
     * offers "Stop", a connect in progress "Cancel", a live tunnel "Disconnect").
     */
    private fun goForeground(label: String, action: String? = null, connected: Boolean = false) {
        shown = Shown(label, connected, action)
        runCatching { startForeground(NOTIF_ID, buildNotification(label, connected, action)) }
            .onFailure { VpnState.addLog("startForeground failed: ${it.message}") }
    }

    private fun cancelErrorNotification() {
        runCatching { (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).cancel(NOTIF_ERR_ID) }
    }

    private fun buildNotification(text: String, connected: Boolean, action: String? = if (connected) "Disconnect" else null): Notification {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            nm.createNotificationChannel(NotificationChannel(CHANNEL, t("notif.channel"), NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val disconnect = PendingIntent.getService(this, 1,
            Intent(this, XrayVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val b = Notification.Builder(this, CHANNEL)
            .setContentTitle("IRNetFree" + if (connected) " • " + t("state.connected") else "")
            .setContentText(text)
            .setSmallIcon(com.irnetfree.vpn.R.drawable.ic_stat_vpn)
            .setOngoing(true)
            .setContentIntent(open)
        if (action != null) {
            val icon = android.graphics.drawable.Icon.createWithResource(this, com.irnetfree.vpn.R.drawable.ic_stat_vpn)
            // the action is kept by its English name (shown.action); the button says it in the app's language
            val word = when (action) { "Disconnect" -> t("notif.disconnect"); "Cancel" -> t("notif.cancel"); "Stop" -> t("notif.stop"); else -> action }
            b.addAction(Notification.Action.Builder(icon, word, disconnect).build())
        }
        return b.build()
    }
    private fun updateNotification(text: String, connected: Boolean) {
        val action = if (connected) "Disconnect" else null
        shown = Shown(text, connected, action)
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIF_ID, buildNotification(text, connected, action))
    }
    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(STOP_FOREGROUND_REMOVE)
        else @Suppress("DEPRECATION") stopForeground(true)
    }

    companion object {
        private const val TAG = "XrayVpnService"
        private const val CHANNEL = "vpn"
        private const val NOTIF_ID = 1
        private const val NOTIF_ERR_ID = 2
        private const val TUN_ADDR4 = "172.19.0.1"
        private const val TUN_ADDR6 = "fdfe:dcba:9876::1"
        /** The tunnel peer the OS is told to resolve at under managed DNS: inside the TUN's route, not the device's own address. */
        const val TUN_DNS4 = "172.19.0.2"
        private const val TUN_MTU = 1500

        const val ACTION_CONNECT = "com.irnetfree.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.irnetfree.vpn.DISCONNECT"
        const val EXTRA_CONFIG = "config"; const val EXTRA_SOCKS = "socks"; const val EXTRA_DNS = "dns"
        const val EXTRA_LABEL = "label"; const val EXTRA_IPV6 = "ipv6"; const val EXTRA_ENGINE = "engine"
        const val EXTRA_PERAPP_MODE = "perAppMode"; const val EXTRA_PERAPPS = "perApps"
        const val EXTRA_GEN = "gen"; const val EXTRA_SOCKS_USER = "socksUser"; const val EXTRA_SOCKS_PASS = "socksPass"
        /** The LAN share the config opens (LanShare JSON); absent = none. */
        const val EXTRA_LAN = "lan"
        /** The fingerprints a drop of this session marks for a mux recheck (Mux.Pick.onDrop); absent = none. */
        const val EXTRA_MUX = "muxTested"
        /** A config that runs a group: its metrics listener's port, and its groups (GroupEvict.mapToJson); absent = none. */
        const val EXTRA_METRICS = "metricsPort"; const val EXTRA_GROUPS = "groups"
        /** This connect is the reload a group's set-aside asked for (watchGroups). */
        const val EXTRA_GROUP_RELOAD = "groupReload"
        /** What restartProcess() leaves for the start after its kill (prefs "irnf-service"): EngineReset.RECONNECT or STAY, why, and when. */
        private const val KEY_ENGINE_RESTART = "engineRestart"
        private const val KEY_ENGINE_WHY = "engineRestartWhy"
        private const val KEY_ENGINE_AT = "engineRestartAt"
        /** When the process restarted itself to connect again (EngineReset.reconnectsNoted): the ceiling on doing so. */
        private const val KEY_ENGINE_RESTARTS = "engineReconnects"

        /** A failure nobody may be watching the app for (always-on at boot, a core that died, a restart that stays off): it stays in the shade. */
        private fun notifyError(ctx: Context, msg: String) {
            runCatching {
                val nm = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                nm.createNotificationChannel(NotificationChannel(CHANNEL, t("notif.channel"), NotificationManager.IMPORTANCE_LOW))
                val open = PendingIntent.getActivity(ctx, 0, Intent(ctx, MainActivity::class.java),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
                nm.notify(NOTIF_ERR_ID, Notification.Builder(ctx, CHANNEL)
                    .setContentTitle("IRNetFree • " + t("state.notConnected"))
                    .setContentText(msg)
                    .setStyle(Notification.BigTextStyle().bigText(msg))
                    .setSmallIcon(com.irnetfree.vpn.R.drawable.ic_stat_vpn)
                    .setContentIntent(open)
                    .setAutoCancel(true)
                    .build())
            }
        }

        /**
         * A group's member that stays dead: out of the running config, tested by
         * the app instead (GroupEvict). Process-wide: every connect's prepare()
         * starts it on its plan and reads what stays out; the session's
         * watchGroups feeds it. On elapsed real time — a clock set by hand moves nothing.
         */
        private val groupEvict = GroupEvict.Evictor(now = { SystemClock.elapsedRealtime() })

        /** Moved on by every connect and disconnect: a prepare or a start carrying an older value was overtaken. */
        private val generation = Generation()

        /**
         * The latest connect move and what it was for — the user's, always-on's,
         * the network watcher's rebuild. An always-on start leaves a tunnel up or
         * coming up for the stored selection alone (AlwaysOnStart); it only
         * counts while its generation is still the latest move.
         */
        @Volatile private var asked: Asked? = null

        @Volatile private var pendingRestart = false

        /** An instance exists (onCreate … onDestroy): a failed connect has something to stop only then. */
        @Volatile private var alive = false

        /**
         * A tunnel of ours carries traffic (tun2socks started … teardown): the
         * instance's `tunnelRunning`, readable from prepare(). The hello check
         * (HelloCut) is asked only without one — through it, it would be about
         * our own server — so a switch in place keeps the last answer.
         */
        @Volatile private var tunnelUp = false

        /**
         * A ticket for work that connects LATER on its own — ⚡ fastest measures
         * for seconds before it connects. Take it when the run starts; if it has
         * moved by the time the run ends, somebody connected or disconnected
         * meanwhile, and that request stands: the run should not connect over it.
         */
        val moves: Long get() = generation.get()

        /**
         * A crash loop's reconnect is waiting out its backoff (StickyRestart).
         * Connect-on-open must not jump it: the app opened during the wait
         * would otherwise connect at once and repeat the crash sooner. (A tap
         * on Connect still connects — the user asked.)
         */
        val restartPending: Boolean get() = pendingRestart

        /**
         * Run [block] on the main thread and hand back its result (or its
         * exception): the process Store's lists are written there by every
         * screen — a subscription refresh replaces them wholesale — so the
         * connect and auto-start threads read and write them only through here.
         */
        private fun <T> onMain(block: () -> T): T {
            if (Looper.myLooper() == Looper.getMainLooper()) return block()
            val task = FutureTask(Callable { block() })
            Handler(Looper.getMainLooper()).post(task)
            return try { task.get() } catch (e: ExecutionException) { throw e.cause ?: e }
        }

        /**
         * Every tunnel start and stop runs here, one at a time and off the main
         * thread. Process-wide, not per instance: hev is one per process, and a
         * destroyed instance's teardown must finish before the next start.
         */
        private val worker: ExecutorService = Executors.newSingleThreadExecutor { r -> Thread(r, "irnf-tunnel").apply { isDaemon = true } }

        /**
         * Run [block] on the worker — and never let an exception out of it. The
         * worker is a plain executor thread: a Runnable that throws ends that
         * thread with its exception, in the process's default handler, and on
         * Android that handler kills the process — the tunnel went down with
         * it, the next open showed the crash screen, and the sticky restart
         * counted it as a crash loop (StickyRestart) and waited before it
         * reconnected. One log line instead, naming the command ([what]); the
         * state a command left behind is whatever it got to, which the next
         * command tidies (every start begins with a teardown).
         */
        private fun onWorker(what: String, block: () -> Unit) {
            worker.execute {
                workerSince = SystemClock.uptimeMillis()
                workerCommand = what
                try { block() } catch (t: Throwable) { unexpected(what, t) } finally { workerCommand = null }
            }
        }

        /**
         * What the worker runs right now and since when (uptime — the clock
         * its own waits run on, which stands still while the phone sleeps;
         * null = idle), for EngineReset.wedged: the user's Disconnect and the
         * service's own tick ask whether a command has run for longer than
         * anything the service does. Written since-then-command, read
         * command-then-since, so a reader never pairs a fresh command with a
         * stale start.
         */
        @Volatile private var workerCommand: String? = null
        @Volatile private var workerSince = 0L

        /** Every screen of ours is away: the app's UI gone (EngineReset.uiGone) and MainActivity stopped. */
        private fun uiAway(): Boolean = EngineReset.uiGone && !VpnState.uiVisible.value

        /** For the background restart's look (engineRestart): the application context, from whoever scheduled it. */
        @Volatile private var appCtx: Context? = null
        private val mainHandler = Handler(Looper.getMainLooper())

        /** The look a grace after the service's end or the screens' going (scheduleEngineRestart). */
        private val engineRestart = Runnable {
            val ctx = appCtx ?: return@Runnable
            val why = EngineReset.stuck ?: return@Runnable
            if (EngineReset.mayRestartInBackground(true, alive, VpnState.state.value, uiAway())) restartProcess(ctx, EngineReset.STAY, why)
        }

        /**
         * A stuck process restarts itself when nothing is lost: the service
         * gone, every screen of ours away, nothing on its way
         * (EngineReset.mayRestartInBackground) — looked at [graceMs] after the
         * service's end (onDestroy: GRACE_MS, by which time the destroy
         * teardown has run and the framework has drained the store's writes)
         * and after the app's UI went away (uiHidden: UI_GONE_GRACE_MS — a
         * share sheet over the app is back within that, and a screen that is
         * back by then is seen). Nothing to do while the engine is fine.
         */
        private fun scheduleEngineRestart(ctx: Context, graceMs: Long) {
            if (EngineReset.stuck == null) return
            appCtx = ctx.applicationContext
            mainHandler.removeCallbacks(engineRestart)
            mainHandler.postDelayed(engineRestart, graceMs)
        }

        /**
         * Every screen of ours went away (IRApp.onTrimMemory, TRIM_MEMORY_UI_HIDDEN
         * — not an Activity's onStop, which the QR scanner or a sheet over the
         * app causes while it is in use): a process whose engine is stuck may
         * restart itself now.
         */
        fun uiHidden(ctx: Context) {
            EngineReset.uiGone = true
            scheduleEngineRestart(ctx, EngineReset.UI_GONE_GRACE_MS)
        }

        /** A screen of ours shows (MainActivity.onStart). */
        fun uiShown() { EngineReset.uiGone = false }

        /**
         * End this process on purpose, for a fresh one with a clean engine
         * (EngineReset) — what a Force Stop did by hand, done by the app at a
         * moment of its choosing. The flag for the start that follows is
         * stored first, with commit(): the kill is a second away. A RECONNECT
         * is counted (EngineReset.mayReconnect): past the ceiling it becomes a
         * STAY and a notification says the engine keeps getting stuck — a
         * config that hangs the start every time would otherwise kill and
         * reconnect for ever, no internet under lockdown and the battery going;
         * and it is the crash-loop logic's attempt too (stickyRestartAt), so a
         * real crash right after counts as one. Then, off the main thread: the
         * log's queue written out (the lines that say why must reach the
         * file), a moment for the store's apply() writes (the framework drains
         * them at the end of a service's stop and a screen's going, both before
         * this is reached), and the kill. Once per process.
         */
        private fun restartProcess(ctx: Context, flag0: String, why: String) {
            if (!EngineReset.beginRestart()) return
            val now = System.currentTimeMillis()
            var flag = flag0
            runCatching {
                val p = ctx.getSharedPreferences("irnf-service", Context.MODE_PRIVATE)
                val e = p.edit()
                if (flag0 == EngineReset.RECONNECT) {
                    val before = EngineReset.parseTimes(p.getString(KEY_ENGINE_RESTARTS, null))
                    if (EngineReset.mayReconnect(before, now)) {
                        e.putString(KEY_ENGINE_RESTARTS, EngineReset.joinTimes(EngineReset.reconnectsNoted(before, now))).putLong("stickyRestartAt", now)
                    } else {
                        flag = EngineReset.STAY
                        VpnState.addLog("⚠ The engine got stuck ${EngineReset.RECONNECT_MAX} times within ${EngineReset.RECONNECT_WINDOW_MS / 60_000} minutes — not connecting again by itself this time; tap Connect when you want it back")
                        notifyError(ctx, t("engine.keepsStuck"))
                    }
                }
                e.putString(KEY_ENGINE_RESTART, flag).putString(KEY_ENGINE_WHY, why).putLong(KEY_ENGINE_AT, now).commit()
            }
            VpnState.addLog("Restarting IRNetFree's engine ($why): the process ends now and " +
                if (flag == EngineReset.RECONNECT) "connects again by itself" else "stays disconnected; the next open starts fresh")
            Thread({
                VpnState.awaitLogFlushed(1500)
                try { Thread.sleep(300) } catch (e: InterruptedException) { }
                android.os.Process.killProcess(android.os.Process.myPid())
            }, "irnf-engine-restart").apply { isDaemon = true }.start()
        }

        /** An exception nothing expected: once in the log and in logcat — never the end of the process. */
        private fun unexpected(what: String, t: Throwable) {
            Log.e(TAG, "$what failed", t)
            runCatching { VpnState.addLog("⚠ Internal error in $what: ${t.javaClass.simpleName}${t.message?.let { m: String -> ": $m" } ?: ""}") }
        }

        /**
         * Build the plan and the config, then start the service. Runs its network
         * steps (certificate pins, WireGuard endpoints) on a worker thread: they
         * are TLS dials and DNS lookups, and the caller is the UI. The state is
         * CONNECTING from the first line, so the screen already shows it.
         * Cancelling — disconnect() while this runs — really cancels: the
         * service is never started for a connect that was overtaken.
         *
         * Onto a live tunnel this is a switch: the service takes the old one
         * down itself when the new one's turn comes (startTunnel), so no
         * disconnect() is needed first — and must not be: the old TUN stays
         * up, carrying nothing, until the new one is established, so no app
         * goes around the VPN at any moment of it (a disconnect first left the
         * phone without the VPN until the new core was up). The move is made
         * FIRST, even for a selection that cannot be built: an older connect
         * still in prepare() then stops there instead of finishing later and
         * taking over. A connect that fails at any point before the service
         * also takes down a tunnel an older connect left up (stopOlder) — it
         * carried the old server under the new one's error, notification
         * still "Connected".
         */
        fun connect(ctx: Context, store: Store) {
            val label = store.selectionLabel()
            val sel = store.selection
            val gen = generation.next { VpnState.set(ConnState.CONNECTING, label) }
            asked = Asked(gen, sel)
            val plan = try { store.buildPlan() } catch (e: Throwable) {
                stopOlder(ctx, gen)
                throw e                           // a user-facing message; the caller reports it
            }
            Thread {
                try {
                    val intent = prepare(ctx, store, plan, label, wanted = { gen == generation.get() })
                    if (gen != generation.get()) { VpnState.addLog("Connect cancelled"); return@Thread }
                    intent.putExtra(EXTRA_GEN, gen)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(intent) else ctx.startService(intent)
                } catch (e: Throwable) {
                    Log.e(TAG, "connect failed", e)
                    if (generation.ifCurrent(gen) { VpnState.set(ConnState.ERROR, error = e.message ?: "connect failed") }) stopOlder(ctx, gen)
                }
            }.also { it.isDaemon = true; it.name = "irnf-connect" }.start()
        }

        /**
         * A connect that never reached the service: whatever an older connect
         * left up goes (a DISCONNECT carrying this connect's generation reaches
         * only older tunnels — Generation.reaches). No service, nothing to stop.
         */
        private fun stopOlder(ctx: Context, gen: Long) {
            if (!alive) return
            runCatching { ctx.startService(Intent(ctx, XrayVpnService::class.java).setAction(ACTION_DISCONNECT).putExtra(EXTRA_GEN, gen)) }
                .onFailure { e -> Log.w(TAG, "could not stop the older tunnel: ${e.message}") }
        }

        /**
         * The hostname Android's Private DNS is set to on the phone's own network
         * (strict mode), else null — Android 9+. Read from the networks that are
         * not a VPN: with the tunnel up, the active network is the tunnel itself.
         */
        private fun privateDnsName(ctx: Context): String? {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
            return runCatching {
                val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                @Suppress("DEPRECATION")
                val nets: Array<Network> = cm.allNetworks
                nets.firstNotNullOfOrNull { n: Network ->
                    val caps = cm.getNetworkCapabilities(n)
                    if (caps == null || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) || !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) null
                    else cm.getLinkProperties(n)?.privateDnsServerName
                }
            }.getOrNull()
        }

        /** What prepare() reads from the store in one go, on the main thread. */
        private class Fresh(val plan: ConnectionPlan, val settings: AppSettings, val pool: List<PoolEntry>, val profile: RoutingProfile?)

        /**
         * Everything before the service: pins, endpoints, mux, the config. Blocks; never on the main thread.
         * [wanted]: false once this connect has been overtaken — the mux test then starts nothing more.
         * [recovery]: a reconnect of the service's own after a drop (not the user's Connect, nor
         * connect-on-open, nor always-on) — it never runs a mux test, it uses what is kept (Mux.choose).
         * [groupReload]: the reload a group's set-aside asked for (watchGroups) — the gap between such
         * reloads keeps counting (GroupEvict.Evictor.reset).
         */
        fun prepare(ctx: Context, store: Store, plan0: ConnectionPlan, label: String, wanted: () -> Boolean = { true }, recovery: Boolean = false, groupReload: Boolean = false): Intent {
            // Certificate pinning on first use (CertPin.kt): a server whose link
            // asked for allowInsecure is dialled once, its leaf certificate hashed
            // and stored; the config then pins it. The core refuses allowInsecure
            // itself, so without this such a server never connected at all.
            //
            // The dials run here; the store takes the result on the main thread,
            // by id (CertPin.applyPins). This thread used to write the list by an
            // index it had looked up earlier, while a subscription refresh could
            // be replacing that very list on the main thread (clear + addAll).
            // The plan holds copies of the records, so its records are taken
            // from the store again afterwards, by id, and the pins learnt just
            // now reach the config. By id, not by the selection: a server picked
            // in the list while the pins were learnt used to be what this
            // connect built — under the label of the one it was asked for.
            //
            // First: does the way out read the names in TLS hellos (HelloCut,
            // the desktop's pathReadsHello)? Two dials, 2 s at most, on this
            // thread — never the main one. Not through a tunnel of ours (a
            // switch in place keeps the last answer), and a recovery has no
            // time for it. On a path that reads names a certificate is the real
            // site's, not the server's: nothing is learned or dropped from it.
            if (!recovery && !tunnelUp) HelloCut.refresh { line -> VpnState.addLog(line) }
            val cutHello = HelloCut.pathCut
            val pins: List<CertPin.PinUpdate> = if (cutHello) emptyList() else CertPin.learn(plan0, System.currentTimeMillis(),
                fetch = { srv -> CertPin.fetchLeafPin(srv.address, srv.port, CertPin.sniOf(srv)) },
                log = { line -> VpnState.addLog(line) })
            val fresh = onMain {
                if (CertPin.applyPins(store.servers, pins)) store.saveServers()
                Fresh(plan0.withRecords { id: String -> store.serverById(id) }, store.settings, store.pool.toList(),
                    (plan0 as? ConnectionPlan.Advanced)?.let { a: ConnectionPlan.Advanced -> store.profileById(a.profileId) })
            }
            val plan = fresh.plan
            val s = fresh.settings

            // A group member set aside lately for not answering stays out
            // (GroupEvict: kept across a reconnect of the same plan): the evictor
            // follows this plan from here — what it no longer holds is forgotten
            // first, so nothing is left out that nobody tests any more.
            groupEvict.reset(plan, reload = groupReload)
            val groupSkip: Set<String> = groupEvict.skip().toSet()

            // Which core, exactly as the desktop decides it (EngineChoice.kt):
            // a single server takes its own choice, and a chain/pool/advanced plan
            // runs on PattN as soon as ANY server in it asks for PattN. Whether
            // that core is bundled for this ABI is asked separately below.
            var engine = EngineChoice.chooseEngine(plan, s.defaultEngine)
            val single = plan as? ConnectionPlan.Single
            // A TUIC / AnyTLS server where sing-box cannot go (a chain, a group, a pool, a
            // profile) is refused now, before a mux test or a DNS lookup for a config that
            // could never be built (TunnelSetup.coreConfig refuses it as well)
            EngineChoice.singboxOnlyInside(plan).firstOrNull()?.let { srv: ServerConfig -> throw IllegalStateException(EngineChoice.singboxOnlyError(srv, EngineChoice.PLAN)) }

            // Geo rules only work when the core can read geoip.dat/geosite.dat.
            // Ask reality instead of hardcoding a flag, so the day those files
            // ship the bypass/block-ads rules start working on their own.
            val geo = GeoAssets.available(ctx)
            if (!geo && (s.routingMode == "bypass-ir" || s.routingMode == "bypass-cn" || s.blockAds))
                VpnState.addLog("No geoip.dat/geosite.dat on this device — geo routing rules are skipped.")

            // Managed DNS off drops every resolver a routing target brings — a
            // corporate WireGuard's own DNS above all. Say so, or nothing does.
            if (!s.dnsManaged) {
                val corp = ConfigBuilder.wgResolverAddresses(plan)
                if (corp.isNotEmpty()) VpnState.addLog("⚠ Managed DNS is off, so the resolver of your WireGuard (${corp.joinToString(", ")}) is not in this config and names inside that network will not resolve — turn Settings → DNS managed by the app back on.")
            }

            // Every WireGuard endpoint that is a name gets an address here, through
            // a resolver that does not believe a fake-IP network (TrustedDns.kt).
            val wgIps = resolveWgEndpoints(plan, s)

            // sing-box has its own config format and only ever runs a single
            // server; PattN takes the very same JSON as the in-process core, so
            // it needs nothing here beyond being present.
            if (engine == EngineChoice.SINGBOX && (single == null || !SingboxCore.available(ctx))) {
                // TUIC / AnyTLS have no other core: said, not handed to one that refuses them
                if (single != null && EngineChoice.isSingboxOnly(single.server))
                    throw IllegalStateException(EngineChoice.singboxOnlyError(single.server, EngineChoice.MISSING))
                if (single != null) VpnState.addLog("sing-box is not bundled for this device — using the in-process core.")
                else VpnState.addLog("sing-box cannot run a chain, pool or advanced plan — using the in-process core.")
                engine = EngineChoice.XRAY
            }
            if (engine == EngineChoice.PATTN && !XrayPattnCore.available(ctx)) {
                VpnState.addLog("Xray-PattN is not bundled for this device (arm64 only) — using the in-process core. A config that needs plaintext VLESS/Trojan will be refused by it.")
                engine = EngineChoice.XRAY
            }
            // Mux (Mux.kt, spec §4): which of the plan's servers carry it —
            // Settings → Mux, and in auto the selected server's own test, run
            // here (a throwaway core, at most 8 s) when it has no fresh verdict,
            // its verdict is past its age, or a drop marked it for a recheck —
            // never before a retry is due, never on a reconnect of the
            // service's own. sing-box and a chain's hops never get it; off,
            // the config is the one of before.
            val mux = if (engine == EngineChoice.SINGBOX) Mux.Pick.NONE else Mux.choose(
                mode = store.muxMode, connection = plan, cache = store.muxProbes,
                now = { System.currentTimeMillis() },
                test = { srv: ServerConfig -> XrayTester.probeMux(ctx, srv, s, wanted) },
                remember = { fp: String, p: Mux.Probe -> store.rememberMux(fp, p) },
                log = { line: String -> VpnState.addLog(line) },
                wanted = wanted,
                recovery = recovery
            )
            // This session's credentials for the tunnel's own inbounds (LocalAuth.kt):
            // hev and the app's clients present them, no other app has them.
            val auth = LocalAuth.random()
            // LAN sharing, when on and when it fits beside this connection's own
            // ports (the tunnel's may have been moved onto it since it was set).
            val lan = lanShareFor(ctx, s, fresh.pool)
            // A config that runs a group opens the core's metrics listener on a
            // loopback port picked free now: the session reads its groups' health
            // check there (watchGroups). Without a group the config opens none.
            val metricsPort = if (engine == EngineChoice.SINGBOX) 0 else freeLocalPort(setOf(s.socksPort, s.httpPort))
            // ...and every TCP dial through a hop rides a loopback socket on another (ConfigBuilder.relayHopDials)
            val relayPort = if (engine == EngineChoice.SINGBOX) 0 else freeLocalPort(setOf(s.socksPort, s.httpPort, metricsPort))
            val built = TunnelSetup.coreConfig(engine, plan, s, geo, wgIps, auth, lan, muxIds = mux.ids,
                groupSkip = groupSkip, metricsPort = metricsPort, relayPort = relayPort, cutHello = cutHello,
                coreVersion = { e -> if (e == EngineChoice.PATTN) XrayPattnCore.version(ctx) else XrayCore.version() }) { line -> VpnState.addLog(line) }
            engine = built.engine
            val config = built.json
            val watched = built.groups.isNotEmpty() && metricsPort > 0 && engine != EngineChoice.SINGBOX
            if (watched && groupSkip.isNotEmpty() && !groupReload)
                VpnState.addLog("Groups: ${groupSkip.size} member(s) set aside lately for not answering stay out of this connection — the app tests them and brings each back when it answers")

            // What the OS resolves at: the tunnel peer under managed DNS (every
            // query enters the TUN and dns-out answers it), the user's own public
            // resolvers otherwise. A sing-box-format config carries no hijack.
            val hijacks = engine != EngineChoice.SINGBOX
            val adapterDns = DnsPlan.adapterDnsServers(s, if (hijacks) TUN_DNS4 else null)

            // What this connect is built from: the screens name every change made
            // after it that the running tunnel does not carry (SettingsApply).
            VpnState.setApplied(SettingsApply.Applied(s, fresh.profile, SettingsApply.muxRead(store.muxMode, plan, engine), SettingsApply.chainsOf(plan)))
            // ...and what of the routing would not do what the screen says
            TunnelSetup.routingNotes(plan, s, engine, geo, privateDnsName(ctx)).forEach { line: String -> VpnState.addLog(line) }

            return Intent(ctx, XrayVpnService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_CONFIG, config)
                putExtra(EXTRA_ENGINE, engine)
                putExtra(EXTRA_SOCKS, s.socksPort)
                putExtra(EXTRA_SOCKS_USER, auth.user)
                putExtra(EXTRA_SOCKS_PASS, auth.pass)
                putStringArrayListExtra(EXTRA_DNS, ArrayList(adapterDns))
                putExtra(EXTRA_LABEL, label)
                putExtra(EXTRA_IPV6, s.ipv6)
                putExtra(EXTRA_PERAPP_MODE, s.perAppMode)
                putStringArrayListExtra(EXTRA_PERAPPS, ArrayList(s.perApps))
                if (lan != null) putExtra(EXTRA_LAN, lan.toJson().toString())
                if (mux.onDrop.isNotEmpty() && built.engine != EngineChoice.SINGBOX) putStringArrayListExtra(EXTRA_MUX, ArrayList(mux.onDrop))
                if (watched) { putExtra(EXTRA_METRICS, metricsPort); putExtra(EXTRA_GROUPS, GroupEvict.mapToJson(built.groups)) }
                if (groupReload) putExtra(EXTRA_GROUP_RELOAD, true)
            }
        }

        /**
         * A loopback port free right now, none of [avoid] (the tunnel's own
         * inbounds); 0 when none could be had — the config then opens no
         * metrics listener and no group is watched.
         */
        private fun freeLocalPort(avoid: Set<Int>): Int {
            repeat(3) {
                val p = try { ServerSocket(0).use { ss: ServerSocket -> ss.localPort } } catch (e: Exception) { 0 }
                if (p > 0 && p !in avoid) return p
            }
            return 0
        }

        /** The LAN share this connection opens: null when it is off, or when it no longer fits (said in the log). */
        private fun lanShareFor(ctx: Context, s: AppSettings, pool: List<PoolEntry>): LanShare? {
            val lan = LanShareStore.load(ctx)
            if (!lan.enabled) return null
            val problem = lan.problem(s, pool)
            if (problem != null) {
                VpnState.addLog("⚠ LAN sharing is off for this connection: $problem — fix it under Settings → LAN sharing")
                return null
            }
            return lan
        }

        /** The WireGuard endpoint names of the plan resolved through TrustedDns; logged as the desktop does. */
        private fun resolveWgEndpoints(plan: ConnectionPlan, s: AppSettings): Map<String, String> {
            val map = HashMap<String, String>()
            for (h in ConfigBuilder.wgEndpointHosts(plan)) {
                val r = TrustedDns.resolveHost(h, ipv6 = s.ipv6, doh = s.dnsRemote)
                if (r.ips.isEmpty()) { VpnState.addLog("Could not resolve the WireGuard endpoint $h — leaving it to the core"); continue }
                map[h] = r.ips[0]
                when (r.source) {
                    "doh" -> VpnState.addLog("WireGuard endpoint: this network answered $h with ${r.suspect.joinToString(", ")}; using ${r.ips[0]} from DoH instead")
                    "os-suspect" -> VpnState.addLog("WireGuard endpoint: $h resolves to ${r.ips[0]}, which no public server can be — if the endpoint is not on this LAN, the network is answering for it")
                }
            }
            if (map.isNotEmpty()) VpnState.addLog("WireGuard endpoint: " + map.entries.joinToString(", ") { "${it.key} → ${it.value}" })
            return map
        }

        /**
         * The user's Disconnect. What comes back is for the screen: null, or
         * — when the worker has not finished a command in all the time the
         * service ever takes (EngineReset.wedged), so this stop queues behind
         * it — what is wrong and that the next Disconnect restarts the engine.
         * The service, which handles the command, decides that (onStartCommand).
         */
        fun disconnect(ctx: Context): String? {
            val gen = generation.stop()            // a connect still in prepare() stops there
            val sent = runCatching { ctx.startService(Intent(ctx, XrayVpnService::class.java).setAction(ACTION_DISCONNECT).putExtra(EXTRA_GEN, gen)) }
            // Android refuses a background start only when no foreground service
            // of ours runs — so no tunnel is up. Not connected, then, now: a
            // "Connecting…" of a connect still in prepare() would stay up for
            // good, since that connect stops there without a word.
            if (sent.isFailure) generation.ifCurrent(gen) { VpnState.set(ConnState.DISCONNECTED, "") }
            val wedged = EngineReset.wedged(workerCommand, workerSince, SystemClock.uptimeMillis())
            return wedged?.let { w: String -> tf("engine.wedged", "what" to w) }
        }
    }
}

/**
 * The single answer to "can the core resolve geosite:/geoip: rules?".
 *
 * Xray needs the routing data files geoip.dat / geosite.dat. The APK carries
 * them as assets (android/scripts/fetch-libs.sh fetches them beside libv2ray);
 * XrayCore.prepareAssets copies them into the app's files dir, which is where
 * the core is told to look. Both the config builder and the Routing screen ask
 * here, so a build without the files degrades honestly: the geo rules are
 * dropped and the screen says so.
 */
object GeoAssets {
    const val GEOIP = "geoip.dat"
    const val GEOSITE = "geosite.dat"
    /** Holds the package's lastUpdateTime for which the two files were copied (XrayCore.prepareAssets). */
    const val STAMP = "geo.stamp"

    /** True only when BOTH data files are actually there and non-empty. */
    fun available(ctx: Context): Boolean = inFilesDir(ctx) || inApkAssets(ctx)

    fun inFilesDir(ctx: Context): Boolean = runCatching {
        File(ctx.filesDir, GEOIP).length() > 0L && File(ctx.filesDir, GEOSITE).length() > 0L
    }.getOrDefault(false)

    fun inApkAssets(ctx: Context): Boolean = runCatching {
        val names = ctx.assets.list("")?.toList() ?: emptyList()
        names.contains(GEOIP) && names.contains(GEOSITE)
    }.getOrDefault(false)
}
