package com.irnetfree.vpn.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import com.irnetfree.vpn.core.AppSettings
import com.irnetfree.vpn.core.CertPin
import com.irnetfree.vpn.core.ConfigBuilder
import com.irnetfree.vpn.core.ConnectionPlan
import com.irnetfree.vpn.core.DnsPlan
import com.irnetfree.vpn.core.EngineChoice
import com.irnetfree.vpn.core.LanShare
import com.irnetfree.vpn.core.LocalAuth
import com.irnetfree.vpn.core.LocalProxyAuth
import com.irnetfree.vpn.core.Mux
import com.irnetfree.vpn.core.PoolEntry
import com.irnetfree.vpn.core.ServerConfig
import com.irnetfree.vpn.core.TrustedDns
import com.irnetfree.vpn.net.Diagnostics
import com.irnetfree.vpn.core.Store
import com.irnetfree.vpn.ui.MainActivity
import hev.htproxy.TProxyService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File
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
 *    by the time its certificate pins are learnt (ConnectionPlan.withRecords).
 */
class XrayVpnService : VpnService() {

    // Written on the worker; @Volatile for the stats loop and the checks that
    // look from other threads.
    @Volatile private var tun: ParcelFileDescriptor? = null
    @Volatile private var xray: XrayCore? = null
    @Volatile private var singbox: SingboxCore? = null
    @Volatile private var pattn: XrayPattnCore? = null
    @Volatile private var tunnelRunning = false
    /** What the running tunnel was started with, to restart a subprocess core that died under it. */
    @Volatile private var running: Launch? = null
    /** The credentials this instance handed LocalProxyAuth; released at teardown. */
    @Volatile private var auth: LocalAuth? = null
    private var coreRestartedAt = 0L
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var statsJob: Job? = null
    /** The running session's self-check; cancelled with it, so a verdict never lands on the next one. */
    private var checkJob: Job? = null
    private val main = Handler(Looper.getMainLooper())
    /** The newest start id: a teardown for an older command must not stop what a newer one started. */
    @Volatile private var lastStartId = 0
    /** A crash loop's delayed reconnect (main thread only); dropped with the service. */
    private var pendingAutoStart: Runnable? = null
    /** What the notification says now: a CONNECT that was overtaken before it arrived posts this again, not its own server. */
    @Volatile private var shown = Shown("IRNetFree", false, null)

    /**
     * [gen]: the connect this session came from — a newer one, or a disconnect, overtakes it. [startId]: its start command.
     * [lan]: the LAN share its config opens (null = none), for VpnState.lanShared.
     * [muxTested]: the fingerprints of the servers auto mode put mux on by their test (Mux.Pick.forget) — forgotten
     * when this session drops (forgetMux), so they are tested again on the next connect.
     */
    private class Launch(val engine: String, val config: String, val socksPort: Int, val gen: Long, val startId: Int, val lan: LanShare?, val muxTested: List<String> = emptyList()) {
        /** Its mux verdicts have been forgotten: one drop, one log line. */
        val muxForgotten = AtomicBoolean(false)
    }

    private class Shown(val text: String, val connected: Boolean, val action: String?)

    override fun onCreate() {
        super.onCreate()
        alive = true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId = startId
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                // disconnect() moved the generation on when it was asked
                // (EXTRA_GEN). Moving it again whenever this command arrives
                // cancelled a connect asked for AFTER the disconnect: reconnect
                // and ⚡ connect ~0.6 s later, and a busy main thread can
                // deliver this later than that. The notification's Disconnect
                // (and its Cancel while connecting) carries no generation and
                // moves it here. A connect that failed before it reached the
                // service sends this too, with ITS generation (stopOlder).
                val gen = if (intent.hasExtra(EXTRA_GEN)) intent.getLongExtra(EXTRA_GEN, 0L) else generation.stop()
                worker.execute { stopFor(gen, startId) }
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
                worker.execute { startTunnel(intent, gen, startId, unattended = false) }
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
                val why = if (intent == null) "restarted after the app was stopped" else "always-on VPN"
                val wait = if (intent == null) stickyRestartWait() else 0L
                if (wait <= 0L) {
                    goForeground("IRNetFree")
                    autoStart(gen, startId, why)
                } else {
                    // A crash loop (StickyRestart): try again later, and say when
                    // — on screen and in the notification, whose Stop ends it. A
                    // connect or a disconnect meanwhile moves the generation on
                    // and this attempt is dropped.
                    val msg = "IRNetFree stopped unexpectedly again — it reconnects by itself in ${wait / 1000} s"
                    goForeground(msg, action = "Stop")
                    VpnState.set(ConnState.ERROR, error = msg)
                    // Counted in elapsed real time, deep sleep included, and looked
                    // at every few seconds (StickyRestart.tick): a postDelayed of
                    // the whole wait runs on uptime, which stops while the phone
                    // sleeps, so the wait stretched with every minute asleep.
                    val due = SystemClock.elapsedRealtime() + wait
                    pendingRestart = true
                    val r = object : Runnable {
                        override fun run() {
                            if (gen != generation.get()) { pendingRestart = false; return }
                            val next = StickyRestart.tick(due, SystemClock.elapsedRealtime())
                            if (next > 0L) { main.postDelayed(this, next); return }
                            pendingRestart = false
                            goForeground("IRNetFree")      // the countdown and its Stop are over
                            autoStart(gen, startId, why)
                        }
                    }
                    pendingAutoStart = r
                    main.postDelayed(r, StickyRestart.tick(due, SystemClock.elapsedRealtime()))
                }
            }
        }
        return START_STICKY
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

    /** The stored selection, through the same prepare() as the Connect button — off the main thread. */
    private fun autoStart(gen: Long, startId: Int, why: String) {
        Thread {
            val intent = try {
                // The process's one Store, the screens' own (Store.get): a second
                // instance saved its copy of the lists (prepare's pins end in
                // saveServers) over whatever the UI had saved since, and the UI
                // never saw the pins. Its lists are read on the main thread,
                // where the screens write them.
                val store = Store.get(this@XrayVpnService)
                val (plan, label) = onMain { store.buildPlan() to store.selectionLabel() }   // throws when nothing usable is selected
                // Overtaken already — a disconnect, or a connect: no "Connecting…"
                // that nothing would clear (checked and set under one lock, Generation).
                if (!generation.ifCurrent(gen) { VpnState.set(ConnState.CONNECTING, label) }) { worker.execute { finishIfIdle(startId) }; return@Thread }
                VpnState.addLog("Connecting by itself ($why): $label")
                prepare(this@XrayVpnService, store, plan, label, wanted = { gen == generation.get() })
            } catch (e: Throwable) {
                Log.e(TAG, "auto start failed", e)
                val msg = "Could not connect by itself ($why): ${e.message ?: "nothing to connect to"}"
                worker.execute { fail(gen, startId, msg, notify = true) }
                return@Thread
            }
            worker.execute { startTunnel(intent, gen, startId, unattended = true) }
        }.also { it.isDaemon = true; it.name = "irnf-autostart" }.start()
    }

    /** Runs on the worker. [unattended]: nobody tapped Connect, so a failure is also a notification. */
    private fun startTunnel(intent: Intent, gen: Long, startId: Int, unattended: Boolean) {
        // Overtaken while prepare() ran: a disconnect, or a newer connect.
        if (gen != generation.get()) { VpnState.addLog("Connect superseded — not started"); finishIfIdle(startId); return }
        val config0 = intent.getStringExtra(EXTRA_CONFIG) ?: return fail(gen, startId, "empty config", unattended)
        val socksPort = intent.getIntExtra(EXTRA_SOCKS, 10808)
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

        // A connect onto a live service: the old core, hev and TUN go first.
        // Otherwise the new core cannot bind the port, hev ignores a second
        // start and keeps the dead session, and the screen says Connected.
        teardown()
        coreRestartedAt = 0L
        cancelErrorNotification()

        // "Connecting…" only while this connect is still the latest move, checked
        // and written under one lock: overtaken between the check above and here,
        // it wrote its own server's name over the newer connect's.
        if (!generation.ifCurrent(gen) { VpnState.set(ConnState.CONNECTING, label) }) {
            VpnState.addLog("Connect superseded — not started"); finishIfIdle(startId); return
        }
        VpnState.addLog("Connecting: $label")

        try {
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
            val first = Launch(engine, config, socksPort, gen, startId, lan, muxTested)
            val firstErr = startCore(first)
            val launch: Launch
            if (firstErr != null && lan != null && gen == generation.get()) {
                // The check above is check-then-bind: another app can still take
                // a LAN port before the core binds it, and a core that cannot bind
                // one does not start at all. Sharing is a convenience, the tunnel
                // is not — once more at once, without it (a failed start leaves
                // nothing running to stop first).
                val held = LocalPort.takenNow(listOf(lan.socksPort, lan.httpPort), LocalPort.ANY, graceMs = 0L)
                val why = if (held.isNotEmpty()) "port ${held.joinToString(" and ")} is in use by another app" else "the core would not start with it ($firstErr)"
                VpnState.addLog("⚠ LAN sharing skipped: $why — connecting without it; choose other ports under Settings → LAN sharing")
                launch = Launch(engine, TunnelSetup.withoutLan(config), socksPort, gen, startId, null, muxTested)
                startCore(launch)?.let { err -> return fail(gen, startId, err, unattended) }
            } else {
                launch = first
                if (firstErr != null) return fail(gen, startId, firstErr, unattended)
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
            // and the core just started must not be left running.
            val fd = builder.establish() ?: return fail(gen, startId, "Android refused the VPN interface — VPN permission missing, or another VPN app holds it", unattended)
            tun = fd
            VpnState.addLog("TUN up (fd=${fd.fd}) · resolver ${dns.joinToString(", ")}")

            // 3) hev tun2socks: TUN fd -> local SOCKS, with the session's credentials
            val cfgPath = writeTun2socksConfig(socksPort, ipv6, sessionAuth)
            TProxyService.TProxyStartService(cfgPath, fd.fd)   // JNI runs on its own thread
            tunnelRunning = true
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
            updateNotification(label, true)
            launch.lan?.let { l: LanShare -> logLan(l) }
            startStatsLoop()
            selfCheck(launch)
            Log.i(TAG, "tunnel up: $label")
        } catch (e: Throwable) {
            Log.e(TAG, "startTunnel failed", e)
            fail(gen, startId, e.message ?: "connect failed", unattended)
        }
    }

    /**
     * A muxed session that broke — its core exited by itself, it carried
     * nothing, or it stalled (spec §4: "when a muxed connection drops, its
     * servers are tested again on the next connect"): the verdicts that put mux
     * on it are forgotten. Only auto's (Launch.muxTested), once per session.
     * Prefs only — any thread.
     */
    private fun forgetMux(l: Launch, why: String) {
        if (l.muxTested.isEmpty() || l.muxForgotten.getAndSet(true)) return
        runCatching { Store.get(this).forgetMux(l.muxTested) }
            .onFailure { e -> Log.w(TAG, "could not forget the mux verdicts: ${e.message}") }
        VpnState.addLog("Mux: $why while muxed — its server is tested for mux again on the next connect")
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
                if (!x.start(l.config, 0)) { runCatching { x.stop() }; return "Xray core failed to start — see logs (More → Logs)." }
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
        worker.execute {
            if (core !== singbox && core !== pattn) return@execute     // stopped or replaced meanwhile
            val l = running ?: return@execute
            val name = if (core === singbox) "sing-box" else "Xray-PattN"
            if (core === singbox) { singbox = null } else { pattn = null }
            VpnState.addLog("⚠ The $name core exited by itself (code $code)")
            forgetMux(l, "the connection dropped")
            if (l.gen != generation.get()) { dropOvertaken(l, "Not restarting it — a disconnect or a new connect is next"); return@execute }
            val now = SystemClock.elapsedRealtime()
            if (coreRestartedAt != 0L && now - coreRestartedAt < 60_000) {
                fail(l.gen, lastStartId, "The $name core stopped again (exit code $code) — reconnect, or see More → Logs", notify = true)
                return@execute
            }
            coreRestartedAt = now
            VpnState.addLog("Restarting the $name core — the tunnel stays up meanwhile")
            val err = startCore(l)
            // Overtaken while it restarted: a core that came back carries the
            // tunnel until the command queued behind this replaces it; one that
            // did not leaves nothing worth keeping up.
            if (l.gen != generation.get()) {
                if (err != null) dropOvertaken(l, "The $name core did not come back — $err")
                return@execute
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
                VpnState.setHealth(false, "Server unreachable — try another config")
                forgetMux(l, "the connection carried nothing")
                return@launch
            }
            val ip = runCatching { Diagnostics.ipInfo(socksPort) }.getOrNull()
            if (running !== l) return@launch
            val where = ip?.takeIf { it.ok }?.let { " · exit ${it.ip} ${it.country}" } ?: ""
            VpnState.addLog("✓ Self-check: core reaches the internet (${ms}ms)$where")
            VpnState.setHealth(true, "Working${if (where.isBlank()) "" else " ·"} ${ip?.takeIf { it.ok }?.let { "${it.country} ${it.ip}" } ?: "${ms}ms"}")
            delay(12_000)
            if (!tunnelRunning || running !== l) return@launch
            val st = runCatching { TProxyService.TProxyGetStats() }.getOrNull()
            val tx = if (st != null && st.size >= 4) st[1] else -1
            val rx = if (st != null && st.size >= 4) st[3] else -1
            when {
                tx < 0 -> VpnState.addLog("? Tunnel stats unavailable (tun2socks may not be running).")
                tx == 0L -> { VpnState.addLog("✗ Tunnel: no packets entered the TUN in 12s — other apps aren't being routed into the VPN."); VpnState.setHealth(false, "Apps aren't reaching the tunnel") }
                rx == 0L -> { VpnState.addLog("✗ Tunnel: sent $tx B but received 0 — packets enter the TUN but nothing returns."); VpnState.setHealth(false, "Tunnel stalled — no data returning"); forgetMux(l, "the connection stalled") }
                else -> VpnState.addLog("✓ Tunnel carrying traffic (↑$tx B ↓$rx B).")
            }
        }
    }

    private fun startStatsLoop() {
        statsJob?.cancel()
        statsJob = scope.launch {
            var lastTx = 0L; var lastRx = 0L; var first = true
            while (isActive && tunnelRunning) {
                val st = runCatching { TProxyService.TProxyGetStats() }.getOrNull()
                if (st != null && st.size >= 4) {
                    val tx = st[1]; val rx = st[3]   // [tx_pkts, tx_bytes, rx_pkts, rx_bytes]
                    val txSpeed = if (first) 0 else (tx - lastTx).coerceAtLeast(0)
                    val rxSpeed = if (first) 0 else (rx - lastRx).coerceAtLeast(0)
                    lastTx = tx; lastRx = rx; first = false
                    VpnState.setTraffic(Traffic(tx, rx, txSpeed, rxSpeed))
                }
                delay(1000)
            }
        }
    }

    /** Core, hev, TUN and credentials down. Runs on the worker; the service and the screen are left alone. */
    private fun teardown() {
        statsJob?.cancel(); statsJob = null
        checkJob?.cancel(); checkJob = null
        running = null
        VpnState.setLanShared(null)
        if (tunnelRunning) { runCatching { TProxyService.TProxyStopService() }; tunnelRunning = false }
        runCatching { xray?.stop() }; xray = null
        runCatching { singbox?.stop() }; singbox = null
        runCatching { pattn?.stop() }; pattn = null
        runCatching { tun?.close() }; tun = null
        LocalProxyAuth.release(auth); auth = null
    }

    private fun live() = tunnelRunning || tun != null || xray != null || singbox != null || pattn != null

    /**
     * The teardown a disconnect asked for: the tunnel down and the service
     * stopped. Its Not connected goes up only while that disconnect is still
     * the latest move (checked and written under the generation lock):
     * reconnect and ⚡ connect ~0.6 s after it, and a teardown landing later
     * than that put "Not protected" over the new connect's CONNECTING (a tap
     * then started yet another connect) or erased its prepare's ERROR.
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
     * newer connect already brought up is not its to touch.
     */
    private fun fail(gen: Long, startId: Int, error: String, notify: Boolean) {
        val newer = !Generation.reaches(gen, running?.gen)
        if (!newer) teardown()
        if (generation.ifCurrent(gen) { VpnState.set(ConnState.ERROR, error = error) }) {
            if (notify) notifyError(error)
            finish(startId)
        } else {
            VpnState.addLog("⚠ $error — a disconnect or another connect has been asked for since")
            if (!newer) finishIfIdle(startId)
        }
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
            stopSelf(startId)
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
        worker.execute { stopAll(id) }
    }

    override fun onDestroy() {
        alive = false
        pendingAutoStart?.let { main.removeCallbacks(it) }; pendingAutoStart = null; pendingRestart = false
        runCatching { scope.cancel() }
        // Normally everything is already down (stopAll ran first). Stopped some
        // other way, the tunnel still goes — on the worker, after whatever it is
        // doing, and without touching a state a newer start may already own.
        worker.execute {
            if (live()) {
                val g = running?.gen
                teardown()
                if (g != null) generation.ifCurrent(g) { VpnState.set(ConnState.DISCONNECTED, "") }
            }
        }
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

    /** A failure nobody may be watching the app for (always-on at boot, a core that died): it stays in the shade. */
    private fun notifyError(msg: String) {
        runCatching {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "VPN status", NotificationManager.IMPORTANCE_LOW))
            val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            nm.notify(NOTIF_ERR_ID, Notification.Builder(this, CHANNEL)
                .setContentTitle("IRNetFree • Not connected")
                .setContentText(msg)
                .setStyle(Notification.BigTextStyle().bigText(msg))
                .setSmallIcon(com.irnetfree.vpn.R.drawable.ic_stat_vpn)
                .setContentIntent(open)
                .setAutoCancel(true)
                .build())
        }
    }

    private fun cancelErrorNotification() {
        runCatching { (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).cancel(NOTIF_ERR_ID) }
    }

    private fun buildNotification(text: String, connected: Boolean, action: String? = if (connected) "Disconnect" else null): Notification {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "VPN status", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val disconnect = PendingIntent.getService(this, 1,
            Intent(this, XrayVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val b = Notification.Builder(this, CHANNEL)
            .setContentTitle("IRNetFree" + if (connected) " • Connected" else "")
            .setContentText(text)
            .setSmallIcon(com.irnetfree.vpn.R.drawable.ic_stat_vpn)
            .setOngoing(true)
            .setContentIntent(open)
        if (action != null) {
            val icon = android.graphics.drawable.Icon.createWithResource(this, com.irnetfree.vpn.R.drawable.ic_stat_vpn)
            b.addAction(Notification.Action.Builder(icon, action, disconnect).build())
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
        /** The fingerprints a drop of this session forgets (Mux.Pick.forget); absent = none. */
        const val EXTRA_MUX = "muxTested"

        /** Moved on by every connect and disconnect: a prepare or a start carrying an older value was overtaken. */
        private val generation = Generation()

        @Volatile private var pendingRestart = false

        /** An instance exists (onCreate … onDestroy): a failed connect has something to stop only then. */
        @Volatile private var alive = false

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
         * Build the plan and the config, then start the service. Runs its network
         * steps (certificate pins, WireGuard endpoints) on a worker thread: they
         * are TLS dials and DNS lookups, and the caller is the UI. The state is
         * CONNECTING from the first line, so the screen already shows it.
         * Cancelling — disconnect() while this runs — really cancels: the
         * service is never started for a connect that was overtaken.
         *
         * Onto a live tunnel this is a switch: the service takes the old one
         * down itself when the new one's turn comes (startTunnel), so no
         * disconnect() is needed first. The move is made FIRST, even for a
         * selection that cannot be built: an older connect still in prepare()
         * then stops there instead of finishing later and taking over. A
         * connect that fails at any point before the service also takes down
         * a tunnel an older connect left up (stopOlder) — it carried the old
         * server under the new one's error, notification still "Connected".
         */
        fun connect(ctx: Context, store: Store) {
            val label = store.selectionLabel()
            val gen = generation.next { VpnState.set(ConnState.CONNECTING, label) }
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

        /** What prepare() reads from the store in one go, on the main thread. */
        private class Fresh(val plan: ConnectionPlan, val settings: AppSettings, val pool: List<PoolEntry>)

        /**
         * Everything before the service: pins, endpoints, mux, the config. Blocks; never on the main thread.
         * [wanted]: false once this connect has been overtaken — the mux test then starts nothing more.
         */
        fun prepare(ctx: Context, store: Store, plan0: ConnectionPlan, label: String, wanted: () -> Boolean = { true }): Intent {
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
            val pins = CertPin.learn(plan0, System.currentTimeMillis(),
                fetch = { srv -> CertPin.fetchLeafPin(srv.address, srv.port, CertPin.sniOf(srv)) },
                log = { line -> VpnState.addLog(line) })
            val fresh = onMain {
                if (CertPin.applyPins(store.servers, pins)) store.saveServers()
                Fresh(plan0.withRecords { id: String -> store.serverById(id) }, store.settings, store.pool.toList())
            }
            val plan = fresh.plan
            val s = fresh.settings

            // Which core, exactly as the desktop decides it (EngineChoice.kt):
            // a single server takes its own choice, and a chain/pool/advanced plan
            // runs on PattN as soon as ANY server in it asks for PattN. Whether
            // that core is bundled for this ABI is asked separately below.
            var engine = EngineChoice.chooseEngine(plan, s.defaultEngine)
            val single = plan as? ConnectionPlan.Single

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
            // here once (a throwaway core, at most 8 s) when it has no fresh
            // verdict. sing-box and a chain's hops never get it; off, the
            // config is the one of before.
            val mux = if (engine == EngineChoice.SINGBOX) Mux.Pick.NONE else Mux.choose(
                mode = store.muxMode, connection = plan, cache = store.muxProbes,
                now = { System.currentTimeMillis() },
                test = { srv: ServerConfig -> XrayTester.probeMux(ctx, srv, s, wanted) },
                remember = { fp: String, p: Mux.Probe -> store.rememberMux(fp, p) },
                log = { line: String -> VpnState.addLog(line) },
                wanted = wanted
            )
            // This session's credentials for the tunnel's own inbounds (LocalAuth.kt):
            // hev and the app's clients present them, no other app has them.
            val auth = LocalAuth.random()
            // LAN sharing, when on and when it fits beside this connection's own
            // ports (the tunnel's may have been moved onto it since it was set).
            val lan = lanShareFor(ctx, s, fresh.pool)
            val built = TunnelSetup.coreConfig(engine, plan, s, geo, wgIps, auth, lan, muxIds = mux.ids,
                coreVersion = { e -> if (e == EngineChoice.PATTN) XrayPattnCore.version(ctx) else XrayCore.version() }) { line -> VpnState.addLog(line) }
            engine = built.engine
            val config = built.json

            // What the OS resolves at: the tunnel peer under managed DNS (every
            // query enters the TUN and dns-out answers it), the user's own public
            // resolvers otherwise. A sing-box-format config carries no hijack.
            val hijacks = engine != EngineChoice.SINGBOX
            val adapterDns = DnsPlan.adapterDnsServers(s, if (hijacks) TUN_DNS4 else null)

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
                if (mux.forget.isNotEmpty() && built.engine != EngineChoice.SINGBOX) putStringArrayListExtra(EXTRA_MUX, ArrayList(mux.forget))
            }
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

        fun disconnect(ctx: Context) {
            val gen = generation.stop()            // a connect still in prepare() stops there
            val sent = runCatching { ctx.startService(Intent(ctx, XrayVpnService::class.java).setAction(ACTION_DISCONNECT).putExtra(EXTRA_GEN, gen)) }
            // Android refuses a background start only when no foreground service
            // of ours runs — so no tunnel is up. Not connected, then, now: a
            // "Connecting…" of a connect still in prepare() would stay up for
            // good, since that connect stops there without a word.
            if (sent.isFailure) generation.ifCurrent(gen) { VpnState.set(ConnState.DISCONNECTED, "") }
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
