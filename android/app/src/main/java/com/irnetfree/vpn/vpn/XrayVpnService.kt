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
import com.irnetfree.vpn.core.CertPin
import com.irnetfree.vpn.core.ConfigBuilder
import com.irnetfree.vpn.core.ConnectionPlan
import com.irnetfree.vpn.core.DnsPlan
import com.irnetfree.vpn.core.EngineChoice
import com.irnetfree.vpn.core.LocalAuth
import com.irnetfree.vpn.core.LocalProxyAuth
import com.irnetfree.vpn.core.SingboxConfig
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
import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.FutureTask
import java.util.concurrent.atomic.AtomicLong

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
    private val main = Handler(Looper.getMainLooper())
    /** The newest start id: a teardown for an older command must not stop what a newer one started. */
    @Volatile private var lastStartId = 0
    /** A crash loop's delayed reconnect (main thread only); dropped with the service. */
    private var pendingAutoStart: Runnable? = null

    /** [gen]: the connect this session came from — a newer one, or a disconnect, overtakes it. */
    private class Launch(val engine: String, val config: String, val socksPort: Int, val gen: Long)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId = startId
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                // disconnect() moved the generation on when it was asked
                // (EXTRA_GEN). Moving it again whenever this command arrives
                // cancelled a connect asked for AFTER the disconnect: reconnect
                // and ⚡ connect ~0.6 s later, and a busy main thread can
                // deliver this later than that. The notification's Disconnect
                // carries no generation and moves it here.
                if (!intent.hasExtra(EXTRA_GEN)) stopGeneration()
                worker.execute { stopAll(startId) }
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                val gen = if (intent.hasExtra(EXTRA_GEN)) intent.getLongExtra(EXTRA_GEN, 0L) else nextGeneration()
                goForeground(intent.getStringExtra(EXTRA_LABEL) ?: "IRNetFree")
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
                val gen = nextGeneration()
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
                    val r = Runnable { if (gen == generation.get()) autoStart(gen, startId, why) }
                    pendingAutoStart = r
                    main.postDelayed(r, wait)
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
                // Overtaken already — a disconnect, or a connect: no "Connecting…" that nothing would clear.
                if (!connectingIfCurrent(gen, label)) { worker.execute { finishIfIdle(startId) }; return@Thread }
                VpnState.addLog("Connecting by itself ($why): $label")
                prepare(this@XrayVpnService, store, plan, label)
            } catch (e: Throwable) {
                Log.e(TAG, "auto start failed", e)
                val msg = "Could not connect by itself ($why): ${e.message ?: "nothing to connect to"}"
                worker.execute { if (gen == generation.get()) stopAll(startId, msg, notify = true) else finishIfIdle(startId) }
                return@Thread
            }
            worker.execute { startTunnel(intent, gen, startId, unattended = true) }
        }.also { it.isDaemon = true; it.name = "irnf-autostart" }.start()
    }

    /** Runs on the worker. [unattended]: nobody tapped Connect, so a failure is also a notification. */
    private fun startTunnel(intent: Intent, gen: Long, startId: Int, unattended: Boolean) {
        // Overtaken while prepare() ran: a disconnect, or a newer connect.
        if (gen != generation.get()) { VpnState.addLog("Connect superseded — not started"); finishIfIdle(startId); return }
        val config = intent.getStringExtra(EXTRA_CONFIG) ?: return stopAll(startId, "empty config", unattended)
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

        // A connect onto a live service: the old core, hev and TUN go first.
        // Otherwise the new core cannot bind the port, hev ignores a second
        // start and keeps the dead session, and the screen says Connected.
        teardown()
        coreRestartedAt = 0L
        cancelErrorNotification()

        VpnState.set(ConnState.CONNECTING, label)
        VpnState.addLog("Connecting: $label")

        try {
            if (!TProxyService.available) return stopAll(startId, "Tunnel core (libhev-socks5-tunnel.so) missing.", unattended)
            // The app's own clients through this tunnel (the self-check, the
            // latency and exit checks, a subscription fetch) present these.
            if (sessionAuth != null) { LocalProxyAuth.set(socksPort, sessionAuth); auth = sessionAuth }

            // 1) Proxy core with a local SOCKS inbound (no internal tun).
            //    EngineChoice already decided which, and prepare() already checked
            //    it is bundled for this ABI; anything else here is a real failure.
            val launch = Launch(engine, config, socksPort, gen)
            startCore(launch)?.let { return stopAll(startId, it, unattended) }
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
            val fd = builder.establish() ?: return stopAll(startId, "Android refused the VPN interface — VPN permission missing, or another VPN app holds it", unattended)
            tun = fd
            VpnState.addLog("TUN up (fd=${fd.fd}) · resolver ${dns.joinToString(", ")}")

            // 3) hev tun2socks: TUN fd -> local SOCKS, with the session's credentials
            val cfgPath = writeTun2socksConfig(socksPort, ipv6, sessionAuth)
            TProxyService.TProxyStartService(cfgPath, fd.fd)   // JNI runs on its own thread
            tunnelRunning = true
            running = launch
            VpnState.addLog("tun2socks started")

            VpnState.set(ConnState.CONNECTED, label)
            VpnState.addLog("Connected")
            updateNotification(label, true)
            startStatsLoop()
            selfCheck(socksPort)
            Log.i(TAG, "tunnel up: $label")
        } catch (e: Throwable) {
            Log.e(TAG, "startTunnel failed", e)
            stopAll(startId, e.message ?: "connect failed", unattended)
        }
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
     * a core it stops anyway.
     */
    private fun onCoreExit(core: Any, code: Int) {
        worker.execute {
            if (core !== singbox && core !== pattn) return@execute     // stopped or replaced meanwhile
            val l = running ?: return@execute
            val name = if (core === singbox) "sing-box" else "Xray-PattN"
            VpnState.addLog("⚠ The $name core exited by itself (code $code)")
            if (l.gen != generation.get()) { VpnState.addLog("Not restarting it — a disconnect or a new connect is next"); return@execute }
            if (core === singbox) { singbox = null } else { pattn = null }
            val now = SystemClock.elapsedRealtime()
            if (coreRestartedAt != 0L && now - coreRestartedAt < 60_000) {
                stopAll(lastStartId, "The $name core stopped again (exit code $code) — reconnect, or see More → Logs", notify = true)
                return@execute
            }
            coreRestartedAt = now
            VpnState.addLog("Restarting the $name core — the tunnel stays up meanwhile")
            val err = startCore(l)
            // Overtaken while it restarted: the command queued behind this takes it from here.
            if (l.gen != generation.get()) return@execute
            if (err == null) VpnState.addLog("✓ The $name core is back")
            else stopAll(lastStartId, "The $name core stopped (exit code $code) and did not come back — $err", notify = true)
        }
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
     */
    private fun selfCheck(socksPort: Int) {
        scope.launch {
            val ms = Diagnostics.httpLatency(socksPort)
            if (ms < 0) {
                VpnState.addLog("✗ Self-check: the core could NOT reach the internet — the server/config is the problem (not the tunnel).")
                VpnState.setHealth(false, "Server unreachable — try another config")
                return@launch
            }
            val ip = runCatching { Diagnostics.ipInfo(socksPort) }.getOrNull()
            val where = ip?.takeIf { it.ok }?.let { " · exit ${it.ip} ${it.country}" } ?: ""
            VpnState.addLog("✓ Self-check: core reaches the internet (${ms}ms)$where")
            VpnState.setHealth(true, "Working${if (where.isBlank()) "" else " ·"} ${ip?.takeIf { it.ok }?.let { "${it.country} ${it.ip}" } ?: "${ms}ms"}")
            delay(12_000)
            if (!tunnelRunning) return@launch
            val st = runCatching { TProxyService.TProxyGetStats() }.getOrNull()
            val tx = if (st != null && st.size >= 4) st[1] else -1
            val rx = if (st != null && st.size >= 4) st[3] else -1
            when {
                tx < 0 -> VpnState.addLog("? Tunnel stats unavailable (tun2socks may not be running).")
                tx == 0L -> { VpnState.addLog("✗ Tunnel: no packets entered the TUN in 12s — other apps aren't being routed into the VPN."); VpnState.setHealth(false, "Apps aren't reaching the tunnel") }
                rx == 0L -> { VpnState.addLog("✗ Tunnel: sent $tx B but received 0 — packets enter the TUN but nothing returns."); VpnState.setHealth(false, "Tunnel stalled — no data returning") }
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
        running = null
        if (tunnelRunning) { runCatching { TProxyService.TProxyStopService() }; tunnelRunning = false }
        runCatching { xray?.stop() }; xray = null
        runCatching { singbox?.stop() }; singbox = null
        runCatching { pattn?.stop() }; pattn = null
        runCatching { tun?.close() }; tun = null
        LocalProxyAuth.release(auth); auth = null
    }

    private fun live() = tunnelRunning || tun != null || xray != null || singbox != null || pattn != null

    /**
     * Take the tunnel down and stop the service. With [error], ERROR and its
     * message stay on screen through the teardown — DISCONNECTED used to
     * overwrite them on the very next line, so every failure in here reached
     * the user as "Not protected" and nothing else — and with [notify] a
     * notification says it too, for when nobody is looking at the app.
     */
    private fun stopAll(startId: Int, error: String? = null, notify: Boolean = false) {
        teardown()
        if (error != null) {
            VpnState.set(ConnState.ERROR, error = error)
            if (notify) notifyError(error)
        } else {
            VpnState.set(ConnState.DISCONNECTED, "")
        }
        finish(startId)
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
        if (generation.get() == stoppedGen && VpnState.state.value == ConnState.CONNECTING) VpnState.set(ConnState.DISCONNECTED, "")
        finish(startId)
    }

    override fun onRevoke() {
        // Another VPN took over, or the user switched this one off in Android's
        // settings. (VpnService's own onRevoke is a bare stopSelf(); finish() does it here.)
        stopGeneration()
        val id = lastStartId
        worker.execute { stopAll(id) }
    }

    override fun onDestroy() {
        pendingAutoStart?.let { main.removeCallbacks(it) }; pendingAutoStart = null
        runCatching { scope.cancel() }
        // Normally everything is already down (stopAll ran first). Stopped some
        // other way, the tunnel still goes — on the worker, after whatever it is
        // doing, and without touching a state a newer start may already own.
        worker.execute { if (live()) { teardown(); VpnState.set(ConnState.DISCONNECTED, "") } }
        super.onDestroy()
    }

    /* ----------------------------- notification ----------------------------- */
    /** [action]: a button on it that sends ACTION_DISCONNECT (a crash loop's wait offers "Stop"). */
    private fun goForeground(label: String, action: String? = null) {
        runCatching { startForeground(NOTIF_ID, buildNotification(label, false, action)) }
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
        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIF_ID, buildNotification(text, connected))
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

        /** Moved on by every connect and disconnect: a prepare or a start carrying an older value was overtaken. */
        private val generation = AtomicLong(0)

        /** The generation the last disconnect moved to: while it is still the current one, no connect is pending. */
        @Volatile private var stoppedGen = -1L

        /** A connect moves the generation on — under the lock connectingIfCurrent takes. */
        private fun nextGeneration(): Long = synchronized(generation) { generation.incrementAndGet() }

        /** So does a disconnect, and it is remembered as one (finishIfIdle). */
        private fun stopGeneration(): Long = synchronized(generation) { generation.incrementAndGet().also { stoppedGen = it } }

        /**
         * CONNECTING for [gen] — only while it is still the current generation,
         * checked and set under the lock every move of it takes. Set without the
         * check, an unattended start that a disconnect had already overtaken
         * put up a "Connecting…" that nothing would ever clear.
         */
        private fun connectingIfCurrent(gen: Long, label: String): Boolean = synchronized(generation) {
            if (gen != generation.get()) false else { VpnState.set(ConnState.CONNECTING, label); true }
        }

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
         */
        fun connect(ctx: Context, store: Store) {
            val plan = store.buildPlan()          // throws with a user-facing message; the caller reports it
            val label = store.selectionLabel()
            val gen = nextGeneration()
            Thread {
                try {
                    val intent = prepare(ctx, store, plan, label)
                    if (gen != generation.get()) { VpnState.addLog("Connect cancelled"); return@Thread }
                    intent.putExtra(EXTRA_GEN, gen)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(intent) else ctx.startService(intent)
                } catch (e: Throwable) {
                    Log.e(TAG, "connect failed", e)
                    if (gen == generation.get()) VpnState.set(ConnState.ERROR, error = e.message ?: "connect failed")
                }
            }.also { it.isDaemon = true; it.name = "irnf-connect" }.start()
        }

        /** Everything before the service: pins, endpoints, the config. Blocks; never on the main thread. */
        fun prepare(ctx: Context, store: Store, plan0: ConnectionPlan, label: String): Intent {
            // Certificate pinning on first use (CertPin.kt): a server whose link
            // asked for allowInsecure is dialled once, its leaf certificate hashed
            // and stored; the config then pins it. The core refuses allowInsecure
            // itself, so without this such a server never connected at all.
            //
            // The dials run here; the store takes the result on the main thread,
            // by id (CertPin.applyPins). This thread used to write the list by an
            // index it had looked up earlier, while a subscription refresh could
            // be replacing that very list on the main thread (clear + addAll).
            // The plan holds copies of the records, so it is rebuilt from the
            // store afterwards and the pins learnt just now reach the config.
            val pins = CertPin.learn(plan0, System.currentTimeMillis(),
                fetch = { srv -> CertPin.fetchLeafPin(srv.address, srv.port, CertPin.sniOf(srv)) },
                log = { line -> VpnState.addLog(line) })
            val (plan, s) = onMain {
                if (CertPin.applyPins(store.servers, pins)) store.saveServers()
                store.buildPlan() to store.settings
            }

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
            // This session's credentials for the tunnel's own inbounds (LocalAuth.kt):
            // hev and the app's clients present them, no other app has them.
            val auth = LocalAuth.random()
            val config: String = if (engine == EngineChoice.SINGBOX && single != null) {
                try { SingboxConfig.build(single.server, s, auth).toString() }
                catch (e: Throwable) { engine = EngineChoice.XRAY; VpnState.addLog("sing-box: ${e.message} — using the in-process core"); ConfigBuilder.build(plan, s, geoAssets = geo, wgEndpointIps = wgIps, inboundAuth = auth).toString() }
            } else {
                ConfigBuilder.build(plan, s, geoAssets = geo, wgEndpointIps = wgIps, inboundAuth = auth).toString()
            }

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
            }
        }

        /** The WireGuard endpoint names of the plan resolved through TrustedDns; logged as the desktop does. */
        private fun resolveWgEndpoints(plan: ConnectionPlan, s: com.irnetfree.vpn.core.AppSettings): Map<String, String> {
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
            val gen = stopGeneration()            // a connect still in prepare() stops there
            ctx.startService(Intent(ctx, XrayVpnService::class.java).setAction(ACTION_DISCONNECT).putExtra(EXTRA_GEN, gen))
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
