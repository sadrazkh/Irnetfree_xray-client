package com.irnetfree.vpn.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.irnetfree.vpn.core.ConfigBuilder
import com.irnetfree.vpn.core.ConnectionPlan
import com.irnetfree.vpn.core.SingboxConfig
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

/**
 * Whole-device tunnel:
 *   1. Xray-core runs in-process with a local SOCKS inbound (tunFd=0, no internal tun).
 *   2. VpnService establishes a TUN; our own app package is EXCLUDED from the VPN
 *      so xray's outbound sockets bypass the tunnel (no protect needed).
 *   3. hev-socks5-tunnel reads the TUN fd and forwards all packets to xray's SOCKS.
 */
class XrayVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var xray: XrayCore? = null
    private var singbox: SingboxCore? = null
    private var tunnelRunning = false
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var statsJob: Job? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> { stopAll(); return START_NOT_STICKY }
            ACTION_CONNECT -> startTunnel(intent)
        }
        return START_STICKY
    }

    private fun startTunnel(intent: Intent) {
        val config = intent.getStringExtra(EXTRA_CONFIG) ?: return fail("empty config")
        val socksPort = intent.getIntExtra(EXTRA_SOCKS, 10808)
        val dns = intent.getStringArrayListExtra(EXTRA_DNS) ?: arrayListOf("1.1.1.1", "8.8.8.8")
        val label = intent.getStringExtra(EXTRA_LABEL) ?: "IRNetFree"
        val ipv6 = intent.getBooleanExtra(EXTRA_IPV6, false)
        val perAppMode = intent.getStringExtra(EXTRA_PERAPP_MODE) ?: "off"
        val perApps = intent.getStringArrayListExtra(EXTRA_PERAPPS) ?: arrayListOf()
        val engine = intent.getStringExtra(EXTRA_ENGINE) ?: "xray"

        VpnState.set(ConnState.CONNECTING, label)
        VpnState.addLog("Connecting: $label")
        runCatching { startForeground(NOTIF_ID, buildNotification(label, false)) }
            .onFailure { VpnState.addLog("startForeground failed: ${it.message}") }

        try {
            // 1) Proxy core with a local SOCKS inbound (no internal tun). The core
            //    is chosen per-config: sing-box (subprocess) or Xray (in-process).
            if (engine == "sing-box") {
                if (!SingboxCore.available(this)) { fail("sing-box core is not bundled for this device."); stopAll(); return }
                val sb = SingboxCore()
                val started = sb.start(this, config, socksPort) { s -> VpnState.addLog(s) }
                if (!started) { fail("sing-box core failed to start — see logs (More → Logs)."); stopAll(); return }
                singbox = sb
                VpnState.addLog("✓ Running on sing-box core (socks=$socksPort)")
            } else {
                if (!XrayCore.available) { fail("Xray core (libv2ray) is not bundled."); stopAll(); return }
                xray = XrayCore(onStatus = { _, s -> if (!s.isNullOrBlank()) VpnState.addLog(s) })
                if (!xray!!.start(config, 0)) { fail("Xray core failed to start — see logs (More → Logs)."); stopAll(); return }
                // startLoop() returning true only means the core booted; make sure it
                // is really listening before we point the tunnel at it.
                if (!waitForPort(socksPort)) {
                    fail("Xray started but its SOCKS port $socksPort never opened — see logs.")
                    stopAll(); return
                }
                VpnState.addLog("✓ Running on Xray core (socks=$socksPort ready)")
            }

            // 2) TUN — exclude our own app so xray's sockets bypass the tunnel
            val builder = Builder()
                .setSession(label)
                .setMtu(TUN_MTU)
                .addAddress(TUN_ADDR4, 30)
                .addRoute("0.0.0.0", 0)
            if (ipv6) { builder.addAddress(TUN_ADDR6, 126); builder.addRoute("::", 0) }
            dns.forEach { runCatching { builder.addDnsServer(it) } }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
            applyPerApp(builder, perAppMode, perApps)

            val fd = builder.establish() ?: return fail("TUN establish failed")
            tun = fd
            VpnState.addLog("TUN up (fd=${fd.fd})")

            // 3) hev tun2socks: TUN fd -> local SOCKS
            if (!TProxyService.available) { fail("Tunnel core (libhev-socks5-tunnel.so) missing."); stopAll(); return }
            val cfgPath = writeTun2socksConfig(socksPort, ipv6)
            TProxyService.TProxyStartService(cfgPath, fd.fd)   // JNI runs on its own thread
            tunnelRunning = true
            VpnState.addLog("tun2socks started")

            VpnState.set(ConnState.CONNECTED, label)
            VpnState.addLog("Connected")
            updateNotification(label, true)
            startStatsLoop()
            selfCheck(socksPort)
            Log.i(TAG, "tunnel up: $label")
        } catch (e: Throwable) {
            Log.e(TAG, "startTunnel failed", e)
            fail(e.message ?: "connect failed"); stopAll()
        }
    }

    private fun applyPerApp(b: Builder, mode: String, apps: List<String>) {
        when {
            mode == "allow" && apps.isNotEmpty() -> for (p in apps) runCatching { b.addAllowedApplication(p) }
            mode == "disallow" -> { for (p in apps) runCatching { b.addDisallowedApplication(p) }; runCatching { b.addDisallowedApplication(packageName) } }
            else -> runCatching { b.addDisallowedApplication(packageName) }
        }
    }

    private fun writeTun2socksConfig(socksPort: Int, ipv6: Boolean): String {
        val yaml = buildString {
            append("tunnel:\n  mtu: $TUN_MTU\n  ipv4: $TUN_ADDR4\n")
            if (ipv6) append("  ipv6: '$TUN_ADDR6'\n")
            append("socks5:\n  port: $socksPort\n  address: 127.0.0.1\n  udp: 'udp'\n")
            append("misc:\n  task-stack-size: 20480\n  connect-timeout: 5000\n  read-write-timeout: 60000\n  log-level: warn\n")
        }
        val f = File(filesDir, "tun2socks.yml"); f.writeText(yaml); return f.absolutePath
    }

    /** Block until 127.0.0.1:port accepts a connection (or we give up). */
    private fun waitForPort(port: Int, timeoutMs: Long = 5000): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            try { java.net.Socket().use { it.connect(java.net.InetSocketAddress("127.0.0.1", port), 300); return true } }
            catch (e: Exception) { try { Thread.sleep(150) } catch (i: InterruptedException) { return false } }
        }
        return false
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

    private fun stopAll() {
        statsJob?.cancel(); statsJob = null
        if (tunnelRunning) { runCatching { TProxyService.TProxyStopService() }; tunnelRunning = false }
        runCatching { xray?.stop() }; xray = null
        runCatching { singbox?.stop() }; singbox = null
        runCatching { tun?.close() }; tun = null
        VpnState.set(ConnState.DISCONNECTED, "")
        stopForegroundCompat(); stopSelf()
    }

    private fun fail(msg: String) { VpnState.set(ConnState.ERROR, error = msg) }
    override fun onRevoke() { stopAll(); super.onRevoke() }
    override fun onDestroy() { runCatching { scope.cancel() }; stopAll(); super.onDestroy() }

    /* ----------------------------- notification ----------------------------- */
    private fun buildNotification(text: String, connected: Boolean): Notification {
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
        if (connected) {
            val icon = android.graphics.drawable.Icon.createWithResource(this, com.irnetfree.vpn.R.drawable.ic_stat_vpn)
            b.addAction(Notification.Action.Builder(icon, "Disconnect", disconnect).build())
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
        private const val TUN_ADDR4 = "172.19.0.1"
        private const val TUN_ADDR6 = "fdfe:dcba:9876::1"
        private const val TUN_MTU = 1500

        const val ACTION_CONNECT = "com.irnetfree.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.irnetfree.vpn.DISCONNECT"
        const val EXTRA_CONFIG = "config"; const val EXTRA_SOCKS = "socks"; const val EXTRA_DNS = "dns"
        const val EXTRA_LABEL = "label"; const val EXTRA_IPV6 = "ipv6"; const val EXTRA_ENGINE = "engine"
        const val EXTRA_PERAPP_MODE = "perAppMode"; const val EXTRA_PERAPPS = "perApps"

        fun connect(ctx: Context, store: Store) {
            val plan = store.buildPlan()
            val s = store.settings

            // Per-config core: only a single server can pick sing-box, and only
            // when its binary is bundled for this device — otherwise use Xray.
            var engine = "xray"
            val single = plan as? ConnectionPlan.Single
            val config: String = if (single != null && single.server.engine == "sing-box" && SingboxCore.available(ctx)) {
                try { engine = "sing-box"; SingboxConfig.build(single.server, s).toString() }
                catch (e: Throwable) { engine = "xray"; VpnState.addLog("sing-box: ${e.message} — using Xray"); ConfigBuilder.build(plan, s, geoAssets = false).toString() }
            } else {
                ConfigBuilder.build(plan, s, geoAssets = false).toString()
            }

            val i = Intent(ctx, XrayVpnService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_CONFIG, config)
                putExtra(EXTRA_ENGINE, engine)
                putExtra(EXTRA_SOCKS, s.socksPort)
                putStringArrayListExtra(EXTRA_DNS, ArrayList(s.dns))
                putExtra(EXTRA_LABEL, store.selectionLabel())
                putExtra(EXTRA_IPV6, s.ipv6)
                putExtra(EXTRA_PERAPP_MODE, s.perAppMode)
                putStringArrayListExtra(EXTRA_PERAPPS, ArrayList(s.perApps))
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(i) else ctx.startService(i)
        }

        fun disconnect(ctx: Context) {
            ctx.startService(Intent(ctx, XrayVpnService::class.java).setAction(ACTION_DISCONNECT))
        }
    }
}
