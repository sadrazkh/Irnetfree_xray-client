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
import com.irnetfree.vpn.core.Store
import com.irnetfree.vpn.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Whole-device tunnel. The VpnService establishes the TUN and hands its fd
 * straight to xray-core (AndroidLibXrayLite CoreController.startLoop), which does
 * tun2socks internally. This app's package is excluded from the VPN so xray's own
 * sockets bypass the tunnel (no protect callback needed in the modern API).
 */
class XrayVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var xray: XrayCore? = null
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
        val dns = intent.getStringArrayListExtra(EXTRA_DNS) ?: arrayListOf("1.1.1.1", "8.8.8.8")
        val label = intent.getStringExtra(EXTRA_LABEL) ?: "IRNetFree"
        val ipv6 = intent.getBooleanExtra(EXTRA_IPV6, false)
        val perAppMode = intent.getStringExtra(EXTRA_PERAPP_MODE) ?: "off"
        val perApps = intent.getStringArrayListExtra(EXTRA_PERAPPS) ?: arrayListOf()

        VpnState.set(ConnState.CONNECTING, label)
        VpnState.addLog("Connecting: $label")
        runCatching { startForeground(NOTIF_ID, buildNotification(label, false)) }
            .onFailure { VpnState.addLog("startForeground failed: ${it.message}") }

        try {
            if (!XrayCore.available) { fail("Xray core (libv2ray) is not bundled in this build."); stopAll(); return }

            // 1) TUN interface — everything routes through us; our own app is
            //    excluded so xray's sockets bypass the tunnel.
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

            // 2) hand the TUN fd to xray-core (internal tun2socks)
            xray = XrayCore(onStatus = { _, s -> if (!s.isNullOrBlank()) VpnState.addLog(s) })
            if (!xray!!.start(config, fd.fd)) { fail("Xray core failed to start — see logs (بیشتر → لاگ‌ها)."); stopAll(); return }

            VpnState.set(ConnState.CONNECTED, label)
            VpnState.addLog("Connected")
            updateNotification(label, true)
            startStatsLoop()
            Log.i(TAG, "tunnel up: $label")
        } catch (e: Throwable) {
            Log.e(TAG, "startTunnel failed", e)
            fail(e.message ?: "connect failed"); stopAll()
        }
    }

    /** allow = tunnel only these apps; disallow = all but these; off = all (minus us). */
    private fun applyPerApp(b: Builder, mode: String, apps: List<String>) {
        when {
            mode == "allow" && apps.isNotEmpty() -> for (p in apps) runCatching { b.addAllowedApplication(p) }
            mode == "disallow" -> { for (p in apps) runCatching { b.addDisallowedApplication(p) }; runCatching { b.addDisallowedApplication(packageName) } }
            else -> runCatching { b.addDisallowedApplication(packageName) }
        }
    }

    private fun startStatsLoop() {
        statsJob?.cancel()
        statsJob = scope.launch {
            var up = 0L; var down = 0L; var first = true
            while (isActive) {
                val (u, d) = xray?.queryTraffic() ?: (0L to 0L)
                val su: Long; val sd: Long
                if (first) { first = false; su = 0; sd = 0 } else { up += u; down += d; su = u; sd = d }
                VpnState.setTraffic(Traffic(up, down, su, sd))
                delay(1000)
            }
        }
    }

    private fun stopAll() {
        statsJob?.cancel(); statsJob = null
        runCatching { xray?.stop() }; xray = null
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
            .setContentTitle("IRNetFree" + if (connected) " • متصل" else "")
            .setContentText(text)
            .setSmallIcon(com.irnetfree.vpn.R.drawable.ic_stat_vpn)
            .setOngoing(true)
            .setContentIntent(open)
        if (connected) {
            val icon = android.graphics.drawable.Icon.createWithResource(this, com.irnetfree.vpn.R.drawable.ic_stat_vpn)
            b.addAction(Notification.Action.Builder(icon, "قطع", disconnect).build())
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
        const val EXTRA_CONFIG = "config"; const val EXTRA_DNS = "dns"
        const val EXTRA_LABEL = "label"; const val EXTRA_IPV6 = "ipv6"
        const val EXTRA_PERAPP_MODE = "perAppMode"; const val EXTRA_PERAPPS = "perApps"

        fun connect(ctx: Context, store: Store) {
            val plan = store.buildPlan()
            val s = store.settings
            val config = ConfigBuilder.build(plan, s, geoAssets = false).toString()
            val i = Intent(ctx, XrayVpnService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_CONFIG, config)
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
