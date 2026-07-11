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
import com.irnetfree.vpn.core.Store
import com.irnetfree.vpn.ui.MainActivity
import hev.htproxy.TProxyService
import java.io.File

/**
 * The whole-device tunnel:
 *   1. Xray runs in-process (libv2ray) with a local SOCKS inbound.
 *   2. VpnService creates a TUN interface (all traffic → this app).
 *   3. hev-socks5-tunnel reads IP packets from the TUN fd and forwards them to
 *      Xray's SOCKS inbound. Xray's own sockets are protect()-ed so they bypass
 *      the tunnel (no loop) — the Android equivalent of the desktop bypass routes.
 */
class XrayVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var xray: XrayCore? = null
    private var tunnelRunning = false

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
        val primary = intent.getStringExtra(EXTRA_PRIMARY) ?: "127.0.0.1:1"
        val dns = intent.getStringArrayListExtra(EXTRA_DNS) ?: arrayListOf("1.1.1.1", "8.8.8.8")
        val label = intent.getStringExtra(EXTRA_LABEL) ?: "IRNetFree"

        VpnState.set(ConnState.CONNECTING, label)
        startForeground(NOTIF_ID, buildNotification(label))

        try {
            // 1) Xray core (socks inbound at 127.0.0.1:socksPort)
            xray = XrayCore(protectFd = { fd -> protect(fd) }).also { it.start(config, primary) }

            // 2) TUN interface — route everything through us
            val builder = Builder()
                .setSession(label)
                .setMtu(TUN_MTU)
                .addAddress(TUN_ADDR, 30)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
            dns.forEach { builder.addDnsServer(it) }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
            // keep this app's own traffic (xray) out of the tunnel
            try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}

            val fd = builder.establish() ?: return fail("TUN establish failed")
            tun = fd

            // 3) hev-socks5-tunnel: TUN fd -> local SOCKS
            val cfgPath = writeTun2socksConfig(socksPort)
            TProxyService.TProxyStartService(cfgPath, fd.fd)
            tunnelRunning = true

            VpnState.set(ConnState.CONNECTED, label)
            updateNotification(label)
            Log.i(TAG, "tunnel up: $label (socks=$socksPort)")
        } catch (e: Throwable) {
            Log.e(TAG, "startTunnel failed", e)
            fail(e.message ?: "connect failed")
            stopAll()
        }
    }

    /** hev-socks5-tunnel YAML: forward the TUN to the local SOCKS inbound. */
    private fun writeTun2socksConfig(socksPort: Int): String {
        val yaml = """
            tunnel:
              mtu: $TUN_MTU
            socks5:
              port: $socksPort
              address: 127.0.0.1
              udp: 'udp'
            misc:
              task-stack-size: 20480
              connect-timeout: 5000
              read-write-timeout: 60000
              log-level: warn
        """.trimIndent()
        val f = File(filesDir, "tun2socks.yml")
        f.writeText(yaml)
        return f.absolutePath
    }

    private fun stopAll() {
        if (tunnelRunning) { try { TProxyService.TProxyStopService() } catch (e: Exception) { Log.w(TAG, "tun stop: ${e.message}") }; tunnelRunning = false }
        try { xray?.stop() } catch (_: Exception) {}
        xray = null
        try { tun?.close() } catch (_: Exception) {}
        tun = null
        VpnState.set(ConnState.DISCONNECTED, "")
        stopForegroundCompat()
        stopSelf()
    }

    private fun fail(msg: String) {
        VpnState.set(ConnState.ERROR, error = msg)
    }

    override fun onRevoke() { stopAll(); super.onRevoke() }
    override fun onDestroy() { stopAll(); super.onDestroy() }

    /* ----------------------------- notification ----------------------------- */

    private fun buildNotification(text: String): Notification {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "VPN status", NotificationManager.IMPORTANCE_LOW))
        }
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL)
            .setContentTitle("IRNetFree")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_vpn_ic)
            .setOngoing(true)
            .setContentIntent(pi)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIF_ID, buildNotification(text))
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(STOP_FOREGROUND_REMOVE)
        else @Suppress("DEPRECATION") stopForeground(true)
    }

    companion object {
        private const val TAG = "XrayVpnService"
        private const val CHANNEL = "vpn"
        private const val NOTIF_ID = 1
        private const val TUN_ADDR = "172.19.0.1"
        private const val TUN_MTU = 1500

        const val ACTION_CONNECT = "com.irnetfree.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.irnetfree.vpn.DISCONNECT"
        const val EXTRA_CONFIG = "config"
        const val EXTRA_SOCKS = "socks"
        const val EXTRA_DNS = "dns"
        const val EXTRA_LABEL = "label"
        const val EXTRA_PRIMARY = "primary"

        /** Kick off a connection from the UI, given a fully-built plan. */
        fun connect(ctx: Context, store: Store) {
            val plan = store.buildPlan()
            val config = ConfigBuilder.build(plan, store.settings).toString()
            val primary = primaryHostPort(store, plan)
            val i = Intent(ctx, XrayVpnService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_CONFIG, config)
                putExtra(EXTRA_SOCKS, store.settings.socksPort)
                putExtra(EXTRA_PRIMARY, primary)
                putStringArrayListExtra(EXTRA_DNS, ArrayList(store.settings.dns))
                putExtra(EXTRA_LABEL, store.selectionLabel())
            }
            ctx.startService(i)
        }

        fun disconnect(ctx: Context) {
            ctx.startService(Intent(ctx, XrayVpnService::class.java).apply { action = ACTION_DISCONNECT })
        }

        private fun primaryHostPort(store: Store, plan: com.irnetfree.vpn.core.ConnectionPlan): String {
            val addrs = store.entryAddresses(plan)
            val first = addrs.firstOrNull() ?: return "127.0.0.1:1"
            val server = when (plan) {
                is com.irnetfree.vpn.core.ConnectionPlan.Single -> plan.server
                is com.irnetfree.vpn.core.ConnectionPlan.Chain -> plan.members.firstOrNull()
                is com.irnetfree.vpn.core.ConnectionPlan.Pool ->
                    plan.serversById.values.firstOrNull { it.address == first }
            }
            return first + ":" + (server?.port ?: 443)
        }
    }
}
