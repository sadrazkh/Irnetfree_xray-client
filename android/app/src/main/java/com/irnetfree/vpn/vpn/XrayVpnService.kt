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
import com.irnetfree.vpn.core.CertPin
import com.irnetfree.vpn.core.ConfigBuilder
import com.irnetfree.vpn.core.ConnectionPlan
import com.irnetfree.vpn.core.DnsPlan
import com.irnetfree.vpn.core.EngineChoice
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
 */
class XrayVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var xray: XrayCore? = null
    private var singbox: SingboxCore? = null
    private var pattn: XrayPattnCore? = null
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
            // 1) Proxy core with a local SOCKS inbound (no internal tun).
            //    EngineChoice already decided which, and prepare() already checked
            //    it is bundled for this ABI; anything else here is a real failure.
            if (engine == EngineChoice.SINGBOX) {
                if (!SingboxCore.available(this)) { fail("sing-box core is not bundled for this device."); stopAll(); return }
                val sb = SingboxCore()
                val started = sb.start(this, config, socksPort) { s -> VpnState.addLog(s) }
                if (!started) { fail("sing-box core failed to start — see logs (More → Logs)."); stopAll(); return }
                singbox = sb
                VpnState.addLog("✓ Running on sing-box core (socks=$socksPort)")
            } else if (engine == EngineChoice.PATTN) {
                if (!XrayPattnCore.available(this)) { fail("Xray-PattN is not bundled for this device."); stopAll(); return }
                // Same geo files as the in-process core, in the same place —
                // the subprocess is pointed at them with XRAY_LOCATION_ASSET.
                XrayCore.prepareAssets(this) { s -> VpnState.addLog(s) }
                val pn = XrayPattnCore()
                val started = pn.start(this, config, socksPort) { s -> VpnState.addLog(s) }
                if (!started) { fail("Xray-PattN failed to start — see logs (More → Logs)."); stopAll(); return }
                pattn = pn
                VpnState.addLog("✓ Running on Xray-PattN core (socks=$socksPort)")
            } else {
                if (!XrayCore.available) { fail("Xray core (libv2ray) is not bundled."); stopAll(); return }
                // The geo files the routing rules and the in-country resolver need,
                // handed to the core before it starts (see XrayCore.prepareAssets).
                XrayCore.prepareAssets(this) { s -> VpnState.addLog(s) }
                xray = XrayCore(onStatus = { _, s -> if (!s.isNullOrBlank()) VpnState.addLog(s) })
                if (!xray!!.start(config, 0)) { fail("Xray core failed to start — see logs (More → Logs)."); stopAll(); return }
                // startLoop() returning true only means the core booted; confirm it
                // is really listening. NEVER abort on this — it is a diagnostic, and
                // a probe that is wrong (as it was) must not take the tunnel down.
                if (waitForPort(socksPort)) VpnState.addLog("✓ Running on Xray core (socks=$socksPort ready)")
                else VpnState.addLog("⚠ Xray is up but SOCKS $socksPort didn't answer the probe — continuing anyway.")
            }

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

            val fd = builder.establish() ?: return fail("TUN establish failed")
            tun = fd
            VpnState.addLog("TUN up (fd=${fd.fd}) · resolver ${dns.joinToString(", ")}")

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

    /**
     * Block until 127.0.0.1:port accepts a connection (or we give up).
     *
     * The probe MUST run off the main thread: startTunnel() is called from
     * onStartCommand(), and Android throws NetworkOnMainThreadException for any
     * socket there — even to loopback — so probing inline always "failed" and
     * made a perfectly healthy core look dead.
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

    private fun stopAll() {
        statsJob?.cancel(); statsJob = null
        if (tunnelRunning) { runCatching { TProxyService.TProxyStopService() }; tunnelRunning = false }
        runCatching { xray?.stop() }; xray = null
        runCatching { singbox?.stop() }; singbox = null
        runCatching { pattn?.stop() }; pattn = null
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
        /** The tunnel peer the OS is told to resolve at under managed DNS: inside the TUN's route, not the device's own address. */
        const val TUN_DNS4 = "172.19.0.2"
        private const val TUN_MTU = 1500

        const val ACTION_CONNECT = "com.irnetfree.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.irnetfree.vpn.DISCONNECT"
        const val EXTRA_CONFIG = "config"; const val EXTRA_SOCKS = "socks"; const val EXTRA_DNS = "dns"
        const val EXTRA_LABEL = "label"; const val EXTRA_IPV6 = "ipv6"; const val EXTRA_ENGINE = "engine"
        const val EXTRA_PERAPP_MODE = "perAppMode"; const val EXTRA_PERAPPS = "perApps"

        /**
         * Build the plan and the config, then start the service. Runs its network
         * steps (certificate pins, WireGuard endpoints) on a worker thread: they
         * are TLS dials and DNS lookups, and the caller is the UI. The state is
         * CONNECTING from the first line, so the screen already shows it.
         */
        fun connect(ctx: Context, store: Store) {
            val plan = store.buildPlan()          // throws with a user-facing message; the caller reports it
            val label = store.selectionLabel()
            Thread {
                try {
                    val intent = prepare(ctx, store, plan, label)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(intent) else ctx.startService(intent)
                } catch (e: Throwable) {
                    Log.e(TAG, "connect failed", e)
                    VpnState.set(ConnState.ERROR, error = e.message ?: "connect failed")
                }
            }.also { it.isDaemon = true; it.name = "irnf-connect" }.start()
        }

        /** Everything before the service: pins, endpoints, the config. Blocks. */
        fun prepare(ctx: Context, store: Store, plan0: ConnectionPlan, label: String): Intent {
            val s = store.settings

            // Certificate pinning on first use (CertPin.kt): a server whose link
            // asked for allowInsecure is dialled once, its leaf certificate hashed
            // and stored; the config then pins it. The core refuses allowInsecure
            // itself, so without this such a server never connected at all. The
            // plan holds copies of the records, so it is rebuilt from the store
            // afterwards and the pins learnt just now reach the config.
            ensureCertPins(store, plan0)
            val plan = store.buildPlan()

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
            val config: String = if (engine == EngineChoice.SINGBOX && single != null) {
                try { SingboxConfig.build(single.server, s).toString() }
                catch (e: Throwable) { engine = EngineChoice.XRAY; VpnState.addLog("sing-box: ${e.message} — using the in-process core"); ConfigBuilder.build(plan, s, geoAssets = geo, wgEndpointIps = wgIps).toString() }
            } else {
                ConfigBuilder.build(plan, s, geoAssets = geo, wgEndpointIps = wgIps).toString()
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
                putStringArrayListExtra(EXTRA_DNS, ArrayList(adapterDns))
                putExtra(EXTRA_LABEL, label)
                putExtra(EXTRA_IPV6, s.ipv6)
                putExtra(EXTRA_PERAPP_MODE, s.perAppMode)
                putStringArrayListExtra(EXTRA_PERAPPS, ArrayList(s.perApps))
            }
        }

        /** Pins learnt or dropped on this connect are written to the store and applied to the plan's own records. */
        private fun ensureCertPins(store: Store, plan: ConnectionPlan) {
            val targets = CertPin.pinTargets(plan)
            for (b in targets.behind) VpnState.addLog("${b.name} sits behind a proxy; its certificate cannot be pinned automatically — connect to it directly once to pin it")
            val now = System.currentTimeMillis()
            // A pin re-checked at most every six hours: a rotated certificate makes
            // the core refuse every dial and it says so only at log level info.
            val due = CertPin.directServers(plan).filter { CertPin.recheckDue(it, now) }
            val stale = ArrayList<String>()
            for (srv in due) {
                val sni = srv.outbound.optJSONObject("streamSettings")?.optJSONObject("tlsSettings")?.optString("serverName")?.takeIf { it.isNotBlank() } ?: srv.address
                val live = runCatching { CertPin.fetchLeafPin(srv.address, srv.port, sni) }.getOrNull() ?: continue   // unreachable is not a verdict
                if (CertPin.normalizePin(live).isNotEmpty() && CertPin.normalizePin(live) != CertPin.normalizePin(srv.certPin)) stale.add(srv.id)
            }
            var changed = false
            for (i in store.servers.indices) {
                val srv = store.servers[i]
                if (due.none { it.id == srv.id }) continue
                store.servers[i] = if (srv.id in stale) srv.copy(certPin = "", certPinAt = "", certPinCheckedAt = now) else srv.copy(certPinCheckedAt = now)
                changed = true
            }
            for (id in stale) VpnState.addLog("Certificate changed for ${store.serverById(id)?.name ?: id} — the old pin is gone; the one it presents now will be pinned instead")
            val probe = ArrayList(targets.probe.map { it.id })
            for (id in stale) if (id !in probe) probe.add(id)
            for (id in probe) {
                val srv = store.serverById(id) ?: continue
                val sni = srv.outbound.optJSONObject("streamSettings")?.optJSONObject("tlsSettings")?.optString("serverName")?.takeIf { it.isNotBlank() } ?: srv.address
                try {
                    val pin = CertPin.fetchLeafPin(srv.address, srv.port, sni)
                    val i = store.servers.indexOfFirst { it.id == id }
                    if (i >= 0) { store.servers[i] = srv.copy(certPin = pin, certPinAt = java.util.Date(now).toString(), certPinCheckedAt = now); changed = true }
                    VpnState.addLog("Certificate pinned on first use for ${srv.name}: $pin")
                } catch (e: Exception) {
                    VpnState.addLog("Could not read the certificate of ${srv.name} to pin it (${e.message}) — the core will verify it itself")
                }
            }
            if (changed) store.saveServers()
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
            ctx.startService(Intent(ctx, XrayVpnService::class.java).setAction(ACTION_DISCONNECT))
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
