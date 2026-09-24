package com.irnetfree.vpn.vpn

import android.content.Context
import com.irnetfree.vpn.core.AppSettings
import com.irnetfree.vpn.core.ConfigBuilder
import com.irnetfree.vpn.core.ConnectionPlan
import com.irnetfree.vpn.core.EngineChoice
import com.irnetfree.vpn.core.ServerConfig
import com.irnetfree.vpn.core.TrustedDns
import org.json.JSONObject
import java.net.ServerSocket

/**
 * Per-config testing: spins up a THROWAWAY xray instance (tunFd=0, so just a
 * local SOCKS inbound + the config's outbound) on a free port. The caller then
 * measures download / UPLOAD latency THROUGH that port (via Diagnostics) and
 * calls [stop]. Split into start/stop so the UI can show the current phase
 * ("testing download" vs "testing upload") between measurements.
 *
 * Callers must serialize tests (one throwaway at a time) — see the UI Mutex.
 *
 * The throwaway runs on the core connecting to the config would use
 * (EngineChoice.testEngineFor: its own choice, else Settings → Default core): a
 * plaintext VLESS config meant for PattN is refused at config load by the
 * official core, so testing it in-process would report every such server as
 * dead while connecting to it works.
 *
 * A WireGuard endpoint that is a name is resolved here, through TrustedDns, as
 * the service's prepare() does — the in-process core shares the process with the
 * live tunnel, and resolving it itself and failing has panicked Xray's
 * WireGuard handler (`close of closed channel`, desktop v1.7.3). No address, no
 * core.
 */
object XrayTester {
    /** One throwaway core, whichever kind it turned out to be. */
    class Handle(val port: Int, private val xray: XrayCore?, private val pattn: XrayPattnCore?) {
        fun stop() { runCatching { xray?.stop() }; runCatching { pattn?.stop() } }
    }

    /**
     * Start a throwaway core for [server]; returns a handle, or null on failure.
     * [settings] defaults to the stored ones (Default core, IPv6, the DoH list).
     */
    fun start(ctx: Context, server: ServerConfig, settings: AppSettings? = null): Handle? {
        val s = settings ?: storedSettings(ctx)
        val wgIps = testEndpoints(server) { h -> TrustedDns.resolveHost(h, ipv6 = s.ipv6, doh = s.dnsRemote).ips.firstOrNull() }
        if (wgIps == null) {
            VpnState.addLog("Test of ${server.name}: the WireGuard endpoint could not be resolved — not started (endpoint unresolved)")
            return null
        }
        val port = freePort() ?: return null
        val config = try { ConfigBuilder.buildTestConfig(server, port, wgIps).toString() } catch (e: Throwable) { return null }
        if (EngineChoice.testEngineFor(server, s.defaultEngine) == EngineChoice.PATTN && XrayPattnCore.available(ctx)) {
            val core = XrayPattnCore()
            // start() already waits for the port, and stops what it launched on failure.
            val ok = core.start(ctx, config, port, onLog = {})
            return if (ok) Handle(port, null, core) else { core.stop(); null }
        }
        if (!XrayCore.available) return null
        val core = XrayCore()
        if (!core.start(config, 0)) return null
        try { Thread.sleep(600) } catch (e: InterruptedException) {}   // let xray bind the inbound
        return Handle(port, core, null)
    }

    fun stop(h: Handle) { h.stop() }

    /**
     * Every WireGuard endpoint name of [server] with the address [resolve] found
     * for it; null as soon as one has none (the core is then not started).
     */
    internal fun testEndpoints(server: ServerConfig, resolve: (String) -> String?): Map<String, String>? {
        val map = HashMap<String, String>()
        for (h in ConfigBuilder.wgEndpointHosts(ConnectionPlan.Single(server))) map[h] = resolve(h) ?: return null
        return map
    }

    /** The settings as the Store keeps them — only what a test needs, without loading every server. */
    private fun storedSettings(ctx: Context): AppSettings = runCatching {
        val raw = ctx.getSharedPreferences("irnetfree", Context.MODE_PRIVATE).getString("settings", null) ?: "{}"
        AppSettings.fromJson(JSONObject(raw))
    }.getOrDefault(AppSettings())

    private fun freePort(): Int? = try { ServerSocket(0).use { it.localPort } } catch (e: Exception) { null }
}
