package com.irnetfree.vpn.vpn

import android.content.Context
import android.os.SystemClock
import com.irnetfree.vpn.core.AppSettings
import com.irnetfree.vpn.core.ConfigBuilder
import com.irnetfree.vpn.core.ConnectionPlan
import com.irnetfree.vpn.core.CoreCompat
import com.irnetfree.vpn.core.EngineChoice
import com.irnetfree.vpn.core.Mux
import com.irnetfree.vpn.core.ServerConfig
import com.irnetfree.vpn.core.SingboxConfig
import com.irnetfree.vpn.core.TrustedDns
import com.irnetfree.vpn.net.Diagnostics
import org.json.JSONObject
import java.net.ServerSocket
import java.util.concurrent.Callable
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit

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
    class Handle(val port: Int, private val xray: XrayCore?, private val pattn: XrayPattnCore?, private val singbox: SingboxCore? = null) {
        fun stop() { runCatching { xray?.stop() }; runCatching { pattn?.stop() }; runCatching { singbox?.stop() } }
    }

    /**
     * Start a throwaway core for [server]; returns a handle, or null on failure.
     * [settings] defaults to the stored ones (Default core, IPv6, the DoH list).
     *
     * [mux]: null for a latency test — the core connecting to the server would
     * use, sing-box included. true / false: the mux test's cores (probeMux) — an
     * Xray-format core, never sing-box (it has no mux of Xray's), whose proxy
     * outbound carries Mux.MUX or not.
     */
    fun start(ctx: Context, server: ServerConfig, settings: AppSettings? = null, mux: Boolean? = null): Handle? {
        val s = settings ?: storedSettings(ctx)
        val wgIps = testEndpoints(server) { h -> TrustedDns.resolveHost(h, ipv6 = s.ipv6, doh = s.dnsRemote).ips.firstOrNull() }
        if (wgIps == null) {
            VpnState.addLog("Test of ${server.name}: the WireGuard endpoint could not be resolved — not started (endpoint unresolved)")
            return null
        }
        val port = freePort() ?: return null
        // A server whose connection runs on sing-box — its own choice, or a
        // Hysteria2 with a certificate only sing-box can accept
        // (EngineChoice.needsInsecureCore) — is measured on sing-box when it is
        // bundled: on Xray it would fail while connecting to it works.
        if (mux == null && EngineChoice.chooseEngine(ConnectionPlan.Single(server), s.defaultEngine) == EngineChoice.SINGBOX && SingboxCore.available(ctx)) {
            val sb = try { SingboxConfig.build(server, s.copy(socksPort = port, httpPort = 0)).toString() } catch (e: Throwable) { null }
            if (sb != null) {
                val core = SingboxCore()
                return if (core.start(ctx, sb, port, onLog = {})) Handle(port, null, null, core) else { core.stop(); null }
            }
        }
        val withMux = mux == true
        val built = try { ConfigBuilder.buildTestConfig(server, port, wgIps, withMux) } catch (e: Throwable) { return null }
        val onPattn = EngineChoice.testEngineFor(server, s.defaultEngine) == EngineChoice.PATTN && XrayPattnCore.available(ctx)
        // mKCP's and Hysteria's settings in the form the testing core takes (CoreCompat)
        val config = (if (CoreCompat.needsCoreVersion(built))
            CoreCompat.adaptForCore(built, if (onPattn) XrayPattnCore.version(ctx) else XrayCore.version()) else built).toString()
        if (onPattn) {
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
     * Does [server] carry traffic with Xray's mux? The test of spec §4
     * (Mux.probe): a throwaway core with Mux.MUX makes two requests, one after
     * the other, each on a connection of its own — the second a second stream
     * through the same mux connection — and, if they fail, a core without it
     * makes one. "ok" | "unsupported" | "unknown". At most
     * Mux.PROBE_BUDGET_MS: a request is abandoned at the time it was given, and
     * its core stopped. Blocking — the connect thread (XrayVpnService.prepare).
     * [wanted]: false once that connect has been overtaken; nothing more starts.
     */
    fun probeMux(ctx: Context, server: ServerConfig, settings: AppSettings, wanted: () -> Boolean = { true }): String =
        Mux.probe<Handle>(
            start = { m: Boolean -> start(ctx, server, settings, m) },
            request = { h: Handle, ms: Int -> roundTrip(h.port, ms) },
            stop = { h: Handle -> h.stop() },
            now = { SystemClock.elapsedRealtime() },
            wanted = wanted
        )

    /**
     * One real round trip through the throwaway on [port] (Diagnostics, the
     * same measurement as every test here), on a connection of its own; -1 when
     * it failed or has not answered within [ms]. Waited for on this thread, so
     * a request that overruns its timeouts cannot hold the connect up past the
     * budget: the caller stops the core, and the request dies with it.
     */
    private fun roundTrip(port: Int, ms: Int): Long {
        val task = FutureTask(Callable { Diagnostics.httpLatency(port, timeout = ms, fresh = true) })
        Thread(task, "irnf-mux-test").apply { isDaemon = true }.start()
        return try { task.get(ms + 300L, TimeUnit.MILLISECONDS) } catch (e: Exception) { task.cancel(true); -1L }
    }

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
