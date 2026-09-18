package com.irnetfree.vpn.vpn

import android.content.Context
import com.irnetfree.vpn.core.ConfigBuilder
import com.irnetfree.vpn.core.EngineChoice
import com.irnetfree.vpn.core.ServerConfig
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
 * The throwaway runs on the core the config itself would run on
 * (EngineChoice.testEngineFor): a plaintext VLESS config asking for PattN is
 * refused at config load by the official core, so testing it in-process would
 * report every such server as dead while connecting to it works.
 */
object XrayTester {
    /** One throwaway core, whichever kind it turned out to be. */
    class Handle(val port: Int, private val xray: XrayCore?, private val pattn: XrayPattnCore?) {
        fun stop() { runCatching { xray?.stop() }; runCatching { pattn?.stop() } }
    }

    /** Start a throwaway core for [server]; returns a handle, or null on failure. */
    fun start(ctx: Context, server: ServerConfig): Handle? {
        val port = freePort() ?: return null
        val config = try { ConfigBuilder.buildTestConfig(server, port).toString() } catch (e: Throwable) { return null }
        if (EngineChoice.testEngineFor(server.engine) == EngineChoice.PATTN && XrayPattnCore.available(ctx)) {
            val core = XrayPattnCore()
            // start() already waits for the port, so no sleep here.
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

    private fun freePort(): Int? = try { ServerSocket(0).use { it.localPort } } catch (e: Exception) { null }
}
