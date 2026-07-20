package com.irnetfree.vpn.vpn

import com.irnetfree.vpn.core.ConfigBuilder
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
 */
object XrayTester {
    class Handle(val core: XrayCore, val port: Int)

    /** Start a throwaway xray for [server]; returns a handle, or null on failure. */
    fun start(server: ServerConfig): Handle? {
        if (!XrayCore.available) return null
        val port = freePort() ?: return null
        val config = try { ConfigBuilder.buildTestConfig(server, port).toString() } catch (e: Throwable) { return null }
        val core = XrayCore()
        if (!core.start(config, 0)) return null
        try { Thread.sleep(600) } catch (e: InterruptedException) {}   // let xray bind the inbound
        return Handle(core, port)
    }

    fun stop(h: Handle) { runCatching { h.core.stop() } }

    private fun freePort(): Int? = try { ServerSocket(0).use { it.localPort } } catch (e: Exception) { null }
}
