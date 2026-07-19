package com.irnetfree.vpn.vpn

import android.util.Log
import com.irnetfree.vpn.core.ConfigBuilder
import com.irnetfree.vpn.core.ServerConfig
import com.irnetfree.vpn.net.Diagnostics
import java.net.ServerSocket

/**
 * Per-config testing: spins up a THROWAWAY xray instance (tunFd=0, so just a
 * local SOCKS inbound + the config's outbound) on a free port, measures real
 * download + UPLOAD latency THROUGH that config, then tears it down. This is how
 * you compare configs — upload is often the slow side even when ping is fine.
 *
 * Tests are serialized (one throwaway at a time). Runtime: call from Dispatchers.IO.
 */
object XrayTester {
    data class Result(val downloadMs: Long, val uploadMs: Long)

    private val lock = Any()

    fun test(server: ServerConfig): Result = synchronized(lock) {
        if (!XrayCore.available) return Result(-1, -1)
        val port = freePort() ?: return Result(-1, -1)
        val config = try { ConfigBuilder.buildTestConfig(server, port).toString() } catch (e: Throwable) { return Result(-1, -1) }
        val core = XrayCore()
        if (!core.start(config, 0)) return Result(-1, -1)
        return try {
            Thread.sleep(600)                     // let xray bind the inbound
            val down = Diagnostics.httpLatency(port)
            val up = if (down >= 0) Diagnostics.uploadTest(port) else -1
            Result(down, up)
        } catch (e: Throwable) { Log.w("XrayTester", "test failed: ${e.message}"); Result(-1, -1) }
        finally { runCatching { core.stop() } }
    }

    private fun freePort(): Int? = try { ServerSocket(0).use { it.localPort } } catch (e: Exception) { null }
}
