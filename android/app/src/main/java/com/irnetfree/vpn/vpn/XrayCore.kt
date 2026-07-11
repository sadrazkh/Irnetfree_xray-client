package com.irnetfree.vpn.vpn

import android.util.Log
import libv2ray.Libv2ray
import libv2ray.V2RayPoint
import libv2ray.V2RayVPNServiceSupportsSet

/**
 * Thin wrapper around AndroidLibXrayLite (libv2ray). Isolated in one file so that
 * if the upstream binding changes, only this needs to be adjusted.
 *
 * `protectFd` is how xray's own sockets bypass the VPN (equivalent to the
 * desktop's per-IP bypass routes) — the service passes VpnService.protect here.
 */
class XrayCore(
    private val protectFd: (Int) -> Boolean,
    private val onStatus: (Long, String?) -> Unit = { _, _ -> }
) {
    private val point: V2RayPoint = Libv2ray.newV2RayPoint(Callback(), false)

    fun start(configJson: String, primaryHostPort: String) {
        point.configureFileContent = configJson
        point.domainName = primaryHostPort   // "host:port" of the first outbound
        point.runLoop(false)                 // prefIPv6 = false
    }

    fun stop() {
        try { point.stopLoop() } catch (e: Exception) { Log.w(TAG, "stopLoop: ${e.message}") }
    }

    val isRunning: Boolean get() = try { point.isRunning } catch (e: Exception) { false }

    /** Measure real delay through the running instance (ms), or -1 on failure. */
    fun measureDelay(url: String = "https://cp.cloudflare.com/generate_204"): Long =
        try { point.measureDelay(url) } catch (e: Exception) { -1 }

    private inner class Callback : V2RayVPNServiceSupportsSet {
        override fun shutdown(): Long = 0
        override fun prepare(): Long = 0
        override fun setup(s: String?): Long = 0
        override fun protect(l: Long): Boolean = protectFd(l.toInt())
        override fun onEmitStatus(l: Long, s: String?): Long { onStatus(l, s); return 0 }
    }

    companion object {
        private const val TAG = "XrayCore"
        fun version(): String = try { Libv2ray.checkVersionX() } catch (e: Exception) { "" }
    }
}
