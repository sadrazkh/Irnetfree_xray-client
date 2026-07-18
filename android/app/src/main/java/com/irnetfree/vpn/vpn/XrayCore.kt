package com.irnetfree.vpn.vpn

import android.util.Log
import java.lang.reflect.Method
import java.lang.reflect.Proxy

/**
 * Reflective wrapper around AndroidLibXrayLite's modern `CoreController` API
 * (github.com/2dust/AndroidLibXrayLite). Reflection keeps compilation independent
 * of the exact .aar version.
 *
 * Modern flow: the VpnService TUN fd is handed straight to the Go core via
 *   StartLoop(configContent string, tunFd int32)
 * and the core does tun2socks internally. The app package is excluded from the
 * VPN (addDisallowedApplication) so xray's own sockets bypass the tunnel — the
 * new API has no Protect callback by design.
 *
 * CoreCallbackHandler: Startup()int, Shutdown()int, OnEmitStatus(int,string)int.
 */
class XrayCore(private val onStatus: (Long, String?) -> Unit = { _, _ -> }) {
    private var controller: Any? = null
    private var stopMethod: Method? = null
    private var queryAllMethod: Method? = null

    /** Start xray, handing it the TUN fd (0 = no tun, run inbounds only). */
    fun start(configJson: String, tunFd: Int): Boolean {
        return try {
            val libv2ray = Class.forName("libv2ray.Libv2ray")
            val handlerIf = Class.forName("libv2ray.CoreCallbackHandler")
            val handler = Proxy.newProxyInstance(handlerIf.classLoader, arrayOf(handlerIf)) { _, m, args ->
                if (m.name == "onEmitStatus") { onStatus((args?.getOrNull(0) as? Long) ?: 0L, args?.getOrNull(1) as? String) }
                0L   // startup / shutdown / onEmitStatus all return Go int (Long)
            }
            val ctrl = libv2ray.getMethod("newCoreController", handlerIf).invoke(null, handler)
            val cls = ctrl.javaClass
            // StartLoop(String, int32) — the crucial 2-arg signature
            cls.getMethod("startLoop", String::class.java, Int::class.javaPrimitiveType).invoke(ctrl, configJson, tunFd)
            controller = ctrl
            stopMethod = cls.getMethod("stopLoop")
            queryAllMethod = runCatching { cls.getMethod("queryAllOutboundTrafficStats") }.getOrNull()
            Log.i(TAG, "xray started (tunFd=$tunFd)")
            true
        } catch (t: Throwable) {
            // Surface the REAL core error (unwrap InvocationTargetException).
            val real = t.cause?.message ?: t.message ?: t.toString()
            Log.e(TAG, "xray start failed: $real", t)
            onStatus(0L, "xray error: $real")
            false
        }
    }

    fun stop() { runCatching { stopMethod?.invoke(controller) }; controller = null; queryAllMethod = null }

    /** (uplinkDelta, downlinkDelta) bytes since the previous call (counters reset). */
    fun queryTraffic(): Pair<Long, Long> {
        val s = runCatching { queryAllMethod?.invoke(controller) as? String }.getOrNull() ?: return 0L to 0L
        var up = 0L; var down = 0L
        for (entry in s.split(";")) {
            val p = entry.split(",")
            if (p.size >= 3) {
                val v = p[2].toLongOrNull() ?: 0L
                if (p[1].equals("uplink", true)) up += v else if (p[1].equals("downlink", true)) down += v
            }
        }
        return up to down
    }

    companion object {
        private const val TAG = "XrayCore"
        val available: Boolean by lazy { try { Class.forName("libv2ray.Libv2ray"); true } catch (t: Throwable) { false } }
        fun version(): String = try { Class.forName("libv2ray.Libv2ray").getMethod("checkVersionX").invoke(null) as? String ?: "" } catch (t: Throwable) { "" }
    }
}
