package com.irnetfree.vpn.vpn

import android.util.Log
import java.lang.reflect.Proxy

/**
 * Reflective wrapper around AndroidLibXrayLite (libv2ray). Accessing the core via
 * reflection (instead of a compile-time dependency on its exact API) means the app
 * ALWAYS compiles into an installable APK even if the upstream `.aar` is absent or
 * its API version differs — in that case `available` is simply false and the VPN
 * service reports a clear message instead of failing to build or crashing.
 *
 * Supports both known API shapes:
 *   - newer: libv2ray.Libv2ray.newCoreController(CoreCallbackHandler)
 *   - older: libv2ray.Libv2ray.newV2RayPoint(V2RayVPNServiceSupportsSet, boolean)
 *
 * `protectFd` bridges VpnService.protect so xray's own sockets bypass the tunnel
 * (the Android equivalent of the desktop per-IP bypass routes).
 */
class XrayCore(
    private val protectFd: (Int) -> Boolean,
    private val onStatus: (Long, String?) -> Unit = { _, _ -> }
) {
    private var point: Any? = null
    private var stopMethod: java.lang.reflect.Method? = null

    fun start(configJson: String, primaryHostPort: String): Boolean {
        return try {
            val libv2ray = Class.forName("libv2ray.Libv2ray")
            // newer CoreController API
            runCatching { startCoreController(libv2ray, configJson) }.getOrNull()?.let { return it }
            // older V2RayPoint API
            startV2RayPoint(libv2ray, configJson, primaryHostPort)
        } catch (t: Throwable) {
            Log.e(TAG, "xray core unavailable: ${t.message}")
            false
        }
    }

    private fun startCoreController(libv2ray: Class<*>, json: String): Boolean {
        val handlerIf = Class.forName("libv2ray.CoreCallbackHandler")
        val newController = libv2ray.getMethod("newCoreController", handlerIf)
        val handler = Proxy.newProxyInstance(handlerIf.classLoader, arrayOf(handlerIf)) { _, m, args ->
            when (m.name) {
                "onEmitStatus" -> { onStatus((args?.getOrNull(0) as? Long) ?: 0L, args?.getOrNull(1) as? String); 0L }
                "startup", "shutdown" -> 0L
                else -> if (m.returnType == java.lang.Boolean.TYPE) true else 0L
            }
        }
        val controller = newController.invoke(null, handler)
        controller.javaClass.getMethod("startLoop", String::class.java).invoke(controller, json)
        point = controller
        stopMethod = controller.javaClass.getMethod("stopLoop")
        Log.i(TAG, "xray started via CoreController")
        return true
    }

    private fun startV2RayPoint(libv2ray: Class<*>, json: String, primary: String): Boolean {
        val cbIf = Class.forName("libv2ray.V2RayVPNServiceSupportsSet")
        val newPoint = libv2ray.getMethod("newV2RayPoint", cbIf, java.lang.Boolean.TYPE)
        val cb = Proxy.newProxyInstance(cbIf.classLoader, arrayOf(cbIf)) { _, m, args ->
            when (m.name) {
                "protect" -> protectFd(((args?.getOrNull(0) as? Long) ?: 0L).toInt())
                "onEmitStatus" -> { onStatus((args?.getOrNull(0) as? Long) ?: 0L, args?.getOrNull(1) as? String); 0L }
                else -> if (m.returnType == java.lang.Boolean.TYPE) true else 0L
            }
        }
        val p = newPoint.invoke(null, cb, false)
        p.javaClass.getMethod("setConfigureFileContent", String::class.java).invoke(p, json)
        runCatching { p.javaClass.getMethod("setDomainName", String::class.java).invoke(p, primary) }
        p.javaClass.getMethod("runLoop", java.lang.Boolean.TYPE).invoke(p, false)
        point = p
        stopMethod = p.javaClass.getMethod("stopLoop")
        Log.i(TAG, "xray started via V2RayPoint")
        return true
    }

    fun stop() {
        try { stopMethod?.invoke(point) } catch (t: Throwable) { Log.w(TAG, "stop: ${t.message}") }
        point = null; stopMethod = null
    }

    companion object {
        private const val TAG = "XrayCore"

        /** Whether the libv2ray classes are present in this build. */
        val available: Boolean by lazy {
            try { Class.forName("libv2ray.Libv2ray"); true } catch (t: Throwable) { false }
        }

        fun version(): String = try {
            Class.forName("libv2ray.Libv2ray").getMethod("checkVersionX").invoke(null) as? String ?: ""
        } catch (t: Throwable) { "" }
    }
}
