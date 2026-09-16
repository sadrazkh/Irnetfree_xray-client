package com.irnetfree.vpn.vpn

import android.content.Context
import android.util.Log
import java.io.File
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

        /**
         * The routing data files (geoip.dat, geosite.dat) the core reads for every
         * `geosite:` / `geoip:` rule and for the in-country resolver's `expectedIPs`.
         *
         * The APK carries them as assets (fetched into app/src/main/assets by
         * android/scripts/fetch-libs.sh, beside libv2ray); assets are not files,
         * so they are copied into the app's files dir once — again when the APK's
         * copy differs in size, i.e. after an update — and the core is pointed at
         * that dir (`Libv2ray.initCoreEnv`, `initV2Env` on older .aar versions).
         * A build without the assets does nothing here and GeoAssets stays false.
         */
        fun prepareAssets(ctx: Context, log: (String) -> Unit = {}) {
            try {
                val names = ctx.assets.list("")?.toSet() ?: emptySet()
                for (name in listOf(GeoAssets.GEOIP, GeoAssets.GEOSITE)) {
                    if (name !in names) continue
                    val dst = File(ctx.filesDir, name)
                    val size = runCatching { ctx.assets.openFd(name).use { it.length } }.getOrDefault(-1L)
                    if (dst.exists() && dst.length() > 0L && (size < 0L || dst.length() == size)) continue
                    ctx.assets.open(name).use { input -> dst.outputStream().use { out -> input.copyTo(out) } }
                    log("Routing data $name installed (${dst.length() / 1024} KB)")
                }
            } catch (t: Throwable) {
                log("Routing data files could not be installed: ${t.message}")
            }
            // Tell the core where they are. Either method name, whichever this .aar has.
            try {
                val libv2ray = Class.forName("libv2ray.Libv2ray")
                val init = runCatching { libv2ray.getMethod("initCoreEnv", String::class.java, String::class.java) }.getOrNull()
                    ?: runCatching { libv2ray.getMethod("initV2Env", String::class.java, String::class.java) }.getOrNull()
                init?.invoke(null, ctx.filesDir.absolutePath, "")
            } catch (t: Throwable) {
                Log.w(TAG, "core env init failed: ${t.cause?.message ?: t.message}")
            }
        }
    }
}
