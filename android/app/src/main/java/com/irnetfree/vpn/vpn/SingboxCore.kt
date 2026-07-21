package com.irnetfree.vpn.vpn

import android.content.Context
import android.util.Log
import java.io.File

/**
 * Runs the bundled sing-box CLI as a subprocess (the alternate per-config core).
 *
 * The sing-box binary ships inside the APK as `libsingbox.so` in jniLibs — the
 * only place Android lets an app execute a native file from (filesDir is noexec
 * on modern Android). It's launched with a socks-inbound-only config, exactly
 * like the Xray path (XrayCore.start(config, tunFd=0)): the VpnService TUN + hev
 * tun2socks then carry the device traffic to that socks port, and our own app is
 * excluded from the VPN so sing-box's own sockets bypass the tunnel.
 *
 * Only bundled for arm64-v8a by default (size); other ABIs report unavailable
 * and the caller falls back to Xray.
 */
class SingboxCore {
    private var proc: Process? = null
    @Volatile private var reader: Thread? = null

    /** Start sing-box with a socks-inbound config. Returns false on immediate failure. */
    fun start(ctx: Context, configJson: String, onLog: (String) -> Unit): Boolean {
        val bin = binary(ctx) ?: run { onLog("sing-box binary (libsingbox.so) not bundled for this device"); return false }
        return try {
            val cfg = File(ctx.filesDir, "singbox.json").apply { writeText(configJson) }
            val pb = ProcessBuilder(bin.absolutePath, "run", "-c", cfg.absolutePath, "-D", ctx.filesDir.absolutePath)
                .directory(ctx.filesDir)
                .redirectErrorStream(true)
            pb.environment()["HOME"] = ctx.filesDir.absolutePath
            val p = pb.start()
            proc = p
            reader = Thread {
                runCatching {
                    p.inputStream.bufferedReader().forEachLine { line ->
                        if (line.isNotBlank()) onLog(line.take(400))
                    }
                }
            }.also { it.isDaemon = true; it.start() }

            // Give it a moment; if it dies immediately, surface the failure.
            try { Thread.sleep(700) } catch (_: InterruptedException) {}
            if (!p.isAlive) {
                onLog("sing-box exited immediately (code ${runCatching { p.exitValue() }.getOrNull()})")
                return false
            }
            Log.i(TAG, "sing-box started")
            true
        } catch (t: Throwable) {
            Log.e(TAG, "sing-box start failed", t)
            onLog("sing-box error: ${t.message ?: t}")
            false
        }
    }

    fun stop() {
        runCatching { proc?.destroy() }
        // give it a beat to exit cleanly, then force
        runCatching {
            val p = proc
            if (p != null && p.isAlive) { Thread.sleep(300); if (p.isAlive) p.destroyForcibly() }
        }
        proc = null; reader = null
    }

    companion object {
        private const val TAG = "SingboxCore"

        /** The executable shipped as a jniLib, or null if not bundled for this ABI. */
        fun binary(ctx: Context): File? {
            val f = File(ctx.applicationInfo.nativeLibraryDir, "libsingbox.so")
            return if (f.exists() && f.canExecute()) f else null
        }

        fun available(ctx: Context): Boolean = binary(ctx) != null
    }
}
