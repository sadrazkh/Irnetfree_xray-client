package com.irnetfree.vpn.vpn

import android.content.Context
import android.util.Log
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

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
 * start() only returns true once the socks port is actually accepting
 * connections — so "connected" never lies. Every failure reason (missing/
 * non-exec binary, immediate exit, port never opened) is written to the log
 * (More → Logs) with sing-box's own output, so problems are diagnosable without
 * adb. Only bundled for arm64-v8a by default; other ABIs fall back to Xray.
 */
class SingboxCore {
    private var proc: Process? = null
    @Volatile private var reader: Thread? = null
    @Volatile private var tail: String = ""   // most recent sing-box output, for error reports

    /** Start sing-box and wait until its socks port is live. False on any failure. */
    fun start(ctx: Context, configJson: String, socksPort: Int, onLog: (String) -> Unit): Boolean {
        val bin = binary(ctx)
        if (bin == null) {
            val f = File(ctx.applicationInfo.nativeLibraryDir, "libsingbox.so")
            onLog(if (!f.exists()) "sing-box: libsingbox.so not bundled for this device (arm64 only) — using Xray"
                  else "sing-box: libsingbox.so present but not executable — using Xray")
            return false
        }
        return try {
            onLog("sing-box: launching ${bin.name} (${bin.length() / 1024 / 1024} MB)")
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
                        if (line.isNotBlank()) { tail = line.take(300); onLog("sing-box: ${line.take(300)}") }
                    }
                }
            }.also { it.isDaemon = true; it.start() }

            // Wait until the socks port is actually accepting connections (or the
            // process dies / times out). Only then is the tunnel really usable.
            val deadline = System.currentTimeMillis() + 6000
            while (System.currentTimeMillis() < deadline) {
                if (!p.isAlive) {
                    onLog("sing-box exited (code ${runCatching { p.exitValue() }.getOrNull()}) — ${tail.ifBlank { "no output; check the config" }}")
                    return false
                }
                if (portOpen(socksPort)) { onLog("sing-box: socks ready on 127.0.0.1:$socksPort"); Log.i(TAG, "sing-box ready"); return true }
                try { Thread.sleep(200) } catch (_: InterruptedException) {}
            }
            onLog("sing-box: socks port $socksPort did not open in time — ${tail.ifBlank { "no output" }}")
            false
        } catch (t: Throwable) {
            Log.e(TAG, "sing-box start failed", t)
            onLog("sing-box error: ${t.message ?: t}")
            false
        }
    }

    fun stop() {
        runCatching { proc?.destroy() }
        runCatching {
            val p = proc
            if (p != null && p.isAlive) { Thread.sleep(300); if (p.isAlive) p.destroyForcibly() }
        }
        proc = null; reader = null
    }

    private fun portOpen(port: Int): Boolean = try {
        Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 300); true }
    } catch (e: Exception) { false }

    companion object {
        private const val TAG = "SingboxCore"

        /** The executable shipped as a jniLib, or null if not bundled/executable. */
        fun binary(ctx: Context): File? {
            val f = File(ctx.applicationInfo.nativeLibraryDir, "libsingbox.so")
            if (!f.exists()) return null
            if (!f.canExecute()) runCatching { f.setExecutable(true) }
            return if (f.canExecute()) f else null
        }

        fun available(ctx: Context): Boolean = binary(ctx) != null
    }
}
