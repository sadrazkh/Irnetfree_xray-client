package com.irnetfree.vpn.vpn

import android.content.Context
import android.util.Log
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Runs the bundled Xray-PattN CLI as a subprocess — the second Xray-format core,
 * the one the desktop offers per config.
 *
 * PattN (patterniha/Xray-core) is upstream Xray with one change that matters
 * here: it does not refuse plaintext VLESS/Trojan to a public address, which
 * upstream rejects outright (validateOutboundTransportSecurity). Plenty of
 * Iranian configs are exactly that, and so is any chain with one plaintext hop —
 * on the official core they fail at config load, with an error that reads like a
 * bug in this app.
 *
 * It takes the SAME JSON ConfigBuilder already produces, so unlike sing-box it
 * needs no translator and works for every plan shape: single, chain, pool,
 * advanced. What it cannot do is take the TUN fd — a subprocess has no handle on
 * it — so it runs socks-inbound-only, exactly like the sing-box path, and
 * hev-socks5-tunnel carries the device's packets to that port (XrayVpnService).
 *
 * The binary ships as `libxraypattn.so` in jniLibs because nativeLibraryDir is
 * the only place Android will execute a file from; filesDir is mounted noexec.
 * arm64 only by default, so `available()` is the question every caller has to
 * ask first — everywhere else the in-process core runs instead, and says so.
 *
 * start() returns true only once the socks port actually accepts a connection,
 * so "connected" never lies.
 */
class XrayPattnCore {
    private var proc: Process? = null
    @Volatile private var reader: Thread? = null
    @Volatile private var tail: String = ""   // most recent core output, for error reports
    @Volatile private var cfgFile: File? = null

    /** Start PattN and wait until its socks port is live. False on any failure. */
    fun start(ctx: Context, configJson: String, socksPort: Int, onLog: (String) -> Unit): Boolean {
        val bin = binary(ctx)
        if (bin == null) {
            val f = File(ctx.applicationInfo.nativeLibraryDir, SO_NAME)
            onLog(if (!f.exists()) "Xray-PattN: $SO_NAME not bundled for this device (arm64 only) — using the in-process core"
                  else "Xray-PattN: $SO_NAME present but not executable — using the in-process core")
            return false
        }
        return try {
            onLog("Xray-PattN: launching ${bin.name} (${bin.length() / 1024 / 1024} MB)")
            // Named for the port, not fixed: a latency test spins up its own PattN
            // while the tunnel may already be running on one, and the two must not
            // write over each other's config.
            val cfg = File(ctx.filesDir, "xray-pattn-$socksPort.json").apply { writeText(configJson) }
            cfgFile = cfg
            val pb = ProcessBuilder(bin.absolutePath, "run", "-c", cfg.absolutePath)
                .directory(ctx.filesDir)
                .redirectErrorStream(true)
            // The geo files live in filesDir (XrayCore.prepareAssets put them there
            // for the in-process core); a separate process finds them only through
            // this variable, and without it every geosite:/geoip: rule in the config
            // is a load error rather than a silent miss.
            pb.environment()["XRAY_LOCATION_ASSET"] = ctx.filesDir.absolutePath
            pb.environment()["HOME"] = ctx.filesDir.absolutePath
            val p = pb.start()
            proc = p
            reader = Thread {
                runCatching {
                    p.inputStream.bufferedReader().forEachLine { line ->
                        if (line.isNotBlank()) { tail = line.take(300); onLog("Xray-PattN: ${line.take(300)}") }
                    }
                }
            }.also { it.isDaemon = true; it.start() }

            // Probing MUST happen off the caller's thread: start() is reached from
            // onStartCommand() (main thread), where Android rejects any socket —
            // even to loopback — with NetworkOnMainThreadException.
            val ready = java.util.concurrent.atomic.AtomicBoolean(false)
            val died = java.util.concurrent.atomic.AtomicBoolean(false)
            val prober = Thread {
                val deadline = System.currentTimeMillis() + 6000
                while (System.currentTimeMillis() < deadline) {
                    if (!p.isAlive) { died.set(true); return@Thread }
                    if (portOpen(socksPort)) { ready.set(true); return@Thread }
                    try { Thread.sleep(200) } catch (i: InterruptedException) { return@Thread }
                }
            }
            prober.start()
            runCatching { prober.join(7000) }
            when {
                ready.get() -> { onLog("Xray-PattN: socks ready on 127.0.0.1:$socksPort"); Log.i(TAG, "pattn ready"); true }
                died.get() -> { onLog("Xray-PattN exited (code ${runCatching { p.exitValue() }.getOrNull()}) — ${tail.ifBlank { "no output; check the config" }}"); false }
                else -> { onLog("Xray-PattN: socks port $socksPort did not open in time — ${tail.ifBlank { "no output" }}"); false }
            }
        } catch (t: Throwable) {
            Log.e(TAG, "Xray-PattN start failed", t)
            onLog("Xray-PattN error: ${t.message ?: t}")
            false
        }
    }

    fun stop() {
        runCatching { cfgFile?.delete() }; cfgFile = null
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
        private const val TAG = "XrayPattnCore"
        private const val SO_NAME = "libxraypattn.so"

        /** The executable shipped as a jniLib, or null if not bundled/executable. */
        fun binary(ctx: Context): File? {
            val f = File(ctx.applicationInfo.nativeLibraryDir, SO_NAME)
            if (!f.exists()) return null
            if (!f.canExecute()) runCatching { f.setExecutable(true) }
            return if (f.canExecute()) f else null
        }

        fun available(ctx: Context): Boolean = binary(ctx) != null

        /** The core's own version string, for the More screen. Blank if it cannot be asked. */
        fun version(ctx: Context): String {
            val bin = binary(ctx) ?: return ""
            return try {
                val p = ProcessBuilder(bin.absolutePath, "version").redirectErrorStream(true).start()
                val out = p.inputStream.bufferedReader().use { it.readText() }
                p.waitFor()
                Regex("Xray[^\\n]*?(\\d+\\.\\d+\\.\\d+)").find(out)?.groupValues?.get(1) ?: ""
            } catch (t: Throwable) { "" }
        }
    }
}
