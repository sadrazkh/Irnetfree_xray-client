package com.irnetfree.vpn

import android.app.ActivityManager
import android.app.Application
import android.app.ApplicationExitInfo
import android.os.Build
import android.util.Log
import com.irnetfree.vpn.vpn.VpnState
import java.security.Security
import javax.net.ssl.SSLContext
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter

/**
 * Two things before anything else runs:
 *
 *  1. TLS 1.3 for the app's own HTTP, on every Android version. The platform
 *     TLS (Conscrypt inside the OS) only learnt TLS 1.3 in Android 10; on 8 and
 *     9 it stops at 1.2. The owner's subscription panel sits behind a Cloudflare
 *     zone whose minimum TLS version is 1.3 — measured: a TLS 1.2 ClientHello
 *     gets `alert protocol version (70)` back — so on such a phone every fetch
 *     of it died with "Handshake failed" while a browser (its own TLS stack),
 *     the desktop (Node's), and the app's own Go core (Go's) all got through.
 *     That took five releases to find because the platform's exception says
 *     "Handshake failed" and nothing else. The Conscrypt library is the same
 *     code the OS ships, a few years newer, and installed as the first security
 *     provider it serves OkHttp, HttpURLConnection, the certificate probe and
 *     DoH alike. On Android 10+ it changes nothing that matters.
 *
 *  2. A global crash handler that writes the last uncaught exception to a
 *     file, so a device crash can be surfaced inside the app (Settings → crash
 *     log) even without adb/logcat.
 *
 * Set as android:name in the manifest.
 */
class IRApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // the log on disk first, so every line from here on (and the run before's) survives a kill
        VpnState.attachLog(filesDir)
        noteLastExit()
        installTls13()
        val prev = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            try {
                val sw = StringWriter()
                e.printStackTrace(PrintWriter(sw))
                val text = "time=" + System.currentTimeMillis() + "\nthread=" + t.name + "\n\n" + sw.toString()
                Log.e("IRNetFree", "FATAL", e)
                runCatching { File(filesDir, CRASH_FILE).writeText(text) }
                runCatching { getExternalFilesDir(null)?.let { File(it, CRASH_FILE).writeText(text) } }
            } catch (_: Throwable) {}
            prev?.uncaughtException(t, e)
        }
    }

    /**
     * Why the app's process ended last time, in the log — Android 11+ keeps the
     * answer (ActivityManager.getHistoricalProcessExitReasons): killed for
     * memory, a crash in native code (a core, hev), a Java crash, an ANR, the
     * user swiping it away, a battery saver. "It cut out in the middle" has
     * several such causes, each with its own cure, and none of them leaves a
     * line in a log that lives in the process; this one is written by the
     * system. Each exit is said once (the newest one seen is remembered).
     */
    private fun noteLastExit() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return
        try {
            val am = getSystemService(ActivityManager::class.java) ?: return
            val prefs = getSharedPreferences(DIAG_PREFS, MODE_PRIVATE)
            val seen = prefs.getLong(KEY_EXIT_SEEN, 0L)
            val exits: List<ApplicationExitInfo> = am.getHistoricalProcessExitReasons(packageName, 0, 8)
            val fresh = exits.filter { e: ApplicationExitInfo -> e.timestamp > seen }.sortedBy { e: ApplicationExitInfo -> e.timestamp }
            if (fresh.isEmpty()) return
            val clock = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US)
            for (e in fresh.takeLast(3)) {
                val why = e.description?.takeIf { d: String -> d.isNotBlank() }?.let { d: String -> " — $d" } ?: ""
                VpnState.addLog("Last stop of the app (${clock.format(java.util.Date(e.timestamp))}): ${exitReason(e.reason)}$why · memory ${e.pss / 1024} MB")
            }
            prefs.edit().putLong(KEY_EXIT_SEEN, fresh.last().timestamp).apply()
        } catch (t: Throwable) {
            Log.w("IRNetFree", "exit reasons unreadable: ${t.message}")
        }
    }

    private fun exitReason(r: Int): String = when (r) {
        ApplicationExitInfo.REASON_LOW_MEMORY -> "Android ended it for memory (low memory)"
        ApplicationExitInfo.REASON_CRASH_NATIVE -> "a crash in native code (a core or the tunnel library)"
        ApplicationExitInfo.REASON_CRASH -> "a crash (Java/Kotlin)"
        ApplicationExitInfo.REASON_ANR -> "not responding (ANR)"
        ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE -> "Android ended it for using too much CPU or battery"
        ApplicationExitInfo.REASON_SIGNALED -> "killed by the system (a signal)"
        ApplicationExitInfo.REASON_USER_REQUESTED -> "closed by the user (force stop or swiped away)"
        ApplicationExitInfo.REASON_USER_STOPPED -> "stopped by the user"
        ApplicationExitInfo.REASON_PERMISSION_CHANGE -> "a permission was changed"
        ApplicationExitInfo.REASON_DEPENDENCY_DIED -> "something it depends on stopped"
        ApplicationExitInfo.REASON_EXIT_SELF -> "it exited by itself"
        ApplicationExitInfo.REASON_INITIALIZATION_FAILURE -> "it failed to start"
        ApplicationExitInfo.REASON_OTHER -> "the system ended it (other)"
        else -> "reason code $r"
    }

    private fun installTls13() {
        try {
            val provider = org.conscrypt.Conscrypt.newProvider()
            Security.insertProviderAt(provider, 1)
            Log.i("IRNetFree", "TLS: Conscrypt ${provider.version} installed; protocols now " +
                SSLContext.getDefault().supportedSSLParameters.protocols.joinToString(","))
        } catch (t: Throwable) {
            // The platform's own TLS then — fine on Android 10+, and the
            // subscription failure message says which protocols it has.
            Log.w("IRNetFree", "TLS: Conscrypt not installed (${t.message}); platform TLS on Android ${Build.VERSION.SDK_INT}", t)
        }
    }

    companion object {
        const val CRASH_FILE = "last-crash.txt"
        private const val DIAG_PREFS = "irnf-diag"
        private const val KEY_EXIT_SEEN = "exitSeenAt"
        fun readCrash(app: Application): String? =
            runCatching { File(app.filesDir, CRASH_FILE).takeIf { it.exists() }?.readText() }.getOrNull()
        fun clearCrash(app: Application) {
            runCatching { File(app.filesDir, CRASH_FILE).delete() }
            runCatching { app.getExternalFilesDir(null)?.let { File(it, CRASH_FILE).delete() } }
        }
    }
}
