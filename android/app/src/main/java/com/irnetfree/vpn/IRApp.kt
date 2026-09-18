package com.irnetfree.vpn

import android.app.Application
import android.os.Build
import android.util.Log
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
        fun readCrash(app: Application): String? =
            runCatching { File(app.filesDir, CRASH_FILE).takeIf { it.exists() }?.readText() }.getOrNull()
        fun clearCrash(app: Application) {
            runCatching { File(app.filesDir, CRASH_FILE).delete() }
            runCatching { app.getExternalFilesDir(null)?.let { File(it, CRASH_FILE).delete() } }
        }
    }
}
