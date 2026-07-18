package com.irnetfree.vpn

import android.app.Application
import android.util.Log
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter

/**
 * Installs a global crash handler that writes the last uncaught exception to a
 * file, so a device crash can be surfaced inside the app (Settings → crash log)
 * even without adb/logcat. Set as android:name in the manifest.
 */
class IRApp : Application() {
    override fun onCreate() {
        super.onCreate()
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
