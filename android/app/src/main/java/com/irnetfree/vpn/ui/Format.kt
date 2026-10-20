package com.irnetfree.vpn.ui

import com.irnetfree.vpn.core.tf

/*
 * The small formatters every screen uses. Their own file, apart from the
 * composables, so the pure list logic (ServerGroups) can use them in a JVM test.
 */

fun fmtBytes(n: Long): String { var v = n.toDouble(); val u = arrayOf("B", "KB", "MB", "GB", "TB"); var i = 0; while (v >= 1024 && i < u.size - 1) { v /= 1024; i++ }; return (if (i == 0) v.toLong().toString() else String.format("%.1f", v)) + " " + u[i] }
fun fmtSpeed(n: Long) = fmtBytes(n) + "/s"

/** "12s" / "7 min" / "3 h" / "2 d" ago — short enough for a list row. */
internal fun fmtAgo(ms: Long): String = when {
    ms < 60_000 -> tf("ago.s", "n" to ms / 1000)
    ms < 3_600_000 -> tf("ago.min", "n" to ms / 60_000)
    ms < 86_400_000 -> tf("ago.h", "n" to ms / 3_600_000)
    else -> tf("ago.d", "n" to ms / 86_400_000)
}
