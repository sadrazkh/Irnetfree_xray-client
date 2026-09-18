package com.irnetfree.vpn.ui

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily

/**
 * The design tokens, from the Android design doc (mint on a near-black green).
 *
 * Every screen reads these names rather than a literal, so the palette is one
 * place — the old blue-on-navy values were spread across MainActivity as private
 * vals and could not be changed without touching every screen.
 *
 * Typography: the design specifies Space Grotesk for UI and JetBrains Mono for
 * metrics. Neither is bundled — a font asset that fails to download breaks the
 * build, and the APK already carries three cores — so metrics use the platform
 * monospace (Roboto Mono), which is what carries the design's character, and UI
 * text uses the platform sans (the Material default, so nothing has to name it).
 * Swapping in the real families later is a res/font drop plus this one val.
 */

/* ---------------- surfaces ---------------- */
val BG = Color(0xFF0A100F)          // app background
val BG2 = Color(0xFF0E1715)         // bottom bar, inset panels
val CARD = Color(0xFF111A18)        // cards, sheets, dialogs
val CARD2 = Color(0xFF1A2523)       // chips, pressed states, the ring's face
val STROKE = Color(0xFF1D2B28)      // hairlines and card borders

/* ---------------- accents ---------------- */
val PRIMARY = Color(0xFF35E0AC)     // mint: the brand, and "connected"
val ON_PRIMARY = Color(0xFF06221B)  // text/icon ON a mint fill
val PRIMARY_DIM = Color(0xFF23443B) // mint at border strength
val PRIMARY_TINT = Color(0xFF0F1F1B)// mint at background strength
val AMBER = Color(0xFFE8A33D)       // "measuring", a slow ping, a warning
val BAD = Color(0xFFF07178)         // errors

/* ---------------- text ---------------- */
val TXT = Color(0xFFE4EFEC)         // primary text
val TXT2 = Color(0xFFC9D8D4)        // secondary text
val MUTED = Color(0xFF7D938E)       // labels, captions
val MUTED2 = Color(0xFF5D746F)      // the quietest text the design uses

/* ---------------- type ---------------- */
/** Metrics, ports, addresses, log lines — anything read as data. */
val MONO = FontFamily.Monospace
