package com.irnetfree.vpn.ui

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.em
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.window.Dialog
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.material3.Surface
import androidx.compose.foundation.layout.widthIn
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.irnetfree.vpn.IRApp
import com.irnetfree.vpn.core.*
import com.irnetfree.vpn.net.Diagnostics
import com.irnetfree.vpn.vpn.ConnState
import com.irnetfree.vpn.vpn.GeoAssets
import com.irnetfree.vpn.vpn.SingboxCore
import com.irnetfree.vpn.vpn.SubFetch
import com.irnetfree.vpn.vpn.XrayCore
import com.irnetfree.vpn.vpn.VpnState
import com.irnetfree.vpn.vpn.XrayPattnCore
import com.irnetfree.vpn.vpn.XrayTester
import com.irnetfree.vpn.vpn.XrayVpnService
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/* The palette and the two type families live in Theme.kt. */

class MainActivity : ComponentActivity() {
    private lateinit var store: Store
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runCatching { enableEdgeToEdge() }
        val crash = IRApp.readCrash(application)
        if (crash != null) { setContent { AppTheme { CrashScreen(crash) { IRApp.clearCrash(application); recreate() } } }; return }
        try {
            store = Store(this)
            setContent { AppTheme { App(store) } }
        } catch (e: Throwable) {
            setContent { AppTheme { CrashScreen("onCreate failed:\n" + e.stackTraceToString()) { finish() } } }
        }
    }
}

@Composable
private fun AppTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = darkColorScheme(primary = PRIMARY, secondary = PRIMARY, background = BG, surface = CARD,
        onPrimary = ON_PRIMARY, onBackground = TXT, onSurface = TXT, surfaceVariant = CARD2, outline = STROKE)) {
        Surface(Modifier.fillMaxSize(), color = BG) { content() }
    }
}

@Composable
private fun CrashScreen(text: String, onClear: () -> Unit) {
    Column(Modifier.fillMaxSize().statusBarsPadding().padding(16.dp)) {
        Text("App error (please send me this text)", color = BAD, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(8.dp))
        SelectionContainer { Text(text, color = TXT, fontSize = 11.sp, modifier = Modifier.weight(1f).verticalScroll(rememberScrollState())) }
        Spacer(Modifier.height(8.dp))
        Button(onClick = onClear, modifier = Modifier.fillMaxWidth()) { Text("Clear & retry") }
    }
}

/* ---------------- nav ---------------- */
// A phone carries four; the desktop's Chain, Proxy Pool, Routing, Logs and
// Settings live behind More (the design doc: "8 sidebar sections, a phone can
// carry 4").
private enum class Tab(val label: String, val icon: ImageVector) {
    HOME("CONNECT", Icons.Filled.PowerSettingsNew),
    SERVERS("SERVERS", Icons.Filled.Dns),
    SUBS("SUBS", Icons.Filled.CloudDownload),
    MORE("MORE", Icons.Filled.Menu)
}

@Composable
private fun App(store: Store) {
    var tab by remember { mutableStateOf(Tab.HOME) }
    var more by remember { mutableStateOf<String?>(null) }
    var rev by remember { mutableIntStateOf(0) }
    val bump: () -> Unit = { rev++ }

    Scaffold(containerColor = BG, bottomBar = {
        Column {
            HorizontalDivider(color = STROKE)
            NavigationBar(containerColor = BG2, tonalElevation = 0.dp) {
                Tab.values().forEach { tb ->
                    NavigationBarItem(selected = tab == tb, onClick = { tab = tb; more = null },
                        icon = { Icon(tb.icon, null, Modifier.size(20.dp)) },
                        label = { Text(tb.label, fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em) },
                        colors = NavigationBarItemDefaults.colors(selectedIconColor = PRIMARY, selectedTextColor = PRIMARY,
                            indicatorColor = PRIMARY_TINT, unselectedIconColor = MUTED2, unselectedTextColor = MUTED2))
                }
            }
        }
    }) { pad ->
        Box(Modifier.padding(bottom = pad.calculateBottomPadding()).fillMaxSize()) {
            key(rev) {
                when (tab) {
                    Tab.HOME -> HomeScreen(store, bump)
                    Tab.SERVERS -> ServersScreen(store, bump)
                    Tab.SUBS -> SubsScreen(store, bump)
                    Tab.MORE -> when (more) {
                        "chains" -> ChainsScreen(store, bump) { more = null }
                        "pool" -> PoolScreen(store, bump) { more = null }
                        "routing" -> RoutingScreen(store, bump) { more = null }
                        "settings" -> SettingsScreen(store, bump) { more = null }
                        "logs" -> LogsScreen { more = null }
                        else -> MoreMenu(store, bump) { more = it }
                    }
                }
            }
        }
    }
}

/* ================================ CONNECT ================================ */
/**
 * Connect, in the shape the Android design doc gives it: one ring, then the
 * numbers, then the facts.
 *
 * The "protection strip" is the desktop Inspector rail folded into a row of
 * chips — but it says what this app can actually see on a phone. The desktop's
 * kill switch and leak guard are Windows adapter work with no Android
 * equivalent (a phone's equivalent is the system's own "Always-on VPN /Block
 * connections without VPN", which is not ours to report), so the chips here are
 * the tunnel's real scope, the real resolver mode, IPv6, and the core that is
 * really running — every one of them read from the store or from the device.
 */
@Composable
private fun HomeScreen(store: Store, bump: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val state by VpnState.state.collectAsState()
    val err by VpnState.lastError.collectAsState()
    val traffic by VpnState.traffic.collectAsState()
    var ip by remember { mutableStateOf("—") }
    var ping by remember { mutableStateOf<Long?>(null) }
    var latency by remember { mutableStateOf<Long?>(null) }
    var measuring by remember { mutableStateOf("") }
    var pickerOpen by remember { mutableStateOf(false) }
    var homeSheet by remember { mutableStateOf<String?>(null) }
    val haptic = LocalHapticFeedback.current
    val connectedSince by VpnState.connectedSince.collectAsState()
    val health by VpnState.health.collectAsState()
    val settings = store.settings
    var elapsed by remember { mutableStateOf(0L) }
    LaunchedEffect(connectedSince) {
        while (connectedSince > 0) { elapsed = System.currentTimeMillis() - connectedSince; delay(1000) }
        elapsed = 0L
    }
    // The sparkline's own history: VpnState publishes a rate, not a series, and
    // this is the only screen that wants one. Cleared when the tunnel goes down.
    val spark = remember { mutableStateListOf<Pair<Long, Long>>() }
    LaunchedEffect(traffic, state) {
        if (state != ConnState.CONNECTED) spark.clear()
        else { spark.add(traffic.rxSpeed to traffic.txSpeed); while (spark.size > 60) spark.removeAt(0) }
    }

    val vpnPrepare = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        if (res.resultCode == android.app.Activity.RESULT_OK) doConnect(ctx, store)
    }
    fun onPower() {
        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
        if (state == ConnState.CONNECTED || state == ConnState.CONNECTING) { XrayVpnService.disconnect(ctx); return }
        val prep: Intent? = VpnService.prepare(ctx)
        if (prep != null) vpnPrepare.launch(prep) else doConnect(ctx, store)
    }
    fun selectedServer(): ServerConfig? {
        val sel = store.selection
        return store.serverById(sel) ?: store.chainById(sel.removePrefix("chain:"))?.let { store.chainMembers(it).firstOrNull() }
    }

    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        /* ---- header: brand, mode, uptime ---- */
        Row(Modifier.fillMaxWidth().padding(start = 16.dp, end = 12.dp, top = 10.dp, bottom = 10.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(18.dp).clip(RoundedCornerShape(5.dp)).background(PRIMARY))
            Spacer(Modifier.width(8.dp))
            Text("IR", color = TXT, fontWeight = FontWeight.Bold, fontSize = 14.sp, letterSpacing = 0.06.em)
            Text("NETFREE", color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 14.sp, letterSpacing = 0.06.em)
            Spacer(Modifier.weight(1f))
            Text(
                if (settings.advancedMode) "ADVANCED" else "SIMPLE",
                color = MUTED, fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em,
                modifier = Modifier.clip(RoundedCornerShape(50)).border(1.dp, STROKE, RoundedCornerShape(50)).padding(horizontal = 8.dp, vertical = 4.dp)
            )
            if (connectedSince > 0) { Spacer(Modifier.width(8.dp)); Text(fmtDuration(elapsed), color = MUTED, fontSize = 10.sp, fontFamily = MONO) }
            IconButton(onClick = { homeSheet = "import" }) { Icon(Icons.Filled.AddCircle, "add config", tint = PRIMARY) }
        }
        HorizontalDivider(color = STROKE)

        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 20.dp)) {
            /* ---- the ring ---- */
            PowerRing(state, ::onPower)
            Spacer(Modifier.height(14.dp))
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    when (state) {
                        ConnState.CONNECTED -> "Connected"; ConnState.CONNECTING -> "Connecting…"
                        ConnState.ERROR -> "Not connected"; else -> "Not protected"
                    },
                    color = TXT, fontSize = 19.sp, fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.height(5.dp))
                Text(
                    when (state) {
                        ConnState.CONNECTED -> store.selectionLabel()
                        ConnState.CONNECTING -> "starting the core and the tunnel"
                        ConnState.ERROR -> err.ifBlank { "see More → Logs" }
                        else -> "tap the ring to connect"
                    },
                    color = if (state == ConnState.ERROR) BAD else MUTED,
                    fontSize = 11.sp, fontFamily = MONO, textAlign = TextAlign.Center, maxLines = 2, overflow = TextOverflow.Ellipsis
                )
            }

            /* ---- post-connect verdict: does traffic really work ---- */
            health?.let { h ->
                Spacer(Modifier.height(14.dp))
                Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp))
                    .background((if (h.ok) PRIMARY else BAD).copy(alpha = 0.10f)).padding(horizontal = 12.dp, vertical = 9.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Text(if (h.ok) "✓" else "✗", color = if (h.ok) PRIMARY else BAD, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.width(8.dp))
                    Text(h.text, color = if (h.ok) PRIMARY else BAD, fontSize = 12.sp, maxLines = 3, overflow = TextOverflow.Ellipsis)
                }
            }

            /* ---- the exit ---- */
            Spacer(Modifier.height(18.dp))
            ExitChip(store, ping) { pickerOpen = true }

            /* ---- the numbers: advanced mode only (the design's simple mode is
                   one ring and one decision) ---- */
            if (settings.advancedMode) {
            Spacer(Modifier.height(12.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Metric(Modifier.weight(1f), "DOWNLOAD", fmtSpeed(traffic.rxSpeed), fmtBytes(traffic.rxBytes) + " total", PRIMARY)
                Metric(Modifier.weight(1f), "UPLOAD", fmtSpeed(traffic.txSpeed), fmtBytes(traffic.txBytes) + " total", TXT)
            }
            Spacer(Modifier.height(10.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Metric(Modifier.weight(1f), "TCP PING", if (measuring == "ping") "…" else fmtLat(ping), "to the server", if (measuring == "ping") AMBER else latColor(ping))
                Metric(Modifier.weight(1f), "REAL DELAY", if (measuring == "delay") "…" else fmtLat(latency), "through the tunnel", if (measuring == "delay") AMBER else latColor(latency))
            }

            /* ---- transfer speed ---- */
            Spacer(Modifier.height(10.dp))
            Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                Column(Modifier.padding(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Transfer speed", color = TXT, fontSize = 13.sp, modifier = Modifier.weight(1f))
                        Text("— down", color = PRIMARY, fontSize = 9.sp, fontFamily = MONO)
                        Spacer(Modifier.width(8.dp))
                        Text("-- up", color = MUTED, fontSize = 9.sp, fontFamily = MONO)
                    }
                    Spacer(Modifier.height(10.dp))
                    Sparkline(spark, Modifier.fillMaxWidth().height(64.dp))
                    Row(Modifier.fillMaxWidth().padding(top = 6.dp)) {
                        Text("last ${spark.size}s", color = MUTED2, fontSize = 9.sp, fontFamily = MONO, modifier = Modifier.weight(1f))
                        Text("now", color = MUTED2, fontSize = 9.sp, fontFamily = MONO)
                    }
                }
            }

            /* ---- the tunnel's real scope ---- */
            Spacer(Modifier.height(10.dp))
            Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                Row(Modifier.padding(horizontal = 14.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("VPN tunnel", color = TXT, fontSize = 13.sp)
                        Text(
                            when (settings.perAppMode) {
                                "allow" -> "only ${settings.perApps.size} app(s) go through it"
                                "disallow" -> "every app except ${settings.perApps.size}"
                                else -> "whole system"
                            },
                            color = MUTED, fontSize = 11.sp, fontFamily = MONO
                        )
                    }
                    Box(Modifier.size(9.dp).clip(CircleShape).background(if (state == ConnState.CONNECTED) PRIMARY else MUTED2))
                }
            }
            }

            /* ---- protection strip ---- */
            Spacer(Modifier.height(16.dp))
            Text("PROTECTION", color = MUTED2, fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em)
            Spacer(Modifier.height(8.dp))
            val geo = remember { GeoAssets.available(ctx) }
            // The core a plan would actually run on, asked the same way the service
            // asks it — not just the default setting.
            val core = remember(settings.defaultEngine, store.selection) {
                EngineChoice.chooseEngine(runCatching { store.buildPlan() }.getOrNull(), settings.defaultEngine)
            }
            FlowChips(listOf(
                Pair("DNS · " + (if (settings.dnsManaged) "managed" else "as given"), settings.dnsManaged),
                Pair("routing · " + routingModeLabel(settings.routingMode), settings.routingMode != "global"),
                Pair("geo data · " + (if (geo) "on device" else "missing"), geo),
                Pair("IPv6 · " + (if (settings.ipv6) "on" else "off"), settings.ipv6),
                Pair("core · " + core, true)
            ))

            /* ---- quick actions ---- */
            Spacer(Modifier.height(16.dp))
            if (settings.advancedMode) Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = {
                        val srv = selectedServer() ?: return@OutlinedButton
                        measuring = "ping"
                        scope.launch {
                            val ms = withContext(Dispatchers.IO) { Diagnostics.tcpPing(srv.address, srv.port) }
                            ping = if (ms >= 0) ms else null; measuring = ""
                        }
                    },
                    modifier = Modifier.weight(1f), shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TXT2), border = BorderStroke(1.dp, STROKE)
                ) { Text("ping test", fontSize = 12.sp) }
                OutlinedButton(
                    onClick = {
                        val sp = if (state == ConnState.CONNECTED) store.settings.socksPort else null
                        measuring = "delay"
                        scope.launch {
                            val ms = withContext(Dispatchers.IO) { Diagnostics.httpLatency(sp) }
                            latency = if (ms >= 0) ms else null
                            val r = withContext(Dispatchers.IO) { Diagnostics.ipInfo(sp) }
                            ip = if (r.ok) "${flag(r.countryCode)} ${r.ip}" else "fail"
                            measuring = ""
                        }
                    },
                    modifier = Modifier.weight(1f), shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TXT2), border = BorderStroke(1.dp, STROKE)
                ) { Text("check IP", fontSize = 12.sp) }
                OutlinedButton(
                    onClick = { if (state == ConnState.CONNECTED) { XrayVpnService.disconnect(ctx); scope.launch { delay(600); doConnect(ctx, store) } } },
                    enabled = state == ConnState.CONNECTED,
                    modifier = Modifier.weight(1f), shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TXT2), border = BorderStroke(1.dp, STROKE)
                ) { Text("reconnect", fontSize = 12.sp) }
            }
            if (ip != "—") {
                Spacer(Modifier.height(8.dp))
                Text("egress $ip", color = MUTED, fontSize = 11.sp, fontFamily = MONO)
            }
            Spacer(Modifier.height(20.dp))
        }
    }
    if (pickerOpen) SelectionSheet(store, { pickerOpen = false }) { pickerOpen = false; bump() }
    AddConfigSheets(store, homeSheet, { homeSheet = it }, bump)
}

/**
 * The power ring. Connected it is a solid mint disc with a ring pulsing out of
 * it; otherwise a dark disc with a hairline. The glyph is the power symbol drawn
 * as an arc with a gap at the top, which is what the design shows.
 */
@Composable private fun PowerRing(state: ConnState, onPower: () -> Unit) {
    val on = state == ConnState.CONNECTED
    val busy = state == ConnState.CONNECTING
    val pulse by rememberInfiniteTransition(label = "ring").animateFloat(
        1f, 1.28f, infiniteRepeatable(tween(2400, easing = LinearEasing), RepeatMode.Restart), label = "scale"
    )
    val fade by rememberInfiniteTransition(label = "ringFade").animateFloat(
        0.5f, 0f, infiniteRepeatable(tween(2400, easing = LinearEasing), RepeatMode.Restart), label = "alpha"
    )
    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
        Box(Modifier.size(188.dp), contentAlignment = Alignment.Center) {
            if (on) Box(Modifier.size(170.dp).scale(pulse).clip(CircleShape).border(2.dp, PRIMARY.copy(alpha = fade), CircleShape))
            Box(
                Modifier.size(170.dp).clip(CircleShape)
                    .background(if (on) PRIMARY else Color(0xFF101B19))
                    .border(if (on) 0.dp else 1.dp, if (on) Color.Transparent else Color(0xFF21302D), CircleShape)
                    .clickable { onPower() },
                contentAlignment = Alignment.Center
            ) {
                when {
                    busy -> CircularProgressIndicator(color = PRIMARY, strokeWidth = 4.dp, modifier = Modifier.size(52.dp))
                    else -> PowerGlyph(if (on) ON_PRIMARY else Color(0xFF486B63))
                }
            }
        }
    }
}

/** The power symbol: a ring open at the top, with a stem through the gap. */
@Composable private fun PowerGlyph(tint: Color) {
    Canvas(Modifier.size(52.dp)) {
        val stroke = 5.dp.toPx()
        val inset = stroke / 2
        drawArc(
            color = tint, startAngle = -60f, sweepAngle = 300f, useCenter = false,
            topLeft = Offset(inset, inset),
            size = Size(size.width - stroke, size.height - stroke),
            style = Stroke(width = stroke, cap = StrokeCap.Round)
        )
        drawLine(
            color = tint,
            start = Offset(size.width / 2, -6.dp.toPx()),
            end = Offset(size.width / 2, size.height * 0.34f),
            strokeWidth = stroke, cap = StrokeCap.Round
        )
    }
}

/** The selected exit, with its protocol, country and last measured ping. */
@Composable private fun ExitChip(store: Store, ping: Long?, onClick: () -> Unit) {
    val srv = store.serverById(store.selection)
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).background(CARD)
            .border(1.dp, STROKE, RoundedCornerShape(14.dp)).clickable { onClick() }
            .padding(horizontal = 13.dp, vertical = 11.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            badge(srv?.protocol ?: ""), color = PRIMARY, fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em,
            modifier = Modifier.clip(RoundedCornerShape(5.dp)).border(1.dp, PRIMARY_DIM, RoundedCornerShape(5.dp)).padding(horizontal = 6.dp, vertical = 4.dp)
        )
        Spacer(Modifier.width(8.dp))
        Text(
            if (srv != null) srv.name else store.selectionLabel(),
            color = TXT, fontSize = 13.sp, fontWeight = FontWeight.SemiBold,
            modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis
        )
        if (ping != null) { Text(fmtLat(ping), color = latColor(ping), fontSize = 12.sp, fontFamily = MONO); Spacer(Modifier.width(8.dp)) }
        Text("›", color = MUTED2, fontSize = 13.sp)
    }
}

/** One metric tile: a mono label, the value, and what it is measuring. */
@Composable private fun Metric(modifier: Modifier, label: String, value: String, sub: String, tint: Color) {
    Card(modifier, colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
        Column(Modifier.padding(13.dp)) {
            Text(label, color = MUTED2, fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em)
            Spacer(Modifier.height(5.dp))
            Text(value, color = tint, fontSize = 17.sp, fontFamily = MONO, fontWeight = FontWeight.Bold, maxLines = 1)
            Text(sub, color = MUTED2, fontSize = 9.sp, fontFamily = MONO, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}

/** Download solid, upload dashed, both scaled to the largest value on screen. */
@Composable private fun Sparkline(points: List<Pair<Long, Long>>, modifier: Modifier) {
    Canvas(modifier) {
        if (points.size < 2) return@Canvas
        val peak = points.maxOf { maxOf(it.first, it.second) }.coerceAtLeast(1L).toFloat()
        val dx = size.width / (points.size - 1).toFloat()
        fun path(pick: (Pair<Long, Long>) -> Long): Path = Path().apply {
            points.forEachIndexed { i, p ->
                val x = i * dx
                val y = size.height - (pick(p) / peak) * size.height
                if (i == 0) moveTo(x, y) else lineTo(x, y)
            }
        }
        drawPath(path { it.first }, PRIMARY, style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round))
        drawPath(
            path { it.second }, MUTED,
            style = Stroke(width = 1.5.dp.toPx(), cap = StrokeCap.Round, pathEffect = PathEffect.dashPathEffect(floatArrayOf(6f, 6f)))
        )
    }
}

/** The protection chips, wrapped onto as many lines as they need. */
@Composable private fun FlowChips(items: List<Pair<String, Boolean>>) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        items.chunked(2).forEach { row ->
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                row.forEach { (text, good) ->
                    Text(
                        text, color = if (good) TXT2 else MUTED, fontSize = 10.sp, fontFamily = MONO,
                        maxLines = 1, overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.clip(RoundedCornerShape(50)).background(if (good) PRIMARY_TINT else CARD)
                            .border(1.dp, if (good) PRIMARY_DIM else STROKE, RoundedCornerShape(50))
                            .padding(horizontal = 9.dp, vertical = 5.dp)
                    )
                }
            }
        }
    }
}

private fun doConnect(ctx: Context, store: Store) {
    try { VpnState.set(ConnState.CONNECTING, store.selectionLabel()); XrayVpnService.connect(ctx, store) }
    catch (e: Exception) { VpnState.set(ConnState.ERROR, error = e.message ?: "connect failed") }
}


@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun SelectionSheet(store: Store, onDismiss: () -> Unit, onPick: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = CARD) {
        val options = buildList {
            if (store.poolEnabledValid().isNotEmpty()) add(Store.POOL_ID to "🧩 Proxy Pool (${store.poolEnabledValid().size})")
            if (store.advancedReady()) add(Store.ADV_ID to "🧭 Advanced routing")
            store.chains.filter { store.chainReady(it) }.forEach { add("chain:${it.id}" to "⛓ ${it.name}") }
            store.servers.forEach { add(it.id to "${badge(it.protocol)} ${it.name}") }
        }
        Column(Modifier.fillMaxWidth().heightIn(max = 460.dp).verticalScroll(rememberScrollState()).padding(bottom = 24.dp)) {
            Text("Select an exit", color = TXT, fontWeight = FontWeight.Bold, modifier = Modifier.padding(16.dp))
            if (options.isEmpty()) Text("No servers yet", color = MUTED, modifier = Modifier.padding(16.dp))
            options.forEach { (id, lbl) ->
                Row(Modifier.fillMaxWidth().clickable { store.saveSelection(id); onPick() }.padding(horizontal = 16.dp, vertical = 14.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(lbl, color = TXT, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                    if (store.selection == id) Icon(Icons.Filled.CheckCircle, null, tint = PRIMARY)
                }
            }
        }
    }
}

/* ================================ SERVERS ================================ */
/**
 * The config list, in the shape of design option 2c: one quiet line per server,
 * and the one you tap opens in place to show what it measured and what you can
 * do with it.
 *
 * The five icon buttons that used to sit on every row are gone. Thirteen
 * servers meant sixty-five tap targets of about nine millimetres, four of them
 * destructive, and the row's actual content — the name and the host — had
 * whatever width was left. Now a row carries the three things you scan for
 * (where it is, what it is, how fast it answered) and nothing you can hit by
 * accident.
 *
 * Tapping a row selects it AND expands it, which is what 2c draws: the open
 * card is the one marked IN USE. Selecting is free — it changes which config
 * the next connect uses, never the tunnel that is already running.
 *
 * Subscriptions stay separated into their own sections, as they are on Windows.
 */
@Composable
private fun ServersScreen(store: Store, bump: () -> Unit) {
    val scope = rememberCoroutineScope()
    var q by remember { mutableStateOf("") }
    var sheet by remember { mutableStateOf<String?>(null) }
    var editId by remember { mutableStateOf<String?>(null) }
    var qrServer by remember { mutableStateOf<ServerConfig?>(null) }
    var confirmDelete by remember { mutableStateOf<ServerConfig?>(null) }
    var addMenu by remember { mutableStateOf(false) }
    // Mirrors store.selection so picking a config repaints the two rows that
    // changed instead of calling bump(), which rebuilds the screen through
    // key(rev) in App and takes the scroll position with it — the list used to
    // jump back to the top whenever you chose something near the bottom.
    var selectedId by remember { mutableStateOf(store.selection) }
    val ctx = LocalContext.current
    val tests = remember { mutableStateMapOf<String, TestState>() }
    val testMutex = remember { Mutex() }
    // The row whose actions are showing. Only ever one, and nothing to begin
    // with: arriving at the list should show the list, not a card mid-flight.
    var openId by remember { mutableStateOf("") }

    // One test at a time; `phase` marks which metric is currently measuring.
    suspend fun testOne(s: ServerConfig) = testMutex.withLock {
        tests[s.id] = TestState(phase = "tcp")
        val h = withContext(Dispatchers.IO) { XrayTester.start(ctx, s) }
        if (h == null) { tests[s.id] = TestState(error = "core error"); return@withLock }
        try {
            val ping = withContext(Dispatchers.IO) { Diagnostics.tcpPing(s.address, s.port) }
            tests[s.id] = TestState(tcp = ping, phase = "down")
            val down = withContext(Dispatchers.IO) { Diagnostics.httpLatency(h.port) }
            tests[s.id] = TestState(tcp = ping, down = down, phase = "up")
            val up = withContext(Dispatchers.IO) { Diagnostics.uploadTest(h.port) }
            tests[s.id] = TestState(tcp = ping, down = down, up = up)
        } finally { withContext(Dispatchers.IO) { XrayTester.stop(h) } }
    }
    fun runTest(s: ServerConfig) { scope.launch { testOne(s) } }
    fun testAll() { scope.launch { for (s in store.servers.toList()) testOne(s) } }
    val testingAll = tests.values.any { it.phase.isNotEmpty() }

    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        /* ---- header: title, ping all, add ---- */
        Row(
            Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 14.dp, bottom = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Servers", color = TXT, fontSize = 20.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
            Text(
                if (testingAll) "testing…" else "ping all",
                color = PRIMARY, fontSize = 10.sp, fontFamily = MONO,
                modifier = Modifier.clip(RoundedCornerShape(50)).border(1.dp, PRIMARY_DIM, RoundedCornerShape(50))
                    .clickable(enabled = !testingAll) { testAll() }
                    .padding(horizontal = 10.dp, vertical = 7.dp)
            )
            Spacer(Modifier.width(12.dp))
            Box {
                Box(
                    Modifier.size(34.dp).clip(RoundedCornerShape(10.dp)).background(PRIMARY).clickable { addMenu = true },
                    contentAlignment = Alignment.Center
                ) { Text("+", color = ON_PRIMARY, fontSize = 18.sp, fontWeight = FontWeight.Bold) }
                DropdownMenu(addMenu, { addMenu = false }, modifier = Modifier.background(CARD)) {
                    listOf(
                        "import" to "Link or subscription",
                        "wg" to "WireGuard",
                        "proxy" to "SOCKS / HTTP"
                    ).forEach { (key, label) ->
                        DropdownMenuItem(
                            text = { Text(label, color = TXT, fontSize = 13.sp) },
                            onClick = { addMenu = false; sheet = key }
                        )
                    }
                }
            }
        }
        HorizontalDivider(color = BG2)

        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).imePadding().padding(horizontal = 16.dp)) {
            Spacer(Modifier.height(14.dp))
            OutlinedTextField(
                q, { q = it }, Modifier.fillMaxWidth(),
                placeholder = { Text("Search…", fontSize = 13.sp) },
                leadingIcon = { Icon(Icons.Filled.Search, null, Modifier.size(18.dp)) },
                singleLine = true, shape = RoundedCornerShape(14.dp), colors = tfColors()
            )

            if (store.servers.isEmpty()) EmptyHint("No servers yet — tap + to add one.")
            // Grouped by where a config came from, as the desktop list is: what
            // you typed yourself first, then one section per subscription. With
            // a subscription of thirteen and a handful of your own, an
            // undifferentiated list makes your own impossible to find again.
            val shown = store.servers.filter { it.name.contains(q, true) || it.address.contains(q, true) }
            val groups = buildList {
                val byHand = shown.filter { it.subId == null }
                if (byHand.isNotEmpty()) add("ADDED BY HAND" to byHand)
                store.subs.forEach { sub ->
                    val mine = shown.filter { it.subId == sub.id }
                    if (mine.isNotEmpty()) add(sub.name.uppercase() to mine)
                }
                // A config whose subscription was deleted still belongs somewhere.
                val orphans = shown.filter { s -> s.subId != null && store.subs.none { it.id == s.subId } }
                if (orphans.isNotEmpty()) add("FROM A REMOVED SUBSCRIPTION" to orphans)
            }
            groups.forEach { (title, list) ->
                Row(Modifier.fillMaxWidth().padding(top = 18.dp, bottom = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(title, color = MUTED, fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        "${list.size}", color = MUTED2, fontSize = 9.sp, fontFamily = MONO,
                        modifier = Modifier.clip(RoundedCornerShape(50)).background(CARD).padding(horizontal = 7.dp, vertical = 2.dp)
                    )
                    Spacer(Modifier.width(10.dp))
                    HorizontalDivider(color = STROKE)
                }
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    list.forEach { s ->
                        ConfigCard(
                            s,
                            selected = selectedId == s.id,
                            open = openId == s.id,
                            result = tests[s.id],
                            onSelect = { store.saveSelection(s.id); selectedId = s.id },
                            onToggle = { openId = if (openId == s.id) "" else s.id },
                            onTest = { runTest(s) },
                            onCopy = { copyLink(ctx, s) },
                            onQr = { qrServer = s },
                            onEdit = { editId = s.id },
                            onDelete = { confirmDelete = s }
                        )
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
        }
        qrServer?.let { QrDialog(it) { qrServer = null } }
    }
    // Delete is one tap away inside the card now, so it asks first.
    confirmDelete?.let { victim ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            containerColor = CARD,
            title = { Text("Delete this config?", color = TXT, fontSize = 16.sp) },
            text = { Text(victim.name, color = MUTED, fontSize = 13.sp, fontFamily = MONO) },
            confirmButton = {
                TextButton(onClick = { store.deleteServer(victim.id); confirmDelete = null; bump() }) {
                    Text("Delete", color = BAD)
                }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text("Cancel", color = MUTED) } }
        )
    }
    AddConfigSheets(store, sheet, { sheet = it }, bump)
    val editing = editId?.let { store.serverById(it) }
    if (editing != null) EditConfigSheet(editing, onDismiss = { editId = null }) { updated ->
        val idx = store.servers.indexOfFirst { it.id == updated.id }
        if (idx >= 0) { store.servers[idx] = updated; store.saveServers() }
        editId = null; bump()
    }
}


/** Shared add-config flow (paste / QR / manual) usable from Home and Servers. */
@Composable
private fun AddConfigSheets(store: Store, sheet: String?, setSheet: (String?) -> Unit, bump: () -> Unit) {
    val ctx = LocalContext.current
    var importText by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    fun addSubAndFetch(url: String) {
        val sub = Subscription(newId("sub"), url.trim().take(30), url.trim())
        store.subs.add(sub); store.saveSubs()
        Toast.makeText(ctx, "Fetching subscription…", Toast.LENGTH_SHORT).show()
        scope.launch {
            try {
                val out = withContext(Dispatchers.IO) { SubFetch.fetch(ctx, store, sub.url) { s -> VpnState.addLog(s) } }
                val r = out.result
                VpnState.addLog("Subscription ${sub.url}: ${r.servers.size} servers via ${out.via}")
                store.servers.removeAll { it.subId == sub.id }
                val tagged = r.servers.map { it.copy(subId = sub.id) }
                store.servers.addAll(tagged); store.saveServers()
                if (tagged.isNotEmpty() && store.selection.isEmpty()) store.saveSelection(store.servers.first().id)
                val idx = store.subs.indexOfFirst { it.id == sub.id }
                if (idx >= 0) store.subs[idx] = sub.copy(serverCount = tagged.size, lastUpdated = System.currentTimeMillis(),
                    upload = r.usage?.upload ?: 0, download = r.usage?.download ?: 0, total = r.usage?.total ?: 0, expire = r.usage?.expire ?: 0)
                store.saveSubs(); Toast.makeText(ctx, "Subscription: ${tagged.size} servers added", Toast.LENGTH_SHORT).show(); bump()
            } catch (e: Exception) {
                VpnState.addLog("Subscription ${sub.url}: ${e.message}")
                Toast.makeText(ctx, "Subscription failed — see More → Logs", Toast.LENGTH_LONG).show(); bump()
            }
        }
    }
    // Auto-detect: http(s) lines -> subscriptions (fetched); the rest -> config(s).
    fun smartImport(text: String) {
        val lines = text.split(Regex("\\r?\\n")).map { it.trim() }.filter { it.isNotEmpty() }
        val isUrl = { s: String -> s.startsWith("http://", true) || s.startsWith("https://", true) }
        val urls = lines.filter(isUrl)
        val rest = lines.filterNot(isUrl).joinToString("\n")
        urls.forEach { addSubAndFetch(it) }
        if (rest.isNotBlank()) {
            val (parsed, errs) = LinkParser.parseMany(rest)
            store.servers.addAll(parsed); store.saveServers()
            if (parsed.isNotEmpty() && store.selection.isEmpty()) store.saveSelection(store.servers.first().id)
            if (urls.isEmpty()) Toast.makeText(ctx, "${parsed.size} config(s) added" + if (errs.isNotEmpty()) " (${errs.size} errors)" else "", Toast.LENGTH_SHORT).show()
        } else if (urls.isEmpty()) Toast.makeText(ctx, "Nothing recognized", Toast.LENGTH_SHORT).show()
        bump()
    }
    val qrLauncher = rememberLauncherForActivityResult(ScanContract()) { res ->
        val t = res.contents; if (!t.isNullOrBlank()) { smartImport(t); setSheet(null); bump() }
    }
    fun launchQr() = qrLauncher.launch(ScanOptions().setOrientationLocked(false).setBeepEnabled(false).setPrompt("Point the camera at the config QR"))
    fun pasteClip() {
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val t = cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(ctx)?.toString()
        if (!t.isNullOrBlank()) importText = t else Toast.makeText(ctx, "Clipboard is empty", Toast.LENGTH_SHORT).show()
    }
    when (sheet) {
        "import" -> AddLinkSheet(importText, { importText = it }, { pasteClip() }, { launchQr() }, { setSheet(null) }) {
            if (importText.isNotBlank()) smartImport(importText); importText = ""; setSheet(null); bump()
        }
        "wg" -> WgSheet(store, { setSheet(null) }) { setSheet(null); bump() }
        "proxy" -> ProxySheet(store, { setSheet(null) }) { setSheet(null); bump() }
        else -> {}
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun AddLinkSheet(value: String, onValue: (String) -> Unit, onPaste: () -> Unit, onScan: () -> Unit, onDismiss: () -> Unit, onSubmit: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = CARD) {
        Column(Modifier.fillMaxWidth().imePadding().padding(16.dp).padding(bottom = 16.dp)) {
            Text("Add config", color = TXT, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(4.dp))
            Text("vless/vmess/trojan/ss/socks/wireguard link, or a subscription URL / base64", color = MUTED, fontSize = 11.sp)
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(value, onValue, Modifier.fillMaxWidth(), placeholder = { Text("Paste or type here…", fontSize = 12.sp) }, minLines = 3, maxLines = 8, shape = RoundedCornerShape(14.dp), colors = tfColors())
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onPaste, modifier = Modifier.weight(1f)) { Icon(Icons.Filled.ContentPaste, null, Modifier.size(18.dp)); Spacer(Modifier.width(6.dp)); Text("Paste") }
                OutlinedButton(onClick = onScan, modifier = Modifier.weight(1f)) { Icon(Icons.Filled.QrCodeScanner, null, Modifier.size(18.dp)); Spacer(Modifier.width(6.dp)); Text("Scan QR") }
            }
            Spacer(Modifier.height(10.dp)); Button(onClick = onSubmit, modifier = Modifier.fillMaxWidth()) { Text("Add") }
        }
    }
}

/** One test's measurements. `phase` = the metric currently measuring. */
data class TestState(val tcp: Long? = null, val down: Long? = null, val up: Long? = null, val phase: String = "", val error: String? = null)


private fun fmtLat(ms: Long?): String = when {
    ms == null -> "—"; ms < 0 -> "×"; ms >= 1000 -> String.format("%.1fs", ms / 1000.0); else -> "$ms"
}
private fun latColor(ms: Long?): Color = when {
    ms == null -> MUTED; ms < 0 -> BAD; ms < 300 -> PRIMARY; ms < 900 -> AMBER; else -> BAD
}

/**
 * One server. Always the same row; selecting only changes its colours, and the
 * actions open underneath it when you ask for them (design 2c).
 *
 * Three things this shape is careful about, each of them a complaint about the
 * first attempt:
 *
 *  - SELECTING DOES NOT MOVE ANYTHING. The row keeps its height and its place;
 *    only the border, the fill and the IN USE badge change. Nor does it rebuild
 *    the screen: the list used to jump back to the top when you picked a config
 *    near the bottom, because selecting called bump() and `key(rev)` in App
 *    throws away the scroll position with everything else.
 *  - THE PANEL DOES NOT OPEN BY ITSELF. Tapping a row selects it, full stop.
 *    Test, copy, QR, edit and delete arrive only when you open the row — tap it
 *    again, or tap the chevron — so choosing a config never re-flows the list
 *    under your thumb.
 *  - IN USE IS WRITTEN BESIDE THE NAME, closed or open, which is where the
 *    design puts it and the only place it means anything at a glance.
 */
@Composable private fun ConfigCard(
    s: ServerConfig,
    selected: Boolean,
    open: Boolean,
    result: TestState?,
    onSelect: () -> Unit,
    onToggle: () -> Unit,
    onTest: () -> Unit,
    onCopy: () -> Unit,
    onQr: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit
) {
    val (flag, label) = ServerLabel.split(s.name)
    val where = "${badge(s.protocol)} · ${s.address}" + if (s.port > 0) ":${s.port}" else ""

    Column(
        Modifier.fillMaxWidth()
            .clip(RoundedCornerShape(if (open) 16.dp else 14.dp))
            .background(if (selected) CARD_SEL else CARD)
            .border(
                if (selected) 1.5.dp else 1.dp,
                if (selected) PRIMARY else STROKE,
                RoundedCornerShape(if (open) 16.dp else 14.dp)
            )
    ) {
        /* ---- the row itself: identical whether or not it is open ---- */
        Row(
            Modifier.fillMaxWidth()
                // Tap to use it. Tapping the one already in use opens it, so the
                // actions are one deliberate tap away and never a surprise.
                .clickable { if (selected) onToggle() else onSelect() }
                .padding(start = 14.dp, end = 6.dp, top = 13.dp, bottom = 13.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Leading(flag, s.protocol)
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        label, color = TXT, fontSize = 14.sp, fontWeight = FontWeight.SemiBold,
                        maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false)
                    )
                    if (selected) {
                        Spacer(Modifier.width(7.dp))
                        Text(
                            "IN USE", color = ON_PRIMARY, fontSize = 8.sp, fontFamily = MONO,
                            fontWeight = FontWeight.SemiBold, letterSpacing = 0.1.em, maxLines = 1,
                            modifier = Modifier.clip(RoundedCornerShape(4.dp)).background(PRIMARY)
                                .padding(horizontal = 5.dp, vertical = 3.dp)
                        )
                    }
                }
                Spacer(Modifier.height(5.dp))
                Text(where, color = if (selected) MUTED else SUBTLE, fontSize = 10.sp, fontFamily = MONO, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Spacer(Modifier.width(8.dp))
            val r = result
            when {
                r?.phase?.isNotEmpty() == true -> Text("…", color = AMBER, fontSize = 12.sp, fontFamily = MONO)
                r?.error != null -> Text("×", color = BAD, fontSize = 12.sp, fontFamily = MONO)
                r?.tcp != null -> Text(fmtLat(r.tcp), color = latColor(r.tcp), fontSize = 12.sp, fontFamily = MONO)
                else -> Text("—", color = SUBTLE, fontSize = 12.sp, fontFamily = MONO)
            }
            // The one affordance that says there is more in here, and opens it
            // without changing which config is in use.
            IconButton(onClick = onToggle, modifier = Modifier.size(34.dp)) {
                Icon(
                    if (open) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                    if (open) "close" else "actions",
                    tint = if (selected) PRIMARY else MUTED2,
                    modifier = Modifier.size(20.dp)
                )
            }
        }

        if (!open) return@Column

        /* ---- what it measured ---- */
        // USED is not among them: this client keeps no per-config byte count, and
        // a tile that can only ever say "—" is worth less than the upload figure,
        // which is the side that actually goes bad.
        Row(Modifier.fillMaxWidth().padding(start = 14.dp, end = 14.dp, bottom = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Tile(Modifier.weight(1f), "TCP", result?.tcp, result?.phase == "tcp", latColor(result?.tcp))
            Tile(Modifier.weight(1f), "REAL", result?.down, result?.phase == "down", latColor(result?.down))
            Tile(Modifier.weight(1f), "UP", result?.up, result?.phase == "up", latColor(result?.up))
        }
        result?.error?.let {
            Text(it, color = BAD, fontSize = 10.sp, fontFamily = MONO, modifier = Modifier.padding(start = 14.dp, end = 14.dp, bottom = 10.dp))
        }

        /* ---- and what you can do with it ---- */
        HorizontalDivider(color = if (selected) STROKE_SEL else STROKE)
        Row(Modifier.fillMaxWidth().height(IntrinsicSize.Min)) {
            val rule = if (selected) STROKE_SEL else STROKE
            CardAction("test", PRIMARY, Modifier.weight(1f), onTest)
            ActionRule(rule)
            CardAction("copy", TXT2, Modifier.weight(1f), onCopy)
            ActionRule(rule)
            CardAction("qr", TXT2, Modifier.weight(1f), onQr)
            ActionRule(rule)
            CardAction("edit", TXT2, Modifier.weight(1f), onEdit)
            ActionRule(rule)
            CardAction("del", BAD, Modifier.weight(1f), onDelete)
        }
    }
}

/** The country flag from the name, or the protocol as a chip when there is none. */
@Composable private fun Leading(flag: String?, proto: String) {
    if (flag != null) Text(flag, fontSize = 16.sp)
    else Text(
        badge(proto), color = protoColor(proto), fontSize = 8.sp, fontFamily = MONO, maxLines = 1,
        modifier = Modifier.clip(RoundedCornerShape(5.dp))
            .border(1.dp, protoColor(proto).copy(alpha = 0.35f), RoundedCornerShape(5.dp))
            .padding(horizontal = 5.dp, vertical = 3.dp)
    )
}

@Composable private fun Tile(modifier: Modifier, label: String, ms: Long?, measuring: Boolean, tint: Color) {
    Column(modifier.clip(RoundedCornerShape(10.dp)).background(TILE).padding(9.dp)) {
        Text(label, color = MUTED2, fontSize = 8.sp, fontFamily = MONO, letterSpacing = 0.08.em)
        Spacer(Modifier.height(6.dp))
        Text(
            if (measuring) "…" else fmtLat(ms),
            color = if (measuring) AMBER else tint,
            fontSize = 13.sp, fontFamily = MONO, fontWeight = FontWeight.Bold, maxLines = 1
        )
    }
}

@Composable private fun CardAction(label: String, tint: Color, modifier: Modifier, onClick: () -> Unit) {
    Text(
        label, color = tint, fontSize = 10.sp, fontFamily = MONO, textAlign = TextAlign.Center, maxLines = 1,
        modifier = modifier.clickable { onClick() }.padding(vertical = 13.dp)
    )
}

@Composable private fun ActionRule(color: Color) {
    Box(Modifier.width(1.dp).fillMaxHeight().background(color))
}

/** QR + copy for a config link that carries ALL settings (incl. patterniha). */
@Composable private fun QrDialog(s: ServerConfig, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val link = remember(s.id) { LinkParser.buildShareLink(s) }
    val bmp = remember(link) { qrBitmap(link) }
    Dialog(onDismissRequest = onDismiss) {
        Surface(shape = RoundedCornerShape(16.dp), color = CARD) {
            Column(Modifier.padding(18.dp).widthIn(max = 320.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Text("Share config", color = TXT, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(12.dp))
                // FilterQuality.None: the bitmap is one pixel per module, so nearest
                // neighbour turns each into a crisp square. The default (bilinear) blurs
                // the module edges a scanner has to threshold.
                if (bmp != null) Image(
                    bmp.asImageBitmap(), "QR",
                    Modifier.size(248.dp).clip(RoundedCornerShape(10.dp)).background(Color.White).padding(6.dp),
                    filterQuality = FilterQuality.None
                )
                else Text("Link too long for a QR — use Copy.", color = MUTED, fontSize = 12.sp)
                Spacer(Modifier.height(10.dp))
                Text(link, color = MUTED, fontSize = 10.sp, maxLines = 3, overflow = TextOverflow.Ellipsis)
                Spacer(Modifier.height(12.dp))
                Button(onClick = { copyLink(ctx, s); onDismiss() }, modifier = Modifier.fillMaxWidth()) { Text("Copy link") }
            }
        }
    }
}

/**
 * The share QR, one pixel per module — the UI scales it up (FilterQuality.None).
 *
 * Asking ZXing for a fixed 640px bitmap made a module a non-integer number of
 * pixels, so it rounded and some modules came out a pixel wider than their
 * neighbours; it also cost 409,600 setPixel calls on the composition thread, and
 * Compose then resampled the result with its default bilinear filter. Three ways
 * to soften the edges a scanner has to threshold. Width and height 0 make ZXing
 * return the matrix at its own size (renderResult takes max(requested, matrix)),
 * which has no resampling error to inherit.
 *
 * MARGIN is the 4 modules of quiet zone the QR spec requires; it was 1, and a
 * scanner is entitled to refuse that.
 */
private fun qrBitmap(text: String): android.graphics.Bitmap? = try {
    val hints = mapOf(
        com.google.zxing.EncodeHintType.MARGIN to 4,
        com.google.zxing.EncodeHintType.CHARACTER_SET to "UTF-8"
    )
    val m = com.google.zxing.qrcode.QRCodeWriter().encode(text, com.google.zxing.BarcodeFormat.QR_CODE, 0, 0, hints)
    val w = m.width; val h = m.height
    val px = IntArray(w * h)
    for (y in 0 until h) { val row = y * w; for (x in 0 until w) px[row + x] = if (m.get(x, y)) android.graphics.Color.BLACK else android.graphics.Color.WHITE }
    android.graphics.Bitmap.createBitmap(px, w, h, android.graphics.Bitmap.Config.RGB_565)
} catch (e: Exception) { null }

private fun copyLink(ctx: android.content.Context, s: ServerConfig) {
    val cm = ctx.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
    cm.setPrimaryClip(android.content.ClipData.newPlainText("config", LinkParser.buildShareLink(s)))
    android.widget.Toast.makeText(ctx, "Copied ✓", android.widget.Toast.LENGTH_SHORT).show()
}


/** One colour per protocol, used by the badge and anywhere a config is listed. */
private fun protoColor(proto: String): Color = when (proto) {
    "vless" -> PRIMARY
    "vmess" -> Color(0xFF84E1BC)
    "trojan" -> AMBER
    "shadowsocks" -> Color(0xFFCDA9FF)
    "wireguard" -> Color(0xFF8FB3AA)
    "socks", "http" -> Color(0xFFF19DC8)
    else -> MUTED
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun WgSheet(store: Store, onDismiss: () -> Unit, done: () -> Unit) {
    var name by remember { mutableStateOf("") }; var ep by remember { mutableStateOf("") }; var priv by remember { mutableStateOf("") }; var pub by remember { mutableStateOf("") }
    var addr by remember { mutableStateOf("") }; var allowed by remember { mutableStateOf("0.0.0.0/0, ::/0") }; var psk by remember { mutableStateOf("") }; var mtu by remember { mutableStateOf("1420") }; var reserved by remember { mutableStateOf("") }
    var dnsLine by remember { mutableStateOf("") }
    val wgSheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = wgSheetState, containerColor = CARD) {
        Column(Modifier.fillMaxWidth().fillMaxHeight(0.92f).verticalScroll(rememberScrollState()).imePadding().padding(16.dp).padding(bottom = 24.dp)) {
            Text("Add WireGuard", color = TXT, fontWeight = FontWeight.Bold)
            Fld("Name", name) { name = it }; Fld("Endpoint (host:port)", ep) { ep = it }; Fld("Private Key", priv) { priv = it }; Fld("Peer Public Key", pub) { pub = it }
            Fld("Address (local /32)", addr) { addr = it }; Fld("Allowed IPs", allowed) { allowed = it }; Fld("PSK (optional)", psk) { psk = it }; Fld("MTU", mtu) { mtu = it }; Fld("Reserved (optional)", reserved) { reserved = it }
            Fld("DNS (optional) — the .conf's DNS line: resolver and search domains", dnsLine) { dnsLine = it }
            Text("e.g. 192.168.60.1, corp.example — names under corp.example are asked of that resolver through this tunnel (needs DNS managed by the app).", color = MUTED, fontSize = 11.sp)
            Spacer(Modifier.height(10.dp))
            Button(onClick = { if (ep.isNotBlank() && priv.isNotBlank() && pub.isNotBlank()) { val s = LinkParser.makeWireguardServer(name, ep, priv, pub, addr, allowed, psk, mtu, reserved, dnsLine); store.servers.add(s); store.saveServers(); if (store.selection.isEmpty()) store.saveSelection(s.id); done() } }, modifier = Modifier.fillMaxWidth()) { Text("Add") }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun ProxySheet(store: Store, onDismiss: () -> Unit, done: () -> Unit) {
    var type by remember { mutableStateOf("socks") }; var name by remember { mutableStateOf("") }; var host by remember { mutableStateOf("") }; var port by remember { mutableStateOf("") }; var user by remember { mutableStateOf("") }; var pass by remember { mutableStateOf("") }
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = CARD) {
        Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).imePadding().padding(16.dp).padding(bottom = 16.dp)) {
            Text("Add SOCKS / HTTP", color = TXT, fontWeight = FontWeight.Bold)
            Row(Modifier.padding(vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) { FilterChip(type == "socks", { type = "socks" }, { Text("SOCKS5") }); FilterChip(type == "http", { type = "http" }, { Text("HTTP") }) }
            Fld("Name", name) { name = it }; Fld("Host", host) { host = it }; Fld("Port", port) { port = it }; Fld("Username (optional)", user) { user = it }; Fld("Password (optional)", pass) { pass = it }
            Spacer(Modifier.height(10.dp))
            Button(onClick = { if (host.isNotBlank() && port.isNotBlank()) { val s = LinkParser.makeProxyServer(type, name, host, port.toIntOrNull() ?: 1080, user, pass); store.servers.add(s); store.saveServers(); if (store.selection.isEmpty()) store.saveSelection(s.id); done() } }, modifier = Modifier.fillMaxWidth()) { Text("Add") }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun EditConfigSheet(server: ServerConfig, onDismiss: () -> Unit, onSave: (ServerConfig) -> Unit) {
    val f = remember(server.id) { ServerEditor.read(server) }
    var name by remember { mutableStateOf(f.name) }; var address by remember { mutableStateOf(f.address) }; var port by remember { mutableStateOf(f.port) }
    var cred by remember { mutableStateOf(f.cred) }; var network by remember { mutableStateOf(f.network) }; var security by remember { mutableStateOf(f.security) }
    var sni by remember { mutableStateOf(f.sni) }; var host by remember { mutableStateOf(f.host) }; var path by remember { mutableStateOf(f.path) }; var fp by remember { mutableStateOf(f.fp) }
    var pbk by remember { mutableStateOf(f.pbk) }; var sid by remember { mutableStateOf(f.sid) }; var allowInsecure by remember { mutableStateOf(f.allowInsecure) }; var method by remember { mutableStateOf(f.method) }
    var pUser by remember { mutableStateOf(f.proxyUser) }; var pPass by remember { mutableStateOf(f.proxyPass) }
    var wgPub by remember { mutableStateOf(f.wgPub) }; var wgAddr by remember { mutableStateOf(f.wgAddr) }; var wgPsk by remember { mutableStateOf(f.wgPsk) }
    var wgMtu by remember { mutableStateOf(f.wgMtu) }; var wgReserved by remember { mutableStateOf(f.wgReserved) }; var wgAllowed by remember { mutableStateOf(f.wgAllowed) }
    var wgDns by remember { mutableStateOf(f.wgDns) }
    var fragment by remember { mutableStateOf(f.fragment) }
    val noisePresetKeys = listOf("random", "faketls", "fakehello")
    var noisePreset by remember { mutableStateOf(when {
        f.noise.isBlank() -> "off"
        f.noise.lowercase() in noisePresetKeys -> if (f.noise.lowercase() == "fakehello") "faketls" else f.noise.lowercase()
        else -> "custom"
    }) }
    var noiseCustom by remember { mutableStateOf(if (noisePreset == "custom") f.noise else "") }
    val effectiveNoise = when (noisePreset) { "off" -> ""; "custom" -> noiseCustom.trim(); else -> noisePreset }
    var cipherSuites by remember { mutableStateOf(f.cipherSuites) }
    var finalMask by remember { mutableStateOf(f.finalMask) }
    var engine by remember { mutableStateOf(f.engine) }
    val isStd = server.protocol == "vless" || server.protocol == "vmess" || server.protocol == "trojan"

    // Open FULLY expanded: a partially-expanded sheet swallows the drag as a sheet
    // gesture instead of scrolling the content, which made everything below the
    // fold (fingerprint, patterniha…) unreachable — it looked like those fields
    // didn't exist. Fill the height so the inner scroll owns the gesture.
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState, containerColor = CARD) {
        Column(Modifier.fillMaxWidth().fillMaxHeight(0.92f).verticalScroll(rememberScrollState()).imePadding().padding(16.dp).padding(bottom = 24.dp)) {
            Text("Edit · ${badge(server.protocol)}", color = TXT, fontWeight = FontWeight.Bold)
            Fld("Name", name) { name = it }; Fld("Address — real server/IP (connection goes here)", address) { address = it }; Fld("Port", port) { port = it }
            when (server.protocol) {
                "vless", "vmess" -> Fld("UUID", cred) { cred = it }
                "trojan" -> Fld("Password", cred) { cred = it }
                "shadowsocks" -> { Fld("Password", cred) { cred = it }; Fld("Method", method) { method = it } }
                "socks", "http" -> { Fld("Username (optional)", pUser) { pUser = it }; Fld("Password (optional)", pPass) { pPass = it } }
                "wireguard" -> Fld("Private Key", cred) { cred = it }
            }
            if (isStd) {
                DropPick("Transport", listOf("tcp" to "tcp", "ws" to "ws", "grpc" to "grpc", "h2" to "h2", "xhttp" to "xhttp", "kcp" to "kcp"), network) { network = it }
                DropPick("Security", listOf("none" to "none", "tls" to "tls", "reality" to "reality"), security) { security = it }
                // Context-aware SNI section: it means different things for
                // reality / CDN-fronting / plain-TLS, so say the right thing.
                val frontable = network in listOf("ws", "grpc", "xhttp", "splithttp", "h2", "http")
                if (security == "tls" || security == "reality") {
                    val head = if (security == "reality") "🛡  REALITY (mimic a real site)" else "🛡  TLS / CDN — SNI & bypass"
                    val sniLabel = when { security == "reality" -> "SNI — must match server's serverNames"; frontable -> "SNI — real domain (CDN reads this; = Host)"; else -> "SNI — must match the server certificate" }
                    val sniHint = when {
                        security == "reality" -> "REALITY is not fronting: the SNI must be the exact site your server mimics (serverNames), e.g. www.google.com. Connection still goes to Address."
                        frontable -> "SNI and Host are your real domain; the CDN routes by the SNI, so they must match (a different fake SNI here won't connect). To bypass DPI, turn on Hide SNI below."
                        else -> "Connection goes to Address; the SNI is sent in the handshake and must match the server certificate (or Allow Insecure)."
                    }
                    Text(head, color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 2.dp))
                    Fld(sniLabel, sni) { sni = it }
                    if (security == "tls" && frontable) Fld("Host — same as SNI", host) { host = it }
                    Text(sniHint, color = MUTED, fontSize = 11.sp)
                    // Working bypass: fragment the ClientHello so DPI can't read the SNI.
                    SwitchRow("🕵 Hide SNI from DPI (fragment / patterniha)", fragment.isNotBlank()) {
                        fragment = if (it) (if (fragment.isBlank()) "tlshello,100-200,10-20" else fragment) else ""
                    }
                }
                Fld("Path / ServiceName", path) { path = it }
                DropPick("Fake ClientHello (browser fingerprint / uTLS)", listOf("chrome" to "chrome", "firefox" to "firefox", "safari" to "safari", "ios" to "ios", "android" to "android", "edge" to "edge", "random" to "random", "randomized" to "randomized", "unsafe" to "unsafe (custom cipherSuites)"), fp) { fp = it }
                if (security == "reality") { Fld("Public Key (pbk)", pbk) { pbk = it }; Fld("Short ID (sid)", sid) { sid = it } }
                // The core no longer accepts allowInsecure: the switch means "pin the
                // certificate this server presents on first use" (CertPin.kt).
                SwitchRow("Allow insecure — pin the server's certificate on first use", allowInsecure) { allowInsecure = it }
                // patterniha custom-TLS
                Text("🧩  patterniha — finalMask / cipherSuites", color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 2.dp))
                Fld("cipherSuites (use with fingerprint = unsafe)", cipherSuites) { cipherSuites = it }
                Fld("finalMask (JSON)", finalMask) { finalMask = it }
                Text("Address = a clean Cloudflare IP, fingerprint = unsafe, paste cipherSuites + finalMask. Paste the JSON exactly; the app does not rewrite it.", color = MUTED, fontSize = 11.sp)
            }
            if (server.protocol == "wireguard") {
                Fld("Peer Public Key", wgPub) { wgPub = it }; Fld("Address (/32)", wgAddr) { wgAddr = it }; Fld("PSK", wgPsk) { wgPsk = it }
                Fld("MTU", wgMtu) { wgMtu = it }; Fld("Reserved", wgReserved) { wgReserved = it }; Fld("Allowed IPs", wgAllowed) { wgAllowed = it }
                Fld("DNS — resolver and search domains (e.g. 192.168.60.1, corp.example)", wgDns) { wgDns = it }
            }
            HorizontalDivider(Modifier.padding(vertical = 8.dp), color = STROKE)
            Text("⚙  Advanced — DPI evasion (optional)", color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(bottom = 4.dp))
            DropPick(
                "Core / Engine",
                listOf(
                    "xray" to "Xray (default)",
                    "xray-pattn" to "Xray-PattN (accepts plaintext VLESS/Trojan)",
                    "sing-box" to "sing-box (fake ClientHello / uTLS)"
                ),
                engine
            ) { engine = it }
            Text(
                "Only this config runs on the chosen core. Pick Xray-PattN when a config has no TLS " +
                    "and the official core refuses it outright; a chain runs on PattN as soon as ONE of " +
                    "its hops asks for it. Both extra cores are bundled for arm64 only — elsewhere the " +
                    "config falls back to the in-process core.",
                color = MUTED, fontSize = 11.sp
            )
            Spacer(Modifier.height(8.dp))
            Fld("Fragment (packets,length,interval — empty = off)", fragment) { fragment = it }
            Text("e.g. tlshello,100-200,10-20", color = MUTED, fontSize = 11.sp)
            Spacer(Modifier.height(8.dp))
            DropPick("Noise (decoy packets before handshake)", listOf("off" to "Off", "random" to "Random", "faketls" to "Fake ClientHello", "custom" to "Custom…"), noisePreset) { noisePreset = it }
            if (noisePreset == "custom") {
                Fld("Noise spec (type:packet:delay; …)", noiseCustom) { noiseCustom = it }
                Text("Decoy packets before the real handshake. type = rand/str/base64/hex.", color = MUTED, fontSize = 11.sp)
            }
            Spacer(Modifier.height(10.dp))
            Button(onClick = {
                val nf = ServerEditor.Fields(name, address, port, cred, network, security, sni, host, path, fp, pbk, sid, allowInsecure, f.alpn, method, pUser, pPass, wgPub, wgAddr, wgPsk, wgMtu, wgReserved, wgAllowed, wgDns, fragment, effectiveNoise, cipherSuites, finalMask, engine, f.spx, f.xmode, f.seed, f.headerType, f.xhttpExtra)
                onSave(ServerEditor.apply(server, nf))
            }, modifier = Modifier.fillMaxWidth()) { Text("Save") }
        }
    }
}

/* ================================ SUBS ================================ */
@Composable
private fun SubsScreen(store: Store, bump: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var url by remember { mutableStateOf("") }; var name by remember { mutableStateOf("") }; var busy by remember { mutableStateOf(false) }; var msg by remember { mutableStateOf("") }
    fun refresh(sub: Subscription) {
        busy = true; msg = "Fetching…"
        scope.launch {
            try {
                val out = withContext(Dispatchers.IO) { SubFetch.fetch(ctx, store, sub.url) { s -> VpnState.addLog(s) } }
                val r = out.result
                VpnState.addLog("Subscription ${sub.url}: ${r.servers.size} servers via ${out.via}")
                store.servers.removeAll { it.subId == sub.id }
                val tagged = r.servers.map { it.copy(subId = sub.id) }; store.servers.addAll(tagged); store.saveServers()
                val idx = store.subs.indexOfFirst { it.id == sub.id }
                if (idx >= 0) store.subs[idx] = sub.copy(serverCount = tagged.size, lastUpdated = System.currentTimeMillis(), upload = r.usage?.upload ?: 0, download = r.usage?.download ?: 0, total = r.usage?.total ?: 0, expire = r.usage?.expire ?: 0)
                store.saveSubs(); msg = "${tagged.size} servers updated"
            } catch (e: Exception) {
                msg = "Error: ${e.message}"
                VpnState.addLog("Subscription ${sub.url}: ${e.message}")
            } finally { busy = false; bump() }
        }
    }
    // Auto update. `autoUpdateSubs` and `autoUpdateInterval` were in the settings
    // model from the start and read by nothing at all, so a subscription only ever
    // refreshed when the user pressed the button. Doing it when this screen opens
    // needs no background work and no extra permission: a list you are looking at
    // is the list worth being current.
    var settings by remember { mutableStateOf(store.settings) }
    LaunchedEffect(Unit) {
        if (!settings.autoUpdateSubs) return@LaunchedEffect
        val maxAge = settings.autoUpdateInterval.coerceAtLeast(5) * 60_000L
        val now = System.currentTimeMillis()
        store.subs.toList().forEach { sub -> if (now - sub.lastUpdated >= maxAge) refresh(sub) }
    }
    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        TopBar("Subscriptions") {
            IconButton(onClick = { store.subs.toList().forEach { refresh(it) } }, enabled = !busy && store.subs.isNotEmpty()) {
                Icon(Icons.Filled.Refresh, "refresh all", tint = PRIMARY)
            }
        }
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).imePadding().padding(horizontal = 16.dp)) {
            Card(Modifier.fillMaxWidth().padding(bottom = 10.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                Row(Modifier.padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Auto update", color = TXT, fontSize = 13.sp)
                        Text("when this screen opens, every ${settings.autoUpdateInterval} min", color = MUTED, fontSize = 11.sp, fontFamily = MONO)
                    }
                    Switch(settings.autoUpdateSubs, { v -> settings = settings.copy(autoUpdateSubs = v); store.saveSettings(settings) },
                        colors = SwitchDefaults.colors(checkedThumbColor = ON_PRIMARY, checkedTrackColor = PRIMARY, uncheckedThumbColor = MUTED, uncheckedTrackColor = CARD2, uncheckedBorderColor = STROKE))
                }
            }
            Fld("Subscription URL (https://…)", url) { url = it }; Fld("Name (optional)", name) { name = it }
            Button(onClick = { if (url.isNotBlank()) { val sub = Subscription(newId("sub"), name.ifBlank { url.take(24) }, url.trim()); store.subs.add(sub); store.saveSubs(); url = ""; name = ""; refresh(sub) } }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Add & fetch") }
            if (msg.isNotEmpty()) Text(msg, color = if (msg.startsWith("Error")) BAD else PRIMARY, fontSize = 12.sp)
            Spacer(Modifier.height(8.dp))
            if (store.subs.isEmpty()) EmptyHint("No subscriptions yet.")
            store.subs.forEach { sub ->
                Card(Modifier.fillMaxWidth().padding(vertical = 5.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                    Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.CloudDownload, null, tint = PRIMARY); Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(sub.name, color = TXT, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(sub.url, color = MUTED2, fontSize = 10.sp, fontFamily = MONO, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(
                                "${sub.serverCount} servers" + if (sub.lastUpdated > 0) " · updated ${fmtAgo(System.currentTimeMillis() - sub.lastUpdated)}" else " · never updated",
                                color = MUTED, fontSize = 11.sp, fontFamily = MONO
                            )
                            if (sub.total > 0) {
                                val used = sub.upload + sub.download
                                val pct = (used.toDouble() / sub.total * 100).toInt().coerceIn(0, 100)
                                val barColor = if (pct >= 90) BAD else if (pct >= 70) AMBER else PRIMARY
                                Spacer(Modifier.height(4.dp))
                                Text("${fmtBytes(used)} / ${fmtBytes(sub.total)} · $pct%", color = MUTED, fontSize = 11.sp)
                                LinearProgressIndicator(progress = pct / 100f, modifier = Modifier.fillMaxWidth().height(5.dp).clip(RoundedCornerShape(3.dp)), color = barColor, trackColor = STROKE)
                            }
                            if (sub.expire > 0) {
                                val daysLeft = (sub.expire * 1000L - System.currentTimeMillis()) / 86_400_000L
                                Text(if (daysLeft >= 0) "$daysLeft days left" else "Expired", color = if (daysLeft < 0) BAD else if (daysLeft <= 3) AMBER else MUTED, fontSize = 11.sp)
                            }
                        }
                        IconButton(onClick = { refresh(sub) }) { Icon(Icons.Filled.Refresh, "refresh", tint = MUTED) }
                        IconButton(onClick = { store.servers.removeAll { it.subId == sub.id }; store.saveServers(); store.subs.removeAll { it.id == sub.id }; store.saveSubs(); bump() }) { Icon(Icons.Filled.DeleteOutline, "del", tint = BAD) }
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
        }
    }
}

/* ================================ POOL ================================ */
@Composable
private fun PoolScreen(store: Store, bump: () -> Unit, back: () -> Unit) {
    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        TopBar("Proxy Pool", back) {
            IconButton(onClick = { val used = usedPorts(store); var sp = 60001; while (used.contains(sp)) sp++; var hp = sp + 1; while (used.contains(hp)) hp++
                store.pool.add(PoolEntry(newId("px"), "Proxy ${store.pool.size + 1}", store.servers.firstOrNull()?.id ?: "", sp, hp, true)); store.savePool(); bump() }) { Icon(Icons.Filled.Add, "add", tint = PRIMARY) }
        }
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).imePadding().padding(horizontal = 16.dp)) {
            Text("Run several exits at once, each on its own local port (first enabled = primary tunnel exit).", color = MUTED, fontSize = 12.sp)
            Button(onClick = { store.saveSelection(Store.POOL_ID); bump() }, modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) { Text("Select pool for connection") }
            if (store.pool.isEmpty()) EmptyHint("No proxies yet.")
            store.pool.toList().forEachIndexed { idx, e ->
                Card(Modifier.fillMaxWidth().padding(vertical = 5.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                    Column(Modifier.padding(14.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(e.name, color = TXT, modifier = Modifier.weight(1f)); Switch(e.enabled, { store.pool[idx] = e.copy(enabled = it); store.savePool(); bump() })
                            IconButton(onClick = { store.pool.removeAt(idx); store.savePool(); bump() }) { Icon(Icons.Filled.DeleteOutline, null, tint = BAD) }
                        }
                        DropPick("Exit", targetOptions(store), e.target) { store.pool[idx] = e.copy(target = it); store.savePool(); bump() }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            NumFld("SOCKS", e.socksPort, Modifier.weight(1f)) { store.pool[idx] = e.copy(socksPort = it); store.savePool() }
                            NumFld("HTTP", e.httpPort, Modifier.weight(1f)) { store.pool[idx] = e.copy(httpPort = it); store.savePool() }
                        }
                        if (!store.poolTargetValid(e.target)) Text("⚠ invalid exit", color = AMBER, fontSize = 12.sp)
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
        }
    }
}

/* ================================ CHAINS ================================ */
@Composable
private fun ChainsScreen(store: Store, bump: () -> Unit, back: () -> Unit) {
    Screen("Proxy Chain", back, { IconButton(onClick = { store.chains.add(ChainConfig(newId("chain"), "Chain ${store.chains.size + 1}", emptyList())); store.saveChains(); bump() }) { Icon(Icons.Filled.Add, "add", tint = PRIMARY) } }) {
        if (store.chains.isEmpty()) EmptyHint("No chains yet.")
        store.chains.toList().forEachIndexed { idx, c ->
            val members = store.chainMembers(c)
            Card(Modifier.fillMaxWidth().padding(vertical = 5.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                Column(Modifier.padding(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("⛓ ${c.name}", color = TXT, modifier = Modifier.weight(1f))
                        if (store.chainReady(c)) IconButton(onClick = { store.saveSelection("chain:${c.id}"); bump() }) { Icon(Icons.Filled.CheckCircle, null, tint = if (store.selection == "chain:${c.id}") PRIMARY else MUTED) }
                        IconButton(onClick = { store.chains.removeAt(idx); store.saveChains(); bump() }) { Icon(Icons.Filled.DeleteOutline, null, tint = BAD) }
                    }
                    Text("Path: " + (members.joinToString(" → ") { it.name }.ifEmpty { "empty — add at least 2 servers" }), color = MUTED, fontSize = 12.sp)
                    members.forEachIndexed { mi, s -> Row(verticalAlignment = Alignment.CenterVertically) { Text("${mi + 1}. ${s.name}", color = TXT, fontSize = 13.sp, modifier = Modifier.weight(1f)); IconButton(onClick = { store.chains[idx] = c.copy(members = c.members.filter { it != s.id }); store.saveChains(); bump() }) { Icon(Icons.Filled.Close, null, tint = BAD) } } }
                    DropPick("+ add server", store.servers.filter { !c.members.contains(it.id) }.map { it.id to it.name }, "") { if (it.isNotEmpty()) { store.chains[idx] = c.copy(members = c.members + it); store.saveChains(); bump() } }
                }
            }
        }
    }
}

/* ================================ ROUTING ================================ */
@Composable
private fun RoutingScreen(store: Store, bump: () -> Unit, back: () -> Unit) {
    val ctx = LocalContext.current
    var s by remember { mutableStateOf(store.settings) }
    // Without geoip.dat/geosite.dat the core drops every geo rule, so the two
    // bypass modes and Block ads would do exactly nothing. Show that instead.
    val geo = remember { GeoAssets.available(ctx) }
    fun save(n: AppSettings) { s = n; store.saveSettings(n); bump() }
    Screen("Routing", back, {}) {
        Text("Routing mode", color = TXT, fontWeight = FontWeight.Bold)
        listOf(Triple("global", "Global (all via proxy)", false), Triple("bypass-ir", "Bypass Iran", true),
            Triple("bypass-cn", "Bypass China", true), Triple("direct", "Direct", false)).forEach { (v, l, needsGeo) ->
            val on = geo || !needsGeo
            Row(Modifier.fillMaxWidth().clickable(enabled = on) { save(s.copy(routingMode = v)) }, verticalAlignment = Alignment.CenterVertically) {
                RadioButton(s.routingMode == v, { save(s.copy(routingMode = v)) }, enabled = on)
                Text(if (on) l else "$l — unavailable", color = if (on) TXT else MUTED)
            }
        }
        if (!geo) Text("Bypass Iran, Bypass China and Block ads need the routing data files (geoip.dat / geosite.dat), which this build doesn't include — those rules would be dropped and the traffic would go through the proxy anyway.", color = MUTED, fontSize = 12.sp)
        SwitchRow("Block ads" + (if (geo) "" else " — unavailable"), s.blockAds && geo, enabled = geo) { save(s.copy(blockAds = it)) }
        SwitchRow("Sniffing", s.enableSniffing) { save(s.copy(enableSniffing = it)) }
        HorizontalDivider(Modifier.padding(vertical = 10.dp), color = STROKE)
        SwitchRow("Advanced routing", s.advancedRouting) { save(s.copy(advancedRouting = it)) }
        if (s.advancedRouting) {
            Text("Pick 🧭 on the Home screen to use it.", color = MUTED, fontSize = 12.sp)
            // The simple routing mode UNDER the user's rules: an explicit corporate
            // rule still wins over a country bypass (configBuilder.js advancedUseMode).
            SwitchRow("Apply the routing mode (Bypass Iran/China) under these rules" + (if (geo) "" else " — needs the geo files"), s.advancedUseMode && geo, enabled = geo) { save(s.copy(advancedUseMode = it)) }
            s.routeRules.forEachIndexed { i, r ->
                Card(Modifier.fillMaxWidth().padding(vertical = 4.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(12.dp)) {
                    Column(Modifier.padding(10.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            DropPick("Type", listOf("domain" to "Domain", "ip" to "IP", "port" to "Port"), r.type) { nt -> save(s.copy(routeRules = s.routeRules.toMutableList().also { it[i] = r.copy(type = nt) })) }
                            Spacer(Modifier.weight(1f)); IconButton(onClick = { save(s.copy(routeRules = s.routeRules.filterIndexed { x, _ -> x != i })) }) { Icon(Icons.Filled.DeleteOutline, null, tint = BAD) }
                        }
                        // Saved when editing ends, not per keystroke: save() rebuilds
                        // the screen, which used to steal focus after every character.
                        DraftField(r.value, Modifier.fillMaxWidth(), placeholder = { Text("value (geosite:google / 1.2.3.0/24 / 443)", fontSize = 11.sp) }) { nv ->
                            val m = s.routeRules.toMutableList()
                            // the rule may have been deleted/moved by the save that rebuilt us
                            if (i < m.size && m[i] == r) { m[i] = r.copy(value = nv); save(s.copy(routeRules = m)) }
                        }
                        DropPick("Target", targetOptionsFull(store), r.target) { save(s.copy(routeRules = s.routeRules.toMutableList().also { m -> m[i] = r.copy(target = it) })) }
                    }
                }
            }
            Button(onClick = { save(s.copy(routeRules = s.routeRules + RouteRule("domain", "", store.servers.firstOrNull()?.id ?: "direct"))) }, modifier = Modifier.fillMaxWidth()) { Text("+ Add rule") }
            Spacer(Modifier.height(8.dp)); Text("Rest of traffic via:", color = MUTED)
            DropPick("Default", targetOptionsFull(store), s.routeDefault) { save(s.copy(routeDefault = it)) }
        }
    }
}

/* ================================ SETTINGS ================================ */
@Composable
private fun SettingsScreen(store: Store, bump: () -> Unit, back: () -> Unit) {
    val ctx = LocalContext.current
    var s by remember { mutableStateOf(store.settings) }
    fun save(n: AppSettings) { s = n; store.saveSettings(n); bump() }
    Screen("Settings", back, {}) {
        Text("Ports & DNS", color = TXT, fontWeight = FontWeight.Bold)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { NumFld("SOCKS", s.socksPort, Modifier.weight(1f)) { save(s.copy(socksPort = it)) }; NumFld("HTTP", s.httpPort, Modifier.weight(1f)) { save(s.copy(httpPort = it)) } }
        // The managed resolver plan (DnsPlan.kt, the desktop's dnsBuilder.js).
        // Typed freely, parsed only when the user leaves the field: parsing per
        // keystroke ate the comma (and the focus) after the first server.
        SwitchRow("DNS managed by the app", s.dnsManaged) { save(s.copy(dnsManaged = it)) }
        Text(if (s.dnsManaged) "On: every DNS query that reaches the core is answered here — the world over DoH through the tunnel, Iranian names by the in-country resolver, nothing in plain text off the tunnel. Needed for a corporate WireGuard's own resolver."
             else "Off: the remote list is used as given, nothing is intercepted, and a corporate WireGuard's resolver is not in the config.", color = MUTED, fontSize = 11.sp)
        DraftField(s.dnsRemote.joinToString(","), Modifier.fillMaxWidth(), label = { Text("Remote DNS — through the tunnel (DoH URLs, comma-separated)") }) { raw ->
            val list = raw.split(",").map { d -> d.trim() }.filter { d -> d.isNotEmpty() }
            save(s.copy(dnsRemote = list.ifEmpty { DnsPlan.DEFAULT_REMOTE }))   // empty field = keep the defaults
        }
        DraftField(s.dnsDirect.joinToString(","), Modifier.fillMaxWidth(), label = { Text("In-country DNS — for Bypass Iran (comma-separated)") }) { raw ->
            val list = raw.split(",").map { d -> d.trim() }.filter { d -> d.isNotEmpty() }
            save(s.copy(dnsDirect = list.ifEmpty { DnsPlan.DEFAULT_DIRECT_IR }))
        }
        DropPick("Log level", listOf("none", "error", "warning", "info", "debug").map { it to it }, s.logLevel) { save(s.copy(logLevel = it)) }
        SwitchRow("IPv6", s.ipv6) { save(s.copy(ipv6 = it)) }
        HorizontalDivider(Modifier.padding(vertical = 10.dp), color = STROKE)
        Text("Core", color = TXT, fontWeight = FontWeight.Bold)
        // The default for configs that do not name a core of their own. A chain,
        // pool or advanced plan has no single owner, so this is what decides it —
        // unless one of its servers asks for PattN, which wins (EngineChoice.kt).
        val pattnHere = remember { XrayPattnCore.available(ctx) }
        DropPick(
            "Default core",
            listOf("xray" to "Xray (in-process, default)", "xray-pattn" to "Xray-PattN (bundled binary)"),
            s.defaultEngine
        ) { save(s.copy(defaultEngine = it)) }
        Text(
            if (!pattnHere) "Xray-PattN is not bundled for this device (arm64 only) — configs asking for it run on the in-process core instead."
            else "PattN is upstream Xray plus one thing: it does not refuse a plaintext VLESS/Trojan config to a public address, which the official core rejects at load. Everything else behaves identically.",
            color = MUTED, fontSize = 11.sp
        )
        HorizontalDivider(Modifier.padding(vertical = 10.dp), color = STROKE)
        Text("Per-app routing", color = TXT, fontWeight = FontWeight.Bold)
        listOf("off" to "Off (whole system)", "allow" to "Only these apps", "disallow" to "All except these").forEach { (v, l) ->
            Row(Modifier.fillMaxWidth().clickable { save(s.copy(perAppMode = v)) }, verticalAlignment = Alignment.CenterVertically) { RadioButton(s.perAppMode == v, { save(s.copy(perAppMode = v)) }); Text(l, color = TXT) }
        }
        if (s.perAppMode != "off") AppPicker(s.perApps) { save(s.copy(perApps = it)) }
    }
}

@Composable private fun AppPicker(selected: List<String>, onChange: (List<String>) -> Unit) {
    val ctx = LocalContext.current
    val apps = remember { runCatching { val pm = ctx.packageManager; pm.getInstalledApplications(0).filter { pm.getLaunchIntentForPackage(it.packageName) != null }.map { it.packageName to pm.getApplicationLabel(it).toString() }.sortedBy { it.second } }.getOrElse { emptyList() } }
    var q by remember { mutableStateOf("") }
    OutlinedTextField(q, { q = it }, Modifier.fillMaxWidth(), placeholder = { Text("Search apps") }, singleLine = true, colors = tfColors())
    Column {
        apps.filter { it.second.contains(q, true) || it.first.contains(q, true) }.take(150).forEach { (pkg, label) ->
            Row(Modifier.fillMaxWidth().clickable { onChange(if (selected.contains(pkg)) selected - pkg else selected + pkg) }, verticalAlignment = Alignment.CenterVertically) {
                Checkbox(selected.contains(pkg), { c -> onChange(if (c) selected + pkg else selected - pkg) }); Text(label, color = TXT, fontSize = 13.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

/* ================================ LOGS / MORE ================================ */
@Composable private fun LogsScreen(back: () -> Unit) {
    val log by VpnState.log.collectAsState()
    Screen("Logs", back, { IconButton(onClick = { VpnState.clearLog() }) { Icon(Icons.Filled.DeleteSweep, "clear", tint = MUTED) } }) {
        if (log.isEmpty()) EmptyHint("No logs yet.")
        SelectionContainer { Column { log.forEach { Text(it, color = Color(0xFFB6C2D4), fontSize = 11.sp) } } }
    }
}

/**
 * More: the desktop sections a phone cannot put in the tab bar.
 *
 * "Advanced mode" is the design's SIMPLE / ADVANCED badge. Off, the screens
 * that only make sense once several configs are in play — chain, pool, routing,
 * logs — are hidden rather than disabled, so a phone that only ever taps
 * Connect has four rows instead of eight. Nothing is deleted: turning it back
 * on shows the same chains and rules, untouched.
 */
@Composable private fun MoreMenu(store: Store, bump: () -> Unit, open: (String) -> Unit) {
    val ctx = LocalContext.current
    var s by remember { mutableStateOf(store.settings) }
    val connectedSince by VpnState.connectedSince.collectAsState()
    var elapsed by remember { mutableStateOf(0L) }
    LaunchedEffect(connectedSince) {
        while (connectedSince > 0) { elapsed = System.currentTimeMillis() - connectedSince; delay(1000) }
        elapsed = 0L
    }
    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        TopBar("More") {}
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 16.dp)) {
            Card(Modifier.fillMaxWidth().padding(bottom = 10.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                Row(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Advanced mode", color = TXT, fontWeight = FontWeight.Medium)
                        Text("chains, routing rules, proxy pool, logs", color = MUTED, fontSize = 11.sp)
                    }
                    Switch(s.advancedMode, { v -> s = s.copy(advancedMode = v); store.saveSettings(s); bump() },
                        colors = SwitchDefaults.colors(checkedThumbColor = ON_PRIMARY, checkedTrackColor = PRIMARY, uncheckedThumbColor = MUTED, uncheckedTrackColor = CARD2, uncheckedBorderColor = STROKE))
                }
            }
            val rows = buildList {
                if (s.advancedMode) {
                    add(MoreRow("chains", "Proxy Chain", "several hops, in order", "${store.chains.size}", Icons.Filled.Link))
                    add(MoreRow("pool", "Proxy Pool", "several exits, each on its own port", "${store.pool.size}", Icons.Filled.Hub))
                    add(MoreRow("routing", "Routing", if (s.advancedRouting) "advanced rules" else routingModeLabel(s.routingMode), if (s.advancedRouting) "${s.routeRules.size} rules" else "", Icons.Filled.CallSplit))
                }
                add(MoreRow("settings", "Settings", "ports, DNS, core, per-app", "", Icons.Filled.Settings))
                if (s.advancedMode) add(MoreRow("logs", "Logs", "what the core actually said", "", Icons.Filled.Article))
            }
            rows.forEach { r ->
                Card(Modifier.fillMaxWidth().padding(vertical = 4.dp).clickable { open(r.key) }, colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                    Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(r.icon, null, tint = PRIMARY, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(r.title, color = TXT)
                            Text(r.sub, color = MUTED, fontSize = 11.sp)
                        }
                        if (r.meta.isNotEmpty()) Text(r.meta, color = MUTED, fontSize = 11.sp, fontFamily = MONO)
                        Spacer(Modifier.width(8.dp))
                        Icon(Icons.Filled.ChevronRight, null, tint = MUTED2)
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
            // Which core is actually installed on this phone, not which one is configured.
            val cores = remember {
                buildList {
                    if (XrayCore.available) add("xray " + XrayCore.version().ifBlank { "core" })
                    if (XrayPattnCore.available(ctx)) {
                        val v = XrayPattnCore.version(ctx)
                        add(if (v.isBlank()) "xray-pattn" else "xray-pattn $v")
                    }
                    if (SingboxCore.available(ctx)) add("sing-box")
                }
            }
            Text(cores.joinToString(" · ").ifEmpty { "no core bundled" }, color = MUTED2, fontSize = 10.sp, fontFamily = MONO)
            if (connectedSince > 0) Text("uptime " + fmtDuration(elapsed), color = MUTED2, fontSize = 10.sp, fontFamily = MONO)
            Spacer(Modifier.height(16.dp))
        }
    }
}

private class MoreRow(val key: String, val title: String, val sub: String, val meta: String, val icon: ImageVector)

private fun routingModeLabel(mode: String): String = when (mode) {
    "bypass-ir" -> "bypass Iran"
    "bypass-cn" -> "bypass China"
    "direct" -> "everything direct"
    else -> "everything through the tunnel"
}

/* ================================ shared ================================ */
@Composable private fun TopBar(title: String, back: (() -> Unit)? = null, actions: @Composable RowScope.() -> Unit) {
    Row(Modifier.fillMaxWidth().padding(horizontal = if (back == null) 16.dp else 8.dp, vertical = if (back == null) 12.dp else 8.dp), verticalAlignment = Alignment.CenterVertically) {
        if (back != null) IconButton(onClick = back) { Icon(Icons.Filled.ArrowBack, "back", tint = TXT) }
        Text(title, color = TXT, fontSize = 22.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f)); actions()
    }
}
@Composable private fun Screen(title: String, back: () -> Unit, actions: @Composable RowScope.() -> Unit, content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = back) { Icon(Icons.Filled.ArrowBack, "back", tint = TXT) }
            Text(title, color = TXT, fontSize = 20.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f)); actions()
        }
        Column(Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()).imePadding().padding(horizontal = 16.dp), content = content)
    }
}
@Composable private fun SwitchRow(label: String, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) { Text(label, color = if (enabled) TXT else MUTED, modifier = Modifier.weight(1f)); Switch(checked, onChange, enabled = enabled) }
}
/**
 * A text field that types into a local draft and only reports it when editing
 * ends — focus leaves, or the field is removed from the screen.
 *
 * Every screen persists through save(), which calls bump(); bump() changes
 * `rev` and key(rev) rebuilds the whole screen, so committing on each keystroke
 * tore the field down under the user's finger: focus and the keyboard were lost
 * after every character, and a half-typed DNS list ("1.1.1.1,") was normalised
 * back before the second server could be typed.
 *
 * `sent` remembers what was last handed over, so a commit that itself causes
 * the rebuild is not repeated on dispose. The draft starts from `value`, so a
 * legitimate rebuild (another setting saved) shows the stored text again.
 */
@Composable private fun DraftField(value: String, modifier: Modifier = Modifier, label: @Composable (() -> Unit)? = null,
                                   placeholder: @Composable (() -> Unit)? = null, onCommit: (String) -> Unit) {
    var text by remember { mutableStateOf(value) }
    var sent by remember { mutableStateOf(value) }
    val commit = { if (text != sent) { sent = text; onCommit(text) } }
    DisposableEffect(Unit) { onDispose { commit() } }
    OutlinedTextField(text, { text = it }, modifier.onFocusChanged { st -> if (!st.isFocused) commit() },
        label = label, placeholder = placeholder, singleLine = true, colors = tfColors())
}
@Composable private fun Fld(label: String, value: String, onChange: (String) -> Unit) {
    OutlinedTextField(value, onChange, Modifier.fillMaxWidth().padding(vertical = 3.dp), label = { Text(label) }, singleLine = true, colors = tfColors())
}
@Composable private fun NumFld(label: String, value: Int, modifier: Modifier = Modifier, onChange: (Int) -> Unit) {
    OutlinedTextField(value.takeIf { it > 0 }?.toString() ?: "", { onChange(it.toIntOrNull() ?: 0) }, modifier, label = { Text(label) }, singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), colors = tfColors())
}
@Composable private fun DropPick(label: String, options: List<Pair<String, String>>, current: String, onPick: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box(Modifier.padding(vertical = 4.dp)) {
        OutlinedButton(onClick = { open = true }, modifier = Modifier.fillMaxWidth()) { Text((options.firstOrNull { it.first == current }?.second ?: label), Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis); Icon(Icons.Filled.ArrowDropDown, null) }
        DropdownMenu(open, { open = false }) { options.forEach { (v, l) -> DropdownMenuItem(text = { Text(l) }, onClick = { onPick(v); open = false }) } }
    }
}
@Composable private fun EmptyHint(text: String) { Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) { Text(text, color = MUTED) } }
@Composable private fun tfColors() = OutlinedTextFieldDefaults.colors(focusedBorderColor = PRIMARY, unfocusedBorderColor = STROKE, focusedTextColor = TXT, unfocusedTextColor = TXT, cursorColor = PRIMARY)

private fun targetOptions(store: Store): List<Pair<String, String>> = buildList { store.servers.forEach { add(it.id to it.name) }; store.chains.filter { store.chainReady(it) }.forEach { add("chain:${it.id}" to "⛓ ${it.name}") } }
private fun targetOptionsFull(store: Store): List<Pair<String, String>> = buildList { add("proxy" to "Proxy (first server)"); add("direct" to "Direct"); add("block" to "Block"); addAll(targetOptions(store)) }
// apiPort belongs here too: it is the core's own metrics/API listener, and a
// pool entry handed that port makes the config fail to build.
private fun usedPorts(store: Store): Set<Int> { val s = HashSet<Int>(); s.add(store.settings.socksPort); s.add(store.settings.httpPort); s.add(store.settings.apiPort); store.pool.forEach { if (it.socksPort > 0) s.add(it.socksPort); if (it.httpPort > 0) s.add(it.httpPort) }; return s }

fun fmtBytes(n: Long): String { var v = n.toDouble(); val u = arrayOf("B", "KB", "MB", "GB", "TB"); var i = 0; while (v >= 1024 && i < u.size - 1) { v /= 1024; i++ }; return (if (i == 0) v.toLong().toString() else String.format("%.1f", v)) + " " + u[i] }
fun fmtSpeed(n: Long) = fmtBytes(n) + "/s"
/** "12s" / "7 min" / "3 h" / "2 d" ago — short enough for a list row. */
private fun fmtAgo(ms: Long): String = when {
    ms < 60_000 -> "${ms / 1000}s ago"
    ms < 3_600_000 -> "${ms / 60_000} min ago"
    ms < 86_400_000 -> "${ms / 3_600_000} h ago"
    else -> "${ms / 86_400_000} d ago"
}

private fun fmtDuration(ms: Long): String {
    val s = (ms / 1000).coerceAtLeast(0); return "%02d:%02d:%02d".format(s / 3600, (s % 3600) / 60, s % 60)
}
private fun msLabel(ms: Long) = if (ms >= 0) "${ms}ms" else "×"
private fun badge(p: String) = when (p) { "vless" -> "VLESS"; "vmess" -> "VMESS"; "trojan" -> "TROJAN"; "shadowsocks" -> "SS"; "wireguard" -> "WG"; "socks" -> "SOCKS"; "http" -> "HTTP"; else -> p.uppercase() }
private fun flag(cc: String): String { if (cc.length != 2) return "🏳"; val base = 0x1F1E6; return String(Character.toChars(base + (cc[0].uppercaseChar() - 'A'))) + String(Character.toChars(base + (cc[1].uppercaseChar() - 'A'))) }
