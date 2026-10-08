package com.irnetfree.vpn.ui

import android.Manifest
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.pulltorefresh.PullToRefreshContainer
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.draw.scale
import androidx.compose.ui.draw.alpha
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
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
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
import androidx.compose.ui.unit.Dp
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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/* The palette and the two type families live in Theme.kt. */

class MainActivity : ComponentActivity() {
    private lateinit var store: Store
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runCatching { enableEdgeToEdge() }
        val crash = IRApp.readCrash(application)
        if (crash != null) { setContent { AppTheme { CrashScreen(crash) { IRApp.clearCrash(application); recreate() } } }; return }
        try {
            store = Store.get(this)
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
    // One place every screen and every background job says what happened —
    // above all what went wrong, which used to vanish without a word. (Before
    // AutoConnect: its effect may speak at once, and a message sent before
    // anyone listens is dropped.)
    val snackHost = remember { SnackbarHostState() }
    LaunchedEffect(Unit) {
        AppWork.snacks.collect { s ->
            val r = snackHost.showSnackbar(
                s.text, actionLabel = s.action, withDismissAction = s.action == null,
                duration = if (s.action != null) SnackbarDuration.Long else SnackbarDuration.Short
            )
            if (r == SnackbarResult.ActionPerformed) s.onAction?.invoke()
        }
    }
    AutoConnect(store)
    // Is a newer IRNetFree out? GitHub is asked at most once a day
    // (AppWork.checkForUpdate); Home shows the card.
    val ctx = LocalContext.current
    LaunchedEffect(Unit) { AppWork.checkForUpdate(ctx, store) }

    Scaffold(containerColor = BG, snackbarHost = {
        SnackbarHost(snackHost) { d -> Snackbar(d, containerColor = CARD2, contentColor = TXT, actionColor = PRIMARY) }
    }, bottomBar = {
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
                        "routing" -> RoutingScreen(store, back = { more = null }, openChains = { more = "chains" })
                        "settings" -> SettingsScreen(store, bump) { more = null }
                        "logs" -> LogsScreen { more = null }
                        else -> MoreMenu(store, bump) { more = it }
                    }
                }
            }
        }
    }
}

/**
 * Connect to the selected config when the app is opened, if the user asked
 * for it (Settings → Connect on open). The desktop does the same on launch;
 * this is the same rule with the two things a phone adds.
 *
 * ONCE PER PROCESS, not once per composition: this sits in the shell, and the
 * shell recomposes whenever a tab changes or bump() fires. A flag on the
 * object survives all of that and dies with the process, which is exactly the
 * lifetime "on open" means.
 *
 * AND NEVER A SURPRISE DIALOG. Android asks for VPN consent through a system
 * dialog, and throwing one at somebody who has just opened the app — perhaps
 * only to paste a config — is not auto-connecting, it is ambushing them. When
 * consent has not been given yet the attempt is skipped and the log says so;
 * one manual connect grants it for good, and every launch after that is
 * silent.
 */
@Composable private fun AutoConnect(store: Store) {
    val ctx = LocalContext.current
    LaunchedEffect(Unit) {
        if (AutoConnectOnce.done) return@LaunchedEffect
        AutoConnectOnce.done = true
        if (!store.settings.autoConnect) return@LaunchedEffect
        if (VpnState.isActive) return@LaunchedEffect
        // Stopped unexpectedly and waiting out a crash loop's backoff: the
        // service reconnects by itself, and an attempt from here would only
        // repeat the crash sooner.
        if (XrayVpnService.restartPending) {
            VpnState.addLog("Connect on open: skipped — IRNetFree reconnects by itself shortly (it stopped unexpectedly)")
            return@LaunchedEffect
        }
        // Only a selection that still resolves — buildPlan throws when the
        // config it names has been deleted, or a chain has lost its members.
        val plan = runCatching { store.buildPlan() }
        if (plan.isFailure) {
            val why = plan.exceptionOrNull()?.message ?: "nothing to connect to"
            VpnState.addLog("Connect on open: $why")
            AppWork.snack("Connect on open skipped: $why")
            return@LaunchedEffect
        }
        if (VpnService.prepare(ctx) != null) {
            VpnState.addLog("Connect on open: Android has not been given VPN permission yet — connect once by hand and it will be automatic after that.")
            AppWork.snack("Connect on open needs one connect by hand first (Android’s VPN permission)")
            return@LaunchedEffect
        }
        // Let the first frame land before a foreground service and a core
        // start competing with it, as the desktop waits for its window.
        delay(700)
        // A connect or a cancel made by hand in that moment wins (the desktop's
        // connect-on-launch steps aside the same way): tapping Connect and then
        // Cancel must not be followed by a connect nobody asked for.
        if (AutoConnectOnce.manual || VpnState.isActive || XrayVpnService.restartPending) return@LaunchedEffect
        VpnState.addLog("Connect on open: ${store.selectionLabel()}")
        doConnect(ctx, store)
    }
}

/** Survives recomposition; dies with the process. [manual]: a connect, cancel or disconnect was made by hand. */
private object AutoConnectOnce { @Volatile var done = false; @Volatile var manual = false }

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
    observeStore()
    val state by VpnState.state.collectAsState()
    val err by VpnState.lastError.collectAsState()
    val traffic by VpnState.traffic.collectAsState()
    // What the running tunnel was started on — not whatever is selected now.
    val connectedLabel by VpnState.label.collectAsState()
    var ip by remember { mutableStateOf("—") }
    var latency by remember { mutableStateOf<Long?>(null) }
    var measuring by remember { mutableStateOf("") }
    var pickerOpen by remember { mutableStateOf(false) }
    var homeSheet by remember { mutableStateOf<String?>(null) }
    // "Auto (fastest)": what it is measuring right now, and the line that says
    // what it chose. Both empty until somebody asks for it. They live in
    // AppWork with the run itself, which a tab switch no longer abandons.
    val autoPhase by AppWork.fastestPhase.collectAsState()
    val autoNote by AppWork.fastestNote.collectAsState()
    val haptic = LocalHapticFeedback.current
    val connectedSince by VpnState.connectedSince.collectAsState()
    val health by VpnState.health.collectAsState()
    val settings = store.settings
    val version = remember { appVersion(ctx) }
    // Something is on its way to a connection — the tunnel coming up, or ⚡
    // measuring before it connects — and can be cancelled from the ring or the
    // button under your thumb.
    val busy = state == ConnState.CONNECTING || autoPhase.isNotEmpty()
    // A cancel asked for and not through yet: the screen says "Cancelling…"
    // instead of a "Connecting…" that looks as if the tap did nothing.
    var cancelAsked by remember { mutableStateOf(false) }
    LaunchedEffect(busy) { if (!busy) cancelAsked = false }
    var pinging by remember { mutableStateOf(false) }
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

    // What to do once Android has said yes (rememberConsent): "fastest", or a
    // plain connect.
    val withConsent = rememberConsent(store) { then: String ->
        if (then == "fastest") AppWork.connectFastest(ctx, store) else doConnect(ctx, store)
    }
    // A newer IRNetFree, from the once-a-day check ("" = none, or put off with Later).
    val update by AppWork.updateAvailable.collectAsState()
    /**
     * The ring and the button under your thumb. While something is on its way
     * it CANCELS: ⚡ stops measuring (a tunnel already up stays up), and a
     * connect in flight goes down the ordinary disconnect path, which drops a
     * connect still being prepared before its service is ever started.
     */
    fun onPower() {
        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
        AutoConnectOnce.manual = true
        if (busy) {
            cancelAsked = true
            if (autoPhase.isNotEmpty()) AppWork.cancelFastest()
            if (state == ConnState.CONNECTING) AppWork.disconnect(ctx)
            return
        }
        if (state == ConnState.CONNECTED) { AppWork.disconnect(ctx); return }
        // Nothing to connect to: say how to get something, instead of an error.
        if (!store.selectionResolves()) {
            if (store.servers.isEmpty()) { homeSheet = "import"; AppWork.snack("Add a server first — a link, a QR code or a subscription") }
            else { pickerOpen = true; AppWork.snack("Pick a server to connect to") }
            return
        }
        withConsent("connect")
    }
    fun selectedServer(): ServerConfig? {
        val sel = store.selection
        return store.serverById(sel) ?: store.chainById(sel.removePrefix("chain:"))?.let { store.chainMembers(it).firstOrNull() }
    }
    /** A TCP ping of the selected server, asked for by a tap; the result is kept with the other tests. */
    fun pingSelected() {
        val srv = selectedServer()
        if (srv == null) { AppWork.snack("Nothing to ping — select a server first"); return }
        if (pinging) return
        pinging = true
        scope.launch {
            val ms = withContext(Dispatchers.IO) { Diagnostics.tcpPing(srv.address, srv.port) }
            AppWork.putPing(srv.id, ms)
            pinging = false
            if (ms < 0) AppWork.snack("${srv.name}: no answer on port ${srv.port}")
        }
    }
    // The last TCP ping of the selected server (a chain: its first hop), from
    // wherever it was measured — a tap here, a test on Servers, ⚡. Never
    // measured on its own: pinging a server nobody asked about, every time the
    // app opens, is not ours to do.
    val selTest = selectedServer()?.let { AppWork.tests[it.id] }

    /**
     * Choose the server instead of being told which one, then connect to it —
     * the ⚡ row in the Windows picker (renderer/app.js connectAuto).
     *
     * IT SAYS WHICH ONE IT PICKED, three times over: the choice is SAVED, so the
     * exit chip and the connected line now name it like any other selection; a
     * line under the chip says it was chosen automatically, out of how many, and
     * on what measurement; and the same sentence goes to the log, where it is
     * still there tomorrow. An auto-connect you cannot audit is a mystery, not a
     * convenience.
     *
     * Nothing is changed when nothing answers: the selection you had is still
     * the selection you have.
     *
     * Android's permissions are asked for FIRST, so the run itself (AppWork)
     * can connect at its end without a screen to show a dialog from.
     */
    fun connectFastest() {
        if (store.servers.size < 2 || autoPhase.isNotEmpty()) return
        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
        AutoConnectOnce.manual = true
        withConsent("fastest")
    }

    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        /* ---- header: brand (and the version under it), mode, uptime ---- */
        Row(Modifier.fillMaxWidth().padding(start = 16.dp, end = 4.dp, top = 6.dp, bottom = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(18.dp).clip(RoundedCornerShape(5.dp)).background(PRIMARY))
                    Spacer(Modifier.width(8.dp))
                    Text("IR", color = TXT, fontWeight = FontWeight.Bold, fontSize = 14.sp, letterSpacing = 0.06.em)
                    Text("NETFREE", color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 14.sp, letterSpacing = 0.06.em)
                }
                // Which build this is, where a screenshot will show it.
                if (version.isNotEmpty()) Text(
                    "v$version", color = MUTED2, fontSize = 9.sp, fontFamily = MONO,
                    modifier = Modifier.padding(start = 26.dp)
                )
            }
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
            /* ---- a newer IRNetFree: on a phone, the way newer cores arrive ---- */
            if (update.isNotEmpty()) {
                UpdateCard(update, onDownload = { openUpdate(ctx, store) }, onLater = { AppWork.dismissUpdate(store) })
                Spacer(Modifier.height(16.dp))
            }

            /* ---- the ring ---- */
            PowerRing(state, busy, ::onPower)
            Spacer(Modifier.height(14.dp))
            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    when {
                        busy && cancelAsked -> "Cancelling…"
                        state == ConnState.CONNECTED -> "Connected"
                        state == ConnState.CONNECTING -> "Connecting…"
                        autoPhase.isNotEmpty() -> "Finding the fastest…"
                        state == ConnState.ERROR -> "Not connected"
                        else -> "Not protected"
                    },
                    color = TXT, fontSize = 19.sp, fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.height(5.dp))
                Text(
                    when {
                        // ⚡ says what it is measuring, even over a tunnel still up
                        autoPhase.isNotEmpty() -> "$autoPhase · tap the ring to cancel"
                        // the server carrying traffic; picking another one only
                        // changes what the NEXT connect uses
                        state == ConnState.CONNECTED -> connectedLabel.ifBlank { store.selectionLabel() }
                        state == ConnState.CONNECTING -> "starting the core and the tunnel · tap the ring to cancel"
                        state == ConnState.ERROR -> err.ifBlank { "see More → Logs" }
                        else -> "tap the ring to connect"
                    },
                    color = if (state == ConnState.ERROR && !busy) BAD else MUTED,
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

            /* ---- let the app choose the exit (Windows: the picker's ⚡ row) ----
                   On the front screen and not only inside the picker, because on
                   a phone this is the shortest honest answer to "which one do I
                   pick?" — one tap, and it tells you what it picked. The exit
                   itself sits at the bottom now, under the thumb. */
            if (store.servers.size >= 2) {
                Spacer(Modifier.height(12.dp))
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                    val running = autoPhase.isNotEmpty()
                    Box(
                        Modifier.heightIn(min = 48.dp).clip(RoundedCornerShape(50))
                            .border(1.dp, if (running) AMBER.copy(alpha = 0.5f) else PRIMARY_DIM, RoundedCornerShape(50))
                            // while it runs the same chip stops it
                            .clickable(onClickLabel = if (running) "cancel" else "connect to the fastest") {
                                if (running) { cancelAsked = true; AppWork.cancelFastest() } else connectFastest()
                            }
                            .padding(horizontal = 18.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            if (running) "✕ stop testing" else "⚡ connect to the fastest",
                            color = if (running) AMBER else PRIMARY,
                            fontSize = 13.sp, fontFamily = MONO, maxLines = 1, overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
            if (autoNote.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                Text(
                    autoNote, color = MUTED, fontSize = 10.sp, fontFamily = MONO,
                    textAlign = TextAlign.Center, maxLines = 2, overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.fillMaxWidth()
                )
            }

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
                Metric(Modifier.weight(1f), "TCP PING", if (pinging) "…" else fmtLat(selTest?.tcp), "to the server", if (pinging) AMBER else latColor(selTest?.tcp))
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
                    onClick = { pingSelected() },
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
                            if (!r.ok) AppWork.snack("IP check failed" + if (r.error.isNotBlank()) ": ${r.error}" else "")
                        }
                    },
                    modifier = Modifier.weight(1f), shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TXT2), border = BorderStroke(1.dp, STROKE)
                ) { Text("check IP", fontSize = 12.sp) }
                OutlinedButton(
                    onClick = { if (state == ConnState.CONNECTED) AppWork.reconnect(ctx, store) },
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

        /* ---- under the thumb: what you connect to, and the button ----
               The ring sits high on a tall phone; the exit and Connect / Cancel /
               Disconnect are pinned at the bottom, where a thumb already is. */
        HorizontalDivider(color = STROKE)
        Box(Modifier.fillMaxWidth().background(BG2).padding(horizontal = 12.dp, vertical = 10.dp)) {
            if (store.servers.isEmpty()) {
                // Nothing to connect to yet: one thing to do about it.
                EmptyState(
                    "No server yet",
                    "Add a config link, a QR code or your subscription link.",
                    "Add a server or subscription"
                ) { homeSheet = "import" }
            } else Row(verticalAlignment = Alignment.CenterVertically) {
                ExitChip(store, selTest, pinging, Modifier.weight(1f), onPick = { pickerOpen = true }, onPing = { pingSelected() })
                Spacer(Modifier.width(10.dp))
                PowerButton(state, busy, ::onPower)
            }
        }
    }
    if (pickerOpen) SelectionSheet(
        store,
        onAuto = { pickerOpen = false; connectFastest() },
        onDismiss = { pickerOpen = false },
        onPick = { pickerOpen = false; bump() }
    )
    AddConfigSheets(store, homeSheet, { homeSheet = it }, bump)
}

/**
 * The power ring. Connected it is a solid mint disc with a ring pulsing out of
 * it; otherwise a dark disc with a hairline. The glyph is the power symbol drawn
 * as an arc with a gap at the top, which is what the design shows.
 *
 * [busy] (connecting, or ⚡ measuring) it spins around a ✕: the ring is also
 * how you cancel, and it should look like it.
 */
@Composable private fun PowerRing(state: ConnState, busy: Boolean, onPower: () -> Unit) {
    val on = state == ConnState.CONNECTED
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
                    .clickable(onClickLabel = if (busy) "cancel" else if (on) "disconnect" else "connect") { onPower() },
                contentAlignment = Alignment.Center
            ) {
                if (busy) Box(contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = if (on) ON_PRIMARY else PRIMARY, strokeWidth = 4.dp, modifier = Modifier.size(64.dp))
                    Icon(Icons.Filled.Close, "cancel", tint = if (on) ON_PRIMARY else TXT2, modifier = Modifier.size(26.dp))
                } else PowerGlyph(if (on) ON_PRIMARY else Color(0xFF486B63))
            }
        }
    }
}

/**
 * The same decision as the ring, under the thumb: Connect, Cancel while
 * something is on its way, Disconnect once it is up.
 */
@Composable private fun PowerButton(state: ConnState, busy: Boolean, onPower: () -> Unit) {
    val shape = RoundedCornerShape(14.dp)
    val mod = Modifier.heightIn(min = 52.dp).widthIn(min = 104.dp)
    val pad = PaddingValues(horizontal = 16.dp)
    when {
        busy -> OutlinedButton(
            onClick = onPower, modifier = mod, shape = shape, contentPadding = pad, border = BorderStroke(1.dp, AMBER.copy(alpha = 0.6f)),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = AMBER)
        ) { Text("Cancel", fontSize = 14.sp, fontWeight = FontWeight.SemiBold) }
        state == ConnState.CONNECTED -> OutlinedButton(
            onClick = onPower, modifier = mod, shape = shape, contentPadding = pad, border = BorderStroke(1.dp, STROKE),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = TXT)
        ) { Text("Disconnect", fontSize = 14.sp, fontWeight = FontWeight.SemiBold, maxLines = 1) }
        else -> Button(
            onClick = onPower, modifier = mod, shape = shape, contentPadding = pad,
            colors = ButtonDefaults.buttonColors(containerColor = PRIMARY, contentColor = ON_PRIMARY)
        ) { Text("Connect", fontSize = 14.sp, fontWeight = FontWeight.SemiBold) }
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

/**
 * The selected exit: its flag, name, protocol and last ping. Tapping it opens
 * the picker; tapping the ping measures it again (a TCP handshake, nothing more).
 */
@Composable private fun ExitChip(store: Store, result: TestState?, pinging: Boolean, modifier: Modifier, onPick: () -> Unit, onPing: () -> Unit) {
    val srv = store.serverById(store.selection)
    val (flag, label) = if (srv != null) ServerLabel.split(srv.name) else null to store.selectionLabel()
    // a routing profile whose traffic rides on a base says which (spec §3: the small path's "via <base>")
    val viaBase = if (srv != null) null else store.selectedProfile()?.let { p: RoutingProfile -> RoutingProfiles.effectiveDefVia(p) ?: p.base }
    Row(
        modifier.heightIn(min = 56.dp).clip(RoundedCornerShape(14.dp)).background(CARD)
            .border(1.dp, STROKE, RoundedCornerShape(14.dp)).clickable(onClickLabel = "choose a server") { onPick() }
            .padding(start = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (srv != null) Leading(flag, srv.protocol)
        Spacer(Modifier.width(if (srv != null) 10.dp else 2.dp))
        Column(Modifier.weight(1f).padding(vertical = 8.dp)) {
            Text(label, color = TXT, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                when {
                    srv != null -> badge(srv.protocol) + " · tap to change"
                    viaBase != null -> "via ${store.targetLabel(viaBase)} · tap to change"
                    else -> "tap to change"
                },
                color = MUTED2, fontSize = 10.sp, fontFamily = MONO, maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
        // The ping: its own 48 dp target, so measuring never opens the picker.
        Box(
            Modifier.heightIn(min = 48.dp).widthIn(min = 52.dp).clickable(onClickLabel = "ping") { onPing() }.padding(horizontal = 8.dp),
            contentAlignment = Alignment.Center
        ) {
            val ms = result?.tcp
            when {
                pinging -> Text("…", color = AMBER, fontSize = 13.sp, fontFamily = MONO)
                ms != null -> Text(if (ms >= 0) "$ms ms" else "×", color = latColor(ms), fontSize = 12.sp, fontFamily = MONO, maxLines = 1)
                else -> Text("ping", color = MUTED, fontSize = 11.sp, fontFamily = MONO)
            }
        }
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

/**
 * "IRNetFree vX is out" (AppWork.checkForUpdate). Android runs no core an app
 * downloads, so on a phone the newer cores come inside the newer APK — the
 * card says so. Download opens the release's APK (the browser takes it from
 * there); Later puts this version off for good, and a newer one is said again.
 */
@Composable private fun UpdateCard(version: String, onDownload: () -> Unit, onLater: () -> Unit) {
    val v = if (version.startsWith("v")) version else "v$version"
    Card(
        Modifier.fillMaxWidth(), shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = CARD), border = BorderStroke(1.dp, PRIMARY_DIM)
    ) {
        Column(Modifier.padding(start = 14.dp, end = 6.dp, top = 12.dp)) {
            Text("IRNetFree $v is out — the cores and fixes come with the app", color = TXT, fontSize = 13.sp, modifier = Modifier.padding(end = 8.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                TextButton(onClick = onLater) { Text("Later", color = MUTED, fontSize = 13.sp) }
                TextButton(onClick = onDownload) { Text("Download", color = PRIMARY, fontSize = 13.sp, fontWeight = FontWeight.SemiBold) }
            }
        }
    }
}

/** Where Download goes when GitHub named no page at all. */
private const val RELEASES_PAGE = "https://github.com/sadrazkh/Irnetfree_xray-client/releases/latest"

/** Open the newer release's APK (else its page) in whatever handles a link. */
private fun openUpdate(ctx: Context, store: Store) {
    val url = store.updateUrl.ifBlank { RELEASES_PAGE }
    runCatching { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
        .onFailure { AppWork.snack("Nothing on this phone can open $url") }
}

private fun doConnect(ctx: Context, store: Store) {
    try { VpnState.set(ConnState.CONNECTING, store.selectionLabel()); XrayVpnService.connect(ctx, store) }
    catch (e: Exception) { VpnState.set(ConnState.ERROR, error = e.message ?: "connect failed") }
}

/**
 * Measure the servers and hand back the winner (null = nothing answered), in
 * two stages because the two measurements cost wildly different amounts.
 *
 *  1. THE HANDSHAKE, to all of them, eight at a time. A TCP connect is a socket
 *     and nothing else, so thirteen servers cost about three seconds — and a
 *     server whose port is shut is out of the running here, for free.
 *  2. A REAL ROUND TRIP, through the three that answered quickest. This one
 *     costs a throwaway xray each (XrayTester), which is why it is not run on
 *     everything: it is the measurement that can tell a server that carries
 *     traffic from one that merely accepts connections, and three of them is
 *     about the most a phone can spend while somebody is watching the screen.
 *
 * If none of those three carried anything, the next handshakes in line are
 * tried too, until one does or [Fastest.MAX_TRIES] cores have been spent
 * ([Fastest.walk]) — a round trip measured as failing disqualifies, so ⚡ never
 * connects to a server it has just seen fail.
 *
 * `onPhase` runs on the caller's dispatcher (the UI's), so it may write state.
 */
private suspend fun pickFastest(
    ctx: Context,
    servers: List<ServerConfig>,
    onPhase: (String) -> Unit
): FastestResult {
    val measured = LinkedHashMap<String, Fastest.Measured>()
    var done = 0
    onPhase("testing 0/${servers.size}…")
    for (batch in servers.chunked(8)) {
        val part = withContext(Dispatchers.IO) {
            batch.map { s -> async { Fastest.Measured(s.id, tcp = Diagnostics.tcpPing(s.address, s.port, timeout = 3000)) } }.awaitAll()
        }
        part.forEach { measured[it.id] = it; AppWork.putPing(it.id, it.tcp ?: -1L) }   // the list shows them too
        done += batch.size
        onPhase("testing $done/${servers.size}…")
    }
    val answered = Fastest.shortlist(measured.values.toList(), Int.MAX_VALUE).size
    if (answered == 0) return FastestResult(null, 0, 0)
    val byId = servers.associateBy { it.id }
    val tried = Fastest.walk(measured.values.toList()) { i, m ->
        val s = byId[m.id]
        if (s == null) -1L else {
            onPhase("checking ${i + 1} · ${s.name.take(16)}")
            realDelayThrough(ctx, s)
        }
    }
    return FastestResult(Fastest.pick(tried), answered, tried.size)
}

/** ⚡'s answer: the winner (null = none), how many shook hands, how many were really tried. */
private class FastestResult(val best: Fastest.Measured?, val answered: Int, val tried: Int)

/**
 * An HTTP round trip through one server, in ms, or -1 if it could not carry it.
 *
 * Start, measure and stop are ONE blocking unit on IO with a plain
 * try/finally. The stop used to sit in a `withContext` in the finally, which a
 * cancelled coroutine never runs, and the start sat outside the try — a screen
 * that went away mid-test left the throwaway core running. Blocking calls are
 * not interrupted by a cancel, so this stop always runs.
 */
private suspend fun realDelayThrough(ctx: Context, s: ServerConfig): Long {
    return AppWork.coreLock.withLock {
        withContext(Dispatchers.IO) {
            val h = XrayTester.start(ctx, s)
            if (h == null) -1L else try { Diagnostics.httpLatency(h.port, timeout = 5000) } finally { XrayTester.stop(h) }
        }
    }
}

/**
 * Work that must outlive the screen that started it.
 *
 * Every screen sits inside `key(rev)` in App, and bump() rebuilds the whole
 * subtree — which cancels every rememberCoroutineScope() beneath it, including
 * the work the screen itself had just started. A subscription refresh ended in
 * bump(), which cancelled the next one in "refresh all", and the rebuilt screen
 * found the failed subscription still stale and fetched it again, for as long
 * as the tab was open; adding a subscription bumped before its own fetch was
 * done, so a first run imported nothing; ⚡ fastest and reconnect were dropped
 * by a tab switch half way, the second after it had already disconnected.
 *
 * What changes the store or the tunnel therefore runs here, on the main thread,
 * for the life of the process, and the screens observe it: [storeRev] tells a
 * screen the lists changed (observeStore), the rest is state to show.
 */
private object AppWork {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    /** One throwaway core at a time (XrayTester's rule), whoever asks: a test, ⚡, a subscription fetch. */
    val coreLock = Mutex()

    /** Subscription fetches, one at a time. */
    private val subLock = Mutex()

    /** Subscriptions being fetched or waiting their turn. */
    val subsBusy = MutableStateFlow<Set<String>>(emptySet())

    /** The last refresh's outcome in one line, and whether it failed. */
    val subsNote = MutableStateFlow("" to false)

    /** Moves whenever work here wrote the store. */
    val storeRev = MutableStateFlow(0)
    /** A screen wrote the store and wants itself (and only itself) redrawn — unlike bump(), the scroll position stays. */
    fun touch() { storeRev.value = storeRev.value + 1 }

    /** ⚡ fastest: what it is measuring now ("" = not running), and what it chose. */
    val fastestPhase = MutableStateFlow("")
    val fastestNote = MutableStateFlow("")
    /** The ⚡ run in flight, and its number: a cancelled run's last words are not shown. */
    private var fastestJob: Job? = null
    private var fastestRun = 0
    /** The second half of a reconnect, waiting its 0.6 s — a Cancel meanwhile drops it. */
    private var pendingConnect: Job? = null

    /** What the app's snackbar is to say; App collects it. */
    class Snack(val text: String, val action: String? = null, val onAction: (() -> Unit)? = null)
    val snacks = MutableSharedFlow<Snack>(extraBufferCapacity = 8)
    fun snack(text: String, action: String? = null, onAction: (() -> Unit)? = null) { snacks.tryEmit(Snack(text, action, onAction)) }

    /**
     * Every server's last measurements, by id — the Servers list, the exit on
     * Connect and ⚡ all write and read the same map, so a ping measured on one
     * screen is still there on the other, and after a tab switch.
     */
    val tests = mutableStateMapOf<String, TestState>()
    /** "ping all" is running (it can be stopped). */
    val testingAll = MutableStateFlow(false)
    private var testAllJob: Job? = null

    /** A handshake time for [id] (-1 = no answer), unless a full test of it is running. */
    fun putPing(id: String, ms: Long) {
        val t = tests[id]
        if (t == null || t.phase.isEmpty()) tests[id] = (t ?: TestState()).copy(tcp = ms, error = null)
    }

    /**
     * One full test — handshake, a real round trip and an upload through a
     * throwaway core — one core at a time, app-wide (coreLock).
     *
     * Start, measure, stop: one blocking unit on IO with a plain try/finally.
     * The stop used to be a `withContext` in the finally, which a cancelled
     * coroutine never runs, and the start sat outside the try: the core kept
     * running. A blocking call is not interrupted by a cancel, so this stop
     * always runs. Stopped half way, the row is left without its "…".
     */
    private suspend fun testOne(ctx: Context, s: ServerConfig) {
        try {
            coreLock.withLock {
                tests[s.id] = TestState(phase = "tcp")
                val result = withContext(Dispatchers.IO) {
                    val h = XrayTester.start(ctx, s)
                    if (h == null) TestState(error = "core error") else try {
                        val ping = Diagnostics.tcpPing(s.address, s.port)
                        tests[s.id] = TestState(tcp = ping, phase = "down")
                        val down = Diagnostics.httpLatency(h.port)
                        tests[s.id] = TestState(tcp = ping, down = down, phase = "up")
                        val up = Diagnostics.uploadTest(h.port)
                        TestState(tcp = ping, down = down, up = up)
                    } finally { XrayTester.stop(h) }
                }
                tests[s.id] = result
            }
        } finally {
            val t = tests[s.id]
            if (t != null && t.phase.isNotEmpty()) tests[s.id] = t.copy(phase = "")
        }
    }

    /** Test one server; it carries on if the screen goes away. */
    fun test(ctx: Context, s: ServerConfig) {
        val app = ctx.applicationContext
        scope.launch { testOne(app, s) }
    }

    /** "ping all": every server in turn, until done or [stopTests]. */
    fun testAll(ctx: Context, list: List<ServerConfig>) {
        if (testAllJob?.isActive == true) return
        val app = ctx.applicationContext
        testingAll.value = true
        testAllJob = scope.launch {
            try { for (s in list) testOne(app, s) } finally { testingAll.value = false }
        }
    }

    fun stopTests() { testAllJob?.cancel(); testAllJob = null; testingAll.value = false }

    /**
     * The user's Disconnect — and Cancel, while a connect is on its way. The
     * service's own path (generation moved on at once, so a connect still being
     * prepared is dropped before its service starts); a reconnect's pending
     * second half goes too, and connect-on-open steps aside.
     */
    fun disconnect(ctx: Context) {
        AutoConnectOnce.manual = true
        pendingConnect?.cancel(); pendingConnect = null
        runCatching { XrayVpnService.disconnect(ctx.applicationContext) }
            .onFailure { e -> snack("Disconnect failed: ${e.message ?: e.javaClass.simpleName}") }
    }

    /** Stop ⚡ where it is. A tunnel already up stays up; the selection is whatever it was when stopped. */
    fun cancelFastest() {
        if (fastestJob == null && fastestPhase.value.isEmpty()) return
        fastestJob?.cancel(); fastestJob = null
        fastestRun++
        fastestPhase.value = ""
        fastestNote.value = "⚡ stopped"
        VpnState.addLog("Auto (fastest): stopped by hand")
    }

    /**
     * Fetch one subscription and apply it (SubRefresh), queued behind any fetch
     * already running; one already waiting is not queued twice. `announce` puts
     * the outcome in the snackbar too — where the user just asked for it.
     */
    fun refreshSub(ctx: Context, store: Store, subId: String, announce: Boolean = false) {
        if (subId in subsBusy.value) return
        subsBusy.value = subsBusy.value + subId
        val app = ctx.applicationContext
        scope.launch {
            try {
                subLock.withLock { refreshNow(app, store, subId, announce) }
            } finally {
                subsBusy.value = subsBusy.value - subId
            }
        }
    }

    private suspend fun refreshNow(ctx: Context, store: Store, subId: String, announce: Boolean) {
        val url = store.subs.firstOrNull { it.id == subId }?.url ?: return   // deleted while it waited
        subsNote.value = "Fetching…" to false
        var error = ""
        val fetched = try {
            coreLock.withLock { withContext(Dispatchers.IO) { SubFetch.fetch(ctx, store, url) { s -> VpnState.addLog(s) } } }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            error = e.message ?: e.javaClass.simpleName
            null
        }
        // Deleted while it was being fetched: the result has nowhere to go.
        val idx = store.subs.indexOfFirst { it.id == subId }
        if (idx < 0) return
        val sub = store.subs[idx]
        val now = System.currentTimeMillis()
        val note: String
        var bad = true
        if (fetched == null) {
            store.subs[idx] = SubRefresh.failed(sub, error, now)
            note = "${sub.name}: $error"
            VpnState.addLog("Subscription ${sub.url}: $error")
        } else {
            val r = fetched.result
            VpnState.addLog("Subscription ${sub.url}: ${r.servers.size} servers via ${fetched.via}")
            val applied = SubRefresh.applyFetch(store.servers.toList(), sub, r.servers, r.usage, r.errors, now)
            store.subs[idx] = applied.sub
            val list = applied.servers
            val m = applied.merged
            if (list == null || m == null) {
                note = "${sub.name}: ${applied.sub.lastError} — kept its ${sub.serverCount} servers"
                VpnState.addLog("Subscription ${sub.url}: ${applied.sub.lastError}; the ${sub.serverCount} servers it had are kept")
            } else {
                store.servers.clear(); store.servers.addAll(list); store.saveServers()
                // Ids are kept across a refresh (SubRefresh.merge), so a selected
                // server is still selected. One the panel dropped falls back to
                // the choice before it, and that is said, not discovered later.
                var moved = ""
                if (store.selection.isEmpty()) m.servers.firstOrNull()?.let { store.saveSelection(it.id) }
                else if (store.repairSelection()) moved = " · your server is gone from it, now using ${store.selectionLabel()}"
                val change = if (m.added == 0 && m.dropped == 0) "" else " · ${m.added} new, ${m.dropped} gone"
                note = "${sub.name}: ${m.servers.size} servers$change$moved"
                bad = false
                VpnState.addLog("Subscription ${sub.url}: ${m.kept} kept (same ids), ${m.added} new, ${m.dropped} gone")
                if (moved.isNotEmpty()) VpnState.addLog("Selection: the selected server left ${sub.name}; now ${store.selectionLabel()}")
            }
        }
        store.saveSubs()
        subsNote.value = note to bad
        storeRev.value = storeRev.value + 1
        if (announce) {
            if (bad) snack(note, "Retry") { refreshSub(ctx, store, subId, announce = true) } else snack(note)
        }
    }

    /**
     * ⚡: measure, choose, save the choice, connect to it. Android's permissions
     * were asked for by the screen before this started, so the end of the run
     * needs no screen at all.
     *
     * [scope]: only these servers — a group's ⚡ on its header — named
     * [scopeName] wherever the run speaks; null = every server (Home's ⚡).
     */
    fun connectFastest(ctx: Context, store: Store, scope: List<ServerConfig>? = null, scopeName: String? = null) {
        val list = (scope ?: store.servers).toList()
        if (list.size < 2 || fastestPhase.value.isNotEmpty()) return
        val inScope = if (scope != null && !scopeName.isNullOrBlank()) " in $scopeName" else ""
        val app = ctx.applicationContext
        val run = ++fastestRun
        // Only this run's words reach the screen: one cancelled a moment ago
        // may still be unwinding (a handshake is not interrupted mid-way).
        val phase: (String) -> Unit = { p -> if (run == fastestRun) fastestPhase.value = p }
        phase("testing 0/${list.size}…")
        fastestNote.value = ""
        // A connect or a disconnect asked for while ⚡ measures (it takes seconds)
        // is the user's newer word: ⚡ then applies nothing at its end.
        val ticket = XrayVpnService.moves
        // this.scope: AppWork's coroutines — `scope` alone is the servers parameter
        fastestJob = this.scope.launch {
            try {
                val out = pickFastest(app, list, phase)
                if (XrayVpnService.moves != ticket) {
                    fastestNote.value = "a connect or disconnect was asked for meanwhile — not applied"
                    VpnState.addLog("Auto (fastest): a connect or disconnect was asked for meanwhile — result not applied")
                    return@launch
                }
                val best = out.best
                val srv = best?.let { store.serverById(it.id) }
                if (best == null || srv == null) {
                    // The winner may have been deleted (or dropped by a refresh) while
                    // it was measured — say that, not that nothing carried traffic.
                    val gone = best?.let { b -> list.firstOrNull { it.id == b.id }?.name ?: "the winner" }
                    val why = when {
                        gone != null -> "$gone won but was removed during the test"
                        out.answered == 0 -> "no server$inScope answered"
                        else -> "none of the ${out.tried} quickest$inScope carried traffic"
                    }
                    fastestNote.value = "$why — the selection was left alone"
                    VpnState.addLog("Auto (fastest): $why; kept ${store.selectionLabel()}")
                    snack(why.replaceFirstChar { it.uppercase() })
                    return@launch
                }
                val real = best.real ?: -1L
                val how = if (real >= 0) "$real ms through it" else "${best.tcp ?: -1L} ms handshake"
                store.saveSelection(best.id)
                storeRev.value = storeRev.value + 1
                fastestNote.value = "⚡ fastest of ${list.size}$inScope: ${srv.name} · $how"
                VpnState.addLog("Auto (fastest): ${srv.name} — $how, out of ${list.size} servers$inScope")
                snack("Fastest$inScope: ${srv.name} · $how")
                // Already up on something else: the service switches a live tunnel
                // onto the new choice itself (one tunnel, no gap without the VPN),
                // so there is no disconnect first any more.
                if (VpnService.prepare(app) != null) {
                    VpnState.addLog("Auto (fastest): Android has not given VPN permission — tap the ring to connect")
                    snack("Android has not given VPN permission yet — tap Connect")
                    return@launch
                }
                phase("")
                doConnect(app, store)
            } finally {
                phase("")
                if (run == fastestRun) fastestJob = null
            }
        }
    }

    /** Down, then up again on the current selection — the second half no longer dies with the screen. */
    fun reconnect(ctx: Context, store: Store) {
        val app = ctx.applicationContext
        runCatching { XrayVpnService.disconnect(app) }
        pendingConnect?.cancel()
        pendingConnect = scope.launch { delay(600); pendingConnect = null; doConnect(app, store) }
    }

    /** A newer IRNetFree than this one, for the card on Home ("" = none, or put off with Later). */
    val updateAvailable = MutableStateFlow("")
    private var updateJob: Job? = null

    /**
     * "A newer IRNetFree is out": GitHub's latest release, asked for at most
     * once a day (UpdateCheck) — directly, the app being outside its own tunnel.
     * Android runs no core an app downloads, so a newer core reaches a phone
     * only inside a newer APK, and this is how the phone hears of one. What the
     * last answer said is shown at once; only a 200 counts as an answer, a
     * failure is one log line and nothing on screen, and the next start asks again.
     */
    fun checkForUpdate(ctx: Context, store: Store) {
        val current = appVersion(ctx)
        publishUpdate(store, current)
        if (updateJob?.isActive == true || !UpdateCheck.due(store.updateCheckedAt, System.currentTimeMillis())) return
        updateJob = scope.launch {
            try {
                val (tag, url) = withContext(Dispatchers.IO) { latestRelease() }
                store.updateLatest = tag
                store.updateUrl = url
                store.updateCheckedAt = System.currentTimeMillis()
                publishUpdate(store, current)
                if (UpdateCheck.newer(tag, current)) VpnState.addLog("Update check: IRNetFree $tag is out (this is $current) — $url")
                else VpnState.addLog("Update check: the latest release is $tag — this build ($current) is not older")
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                VpnState.addLog("Update check: GitHub could not be asked — ${e.message ?: e.javaClass.simpleName}")
            }
        }
    }

    /** "Later" on the card: this version is not mentioned again; a newer one will be. */
    fun dismissUpdate(store: Store) {
        val v = updateAvailable.value
        if (v.isEmpty()) return
        store.updateDismissed = v
        updateAvailable.value = ""
    }

    /** The newest release GitHub named, when it is newer than this build and was not put off. */
    private fun publishUpdate(store: Store, current: String) {
        val latest = store.updateLatest
        val show = latest.isNotEmpty() && latest != store.updateDismissed && UpdateCheck.newer(latest, current)
        updateAvailable.value = if (show) latest else ""
    }

    /** GitHub's latest release: its tag, and its APK (else its page). Blocking — IO only. */
    private fun latestRelease(): Pair<String, String> {
        val c = URL(UpdateCheck.LATEST_URL).openConnection() as HttpURLConnection
        try {
            c.connectTimeout = 10_000
            c.readTimeout = 10_000
            c.setRequestProperty("User-Agent", "IRNetFree-Android")
            c.setRequestProperty("Accept", "application/vnd.github+json")
            val code = c.responseCode
            if (code != 200) throw IllegalStateException("HTTP $code")
            val release = JSONObject(c.inputStream.bufferedReader().use { r -> r.readText() })
            val tag = release.optString("tag_name")
            if (tag.isEmpty()) throw IllegalStateException("the latest release names no version")
            return Pair(tag, UpdateCheck.downloadUrl(release))
        } finally {
            c.disconnect()
        }
    }
}

/**
 * Recompose the caller whenever AppWork has changed the store. The lists are
 * plain lists, not Compose state, so a screen showing them reads this to be
 * told — instead of the whole-tree rebuild (bump) that used to cancel the work.
 * (Not Unit-returning, so the read counts for the caller's own scope.)
 */
@Composable private fun observeStore(): Int = AppWork.storeRev.collectAsState().value

/** Android 13+, POST_NOTIFICATIONS not granted, and not asked for before. */
private fun needsNotificationAsk(ctx: Context, store: Store): Boolean =
    Build.VERSION.SDK_INT >= 33 && !store.notifAsked &&
        ctx.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED

/**
 * Android's permissions before anything connects, asked by the screen that is
 * about to connect (Home's ring and ⚡, a group's ⚡ on Servers). The returned
 * function takes the word for what follows — "connect", "fastest", a group's
 * key — and [proceed] gets it back once Android has said yes. The word is
 * saveable, because both system dialogs are other activities and the screen
 * can be recreated behind them.
 *
 * Android 13+ shows no notification without POST_NOTIFICATIONS — and the VPN's
 * status notification is where its Disconnect button lives. Asked once, before
 * the first connect; granted or refused, the connect goes on to the VPN consent.
 */
@Composable private fun rememberConsent(store: Store, proceed: (String) -> Unit): (String) -> Unit {
    val ctx = LocalContext.current
    var afterConsent by rememberSaveable { mutableStateOf("connect") }
    val vpnPrepare = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        if (res.resultCode == android.app.Activity.RESULT_OK) proceed(afterConsent)
        else AppWork.snack("Android’s VPN permission was not given — nothing was connected")
    }
    fun vpnConsentThenProceed() {
        val prep: Intent? = VpnService.prepare(ctx)
        if (prep != null) vpnPrepare.launch(prep) else proceed(afterConsent)
    }
    val notifAsk = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { _ -> vpnConsentThenProceed() }
    return { then: String ->
        afterConsent = then
        if (needsNotificationAsk(ctx, store)) { store.notifAsked = true; notifAsk.launch(Manifest.permission.POST_NOTIFICATIONS) }
        else vpnConsentThenProceed()
    }
}


/**
 * The exit picker. Every row here is a SELECTION except the first one: "Auto
 * (fastest)" is an action — it measures, then connects — which is exactly how
 * the same row behaves in the Windows picker, and why it sits above the divider
 * rather than in the list with a tick beside it.
 *
 * A lazy list, with the servers under their subscription's name as on Servers:
 * a subscription can hold hundreds, and one flat list of them was a long scroll
 * with nothing to find your own by.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun SelectionSheet(store: Store, onAuto: () -> Unit, onDismiss: () -> Unit, onPick: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = CARD) {
        observeStore()
        val modes = buildList {
            if (store.poolEnabledValid().isNotEmpty()) add(Store.POOL_ID to "🧩 Proxy Pool (${store.poolEnabledValid().size})")
            // one row per routing profile that has rules or a default (spec §1)
            store.profiles.filter { p: RoutingProfile -> store.profileReady(p) }.forEach { p: RoutingProfile -> add(Selection.forProfile(p.id) to "🧭 ${p.name}") }
            store.chains.filter { store.chainReady(it) }.forEach { add("chain:${it.id}" to "⛓ ${it.name}") }
        }
        // an old plain "__advanced__" selection is the first profile's row
        val selKey = store.selectedProfile()?.let { p: RoutingProfile -> Selection.forProfile(p.id) } ?: store.selection
        val groups = ServerGroups.build(store.servers, store.subs, "", emptySet(), store.selection)
        val pick: (String) -> Unit = { id -> store.saveSelection(id); onPick() }
        LazyColumn(Modifier.fillMaxWidth().heightIn(max = 560.dp), contentPadding = PaddingValues(bottom = 24.dp)) {
            item { Text("Select an exit", color = TXT, fontWeight = FontWeight.Bold, modifier = Modifier.padding(16.dp)) }
            if (store.servers.size >= 2) item {
                Column {
                    Row(
                        Modifier.fillMaxWidth().heightIn(min = 56.dp).clickable { onAuto() }.padding(horizontal = 16.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("⚡", fontSize = 15.sp)
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Text("Auto (fastest)", color = PRIMARY, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                            Text(
                                "tests every server, then connects to the one that answers fastest",
                                color = MUTED, fontSize = 10.sp, fontFamily = MONO, maxLines = 2, overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                    HorizontalDivider(color = STROKE)
                }
            }
            if (modes.isEmpty() && store.servers.isEmpty()) item { Text("No servers yet", color = MUTED, modifier = Modifier.padding(16.dp)) }
            items(modes) { (id, lbl) -> PickRow(lbl, null, null, null, selKey == id, null) { pick(id) } }
            for (g in groups) {
                if (g.servers.isEmpty()) continue
                item {
                    Text(
                        g.title.uppercase(), color = MUTED2, fontSize = 10.sp, fontFamily = MONO, letterSpacing = 0.08.em, maxLines = 1,
                        overflow = TextOverflow.Ellipsis, modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 14.dp, bottom = 4.dp)
                    )
                }
                items(g.servers) { s ->
                    val (flag, label) = ServerLabel.split(s.name)
                    PickRow(label, flag, s.protocol, s.address, store.selection == s.id, AppWork.tests[s.id]?.tcp) { pick(s.id) }
                }
            }
        }
    }
}

/** One row of the picker: 56 dp, the flag or protocol, the name, the last ping, a tick when it is the one. */
@Composable private fun PickRow(label: String, flag: String?, proto: String?, address: String?, selected: Boolean, ping: Long?, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp).background(if (selected) CARD_SEL else Color.Transparent)
            .clickable { onClick() }.padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (proto != null) { Leading(flag, proto); Spacer(Modifier.width(10.dp)) }
        Column(Modifier.weight(1f)) {
            Text(
                label, color = TXT, fontSize = 14.sp, maxLines = 1, overflow = TextOverflow.Ellipsis,
                fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal
            )
            if (proto != null) Text(
                badge(proto) + (if (address.isNullOrBlank()) "" else " · $address"),
                color = MUTED2, fontSize = 10.sp, fontFamily = MONO, maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
        if (ping != null) { Spacer(Modifier.width(8.dp)); Text(fmtLat(ping), color = latColor(ping), fontSize = 12.sp, fontFamily = MONO) }
        if (selected) { Spacer(Modifier.width(10.dp)); Icon(Icons.Filled.CheckCircle, "selected", tint = PRIMARY) }
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
 * Subscriptions are groups that fold away under their header (ServerGroups),
 * each with its usage, expiry and a refresh button of its own, and what is
 * folded is remembered across restarts. A lazy list, because a subscription
 * can hold hundreds; pull it down to refresh every subscription. Adding,
 * renaming and deleting subscriptions stays on the SUBS tab.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ServersScreen(store: Store, bump: () -> Unit) {
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
    // Re-read whenever AppWork changed the store: ⚡ fastest or a first import
    // can move the selection while this tab is open, and a plain remember kept
    // the tick on the old row. (Deletes and edits here move storeRev too, for
    // the same reason, instead of bump().)
    val storeRev = observeStore()
    var selectedId by remember(storeRev) { mutableStateOf(store.selection) }
    val ctx = LocalContext.current
    // Test results live in AppWork: a ping measured here is on Connect too,
    // and "ping all" carries on (and can be stopped) if you leave the tab.
    val tests = AppWork.tests
    val testingAll by AppWork.testingAll.collectAsState()
    val busy by AppWork.subsBusy.collectAsState()
    // 📶 and ⚡ on a group's header, acting on the whole group. ⚡ is AppWork's
    // run, as on Home, after Android's permissions (rememberConsent): the group
    // goes through the consent dialogs as its key, and its servers are looked
    // up again once Android has answered. Which header asked is kept here only
    // to put the spinner, and ⚡'s progress, on that header.
    val fastestPhase by AppWork.fastestPhase.collectAsState()
    var fastestKey by remember { mutableStateOf("") }
    var testKey by remember { mutableStateOf("") }
    val haptic = LocalHapticFeedback.current
    val groupFastest = rememberConsent(store) { then: String ->
        val key = then.removePrefix("group:")
        val g = ServerGroups.build(store.servers, store.subs, "", emptySet(), "").firstOrNull { it.key == key }
        if (g == null || g.all.size < 2) AppWork.snack("That group no longer has two servers to choose from")
        else { fastestKey = g.key; AppWork.connectFastest(ctx, store, g.all, g.title) }
    }
    // The row whose actions are showing. Only ever one, and nothing to begin
    // with: arriving at the list should show the list, not a card mid-flight.
    var openId by remember { mutableStateOf("") }
    // Folded groups, kept across restarts; a deleted subscription's is forgotten.
    var collapsed by remember { mutableStateOf(ServerGroups.prune(store.collapsedGroups, store.subs)) }
    val searching = q.isNotBlank()
    val groups = ServerGroups.build(store.servers, store.subs, q, collapsed, selectedId)
    val entries = ServerGroups.entries(groups, searching)
    val now = remember(storeRev) { System.currentTimeMillis() }
    val listState = rememberLazyListState()
    // Open at the server in use — not at the top of a list of hundreds.
    LaunchedEffect(Unit) {
        val i = ServerGroups.scrollTarget(entries, store.selection)
        if (i > 1) listState.scrollToItem(i - 1)
    }
    val pull = rememberPullToRefreshState()
    if (pull.isRefreshing) LaunchedEffect(true) {
        refreshAllSubs(ctx, store)
        pull.endRefresh()
    }
    val clearSearch: @Composable (() -> Unit)? = if (q.isEmpty()) null else ({
        IconButton(onClick = { q = "" }) { Icon(Icons.Filled.Close, "clear the search", tint = MUTED) }
    })

    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        /* ---- header: title, ping all, add ---- */
        Row(
            Modifier.fillMaxWidth().padding(start = 16.dp, end = 6.dp, top = 6.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Servers", color = TXT, fontSize = 20.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
            if (store.servers.isNotEmpty()) Box(
                Modifier.heightIn(min = 48.dp).clip(RoundedCornerShape(50))
                    .clickable(onClickLabel = if (testingAll) "stop testing" else "test every server") {
                        if (testingAll) AppWork.stopTests() else { testKey = ""; AppWork.testAll(ctx, store.servers.toList()) }
                    }
                    .padding(horizontal = 4.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    if (testingAll) "stop testing" else "ping all",
                    color = if (testingAll) AMBER else PRIMARY, fontSize = 12.sp, fontFamily = MONO,
                    modifier = Modifier.clip(RoundedCornerShape(50))
                        .border(1.dp, if (testingAll) AMBER.copy(alpha = 0.5f) else PRIMARY_DIM, RoundedCornerShape(50))
                        .padding(horizontal = 12.dp, vertical = 8.dp)
                )
            }
            Box {
                IconButton(onClick = { addMenu = true }) {
                    Box(
                        Modifier.size(36.dp).clip(RoundedCornerShape(10.dp)).background(PRIMARY),
                        contentAlignment = Alignment.Center
                    ) { Icon(Icons.Filled.Add, "add a server", tint = ON_PRIMARY, modifier = Modifier.size(22.dp)) }
                }
                DropdownMenu(addMenu, { addMenu = false }, modifier = Modifier.background(CARD)) {
                    listOf(
                        "import" to "Link or subscription",
                        "wg" to "WireGuard",
                        "proxy" to "SOCKS / HTTP"
                    ).forEach { (key, label) ->
                        DropdownMenuItem(
                            text = { Text(label, color = TXT, fontSize = 14.sp) },
                            onClick = { addMenu = false; sheet = key }
                        )
                    }
                }
            }
        }
        HorizontalDivider(color = BG2)
        if (store.servers.isNotEmpty()) OutlinedTextField(
            q, { q = it }, Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 10.dp, bottom = 4.dp),
            placeholder = { Text("Search name or address…", fontSize = 13.sp) },
            leadingIcon = { Icon(Icons.Filled.Search, null, Modifier.size(18.dp)) },
            trailingIcon = clearSearch,
            singleLine = true, shape = RoundedCornerShape(14.dp), colors = tfColors()
        )

        Box(Modifier.weight(1f).fillMaxWidth().clipToBounds().nestedScroll(pull.nestedScrollConnection)) {
            LazyColumn(
                Modifier.fillMaxSize().imePadding(), state = listState,
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp)
            ) {
                if (store.servers.isEmpty() && store.subs.isEmpty()) item(key = "empty") {
                    Box(Modifier.padding(top = 32.dp)) {
                        EmptyState(
                            "No servers yet",
                            "Paste a config link or your subscription link, scan a QR code, or add a WireGuard or SOCKS server by hand.",
                            "Add a server or subscription"
                        ) { sheet = "import" }
                    }
                }
                if (searching && entries.isEmpty()) item(key = "nomatch") { EmptyHint("Nothing matches “${q.trim()}”.") }
                items(entries, key = { it.key }) { e ->
                    when (e) {
                        is ServerGroups.ListEntry.Head -> {
                            val g = e.group
                            val sub = g.sub
                            val refresh: (() -> Unit)? = if (sub == null) null else ({ AppWork.refreshSub(ctx, store, sub.id, announce = true) })
                            GroupHeader(
                                g, now, refreshing = sub != null && sub.id in busy, foldable = !searching,
                                onToggle = { collapsed = ServerGroups.toggle(collapsed, g.key); store.collapsedGroups = collapsed },
                                onRefresh = refresh,
                                onTest = { testKey = g.key; AppWork.testAll(ctx, g.all) },
                                onFastest = {
                                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                                    AutoConnectOnce.manual = true
                                    groupFastest("group:" + g.key)
                                },
                                testBusy = testingAll, testingHere = testingAll && testKey == g.key,
                                fastestBusy = fastestPhase.isNotEmpty(), fastestPhase = if (fastestKey == g.key) fastestPhase else ""
                            )
                        }
                        is ServerGroups.ListEntry.Item -> {
                            val s = e.server
                            Box(Modifier.padding(bottom = 8.dp)) {
                                ConfigCard(
                                    s,
                                    selected = selectedId == s.id,
                                    open = openId == s.id,
                                    result = tests[s.id],
                                    onSelect = { store.saveSelection(s.id); selectedId = s.id },
                                    onToggle = { openId = if (openId == s.id) "" else s.id },
                                    onTest = { AppWork.test(ctx, s) },
                                    onCopy = { copyLink(ctx, s) },
                                    onQr = { qrServer = s },
                                    onEdit = { editId = s.id },
                                    onDelete = { confirmDelete = s }
                                )
                            }
                        }
                        is ServerGroups.ListEntry.Empty -> Text(
                            if (e.group.sub?.lastError?.isNotEmpty() == true) "no servers — the last fetch failed; tap ⟳ or pull down to try again"
                            else "no servers yet — tap ⟳ or pull down to fetch them",
                            color = MUTED, fontSize = 12.sp, modifier = Modifier.padding(start = 30.dp, bottom = 10.dp)
                        )
                    }
                }
            }
            PullToRefreshContainer(state = pull, modifier = Modifier.align(Alignment.TopCenter), containerColor = CARD2, contentColor = PRIMARY)
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
                TextButton(onClick = {
                    val wasSelected = store.selection == victim.id
                    store.deleteServer(victim.id)   // a selection that named it falls back (Store.repairSelection)
                    confirmDelete = null
                    AppWork.touch()                 // not bump(): the list keeps its place
                    AppWork.snack(
                        if (wasSelected && store.selection.isNotEmpty()) "Deleted ${victim.name} — now using ${store.selectionLabel()}"
                        else "Deleted ${victim.name}"
                    )
                }) {
                    Text("Delete", color = BAD)
                }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text("Cancel", color = MUTED) } }
        )
    }
    AddConfigSheets(store, sheet, { sheet = it }, bump)
    val editing = editId?.let { store.serverById(it) }
    val saveEdit: (ServerConfig) -> Unit = { updated: ServerConfig ->
        val idx = store.servers.indexOfFirst { it.id == updated.id }
        if (idx >= 0) { store.servers[idx] = updated; store.saveServers() }
        editId = null
        AppWork.touch()
    }
    if (editing != null) {
        // a JSON server is edited as its config, never through link fields
        if (editing.isJson) EditJsonSheet(editing, onDismiss = { editId = null }, onSave = saveEdit)
        else EditConfigSheet(editing, onDismiss = { editId = null }, onSave = saveEdit)
    }
}

/**
 * Pull to refresh: every subscription, one after another (AppWork queues them),
 * then one line on how it went. The fetches are AppWork's, so leaving the screen
 * stops only the spinner, never a fetch.
 */
private suspend fun refreshAllSubs(ctx: Context, store: Store) {
    val subs = store.subs.toList()
    if (subs.isEmpty()) { AppWork.snack("No subscriptions to refresh — add one on the SUBS tab"); return }
    val started = System.currentTimeMillis()
    subs.forEach { AppWork.refreshSub(ctx, store, it.id) }
    AppWork.subsBusy.first { it.isEmpty() }
    val ids = subs.mapTo(HashSet()) { it.id }
    val failed = store.subs.count { it.id in ids && it.lastError.isNotEmpty() && it.lastTried >= started }
    AppWork.snack(
        when {
            subs.size == 1 -> AppWork.subsNote.value.first
            failed == 0 -> "${subs.size} subscriptions refreshed"
            else -> "$failed of ${subs.size} subscriptions failed — their servers are kept"
        }
    )
}

/**
 * A group's header: tap it to fold or unfold the group. A subscription's shows
 * its usage, expiry and last update, and a refresh button of its own; a folded
 * group holding the server in use says so.
 *
 * A group of two or more also gets 📶 — test every server in it, as "ping all"
 * does — and ⚡ — connect to its fastest, as Home's ⚡ does for every server.
 * Both act on the whole group, whatever a search shows of it. 📶 waits while a
 * test is running ([testBusy]; "stop testing" up top stops it), ⚡ while a ⚡ is
 * ([fastestBusy]); the group whose own run it is shows a spinner instead, and
 * [fastestPhase] — what ⚡ is measuring in it — where its summary was.
 */
@Composable private fun GroupHeader(
    g: ServerGroups.Group,
    now: Long,
    refreshing: Boolean,
    foldable: Boolean,
    onToggle: () -> Unit,
    onRefresh: (() -> Unit)?,
    onTest: (() -> Unit)?,
    onFastest: (() -> Unit)?,
    testBusy: Boolean,
    testingHere: Boolean,
    fastestBusy: Boolean,
    fastestPhase: String
) {
    val summary = g.sub?.let { ServerGroups.summary(it, now) }
    val line = when {
        fastestPhase.isNotEmpty() -> "⚡ $fastestPhase"
        summary != null -> summary.text
        g.key == ServerGroups.MANUAL -> "added by hand"
        else -> "their subscription was deleted"
    }
    val tint = when {
        fastestPhase.isNotEmpty() -> AMBER
        summary?.level == ServerGroups.LEVEL_BAD -> BAD
        summary?.level == ServerGroups.LEVEL_WARN -> AMBER
        else -> MUTED2
    }
    val actions = g.total >= 2
    Row(
        Modifier.fillMaxWidth().padding(top = 8.dp, bottom = 4.dp).heightIn(min = 52.dp).clip(RoundedCornerShape(12.dp))
            .clickable(enabled = foldable, onClickLabel = if (g.open) "fold" else "unfold") { onToggle() }
            .padding(start = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            if (g.open) Icons.Filled.KeyboardArrowDown else Icons.Filled.KeyboardArrowRight,
            null, tint = MUTED, modifier = Modifier.size(22.dp)
        )
        Spacer(Modifier.width(6.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    g.title.uppercase(), color = TXT2, fontSize = 11.sp, fontFamily = MONO, letterSpacing = 0.08.em,
                    fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    if (g.servers.size == g.total) "${g.total}" else "${g.servers.size}/${g.total}",
                    color = MUTED2, fontSize = 10.sp, fontFamily = MONO,
                    modifier = Modifier.clip(RoundedCornerShape(50)).background(CARD).padding(horizontal = 7.dp, vertical = 2.dp)
                )
                if (!g.open && g.hasSelected) {
                    Spacer(Modifier.width(6.dp))
                    Text(
                        "IN USE", color = ON_PRIMARY, fontSize = 8.sp, fontFamily = MONO, fontWeight = FontWeight.SemiBold,
                        letterSpacing = 0.1.em, maxLines = 1,
                        modifier = Modifier.clip(RoundedCornerShape(4.dp)).background(PRIMARY).padding(horizontal = 5.dp, vertical = 2.dp)
                    )
                }
            }
            // two lines: with 📶 and ⚡ beside it a phone leaves the line half its width
            Text(line, color = tint, fontSize = 10.sp, fontFamily = MONO, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
        if (actions && onTest != null) GroupAction("📶", "test every server in ${g.title}", enabled = !testBusy, running = testingHere, onClick = onTest)
        if (actions && onFastest != null) GroupAction("⚡", "connect to the fastest in ${g.title}", enabled = !fastestBusy, running = fastestPhase.isNotEmpty(), onClick = onFastest)
        if (onRefresh != null) IconButton(onClick = onRefresh, enabled = !refreshing) {
            if (refreshing) CircularProgressIndicator(color = PRIMARY, strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
            else Icon(Icons.Filled.Refresh, "refresh ${g.title}", tint = MUTED)
        }
    }
}

/**
 * One of a group header's emoji buttons, the size of the refresh beside it. An
 * emoji keeps its own colours whatever the button's, so a button that has to
 * wait is dimmed by hand; one whose run is going shows a spinner instead.
 */
@Composable private fun GroupAction(glyph: String, label: String, enabled: Boolean, running: Boolean, onClick: () -> Unit) {
    IconButton(onClick = onClick, enabled = enabled && !running) {
        Box(Modifier.clearAndSetSemantics { contentDescription = label }, contentAlignment = Alignment.Center) {
            if (running) CircularProgressIndicator(color = PRIMARY, strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
            else Text(glyph, fontSize = 16.sp, modifier = Modifier.alpha(if (enabled) 1f else 0.35f))
        }
    }
}

/** Nothing here yet: what is missing, and the one thing to do about it. */
@Composable private fun EmptyState(title: String, text: String, action: String, onAction: () -> Unit) {
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Text(title, color = TXT, fontSize = 15.sp, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
        Spacer(Modifier.height(4.dp))
        Text(text, color = MUTED, fontSize = 12.sp, textAlign = TextAlign.Center)
        Spacer(Modifier.height(12.dp))
        Button(
            onClick = onAction, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp), shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(containerColor = PRIMARY, contentColor = ON_PRIMARY)
        ) { Text(action, fontSize = 14.sp, fontWeight = FontWeight.SemiBold) }
    }
}


/** Shared add-config flow (paste / QR / manual) usable from Home and Servers. */
@Composable
private fun AddConfigSheets(store: Store, sheet: String?, setSheet: (String?) -> Unit, bump: () -> Unit) {
    val ctx = LocalContext.current
    var importText by remember { mutableStateOf("") }
    // An irnetfree://routing/ link (a profile or a chain, RouteShare) waiting
    // for its preview. Set WITHOUT bump(): the rebuild would take it away.
    var routeLink by remember { mutableStateOf<String?>(null) }
    // The fetch runs in AppWork: the bump() that shows the new subscription
    // used to cancel its own fetch, so a first run imported nothing.
    fun addSubAndFetch(url: String) {
        val sub = Subscription(newId("sub"), url.trim().take(30), url.trim())
        store.subs.add(sub); store.saveSubs()
        AppWork.snack("Fetching the subscription…")
        AppWork.refreshSub(ctx, store, sub.id, announce = true)
    }
    // Auto-detect: http(s) lines -> subscriptions (fetched); the rest -> config(s).
    // An HTTP proxy link (`http://user@host:port#name`) is a config, not a
    // subscription URL — renderer/app.js isSubUrl.
    fun addParsed(parsed: List<ServerConfig>, errs: List<String>, quiet: Boolean) {
        store.servers.addAll(parsed); store.saveServers()
        if (parsed.isNotEmpty() && store.selection.isEmpty()) store.saveSelection(store.servers.first().id)
        if (quiet) return
        // nothing came of it: say why (a Clash YAML, an unsupported sing-box type…), not "0 added"
        if (parsed.isEmpty() && errs.isNotEmpty()) AppWork.snack("Nothing added — " + errs.first())
        else AppWork.snack("${parsed.size} config(s) added" + if (errs.isNotEmpty()) " · ${errs.size} line(s) not recognised" else "")
    }
    fun smartImport(text: String) {
        // A whole JSON config (one, an array, several) is one text, not lines
        // that might be subscription URLs (LinkParser.parseMany → JsonImport).
        if (JsonImport.looksLikeJson(text)) {
            val (parsed, errs) = LinkParser.parseMany(text)
            addParsed(parsed, errs, quiet = false)
            bump()
            return
        }
        val lines = text.split(Regex("\\r?\\n")).map { it.trim() }.filter { it.isNotEmpty() }
        val isUrl = { s: String -> LinkParser.isSubUrl(s) }
        val urls = lines.filter(isUrl)
        val rest = lines.filterNot(isUrl).joinToString("\n")
        urls.forEach { addSubAndFetch(it) }
        if (rest.isNotBlank()) {
            val (parsed, errs) = LinkParser.parseMany(rest)
            addParsed(parsed, errs, quiet = urls.isNotEmpty())
        } else if (urls.isEmpty()) AppWork.snack("Nothing recognised — paste a vless/vmess/trojan/ss/wireguard link, a JSON config or a subscription URL")
        bump()
    }
    val qrLauncher = rememberLauncherForActivityResult(ScanContract()) { res ->
        val t = res.contents
        if (!t.isNullOrBlank()) {
            if (RouteShare.looksLikeShare(t)) { routeLink = t.trim(); setSheet(null) }
            else { smartImport(t); setSheet(null); bump() }
        }
    }
    fun launchQr() = qrLauncher.launch(ScanOptions().setOrientationLocked(false).setBeepEnabled(false).setPrompt("Point the camera at the config QR"))
    fun pasteClip() {
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val t = cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(ctx)?.toString()
        if (!t.isNullOrBlank()) importText = t else Toast.makeText(ctx, "Clipboard is empty", Toast.LENGTH_SHORT).show()
    }
    when (sheet) {
        "import" -> AddLinkSheet(importText, { importText = it }, { pasteClip() }, { launchQr() }, { setSheet(null) }) {
            // An empty Add used to close the sheet as if something had been added.
            if (importText.isBlank()) Toast.makeText(ctx, "Paste a link first, or scan a QR code", Toast.LENGTH_SHORT).show()
            else if (RouteShare.looksLikeShare(importText)) { routeLink = importText.trim(); importText = ""; setSheet(null) }
            else { smartImport(importText); importText = ""; setSheet(null); bump() }
        }
        "wg" -> WgSheet(store, { setSheet(null) }) { setSheet(null); bump() }
        "proxy" -> ProxySheet(store, { setSheet(null) }) { setSheet(null); bump() }
        else -> {}
    }
    // the import itself moves AppWork.storeRev, which the screens observe: no rebuild needed
    routeLink?.let { t: String -> RouteImportDialog(store, t) { routeLink = null } }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun AddLinkSheet(value: String, onValue: (String) -> Unit, onPaste: () -> Unit, onScan: () -> Unit, onDismiss: () -> Unit, onSubmit: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = CARD) {
        Column(Modifier.fillMaxWidth().imePadding().padding(16.dp).padding(bottom = 16.dp)) {
            Text("Add config", color = TXT, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(4.dp))
            Text("vless/vmess/trojan/ss/hysteria2/socks/wireguard link, an Xray or sing-box JSON config, a subscription URL / base64, or an irnetfree://routing/ link (a routing profile or a chain)", color = MUTED, fontSize = 11.sp)
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
                .padding(start = 14.dp, end = 0.dp, top = 8.dp, bottom = 8.dp),
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
                    // imported from a whole JSON config (JsonImport); on Android it always runs in full
                    if (s.isJson) {
                        Spacer(Modifier.width(6.dp))
                        Text(
                            "JSON", color = AMBER, fontSize = 8.sp, fontFamily = MONO,
                            fontWeight = FontWeight.SemiBold, letterSpacing = 0.1.em, maxLines = 1,
                            modifier = Modifier.clip(RoundedCornerShape(4.dp))
                                .border(1.dp, AMBER.copy(alpha = 0.5f), RoundedCornerShape(4.dp))
                                .padding(horizontal = 5.dp, vertical = 2.dp)
                        )
                    }
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
                r?.tcp != null -> Text(fmtLat(r.tcp) + (if (r.tcp in 0L..999L) " ms" else ""), color = latColor(r.tcp), fontSize = 12.sp, fontFamily = MONO, maxLines = 1)
                else -> Text("—", color = SUBTLE, fontSize = 12.sp, fontFamily = MONO)
            }
            // The one affordance that says there is more in here, and opens it
            // without changing which config is in use. A full 48 dp target.
            IconButton(onClick = onToggle, modifier = Modifier.size(48.dp)) {
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
    Box(modifier.heightIn(min = 48.dp).clickable { onClick() }, contentAlignment = Alignment.Center) {
        Text(label, color = tint, fontSize = 12.sp, fontFamily = MONO, textAlign = TextAlign.Center, maxLines = 1)
    }
}

@Composable private fun ActionRule(color: Color) {
    Box(Modifier.width(1.dp).fillMaxHeight().background(color))
}

/** QR + copy for a config link that carries ALL settings (incl. patterniha). */
@Composable private fun QrDialog(s: ServerConfig, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    // A JSON server's QR holds its config, minified — when it fits one (the
    // desktop's 1,700 bytes); Copy gives it pretty-printed either way.
    val cfg = s.json
    val isJson = s.isJson && cfg != null
    val link = remember(s.id) { if (isJson && cfg != null) JsonText.minify(cfg) else LinkParser.buildShareLink(s) }
    val tooLarge = isJson && link.toByteArray(Charsets.UTF_8).size > QR_MAX_JSON_BYTES
    val bmp = remember(link) { if (tooLarge) null else qrBitmap(link) }
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
                else Text(if (isJson) "Too large for a QR — use Copy." else "Link too long for a QR — use Copy.", color = MUTED, fontSize = 12.sp)
                Spacer(Modifier.height(10.dp))
                Text(link, color = MUTED, fontSize = 10.sp, maxLines = 3, overflow = TextOverflow.Ellipsis)
                Spacer(Modifier.height(12.dp))
                Button(onClick = { copyLink(ctx, s); onDismiss() }, modifier = Modifier.fillMaxWidth()) { Text(if (isJson) "Copy JSON" else "Copy link") }
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

/** The most a JSON server's QR holds (the minified config, UTF-8) — the desktop's limit: larger codes do not scan. */
private const val QR_MAX_JSON_BYTES = 1700

/** Its share link — a JSON server's config, pretty-printed (LinkParser.buildShareLink). */
private fun copyLink(ctx: android.content.Context, s: ServerConfig) {
    copyConfigText(ctx, LinkParser.buildShareLink(s))
}

private fun copyConfigText(ctx: android.content.Context, text: String) {
    val cm = ctx.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
    cm.setPrimaryClip(android.content.ClipData.newPlainText("config", text))
    android.widget.Toast.makeText(ctx, "Copied ✓", android.widget.Toast.LENGTH_SHORT).show()
}


/** One colour per protocol, used by the badge and anywhere a config is listed. */
private fun protoColor(proto: String): Color = when (proto) {
    "vless" -> PRIMARY
    "vmess" -> Color(0xFF84E1BC)
    "trojan" -> AMBER
    "shadowsocks" -> Color(0xFFCDA9FF)
    "wireguard" -> Color(0xFF8FB3AA)
    "hysteria2" -> Color(0xFF7FB4FF)
    "socks", "http" -> Color(0xFFF19DC8)
    else -> MUTED
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun WgSheet(store: Store, onDismiss: () -> Unit, done: () -> Unit) {
    val ctx = LocalContext.current
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
            Button(onClick = {
                if (ep.isNotBlank() && priv.isNotBlank() && pub.isNotBlank()) { val s = LinkParser.makeWireguardServer(name, ep, priv, pub, addr, allowed, psk, mtu, reserved, dnsLine); store.servers.add(s); store.saveServers(); if (store.selection.isEmpty()) store.saveSelection(s.id); done() }
                else Toast.makeText(ctx, "Endpoint, private key and peer public key are needed", Toast.LENGTH_SHORT).show()
            }, modifier = Modifier.fillMaxWidth()) { Text("Add") }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun ProxySheet(store: Store, onDismiss: () -> Unit, done: () -> Unit) {
    val ctx = LocalContext.current
    var type by remember { mutableStateOf("socks") }; var name by remember { mutableStateOf("") }; var host by remember { mutableStateOf("") }; var port by remember { mutableStateOf("") }; var user by remember { mutableStateOf("") }; var pass by remember { mutableStateOf("") }
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = CARD) {
        Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).imePadding().padding(16.dp).padding(bottom = 16.dp)) {
            Text("Add SOCKS / HTTP", color = TXT, fontWeight = FontWeight.Bold)
            Row(Modifier.padding(vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) { FilterChip(type == "socks", { type = "socks" }, { Text("SOCKS5") }); FilterChip(type == "http", { type = "http" }, { Text("HTTP") }) }
            Fld("Name", name) { name = it }; Fld("Host", host) { host = it }; Fld("Port", port) { port = it }; Fld("Username (optional)", user) { user = it }; Fld("Password (optional)", pass) { pass = it }
            Spacer(Modifier.height(10.dp))
            Button(onClick = {
                if (host.isNotBlank() && port.isNotBlank()) { val s = LinkParser.makeProxyServer(type, name, host, port.toIntOrNull() ?: 1080, user, pass); store.servers.add(s); store.saveServers(); if (store.selection.isEmpty()) store.saveSelection(s.id); done() }
                else Toast.makeText(ctx, "Host and port are needed", Toast.LENGTH_SHORT).show()
            }, modifier = Modifier.fillMaxWidth()) { Text("Add") }
        }
    }
}

/**
 * A JSON server's edit sheet (the desktop's JSON edit view): its name, its
 * mode as a note — raw runs on the desktop in proxy mode; Android's VPN is
 * always a TUN, so here the full form runs whatever the mode, which is kept as
 * stored — the config itself as text, checked on Save, which re-derives the
 * main outbound and helpers from it; Copy JSON; and what the config holds that
 * the app does not use. No link fields: the JSON stays the one source.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun EditJsonSheet(server: ServerConfig, onDismiss: () -> Unit, onSave: (ServerConfig) -> Unit) {
    val ctx = LocalContext.current
    var name by remember(server.id) { mutableStateOf(server.name) }
    val mode = server.jsonMode
    var text by remember(server.id) { mutableStateOf(server.json?.let { c: JSONObject -> JsonText.pretty(c) } ?: "") }
    var error by remember(server.id) { mutableStateOf("") }
    val info = server.jsonInfo
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState, containerColor = CARD) {
        Column(Modifier.fillMaxWidth().fillMaxHeight(0.92f).verticalScroll(rememberScrollState()).imePadding().padding(16.dp).padding(bottom = 24.dp)) {
            Text("Edit · JSON · ${badge(server.protocol)}", color = TXT, fontWeight = FontWeight.Bold)
            Fld("Name", name) { name = it }
            // The mode is a note here, not a switch: it is kept as stored, so a backup round-trips.
            Text("Mode: " + (if (mode == JsonImport.MODE_RAW) "Raw" else "Full"), color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 2.dp))
            Text("Raw (exactly as written) runs on Windows/macOS/Linux in proxy mode; here the full form runs.", color = MUTED, fontSize = 11.sp)
            Text("Config (JSON)", color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 4.dp))
            // JSON reads left to right in either language
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                OutlinedTextField(
                    text, { v: String -> text = v; error = "" }, Modifier.fillMaxWidth(),
                    textStyle = TextStyle(fontFamily = MONO, fontSize = 11.sp, color = TXT),
                    minLines = 8, maxLines = 18, shape = RoundedCornerShape(10.dp), colors = tfColors()
                )
            }
            Spacer(Modifier.height(6.dp))
            OutlinedButton(onClick = { copyConfigText(ctx, text) }, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Filled.ContentCopy, null, Modifier.size(16.dp)); Spacer(Modifier.width(6.dp)); Text("Copy JSON")
            }
            // the full form is what runs here, raw or not: what it leaves out is always worth saying
            if (info != null) {
                Text("Not used in full mode — the app's own apply instead", color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 2.dp))
                Text("Its own routing: ${info.rules.size} rule" + (if (info.rules.size == 1) "" else "s"), color = TXT2, fontSize = 11.sp)
                // the record's neutral tokens (`*`, `balancer:<tag>`, "") in words
                info.rules.forEach { r: JsonRule ->
                    Text("   ${JsonImport.matchInWords(r.match)} → ${JsonImport.targetInWords(r.to)}", color = MUTED, fontSize = 11.sp, fontFamily = MONO)
                }
                if (info.dns) Text("Its own DNS servers", color = TXT2, fontSize = 11.sp)
                if (info.balancers > 0) Text("${info.balancers} balancer" + (if (info.balancers == 1) "" else "s") + " — each member is its own server here", color = TXT2, fontSize = 11.sp)
                if (info.observatory) Text("Its observatory", color = TXT2, fontSize = 11.sp)
            }
            if (error.isNotEmpty()) Text(error, color = BAD, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp))
            Spacer(Modifier.height(10.dp))
            Button(onClick = {
                // a config that no longer parses, or has no proxy outbound, is refused with the reason
                try {
                    onSave(JsonImport.applyEdits(server, name, mode, text))
                } catch (e: Exception) {
                    error = "Not saved — " + (e.message ?: "the config is not valid")
                }
            }, modifier = Modifier.fillMaxWidth()) { Text("Save") }
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
    var ech by remember { mutableStateOf(f.ech) }; var pcs by remember { mutableStateOf(f.pcs) }
    var vcn by remember { mutableStateOf(f.vcn) }; var pqv by remember { mutableStateOf(f.pqv) }
    var hy2Obfs by remember { mutableStateOf(f.hy2Obfs) }; var hy2Ports by remember { mutableStateOf(f.hy2Ports) }
    var engine by remember { mutableStateOf(f.engine) }
    val isStd = server.protocol == "vless" || server.protocol == "vmess" || server.protocol == "trojan"
    val isHy2 = server.protocol == "hysteria2"

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
                "hysteria2" -> Fld("Password (auth)", cred) { cred = it }
            }
            if (isHy2) {
                Text("🛡  TLS (over QUIC)", color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 2.dp))
                Fld("SNI — must match the server certificate", sni) { sni = it }
                // QUIC: no first-use pin. Allow insecure without a pin runs on sing-box (EngineChoice.needsInsecureCore).
                SwitchRow("Allow insecure (runs on sing-box unless a pcs is set)", allowInsecure) { allowInsecure = it }
                Text("The Xray cores can no longer skip the certificate check, and pinning on first use cannot work over QUIC — so a Hysteria2 with this on and no pcs runs on sing-box. Put the certificate's SHA-256 in pcs to run it on Xray.", color = MUTED, fontSize = 11.sp)
                Fld("Obfs password (salamander)", hy2Obfs) { hy2Obfs = it }
                Fld("Port hopping (e.g. 20000-50000)", hy2Ports) { hy2Ports = it }
                TlsExtraFields(ech, { ech = it }, pcs, { pcs = it }, vcn, { vcn = it })
            }
            if (isStd) {
                DropPick("Transport", listOf("tcp" to "tcp", "ws" to "ws", "grpc" to "grpc", "h2" to "h2", "xhttp" to "xhttp", "httpupgrade" to "httpupgrade", "kcp" to "kcp"), network) { network = it }
                DropPick("Security", listOf("none" to "none", "tls" to "tls", "reality" to "reality"), security) { security = it }
                // Context-aware SNI section: it means different things for
                // reality / CDN-fronting / plain-TLS, so say the right thing.
                val frontable = network in listOf("ws", "grpc", "xhttp", "splithttp", "h2", "http", "httpupgrade")
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
                if (security == "reality") {
                    Fld("Public Key (pbk)", pbk) { pbk = it }; Fld("Short ID (sid)", sid) { sid = it }
                    Fld("ML-DSA-65 verify key (pqv)", pqv) { pqv = it }
                }
                if (security == "tls") TlsExtraFields(ech, { ech = it }, pcs, { pcs = it }, vcn, { vcn = it })
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
                val nf = ServerEditor.Fields(
                    name = name, address = address, port = port, cred = cred, network = network, security = security,
                    sni = sni, host = host, path = path, fp = fp, pbk = pbk, sid = sid, allowInsecure = allowInsecure, alpn = f.alpn,
                    method = method, proxyUser = pUser, proxyPass = pPass,
                    wgPub = wgPub, wgAddr = wgAddr, wgPsk = wgPsk, wgMtu = wgMtu, wgReserved = wgReserved, wgAllowed = wgAllowed, wgDns = wgDns,
                    fragment = fragment, noise = effectiveNoise, cipherSuites = cipherSuites, finalMask = finalMask,
                    ech = ech, pcs = pcs, vcn = vcn, pqv = pqv, hy2Obfs = hy2Obfs, hy2Ports = hy2Ports,
                    engine = engine, spx = f.spx, xmode = f.xmode, seed = f.seed, headerType = f.headerType, xhttpExtra = f.xhttpExtra)
                onSave(ServerEditor.apply(server, nf))
            }, modifier = Modifier.fillMaxWidth()) { Text("Save") }
        }
    }
}

/**
 * The newer TLS knobs (LinkParser.tlsExtras): Encrypted Client Hello, a
 * certificate pin and the name to verify the certificate against.
 */
@Composable private fun TlsExtraFields(
    ech: String, onEch: (String) -> Unit, pcs: String, onPcs: (String) -> Unit, vcn: String, onVcn: (String) -> Unit
) {
    Fld("ECH — Encrypted Client Hello (e.g. cloudflare-ech.com+udp://1.1.1.1)", ech, onEch)
    Text("Hides the real SNI inside an encrypted ClientHello: the ECH config itself (base64) or where to fetch it — name+udp://resolver or name+https://resolver/dns-query. Empty = off.", color = MUTED, fontSize = 11.sp)
    Fld("Certificate SHA-256 (pcs)", pcs, onPcs)
    Fld("Verify certificate as (vcn)", vcn, onVcn)
    Text("pcs: accept exactly this certificate (a self-signed one too) — what replaced Allow Insecure. vcn: check the certificate against this name instead of the SNI.", color = MUTED, fontSize = 11.sp)
}

/* ================================ SUBS ================================ */
@Composable
private fun SubsScreen(store: Store, bump: () -> Unit) {
    val ctx = LocalContext.current
    observeStore()
    var url by remember { mutableStateOf("") }; var name by remember { mutableStateOf("") }
    // Fetches run in AppWork, one at a time, and apply even if you leave the
    // tab; this screen only shows them. It used to run them itself and end
    // each one in bump(), which cancelled the rest of "refresh all" and rebuilt
    // this screen — whose auto-update then fetched the failed one again.
    val busy by AppWork.subsBusy.collectAsState()
    val note by AppWork.subsNote.collectAsState()
    var confirmDelete by remember { mutableStateOf<Subscription?>(null) }
    fun refresh(sub: Subscription) = AppWork.refreshSub(ctx, store, sub.id)
    // Auto update. `autoUpdateSubs` and `autoUpdateInterval` were in the settings
    // model from the start and read by nothing at all, so a subscription only ever
    // refreshed when the user pressed the button. Doing it when this screen opens
    // needs no background work and no extra permission: a list you are looking at
    // is the list worth being current. A failed attempt counts too (SubRefresh.due),
    // so a subscription that fails is not fetched again on every visit.
    var settings by remember { mutableStateOf(store.settings) }
    LaunchedEffect(Unit) {
        if (!settings.autoUpdateSubs) return@LaunchedEffect
        val maxAge = settings.autoUpdateInterval.coerceAtLeast(5) * 60_000L
        val now = System.currentTimeMillis()
        store.subs.toList().forEach { sub -> if (SubRefresh.due(sub, now, maxAge)) refresh(sub) }
    }
    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        TopBar("Subscriptions") {
            IconButton(onClick = { store.subs.toList().forEach { refresh(it) } }, enabled = store.subs.any { it.id !in busy }) {
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
            Button(onClick = {
                if (url.isBlank()) AppWork.snack("Paste your subscription link (https://…) first")
                else { val sub = Subscription(newId("sub"), name.ifBlank { url.take(24) }, url.trim()); store.subs.add(sub); store.saveSubs(); url = ""; name = ""; AppWork.refreshSub(ctx, store, sub.id, announce = true) }
            }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text("Add & fetch") }
            if (note.first.isNotEmpty()) Text(note.first, color = if (note.second) BAD else PRIMARY, fontSize = 12.sp)
            Spacer(Modifier.height(8.dp))
            if (store.subs.isEmpty()) EmptyHint("No subscriptions yet — paste your subscription link above. Its servers appear on SERVERS, in a group of their own.")
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
                            // The last attempt failed (its servers were kept): say when and why.
                            if (sub.lastError.isNotEmpty() && sub.lastTried > 0) Text(
                                "last try ${fmtAgo(System.currentTimeMillis() - sub.lastTried)}: ${sub.lastError}",
                                color = BAD, fontSize = 11.sp, fontFamily = MONO, maxLines = 2, overflow = TextOverflow.Ellipsis
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
                        IconButton(onClick = { AppWork.refreshSub(ctx, store, sub.id, announce = true) }, enabled = sub.id !in busy) {
                            if (sub.id in busy) CircularProgressIndicator(color = PRIMARY, strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
                            else Icon(Icons.Filled.Refresh, "refresh", tint = MUTED)
                        }
                        IconButton(onClick = { confirmDelete = sub }) { Icon(Icons.Filled.DeleteOutline, "delete", tint = BAD) }
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
        }
    }
    // A subscription takes all of its servers with it, so it asks first — it
    // used to go on one tap of an icon next to Refresh.
    confirmDelete?.let { victim ->
        val count = store.servers.count { it.subId == victim.id }
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            containerColor = CARD,
            title = { Text("Delete this subscription?", color = TXT, fontSize = 16.sp) },
            text = { Text("${victim.name} and its $count server(s)", color = MUTED, fontSize = 13.sp, fontFamily = MONO) },
            confirmButton = {
                TextButton(onClick = {
                    val wasIn = store.serverById(store.selection)?.subId == victim.id
                    store.deleteSubscription(victim.id)   // a selection among its servers falls back
                    confirmDelete = null
                    AppWork.snack(
                        if (wasIn && store.selection.isNotEmpty()) "Deleted ${victim.name} — now using ${store.selectionLabel()}"
                        else "Deleted ${victim.name}"
                    )
                    bump()
                }) { Text("Delete", color = BAD) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text("Cancel", color = MUTED) } }
        )
    }
}

/* ================================ POOL ================================ */
@Composable
private fun PoolScreen(store: Store, bump: () -> Unit, back: () -> Unit) {
    observeStore()
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
    observeStore()
    // a chain's share link (RouteShare): copy, and a QR when it fits
    var shared by remember { mutableStateOf<SharedText?>(null) }
    Screen("Proxy Chain", back, { IconButton(onClick = { store.chains.add(ChainConfig(newId("chain"), "Chain ${store.chains.size + 1}", emptyList())); store.saveChains(); bump() }) { Icon(Icons.Filled.Add, "add", tint = PRIMARY) } }) {
        if (store.chains.isEmpty()) EmptyHint("No chains yet.")
        store.chains.toList().forEachIndexed { idx, c ->
            val members = store.chainMembers(c)
            Card(Modifier.fillMaxWidth().padding(vertical = 5.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                Column(Modifier.padding(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("⛓ ${c.name}", color = TXT, modifier = Modifier.weight(1f))
                        if (members.isNotEmpty()) IconButton(onClick = { shared = chainShare(store, c) }) { Icon(Icons.Filled.Share, "share this chain", tint = TXT2) }
                        if (store.chainReady(c)) IconButton(onClick = { store.saveSelection("chain:${c.id}"); bump() }) { Icon(Icons.Filled.CheckCircle, null, tint = if (store.selection == "chain:${c.id}") PRIMARY else MUTED) }
                        IconButton(onClick = {
                            val wasSelected = store.selection == "chain:${c.id}"
                            store.deleteChain(c.id)   // a selection that named it falls back
                            if (wasSelected && store.selection.isNotEmpty()) AppWork.snack("Deleted ${c.name} — now using ${store.selectionLabel()}")
                            bump()
                        }) { Icon(Icons.Filled.DeleteOutline, "delete chain", tint = BAD) }
                    }
                    Text("Path: " + (members.joinToString(" → ") { it.name }.ifEmpty { "empty — add at least 2 servers" }), color = MUTED, fontSize = 12.sp)
                    members.forEachIndexed { mi, s -> Row(verticalAlignment = Alignment.CenterVertically) { Text("${mi + 1}. ${s.name}", color = TXT, fontSize = 13.sp, modifier = Modifier.weight(1f)); IconButton(onClick = { store.chains[idx] = c.copy(members = c.members.filter { it != s.id }); store.saveChains(); bump() }) { Icon(Icons.Filled.Close, null, tint = BAD) } } }
                    DropPick("+ add server", store.servers.filter { !c.members.contains(it.id) }.map { it.id to it.name }, "") { if (it.isNotEmpty()) { store.chains[idx] = c.copy(members = c.members + it); store.saveChains(); bump() } }
                }
            }
        }
    }
    shared?.let { st: SharedText -> RouteShareDialog(st) { shared = null } }
}

/* ================================ ROUTING ================================ */
/**
 * Routing: the simple modes, then advanced routing as PROFILES — several saved
 * rule sets, each with an optional base its targets ride on ("via a base"),
 * and the profile drawn as a vertical flow, rule → target → base (RoutingProfiles
 * .kt; spec 2026-10-09 §1–§3, the desktop's routing page in the app's style).
 *
 * Saves recompose through the store (AppWork.touch) instead of rebuilding the
 * screen (bump): a long profile keeps its place while it is edited, and the
 * rule dialog opened from the flow stays open while it is changed. A rule's
 * row is keyed by what it holds, so a deleted rule's draft never shows up in
 * the one that took its place.
 */
@Composable
private fun RoutingScreen(store: Store, back: () -> Unit, openChains: () -> Unit) {
    val ctx = LocalContext.current
    observeStore()
    var s by remember { mutableStateOf(store.settings) }
    // Without geoip.dat/geosite.dat the core drops every geo rule, so the two
    // bypass modes and Block ads would do exactly nothing. Show that instead.
    val geo = remember { GeoAssets.available(ctx) }
    fun save(n: AppSettings) { store.saveSettings(n); s = store.settings; AppWork.touch() }
    // The profile being edited: one just imported, else the one Connect uses, else the first.
    var editId by remember { mutableStateOf(RoutingUi.focus.ifEmpty { store.selectedProfile()?.id ?: "" }) }
    LaunchedEffect(Unit) { RoutingUi.focus = "" }
    val prof = store.profileById(editId) ?: store.profiles.firstOrNull()
    var edited by remember { mutableStateOf(false) }
    var shared by remember { mutableStateOf<SharedText?>(null) }
    var confirmDelete by remember { mutableStateOf<RoutingProfile?>(null) }
    var ruleDialog by remember { mutableIntStateOf(-1) }
    var editServerId by remember { mutableStateOf<String?>(null) }
    var sheet by remember { mutableStateOf<String?>(null) }
    val state by VpnState.state.collectAsState()

    /** [f] applied to the profile as the store holds it NOW (a field's late commit must not bring an older copy back). */
    fun update(id: String, f: (RoutingProfile) -> RoutingProfile) {
        val i = store.profiles.indexOfFirst { x: RoutingProfile -> x.id == id }
        if (i < 0) return
        val cur = store.profiles[i]
        val next = RoutingProfiles.normalize(f(cur))
        if (next == cur) return
        store.profiles[i] = next
        store.saveProfiles()
        s = store.settings
        edited = true
        AppWork.touch()
    }
    /** Rule [i] of profile [id] becomes [nr] — only while it is still [old] (it may have been moved or deleted meanwhile). */
    fun setRule(id: String, i: Int, old: RouteRule, nr: RouteRule) = update(id) { cur: RoutingProfile ->
        if (i < cur.rules.size && cur.rules[i] == old) cur.copy(rules = cur.rules.toMutableList().also { m: MutableList<RouteRule> -> m[i] = nr }) else cur
    }
    fun deleteRule(id: String, i: Int, old: RouteRule) = update(id) { cur: RoutingProfile ->
        if (i < cur.rules.size && cur.rules[i] == old) cur.copy(rules = cur.rules.filterIndexed { x: Int, _: RouteRule -> x != i }) else cur
    }
    // a chain opens the chains screen, a server its edit sheet; direct/block are nothing to open
    val onNode: (String) -> Unit = { t: String ->
        if (t.startsWith("chain:")) openChains()
        if (store.serverById(t) != null) editServerId = t
    }

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
        SwitchRow("Block ads" + (if (geo) "" else " — unavailable"), s.blockAds && geo, enabled = geo) { v: Boolean -> save(s.copy(blockAds = v)) }
        SwitchRow("Sniffing", s.enableSniffing) { v: Boolean -> save(s.copy(enableSniffing = v)) }
        HorizontalDivider(Modifier.padding(vertical = 10.dp), color = STROKE)
        SwitchRow("Advanced routing", s.advancedRouting) { v: Boolean -> save(s.copy(advancedRouting = v)) }
        if (s.advancedRouting && prof != null) {
            Text("Each profile is a set of rules of its own. Pick 🧭 and its name on the Home screen to connect with it.", color = MUTED, fontSize = 12.sp)
            Spacer(Modifier.height(10.dp))
            Text("PROFILES", color = MUTED2, fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em)
            Spacer(Modifier.height(4.dp))
            val inUseId = store.selectedProfile()?.id
            store.profiles.toList().forEach { p: RoutingProfile ->
                ProfileRow(
                    store, p, editing = p.id == prof.id, inUse = p.id == inUseId,
                    onEdit = { editId = p.id },
                    onUse = {
                        store.saveSelection(Selection.forProfile(p.id))
                        AppWork.touch()
                        AppWork.snack("Connect now uses 🧭 ${p.name}")
                    },
                    onShare = { shared = profileShare(store, p) },
                    onDuplicate = {
                        val copy = p.copy(id = RoutingProfiles.newProfileId(), name = RoutingProfiles.uniqueName(p.name, store.profiles.map { x: RoutingProfile -> x.name }))
                        store.profiles.add(copy); store.saveProfiles()
                        editId = copy.id
                        AppWork.touch()
                    },
                    // the last one stays: Connect's plain 🧭 always has a profile to mean
                    onDelete = if (store.profiles.size > 1) ({ confirmDelete = p }) else null
                )
            }
            Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = {
                    val np = RoutingProfile(
                        RoutingProfiles.newProfileId(),
                        RoutingProfiles.uniqueName("Routing", store.profiles.map { x: RoutingProfile -> x.name }),
                        def = store.servers.firstOrNull()?.id ?: "direct"
                    )
                    store.profiles.add(np); store.saveProfiles()
                    editId = np.id
                    AppWork.touch()
                }, modifier = Modifier.weight(1f)) { Text("+ New profile", fontSize = 13.sp) }
                OutlinedButton(onClick = { sheet = "import" }, modifier = Modifier.weight(1f)) { Text("Import a link", fontSize = 13.sp) }
            }

            HorizontalDivider(Modifier.padding(vertical = 10.dp), color = STROKE)
            // edits to the profile the tunnel is running on reach it at the next connect
            if (edited && state == ConnState.CONNECTED && inUseId == prof.id) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Connected on this profile — changes apply on the next connect.", color = AMBER, fontSize = 12.sp, modifier = Modifier.weight(1f))
                    TextButton(onClick = { edited = false; AppWork.reconnect(ctx, store) }) { Text("Reconnect now", color = PRIMARY) }
                }
            }
            key(prof.id, prof.name) {
                DraftField(prof.name, Modifier.fillMaxWidth(), label = { Text("Profile name") }) { v: String -> update(prof.id) { cur: RoutingProfile -> cur.copy(name = v) } }
            }
            // The simple routing mode UNDER the profile's rules: an explicit corporate
            // rule still wins over a country bypass (configBuilder.js advancedUseMode).
            SwitchRow("Apply the routing mode (Bypass Iran/China) under these rules" + (if (geo) "" else " — needs the geo files"), prof.useMode && geo, enabled = geo) { v: Boolean ->
                update(prof.id) { cur: RoutingProfile -> cur.copy(useMode = v) }
            }

            Spacer(Modifier.height(6.dp))
            Text("Base", color = TXT, fontWeight = FontWeight.Bold)
            Text("A config the targets below ride on, unless a rule says otherwise — for example two chains that both leave through one server.", color = MUTED, fontSize = 11.sp)
            val base = prof.base
            DropPick(if (base == null) "No base" else "⚠ ${store.targetLabel(base)}", listOf("" to "No base") + targetOptions(store), base ?: "") { b: String ->
                update(prof.id) { cur: RoutingProfile -> cur.copy(base = b.ifEmpty { null }) }
            }
            if (base != null && !store.targetExists(base)) Text("⚠ The base is gone — connecting is refused while something rides on it. Pick another.", color = BAD, fontSize = 11.sp)

            Spacer(Modifier.height(6.dp))
            Text("Rules", color = TXT, fontWeight = FontWeight.Bold)
            prof.rules.forEachIndexed { i: Int, r: RouteRule ->
                key(prof.id, i, r) {
                    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(12.dp)) {
                        Column(Modifier.padding(10.dp)) {
                            RuleEditor(store, prof, r,
                                onChange = { nr: RouteRule -> setRule(prof.id, i, r, nr) },
                                onDelete = { deleteRule(prof.id, i, r) })
                        }
                    }
                }
            }
            Button(onClick = {
                update(prof.id) { cur: RoutingProfile -> cur.copy(rules = cur.rules + RouteRule("domain", "", store.servers.firstOrNull()?.id ?: "direct")) }
            }, modifier = Modifier.fillMaxWidth()) { Text("+ Add rule") }

            Spacer(Modifier.height(8.dp)); Text("Rest of traffic via:", color = MUTED)
            DropPick("Default", targetOptionsFull(store), prof.def) { t: String -> update(prof.id) { cur: RoutingProfile -> cur.copy(def = t) } }
            if (!store.targetExists(prof.def)) Text("⚠ The default is gone — connecting is refused until you pick another.", color = BAD, fontSize = 11.sp)
            if (RoutingProfiles.takesVia(prof.def)) {
                DropPick("Base", viaOptions(store, prof, prof.def), prof.defVia) { v: String -> update(prof.id) { cur: RoutingProfile -> cur.copy(defVia = v) } }
                val dv = RoutingProfiles.effectiveDefVia(prof)
                if (dv != null && !store.targetExists(dv)) Text("⚠ Its base is gone — connecting is refused until you pick another.", color = BAD, fontSize = 11.sp)
            }

            HorizontalDivider(Modifier.padding(vertical = 12.dp), color = STROKE)
            FlowList(store, prof, onRule = { i: Int -> ruleDialog = i }, onNode = onNode)
            Spacer(Modifier.height(16.dp))
        }
    }

    // The rule a flow node was tapped for, in its editor row.
    val rd = ruleDialog
    if (prof != null && rd >= 0 && rd < prof.rules.size) {
        val r = prof.rules[rd]
        Dialog(onDismissRequest = { ruleDialog = -1 }) {
            Surface(shape = RoundedCornerShape(16.dp), color = CARD) {
                Column(Modifier.padding(16.dp).widthIn(max = 360.dp)) {
                    Text("Rule ${rd + 1}", color = TXT, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(6.dp))
                    key(prof.id, rd, r) {
                        RuleEditor(store, prof, r,
                            onChange = { nr: RouteRule -> setRule(prof.id, rd, r, nr) },
                            onDelete = { deleteRule(prof.id, rd, r); ruleDialog = -1 })
                    }
                    TextButton(onClick = { ruleDialog = -1 }, modifier = Modifier.align(Alignment.End)) { Text("Done", color = PRIMARY) }
                }
            }
        }
    }
    confirmDelete?.let { victim: RoutingProfile ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            containerColor = CARD,
            title = { Text("Delete this routing profile?", color = TXT, fontSize = 16.sp) },
            text = { Text("${victim.name} · ${victim.rules.size} rule(s)", color = MUTED, fontSize = 13.sp, fontFamily = MONO) },
            confirmButton = {
                TextButton(onClick = {
                    store.profiles.removeAll { x: RoutingProfile -> x.id == victim.id }
                    store.saveProfiles()
                    val moved = store.repairSelection()   // a selection that named it falls back
                    if (editId == victim.id) editId = store.profiles.firstOrNull()?.id ?: ""
                    confirmDelete = null
                    AppWork.touch()
                    AppWork.snack(if (moved && store.selection.isNotEmpty()) "Deleted ${victim.name} — now using ${store.selectionLabel()}" else "Deleted ${victim.name}")
                }) { Text("Delete", color = BAD) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text("Cancel", color = MUTED) } }
        )
    }
    shared?.let { st: SharedText -> RouteShareDialog(st) { shared = null } }
    // a server tapped in the flow, in the same editor as on Servers
    val editing = editServerId?.let { id: String -> store.serverById(id) }
    if (editing != null) {
        val saveEdit: (ServerConfig) -> Unit = { updated: ServerConfig ->
            val idx = store.servers.indexOfFirst { x: ServerConfig -> x.id == updated.id }
            if (idx >= 0) { store.servers[idx] = updated; store.saveServers() }
            editServerId = null
            AppWork.touch()
        }
        if (editing.isJson) EditJsonSheet(editing, onDismiss = { editServerId = null }, onSave = saveEdit)
        else EditConfigSheet(editing, onDismiss = { editServerId = null }, onSave = saveEdit)
    }
    AddConfigSheets(store, sheet, { v: String? -> sheet = v }, { AppWork.touch() })
}

/** What Routing remembers across its own rebuilds: the profile an import just brought, to open at. */
private object RoutingUi { @Volatile var focus = "" }

/** One profile in Routing's list: tap to edit it; use it for Connect, share it, duplicate or delete it. */
@Composable private fun ProfileRow(
    store: Store, p: RoutingProfile, editing: Boolean, inUse: Boolean,
    onEdit: () -> Unit, onUse: () -> Unit, onShare: () -> Unit, onDuplicate: () -> Unit, onDelete: (() -> Unit)?
) {
    var menu by remember { mutableStateOf(false) }
    val dv = RoutingProfiles.effectiveDefVia(p)
    Row(
        Modifier.fillMaxWidth().padding(vertical = 4.dp).clip(RoundedCornerShape(12.dp))
            .background(if (editing) CARD_SEL else CARD)
            .border(if (editing) 1.5.dp else 1.dp, if (editing) PRIMARY else STROKE, RoundedCornerShape(12.dp))
            .clickable(onClickLabel = "edit this profile") { onEdit() }
            .padding(start = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f).padding(vertical = 8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "🧭 ${p.name}", color = TXT, fontSize = 14.sp, fontWeight = FontWeight.SemiBold,
                    maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false)
                )
                if (inUse) {
                    Spacer(Modifier.width(7.dp))
                    Text(
                        "IN USE", color = ON_PRIMARY, fontSize = 8.sp, fontFamily = MONO,
                        fontWeight = FontWeight.SemiBold, letterSpacing = 0.1.em, maxLines = 1,
                        modifier = Modifier.clip(RoundedCornerShape(4.dp)).background(PRIMARY).padding(horizontal = 5.dp, vertical = 3.dp)
                    )
                }
            }
            Text(
                "${p.rules.size} rule(s) · rest → ${store.targetLabel(p.def)}" + (if (dv != null) " via ${store.targetLabel(dv)}" else ""),
                color = MUTED2, fontSize = 10.sp, fontFamily = MONO, maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
        IconButton(onClick = onUse) { Icon(Icons.Filled.CheckCircle, "use this profile for Connect", tint = if (inUse) PRIMARY else MUTED) }
        IconButton(onClick = onShare) { Icon(Icons.Filled.Share, "share this profile", tint = TXT2) }
        Box {
            IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, "more", tint = MUTED) }
            DropdownMenu(menu, { menu = false }, modifier = Modifier.background(CARD)) {
                DropdownMenuItem(text = { Text("Duplicate", color = TXT) }, onClick = { menu = false; onDuplicate() })
                if (onDelete != null) {
                    DropdownMenuItem(text = { Text("Delete", color = BAD) }, onClick = { menu = false; onDelete() })
                }
            }
        }
    }
}

/** One rule's editor row: type, value, target, and — for a target that can take one — the base it rides on. */
@Composable private fun RuleEditor(store: Store, p: RoutingProfile, r: RouteRule, onChange: (RouteRule) -> Unit, onDelete: () -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        DropPick("Type", listOf("domain" to "Domain", "ip" to "IP", "port" to "Port"), r.type) { nt: String -> onChange(r.copy(type = nt)) }
        Spacer(Modifier.weight(1f))
        IconButton(onClick = onDelete) { Icon(Icons.Filled.DeleteOutline, "delete this rule", tint = BAD) }
    }
    // Saved when editing ends, not per keystroke (DraftField).
    DraftField(r.value, Modifier.fillMaxWidth(), placeholder = { Text("value (geosite:google / 1.2.3.0/24 / 443)", fontSize = 11.sp) }) { nv: String -> onChange(r.copy(value = nv)) }
    DropPick("⚠ ${store.targetLabel(r.target)}", targetOptionsFull(store), r.target) { t: String -> onChange(r.copy(target = t)) }
    if (!store.targetExists(r.target)) Text("⚠ This target is gone — the rule is skipped (its traffic follows the default) until you pick another.", color = BAD, fontSize = 11.sp)
    if (RoutingProfiles.takesVia(r.target)) {
        DropPick("⚠ via ${store.targetLabel(r.via)}", viaOptions(store, p, r.target), r.via.ifEmpty { RoutingProfiles.VIA_INHERIT }) { v: String -> onChange(r.copy(via = v)) }
        val eff = RoutingProfiles.effectiveVia(r, p)
        if (eff != null && !store.targetExists(eff)) Text("⚠ Its base is gone — connecting is refused until you pick another.", color = BAD, fontSize = 11.sp)
    }
}

/** What a target can ride on: the profile's base, nothing, or any server or chain but itself. */
private fun viaOptions(store: Store, p: RoutingProfile, target: String): List<Pair<String, String>> = buildList {
    val base = p.base
    add(RoutingProfiles.VIA_INHERIT to (if (base != null) "via the profile’s base (${store.targetLabel(base)})" else "via the profile’s base (none set)"))
    add(RoutingProfiles.VIA_NONE to "No base — dial it directly")
    targetOptions(store).filter { o: Pair<String, String> -> o.first != target }.forEach { o: Pair<String, String> -> add(o.first to "via ${o.second}") }
}

/** One step of the flow: a glyph, what it is, and why it is red when it is. */
@Composable private fun FlowNode(glyph: String, label: String, tint: Color, note: String?, indent: Dp, onClick: (() -> Unit)?) {
    val click = if (onClick == null) Modifier else Modifier.clickable { onClick() }
    Row(
        Modifier.fillMaxWidth().padding(start = indent).heightIn(min = 40.dp).clip(RoundedCornerShape(8.dp))
            .then(click).padding(horizontal = 6.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(glyph, color = tint, fontSize = 13.sp, fontFamily = MONO, modifier = Modifier.width(24.dp))
        Column(Modifier.weight(1f)) {
            Text(label, color = if (note != null) BAD else TXT, fontSize = 13.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
            if (note != null) Text(note, color = BAD, fontSize = 10.sp)
        }
    }
}

@Composable private fun FlowArrow(text: String, indent: Dp) {
    Text(text, color = MUTED2, fontSize = 11.sp, fontFamily = MONO, modifier = Modifier.padding(start = indent + 10.dp))
}

/** The rule's values, short: the first two and how many more. */
private fun ruleSummary(r: RouteRule): String {
    val vals = r.value.split(Regex("[|,]")).map { v: String -> v.trim() }.filter { v: String -> v.isNotEmpty() }
    if (vals.isEmpty()) return "(no value — skipped)"
    return vals.take(2).joinToString(", ") + (if (vals.size > 2) " +${vals.size - 2}" else "")
}

private fun ruleGlyph(type: String): String = when (type) {
    "domain" -> "🌐"
    "ip" -> "#"
    "port" -> ":"
    else -> "•"
}

private fun targetGlyph(t: String): String = when {
    t == "direct" -> "→"
    t == "block" -> "⛔"
    t.startsWith("chain:") -> "⛓"
    else -> "▣"
}

/**
 * The profile as a vertical flow (spec §3, Android): each step is the rules
 * (consecutive ones to the same place grouped) → where they go → the base it
 * rides on; the default last, as "everything else". Then each base once, with
 * every target through it. A rule opens its editor; a server its edit sheet; a
 * chain the chains screen. What is gone is red, with what connecting does about it.
 */
@Composable private fun FlowList(store: Store, p: RoutingProfile, onRule: (Int) -> Unit, onNode: (String) -> Unit) {
    val lanes = RoutingProfiles.lanes(p) { t: String -> store.targetExists(t) }
    Text("FLOW", color = MUTED2, fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em)
    Text("Top to bottom: the first rule that matches decides where the traffic goes, then what that rides on.", color = MUTED, fontSize = 11.sp)
    Spacer(Modifier.height(6.dp))
    lanes.forEach { lane: RoutingProfiles.Lane ->
        Card(Modifier.fillMaxWidth().padding(vertical = 4.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(12.dp)) {
            Column(Modifier.padding(horizontal = 6.dp, vertical = 6.dp)) {
                if (lane.isDefault) {
                    FlowNode("★", "Everything else", TXT2, null, 0.dp, null)
                } else {
                    lane.rules.forEach { i: Int ->
                        val r = p.rules[i]
                        FlowNode(ruleGlyph(r.type), ruleSummary(r), TXT2, null, 0.dp) { onRule(i) }
                    }
                }
                FlowArrow("↓", 12.dp)
                val targetNote = if (!lane.targetMissing) null
                    else if (lane.isDefault) "gone — connecting is refused"
                    else "gone — skipped, its traffic follows the default"
                val target = if (lane.target.isEmpty() && lane.isDefault) (store.servers.firstOrNull()?.id ?: "direct") else lane.target
                FlowNode(targetGlyph(target), store.targetLabel(target), PRIMARY, targetNote, 12.dp) { onNode(target) }
                val via = lane.via
                if (via != null) {
                    FlowArrow("↓ via", 24.dp)
                    FlowNode("◆", store.targetLabel(via), AMBER, if (lane.viaMissing) "base gone — connecting is refused" else null, 24.dp) { onNode(via) }
                }
            }
        }
    }
    val bases = RoutingProfiles.lanesByBase(lanes)
    if (bases.isNotEmpty()) {
        Spacer(Modifier.height(8.dp))
        Text("BASES", color = MUTED2, fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em)
        bases.forEach { e: Pair<String, List<RoutingProfiles.Lane>> ->
            val base = e.first
            Card(Modifier.fillMaxWidth().padding(vertical = 4.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(12.dp)) {
                Column(Modifier.padding(horizontal = 6.dp, vertical = 6.dp)) {
                    FlowNode("◆", store.targetLabel(base), AMBER, if (store.targetExists(base)) null else "gone — connecting is refused", 0.dp) { onNode(base) }
                    e.second.forEach { l: RoutingProfiles.Lane ->
                        Text(
                            "← " + store.targetLabel(l.target) + (if (l.isDefault) " (everything else)" else ""),
                            color = MUTED, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.padding(start = 34.dp, top = 2.dp, bottom = 2.dp)
                        )
                    }
                }
            }
        }
    }
}

/** A routing link ready to hand over: what it is called, the text, and how many servers it carries. */
private class SharedText(val title: String, val text: String, val servers: Int)

/** A profile's share link (RouteShare), or null after saying why there is none. */
private fun profileShare(store: Store, p: RoutingProfile): SharedText? = try {
    val payload = RouteShare.profilePayload(p, store.servers.toList(), store.chains.toList()) { srv: ServerConfig -> LinkParser.buildShareLink(srv) }
    SharedText("Share “${p.name}”", RouteShare.encode(payload), payload.getJSONArray("servers").length())
} catch (e: Exception) {
    AppWork.snack("Can’t share ${p.name}: ${e.message ?: "error"}")
    null
}

/** A chain's share link, or null after saying why there is none. */
private fun chainShare(store: Store, c: ChainConfig): SharedText? = try {
    val payload = RouteShare.chainPayload(c, store.servers.toList()) { srv: ServerConfig -> LinkParser.buildShareLink(srv) }
    SharedText("Share ⛓ ${c.name}", RouteShare.encode(payload), payload.getJSONArray("servers").length())
} catch (e: Exception) {
    AppWork.snack("Can’t share ${c.name}: ${e.message ?: "error"}")
    null
}

/**
 * Copy (and QR, when it fits — the desktop's 1,700 bytes) a routing link. It
 * says, every time, that the servers' details are inside: whoever has the
 * link can connect to them.
 */
@Composable private fun RouteShareDialog(st: SharedText, onDismiss: () -> Unit) {
    val ctx = LocalContext.current
    val fits = RouteShare.fitsQr(st.text)
    val bmp = remember(st.text) { if (fits) qrBitmap(st.text) else null }
    Dialog(onDismissRequest = onDismiss) {
        Surface(shape = RoundedCornerShape(16.dp), color = CARD) {
            Column(Modifier.padding(18.dp).widthIn(max = 320.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Text(st.title, color = TXT, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
                Spacer(Modifier.height(8.dp))
                Text(
                    "⚠ This link carries everything needed to connect — ${st.servers} server(s), with their addresses and keys. Give it only to someone you would give those servers to.",
                    color = AMBER, fontSize = 12.sp
                )
                Spacer(Modifier.height(12.dp))
                if (bmp != null) Image(
                    bmp.asImageBitmap(), "QR",
                    Modifier.size(248.dp).clip(RoundedCornerShape(10.dp)).background(Color.White).padding(6.dp),
                    filterQuality = FilterQuality.None
                )
                else Text("Too large for a QR — use Copy.", color = MUTED, fontSize = 12.sp)
                Spacer(Modifier.height(8.dp))
                Text("${st.text.toByteArray(Charsets.UTF_8).size} bytes", color = MUTED2, fontSize = 10.sp, fontFamily = MONO)
                Spacer(Modifier.height(12.dp))
                Button(onClick = { copyConfigText(ctx, st.text); onDismiss() }, modifier = Modifier.fillMaxWidth()) { Text("Copy link") }
            }
        }
    }
}

/**
 * The preview of an `irnetfree://routing/` link (pasted, typed or scanned):
 * what it is, its rules and chains, the servers already here and the new ones,
 * anything this app cannot read — then Import. A link that cannot be read says
 * why, and nothing is written.
 */
@Composable private fun RouteImportDialog(store: Store, text: String, onClose: () -> Unit) {
    val decoded = remember(text) { runCatching { RouteShare.decode(text) } }
    val payload = decoded.getOrNull()
    val summary = remember(text) {
        payload?.let { p: JSONObject ->
            runCatching {
                RouteShare.previewImport(p, store.servers.toList(), store.chains.toList(), store.profiles.toList(),
                    { l: String -> RouteShare.parseServer(l) }, { srv: ServerConfig -> SubRefresh.strictIdentity(srv) })
            }.getOrNull()
        }
    }
    val why = decoded.exceptionOrNull()?.message ?: "This link could not be read."
    AlertDialog(
        onDismissRequest = onClose,
        containerColor = CARD,
        title = {
            Text(
                when {
                    summary == null -> "Can’t import this link"
                    summary.kind == RouteShare.KIND_CHAIN -> "Import chain “${summary.name}”"
                    else -> "Import routing “${summary.name}”"
                },
                color = TXT, fontSize = 16.sp
            )
        },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                if (summary == null) {
                    Text(why, color = BAD, fontSize = 13.sp)
                } else {
                    if (summary.kind == RouteShare.KIND_PROFILE) Text("${summary.rules} rule(s) — added as a new profile", color = TXT, fontSize = 13.sp)
                    Text("${summary.chains} chain(s)", color = TXT, fontSize = 13.sp)
                    Text("${summary.serversNew} new server(s) · ${summary.serversExisting} already here", color = TXT, fontSize = 13.sp)
                    if (summary.unreadable.isNotEmpty()) {
                        Spacer(Modifier.height(6.dp))
                        Text("Not readable here — what names them is marked missing:", color = AMBER, fontSize = 12.sp)
                        summary.unreadable.forEach { u: String -> Text("· $u", color = AMBER, fontSize = 11.sp) }
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "New servers are added by hand, not to a subscription. Of the settings only “routing mode under these rules” comes with it — your routing mode, DNS and the rest stay yours.",
                        color = MUTED, fontSize = 11.sp
                    )
                }
            }
        },
        confirmButton = {
            if (summary != null && payload != null) {
                TextButton(onClick = { importRouting(store, payload); onClose() }) { Text("Import", color = PRIMARY) }
            }
        },
        dismissButton = { TextButton(onClick = onClose) { Text(if (summary == null) "Close" else "Cancel", color = MUTED) } }
    )
}

/** Take a decoded routing link into the store (RouteShare.applyImport) and say what came of it. */
private fun importRouting(store: Store, payload: JSONObject) {
    val r = try {
        RouteShare.applyImport(payload, store.servers.toList(), store.chains.toList(), store.profiles.toList(),
            { l: String -> RouteShare.parseServer(l) }, { srv: ServerConfig -> SubRefresh.strictIdentity(srv) }, { prefix: String -> newId(prefix) })
    } catch (e: Exception) {
        AppWork.snack("Nothing imported — ${e.message ?: "the link could not be read"}")
        return
    }
    store.applyImported(r)
    if (store.selection.isEmpty()) r.servers.firstOrNull()?.let { srv: ServerConfig -> store.saveSelection(srv.id) }
    val pid = r.profileId
    if (pid != null) RoutingUi.focus = pid
    val what = if (pid != null) "🧭 ${store.profileById(pid)?.name ?: "the profile"}" else "the chain"
    val hint = if (pid != null && !store.settings.advancedRouting) " — turn on Routing → Advanced routing to use it" else ""
    AppWork.snack("Imported $what: ${r.addedServers} new server(s), ${r.addedChains} new chain(s)$hint")
    AppWork.touch()
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
        SwitchRow("Connect on open", s.autoConnect) { save(s.copy(autoConnect = it)) }
        Text(
            if (s.autoConnect) "When the app is opened it connects to the config in use, without asking. Android needs VPN permission first — connect once by hand and it is silent from then on."
            else "The app opens without connecting; the ring waits for you.",
            color = MUTED, fontSize = 11.sp
        )
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
        // What this APK carries, as the cores themselves say it — off the main
        // thread, since PattN is asked by running it. Android runs no core an
        // app downloads, so these change only with a newer IRNetFree.
        val cores by produceState(coresKnown.ifEmpty { "Cores in this app: …" }) {
            if (coresKnown.isEmpty()) coresKnown = withContext(Dispatchers.IO) { coresLine(ctx) }
            value = coresKnown
        }
        Text(cores, color = MUTED, fontSize = 11.sp, fontFamily = MONO, modifier = Modifier.padding(top = 6.dp))
        // Mux (Mux.kt, spec §4). Its own key, like LAN sharing — not in this
        // screen's copy of AppSettings; read by the next connect.
        var mux by remember { mutableStateOf(store.muxMode) }
        fun pickMux(v: String) { store.muxMode = v; mux = v }
        Text("Mux (multiplexing)", color = TXT, modifier = Modifier.padding(top = 10.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            listOf(Mux.AUTO to "Auto", Mux.ON to "On", Mux.OFF to "Off").forEach { (v, l) ->
                Row(Modifier.clickable { pickMux(v) }.padding(end = 14.dp), verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(mux == v, { pickMux(v) }); Text(l, color = TXT)
                }
            }
        }
        Text(muxHelp(mux), color = MUTED, fontSize = 11.sp)
        HorizontalDivider(Modifier.padding(vertical = 10.dp), color = STROKE)
        Text("Per-app routing", color = TXT, fontWeight = FontWeight.Bold)
        listOf("off" to "Off (whole system)", "allow" to "Only these apps", "disallow" to "All except these").forEach { (v, l) ->
            Row(Modifier.fillMaxWidth().clickable { save(s.copy(perAppMode = v)) }, verticalAlignment = Alignment.CenterVertically) { RadioButton(s.perAppMode == v, { save(s.copy(perAppMode = v)) }); Text(l, color = TXT) }
        }
        if (s.perAppMode != "off") AppPicker(s.perApps) { save(s.copy(perApps = it)) }
        LanShareSection(store)
    }
}

/** Settings → Mux: one line of help, for the choice it is on (Off is the default). */
private fun muxHelp(mode: String): String = when (mode) {
    Mux.AUTO -> "Auto: each WebSocket / HTTPUpgrade server is tested once and uses mux where it works — far fewer handshakes, less battery."
    Mux.ON -> "On: every VLESS (without flow), VMess and Trojan server over WebSocket or HTTPUpgrade uses mux, untested."
    else -> "Off (the default): every connection makes its own handshake with the server, as before."
}

/**
 * Settings' cores line once worked out: the cores inside an APK do not change
 * while it runs, and every setting saved rebuilds the screen (no "…" flash).
 */
private var coresKnown = ""

/**
 * "Cores in this app: Xray 26.9.30 · Xray-PattN 26.10.3 · sing-box —" — the
 * in-process core's own answer (Libv2ray.checkVersionX, "Lib v…, Xray-core
 * v26.9.30", trimmed to its number) and PattN's `version`; "—" for a core that
 * is not bundled here or cannot say (sing-box has no version call in this app).
 * Blocking: PattN is run once.
 */
private fun coresLine(ctx: Context): String {
    val num = Regex("""\d+\.\d+\.\d+""")
    val xray = XrayCore.version().let { v -> num.find(v)?.value ?: v.ifBlank { "—" } }
    val pattn = XrayPattnCore.version(ctx).ifBlank { "—" }
    return "Cores in this app: Xray $xray · Xray-PattN $pattn · sing-box —"
}

@Composable private fun AppPicker(selected: List<String>, onChange: (List<String>) -> Unit) {
    val ctx = LocalContext.current
    // Never IRNetFree itself: the app is excluded from its own tunnel so the
    // core's sockets can leave the device, and "only these apps" with it on the
    // list would route the core's own traffic back into the core.
    val apps = remember { runCatching { val pm = ctx.packageManager; pm.getInstalledApplications(0).filter { it.packageName != ctx.packageName && pm.getLaunchIntentForPackage(it.packageName) != null }.map { it.packageName to pm.getApplicationLabel(it).toString() }.sortedBy { it.second } }.getOrElse { emptyList() } }
    // ...and a list saved before it was hidden here loses it, since it can no longer be unticked
    LaunchedEffect(Unit) { if (ctx.packageName in selected) onChange(selected - ctx.packageName) }
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
                    add(MoreRow("routing", "Routing", if (s.advancedRouting) "advanced routing profiles" else routingModeLabel(s.routingMode), if (s.advancedRouting) "${store.profiles.size} profile(s)" else "", Icons.Filled.CallSplit))
                }
                add(MoreRow("settings", "Settings", "ports, DNS, core, mux, per-app", "", Icons.Filled.Settings))
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

// fmtBytes, fmtSpeed and fmtAgo live in Format.kt (the list logic's tests use them).

/** "1.15.0" — the installed build's versionName; "" when the platform will not say. */
private fun appVersion(ctx: Context): String = runCatching {
    val pm = ctx.packageManager
    val info = if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(ctx.packageName, PackageManager.PackageInfoFlags.of(0))
               else @Suppress("DEPRECATION") pm.getPackageInfo(ctx.packageName, 0)
    info.versionName ?: ""
}.getOrDefault("")

private fun fmtDuration(ms: Long): String {
    val s = (ms / 1000).coerceAtLeast(0); return "%02d:%02d:%02d".format(s / 3600, (s % 3600) / 60, s % 60)
}
private fun msLabel(ms: Long) = if (ms >= 0) "${ms}ms" else "×"
private fun badge(p: String) = when (p) { "vless" -> "VLESS"; "vmess" -> "VMESS"; "trojan" -> "TROJAN"; "shadowsocks" -> "SS"; "wireguard" -> "WG"; "hysteria2" -> "HY2"; "socks" -> "SOCKS"; "http" -> "HTTP"; else -> p.uppercase() }
private fun flag(cc: String): String { if (cc.length != 2) return "🏳"; val base = 0x1F1E6; return String(Character.toChars(base + (cc[0].uppercaseChar() - 'A'))) + String(Character.toChars(base + (cc[1].uppercaseChar() - 'A'))) }
