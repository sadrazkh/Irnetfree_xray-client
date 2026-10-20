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
import androidx.compose.foundation.horizontalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.material3.pulltorefresh.PullToRefreshContainer
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.snapshots.SnapshotStateMap
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
// by name: another star import here also has a Selection, and the star imports tie
import com.irnetfree.vpn.core.Selection
// by name too: the extended icons' star import has a `Groups` of its own (Icons.Filled.Groups)
import com.irnetfree.vpn.core.Groups
import com.irnetfree.vpn.core.GroupConfig
import com.irnetfree.vpn.core.GroupMember
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
    // the per-second figures run only while the app is on screen (VpnState.uiVisible)
    override fun onStart() { super.onStart(); VpnState.setUiVisible(true) }
    override fun onStop() { VpnState.setUiVisible(false); super.onStop() }
}

@Composable
private fun AppTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = darkColorScheme(primary = PRIMARY, secondary = PRIMARY, background = BG, surface = CARD,
        onPrimary = ON_PRIMARY, onBackground = TXT, onSurface = TXT, surfaceVariant = CARD2, outline = STROKE)) {
        // Persian reads right to left: the whole app is laid out that way, and a
        // language switch (I18n.rtl is a Compose state) turns it at once.
        CompositionLocalProvider(LocalLayoutDirection provides (if (I18n.rtl) LayoutDirection.Rtl else LayoutDirection.Ltr)) {
            Surface(Modifier.fillMaxSize(), color = BG) { content() }
        }
    }
}

@Composable
private fun CrashScreen(text: String, onClear: () -> Unit) {
    Column(Modifier.fillMaxSize().statusBarsPadding().padding(16.dp)) {
        Text(t("crash.title"), color = BAD, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(8.dp))
        // a stack trace reads left to right in either language
        LtrBlock { SelectionContainer { Text(text, color = TXT, fontSize = 11.sp, modifier = Modifier.weight(1f).verticalScroll(rememberScrollState())) } }
        Spacer(Modifier.height(8.dp))
        Button(onClick = onClear, modifier = Modifier.fillMaxWidth()) { Text(t("crash.retry")) }
    }
}

/* ---------------- nav ---------------- */
// A phone carries four; the desktop's Chain, Proxy Pool, Routing, Logs and
// Settings live behind More (the design doc: "8 sidebar sections, a phone can
// carry 4").
private enum class Tab(val labelKey: String, val icon: ImageVector) {
    HOME("nav.home", Icons.Filled.PowerSettingsNew),
    SERVERS("nav.servers", Icons.Filled.Dns),
    SUBS("nav.subs", Icons.Filled.CloudDownload),
    MORE("nav.more", Icons.Filled.Menu)
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
                        label = { Text(t(tb.labelKey), fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em) },
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
            AppWork.snack(tf("auto.skipped", "why" to why))
            return@LaunchedEffect
        }
        if (VpnService.prepare(ctx) != null) {
            VpnState.addLog("Connect on open: Android has not been given VPN permission yet — connect once by hand and it will be automatic after that.")
            AppWork.snack(t("auto.needsHand"))
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

/** Store.selectionLabel on screen: the pool's row in the app's language, any other selection by its name. */
private fun selectionWord(store: Store): String =
    if (store.selection == Store.POOL_ID) "🧩 " + tf("pick.pool", "n" to store.poolEnabledValid().size) else store.selectionLabel()

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
        while (connectedSince > 0) {
            // off screen: no tick until the app is seen again (VpnState.uiVisible)
            if (!VpnState.uiVisible.value) VpnState.uiVisible.first { v: Boolean -> v }
            elapsed = System.currentTimeMillis() - connectedSince; delay(1000)
        }
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
            if (store.servers.isEmpty()) { homeSheet = "import"; AppWork.snack(t("home.addFirst")) }
            else { pickerOpen = true; AppWork.snack(t("home.pickFirst")) }
            return
        }
        withConsent("connect")
    }
    fun selectedServer(): ServerConfig? {
        val sel = store.selection
        val s = store.serverById(sel) ?: store.chainById(sel.removePrefix("chain:"))?.let { store.chainMembers(it).firstOrNull() }
        // a group (or a chain entered through one) has no one address to knock on
        return if (Groups.isGroupRecord(s)) null else s
    }
    /** Is the selection a group, or a chain whose first hop is one? */
    fun selectedViaGroup(): Boolean {
        val sel = store.selection
        if (store.groupById(sel) != null) return true
        val c = store.chainById(sel.removePrefix("chain:")) ?: return false
        return Groups.isGroupRecord(store.chainMembers(c).firstOrNull())
    }
    /** A TCP ping of the selected server, asked for by a tap; the result is kept with the other tests. */
    fun pingSelected() {
        val srv = selectedServer()
        if (srv == null) {
            // a group has no one address to knock on (the desktop's ping:tcp says the same)
            AppWork.snack(if (selectedViaGroup()) t("home.groupNoPing") else t("home.nothingToPing"))
            return
        }
        if (pinging) return
        pinging = true
        val app = ctx.applicationContext
        scope.launch {
            // a UDP-only server (Fastest.udpOnly) has no TCP port to knock on: a real
            // round trip through a throwaway core instead, as ⚡ measures it
            if (Fastest.udpOnly(srv)) {
                val real = realDelayThrough(app, srv, Fastest.UDP_TIMEOUT_MS)
                AppWork.putReal(srv.id, real)
                pinging = false
                if (real < 0) AppWork.snack("${srv.name}: no answer through it")
                return@launch
            }
            val ms = withContext(Dispatchers.IO) { Diagnostics.tcpPing(srv.address, srv.port) }
            AppWork.putPing(srv.id, ms)
            pinging = false
            if (ms < 0) AppWork.snack(tf("home.noAnswer", "name" to srv.name, "port" to srv.port))
        }
    }
    // The last TCP ping of the selected server (a chain: its first hop), from
    // wherever it was measured — a tap here, a test on Servers, ⚡. Never
    // measured on its own: pinging a server nobody asked about, every time the
    // app opens, is not ours to do. A UDP-only server's is its real round trip.
    val selUdp = selectedServer()?.let { s: ServerConfig -> Fastest.udpOnly(s) } == true
    val selTest = selectedServer()?.let { AppWork.tests[it.id] }?.let { t: TestState -> if (selUdp) t.copy(tcp = t.down) else t }

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
            LtrBlock { Column {
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
            } }
            Spacer(Modifier.weight(1f))
            Text(
                if (settings.advancedMode) t("mode.advancedBadge") else t("mode.simpleBadge"),
                color = MUTED, fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em,
                modifier = Modifier.clip(RoundedCornerShape(50)).border(1.dp, STROKE, RoundedCornerShape(50)).padding(horizontal = 8.dp, vertical = 4.dp)
            )
            if (connectedSince > 0) { Spacer(Modifier.width(8.dp)); Text(fmtDuration(elapsed), color = MUTED, fontSize = 10.sp, fontFamily = MONO) }
            IconButton(onClick = { homeSheet = "import" }) { Icon(Icons.Filled.AddCircle, t("home.addConfig"), tint = PRIMARY) }
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
                        busy && cancelAsked -> t("state.cancelling")
                        state == ConnState.CONNECTED -> t("state.connected")
                        state == ConnState.CONNECTING -> t("state.connecting")
                        autoPhase.isNotEmpty() -> t("home.findingFastest")
                        state == ConnState.ERROR -> t("state.notConnected")
                        else -> t("state.notProtected")
                    },
                    color = TXT, fontSize = 19.sp, fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.height(5.dp))
                Text(
                    when {
                        // ⚡ says what it is measuring, even over a tunnel still up
                        autoPhase.isNotEmpty() -> tf("home.phaseCancel", "phase" to autoPhase)
                        // the server carrying traffic; picking another one only
                        // changes what the NEXT connect uses
                        state == ConnState.CONNECTED -> connectedLabel.ifBlank { selectionWord(store) }
                        state == ConnState.CONNECTING -> t("home.starting")
                        state == ConnState.ERROR -> err.ifBlank { t("home.seeLogs") }
                        else -> t("home.tapToConnect")
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
                            .clickable(onClickLabel = if (running) t("power.cancel") else t("home.fastestA11y")) {
                                if (running) { cancelAsked = true; AppWork.cancelFastest() } else connectFastest()
                            }
                            .padding(horizontal = 18.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            if (running) t("home.stopTesting") else t("home.fastest"),
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
                Metric(Modifier.weight(1f), t("metric.down"), fmtSpeed(traffic.rxSpeed), tf("metric.total", "v" to fmtBytes(traffic.rxBytes)), PRIMARY)
                Metric(Modifier.weight(1f), t("metric.up"), fmtSpeed(traffic.txSpeed), tf("metric.total", "v" to fmtBytes(traffic.txBytes)), TXT)
            }
            Spacer(Modifier.height(10.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Metric(Modifier.weight(1f), if (selUdp) t("metric.udp") else t("metric.tcp"), if (pinging) "…" else fmtLat(selTest?.tcp), if (selUdp) t("metric.throughTestCore") else t("metric.toServer"), if (pinging) AMBER else latColor(selTest?.tcp))
                Metric(Modifier.weight(1f), t("metric.real"), if (measuring == "delay") "…" else fmtLat(latency), t("metric.throughTunnel"), if (measuring == "delay") AMBER else latColor(latency))
            }

            /* ---- transfer speed ---- */
            Spacer(Modifier.height(10.dp))
            Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                Column(Modifier.padding(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(t("chart.title"), color = TXT, fontSize = 13.sp, modifier = Modifier.weight(1f))
                        Text(t("chart.down"), color = PRIMARY, fontSize = 9.sp, fontFamily = MONO)
                        Spacer(Modifier.width(8.dp))
                        Text(t("chart.up"), color = MUTED, fontSize = 9.sp, fontFamily = MONO)
                    }
                    Spacer(Modifier.height(10.dp))
                    Sparkline(spark, Modifier.fillMaxWidth().height(64.dp))
                    // the chart runs left to right (newest on the right) in either language, and so do its ends
                    LtrBlock {
                        Row(Modifier.fillMaxWidth().padding(top = 6.dp)) {
                            Text(tf("chart.last", "n" to spark.size), color = MUTED2, fontSize = 9.sp, fontFamily = MONO, modifier = Modifier.weight(1f))
                            Text(t("chart.now"), color = MUTED2, fontSize = 9.sp, fontFamily = MONO)
                        }
                    }
                }
            }

            /* ---- the tunnel's real scope ---- */
            Spacer(Modifier.height(10.dp))
            ApplyBar(store, settings)
            Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                Row(Modifier.padding(horizontal = 14.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(t("home.tunnel"), color = TXT, fontSize = 13.sp)
                        Text(
                            // as the VPN takes it: "only these" with none of them left is the whole device (TunnelSetup.perApp)
                            when {
                                settings.perAppMode == "allow" && settings.perApps.isNotEmpty() -> tf("home.onlyApps", "n" to settings.perApps.size)
                                settings.perAppMode == "disallow" && settings.perApps.isNotEmpty() -> tf("home.allAppsBut", "n" to settings.perApps.size)
                                else -> t("home.wholeSystem")
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
            Text(t("home.protection"), color = MUTED2, fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em)
            Spacer(Modifier.height(8.dp))
            val geo = remember { GeoAssets.available(ctx) }
            // The core a plan would actually run on, asked the same way the service
            // asks it — not just the default setting.
            val core = remember(settings.defaultEngine, store.selection) {
                EngineChoice.chooseEngine(runCatching { store.buildPlan() }.getOrNull(), settings.defaultEngine)
            }
            FlowChips(listOf(
                Pair(if (settings.dnsManaged) t("chip.dnsManaged") else t("chip.dnsGiven"), settings.dnsManaged),
                Pair(tf("chip.routing", "mode" to routingModeLabel(settings.routingMode)), settings.routingMode != "global"),
                Pair(if (geo) t("chip.geoOn") else t("chip.geoMissing"), geo),
                Pair(if (settings.ipv6) t("chip.ipv6On") else t("chip.ipv6Off"), settings.ipv6),
                Pair(tf("chip.core", "core" to core), true)
            ))

            /* ---- quick actions ---- */
            Spacer(Modifier.height(16.dp))
            if (settings.advancedMode) Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = { pingSelected() },
                    modifier = Modifier.weight(1f), shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TXT2), border = BorderStroke(1.dp, STROKE)
                ) { Text(t("home.pingTest"), fontSize = 12.sp) }
                OutlinedButton(
                    onClick = {
                        val sp = if (state == ConnState.CONNECTED) store.settings.socksPort else null
                        measuring = "delay"
                        scope.launch {
                            val ms = withContext(Dispatchers.IO) { Diagnostics.httpLatency(sp) }
                            latency = if (ms >= 0) ms else null
                            val r = withContext(Dispatchers.IO) { Diagnostics.ipInfo(sp) }
                            ip = if (r.ok) "${flag(r.countryCode)} ${r.ip}" else t("home.ipFail")
                            measuring = ""
                            if (!r.ok) AppWork.snack(t("home.ipCheckFailed") + if (r.error.isNotBlank()) ": ${r.error}" else "")
                        }
                    },
                    modifier = Modifier.weight(1f), shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TXT2), border = BorderStroke(1.dp, STROKE)
                ) { Text(t("home.checkIp"), fontSize = 12.sp) }
                OutlinedButton(
                    onClick = { if (state == ConnState.CONNECTED) AppWork.reconnect(ctx, store) },
                    enabled = state == ConnState.CONNECTED,
                    modifier = Modifier.weight(1f), shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TXT2), border = BorderStroke(1.dp, STROKE)
                ) { Text(t("home.reconnect"), fontSize = 12.sp) }
            }
            if (ip != "—") {
                Spacer(Modifier.height(8.dp))
                Text(tf("home.egress", "ip" to ip), color = MUTED, fontSize = 11.sp, fontFamily = MONO)
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
                    t("home.noServer"),
                    t("home.noServerHint"),
                    t("home.addServerOrSub")
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
                    .clickable(onClickLabel = if (busy) t("power.cancel") else if (on) t("power.disconnect") else t("power.connect")) { onPower() },
                contentAlignment = Alignment.Center
            ) {
                if (busy) Box(contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = if (on) ON_PRIMARY else PRIMARY, strokeWidth = 4.dp, modifier = Modifier.size(64.dp))
                    Icon(Icons.Filled.Close, t("power.cancel"), tint = if (on) ON_PRIMARY else TXT2, modifier = Modifier.size(26.dp))
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
        ) { Text(t("power.cancel"), fontSize = 14.sp, fontWeight = FontWeight.SemiBold) }
        state == ConnState.CONNECTED -> OutlinedButton(
            onClick = onPower, modifier = mod, shape = shape, contentPadding = pad, border = BorderStroke(1.dp, STROKE),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = TXT)
        ) { Text(t("power.disconnect"), fontSize = 14.sp, fontWeight = FontWeight.SemiBold, maxLines = 1) }
        else -> Button(
            onClick = onPower, modifier = mod, shape = shape, contentPadding = pad,
            colors = ButtonDefaults.buttonColors(containerColor = PRIMARY, contentColor = ON_PRIMARY)
        ) { Text(t("power.connect"), fontSize = 14.sp, fontWeight = FontWeight.SemiBold) }
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
    val (flag, label) = if (srv != null) ServerLabel.split(srv.name) else null to selectionWord(store)
    // a routing profile whose traffic rides on a base says which (spec §3: the small path's "via <base>")
    val viaBase = if (srv != null) null else store.selectedProfile()?.let { p: RoutingProfile -> RoutingProfiles.effectiveDefVia(p) ?: p.base }
    // a group (Groups.kt) says how many configs it spreads over, and how
    val grp = if (srv != null) null else store.groupById(store.selection)
    Row(
        modifier.heightIn(min = 56.dp).clip(RoundedCornerShape(14.dp)).background(CARD)
            .border(1.dp, STROKE, RoundedCornerShape(14.dp)).clickable(onClickLabel = t("exit.choose")) { onPick() }
            .padding(start = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (srv != null) Leading(flag, srv.protocol)
        Spacer(Modifier.width(if (srv != null) 10.dp else 2.dp))
        Column(Modifier.weight(1f).padding(vertical = 8.dp)) {
            Text(label, color = TXT, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                when {
                    srv != null -> badge(srv.protocol) + " · " + t("exit.tapChange")
                    grp != null -> configsWord(Groups.sizeOf(store.groupRecord(grp.id))) + " · " + strategyWord(grp.strategy).lowercase() + " · " + t("exit.tapChange")
                    viaBase != null -> tf("exit.via", "name" to targetWord(store, viaBase)) + " · " + t("exit.tapChange")
                    else -> t("exit.tapChange")
                },
                color = MUTED2, fontSize = 10.sp, fontFamily = MONO, maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
        // The ping: its own 48 dp target, so measuring never opens the picker.
        Box(
            Modifier.heightIn(min = 48.dp).widthIn(min = 52.dp).clickable(onClickLabel = t("exit.ping")) { onPing() }.padding(horizontal = 8.dp),
            contentAlignment = Alignment.Center
        ) {
            val ms = result?.tcp
            when {
                pinging -> Text("…", color = AMBER, fontSize = 13.sp, fontFamily = MONO)
                ms != null -> Text(if (ms >= 0) "$ms ms" else "×", color = latColor(ms), fontSize = 12.sp, fontFamily = MONO, maxLines = 1)
                else -> Text(t("exit.ping"), color = MUTED, fontSize = 11.sp, fontFamily = MONO)
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
            Text(tf("upd.out", "v" to v), color = TXT, fontSize = 13.sp, modifier = Modifier.padding(end = 8.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                TextButton(onClick = onLater) { Text(t("btn.later"), color = MUTED, fontSize = 13.sp) }
                TextButton(onClick = onDownload) { Text(t("btn.download"), color = PRIMARY, fontSize = 13.sp, fontWeight = FontWeight.SemiBold) }
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
        .onFailure { AppWork.snack(tf("upd.noOpener", "url" to url)) }
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
 * A UDP-only server (WireGuard, Hysteria2, MASQUE over HTTP/3 — [Fastest.udpOnly])
 * has no TCP port to knock on: a handshake failed for every one, so ⚡ could
 * never pick one. Its first stage is a real round trip instead, through a
 * throwaway core one at a time, bounded like the handshake batch
 * ([Fastest.measureUdp]); it is then ranked beside the TCP servers' round trips.
 *
 * `onPhase` runs on the caller's dispatcher (the UI's), so it may write state.
 */
private suspend fun pickFastest(
    ctx: Context,
    servers: List<ServerConfig>,
    onPhase: (String) -> Unit
): FastestResult {
    val (udpServers, tcpServers) = servers.partition { s: ServerConfig -> Fastest.udpOnly(s) }
    val measured = LinkedHashMap<String, Fastest.Measured>()
    var done = 0
    onPhase(tf("fast.testing", "progress" to "0/${servers.size}"))
    for (batch in tcpServers.chunked(8)) {
        val part = withContext(Dispatchers.IO) {
            batch.map { s -> async { Fastest.Measured(s.id, tcp = Diagnostics.tcpPing(s.address, s.port, timeout = 3000)) } }.awaitAll()
        }
        part.forEach { measured[it.id] = it; AppWork.putPing(it.id, it.tcp ?: -1L) }   // the list shows them too
        done += batch.size
        onPhase(tf("fast.testing", "progress" to "$done/${servers.size}"))
    }
    val byId = servers.associateBy { it.id }
    val udp = Fastest.measureUdp(udpServers.map { s: ServerConfig -> s.id }, now = { System.nanoTime() / 1_000_000L }) { i: Int, id: String ->
        val s = byId[id]
        if (s == null) -1L else {
            onPhase(tf("fast.testing", "progress" to "${done + i + 1}/${servers.size} · ${s.name.take(16)} (UDP)"))
            val ms = realDelayThrough(ctx, s, Fastest.UDP_TIMEOUT_MS)
            AppWork.putReal(s.id, ms)   // the list shows it too
            ms
        }
    }
    if (udp.size < udpServers.size)
        VpnState.addLog("Auto (fastest): ${udp.size} of the ${udpServers.size} UDP-only servers measured (a throwaway core each, at most ${Fastest.UDP_MAX} or ${Fastest.UDP_BUDGET_MS / 1000} s) — the rest were not candidates")
    val udpCarried = udp.count { m: Fastest.Measured -> (m.real ?: -1L) >= 0L }
    val answered = Fastest.shortlist(measured.values.toList(), Int.MAX_VALUE).size + udpCarried
    if (answered == 0) return FastestResult(null, 0, udp.size)
    // a UDP-only server already carried traffic: the quickest handshakes are
    // still tried, but no further cores are spent looking for a TCP one that does
    val tried = Fastest.walk(measured.values.toList(), maxTries = if (udpCarried > 0) Fastest.SHORTLIST else Fastest.MAX_TRIES) { i, m ->
        val s = byId[m.id]
        if (s == null) -1L else {
            onPhase(tf("fast.checking", "i" to i + 1, "name" to s.name.take(16)))
            realDelayThrough(ctx, s)
        }
    }
    return FastestResult(Fastest.pick(tried + udp), answered, tried.size + udp.size)
}

/** ⚡'s answer: the winner (null = none), how many answered (a handshake, or a UDP-only server's round trip), how many were really tried. */
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
private suspend fun realDelayThrough(ctx: Context, s: ServerConfig, timeout: Int = 5000): Long {
    return AppWork.coreLock.withLock {
        withContext(Dispatchers.IO) {
            val h = XrayTester.start(ctx, s)
            if (h == null) -1L else try { Diagnostics.httpLatency(h.port, timeout = timeout) } finally { XrayTester.stop(h) }
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

    /** One throwaway core at a time (XrayTester's rule), whoever asks: a test, ⚡, a subscription fetch — and the tunnel service's group tests. */
    val coreLock = XrayTester.coreLock

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
     * ⚡'s real round trip through a UDP-only server (-1 = it carried nothing),
     * unless a full test of it is running. No TCP figure beside it: the server
     * has no TCP port a handshake could time (Fastest.udpOnly).
     */
    fun putReal(id: String, ms: Long) {
        val t = tests[id]
        if (t == null || t.phase.isEmpty()) tests[id] = (t ?: TestState()).copy(tcp = null, down = ms, error = null)
    }

    /**
     * A group's real delay (Groups.kt): one round trip through a throwaway
     * core carrying its members and balancer (ConfigBuilder.buildTestConfig),
     * one core at a time like every test here; kept under the group's id. A
     * group has no one address, so there is no handshake to time.
     */
    fun testGroup(ctx: Context, rec: ServerConfig) {
        val id = rec.id
        if (tests[id]?.phase?.isNotEmpty() == true) return
        tests[id] = TestState(phase = "down")
        scope.launch {
            val ms: Long = try { realDelayThrough(ctx, rec) } catch (e: Exception) { -1L }
            tests[id] = TestState(down = ms)
        }
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
     *
     * A UDP-only server (Fastest.udpOnly) has no TCP port a handshake could
     * time: no TCP figure for it (the row shows its real round trip, × only
     * when that failed), as ⚡ measures it.
     */
    private suspend fun testOne(ctx: Context, s: ServerConfig) {
        val udp = Fastest.udpOnly(s)
        try {
            coreLock.withLock {
                tests[s.id] = TestState(phase = if (udp) "down" else "tcp")
                val result = withContext(Dispatchers.IO) {
                    val h = XrayTester.start(ctx, s)
                    if (h == null) TestState(error = t("test.coreError")) else try {
                        val ping: Long? = if (udp) null else Diagnostics.tcpPing(s.address, s.port)
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
     * The user's Disconnect — and Cancel, while a connect is on its way (a
     * Reconnect's too). The service's own path (generation moved on at once,
     * so a connect still being prepared is dropped before its service starts),
     * and connect-on-open steps aside.
     */
    fun disconnect(ctx: Context) {
        AutoConnectOnce.manual = true
        runCatching { XrayVpnService.disconnect(ctx.applicationContext) }
            .onFailure { e -> snack(tf("err.disconnect", "msg" to (e.message ?: e.javaClass.simpleName))) }
    }

    /** Stop ⚡ where it is. A tunnel already up stays up; the selection is whatever it was when stopped. */
    fun cancelFastest() {
        if (fastestJob == null && fastestPhase.value.isEmpty()) return
        fastestJob?.cancel(); fastestJob = null
        fastestRun++
        fastestPhase.value = ""
        fastestNote.value = t("fast.stopped")
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
        subsNote.value = t("subs.fetching") to false
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
                note = tf("subs.keptServers", "name" to sub.name, "error" to applied.sub.lastError, "n" to sub.serverCount)
                VpnState.addLog("Subscription ${sub.url}: ${applied.sub.lastError}; the ${sub.serverCount} servers it had are kept")
            } else {
                store.servers.clear(); store.servers.addAll(list); store.saveServers()
                // Ids are kept across a refresh (SubRefresh.merge), so a selected
                // server is still selected. One the panel dropped falls back to
                // the choice before it, and that is said, not discovered later.
                var moved = ""
                if (store.selection.isEmpty()) m.servers.firstOrNull()?.let { store.saveSelection(it.id) }
                else if (store.repairSelection()) moved = " · " + tf("subs.selMoved", "name" to selectionWord(store))
                val change = if (m.added == 0 && m.dropped == 0) "" else " · " + tf("subs.change", "added" to m.added, "dropped" to m.dropped)
                note = tf("subs.countNote", "name" to sub.name, "n" to m.servers.size) + change + moved
                bad = false
                VpnState.addLog("Subscription ${sub.url}: ${m.kept} kept (same ids), ${m.added} new, ${m.dropped} gone")
                if (moved.isNotEmpty()) VpnState.addLog("Selection: the selected server left ${sub.name}; now ${store.selectionLabel()}")
            }
        }
        store.saveSubs()
        subsNote.value = note to bad
        storeRev.value = storeRev.value + 1
        if (announce) {
            if (bad) snack(note, t("btn.retry")) { refreshSub(ctx, store, subId, announce = true) } else snack(note)
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
        phase(tf("fast.testing", "progress" to "0/${list.size}"))
        fastestNote.value = ""
        // A connect or a disconnect asked for while ⚡ measures (it takes seconds)
        // is the user's newer word: ⚡ then applies nothing at its end.
        val ticket = XrayVpnService.moves
        // this.scope: AppWork's coroutines — `scope` alone is the servers parameter
        fastestJob = this.scope.launch {
            try {
                val out = pickFastest(app, list, phase)
                if (XrayVpnService.moves != ticket) {
                    fastestNote.value = t("fast.overtaken")
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
                    // the same, in the app's language (the log above stays English)
                    val group = scopeName ?: ""
                    val whyUi = when {
                        gone != null -> tf("fast.goneWinner", "name" to (best?.let { b -> list.firstOrNull { it.id == b.id }?.name } ?: t("fast.theWinner")))
                        out.answered == 0 -> if (inScope.isEmpty()) t("fast.noneAnswered") else tf("fast.noneAnsweredIn", "group" to group)
                        else -> if (inScope.isEmpty()) tf("fast.noneCarried", "n" to out.tried) else tf("fast.noneCarriedIn", "n" to out.tried, "group" to group)
                    }
                    fastestNote.value = tf("fast.leftAlone", "why" to whyUi)
                    VpnState.addLog("Auto (fastest): $why; kept ${store.selectionLabel()}")
                    snack(whyUi.replaceFirstChar { it.uppercase() })
                    return@launch
                }
                val real = best.real ?: -1L
                val how = if (real >= 0) "$real ms through it" else "${best.tcp ?: -1L} ms handshake"
                store.saveSelection(best.id)
                storeRev.value = storeRev.value + 1
                val howUi = if (real >= 0) tf("fast.howReal", "ms" to "$real ms") else tf("fast.howTcp", "ms" to "${best.tcp ?: -1L} ms")
                fastestNote.value = if (inScope.isEmpty()) tf("fast.picked", "n" to list.size, "name" to srv.name, "how" to howUi)
                    else tf("fast.pickedIn", "n" to list.size, "group" to (scopeName ?: ""), "name" to srv.name, "how" to howUi)
                VpnState.addLog("Auto (fastest): ${srv.name} — $how, out of ${list.size} servers$inScope")
                snack(if (inScope.isEmpty()) tf("fast.snack", "name" to srv.name, "how" to howUi)
                    else tf("fast.snackIn", "group" to (scopeName ?: ""), "name" to srv.name, "how" to howUi))
                // Already up on something else: the service switches a live tunnel
                // onto the new choice itself (one tunnel, no gap without the VPN),
                // so there is no disconnect first any more.
                if (VpnService.prepare(app) != null) {
                    VpnState.addLog("Auto (fastest): Android has not given VPN permission — tap the ring to connect")
                    snack(t("fast.noPermission"))
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

    /**
     * Up again on the current selection: one connect onto the live tunnel,
     * which the service makes as a switch (XrayVpnService.connect) — the new
     * tunnel replaces the old one in place. It used to be a disconnect, 0.6 s,
     * then a connect: for that pause and the new core's start the phone had no
     * VPN, every app straight out over the ISP. A Cancel meanwhile is the
     * user's Disconnect (disconnect below): its move overtakes this connect
     * wherever it is — in prepare(), queued for the service, or starting.
     */
    fun reconnect(ctx: Context, store: Store) {
        doConnect(ctx.applicationContext, store)
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
        else AppWork.snack(t("consent.denied"))
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
            if (store.poolEnabledValid().isNotEmpty()) add(Store.POOL_ID to "🧩 " + tf("pick.pool", "n" to store.poolEnabledValid().size))
            // one row per routing profile that has rules or a default (spec §1)
            store.profiles.filter { p: RoutingProfile -> store.profileReady(p) }.forEach { p: RoutingProfile -> add(Selection.forProfile(p.id) to "🧭 ${p.name}") }
            store.chains.filter { store.chainReady(it) }.forEach { add("chain:${it.id}" to "⛓ ${it.name}") }
            // a group (Groups.kt) is selected by its bare id, like a server
            store.groups.forEach { g: GroupConfig ->
                val n = Groups.sizeOf(store.groupRecord(g.id))
                if (n > 0) add(g.id to "⧉ ${g.name} · ${configsWord(n)}")
            }
        }
        // an old plain "__advanced__" selection is the first profile's row
        val selKey = store.selectedProfile()?.let { p: RoutingProfile -> Selection.forProfile(p.id) } ?: store.selection
        val groups = ServerGroups.build(store.servers, store.subs, "", emptySet(), store.selection)
        val pick: (String) -> Unit = { id -> store.saveSelection(id); onPick() }
        LazyColumn(Modifier.fillMaxWidth().heightIn(max = 560.dp), contentPadding = PaddingValues(bottom = 24.dp)) {
            item { Text(t("pick.title"), color = TXT, fontWeight = FontWeight.Bold, modifier = Modifier.padding(16.dp)) }
            if (store.servers.size >= 2) item {
                Column {
                    Row(
                        Modifier.fillMaxWidth().heightIn(min = 56.dp).clickable { onAuto() }.padding(horizontal = 16.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("⚡", fontSize = 15.sp)
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Text(t("pick.auto"), color = PRIMARY, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                            Text(
                                t("pick.autoHint"),
                                color = MUTED, fontSize = 10.sp, fontFamily = MONO, maxLines = 2, overflow = TextOverflow.Ellipsis
                            )
                        }
                    }
                    HorizontalDivider(color = STROKE)
                }
            }
            if (modes.isEmpty() && store.servers.isEmpty()) item { Text(t("pick.noServers"), color = MUTED, modifier = Modifier.padding(16.dp)) }
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
                    // a UDP-only server ⚡ measured shows its real round trip (no handshake to time)
                    PickRow(label, flag, s.protocol, s.address, store.selection == s.id, AppWork.tests[s.id]?.let { t: TestState -> t.tcp ?: t.down }) { pick(s.id) }
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
        if (selected) { Spacer(Modifier.width(10.dp)); Icon(Icons.Filled.CheckCircle, t("a11y.selected"), tint = PRIMARY) }
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
        if (g == null || g.all.size < 2) AppWork.snack(t("srv.groupTooSmall"))
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
        IconButton(onClick = { q = "" }) { Icon(Icons.Filled.Close, t("a11y.clearSearch"), tint = MUTED) }
    })

    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        /* ---- header: title, ping all, add ---- */
        Row(
            Modifier.fillMaxWidth().padding(start = 16.dp, end = 6.dp, top = 6.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(t("servers.title"), color = TXT, fontSize = 20.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
            if (store.servers.isNotEmpty()) Box(
                Modifier.heightIn(min = 48.dp).clip(RoundedCornerShape(50))
                    .clickable(onClickLabel = if (testingAll) t("srv.stopTesting") else t("srv.testAll")) {
                        if (testingAll) AppWork.stopTests() else { testKey = ""; AppWork.testAll(ctx, store.servers.toList()) }
                    }
                    .padding(horizontal = 4.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    if (testingAll) t("srv.stopTesting") else t("srv.pingAll"),
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
                    ) { Icon(Icons.Filled.Add, t("srv.addA11y"), tint = ON_PRIMARY, modifier = Modifier.size(22.dp)) }
                }
                DropdownMenu(addMenu, { addMenu = false }, modifier = Modifier.background(CARD)) {
                    listOf(
                        "import" to t("srv.addLink"),
                        "wg" to "WireGuard",
                        "warp" to t("srv.addWarp"),
                        "proxy" to "SOCKS / HTTP",
                        "manual" to t("srv.addManual")
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
            placeholder = { Text(t("srv.search"), fontSize = 13.sp) },
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
                            t("pick.noServers"),
                            t("srv.emptyHint"),
                            t("home.addServerOrSub")
                        ) { sheet = "import" }
                    }
                }
                if (searching && entries.isEmpty()) item(key = "nomatch") { EmptyHint(tf("srv.noMatch", "q" to q.trim())) }
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
                            if (e.group.sub?.lastError?.isNotEmpty() == true) t("srv.groupFailed")
                            else t("srv.groupEmpty"),
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
            title = { Text(t("srv.deleteTitle"), color = TXT, fontSize = 16.sp) },
            text = { Text(victim.name, color = MUTED, fontSize = 13.sp, fontFamily = MONO) },
            confirmButton = {
                TextButton(onClick = {
                    val wasSelected = store.selection == victim.id
                    store.deleteServer(victim.id)   // a selection that named it falls back (Store.repairSelection)
                    confirmDelete = null
                    AppWork.touch()                 // not bump(): the list keeps its place
                    AppWork.snack(
                        if (wasSelected && store.selection.isNotEmpty()) tf("srv.deletedNow", "name" to victim.name, "now" to selectionWord(store))
                        else tf("srv.deleted", "name" to victim.name)
                    )
                }) {
                    Text(t("btn.delete"), color = BAD)
                }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text(t("btn.cancel"), color = MUTED) } }
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
    if (subs.isEmpty()) { AppWork.snack(t("subs.noneToRefresh")); return }
    val started = System.currentTimeMillis()
    subs.forEach { AppWork.refreshSub(ctx, store, it.id) }
    AppWork.subsBusy.first { it.isEmpty() }
    val ids = subs.mapTo(HashSet()) { it.id }
    val failed = store.subs.count { it.id in ids && it.lastError.isNotEmpty() && it.lastTried >= started }
    AppWork.snack(
        when {
            subs.size == 1 -> AppWork.subsNote.value.first
            failed == 0 -> tf("subs.refreshedN", "n" to subs.size)
            else -> tf("subs.failedN", "failed" to failed, "n" to subs.size)
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
        g.key == ServerGroups.MANUAL -> t("srv.byHand")
        else -> t("srv.subDeleted")
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
            .clickable(enabled = foldable, onClickLabel = if (g.open) t("a11y.fold") else t("a11y.unfold")) { onToggle() }
            .padding(start = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            if (g.open) Icons.Filled.KeyboardArrowDown else Icons.Filled.KeyboardArrowRight,
            null, tint = MUTED, modifier = Modifier.size(22.dp).mirrorRtl()
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
                        t("srv.inUse"), color = ON_PRIMARY, fontSize = 8.sp, fontFamily = MONO, fontWeight = FontWeight.SemiBold,
                        letterSpacing = 0.1.em, maxLines = 1,
                        modifier = Modifier.clip(RoundedCornerShape(4.dp)).background(PRIMARY).padding(horizontal = 5.dp, vertical = 2.dp)
                    )
                }
            }
            // two lines: with 📶 and ⚡ beside it a phone leaves the line half its width
            Text(line, color = tint, fontSize = 10.sp, fontFamily = MONO, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
        if (actions && onTest != null) GroupAction("📶", tf("srv.groupTest", "group" to g.title), enabled = !testBusy, running = testingHere, onClick = onTest)
        if (actions && onFastest != null) GroupAction("⚡", tf("srv.groupFastest", "group" to g.title), enabled = !fastestBusy, running = fastestPhase.isNotEmpty(), onClick = onFastest)
        if (onRefresh != null) IconButton(onClick = onRefresh, enabled = !refreshing) {
            if (refreshing) CircularProgressIndicator(color = PRIMARY, strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
            else Icon(Icons.Filled.Refresh, tf("srv.groupRefresh", "group" to g.title), tint = MUTED)
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
        AppWork.snack(t("imp.fetchingSub"))
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
        if (parsed.isEmpty() && errs.isNotEmpty()) AppWork.snack(t("imp.nothingAdded") + " — " + errs.first())
        else AppWork.snack(tf("imp.added", "n" to parsed.size) + if (errs.isNotEmpty()) " · " + tf("imp.notRecognised", "n" to errs.size) else "")
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
        } else if (urls.isEmpty()) AppWork.snack(t("imp.nothingRecognised"))
        bump()
    }
    val qrLauncher = rememberLauncherForActivityResult(ScanContract()) { res ->
        val t = res.contents
        if (!t.isNullOrBlank()) {
            if (RouteShare.looksLikeShare(t)) { routeLink = t.trim(); setSheet(null) }
            else { smartImport(t); setSheet(null); bump() }
        }
    }
    fun launchQr() = qrLauncher.launch(ScanOptions().setOrientationLocked(false).setBeepEnabled(false).setPrompt(t("imp.qrPrompt")))
    fun pasteClip() {
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(ctx)?.toString()
        if (!clip.isNullOrBlank()) importText = clip else Toast.makeText(ctx, t("imp.clipEmpty"), Toast.LENGTH_SHORT).show()
    }
    when (sheet) {
        "import" -> AddLinkSheet(importText, { importText = it }, { pasteClip() }, { launchQr() }, { setSheet(null) }) {
            // An empty Add used to close the sheet as if something had been added.
            if (importText.isBlank()) Toast.makeText(ctx, t("imp.pasteFirst"), Toast.LENGTH_SHORT).show()
            else if (RouteShare.looksLikeShare(importText)) { routeLink = importText.trim(); importText = ""; setSheet(null) }
            else { smartImport(importText); importText = ""; setSheet(null); bump() }
        }
        "wg" -> WgSheet(store, { setSheet(null) }) { setSheet(null); bump() }
        "warp" -> WarpSheet(store, { setSheet(null) }) { setSheet(null); bump() }
        "proxy" -> ProxySheet(store, { setSheet(null) }) { setSheet(null); bump() }
        "manual" -> NewServerSheet(store, { setSheet(null) }) { setSheet(null); bump() }
        else -> {}
    }
    // the import itself moves AppWork.storeRev, which the screens observe: no rebuild needed
    routeLink?.let { t: String -> RouteImportDialog(store, t) { routeLink = null } }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun AddLinkSheet(value: String, onValue: (String) -> Unit, onPaste: () -> Unit, onScan: () -> Unit, onDismiss: () -> Unit, onSubmit: () -> Unit) {
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = CARD) {
        Column(Modifier.fillMaxWidth().imePadding().padding(16.dp).padding(bottom = 16.dp)) {
            Text(t("imp.title"), color = TXT, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(4.dp))
            Text(t("imp.hint"), color = MUTED, fontSize = 11.sp)
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(value, onValue, Modifier.fillMaxWidth(), placeholder = { Text(t("imp.placeholder"), fontSize = 12.sp) }, minLines = 3, maxLines = 8, shape = RoundedCornerShape(14.dp), colors = tfColors())
            Spacer(Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onPaste, modifier = Modifier.weight(1f)) { Icon(Icons.Filled.ContentPaste, null, Modifier.size(18.dp)); Spacer(Modifier.width(6.dp)); Text(t("btn.paste")) }
                OutlinedButton(onClick = onScan, modifier = Modifier.weight(1f)) { Icon(Icons.Filled.QrCodeScanner, null, Modifier.size(18.dp)); Spacer(Modifier.width(6.dp)); Text(t("btn.scanQr")) }
            }
            Spacer(Modifier.height(10.dp)); Button(onClick = onSubmit, modifier = Modifier.fillMaxWidth()) { Text(t("btn.add")) }
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
    val where = "${badge(s.protocol)}${protoTags(s)} · ${s.address}" + if (s.port > 0) ":${s.port}" else ""

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
                            t("srv.inUse"), color = ON_PRIMARY, fontSize = 8.sp, fontFamily = MONO,
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
                // a UDP-only server ⚡ measured: its real round trip (no handshake to time)
                r?.down != null -> Text(fmtLat(r.down) + (if (r.down in 0L..999L) " ms" else ""), color = latColor(r.down), fontSize = 12.sp, fontFamily = MONO, maxLines = 1)
                else -> Text("—", color = SUBTLE, fontSize = 12.sp, fontFamily = MONO)
            }
            // The one affordance that says there is more in here, and opens it
            // without changing which config is in use. A full 48 dp target.
            IconButton(onClick = onToggle, modifier = Modifier.size(48.dp)) {
                Icon(
                    if (open) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                    if (open) t("a11y.close") else t("a11y.actions"),
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
            Tile(Modifier.weight(1f), t("tile.tcp"), result?.tcp, result?.phase == "tcp", latColor(result?.tcp))
            Tile(Modifier.weight(1f), t("tile.real"), result?.down, result?.phase == "down", latColor(result?.down))
            Tile(Modifier.weight(1f), t("tile.up"), result?.up, result?.phase == "up", latColor(result?.up))
        }
        result?.error?.let {
            Text(it, color = BAD, fontSize = 10.sp, fontFamily = MONO, modifier = Modifier.padding(start = 14.dp, end = 14.dp, bottom = 10.dp))
        }

        /* ---- and what you can do with it ---- */
        HorizontalDivider(color = if (selected) STROKE_SEL else STROKE)
        Row(Modifier.fillMaxWidth().height(IntrinsicSize.Min)) {
            val rule = if (selected) STROKE_SEL else STROKE
            CardAction(t("card.test"), PRIMARY, Modifier.weight(1f), onTest)
            ActionRule(rule)
            CardAction(t("card.copy"), TXT2, Modifier.weight(1f), onCopy)
            ActionRule(rule)
            CardAction(t("card.qr"), TXT2, Modifier.weight(1f), onQr)
            ActionRule(rule)
            CardAction(t("card.edit"), TXT2, Modifier.weight(1f), onEdit)
            ActionRule(rule)
            CardAction(t("card.del"), BAD, Modifier.weight(1f), onDelete)
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
    // a MASQUE server has no link: it is shared as its one line of Xray JSON (Masque.shareJson)
    val isJson = (s.isJson && cfg != null) || s.protocol == Masque.PROTOCOL
    val link = remember(s.id) { if (s.isJson && cfg != null) JsonText.minify(cfg) else LinkParser.buildShareLink(s) }
    val tooLarge = isJson && link.toByteArray(Charsets.UTF_8).size > QR_MAX_JSON_BYTES
    val bmp = remember(link) { if (tooLarge) null else qrBitmap(link) }
    Dialog(onDismissRequest = onDismiss) {
        Surface(shape = RoundedCornerShape(16.dp), color = CARD) {
            Column(Modifier.padding(18.dp).widthIn(max = 320.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Text(t("qr.title"), color = TXT, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(12.dp))
                // FilterQuality.None: the bitmap is one pixel per module, so nearest
                // neighbour turns each into a crisp square. The default (bilinear) blurs
                // the module edges a scanner has to threshold.
                if (bmp != null) Image(
                    bmp.asImageBitmap(), "QR",
                    Modifier.size(248.dp).clip(RoundedCornerShape(10.dp)).background(Color.White).padding(6.dp),
                    filterQuality = FilterQuality.None
                )
                else Text(if (isJson) t("qr.tooLarge") else t("qr.tooLong"), color = MUTED, fontSize = 12.sp)
                Spacer(Modifier.height(10.dp))
                Text(link, color = MUTED, fontSize = 10.sp, maxLines = 3, overflow = TextOverflow.Ellipsis)
                Spacer(Modifier.height(12.dp))
                Button(onClick = { copyLink(ctx, s); onDismiss() }, modifier = Modifier.fillMaxWidth()) { Text(if (isJson) t("btn.copyJson") else t("btn.copyLink")) }
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
    android.widget.Toast.makeText(ctx, t("toast.copied"), android.widget.Toast.LENGTH_SHORT).show()
}


/** One colour per protocol, used by the badge and anywhere a config is listed. */
private fun protoColor(proto: String): Color = when (proto) {
    "vless" -> PRIMARY
    "vmess" -> Color(0xFF84E1BC)
    "trojan" -> AMBER
    "shadowsocks" -> Color(0xFFCDA9FF)
    "wireguard" -> Color(0xFF8FB3AA)
    "hysteria2" -> Color(0xFF7FB4FF)
    "masque" -> Color(0xFFF6A35C)
    "socks", "http" -> Color(0xFFF19DC8)
    else -> MUTED
}

/**
 * The card's tags beside the badge: WARP for a server the + WARP sheet made
 * (either kind, `warp` on its record) or a MASQUE WARP account, WARP+ when its
 * account has it; a MASQUE server's HTTP version — derived, never stored.
 */
private fun protoTags(s: ServerConfig): String {
    val acct = s.warp
    val warp = when {
        acct != null && acct.warpPlus -> " · WARP+"
        acct != null || Masque.isWarp(s) -> " · WARP"
        else -> ""
    }
    if (s.protocol != Masque.PROTOCOL) return warp
    val http = Masque.httpOf(s.outbound.optJSONObject("streamSettings")?.optJSONObject("tlsSettings")).uppercase()
    return "$warp · $http"
}

/**
 * WARP: a WARP device registered with Cloudflare from the phone — straight
 * out, or through the running tunnel's own SOCKS port — one account or
 * several from a list of WARP+ keys, or an existing account imported; on
 * WireGuard (the default: the exit of a chain over a config of the user's, or
 * dialled from here) or on MASQUE (one server per HTTP version).
 * Warp.addWarpOnce, the desktop's «+ WARP» window (warp-wg/design.md §8).
 * The work runs in AppWork's scope, so a sheet closed mid-way still saves
 * what Cloudflare already made.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun WarpSheet(store: Store, onDismiss: () -> Unit, done: () -> Unit) {
    val ctx = LocalContext.current
    var kind by remember { mutableStateOf(Warp.KIND_WIREGUARD) }
    var mode by remember { mutableStateOf("new") }
    var via by remember { mutableStateOf("direct") }
    var count by remember { mutableStateOf("1") }
    var keysText by remember { mutableStateOf("") }
    var importText by remember { mutableStateOf("") }
    // WireGuard: chained over a config of mine (the default), or dialled from here
    val hops = remember { warpHopOptions(store) }
    var use by remember { mutableStateOf("chain") }
    var chainWith by remember { mutableStateOf(defaultWarpHop(store, hops)) }
    var wgEndpoint by remember { mutableStateOf("auto") }
    var wgAddress by remember { mutableStateOf("") }
    var wgAntiDpi by remember { mutableStateOf(true) }
    // MASQUE
    var http by remember { mutableStateOf("both") }
    var endpoint by remember { mutableStateOf("auto") }
    var address by remember { mutableStateOf("") }
    var cover by remember { mutableStateOf("") }
    var antiDpi by remember { mutableStateOf(true) }
    var running by remember { mutableStateOf(false) }
    val progress = remember { mutableStateListOf<String>() }
    var error by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<Warp.AddResult?>(null) }
    val connState by VpnState.state.collectAsState()
    val connected = connState == ConnState.CONNECTED
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState, containerColor = CARD) {
        Column(Modifier.fillMaxWidth().fillMaxHeight(0.92f).verticalScroll(rememberScrollState()).imePadding().padding(16.dp).padding(bottom = 24.dp)) {
            Text(t("warp.title"), color = TXT, fontWeight = FontWeight.Bold)
            val res = result
            if (res != null && res.ok) {
                WarpDone(res, kind, done)
            } else {
                Text(
                    if (kind == Warp.KIND_WIREGUARD) t("warp.ledeWg")
                    else t("warp.ledeMasque"),
                    color = MUTED, fontSize = 11.sp
                )
                Row(Modifier.horizontalScroll(rememberScrollState()).padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(kind == Warp.KIND_WIREGUARD, { kind = Warp.KIND_WIREGUARD; error = "" }, { Text(t("warp.kindWg")) })
                    FilterChip(kind == Warp.KIND_MASQUE, { kind = Warp.KIND_MASQUE; error = "" }, { Text("MASQUE") })
                }

                Text(t("warp.step1"), color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 12.dp, bottom = 2.dp))
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(mode == "new", { mode = "new" }, { Text(t("warp.wayNew")) })
                    FilterChip(mode == "import", { mode = "import" }, { Text(t("warp.wayImport")) })
                }
                if (mode == "new") {
                    Text(t("warp.signUp"), color = MUTED, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
                    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(via == "direct", { via = "direct" }, { Text(t("warp.direct")) })
                        FilterChip(via == "proxy", { via = "proxy" }, { Text(t("warp.routeProxy")) })
                    }
                    Text(
                        if (via == "proxy") t("warp.routeProxyHint")
                        else t("warp.routeDirectHint"),
                        color = MUTED, fontSize = 11.sp
                    )
                    if (via == "proxy" && !connected) Text(t("warp.connectFirst"), color = AMBER, fontSize = 11.sp)
                    OutlinedTextField(
                        count, { v: String -> count = v.filter { c: Char -> c.isDigit() }.take(2); error = "" },
                        Modifier.fillMaxWidth().padding(vertical = 3.dp), label = { Text(tf("warp.accounts", "max" to Warp.MAX_ACCOUNTS)) }, singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), colors = tfColors()
                    )
                    OutlinedTextField(
                        keysText, { v: String -> keysText = v; error = "" }, Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        label = { Text(t("warp.keys")) },
                        placeholder = { Text("xxxxxxxx-xxxxxxxx-xxxxxxxx", fontSize = 12.sp) },
                        textStyle = TextStyle(fontFamily = MONO, fontSize = 12.sp, color = TXT),
                        minLines = 2, maxLines = 10, shape = RoundedCornerShape(10.dp), colors = tfColors()
                    )
                    // read back as it is typed: how many accounts, how many with WARP+ — a bad key named by its number, never shown
                    val readBack = warpReadBack(keysText, count.toIntOrNull() ?: 1)
                    Text(readBack.second, color = if (readBack.first) TXT2 else AMBER, fontSize = 12.sp)
                    Text(t("warp.keysHint"),
                        color = MUTED, fontSize = 11.sp)
                    Text(t("warp.tos"), color = MUTED, fontSize = 11.sp)
                } else {
                    OutlinedTextField(
                        importText, { v: String -> importText = v; error = "" }, Modifier.fillMaxWidth().padding(vertical = 4.dp),
                        placeholder = {
                            Text(if (kind == Warp.KIND_WIREGUARD) t("warp.importWg")
                                 else t("warp.importMasque"), fontSize = 12.sp)
                        },
                        textStyle = TextStyle(fontFamily = MONO, fontSize = 11.sp, color = TXT),
                        minLines = 4, maxLines = 10, shape = RoundedCornerShape(10.dp), colors = tfColors()
                    )
                    OutlinedButton(onClick = {
                        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        val clip = cm.primaryClip?.takeIf { c: android.content.ClipData -> c.itemCount > 0 }?.getItemAt(0)?.coerceToText(ctx)?.toString()
                        if (!clip.isNullOrBlank()) importText = clip else Toast.makeText(ctx, t("imp.clipEmpty"), Toast.LENGTH_SHORT).show()
                    }, modifier = Modifier.fillMaxWidth()) { Icon(Icons.Filled.ContentPaste, null, Modifier.size(18.dp)); Spacer(Modifier.width(6.dp)); Text(t("btn.paste")) }
                }

                Text(t("warp.step2"), color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 12.dp, bottom = 2.dp))
                if (kind == Warp.KIND_WIREGUARD) {
                    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(use == "chain", { use = "chain"; error = "" }, { Text(t("warp.useChain")) })
                        FilterChip(use == "direct", { use = "direct"; error = "" }, { Text(t("warp.direct")) })
                    }
                    if (use == "chain") {
                        if (hops.isEmpty()) {
                            Text(t("warp.noHop"), color = AMBER, fontSize = 11.sp)
                        } else {
                            DropPick(t("warp.pickHop"), hops, chainWith) { v: String -> chainWith = v; error = "" }
                        }
                        Text(t("warp.chainHint"),
                            color = MUTED, fontSize = 11.sp)
                    } else {
                        Text(t("warp.endpoint"), color = MUTED, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
                        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            FilterChip(wgEndpoint == "auto", { wgEndpoint = "auto" }, { Text(t("warp.epAuto")) })
                            FilterChip(wgEndpoint == "v6", { wgEndpoint = "v6" }, { Text("IPv6") })
                            FilterChip(wgEndpoint == "custom", { wgEndpoint = "custom" }, { Text(t("warp.epCustom")) })
                        }
                        if (wgEndpoint == "custom") Fld(tf("warp.wgIp", "port" to Warp.WG_PORT), wgAddress) { wgAddress = it }
                        SwitchRow(t("warp.antiDpiWg"), wgAntiDpi) { wgAntiDpi = it }
                    }
                } else {
                    Text(t("warp.http"), color = MUTED, fontSize = 11.sp)
                    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(http == "both", { http = "both" }, { Text(t("warp.httpBoth")) })
                        FilterChip(http == "h3", { http = "h3" }, { Text("HTTP/3") })
                        FilterChip(http == "h2", { http = "h2" }, { Text("HTTP/2") })
                    }
                    Text(t("warp.httpBothHint"), color = MUTED, fontSize = 11.sp)
                    Text(t("warp.endpoint"), color = MUTED, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
                    Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FilterChip(endpoint == "auto", { endpoint = "auto" }, { Text(t("warp.epAuto")) })
                        FilterChip(endpoint == "v6", { endpoint = "v6" }, { Text("IPv6") })
                        FilterChip(endpoint == "custom", { endpoint = "custom" }, { Text(t("warp.epCustom")) })
                    }
                    if (endpoint == "custom") Fld(t("warp.address"), address) { address = it }
                    Fld(t("warp.cover"), cover) { cover = it }
                    Text(t("warp.coverHint"), color = MUTED, fontSize = 11.sp)
                    SwitchRow(t("warp.antiDpi"), antiDpi) { antiDpi = it }
                }

                if (progress.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    for (line in progress) Text(line, color = MUTED, fontSize = 10.sp, fontFamily = MONO)
                }
                if (error.isNotEmpty()) Text(error, color = BAD, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp))
                Spacer(Modifier.height(10.dp))
                Button(enabled = !running, onClick = {
                    running = true; error = ""; progress.clear()
                    val keys = keysText.split(Regex("\\r?\\n")).map { l: String -> l.trim() }.filter { l: String -> l.isNotEmpty() }
                    val args = Warp.AddArgs(
                        kind = kind, mode = mode, via = via, importText = importText,
                        count = (count.toIntOrNull() ?: 1).coerceIn(1, Warp.MAX_ACCOUNTS), licenses = keys,
                        options = Warp.Options(http = http, endpoint = endpoint, address = address, cover = cover, antiDpi = antiDpi),
                        wg = Warp.WgOptions(use = use, chainWith = chainWith, endpoint = wgEndpoint, address = wgAddress, antiDpi = wgAntiDpi))
                    // the tunnel's own SOCKS port, the one it really runs on (SubFetch's choice)
                    val port = LocalProxyAuth.activePort ?: store.settings.socksPort
                    // what there is now (names, hops), read here on the main thread
                    val serversNow = store.servers.toList()
                    val chainsNow = store.chains.toList()
                    AppWork.scope.launch {
                        val r = withContext(Dispatchers.IO) {
                            Warp.addWarpOnce(args, Warp.Deps(
                                connected = { VpnState.state.value == ConnState.CONNECTED },
                                socksPort = { port },
                                getServers = { serversNow },
                                getChains = { chainsNow },
                                log = { line: String, _: String ->
                                    VpnState.addLog(line)
                                    AppWork.scope.launch { progress.add(line) }
                                }))
                        }
                        if (r.ok) {
                            store.servers.addAll(r.added); store.saveServers()
                            if (r.addedChains.isNotEmpty()) { store.chains.addAll(r.addedChains); store.saveChains() }
                            // nothing chosen yet: the first chain made (WARP through my config), else the first server
                            val pick: String? = r.addedChains.firstOrNull()?.let { c: ChainConfig -> "chain:" + c.id } ?: r.added.firstOrNull()?.id
                            if (store.selection.isEmpty() && pick != null) store.saveSelection(pick)
                            AppWork.touch()
                            val st = r.stopped
                            val note = if (st != null) " — " + tf("warp.stoppedAfter", "made" to st.made, "wanted" to st.wanted) else ""
                            AppWork.snack(tf("warp.addedSnack", "names" to r.added.joinToString(t("sep.list")) { s: ServerConfig -> s.name }) + note)
                        } else {
                            error = warpMessage(r.code, r.detail)
                        }
                        result = r
                        running = false
                    }
                }, modifier = Modifier.fillMaxWidth()) {
                    if (running) CircularProgressIndicator(color = ON_PRIMARY, strokeWidth = 2.dp, modifier = Modifier.size(16.dp))
                    else Text(if (mode == "import") t("warp.import") else t("warp.create"))
                }
            }
        }
    }
}

/** What a chained WireGuard WARP can ride: every server but an HTTP proxy (no UDP), and every chain whose servers are all there and whose last is not one. */
private fun warpHopOptions(store: Store): List<Pair<String, String>> {
    val out = ArrayList<Pair<String, String>>()
    for (s in store.servers) {
        if (s.protocol != "http") out.add(s.id to s.name)
    }
    for (c in store.chains) {
        val members = store.chainMembers(c)
        val whole = members.isNotEmpty() && members.size == c.members.size && members.last().protocol != "http"
        if (whole) out.add("chain:${c.id}" to "⛓ ${c.name}")
    }
    return out
}

/** The hop the sheet starts on: the selected server (or chain) when WARP can ride it, else the first one there is. */
private fun defaultWarpHop(store: Store, hops: List<Pair<String, String>>): String {
    val sel = store.selection
    return if (hops.any { p: Pair<String, String> -> p.first == sel }) sel else (hops.firstOrNull()?.first ?: "")
}

/**
 * Warp.messageFor in the app's language: the same codes as the desktop's
 * warp.err.* (Warp.kt keeps the English its tests and the log read). A bad key
 * of several is named by its number; "At most N keys" is Warp.kt's own line.
 */
private fun warpMessage(code: String, detail: String): String {
    if (code == "badLicense") {
        val m = Regex("^Key (\\d+) ").find(detail)
        if (m != null) return tf("warp.keyN", "n" to m.groupValues[1]) + " " + t("warp.err.badLicense")
        if (detail.startsWith("At most")) return detail
    }
    val key = "warp.err.$code"
    return if (I18n.has(key)) tf(key, "msg" to detail) else tf("warp.err.failed", "msg" to detail)
}

/** Warp.warningText in the app's language; a code the dictionary does not know keeps Warp.kt's words. */
private fun warpWarning(w: Warp.Warning): String {
    val key = "warp.warn." + w.code
    return if (I18n.has(key)) tf(key, "msg" to w.message) else Warp.warningText(w)
}

/**
 * Warp.licenseReadBack in the app's language: (ok, the line). A bad key keeps
 * Warp.kt's words (it names the key by its number); a good list is counted the
 * same way (one key on every account, several one each, the rest free).
 */
private fun warpReadBack(keysText: String, count: Int): Pair<Boolean, String> {
    val rb = Warp.licenseReadBack(keysText, count)
    if (!rb.ok) return Pair(false, rb.text)
    val keys = keysText.split(Regex("\\r?\\n")).count { l: String -> l.isNotBlank() }
    val n = minOf(Warp.MAX_ACCOUNTS, maxOf(1, count, keys))
    val plus = if (keys == 1) n else minOf(keys, n)
    val free = n - plus
    val parts = ArrayList<String>()
    if (plus > 0) parts.add(tf("warp.rbPlus", "n" to plus))
    if (free > 0) parts.add(tf("warp.rbFree", "n" to free))
    return Pair(true, tf("warp.rb", "n" to n, "parts" to parts.joinToString(t("sep.list"))))
}

/** Warp.accountLines in the app's language; premium_data / quota / usage stay Cloudflare's own names. */
private fun warpAccountLines(info: Warp.AccountInfo): List<String> {
    if (info.imported) return listOf(t("warp.acctImported"))
    val out = ArrayList<String>()
    val type = if (info.type in listOf("free", "limited", "unlimited", "team")) info.type else "unknown"
    out.add(tf("warp.acctType", "type" to t("warp.type.$type")))
    val tail = if (info.licenseTail.isNotEmpty()) " …${info.licenseTail}" else ""
    when (info.license) {
        "applied" -> {
            out.add(tf("warp.keyApplied", "tail" to tail))
            if (info.type == "free") out.add(t("warp.keyStillFree"))
        }
        "refused" -> out.add(tf("warp.keyRefused", "tail" to tail) + (if (info.licenseError.isNotEmpty()) " — ${info.licenseError}" else ""))
        else -> out.add(t("warp.noKey"))
    }
    out.add(listOf("premium_data" to info.premiumData, "quota" to info.quota, "usage" to info.usage)
        .joinToString(" · ") { p: Pair<String, Long?> -> p.first + " " + (p.second?.let { v: Long -> Warp.humanBytes(v) } ?: "—") })
    val d = info.devices
    if (d != null) out.add(tf("warp.devices", "n" to d))
    return out
}

/** The WARP sheet's answer: a batch stopped part-way, one box per account, and what to do next. */
@Composable private fun WarpDone(res: Warp.AddResult, kind: String, done: () -> Unit) {
    Text(t("warp.added"), color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 13.sp, modifier = Modifier.padding(top = 12.dp, bottom = 4.dp))
    val st = res.stopped
    if (st != null) {
        Text(tf("warp.madeOf", "made" to st.made, "wanted" to st.wanted) + " — " + warpMessage(st.code, st.detail), color = AMBER, fontSize = 12.sp, modifier = Modifier.padding(bottom = 4.dp))
    }
    val byId = res.added.associateBy { s: ServerConfig -> s.id }
    for (acct in res.accounts) {
        WarpAccountBox(acct.name, acct.info, acct.serverIds.mapNotNull { id: String -> byId[id] }, acct.chainName, acct.warnings)
    }
    val hint = when {
        res.addedChains.isNotEmpty() -> t("warp.doneChain")
        kind == Warp.KIND_WIREGUARD -> t("warp.doneOne")
        else -> t("warp.doneMasque")
    }
    Text(hint, color = MUTED, fontSize = 11.sp, modifier = Modifier.padding(top = 8.dp))
    Spacer(Modifier.height(10.dp))
    Button(onClick = done, modifier = Modifier.fillMaxWidth()) { Text(t("warp.see")) }
}

/**
 * One WARP account as Cloudflare told it (Warp.accountLines — the desktop's
 * account box): its name, its servers, its type, how the WARP+ key went,
 * premium_data / quota / usage under Cloudflare's own names, the devices on
 * it, its chain and its warnings. In the sheet's answer and in the editor.
 */
@Composable private fun WarpAccountBox(name: String, info: Warp.AccountInfo, servers: List<ServerConfig>, chainName: String?, warnings: List<Warp.Warning>) {
    Column(Modifier.fillMaxWidth().padding(top = 8.dp).border(1.dp, STROKE, RoundedCornerShape(10.dp)).padding(10.dp)) {
        if (name.isNotEmpty()) Text(name, color = TXT, fontWeight = FontWeight.Bold, fontSize = 13.sp)
        for (s in servers) Text("• ${s.name} — ${s.address}:${s.port}", color = TXT2, fontSize = 12.sp, fontFamily = MONO)
        for (line in warpAccountLines(info)) Text(line, color = MUTED, fontSize = 11.sp)
        if (!info.imported && info.checkedAt.isNotEmpty()) {
            Text(tf("warp.asOf", "when" to info.checkedAt.replace('T', ' ').take(16) + " UTC"), color = MUTED, fontSize = 10.sp)
        }
        if (chainName != null) Text("⛓ $chainName", color = PRIMARY, fontSize = 12.sp, modifier = Modifier.padding(top = 2.dp))
        for (w in warnings) Text("⚠ " + warpWarning(w), color = AMBER, fontSize = 11.sp, modifier = Modifier.padding(top = 2.dp))
    }
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
            Text(t("wg.title"), color = TXT, fontWeight = FontWeight.Bold)
            Fld(t("f.name"), name) { name = it }; Fld(t("f.endpoint"), ep) { ep = it }; Fld(t("f.privKey"), priv) { priv = it }; Fld(t("f.peerPub"), pub) { pub = it }
            Fld(t("f.wgAddr"), addr) { addr = it }; Fld(t("f.allowed"), allowed) { allowed = it }; Fld(t("f.pskOpt"), psk) { psk = it }; Fld("MTU", mtu) { mtu = it }; Fld(t("f.reservedOpt"), reserved) { reserved = it }
            Fld(t("wg.dnsLine"), dnsLine) { dnsLine = it }
            Text(t("wg.dnsHint"), color = MUTED, fontSize = 11.sp)
            Spacer(Modifier.height(10.dp))
            Button(onClick = {
                if (ep.isNotBlank() && priv.isNotBlank() && pub.isNotBlank()) { val s = LinkParser.makeWireguardServer(name, ep, priv, pub, addr, allowed, psk, mtu, reserved, dnsLine); store.servers.add(s); store.saveServers(); if (store.selection.isEmpty()) store.saveSelection(s.id); done() }
                else Toast.makeText(ctx, t("wg.missing"), Toast.LENGTH_SHORT).show()
            }, modifier = Modifier.fillMaxWidth()) { Text(t("btn.add")) }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun ProxySheet(store: Store, onDismiss: () -> Unit, done: () -> Unit) {
    val ctx = LocalContext.current
    var type by remember { mutableStateOf("socks") }; var name by remember { mutableStateOf("") }; var host by remember { mutableStateOf("") }; var port by remember { mutableStateOf("") }; var user by remember { mutableStateOf("") }; var pass by remember { mutableStateOf("") }
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = CARD) {
        Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).imePadding().padding(16.dp).padding(bottom = 16.dp)) {
            Text(t("proxy.title"), color = TXT, fontWeight = FontWeight.Bold)
            Row(Modifier.padding(vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) { FilterChip(type == "socks", { type = "socks" }, { Text("SOCKS5") }); FilterChip(type == "http", { type = "http" }, { Text("HTTP") }) }
            Fld(t("f.name"), name) { name = it }; Fld(t("f.host"), host) { host = it }; Fld(t("f.port"), port) { port = it }; Fld(t("f.userOpt"), user) { user = it }; Fld(t("f.passOpt"), pass) { pass = it }
            Spacer(Modifier.height(10.dp))
            Button(onClick = {
                if (host.isNotBlank() && port.isNotBlank()) { val s = LinkParser.makeProxyServer(type, name, host, port.toIntOrNull() ?: 1080, user, pass); store.servers.add(s); store.saveServers(); if (store.selection.isEmpty()) store.saveSelection(s.id); done() }
                else Toast.makeText(ctx, t("proxy.missing"), Toast.LENGTH_SHORT).show()
            }, modifier = Modifier.fillMaxWidth()) { Text(t("btn.add")) }
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
            Text(tf("json.title", "proto" to badge(server.protocol)), color = TXT, fontWeight = FontWeight.Bold)
            Fld(t("f.name"), name) { name = it }
            // The mode is a note here, not a switch: it is kept as stored, so a backup round-trips.
            Text(if (mode == JsonImport.MODE_RAW) t("json.modeRaw") else t("json.modeFull"), color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 2.dp))
            Text(t("json.rawNote"), color = MUTED, fontSize = 11.sp)
            Text(t("json.config"), color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 4.dp))
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
                Icon(Icons.Filled.ContentCopy, null, Modifier.size(16.dp)); Spacer(Modifier.width(6.dp)); Text(t("btn.copyJson"))
            }
            // the full form is what runs here, raw or not: what it leaves out is always worth saying
            if (info != null) {
                Text(t("json.notUsed"), color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 2.dp))
                Text(tf("json.rules", "n" to info.rules.size), color = TXT2, fontSize = 11.sp)
                // the record's neutral tokens (`*`, `balancer:<tag>`, "") in words
                info.rules.forEach { r: JsonRule ->
                    LtrBlock { Text("   ${JsonImport.matchInWords(r.match)} → ${JsonImport.targetInWords(r.to)}", color = MUTED, fontSize = 11.sp, fontFamily = MONO) }
                }
                if (info.dns) Text(t("json.dns"), color = TXT2, fontSize = 11.sp)
                if (info.balancers > 0) Text(tf("json.balancers", "n" to info.balancers), color = TXT2, fontSize = 11.sp)
                if (info.observatory) Text(t("json.observatory"), color = TXT2, fontSize = 11.sp)
            }
            if (error.isNotEmpty()) Text(error, color = BAD, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp))
            Spacer(Modifier.height(10.dp))
            Button(onClick = {
                // a config that no longer parses, or has no proxy outbound, is refused with the reason
                try {
                    onSave(JsonImport.applyEdits(server, name, mode, text))
                } catch (e: Exception) {
                    error = tf("json.notSaved", "why" to (e.message ?: t("json.invalid")))
                }
            }, modifier = Modifier.fillMaxWidth()) { Text(t("btn.save")) }
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
    var masqueHttp by remember { mutableStateOf(f.masqueHttp) }
    val isStd = server.protocol == "vless" || server.protocol == "vmess" || server.protocol == "trojan"
    val isHy2 = server.protocol == "hysteria2"
    val isMasque = server.protocol == Masque.PROTOCOL
    // the full editor (ServerFields): the table's fields this sheet has no input of
    // its own for (flow, Encryption, …), and the Pro view over one draft
    val ctx = LocalContext.current
    val pro = remember(server.id) { mutableStateMapOf<String, String>().apply { putAll(f.pro) } }
    val encOn = remember(server.id) { mutableStateOf((f.pro["encryption"] ?: "none").let { e: String -> e.isNotBlank() && e != "none" }) }
    var proView by remember { mutableStateOf(EditView.pro) }
    val draft = remember(server.id) { mutableStateMapOf<String, String>() }
    val tab = remember(server.id) { mutableStateOf("protocol") }
    /** The Simple view's inputs, as a save sends them. */
    fun simpleFields(): ServerEditor.Fields = ServerEditor.Fields(
        name = name, address = address, port = port, cred = cred, network = network, security = security,
        sni = sni, host = host, path = path, fp = fp, pbk = pbk, sid = sid, allowInsecure = allowInsecure, alpn = f.alpn,
        method = method, proxyUser = pUser, proxyPass = pPass,
        wgPub = wgPub, wgAddr = wgAddr, wgPsk = wgPsk, wgMtu = wgMtu, wgReserved = wgReserved, wgAllowed = wgAllowed, wgDns = wgDns,
        fragment = fragment, noise = effectiveNoise, cipherSuites = cipherSuites, finalMask = finalMask,
        ech = ech, pcs = pcs, vcn = vcn, pqv = pqv, hy2Obfs = hy2Obfs, hy2Ports = hy2Ports,
        engine = engine, spx = f.spx, xmode = f.xmode, seed = f.seed, headerType = f.headerType, xhttpExtra = f.xhttpExtra,
        tcpHeader = f.tcpHeader, hy2Hop = f.hy2Hop, hy2Up = f.hy2Up, hy2Down = f.hy2Down, plugin = f.plugin,
        masqueHttp = masqueHttp, pro = HashMap(pro))
    /** The Pro view's draft, back into the Simple view's inputs. */
    fun loadSimple(nf: ServerEditor.Fields) {
        name = nf.name; address = nf.address; port = nf.port; cred = nf.cred; network = nf.network; security = nf.security
        sni = nf.sni; host = nf.host; path = nf.path; fp = nf.fp; pbk = nf.pbk; sid = nf.sid; allowInsecure = nf.allowInsecure; method = nf.method
        pUser = nf.proxyUser; pPass = nf.proxyPass; wgPub = nf.wgPub; wgAddr = nf.wgAddr; wgPsk = nf.wgPsk; wgMtu = nf.wgMtu
        wgReserved = nf.wgReserved; wgAllowed = nf.wgAllowed; wgDns = nf.wgDns; fragment = nf.fragment
        cipherSuites = nf.cipherSuites; finalMask = nf.finalMask; ech = nf.ech; pcs = nf.pcs; vcn = nf.vcn; pqv = nf.pqv
        hy2Obfs = nf.hy2Obfs; hy2Ports = nf.hy2Ports; engine = nf.engine; masqueHttp = nf.masqueHttp
        noisePreset = when { nf.noise.isBlank() -> "off"; nf.noise.lowercase() in noisePresetKeys -> if (nf.noise.lowercase() == "fakehello") "faketls" else nf.noise.lowercase(); else -> "custom" }
        noiseCustom = if (noisePreset == "custom") nf.noise else ""
        pro.clear(); pro.putAll(nf.pro)
        f.spx = nf.spx; f.xmode = nf.xmode; f.seed = nf.seed; f.headerType = nf.headerType
        f.tcpHeader = nf.tcpHeader; f.hy2Hop = nf.hy2Hop; f.hy2Up = nf.hy2Up; f.hy2Down = nf.hy2Down; f.plugin = nf.plugin
    }

    // Open FULLY expanded: a partially-expanded sheet swallows the drag as a sheet
    // gesture instead of scrolling the content, which made everything below the
    // fold (fingerprint, patterniha…) unreachable — it looked like those fields
    // didn't exist. Fill the height so the inner scroll owns the gesture.
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState, containerColor = CARD) {
        Column(Modifier.fillMaxWidth().fillMaxHeight(0.92f).verticalScroll(rememberScrollState()).imePadding().padding(16.dp).padding(bottom = 24.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(tf("ed.title", "proto" to badge(server.protocol)), color = TXT, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                ViewSwitch(proView) { toPro: Boolean ->
                    if (toPro && !proView) { draft.clear(); draft.putAll(ServerEditor.toDraft(server.protocol, simpleFields())) }
                    if (!toPro && proView) loadSimple(ServerEditor.fromDraft(server.protocol, draft, simpleFields()))
                    proView = toPro
                    EditView.pro = toPro
                }
            }
            // a WARP server's account as Cloudflare told it when it was made — read-only
            val warpInfo = server.warp
            if (warpInfo != null) WarpAccountBox(t("warp.acctTitle"), warpInfo, emptyList(), null, emptyList())
            if (proView) ProFields(server.protocol, draft, false, {}, tab, encOn) else {
            Fld(t("f.name"), name) { name = it }; Fld(t("ed.address"), address) { address = it }; Fld(t("f.port"), port) { port = it }
            when (server.protocol) {
                "vless", "vmess" -> Fld(t("ed.uuid"), cred) { cred = it }
                "trojan" -> Fld(t("f.password"), cred) { cred = it }
                "shadowsocks" -> {
                    Fld(t("f.password"), cred) { cred = it }
                    val methods = ServerFields.SS_METHODS.map { m: String -> m to tf("ed.methodOpt", "m" to m) } + (if (method.isNotBlank() && method !in ServerFields.SS_METHODS) listOf(method to tf("ed.methodOpt", "m" to method)) else emptyList())
                    DropPick(t("ed.method"), methods, method) { m: String -> method = m }
                }
                "socks", "http" -> { Fld(t("f.userOpt"), pUser) { pUser = it }; Fld(t("f.passOpt"), pPass) { pPass = it } }
                "wireguard" -> Fld(t("f.privKey"), cred) { cred = it }
                "hysteria2" -> Fld(t("ed.passAuth"), cred) { cred = it }
            }
            // what the sheet lacked (the full editor's table): VLESS flow and Encryption, the VMess cipher
            when (server.protocol) {
                "vless" -> {
                    DropPick(t("ed.flow"), listOf("" to t("ed.flowNone"), "xtls-rprx-vision" to "Flow: xtls-rprx-vision", "xtls-rprx-vision-udp443" to "Flow: xtls-rprx-vision-udp443"), pro["flow"] ?: "") { x: String -> pro["flow"] = x }
                    EncryptionField(pro["encryption"] ?: "none", encOn) { x: String -> pro["encryption"] = x }
                }
                "vmess" -> {
                    DropPick(t("ed.cipher"), listOf("auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero").map { c: String -> c to tf("ed.cipherOpt", "c" to c) }, pro["vmessSecurity"] ?: "auto") { x: String -> pro["vmessSecurity"] = x }
                    Fld(t("ed.alterId"), pro["alterId"] ?: "0") { x: String -> pro["alterId"] = x }
                }
                else -> {}
            }
            if (isHy2) {
                Text(t("ed.tlsQuic"), color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 2.dp))
                Fld(t("ed.sniCert"), sni) { sni = it }
                // QUIC: no first-use pin. Allow insecure without a pin runs on sing-box (EngineChoice.needsInsecureCore).
                SwitchRow(t("ed.insecureHy2"), allowInsecure) { allowInsecure = it }
                Text(t("ed.insecureHy2Hint"), color = MUTED, fontSize = 11.sp)
                Fld(t("ed.obfs"), hy2Obfs) { hy2Obfs = it }
                Fld(t("ed.hops"), hy2Ports) { hy2Ports = it }
                TlsExtraFields(ech, { ech = it }, pcs, { pcs = it }, vcn, { vcn = it })
            }
            if (isStd) {
                DropPick(t("ed.transport"), listOf("tcp" to "tcp", "ws" to "ws", "grpc" to "grpc", "h2" to "h2", "xhttp" to "xhttp", "httpupgrade" to "httpupgrade", "kcp" to "kcp"), network) { network = it }
                DropPick(t("ed.security"), listOf("none" to "none", "tls" to "tls", "reality" to "reality"), security) { security = it }
                // Context-aware SNI section: it means different things for
                // reality / CDN-fronting / plain-TLS, so say the right thing.
                val frontable = network in listOf("ws", "grpc", "xhttp", "splithttp", "h2", "http", "httpupgrade")
                if (security == "tls" || security == "reality") {
                    val head = if (security == "reality") t("ed.headReality") else t("ed.headTls")
                    val sniLabel = when { security == "reality" -> t("ed.sniReality"); frontable -> t("ed.sniFront"); else -> t("ed.sniCert") }
                    val sniHint = when {
                        security == "reality" -> t("ed.hintReality")
                        frontable -> t("ed.hintFront")
                        else -> t("ed.hintTls")
                    }
                    Text(head, color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 2.dp))
                    Fld(sniLabel, sni) { sni = it }
                    if (security == "tls" && frontable) Fld(t("ed.hostSni"), host) { host = it }
                    Text(sniHint, color = MUTED, fontSize = 11.sp)
                    // Working bypass: fragment the ClientHello so DPI can't read the SNI.
                    SwitchRow(t("ed.hideSni"), fragment.isNotBlank()) {
                        fragment = if (it) (if (fragment.isBlank()) "tlshello,100-200,10-20" else fragment) else ""
                    }
                }
                Fld("Path / ServiceName", path) { path = it }
                DropPick(t("ed.fp"), listOf("chrome" to "chrome", "firefox" to "firefox", "safari" to "safari", "ios" to "ios", "android" to "android", "edge" to "edge", "random" to "random", "randomized" to "randomized", "unsafe" to t("ed.fpUnsafe")), fp) { fp = it }
                if (security == "reality") {
                    Fld("Public Key (pbk)", pbk) { pbk = it }; Fld("Short ID (sid)", sid) { sid = it }
                    Fld(t("ed.pqv"), pqv) { pqv = it }
                }
                if (security == "tls") TlsExtraFields(ech, { ech = it }, pcs, { pcs = it }, vcn, { vcn = it })
                // The core no longer accepts allowInsecure: the switch means "pin the
                // certificate this server presents on first use" (CertPin.kt).
                SwitchRow(t("ed.insecurePin"), allowInsecure) { allowInsecure = it }
                // patterniha custom-TLS
                Text(t("ed.pattn"), color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 2.dp))
                Fld(t("ed.cipherSuites"), cipherSuites) { cipherSuites = it }
                Fld("finalMask (JSON)", finalMask) { finalMask = it }
                Text(t("ed.pattnHint"), color = MUTED, fontSize = 11.sp)
            }
            if (server.protocol == "wireguard") {
                Fld(t("f.peerPub"), wgPub) { wgPub = it }; Fld("Address (/32)", wgAddr) { wgAddr = it }; Fld(t("ed.psk"), wgPsk) { wgPsk = it }
                Fld("MTU", wgMtu) { wgMtu = it }; Fld("Reserved", wgReserved) { wgReserved = it }; Fld(t("f.allowed"), wgAllowed) { wgAllowed = it }
                Fld(t("ed.wgDns"), wgDns) { wgDns = it }
            }
            if (isMasque) {
                // MASQUE: its HTTP version, the SNI, a user and password or the WARP account's
                // summary (its keys live in the Pro view), the certificate knobs; then anti-DPI by
                // HTTP version and the core — Xray or Xray-PattN only
                Text(t("ed.masqueHead"), color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 2.dp))
                DropPick(t("sf.masqueHttp"), listOf("h3" to t("sfo.masqueHttp.h3"), "h2" to t("sfo.masqueHttp.h2")), masqueHttp) { x: String -> masqueHttp = x }
                Text(t("sf.masqueHttp.hint"), color = MUTED, fontSize = 11.sp)
                Fld("SNI", sni) { sni = it }
                val warpAddr = pro["warpAddress"] ?: ""
                if ((pro["warpPrivateKey"] ?: "").isNotBlank()) {
                    Text(t("sfg.warp"), color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 8.dp, bottom = 2.dp))
                    Text(tf("ed.warpAddrs", "a" to warpAddr.ifBlank { "—" }), color = TXT2, fontSize = 11.sp, fontFamily = MONO)
                    Text(t("ed.warpKeys"), color = MUTED, fontSize = 11.sp)
                } else {
                    Fld(t("f.userOpt"), pro["masqueUser"] ?: "") { x: String -> pro["masqueUser"] = x }
                    Fld(t("f.passOpt"), pro["masquePass"] ?: "") { x: String -> pro["masquePass"] = x }
                }
                if (masqueHttp == "h2") {
                    val fps = listOf("" to t("ed.fpNone")) + listOf("chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized").map { x: String -> x to tf("ed.fpOpt", "x" to x) }
                    DropPick(t("sf.fp.masque"), fps, fp) { x: String -> fp = x }
                }
                TlsExtraFields(ech, { ech = it }, pcs, { pcs = it }, vcn, { vcn = it })
                HorizontalDivider(Modifier.padding(vertical = 8.dp), color = STROKE)
                Text(t("ed.antiDpiCore"), color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(bottom = 4.dp))
                if (masqueHttp == "h2") {
                    SwitchRow(t("ed.fragH2"), fragment.isNotBlank()) { on: Boolean ->
                        fragment = if (on) (if (fragment.isBlank()) "tlshello,100-200,10-20" else fragment) else ""
                    }
                } else {
                    SwitchRow(t("ed.noiseH3"), noisePreset != "off") { on: Boolean -> noisePreset = if (on) "random" else "off" }
                }
                DropPick(t("ed.engine"), listOf("xray" to t("ed.xrayDefault"), "xray-pattn" to "Xray-PattN"), if (engine == "xray-pattn") "xray-pattn" else "xray") { x: String -> engine = x }
                Text(t("ed.masqueXrayOnly"), color = MUTED, fontSize = 11.sp)
            }
            if (!isMasque) {
            HorizontalDivider(Modifier.padding(vertical = 8.dp), color = STROKE)
            Text(t("ed.advanced"), color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(bottom = 4.dp))
            DropPick(
                t("ed.engine"),
                listOf(
                    "xray" to t("ed.xrayDefault"),
                    "xray-pattn" to t("ed.pattnOpt"),
                    "sing-box" to t("ed.singboxOpt")
                ),
                engine
            ) { engine = it }
            Text(
                t("ed.engineHint"),
                color = MUTED, fontSize = 11.sp
            )
            Spacer(Modifier.height(8.dp))
            Fld(t("ed.fragment"), fragment) { fragment = it }
            Text(t("ed.fragmentEg"), color = MUTED, fontSize = 11.sp)
            Spacer(Modifier.height(8.dp))
            DropPick(t("ed.noise"), listOf("off" to t("ed.noiseOff"), "random" to t("ed.noiseRandom"), "faketls" to t("ed.noiseFake"), "custom" to t("ed.noiseCustom")), noisePreset) { noisePreset = it }
            if (noisePreset == "custom") {
                Fld(t("ed.noiseSpec"), noiseCustom) { noiseCustom = it }
                Text(t("ed.noiseHint"), color = MUTED, fontSize = 11.sp)
            }
            }
            }
            Spacer(Modifier.height(10.dp))
            Button(onClick = {
                // the whole draft from whichever view is open; what it cannot send is said, its tab shown
                val nf = if (proView) ServerEditor.fromDraft(server.protocol, draft, simpleFields()) else simpleFields()
                val p = ServerEditor.problem(server.protocol, if (proView) HashMap<String, String>(draft) else ServerEditor.toDraft(server.protocol, nf), false, encOn.value)
                if (p != null) {
                    Toast.makeText(ctx, problemTextUi(server.protocol, p), Toast.LENGTH_LONG).show()
                    if (proView) tab.value = p.second
                } else {
                    try { onSave(ServerEditor.apply(server, nf)) }
                    catch (e: Exception) { Toast.makeText(ctx, e.message ?: t("ed.saveFailed"), Toast.LENGTH_LONG).show() }
                }
            }, modifier = Modifier.fillMaxWidth()) { Text(t("btn.save")) }
        }
    }
}

/* ---------- the full server editor: the Pro view and a server made by hand (ServerFields) ---------- */

/** ServerEditor.problemText in the app's language: the table's strings through t() (ServerEditor keeps the English). */
private fun problemTextUi(protocol: String, p: Triple<String, String, String>): String {
    val label = t("sf.${p.first}.$protocol").takeIf { x: String -> !x.startsWith("sf.") } ?: t("sf.${p.first}")
    return if (p.third == "edit.err.required") t(p.third).replace("{field}", label)
    else t("edit.err.in").replace("{field}", label).replace("{why}", t(p.third))
}

/** The editor's view, remembered while the app runs: the sheet opens in the one used last. */
private object EditView { var pro: Boolean = false }

/** A field's label: by protocol or transport where it reads differently, its key, "this device only". */
private fun proLabel(protocol: String, d: Map<String, String>, fld: SfField): String {
    val net = d["network"] ?: "tcp"
    val own = listOf("sf.${fld.id}.$protocol", "sf.${fld.id}.$net", "sf.${fld.id}").map { k: String -> t(k) }.firstOrNull { v: String -> !v.startsWith("sf.") } ?: fld.id
    return if (fld.local) "$own · ${fld.key} · ${t("edit.local")}" else "$own · ${fld.key}"
}

/** An option's label: its own string where it has one (the empty one, Mux, the core), else the value. */
private fun proOption(fld: SfField, o: String): String {
    if (fld.optionLabels.isEmpty() || (fld.optionLabels != "all" && o.isNotEmpty())) return o
    val k = "sfo.${fld.id}.${o.ifEmpty { "_" }}"
    val v = t(k)
    return if (v == k) o.ifEmpty { "—" } else v
}

/** Simple | Pro, beside the sheet's title. */
@Composable private fun ViewSwitch(pro: Boolean, onPick: (Boolean) -> Unit) {
    Row(Modifier.clip(RoundedCornerShape(8.dp)).border(1.dp, STROKE, RoundedCornerShape(8.dp))) {
        for (p in listOf(false, true)) {
            val on = p == pro
            Text(
                t(if (p) "edit.view.pro" else "edit.view.simple"),
                color = if (on) ON_PRIMARY else MUTED, fontSize = 12.sp, fontWeight = FontWeight.Bold,
                modifier = Modifier.background(if (on) PRIMARY else Color.Transparent).clickable { onPick(p) }.padding(horizontal = 12.dp, vertical = 6.dp)
            )
        }
    }
}

/** VLESS Encryption: none, or the panel's value — read back (auth, mode, RTT) or why it is not one. */
@Composable private fun EncryptionField(value: String, encOn: MutableState<Boolean>, onChange: (String) -> Unit) {
    Text("${t("sf.encryption")} · encryption", color = MUTED, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
    DropPick(
        t("sf.encryption"),
        listOf("none" to t("sfo.encMode.none"), "mlkem" to t("sfo.encMode.mlkem")),
        if (encOn.value) "mlkem" else "none"
    ) { m: String ->
        encOn.value = m == "mlkem"
        onChange(if (m == "mlkem") (if (value == "none") "" else value) else "none")
    }
    if (encOn.value) {
        OutlinedTextField(
            if (value == "none") "" else value, { x: String -> onChange(x.trim()) },
            Modifier.fillMaxWidth().padding(vertical = 3.dp), label = { Text(t("sf.encryptionValue")) }, colors = tfColors()
        )
        val r = ServerFields.readEncryption(value)
        if (r != null) {
            val bad = r.bad
            if (bad != null) Text("✗ " + t(bad), color = BAD, fontSize = 11.sp)
            else {
                val auth = t("edit.enc.auth").replace("{v}", r.auth + if (r.auth == "ML-KEM-768") " — " + t("edit.enc.pq") else "")
                val mode = t("edit.enc.mode").replace("{v}", r.mode)
                Text("$auth · $mode · ${if (r.rtt == "0rtt") "0-RTT" else "1-RTT"}", color = PRIMARY, fontSize = 11.sp)
            }
        }
        Text(t("sf.encryption.hint"), color = MUTED, fontSize = 11.sp)
    }
}

/** One field of the draft, by its kind; every input writes straight back to [d]. */
@Composable private fun ProField(protocol: String, fld: SfField, d: SnapshotStateMap<String, String>, encOn: MutableState<Boolean>) {
    val label = proLabel(protocol, d, fld)
    val v = d[fld.id] ?: ""
    when (fld.kind) {
        "switch" -> SwitchRow(label, v == "true") { on: Boolean -> d[fld.id] = if (on) "true" else "" }
        "select", "seg" -> {
            Text(label, color = MUTED, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
            // MASQUE: no sing-box core (it has no MASQUE), and no fingerprint at all is a choice (HTTP/3 has none)
            val options = when {
                fld.id == "engine" -> ServerEditor.engineOptions(protocol)
                fld.id == "fp" && protocol == Masque.PROTOCOL -> listOf("") + fld.options
                else -> fld.options
            }
            val opts = options.map { o: String -> o to (if (o.isEmpty() && fld.id == "fp") "—" else proOption(fld, o)) } +
                (if (v.isNotEmpty() && v !in options) listOf(v to v) else emptyList())
            DropPick(label, opts, v) { x: String -> d[fld.id] = x }
        }
        "network" -> {
            Text(label, color = MUTED, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
            val opts = ServerFields.NETWORKS.map { n: String -> n to t("sfo.network.$n") } + (if (v.isNotEmpty() && v !in ServerFields.NETWORKS) listOf(v to v) else emptyList())
            DropPick(label, opts, v) { x: String -> d[fld.id] = x }
        }
        "security" -> {
            Text(label, color = MUTED, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
            DropPick(label, ServerFields.securitiesOf(protocol).map { s: String -> s to t("sfo.security.$s") }, v) { x: String -> d[fld.id] = x }
        }
        "encryption" -> EncryptionField(v.ifEmpty { "none" }, encOn) { x: String -> d[fld.id] = x }
        "uuid" -> {
            Fld(label, v) { x: String -> d[fld.id] = x }
            TextButton(onClick = { d[fld.id] = java.util.UUID.randomUUID().toString() }) { Text(t("edit.genUuid"), color = PRIMARY, fontSize = 12.sp) }
        }
        else -> Fld(label, v) { x: String -> d[fld.id] = x }
    }
    if (fld.hint) Text(t("sf.${fld.id}.hint"), color = MUTED, fontSize = 11.sp)
}

/**
 * The Pro view: the five tabs and the open tab's fields, from the table
 * (ServerFields). [isNew]: a server made by hand — its protocol is picked on
 * Basics; an edited server keeps the one it has.
 */
@Composable private fun ProFields(protocol: String, d: SnapshotStateMap<String, String>, isNew: Boolean, onProtocol: (String) -> Unit, tab: MutableState<String>, encOn: MutableState<Boolean>) {
    val noTransport = !ServerFields.hasTransport(protocol)
    val noSecurity = ServerFields.securitiesOf(protocol).isEmpty()
    // a tab this protocol has none of shows the Protocol tab (never written to the state while composing)
    val cur = if ((tab.value == "transport" && noTransport) || (tab.value == "security" && noSecurity)) "protocol" else tab.value
    Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())) {
        for (tb in ServerFields.TABS) {
            val off = (tb == "transport" && noTransport) || (tb == "security" && noSecurity)
            val on = tb == cur
            Text(
                t("edit.tab.$tb"),
                color = when { off -> STROKE; on -> PRIMARY; else -> MUTED }, fontSize = 13.sp,
                fontWeight = if (on) FontWeight.Bold else FontWeight.Normal,
                modifier = Modifier.clickable(enabled = !off) { tab.value = tb }.padding(horizontal = 10.dp, vertical = 8.dp)
            )
        }
    }
    HorizontalDivider(color = STROKE)
    if (cur == "basics") {
        if (isNew) {
            Text(t("sf.protocol"), color = MUTED, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
            DropPick(t("sf.protocol"), ServerFields.PROTOCOLS.map { p: String -> p to "${badge(p)} — ${t("sfp.$p")}" }, protocol) { p: String -> onProtocol(p) }
            Text(t("edit.protoPick"), color = MUTED, fontSize = 11.sp)
        } else Text(t("edit.protoFixed"), color = MUTED, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
    }
    val name = badge(protocol)
    when {
        cur == "transport" && noTransport -> Text(t("edit.noTransport").replace("{proto}", name), color = MUTED, fontSize = 12.sp, modifier = Modifier.padding(vertical = 16.dp))
        cur == "security" && noSecurity -> Text(t("edit.noSecurity").replace("{proto}", name), color = MUTED, fontSize = 12.sp, modifier = Modifier.padding(vertical = 16.dp))
        else -> {
            var group: String? = null
            for (fld in ServerFields.FIELDS) {
                if (fld.tab != cur || fld.kind == "protocol" || !ServerEditor.shown(protocol, d, fld)) continue
                val g = fld.group
                if (g != null && g != group) Text(t("sfg.$g"), color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 12.dp, bottom = 2.dp))
                group = g
                ProField(protocol, fld, d, encOn)
            }
        }
    }
    if (cur == "security" && !noSecurity && (d["security"] ?: "none") == "none") Text(t("edit.noTls"), color = AMBER, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
    Text(t("edit.localNote"), color = MUTED, fontSize = 10.sp, modifier = Modifier.padding(top = 10.dp))
}

/** A server made by hand: the Pro view on Basics, its protocol picked first (ServerEditor.create). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun NewServerSheet(store: Store, onDismiss: () -> Unit, done: () -> Unit) {
    val ctx = LocalContext.current
    var protocol by remember { mutableStateOf("vless") }
    val draft = remember { mutableStateMapOf<String, String>().apply { putAll(ServerEditor.newDraft("vless")) } }
    val tab = remember { mutableStateOf("basics") }
    val encOn = remember { mutableStateOf(false) }
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState, containerColor = CARD) {
        Column(Modifier.fillMaxWidth().fillMaxHeight(0.92f).verticalScroll(rememberScrollState()).imePadding().padding(16.dp).padding(bottom = 24.dp)) {
            Text(t("edit.newTitle") + " · " + badge(protocol), color = TXT, fontWeight = FontWeight.Bold)
            ProFields(protocol, draft, true, { p: String ->
                val keep = HashMap<String, String>(draft)
                draft.clear(); draft.putAll(ServerEditor.newDraft(p, keep))
                encOn.value = false
                protocol = p
            }, tab, encOn)
            Spacer(Modifier.height(10.dp))
            Button(onClick = {
                val p = ServerEditor.problem(protocol, draft, true, encOn.value)
                if (p != null) {
                    Toast.makeText(ctx, problemTextUi(protocol, p), Toast.LENGTH_LONG).show()
                    tab.value = p.second
                } else {
                    try {
                        val s = ServerEditor.create(protocol, ServerEditor.fromDraft(protocol, draft, ServerEditor.Fields()))
                        store.servers.add(s); store.saveServers()
                        if (store.selection.isEmpty()) store.saveSelection(s.id)
                        Toast.makeText(ctx, t("t.serverCreated").replace("{name}", s.name), Toast.LENGTH_SHORT).show()
                        done()
                    } catch (e: Exception) {
                        Toast.makeText(ctx, e.message ?: t("ed.addFailed"), Toast.LENGTH_LONG).show()
                    }
                }
            }, modifier = Modifier.fillMaxWidth()) { Text(t("btn.add")) }
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
    Fld(t("ed.ech"), ech, onEch)
    Text(t("ed.echHint"), color = MUTED, fontSize = 11.sp)
    Fld(t("ed.pcs"), pcs, onPcs)
    Fld(t("ed.vcn"), vcn, onVcn)
    Text(t("ed.pcsHint"), color = MUTED, fontSize = 11.sp)
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
        TopBar(t("subs.title")) {
            IconButton(onClick = { store.subs.toList().forEach { refresh(it) } }, enabled = store.subs.any { it.id !in busy }) {
                Icon(Icons.Filled.Refresh, t("subs.refreshAll"), tint = PRIMARY)
            }
        }
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).imePadding().padding(horizontal = 16.dp)) {
            Card(Modifier.fillMaxWidth().padding(bottom = 10.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                Row(Modifier.padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(t("subs.auto"), color = TXT, fontSize = 13.sp)
                        Text(tf("subs.autoLine", "n" to settings.autoUpdateInterval), color = MUTED, fontSize = 11.sp, fontFamily = MONO)
                    }
                    Switch(settings.autoUpdateSubs, { v -> settings = settings.copy(autoUpdateSubs = v); store.saveSettings(settings) },
                        colors = SwitchDefaults.colors(checkedThumbColor = ON_PRIMARY, checkedTrackColor = PRIMARY, uncheckedThumbColor = MUTED, uncheckedTrackColor = CARD2, uncheckedBorderColor = STROKE))
                }
            }
            Fld(t("subs.url"), url) { url = it }; Fld(t("subs.nameOpt"), name) { name = it }
            Button(onClick = {
                if (url.isBlank()) AppWork.snack(t("subs.pasteFirst"))
                else { val sub = Subscription(newId("sub"), name.ifBlank { url.take(24) }, url.trim()); store.subs.add(sub); store.saveSubs(); url = ""; name = ""; AppWork.refreshSub(ctx, store, sub.id, announce = true) }
            }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(t("subs.addFetch")) }
            if (note.first.isNotEmpty()) Text(note.first, color = if (note.second) BAD else PRIMARY, fontSize = 12.sp)
            Spacer(Modifier.height(8.dp))
            if (store.subs.isEmpty()) EmptyHint(t("subs.empty"))
            store.subs.forEach { sub ->
                Card(Modifier.fillMaxWidth().padding(vertical = 5.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                    Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.CloudDownload, null, tint = PRIMARY); Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(sub.name, color = TXT, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(sub.url, color = MUTED2, fontSize = 10.sp, fontFamily = MONO, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(
                                tf("subs.servers", "n" to sub.serverCount) + " · " + if (sub.lastUpdated > 0) tf("subs.updated", "ago" to fmtAgo(System.currentTimeMillis() - sub.lastUpdated)) else t("subs.never"),
                                color = MUTED, fontSize = 11.sp, fontFamily = MONO
                            )
                            // The last attempt failed (its servers were kept): say when and why.
                            if (sub.lastError.isNotEmpty() && sub.lastTried > 0) Text(
                                tf("subs.lastTry", "ago" to fmtAgo(System.currentTimeMillis() - sub.lastTried), "error" to sub.lastError),
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
                                Text(if (daysLeft >= 0) tf("subs.daysLeft", "n" to daysLeft) else t("subs.expired"), color = if (daysLeft < 0) BAD else if (daysLeft <= 3) AMBER else MUTED, fontSize = 11.sp)
                            }
                        }
                        IconButton(onClick = { AppWork.refreshSub(ctx, store, sub.id, announce = true) }, enabled = sub.id !in busy) {
                            if (sub.id in busy) CircularProgressIndicator(color = PRIMARY, strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
                            else Icon(Icons.Filled.Refresh, t("a11y.refresh"), tint = MUTED)
                        }
                        IconButton(onClick = { confirmDelete = sub }) { Icon(Icons.Filled.DeleteOutline, t("a11y.delete"), tint = BAD) }
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
            title = { Text(t("subs.deleteTitle"), color = TXT, fontSize = 16.sp) },
            text = { Text(tf("subs.deleteBody", "name" to victim.name, "n" to count), color = MUTED, fontSize = 13.sp, fontFamily = MONO) },
            confirmButton = {
                TextButton(onClick = {
                    val wasIn = store.serverById(store.selection)?.subId == victim.id
                    store.deleteSubscription(victim.id)   // a selection among its servers falls back
                    confirmDelete = null
                    AppWork.snack(
                        if (wasIn && store.selection.isNotEmpty()) tf("srv.deletedNow", "name" to victim.name, "now" to selectionWord(store))
                        else tf("srv.deleted", "name" to victim.name)
                    )
                    bump()
                }) { Text(t("btn.delete"), color = BAD) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text(t("btn.cancel"), color = MUTED) } }
        )
    }
}

/* ================================ POOL ================================ */
@Composable
private fun PoolScreen(store: Store, bump: () -> Unit, back: () -> Unit) {
    observeStore()
    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        TopBar(t("pool.title"), back) {
            IconButton(onClick = { val used = usedPorts(store); var sp = 60001; while (used.contains(sp)) sp++; var hp = sp + 1; while (used.contains(hp)) hp++
                store.pool.add(PoolEntry(newId("px"), tf("pool.newName", "n" to store.pool.size + 1), store.servers.firstOrNull()?.id ?: "", sp, hp, true)); store.savePool(); bump() }) { Icon(Icons.Filled.Add, t("a11y.add"), tint = PRIMARY) }
        }
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).imePadding().padding(horizontal = 16.dp)) {
            Text(t("pool.intro"), color = MUTED, fontSize = 12.sp)
            Button(onClick = { store.saveSelection(Store.POOL_ID); bump() }, modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) { Text(t("pool.select")) }
            if (store.pool.isEmpty()) EmptyHint(t("pool.empty"))
            store.pool.toList().forEachIndexed { idx, e ->
                Card(Modifier.fillMaxWidth().padding(vertical = 5.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                    Column(Modifier.padding(14.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(e.name, color = TXT, modifier = Modifier.weight(1f)); Switch(e.enabled, { store.pool[idx] = e.copy(enabled = it); store.savePool(); bump() })
                            IconButton(onClick = { store.pool.removeAt(idx); store.savePool(); bump() }) { Icon(Icons.Filled.DeleteOutline, null, tint = BAD) }
                        }
                        DropPick(t("pool.exit"), targetOptions(store), e.target) { store.pool[idx] = e.copy(target = it); store.savePool(); bump() }
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            NumFld(t("set.socks"), e.socksPort, Modifier.weight(1f)) { store.pool[idx] = e.copy(socksPort = it); store.savePool() }
                            NumFld(t("set.http"), e.httpPort, Modifier.weight(1f)) { store.pool[idx] = e.copy(httpPort = it); store.savePool() }
                        }
                        if (!store.poolTargetValid(e.target)) Text(t("pool.invalid"), color = AMBER, fontSize = 12.sp)
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
        }
    }
}

/* ================================ CHAINS & GROUPS ================================ */
/**
 * Chains (several hops, in order) and groups (several configs used as one —
 * Groups.kt): a group is a hop like a server, and the chain's member picker
 * offers them too. A chain's rows come from its ids, so a hop that is gone (a
 * group with no server left, say) is shown — and can be removed — instead of
 * silently missing from the list.
 */
@Composable
private fun ChainsScreen(store: Store, bump: () -> Unit, back: () -> Unit) {
    observeStore()
    // a chain's share link (RouteShare): copy, and a QR when it fits
    var shared by remember { mutableStateOf<SharedText?>(null) }
    // the group open in the editor (null = none), and whether it is a new one
    var editing by remember { mutableStateOf<GroupConfig?>(null) }
    var editingNew by remember { mutableStateOf(false) }
    Screen(t("chain.screen"), back, { IconButton(onClick = { store.chains.add(ChainConfig(newId("chain"), tf("chain.newName", "n" to store.chains.size + 1), emptyList())); store.saveChains(); bump() }) { Icon(Icons.Filled.Add, t("chain.add"), tint = PRIMARY) } }) {
        // a hop added to or removed from a chain the connection runs waits for a reconnect
        ApplyBar(store, store.settings)
        Text(t("chain.section"), color = MUTED2, fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em)
        if (store.chains.isEmpty()) EmptyHint(t("chain.empty"))
        store.chains.toList().forEachIndexed { idx, c ->
            val members = store.chainMembers(c)
            Card(Modifier.fillMaxWidth().padding(vertical = 5.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                Column(Modifier.padding(14.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("⛓ ${c.name}", color = TXT, modifier = Modifier.weight(1f))
                        if (members.isNotEmpty()) IconButton(onClick = { shared = chainShare(store, c) }) { Icon(Icons.Filled.Share, t("chain.share"), tint = TXT2) }
                        if (store.chainReady(c)) IconButton(onClick = { store.saveSelection("chain:${c.id}"); bump() }) { Icon(Icons.Filled.CheckCircle, null, tint = if (store.selection == "chain:${c.id}") PRIMARY else MUTED) }
                        IconButton(onClick = {
                            val wasSelected = store.selection == "chain:${c.id}"
                            store.deleteChain(c.id)   // a selection that named it falls back
                            if (wasSelected && store.selection.isNotEmpty()) AppWork.snack(tf("srv.deletedNow", "name" to c.name, "now" to selectionWord(store)))
                            bump()
                        }) { Icon(Icons.Filled.DeleteOutline, t("chain.delete"), tint = BAD) }
                    }
                    // the hops in reading order: → in English, ← in Persian (I18n.flow)
                    Text(tf("chain.path", "path" to (if (members.isEmpty()) t("chain.pathEmpty") else I18n.flow(members.map { s: ServerConfig -> hopName(s) }))), color = MUTED, fontSize = 12.sp)
                    c.members.forEachIndexed { mi: Int, id: String ->
                        val hop = chainHopLabel(store, id)
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("${mi + 1}. ${hop.first}", color = if (hop.second) TXT else BAD, fontSize = 13.sp, modifier = Modifier.weight(1f))
                            IconButton(onClick = { store.chains[idx] = c.copy(members = c.members.filterIndexed { x: Int, _: String -> x != mi }); store.saveChains(); bump() }) { Icon(Icons.Filled.Close, t("chain.removeHop"), tint = BAD) }
                        }
                    }
                    DropPick(t("chain.addHop"), chainHopOptions(store, c), "") { id: String -> if (id.isNotEmpty()) { store.chains[idx] = c.copy(members = c.members + id); store.saveChains(); bump() } }
                }
            }
        }

        Spacer(Modifier.height(14.dp))
        Text(t("grp.section"), color = MUTED2, fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em)
        Text(
            t("grp.intro"),
            color = MUTED, fontSize = 12.sp
        )
        OutlinedButton(
            onClick = { editingNew = true; editing = GroupConfig(Groups.newGroupId(), tf("grp.newName", "n" to store.groups.size + 1)) },
            modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)
        ) { Text(t("grp.new")) }
        if (store.groups.isEmpty()) EmptyHint(t("grp.empty"))
        store.groups.toList().forEach { g: GroupConfig ->
            GroupCard(store, g, onEdit = { editingNew = false; editing = g }, bump = bump)
        }
        Spacer(Modifier.height(16.dp))
    }
    shared?.let { st: SharedText -> RouteShareDialog(st) { shared = null } }
    editing?.let { g: GroupConfig ->
        GroupEditorSheet(store, g, editingNew, onDismiss = { editing = null }, onSave = { saved: GroupConfig ->
            val i = store.groups.indexOfFirst { x: GroupConfig -> x.id == saved.id }
            if (i >= 0) { store.groups[i] = saved } else { store.groups.add(saved) }
            store.saveGroups()
            editing = null
            AppWork.snack(tf("grp.savedName", "name" to saved.name))
            bump()
        })
    }
}

/** A chain hop's name: a group's with its mark. */
private fun hopName(s: ServerConfig): String = if (Groups.isGroupRecord(s)) "⧉ ${s.name}" else s.name

/** One hop of a chain by its id, in words, and whether it is there: a server, a group (with a server left), or what is missing. */
private fun chainHopLabel(store: Store, id: String): Pair<String, Boolean> {
    val s = store.serverById(id)
    if (s != null) return Pair(s.name, true)
    val g = store.groupById(id) ?: return Pair(if (Groups.isGroupId(id)) t("chain.missingGroup") else t("chain.missingServer"), false)
    return if (store.groupRecord(id) != null) Pair("⧉ ${g.name}", true) else Pair("⧉ " + tf("chain.groupEmpty", "name" to g.name), false)
}

/** What can be added to [c]: every server and every group with a server left, not already in it. */
private fun chainHopOptions(store: Store, c: ChainConfig): List<Pair<String, String>> = buildList {
    store.servers.filter { s: ServerConfig -> !c.members.contains(s.id) }.forEach { s: ServerConfig -> add(s.id to s.name) }
    groupOptions(store).filter { o: Pair<String, String> -> !c.members.contains(o.first) }.forEach { o: Pair<String, String> -> add(o) }
}

/** Every group that has a server left, as a picker option: its bare id, "⧉ name". */
private fun groupOptions(store: Store): List<Pair<String, String>> =
    store.groups.filter { g: GroupConfig -> store.groupRecord(g.id) != null }.map { g: GroupConfig -> g.id to "⧉ ${g.name}" }

/** "1 config" / "3 configs". */
private fun configsWord(n: Int): String = if (n == 1) t("cfg.one") else tf("cfg.many", "n" to n)

/** A group's strategy in words (Groups.strategyLabel, in the app's language). */
private fun strategyWord(strategy: String): String {
    val key = "grp.st.$strategy"
    return if (I18n.has(key)) t(key) else Groups.strategyLabel(strategy)
}

/** What a strategy does, one line (Groups.strategyHelp, in the app's language). */
private fun strategyHelpWord(strategy: String): String {
    val key = "grp.stLine.$strategy"
    return if (I18n.has(key)) t(key) else Groups.strategyHelp(strategy)
}

/**
 * One group on the chains screen: its name, how many configs it has (and how
 * many are gone), its strategy, the last real delay through it — select it
 * for Connect, test it, edit it, delete it.
 */
@Composable private fun GroupCard(store: Store, g: GroupConfig, onEdit: () -> Unit, bump: () -> Unit) {
    val ctx = LocalContext.current
    val rec = store.groupRecord(g.id)
    val size = Groups.sizeOf(rec)
    val gone = g.members.size - size
    val selected = store.selection == g.id
    val test = AppWork.tests[g.id]
    Card(Modifier.fillMaxWidth().padding(vertical = 5.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("⧉ ${g.name}", color = TXT, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                if (rec != null) IconButton(onClick = { store.saveSelection(g.id); bump() }) {
                    Icon(Icons.Filled.CheckCircle, t("grp.use"), tint = if (selected) PRIMARY else MUTED)
                }
                IconButton(onClick = onEdit) { Icon(Icons.Filled.Edit, t("grp.edit"), tint = TXT2) }
                IconButton(onClick = {
                    store.deleteGroup(g.id)   // a selection that named it falls back; chains lose it as a hop
                    if (selected && store.selection.isNotEmpty()) AppWork.snack(tf("srv.deletedNow", "name" to g.name, "now" to selectionWord(store)))
                    bump()
                }) { Icon(Icons.Filled.DeleteOutline, t("grp.delete"), tint = BAD) }
            }
            Text(
                configsWord(size) + " · " + strategyWord(g.strategy) + (if (gone > 0) " · " + tf("grp.missingN", "n" to gone) else ""),
                color = MUTED, fontSize = 12.sp, fontFamily = MONO
            )
            if (rec == null) {
                Text(t("grp.noneLeft"), color = BAD, fontSize = 11.sp)
            } else {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    val down = test?.down
                    Text(
                        when {
                            test != null && test.phase.isNotEmpty() -> t("grp.measuring")
                            down != null && down >= 0 -> tf("grp.realDelay", "ms" to "$down ms")
                            down != null -> t("grp.noAnswer")
                            else -> t("grp.notMeasured")
                        },
                        color = if (down != null && down < 0) BAD else MUTED2, fontSize = 11.sp, fontFamily = MONO, modifier = Modifier.weight(1f)
                    )
                    TextButton(onClick = { AppWork.testGroup(ctx, rec) }) { Text(t("card.test"), color = PRIMARY, fontSize = 12.sp) }
                }
            }
        }
    }
}

/**
 * A group's editor: its name; its strategy — round-robin (the default),
 * fastest, random — one line each on what it does; its members: servers added
 * from a picker, or one server at several addresses ("+ clean IPs": pasted one
 * per line, a bad line flagged by its number); a member whose server is gone
 * shown as missing; any removed. Save hands the group back; nothing is written
 * before it.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun GroupEditorSheet(store: Store, initial: GroupConfig, isNew: Boolean, onDismiss: () -> Unit, onSave: (GroupConfig) -> Unit) {
    val ctx = LocalContext.current
    var name by remember(initial.id) { mutableStateOf(initial.name) }
    var strategy by remember(initial.id) { mutableStateOf(initial.strategy) }
    var members by remember(initial.id) { mutableStateOf(initial.members) }
    var cleanOpen by remember(initial.id) { mutableStateOf(false) }
    var cleanServer by remember(initial.id) { mutableStateOf("") }
    var cleanText by remember(initial.id) { mutableStateOf("") }
    var cleanError by remember(initial.id) { mutableStateOf("") }
    val serverOptions = store.servers.map { s: ServerConfig -> s.id to s.name }
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheetState, containerColor = CARD) {
        Column(Modifier.fillMaxWidth().fillMaxHeight(0.92f).verticalScroll(rememberScrollState()).imePadding().padding(16.dp).padding(bottom = 24.dp)) {
            Text(if (isNew) t("grp.newTitle") else t("grp.editTitle"), color = TXT, fontWeight = FontWeight.Bold)
            Fld(t("f.name"), name) { v: String -> name = v }

            Text(t("grp.strategy"), color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 2.dp))
            Groups.STRATEGIES.forEach { st: String ->
                Row(Modifier.fillMaxWidth().clickable { strategy = st }.padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(strategy == st, { strategy = st })
                    Column(Modifier.weight(1f)) {
                        Text(if (st == Groups.DEFAULT_STRATEGY) tf("grp.stDefault", "name" to strategyWord(st)) else strategyWord(st), color = TXT, fontSize = 14.sp)
                        Text(strategyHelpWord(st), color = MUTED, fontSize = 11.sp)
                    }
                }
            }

            Text(t("grp.members"), color = PRIMARY, fontWeight = FontWeight.Bold, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp, bottom = 2.dp))
            if (members.isEmpty()) Text(t("grp.noMembers"), color = MUTED, fontSize = 12.sp)
            members.forEachIndexed { i: Int, m: GroupMember ->
                val srv = store.serverById(m.id)
                val at = Groups.memberAddress(m)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            "${i + 1}. " + (srv?.name ?: t("chain.missingServer")), color = if (srv == null) BAD else TXT,
                            fontSize = 13.sp, maxLines = 1, overflow = TextOverflow.Ellipsis
                        )
                        if (at.isNotEmpty()) Text(tf("grp.at", "addr" to at), color = MUTED2, fontSize = 10.sp, fontFamily = MONO)
                        if (srv == null) Text(t("grp.memberGone"), color = BAD, fontSize = 10.sp)
                    }
                    IconButton(onClick = { members = members.filterIndexed { x: Int, _: GroupMember -> x != i } }) {
                        Icon(Icons.Filled.Close, t("grp.removeMember"), tint = BAD)
                    }
                }
            }
            DropPick(t("grp.addServer"), serverOptions, "") { id: String -> if (id.isNotEmpty()) { members = members + GroupMember(id) } }
            OutlinedButton(onClick = { cleanOpen = !cleanOpen; cleanError = "" }, modifier = Modifier.fillMaxWidth()) {
                Text(if (cleanOpen) t("grp.closeIps") else t("grp.addIps"))
            }
            if (cleanOpen) {
                Text(
                    t("grp.ipsIntro"),
                    color = MUTED, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp)
                )
                DropPick(t("grp.pickServer"), serverOptions, cleanServer) { id: String -> cleanServer = id; cleanError = "" }
                // addresses read left to right in either language
                CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
                    OutlinedTextField(
                        cleanText, { v: String -> cleanText = v; cleanError = "" }, Modifier.fillMaxWidth(),
                        placeholder = { Text("104.16.1.1\n104.17.2.2:2053\n[2606:4700::1]:443", fontSize = 11.sp, fontFamily = MONO) },
                        textStyle = TextStyle(fontFamily = MONO, fontSize = 12.sp, color = TXT),
                        minLines = 4, maxLines = 10, shape = RoundedCornerShape(10.dp), colors = tfColors()
                    )
                }
                if (cleanError.isNotEmpty()) Text(cleanError, color = BAD, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp))
                Button(onClick = {
                    val srv = store.serverById(cleanServer)
                    val parsed = Groups.parseCleanIps(cleanText)
                    val why = Groups.cleanIpProblem(srv, parsed)
                    if (why != null || srv == null) {
                        cleanError = why ?: t("grp.pickServerFor")
                    } else {
                        members = members + parsed.targets.map { t: Pair<String, Int?> -> GroupMember(srv.id, t.first, t.second) }
                        cleanText = ""
                        cleanOpen = false
                    }
                }, modifier = Modifier.fillMaxWidth().padding(top = 4.dp)) { Text(t("grp.ipsAdd")) }
            }

            Spacer(Modifier.height(12.dp))
            Button(onClick = {
                if (members.isEmpty()) {
                    Toast.makeText(ctx, t("grp.needOne"), Toast.LENGTH_SHORT).show()
                } else {
                    onSave(initial.copy(name = name.trim().ifEmpty { t("grp.defaultName") }, strategy = strategy, members = members))
                }
            }, modifier = Modifier.fillMaxWidth()) { Text(t("btn.save")) }
        }
    }
}

/* ================================ ROUTING ================================ */
/**
 * Routing: the simple modes, then advanced routing as PROFILES — several saved
 * rule sets, each with an optional base its targets ride on ("via a base") or
 * leave from ("exit at the base"), and the profile drawn as a vertical flow,
 * rule → base → target, among the app's own rules (RoutingProfiles.kt; spec
 * 2026-10-09 §1–§3, the desktop's routing page in the app's style).
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
    val rev = observeStore()
    var s by remember { mutableStateOf(store.settings) }
    // Without geoip.dat/geosite.dat the core drops every geo rule, so the two
    // bypass modes and Block ads would do exactly nothing. Show that instead.
    val geo = remember { GeoAssets.available(ctx) }
    fun save(n: AppSettings) { store.saveSettings(n); s = store.settings; AppWork.touch() }
    // The profile being edited: one just imported, else the one Connect uses, else the first.
    var editId by remember { mutableStateOf(RoutingUi.focus.ifEmpty { store.selectedProfile()?.id ?: "" }) }
    // an import made here (or on Home since) opens the profile it brought
    LaunchedEffect(rev) {
        val f = RoutingUi.focus
        if (f.isNotEmpty()) {
            if (store.profileById(f) != null) editId = f
            RoutingUi.focus = ""
        }
    }
    val prof = store.profileById(editId) ?: store.profiles.firstOrNull()
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
        AppWork.touch()
    }
    /** Rule [i] of profile [id] becomes [nr] — only while it is still [old] (it may have been moved or deleted meanwhile). */
    fun setRule(id: String, i: Int, old: RouteRule, nr: RouteRule) = update(id) { cur: RoutingProfile ->
        if (i < cur.rules.size && cur.rules[i] == old) cur.copy(rules = cur.rules.toMutableList().also { m: MutableList<RouteRule> -> m[i] = nr }) else cur
    }
    fun deleteRule(id: String, i: Int, old: RouteRule) = update(id) { cur: RoutingProfile ->
        if (i < cur.rules.size && cur.rules[i] == old) cur.copy(rules = cur.rules.filterIndexed { x: Int, _: RouteRule -> x != i }) else cur
    }
    // a chain or a group opens the chains & groups screen, a server its edit sheet; direct/block are nothing to open
    val onNode: (String) -> Unit = { t: String ->
        if (t.startsWith("chain:") || store.groupById(t) != null) openChains()
        if (store.serverById(t) != null) editServerId = t
    }

    Screen(t("rt.title"), back, {}) {
        ApplyBar(store, s)
        Text(t("rt.mode"), color = TXT, fontWeight = FontWeight.Bold)
        listOf(Triple("global", t("rt.global"), false), Triple("bypass-ir", t("rt.bypassIr"), true),
            Triple("bypass-cn", t("rt.bypassCn"), true), Triple("direct", t("rt.direct"), false)).forEach { (v, l, needsGeo) ->
            val on = geo || !needsGeo
            Row(Modifier.fillMaxWidth().clickable(enabled = on) { save(s.copy(routingMode = v)) }, verticalAlignment = Alignment.CenterVertically) {
                RadioButton(s.routingMode == v, { save(s.copy(routingMode = v)) }, enabled = on)
                Text(if (on) l else tf("rt.unavailable", "what" to l), color = if (on) TXT else MUTED)
            }
        }
        if (!geo) Text(t("rt.noGeo"), color = MUTED, fontSize = 12.sp)
        SwitchRow(if (geo) t("rt.blockAds") else tf("rt.unavailable", "what" to t("rt.blockAds")), s.blockAds && geo, enabled = geo) { v: Boolean -> save(s.copy(blockAds = v)) }
        SwitchRow(t("rt.sniffing"), s.enableSniffing) { v: Boolean -> save(s.copy(enableSniffing = v)) }
        HorizontalDivider(Modifier.padding(vertical = 10.dp), color = STROKE)
        SwitchRow(t("rt.advanced"), s.advancedRouting) { v: Boolean -> save(s.copy(advancedRouting = v)) }
        if (s.advancedRouting && prof != null) {
            Text(t("rt.profilesIntro"), color = MUTED, fontSize = 12.sp)
            Spacer(Modifier.height(10.dp))
            Text(t("rt.profiles"), color = MUTED2, fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em)
            Spacer(Modifier.height(4.dp))
            val inUseId = store.selectedProfile()?.id
            store.profiles.toList().forEach { p: RoutingProfile ->
                ProfileRow(
                    store, p, editing = p.id == prof.id, inUse = p.id == inUseId,
                    onEdit = { editId = p.id },
                    onUse = {
                        store.saveSelection(Selection.forProfile(p.id))
                        AppWork.touch()
                        AppWork.snack(tf("rt.useSnack", "name" to p.name))
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
                        RoutingProfiles.uniqueName(t("rt.defaultName"), store.profiles.map { x: RoutingProfile -> x.name }),
                        def = store.servers.firstOrNull()?.id ?: "direct"
                    )
                    store.profiles.add(np); store.saveProfiles()
                    editId = np.id
                    AppWork.touch()
                }, modifier = Modifier.weight(1f)) { Text(t("rt.newProfile"), fontSize = 13.sp) }
                OutlinedButton(onClick = { sheet = "import" }, modifier = Modifier.weight(1f)) { Text(t("rt.importLink"), fontSize = 13.sp) }
            }

            HorizontalDivider(Modifier.padding(vertical = 10.dp), color = STROKE)
            // edits to the profile the tunnel is running on reach it at the next connect: ApplyBar, at the top, says so
            key(prof.id, prof.name) {
                DraftField(prof.name, Modifier.fillMaxWidth(), label = { Text(t("rt.profileName")) }) { v: String -> update(prof.id) { cur: RoutingProfile -> cur.copy(name = v) } }
            }
            // The simple routing mode UNDER the profile's rules: an explicit corporate
            // rule still wins over a country bypass (configBuilder.js advancedUseMode).
            SwitchRow(if (geo) t("rt.useMode") else tf("rt.needsGeo", "what" to t("rt.useMode")), prof.useMode && geo, enabled = geo) { v: Boolean ->
                update(prof.id) { cur: RoutingProfile -> cur.copy(useMode = v) }
            }
            // the switch adds the mode chosen at the top — with Global there, it adds nothing
            if (prof.useMode && geo && !s.routingMode.startsWith("bypass"))
                Text(tf("rt.useModeNothing", "mode" to routingModeLabel(s.routingMode)), color = AMBER, fontSize = 11.sp)

            Spacer(Modifier.height(6.dp))
            Text(t("rt.base"), color = TXT, fontWeight = FontWeight.Bold)
            Text(t("rt.baseHint"), color = MUTED, fontSize = 11.sp)
            val base = prof.base
            DropPick(if (base == null) t("rt.noBase") else "⚠ ${targetWord(store, base)}", listOf("" to t("rt.noBase")) + targetOptions(store), base ?: "") { b: String ->
                update(prof.id) { cur: RoutingProfile -> cur.copy(base = b.ifEmpty { null }) }
            }
            if (base != null && !store.targetExists(base)) Text(t("rt.baseGone"), color = BAD, fontSize = 11.sp)

            Spacer(Modifier.height(6.dp))
            Text(t("rt.rules"), color = TXT, fontWeight = FontWeight.Bold)
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
            }, modifier = Modifier.fillMaxWidth()) { Text(t("rt.addRule")) }

            Spacer(Modifier.height(8.dp)); Text(t("rt.restVia"), color = MUTED)
            val defAtBase = prof.def == RoutingProfiles.TARGET_BASE
            DropPick(if (defAtBase) targetWord(store, prof.def, prof) else t("rt.default"), targetOptionsFor(store, prof), prof.def) { t: String -> update(prof.id) { cur: RoutingProfile -> cur.copy(def = t) } }
            when {
                defAtBase && prof.base == null -> Text(t("rt.noBaseDefault"), color = BAD, fontSize = 11.sp)
                !store.targetExists(prof.def, prof) -> Text(t("rt.defaultGone"), color = BAD, fontSize = 11.sp)
            }
            // "exit at the base" IS the base: nothing to ride on
            if (RoutingProfiles.takesVia(prof.def)) {
                DropPick(t("rt.base"), viaOptions(store, prof, prof.def), prof.defVia) { v: String -> update(prof.id) { cur: RoutingProfile -> cur.copy(defVia = v) } }
                val dv = RoutingProfiles.effectiveDefVia(prof)
                if (dv != null && !store.targetExists(dv)) Text(t("rt.itsBaseGone"), color = BAD, fontSize = 11.sp)
            }

            HorizontalDivider(Modifier.padding(vertical = 12.dp), color = STROKE)
            FlowList(store, prof, s, geo, onRule = { i: Int -> ruleDialog = i }, onNode = onNode)
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
                    Text(tf("rt.ruleN", "n" to rd + 1), color = TXT, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(6.dp))
                    key(prof.id, rd, r) {
                        RuleEditor(store, prof, r,
                            onChange = { nr: RouteRule -> setRule(prof.id, rd, r, nr) },
                            onDelete = { deleteRule(prof.id, rd, r); ruleDialog = -1 })
                    }
                    TextButton(onClick = { ruleDialog = -1 }, modifier = Modifier.align(Alignment.End)) { Text(t("btn.done"), color = PRIMARY) }
                }
            }
        }
    }
    confirmDelete?.let { victim: RoutingProfile ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            containerColor = CARD,
            title = { Text(t("rt.deleteTitle"), color = TXT, fontSize = 16.sp) },
            text = { Text(victim.name + " · " + tf("rt.rulesN", "n" to victim.rules.size), color = MUTED, fontSize = 13.sp, fontFamily = MONO) },
            confirmButton = {
                TextButton(onClick = {
                    store.profiles.removeAll { x: RoutingProfile -> x.id == victim.id }
                    store.saveProfiles()
                    val moved = store.repairSelection()   // a selection that named it falls back
                    if (editId == victim.id) editId = store.profiles.firstOrNull()?.id ?: ""
                    confirmDelete = null
                    AppWork.touch()
                    AppWork.snack(if (moved && store.selection.isNotEmpty()) tf("srv.deletedNow", "name" to victim.name, "now" to selectionWord(store)) else tf("srv.deleted", "name" to victim.name))
                }) { Text(t("btn.delete"), color = BAD) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text(t("btn.cancel"), color = MUTED) } }
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
            .clickable(onClickLabel = t("rt.editProfile")) { onEdit() }
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
                        t("srv.inUse"), color = ON_PRIMARY, fontSize = 8.sp, fontFamily = MONO,
                        fontWeight = FontWeight.SemiBold, letterSpacing = 0.1.em, maxLines = 1,
                        modifier = Modifier.clip(RoundedCornerShape(4.dp)).background(PRIMARY).padding(horizontal = 5.dp, vertical = 3.dp)
                    )
                }
            }
            Text(
                tf("rt.rulesN", "n" to p.rules.size) + " · " + tf("rt.rest", "to" to targetWord(store, p.def, p)) + (if (dv != null) " " + tf("exit.via", "name" to targetWord(store, dv)) else ""),
                color = MUTED2, fontSize = 10.sp, fontFamily = MONO, maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
        IconButton(onClick = onUse) { Icon(Icons.Filled.CheckCircle, t("rt.useProfile"), tint = if (inUse) PRIMARY else MUTED) }
        IconButton(onClick = onShare) { Icon(Icons.Filled.Share, t("rt.shareProfile"), tint = TXT2) }
        Box {
            IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, t("a11y.more"), tint = MUTED) }
            DropdownMenu(menu, { menu = false }, modifier = Modifier.background(CARD)) {
                DropdownMenuItem(text = { Text(t("rt.duplicate"), color = TXT) }, onClick = { menu = false; onDuplicate() })
                if (onDelete != null) {
                    DropdownMenuItem(text = { Text(t("btn.delete"), color = BAD) }, onClick = { menu = false; onDelete() })
                }
            }
        }
    }
}

/** One rule's editor row: type, value, target, and — for a target that can take one — the base it rides on. */
@Composable private fun RuleEditor(store: Store, p: RoutingProfile, r: RouteRule, onChange: (RouteRule) -> Unit, onDelete: () -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        DropPick(t("rt.type"), listOf("domain" to t("rt.typeDomain"), "ip" to "IP", "port" to t("rt.typePort")), r.type) { nt: String -> onChange(r.copy(type = nt)) }
        Spacer(Modifier.weight(1f))
        IconButton(onClick = onDelete) { Icon(Icons.Filled.DeleteOutline, t("rt.deleteRule"), tint = BAD) }
    }
    // Saved when editing ends, not per keystroke (DraftField).
    DraftField(r.value, Modifier.fillMaxWidth(), placeholder = { Text(t("rt.valuePh"), fontSize = 11.sp) }) { nv: String -> onChange(r.copy(value = nv)) }
    DropPick("⚠ ${targetWord(store, r.target, p)}", targetOptionsFor(store, p), r.target) { t: String -> onChange(r.copy(target = t)) }
    when {
        r.target == RoutingProfiles.TARGET_BASE && p.base == null -> Text(t("rt.ruleNoBase"), color = BAD, fontSize = 11.sp)
        // left out, its traffic would follow the default — perhaps direct (RoutingProfiles.planRoutes)
        r.target == RoutingProfiles.TARGET_BASE && !store.targetExists(r.target, p) -> Text(t("rt.ruleBaseGone"), color = BAD, fontSize = 11.sp)
        !store.targetExists(r.target, p) -> Text(t("rt.targetGone"), color = BAD, fontSize = 11.sp)
    }
    // "exit at the base" IS the base: no via picker
    if (RoutingProfiles.takesVia(r.target)) {
        DropPick("⚠ " + tf("exit.via", "name" to targetWord(store, r.via)), viaOptions(store, p, r.target), r.via.ifEmpty { RoutingProfiles.VIA_INHERIT }) { v: String -> onChange(r.copy(via = v)) }
        val eff = RoutingProfiles.effectiveVia(r, p)
        if (eff != null && !store.targetExists(eff)) Text(t("rt.itsBaseGone"), color = BAD, fontSize = 11.sp)
    }
}

/**
 * Store.targetLabel in the app's language: the fixed words (direct, block, the
 * first server, exit at the base, a missing one) translated, a name as it is.
 * The parameter is not `t`: that is the dictionary.
 */
private fun targetWord(store: Store, target: String): String = when {
    target.isEmpty() -> t("tgt.first")
    target == "direct" -> t("tgt.direct")
    target == "block" -> t("tgt.block")
    target == "proxy" -> t("tgt.proxy")
    target == RoutingProfiles.TARGET_BASE -> "⚓ " + t("tgt.exitBase")
    else -> {
        val w = store.targetLabel(target)
        when (w) {
            "missing chain" -> t("tgt.missingChain")
            "missing group" -> t("chain.missingGroup")
            "missing server" -> t("chain.missingServer")
            else -> w
        }
    }
}

/** [target] as a target of [p]: "exit at the base" names the base it stands for (Store.targetLabel(t, p)). */
private fun targetWord(store: Store, target: String, p: RoutingProfile): String {
    if (target != RoutingProfiles.TARGET_BASE) return targetWord(store, target)
    val b = p.base ?: return "⚓ " + tf("tgt.exitBaseOf", "base" to t("tgt.noBase"))
    return "⚓ " + tf("tgt.exitBaseOf", "base" to targetWord(store, b))
}

/** A rule's or the default's targets in [p]: every target, and — while [p] has a base — "exit at the base" (it follows the base). */
private fun targetOptionsFor(store: Store, p: RoutingProfile): List<Pair<String, String>> {
    val all = targetOptionsFull(store)
    val base = p.base ?: return all
    // after Direct and Block: the words, then the servers and chains
    return all.take(3) + (RoutingProfiles.TARGET_BASE to "⚓ " + tf("tgt.exitBaseOf", "base" to targetWord(store, base))) + all.drop(3)
}

/** What a target can ride on: the profile's base, nothing, or any server or chain but itself. */
private fun viaOptions(store: Store, p: RoutingProfile, target: String): List<Pair<String, String>> = buildList {
    val base = p.base
    add(RoutingProfiles.VIA_INHERIT to (if (base != null) tf("rt.viaInherit", "base" to targetWord(store, base)) else t("rt.viaInheritNone")))
    add(RoutingProfiles.VIA_NONE to t("rt.viaNone"))
    targetOptions(store).filter { o: Pair<String, String> -> o.first != target }.forEach { o: Pair<String, String> -> add(o.first to tf("exit.via", "name" to o.second)) }
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
    if (vals.isEmpty()) return t("rt.noValue")
    // an app rule from a Windows profile: Android never says which app opened a connection (TunnelSetup.routingNotes)
    if (r.type == "process") return tf("rt.appRule", "apps" to vals.take(2).joinToString(", "))
    return vals.take(2).joinToString(", ") + (if (vals.size > 2) " +${vals.size - 2}" else "")
}

private fun ruleGlyph(type: String): String = when (type) {
    "domain" -> "🌐"
    "ip" -> "#"
    "port" -> ":"
    "process" -> "▣"
    else -> "•"
}

private fun targetGlyph(t: String): String = when {
    t == "direct" -> flowArrow()
    t == "block" -> "⛔"
    t.startsWith("chain:") -> "⛓"
    Groups.isGroupId(t) -> "⧉"
    else -> "▣"
}

/**
 * The profile as a vertical flow (spec §3, Android), in the order the
 * connection applies it (ConfigBuilder.buildAdvanced): Block ads, the
 * profile's rules, the local network, the routing mode's country bypass, then
 * everything else. A step of the profile's is its rules (consecutive ones to
 * the same place grouped) → the base they go through, when they do — it sits
 * between the phone and the target: the phone dials the base, the base the
 * target → where they go ("leaves here" at the base). The app's own steps are
 * dimmed and read-only. Then each base once, with every target through it. A
 * rule opens its editor; a server its edit sheet; a chain the chains screen.
 * What is gone is red, with what connecting does about it.
 */
@Composable private fun FlowList(store: Store, p: RoutingProfile, s: AppSettings, geo: Boolean, onRule: (Int) -> Unit, onNode: (String) -> Unit) {
    val lanes = RoutingProfiles.lanes(p) { t: String -> store.targetExists(t) }
    Text(t("rt.flow"), color = MUTED2, fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em)
    Text(t("rt.flowHint"), color = MUTED, fontSize = 11.sp)
    Spacer(Modifier.height(6.dp))
    // without the geo files the config has no geo rule at all (ConfigBuilder's `&& geo`)
    if (s.blockAds && geo) FlowAppRow("🚫", t("rt.ads"), t("tgt.block"), t("rt.tagApp"))
    lanes.filter { l: RoutingProfiles.Lane -> !l.isDefault }.forEach { l: RoutingProfiles.Lane -> FlowLane(store, p, l, onRule, onNode) }
    FlowAppRow("🏠", t("rt.lan"), t("tgt.direct"), t("rt.tagApp"))
    // the simple routing mode under the rules, when the profile applies it (its useMode)
    if (p.useMode && geo && s.routingMode == "bypass-ir") FlowAppRow("🇮🇷", t("rt.iranMode"), t("tgt.direct"), t("rt.tagMode"))
    if (p.useMode && geo && s.routingMode == "bypass-cn") FlowAppRow("🇨🇳", t("rt.chinaMode"), t("tgt.direct"), t("rt.tagMode"))
    lanes.filter { l: RoutingProfiles.Lane -> l.isDefault }.forEach { l: RoutingProfiles.Lane -> FlowLane(store, p, l, onRule, onNode) }
    val bases = RoutingProfiles.lanesByBase(lanes)
    if (bases.isNotEmpty()) {
        Spacer(Modifier.height(8.dp))
        Text(t("rt.bases"), color = MUTED2, fontSize = 9.sp, fontFamily = MONO, letterSpacing = 0.1.em)
        bases.forEach { e: Pair<String, List<RoutingProfiles.Lane>> ->
            val base = e.first
            Card(Modifier.fillMaxWidth().padding(vertical = 4.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(12.dp)) {
                Column(Modifier.padding(horizontal = 6.dp, vertical = 6.dp)) {
                    FlowNode("⚓", targetWord(store, base), AMBER, if (store.targetExists(base)) null else t("rt.goneRefused"), 0.dp) { onNode(base) }
                    e.second.forEach { l: RoutingProfiles.Lane ->
                        Text(
                            tf("rt.toTarget", "to" to targetWord(store, l.target)) + (if (l.isDefault) " " + t("rt.everythingElseParen") else ""),
                            color = MUTED, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.padding(start = 34.dp, top = 2.dp, bottom = 2.dp)
                        )
                    }
                }
            }
        }
    }
}

/**
 * One step of the profile's flow: its rules (or "everything else") → the base
 * they go through, when they do → where they go. A step at the base ("exit at
 * the base") reads rules → ⚓ the base → 🌐 leaves here; without a base it is
 * red, with what connecting does about it.
 */
@Composable private fun FlowLane(store: Store, p: RoutingProfile, lane: RoutingProfiles.Lane, onRule: (Int) -> Unit, onNode: (String) -> Unit) {
    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(12.dp)) {
        Column(Modifier.padding(horizontal = 6.dp, vertical = 6.dp)) {
            if (lane.isDefault) {
                FlowNode("★", t("rt.everythingElse"), TXT2, null, 0.dp, null)
            } else {
                lane.rules.forEach { i: Int ->
                    val r = p.rules[i]
                    FlowNode(ruleGlyph(r.type), ruleSummary(r), TXT2, null, 0.dp) { onRule(i) }
                }
            }
            // what connecting does about a step whose target is not there
            val missing = if (lane.isDefault) t("rt.missingRefused") else t("rt.missingSkipped")
            if (lane.target == RoutingProfiles.TARGET_BASE) {
                val base = p.base
                FlowArrow("↓", 12.dp)
                if (base == null) {
                    FlowNode("⚓", t("tgt.exitBase"), BAD, tf("rt.noBaseLane", "what" to missing), 12.dp, null)
                } else {
                    FlowNode("⚓", targetWord(store, base), AMBER, if (lane.targetMissing) tf("rt.baseGoneLane", "what" to missing) else null, 12.dp) { onNode(base) }
                    FlowArrow("↓", 24.dp)
                    FlowNode("🌐", t("rt.leavesHere"), PRIMARY, null, 24.dp, null)
                }
            } else {
                // the base first: the phone dials it, and it dials the target
                val via = lane.via
                if (via != null) {
                    FlowArrow(t("rt.through"), 12.dp)
                    FlowNode("⚓", targetWord(store, via), AMBER, if (lane.viaMissing) tf("rt.baseGoneLane", "what" to t("rt.missingRefused")) else null, 12.dp) { onNode(via) }
                }
                val indent = if (via != null) 24.dp else 12.dp
                FlowArrow("↓", indent)
                val target = if (lane.target.isEmpty() && lane.isDefault) (store.servers.firstOrNull()?.id ?: "direct") else lane.target
                FlowNode(targetGlyph(target), targetWord(store, target), PRIMARY, if (lane.targetMissing) tf("rt.goneLane", "what" to missing) else null, indent) { onNode(target) }
            }
        }
    }
}

/** One of the app's own rules in the flow: read-only, dimmed, tagged with where it comes from ("app", "mode"). */
@Composable private fun FlowAppRow(glyph: String, what: String, target: String, tag: String) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 3.dp).alpha(0.6f)
            .border(1.dp, STROKE, RoundedCornerShape(12.dp)).padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(glyph, fontSize = 13.sp, modifier = Modifier.width(24.dp))
        Text(what + " " + flowArrow() + " " + target, color = TXT2, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
        Text(
            tag.uppercase(), color = MUTED, fontSize = 8.sp, fontFamily = MONO, letterSpacing = 0.1.em, maxLines = 1,
            modifier = Modifier.border(1.dp, STROKE, RoundedCornerShape(4.dp)).padding(horizontal = 5.dp, vertical = 2.dp)
        )
    }
}

/** A routing link ready to hand over: what it is called, the text, and how many servers it carries. */
private class SharedText(val title: String, val text: String, val servers: Int)

/** A profile's share link (RouteShare), or null after saying why there is none. */
private fun profileShare(store: Store, p: RoutingProfile): SharedText? = try {
    val payload = RouteShare.profilePayload(p, store.servers.toList(), store.chains.toList()) { srv: ServerConfig -> LinkParser.buildShareLink(srv) }
    SharedText(tf("share.profile", "name" to p.name), RouteShare.encode(payload), payload.getJSONArray("servers").length())
} catch (e: Exception) {
    AppWork.snack(tf("share.cant", "name" to p.name, "msg" to (e.message ?: t("share.error"))))
    null
}

/** A chain's share link, or null after saying why there is none. */
private fun chainShare(store: Store, c: ChainConfig): SharedText? = try {
    val payload = RouteShare.chainPayload(c, store.servers.toList()) { srv: ServerConfig -> LinkParser.buildShareLink(srv) }
    SharedText(tf("share.chain", "name" to c.name), RouteShare.encode(payload), payload.getJSONArray("servers").length())
} catch (e: Exception) {
    AppWork.snack(tf("share.cant", "name" to c.name, "msg" to (e.message ?: t("share.error"))))
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
                    tf("share.warn", "n" to st.servers),
                    color = AMBER, fontSize = 12.sp
                )
                Spacer(Modifier.height(12.dp))
                if (bmp != null) Image(
                    bmp.asImageBitmap(), "QR",
                    Modifier.size(248.dp).clip(RoundedCornerShape(10.dp)).background(Color.White).padding(6.dp),
                    filterQuality = FilterQuality.None
                )
                else Text(t("qr.tooLarge"), color = MUTED, fontSize = 12.sp)
                Spacer(Modifier.height(8.dp))
                Text(tf("share.bytes", "n" to st.text.toByteArray(Charsets.UTF_8).size), color = MUTED2, fontSize = 10.sp, fontFamily = MONO)
                Spacer(Modifier.height(12.dp))
                Button(onClick = { copyConfigText(ctx, st.text); onDismiss() }, modifier = Modifier.fillMaxWidth()) { Text(t("btn.copyLink")) }
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
    val why = decoded.exceptionOrNull()?.message ?: t("imp.cantRead")
    AlertDialog(
        onDismissRequest = onClose,
        containerColor = CARD,
        title = {
            Text(
                when {
                    summary == null -> t("imp.cantImport")
                    summary.kind == RouteShare.KIND_CHAIN -> tf("imp.chainTitle", "name" to summary.name)
                    else -> tf("imp.profileTitle", "name" to summary.name)
                },
                color = TXT, fontSize = 16.sp
            )
        },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                if (summary == null) {
                    Text(why, color = BAD, fontSize = 13.sp)
                } else {
                    if (summary.kind == RouteShare.KIND_PROFILE) Text(tf("imp.rulesNew", "n" to summary.rules), color = TXT, fontSize = 13.sp)
                    Text(tf("imp.chainsN", "n" to summary.chains), color = TXT, fontSize = 13.sp)
                    Text(tf("imp.serversN", "new" to summary.serversNew, "old" to summary.serversExisting), color = TXT, fontSize = 13.sp)
                    if (summary.unreadable.isNotEmpty()) {
                        Spacer(Modifier.height(6.dp))
                        Text(t("imp.unreadable"), color = AMBER, fontSize = 12.sp)
                        summary.unreadable.forEach { u: String -> Text("· $u", color = AMBER, fontSize = 11.sp) }
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        t("imp.note"),
                        color = MUTED, fontSize = 11.sp
                    )
                }
            }
        },
        confirmButton = {
            if (summary != null && payload != null) {
                TextButton(onClick = { importRouting(store, payload); onClose() }) { Text(t("imp.import"), color = PRIMARY) }
            }
        },
        dismissButton = { TextButton(onClick = onClose) { Text(if (summary == null) t("btn.close") else t("btn.cancel"), color = MUTED) } }
    )
}

/** Take a decoded routing link into the store (RouteShare.applyImport) and say what came of it. */
private fun importRouting(store: Store, payload: JSONObject) {
    val r = try {
        RouteShare.applyImport(payload, store.servers.toList(), store.chains.toList(), store.profiles.toList(),
            { l: String -> RouteShare.parseServer(l) }, { srv: ServerConfig -> SubRefresh.strictIdentity(srv) }, { prefix: String -> newId(prefix) })
    } catch (e: Exception) {
        AppWork.snack(tf("imp.nothing", "why" to (e.message ?: t("imp.linkUnread"))))
        return
    }
    store.applyImported(r)
    if (store.selection.isEmpty()) r.servers.firstOrNull()?.let { srv: ServerConfig -> store.saveSelection(srv.id) }
    val pid = r.profileId
    if (pid != null) RoutingUi.focus = pid
    val what = if (pid != null) "🧭 ${store.profileById(pid)?.name ?: t("imp.theProfile")}" else t("imp.theChain")
    val hint = if (pid != null && !store.settings.advancedRouting) " — " + t("imp.turnOn") else ""
    AppWork.snack(tf("imp.done", "what" to what, "servers" to r.addedServers, "chains" to r.addedChains) + hint)
    AppWork.touch()
}

/* ================================ SETTINGS ================================ */
@Composable
private fun SettingsScreen(store: Store, bump: () -> Unit, back: () -> Unit) {
    val ctx = LocalContext.current
    var s by remember { mutableStateOf(store.settings) }
    fun save(n: AppSettings) { s = n; store.saveSettings(n); bump() }
    Screen(t("set.title"), back, {}) {
        ApplyBar(store, s)
        // The app's language: Persian (right to left, the default) or English.
        // Saved with the settings; Store.saveSettings hands it to I18n, whose
        // Compose state redraws every screen at once.
        Text(t("set.lang"), color = TXT, fontWeight = FontWeight.Bold)
        Row(verticalAlignment = Alignment.CenterVertically) {
            listOf(I18n.FA to "فارسی", I18n.EN to "English").forEach { (v, l) ->
                Row(Modifier.clickable { save(s.copy(lang = v)) }.padding(end = 14.dp), verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(I18n.norm(s.lang) == v, { save(s.copy(lang = v)) }); Text(l, color = TXT)
                }
            }
        }
        Text(t("set.langHint"), color = MUTED, fontSize = 11.sp)
        HorizontalDivider(Modifier.padding(vertical = 10.dp), color = STROKE)
        Text(t("set.portsDns"), color = TXT, fontWeight = FontWeight.Bold)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { NumFld(t("set.socks"), s.socksPort, Modifier.weight(1f)) { save(s.copy(socksPort = it)) }; NumFld(t("set.http"), s.httpPort, Modifier.weight(1f)) { save(s.copy(httpPort = it)) } }
        // The managed resolver plan (DnsPlan.kt, the desktop's dnsBuilder.js).
        // Typed freely, parsed only when the user leaves the field: parsing per
        // keystroke ate the comma (and the focus) after the first server.
        SwitchRow(t("set.dnsManaged"), s.dnsManaged) { save(s.copy(dnsManaged = it)) }
        Text(if (s.dnsManaged) t("set.dnsOn")
             else t("set.dnsOff"), color = MUTED, fontSize = 11.sp)
        DraftField(s.dnsRemote.joinToString(","), Modifier.fillMaxWidth(), label = { Text(t("set.dnsRemote")) }) { raw ->
            val list = raw.split(",").map { d -> d.trim() }.filter { d -> d.isNotEmpty() }
            save(s.copy(dnsRemote = list.ifEmpty { DnsPlan.DEFAULT_REMOTE }))   // empty field = keep the defaults
        }
        DraftField(s.dnsDirect.joinToString(","), Modifier.fillMaxWidth(), label = { Text(t("set.dnsDirect")) }) { raw ->
            val list = raw.split(",").map { d -> d.trim() }.filter { d -> d.isNotEmpty() }
            save(s.copy(dnsDirect = list.ifEmpty { DnsPlan.DEFAULT_DIRECT_IR }))
        }
        DropPick(t("set.logLevel"), listOf("none", "error", "warning", "info", "debug").map { it to it }, s.logLevel) { save(s.copy(logLevel = it)) }
        SwitchRow("IPv6", s.ipv6) { save(s.copy(ipv6 = it)) }
        SwitchRow(t("set.autoConnect"), s.autoConnect) { save(s.copy(autoConnect = it)) }
        Text(
            if (s.autoConnect) t("set.autoConnectOn")
            else t("set.autoConnectOff"),
            color = MUTED, fontSize = 11.sp
        )
        HorizontalDivider(Modifier.padding(vertical = 10.dp), color = STROKE)
        Text(t("set.core"), color = TXT, fontWeight = FontWeight.Bold)
        // The default for configs that do not name a core of their own. A chain,
        // pool or advanced plan has no single owner, so this is what decides it —
        // unless one of its servers asks for PattN, which wins (EngineChoice.kt).
        val pattnHere = remember { XrayPattnCore.available(ctx) }
        DropPick(
            t("set.defaultCore"),
            listOf("xray" to t("set.coreXray"), "xray-pattn" to t("set.corePattn")),
            s.defaultEngine
        ) { save(s.copy(defaultEngine = it)) }
        Text(
            if (!pattnHere) t("set.noPattn")
            else t("set.pattnHint"),
            color = MUTED, fontSize = 11.sp
        )
        // What this APK carries, as the cores themselves say it — off the main
        // thread, since PattN is asked by running it. Android runs no core an
        // app downloads, so these change only with a newer IRNetFree.
        val cores by produceState(coresKnown.ifEmpty { "…" }) {
            if (coresKnown.isEmpty()) coresKnown = withContext(Dispatchers.IO) { coresLine(ctx) }
            value = coresKnown
        }
        Text(tf("set.cores", "list" to cores), color = MUTED, fontSize = 11.sp, fontFamily = MONO, modifier = Modifier.padding(top = 6.dp))
        // Mux (Mux.kt, spec §4). Its own key, like LAN sharing — not in this
        // screen's copy of AppSettings; read by the next connect.
        var mux by remember { mutableStateOf(store.muxMode) }
        // touch(): the bar above names a mode the running connection does not carry (SettingsApply)
        fun pickMux(v: String) { store.muxMode = v; mux = v; AppWork.touch() }
        Text(t("set.mux"), color = TXT, modifier = Modifier.padding(top = 10.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            listOf(Mux.AUTO to t("mux.auto"), Mux.ON to t("mux.on"), Mux.OFF to t("mux.off")).forEach { (v, l) ->
                Row(Modifier.clickable { pickMux(v) }.padding(end = 14.dp), verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(mux == v, { pickMux(v) }); Text(l, color = TXT)
                }
            }
        }
        Text(muxHelp(mux), color = MUTED, fontSize = 11.sp)
        HorizontalDivider(Modifier.padding(vertical = 10.dp), color = STROKE)
        Text(t("set.perApp"), color = TXT, fontWeight = FontWeight.Bold)
        listOf("off" to t("set.perAppOff"), "allow" to t("set.perAppAllow"), "disallow" to t("set.perAppDisallow")).forEach { (v, l) ->
            Row(Modifier.fillMaxWidth().clickable { save(s.copy(perAppMode = v)) }, verticalAlignment = Alignment.CenterVertically) { RadioButton(s.perAppMode == v, { save(s.copy(perAppMode = v)) }); Text(l, color = TXT) }
        }
        if (s.perAppMode != "off") AppPicker(s.perApps) { save(s.copy(perApps = it)) }
        Text(t("set.perAppNote"),
            color = MUTED, fontSize = 11.sp)
        val lockdown by VpnState.lockdown.collectAsState()
        if (lockdown && s.perAppMode != "off")
            Text(t("set.lockdown"), color = AMBER, fontSize = 11.sp)
        LanShareSection(store)
    }
}

/** Settings → Mux: one line of help, for the choice it is on (Off is the default). */
private fun muxHelp(mode: String): String = when (mode) {
    Mux.AUTO -> t("mux.helpAuto")
    Mux.ON -> t("mux.helpOn")
    else -> t("mux.helpOff")
}

/**
 * Settings' cores line once worked out: the cores inside an APK do not change
 * while it runs, and every setting saved rebuilds the screen (no "…" flash).
 */
private var coresKnown = ""

/**
 * "Cores in this app: Xray 26.10.10 · Xray-PattN 26.10.13 · sing-box —" — the
 * in-process core's own answer (Libv2ray.checkVersionX, "Lib v…, Xray-core
 * v26.10.10", trimmed to its number) and PattN's `version`; "—" for a core that
 * is not bundled here or cannot say (sing-box has no version call in this app).
 * Blocking: PattN is run once.
 */
private fun coresLine(ctx: Context): String {
    val num = Regex("""\d+\.\d+\.\d+""")
    val xray = XrayCore.version().let { v -> num.find(v)?.value ?: v.ifBlank { "—" } }
    val pattn = XrayPattnCore.version(ctx).ifBlank { "—" }
    return "Xray $xray · Xray-PattN $pattn · sing-box —"
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
    OutlinedTextField(q, { q = it }, Modifier.fillMaxWidth(), placeholder = { Text(t("set.searchApps")) }, singleLine = true, colors = tfColors())
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
    Screen(t("logs.title"), back, { IconButton(onClick = { VpnState.clearLog() }) { Icon(Icons.Filled.DeleteSweep, t("logs.clear"), tint = MUTED) } }) {
        if (log.isEmpty()) EmptyHint(t("logs.empty"))
        // the log is English and reads left to right in either language
        LtrBlock { SelectionContainer { Column { log.forEach { Text(it, color = Color(0xFFB6C2D4), fontSize = 11.sp) } } } }
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
        while (connectedSince > 0) {
            if (!VpnState.uiVisible.value) VpnState.uiVisible.first { v: Boolean -> v }
            elapsed = System.currentTimeMillis() - connectedSince; delay(1000)
        }
        elapsed = 0L
    }
    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        TopBar(t("more.title")) {}
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 16.dp)) {
            Card(Modifier.fillMaxWidth().padding(bottom = 10.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                Row(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(t("more.advanced"), color = TXT, fontWeight = FontWeight.Medium)
                        Text(t("more.advancedSub"), color = MUTED, fontSize = 11.sp)
                    }
                    Switch(s.advancedMode, { v -> s = s.copy(advancedMode = v); store.saveSettings(s); bump() },
                        colors = SwitchDefaults.colors(checkedThumbColor = ON_PRIMARY, checkedTrackColor = PRIMARY, uncheckedThumbColor = MUTED, uncheckedTrackColor = CARD2, uncheckedBorderColor = STROKE))
                }
            }
            val rows = buildList {
                if (s.advancedMode) {
                    add(MoreRow("chains", t("chain.screen"), t("more.chainsSub"), "${store.chains.size} · ${store.groups.size}", Icons.Filled.Link))
                    add(MoreRow("pool", t("pool.title"), t("more.poolSub"), "${store.pool.size}", Icons.Filled.Hub))
                    add(MoreRow("routing", t("rt.title"), if (s.advancedRouting) t("more.routingAdvanced") else routingModeLabel(s.routingMode), if (s.advancedRouting) tf("more.profiles", "n" to store.profiles.size) else "", Icons.Filled.CallSplit))
                }
                add(MoreRow("settings", t("set.title"), t("more.settingsSub"), "", Icons.Filled.Settings))
                if (s.advancedMode) add(MoreRow("logs", t("logs.title"), t("more.logsSub"), "", Icons.Filled.Article))
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
                        Icon(Icons.Filled.ChevronRight, null, tint = MUTED2, modifier = Modifier.mirrorRtl())
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
            Text(cores.joinToString(" · ").ifEmpty { t("more.noCore") }, color = MUTED2, fontSize = 10.sp, fontFamily = MONO)
            if (connectedSince > 0) Text(tf("more.uptime", "time" to fmtDuration(elapsed)), color = MUTED2, fontSize = 10.sp, fontFamily = MONO)
            Spacer(Modifier.height(16.dp))
        }
    }
}

private class MoreRow(val key: String, val title: String, val sub: String, val meta: String, val icon: ImageVector)

private fun routingModeLabel(mode: String): String = when (mode) {
    "bypass-ir" -> t("mode.bypassIr")
    "bypass-cn" -> t("mode.bypassCn")
    "direct" -> t("mode.direct")
    else -> t("mode.global")
}

/* ================================ shared ================================ */
@Composable private fun TopBar(title: String, back: (() -> Unit)? = null, actions: @Composable RowScope.() -> Unit) {
    Row(Modifier.fillMaxWidth().padding(horizontal = if (back == null) 16.dp else 8.dp, vertical = if (back == null) 12.dp else 8.dp), verticalAlignment = Alignment.CenterVertically) {
        if (back != null) IconButton(onClick = back) { Icon(Icons.Filled.ArrowBack, t("a11y.back"), tint = TXT, modifier = Modifier.mirrorRtl()) }
        Text(title, color = TXT, fontSize = 22.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f)); actions()
    }
}
@Composable private fun Screen(title: String, back: () -> Unit, actions: @Composable RowScope.() -> Unit, content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = back) { Icon(Icons.Filled.ArrowBack, t("a11y.back"), tint = TXT, modifier = Modifier.mirrorRtl()) }
            Text(title, color = TXT, fontSize = 20.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f)); actions()
        }
        Column(Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()).imePadding().padding(horizontal = 16.dp), content = content)
    }
}
/**
 * Connected, and the settings changed since the connect in ways the running
 * tunnel does not carry (SettingsApply — the core has no hot reload): what
 * changed, said by name, and a Reconnect. [now]: the settings as the screen
 * holds them (each screen saves its own copy); the Mux mode, the profile and
 * the chains the connection runs are read from the store as it is now.
 */
@Composable private fun ApplyBar(store: Store, now: AppSettings) {
    val ctx = LocalContext.current
    observeStore()
    val state by VpnState.state.collectAsState()
    val applied by VpnState.applied.collectAsState()
    if (state != ConnState.CONNECTED) return
    val keys = SettingsApply.pending(applied, now, applied?.profile?.let { p: RoutingProfile -> store.profileById(p.id) }, store.muxMode) { id: String ->
        store.chainById(id)?.let { c: ChainConfig -> SettingsApply.ChainNow(c.name, store.chainMembers(c).map { m: ServerConfig -> m.id }) }
    }
    if (keys.isEmpty()) return
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp).clip(RoundedCornerShape(10.dp)).background(CARD2).padding(start = 12.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically) {
        Text(tf("apply.pending", "list" to keys.joinToString(t("sep.list")) { k: String -> applyName(k) }), color = AMBER, fontSize = 12.sp, modifier = Modifier.weight(1f))
        TextButton(onClick = { AppWork.reconnect(ctx, store) }) { Text(t("apply.reconnect"), color = PRIMARY) }
    }
}

/** SettingsApply.pending's English names, in the app's language (SettingsApply keeps the English its tests read). */
private val APPLY_NAMES: Map<String, String> = mapOf(
    "Routing mode" to "rt.mode",
    "Block ads" to "rt.blockAds",
    "Sniffing" to "rt.sniffing",
    "Custom rules" to "apply.customRules",
    "Advanced routing" to "rt.advanced",
    "Routing mode under the rules" to "apply.useMode",
    "Per-app routing" to "set.perApp",
    "DNS" to "apply.dns",
    "IPv6" to "apply.ipv6",
    "Log level" to "set.logLevel",
    "Default core" to "set.defaultCore",
    "Local ports" to "apply.localPorts",
    "Mux" to "set.mux"
)

/** One of SettingsApply.pending's names on screen; a name this table does not know stays as it is. */
private fun applyName(name: String): String {
    val key = APPLY_NAMES[name]
    if (key != null) return t(key)
    if (name == "Routing profile (deleted)") return t("apply.profileDeleted")
    if (name == "Chain (deleted)") return t("apply.chainDeleted")
    if (name.startsWith("Chain “") && name.endsWith("”")) return tf("apply.chain", "name" to name.removePrefix("Chain “").removeSuffix("”"))
    if (name.startsWith("Routing profile “") && name.endsWith("”")) {
        return tf("apply.profile", "name" to name.removePrefix("Routing profile “").removeSuffix("”"))
    }
    return name
}

/** Left to right whatever the language: addresses, keys, links, JSON, logs and the brand read that way. */
@Composable private fun LtrBlock(content: @Composable () -> Unit) {
    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr, content = content)
}

/** Flips a directional icon (an arrow, a chevron) when the layout runs right to left. */
@Composable private fun Modifier.mirrorRtl(): Modifier =
    if (LocalLayoutDirection.current == LayoutDirection.Rtl) this.scale(scaleX = -1f, scaleY = 1f) else this

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

/** Every server, chain and group a picker offers — a routing target, a base, a pool exit: a group by its bare id, "⧉ name" (Groups.kt). */
private fun targetOptions(store: Store): List<Pair<String, String>> = buildList { store.servers.forEach { add(it.id to it.name) }; store.chains.filter { store.chainReady(it) }.forEach { add("chain:${it.id}" to "⛓ ${it.name}") }; addAll(groupOptions(store)) }
private fun targetOptionsFull(store: Store): List<Pair<String, String>> = buildList { add("proxy" to t("tgt.proxy")); add("direct" to t("tgt.direct")); add("block" to t("tgt.block")); addAll(targetOptions(store)) }
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
private fun badge(p: String) = when (p) { "vless" -> "VLESS"; "vmess" -> "VMESS"; "trojan" -> "TROJAN"; "shadowsocks" -> "SS"; "wireguard" -> "WG"; "hysteria2" -> "HY2"; "masque" -> "MASQUE"; "socks" -> "SOCKS"; "http" -> "HTTP"; else -> p.uppercase() }
private fun flag(cc: String): String { if (cc.length != 2) return "🏳"; val base = 0x1F1E6; return String(Character.toChars(base + (cc[0].uppercaseChar() - 'A'))) + String(Character.toChars(base + (cc[1].uppercaseChar() - 'A'))) }
