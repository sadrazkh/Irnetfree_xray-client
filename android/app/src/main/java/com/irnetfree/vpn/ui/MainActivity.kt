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
import androidx.compose.animation.animateColorAsState
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
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
import com.irnetfree.vpn.vpn.VpnState
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

/* ---------------- palette ---------------- */
private val BG = Color(0xFF0A0E17)
private val BG2 = Color(0xFF0E1420)
private val CARD = Color(0xFF141A24)
private val CARD2 = Color(0xFF1B2330)
private val STROKE = Color(0xFF232D3B)
private val PRIMARY = Color(0xFF5B8DEF)
private val GREEN = Color(0xFF34D399)
private val AMBER = Color(0xFFE3B85A)
private val TXT = Color(0xFFE6EDF3)
private val MUTED = Color(0xFF8B98A9)
private val BAD = Color(0xFFF07178)

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
    MaterialTheme(colorScheme = darkColorScheme(primary = PRIMARY, secondary = GREEN, background = BG, surface = CARD,
        onPrimary = Color.White, onBackground = TXT, onSurface = TXT)) {
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
private enum class Tab(val label: String, val icon: ImageVector) {
    HOME("Home", Icons.Filled.Home),
    SERVERS("Servers", Icons.Filled.Dns),
    SUBS("Subs", Icons.Filled.CloudDownload),
    POOL("Pool", Icons.Filled.Hub),
    MORE("More", Icons.Filled.Menu)
}

@Composable
private fun App(store: Store) {
    var tab by remember { mutableStateOf(Tab.HOME) }
    var more by remember { mutableStateOf<String?>(null) }
    var rev by remember { mutableIntStateOf(0) }
    val bump: () -> Unit = { rev++ }

    Scaffold(containerColor = BG, bottomBar = {
        NavigationBar(containerColor = BG2, tonalElevation = 0.dp) {
            Tab.values().forEach { tb ->
                NavigationBarItem(selected = tab == tb, onClick = { tab = tb; more = null },
                    icon = { Icon(tb.icon, null) }, label = { Text(tb.label, fontSize = 11.sp) },
                    colors = NavigationBarItemDefaults.colors(selectedIconColor = PRIMARY, selectedTextColor = PRIMARY,
                        indicatorColor = CARD2, unselectedIconColor = MUTED, unselectedTextColor = MUTED))
            }
        }
    }) { pad ->
        Box(Modifier.padding(bottom = pad.calculateBottomPadding()).fillMaxSize()) {
            key(rev) {
                when (tab) {
                    Tab.HOME -> HomeScreen(store, bump)
                    Tab.SERVERS -> ServersScreen(store, bump)
                    Tab.SUBS -> SubsScreen(store, bump)
                    Tab.POOL -> PoolScreen(store, bump)
                    Tab.MORE -> when (more) {
                        "chains" -> ChainsScreen(store, bump) { more = null }
                        "routing" -> RoutingScreen(store, bump) { more = null }
                        "settings" -> SettingsScreen(store, bump) { more = null }
                        "logs" -> LogsScreen { more = null }
                        else -> MoreMenu { more = it }
                    }
                }
            }
        }
    }
}

/* ================================ HOME ================================ */
@Composable
private fun HomeScreen(store: Store, bump: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val state by VpnState.state.collectAsState()
    val err by VpnState.lastError.collectAsState()
    val traffic by VpnState.traffic.collectAsState()
    var ip by remember { mutableStateOf("—") }
    var ping by remember { mutableStateOf("—") }
    var latency by remember { mutableStateOf("—") }
    var pickerOpen by remember { mutableStateOf(false) }
    var homeSheet by remember { mutableStateOf<String?>(null) }
    val haptic = LocalHapticFeedback.current
    val connectedSince by VpnState.connectedSince.collectAsState()
    var elapsed by remember { mutableStateOf(0L) }
    LaunchedEffect(connectedSince) {
        while (connectedSince > 0) { elapsed = System.currentTimeMillis() - connectedSince; delay(1000) }
        elapsed = 0L
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

    val ringColor by animateColorAsState(when (state) {
        ConnState.CONNECTED -> GREEN; ConnState.CONNECTING -> AMBER; ConnState.ERROR -> BAD; else -> PRIMARY
    }, label = "ring")
    val pulse by rememberInfiniteTransition(label = "pulse").animateFloat(0.10f, 0.32f,
        infiniteRepeatable(tween(1000), RepeatMode.Reverse), label = "glow")
    val glow = if (state == ConnState.CONNECTING || state == ConnState.CONNECTED) pulse else 0.14f

    Column(Modifier.fillMaxSize().statusBarsPadding().verticalScroll(rememberScrollState()).padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text("IR", color = TXT, fontWeight = FontWeight.Black, fontSize = 20.sp)
            Text("NetFree", color = PRIMARY, fontWeight = FontWeight.Black, fontSize = 20.sp)
            Spacer(Modifier.weight(1f))
            IconButton(onClick = { homeSheet = "import" }) { Icon(Icons.Filled.AddCircle, "add config", tint = PRIMARY) }
            StatusPill(state)
        }
        Spacer(Modifier.height(24.dp))
        Box(contentAlignment = Alignment.Center, modifier = Modifier.size(210.dp)) {
            Box(Modifier.size(210.dp).clip(CircleShape).background(Brush.radialGradient(listOf(ringColor.copy(alpha = glow), Color.Transparent))))
            Box(Modifier.size(168.dp).clip(CircleShape).border(2.dp, ringColor.copy(alpha = 0.5f), CircleShape)
                .background(Brush.verticalGradient(listOf(CARD2, CARD))).clickable { onPower() }, contentAlignment = Alignment.Center) {
                if (state == ConnState.CONNECTING) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        CircularProgressIndicator(color = ringColor, strokeWidth = 3.dp, modifier = Modifier.size(44.dp))
                        Spacer(Modifier.height(8.dp)); Text("Connecting…", color = ringColor, fontSize = 12.sp)
                    }
                } else {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Filled.PowerSettingsNew, null, tint = ringColor, modifier = Modifier.size(56.dp))
                        Spacer(Modifier.height(6.dp))
                        Text(when (state) { ConnState.CONNECTED -> "Connected"; ConnState.ERROR -> "Error"; else -> "Tap to connect" },
                            color = ringColor, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        if (state == ConnState.CONNECTED) Text(fmtDuration(elapsed), color = MUTED, fontSize = 12.sp)
                    }
                }
            }
        }
        Spacer(Modifier.height(20.dp))
        val selSrv = store.serverById(store.selection)
        Card(Modifier.fillMaxWidth().clickable { pickerOpen = true }, colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(16.dp)) {
            Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                if (selSrv != null) ProtoBadge(selSrv.protocol) else Icon(Icons.Filled.Bolt, null, tint = PRIMARY, modifier = Modifier.size(40.dp))
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text("Selected exit", color = MUTED, fontSize = 12.sp)
                    Text(if (selSrv != null) selSrv.name else store.selectionLabel(), color = TXT, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    if (selSrv != null) Text("${selSrv.address}:${selSrv.port}", color = MUTED, fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                Icon(Icons.Filled.UnfoldMore, null, tint = MUTED)
            }
        }
        Spacer(Modifier.height(14.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatCard(Modifier.weight(1f), Icons.Filled.SouthWest, "Download", fmtSpeed(traffic.rxSpeed), fmtBytes(traffic.rxBytes), GREEN)
            StatCard(Modifier.weight(1f), Icons.Filled.NorthEast, "Upload", fmtSpeed(traffic.txSpeed), fmtBytes(traffic.txBytes), PRIMARY)
        }
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            InfoCard(Modifier.weight(1f), "Egress IP", ip)
            InfoCard(Modifier.weight(1f), "Real delay", latency)
        }
        Spacer(Modifier.height(12.dp))
        // clear test buttons
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = {
                val srv = selectedServer() ?: return@OutlinedButton
                ping = "…"; scope.launch { val ms = withContext(Dispatchers.IO) { Diagnostics.tcpPing(srv.address, srv.port) }; ping = if (ms >= 0) "${ms}ms" else "fail" }
            }, modifier = Modifier.weight(1f)) { Text("Ping " + if (ping != "—") ping else "") }
            OutlinedButton(onClick = {
                val sp = if (state == ConnState.CONNECTED) store.settings.socksPort else null
                latency = "…"; scope.launch { val ms = withContext(Dispatchers.IO) { Diagnostics.httpLatency(sp) }; latency = if (ms >= 0) "${ms}ms" else "fail" }
            }, modifier = Modifier.weight(1f)) { Text("Test") }
            OutlinedButton(onClick = {
                val sp = if (state == ConnState.CONNECTED) store.settings.socksPort else null
                ip = "…"; scope.launch { val r = withContext(Dispatchers.IO) { Diagnostics.ipInfo(sp) }; ip = if (r.ok) "${flag(r.countryCode)} ${r.ip}" else "fail" }
            }, modifier = Modifier.weight(1f)) { Text("IP") }
        }
        Text("«Test» measures real latency through the tunnel; «IP» shows your exit IP — both prove it works.", color = MUTED, fontSize = 11.sp, modifier = Modifier.padding(top = 8.dp))
        if (state == ConnState.ERROR && err.isNotBlank()) { Spacer(Modifier.height(12.dp)); Text(err, color = BAD, fontSize = 12.sp) }
        Spacer(Modifier.height(16.dp))
    }
    if (pickerOpen) SelectionSheet(store, { pickerOpen = false }) { pickerOpen = false; bump() }
    AddConfigSheets(store, homeSheet, { homeSheet = it }, bump)
}

private fun doConnect(ctx: Context, store: Store) {
    try { VpnState.set(ConnState.CONNECTING, store.selectionLabel()); XrayVpnService.connect(ctx, store) }
    catch (e: Exception) { VpnState.set(ConnState.ERROR, error = e.message ?: "connect failed") }
}

@Composable private fun StatusPill(state: ConnState) {
    val (c, t) = when (state) { ConnState.CONNECTED -> GREEN to "Connected"; ConnState.CONNECTING -> AMBER to "Connecting"; ConnState.ERROR -> BAD to "Error"; else -> MUTED to "Off" }
    Row(Modifier.clip(RoundedCornerShape(50)).background(c.copy(alpha = 0.15f)).padding(horizontal = 12.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(8.dp).clip(CircleShape).background(c)); Spacer(Modifier.width(6.dp)); Text(t, color = c, fontSize = 12.sp)
    }
}
@Composable private fun StatCard(modifier: Modifier, icon: ImageVector, label: String, speed: String, total: String, tint: Color) {
    Card(modifier, colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) { Icon(icon, null, tint = tint, modifier = Modifier.size(18.dp)); Spacer(Modifier.width(6.dp)); Text(label, color = MUTED, fontSize = 12.sp) }
            Spacer(Modifier.height(6.dp)); Text(speed, color = TXT, fontWeight = FontWeight.Bold); Text(total, color = MUTED, fontSize = 11.sp)
        }
    }
}
@Composable private fun InfoCard(modifier: Modifier, label: String, value: String) {
    Card(modifier, colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.padding(14.dp)) { Text(label, color = MUTED, fontSize = 12.sp); Spacer(Modifier.height(4.dp)); Text(value, color = TXT, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis) }
    }
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
                    if (store.selection == id) Icon(Icons.Filled.CheckCircle, null, tint = GREEN)
                }
            }
        }
    }
}

/* ================================ SERVERS ================================ */
@Composable
private fun ServersScreen(store: Store, bump: () -> Unit) {
    val scope = rememberCoroutineScope()
    var q by remember { mutableStateOf("") }
    var sheet by remember { mutableStateOf<String?>(null) }
    var editId by remember { mutableStateOf<String?>(null) }
    val tests = remember { mutableStateMapOf<String, String>() }
    val testMutex = remember { Mutex() }
    // One test at a time; the UI shows the current phase (download vs upload).
    suspend fun testOne(s: ServerConfig) = testMutex.withLock {
        tests[s.id] = "starting…"
        val h = withContext(Dispatchers.IO) { XrayTester.start(s) }
        if (h == null) { tests[s.id] = "× core error"; return@withLock }
        try {
            val ping = withContext(Dispatchers.IO) { Diagnostics.tcpPing(s.address, s.port) }
            tests[s.id] = "⚡${msLabel(ping)}  ↓ testing download…"
            val down = withContext(Dispatchers.IO) { Diagnostics.httpLatency(h.port) }
            tests[s.id] = "⚡${msLabel(ping)}  ↓${msLabel(down)}  ↑ testing upload…"
            val up = withContext(Dispatchers.IO) { Diagnostics.uploadTest(h.port) }
            tests[s.id] = "⚡${msLabel(ping)}  ↓${msLabel(down)}  ↑${msLabel(up)}"
        } finally { withContext(Dispatchers.IO) { XrayTester.stop(h) } }
    }
    fun runTest(s: ServerConfig) { scope.launch { testOne(s) } }
    fun testAll() { scope.launch { for (s in store.servers.toList()) testOne(s) } }

    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        TopBar("Servers") {
            IconButton(onClick = { testAll() }) { Icon(Icons.Filled.Speed, "test all", tint = PRIMARY) }
            IconButton(onClick = { sheet = "import" }) { Icon(Icons.Filled.Add, "add", tint = PRIMARY) }
        }
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).imePadding().padding(horizontal = 16.dp)) {
            OutlinedTextField(q, { q = it }, Modifier.fillMaxWidth(), placeholder = { Text("Search…") }, leadingIcon = { Icon(Icons.Filled.Search, null) }, singleLine = true, shape = RoundedCornerShape(14.dp), colors = tfColors())
            Row(Modifier.padding(vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(onClick = { sheet = "import" }, label = { Text("+ Link/Sub") })
                AssistChip(onClick = { sheet = "wg" }, label = { Text("+ WireGuard") })
                AssistChip(onClick = { sheet = "proxy" }, label = { Text("+ SOCKS/HTTP") })
            }
            if (store.servers.isEmpty()) EmptyHint("No servers yet — tap + to add one.")
            store.servers.filter { it.name.contains(q, true) || it.address.contains(q, true) }.forEach { s ->
                ConfigCard(s, store.selection == s.id, tests[s.id],
                    onSelect = { store.saveSelection(s.id); bump() },
                    onTest = { runTest(s) },
                    onEdit = { editId = s.id },
                    onDelete = { store.deleteServer(s.id); bump() })
            }
            Spacer(Modifier.height(16.dp))
        }
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
                val r = withContext(Dispatchers.IO) { Subscriptions.fetch(sub.url) }
                store.servers.removeAll { it.subId == sub.id }
                val tagged = r.servers.map { it.copy(subId = sub.id) }
                store.servers.addAll(tagged); store.saveServers()
                if (tagged.isNotEmpty() && store.selection.isEmpty()) store.saveSelection(store.servers.first().id)
                val idx = store.subs.indexOfFirst { it.id == sub.id }
                if (idx >= 0) store.subs[idx] = sub.copy(serverCount = tagged.size, lastUpdated = System.currentTimeMillis(),
                    upload = r.usage?.upload ?: 0, download = r.usage?.download ?: 0, total = r.usage?.total ?: 0, expire = r.usage?.expire ?: 0)
                store.saveSubs(); Toast.makeText(ctx, "Subscription: ${tagged.size} servers added", Toast.LENGTH_SHORT).show(); bump()
            } catch (e: Exception) { Toast.makeText(ctx, "Subscription error: ${e.message}", Toast.LENGTH_LONG).show(); bump() }
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

@Composable private fun ConfigCard(s: ServerConfig, selected: Boolean, result: String?, onSelect: () -> Unit, onTest: () -> Unit, onEdit: () -> Unit, onDelete: () -> Unit) {
    Card(Modifier.fillMaxWidth().padding(vertical = 5.dp).clickable { onSelect() }, colors = CardDefaults.cardColors(containerColor = if (selected) CARD2 else CARD), shape = RoundedCornerShape(14.dp),
        border = if (selected) androidx.compose.foundation.BorderStroke(1.dp, GREEN) else null) {
        Row(Modifier.padding(start = 14.dp, top = 8.dp, bottom = 8.dp, end = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            ProtoBadge(s.protocol); Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(s.name, color = TXT, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text("${s.address}:${s.port}", color = MUTED, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                if (result != null) {
                    val rc = when { result.contains("testing") || result == "starting…" -> AMBER; result.contains("×") -> BAD; else -> GREEN }
                    Text(result, color = rc, fontSize = 12.sp, maxLines = 1, fontWeight = FontWeight.Medium)
                }
            }
            IconButton(onClick = onTest, modifier = Modifier.size(38.dp)) { Icon(Icons.Filled.Speed, "test", tint = PRIMARY, modifier = Modifier.size(20.dp)) }
            IconButton(onClick = onEdit, modifier = Modifier.size(38.dp)) { Icon(Icons.Filled.Edit, "edit", tint = MUTED, modifier = Modifier.size(20.dp)) }
            IconButton(onClick = onDelete, modifier = Modifier.size(38.dp)) { Icon(Icons.Filled.DeleteOutline, "del", tint = BAD, modifier = Modifier.size(20.dp)) }
        }
    }
}
@Composable private fun ProtoBadge(proto: String) {
    val c = when (proto) { "vless" -> PRIMARY; "vmess" -> GREEN; "trojan" -> AMBER; "shadowsocks" -> Color(0xFFCDA9FF); "wireguard" -> Color(0xFF84E1BC); "socks" -> Color(0xFFF19DC8); else -> MUTED }
    Box(Modifier.size(44.dp).clip(RoundedCornerShape(12.dp)).background(c.copy(alpha = 0.16f)), contentAlignment = Alignment.Center) { Text(badge(proto), color = c, fontSize = 10.sp, fontWeight = FontWeight.Bold) }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun WgSheet(store: Store, onDismiss: () -> Unit, done: () -> Unit) {
    var name by remember { mutableStateOf("") }; var ep by remember { mutableStateOf("") }; var priv by remember { mutableStateOf("") }; var pub by remember { mutableStateOf("") }
    var addr by remember { mutableStateOf("") }; var allowed by remember { mutableStateOf("0.0.0.0/0, ::/0") }; var psk by remember { mutableStateOf("") }; var mtu by remember { mutableStateOf("1420") }; var reserved by remember { mutableStateOf("") }
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = CARD) {
        Column(Modifier.fillMaxWidth().heightIn(max = 520.dp).verticalScroll(rememberScrollState()).imePadding().padding(16.dp).padding(bottom = 16.dp)) {
            Text("Add WireGuard", color = TXT, fontWeight = FontWeight.Bold)
            Fld("Name", name) { name = it }; Fld("Endpoint (host:port)", ep) { ep = it }; Fld("Private Key", priv) { priv = it }; Fld("Peer Public Key", pub) { pub = it }
            Fld("Address (local /32)", addr) { addr = it }; Fld("Allowed IPs", allowed) { allowed = it }; Fld("PSK (optional)", psk) { psk = it }; Fld("MTU", mtu) { mtu = it }; Fld("Reserved (optional)", reserved) { reserved = it }
            Spacer(Modifier.height(10.dp))
            Button(onClick = { if (ep.isNotBlank() && priv.isNotBlank() && pub.isNotBlank()) { val s = LinkParser.makeWireguardServer(name, ep, priv, pub, addr, allowed, psk, mtu, reserved); store.servers.add(s); store.saveServers(); if (store.selection.isEmpty()) store.saveSelection(s.id); done() } }, modifier = Modifier.fillMaxWidth()) { Text("Add") }
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
    var fragment by remember { mutableStateOf(f.fragment) }
    val isStd = server.protocol == "vless" || server.protocol == "vmess" || server.protocol == "trojan"

    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = CARD) {
        Column(Modifier.fillMaxWidth().heightIn(max = 560.dp).verticalScroll(rememberScrollState()).imePadding().padding(16.dp).padding(bottom = 16.dp)) {
            Text("Edit · ${badge(server.protocol)}", color = TXT, fontWeight = FontWeight.Bold)
            Fld("Name", name) { name = it }; Fld("Address", address) { address = it }; Fld("Port", port) { port = it }
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
                Fld("SNI", sni) { sni = it }; Fld("Host", host) { host = it }; Fld("Path / ServiceName", path) { path = it }; Fld("Fingerprint", fp) { fp = it }
                if (security == "reality") { Fld("Public Key (pbk)", pbk) { pbk = it }; Fld("Short ID (sid)", sid) { sid = it } }
                SwitchRow("Allow Insecure", allowInsecure) { allowInsecure = it }
            }
            if (server.protocol == "wireguard") {
                Fld("Peer Public Key", wgPub) { wgPub = it }; Fld("Address (/32)", wgAddr) { wgAddr = it }; Fld("PSK", wgPsk) { wgPsk = it }
                Fld("MTU", wgMtu) { wgMtu = it }; Fld("Reserved", wgReserved) { wgReserved = it }; Fld("Allowed IPs", wgAllowed) { wgAllowed = it }
            }
            HorizontalDivider(Modifier.padding(vertical = 8.dp), color = STROKE)
            Fld("Fragment (packets,length,interval — empty = off)", fragment) { fragment = it }
            Text("e.g. tlshello,100-200,10-20", color = MUTED, fontSize = 11.sp)
            Spacer(Modifier.height(10.dp))
            Button(onClick = {
                val nf = ServerEditor.Fields(name, address, port, cred, network, security, sni, host, path, fp, pbk, sid, allowInsecure, f.alpn, method, pUser, pPass, wgPub, wgAddr, wgPsk, wgMtu, wgReserved, wgAllowed, fragment)
                onSave(ServerEditor.apply(server, nf))
            }, modifier = Modifier.fillMaxWidth()) { Text("Save") }
        }
    }
}

/* ================================ SUBS ================================ */
@Composable
private fun SubsScreen(store: Store, bump: () -> Unit) {
    val scope = rememberCoroutineScope()
    var url by remember { mutableStateOf("") }; var name by remember { mutableStateOf("") }; var busy by remember { mutableStateOf(false) }; var msg by remember { mutableStateOf("") }
    fun refresh(sub: Subscription) {
        busy = true; msg = "Fetching…"
        scope.launch {
            try {
                val r = withContext(Dispatchers.IO) { Subscriptions.fetch(sub.url) }
                store.servers.removeAll { it.subId == sub.id }
                val tagged = r.servers.map { it.copy(subId = sub.id) }; store.servers.addAll(tagged); store.saveServers()
                val idx = store.subs.indexOfFirst { it.id == sub.id }
                if (idx >= 0) store.subs[idx] = sub.copy(serverCount = tagged.size, lastUpdated = System.currentTimeMillis(), upload = r.usage?.upload ?: 0, download = r.usage?.download ?: 0, total = r.usage?.total ?: 0, expire = r.usage?.expire ?: 0)
                store.saveSubs(); msg = "${tagged.size} servers updated"
            } catch (e: Exception) { msg = "Error: ${e.message}" } finally { busy = false; bump() }
        }
    }
    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        TopBar("Subscriptions") {}
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).imePadding().padding(horizontal = 16.dp)) {
            Fld("Subscription URL (https://…)", url) { url = it }; Fld("Name (optional)", name) { name = it }
            Button(onClick = { if (url.isNotBlank()) { val sub = Subscription(newId("sub"), name.ifBlank { url.take(24) }, url.trim()); store.subs.add(sub); store.saveSubs(); url = ""; name = ""; refresh(sub) } }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Add & fetch") }
            if (msg.isNotEmpty()) Text(msg, color = if (msg.startsWith("Error")) BAD else GREEN, fontSize = 12.sp)
            Spacer(Modifier.height(8.dp))
            if (store.subs.isEmpty()) EmptyHint("No subscriptions yet.")
            store.subs.forEach { sub ->
                Card(Modifier.fillMaxWidth().padding(vertical = 5.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                    Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Filled.CloudDownload, null, tint = PRIMARY); Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(sub.name, color = TXT, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text("${sub.serverCount} servers", color = MUTED, fontSize = 12.sp)
                            if (sub.total > 0) {
                                val used = sub.upload + sub.download
                                val pct = (used.toDouble() / sub.total * 100).toInt().coerceIn(0, 100)
                                val barColor = if (pct >= 90) BAD else if (pct >= 70) AMBER else GREEN
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
private fun PoolScreen(store: Store, bump: () -> Unit) {
    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        TopBar("Proxy Pool") {
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
                        if (store.chainReady(c)) IconButton(onClick = { store.saveSelection("chain:${c.id}"); bump() }) { Icon(Icons.Filled.CheckCircle, null, tint = if (store.selection == "chain:${c.id}") GREEN else MUTED) }
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
    var s by remember { mutableStateOf(store.settings) }
    fun save(n: AppSettings) { s = n; store.saveSettings(n); bump() }
    Screen("Routing", back, {}) {
        Text("Routing mode", color = TXT, fontWeight = FontWeight.Bold)
        listOf("global" to "Global (all via proxy)", "bypass-ir" to "Bypass Iran", "bypass-cn" to "Bypass China", "direct" to "Direct").forEach { (v, l) ->
            Row(Modifier.fillMaxWidth().clickable { save(s.copy(routingMode = v)) }, verticalAlignment = Alignment.CenterVertically) { RadioButton(s.routingMode == v, { save(s.copy(routingMode = v)) }); Text(l, color = TXT) }
        }
        SwitchRow("Block ads", s.blockAds) { save(s.copy(blockAds = it)) }
        SwitchRow("Sniffing", s.enableSniffing) { save(s.copy(enableSniffing = it)) }
        HorizontalDivider(Modifier.padding(vertical = 10.dp), color = STROKE)
        SwitchRow("Advanced routing", s.advancedRouting) { save(s.copy(advancedRouting = it)) }
        if (s.advancedRouting) {
            Text("Pick 🧭 on the Home screen to use it.", color = MUTED, fontSize = 12.sp)
            s.routeRules.forEachIndexed { i, r ->
                Card(Modifier.fillMaxWidth().padding(vertical = 4.dp), colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(12.dp)) {
                    Column(Modifier.padding(10.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            DropPick("Type", listOf("domain" to "Domain", "ip" to "IP", "port" to "Port"), r.type) { nt -> save(s.copy(routeRules = s.routeRules.toMutableList().also { it[i] = r.copy(type = nt) })) }
                            Spacer(Modifier.weight(1f)); IconButton(onClick = { save(s.copy(routeRules = s.routeRules.filterIndexed { x, _ -> x != i })) }) { Icon(Icons.Filled.DeleteOutline, null, tint = BAD) }
                        }
                        OutlinedTextField(r.value, { save(s.copy(routeRules = s.routeRules.toMutableList().also { m -> m[i] = r.copy(value = it) })) }, Modifier.fillMaxWidth(), placeholder = { Text("value (geosite:google / 1.2.3.0/24 / 443)", fontSize = 11.sp) }, singleLine = true, colors = tfColors())
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
    var s by remember { mutableStateOf(store.settings) }
    fun save(n: AppSettings) { s = n; store.saveSettings(n); bump() }
    Screen("Settings", back, {}) {
        Text("Ports & DNS", color = TXT, fontWeight = FontWeight.Bold)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { NumFld("SOCKS", s.socksPort, Modifier.weight(1f)) { save(s.copy(socksPort = it)) }; NumFld("HTTP", s.httpPort, Modifier.weight(1f)) { save(s.copy(httpPort = it)) } }
        OutlinedTextField(s.dns.joinToString(","), { save(s.copy(dns = it.split(",").map { d -> d.trim() }.filter { d -> d.isNotEmpty() })) }, Modifier.fillMaxWidth(), label = { Text("DNS (comma-separated)") }, singleLine = true, colors = tfColors())
        DropPick("Log level", listOf("none", "error", "warning", "info", "debug").map { it to it }, s.logLevel) { save(s.copy(logLevel = it)) }
        SwitchRow("IPv6", s.ipv6) { save(s.copy(ipv6 = it)) }
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

@Composable private fun MoreMenu(open: (String) -> Unit) {
    Column(Modifier.fillMaxSize().statusBarsPadding()) {
        TopBar("More") {}
        Column(Modifier.padding(horizontal = 16.dp)) {
            listOf(Triple("chains", "Proxy Chain", Icons.Filled.Link), Triple("routing", "Routing", Icons.Filled.CallSplit), Triple("settings", "Settings", Icons.Filled.Settings), Triple("logs", "Logs", Icons.Filled.Article)).forEach { (k, l, ic) ->
                Card(Modifier.fillMaxWidth().padding(vertical = 5.dp).clickable { open(k) }, colors = CardDefaults.cardColors(containerColor = CARD), shape = RoundedCornerShape(14.dp)) {
                    Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) { Icon(ic, null, tint = PRIMARY); Spacer(Modifier.width(12.dp)); Text(l, color = TXT, modifier = Modifier.weight(1f)); Icon(Icons.Filled.ChevronRight, null, tint = MUTED) }
                }
            }
        }
    }
}

/* ================================ shared ================================ */
@Composable private fun TopBar(title: String, actions: @Composable RowScope.() -> Unit) {
    Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) { Text(title, color = TXT, fontSize = 22.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f)); actions() }
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
@Composable private fun SwitchRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) { Text(label, color = TXT, modifier = Modifier.weight(1f)); Switch(checked, onChange) }
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
private fun usedPorts(store: Store): Set<Int> { val s = HashSet<Int>(); s.add(store.settings.socksPort); s.add(store.settings.httpPort); store.pool.forEach { if (it.socksPort > 0) s.add(it.socksPort); if (it.httpPort > 0) s.add(it.httpPort) }; return s }

fun fmtBytes(n: Long): String { var v = n.toDouble(); val u = arrayOf("B", "KB", "MB", "GB", "TB"); var i = 0; while (v >= 1024 && i < u.size - 1) { v /= 1024; i++ }; return (if (i == 0) v.toLong().toString() else String.format("%.1f", v)) + " " + u[i] }
fun fmtSpeed(n: Long) = fmtBytes(n) + "/s"
private fun fmtDuration(ms: Long): String {
    val s = (ms / 1000).coerceAtLeast(0); return "%02d:%02d:%02d".format(s / 3600, (s % 3600) / 60, s % 60)
}
private fun msLabel(ms: Long) = if (ms >= 0) "${ms}ms" else "×"
private fun badge(p: String) = when (p) { "vless" -> "VLESS"; "vmess" -> "VMESS"; "trojan" -> "TROJAN"; "shadowsocks" -> "SS"; "wireguard" -> "WG"; "socks" -> "SOCKS"; "http" -> "HTTP"; else -> p.uppercase() }
private fun flag(cc: String): String { if (cc.length != 2) return "🏳"; val base = 0x1F1E6; return String(Character.toChars(base + (cc[0].uppercaseChar() - 'A'))) + String(Character.toChars(base + (cc[1].uppercaseChar() - 'A'))) }
