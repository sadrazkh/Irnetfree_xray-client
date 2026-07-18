package com.irnetfree.vpn.ui

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.irnetfree.vpn.core.*
import com.irnetfree.vpn.net.Diagnostics
import com.irnetfree.vpn.vpn.ConnState
import com.irnetfree.vpn.vpn.VpnState
import com.irnetfree.vpn.vpn.XrayVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val BG = Color(0xFF0D1117)
private val CARD = Color(0xFF161B22)
private val ACCENT = Color(0xFF4F8CFF)
private val ACCENT2 = Color(0xFF2DD4BF)
private val MUTED = Color(0xFF8B98A9)
private val BAD = Color(0xFFF07178)
private val WARN = Color(0xFFE3B85A)

class MainActivity : ComponentActivity() {
    private lateinit var store: Store
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = Store(this)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(primary = ACCENT, secondary = ACCENT2, background = BG, surface = CARD)) {
                Surface(Modifier.fillMaxSize(), color = BG) { App(store) }
            }
        }
    }
}

/* ----------------------------- helpers ----------------------------- */
fun fmtBytes(n: Long): String {
    var v = n.toDouble(); val u = arrayOf("B", "KB", "MB", "GB", "TB"); var i = 0
    while (v >= 1024 && i < u.size - 1) { v /= 1024; i++ }
    return (if (i == 0) v.toLong().toString() else String.format("%.1f", v)) + " " + u[i]
}
fun fmtSpeed(n: Long) = fmtBytes(n) + "/s"

private enum class Tab(val label: String, val icon: androidx.compose.ui.graphics.vector.ImageVector) {
    CONNECT("اتصال", Icons.Filled.PlayArrow),
    SERVERS("سرورها", Icons.Filled.List),
    SUBS("ساب‌ها", Icons.Filled.Share),
    POOL("استخر", Icons.Filled.Star),
    MORE("بیشتر", Icons.Filled.Settings)
}

@Composable
private fun App(store: Store) {
    var tab by remember { mutableStateOf(Tab.CONNECT) }
    var more by remember { mutableStateOf<String?>(null) }   // sub-screen in MORE
    var rev by remember { mutableIntStateOf(0) }
    val bump: () -> Unit = { rev++ }

    Scaffold(containerColor = Color.Transparent, bottomBar = {
        NavigationBar(containerColor = Color(0xFF12161D)) {
            Tab.values().forEach { tb ->
                NavigationBarItem(selected = tab == tb, onClick = { tab = tb; more = null },
                    icon = { Icon(tb.icon, null) }, label = { Text(tb.label) })
            }
        }
    }) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            key(rev) {
                when (tab) {
                    Tab.CONNECT -> ConnectScreen(store, bump)
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

/* ============================= CONNECT ============================= */
@Composable
private fun ConnectScreen(store: Store, bump: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val state by VpnState.state.collectAsState()
    val err by VpnState.lastError.collectAsState()
    val traffic by VpnState.traffic.collectAsState()
    var ip by remember { mutableStateOf("—") }
    var ping by remember { mutableStateOf("—") }

    val vpnPrepare = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        if (res.resultCode == android.app.Activity.RESULT_OK) doConnect(ctx, store)
    }
    fun onPower() {
        if (state == ConnState.CONNECTED || state == ConnState.CONNECTING) { XrayVpnService.disconnect(ctx); return }
        val prep: Intent? = VpnService.prepare(ctx)
        if (prep != null) vpnPrepare.launch(prep) else doConnect(ctx, store)
    }

    Column(Modifier.fillMaxSize().padding(20.dp).verticalScroll(rememberScrollState()), horizontalAlignment = Alignment.CenterHorizontally) {
        Spacer(Modifier.height(16.dp))
        Text("IRNetFree", style = MaterialTheme.typography.headlineSmall)
        Text(when (state) {
            ConnState.CONNECTED -> "متصل"; ConnState.CONNECTING -> "در حال اتصال…"; ConnState.ERROR -> "خطا"; else -> "قطع" },
            color = if (state == ConnState.CONNECTED) ACCENT2 else MUTED)
        Spacer(Modifier.height(24.dp))
        Button(onClick = { onPower() }, modifier = Modifier.size(150.dp), shape = CircleShape,
            colors = ButtonDefaults.buttonColors(containerColor = if (state == ConnState.CONNECTED) Color(0xFF17604B) else Color(0xFF1E2A44))) {
            Icon(if (state == ConnState.CONNECTED) Icons.Filled.Stop else Icons.Filled.PlayArrow, null, Modifier.size(56.dp))
        }
        Spacer(Modifier.height(20.dp))
        Text("خروجی انتخابی", color = MUTED, style = MaterialTheme.typography.labelMedium)
        Spacer(Modifier.height(6.dp))
        SelectionPicker(store, bump)
        Text(store.selectionLabel(), color = Color(0xFFB6C2D4), maxLines = 1, overflow = TextOverflow.Ellipsis)
        Spacer(Modifier.height(18.dp))
        // stats
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
            StatCell("IP خروجی", ip); StatCell("پینگ", ping)
        }
        Spacer(Modifier.height(10.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
            StatCell("▼ دانلود", fmtSpeed(traffic.rxSpeed)); StatCell("▲ آپلود", fmtSpeed(traffic.txSpeed))
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
            StatCell("مجموع دانلود", fmtBytes(traffic.rxBytes)); StatCell("مجموع آپلود", fmtBytes(traffic.txBytes))
        }
        Spacer(Modifier.height(14.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = {
                val sel = store.selection
                val srv = store.serverById(sel) ?: store.chainById(sel.removePrefix("chain:"))?.let { store.chainMembers(it).firstOrNull() }
                if (srv == null) return@OutlinedButton
                ping = "…"
                scope.launch { val ms = withContext(Dispatchers.IO) { Diagnostics.tcpPing(srv.address, srv.port) }; ping = if (ms >= 0) "${ms}ms" else "خطا" }
            }) { Text("تست پینگ") }
            OutlinedButton(onClick = {
                ip = "…"
                scope.launch { val r = withContext(Dispatchers.IO) { Diagnostics.ipInfo() }; ip = if (r.ok) "${r.countryCode} ${r.ip}" else "خطا" }
            }) { Text("بررسی IP") }
        }
        if (state == ConnState.ERROR && err.isNotBlank()) { Spacer(Modifier.height(12.dp)); Text(err, color = BAD, style = MaterialTheme.typography.bodySmall) }
    }
}

private fun doConnect(ctx: android.content.Context, store: Store) {
    try { VpnState.set(ConnState.CONNECTING, store.selectionLabel()); XrayVpnService.connect(ctx, store) }
    catch (e: Exception) { VpnState.set(ConnState.ERROR, error = e.message ?: "connect failed") }
}

@Composable private fun StatCell(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(label, color = MUTED, style = MaterialTheme.typography.labelSmall)
        Text(value, style = MaterialTheme.typography.titleSmall)
    }
}

@Composable
private fun SelectionPicker(store: Store, bump: () -> Unit) {
    var open by remember { mutableStateOf(false) }
    val options = buildList {
        if (store.poolEnabledValid().isNotEmpty()) add(Store.POOL_ID to "🧩 استخر پروکسی (${store.poolEnabledValid().size})")
        if (store.advancedReady()) add(Store.ADV_ID to "🧭 روتینگ ویژه")
        store.chains.filter { store.chainReady(it) }.forEach { add("chain:${it.id}" to "⛓ ${it.name}") }
        store.servers.forEach { add(it.id to "${it.protocol} · ${it.name}") }
    }
    Box {
        OutlinedButton(onClick = { open = true }) {
            Text(options.firstOrNull { it.first == store.selection }?.second ?: "انتخاب کن", maxLines = 1, overflow = TextOverflow.Ellipsis)
            Icon(Icons.Filled.ArrowDropDown, null)
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            if (options.isEmpty()) DropdownMenuItem(text = { Text("سروری اضافه نشده") }, onClick = { open = false })
            options.forEach { (id, lbl) -> DropdownMenuItem(text = { Text(lbl) }, onClick = { store.saveSelection(id); open = false; bump() }) }
        }
    }
}

/* ============================= SERVERS ============================= */
@Composable
private fun ServersScreen(store: Store, bump: () -> Unit) {
    val scope = rememberCoroutineScope()
    var importText by remember { mutableStateOf("") }
    var msg by remember { mutableStateOf("") }
    var showWg by remember { mutableStateOf(false) }
    var showProxy by remember { mutableStateOf(false) }
    val pings = remember { mutableStateMapOf<String, String>() }

    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        Text("سرورها", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(10.dp))
        OutlinedTextField(importText, { importText = it }, Modifier.fillMaxWidth(),
            label = { Text("لینک(های) کانفیگ / socks:// / وایرگارد / base64 ساب") }, minLines = 2, maxLines = 6)
        Spacer(Modifier.height(8.dp))
        FlowButtons {
            Button(onClick = {
                val (parsed, errs) = LinkParser.parseMany(importText)
                store.servers.addAll(parsed); store.saveServers()
                if (parsed.isNotEmpty() && store.selection.isEmpty()) store.saveSelection(store.servers.first().id)
                msg = "${parsed.size} افزوده شد" + if (errs.isNotEmpty()) " (${errs.size} خطا)" else ""
                importText = ""; bump()
            }) { Text("وارد کردن") }
            OutlinedButton(onClick = { showWg = !showWg; showProxy = false }) { Text("+ WireGuard") }
            OutlinedButton(onClick = { showProxy = !showProxy; showWg = false }) { Text("+ SOCKS/HTTP") }
        }
        if (msg.isNotEmpty()) Text(msg, color = ACCENT2, style = MaterialTheme.typography.bodySmall)

        if (showWg) WgForm(store) { showWg = false; bump() }
        if (showProxy) ProxyForm(store) { showProxy = false; bump() }

        Spacer(Modifier.height(12.dp))
        if (store.servers.isEmpty()) Text("هنوز سروری نیست.", color = MUTED)
        store.servers.toList().forEach { s ->
            Card(Modifier.fillMaxWidth().padding(vertical = 4.dp), colors = CardDefaults.cardColors(containerColor = CARD)) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(s.name, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text("${s.protocol} · ${s.address}:${s.port}", color = MUTED, style = MaterialTheme.typography.bodySmall)
                        pings[s.id]?.let { Text("پینگ: $it", color = ACCENT2, style = MaterialTheme.typography.labelSmall) }
                    }
                    IconButton(onClick = { pings[s.id] = "…"; scope.launch { val ms = withContext(Dispatchers.IO) { Diagnostics.tcpPing(s.address, s.port) }; pings[s.id] = if (ms >= 0) "${ms}ms" else "خطا" } }) { Icon(Icons.Filled.Bolt, "ping") }
                    IconButton(onClick = { store.saveSelection(s.id); bump() }) { Icon(Icons.Filled.CheckCircle, null, tint = if (store.selection == s.id) ACCENT2 else MUTED) }
                    IconButton(onClick = { store.deleteServer(s.id); bump() }) { Icon(Icons.Filled.Delete, null, tint = BAD) }
                }
            }
        }
    }
}

@Composable private fun WgForm(store: Store, done: () -> Unit) {
    var name by remember { mutableStateOf("") }; var ep by remember { mutableStateOf("") }
    var priv by remember { mutableStateOf("") }; var pub by remember { mutableStateOf("") }
    var addr by remember { mutableStateOf("") }; var allowed by remember { mutableStateOf("0.0.0.0/0, ::/0") }
    var psk by remember { mutableStateOf("") }; var mtu by remember { mutableStateOf("1420") }; var reserved by remember { mutableStateOf("") }
    Card(Modifier.fillMaxWidth().padding(vertical = 8.dp), colors = CardDefaults.cardColors(containerColor = CARD)) {
        Column(Modifier.padding(12.dp)) {
            Text("افزودن WireGuard", style = MaterialTheme.typography.titleSmall)
            Fld("نام", name) { name = it }; Fld("Endpoint (host:port)", ep) { ep = it }
            Fld("Private Key", priv) { priv = it }; Fld("Peer Public Key", pub) { pub = it }
            Fld("Address (محلی /32)", addr) { addr = it }; Fld("Allowed IPs", allowed) { allowed = it }
            Fld("Pre-shared Key (اختیاری)", psk) { psk = it }; Fld("MTU", mtu) { mtu = it }; Fld("Reserved (اختیاری)", reserved) { reserved = it }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    if (ep.isBlank() || priv.isBlank() || pub.isBlank()) return@Button
                    val s = LinkParser.makeWireguardServer(name, ep, priv, pub, addr, allowed, psk, mtu, reserved)
                    store.servers.add(s); store.saveServers(); if (store.selection.isEmpty()) store.saveSelection(s.id); done()
                }) { Text("افزودن") }
                OutlinedButton(onClick = done) { Text("انصراف") }
            }
        }
    }
}

@Composable private fun ProxyForm(store: Store, done: () -> Unit) {
    var type by remember { mutableStateOf("socks") }; var name by remember { mutableStateOf("") }
    var host by remember { mutableStateOf("") }; var port by remember { mutableStateOf("") }
    var user by remember { mutableStateOf("") }; var pass by remember { mutableStateOf("") }
    Card(Modifier.fillMaxWidth().padding(vertical = 8.dp), colors = CardDefaults.cardColors(containerColor = CARD)) {
        Column(Modifier.padding(12.dp)) {
            Text("افزودن پروکسی SOCKS / HTTP", style = MaterialTheme.typography.titleSmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(type == "socks", { type = "socks" }, { Text("SOCKS5") })
                FilterChip(type == "http", { type = "http" }, { Text("HTTP") })
            }
            Fld("نام", name) { name = it }; Fld("Host", host) { host = it }; Fld("پورت", port) { port = it }
            Fld("Username (اختیاری)", user) { user = it }; Fld("Password (اختیاری)", pass) { pass = it }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    if (host.isBlank() || port.isBlank()) return@Button
                    val s = LinkParser.makeProxyServer(type, name, host, port.toIntOrNull() ?: 1080, user, pass)
                    store.servers.add(s); store.saveServers(); if (store.selection.isEmpty()) store.saveSelection(s.id); done()
                }) { Text("افزودن") }
                OutlinedButton(onClick = done) { Text("انصراف") }
            }
        }
    }
}

/* ============================= SUBS ============================= */
@Composable
private fun SubsScreen(store: Store, bump: () -> Unit) {
    val scope = rememberCoroutineScope()
    var url by remember { mutableStateOf("") }; var name by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }; var msg by remember { mutableStateOf("") }

    fun refresh(sub: Subscription) {
        busy = true; msg = "در حال دریافت…"
        scope.launch {
            try {
                val r = withContext(Dispatchers.IO) { Subscriptions.fetch(sub.url) }
                store.servers.removeAll { it.subId == sub.id }
                val tagged = r.servers.map { it.copy(subId = sub.id) }
                store.servers.addAll(tagged); store.saveServers()
                val idx = store.subs.indexOfFirst { it.id == sub.id }
                if (idx >= 0) store.subs[idx] = sub.copy(serverCount = tagged.size, lastUpdated = System.currentTimeMillis(),
                    upload = r.usage?.upload ?: 0, download = r.usage?.download ?: 0, total = r.usage?.total ?: 0, expire = r.usage?.expire ?: 0)
                store.saveSubs(); msg = "${tagged.size} سرور به‌روز شد"
            } catch (e: Exception) { msg = "خطا: ${e.message}" } finally { busy = false; bump() }
        }
    }

    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        Text("ساب‌اسکریپشن‌ها", style = MaterialTheme.typography.titleLarge)
        Fld("آدرس ساب (https://…)", url) { url = it }; Fld("نام (اختیاری)", name) { name = it }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(enabled = !busy, onClick = {
                if (url.isBlank()) return@Button
                val sub = Subscription(newId("sub"), name.ifBlank { url.take(24) }, url.trim())
                store.subs.add(sub); store.saveSubs(); url = ""; name = ""; refresh(sub)
            }) { Text("افزودن و دریافت") }
            if (msg.isNotEmpty()) Text(msg, color = if (msg.startsWith("خطا")) BAD else ACCENT2, modifier = Modifier.align(Alignment.CenterVertically))
        }
        Spacer(Modifier.height(12.dp))
        if (store.subs.isEmpty()) Text("هنوز ساب اضافه نشده.", color = MUTED)
        store.subs.toList().forEach { sub ->
            Card(Modifier.fillMaxWidth().padding(vertical = 4.dp), colors = CardDefaults.cardColors(containerColor = CARD)) {
                Column(Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(sub.name, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text("${sub.serverCount} سرور", color = MUTED, style = MaterialTheme.typography.bodySmall)
                            if (sub.total > 0) Text("مصرف: ${fmtBytes(sub.upload + sub.download)} / ${fmtBytes(sub.total)}", color = MUTED, style = MaterialTheme.typography.labelSmall)
                        }
                        IconButton(onClick = { refresh(sub) }) { Icon(Icons.Filled.Refresh, "refresh") }
                        IconButton(onClick = {
                            store.servers.removeAll { it.subId == sub.id }; store.saveServers()
                            store.subs.removeAll { it.id == sub.id }; store.saveSubs(); bump()
                        }) { Icon(Icons.Filled.Delete, null, tint = BAD) }
                    }
                }
            }
        }
    }
}

/* ============================= POOL ============================= */
@Composable
private fun PoolScreen(store: Store, bump: () -> Unit) {
    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("استخر پروکسی", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            Button(onClick = {
                val used = usedPorts(store); var sp = 60001; while (used.contains(sp)) sp++; var hp = sp + 1; while (used.contains(hp)) hp++
                store.pool.add(PoolEntry(newId("px"), "پروکسی ${store.pool.size + 1}", store.servers.firstOrNull()?.id ?: "", sp, hp, true))
                store.savePool(); bump()
            }) { Text("+ جدید") }
        }
        Text("چند خروجی هم‌زمان روی پورت‌های جدا (اولین موردِ فعال = خروجی اصلی).", color = MUTED, style = MaterialTheme.typography.bodySmall)
        Button(onClick = { store.saveSelection(Store.POOL_ID); bump() }, Modifier.padding(top = 6.dp)) { Text("انتخاب استخر برای اتصال") }
        Spacer(Modifier.height(8.dp))
        if (store.pool.isEmpty()) Text("هنوز پروکسی‌ای نیست.", color = MUTED)
        store.pool.toList().forEachIndexed { idx, e ->
            val valid = store.poolTargetValid(e.target)
            Card(Modifier.fillMaxWidth().padding(vertical = 6.dp), colors = CardDefaults.cardColors(containerColor = CARD)) {
                Column(Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(e.name, Modifier.weight(1f))
                        Switch(e.enabled, { store.pool[idx] = e.copy(enabled = it); store.savePool(); bump() })
                        IconButton(onClick = { store.pool.removeAt(idx); store.savePool(); bump() }) { Icon(Icons.Filled.Delete, null, tint = BAD) }
                    }
                    TargetPicker(store, e.target) { store.pool[idx] = e.copy(target = it); store.savePool(); bump() }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        NumFld("SOCKS", e.socksPort, Modifier.weight(1f)) { store.pool[idx] = e.copy(socksPort = it); store.savePool() }
                        NumFld("HTTP", e.httpPort, Modifier.weight(1f)) { store.pool[idx] = e.copy(httpPort = it); store.savePool() }
                    }
                    if (!valid) Text("⚠ خروجی نامعتبر", color = WARN, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable private fun TargetPicker(store: Store, current: String, onPick: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    val options = buildList {
        store.servers.forEach { add(it.id to it.name) }
        store.chains.filter { store.chainReady(it) }.forEach { add("chain:${it.id}" to "⛓ ${it.name}") }
    }
    Box {
        OutlinedButton(onClick = { open = true }, modifier = Modifier.fillMaxWidth()) {
            Text(options.firstOrNull { it.first == current }?.second ?: "انتخاب خروجی", Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis); Icon(Icons.Filled.ArrowDropDown, null)
        }
        DropdownMenu(open, { open = false }) { options.forEach { (id, l) -> DropdownMenuItem(text = { Text(l) }, onClick = { onPick(id); open = false }) } }
    }
}

/* ============================= CHAINS ============================= */
@Composable
private fun ChainsScreen(store: Store, bump: () -> Unit, back: () -> Unit) {
    ScreenHeader("زنجیره پروکسی", back) {
        Button(onClick = { store.chains.add(ChainConfig(newId("chain"), "زنجیره ${store.chains.size + 1}", emptyList())); store.saveChains(); bump() }) { Text("+ جدید") }
    }
    Column(Modifier.fillMaxSize().padding(16.dp).padding(top = 56.dp).verticalScroll(rememberScrollState())) {
        if (store.chains.isEmpty()) Text("هنوز زنجیره‌ای نیست.", color = MUTED)
        store.chains.toList().forEachIndexed { idx, c ->
            val members = store.chainMembers(c)
            Card(Modifier.fillMaxWidth().padding(vertical = 6.dp), colors = CardDefaults.cardColors(containerColor = CARD)) {
                Column(Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("⛓ ${c.name}", Modifier.weight(1f))
                        if (store.chainReady(c)) IconButton(onClick = { store.saveSelection("chain:${c.id}"); bump() }) { Icon(Icons.Filled.CheckCircle, null, tint = if (store.selection == "chain:${c.id}") ACCENT2 else MUTED) }
                        IconButton(onClick = { store.chains.removeAt(idx); store.saveChains(); bump() }) { Icon(Icons.Filled.Delete, null, tint = BAD) }
                    }
                    Text("مسیر: " + (members.joinToString(" → ") { it.name }.ifEmpty { "خالی — حداقل ۲ سرور اضافه کن" }), color = MUTED, style = MaterialTheme.typography.bodySmall)
                    // add member
                    var open by remember { mutableStateOf(false) }
                    Box {
                        OutlinedButton(onClick = { open = true }) { Text("+ افزودن سرور به زنجیره"); Icon(Icons.Filled.ArrowDropDown, null) }
                        DropdownMenu(open, { open = false }) {
                            store.servers.filter { !c.members.contains(it.id) }.forEach { s ->
                                DropdownMenuItem(text = { Text(s.name) }, onClick = { store.chains[idx] = c.copy(members = c.members + s.id); store.saveChains(); open = false; bump() })
                            }
                        }
                    }
                    members.forEachIndexed { mi, s ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("${mi + 1}. ${s.name}", Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                            IconButton(onClick = { store.chains[idx] = c.copy(members = c.members.filter { it != s.id }); store.saveChains(); bump() }) { Icon(Icons.Filled.Close, null, tint = BAD) }
                        }
                    }
                }
            }
        }
    }
}

/* ============================= ROUTING ============================= */
@Composable
private fun RoutingScreen(store: Store, bump: () -> Unit, back: () -> Unit) {
    var s by remember { mutableStateOf(store.settings) }
    fun save(n: AppSettings) { s = n; store.saveSettings(n); bump() }
    ScreenHeader("روتینگ", back) {}
    Column(Modifier.fillMaxSize().padding(16.dp).padding(top = 56.dp).verticalScroll(rememberScrollState())) {
        Text("حالت روتینگ ساده", style = MaterialTheme.typography.titleSmall)
        listOf("global" to "گلوبال (همه از پروکسی)", "bypass-ir" to "دور زدن ایران", "bypass-cn" to "دور زدن چین", "direct" to "مستقیم").forEach { (v, l) ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(s.routingMode == v, { save(s.copy(routingMode = v)) }); Text(l)
            }
        }
        Text("دور زدن ایران/چین به فایل‌های geo نیاز دارد (در این نسخه بندل نشده — فعلاً مثل گلوبال عمل می‌کند).", color = WARN, style = MaterialTheme.typography.labelSmall)
        SwitchRow("مسدودسازی تبلیغات", s.blockAds) { save(s.copy(blockAds = it)) }
        SwitchRow("Sniffing", s.enableSniffing) { save(s.copy(enableSniffing = it)) }
        Divider(Modifier.padding(vertical = 10.dp))
        SwitchRow("روتینگ ویژه (پیشرفته)", s.advancedRouting) { save(s.copy(advancedRouting = it)) }
        if (s.advancedRouting) {
            Text("هر قانون: نوع، مقدار، مقصد. در «اتصال» گزینه 🧭 را انتخاب کن.", color = MUTED, style = MaterialTheme.typography.bodySmall)
            s.routeRules.forEachIndexed { i, r ->
                Card(Modifier.fillMaxWidth().padding(vertical = 4.dp), colors = CardDefaults.cardColors(containerColor = CARD)) {
                    Column(Modifier.padding(10.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            TypeDrop(r.type) { nt -> save(s.copy(routeRules = s.routeRules.toMutableList().also { it[i] = r.copy(type = nt) })) }
                            Spacer(Modifier.weight(1f))
                            IconButton(onClick = { save(s.copy(routeRules = s.routeRules.filterIndexed { x, _ -> x != i })) }) { Icon(Icons.Filled.Delete, null, tint = BAD) }
                        }
                        OutlinedTextField(r.value, { save(s.copy(routeRules = s.routeRules.toMutableList().also { m -> m[i] = r.copy(value = it) })) }, Modifier.fillMaxWidth(), label = { Text("مقدار (مثلاً domain:example.com یا 1.2.3.0/24 یا 443)") }, singleLine = true)
                        TargetDrop(store, r.target) { save(s.copy(routeRules = s.routeRules.toMutableList().also { m -> m[i] = r.copy(target = it) })) }
                    }
                }
            }
            Button(onClick = { save(s.copy(routeRules = s.routeRules + RouteRule("domain", "", store.servers.firstOrNull()?.id ?: "direct"))) }) { Text("+ افزودن قانون") }
            Spacer(Modifier.height(6.dp)); Text("بقیه‌ی ترافیک از:", color = MUTED)
            TargetDrop(store, s.routeDefault) { save(s.copy(routeDefault = it)) }
        }
    }
}

@Composable private fun TypeDrop(current: String, onPick: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box { OutlinedButton(onClick = { open = true }) { Text(when (current) { "ip" -> "IP"; "port" -> "پورت"; else -> "دامنه" }) }
        DropdownMenu(open, { open = false }) { listOf("domain" to "دامنه", "ip" to "IP", "port" to "پورت").forEach { (v, l) -> DropdownMenuItem(text = { Text(l) }, onClick = { onPick(v); open = false }) } } }
}
@Composable private fun TargetDrop(store: Store, current: String, onPick: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    val opts = buildList { add("proxy" to "پروکسی (سرور اول)"); add("direct" to "مستقیم"); add("block" to "بلاک"); store.servers.forEach { add(it.id to it.name) }; store.chains.filter { store.chainReady(it) }.forEach { add("chain:${it.id}" to "⛓ ${it.name}") } }
    Box { OutlinedButton(onClick = { open = true }, Modifier.fillMaxWidth()) { Text(opts.firstOrNull { it.first == current }?.second ?: "مقصد", Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis); Icon(Icons.Filled.ArrowDropDown, null) }
        DropdownMenu(open, { open = false }) { opts.forEach { (v, l) -> DropdownMenuItem(text = { Text(l) }, onClick = { onPick(v); open = false }) } } }
}

/* ============================= SETTINGS ============================= */
@Composable
private fun SettingsScreen(store: Store, bump: () -> Unit, back: () -> Unit) {
    var s by remember { mutableStateOf(store.settings) }
    fun save(n: AppSettings) { s = n; store.saveSettings(n); bump() }
    ScreenHeader("تنظیمات", back) {}
    Column(Modifier.fillMaxSize().padding(16.dp).padding(top = 56.dp).verticalScroll(rememberScrollState())) {
        Text("پورت‌ها و DNS", style = MaterialTheme.typography.titleSmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            NumFld("SOCKS", s.socksPort, Modifier.weight(1f)) { save(s.copy(socksPort = it)) }
            NumFld("HTTP", s.httpPort, Modifier.weight(1f)) { save(s.copy(httpPort = it)) }
        }
        OutlinedTextField(s.dns.joinToString(","), { save(s.copy(dns = it.split(",").map { d -> d.trim() }.filter { d -> d.isNotEmpty() })) }, Modifier.fillMaxWidth(), label = { Text("DNS (با کاما)") }, singleLine = true)
        var logOpen by remember { mutableStateOf(false) }
        Box { OutlinedButton(onClick = { logOpen = true }) { Text("سطح لاگ: ${s.logLevel}") }
            DropdownMenu(logOpen, { logOpen = false }) { listOf("none", "error", "warning", "info", "debug").forEach { l -> DropdownMenuItem(text = { Text(l) }, onClick = { save(s.copy(logLevel = l)); logOpen = false }) } } }
        SwitchRow("IPv6", s.ipv6) { save(s.copy(ipv6 = it)) }
        Divider(Modifier.padding(vertical = 10.dp))
        Text("روتینگ بر اساس اپ (Per-App)", style = MaterialTheme.typography.titleSmall)
        listOf("off" to "خاموش (همه‌ی سیستم)", "allow" to "فقط این اپ‌ها تونل شوند", "disallow" to "همه به‌جز این اپ‌ها").forEach { (v, l) ->
            Row(verticalAlignment = Alignment.CenterVertically) { RadioButton(s.perAppMode == v, { save(s.copy(perAppMode = v)) }); Text(l) }
        }
        if (s.perAppMode != "off") AppPicker(s.perApps) { save(s.copy(perApps = it)) }
    }
}

@Composable private fun AppPicker(selected: List<String>, onChange: (List<String>) -> Unit) {
    val ctx = LocalContext.current
    val apps = remember {
        val pm = ctx.packageManager
        pm.getInstalledApplications(0).filter { pm.getLaunchIntentForPackage(it.packageName) != null }
            .map { it.packageName to (pm.getApplicationLabel(it).toString()) }.sortedBy { it.second }
    }
    var q by remember { mutableStateOf("") }
    OutlinedTextField(q, { q = it }, Modifier.fillMaxWidth(), label = { Text("جستجوی اپ") }, singleLine = true)
    Column(Modifier.heightIn(max = 320.dp).verticalScroll(rememberScrollState())) {
        apps.filter { it.second.contains(q, true) || it.first.contains(q, true) }.take(200).forEach { (pkg, label) ->
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Checkbox(selected.contains(pkg), { c -> onChange(if (c) selected + pkg else selected - pkg) })
                Text(label, Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

/* ============================= LOGS / MORE ============================= */
@Composable private fun LogsScreen(back: () -> Unit) {
    val log by VpnState.log.collectAsState()
    ScreenHeader("لاگ‌ها", back) { OutlinedButton(onClick = { VpnState.clearLog() }) { Text("پاک کردن") } }
    Column(Modifier.fillMaxSize().padding(12.dp).padding(top = 56.dp).verticalScroll(rememberScrollState())) {
        if (log.isEmpty()) Text("لاگی نیست.", color = MUTED)
        log.forEach { Text(it, style = MaterialTheme.typography.labelSmall, color = Color(0xFFB6C2D4)) }
    }
}

@Composable private fun MoreMenu(open: (String) -> Unit) {
    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Text("بیشتر", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(8.dp))
        listOf("chains" to "⛓ زنجیره پروکسی", "routing" to "🧭 روتینگ", "settings" to "⚙ تنظیمات", "logs" to "📜 لاگ‌ها").forEach { (k, l) ->
            Card(Modifier.fillMaxWidth().padding(vertical = 4.dp).clickable { open(k) }, colors = CardDefaults.cardColors(containerColor = CARD)) {
                Text(l, Modifier.padding(16.dp))
            }
        }
    }
}

/* ============================= small shared UI ============================= */
@Composable private fun ScreenHeader(title: String, back: () -> Unit, actions: @Composable () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
        IconButton(onClick = back) { Icon(Icons.Filled.ArrowBack, "back") }
        Text(title, Modifier.weight(1f), style = MaterialTheme.typography.titleLarge)
        actions()
    }
}
@Composable private fun SwitchRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) { Text(label, Modifier.weight(1f)); Switch(checked, onChange) }
}
@Composable private fun Fld(label: String, value: String, onChange: (String) -> Unit) {
    OutlinedTextField(value, onChange, Modifier.fillMaxWidth().padding(vertical = 3.dp), label = { Text(label) }, singleLine = true)
}
@Composable private fun NumFld(label: String, value: Int, modifier: Modifier = Modifier, onChange: (Int) -> Unit) {
    OutlinedTextField(value.takeIf { it > 0 }?.toString() ?: "", { onChange(it.toIntOrNull() ?: 0) }, modifier, label = { Text(label) }, singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
}
@Composable private fun FlowButtons(content: @Composable () -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) { content() }
}
private fun usedPorts(store: Store): Set<Int> {
    val s = HashSet<Int>(); s.add(store.settings.socksPort); s.add(store.settings.httpPort)
    store.pool.forEach { if (it.socksPort > 0) s.add(it.socksPort); if (it.httpPort > 0) s.add(it.httpPort) }
    return s
}
