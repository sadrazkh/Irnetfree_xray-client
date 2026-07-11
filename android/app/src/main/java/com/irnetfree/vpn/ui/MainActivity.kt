package com.irnetfree.vpn.ui

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
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
import androidx.compose.ui.unit.dp
import com.irnetfree.vpn.core.*
import com.irnetfree.vpn.vpn.ConnState
import com.irnetfree.vpn.vpn.VpnState
import com.irnetfree.vpn.vpn.XrayVpnService

class MainActivity : ComponentActivity() {
    private lateinit var store: Store

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = Store(this)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(primary = Color(0xFF4F8CFF), secondary = Color(0xFF2DD4BF))) {
                Surface(Modifier.fillMaxSize(), color = Color(0xFF0D1117)) {
                    App(store)
                }
            }
        }
    }
}

private enum class Tab(val label: String) { CONNECT("اتصال"), SERVERS("سرورها"), POOL("استخر") }

@Composable
private fun App(store: Store) {
    var tab by remember { mutableStateOf(Tab.CONNECT) }
    var rev by remember { mutableIntStateOf(0) }              // bump to force recompose after store edits
    val bump = { rev++ }

    Scaffold(
        containerColor = Color.Transparent,
        bottomBar = {
            NavigationBar(containerColor = Color(0xFF12161d)) {
                Tab.entries.forEach { tb ->
                    NavigationBarItem(
                        selected = tab == tb,
                        onClick = { tab = tb },
                        icon = {
                            Icon(
                                when (tb) {
                                    Tab.CONNECT -> Icons.Filled.Power
                                    Tab.SERVERS -> Icons.Filled.Dns
                                    Tab.POOL -> Icons.Filled.Extension
                                }, null
                            )
                        },
                        label = { Text(tb.label) }
                    )
                }
            }
        }
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            key(rev) {
                when (tab) {
                    Tab.CONNECT -> ConnectTab(store, bump)
                    Tab.SERVERS -> ServersTab(store, bump)
                    Tab.POOL -> PoolTab(store, bump)
                }
            }
        }
    }
}

/* ----------------------------- Connect ----------------------------- */

@Composable
private fun ConnectTab(store: Store, bump: () -> Unit) {
    val ctx = LocalContext.current
    val state by VpnState.state.collectAsState()
    val label by VpnState.label.collectAsState()
    val err by VpnState.lastError.collectAsState()

    val vpnPrepare = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
        if (res.resultCode == android.app.Activity.RESULT_OK) startConnect(ctx, store)
    }

    fun onConnectClick() {
        if (state == ConnState.CONNECTED || state == ConnState.CONNECTING) {
            XrayVpnService.disconnect(ctx); return
        }
        val prepare: Intent? = VpnService.prepare(ctx)
        if (prepare != null) vpnPrepare.launch(prepare) else startConnect(ctx, store)
    }

    Column(
        Modifier.fillMaxSize().padding(20.dp).verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(24.dp))
        Text("IRNetFree", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(4.dp))
        Text(
            when (state) {
                ConnState.CONNECTED -> "متصل"
                ConnState.CONNECTING -> "در حال اتصال…"
                ConnState.ERROR -> "خطا"
                else -> "قطع"
            },
            color = if (state == ConnState.CONNECTED) Color(0xFF2DD4BF) else Color.Gray
        )
        Spacer(Modifier.height(28.dp))

        // big connect button
        Button(
            onClick = { onConnectClick() },
            modifier = Modifier.size(150.dp),
            shape = androidx.compose.foundation.shape.CircleShape,
            colors = ButtonDefaults.buttonColors(
                containerColor = if (state == ConnState.CONNECTED) Color(0xFF17604b) else Color(0xFF1e2a44)
            )
        ) { Icon(Icons.Filled.Power, null, Modifier.size(56.dp)) }

        Spacer(Modifier.height(28.dp))

        // target selector
        Text("خروجی انتخابی", color = Color.Gray, style = MaterialTheme.typography.labelMedium)
        Spacer(Modifier.height(6.dp))
        SelectionPicker(store)
        Spacer(Modifier.height(6.dp))
        Text(store.selectionLabel(), color = Color(0xFFB6C2D4))

        if (state == ConnState.ERROR && err.isNotBlank()) {
            Spacer(Modifier.height(16.dp))
            Text(err, color = Color(0xFFf07178), style = MaterialTheme.typography.bodySmall)
        }
        Spacer(Modifier.height(24.dp))
        Text(
            "حالت تونل کل سیستم (TUN). استخر پروکسی هم روی همین اتصال، پورت‌های جدا را باز می‌کند.",
            color = Color.Gray, style = MaterialTheme.typography.bodySmall
        )
    }
}

private fun startConnect(ctx: android.content.Context, store: Store) {
    try {
        VpnState.set(ConnState.CONNECTING, store.selectionLabel())
        XrayVpnService.connect(ctx, store)
    } catch (e: Exception) {
        VpnState.set(ConnState.ERROR, error = e.message ?: "connect failed")
    }
}

@Composable
private fun SelectionPicker(store: Store) {
    var open by remember { mutableStateOf(false) }
    val options = buildList {
        if (store.poolEnabledValid().isNotEmpty()) add(Store.POOL_ID to "🧩 Proxy Pool (${store.poolEnabledValid().size})")
        store.chains.filter { store.chainReady(it) }.forEach { add("chain:${it.id}" to "⛓ ${it.name}") }
        store.servers.forEach { add(it.id to "${it.protocol} · ${it.name}") }
    }
    Box {
        OutlinedButton(onClick = { open = true }) {
            Text(options.firstOrNull { it.first == store.selection }?.second ?: "انتخاب کن")
            Icon(Icons.Filled.ArrowDropDown, null)
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            if (options.isEmpty()) DropdownMenuItem(text = { Text("سروری اضافه نشده") }, onClick = { open = false })
            options.forEach { (id, lbl) ->
                DropdownMenuItem(text = { Text(lbl) }, onClick = { store.saveSelection(id); open = false })
            }
        }
    }
}

/* ----------------------------- Servers ----------------------------- */

@Composable
private fun ServersTab(store: Store, bump: () -> Unit) {
    var importText by remember { mutableStateOf("") }
    var msg by remember { mutableStateOf("") }

    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        Text("سرورها", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(10.dp))
        OutlinedTextField(
            value = importText, onValueChange = { importText = it },
            label = { Text("لینک کانفیگ یا socks:// (چند خط مجاز است)") },
            modifier = Modifier.fillMaxWidth(), minLines = 2, maxLines = 5
        )
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = {
                val (parsed, errs) = LinkParser.parseMany(importText)
                store.servers.addAll(parsed); store.saveServers()
                if (parsed.isNotEmpty() && store.selection.isEmpty()) store.saveSelection(store.servers.first().id)
                msg = "${parsed.size} افزوده شد" + if (errs.isNotEmpty()) " (${errs.size} خطا)" else ""
                importText = ""; bump()
            }) { Text("وارد کردن") }
            if (msg.isNotEmpty()) Text(msg, color = Color(0xFF2DD4BF), modifier = Modifier.align(Alignment.CenterVertically))
        }
        Spacer(Modifier.height(16.dp))
        if (store.servers.isEmpty()) {
            Text("هنوز سروری نیست. یک لینک را بالا وارد کن.", color = Color.Gray)
        }
        store.servers.toList().forEach { s ->
            Card(Modifier.fillMaxWidth().padding(vertical = 4.dp), colors = CardDefaults.cardColors(containerColor = Color(0xFF161b22))) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(s.name)
                        Text("${s.protocol} · ${s.address}:${s.port}", color = Color.Gray, style = MaterialTheme.typography.bodySmall)
                    }
                    IconButton(onClick = { store.saveSelection(s.id); bump() }) {
                        Icon(Icons.Filled.CheckCircle, null,
                            tint = if (store.selection == s.id) Color(0xFF2DD4BF) else Color.Gray)
                    }
                    IconButton(onClick = {
                        store.servers.removeAll { it.id == s.id }; store.saveServers(); bump()
                    }) { Icon(Icons.Filled.Delete, null, tint = Color(0xFFf07178)) }
                }
            }
        }
    }
}

/* ----------------------------- Pool ----------------------------- */

@Composable
private fun PoolTab(store: Store, bump: () -> Unit) {
    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("استخر پروکسی", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            Button(onClick = {
                val used = usedPorts(store)
                var sp = 60001; while (used.contains(sp)) sp++
                var hp = sp + 1; while (used.contains(hp)) hp++
                store.pool.add(
                    PoolEntry(newId("px"), "پروکسی ${store.pool.size + 1}",
                        store.servers.firstOrNull()?.id ?: "", sp, hp, true)
                )
                store.savePool(); bump()
            }) { Text("+ جدید") }
        }
        Spacer(Modifier.height(6.dp))
        Text(
            "چند خروجی هم‌زمان، هرکدام روی پورت محلی جدا. «اولین موردِ فعال» خروجی اصلیِ TUN است.",
            color = Color.Gray, style = MaterialTheme.typography.bodySmall
        )
        Spacer(Modifier.height(6.dp))
        Button(onClick = { store.saveSelection(Store.POOL_ID); bump() }) { Text("انتخاب استخر برای اتصال") }
        Spacer(Modifier.height(12.dp))

        if (store.pool.isEmpty()) Text("هنوز پروکسی‌ای نیست.", color = Color.Gray)

        store.pool.toList().forEachIndexed { idx, entry ->
            PoolCard(store, entry, idx, bump)
        }
    }
}

@Composable
private fun PoolCard(store: Store, entry: PoolEntry, idx: Int, bump: () -> Unit) {
    val valid = store.poolTargetValid(entry.target)
    Card(Modifier.fillMaxWidth().padding(vertical = 6.dp), colors = CardDefaults.cardColors(containerColor = Color(0xFF161b22))) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(entry.name, Modifier.weight(1f))
                Switch(checked = entry.enabled, onCheckedChange = {
                    store.pool[idx] = entry.copy(enabled = it); store.savePool(); bump()
                })
                IconButton(onClick = { store.pool.removeAt(idx); store.savePool(); bump() }) {
                    Icon(Icons.Filled.Delete, null, tint = Color(0xFFf07178))
                }
            }
            // target picker
            TargetPicker(store, entry.target) { t -> store.pool[idx] = entry.copy(target = t); store.savePool(); bump() }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = entry.socksPort.takeIf { it > 0 }?.toString() ?: "",
                    onValueChange = { store.pool[idx] = entry.copy(socksPort = it.toIntOrNull() ?: 0); store.savePool() },
                    label = { Text("SOCKS") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.weight(1f)
                )
                OutlinedTextField(
                    value = entry.httpPort.takeIf { it > 0 }?.toString() ?: "",
                    onValueChange = { store.pool[idx] = entry.copy(httpPort = it.toIntOrNull() ?: 0); store.savePool() },
                    label = { Text("HTTP") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.weight(1f)
                )
            }
            if (!valid) Text("⚠ خروجی نامعتبر — یک کانفیگ/زنجیرهٔ آماده انتخاب کن.",
                color = Color(0xFFE3B85A), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun TargetPicker(store: Store, current: String, onPick: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    val options = buildList {
        store.servers.forEach { add(it.id to it.name) }
        store.chains.filter { store.chainReady(it) }.forEach { add("chain:${it.id}" to "⛓ ${it.name}") }
    }
    val label = options.firstOrNull { it.first == current }?.second ?: "انتخاب خروجی"
    Box {
        OutlinedButton(onClick = { open = true }, modifier = Modifier.fillMaxWidth()) {
            Text(label, Modifier.weight(1f)); Icon(Icons.Filled.ArrowDropDown, null)
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            options.forEach { (id, lbl) -> DropdownMenuItem(text = { Text(lbl) }, onClick = { onPick(id); open = false }) }
        }
    }
}

private fun usedPorts(store: Store): Set<Int> {
    val s = HashSet<Int>()
    s.add(store.settings.socksPort); s.add(store.settings.httpPort)
    store.pool.forEach { if (it.socksPort > 0) s.add(it.socksPort); if (it.httpPort > 0) s.add(it.httpPort) }
    return s
}
