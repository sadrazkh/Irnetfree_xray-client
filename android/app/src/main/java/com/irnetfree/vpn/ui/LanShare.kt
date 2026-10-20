package com.irnetfree.vpn.ui

import android.os.Build
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextFieldColors
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.irnetfree.vpn.core.LanShare
import com.irnetfree.vpn.core.Store
import com.irnetfree.vpn.core.t
import com.irnetfree.vpn.core.tf
import com.irnetfree.vpn.vpn.ConnState
import com.irnetfree.vpn.vpn.LanAddresses
import com.irnetfree.vpn.vpn.LanShareStore
import com.irnetfree.vpn.vpn.VpnState
import com.irnetfree.vpn.vpn.XrayVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext

/**
 * Settings → LAN sharing: other devices on the phone's Wi-Fi, or on its
 * hotspot, use the phone as a SOCKS5 or HTTP proxy while it is connected
 * (LanShare; the service opens it — ConfigBuilder / SingboxConfig).
 *
 * The switch, the two ports, the username and password (on by default,
 * generated, readable, copyable, changeable — off only with a warning), and
 * the phone's current addresses as ready-to-copy proxy URLs, asked again every
 * few seconds so they follow the network. A change while connected applies on
 * the next connect, and says so, with a Reconnect button right there — a
 * reconnect is a switch onto the same server (XrayVpnService.connect).
 *
 * Saved on its own (LanShareStore), never through the Settings screen's copy
 * of AppSettings. The fields save once the whole share is valid; until then
 * they say what is wrong and the last valid share stays in force.
 */
@Composable
fun LanShareSection(store: Store) {
    val ctx = LocalContext.current
    val clipboard = LocalClipboardManager.current
    var lan by remember { mutableStateOf(LanShareStore.load(ctx)) }
    var socksText by remember { mutableStateOf(lan.socksPort.toString()) }
    var httpText by remember { mutableStateOf(lan.httpPort.toString()) }
    var userText by remember { mutableStateOf(lan.user) }
    var passText by remember { mutableStateOf(lan.pass) }
    // What is wrong with the fields as typed (they are not saved then); null = saved.
    var draftProblem by remember { mutableStateOf<String?>(null) }
    var addrs by remember { mutableStateOf(emptyList<LanAddresses.Addr>()) }
    val state by VpnState.state.collectAsState()
    val applied by VpnState.lanShared.collectAsState()

    // Wi-Fi joined or left, the hotspot on or off: the addresses change with
    // it. Asked every few seconds while this is on screen — a hotspot is not a
    // Network the system's connectivity callbacks report.
    LaunchedEffect(Unit) {
        while (true) {
            // off screen (the app behind another): nothing asked until it is seen again (battery)
            if (!VpnState.uiVisible.value) VpnState.uiVisible.first { v: Boolean -> v }
            addrs = withContext(Dispatchers.IO) { LanAddresses.current() }
            delay(3000)
        }
    }

    fun save(n: LanShare) { lan = n; LanShareStore.save(ctx, n) }
    fun commitFields() {
        val c = lan.copy(
            socksPort = socksText.trim().toIntOrNull() ?: 0,
            httpPort = httpText.trim().toIntOrNull() ?: 0,
            user = userText, pass = passText
        )
        val p = c.problem(store.settings, store.pool)
        draftProblem = p
        if (p == null && c != lan) save(c)
    }
    fun copyText(text: String) {
        clipboard.setText(AnnotatedString(text))
        // Android 13+ confirms a copy itself.
        if (Build.VERSION.SDK_INT < 33) Toast.makeText(ctx, t("toast.copiedShort"), Toast.LENGTH_SHORT).show()
    }

    HorizontalDivider(Modifier.padding(vertical = 10.dp), color = STROKE)
    Text(t("lan.title"), color = TXT, fontWeight = FontWeight.Bold)
    LanSwitchRow(t("lan.switch"), lan.enabled) { v: Boolean -> save(lan.copy(enabled = v)) }
    Text(
        t("lan.intro"),
        color = MUTED, fontSize = 11.sp
    )
    if (!lan.enabled) return

    Spacer(Modifier.height(8.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            socksText, { v: String -> socksText = v.filter { c -> c.isDigit() }.take(5); commitFields() },
            Modifier.weight(1f), label = { Text(t("lan.socksPort")) }, singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), colors = lanTfColors()
        )
        OutlinedTextField(
            httpText, { v: String -> httpText = v.filter { c -> c.isDigit() }.take(5); commitFields() },
            Modifier.weight(1f), label = { Text(t("lan.httpPort")) }, singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), colors = lanTfColors()
        )
    }

    LanSwitchRow(t("lan.auth"), lan.auth) { v: Boolean -> save(lan.copy(auth = v)) }
    if (lan.auth) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                userText, { v: String -> userText = v; commitFields() },
                Modifier.weight(1f), label = { Text(t("lan.user")) }, singleLine = true, colors = lanTfColors()
            )
            IconButton(onClick = { copyText(userText) }) { Icon(Icons.Filled.ContentCopy, t("lan.copyUser"), tint = PRIMARY) }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                passText, { v: String -> passText = v; commitFields() },
                Modifier.weight(1f), label = { Text(t("f.password")) }, singleLine = true, colors = lanTfColors()
            )
            IconButton(onClick = { copyText(passText) }) { Icon(Icons.Filled.ContentCopy, t("lan.copyPass"), tint = PRIMARY) }
        }
        TextButton(onClick = { userText = LanShare.newUser(); passText = LanShare.newPass(); commitFields() }) {
            Icon(Icons.Filled.Refresh, null, tint = PRIMARY, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(t("lan.newCreds"), color = PRIMARY, fontSize = 13.sp)
        }
    } else {
        Text(
            t("lan.noAuthWarn"),
            color = AMBER, fontSize = 11.sp
        )
    }

    val problem = draftProblem ?: lan.problem(store.settings, store.pool)
    if (problem != null) {
        Spacer(Modifier.height(4.dp))
        Text(tf("lan.problem", "problem" to problem), color = BAD, fontSize = 11.sp)
    }

    // Is what is set here what the running tunnel opened?
    val connected = state == ConnState.CONNECTED
    val same = LanShare.same(lan, applied)
    Spacer(Modifier.height(6.dp))
    when {
        connected && applied != null && same -> Text(t("lan.sharing"), color = PRIMARY, fontSize = 12.sp)
        connected && !same -> Row(verticalAlignment = Alignment.CenterVertically) {
            Text(t("lan.nextConnect"), color = AMBER, fontSize = 12.sp, modifier = Modifier.weight(1f))
            TextButton(onClick = {
                try { XrayVpnService.connect(ctx, store) }
                catch (e: Exception) { VpnState.set(ConnState.ERROR, error = e.message ?: "connect failed") }
            }) { Text(t("apply.reconnect"), color = PRIMARY) }
        }
        else -> Text(t("lan.opensOnConnect"), color = MUTED, fontSize = 12.sp)
    }

    Spacer(Modifier.height(8.dp))
    Text(t("lan.pointAt"), color = TXT2, fontSize = 12.sp)
    if (addrs.isEmpty()) {
        Text(t("lan.noAddr"), color = MUTED, fontSize = 11.sp)
    }
    for (a in addrs) {
        Text("${a.kind} · ${a.iface}", color = MUTED, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp))
        CopyLine(LanAddresses.socksUrl(a.ip, lan)) { t: String -> copyText(t) }
        CopyLine(LanAddresses.httpUrl(a.ip, lan)) { t: String -> copyText(t) }
    }
    if (lan.auth && addrs.isNotEmpty()) Text(t("lan.httpAuth"), color = MUTED, fontSize = 11.sp)
}

@Composable private fun CopyLine(text: String, onCopy: (String) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(text, color = TXT2, fontSize = 12.sp, fontFamily = MONO, modifier = Modifier.weight(1f))
        IconButton(onClick = { onCopy(text) }) { Icon(Icons.Filled.ContentCopy, t("card.copy"), tint = PRIMARY) }
    }
}

@Composable private fun LanSwitchRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = TXT, modifier = Modifier.weight(1f))
        Switch(checked, onChange)
    }
}

@Composable private fun lanTfColors(): TextFieldColors = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = PRIMARY, unfocusedBorderColor = STROKE, focusedTextColor = TXT, unfocusedTextColor = TXT, cursorColor = PRIMARY
)
