package com.irnetfree.vpn.vpn

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.irnetfree.vpn.core.Store
import com.irnetfree.vpn.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * The Quick Settings tile: lit while connected (or on its way), and a tap
 * connects the selected config or disconnects — the app's own paths
 * (XrayVpnService.connect, as the Connect button calls it, and
 * XrayVpnService.disconnect), with no screen in between. Android's VPN
 * permission is the one thing a tile cannot ask for: until it is given, a tap
 * opens the app, whose Connect asks for it.
 *
 * Not an "active" tile: Android binds it while the Quick Settings panel shows
 * it, and the tile follows VpnState for exactly that long.
 */
class ConnectTile : TileService() {
    /** The VpnState watch while the panel shows the tile; null otherwise. */
    private var watch: CoroutineScope? = null

    override fun onStartListening() {
        super.onStartListening()
        watch?.cancel()
        val sc = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        watch = sc
        sc.launch { VpnState.state.collect { s: ConnState -> show(s) } }
        // a switch while connected names the new config (the state may not move)
        sc.launch { VpnState.label.collect { _: String -> show(VpnState.state.value) } }
    }

    override fun onStopListening() {
        watch?.cancel(); watch = null
        super.onStopListening()
    }

    override fun onDestroy() {
        watch?.cancel(); watch = null
        super.onDestroy()
    }

    override fun onClick() {
        super.onClick()
        val app = applicationContext
        // lit: a tap disconnects — and cancels a connect on its way, as the app's ring does
        if (TileLook.tapDisconnects(VpnState.state.value)) {
            runCatching { XrayVpnService.disconnect(app) }
            return
        }
        if (VpnService.prepare(app) != null) {
            VpnState.addLog("Quick Settings: Android has not given VPN permission yet — connect once in the app")
            openApp()
            return
        }
        // The Connect button's path (doConnect), on the main thread like it: the
        // store's lists are read there. A selection that cannot be built says
        // why in the app, which is opened for it.
        val store = Store.get(app)
        try {
            VpnState.set(ConnState.CONNECTING, store.selectionLabel())
            XrayVpnService.connect(app, store)
        } catch (e: Exception) {
            VpnState.set(ConnState.ERROR, error = e.message ?: "connect failed")
            openApp()
        }
    }

    private fun show(s: ConnState) {
        val tile: Tile = qsTile ?: return
        val look = TileLook.of(s, VpnState.label.value)
        tile.state = if (look.active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = getString(com.irnetfree.vpn.R.string.app_name)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) tile.subtitle = look.subtitle
        tile.contentDescription = "IRNetFree: ${look.subtitle}"
        tile.updateTile()
    }

    /** The app, over the lock screen once it is unlocked; the panel closes. Android 14 takes a PendingIntent only. */
    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val go = Runnable {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startActivityAndCollapse(PendingIntent.getActivity(this, REQUEST_OPEN, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT))
            } else {
                @Suppress("DEPRECATION") startActivityAndCollapse(intent)
            }
        }
        if (isLocked) unlockAndRun(go) else go.run()
    }

    private companion object {
        /** Apart from the notification's PendingIntent (request code 0). */
        const val REQUEST_OPEN = 3
    }
}

/** What the tile shows for a connection state, and what a tap does — pure, so the JVM tests reach it. */
internal object TileLook {
    /** [active]: the tile is lit; [subtitle]: the line under its label (Android 10+). */
    data class Look(val active: Boolean, val subtitle: String)

    fun of(state: ConnState, label: String): Look = when (state) {
        ConnState.CONNECTED -> Look(true, label.ifBlank { "Connected" })
        ConnState.CONNECTING -> Look(true, "Connecting…")
        ConnState.ERROR -> Look(false, "Not connected")
        ConnState.DISCONNECTED -> Look(false, "Off")
    }

    /** Connected or on its way: a tap disconnects (a connect still being prepared stops there). Otherwise it connects. */
    fun tapDisconnects(state: ConnState): Boolean = state == ConnState.CONNECTED || state == ConnState.CONNECTING
}
