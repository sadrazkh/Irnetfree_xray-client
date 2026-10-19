package com.irnetfree.vpn.vpn

import com.irnetfree.vpn.core.LanShare
import com.irnetfree.vpn.core.SettingsApply
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

enum class ConnState { DISCONNECTED, CONNECTING, CONNECTED, ERROR }

data class Traffic(val txBytes: Long = 0, val rxBytes: Long = 0, val txSpeed: Long = 0, val rxSpeed: Long = 0)

/** Process-wide connection state + live traffic, observed by the UI. */
object VpnState {
    private val _state = MutableStateFlow(ConnState.DISCONNECTED)
    val state: StateFlow<ConnState> = _state

    private val _label = MutableStateFlow("")
    val label: StateFlow<String> = _label

    private val _lastError = MutableStateFlow("")
    val lastError: StateFlow<String> = _lastError

    private val _traffic = MutableStateFlow(Traffic())
    val traffic: StateFlow<Traffic> = _traffic

    private val _log = MutableStateFlow<List<String>>(emptyList())
    val log: StateFlow<List<String>> = _log

    private val _connectedSince = MutableStateFlow(0L)
    val connectedSince: StateFlow<Long> = _connectedSince

    /** Post-connect verdict shown on Home: is traffic really working, and if not, where it breaks. */
    private val _health = MutableStateFlow<Health?>(null)
    val health: StateFlow<Health?> = _health
    data class Health(val ok: Boolean, val text: String)
    fun setHealth(ok: Boolean, text: String) { _health.value = Health(ok, text) }

    /**
     * The LAN share the running tunnel really opened (null = none): what
     * Settings → LAN sharing holds against it, to say "sharing now" or
     * "applies on the next connect". Only a CONNECTED tunnel has one.
     */
    private val _lanShared = MutableStateFlow<LanShare?>(null)
    val lanShared: StateFlow<LanShare?> = _lanShared
    fun setLanShared(v: LanShare?) { _lanShared.value = v }

    fun set(s: ConnState, label: String? = null, error: String? = null) {
        _state.value = s
        if (label != null) _label.value = label
        if (error != null && error.isNotBlank()) { _lastError.value = error; addLog("⚠ $error") }
        if (s == ConnState.CONNECTED) { if (_connectedSince.value == 0L) _connectedSince.value = System.currentTimeMillis() }
        // ERROR is reached only once the tunnel is down (XrayVpnService.stopAll
        // keeps it through the teardown), so it ends the session like DISCONNECTED.
        if (s == ConnState.DISCONNECTED || s == ConnState.ERROR) { _connectedSince.value = 0L; _traffic.value = Traffic(); _health.value = null }
        if (s == ConnState.CONNECTING) _health.value = null
        if (s != ConnState.CONNECTED) _lanShared.value = null
    }
    fun setTraffic(t: Traffic) { _traffic.value = t }

    /**
     * Is the app on screen (MainActivity between onStart and onStop)? The
     * per-second figures — the service's traffic reading, the screen's
     * "connected for" clock — are only drawn, so they wait while nobody can
     * see them instead of waking the phone every second (battery).
     */
    private val _uiVisible = MutableStateFlow(false)
    val uiVisible: StateFlow<Boolean> = _uiVisible
    fun setUiVisible(v: Boolean) { _uiVisible.value = v }

    /**
     * What the latest connect built its config from (SettingsApply): the
     * screens name every change made since that the running tunnel does not
     * carry, beside a Reconnect. Written by the connect's prepare.
     */
    private val _applied = MutableStateFlow<SettingsApply.Applied?>(null)
    val applied: StateFlow<SettingsApply.Applied?> = _applied
    fun setApplied(a: SettingsApply.Applied?) { _applied.value = a }

    /**
     * Android's "Block connections without VPN" is on (VpnService.isLockdownEnabled,
     * read when the tunnel comes up): an app per-app routing leaves out of the
     * VPN then has no internet at all instead of going direct.
     */
    private val _lockdown = MutableStateFlow(false)
    val lockdown: StateFlow<Boolean> = _lockdown
    fun setLockdown(v: Boolean) { _lockdown.value = v }
    fun addLog(line: String) { _log.value = (_log.value + line).takeLast(300) }
    fun clearLog() { _log.value = emptyList() }

    val isActive: Boolean get() = _state.value == ConnState.CONNECTED || _state.value == ConnState.CONNECTING
}
