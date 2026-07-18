package com.irnetfree.vpn.vpn

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

    fun set(s: ConnState, label: String? = null, error: String? = null) {
        _state.value = s
        if (label != null) _label.value = label
        if (error != null && error.isNotBlank()) { _lastError.value = error; addLog("⚠ $error") }
        if (s == ConnState.CONNECTED) { if (_connectedSince.value == 0L) _connectedSince.value = System.currentTimeMillis() }
        if (s == ConnState.DISCONNECTED) { _connectedSince.value = 0L; _traffic.value = Traffic() }
    }
    fun setTraffic(t: Traffic) { _traffic.value = t }
    fun addLog(line: String) { _log.value = (_log.value + line).takeLast(300) }
    fun clearLog() { _log.value = emptyList() }

    val isActive: Boolean get() = _state.value == ConnState.CONNECTED || _state.value == ConnState.CONNECTING
}
