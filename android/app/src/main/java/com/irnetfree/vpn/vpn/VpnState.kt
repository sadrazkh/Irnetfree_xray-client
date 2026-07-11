package com.irnetfree.vpn.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

enum class ConnState { DISCONNECTED, CONNECTING, CONNECTED, ERROR }

/** Process-wide connection state, observed by the UI. */
object VpnState {
    private val _state = MutableStateFlow(ConnState.DISCONNECTED)
    val state: StateFlow<ConnState> = _state

    private val _label = MutableStateFlow("")
    val label: StateFlow<String> = _label

    private val _lastError = MutableStateFlow("")
    val lastError: StateFlow<String> = _lastError

    fun set(s: ConnState, label: String? = null, error: String? = null) {
        _state.value = s
        if (label != null) _label.value = label
        if (error != null) _lastError.value = error
    }

    val isActive: Boolean get() = _state.value == ConnState.CONNECTED || _state.value == ConnState.CONNECTING
}
