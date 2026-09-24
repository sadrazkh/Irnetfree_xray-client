package com.irnetfree.vpn.core

import java.net.Authenticator

/** The per-session credentials of the tunnel's own local inbounds. */
data class LocalAuth(val user: String, val pass: String) {
    companion object {
        fun random(): LocalAuth = LocalAuth("", "")
    }
}

/** Answers Java's SOCKS client for the tunnel's own inbound. */
object LocalProxyAuth : Authenticator() {
    val activePort: Int? get() = null
    fun set(port: Int, auth: LocalAuth) {}
    fun release(auth: LocalAuth?) {}
}
