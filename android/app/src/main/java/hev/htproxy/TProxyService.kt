package hev.htproxy

/**
 * JNI binding for hev-socks5-tunnel (libhev-socks5-tunnel.so). The native symbol
 * names are tied to THIS exact package/class path (hev.htproxy.TProxyService), so
 * it must match the prebuilt .so downloaded by scripts/fetch-libs.sh. This is the
 * standard upstream binding used by several Android proxy clients.
 *
 * It reads all IP packets from the VpnService TUN fd and forwards them to a local
 * SOCKS5 server (our in-process Xray socks inbound).
 *
 * The .so is optional at build time (fetch-libs.sh may skip it), so the library is
 * loaded lazily and guarded: the app installs and runs without it, and the VPN
 * service reports a clear "tunnel core missing" error instead of crashing.
 *
 * What the service relies on, as hev-socks5-tunnel 2.16.0 — the tag the release
 * workflow builds from source (release.yml, HEV_TAG) — behaves in its hev-jni.c:
 *  - TProxyStartService runs hev_socks5_tunnel_main on a pthread of its own and
 *    returns at once. A start while the previous tunnel is still marked working
 *    (the static is_working flag) is SILENTLY IGNORED — which is why every start
 *    in the service is preceded by a stop (XrayVpnService.teardown).
 *  - TProxyStopService asks the tunnel to quit and JOINS its thread before it
 *    returns: once it is back, hev has let go of the TUN fd (which it never
 *    closes — the caller owns it), its sessions are gone and the next start is
 *    clean. With no tunnel marked working it does nothing.
 *  - TProxyGetStats reads [tx_packets, tx_bytes, rx_packets, rx_bytes]: tx is
 *    what hev READ from the TUN (the apps' packets going in), rx what it WROTE
 *    back to it. Zeroed when a tunnel ends. The self-check and the stall
 *    watchdog (StallWatch) judge by these.
 *  - A limit of this tag: a tunnel whose main returned by itself (an init
 *    failure — the only way; the TUN read loop never exits on its own) leaves
 *    is_working set, and the stop that follows spins forever in
 *    hev_socks5_tunnel_stop waiting for an event fd that will never exist —
 *    with the JNI mutex held, so a later start would block on it too. Nothing
 *    here can tell: this tag has no TProxyIsRunning. The service therefore
 *    waits for the stop only so long (EngineReset.bounded), and a process
 *    whose stop never returned runs no tunnel again and restarts itself
 *    (EngineReset) — it used to take a Force Stop. hev 2.17.0+
 *    clears the flag from the thread itself, exposes IsRunning and returns a
 *    boolean from start and stop — but its method table then reads (…)Z, and
 *    RegisterNatives refuses a class whose signatures differ, so the library
 *    would not load at all. The HEV_TAG bump and the declarations below must
 *    change TOGETHER: Boolean returns here the moment the tag moves, never before.
 *
 * The declarations are the 2.16.0 method table exactly — TProxyStartService
 * (Ljava/lang/String;I)V, TProxyStopService ()V, TProxyGetStats ()[J.
 */
object TProxyService {
    /** True when libhev-socks5-tunnel.so is present and loaded. */
    val available: Boolean by lazy {
        try { System.loadLibrary("hev-socks5-tunnel"); true }
        catch (t: Throwable) { false }
    }

    // The JNI (hev-jni.c) runs hev_socks5_tunnel_main on its OWN pthread, so
    // TProxyStartService returns immediately — no need to wrap it in a thread.
    external fun TProxyStartService(configPath: String, fd: Int)
    /** Blocks until hev's thread has ended (see the class comment); call only after a start. */
    external fun TProxyStopService()
    /** [tx_packets, tx_bytes, rx_packets, rx_bytes] — in and out of the TUN as hev saw them. */
    external fun TProxyGetStats(): LongArray
}
