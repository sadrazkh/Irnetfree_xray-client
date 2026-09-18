package com.irnetfree.vpn.vpn

import android.content.Context
import com.irnetfree.vpn.core.ServerConfig
import com.irnetfree.vpn.core.Store
import com.irnetfree.vpn.core.Subscriptions

/**
 * Gets a subscription through a core, whether or not the tunnel is up.
 *
 * WHY THIS EXISTS, from the log line that finally said it:
 *
 *   sub.irnetfree.info -> 2a06:98c1:3120::3, …, 188.114.99.0 (os);
 *   could not read the certificate (Handshake failed)
 *
 * Every address there is Cloudflare's, so the name resolved correctly — DNS was
 * never the problem, and neither was the certificate: that probe runs with
 * verification switched off and still got no certificate at all. Nothing
 * answered for the panel. The TLS connection was being broken before a
 * certificate could arrive, which is what SNI-triggered interference looks
 * like from inside the client: the ClientHello carrying `sub.irnetfree.info`
 * goes out in the clear and the connection dies.
 *
 * A browser gets away with it (encrypted ClientHello, or QUIC) and so does the
 * desktop client — but only because the desktop's whole system sits inside the
 * TUN, so its fetch was never on the raw network in the first place. The phone
 * has no such luck: this app excludes its own package from the VPN so the
 * core's sockets can leave the device, which puts every request it makes back
 * out on the network that is breaking them.
 *
 * So the fetch goes through a core, always:
 *
 *   - tunnel up  -> the running core's own SOCKS inbound
 *   - tunnel down -> a THROWAWAY core on a free port, exactly as a latency test
 *     already does, torn down as soon as the body is in
 *   - no servers at all -> direct, because there is nothing else to try; a
 *     brand-new install with only a subscription URL has no core to borrow
 *
 * The throwaway is what removes the chicken and egg. "Connect first" is not an
 * answer when connecting is what needs the subscription.
 *
 * Blocking — run on Dispatchers.IO.
 */
object SubFetch {

    /** What was used, for the log. */
    data class Outcome(val result: Subscriptions.Result, val via: String)

    fun fetch(ctx: Context, store: Store, url: String, log: (String) -> Unit = {}): Outcome {
        // 1. The tunnel, if it is up: its inbound is already listening.
        if (VpnState.state.value == ConnState.CONNECTED) {
            return Outcome(Subscriptions.fetch(url, store.settings.socksPort), "the tunnel")
        }

        // 2. A throwaway core on a free port. Not being connected is the normal
        //    case for "add a subscription", so this is the path that matters.
        val server = borrowServer(store)
        if (server != null) {
            log("Subscription: not connected — fetching through a temporary ${server.name} core")
            val handle = XrayTester.start(ctx, server)
            if (handle != null) {
                try {
                    return Outcome(Subscriptions.fetch(url, handle.port), "a temporary core (${server.name})")
                } finally {
                    XrayTester.stop(handle)
                }
            }
            log("Subscription: the temporary core did not start — trying the network directly")
        }

        // 3. Nothing to borrow.
        return Outcome(Subscriptions.fetch(url, null), "your normal network")
    }

    /**
     * A server to borrow: the selected one when it is a single config, else the
     * first config that can be dialled on its own. A chain or pool selection has
     * no single server to hand a test config, so its first member is used —
     * reaching the panel is the only job here, not reproducing the route.
     */
    private fun borrowServer(store: Store): ServerConfig? {
        val sel = store.selection
        store.serverById(sel)?.let { return it }
        store.chainById(sel.removePrefix("chain:"))?.let { c ->
            store.chainMembers(c).firstOrNull()?.let { return it }
        }
        return store.servers.firstOrNull { it.outbound.length() > 0 }
    }
}
