package com.irnetfree.vpn.vpn

import android.content.Context
import com.irnetfree.vpn.core.LocalProxyAuth
import com.irnetfree.vpn.core.ServerConfig
import com.irnetfree.vpn.core.Store
import com.irnetfree.vpn.core.Subscriptions

/**
 * Gets a subscription through a core, whether or not the tunnel is up.
 *
 * Two reasons a phone's own request to a panel can fail where the desktop's
 * does not, and this handles the one that is about the PATH:
 *
 * This app excludes its own package from the VPN so the core's sockets can
 * leave the device — which puts every request the app makes on the raw ISP
 * network, even while the tunnel is up. The desktop's whole system sits inside
 * the TUN, so its fetch of the same URL rides the tunnel. A panel the ISP
 * blocks therefore loads on the laptop and not on the phone.
 *
 * (The other reason — the phone's platform TLS lacking the TLS 1.3 a
 * Cloudflare zone demands — is not about the path at all and is handled by
 * IRApp.installTls13. It was the owner's actual bug, and no choice of path
 * could have fixed it.)
 *
 * So the fetch goes through a core when it can:
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
        // 1. The tunnel, if it is up: its inbound is already listening. It asks
        //    for the session's credentials, which java.net's SOCKS client gets
        //    from LocalProxyAuth — for that port, the one the tunnel really
        //    runs on even if Settings has changed since.
        if (VpnState.state.value == ConnState.CONNECTED) {
            val port = LocalProxyAuth.activePort ?: store.settings.socksPort
            return tagged("the tunnel") { Outcome(Subscriptions.fetch(url, port), "the tunnel") }
        }

        // 2. A throwaway core on a free port. Not being connected is the normal
        //    case for "add a subscription", so this is the path that matters.
        val server = borrowServer(store)
        if (server == null) {
            log("Subscription: not connected and no config to borrow a core from — trying the network directly")
        } else {
            log("Subscription: not connected — fetching through a temporary ${server.name} core")
            val handle = XrayTester.start(ctx, server, store.settings)
            if (handle == null) {
                log("Subscription: the temporary ${server.name} core did not start — trying the network directly")
            } else {
                val via = "a temporary core (${server.name})"
                try {
                    return tagged(via) { Outcome(Subscriptions.fetch(url, handle.port), via) }
                } finally {
                    XrayTester.stop(handle)
                }
            }
        }

        // 3. Nothing to borrow, or nothing that would start.
        val why = if (server == null) "your normal network (no config to borrow)" else "your normal network (the ${server.name} core would not start)"
        return tagged(why) { Outcome(Subscriptions.fetch(url, null), why) }
    }

    /** Whatever went wrong, the message says which of the three paths it was on. */
    private inline fun tagged(via: String, body: () -> Outcome): Outcome = try {
        body()
    } catch (e: Exception) {
        throw RuntimeException("via $via: ${e.message ?: e.javaClass.simpleName}", e)
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
