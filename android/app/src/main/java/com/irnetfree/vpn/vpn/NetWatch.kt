package com.irnetfree.vpn.vpn

/**
 * The phone's own network under a live tunnel — the pure part of the
 * service's watcher (XrayVpnService.NetWatcher), kept here so the JVM tests
 * reach it.
 *
 * Why it exists: a move from Wi-Fi to mobile data, onto another Wi-Fi, or the
 * same Wi-Fi dropping and coming back does not stop the core — it only kills
 * the sockets the core held (a WireGuard outbound's above all), and the
 * session can sit there "Connected" carrying nothing. The desktop rebuilds on
 * every settled change (netWatcher.js); the router learnt that most changes
 * leave the tunnel working and that a needless rebuild is seconds of no tunnel
 * for nothing, so it asks the tunnel first (wanWatch.js: a 204 through the
 * local SOCKS inbound, twice, 5 s apart; rebuilt only when neither answered).
 * This is the router's judgement on Android's own signal: nothing is polled —
 * ConnectivityManager says when the default network moves
 * (registerDefaultNetworkCallback; this app is outside its own VPN, so its
 * default network is the phone's real one, never the tunnel).
 */
object NetWatch {
    /** How long the default network must hold still after a change before the tunnel is asked. */
    const val SETTLE_MS = 3_000L

    /** Between the two asks (wanWatch.js probeGapMs). */
    const val PROBE_GAP_MS = 5_000L

    /** One ask's connect and read timeout, in ms (Diagnostics.httpLatency). */
    const val PROBE_TIMEOUT_MS = 6_000

    /** At most one rebuild in this long: a network that keeps moving must not keep the tunnel rebuilding. */
    const val REBUILD_EVERY_MS = 60_000L

    /** Transport names (the service maps NetworkCapabilities onto them). */
    const val WIFI = "wifi"
    const val CELLULAR = "cellular"
    const val ETHERNET = "ethernet"
    const val BLUETOOTH = "bluetooth"
    const val OTHER = "other"

    /** What a change that has held still comes to. */
    enum class Settled {
        /** The default network never left what the tunnel was judged on. */
        NOTHING,
        /** It moved, and there is no network now: nothing to rebuild onto — held until one comes. */
        NO_NETWORK,
        /** It moved and has settled on a network: ask the tunnel whether it survived. */
        ASK
    }

    /**
     * The default network as the callbacks have told it, and whether it has
     * moved since the tunnel was last judged. One per session; used on one
     * thread (the service's main thread, where its callbacks are delivered).
     *
     * The question a settle answers is "did the network LEAVE what it was at
     * any point" — not "is it different now" (netWatcher.js tick): Wi-Fi that
     * drops and comes back on the same access point reads as no change if
     * only the end state is compared, while every socket the core held died
     * with the link.
     */
    class Tracker {
        /** The default network's id (Network.toString(), its netId); null = none. */
        var id: String? = null
            private set

        /** Its transports once onCapabilitiesChanged has named them; empty = not told yet. */
        var transports: Set<String> = emptySet()
            private set

        /** The network has LEFT what it was since the last judgement (a flap back still counts). */
        var moved = false
            private set

        /** A baseline is known — [begin], or the first network the callbacks named. */
        private var seen = false

        /**
         * What the phone was on when the watch began ([netId] null = no network
         * at all): a network that only comes after it is then a change. Without
         * it, the first network the callbacks name is the baseline.
         */
        fun begin(netId: String?) { seen = true; id = netId; transports = emptySet() }

        /** onAvailable: [netId] is the default network now. True when that is a change. */
        fun available(netId: String): Boolean {
            if (!seen) { begin(netId); return false }
            if (netId == id) return false
            id = netId; transports = emptySet(); moved = true
            return true
        }

        /** onLost: true when it was the default network that went. */
        fun lost(netId: String): Boolean {
            if (!seen || netId != id) return false
            id = null; transports = emptySet(); moved = true
            return true
        }

        /**
         * onCapabilitiesChanged: true only when the default network's transport
         * changed under the same network — never its signal strength or its
         * validation, which change all the time, and not the transports being
         * named for the first time (that is learning, not a move).
         */
        fun capabilities(netId: String, now: Set<String>): Boolean {
            if (!seen) { begin(netId); transports = now; return false }
            if (netId != id) return false
            val was = transports
            transports = now
            if (was.isEmpty() || was == now) return false
            moved = true
            return true
        }

        /** The last change has held still for [SETTLE_MS]: what now. ASK clears the move (it is being judged). */
        fun settle(): Settled = when {
            !moved -> Settled.NOTHING
            id == null -> Settled.NO_NETWORK
            else -> { moved = false; Settled.ASK }
        }
    }

    /**
     * How long until a rebuild may run (0 = now), given when the last one ran
     * ([lastAt], elapsed real time; 0 = never): at most one per [REBUILD_EVERY_MS].
     */
    fun rebuildWait(lastAt: Long, now: Long): Long {
        if (lastAt <= 0L || now < lastAt) return 0L
        val since = now - lastAt
        return if (since >= REBUILD_EVERY_MS) 0L else REBUILD_EVERY_MS - since
    }

    /** The network named for the log: "Wi-Fi", "mobile data", … ; "the new network" while its transport is not known yet. */
    fun label(transports: Set<String>): String = when {
        WIFI in transports -> "Wi-Fi"
        CELLULAR in transports -> "mobile data"
        ETHERNET in transports -> "Ethernet"
        BLUETOOTH in transports -> "Bluetooth tethering"
        transports.isEmpty() -> "the new network"
        else -> "a network"
    }
}
