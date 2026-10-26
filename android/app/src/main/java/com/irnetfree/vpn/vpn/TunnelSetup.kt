package com.irnetfree.vpn.vpn

import com.irnetfree.vpn.core.AppSettings
import com.irnetfree.vpn.core.ConfigBuilder
import com.irnetfree.vpn.core.ConnectionPlan
import com.irnetfree.vpn.core.CoreCompat
import com.irnetfree.vpn.core.EngineChoice
import com.irnetfree.vpn.core.GroupEvict
import com.irnetfree.vpn.core.Groups
import com.irnetfree.vpn.core.JsonImport
import com.irnetfree.vpn.core.LanShare
import com.irnetfree.vpn.core.LocalAuth
import com.irnetfree.vpn.core.PoolEntry
import com.irnetfree.vpn.core.RouteRule
import com.irnetfree.vpn.core.RoutingProfiles
import com.irnetfree.vpn.core.ServerConfig
import com.irnetfree.vpn.core.SingboxConfig
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicLong

/**
 * The pure parts of bringing the tunnel up, kept out of the VpnService so the
 * JVM tests reach them: which apps the TUN takes, and what hev is told.
 */
object TunnelSetup {
    /** What the VpnService.Builder is told. The two lists are never both used (the builder refuses a mix). */
    data class PerApp(val allowed: List<String>, val disallowed: List<String>)

    /**
     * Our own package is never inside the TUN: the core's sockets would loop
     * back into it. "Only these apps" simply leaves it out of the list — and if
     * that leaves nothing, the whole device goes through, minus us.
     */
    fun perApp(mode: String, apps: List<String>, self: String): PerApp {
        val others = apps.filter { it.isNotBlank() && it != self }.distinct()
        return when {
            mode == "allow" && others.isNotEmpty() -> PerApp(others, emptyList())
            mode == "disallow" -> PerApp(emptyList(), others + self)
            else -> PerApp(emptyList(), listOf(self))
        }
    }

    /**
     * hev-socks5-tunnel's config: the TUN → the core's local SOCKS inbound, with
     * the session's credentials when the inbound asks for them (LocalAuth.kt).
     * They are single-quoted, so a quote inside is doubled — LocalAuth.random()
     * never makes one, but nothing else here stops a caller that does.
     */
    fun tun2socksYaml(socksPort: Int, auth: LocalAuth?, mtu: Int, ipv4: String, ipv6: String?): String = buildString {
        fun q(s: String) = s.replace("'", "''")
        append("tunnel:\n  mtu: $mtu\n  ipv4: $ipv4\n")
        if (ipv6 != null) append("  ipv6: '$ipv6'\n")
        append("socks5:\n  port: $socksPort\n  address: 127.0.0.1\n  udp: 'udp'\n")
        if (auth != null) append("  username: '${q(auth.user)}'\n  password: '${q(auth.pass)}'\n")
        append("misc:\n  task-stack-size: 20480\n  connect-timeout: 5000\n  read-write-timeout: 60000\n  log-level: warn\n")
    }

    /** The core a connect really runs, its config, and the groups that config runs (ConfigBuilder.Built; empty: none). */
    class CoreConfig(val engine: String, val json: String, val groups: List<GroupEvict.Group> = emptyList())

    /**
     * A JSON server set to run raw (exactly as written) — which the desktop
     * does in proxy mode only. Android's VPN is always a TUN, so here it runs
     * in its full form; the stored mode is kept, so a backup round-trips.
     */
    fun setToRaw(server: ServerConfig): Boolean = server.isJson && server.jsonMode == JsonImport.MODE_RAW

    /**
     * The servers a plan routes to: a single server, a chain's hops, the
     * targets of a pool's entries or of advanced routing's rules (not every
     * server the store holds, which those plans carry along). A group stands
     * for its members (Groups.serversOf).
     */
    fun planTargets(plan: ConnectionPlan): List<ServerConfig> = planRecords(plan).flatMap { srv: ServerConfig -> Groups.serversOf(srv) }

    private fun planRecords(plan: ConnectionPlan): List<ServerConfig> {
        fun resolve(t: String, byId: Map<String, ServerConfig>, chains: Map<String, List<ServerConfig>>): List<ServerConfig> = when {
            t.startsWith("chain:") -> chains[t.substring(6)] ?: emptyList()
            t == "proxy" -> listOfNotNull(byId.values.firstOrNull { srv: ServerConfig -> srv.outbound.length() > 0 })
            else -> listOfNotNull(byId[t])
        }
        return when (plan) {
            is ConnectionPlan.Single -> listOf(plan.server)
            is ConnectionPlan.Chain -> plan.members
            is ConnectionPlan.Pool -> (plan.entries.map { e: PoolEntry -> e.target } + plan.primary)
                .flatMap { t: String -> resolve(t, plan.serversById, plan.chainsById) }
            // the bases the targets ride on are routed to as well (RoutingProfiles.basesOf)
            is ConnectionPlan.Advanced -> (plan.rules.map { r: RouteRule -> r.target } + plan.def + RoutingProfiles.basesOf(plan))
                .flatMap { t: String -> resolve(t, plan.serversById, plan.chainsById) }
        }
    }

    /**
     * The config for [engine]: sing-box's own format for a single server, the
     * Xray format for everything else — PattN takes that very JSON, so the
     * in-process core and PattN carry LAN sharing identically. A server
     * sing-box cannot express (WireGuard, an exotic transport) falls back to
     * the Xray format on the in-process core, and says so through [log].
     * (XrayVpnService.prepare has already moved a non-single plan, or a
     * sing-box that is not bundled, onto the in-process core.)
     *
     * [muxIds]: the servers whose outbounds carry Xray's mux (Mux.choose) — in
     * the Xray format only; sing-box's config never has it.
     *
     * [groupSkip], [metricsPort]: the group members set aside, and where a
     * config that runs a group opens its metrics listener (ConfigBuilder.build).
     * [relayPort]: the chain relay's loopback port, locked with [auth]
     * (ConfigBuilder.relayHopDials); 0: none.
     */
    fun coreConfig(
        engine: String, plan: ConnectionPlan, s: AppSettings, geo: Boolean, wgIps: Map<String, String>,
        auth: LocalAuth?, lan: LanShare?, muxIds: Set<String> = emptySet(),
        groupSkip: Set<String> = emptySet(), metricsPort: Int = 0, relayPort: Int = 0,
        coreVersion: (String) -> String = { "" }, log: (String) -> Unit
    ): CoreConfig {
        val single = plan as? ConnectionPlan.Single
        // Raw (exactly as written) runs on the desktop in proxy mode; Android's
        // VPN is always a TUN, so a JSON server set to raw runs in its full form
        // here, wherever the plan uses it — said once per connect.
        planTargets(plan).filter { srv: ServerConfig -> setToRaw(srv) }.distinctBy { srv: ServerConfig -> srv.id }
            .forEach { srv: ServerConfig -> log("\"${srv.name}\" is set to run raw — on Android its full form runs, so the app's DNS and tunnel rules apply") }
        if (engine == EngineChoice.SINGBOX && single != null) {
            try {
                return CoreConfig(engine, SingboxConfig.build(single.server, s, auth, lan).toString())
            } catch (t: Throwable) {
                log("sing-box: ${t.message} — using the in-process core")
            }
        }
        val e = if (engine == EngineChoice.SINGBOX) EngineChoice.XRAY else engine
        val built = ConfigBuilder.buildWithGroups(plan, s, geoAssets = geo, wgEndpointIps = wgIps, inboundAuth = auth, lan = lan, muxIds = muxIds,
            groupSkip = groupSkip, metricsPort = metricsPort, relayPort = relayPort)
        val config = built.config
        // mKCP's and Hysteria's settings, in the form THIS core's version takes
        // (CoreCompat) — its version is asked only for a config that has them
        val adapted = if (CoreCompat.needsCoreVersion(config)) CoreCompat.adaptForCore(config, coreVersion(e)) else config
        return CoreConfig(e, adapted.toString(), built.groups)
    }

    /**
     * The same config without LAN sharing — for a connect whose LAN port turned
     * out to be taken by another app when it came to bind it: bound on every
     * interface, one taken port takes the whole core down with "address in use".
     * Drops the lan-* inbounds and the rules that name only them; in a rule that
     * also names another inbound (the pool's), just their tags. Both formats:
     * Xray's routing.rules[].inboundTag, sing-box's route.rules[].inbound.
     */
    fun withoutLan(config: String): String {
        val c = JSONObject(config)
        val lan = setOf(LanShare.SOCKS_TAG, LanShare.HTTP_TAG)
        c.optJSONArray("inbounds")?.let { a -> c.put("inbounds", keep(a) { o -> o.optString("tag") !in lan }) }
        for ((section, key) in listOf("routing" to "inboundTag", "route" to "inbound")) {
            val rules = c.optJSONObject(section)?.optJSONArray("rules") ?: continue
            val out = JSONArray()
            for (i in 0 until rules.length()) {
                val r = rules.optJSONObject(i) ?: continue
                val tags = r.optJSONArray(key)
                if (tags == null) { out.put(r); continue }
                val rest = (0 until tags.length()).map { j -> tags.optString(j) }.filter { t -> t !in lan }
                if (rest.size == tags.length()) { out.put(r); continue }
                if (rest.isEmpty()) continue
                out.put(r.put(key, JSONArray(rest)))
            }
            // sing-box's route has no rules at all without LAN sharing
            if (out.length() == 0) c.getJSONObject(section).remove("rules") else c.getJSONObject(section).put("rules", out)
        }
        return c.toString()
    }

    /**
     * The log lines a connect owes about its routing — what it applies, and
     * whatever of the screen's routing it cannot (each said once a connect):
     *  - the simple mode it runs ("Routing: Bypass Iran …"), or the profile's rules;
     *  - a server on sing-box carries none of the app's routing here (SingboxConfig
     *    has no geo rules), so Bypass Iran and custom rules do not apply to it;
     *  - app rules ('process', from a Windows profile): Android never tells a VPN
     *    which app opened a connection, so they are left out;
     *  - Android's Private DNS set to a host ([privateDns]): the phone asks it,
     *    not the core's resolver, so a bypass can miss Iranian sites on foreign CDNs.
     */
    fun routingNotes(plan: ConnectionPlan, s: AppSettings, engine: String, geo: Boolean, privateDns: String?): List<String> {
        val out = ArrayList<String>()
        val adv = plan as? ConnectionPlan.Advanced
        val modeOn = (adv == null || (adv.useMode ?: s.advancedUseMode)) && geo
        val mode = when (s.routingMode) { "bypass-ir" -> "Bypass Iran"; "bypass-cn" -> "Bypass China"; "direct" -> "Direct"; else -> "Global" }
        if (engine == EngineChoice.SINGBOX) {
            if (s.routingMode != "global" || s.customRules.isNotEmpty())
                out.add("⚠ This server runs on sing-box, which carries none of the app's routing here — $mode and the custom rules do not apply to it. Choose Xray as its core in its edit sheet to have them.")
            return out
        }
        if (adv != null) {
            val apps = adv.rules.count { r: RouteRule -> r.type == "process" }
            out.add("Routing: the profile's ${adv.rules.size - apps} rule(s)" + (if (modeOn && s.routingMode.startsWith("bypass")) ", then $mode under them" else "") + ", the rest to its default")
            if (apps > 0) out.add("⚠ ${if (apps == 1) "1 app rule" else "$apps app rules"} of this profile came from Windows and ${if (apps == 1) "is" else "are"} left out: Android does not tell a VPN which app opened a connection. Settings → Per-app routing chooses which apps use the VPN at all.")
        } else {
            out.add("Routing: $mode" + when {
                s.routingMode == "bypass-ir" && geo -> " — Iranian sites go direct, by name (sniffing ${if (s.enableSniffing) "on" else "OFF — names are not seen"}) and by address"
                s.routingMode.startsWith("bypass") && !geo -> " — not applied: no geo data on this device"
                else -> ""
            })
        }
        if (privateDns != null && s.routingMode.startsWith("bypass") && modeOn)
            out.add("⚠ Android's Private DNS is set to $privateDns: the phone asks it (through the tunnel) instead of the app's resolver, so $mode can miss Iranian sites that sit on foreign CDNs. Set Private DNS to Automatic or Off (Android Settings → Network → Private DNS).")
        return out
    }

    private fun keep(a: JSONArray, pred: (JSONObject) -> Boolean): JSONArray {
        val out = JSONArray()
        for (i in 0 until a.length()) { val o = a.optJSONObject(i) ?: continue; if (pred(o)) out.put(o) }
        return out
    }
}

/**
 * The tunnel service's generation: moved on by every connect and every
 * disconnect, so a prepare or a start that carries an older value knows it was
 * overtaken. [ifCurrent] checks and acts under the lock every move takes: an
 * unattended start's "Connecting…" can then never land after the disconnect
 * that overtook it (whose Not connected comes after its move) — checked first
 * and set after, it stayed up for good.
 */
class Generation {
    private val value = AtomicLong(0)
    @Volatile private var stopped = -1L

    fun get(): Long = value.get()

    /** A connect. */
    fun next(): Long = synchronized(this) { value.incrementAndGet() }

    /**
     * A connect, with its "Connecting…" put up under the same lock: an older
     * start's check-and-write (ifCurrent) then lands wholly before the move or
     * is refused after it — never between the two, where its Connected (or its
     * error) went up over the newer connect's Connecting.
     */
    fun next(show: () -> Unit): Long = synchronized(this) { value.incrementAndGet().also { show() } }

    /** A disconnect, remembered as one ([stopLatest]). */
    fun stop(): Long = synchronized(this) { value.incrementAndGet().also { stopped = it } }

    /** Run [show] only while [gen] is still the current generation; true when it ran. */
    fun ifCurrent(gen: Long, show: () -> Unit): Boolean = synchronized(this) {
        if (gen != value.get()) false else { show(); true }
    }

    /** Run [show] only while the latest move is a disconnect ([stopLatest], checked under the lock); true when it ran. */
    fun ifStopped(show: () -> Unit): Boolean = synchronized(this) {
        if (value.get() != stopped) false else { show(); true }
    }

    /** The latest move was a disconnect: no connect is pending, so a "Connecting…" still up is nobody's. */
    val stopLatest: Boolean get() = value.get() == stopped

    companion object {
        /**
         * Does a stop for generation [cmd] reach the tunnel a connect of
         * generation [session] brought up (null = none is up)? Only one from
         * that connect or an older one. The service runs every command in
         * order, but a stop can still be SENT late — a connect that failed on
         * its own thread sends one for whatever an older connect left up, and
         * a newer connect can be up by the time it runs. It must not take that
         * one down: the last thing asked for would lose to an earlier one.
         */
        fun reaches(cmd: Long, session: Long?): Boolean = session == null || session <= cmd
    }
}

/**
 * When a START_STICKY restart (the process was killed under a live tunnel)
 * connects by itself again. At once — unless the previous attempt was under
 * two minutes ago: that is a crash loop (a config that takes the core down as
 * it starts, a native crash IRApp's handler never sees), and connecting at
 * once only repeats it. It then waits 30 s, 60 s, then 120 s each time, and
 * keeps trying: giving up left a phone under lockdown with no internet until
 * somebody opened the app.
 */
object StickyRestart {
    /** A restart this soon after the previous attempt is the same crash again. */
    const val WINDOW_MS = 120_000L

    /** How often a waiting restart looks at the clock, in uptime. */
    const val TICK_MS = 5_000L

    /** [attemptAt]: when this restart connects — what the next one measures from. */
    class Next(val streak: Int, val waitMs: Long, val attemptAt: Long)

    /**
     * The wait is counted in elapsed real time — deep sleep included, which a
     * Handler's uptime is not — and looked at every [TICK_MS]: how long until
     * the next look, 0 = [due] has come.
     */
    fun tick(due: Long, now: Long): Long = if (now >= due) 0L else minOf(due - now, TICK_MS)

    /**
     * [lastAttemptAt]/[streak]: what the previous restart stored (0 = none).
     * A restart before that attempt was even due — killed while it waited —
     * counts as the same loop; one from a clock set far back does not.
     */
    fun next(lastAttemptAt: Long, streak: Int, now: Long): Next {
        val gap = now - lastAttemptAt
        val s = if (lastAttemptAt > 0L && gap >= -WINDOW_MS && gap < WINDOW_MS) (streak + 1).coerceAtMost(100) else 0
        val wait = when {
            s <= 0 -> 0L
            s == 1 -> 30_000L
            s == 2 -> 60_000L
            else -> 120_000L
        }
        return Next(s, wait, now + wait)
    }
}

/**
 * Android starts the service for always-on VPN at boot, but also whenever
 * always-on is switched on — or asks again — while this app is already
 * connected or connecting. That start used to rebuild the tunnel regardless:
 * seconds of a tunnel torn down and built again for the very same selection,
 * and a connect still being prepared was overtaken and started over.
 */
object AlwaysOnStart {
    /**
     * Leave the tunnel alone: the latest move is a connect ([askedIsLatest])
     * made for [asked], the selection always-on would connect ([stored]) — and
     * that connect is up ([state] CONNECTED with the tunnel really up,
     * [tunnelUp]) or still on its way (CONNECTING). Anything else — a
     * disconnect last, a failed connect (ERROR), a tunnel for another
     * selection — is connected exactly as before.
     */
    fun leaveAlone(state: ConnState, tunnelUp: Boolean, askedIsLatest: Boolean, asked: String?, stored: String?): Boolean {
        if (!askedIsLatest || asked.isNullOrEmpty() || asked != stored) return false
        return when (state) {
            ConnState.CONNECTED -> tunnelUp
            ConnState.CONNECTING -> true
            else -> false
        }
    }
}

/**
 * Is a loopback port free for a core to bind? A subprocess core's "ready" is
 * "the port answers" — which another app, or an orphan of ours, satisfies just
 * as well — so the port is checked BEFORE the launch, bound exactly as the core
 * will bind it.
 */
object LocalPort {
    /** Every interface — where LAN sharing's inbounds bind (LanShare.LISTEN). */
    const val ANY = "0.0.0.0"

    fun isFree(port: Int, host: String = "127.0.0.1"): Boolean = try {
        ServerSocket().use { it.reuseAddress = true; it.bind(InetSocketAddress(InetAddress.getByName(host), port)) }
        true
    } catch (e: Exception) { false }

    /**
     * Which of [ports] somebody holds on [host] — all asked at once, never
     * waited on: the caller is the tunnel's one worker, and every queued Cancel
     * and connect waits behind it (two waitFree()s were up to four seconds of
     * a "Connecting…" that looked stuck). One second look after [graceMs],
     * for all of them together, covers a core of ours stopped a moment ago
     * that is still letting go. A port free here can still be taken before the
     * core binds it — the caller must survive that too (startTunnel retries
     * without LAN sharing).
     */
    fun takenNow(ports: List<Int>, host: String, graceMs: Long = 150): List<Int> {
        val taken = ports.distinct().filter { p: Int -> !isFree(p, host) }
        if (taken.isEmpty() || graceMs <= 0L) return taken
        try { Thread.sleep(graceMs) } catch (e: InterruptedException) { return taken }
        return taken.filter { p: Int -> !isFree(p, host) }
    }

    /** Wait a moment for a port to come free: the core just stopped may still be letting go of it. */
    fun waitFree(port: Int, timeoutMs: Long = 3000, host: String = "127.0.0.1"): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (!isFree(port, host)) {
            if (System.currentTimeMillis() >= deadline) return false
            try { Thread.sleep(100) } catch (e: InterruptedException) { return false }
        }
        return true
    }
}
