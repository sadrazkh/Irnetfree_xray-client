package com.irnetfree.vpn.core

import org.json.JSONObject
import kotlin.reflect.KMutableProperty1

/**
 * What a subscription refresh does to the servers that subscription already
 * gave you. Pure — the fetch is the caller's (SubFetch), and so is the store —
 * so all of it runs off a device.
 *
 * TWO THINGS A REFRESH MUST NOT DO, and both used to happen on every one:
 *
 *  - HAND OUT NEW IDS. The list was dropped and re-parsed, and the parser gives
 *    every server a fresh random id. Everything that points at a server by id —
 *    the selection, a chain's members, a pool entry's exit, an advanced-routing
 *    rule — then pointed at nothing: "Select a server first", a chain with fewer
 *    than two members, "⚠ invalid exit", every hour. The owner's corporate chain
 *    starts at a subscription server. Now each fresh server is matched to the
 *    old one it IS and keeps that one's id, along with what the user set on it.
 *  - EMPTY IT. A captive portal, a panel's error page or a format nobody parses
 *    answers 200 with zero servers, and zero servers replaced the list. Now a
 *    refresh that brings nothing changes nothing, and says so.
 */
object SubRefresh {

    /** A refresh's servers for one subscription, and how they came out. */
    data class Merged(val servers: List<ServerConfig>, val kept: Int, val added: Int, val dropped: Int)

    /**
     * What the store should become. `servers` null = leave the list alone (the
     * response had no servers — the subscription's own list is kept as it was).
     */
    data class Applied(val servers: List<ServerConfig>?, val sub: Subscription, val merged: Merged?)

    /**
     * Who a server is, whatever it is called: the same protocol at the same
     * address and port, with the same credential (uuid / password / private key /
     * proxy login), over the same transport, path and host.
     */
    fun identity(s: ServerConfig): String {
        val f = ServerEditor.read(s)
        return listOf(
            s.protocol, s.address.trim().lowercase(), s.port.toString(),
            f.cred, f.proxyUser, f.proxyPass, f.network, f.path, f.host.lowercase()
        ).joinToString("\u0001")
    }

    /**
     * [identity] and the handshake too — security, SNI, fingerprint, REALITY key
     * and short id, VLESS flow. A panel that offers one server under several
     * SNIs or fingerprints and reorders them must not swap their ids, which the
     * looser identity alone would do.
     */
    fun strictIdentity(s: ServerConfig): String {
        val f = ServerEditor.read(s)
        val flow = s.outbound.optJSONObject("settings")?.optJSONArray("vnext")?.optJSONObject(0)
            ?.optJSONArray("users")?.optJSONObject(0)?.optString("flow") ?: ""
        return listOf(identity(s), f.security, f.sni.lowercase(), f.fp, f.pbk, f.sid, flow).joinToString("\u0001")
    }

    /**
     * Each fresh server paired with the old server of this subscription it is —
     * the identical link first, then [strictIdentity], then [identity] — each
     * old one claimed at most once, so a subscription that lists the same server
     * twice keeps two servers. A matched server keeps the old id and what the
     * user set on it ([carry]); an unmatched fresh one keeps its new id; an
     * unmatched old one is gone, as it is gone from the subscription.
     */
    fun merge(old: List<ServerConfig>, fresh: List<ServerConfig>, subId: String): Merged {
        val claimed = BooleanArray(old.size)
        val match = IntArray(fresh.size) { -1 }
        // What each old server's own link gives: the identities below compare the
        // panel's link with the panel's link, not with what the user made of it —
        // a server whose address the user swapped for a clean IP is still the
        // panel's server. (No link, or one that no longer parses: the server as stored.)
        val linked = old.map { linkedForm(it) }
        val basis = old.indices.map { linked[it] ?: old[it] }
        // 1. the identical link — the strongest evidence there is
        for (i in fresh.indices) {
            val raw = fresh[i].raw
            if (raw.isBlank()) continue
            val j = old.indices.firstOrNull { !claimed[it] && old[it].raw == raw } ?: continue
            claimed[j] = true; match[i] = j
        }
        // 2. the same server under a changed link: renamed, parameters reordered,
        //    retuned, or stored before links were kept at all (an older store has
        //    no raw) — the tight identity first, so variants keep their own ids
        val passes: List<(ServerConfig) -> String> = listOf({ s -> strictIdentity(s) }, { s -> identity(s) })
        for (key in passes) {
            val oldKeys = basis.map { key(it) }
            for (i in fresh.indices) {
                if (match[i] >= 0) continue
                val k = key(fresh[i])
                val j = old.indices.firstOrNull { !claimed[it] && oldKeys[it] == k } ?: continue
                claimed[j] = true; match[i] = j
            }
        }
        val servers = fresh.indices.map { i ->
            val j = match[i]
            (if (j >= 0) carry(old[j], fresh[i], linked[j]) else fresh[i]).copy(subId = subId)
        }
        val kept = match.count { it >= 0 }
        return Merged(servers, kept, fresh.size - kept, old.size - kept)
    }

    /**
     * [s] as its own link gives it, read the way the store reads a record
     * (LinkParser.migrateStoredServer), or null when it has no link or the link
     * no longer parses.
     */
    fun linkedForm(s: ServerConfig): ServerConfig? {
        val raw = s.raw.takeIf { it.isNotBlank() } ?: return null
        return try { LinkParser.migrateStoredServer(LinkParser.parseLink(raw)) } catch (e: Exception) { null }
    }

    /**
     * A fresh server that is [old]: the old id and the certificate pinned on
     * first use (which no link carries). Everything else comes from the
     * subscription, which is what a refresh is for — except what the USER set.
     *
     * "What the user set" is what differs from the old server's own link
     * ([linked]): that is carried onto the fresh server, and the rest follows the
     * fresh link — changed, or dropped. It covers everything the edit sheet
     * writes: the connection (address — a clean Cloudflare IP swapped in is the
     * usual one — port, credential, transport, path, host, SNI, fingerprint,
     * REALITY keys, WireGuard fields, patterniha), the name, and the core, TLS
     * fragment and noise, which a link carries too (`engine=`, `fragment=`,
     * `noise=`) and a panel retunes when the DPI changes. (Keeping any non-blank
     * old value froze a panel's old fragment forever; keeping none reverted
     * every edit every hour.)
     *
     * Without a link nothing can tell the user's from the panel's: the fresh
     * connection wins, as it always has, and the core, fragment and noise keep
     * what they have.
     */
    fun carry(old: ServerConfig, fresh: ServerConfig, linked: ServerConfig? = linkedForm(old)): ServerConfig {
        val base = if (linked != null) withUsersEdits(old, linked, fresh) else fresh
        val ob = JSONObject(base.outbound.toString())
        for (k in listOf("_fragment", "_noise")) {
            val mine = old.outbound.optString(k)
            val usersOwn = if (linked != null) sheetForm(k, mine) != sheetForm(k, linked.outbound.optString(k)) else mine.isNotBlank()
            if (usersOwn) { if (mine.isBlank()) ob.remove(k) else ob.put(k, mine) }
        }
        val engine = when {
            linked == null -> old.engine ?: fresh.engine
            old.engine != linked.engine -> old.engine
            else -> fresh.engine
        }
        return base.copy(
            id = old.id, outbound = ob, engine = engine,
            certPin = old.certPin, certPinAt = old.certPinAt, certPinCheckedAt = old.certPinCheckedAt
        )
    }

    /** The edit sheet's text fields other than fragment/noise/core (handled in [carry]). */
    private val SHEET_FIELDS: List<KMutableProperty1<ServerEditor.Fields, String>> = listOf(
        ServerEditor.Fields::name, ServerEditor.Fields::address, ServerEditor.Fields::port, ServerEditor.Fields::cred,
        ServerEditor.Fields::network, ServerEditor.Fields::security, ServerEditor.Fields::sni, ServerEditor.Fields::host,
        ServerEditor.Fields::path, ServerEditor.Fields::fp, ServerEditor.Fields::pbk, ServerEditor.Fields::sid,
        ServerEditor.Fields::method, ServerEditor.Fields::proxyUser, ServerEditor.Fields::proxyPass,
        ServerEditor.Fields::wgPub, ServerEditor.Fields::wgAddr, ServerEditor.Fields::wgPsk, ServerEditor.Fields::wgMtu,
        ServerEditor.Fields::wgReserved, ServerEditor.Fields::wgAllowed, ServerEditor.Fields::wgDns,
        ServerEditor.Fields::cipherSuites, ServerEditor.Fields::finalMask
    )

    /**
     * [fresh] with every sheet field the user changed on [old] (it differs from
     * [linked], old's own link) written into it — through ServerEditor.apply,
     * which patches exactly those fields and leaves the rest of the fresh
     * outbound as the panel sent it.
     */
    private fun withUsersEdits(old: ServerConfig, linked: ServerConfig, fresh: ServerConfig): ServerConfig {
        val mine = ServerEditor.read(old)
        val link = ServerEditor.read(linked)
        val f = ServerEditor.read(fresh)
        var edited = false
        for (p in SHEET_FIELDS) {
            if (p.get(mine) != p.get(link)) { p.set(f, p.get(mine)); edited = true }
        }
        if (mine.allowInsecure != link.allowInsecure) { f.allowInsecure = mine.allowInsecure; edited = true }
        return if (edited) ServerEditor.apply(fresh, f) else fresh
    }

    /**
     * A fragment / noise value as the edit sheet writes it back: trimmed, and for
     * noise its presets lower-cased with "fakehello" as "faketls". Opening the
     * sheet and saving rewrites a link's `noise=fakehello` as "faketls"; that
     * spelling is the sheet's, not an edit of the user's.
     */
    private fun sheetForm(key: String, v: String): String {
        val t = v.trim()
        if (key != "_noise") return t
        return when (val l = t.lowercase()) {
            "fakehello" -> "faketls"
            "random", "faketls" -> l
            else -> t
        }
    }

    /**
     * [all] with [subId]'s servers replaced by [servers], in the place the
     * subscription's servers had — a refresh does not move a list to the end.
     */
    fun replace(all: List<ServerConfig>, subId: String, servers: List<ServerConfig>): List<ServerConfig> {
        val at = all.indexOfFirst { it.subId == subId }
        val rest = all.filter { it.subId != subId }
        // everything before the first server of the subscription is someone else's
        return if (at < 0) rest + servers else rest.subList(0, at) + servers + rest.subList(at, rest.size)
    }

    /**
     * A fetch's result applied: the merged list and the subscription's new
     * record — or, when the response had no servers at all, the list untouched,
     * `lastUpdated` untouched and the attempt recorded as a failure.
     */
    fun applyFetch(all: List<ServerConfig>, sub: Subscription, fresh: List<ServerConfig>,
                   usage: Subscriptions.Usage?, errors: List<String>, now: Long): Applied {
        if (fresh.isEmpty()) {
            val why = "no servers in the response" + (errors.firstOrNull()?.let { " ($it)" } ?: "")
            return Applied(null, failed(sub, why, now), null)
        }
        val m = merge(all.filter { it.subId == sub.id }, fresh, sub.id)
        val next = sub.copy(
            serverCount = m.servers.size, lastUpdated = now, lastTried = now, lastError = "",
            upload = usage?.upload ?: 0, download = usage?.download ?: 0, total = usage?.total ?: 0, expire = usage?.expire ?: 0
        )
        return Applied(replace(all, sub.id, m.servers), next, m)
    }

    /** A failed attempt: remembered, so auto-update waits before the next one. */
    fun failed(sub: Subscription, message: String, now: Long): Subscription =
        sub.copy(lastTried = now, lastError = message.ifBlank { "failed" })

    /**
     * Whether auto-update should fetch [sub] now: its last ATTEMPT, good or bad,
     * is at least [maxAgeMs] old. Counting only good ones meant a failing
     * subscription was due again the moment its fetch ended — and the Subs
     * screen, rebuilt by that very fetch, started the next one.
     */
    fun due(sub: Subscription, now: Long, maxAgeMs: Long): Boolean =
        now - maxOf(sub.lastUpdated, sub.lastTried) >= maxAgeMs
}
