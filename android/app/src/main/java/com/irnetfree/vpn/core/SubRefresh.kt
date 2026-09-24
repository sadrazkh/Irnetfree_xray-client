package com.irnetfree.vpn.core

import org.json.JSONObject

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
     * Each fresh server paired with the old server of this subscription it is —
     * first by the identical link, then by [identity] — each old one claimed at
     * most once, so a subscription that lists the same server twice keeps two
     * servers. A matched server keeps the old id and what the user set on it
     * ([carry]); an unmatched fresh one keeps its new id; an unmatched old one
     * is gone, as it is gone from the subscription.
     */
    fun merge(old: List<ServerConfig>, fresh: List<ServerConfig>, subId: String): Merged {
        val claimed = BooleanArray(old.size)
        val match = arrayOfNulls<ServerConfig>(fresh.size)
        // 1. the identical link — the strongest evidence there is
        for (i in fresh.indices) {
            val raw = fresh[i].raw
            if (raw.isBlank()) continue
            val j = old.indices.firstOrNull { !claimed[it] && old[it].raw == raw } ?: continue
            claimed[j] = true; match[i] = old[j]
        }
        // 2. the same server under a changed link: renamed, parameters reordered,
        //    or stored before links were kept at all (an older store has no raw)
        val oldKeys = old.map { identity(it) }
        for (i in fresh.indices) {
            if (match[i] != null) continue
            val key = identity(fresh[i])
            val j = old.indices.firstOrNull { !claimed[it] && oldKeys[it] == key } ?: continue
            claimed[j] = true; match[i] = old[j]
        }
        val servers = fresh.indices.map { i ->
            val m = match[i]
            (if (m != null) carry(m, fresh[i]) else fresh[i]).copy(subId = subId)
        }
        val kept = match.count { it != null }
        return Merged(servers, kept, fresh.size - kept, old.size - kept)
    }

    /**
     * A fresh server that is [old]: the old id, and what the user set on it that
     * a link does not carry — the core it runs on, the certificate pinned on
     * first use, the TLS fragment and noise. Everything the link does carry
     * (name, address, keys, transport) comes from the subscription, which is what
     * a refresh is for.
     */
    fun carry(old: ServerConfig, fresh: ServerConfig): ServerConfig {
        val ob = JSONObject(fresh.outbound.toString())
        old.outbound.optString("_fragment").takeIf { it.isNotBlank() }?.let { ob.put("_fragment", it) }
        old.outbound.optString("_noise").takeIf { it.isNotBlank() }?.let { ob.put("_noise", it) }
        return fresh.copy(
            id = old.id, outbound = ob,
            engine = old.engine ?: fresh.engine,
            certPin = old.certPin, certPinAt = old.certPinAt, certPinCheckedAt = old.certPinCheckedAt
        )
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
