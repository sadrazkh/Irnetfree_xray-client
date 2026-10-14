package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Port of src/main/coreCompat.js — one config, written for the core that runs it.
 *
 * The 2026 cores moved two transports' settings around, release by release:
 *  - mKCP: up to 26.1.23 `kcpSettings.header` / `.seed`; from 26.1.31 those keys
 *    are REFUSED and taken as finalmask udp masks `header-<type>` plus
 *    `mkcp-original` / `mkcp-aes128gcm`; from 26.6.1 one type, `mkcp-legacy`.
 *  - Hysteria's port hopping: `hysteriaSettings.udphop` up to 26.3.x,
 *    `finalmask.quicParams.udpHop` from 26.3.23, a `udphop` udp mask from 26.9.9.
 *  - XDNS (an `xdns` udp mask): up to 26.10.3 a domain is `{ name }` and a resolver
 *    `{ type, settings: { addr } }`; from 26.10.5 (XTLS/Xray-core#7090) `{ names }`
 *    and `{ addrs: ["1.1.1.1", "tcp://8.8.8.8:53"] }` — each core ignores the
 *    other's keys, and every dial fails "empty domains".
 *
 * The record keeps a link's own terms (kcp) or the newest core's form (hysteria);
 * this writes the form of the core about to run — the in-process libv2ray
 * (Libv2ray.checkVersionX: "Lib v…, Xray-core v26.7.11") or the bundled
 * Xray-PattN binary, whose numbers follow upstream's. Pure: the input is never
 * changed. An unknown version ("") is taken as the newest.
 */
object CoreCompat {
    const val KCP_MASKS_SINCE = "26.1.31"
    const val KCP_LEGACY_MASK_SINCE = "26.6.1"
    const val QUIC_PARAMS_SINCE = "26.3.23"
    const val UDPHOP_MASK_SINCE = "26.9.9"
    const val XDNS_NAMES_SINCE = "26.10.5"

    private fun parse(v: String?): List<Int>? =
        Regex("(\\d+)\\.(\\d+)\\.(\\d+)").find(v ?: "")?.groupValues?.drop(1)?.map { it.toInt() }

    /** "26.3.27" below "26.6.1", as numbers. No x.y.z in it (unknown) is never below anything. */
    fun below(v: String?, min: String): Boolean {
        val a = parse(v) ?: return false
        val b = parse(min) ?: return false
        for (i in 0 until 3) if (a[i] != b[i]) return a[i] < b[i]
        return false
    }

    private val KCP_HEADERS = mapOf("srtp" to "srtp", "utp" to "utp", "wechat-video" to "wechat", "wechat" to "wechat",
        "dtls" to "dtls", "wireguard" to "wireguard", "dns" to "dns")
    fun kcpHeaderName(t: String?): String = KCP_HEADERS[(t ?: "").trim().lowercase()] ?: ""

    /** An mKCP mask in neutral terms; null for any other mask. */
    private class KcpMask(val crypto: String? = null, val password: String = "", val header: String? = null, val value: String = "")

    private fun readKcpMask(m: JSONObject?): KcpMask? {
        if (m == null) return null
        val s = m.optJSONObject("settings") ?: JSONObject()
        when (m.optString("type")) {
            "mkcp-original" -> return KcpMask(crypto = "original")
            "mkcp-aes128gcm" -> return KcpMask(crypto = "aes", password = s.optString("password"))
            "mkcp-legacy" -> {
                val h = s.optString("header")
                if (h.isNotEmpty()) return KcpMask(header = kcpHeaderName(h).ifEmpty { h.lowercase() }, value = s.optString("value"))
                val v = s.optString("value")
                return if (v.isNotEmpty()) KcpMask(crypto = "aes", password = v) else KcpMask(crypto = "original")
            }
        }
        val h = Regex("^header-(dns|dtls|srtp|utp|wechat|wireguard)$").find(m.optString("type"))?.groupValues?.get(1) ?: return null
        return KcpMask(header = h, value = if (h == "dns") s.optString("domain") else "")
    }

    private fun writeKcpMask(k: KcpMask, version: String?): JSONObject {
        if (!below(version, KCP_LEGACY_MASK_SINCE)) {
            return when (k.crypto) {
                "original" -> JSONObject().put("type", "mkcp-legacy")
                "aes" -> JSONObject().put("type", "mkcp-legacy").put("settings", JSONObject().put("value", k.password))
                else -> JSONObject().put("type", "mkcp-legacy").put("settings", JSONObject().put("header", k.header)
                    .apply { if (k.header == "dns" && k.value.isNotEmpty()) put("value", k.value) })
            }
        }
        return when (k.crypto) {
            "original" -> JSONObject().put("type", "mkcp-original")
            "aes" -> JSONObject().put("type", "mkcp-aes128gcm").put("settings", JSONObject().put("password", k.password))
            else -> if (k.header == "dns" && k.value.isNotEmpty()) JSONObject().put("type", "header-dns").put("settings", JSONObject().put("domain", k.value))
                    else JSONObject().put("type", "header-" + k.header)
        }
    }

    private fun objects(a: JSONArray?): List<JSONObject?> = if (a == null) emptyList() else (0 until a.length()).map { a.optJSONObject(it) }

    /** mKCP in the form this core takes. Mutates [ss]; true when it changed. */
    private fun adaptKcp(ss: JSONObject, version: String?): Boolean {
        val ks = ss.optJSONObject("kcpSettings")
        val fm = ss.optJSONObject("finalmask")
        val udpRaw = fm?.optJSONArray("udp")
        val udp = objects(udpRaw)
        val hasLegacyKeys = ks != null && (ks.has("header") || ks.has("seed"))
        val masks = udp.map { readKcpMask(it) }
        if (!hasLegacyKeys && masks.all { it == null }) return false

        if (below(version, KCP_MASKS_SINCE)) {
            if (masks.all { it == null }) return false
            val k = ks ?: JSONObject().also { ss.put("kcpSettings", it) }
            for (m in masks) {
                if (m == null) continue
                if (m.crypto == "aes") k.put("seed", m.password)
                else if (m.header != null) k.put("header", if (m.header == "dns" && m.value.isNotEmpty()) JSONObject().put("type", "dns").put("domain", m.value)
                    else JSONObject().put("type", if (m.header == "wechat") "wechat-video" else m.header))
            }
            val rest = JSONArray(); udp.forEachIndexed { i, o -> if (masks[i] == null && o != null) rest.put(o) }
            if (rest.length() > 0) fm!!.put("udp", rest)
            else if (fm != null) { fm.remove("udp"); if (fm.length() == 0) ss.remove("finalmask") }
            return true
        }

        var list: List<JSONObject> = udp.filterNotNull()
        if (hasLegacyKeys) {
            val hdr = ks!!.opt("header")
            val header = kcpHeaderName(if (hdr is JSONObject) hdr.optString("type") else hdr?.toString())
            val domain = (hdr as? JSONObject)?.optString("domain") ?: ""
            val seed = if (ks.isNull("seed")) "" else ks.optString("seed")
            ks.remove("header"); ks.remove("seed")
            if (masks.all { it == null }) {
                // applied first to what is sent: the encryption, then the header
                val synth = ArrayList<JSONObject>()
                synth.add(if (seed.isNotEmpty()) JSONObject().put("type", "mkcp-aes128gcm").put("settings", JSONObject().put("password", seed)) else JSONObject().put("type", "mkcp-original"))
                if (header.isNotEmpty()) synth.add(if (header == "dns" && domain.isNotEmpty()) JSONObject().put("type", "header-dns").put("settings", JSONObject().put("domain", domain)) else JSONObject().put("type", "header-$header"))
                list = synth + list
            }
        }
        val out = JSONArray()
        for (m in list) { val k = readKcpMask(m); out.put(if (k != null) writeKcpMask(k, version) else m) }
        (fm ?: JSONObject().also { ss.put("finalmask", it) }).put("udp", out)
        return true
    }

    /** Hysteria's port hopping (and bandwidth) where this core reads them. Mutates [ss]; true when it changed. */
    private fun adaptHysteria(ss: JSONObject, version: String?): Boolean {
        val fm = ss.optJSONObject("finalmask") ?: return false
        val udp = objects(fm.optJSONArray("udp"))
        val qp = fm.optJSONObject("quicParams")
        val hopIdx = udp.indexOfFirst { it?.optString("type") == "udphop" }
        val hopMask = if (hopIdx == -1) null else udp[hopIdx]
        val oldHop = qp?.optJSONObject("udpHop")
        var ports: Any? = null; var interval: Any? = null
        if (hopMask != null) { val s = hopMask.optJSONObject("settings") ?: JSONObject(); ports = s.opt("remotePorts"); interval = s.opt("interval") }
        else if (oldHop != null) { ports = oldHop.opt("ports"); interval = oldHop.opt("interval") }

        if (!below(version, UDPHOP_MASK_SINCE)) {
            if (oldHop == null) return false
            qp.remove("udpHop"); if (qp.length() == 0) fm.remove("quicParams")
            if (hopMask == null && ports != null && ports.toString().isNotEmpty()) {
                val a = fm.optJSONArray("udp") ?: JSONArray().also { fm.put("udp", it) }
                a.put(JSONObject().put("type", "udphop").put("settings", JSONObject()
                    .put("mode", "intervalLocal,intervalRemote").put("interval", interval?.toString() ?: "30").put("remotePorts", ports)))
            }
            return true
        }

        if (hopMask == null) return false
        val rest = JSONArray(); udp.forEachIndexed { i, o -> if (i != hopIdx && o != null) rest.put(o) }
        if (rest.length() > 0) fm.put("udp", rest) else fm.remove("udp")
        val legacy = JSONObject().put("ports", ports)
        if (interval != null && interval.toString().isNotEmpty()) legacy.put("interval", interval)
        if (!below(version, QUIC_PARAMS_SINCE)) {
            (qp ?: JSONObject().also { fm.put("quicParams", it) }).put("udpHop", legacy)
        } else {
            val hs = ss.optJSONObject("hysteriaSettings") ?: JSONObject().also { ss.put("hysteriaSettings", it) }
            hs.put("udphop", legacy)
            if (qp != null) {
                qp.optString("brutalUp").takeIf { it.isNotEmpty() }?.let { hs.put("up", it) }
                qp.optString("brutalDown").takeIf { it.isNotEmpty() }?.let { hs.put("down", it) }
                qp.optString("congestion").takeIf { it.isNotEmpty() }?.let { hs.put("congestion", it) }
                fm.remove("quicParams")
            }
        }
        if (fm.length() == 0) ss.remove("finalmask")
        return true
    }

    /** Does this stream carry an XDNS mask? */
    private fun hasXdns(ss: JSONObject): Boolean =
        objects(ss.optJSONObject("finalmask")?.optJSONArray("udp")).any { it?.optString("type") == "xdns" }

    /** A resolver of the newer form ("1.1.1.1", "tcp://8.8.8.8", "[2606:4700::1111]:53") → the older type and host:port. */
    private fun olderResolver(a: String): Pair<String, String> {
        val text = a.trim()
        val m = Regex("""^([a-zA-Z]+)://(.*)$""").find(text)
        val type = m?.groupValues?.get(1)?.lowercase() ?: "udp"
        val hp = (m?.groupValues?.get(2) ?: text).replace(Regex("/.*$"), "")
        if (Regex("""^\[[^\]]*\]:\d+$""").matches(hp) || Regex("""^[^:]+:\d+$""").matches(hp)) return Pair(type, hp)
        if (Regex("""^\[[^\]]*\]$""").matches(hp)) return Pair(type, "$hp:53")
        return Pair(type, if (hp.contains(':')) "[$hp]:53" else "$hp:53")
    }

    /** XDNS: its domains and resolvers in the form this core reads. Mutates [ss]; true when it changed. */
    private fun adaptXdns(ss: JSONObject, version: String?): Boolean {
        val udp = ss.optJSONObject("finalmask")?.optJSONArray("udp") ?: return false
        val plural = !below(version, XDNS_NAMES_SINCE)
        var changed = false
        for (i in 0 until udp.length()) {
            val m = udp.optJSONObject(i) ?: continue
            if (m.optString("type") != "xdns") continue
            val st = m.optJSONObject("settings") ?: continue
            val domains = objects(st.optJSONArray("domains"))
            val resolvers = objects(st.optJSONArray("resolvers"))
            if (plural) {
                val oldDomain = { d: JSONObject? -> d != null && d.has("name") && !d.has("names") }
                val oldResolver = { r: JSONObject? -> r != null && !r.has("addrs") && (r.has("type") || r.optJSONObject("settings") != null) }
                if (domains.none(oldDomain) && resolvers.none(oldResolver)) continue
                val nd = JSONArray()
                for (d in domains) {
                    if (d == null || !oldDomain(d)) { nd.put(d ?: JSONObject.NULL); continue }
                    val o = JSONObject(d.toString())
                    o.put("names", JSONArray().put(d.optString("name"))); o.remove("name")
                    nd.put(o)
                }
                val nr = JSONArray()
                for (r in resolvers) {
                    if (r == null || !oldResolver(r)) { nr.put(r ?: JSONObject.NULL); continue }
                    val addr = r.optJSONObject("settings")?.optString("addr").orEmpty()
                    val list = JSONArray()
                    if (addr.isNotEmpty()) list.put(r.optString("type", "udp").ifEmpty { "udp" }.lowercase() + "://" + addr)
                    nr.put(JSONObject().put("addrs", list))
                }
                if (st.has("domains")) st.put("domains", nd)
                if (st.has("resolvers")) st.put("resolvers", nr)
            } else {
                val newDomain = { d: JSONObject? -> d != null && d.optJSONArray("names") != null }
                val newResolver = { r: JSONObject? -> r != null && r.optJSONArray("addrs") != null }
                if (domains.none(newDomain) && resolvers.none(newResolver)) continue
                val nd = JSONArray()
                for (d in domains) {
                    if (d == null || !newDomain(d)) { nd.put(d ?: JSONObject.NULL); continue }
                    val names = d.getJSONArray("names")
                    for (j in 0 until names.length()) {
                        val o = JSONObject(d.toString())
                        o.remove("names"); o.put("name", names.optString(j))
                        nd.put(o)
                    }
                }
                val nr = JSONArray()
                for (r in resolvers) {
                    if (r == null || !newResolver(r)) { nr.put(r ?: JSONObject.NULL); continue }
                    val addrs = r.getJSONArray("addrs")
                    for (j in 0 until addrs.length()) {
                        val (type, addr) = olderResolver(addrs.optString(j))
                        nr.put(JSONObject().put("type", type).put("settings", JSONObject().put("addr", addr)))
                    }
                }
                if (st.has("domains")) st.put("domains", nd)
                if (st.has("resolvers")) st.put("resolvers", nr)
            }
            changed = true
        }
        return changed
    }

    private fun touches(o: JSONObject?): Boolean {
        val ss = o?.optJSONObject("streamSettings") ?: return false
        val net = ss.optString("network").lowercase()
        return net == "kcp" || net == "mkcp" || net == "hysteria" || hasXdns(ss)
    }

    /** Does this config hold anything [adaptForCore] may rewrite? (The core's version is asked only then.) */
    fun needsCoreVersion(config: JSONObject): Boolean = objects(config.optJSONArray("outbounds")).any { touches(it) }

    /** The config in the form the core of [version] takes; the same object when there is nothing to do. */
    fun adaptForCore(config: JSONObject, version: String?): JSONObject {
        if (!needsCoreVersion(config)) return config
        val out = JSONObject(config.toString())
        var changed = false
        val obs = out.optJSONArray("outbounds") ?: return config
        for (i in 0 until obs.length()) {
            val o = obs.optJSONObject(i)
            if (!touches(o)) continue
            val ss = o!!.getJSONObject("streamSettings")
            val net = ss.optString("network").lowercase()
            if (net == "hysteria") changed = adaptHysteria(ss, version) || changed
            else if (net == "kcp" || net == "mkcp") changed = adaptKcp(ss, version) || changed
            if (hasXdns(ss)) changed = adaptXdns(ss, version) || changed
        }
        return if (changed) out else config
    }

    /** The same for a config as text (TunnelSetup / XrayTester hand the cores strings). */
    fun adaptForCore(config: String, version: String?): String {
        val o = try { JSONObject(config) } catch (e: Exception) { return config }
        if (!needsCoreVersion(o)) return config
        val a = adaptForCore(o, version)
        return if (a === o) config else a.toString()
    }
}
