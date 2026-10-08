package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

/**
 * Whole JSON configs as servers — the Android side of the desktop's
 * src/main/jsonImport.js, with the same rules:
 *
 *  - XRAY JSON: one config object (it has `outbounds`), an array of them, or
 *    the same text in base64 — pasted, or a subscription's answer. Each config
 *    gives one server (a balancer: one per member). Its record is the link
 *    record plus `source: "json"`, the config itself (`json`), the helper
 *    outbounds its main outbound dials through (`extraOutbounds`, original
 *    tags) and `jsonMode` ("full" by default, "raw" runs it as written);
 *    `raw` is the config's minified JSON, `jsonInfo` what full mode leaves out.
 *  - SING-BOX JSON (its outbounds carry `type`): every supported outbound is
 *    an ordinary server, exactly as if imported from its link.
 *  - CLASH YAML is refused with a sentence that says what to do instead.
 *
 * Pure: no android.* here (java.util.Base64 for base64), so the JVM tests run it.
 */
object JsonImport {
    const val SOURCE = "json"
    const val MODE_FULL = "full"
    const val MODE_RAW = "raw"
    const val CLASH_ERROR = "Clash YAML is not supported — use the subscription link"
    const val NO_PROXY = "This config has no proxy outbound (vless, vmess, trojan, shadowsocks, socks, http, wireguard or hysteria)"

    /** "raw" stays raw; anything else (absent, unknown) is full. */
    fun modeOf(v: String?): String = if (v == MODE_RAW) MODE_RAW else MODE_FULL

    /** An import problem: the entry it is about (a sing-box tag; "" = the text as a whole) and why. */
    data class Problem(val line: String, val error: String) {
        /** In the form LinkParser.parseMany reports its errors. */
        fun text(): String = if (line.isBlank()) error else "$line: $error"
    }

    data class Result(val servers: List<ServerConfig>, val errors: List<Problem>)

    /** A config's main outbound: one tag, or (`balancer` = its tag) every member of the balancer. */
    data class MainChoice(val tags: List<String>, val balancer: String? = null)

    /** Outbound protocols that reach a server; freedom, blackhole, dns and loopback do not. */
    val PROXY_PROTOCOLS: Set<String> = setOf("vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard", "hysteria")

    /** A routing rule holding none of these catches whatever the rules before it left. */
    private val RULE_KEYS = listOf("domain", "ip", "port", "sourcePort", "protocol", "inboundTag", "user", "attrs")
    private val SINGBOX_SKIPPED = setOf("selector", "urltest", "direct", "block", "dns")
    private val SINGBOX_SUPPORTED = setOf("vless", "vmess", "trojan", "shadowsocks", "hysteria2", "wireguard", "socks", "http")
    private val CLASH = Regex("^(proxies|proxy-providers|proxy-groups)\\s*:", RegexOption.MULTILINE)
    private val B64_TEXT = Regex("^[A-Za-z0-9+/=_\\-\\s]+$")

    /* ============================== detection ============================== */

    private fun clean(text: String): String = text.trim().removePrefix("\uFEFF").trim()

    /**
     * Does [text] start like a JSON config — `{"…` or `[{…` (an empty `{}` / `[]`
     * too)? Stricter than "starts with a bracket": a WireGuard .conf starts with
     * `[Interface]`, and that is no JSON.
     */
    fun looksLikeJson(text: String): Boolean {
        val t = clean(text)
        if (t.isEmpty()) return false
        val next = t.substring(1).trimStart().firstOrNull()
        return when (t[0]) {
            '{' -> next == '"' || next == '}'
            '[' -> next == '{' || next == ']'
            else -> false
        }
    }

    /** The JSON [text] carries: itself, or what its base64 decodes to; null when it is neither. */
    private fun jsonText(text: String): String? {
        val t = clean(text)
        if (looksLikeJson(t)) return t
        if (t.length < 8 || !B64_TEXT.matches(t)) return null
        val decoded = try {
            String(java.util.Base64.getDecoder().decode(LinkParser.b64Normalize(t)), Charsets.UTF_8)
        } catch (e: Exception) {
            return null
        }
        val d = clean(decoded)
        return if (looksLikeJson(d)) d else null
    }

    /** Every JSON value in [body], one after another (a config, an array, or several in a row). */
    private fun readValues(body: String): List<Any> {
        val tk = JSONTokener(body)
        val out = ArrayList<Any>()
        while (true) {
            val c = tk.nextClean()
            if (c == 0.toChar()) break
            if (c == ',') continue
            tk.back()
            out.add(tk.nextValue())
        }
        return out
    }

    /** sing-box's format: its outbounds (or 1.11's endpoints) say `type`, Xray's say `protocol`. */
    private fun isSingbox(c: JSONObject): Boolean {
        fun typed(a: JSONArray?): Boolean = a != null && (0 until a.length()).any { i: Int ->
            val o = a.optJSONObject(i)
            o != null && o.has("type") && !o.has("protocol")
        }
        return typed(c.optJSONArray("outbounds")) || typed(c.optJSONArray("endpoints"))
    }

    /**
     * [text] as servers, or null when it is not JSON at all (LinkParser.parseMany
     * then reads it as links, exactly as before). A config that holds no proxy
     * outbound — a panel's "expires on" / "volume left" rows — is no server and
     * no error.
     */
    fun importJson(text: String): Result? {
        val t = clean(text)
        if (!looksLikeJson(t) && CLASH.containsMatchIn(t)) return Result(emptyList(), listOf(Problem("", CLASH_ERROR)))
        val body = jsonText(t) ?: return null
        val values: List<Any> = try {
            readValues(body)
        } catch (e: Exception) {
            return Result(emptyList(), listOf(Problem("", "Not valid JSON: " + (e.message ?: "parse error"))))
        }
        val configs = ArrayList<JSONObject>()
        for (v in values) {
            when (v) {
                is JSONObject -> configs.add(v)
                is JSONArray -> {
                    for (i in 0 until v.length()) {
                        val o = v.optJSONObject(i)
                        if (o != null) configs.add(o)
                    }
                }
                else -> {}
            }
        }
        val servers = ArrayList<ServerConfig>()
        val errors = ArrayList<Problem>()
        for (c in configs) {
            if (isSingbox(c)) {
                val r = serversFromSingbox(c)
                servers.addAll(r.servers); errors.addAll(r.errors)
            } else if (c.optJSONArray("outbounds") != null) {
                servers.addAll(serversFromXray(c))
            } else {
                errors.add(Problem(nameOf(c).ifBlank { "JSON" }, "not an Xray or sing-box config — it has no outbounds"))
            }
        }
        return Result(servers, errors)
    }

    /* ============================== Xray JSON ============================== */

    private fun objects(a: JSONArray?): List<JSONObject> =
        if (a == null) emptyList() else (0 until a.length()).mapNotNull { i: Int -> a.optJSONObject(i) }

    private fun strings(a: JSONArray?): List<String> =
        if (a == null) emptyList() else (0 until a.length()).map { i: Int -> a.optString(i) }

    /** A value as JavaScript reads it in an `if`: absent, null, false, 0 and "" are false. */
    private fun truthy(v: Any?): Boolean = when {
        v == null || v == JSONObject.NULL -> false
        v is Boolean -> v
        v is String -> v.isNotEmpty()
        v is Number -> v.toDouble() != 0.0
        else -> true
    }

    private fun proxyProtocol(o: JSONObject): Boolean = o.optString("protocol").lowercase() in PROXY_PROTOCOLS

    /** The proxy outbound tagged [tag] ("" = the first untagged one). */
    private fun outboundByTag(config: JSONObject, tag: String): JSONObject? =
        objects(config.optJSONArray("outbounds")).firstOrNull { o: JSONObject -> o.optString("tag") == tag && proxyProtocol(o) }

    private fun networkIsAll(v: Any?): Boolean {
        val s = when (v) {
            is String -> v
            is JSONArray -> strings(v).joinToString(",")
            else -> ""
        }
        val parts = s.split(",").map { p: String -> p.trim().lowercase() }.filter { p: String -> p.isNotEmpty() }.toSet()
        return parts == setOf("tcp", "udp")
    }

    /** The rule that catches everything left over: it matches on nothing, or on all of `network: "tcp,udp"`. */
    private fun isCatchAll(r: JSONObject): Boolean =
        networkIsAll(r.opt("network")) || RULE_KEYS.none { k: String -> truthy(r.opt(k)) }

    /**
     * The main outbound, in order: the catch-all rule's outbound (or the members
     * of its balancer); else the outbound tagged `proxy`; else the first proxy
     * outbound. Each must be a proxy outbound — a catch-all to `direct` is a
     * config's bypass, not its server. Null: there is none (an info row).
     */
    fun mainOutboundTag(config: JSONObject): MainChoice? {
        val outs = objects(config.optJSONArray("outbounds"))
        fun isProxy(tag: String): Boolean = outs.any { o: JSONObject -> o.optString("tag") == tag && proxyProtocol(o) }
        val routing = config.optJSONObject("routing")
        val catchAll = objects(routing?.optJSONArray("rules")).lastOrNull { r: JSONObject ->
            isCatchAll(r) && (truthy(r.opt("outboundTag")) || truthy(r.opt("balancerTag")))
        }
        if (catchAll != null) {
            if (truthy(catchAll.opt("outboundTag"))) {
                val to = catchAll.optString("outboundTag")
                if (isProxy(to)) return MainChoice(listOf(to))
            } else {
                val bt = catchAll.optString("balancerTag")
                val bal = objects(routing?.optJSONArray("balancers")).firstOrNull { b: JSONObject -> b.optString("tag") == bt }
                if (bal != null) {
                    val sel = strings(bal.optJSONArray("selector")).filter { p: String -> p.isNotEmpty() }
                    val tags = outs.filter { o: JSONObject ->
                        val t = o.optString("tag")
                        proxyProtocol(o) && t.isNotEmpty() && sel.any { p: String -> t.startsWith(p) }
                    }.map { o: JSONObject -> o.optString("tag") }.distinct()
                    if (tags.isNotEmpty()) return MainChoice(tags, bt)
                }
            }
        }
        if (isProxy("proxy")) return MainChoice(listOf("proxy"))
        val first = outs.firstOrNull { o: JSONObject -> proxyProtocol(o) } ?: return null
        return MainChoice(listOf(first.optString("tag")))
    }

    /** Where an outbound dials through: its `sockopt.dialerProxy`, its `proxySettings.tag`. */
    internal fun refsOf(o: JSONObject): List<String> {
        val dialer = o.optJSONObject("streamSettings")?.optJSONObject("sockopt")?.optString("dialerProxy") ?: ""
        val via = o.optJSONObject("proxySettings")?.optString("tag") ?: ""
        return listOf(dialer, via).filter { r: String -> r.isNotEmpty() }
    }

    /**
     * The helper outbounds of the outbound tagged [tag]: every outbound it
     * reaches through dialerProxy / proxySettings, recursively — a fragment
     * freedom, a chain's hops — copied verbatim, original tags kept.
     */
    fun helperClosure(config: JSONObject, tag: String): List<JSONObject> {
        val outs = objects(config.optJSONArray("outbounds"))
        val main = outboundByTag(config, tag) ?: return emptyList()
        val seen = HashSet<String>()
        val found = ArrayList<JSONObject>()
        fun visit(o: JSONObject) {
            for (ref in refsOf(o)) {
                if (ref == tag || ref in seen) continue
                val h = outs.firstOrNull { x: JSONObject -> x.optString("tag") == ref } ?: continue
                seen.add(ref)
                found.add(copy(h))
                visit(h)
            }
        }
        visit(main)
        return found
    }

    /**
     * What full mode does not use of [config]: its routing rules, DNS, balancers
     * and observatory — in the desktop's neutral tokens (jsonImport.js jsonInfo),
     * which the edit sheet puts in words (matchInWords / targetInWords).
     */
    fun jsonInfo(config: JSONObject): JsonInfo {
        val routing = config.optJSONObject("routing")
        val rules = objects(routing?.optJSONArray("rules")).map { r: JSONObject -> ruleInfo(r) }
        val dns = (config.optJSONObject("dns")?.length() ?: 0) > 0
        val balancers = objects(routing?.optJSONArray("balancers")).size
        val observatory = truthy(config.opt("observatory")) || truthy(config.opt("burstObservatory"))
        return JsonInfo(rules, dns, balancers, observatory)
    }

    /** Present as the desktop reads it: not null, not "", not an empty array or object. */
    private fun present(v: Any?): Boolean = when {
        v == null || v == JSONObject.NULL -> false
        v is String -> v.isNotEmpty()
        v is JSONArray -> v.length() > 0
        v is JSONObject -> v.length() > 0
        else -> true
    }

    /** A value as JavaScript's String() writes it (an array: its items joined by commas). */
    private fun jsString(v: Any?): String = if (v is JSONArray) strings(v).joinToString(",") else (v?.toString() ?: "")

    /** Its items as text, empty ones left out. */
    private fun vals(v: Any?): List<String> = (if (v is JSONArray) strings(v) else listOf(jsString(v))).filter { s: String -> s.isNotEmpty() }

    /** Up to three items, then how many more. */
    private fun short(v: Any?): String {
        val l = vals(v)
        return if (l.size > 3) l.take(3).joinToString(", ") + " +" + (l.size - 3) else l.joinToString(", ")
    }

    /** A port condition that is every port (the app's own catch-all is `port: 0-65535`). */
    private fun anyPort(v: Any?): Boolean = Regex("^\\s*[01]\\s*-\\s*65535\\s*$").matches(jsString(v))

    /** `network` absent, or naming both TCP and UDP. */
    private fun coversBoth(n: Any?): Boolean {
        if (!present(n)) return true
        val set = vals(n).joinToString(",").lowercase().split(",").map { x: String -> x.trim() }.toSet()
        return "tcp" in set && "udp" in set
    }

    /**
     * One routing rule as the edit sheet says it (jsonImport.js ruleInfo): its
     * conditions joined by " + ", or `*` when it has none → its outbound, or
     * `balancer:<tag>`, or "" when it names neither.
     */
    private fun ruleInfo(r: JSONObject): JsonRule {
        val parts = ArrayList<String>()
        if (present(r.opt("domain"))) parts.add(short(r.opt("domain")))
        if (present(r.opt("ip"))) parts.add(short(r.opt("ip")))
        if (present(r.opt("port")) && !anyPort(r.opt("port"))) parts.add("port " + jsString(r.opt("port")))
        if (present(r.opt("sourcePort"))) parts.add("source port " + jsString(r.opt("sourcePort")))
        if (present(r.opt("source")) || present(r.opt("sourceIP"))) parts.add("source " + short(if (present(r.opt("source"))) r.opt("source") else r.opt("sourceIP")))
        if (present(r.opt("localIP"))) parts.add("local " + short(r.opt("localIP")))
        if (present(r.opt("localPort"))) parts.add("local port " + jsString(r.opt("localPort")))
        if (present(r.opt("protocol"))) parts.add(short(r.opt("protocol")))
        if (present(r.opt("inboundTag"))) parts.add("inbound " + short(r.opt("inboundTag")))
        if (present(r.opt("user"))) parts.add("user " + short(r.opt("user")))
        if (present(r.opt("process"))) parts.add("process " + short(r.opt("process")))
        if (present(r.opt("vlessRoute"))) parts.add("vlessRoute " + jsString(r.opt("vlessRoute")))
        if (present(r.opt("attrs"))) parts.add("attrs")
        if (!coversBoth(r.opt("network"))) parts.add(vals(r.opt("network")).joinToString(","))
        val match = if (parts.isEmpty()) "*" else parts.joinToString(" + ")
        val to = when {
            truthy(r.opt("outboundTag")) -> jsString(r.opt("outboundTag"))
            truthy(r.opt("balancerTag")) -> "balancer:" + jsString(r.opt("balancerTag"))
            else -> ""
        }
        return JsonRule(match, to)
    }

    /** A rule's match in words: `*` is everything else, nothing is "—". */
    fun matchInWords(match: String): String = if (match == "*") "everything else" else match.ifEmpty { "—" }

    /** A rule's target in words: `balancer:<tag>` is "balancer <tag>", nothing is "—". */
    fun targetInWords(to: String): String = when {
        to.startsWith("balancer:") -> "balancer " + to.removePrefix("balancer:")
        to.isEmpty() -> "—"
        else -> to
    }

    private fun nameOf(c: JSONObject): String = c.optString("remarks").trim().ifBlank { c.optString("ps").trim() }

    /** Address and port of an outbound: vnext / servers / the flat form / a WireGuard peer's endpoint. */
    internal fun addressOf(o: JSONObject): Pair<String, Int> {
        val st = o.optJSONObject("settings") ?: JSONObject()
        if (o.optString("protocol").lowercase() == "wireguard") {
            return splitEndpoint(st.optJSONArray("peers")?.optJSONObject(0)?.optString("endpoint") ?: "")
        }
        val entry = st.optJSONArray("vnext")?.optJSONObject(0) ?: st.optJSONArray("servers")?.optJSONObject(0) ?: st
        return entry.optString("address").trim() to entry.optInt("port", 0)
    }

    private fun splitEndpoint(ep: String): Pair<String, Int> {
        val e = ep.trim()
        val v6 = Regex("^\\[([^\\]]+)\\](?::(\\d{1,5}))?$").find(e)
        if (v6 != null) return v6.groupValues[1] to (v6.groupValues[2].toIntOrNull() ?: 0)
        val i = e.lastIndexOf(':')
        if (i > 0 && e.indexOf(':') == i) return e.substring(0, i) to (e.substring(i + 1).toIntOrNull() ?: 0)
        return e to 0
    }

    private fun copy(o: JSONObject): JSONObject = JSONObject(o.toString())

    /** The record of one server of [config], whose main outbound is [main]. Null when [main] reaches no server. */
    private fun record(config: JSONObject, main: JSONObject, helpers: List<JSONObject>, name0: String, raw: String, info: JsonInfo): ServerConfig? {
        val proto = main.optString("protocol").lowercase()
        if (proto !in PROXY_PROTOCOLS) return null
        val (address, port) = addressOf(main)
        val outbound = copy(main)
        outbound.remove("tag")
        val name = name0.ifBlank { if (port > 0) "$address:$port" else address }.ifBlank { proto }
        return ServerConfig(
            newId("s"), name, if (proto == "hysteria") "hysteria2" else proto, address, port, outbound, raw,
            source = SOURCE, json = copy(config), extraOutbounds = helpers, jsonMode = MODE_FULL, jsonInfo = info
        )
    }

    /** One Xray config as its server(s): none for an info row, one per member for a balancer. */
    fun serversFromXray(config: JSONObject): List<ServerConfig> {
        val choice = mainOutboundTag(config) ?: return emptyList()
        val raw = JsonText.minify(config)
        val info = jsonInfo(config)
        val base = nameOf(config)
        val out = ArrayList<ServerConfig>()
        for (tag in choice.tags) {
            val main = outboundByTag(config, tag) ?: continue
            val name = if (choice.balancer == null) base else if (base.isNotBlank()) "$base · $tag" else tag
            record(config, main, helperClosure(config, tag), name, raw, info)?.let { s: ServerConfig -> out.add(s) }
        }
        return out
    }

    /**
     * The tag of [s]'s main outbound inside its own config — for a balancer's
     * member, the member it is (the same outbound, else the one its name ends
     * with, else the one at its address). Null when the config has none.
     */
    fun mainTagOf(s: ServerConfig): String? {
        val cfg = s.json ?: return null
        val choice = mainOutboundTag(cfg) ?: return null
        return if (choice.tags.size == 1) choice.tags[0] else sameMain(s, cfg, choice.tags)
    }

    private fun sameMain(s: ServerConfig, cfg: JSONObject, tags: List<String>): String? {
        val mine = JsonText.canonical(s.outbound)
        for (t in tags) {
            val o = outboundByTag(cfg, t) ?: continue
            val c = copy(o)
            c.remove("tag")
            if (JsonText.canonical(c) == mine) return t
        }
        for (t in tags) if (s.name.endsWith(" · $t")) return t
        for (t in tags) {
            val o = outboundByTag(cfg, t) ?: continue
            if (addressOf(o) == (s.address to s.port)) return t
        }
        return null
    }

    /**
     * A JSON server saved from the edit sheet: its name, its mode and its config
     * text. The main outbound, the helpers, protocol, address, port and
     * `jsonInfo` are derived again from the config; the keys this save changed
     * join [ServerConfig.edited]. `raw` stays the provider's own text, so a
     * subscription refresh still finds this server by it first and keeps the
     * edit (SubRefresh). Throws IllegalArgumentException with the reason when
     * the text is no JSON, or no Xray config with a proxy outbound.
     */
    fun applyEdits(s: ServerConfig, name: String, jsonMode: String, jsonText: String): ServerConfig {
        val cfg = parseConfig(jsonText)
        val choice = mainOutboundTag(cfg) ?: throw IllegalArgumentException(NO_PROXY)
        val tag = if (choice.tags.size == 1) choice.tags[0] else (sameMain(s, cfg, choice.tags) ?: choice.tags[0])
        val main = outboundByTag(cfg, tag) ?: throw IllegalArgumentException(NO_PROXY)
        val raw = s.raw.ifEmpty { JsonText.minify(cfg) }
        val fresh = record(cfg, main, helperClosure(cfg, tag), s.name, raw, jsonInfo(cfg)) ?: throw IllegalArgumentException(NO_PROXY)
        val newName = name.trim().ifEmpty { s.name }
        val mode = modeOf(jsonMode)
        val changed = ArrayList<String>()
        if (newName != s.name) changed.add("name")
        if (mode != s.jsonMode) changed.add("jsonMode")
        val before = s.json
        if (before == null || JsonText.canonical(before) != JsonText.canonical(cfg)) changed.add("json")
        return s.copy(
            name = newName, protocol = fresh.protocol, address = fresh.address, port = fresh.port,
            outbound = fresh.outbound, raw = raw, source = SOURCE, json = fresh.json,
            extraOutbounds = fresh.extraOutbounds, jsonMode = mode, jsonInfo = fresh.jsonInfo,
            edited = (s.edited + changed).distinct()
        )
    }

    /** The edit sheet's text as one Xray config, or the reason it is not one. */
    private fun parseConfig(text: String): JSONObject {
        val t = clean(text)
        if (!t.startsWith("{")) throw IllegalArgumentException("The config must be one JSON object, starting with {")
        val v: Any = try {
            JSONTokener(t).nextValue()
        } catch (e: Exception) {
            throw IllegalArgumentException("Not valid JSON: " + (e.message ?: "parse error"))
        }
        val cfg = v as? JSONObject ?: throw IllegalArgumentException("The config must be one JSON object, starting with {")
        if (isSingbox(cfg)) throw IllegalArgumentException("This is a sing-box config — only an Xray config can be edited here")
        if (cfg.optJSONArray("outbounds") == null) throw IllegalArgumentException("The config has no outbounds")
        return cfg
    }

    /* ============================== sing-box JSON ============================== */

    /**
     * A sing-box config as ordinary servers: every vless, vmess, trojan,
     * shadowsocks, hysteria2, wireguard, socks and http outbound (and a 1.11
     * WireGuard endpoint) becomes the server its share link would be — it is
     * written as that link and parsed. selector, urltest, direct, block and dns
     * are skipped; a `detour` is said in the name, not chained; anything else is
     * reported by name.
     */
    fun serversFromSingbox(config: JSONObject): Result {
        val servers = ArrayList<ServerConfig>()
        val errors = ArrayList<Problem>()
        val entries = objects(config.optJSONArray("outbounds")) + objects(config.optJSONArray("endpoints"))
        for (o in entries) {
            val type = o.optString("type").trim().lowercase()
            val tag = o.optString("tag").trim()
            if (type.isEmpty() || type in SINGBOX_SKIPPED) continue
            if (type !in SINGBOX_SUPPORTED) {
                errors.add(Problem(tag.ifEmpty { type }, "unsupported protocol: $type"))
                continue
            }
            try {
                servers.add(fromSingbox(o, type, tag))
            } catch (e: Exception) {
                errors.add(Problem(tag.ifEmpty { type }, e.message ?: "could not be read"))
            }
        }
        return Result(servers, errors)
    }

    private fun fromSingbox(o: JSONObject, type: String, tag: String): ServerConfig {
        val detour = o.optString("detour").trim()
        val base = tag.ifEmpty { o.optString("server").trim() }
        val name = if (detour.isNotEmpty()) "$base (via $detour)" else base
        val s = if (type == "vmess") singboxVmess(o, name) else LinkParser.parseLink(singboxLink(o, type, name))
        return s.copy(name = name)
    }

    // encodeURIComponent: URLEncoder's '+' for a space would come back as a '+'
    private fun enc(s: String): String = java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20")

    private fun qs(q: Map<String, String>): String =
        q.entries.filter { e: Map.Entry<String, String> -> e.value.isNotEmpty() }.joinToString("&") { e: Map.Entry<String, String> -> e.key + "=" + enc(e.value) }

    private fun firstPort(v: String): Int? = Regex("^\\s*(\\d+)").find(v)?.groupValues?.get(1)?.toIntOrNull()

    private fun portOf(o: JSONObject, def: Int): Int {
        val p = o.optInt("server_port", 0)
        if (p > 0) return p
        return firstPort(serverPorts(o).firstOrNull() ?: "") ?: def
    }

    private fun serverPorts(o: JSONObject): List<String> {
        val v = o.opt("server_ports")
        val list = when (v) {
            is JSONArray -> strings(v)
            is String -> v.split(",")
            else -> emptyList<String>()
        }
        return list.map { p: String -> p.trim() }.filter { p: String -> p.isNotEmpty() }
    }

    private fun hostPort(host0: String, port: Int): String {
        val h = host0.trim()
        if (h.isEmpty()) throw IllegalArgumentException("no server address")
        val host = if (h.contains(':') && !h.startsWith("[")) "[$h]" else h
        return "$host:$port"
    }

    /** TLS / REALITY of a sing-box outbound as link parameters; none = `security=none`. */
    private fun tlsQ(o: JSONObject, q: MutableMap<String, String>) {
        val tls = o.optJSONObject("tls")
        if (tls == null || !tls.optBoolean("enabled", false)) {
            q["security"] = "none"
            return
        }
        val reality = tls.optJSONObject("reality")
        val isReality = reality != null && reality.optBoolean("enabled", false)
        q["security"] = if (isReality) "reality" else "tls"
        tls.optString("server_name").trim().takeIf { v: String -> v.isNotEmpty() }?.let { v: String -> q["sni"] = v }
        val utls = tls.optJSONObject("utls")
        if (utls != null && utls.optBoolean("enabled", false)) {
            utls.optString("fingerprint").trim().takeIf { v: String -> v.isNotEmpty() }?.let { v: String -> q["fp"] = v }
        }
        if (tls.optBoolean("insecure", false)) q["allowInsecure"] = "1"
        val alpn = when (val a = tls.opt("alpn")) {
            is JSONArray -> strings(a).joinToString(",")
            is String -> a
            else -> ""
        }
        if (alpn.isNotBlank()) q["alpn"] = alpn
        if (isReality && reality != null) {
            q["pbk"] = reality.optString("public_key")
            q["sid"] = reality.optString("short_id")
        }
        echOf(tls)?.let { v: String -> q["ech"] = v }
    }

    /** sing-box's ECH config (PEM lines) as the base64 list a link carries. */
    private fun echOf(tls: JSONObject): String? {
        val ech = tls.optJSONObject("ech") ?: return null
        if (!ech.optBoolean("enabled", false)) return null
        val lines = when (val c = ech.opt("config")) {
            is JSONArray -> strings(c)
            is String -> c.split("\n")
            else -> emptyList<String>()
        }
        val body = lines.map { l: String -> l.trim() }.filter { l: String -> l.isNotEmpty() && !l.startsWith("-----") }.joinToString("")
        return body.ifEmpty { null }
    }

    /** A sing-box transport as link parameters (none = TCP). */
    private fun transportQ(o: JSONObject, q: MutableMap<String, String>) {
        val t = o.optJSONObject("transport") ?: JSONObject()
        when (val type = t.optString("type").trim().lowercase()) {
            "" -> { q["type"] = "tcp" }
            "ws" -> {
                q["type"] = "ws"
                var path = t.optString("path")
                // sing-box spells out Xray's `?ed=` early data
                val ed = t.optInt("max_early_data", 0)
                if (ed > 0 && t.optString("early_data_header_name") == "Sec-WebSocket-Protocol") path += (if (path.contains('?')) "&" else "?") + "ed=$ed"
                q["path"] = path.ifEmpty { "/" }
                val h = t.optJSONObject("headers")
                val host = h?.optString("Host")?.takeIf { v: String -> v.isNotBlank() } ?: h?.optString("host") ?: ""
                if (host.isNotBlank()) q["host"] = host
            }
            "grpc" -> {
                q["type"] = "grpc"
                q["serviceName"] = t.optString("service_name")
            }
            "http" -> {
                q["type"] = "http"
                q["path"] = t.optString("path")
                val hosts = when (val h = t.opt("host")) {
                    is JSONArray -> strings(h)
                    is String -> listOf(h)
                    else -> emptyList<String>()
                }
                q["host"] = hosts.joinToString(",")
            }
            "httpupgrade" -> {
                q["type"] = "httpupgrade"
                q["path"] = t.optString("path")
                q["host"] = t.optString("host")
            }
            else -> throw IllegalArgumentException("unsupported transport: $type")
        }
    }

    /** A WireGuard `reserved` (a list, or sing-box's base64 form) as "1,2,3". */
    private fun reservedOf(v: Any?): String = when (v) {
        is JSONArray -> strings(v).joinToString(",")
        is String -> try {
            java.util.Base64.getDecoder().decode(v.trim()).joinToString(",") { b: Byte -> (b.toInt() and 0xff).toString() }
        } catch (e: Exception) {
            ""
        }
        else -> ""
    }

    /** The share link a sing-box outbound stands for (vmess aside: singboxVmess). */
    internal fun singboxLink(o: JSONObject, type: String, name: String): String {
        val frag = "#" + enc(name)
        val server = o.optString("server")
        return when (type) {
            "vless" -> {
                val q = LinkedHashMap<String, String>()
                q["encryption"] = "none"
                q["flow"] = o.optString("flow").trim()
                transportQ(o, q); tlsQ(o, q)
                "vless://" + o.optString("uuid").trim() + "@" + hostPort(server, portOf(o, 443)) + "?" + qs(q) + frag
            }
            "trojan" -> {
                val q = LinkedHashMap<String, String>()
                transportQ(o, q); tlsQ(o, q)
                "trojan://" + enc(o.optString("password")) + "@" + hostPort(server, portOf(o, 443)) + "?" + qs(q) + frag
            }
            "shadowsocks" -> {
                val plugin = o.optString("plugin").trim()
                val opts = o.optString("plugin_opts").trim()
                val p = if (plugin.isEmpty()) "" else "/?plugin=" + enc(if (opts.isEmpty()) plugin else "$plugin;$opts")
                "ss://" + enc(o.optString("method")) + ":" + enc(o.optString("password")) + "@" + hostPort(server, portOf(o, 8388)) + p + frag
            }
            "hysteria2" -> {
                val q = LinkedHashMap<String, String>()
                val tls = o.optJSONObject("tls") ?: JSONObject()
                q["sni"] = tls.optString("server_name").trim()
                if (tls.optBoolean("insecure", false)) q["insecure"] = "1"
                q["alpn"] = when (val a = tls.opt("alpn")) {
                    is JSONArray -> strings(a).joinToString(",")
                    is String -> a
                    else -> ""
                }
                echOf(tls)?.let { v: String -> q["ech"] = v }
                val obfs = o.optJSONObject("obfs")
                if (obfs != null && obfs.optString("type").ifBlank { "salamander" } == "salamander" && obfs.optString("password").isNotEmpty()) {
                    q["obfs"] = "salamander"
                    q["obfs-password"] = obfs.optString("password")
                }
                val ports = serverPorts(o)
                if (ports.isNotEmpty()) {
                    q["mport"] = ports.joinToString(",") { r: String -> r.replace(':', '-') }
                    firstPort(o.optString("hop_interval"))?.let { n: Int -> q["hopInterval"] = n.toString() }
                }
                val up = o.optInt("up_mbps", 0)
                val down = o.optInt("down_mbps", 0)
                q["up"] = if (up > 0) up.toString() else o.optString("up").trim()
                q["down"] = if (down > 0) down.toString() else o.optString("down").trim()
                "hysteria2://" + enc(o.optString("password")) + "@" + hostPort(server, portOf(o, 443)) + "/?" + qs(q) + frag
            }
            "wireguard" -> {
                // a 1.11 endpoint: the peer carries the server; the older outbound: itself
                val peer = o.optJSONArray("peers")?.optJSONObject(0)
                val host = peer?.optString("address")?.takeIf { v: String -> v.isNotBlank() }
                    ?: peer?.optString("server")?.takeIf { v: String -> v.isNotBlank() } ?: server
                val port = peer?.optInt("port", 0)?.takeIf { n: Int -> n > 0 }
                    ?: peer?.optInt("server_port", 0)?.takeIf { n: Int -> n > 0 } ?: portOf(o, 51820)
                val local = strings(o.optJSONArray("local_address")).ifEmpty { strings(o.optJSONArray("address")) }
                val q = LinkedHashMap<String, String>()
                q["publickey"] = peer?.optString("public_key")?.takeIf { v: String -> v.isNotBlank() } ?: o.optString("peer_public_key")
                q["address"] = local.joinToString(",")
                q["presharedkey"] = peer?.optString("pre_shared_key")?.takeIf { v: String -> v.isNotBlank() } ?: o.optString("pre_shared_key")
                q["allowedips"] = strings(peer?.optJSONArray("allowed_ips")).joinToString(",")
                val mtu = o.optInt("mtu", 0)
                q["mtu"] = if (mtu > 0) mtu.toString() else ""
                q["reserved"] = reservedOf(peer?.opt("reserved") ?: o.opt("reserved"))
                "wireguard://" + enc(o.optString("private_key")) + "@" + hostPort(host, port) + "?" + qs(q) + frag
            }
            "socks", "http" -> {
                if (type == "http" && o.optJSONObject("tls")?.optBoolean("enabled", false) == true) {
                    throw IllegalArgumentException("an HTTP proxy over TLS is not supported")
                }
                val user = o.optString("username")
                val pass = o.optString("password")
                val auth = if (user.isNotEmpty() || pass.isNotEmpty()) enc(user) + ":" + enc(pass) + "@" else ""
                type + "://" + auth + hostPort(server, portOf(o, if (type == "http") 8080 else 1080)) + frag
            }
            else -> throw IllegalArgumentException("unsupported protocol: $type")
        }
    }

    /** A sing-box vmess outbound as the vmess link's JSON, read the way that link is. */
    private fun singboxVmess(o: JSONObject, name: String): ServerConfig {
        val q = LinkedHashMap<String, String>()
        transportQ(o, q); tlsQ(o, q)
        if (q["security"] == "reality") throw IllegalArgumentException("VMess over REALITY is not supported")
        val server = o.optString("server").trim()
        if (server.isEmpty()) throw IllegalArgumentException("no server address")
        val net = q["type"] ?: "tcp"
        val v = JSONObject()
            .put("v", "2").put("ps", name).put("add", server).put("port", portOf(o, 443).toString())
            .put("id", o.optString("uuid").trim()).put("aid", o.optInt("alter_id", 0).toString())
            .put("scy", o.optString("security").trim().ifBlank { "auto" })
            .put("net", net).put("type", "none").put("host", q["host"] ?: "")
            .put("path", if (net == "grpc") (q["serviceName"] ?: "") else (q["path"] ?: ""))
            .put("tls", if (q["security"] == "tls") "tls" else "")
            .put("sni", q["sni"] ?: "").put("fp", q["fp"] ?: "").put("alpn", q["alpn"] ?: "")
        if (q["allowInsecure"] == "1") v.put("allowInsecure", "1")
        q["ech"]?.let { e: String -> v.put("ech", e) }
        val link = "vmess://" + java.util.Base64.getEncoder().encodeToString(JsonText.minify(v).toByteArray(Charsets.UTF_8))
        return LinkParser.vmessFromJson(v, link)
    }
}

/**
 * JSON text the way JavaScript's JSON.stringify writes it — keys in the
 * object's own order, `/` left alone (org.json on Android writes `\/`), no
 * escapes for non-ASCII. What a JSON server's `raw`, its Copy and its QR are.
 */
object JsonText {
    /** One line, no spaces: JSON.stringify(v). */
    fun minify(v: Any?): String = StringBuilder().also { sb: StringBuilder -> write(sb, v, null, 0, false) }.toString()

    /** Two-space indents: JSON.stringify(v, null, 2). */
    fun pretty(v: Any?): String = StringBuilder().also { sb: StringBuilder -> write(sb, v, "  ", 0, false) }.toString()

    /** One line with every object's keys sorted: two configs with the same content compare equal. */
    fun canonical(v: Any?): String = StringBuilder().also { sb: StringBuilder -> write(sb, v, null, 0, true) }.toString()

    private fun newline(sb: StringBuilder, indent: String?, depth: Int) {
        if (indent == null) return
        sb.append('\n')
        repeat(depth) { sb.append(indent) }
    }

    private fun write(sb: StringBuilder, v: Any?, indent: String?, depth: Int, sorted: Boolean) {
        when {
            v == null || v == JSONObject.NULL -> sb.append("null")
            v is JSONObject -> {
                val keys0 = v.keys().asSequence().toList()
                val keys = if (sorted) keys0.sorted() else keys0
                if (keys.isEmpty()) {
                    sb.append("{}")
                } else {
                    sb.append('{')
                    keys.forEachIndexed { i: Int, k: String ->
                        if (i > 0) sb.append(',')
                        newline(sb, indent, depth + 1)
                        quote(sb, k)
                        sb.append(':')
                        if (indent != null) sb.append(' ')
                        write(sb, v.opt(k), indent, depth + 1, sorted)
                    }
                    newline(sb, indent, depth)
                    sb.append('}')
                }
            }
            v is JSONArray -> {
                if (v.length() == 0) {
                    sb.append("[]")
                } else {
                    sb.append('[')
                    for (i in 0 until v.length()) {
                        if (i > 0) sb.append(',')
                        newline(sb, indent, depth + 1)
                        write(sb, v.opt(i), indent, depth + 1, sorted)
                    }
                    newline(sb, indent, depth)
                    sb.append(']')
                }
            }
            v is String -> quote(sb, v)
            v is Boolean -> sb.append(if (v) "true" else "false")
            v is Number -> sb.append(JSONObject.numberToString(v))
            else -> quote(sb, v.toString())
        }
    }

    private fun hex4(c: Char): String = "\\u" + c.code.toString(16).padStart(4, '0')

    private fun quote(sb: StringBuilder, s: String) {
        sb.append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c == '\b' -> sb.append("\\b")
                c == '\u000C' -> sb.append("\\f")
                c < ' ' -> sb.append(hex4(c))
                Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1]) -> {
                    sb.append(c).append(s[i + 1])
                    i++
                }
                Character.isSurrogate(c) -> sb.append(hex4(c))
                else -> sb.append(c)
            }
            i++
        }
        sb.append('"')
    }
}
