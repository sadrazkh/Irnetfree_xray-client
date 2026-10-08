package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.util.zip.DataFormatException
import java.util.zip.Deflater
import java.util.zip.Inflater

/**
 * Routing-profile and chain share links — the desktop's src/main/routeShare.js
 * (spec §4). One line of text:
 *
 *     irnetfree://routing/<base64url(deflate-raw(JSON))>
 *
 * The JSON is `{ v: 1, kind: "profile"|"chain", profile?, chains, servers }`:
 * servers `{ key: "s<n>", name, link }` (link = what Copy gives for that
 * server: a share link, or a JSON server's config text), chains `{ key:
 * "c<n>", name, members: [server keys] }`, and the profile with every target,
 * via and base rewritten to those keys (`sN`, `chain:cN`). Only the profile's
 * useMode travels; the receiver's routing mode, DNS and the rest stay theirs.
 *
 * Pure (java.util.zip raw deflate + java.util.Base64, no android.*): the JVM
 * tests decode the very text the desktop's tests do (tests/fixtures/routing/).
 */
object RouteShare {
    const val PREFIX = "irnetfree://routing/"
    /** The most a link's JSON may inflate to; more is refused, nothing written. */
    const val MAX_DECODED = 65536
    /** A QR is offered up to this many bytes of text; larger codes do not scan (the desktop's limit). */
    const val QR_MAX_BYTES = 1700
    const val KIND_PROFILE = "profile"
    const val KIND_CHAIN = "chain"

    private val SERVER_KEY = Regex("^s\\d+$")
    private val CHAIN_KEY = Regex("^c\\d+$")

    /** Does [text] look like one of these links (the add box, paste, a scanned QR)? */
    fun looksLikeShare(text: String): Boolean = text.trim().startsWith(PREFIX, ignoreCase = true)

    /** Small enough for a QR that scans. */
    fun fitsQr(text: String): Boolean = text.toByteArray(Charsets.UTF_8).size <= QR_MAX_BYTES

    /* ----------------------------- the text ----------------------------- */

    /** The link for [payload]. Throws IllegalArgumentException when it would be over [MAX_DECODED] — no receiver takes it. */
    fun encode(payload: JSONObject): String {
        val raw = payload.toString().toByteArray(Charsets.UTF_8)
        if (raw.size > MAX_DECODED) throw IllegalArgumentException("Too much to share in one link (${raw.size / 1024} KB; at most 64 KB) — share fewer servers")
        val d = Deflater(Deflater.BEST_COMPRESSION, true)
        try {
            d.setInput(raw)
            d.finish()
            val out = ByteArrayOutputStream()
            val buf = ByteArray(4096)
            while (!d.finished()) {
                val n = d.deflate(buf)
                out.write(buf, 0, n)
            }
            return PREFIX + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(out.toByteArray())
        } finally {
            d.end()
        }
    }

    /**
     * The payload a link carries, checked: the prefix, base64url, a whole raw
     * deflate stream of at most [MAX_DECODED] bytes, JSON, `v` 1, a known kind,
     * well-formed servers and chains, and every key the profile and chains
     * name present. Throws IllegalArgumentException with the reason in words.
     */
    fun decode(text: String): JSONObject {
        val t = text.trim()
        if (!t.startsWith(PREFIX, ignoreCase = true)) throw IllegalArgumentException("Not a routing link — it starts with $PREFIX")
        // base64url, with the plain alphabet and padding forgiven (a hand-copied line)
        val body = t.substring(PREFIX.length).replace(Regex("\\s"), "").replace('+', '-').replace('/', '_').trimEnd('=')
        if (body.isEmpty()) throw IllegalArgumentException("The routing link is empty")
        val packed = try {
            java.util.Base64.getUrlDecoder().decode(body)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("The routing link is damaged (not base64url) — copy the whole line again")
        }
        val json = inflate(packed)
        val o = try { JSONObject(json) } catch (e: Exception) { throw IllegalArgumentException("The routing link is damaged (its content is not JSON)") }
        validate(o)
        return o
    }

    private fun inflate(packed: ByteArray): String {
        val inf = Inflater(true)
        try {
            // java.util.zip's raw mode asks for one byte past the stream (Inflater, "nowrap")
            inf.setInput(packed + byteArrayOf(0))
            val out = ByteArrayOutputStream()
            val buf = ByteArray(8192)
            while (!inf.finished()) {
                val n = try { inf.inflate(buf) } catch (e: DataFormatException) {
                    throw IllegalArgumentException("The routing link is damaged (not deflate data) — copy the whole line again")
                }
                if (n == 0 && !inf.finished()) throw IllegalArgumentException("The routing link is cut short — copy the whole line again")
                out.write(buf, 0, n)
                if (out.size() > MAX_DECODED) throw IllegalArgumentException("The routing link is too large (more than 64 KB once unpacked) — refused")
            }
            return String(out.toByteArray(), Charsets.UTF_8)
        } finally {
            inf.end()
        }
    }

    /** A string field: "" when absent, null or not a string (Android's org.json reads a null as "null"). */
    private fun str(o: JSONObject, k: String): String = if (o.isNull(k)) "" else (o.opt(k) as? String) ?: ""

    private fun bad(why: String): IllegalArgumentException = IllegalArgumentException("The routing link is not valid: $why")

    private fun validate(o: JSONObject) {
        val v = o.opt("v")
        if (v !is Number || v.toDouble() != 1.0) {
            if (v is Number && v.toDouble() > 1.0) throw IllegalArgumentException("This routing link was made by a newer IRNetFree (version $v) — update the app to import it")
            throw IllegalArgumentException("Not a routing link this app knows (no version 1)")
        }
        val kind = str(o, "kind")
        if (kind != KIND_PROFILE && kind != KIND_CHAIN) throw IllegalArgumentException("Unknown kind of routing link \"$kind\"")
        val servers = o.opt("servers") as? JSONArray ?: throw bad("no server list")
        val chains = o.opt("chains") as? JSONArray ?: throw bad("no chain list")
        val sKeys = HashSet<String>()
        for (i in 0 until servers.length()) {
            val s = servers.opt(i) as? JSONObject ?: throw bad("a server entry is not an object")
            val key = str(s, "key")
            if (!SERVER_KEY.matches(key)) throw bad("a server key \"$key\"")
            if (!sKeys.add(key)) throw bad("server $key twice")
            if (str(s, "link").isBlank()) throw bad("server $key carries no link")
        }
        val cKeys = HashSet<String>()
        for (i in 0 until chains.length()) {
            val c = chains.opt(i) as? JSONObject ?: throw bad("a chain entry is not an object")
            val key = str(c, "key")
            if (!CHAIN_KEY.matches(key)) throw bad("a chain key \"$key\"")
            if (!cKeys.add(key)) throw bad("chain $key twice")
            val members = c.opt("members") as? JSONArray ?: throw bad("chain $key has no members list")
            for (j in 0 until members.length()) {
                val m = members.opt(j) as? String ?: throw bad("chain $key names a member that is not a key")
                if (m !in sKeys) throw bad("chain $key names server $m, which the link does not carry")
            }
        }
        fun target(t: String, what: String) {
            when {
                t.isEmpty() || t == "direct" || t == "block" -> {}
                t.startsWith("chain:") -> { if (t.substring(6) !in cKeys) throw bad("$what names chain ${t.substring(6)}, which the link does not carry") }
                t in sKeys -> {}
                else -> throw bad("$what names \"$t\", which the link does not carry")
            }
        }
        fun via(t: String, what: String) {
            if (t.isEmpty() || t == RoutingProfiles.VIA_INHERIT || t == RoutingProfiles.VIA_NONE) return
            if (t == "direct" || t == "block") throw bad("$what goes via $t")
            target(t, what)
        }
        if (kind == KIND_CHAIN) {
            if (chains.length() == 0) throw bad("a chain link without its chain")
            return
        }
        val p = o.opt("profile") as? JSONObject ?: throw bad("a profile link without its profile")
        val rules = p.opt("rules") as? JSONArray ?: throw bad("the profile has no rules list")
        for (i in 0 until rules.length()) {
            val r = rules.opt(i) as? JSONObject ?: throw bad("rule ${i + 1} is not an object")
            target(str(r, "target"), "rule ${i + 1}")
            via(str(r, "via"), "rule ${i + 1}")
        }
        target(str(p, "def"), "the default")
        via(str(p, "defVia"), "the default")
        val base = str(p, "base")
        if (base == "direct" || base == "block") throw bad("the base is $base")
        target(base, "the base")
    }

    /* ----------------------------- making one ----------------------------- */

    /**
     * Local keys for what a payload carries, handed out in the order things are
     * met (`s1`, `s2`…, `c1`…), never the sender's ids. A target that no longer
     * exists refuses the share: the receiver could not route it either.
     */
    private class Keys(val servers: List<ServerConfig>, val chains: List<ChainConfig>) {
        val serverKeys = LinkedHashMap<String, String>()
        val chainKeys = LinkedHashMap<String, String>()

        fun server(id: String): String {
            serverKeys[id]?.let { k: String -> return k }
            if (servers.none { s: ServerConfig -> s.id == id }) throw IllegalArgumentException("It names a server that no longer exists — fix it under Routing first")
            val k = "s${serverKeys.size + 1}"
            serverKeys[id] = k
            return k
        }

        fun chain(id: String): String {
            chainKeys[id]?.let { k: String -> return k }
            val c = chains.firstOrNull { x: ChainConfig -> x.id == id } ?: throw IllegalArgumentException("It names a chain that no longer exists — fix it under Routing first")
            val k = "c${chainKeys.size + 1}"
            chainKeys[id] = k
            // its members get their keys as the chain is met
            for (m in c.members) if (servers.any { s: ServerConfig -> s.id == m }) server(m)
            return k
        }

        fun target(t: String): String = when {
            t.isEmpty() || t == "direct" || t == "block" -> t
            // Android's legacy "Proxy (first server)" is that server — the desktop has no such target
            t == "proxy" -> servers.firstOrNull { s: ServerConfig -> s.outbound.length() > 0 }?.let { s: ServerConfig -> server(s.id) } ?: "direct"
            t.startsWith("chain:") -> "chain:" + chain(t.substring(6))
            else -> server(t)
        }

        fun via(v: String): String = when (v) {
            "", RoutingProfiles.VIA_INHERIT -> RoutingProfiles.VIA_INHERIT
            RoutingProfiles.VIA_NONE -> RoutingProfiles.VIA_NONE
            else -> target(v)
        }

        fun serversJson(linkOf: (ServerConfig) -> String): JSONArray = JSONArray().apply {
            for ((id, key) in serverKeys) {
                val s = servers.first { x: ServerConfig -> x.id == id }
                put(JSONObject().put("key", key).put("name", s.name).put("link", linkOf(s)))
            }
        }

        fun chainsJson(): JSONArray = JSONArray().apply {
            for ((id, key) in chainKeys) {
                val c = chains.first { x: ChainConfig -> x.id == id }
                val members = JSONArray()
                for (m in c.members) serverKeys[m]?.let { k: String -> members.put(k) }
                put(JSONObject().put("key", key).put("name", c.name).put("members", members))
            }
        }
    }

    /**
     * The payload for a routing profile: the profile (no id; its useMode the one
     * setting carried) with targets, vias and base rewritten to keys, and only
     * the servers and chains it names. [linkOf]: what Copy gives for a server
     * (LinkParser.buildShareLink). Throws when it names something gone.
     */
    fun profilePayload(profile: RoutingProfile, servers: List<ServerConfig>, chains: List<ChainConfig>, linkOf: (ServerConfig) -> String): JSONObject {
        val k = Keys(servers, chains)
        val p = RoutingProfiles.normalize(profile)
        // the order keys are handed out in: the base, the default, then each rule's target and via
        val base = p.base?.let { b: String -> k.target(b) }
        val def = k.target(p.def)
        val defVia = k.via(p.defVia)
        val rules = JSONArray()
        for (r in p.rules) {
            val t = k.target(r.target)
            val o = JSONObject().put("type", r.type).put("value", r.value).put("target", t)
            if (RoutingProfiles.takesVia(t)) o.put("via", k.via(r.via))
            rules.put(o)
        }
        val po = JSONObject()
            .put("name", p.name)
            .put("useMode", p.useMode)
            .put("base", base ?: JSONObject.NULL)
            .put("def", def)
            .put("defVia", defVia)
            .put("rules", rules)
        return JSONObject()
            .put("v", 1)
            .put("kind", KIND_PROFILE)
            .put("servers", k.serversJson(linkOf))
            .put("chains", k.chainsJson())
            .put("profile", po)
    }

    /** The payload for one chain: the chain and its servers. */
    fun chainPayload(chain: ChainConfig, servers: List<ServerConfig>, linkOf: (ServerConfig) -> String): JSONObject {
        val k = Keys(servers, listOf(chain))
        k.chain(chain.id)
        return JSONObject()
            .put("v", 1)
            .put("kind", KIND_CHAIN)
            .put("servers", k.serversJson(linkOf))
            .put("chains", k.chainsJson())
    }

    /* ----------------------------- taking one in ----------------------------- */

    /** What an import would do, before it does it (the preview). [unreadable]: the servers whose link this app cannot read, by name, with why. */
    data class Summary(
        val kind: String,
        val name: String,
        val rules: Int,
        val chains: Int,
        val serversNew: Int,
        val serversExisting: Int,
        val unreadable: List<String>
    )

    /** A payload server's link read back as this app reads a pasted one (LinkParser.parseMany): its first server, or why not. */
    fun parseServer(link: String): ServerConfig {
        val (list, errs) = LinkParser.parseMany(link)
        return list.firstOrNull() ?: throw IllegalArgumentException(errs.firstOrNull() ?: "not a server link this app reads")
    }

    /** One payload server, as it would come in: a server already here ([existingId]), a new one ([server]), or unreadable ([error]). */
    private class Incoming(val key: String, val name: String, val existingId: String?, val server: ServerConfig?, val error: String?)

    /**
     * Each payload server matched against [servers] by [identityOf] (the strict
     * identity, SubRefresh.strictIdentity): the same server is reused, a new
     * one is read with [parse] (throws when it cannot). Two payload entries
     * that are one server come in once.
     */
    private fun incoming(payload: JSONObject, servers: List<ServerConfig>, parse: (String) -> ServerConfig, identityOf: (ServerConfig) -> String): List<Incoming> {
        val known = HashMap<String, String>()
        for (s in servers) { val id = identityOf(s); if (id.isNotEmpty() && id !in known) known[id] = s.id }
        val fresh = HashMap<String, String>()   // identity → the payload key that brings it
        val list = payload.optJSONArray("servers") ?: JSONArray()
        val out = ArrayList<Incoming>()
        for (i in 0 until list.length()) {
            val o = list.optJSONObject(i) ?: continue
            val key = str(o, "key")
            val name = str(o, "name")
            val parsed = try { parse(str(o, "link")) } catch (e: Exception) {
                out.add(Incoming(key, name, null, null, e.message ?: "unreadable"))
                continue
            }
            val ident = identityOf(parsed)
            val here = known[ident]
            val twin = fresh[ident]
            when {
                here != null -> out.add(Incoming(key, name, here, null, null))
                twin != null -> out.add(Incoming(key, name, "=$twin", null, null))
                else -> {
                    if (ident.isNotEmpty()) fresh[ident] = key
                    out.add(Incoming(key, name, null, parsed, null))
                }
            }
        }
        return out
    }

    /** The preview of importing [payload] (already decoded) into these lists. */
    fun previewImport(
        payload: JSONObject, servers: List<ServerConfig>, chains: List<ChainConfig>, profiles: List<RoutingProfile>,
        parse: (String) -> ServerConfig, identityOf: (ServerConfig) -> String
    ): Summary {
        val kind = str(payload, "kind")
        val inc = incoming(payload, servers, parse, identityOf)
        val chainList = payload.optJSONArray("chains") ?: JSONArray()
        val p = payload.optJSONObject("profile")
        val name = if (kind == KIND_PROFILE) str(p ?: JSONObject(), "name")
            else chainList.optJSONObject(0)?.let { c: JSONObject -> str(c, "name") } ?: ""
        return Summary(
            kind = kind,
            name = name,
            rules = if (kind == KIND_PROFILE) (p?.optJSONArray("rules")?.length() ?: 0) else 0,
            chains = chainList.length(),
            serversNew = inc.count { x: Incoming -> x.server != null },
            serversExisting = inc.count { x: Incoming -> x.existingId != null },
            unreadable = inc.filter { x: Incoming -> x.error != null }.map { x: Incoming -> "${x.name.ifBlank { x.key }}: ${x.error}" }
        )
    }

    /** What an import did: the new lists, how much it added, and the profile (or chain) it brought. */
    class Imported(
        val servers: List<ServerConfig>,
        val chains: List<ChainConfig>,
        val profiles: List<RoutingProfile>,
        val addedServers: Int,
        val addedChains: Int,
        val addedProfiles: Int,
        val profileId: String?,
        val chainId: String?
    )

    /** What a reference to a server this phone could not read becomes: a target that does not exist, which Routing marks. */
    const val UNREADABLE_PREFIX = "unreadable-"

    /**
     * [payload] (already decoded) taken into the lists — pure: new lists back,
     * nothing written. Servers already here (the same strict identity) are
     * reused, new ones added by hand (no subscription); a chain with the same
     * name and members (after mapping) is reused, else created; the profile is
     * always added as new, its name made unique ("Work (2)"). A chain link
     * brings its chain and servers only. [newId]: a fresh id for a prefix ("s",
     * "chain", "rp").
     */
    fun applyImport(
        payload: JSONObject, servers: List<ServerConfig>, chains: List<ChainConfig>, profiles: List<RoutingProfile>,
        parse: (String) -> ServerConfig, identityOf: (ServerConfig) -> String, newId: (String) -> String
    ): Imported {
        validate(payload)
        val kind = str(payload, "kind")
        val outServers = servers.toMutableList()
        val idOf = HashMap<String, String>()
        var addedServers = 0
        val twins = ArrayList<Pair<String, String>>()
        for (x in incoming(payload, servers, parse, identityOf)) {
            val existing = x.existingId
            val parsed = x.server
            when {
                existing != null && existing.startsWith("=") -> twins.add(Pair(x.key, existing.substring(1)))
                existing != null -> idOf[x.key] = existing
                parsed != null -> {
                    val s = parsed.copy(id = newId("s"), name = x.name.ifBlank { parsed.name }, subId = null)
                    outServers.add(s)
                    idOf[x.key] = s.id
                    addedServers++
                }
                else -> {}
            }
        }
        for ((key, twinOf) in twins) idOf[twinOf]?.let { id: String -> idOf[key] = id }

        val outChains = chains.toMutableList()
        val chainIdOf = HashMap<String, String>()
        var addedChains = 0
        val chainList = payload.optJSONArray("chains") ?: JSONArray()
        for (i in 0 until chainList.length()) {
            val c = chainList.optJSONObject(i) ?: continue
            val key = str(c, "key")
            val name = str(c, "name").ifBlank { "Chain" }
            val m = c.optJSONArray("members") ?: JSONArray()
            val members = (0 until m.length()).mapNotNull { j: Int -> idOf[m.optString(j)] }
            val same = outChains.firstOrNull { x: ChainConfig -> x.name == name && x.members == members }
            if (same != null) {
                chainIdOf[key] = same.id
            } else {
                val made = ChainConfig(newId("chain"), name, members)
                outChains.add(made)
                chainIdOf[key] = made.id
                addedChains++
            }
        }

        fun mapTarget(t: String): String = when {
            t.isEmpty() || t == "direct" || t == "block" -> t
            t.startsWith("chain:") -> chainIdOf[t.substring(6)]?.let { id: String -> "chain:$id" } ?: (UNREADABLE_PREFIX + t.substring(6))
            else -> idOf[t] ?: (UNREADABLE_PREFIX + t)
        }
        fun mapVia(v: String): String = when (v) {
            "", RoutingProfiles.VIA_INHERIT -> RoutingProfiles.VIA_INHERIT
            RoutingProfiles.VIA_NONE -> RoutingProfiles.VIA_NONE
            else -> mapTarget(v)
        }

        val outProfiles = profiles.toMutableList()
        var profileId: String? = null
        val po = payload.optJSONObject("profile")
        if (kind == KIND_PROFILE && po != null) {
            val ra = po.optJSONArray("rules") ?: JSONArray()
            val rules = (0 until ra.length()).mapNotNull { i: Int -> ra.optJSONObject(i) }.map { r: JSONObject ->
                val t = mapTarget(str(r, "target"))
                RouteRule(str(r, "type").ifEmpty { "domain" }, str(r, "value"), t, if (RoutingProfiles.takesVia(t)) mapVia(str(r, "via")) else "")
            }
            val base = str(po, "base")
            val made = RoutingProfiles.normalize(RoutingProfile(
                id = newId("rp"),
                name = RoutingProfiles.uniqueName(str(po, "name"), outProfiles.map { x: RoutingProfile -> x.name }),
                rules = rules,
                def = mapTarget(str(po, "def")),
                defVia = mapVia(str(po, "defVia")),
                useMode = po.optBoolean("useMode", false),
                base = if (base.isEmpty()) null else mapTarget(base)
            ))
            outProfiles.add(made)
            profileId = made.id
        }
        val chainId = if (kind == KIND_CHAIN) chainList.optJSONObject(0)?.let { c: JSONObject -> chainIdOf[str(c, "key")] } else null
        return Imported(outServers, outChains, outProfiles, addedServers, addedChains, if (profileId != null) 1 else 0, profileId, chainId)
    }
}
