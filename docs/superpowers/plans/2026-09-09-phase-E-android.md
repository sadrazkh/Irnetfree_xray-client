# Phase E — Android parity — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Run on Opus; Fable reviews E1 and E3 for parity with the desktop builders.

**Goal:** Bring the Android port up to the desktop on the three things that changed the shape of the config since it was written: the managed DNS plan (DoH through the tunnel, an in-country resolver for bypass modes, every port-53 packet answered by the core) — E1; `dns=` on WireGuard share links — E2; `advancedUseMode` (the simple routing mode applied under the advanced rules) — E3.

**Architecture:** `ConfigBuilder.kt` and `LinkParser.kt` are hand-written ports of `configBuilder.js`/`dnsBuilder.js` and `parser.js`; parity is by construction, pinned by reading the JS tests next to each Kotlin change. A new `DnsPlan.kt` mirrors `dnsBuilder.js` function for function. No local Kotlin toolchain exists: the compile gate is CI (`test.yml` → `compile android`), and the JS tests named in each task are the specification.

**Tech Stack:** Kotlin, `org.json`, Android VpnService + libv2ray (XrayCore.kt) + hev-socks5-tunnel; CI on GitHub Actions (JDK 17, Gradle 8.7). Branch `feature/phase-E` from `main`. Tag: v1.7.0 (`android/app/build.gradle.kts` `versionName` default follows).

## Global Constraints

- No Kotlin can be compiled on this machine. Every task ends with a push to the branch and a green `compile android` job in `test.yml`; a red job is fixed before the next task starts.
- The desktop is the specification. For every rule list, the JS test that pins its order is named in the task; the Kotlin must produce the SAME order. Do not "improve" the order.
- The desktop's own files are not touched in this phase (no JS changes; if a mismatch in the JS is found, note it in the commit body and stop — it is a desktop bug to fix there first).
- `versionName` default in `android/app/build.gradle.kts` (line 34) stays `1.3.0` until the owner tags; the release workflow injects the tag.
- Persian strings in `MainActivity.kt` follow the existing style (Persian first, English in parentheses where the file does that).
- Commits in the owner's name only, no `Co-Authored-By`.

Order: E1 → E3 (E3 reads the region helper E1 adds) → E2 (independent).

---

## File map

| File | Responsibility | Tasks |
|---|---|---|
| `android/app/src/main/java/com/irnetfree/vpn/core/DnsPlan.kt` (new) | port of `dnsBuilder.js` (managed plan, no target resolvers) | E1 |
| `android/…/core/Models.kt` | `AppSettings.dnsManaged/dnsRemote/dnsDirect/advancedUseMode`; `ServerConfig.dns/dnsDomains` | E1, E2, E3 |
| `android/…/core/ConfigBuilder.kt` | use the plan in `assemble`; `advancedUseMode` splice; region helper | E1, E3 |
| `android/…/core/LinkParser.kt` | `dns=` in/out, `withWgDns`, `splitDnsField`, a real `wireguard://` share link | E2 |
| `android/…/core/SingboxConfig.kt` | read `dnsRemote` | E1 |
| `android/…/ui/MainActivity.kt` | DNS fields, the `advancedUseMode` switch | E1, E3 |
| `android/…/vpn/XrayVpnService.kt` | unchanged (see the note in E1 step 6) | — |

---

### Task E1: the managed DNS plan

**Specification:** `src/main/dnsBuilder.js` (`buildDnsPlan`, `directRegion`, `serverEntry`, `resolverIp`, `isPrivateIp`, `cleanList`) and the tests in `tests/dnsBuilder.test.js` — read them first. The plan emitted for the desktop's default settings is:

```json
"dns": { "tag": "dns-internal", "queryStrategy": "UseIPv4",
         "servers": [ "https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query" ] }
```
and with `routingMode: "bypass-ir"` + geo files:
```json
"servers": [
  { "address": "178.22.122.100", "domains": ["geosite:category-ir", "regexp:.*\\.ir$"], "expectedIPs": ["geoip:ir"], "skipFallback": true },
  { "address": "185.51.200.2",   "domains": ["geosite:category-ir", "regexp:.*\\.ir$"], "expectedIPs": ["geoip:ir"], "skipFallback": true },
  "https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query" ]
```
plus the outbound `{ "tag": "dns-out", "protocol": "dns", "settings": { "rules": [ { "action": "return", "rCode": 5, "qType": "0,2-27,29-65535" } ] } }` and, FIRST in `routing.rules`:
```json
{ "type": "field", "inboundTag": ["dns-internal"], "ip": ["178.22.122.100", "185.51.200.2"], "outboundTag": "direct" },
{ "type": "field", "inboundTag": ["dns-internal"], "outboundTag": "<exitTag>" },
{ "type": "field", "port": "53", "network": "tcp,udp", "outboundTag": "dns-out" }
```
(the first rule only when there are direct resolver IPs). `dnsManaged: false` = the legacy shape (`servers: dnsRemote` as given, no tag, no hijack, no rules). Target resolvers (a corporate WireGuard's DNS) are NOT ported in this task: Android's `ConfigBuilder.kt` has no `wgResolvers` yet; `targetResolvers` is left as an empty list with a comment naming the JS function.

- [ ] **Step 1: `AppSettings`**

`Models.kt` `data class AppSettings`: keep `dns` (legacy, still read by the UI) and add
```kotlin
    // The managed resolver plan (see DnsPlan.kt / desktop dnsBuilder.js). `dns` is the legacy list.
    val dnsManaged: Boolean = true,
    val dnsRemote: List<String> = listOf("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"),
    val dnsDirect: List<String> = listOf("178.22.122.100", "185.51.200.2"),
```
`toJson()`: `put("dnsManaged", dnsManaged); put("dnsRemote", JSONArray(dnsRemote)); put("dnsDirect", JSONArray(dnsDirect))`.
`fromJson()`: 
```kotlin
            val remote = strList(o.optJSONArray("dnsRemote")).ifEmpty {
                // a store from before the managed plan: its `dns` list was the remote list
                strList(o.optJSONArray("dns")).ifEmpty { listOf("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query") }
            }
            …
                dnsManaged = o.optBoolean("dnsManaged", true),
                dnsRemote = remote,
                dnsDirect = strList(o.optJSONArray("dnsDirect")).ifEmpty { listOf("178.22.122.100", "185.51.200.2") },
```

- [ ] **Step 2: `DnsPlan.kt`**

```kotlin
package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * Port of src/main/dnsBuilder.js — the resolver plan and the routing rules
 * that make it safe. Function for function; the JS tests
 * (tests/dnsBuilder.test.js) are the specification. Target resolvers (a
 * corporate WireGuard's DNS, `targetResolvers` in the JS) are not ported yet.
 */
object DnsPlan {
    const val DNS_TAG = "dns-internal"
    const val HIJACK_TAG = "dns-out"
    private val DEFAULT_REMOTE = listOf("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query")
    private val DEFAULT_DIRECT_IR = listOf("178.22.122.100", "185.51.200.2")
    private val DEFAULT_DIRECT_CN = listOf("223.5.5.5")
    private val URL_SCHEME = Regex("^[a-z+]+://", RegexOption.IGNORE_CASE)
    private val IPV4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")

    class Result(val dns: JSONObject, val hijackOutbound: JSONObject?, val rules: List<JSONObject>, val directResolverIps: List<String>)

    fun isDohUrl(s: String?): Boolean = Regex("^https(\\+local)?://", RegexOption.IGNORE_CASE).containsMatchIn((s ?: "").trim())

    /** "host:port" / "[v6]:port" → host to port; anything else keeps port null. */
    private fun splitHostPort(e: String): Pair<String, Int?> {
        Regex("^\\[([^\\]]+)\\]:(\\d{1,5})$").find(e)?.let { return it.groupValues[1] to it.groupValues[2].toInt() }
        Regex("^([^:/]+):(\\d{1,5})$").find(e)?.let { return it.groupValues[1] to it.groupValues[2].toInt() }
        return e to null
    }

    private fun isIp(h: String): Boolean = IPV4.matches(h) || (h.contains(":") && Regex("^[0-9a-fA-F:.]+$").matches(h))

    /** The literal IP an entry dials, or null for a hostname (bare or in a URL). */
    fun resolverIp(entry: String?): String? {
        val e = (entry ?: "").trim()
        val m = Regex("^[a-z+]+://(\\[[^\\]]+\\]|[^/:?#]+)", RegexOption.IGNORE_CASE).find(e)
        val host = if (m != null) m.groupValues[1].removePrefix("[").removeSuffix("]") else splitHostPort(e).first
        return if (isIp(host)) host else null
    }

    fun isPrivateIp(ip: String): Boolean {
        if (IPV4.matches(ip)) {
            val p = ip.split(".").map { it.toInt() }
            val a = p[0]; val b = p[1]
            return a == 10 || a == 127 || (a == 172 && b in 16..31) || (a == 192 && b == 168) || (a == 169 && b == 254) || (a == 100 && b in 64..127)
        }
        return Regex("^(fc|fd|fe80:|::1$)", RegexOption.IGNORE_CASE).containsMatchIn(ip)
    }

    /** A resolver entry in the core's shape: a URL / bare address as a string, "host:port" as { address, port }. */
    fun serverEntry(entry: String): Any {
        val e = entry.trim()
        if (URL_SCHEME.containsMatchIn(e)) return e
        val (host, port) = splitHostPort(e)
        return if (port != null) JSONObject().put("address", host).put("port", port) else e
    }

    fun cleanList(list: List<String>?): List<String> {
        val out = ArrayList<String>()
        for (raw in list ?: emptyList()) { val v = raw.trim(); if (v.isNotEmpty() && v !in out) out.add(v) }
        return out
    }

    /** 'ir' | 'cn' | null — mirrors directRegion() in dnsBuilder.js, geoAssets being the veto. */
    fun directRegion(s: AppSettings, geoAssets: Boolean): String? {
        if (!geoAssets) return null
        if (s.advancedRouting) {
            var region: String? = null
            for (r in s.routeRules) {
                if (r.type != "domain" || r.target != "direct") continue
                val v = r.value.lowercase()
                if (v.contains("geosite:category-ir")) return "ir"
                if (v.contains("geosite:cn")) region = region ?: "cn"
            }
            if (region != null || !s.advancedUseMode) return region
        }
        return when (s.routingMode) { "bypass-ir" -> "ir"; "bypass-cn" -> "cn"; else -> null }
    }

    fun build(s: AppSettings, geoAssets: Boolean, exitTag: String): Result {
        val queryStrategy = if (s.ipv6) "UseIP" else "UseIPv4"
        var remote = cleanList(s.dnsRemote)
        if (remote.isEmpty()) remote = DEFAULT_REMOTE

        if (!s.dnsManaged) {
            val servers = JSONArray(); remote.forEach { servers.put(serverEntry(it)) }
            return Result(JSONObject().put("queryStrategy", queryStrategy).put("servers", servers), null, emptyList(), emptyList())
        }

        val servers = JSONArray()
        val directResolverIps = ArrayList<String>()
        val region = directRegion(s, geoAssets)
        if (region != null) {
            var direct = if (region == "cn") DEFAULT_DIRECT_CN else cleanList(s.dnsDirect)
            if (direct.isEmpty()) direct = if (region == "cn") DEFAULT_DIRECT_CN else DEFAULT_DIRECT_IR
            val domains = if (region == "ir") listOf("geosite:category-ir", "regexp:.*\\.ir$") else listOf("geosite:cn")
            val expected = if (region == "ir") listOf("geoip:ir") else listOf("geoip:cn")
            for (address in direct.take(2)) {
                val ent = serverEntry(address)
                val srv = if (ent is JSONObject) ent else JSONObject().put("address", ent)
                srv.put("domains", JSONArray(domains)).put("expectedIPs", JSONArray(expected)).put("skipFallback", true)
                servers.put(srv)
                resolverIp(address)?.let { if (it !in directResolverIps) directResolverIps.add(it) }
            }
        }
        for (r in remote) {
            servers.put(serverEntry(r))
            val ip = resolverIp(r)
            if (ip != null && isPrivateIp(ip) && ip !in directResolverIps) directResolverIps.add(ip)
        }
        // targetResolvers (dnsBuilder.js): not ported — Android has no WireGuard resolver extraction yet.

        val rules = ArrayList<JSONObject>()
        if (directResolverIps.isNotEmpty()) rules.add(JSONObject().put("type", "field").put("inboundTag", JSONArray().put(DNS_TAG)).put("ip", JSONArray(directResolverIps)).put("outboundTag", "direct"))
        rules.add(JSONObject().put("type", "field").put("inboundTag", JSONArray().put(DNS_TAG)).put("outboundTag", exitTag))
        rules.add(JSONObject().put("type", "field").put("port", "53").put("network", "tcp,udp").put("outboundTag", HIJACK_TAG))

        val hijack = JSONObject().put("tag", HIJACK_TAG).put("protocol", "dns").put("settings", JSONObject().put("rules",
            JSONArray().put(JSONObject().put("action", "return").put("rCode", 5).put("qType", "0,2-27,29-65535"))))
        return Result(JSONObject().put("tag", DNS_TAG).put("queryStrategy", queryStrategy).put("servers", servers), hijack, rules, directResolverIps)
    }
}
```

- [ ] **Step 3: `ConfigBuilder.assemble` takes the plan**

Change the signature to `assemble(s: AppSettings, inbounds: JSONArray, outboundsIn: JSONArray, rules: JSONArray, geoAssets: Boolean, exitTag: String)`. Inside, before `val outbounds = applyFragments(outboundsIn)`:
```kotlin
        val plan = DnsPlan.build(s, geoAssets, exitTag)
        plan.hijackOutbound?.let { outboundsIn.put(it) }
        // The DNS rules go FIRST: the port-53 hijack must beat the private-IP
        // bypass (configBuilder.js: `rules = [...dnsPlan.rules, ...rules]`).
        val allRules = JSONArray()
        plan.rules.forEach { allRules.put(it) }
        for (i in 0 until rules.length()) allRules.put(rules.getJSONObject(i))
```
Replace `.put("dns", JSONObject().put("servers", JSONArray(s.dns))…)` with `.put("dns", plan.dns)` and `.put("routing", JSONObject().put("domainStrategy", "IPIfNonMatch").put("rules", rules))` with `.put("routing", JSONObject().put("domainStrategy", if (s.dnsManaged) "IPOnDemand" else "IPIfNonMatch").put("rules", allRules))` (desktop `routingStrategy()`).

Callers: `build()` → `assemble(s, …, rules, geoAssets, if (catchAllTag == "direct") "direct" else "proxy")`; `buildAdvanced()` → the desktop's exit choice: `defTag` unless it is `block`, then the first rule target that is neither `direct` nor `block` (a WireGuard split-tunnel check is not ported: Android has no `isSplitTunnelWg`; note it), else `direct` — pass that; `buildPool()` → `"direct"` is wrong; the desktop pool config uses its `primaryTag` as `exitTag` (`buildPoolConfig`, configBuilder.js ≈ 666) — pass `primaryTag`. `buildTestConfig` keeps its own minimal shape (no DNS plan), as on the desktop.

- [ ] **Step 4: `SingboxConfig.kt`**

Line 38: `val dnsServer = s.dnsRemote.firstOrNull { it.isNotBlank() } ?: s.dns.firstOrNull()?.takeIf { it.isNotBlank() } ?: "1.1.1.1"`.

- [ ] **Step 5: UI**

`MainActivity.kt` line ≈ 876 (the DNS field): rename its label to `"DNS خارجی — از داخل تونل (comma-separated)"`, bind it to `dnsRemote`; add a second `DraftField` for `dnsDirect` labelled `"DNS داخلی برای دور زدن ایران (comma-separated)"` and a `Switch` row `"DNS مدیریت‌شده (DoH از تونل، پاسخ به هر پورت ۵۳)"` bound to `dnsManaged`. Keep `dns` written in `save()` as `dnsRemote` too (`s.copy(dns = list, dnsRemote = list)`) so an older APK reading the same store still works.

- [ ] **Step 6: The VPN DNS — no change, and why**

`XrayVpnService.kt` hands `s.dns` to `builder.addDnsServer`. With the hijack in place every query the OS sends to that address enters the TUN, reaches the SOCKS inbound and is answered by `dns-out` — the address itself no longer matters, exactly as on the desktop under tun2socks. Leave it; add the comment.

- [ ] **Step 7: Push, wait for CI, commit message**

```bash
git add android/app/src/main/java/com/irnetfree/vpn/core/DnsPlan.kt android/app/src/main/java/com/irnetfree/vpn/core/Models.kt android/app/src/main/java/com/irnetfree/vpn/core/ConfigBuilder.kt android/app/src/main/java/com/irnetfree/vpn/core/SingboxConfig.kt android/app/src/main/java/com/irnetfree/vpn/ui/MainActivity.kt android/app/src/main/java/com/irnetfree/vpn/vpn/XrayVpnService.kt
git commit -m "Android resolves names the way the desktop does: DoH through the tunnel, an in-country resolver for bypass modes, every port-53 packet answered by the core"
git push -u origin feature/phase-E
```
Wait for `compile android` in Actions to be green. Fable review: compare `DnsPlan.build` against `buildDnsPlan` line by line and `assemble`'s rule order against configBuilder.js 566–569.

---

### Task E3: `advancedUseMode`

**Specification:** configBuilder.js 535–546 and the test in `tests/configBuilder.test.js` named for `advancedUseMode` (`grep -n advancedUseMode tests/configBuilder.test.js`): the order is ad-block, the user's rules, the private-IP bypass, **then the mode's bypass pair**, then the catch-all; `global`/`direct` contribute nothing.

- [ ] **Step 1: Setting**

`AppSettings`: `val advancedUseMode: Boolean = false,` (+ `toJson`/`fromJson` with default `false`).

- [ ] **Step 2: Builder**

`ConfigBuilder.buildAdvanced`, after `rules.put(fieldRule().put("ip", JSONArray(PRIVATE_IPS)).put("outboundTag", "direct"))` and before the catch-all:
```kotlin
        // `advancedUseMode`: the simple routing mode UNDER the user's rules — an
        // explicit corporate rule must still win over a country bypass.
        // configBuilder.js: modeBypassRules() = buildRoutingRules(mode) minus its
        // private-range head and its catch-all tail.
        if (s.advancedUseMode && geo) {
            when (s.routingMode) {
                "bypass-ir" -> {
                    rules.put(fieldRule().put("domain", JSONArray().put("geosite:category-ir").put("regexp:.*\\.ir$")).put("outboundTag", "direct"))
                    rules.put(fieldRule().put("ip", JSONArray().put("geoip:ir")).put("outboundTag", "direct"))
                }
                "bypass-cn" -> {
                    rules.put(fieldRule().put("domain", JSONArray().put("geosite:cn")).put("outboundTag", "direct"))
                    rules.put(fieldRule().put("ip", JSONArray().put("geoip:cn")).put("outboundTag", "direct"))
                }
            }
        }
```
(`DnsPlan.directRegion` from E1 already honours `advancedUseMode`, so the in-country resolver follows.)

- [ ] **Step 3: UI**

In the advanced-routing screen of `MainActivity.kt` (`grep -n "advancedRouting" android/app/src/main/java/com/irnetfree/vpn/ui/MainActivity.kt`), under the enable switch: a `Switch` row `"اعمال حالت ساده (دور زدن ایران/چین) زیرِ قانون‌ها"` bound to `advancedUseMode`.

- [ ] **Step 4: Push, CI, commit**

```bash
git add android/app/src/main/java/com/irnetfree/vpn/core/Models.kt android/app/src/main/java/com/irnetfree/vpn/core/ConfigBuilder.kt android/app/src/main/java/com/irnetfree/vpn/ui/MainActivity.kt
git commit -m "Android: advanced routing can apply the simple bypass mode under the user's rules, like the desktop"
git push
```
Fable review: rule order against the JS test.

---

### Task E2: `dns=` on WireGuard links

**Specification:** parser.js `splitDnsField` (485–491), `isResolverEntry`, `withWgDns` (503–508), `parseWireguard` (603), `buildShareLink` wireguard branch (926–938) and the tests in `tests/parser.test.js` that mention `dnsDomains`.

- [ ] **Step 1: `ServerConfig`**

`Models.kt`: add `val dns: List<String> = emptyList(), val dnsDomains: List<String> = emptyList()` after `engine`; `toJson`: `if (dns.isNotEmpty()) put("dns", JSONArray(dns)); if (dnsDomains.isNotEmpty()) put("dnsDomains", JSONArray(dnsDomains))`; `fromJson`: read both with `strList` (accepting a string too: split it with `LinkParser.splitDnsField` — the desktop's `repairWgDnsFields`).

- [ ] **Step 2: `LinkParser`**

```kotlin
    /** An IP, "ip:port" or "[v6]:port" — the forms DnsPlan takes as a resolver. */
    private fun isResolverEntry(v: String): Boolean {
        if (DnsPlan.resolverIp(v) != null && !v.contains("://")) return true
        return false
    }
    /** `DNS = 10.0.0.53, corp.local` → resolvers and search domains. Mirrors parser.js splitDnsField. */
    fun splitDnsField(value: String?): Pair<List<String>, List<String>> {
        val dns = ArrayList<String>(); val domains = ArrayList<String>()
        for (v in splitCommas(value)) { if (isResolverEntry(v)) dns.add(v) else domains.add(v.trimStart('.').lowercase()) }
        return dns to domains
    }
```
`parseWireguard`: build the `ServerConfig` with `dns`/`dnsDomains` from `splitDnsField(q["dns"])`. `buildShareLink`: replace `else -> s.raw` with a `"wireguard"` branch mirroring the JS field order:
```kotlin
            "wireguard" -> {
                val st = ob.optJSONObject("settings") ?: JSONObject()
                val peer = st.optJSONArray("peers")?.optJSONObject(0) ?: JSONObject()
                val q = LinkedHashMap<String, String>()
                q["publickey"] = peer.optString("publicKey")
                q["address"] = jarr(st.optJSONArray("address")).joinToString(",")
                q["allowedips"] = jarr(peer.optJSONArray("allowedIPs")).joinToString(",")
                q["presharedkey"] = peer.optString("preSharedKey")
                q["mtu"] = if (st.has("mtu")) st.optInt("mtu").toString() else ""
                q["reserved"] = jarr(st.optJSONArray("reserved")).joinToString(",")
                q["dns"] = (s.dns + s.dnsDomains).joinToString(",")
                "wireguard://${enc(st.optString("secretKey"))}@${s.address}:${s.port}?${qstr(q)}$name"
            }
            else -> s.raw
```
(`qstr` drops blank values, as the JS `qs` does; `jarr` exists at line 428.)

- [ ] **Step 3: Push, CI, commit**

```bash
git add android/app/src/main/java/com/irnetfree/vpn/core/Models.kt android/app/src/main/java/com/irnetfree/vpn/core/LinkParser.kt
git commit -m "Android keeps a WireGuard link's DNS and search domains and writes them back into the share link"
git push
```

---

## Phase gate

- `compile android` green on the branch for every commit; the release workflow's `Build Android APK` job green on a dry `workflow_dispatch`.
- Fable review of E1 (`DnsPlan.kt` vs `dnsBuilder.js`, `assemble` rule order) and E3 (rule order).
- The owner installs the CI APK on a device: with "bypass Iran" a `.ir` site resolves through the domestic resolver (Xray log at `debug` shows `dns-internal` → `178.22.122.100` direct) and everything else through DoH; `nslookup` from a terminal app on the phone gets an answer (the hijack).
- Merge `feature/phase-E`, tag v1.7.0.
