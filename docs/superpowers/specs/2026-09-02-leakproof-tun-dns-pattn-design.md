# IRNetFree 1.0 — leak-proof TUN, working geo-routing, dual Xray cores, standard finalmask

Date: 2026-09-02 · Scope: desktop (Windows first, macOS compatible), headless server. Android is phase 8.

## 1. Why

A code review plus a comparison against v2rayN / PattN / current Xray-core turned up four things the
app gets wrong today, all of which the owner has hit in practice:

1. **Modern Xray-core refuses plaintext configs.** `infra/conf/xray.go:validateOutboundTransportSecurity`
   rejects VLESS/Trojan with `security=none` to a public address ("vless without TLS or other encryption is
   prohibited unless the server address is a private IP or domain"). No escape hatch exists. The app always
   downloads the *latest* core, so every `vless+ws` CDN config on port 80 fails to start. patterniha's fork
   (`patterniha/Xray-core`, releases `v26.x` with the same asset names as upstream) only comments that
   check out. PattN itself is a v2rayN fork (GUI), not a core.
2. **fragment/noise moved into `finalmask`** (Xray ≥ 26.3.27). The standard shape is plural
   (`lengths: ["3-5","6-8"]`, `delays: ["10-20"]`, `maxSplit`); share links carry `fm=` (URL-encoded compact
   JSON) and `cs=` (cipherSuites); `fp=unsafe` is upstream. The app reads non-standard `finalMask=` /
   `cipherSuites=`, and `normalizeFinalMask()` rewrites plural→singular, which *breaks* the JSON on the very
   core the app downloads. The "Fake SNI decoy" is implemented with freedom `noises`, which only exist for
   UDP — it has no effect on a TLS/TCP connection.
3. **Geo routing silently degrades.** Xray's internal DNS uses plain UDP to `1.1.1.1` *through the proxy*.
   When the server drops UDP (common), resolution fails, `IPIfNonMatch` never yields an IP, `geoip:ir` never
   matches and everything goes through the proxy. In TUN mode the whole system's DNS takes the same path.
4. **TUN leaks.** Windows TUN adds only IPv4 split routes (IPv6 goes straight out), leaves the physical
   adapters' DNS untouched (Windows multihomed resolution asks the router/ISP in parallel), and switching
   servers under TUN keeps the *old* /32 bypass so the new server loops through the tunnel.

Plus: live stats are 0 in pool/advanced modes and cost a process spawn per second; the searchable
dropdowns squash their rows; WireGuard can only be added by form; no light theme.

## 2. Decisions already taken with the owner

- **Core selection is per config**: `xray` (official) or `xray-pattn` (patterniha fork). Both are
  downloaded/updated from Settings → Required files. Neither is hard-coded as "the" core.
- **TUN forwarding layer = sing-box** (`tun inbound → socks outbound → Xray/PattN`). sing-box does *no*
  proxying and no protocol translation; it replaces `tun2socks` + our hand-written route/DNS scripts.
  tun2socks stays as a selectable legacy backend for one release.
- **Windows is built and verified here; macOS code paths are written to the documented sing-box/Xray
  behaviour and unit-tested at the script/config level but not run** (no Mac available). Android sync is
  its own later phase.

## 3. Architecture after this work

```
                     ┌──────────────── desktop / headless (Node) ────────────────┐
apps ─► TUN ─► sing-box (tun→socks) ─► 127.0.0.1:socksPort ─► Xray | Xray-PattN ─► server
                 │  auto_route v4+v6                 │  routing (single/chain/pool/advanced)
                 │  route_exclude_address = server   │  built-in DNS (DoH) + `dns-out` hijack of :53
                 │  strict_route (guard = strict)    │  finalmask / fingerprint / cipherSuites
                 └── WFP filters die with the process└─ metrics.listen → /debug/vars (stats)
browsers/system proxy ─────────────────────────────►┘
```

Everything that decides *where traffic goes* stays in the Xray config built by `configBuilder.js`; the
sing-box config is ~25 lines and never changes with the user's proxy settings except the socks port and the
server IPs to exclude.

## 4. Phases

Each phase is one PR, independently shippable, with its own tests. Order is by value and dependency.

### Phase 0 — Quick fixes (findings from the review)

| Fix | Where |
|---|---|
| Searchable dropdown rows squash instead of scrolling: `.ss-list` and `.chain-pool` are `display:flex` + `max-height`; add `flex: 0 0 auto` to `.ss-item` / `.pool-item` | `styles.css` |
| Headless: `allowLan` default → `false`; `/rpc` and `/events` require `Origin`/`Referer` (when present) to match the server's own origin and `Host` to be the bound address — reject otherwise | `service.js`, `server.js` |
| Pool config reserves `apiPort` before adding entries; renderer `usedPoolPorts()` includes it | `configBuilder.js`, `app.js` |
| Headless `assetStatus()` reports `sing-box` and (later) `xray-pattn` — extract one `assetStatus(dirs)` helper shared by main and service | `service.js`, new `src/main/assets.js` |
| HTTP-proxy share link: `parseLink` accepts `http://` *only* when the URL is `[b64creds@]host:port[#name]` with no path and no query (v2rayN's shape); `smartImport` tries that first and only then treats an `http(s)://` line as a subscription URL. A bare `http://host:port` subscription with no path is therefore misread as a proxy — accepted, since real subscription URLs carry a path/token | `parser.js`, `app.js` |
| `saveSettings()` only submits the form fields when called from the Settings page (`{fromForm:true}`); other callers send just their partial | `app.js` |
| Custom-rules card hidden while advanced routing is on (they are not applied there) | `app.js`, `index.html` |
| `downloadFile()` closes and unlinks the temp file on non-200 | `downloader.js` |
| `socks5Connect()` buffers until 2 / 10 bytes before reading the reply | `netutils.js` |
| `routingGeoNote` shown only when `state.assets.geoip && geosite` is false | `app.js` |

The TUN server-switch bug and the stats bug are fixed structurally in phases 3 and 5.

### Phase 1 — Dual Xray cores

**engines.js** gains:

```js
'xray-pattn': { id:'xray-pattn', label:'Xray-PattN (patterniha)', format:'xray',
                exe:{ win32:'xray-pattn.exe', default:'xray-pattn' },
                repo:'patterniha/Xray-core', runArgs, testArgs /* same as xray */ }
```
and `xray` gets `repo:'XTLS/Xray-core'`. Both share the Xray JSON format, argv and geo assets.

**Downloader.getXray(engineId)** downloads `Xray-<os>-<arch>.zip` from the engine's repo and places the
binary under the engine's exe name; geo files from either archive are placed as today. Per-engine version is
read with `<exe> version` and shown in Settings (`Xray core (official) 26.9.1`, `Xray-PattN 26.9.1`).
Both rows have Download / Update. `assetStatus()` reports `xray`, `xray-pattn`, `sing-box` separately.

**Selection rules (main.js `buildActive`)**:
- New setting `defaultEngine: 'xray'` (Settings → core). A single config with `server.engine` set uses it;
  otherwise `defaultEngine`.
- Chain / pool / advanced: engine = `xray-pattn` if `defaultEngine` is `xray-pattn` **or** any server that
  participates in the plan has `engine:'xray-pattn'`; else `xray`. (PattN is a superset of official; a chain
  containing one plaintext hop must run on it.) `sing-box` as a *proxy* engine remains single-config only.
- Fallback: if the chosen engine's binary is missing → the other Xray engine (logged); if both missing →
  existing "core not found" error.

**Auto-recovery**: when `validate()` on `xray` fails and the message matches
`/without TLS.*prohibited/i`: if `xray-pattn` is installed, re-validate and run on it and log
`"official core rejects plaintext config — running on Xray-PattN"`; if not installed, surface a status error
whose text names the fix and the renderer shows a "Download Xray-PattN" action next to the toast.

Renderer: edit form engine select gets the third option; Required-files list gets the second Xray row.
Tests: engines registry, `buildActive` engine choice matrix (6 cases), downloader asset naming per engine.

### Phase 2 — DNS and routing that actually works

**Xray DNS section** (`buildDns(settings, plan)` in a new `src/main/dnsBuilder.js`):

```js
dns: {
  tag: 'dns-internal',
  queryStrategy: settings.ipv6 ? 'UseIP' : 'UseIPv4',
  servers: [
    // remote — through the proxy (routing sends 1.1.1.1 to the catch-all)
    'https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query',      // from settings.dnsRemote
    // direct — only in bypass modes; answers must be in-country
    { address: '178.22.122.100', domains: ['geosite:category-ir', 'regexp:.*\\.ir$'],
      expectedIPs: ['geoip:ir'], skipFallback: true }                // bypass-ir, from settings.dnsDirect
  ]
}
```
- `bypass-cn` uses `223.5.5.5` with `geosite:cn` / `geoip:cn`; `global` and `direct` have no direct server.
- Advanced routing: if any `domain` rule targets `direct` with value `geosite:category-ir` (or `geosite:cn`),
  the matching direct resolver is added exactly as in the bypass mode, so those domains resolve in-country
  too. Other geosite values get no direct resolver (no known `expectedIPs` for them).
- `direct` routing mode: remote servers are still used but everything is direct anyway.

**Hijack**: outbound `{ tag:'dns-out', protocol:'dns' }` and rule
`{ type:'field', port:'53', network:'tcp,udp', outboundTag:'dns-out' }` placed immediately after the `api`
rule in every plan (single/chain/advanced/pool). Any DNS packet that enters Xray — from SOCKS UDP clients or
from the TUN — is answered by the internal resolver. Plain UDP DNS never leaves through the proxy again.

**Settings** (all reconnect-relevant, added to `RECONNECT_KEYS` + i18n):
- `dnsRemote: ['https://1.1.1.1/dns-query','https://8.8.8.8/dns-query']` replaces `dns`; the existing
  `dns` array is migrated: known IPs map to their DoH URL (1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9,
  94.140.14.14, 208.67.222.222), anything else is kept as UDP.
- `dnsDirect: ['178.22.122.100','185.51.200.2']` (Shecan) with presets Shecan / Electro / Begzar / custom.
  Iranian presets are UDP; a user may enter a DoH URL. Under guard level *strict* (phase 3) UDP direct
  resolvers are dropped at build time with a logged warning, because strict_route blocks port 53 off-TUN;
  bypass still works through the remote DoH + `geoip:ir` on `IPIfNonMatch`.
- `ipv6: false` → also `freedom.domainStrategy = 'UseIPv4'`; `true` → `'UseIP'`.
- The old TUN-adapter DNS list is gone: the TUN adapter DNS is the tunnel peer address (phase 3).

**Verification of the owner's report** ("geo files missing although downloaded", "bypass Iran does nothing"):
before changing code, run the app on this machine with a real config the owner provides, reproduce both, and
record the actual cause in the PR. The DNS change above is expected to fix the second regardless.

Tests: dns section per routing mode × ipv6; hijack rule position in all four plans; migration of `dns` →
`dnsRemote`; strict-level UDP-direct dropping.

### Phase 3 — sing-box TUN and leak guard

**New `src/main/tunSingbox.js`** (implements the same `start(socksPort, entryAddrs, opts)/stop()/active`
surface as `TunManager`, selected by setting `tunBackend: 'sing-box' | 'tun2socks'`, default `sing-box`).

Generated config (`buildTunConfig({ socksPort, excludeIps, ipv6, strict, stack, mtu })`, pure, unit-tested):

```json
{ "log": { "level": "warn" },
  "inbounds": [{ "type": "tun", "tag": "tun-in", "interface_name": "IRNetFree",
     "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],   // v6 entry always present → v6 never bypasses
     "mtu": 1500, "auto_route": true, "strict_route": <strict>, "stack": "system",
     "route_exclude_address": ["<server ip>/32", …] }],
  "outbounds": [{ "type": "socks", "tag": "socks-out", "server": "127.0.0.1", "server_port": <socksPort>, "version": "5" }],
  "route": { "final": "socks-out", "auto_detect_interface": true } }
```
- sing-box's own WFP filters (strict_route) and routes are removed by sing-box on exit and die with the
  process on a crash — nothing persists.
- `excludeIps` = resolved entry addresses (existing `resolveServerIps`). On a server switch under TUN the
  sing-box process is restarted with the new list (~0.5 s, logged); the kill switch semantics of
  `reapplyConnection()` cover the gap.
- Windows: run elevated (already handled); `wintun.dll` must sit next to `sing-box.exe` in userData/bin
  (downloader already places both there). macOS: launch as root through the existing `runScriptPrivileged`
  helper with a pid file; teardown = `kill <pid>` (sing-box cleans its routes on SIGTERM).
- TUN adapter DNS: Windows `netsh interface ip set dnsservers name="IRNetFree" static 172.19.0.2 validate=no`
  (+ v6 `fdfe:dcba:9876::2`); macOS `networksetup -setdnsservers <service> 172.19.0.2`. Queries to the
  peer address enter the TUN and are hijacked by Xray (phase 2).

**Leak guard** (`src/main/leakGuard.js`, setting `leakGuard: 'off' | 'standard' | 'strict'`, default
`standard`; only meaningful in TUN mode — in proxy mode the setting is shown disabled with the note
"WebRTC/UDP and non-proxied apps bypass the system proxy; use TUN"):

| Level | Adds |
|---|---|
| off | TUN as above (v4+v6 default routes, TUN DNS = peer, Xray hijack). Already no plain-DNS and no v6 bypass. |
| standard | **Adapter DNS override**: every connected physical IPv4/IPv6 adapter's DNS set to the TUN peer for the session; the original (DHCP / static list) is recorded in `userData/tun-state.json` and restored on disconnect, quit, `process.on('exit')`, and at next launch if the file is still present (crash repair). Windows via one PowerShell script (`Get-DnsClientServerAddress` / `Set-DnsClientServerAddress`), macOS via `networksetup` for every service. |
| strict | + sing-box `strict_route:true` (WFP: block :53 off-TUN, block v6 off-TUN, permit only TUN + sing-box). + Windows allow-list: one `New-NetFirewallRule -Group IRNetFree -Direction Outbound -Action Block -InterfaceAlias <each physical adapter> -Protocol TCP/UDP -RemoteAddress <ranges>` where `<ranges>` = 0.0.0.0–255.255.255.255 minus {server entry IPs, 10/8, 172.16/12, 192.168/16, 169.254/16, 127/8, 224/4}. Removed with `Remove-NetFirewallRule -Group IRNetFree` on disconnect/quit/exit and at launch. macOS strict = strict_route only (no pf rules this round; documented). |

Range-complement computation is a pure function with tests. All Windows shell work for connect and for
teardown is batched into one PowerShell invocation each (today: 6–8 sequential spawns).

**Proxy mode option** `blockUdpInProxyMode: false`: when on, a `-Group IRNetFree` rule blocks outbound UDP
on physical adapters except :53 (stops WebRTC STUN leaking the real IP; breaks games/VoIP — said in the UI).

**Kill switch** stays as is (block-all on unexpected drop); the guard rules are independent of it.

**Legacy tun2socks backend**: `tunManager.js` is kept, gets the v6 split routes and the same adapter-DNS
override, and is chosen only when `tunBackend:'tun2socks'` or sing-box is not installed (logged). It is
removed in the release after next.

Tests: `buildTunConfig` matrix (ipv6 × strict × excludeIps); range complement; PowerShell/`networksetup`
script generation snapshots; `tun-state.json` round-trip and crash-repair path. Manual (Windows, each
level): browserleaks.com/webrtc, ipleak.net (DNS + IPv6), `nslookup` against the router IP must fail under
strict, switching servers under TUN keeps traffic flowing.

### Phase 4 — Standard finalmask / fingerprint / cipherSuites

**Parser** (`parser.js`, mirrored later in `LinkParser.kt`):
- Read `fm` (and legacy `finalMask`) → `streamSettings.finalmask` **verbatim** (JSON-parsed, not
  rewritten); invalid JSON → link error naming the field. `normalizeFinalMask` is deleted.
- Read `cs` (and legacy `cipherSuites`) → `tlsSettings.cipherSuites`; `fp` accepted as any string
  (`unsafe` included). vmess JSON: `fm`/`finalmask`, `cs`/`cipherSuites`.
- `buildShareLink` emits `fm=`, `cs=`, `fp=`; never the legacy names.
- `_fakesni` is dropped (parsed and discarded on load with a one-time log line). `_fragment` / `_noise`
  markers stay as the app's own *simple* controls.

**Config builder** (`applyFragments` → `applyDpi`):
- Core version ≥ 26.3.27 (`xray.version()` parsed, per engine): simple markers become masks *on the
  outbound that touches the wire*:
  `finalmask.tcp += [{ type:'fragment', settings:{ packets, lengths:[length], delays:[interval], maxSplit:'3-6' } }]`,
  `finalmask.udp += [{ type:'noise', settings:{ noise:[{ rand:…, delay:… }] } }]` (presets mapped to the
  new shape). A user-supplied `fm` is kept as-is and the simple markers are *not* merged into it (the UI
  shows one or the other).
- Older core: the existing freedom-dialer path (`dpi-*` outbounds) is used unchanged.
- Chains: masks only on hop 0 (as today); pool/advanced: per-outbound, deduplicated by content.

**Edit form**: the "SNI spoofing" block is replaced by one *DPI evasion* section: Fingerprint (all upstream
values + `unsafe`), cipherSuites, Fragment (off / default `tlshello,100-200,10-20` / custom
`packets,lengths,delays,maxSplit`), Noise (UDP presets), and a collapsed **finalmask JSON** editor that,
when non-empty, overrides the two simple controls. Copy/QR carry everything via `fm`/`cs`/`fp`.

Tests: parser round-trips for `fm`/`cs`/`fp=unsafe` (vless, trojan, vmess), legacy-name acceptance,
finalmask emitted verbatim, mask generation for both core versions, chain hop-0 rule, no `_fakesni` output.

### Phase 5 — Stats via `metrics`

`configBuilder` emits `metrics: { listen: '127.0.0.1:<apiPort>' }` and drops the `api` inbound, the
`api` routing rule and `stats/policy` blocks. `StatsPoller` does one `GET /debug/vars` per second and sums
`stats.outbound[*].uplink/downlink` for every tag except `direct`, `block`, `dns-out`, `dpi-*`. This fixes
the 0 B/s display in pool/advanced modes and removes the per-second process spawn. Test: parser over a
fixture `/debug/vars` body.

### Phase 6 — WireGuard `.conf` import

`parseWireguardConf(text)` (INI: `[Interface]` PrivateKey/Address/DNS/MTU, `[Peer]`
PublicKey/PresharedKey/AllowedIPs/Endpoint/PersistentKeepalive) → `makeWireguardServer` fields. Hooked into
`parseMany` (a block starting with `[Interface]` is one config), `smartImport`, global paste, a "Choose
.conf file" button (Electron open dialog; headless: file input) and a paste box in the WG form. Export:
`buildShareLink` produces a real `wireguard://<pk>@host:port?publickey=&address=&presharedkey=&mtu=&reserved=#name`.
Tests: the owner's screenshot config, missing fields, two peers (first wins, logged).

### Phase 7 — Light theme

`theme: 'dark' | 'light' | 'system'` (setting exists, unused). `[data-theme=light]` overrides the `:root`
variables (bg/panel/border/text/muted; accent colours unchanged), applied at startup and on change; `system`
follows `nativeTheme` via a new preload event. Titlebar tint classes and `BrowserWindow.backgroundColor`
follow. Verified with a screenshot of every page in both themes.

### Phase 8 — Android sync (later)

`LinkParser.kt` (fm/cs, WG conf, drop fakesni), `ConfigBuilder.kt` (custom-rule order, dns section,
hijack rule, geoAssets flag), `MainActivity.kt` (DNS field and rule-value field losing focus/commas),
`XrayVpnService.kt` (geo assets). Not in this round.

## 5. Settings added / changed

| Key | Default | Reconnect? | Phase |
|---|---|---|---|
| `defaultEngine` | `'xray'` | yes | 1 |
| `dnsRemote` (replaces `dns`) | DoH 1.1.1.1 + 8.8.8.8 | yes | 2 |
| `dnsDirect` | Shecan UDP | yes | 2 |
| `ipv6` | `false` | yes | 2 |
| `tunBackend` | `'sing-box'` | yes | 3 |
| `leakGuard` | `'standard'` | yes | 3 |
| `blockUdpInProxyMode` | `false` | yes | 3 |
| `theme` | `'dark'` | no | 7 |

Every "yes" goes into `RECONNECT_KEYS` with `set.<key>` strings in both languages (the existing test
enforces this).

## 6. Compatibility and migration

- Stored servers: `_fakesni` stripped on load; `finalmask` objects saved by the old normalizer are re-read
  as-is (they carry singular keys and will be rejected by a modern core — the edit form shows the raw JSON so
  the user can re-paste the link; the auto-recovery log line explains).
- `dns` → `dnsRemote` migrated once in `getSettings()`; old key removed from the store.
- Headless: identical behaviour; sing-box TUN needs root there too (documented in README §CLI).
- Android keeps building; it only lags on the parser param names until phase 8.

## 7. Verification plan (owner-facing)

1. Windows, real config from the owner: reproduce the two reported failures before phase 2; after phase 2
   `bypass-ir` sends `digikala.com` direct and `google.com` via proxy (Xray log at `info`).
2. After phase 3 at each guard level: browserleaks WebRTC shows only the exit IP; ipleak.net shows no ISP
   DNS and no IPv6 (or the exit's v6 when `ipv6` is on); switching servers under TUN keeps browsing working.
3. After phase 4: a PattN/v2rayN share link with `fm=`/`cs=`/`fp=unsafe` imports, connects on Xray-PattN,
   exports byte-identical `fm`.
4. After phase 5: pool mode shows live speeds.
5. Resource check: Task Manager CPU of `IRNetFree` + cores idle ≤ 1 % (no per-second spawns).

## 8. Risks

- **macOS unverified.** sing-box auto_route on darwin is the same code every sing-box GUI uses, which is
  the reason to adopt it; still, the first Mac run may need one fix. Mitigation: legacy backend selectable.
- **strict_route blocks UDP :53 for Xray's direct resolver.** Handled by dropping UDP direct resolvers at
  strict level (phase 2 rule).
- **Core version detection**: `xray version` output format changes → default to the finalmask path and
  fall back to freedom-dialer only when the core rejects the config (validate() error contains `finalmask`).
- **Patterniha fork trust**: same asset names as upstream; the app shows which engine a config ran on in
  the status line so the owner always knows.
