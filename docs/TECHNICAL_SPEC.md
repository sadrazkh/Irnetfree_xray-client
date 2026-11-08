Last verified: 2026-11-08
Scope: data shapes, surfaces, generated config conventions and version gates in `src/`, `relay/`, `openwrt/`, `android/app/src/main/.../core`, at commit 3e5b74d. Read only; behaviour read from code, not observed at runtime.

# Technical specification

Labels: **[V]** Verified (evidence named), **[A]** Assumption, **[R]** Recommendation. Evidence is the file and symbol in the right-hand column of each table; those rows are [V] unless tagged otherwise.

## 1. Persistent data

### Desktop and headless

Data dir: Electron `userData` (`dataDir` in `main.js`); headless `IRNETFREE_DATA`, else `APPDATA\IRNetFree` or `$XDG_DATA_HOME/irnetfree`, or `--data-dir` (`defaultDataDir`, `parseArgs`).

| File | Holds | Written by | Evidence |
|---|---|---|---|
| `store.json` | Servers, subscriptions, settings, chains, groups, pool, routing profiles, lanUsers, selection | `Store`: atomic tmp + fsync + rename, bad file quarantined as `.corrupt-<ts>` | `src/main/store.js`; `store = new Store` |
| `usage.json` | Traffic per config, `multiWanUsage` | Same class, its own file so counters do not rewrite the server list | comment at `usage` in `main.js` |
| `site-usage.json` | Traffic by site, router | `siteStore` | `service.js` |
| `tun-state.json` | Leak guard's record of what to restore after a crash | Written before the first adapter is touched | `leakGuard.js` header, `STATE_FILE` |
| `proxy-journal.json` (`proxy-journal-server.json` headless) | System proxy as it was | `useProxyJournal` | `main.js`, `service.js` |
| `remote.json` (mode 0600) | Relay and cloudflared settings, device token; never in a backup | `src/server/remote/api.js` | header of `api.js` |
| `token`, `killswitch.nft` | Router UI token; kill switch ruleset replayed at boot | `tokenFromFile`; `killSwitchOpenwrt.js` | `server.js`, `irnetfree-ks.init` |

`store.json` keys [V: `store.get`/`store.set` in `main.js`, `service.js`]: `servers`, `subscriptions`, `settings`, `chains`, `chain` (legacy), `groups`, `pool`, `routingProfiles`, `lanUsers`, `activeServerId`, `lastServerId`, `selectedServerId`, `procIpCache`, `muxProbes`, `multiWanTests`, `assetsCheckedAt`, `xrayPath`, and on the router `connectIntent`, `routerDefaultsApplied`, `routerRepair`, `remote`.

Android uses one `SharedPreferences` file `irnetfree` (`core/Store.kt` `Store`).

### Record shapes

| Record | Shape | Evidence |
|---|---|---|
| Server | `{ id, name, protocol, address, port, raw, outbound, subId?, engine?, certPin?, certPinAt?, mux?, source?, json?, extraOutbounds?, jsonMode?, sniSpoof?, sniSpoofNames?, sniSpoofMethod?, warp? }`; `outbound` is an Xray-shaped outbound | `parser.js` `mkServer`; `jsonImport.js` header; `sniSpoof.js` header; Kotlin twin `core/Models.kt` `ServerConfig` |
| Subscription | `{ id, name, url, lastUpdated, serverCount, autoUpdate }` | `subscription.js` header |
| Chain | `{ id, name, members: [serverId or groupId] }` | `app.js` `state.chains` comment; `main.js` `buildPlan` |
| Group | `{ id: 'grp-…', name, strategy: roundRobin, leastPing, random, members: [{ id, address?, port? }] }`; a member is never a group | `groups.js` header, `normalizeMember` |
| Pool entry | `{ id, name, target, socksPort, httpPort, enabled }` | `app.js` `state.pool` comment; `buildPlan` |
| Routing profile | `{ id, name, rules: [{ type, value, target, via? }], def, defVia, useMode, base }` | `routingProfiles.js` header |
| LAN user | `{ id, username, password, name, target, quotaGb, quotaPeriod, limits, routing, schedule, speed, expiresAt, maxDevices, enabled, remember, priority, filter, voucher, … }` | `src/modules/lanUsers/model.js` header |

Backup format: `exportBundle` / `importBundle` in `backup.js`. Export is a plain copy; import merges by id and drops anything failing `validId` or `PROTOCOLS`.

### Target ids

`'direct'`, `'block'`, a server id, a group id (`grp-…`), `chain:<id>`, legacy `chain`, and in a profile `base`. Selections add `__chain__`, `__pool__`, `__advanced__`, `__advanced__:<profileId>` [V: `buildPlan`, `routingProfiles.js`].

## 2. Connection plan

`buildPlan(serverId, settings)` returns `{ plan, label, entryAddrs }` [V: `main.js`]:

| `plan.mode` | Fields |
|---|---|
| `single` | `server` |
| `chain` | `chain`, `name` |
| `pool` | `entries`, `primary`, `serversById`, `chainsById`, `chain` |
| `advanced` | `profileId`, `serversById`, `chainsById`, `chain`, `rules`, `def`, `defVia`, `base`, `useMode` |

## 3. Engine selection

Registry: `ENGINES` in `engines.js`: `xray`, `xray-pattn` (format `xray`), `sing-box` (format `sing-box`).

`chooseEngine` in `engineChoice.js`, first match wins for a single non-group server:

1. MASQUE: `xray-pattn` if the server asks, else the default Xray engine.
2. TUIC or AnyTLS: `sing-box`.
3. SNI spoof extension on and record asks: `sing-box`.
4. The record's `engine`; else `sing-box` for a Hysteria2 with no certificate check possible (`needsInsecureCore`); else the default.

Chain, pool, advanced and group plans: `xray-pattn` if any server asks, else the default; never sing-box.

`XrayManager.validateWithFallback` then runs the core's `-test` and may move the run to another installed core or refuse (section 7). The effective engine decides the config format (`buildActive`). Android applies the same rules plus `needsPattn` (`core/EngineChoice.kt`).

## 4. Generated Xray config: tags

| Tag | Meaning | Evidence |
|---|---|---|
| `socks-in`, `http-in` | Local inbounds, SOCKS `noauth` | `localInbounds` |
| `proxy`, `direct`, `block` | Exit, freedom, blackhole | `buildConfig`, `BLACKHOLE` |
| `dns-out`, `dns-internal` | Port-53 hijack, DNS module tag | `dnsBuilder.js` |
| `<T>~gm<i>`, `<T>~bal`, `<T>~fb` | Group members, balancer, fallback | `expandGroups` |
| `dpi-<n>` | Anti-DPI dialer | `applyFragments` |
| `chain-relay`, `chain-relay~<hop>` | Loopback SOCKS relay for hop dials | `RELAY_IN`, `relayHopDials` |
| `dp-direct` | Direct ports | `directPorts.js` `OUT_TAG` |
| `lu-socks`, `lu-http`, `lu-out-*`, `lu-d-<id>`, `lu-tp-<n>`, `lu-ss-*` | LAN users | `src/modules/lanUsers/xray.js` |
| `pa-<n>`, `pa-out-*` | Per-app inbounds, targets | `tunAppTargets.js` |

Non-enumerable extras on the built config: `groupTags`, `multiWanSplit` (`withGroupTags`). Stats come from `metrics` over `/debug/vars` on `apiPort` (`stats.js`). `config.api` exists only with a group, used for `xray api rmo|ado` (`groupLive.js`).

Sing-box format (`buildSingboxConfig`): one server outbound, a `direct`, SOCKS and HTTP inbounds, DNS via direct, `route.final: 'proxy'`. It carries **no routing rules** (no routing mode, custom rules or advanced rules) [V: the function body; no `rules` in the file].

## 5. Surfaces

### IPC (desktop)

Channels in `registerIpc`, exposed by `preload.js` [V: grep of `ipcMain.handle`/`on`, 93 registrations]: `app:*`, `servers:*`, `wg:*`, `chain:*`, `chains:*`, `groups:*`, `pool:*`, `routing:*`, `selection:set`, `links:take`, `subs:*`, `connect`, `disconnect`, `settings:*`, `modules:*`, `multiwan:*`, `conns:*`, `sites:*`, `ping:*`, `ip:check`, `win:*`, `open:*`, `autostart:*`, `assets:*`, `cores:*`, `xray:*`, `proc:*`, `net:*`, `killswitch:*`, `usage:*`, `backup:*`, `vpn:reconnect`, `guard:release`, `native:service`, `network:repair`, `diagnostics:connection`, and `lanusers:*` from `src/modules/lanUsers/ipc.js`.

Events to the window (`preload.js` `on*`): `log`, `status`, `route-health`, `xray-status`, `stats`, `usage`, `subs-updated`, `asset-progress`, `killswitch`, `system-theme`, `store-error`, `deep-link`.

The headless `handlers` table is the same set with these differences [V: comparing the two channel lists]: desktop-only `links:take`, `autostart:*`; headless-only `net:lanDevices`, `remote:bypass`; `win:*` are no-ops.

### HTTP (headless, `server.js`)

| Route | Auth | Notes |
|---|---|---|
| `POST /rpc` `{channel, arg}` | Token (query or `x-irnetfree-token`), Origin check | Answers `{result}` or `{error}` |
| `GET /events` | Same | SSE; first event `conn:snapshot` |
| `POST /luci/<method>` `{token, arg}` | Loopback peer + token | Errors as HTTP 200 `{error}` because `uclient-fetch` drops non-2xx bodies |
| `GET /`, `/index.html` | Token | Injects `web-api.js` |
| `GET /web-api.js`, `/assets/*`, renderer files | None | Static |

Guards: `hostAllowed` (DNS rebinding) and `originAllowed` (`guard.js`). No token on a loopback bind unless given; a non-loopback bind auto-creates one (`server.js`).

LuCI methods (`luciApi.js`): `status`, `version`, `traffic`, `configs`, `connect`, `select`, `disconnect`, `reconnect`, `test`, `subs_update`, `settings_get`, `settings_set`, `devices`, `log`, `diagnostics`, and `remote_get`, `remote_set`, `remote_status`, `cloudflared_install` delegated to `remote/api.js`.

### Relay

`/_relay/login`, `/_relay/logout`, `/_relay/`, `/_relay/routers`, `/_relay/health`, `/_relay/agent` (WebSocket); everything else is carried to the selected router (`relay/server.js`). Frame: `[type u8][stream u32 BE][payload]`, types `HELLO`, `REQ_HEAD`, `REQ_BODY`, `REQ_END`, `RES_HEAD`, `RES_BODY`, `RES_END`, `CANCEL` (`frames.js`). `RELAY_PASSWORD` must be 12 characters or more (`auth.js`).

## 6. Links and import

| Form | Handled by |
|---|---|
| `vless, vmess, trojan, ss, socks, socks5, wireguard, wg, hysteria2, hy2, tuic, anytls` links, plus HTTP proxy links | `parser.js` `SUPPORTED`, `parseLink`, `parseMany` |
| WireGuard `.conf` text | `parseWireguardConf` |
| Xray JSON, sing-box JSON (Clash YAML refused by name) | `jsonImport.js` header |
| `irnetfree://routing/<base64url(deflate-raw(JSON))>` | `routeShare.js`, `RouteShare.kt`; max 65,536 bytes |
| `irnetfree://import/...`, `irnetfree://import?url=&name=` | `deepLink.js`, `DeepLink.kt`; classifies only, the window asks before writing, never connects |
| Unknown link keys | `unreadLinkKeys`, logged by `sayUnread` |

Subscription refresh keeps identity across rotating panels: `serverIdentity` and related functions in `subscription.js`; Kotlin twin `core/SubRefresh.kt`.

## 7. Version gates

| Gate | Needs | Constant / place |
|---|---|---|
| `dialMode` OOB, `merge` mask | Xray-PattN 26.10.27 | `PATTN_OOB_SINCE` |
| `finalmask` | official 26.3.27 | `FINALMASK_SINCE` |
| ECH | official 25.8.3 | `ECH_SINCE` |
| MASQUE / WARP over MASQUE | 26.9.30 / 26.10.10 | `MASQUE_SINCE`, `MASQUE_WARP_SINCE` |
| ECH outbound | 26.10.10 | `ECH_OUTBOUND_SINCE` |
| Group on a loopback | 26.4.25, else warned | `GROUP_LOOPBACK_SINCE` |
| SNI spoof | sing-box 1.14 | `SINGBOX_SPOOF_SINCE` |
| TUN `dns_mode: disabled` | sing-box 1.14 | `DNS_MODE_SINCE` in `tunSingbox.js` |
| `record_fragment` | sing-box 1.12 | `RECORD_FRAGMENT_SINCE` |
| mKCP, Hysteria port hopping, XDNS rewrites | per core version | `coreCompat.js` constants |

Pins [V]: `SUGGESTED` in `coreVersions.js`. Android, in `android/scripts/fetch-libs.sh`: libv2ray `v26.10.31`, Xray-PattN `v26.11.1`, sing-box `v1.13.14`; hev 2.16.0 from `release.yml`. The geo data tag is pinned there too.

## 8. Settings

`DEFAULT_SETTINGS` exists separately in `main.js` and `service.js`. Headless differs: `systemProxy: false`; on a router `ROUTER_FORCED` holds `dnsManaged` and `tunMode` true. Defaults worth knowing [V]:

| Key | Default |
|---|---|
| `socksPort`, `httpPort`, `apiPort` | 30808, 30809, 30085 |
| `routingMode` | `global` |
| `tunMode` / `tunBackend` / `leakGuard` | `true` / `sing-box` / `standard` |
| `mux` | `off` |
| `killSwitch` | `false` |
| `autoUpdateAssets` | `geo` |
| `defaultEngine` | `xray` |
| `modules` | `{}` (every extension off) |
| `uiMode` | `''`: `simple`, or `advanced` when chains, groups, a pool or routing rules exist (`defaultUiMode` in `app.js`) |

`RECONNECT_KEYS` in `settingsMeta.js` lists what is baked into a running config: changing one sets `pendingReconnect` rather than taking effect. Other keys are read live.

## 9. Security controls

| Control | Evidence |
|---|---|
| Renderer CSP, `script-src 'self'` | `src/renderer/index.html` |
| Window navigation locked to the app page; web links to the browser | `createWindow`, `urlGuard.js` |
| App update verified against `SHA256SUMS-<os>.txt` from the release | `appUpdate.js`; `app:downloadUpdate` |
| APK signing certificate checked in CI | `release.yml` step "Verify the APK's certificate" |
| Android local inbounds have per-session credentials | `core/LocalAuth.kt` |
| Native macOS bridge takes commands, never shell text or core configs | `nativeMacTun.js` `runNative` |
| Backup input held to known shapes | `backup.js` |
| Tokens not logged; diagnostics allow-listed and redacted | `connectionDiagnostics.js`, `service.js` `redact` |

Gaps are in [KNOWN_ISSUES_AND_TECH_DEBT.md](KNOWN_ISSUES_AND_TECH_DEBT.md).

## 10. Test architecture

| Layer | What | Where |
|---|---|---|
| Unit, Node core modules only | `npm test`, guarded by `tests/noNetwork.preload.js` against touching the machine's network | `tests/*.test.js` |
| Every JS file must parse | `tests/syntax.test.js` | |
| Real cores accept every config | `scripts/validate-configs.js` in CI job `cores` | |
| Behaviour on real cores | 18 of the 20 probe scripts (`probe-*`, `tun-dns-probe`) run in CI; `probe-dns-leak.js` and `probe-wg-chain.js` do not | `test.yml` |
| Network namespaces, some with a real TUN (`tun-dns-probe.js`, `probe-router-site-usage.js`, `probe-lan-portal.js`) | Also `probe-sni-spoof.js`, `probe-multiwan.js`, `probe-lan-shape.js` | `test.yml` jobs |
| OpenWrt in QEMU | `openwrt/ci/qemu-smoke.js`, `guest-smoke.sh`; releases 24.10.2 and 23.05.5 | `test.yml` job `openwrt` |
| Android JVM tests | Pure core, compiled in CI only | `android/app/src/test`, job `android` |
| Native macOS | Swift validation and packaging | `native-macos.yml` |
