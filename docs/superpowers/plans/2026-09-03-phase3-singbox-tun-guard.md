# Phase 3 — sing-box TUN, leak guard, direct-outbound binding, certificate pinning

Branch: `feature/phase3-tun-guard` (base: `main` at v0.13.0). Models: T0/T1/T2/T3a/T3b/T5 Fable,
T4/T6 Opus; Fable reviews the branch before merge. Tag at the end: v0.14.0.

Design: `docs/superpowers/specs/2026-09-02-leakproof-tun-dns-pattn-design.md` §Phase 3 and §4b
(macOS parity). This plan refines it with what was measured on this machine on 2026-09-03.

## Facts established before planning (real binaries, this machine)

| Fact | Evidence |
|---|---|
| `sockopt.interface: "Wi-Fi"` on a `freedom` outbound binds the dial to the physical NIC on Windows, on both cores (26.3.27 and PattN 26.9.1) | bound dial left with source `192.168.8.63` and the ISP's public IP while the default route was the owner's TUN; unbound left via `10.255.0.2` and the VPN exit |
| sing-box 1.13.14 (installed in userData/bin) accepts the TUN shape below (`sing-box check`), with and without `strict_route` | probe |
| Under the tun2socks backend, `direct` re-enters the tunnel via the `/1` split routes (phase-2 review H1) | design note |
| Both current cores REJECT `tlsSettings.allowInsecure: true` ("removed and migrated to pinnedPeerCertSha256"; PattN also names `verifyPeerCertByName`) | `-test` on both |
| `pinnedPeerCertSha256` is a **string**, hex, case-insensitive, `:` separators tolerated, several joined by `,`; = SHA-256 of the leaf certificate DER | `-test` on both + docs |
| `nonIPQuery` is deprecated on main/PattN ("will be removed soon, migrated to rules"); the `rules` form `[{ action:'return', rCode:5, qType:'0,2-27,29-65535' }]` is accepted by BOTH cores; mixing both is rejected by PattN | `-test` on both, clean startup on PattN |
| WireGuard through a chain works identically on both cores (SOCKS hop, TLS VLESS hop with mux UDP, fragment dialer, hostname endpoint) | probes; no PattN-specific defect found |
| Windows multihomed DNS: the physical adapters keep their resolvers under phase 2; only the TUN adapter's DNS is ours | tunManager.js |

The sing-box TUN config that passed `check`:

```json
{ "log": { "level": "warn", "timestamp": false },
  "inbounds": [{ "type": "tun", "tag": "tun-in", "interface_name": "IRNetFree",
     "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"], "mtu": 1500,
     "auto_route": true, "strict_route": false, "stack": "system",
     "route_exclude_address": ["<bypass ip>/32", "..."] }],
  "outbounds": [{ "type": "socks", "tag": "socks-out", "server": "127.0.0.1", "server_port": <socksPort>, "version": "5" }],
  "route": { "final": "socks-out", "auto_detect_interface": true } }
```

TUN adapter DNS = `172.19.0.2` (v4) and `fdfe:dcba:9876::2` (v6, only when `ipv6`): on-link, enters the
TUN, reaches Xray's port-53 hijack. `route_exclude_address` = resolved server entry IPs + `resolverBypassIps`
(phase 2b) — same list tun2socks gets as `/32` routes.

## Settings (all in `RECONNECT_KEYS`, i18n `set.<key>` in both languages)

| Key | Default | Meaning |
|---|---|---|
| `tunBackend` | `'sing-box'` | `'sing-box'` \| `'tun2socks'`; sing-box is used when installed, else tun2socks with a log line |
| `leakGuard` | `'standard'` | `'off'` \| `'standard'` \| `'strict'`; TUN mode only (disabled note in proxy mode) |
| `blockUdpInProxyMode` | `false` | proxy mode only: block outbound UDP except :53 on physical adapters (stops WebRTC STUN) |

`killSwitch` is unchanged.

---

### T0 (Fable, done by the lead before dispatch): dns-out `rules`, validate env

- `dnsBuilder.js`: hijack outbound `settings: { rules: [{ action: 'return', rCode: 5, qType: '0,2-27,29-65535' }] }`
  instead of `nonIPQuery: 'reject'` (REFUSED for every non-A/AAAA query, same intent, no deprecation
  warning on main). Tests + validate on both cores (`IRNF_XRAY_EXE`).
- `scripts/validate-configs.js` honours `IRNF_XRAY_EXE` (already patched, uncommitted) — commit it.

### T1 (Fable, ★★★★): the sing-box TUN backend

**Files:** `src/main/tunSingbox.js` (new), `src/main/tunPlatform.js` (new: helpers moved out of
`tunManager.js` — `run`, `delay`, `getDefaultGatewayWin`, `getTunIfIndex`-style adapter wait,
`resolveServerIps`, `runScriptPrivileged`, `getDefaultRouteMac`, `serviceForDeviceMac`, `getServiceDnsMac`,
plus new `physicalInterface()` → `{ name, ifIndex, gateway }` on Windows via
`(Get-NetAdapter -InterfaceIndex <idx>).Name`, `{ name: device, gateway }` on macOS from `route -n get
default`), `src/main/tunManager.js` (uses the shared helpers; behaviour unchanged; `isOwnTunInterface`
also matches `IRNetFree`), `tests/tunSingbox.test.js`, `scripts/validate-configs.js` (+ `IRNF_SINGBOX_EXE`
→ `sing-box check` on every generated TUN config), `tests/tunManager.test.js` if needed for the move.

**Surface** (same as `TunManager` so main/service swap them freely):
`start(socksPort, bypassAddrs, dnsServers, { ipv6, strict })`, `stop()`, `active`, `isAvailable()`,
`isElevated()`, `cleanupSync()`, `lang`, plus `dnsPeer` (`'172.19.0.2'`), `dnsPeer6`, `interfaceName`
(`'IRNetFree'`), `physicalInterface()`.

- `buildTunConfig({ socksPort, excludeIps, ipv6, strict, stack = 'system', mtu = 1500 })` pure: the
  shape above; without `ipv6` the v6 address stays (design: a v6 entry always present so v6 never
  bypasses — the OS gets a v6 default through the TUN and Xray answers no AAAA when `ipv6:false`).
- **Windows**: `isAvailable()` = sing-box.exe + wintun.dll in the same dir (sing-box loads wintun from
  its own directory). Start: resolve bypass IPs (existing helper), write config to a temp dir, spawn
  `sing-box run -c <cfg>` (`windowsHide`), watch stdout/stderr into the app log, 400 ms fail-fast,
  wait for the adapter `IRNetFree` to be Up (existing wait helper), set adapter DNS with `netsh`
  (`validate=no`; v6 with `netsh interface ipv6 set dnsservers` when `ipv6`). sing-box lays the routes
  (`auto_route`). Stop: kill the process (taskkill /t /f) — sing-box removes routes and WFP filters on
  exit; `cleanupSync` = taskkill only. On `exit` of the process while active → mark inactive and log
  (the recovery path already treats a dead TUN as a drop).
- **macOS (blind — reason it through, quote each command in the report)**: launch as root through
  `runScriptPrivileged` with the same `trap '' HUP` + backgrounding + pid file pattern as `startMac`,
  wait for a NEW `utun` (same snapshot loop), DNS via `networksetup -setdnsservers <service> 172.19.0.2`
  (saved and restored like today), teardown script `kill <pid>` (sing-box cleans its routes on SIGTERM)
  + DNS restore; `cleanupSync` only when root. sing-box's binary goes through the existing
  quarantine-strip/codesign step. Log tail like today.
- Linux: same as macOS minus `networksetup` (best effort, as today).
- Tests: `buildTunConfig` matrix (ipv6 × strict × excludeIps), the macOS setup/teardown script text
  (snapshot: pid file, utun wait, DNS line, kill), Windows argv and the DNS `netsh` calls with a spawn
  stub (the `xrayManager.test.js` pattern), `isOwnTunInterface('IRNetFree') === true`.
- Manual on this machine is NOT possible (the owner's own app holds the TUN). The validate run with
  `IRNF_SINGBOX_EXE=%APPDATA%/IRNetFree/bin/sing-box.exe` is the check.

### T2 (Fable, ★★★★): backend selection, direct-outbound binding, wiring in both mirrors

**Files:** `src/main/main.js`, `src/server/service.js`, `src/main/configBuilder.js`,
`src/main/assets.js`, `src/main/settingsMeta.js`, `tests/configBuilder.test.js`, `tests/settingsMeta.test.js`,
`tests/assets.test.js`, `scripts/validate-configs.js`.

- `makeTun(settings, assets)` in both mirrors: `'sing-box'` when `tunBackend !== 'tun2socks'` and
  sing-box (+ wintun on Windows) is installed, else tun2socks with one log line naming why. Built at
  connect time (the setting is reconnect-relevant), kept on `tun` for stop/recovery.
- `adapterDnsServers(settings, hijacks ? tun.dnsPeer : null)`; the "TUN needs tun2socks" messages become
  "TUN needs sing-box (or tun2socks) …".
- **Direct binding (the H1 fix)**: when `tunMode` is on, before `buildActive`, `await tun.physicalInterface()`
  → `settings.directInterface = name`. `configBuilder`: when `s.directInterface` is set, every outbound that
  dials the network itself — no `sockopt.dialerProxy`, protocol not `dns`/`blackhole` — gets
  `streamSettings.sockopt.interface = name` (freedom `direct`, the `dpi-*` fragment dialers, single
  proxies, the first hop of a chain, a directly-dialled WireGuard). `buildTestConfig` untouched. Tests pin
  each case, and that `buildConfig` without the key emits no `sockopt.interface` anywhere (byte-stable
  goldens). validate: one shape with `directInterface: 'Wi-Fi'` on both cores. The value is re-derived on
  every (re)connect, so the network-change recovery keeps it right.
- `assets.js`: `tunReady` = (sing-box && (win ? wintun : true)) || (tun2socks && (win ? wintun : true));
  the renderer reads that instead of `tun2socks`.
- `RECONNECT_KEYS` += `tunBackend`, `leakGuard`, `blockUdpInProxyMode` (drift test red until T4 lands —
  expected, say so). `DEFAULT_SETTINGS` in both mirrors.

### T3a (Fable, ★★★★): leak guard *standard* — adapter DNS override with crash repair

**Files:** `src/main/leakGuard.js` (new), `tests/leakGuard.test.js`, `src/main/main.js`,
`src/server/service.js`, `src/main/dnsBuilder.js` (nothing new; `dropUdpDirect` is for T3b).

- Pure script generators, tested by snapshot: Windows one PowerShell script that records every
  physical connected adapter's DNS (`Get-DnsClientServerAddress` v4+v6, JSON to stdout) and sets them to
  the TUN peer(s); macOS one bash script over every service from `networksetup -listallnetworkservices`
  (skipping disabled `*` entries), recording `-getdnsservers` and setting the peer.
- `userData/tun-state.json` written BEFORE the override with the recorded originals (+ timestamp,
  backend, interface); removed after a successful restore. Restore runs on disconnect, quit,
  `process.on('exit')` (sync, Windows: one `netsh`/PowerShell call; macOS only when root), and **at
  launch if the file exists** (crash repair, logged).
- Wiring: after `tun.start` succeeds and `leakGuard !== 'off'`; before `tun.stop` on the way down;
  `reapplyConnection` covers the gap by holding the override (do not restore between teardown and
  rebuild). Headless mirror identical.

### T3b (Fable, ★★★★): leak guard *strict* + proxy-mode UDP block

**Files:** `src/main/leakGuard.js`, `tests/leakGuard.test.js`, `src/main/tunSingbox.js` (strict flag),
`src/main/configBuilder.js` (`dropUdpDirect` from `leakGuard === 'strict'` under TUN), both mirrors.

- Strict = `strict_route: true` in the sing-box config + Windows outbound block rules on each physical
  adapter for the complement of {server entry IPs, resolver bypass IPs, RFC1918, 169.254/16, 127/8,
  224/4} — `rangeComplement(excludes)` pure with tests (CIDR maths, IPv4 only; v6 is blocked entirely off-TUN by
  strict_route). One `New-NetFirewallRule -Group IRNetFree …` per adapter per protocol, batched into one
  PowerShell script; `Remove-NetFirewallRule -Group IRNetFree` on the way down and at launch.
- macOS strict = strict_route + a `pf` anchor `/etc/pf.anchors/irnetfree` (block out on non-utun except
  the same excludes; loaded with `pfctl -a irnetfree -f`, removed with `pfctl -a irnetfree -F all`),
  generated by a pure function with tests, shipped behind the "experimental" label the UI shows on macOS.
- `blockUdpInProxyMode`: proxy mode only, one block rule (UDP, remote port not 53) per physical adapter;
  same group; removed on disconnect/quit/launch.
- `dropUdpDirect: true` into `buildDnsPlan` when strict under TUN (bypass still works via DoH + geoip).

### T4 (Opus, ★★): Settings UI, i18n, Required files, README

- Settings → TUN card: backend select (sing-box / tun2socks) with the "recommended" note; leak guard
  select (off / standard / strict) with one-line descriptions, strict marked *experimental* on macOS;
  "Block UDP in proxy mode" switch, shown disabled with the note when TUN is on. Every control saves only
  its own key. `set.tunBackend`, `set.leakGuard`, `set.blockUdpInProxyMode` + all labels in both languages.
- Mode card / TUN messages: "needs sing-box (or tun2socks) and admin rights". Required-files list: TUN
  needs sing-box + wintun (Windows) — the `tunReady` flag from T2.
- README: TUN section rewritten (sing-box, guard levels, what each blocks, macOS first-run notes,
  headless needs root).

### T5 (Fable, ★★★): `allowInsecure` → certificate pinning (TOFU)

**Files:** `src/main/certPin.js` (new), `tests/certPin.test.js`, `src/main/configBuilder.js`,
`src/main/main.js`, `src/server/service.js`, `src/main/parser.js` (share link keeps `allowInsecure=1`),
`src/renderer/app.js` + `i18n.js` (edit-form hint only).

- `fetchLeafPin({ host, port, servername, timeoutMs })` with Node `tls.connect({ rejectUnauthorized:
  false, servername })` → `getPeerCertificate(false).raw` → SHA-256 hex. Unit test against a local TLS
  server made with `xray tls cert` output or Node's own self-signed helper.
- Before `buildActive` (both mirrors): for every server the plan dials **directly** (single, first hop of a
  chain, advanced/pool targets' first hops) whose `tlsSettings.allowInsecure` is true: use the stored
  `server.certPin` if present, else probe once (5 s), store it on the record (`certPin`, plus
  `certPinAt`), log "certificate pinned (TOFU)". Later hops behind a proxy cannot be probed here → keep
  `allowInsecure` off them and log that the pin must be entered by hand (edit form field in T4? no — a
  read-only display of the pin in the edit form with a "clear" button; the field is `#edCertPin`).
- `configBuilder`: `allowInsecure` is never emitted; a `certPin` becomes `pinnedPeerCertSha256`; without a
  pin the verification stays on (the core's own error surfaces).
- Auto-heal: a connect whose core log shows the pin mismatch (`pinnedPeerCertSha256` in the error) clears
  the stored pin and retries once with a fresh probe, logged.
- Tests: emission with/without pin; the probe against a local TLS server; the "not directly dialable"
  rule; the share link still carries `allowInsecure=1`.

### T6 (Opus, ★): macOS self-check script + docs

- `scripts/mac-selfcheck.sh`: prints sing-box/xray versions in userData/bin, `codesign -dv` status,
  `route -n get default`, `networksetup -listnetworkserviceorder`, runs `sing-box check` on a generated
  TUN config, `pfctl -s info`; every line tagged OK/WARN so the owner can paste the output.
- README "macOS: first run" + the phase-3 verification checklist from the design (§7).

### Order

T0 (lead) → T1 ∥ T5 → T2 → T3a ∥ T4 → T3b → T6 → Fable whole-branch review → fix round → merge → v0.14.0.

### Carried into this phase from the PattN investigation

- `verifyPeerCertByName` (main/PattN only): the right tool for fake-SNI configs; expose later in the
  edit form for the PattN engine (phase 4 territory). Not in this phase.
- The owner's "WireGuard through the chain fails on PattN" report could not be reproduced; the app
  already surfaces the core's rejection line — the owner is asked for that line.
