# IRNetFree on OpenWrt — the router as the tunnel for the whole LAN

Date: 2026-09-23 · Scope: a new platform (OpenWrt 24.10 routers with ≥256 MB RAM and ≥128 MB storage;
first target Google Wifi AC-1304). Windows, macOS and Android are untouched. Ships as v1.13.0.

## 1. Why

The owner wants "the OpenWrt version of this app" — install it on a router such as the Google Wifi
AC-1304 and every device behind the router goes through the tunnel, with PattN and the other cores
working as they do on the desktop.

Facts established before this design (all verified, not assumed):

- **"Google router 1304" is the Google Wifi first generation, model AC-1304.** OpenWrt 24.10.2 supports
  it officially (`targets/ipq40xx/chromium`, device `google_wifi`, `squashfs-factory.bin` and
  `sysupgrade.bin` published). Qualcomm IPQ4019: ARMv7 Cortex-A7 ×4, **512 MB RAM, 4 GB eMMC**.
  OpenWrt package architecture `arm_cortex-a7_neon-vfpv4`; Node's `process.arch` is `arm`.
- **The official 24.10.2 package feed for that architecture carries `node` 20.20.2** (36 MB installed),
  `sing-box` 1.12.22, `xray-core` 25.1.30, `jq`, `unzip`, `nftables`, `kmod-tun`.
- **patterniha/Xray-core v26.9.13 publishes `Xray-linux-arm32-v7a.zip`** (19.5 MB), plus mips32,
  mips32le, arm64 — so the PattN core exists for this router without building anything.
- **The headless server already exists.** `src/server/service.js` requires every `src/main/*` module
  verbatim and mirrors `main.js`; `src/server/server.js` serves the same renderer over HTTP + SSE with a
  token; `src/server/web-api.js` rebuilds `window.api` in the browser. Runtime dependencies: Node core
  only. `src/` is 1.4 MB.
- **sing-box's Linux `auto_route` captures forwarded traffic by default.** Read from sing-tun
  `tun_linux.go` (`rules()`): the IPv4 rule set ends in `not iif lo → lookup <tun table>`, so packets
  forwarded from `br-lan` are routed into the TUN; `not dport 53 → lookup main suppress_prefixlength 0`
  keeps LAN-destined and specifically-routed traffic direct while **every port-53 packet goes to the
  tunnel** — the port-53 hijack the desktop's DNS plan relies on, for free, for every LAN client and for
  dnsmasq's own upstream queries. Rules start at `iproute2_rule_index` (default 9000), table 2022.

## 2. Decisions taken with the owner

1. **Target class: Google Wifi AC-1304 and routers like it** (≥256 MB RAM, ≥128 MB storage). Small
   32–64 MB-flash MIPS routers are explicitly not a target of this work.
2. **LAN mode: the whole network, transparently, with per-device exclusions.** Every device behind the
   router goes through the tunnel with no configuration on the device; chosen devices (by MAC) go direct.
3. **Approach: the desktop's Node service and UI run on the router.** Not a LuCI/shell rewrite (a third
   implementation of parser, config builder, subscriptions, DNS plan and engine choice, months of work,
   permanent drift), not a router-as-engine driven from Windows (the router would not be standalone).
   Cost accepted: ~60 MB storage and ~100–150 MB RAM at runtime; Node start of a few seconds on a
   Cortex-A7.
4. **Kill switch ("block WAN while the tunnel is down") is not in v1** — offered, declined for now.

## 3. Architecture

```
LAN devices ─► br-lan ─► ip rules (sing-box, pref 9000+) ─► TUN "IRNetFree" ─► sing-box ─socks─► xray | xray-pattn ─► WAN
                 │                                                                                          ▲
                 └─ nft inet irnetfree: ether saddr ∈ @bypass_macs → mark 0x1f1e ─► ip rule pref 8999 → main ─► WAN direct (fw4 NAT)
                                                                                                             │
browser ─► http://<router>:6969/?token=… ─► node src/server/server.js ─► service.js (same modules as main.js) ──┘
                                                                          └─ makeTun() → TunOpenwrt (new) wraps TunSingbox
LuCI ─► Services → IRNetFree ─► the link above (token read behind LuCI's login)
```

Nothing that decides where traffic goes is new: the Xray config is built by `configBuilder.js`, the
core by `engineChoice.js`, the sing-box TUN config by `tunSingbox.buildTunConfig`. The new code is the
router-specific wrapper around the TUN, the package, the service files, the device list, and the tests.

**Files `src/main/` gains or changes:** `tunOpenwrt.js` (new), `openwrtNet.js` (new, pure helpers),
the arch table in `downloader.js` (§4.4 — three pure pickers, existing amd64/arm64 rows byte-identical),
and one line in `main.js` `DEFAULT_SETTINGS` (the `lanBypassMacs` default, per the "both
DEFAULT_SETTINGS" rule — no behaviour change; Electron never runs on a router). `tunSingbox.js`,
`tunManager.js`, `nativeMacTun.js`, `xrayManager.js`, `configBuilder.js` are not edited.

## 4. Components

### 4.1 Platform detection — `src/main/openwrtNet.js`

- `isOpenwrt()` → `process.platform === 'linux'` and (`/etc/openwrt_release` exists **or**
  `process.env.IRNETFREE_PLATFORM === 'openwrt'`). The env override is for tests and QEMU images built
  from other roots.
- Reported to the renderer as `flavor: 'openwrt'` next to the existing `platform: 'linux'` in the two
  status payloads (`service.js` lines ~367 and ~1533). The renderer never checks `platform` for this.
- `lanInterface()` → `ubus call network.interface.lan status` → `.l3_device`; falls back to `br-lan`.
  Async, never throws.
- `parseDhcpLeases(text)` — pure. `/tmp/dhcp.leases` lines are `<expiry> <mac> <ip> <name> <clientid>`;
  returns `[{ mac, ip, name, expires }]`, MACs lower-cased, `*` name → `''`.
- `parseNeigh(text)` — pure. `ip neigh show dev <lan>` lines → `[{ ip, mac, state }]`; `REACHABLE`/
  `STALE`/`DELAY` count as online, `FAILED`/`INCOMPLETE` do not.
- `lanDevices()` → merges leases and neighbours by MAC: `[{ mac, ip, name, online }]`, sorted online
  first then by name. This is what the UI lists.
- `buildNftRuleset({ lanIf, macs, mark })` — pure, returns the text for `nft -f -`:
  ```
  table inet irnetfree
  delete table inet irnetfree
  table inet irnetfree {
    set bypass_macs { type ether_addr; elements = { aa:bb:cc:dd:ee:ff, ... } }
    chain pre { type filter hook prerouting priority mangle; policy accept;
      iifname "br-lan" ether saddr @bypass_macs meta mark set 0x1f1e counter }
  }
  ```
  The first two lines make the load an atomic replace (create-if-missing, delete, recreate in one
  transaction). An empty MAC list produces a set with no `elements` line — still valid, still loaded,
  so a later add needs no special case. MACs are validated (`/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/`); anything
  else is dropped, never interpolated.
- `bypassRuleArgs(mark)` → the `ip rule` argv pairs for add/del of `pref 8999 fwmark 0x1f1e lookup main`
  (v4 and v6). 8999 < 9000 so it is evaluated before every sing-box rule.

### 4.2 The gateway backend — `src/main/tunOpenwrt.js`

`class TunOpenwrt` — the same contract the service already drives (`isAvailable`, `isElevated`,
`prepare`, `start(socksPort, bypassAddrs, dnsServers, opts)`, `stop`, `cleanupSync`, `physicalInterface`,
`dnsPeer`, `dnsPeer6`, `active`, `excludeIps`, `onUnexpectedExit`). It **composes** a `TunSingbox` built
with the same `opts`; it does not subclass it and does not reach into its internals beyond the public
contract.

- `isAvailable()` → the inner sing-box backend is available **and** `nft` is on PATH.
- `isElevated()` → root (procd runs the service as root; `server.js` run by hand as a user gets the
  existing "TUN mode requires root" error from the inner backend).
- `start(...)`:
  1. `lanIf = await lanInterface()`; `macs = settings.lanBypassMacs` (passed in `opts.bypassMacs` by the
     service, the way `opts.apps` is today).
  2. `nft -f -` with `buildNftRuleset(...)`; then `ip rule add …` (v4, v6) — each idempotent: a rule
     that already exists is deleted first.
  3. `await sb.start(socksPort, bypassAddrs, dnsServers, opts)` — identical call, identical sing-box
     config (`auto_route`, `route_exclude_address` = the server IPs, `auto_detect_interface`).
  4. Verify: `ip link show IRNetFree` succeeds and `ip rule` lists table 2022. If not, roll back (stop the
     inner backend, delete the nft table and rules) and throw with the `ip rule` output in the message.
  5. `active = true`, `excludeIps = sb.excludeIps`. Log: `Gateway up on <lanIf>: every device goes through
     the tunnel; N excluded by MAC`.
- `stop()` → `sb.stop()`, then `ip rule del …`, `nft delete table inet irnetfree` (each ignoring
  "does not exist"). `cleanupSync()` → the same with `execFileSync`, best effort.
- `setBypassMacs(macs)` — while active, reload the nft table with the new list (atomic replace); the
  tunnel is not touched. Called by the service when `lanBypassMacs` changes; **`lanBypassMacs` is not a
  reconnect-relevant key** (`settingsMeta.js` is not extended).
- `physicalInterface()` → `tunPlatform.physicalInterface()`; on OpenWrt `ip route show default` names the
  WAN device (`wan`, `eth0`, `pppoe-wan`), which becomes `directInterface` exactly as on Linux today.
- Unexpected exit of sing-box propagates through the inner backend's `onUnexpectedExit` → the existing
  `runRecovery()`.

Behavioural notes recorded here so nobody re-derives them:

- **DNS needs no configuration.** dnsmasq keeps serving the LAN; its upstream queries and every client's
  hard-coded resolver are port-53 packets and go to the tunnel, where Xray's `dns-out` answers (DoH
  through the tunnel, the desktop's DNS plan). An excluded device's DNS still resolves through dnsmasq,
  i.e. through the tunnel — only its traffic is direct. Documented in the UI hint.
- **Fail-closed on a dead core, fail-open on a dead sing-box.** Routes into the TUN survive an Xray
  crash (traffic stops, nothing leaks); a sing-box crash removes its own rules and traffic goes direct
  until recovery. The kill switch that would close that window is deferred (§9).
- **Loops** are prevented the way they are on Linux today: server IPs in `route_exclude_address`, Xray's
  direct/first-hop dials bound to `directInterface`, sing-box `auto_detect_interface`.
- **IPv6** clients are captured by the v6 rules; with `ipv6: false` Xray answers no AAAA, so nothing v6
  is dialled — unchanged from the desktop.

### 4.3 Service wiring — `src/server/service.js`

- `makeTun()`: `if (isOpenwrt()) return (selected = new TunOpenwrt(opts))` before the existing
  sing-box/tun2socks selection. `tunBackend` setting is ignored on OpenWrt (logged once, quiet paths
  silent).
- `DEFAULT_SETTINGS.lanBypassMacs = []` (and the same line in `main.js`).
- The TUN start call passes `bypassMacs: settings.lanBypassMacs` in `opts`, next to `apps` — the other
  backends ignore the key.
- New RPC channels: `net:lanDevices` → `lanDevices()`; the existing `settings:set` path calls
  `tun.setBypassMacs()` when the key changes and the tunnel is active.
- `binDirs()` gains `/usr/bin` on OpenWrt so cores installed with `opkg install xray-core sing-box` are
  found; `userBinDir` (`/etc/irnetfree/bin`) stays first so a downloaded PattN wins.
- Status payloads carry `flavor`.

### 4.4 Cores — `src/main/downloader.js` asset pickers

Extend the three pickers (`xrayAssetName`, `tun2socksAssetName`, `singboxAssetPattern`) for
`process.arch`:

| `os.arch()` | Xray / Xray-PattN | sing-box | tun2socks |
|---|---|---|---|
| `arm` | `Xray-linux-arm32-v7a.zip` | `sing-box-*-linux-armv7.tar.gz` | `tun2socks-linux-armv7.zip` |
| `arm64` | unchanged | unchanged | unchanged |
| `mips` | `Xray-linux-mips32.zip` | `sing-box-*-linux-mips.tar.gz` | `tun2socks-linux-mips.zip` |
| `mipsel` | `Xray-linux-mips32le.zip` | `sing-box-*-linux-mipsle.tar.gz` | `tun2socks-linux-mipsle.zip` |

mips entries are a best-effort mapping (not a supported target); tests pin the table. The Downloader's
extraction shells out to `unzip` / `tar` — both are package dependencies. PattN has no feed package and
is always downloaded from GitHub (`patterniha/Xray-core`); if GitHub is unreachable from the router the
install guide shows the `scp` path into `/etc/irnetfree/bin/`.

### 4.5 Package — `openwrt/`

- `openwrt/build-ipk.js` (Node, uses the runner's GNU `tar`): stages `./usr/lib/irnetfree/{src,assets,
  package.json}` and the files below, writes `control`, `postinst` (enable + start the service),
  `prerm` (stop + disable), `conffiles` (`/etc/config/irnetfree`), then `data.tar.gz`, `control.tar.gz`,
  `debian-binary` (`2.0`) and the outer `irnetfree_<version>_all.ipk` (an ipk is a gzipped tar). Owner
  0:0, files 0644, scripts 0755. `Installed-Size` computed. Fails loudly on any missing file.
- `control`: `Package: irnetfree`, `Version` = `package.json`, `Architecture: all`, `Section: net`,
  `Depends: node, kmod-tun, nftables, unzip, ca-bundle`, `Description` (one line, Persian + English
  names). No dependency on `luci-base`: the LuCI files are inert without LuCI.
- `openwrt/files/irnetfree.init` → `/etc/init.d/irnetfree` — **POSIX sh (busybox ash)**, procd:
  `START=95`, `USE_PROCD=1`, reads `/etc/config/irnetfree` with `config_load`, ensures `/etc/irnetfree/
  token` (16 random bytes, hex, mode 0600), then
  `procd_set_param command /usr/bin/node --max-old-space-size=160 /usr/lib/irnetfree/src/server/server.js
  --host <bind> --port <port> --data-dir <data_dir> --token <token>`, `respawn`, `stdout 1`, `stderr 1`
  (so `logread` shows the app log). `IRNETFREE_PLATFORM=openwrt` in `procd_set_param env` — belt and
  braces beside the `/etc/openwrt_release` check.
- `openwrt/files/irnetfree.config` → `/etc/config/irnetfree`:
  ```
  config irnetfree 'main'
      option enabled '1'
      option port '6969'
      option bind '0.0.0.0'
      option data_dir '/etc/irnetfree'
  ```
- `openwrt/files/99-irnetfree.defaults` → `/etc/uci-defaults/99-irnetfree` (runs once at install):
  firewall zone `irnetfree` with `device 'IRNetFree'`, `input REJECT`, `output ACCEPT`, `forward REJECT`,
  `masq 0`, and `forwarding lan → irnetfree`; `uci commit firewall`; `fw4 reload` if running. Explicit
  rather than relying on the lan zone's forward policy; the QEMU test asserts the forward is accepted.
- LuCI (three static files, no server code):
  `/usr/share/luci/menu.d/luci-app-irnetfree.json` (Services → IRNetFree, `view` `irnetfree`),
  `/usr/share/rpcd/acl.d/luci-app-irnetfree.json` (read access to `/etc/irnetfree/token` only, via the
  `file` ubus object), `/www/luci-static/resources/view/irnetfree.js` (reads the token, renders one
  button whose href is `http://<location.hostname>:<port>/?token=<token>`, plus the two-line
  explanation). `web-api.js` already takes the token from the URL.
- `.github/workflows/release.yml`: a `Build OpenWrt package` job (ubuntu) runs the builder and uploads
  `irnetfree_<version>_all.ipk` with a SHA256 line.

### 4.6 Renderer — `src/renderer/`

Only when `state.flavor === 'openwrt'` (all strings through `t()` / `data-i18n`, fa + en, no `'` inside a
single-quoted string):

- **Settings → LAN → "Devices on this network"**: table from `net:lanDevices` — online dot, name (or the
  MAC when unnamed), IP, MAC, a toggle "direct — not through the tunnel". Toggling writes
  `lanBypassMacs` and applies live. Refresh button. Hint line: excluded devices still resolve names
  through the router's DNS.
- **Inspector**: one line under the TUN status — `Gateway: whole network through the tunnel · N devices
  online · M direct`.
- Hidden on this flavor: system proxy, autostart, "relaunch as administrator", tray-related settings
  (the headless service already no-ops most; the switches should not be shown).
- The Required-files modal's copy for the core downloads mentions `opkg install xray-core sing-box` as
  the alternative for the two official cores.

### 4.7 Installation guide — `docs/openwrt.md` (Persian) + a README section

Flash OpenWrt 24.10.2 on the AC-1304 (link to the device page, factory then sysupgrade); `opkg update &&
opkg install node kmod-tun nftables unzip ca-bundle`; `opkg install irnetfree_<v>_all.ipk`; open LuCI →
Services → IRNetFree → "Open"; Settings → Required files → download the cores (or `opkg install xray-core
sing-box`, or `scp` into `/etc/irnetfree/bin/`); add a subscription; connect; exclude devices under
Settings → LAN. Storage/RAM expectations, `logread -e irnetfree`, and how to stop/uninstall.

## 5. Connect sequence on the router

1. UI → `xray:connect(id)` (unchanged) → `service.js` `doConnect`.
2. `makeTun()` → `TunOpenwrt`. `prepare({strict})` → inner backend (no-op on Linux).
3. `physicalInterface()` → WAN device → `directInterface`.
4. Xray config built and validated as today; core chosen by `engineChoice` (PattN if the config or the
   default asks for it); `xray.start()`.
5. `TunOpenwrt.start()`: nft table + ip rules → sing-box TUN with `route_exclude_address` = server IPs →
   verify link and rules → active.
6. LAN packets: `br-lan → (marked? → main → WAN) | (else → table 2022 → IRNetFree → sing-box → socks →
   xray → WAN)`. Port 53 always to the tunnel.
7. Disconnect: `xray.stop()` and `TunOpenwrt.stop()` in the order the service uses today; routes,
   rules and the nft table are gone; LAN goes direct.

## 6. Error handling

- Missing `nft` / `sing-box` / `kmod-tun` → `isAvailable()` false → the existing "TUN requested but
  … not found — connected proxy-only" path, with the message naming the OpenWrt package to install.
- `nft -f` or `ip rule` failure → rollback, error with the command's stderr; the connect fails as a TUN
  error (proxy still up, as on the desktop).
- `ip link show IRNetFree` absent after `sb.start()` → rollback and error including the `ip rule` dump.
- Service start without root → inner backend's existing error.
- Unexpected sing-box exit → existing recovery. Unexpected Xray exit → existing recovery; LAN is
  fail-closed meanwhile.
- Node killed (OOM, `/etc/init.d/irnetfree stop`) → `cleanupSync()` on `SIGTERM`; on a hard kill the
  next start's `repairAtLaunch` plus `TunOpenwrt.start()`'s idempotent add-after-delete of rules and the
  atomic nft replace make a stale table harmless.

## 7. Testing

### 7.1 Unit (`node --test`, runs everywhere)

- `openwrtNet.test.js`: `parseDhcpLeases` (real busybox lines incl. `*` names and a stale entry),
  `parseNeigh` (state mapping), `lanDevices` merge/sort, `buildNftRuleset` (byte-exact text for 0, 1, 3
  MACs; invalid MAC dropped; mark hex), `bypassRuleArgs`, `isOpenwrt` via the env override.
- `tunOpenwrt.test.js`: with an injected fake inner backend and a recorded `run()`: start applies nft
  then rules then inner start then verifies; failure at each step rolls back in reverse; `stop` order;
  `setBypassMacs` while active reloads the table and does not touch the inner backend; while inactive it
  only records.
- `downloader.test.js` additions: the arch table in §4.4.
- `service` wiring: `makeTun` picks `TunOpenwrt` under the env override (existing service tests' style).
- `openwrtPackage.test.js`: builds the ipk into a temp dir, `tar -tzf` the outer and inner archives, asserts
  the file list, `control` fields (version = package.json), modes of scripts, `conffiles`; **the init and
  uci-defaults scripts contain no bashisms** (`[[`, `function`, arrays, `$'`, `==` inside `[ ]`,
  `local` is fine in ash); the LuCI JSON files parse.
- `releaseWorkflow.test.js` addition: the release workflow has the OpenWrt job and uploads the ipk.

### 7.2 Integration — OpenWrt in QEMU in CI (`test.yml`, new job)

Like Android, the only place this code runs before the owner's router is CI.

- `ubuntu-latest`, `apt-get install qemu-system-arm sshpass`; download
  `openwrt-24.10.2-armsr-armv7-generic-initramfs-kernel.bin`; boot
  `qemu-system-arm -M virt -cpu cortex-a15 -smp 2 -m 768 -nographic -kernel … -netdev user,id=n0,
  net=192.168.1.0/24,host=192.168.1.2,dns=192.168.1.3,hostfwd=tcp::2222-:22,hostfwd=tcp::6969-:6969
  -device virtio-net-pci,netdev=n0` in the background (OpenWrt's default lan is static 192.168.1.1, so the
  user network is placed on that subnet).
- `sshpass -p '' ssh root@localhost -p 2222`: add `default via 192.168.1.2`, resolver 192.168.1.3,
  `opkg update && opkg install node kmod-tun nftables unzip ca-bundle sing-box xray-core`, `scp` the ipk,
  `opkg install irnetfree_*.ipk`, wait for `:6969`.
- Through `/rpc` with the token: import `socks://127.0.0.1:1#ci-dummy` (a SOCKS server config needs
  no internet and Xray starts with a dead upstream), set `lanBypassMacs` to one MAC, `xray:connect`.
- Assert on the guest: `ip link show IRNetFree`, `ip rule` contains table 2022 and pref 8999, `nft list
  table inet irnetfree` contains the MAC, the `irnetfree` firewall zone exists and `nft list ruleset`
  contains an accept for forwards from `br-lan` toward `IRNetFree`; `curl --socks5 127.0.0.1:10808`
  is not asserted (no internet). Change `lanBypassMacs` → set updated, tunnel pid unchanged.
  `xray:disconnect` → link, rules and table gone. Job budget 15 minutes; TCG is slow.
- Device acceptance on the real AC-1304 is the owner's (as with Android); the guide lists what to check
  (`logread`, `ip rule`, a phone with no proxy settings reaching a blocked site, an excluded device
  showing its real IP).

## 8. Constraints carried from the project

- Commits in the owner's name only, no `Co-Authored-By`. Minor bump per phase; tags ship, merges do not.
- `src/main/` connect path for Windows/macOS unchanged: verified at the end with
  `git diff --stat v1.12.0..v1.13.0 -- src/main/` listing only `tunOpenwrt.js`, `openwrtNet.js`,
  `downloader.js` (arch table) and the one default line in `main.js`.
- Runtime code Node core only. Renderer strings via `t()` / `data-i18n`.
- Every new setting defaults in both `DEFAULT_SETTINGS`.

## 9. Not in v1 (deliberately)

Kill switch (block WAN for non-excluded devices while the tunnel is down); a different server per
device (the pool by device); small MIPS routers; OpenWrt 25 / SNAPSHOT `apk` packaging; an SDK
`Makefile` for a feed; IPv6-only LANs; bandwidth accounting per device.

## 10. Risks and how each is closed

| Risk | Closed by |
|---|---|
| fw4 drops lan→TUN forwards | explicit zone + forwarding in uci-defaults; asserted in QEMU |
| busybox `ip` lacks `rule` | asserted in QEMU; fallback is a dependency on `ip-tiny` |
| Node start time / RSS on Cortex-A7 | measured in QEMU (not representative) and reported by the owner from the device; `--max-old-space-size=160` |
| GitHub unreachable from the router | feed cores found in `/usr/bin`; `scp` path documented; PattN needs one of the two |
| sing-box feed version older than the desktop's | config fields used exist since 1.8; the Downloader fetches the latest anyway |
| service started by hand as non-root | existing root error from the inner backend |
| a stale nft table from a hard kill | atomic create/delete/recreate on every start |
