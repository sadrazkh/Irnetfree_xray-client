# v1.16.0 — the router: stable status, kill switch, start with the router, a real LuCI app, remote control

Date: 2026-10-01. Target: OpenWrt build only (desktop and Android untouched except the shared renderer fix in §2.1
S1, which the desktop also gets for parity). Owner's device: Google Wifi AC-1304, OpenWrt 23.05.4, ARMv7 Cortex-A7,
512 MB RAM, node 18 from the feed.

## 1. What the owner asked (verbatim, then meaning)

> برای روتر اولا کمی ناپایداره وقتی وصلع یهو نشون میده دیسکانکته گزینه کیل سوییچ و گزینه این که وقتی بالا میاد
> روشن بشه داشته باشه و مثل passwall بشه تو محیط خود لوکی هم تنظیمات بیاد دقیق اکتیو بشه عالیه خالا میتونه ui
> کمکیش تو وب باشه و این که ریموت بشه داد یعنی بایپس وی پی ان روی اینترنت من بتونم از بیرون به روتر خونمون وصل
> بشم بتونم این وی پی ان رو روشن خاموش یا کانفیگ رو عوض کنم و اینم در نظر بگیر این ایپی استاتیک نداریم یا ممکنه
> پشت nat باشه حتی ترجیحا بدون سرویس دهنده خارجی یا یه سرویس رو خودم رو مثلا هاربروا نصب کنم اینکارو بکنه یا
> کلادفلر اگر سرویس ساده ای داره اونشکلی

1. While connected the router "suddenly shows disconnected" — make it stable.
2. A kill switch.
3. An option to come up connected when the router boots.
4. Like PassWall: the settings live in LuCI itself and take effect exactly; the web UI stays as the helper.
5. Remote control from outside the home — turn the VPN on/off, change the config — with no static IP, possibly
   behind CGNAT, the control path bypassing the VPN; preferably no third party: a relay the owner hosts (Harbora),
   or Cloudflare if simple.

Decisions taken with the owner (2026-10-01): remote access = **both** (own relay as the main path, Cloudflare Tunnel
as a second option in LuCI); kill switch = **blocks only while the VPN is meant to be on** (the owner turning the VPN
off gives the LAN normal internet).

## 2. Findings that drive the stability work

Read in code (file:line as of main 3c0b274):

1. **Display-only "disconnected" (high, very likely the report).** `app:init` (service.js:2100-2128) returns no
   connection fact; the renderer starts with `connected:false` (app.js:17) and `init()` never derives it, ending in
   `setConnUI('disconnected')`. Every page load while connected — a phone reloading a background tab, F5, a browser
   restore — shows «قطع شده», uptime 00:00, and stays so until the next status event, which never comes on a stable
   tunnel. Pressing Connect there runs `doConnect` → full teardown and rebuild: a needless 20-40 s LAN outage.
   SSE has no resync either (`es.onerror` no-op, nothing replayed on reconnect).
2. **The netWatcher rebuilds on any address blip (high, real outages).** On OpenWrt the fingerprint is every
   non-link-local address on every interface (netWatcher.js:103-118), one settled 3 s poll fires a full rebuild:
   an IPv6 PD prefix rotation (twice: new prefix, then the old one leaving), a WAN/PPPoE carrier flap, br-lan losing
   all carriers on an ath10k firmware reset. Each costs 20-40 s with the LAN direct.
3. **A core exit shows "disconnected" through the whole backoff (medium).** `xray-status stopped` paints
   `disconnected` + red toast, then `recoverFromDrop` waits 2/5/15/30/60 s without any status event.
4. **The service can die for good (medium).** Only `unhandledRejection` is handled; procd's default respawn gives up
   after 5 crashes in an hour; the banner/shutdown/stderr lines lack the `irnetfree:` prefix so `logread -e
   irnetfree` misses them; `app:quit` (any token holder) shuts the gateway down and leaves node running with
   `isQuitting=true` — no recovery, no boot connect until a restart.
5. Smaller: a test core is spawned 700 ms after every connect (memory on 512 MB); boot retries flip
   connecting↔error every 15 s until WAN/NTP; `Date.now()` deadlines jump with NTP (cosmetic).

Ruled out: subscription refresh (keeps ids, never touches the core), the asset updater (skips under a live tunnel),
`settings:set` (live-only), stats polling.

## 3. Design

### 3.1 Stability (workstream W1)

- **S1 — State on load and after every SSE reconnect.** One `connSnapshot()` in the service:
  `{ state: 'connected'|'connecting'|'reconnecting'|'waiting'|'disconnected'|'error', reason, cause, attempt,
  retryInMs, since, serverId, label, engine, tun, killSwitch: {enabled, armed, blocking} }`. `app:init` returns it as
  `conn` (service.js **and** main.js, same shape); the renderer seeds `connected/connecting/activeServerId/
  activeEngine/uptime` from it without toasts or log lines. The server sends `{channel:'conn:snapshot'}` as the first
  event of every `/events` connection; the renderer applies it idempotently. `waiting` = boot retries before the
  WAN/first success.
- **S2 — A stale page cannot tear down a live gateway.** On the router, `connect(target)` while that same target is
  up and healthy returns ok without a rebuild (logged "already connected").
- **S3 — Network changes on OpenWrt are judged, not obeyed.** The router's watcher looks at WAN facts only (the
  interfaces carrying the default routes, from ubus `network.interface` — `up`, `l3_device`, IPv4 address and
  nexthop; for IPv6 only `up`/`l3_device`, never address or prefix churn); LAN-side changes never count. After a
  change: settle 10 s, then probe end-to-end through the tunnel (HTTP 204 via the local SOCKS, 5 s timeout, two
  tries 5 s apart). Rebuild only when the probe fails both times, or when the WAN device xray binds its dials to has
  vanished. Log the fingerprint diff and the decision ("network changed: wan6 prefix …; the tunnel answers — kept").
  The desktop watcher is unchanged.
- **S4 — Drops show as reconnecting.** `recoverFromDrop` emits `reconnecting` (attempt, retry-in) at once and keeps
  it through the backoff; `xray-status stopped` during a recovery carries `rebuilding:true`; the renderer shows
  «اتصال مجدد…» (attempt n) instead of «قطع شده», and the red "disconnected" toast only on a final stop.
- **S5 — The service never stays dead.** `uncaughtException` → log (prefixed) → orderly shutdown → exit 1;
  procd `respawn 3600 5 0` (never give up); every stdout/stderr line prefixed `irnetfree:`; `app:quit` on the
  headless service = orderly exit for procd to restart (never "quitting but alive"); token compare with
  `crypto.timingSafeEqual`.
- **S6 — Memory.** No automatic quick-ping test core after a connect on the router; log MemAvailable and the RSS of
  node/xray/sing-box at every connect and drop. W1 may set `GOMEMLIMIT` for xray/sing-box on the router if QEMU
  RSS measurements justify it (document the value and why).
- **S7 — Diagnostics.** Every status transition logged once with cause (user/boot/recovery/switch/abort/netwatch)
  and generation; core uptime and last stderr lines at an exit; a 500-line in-memory log ring the LuCI Log tab and
  "Copy diagnostics" read (status JSON + versions + MemAvailable + RSS + `ip rule` + the last 300 lines; no
  secrets).

### 3.2 Kill switch (W1)

- **K1 — Setting.** The existing `settings.killSwitch` (desktop key; hidden and ignored on the router until now),
  default off, shown on the router in the web UI (router wording) and LuCI.
- **K2 — Semantics.** Armed ⇔ `killSwitch && connectIntent` (the VPN is switched on — by the user, or restored at
  boot). Armed: LAN devices' forwarded traffic towards the internet is rejected unless it goes through the tunnel.
  Never blocked: devices in `lanBypassMacs`, destinations that are private/link-local/multicast/CGNAT (LAN↔LAN,
  guest↔LAN, the ISP modem's page), reply-direction packets of inbound (port-forwarded) connections, and all of the
  router's own traffic (OUTPUT — the router must still reach servers, NTP, opkg and the remote relay). The owner
  turning the VPN off (disconnect, LuCI switch) disarms it and the LAN goes direct. Turning the setting off
  disarms it.
- **K3 — Survives everything that is not the owner's choice.** Rebuilds, recoveries, server switches, a service
  crash/SIGKILL/respawn, firewall reloads/restarts, a reboot — armed before any interface comes up at boot.
  Implementation: its own table `inet irnetfree_ks`, never touched by the gateway's teardown or the orphan sweep;
  applied atomically (`nft -c -f` validation first, then `nft -f`); the bypass MACs live in this table too (the
  gateway's `inet irnetfree` table and its 0x1f1e mark are deleted on every rebuild). Boot persistence: the service
  writes the validated snippet to `<data_dir>/killswitch.nft` when arming and removes it when disarming; a new
  init script `irnetfree-ks` (START=19, after `firewall`, before `network` at 20) loads it if present. Not a fw4
  include: a broken include would stop fw4 loading the whole firewall. WAN device names (for any rule that needs
  them) are persisted in the snippet — `oifname` matches by name, so they work before the device exists.
- **K4 — Visible.** Status carries `killSwitch {enabled, armed, blocking}` (blocking = armed and the tunnel not
  up). Web UI banner and LuCI say "LAN internet is blocked until the VPN is back" with "Turn the VPN off" (=
  disconnect, which disarms).
- **K5 — Escape hatches.** `prerm` removes the table, the snippet and the boot script's effect;
  `/etc/init.d/irnetfree-ks stop` (documented in docs/openwrt.md) lifts it from SSH.
- **K6 — Tests.** Unit: snippet generation (MAC validation, idempotent `table/delete table/table {…}` form,
  private ranges, both families). QEMU (both images): arm → kill sing-box → the table is present and a forwarded
  probe from a LAN-side network namespace to a public address is rejected (reject-rule counter moves); an excluded
  MAC passes; disconnect → table gone; reboot-equivalent (`/etc/init.d/irnetfree-ks start` with the snippet) →
  table back before the service starts.

### 3.3 Connect when the router starts (W1)

- **B1.** The existing `settings.autoConnect` is labelled on the router "Connect when the router starts" (web UI and
  LuCI). On: after a reboot or power cut the VPN comes back exactly as it was — if it was on, with the same config;
  if the owner had turned it off, it stays off. Off: it stays off after a reboot until turned on.
- **B2.** LuCI's main switch is the VPN itself: on = connect to the selected config (sets the intent), off =
  disconnect (clears it).
- **B3.** Boot retries (19 × 15 s, then every 60 s) show `waiting` ("Waiting for internet, attempt n") instead of
  flipping connecting↔error.

### 3.4 LuCI app (W2; the service-side facade is W1)

- **L1 — Menu.** Services → IRNetFree with tabs Overview, Settings, Remote access, Log (replaces today's
  link-only page; still one package `irnetfree`, no separate luci-app ipk — install.sh takes the first `_all.ipk`).
- **L2 — Overview.** State badge (Connected / Connecting / Reconnecting n / Waiting for internet / Disconnected /
  Error + reason), config name + engine + uptime, traffic, kill switch state, remote-link states; the VPN on/off
  switch; the config picker grouped like the web UI (each subscription, manual servers, chains, pools, advanced
  routing) with Connect / Reconnect / Test connection (through the tunnel → ms or the error) / Update subscriptions;
  "Open full web UI" (the token link, as today). Polls every 3 s.
- **L3 — Settings.** Connect when the router starts; Kill switch (with its explanation); Block QUIC from the LAN;
  Devices that bypass the VPN (DHCP leases with names + manual MAC); web UI port/listen address (UCI, restart
  notice). Changes apply at once through the service (port/bind via UCI + service restart).
- **L4 — Remote access.** Relay: enabled, relay URL, router name, device token (write-only: shows "set", can be
  replaced), state (online via direct / via VPN / offline + last error + since), an "Open" link. Cloudflare Tunnel:
  installed or not (+ install button running `opkg update && opkg install cloudflared` asynchronously), token
  (write-only), enabled, state. Both can be on at once.
- **L5 — Log.** The service's 500-line ring (refresh) and "Copy diagnostics".
- **L6 — Plumbing.** rpcd exec plugin `/usr/libexec/rpcd/luci.irnetfree` (POSIX sh, BusyBox only): `list` declares
  the methods; `call` sends `{"token":"<data_dir/token>","arg":<stdin JSON>}` with `uclient-fetch --post-file` to
  `http://127.0.0.1:<uci port>/luci/<method>` and prints the JSON reply; a down service → `{"error":"not-running"}`;
  plus a local `service` method (start/restart). The token never travels in argv or to the browser (except the
  existing "Open full web UI" link). Long actions return at once (`{accepted:true}`) and the page follows the status.
- **L7 — ACL.** `luci-app-irnetfree`: read = status/configs/settings_get/devices/log/diagnostics/remote_get; write =
  connect/disconnect/reconnect/select/test/subs_update/settings_set/remote_set/cloudflared_install/service; file
  read only for the token (the link).
- **L8 — Language.** English; Persian when LuCI runs in `fa` (a dictionary inside the views; LuCI's theme does RTL).
- **L9 — Install hygiene.** postinst: `/etc/init.d/rpcd reload`, clear `/tmp/luci-indexcache*` and
  `/tmp/luci-modulecache/`. A stopped service shows "Service not running" + Start.
- **L10 — Tests.** Syntax of every view (syntax.test.js), menu/ACL JSON shape (openwrtPackage.test.js), the plugin's
  `list` output; QEMU: `ubus -v list luci.irnetfree`, `ubus call luci.irnetfree status` reports the live state,
  `settings_set {killSwitch:true}` arms the table.

**Facade contract (W1 implements in `src/server/luciApi.js`, mounted by server.js at `POST /luci/<method>`;
loopback peers only, body `{token,arg}`, token compared in constant time, any Content-Type):**

| method | arg | reply |
|---|---|---|
| `status` | — | `connSnapshot()` + `{version, traffic:{up,down,upRate,downRate}, memAvailableKb, remote: <remote_get().status>}` |
| `configs` | — | `{selectedId, activeId, groups:[{id, name, kind:'subscription'\|'manual'\|'chains'\|'pools'\|'routing', items:[{id, name, proto}]}]}` |
| `connect` | `{id}` | `{accepted:true}` (select + connect, or switch in place) |
| `select` | `{id}` | `{ok:true}` |
| `disconnect` / `reconnect` | — | `{accepted:true}` |
| `test` | — | `{ok, ms}` or `{ok:false, error}` (HTTP 204 through the tunnel) |
| `subs_update` | — | `{accepted:true}` |
| `settings_get` | — | `{autoConnect, killSwitch, lanBlockQuic, lanBypassMacs}` |
| `settings_set` | partial of the above | `{ok:true, settings}` (validated; applied live) |
| `devices` | — | `[{mac, ip, name, bypass}]` (DHCP leases + bypass list) |
| `log` | `{lines}` | `{lines:[…]}` |
| `diagnostics` | — | `{text}` |
| `remote_get` / `remote_set` / `cloudflared_install` | see §3.5 | from `src/server/remote/api.js` (W3), mounted if present |

### 3.5 Remote control (W3; the bypass hook in the gateway is W1)

**Relay (main path).**

- **R1 — App.** `relay/` in this repo: Node ≥ 20, **zero npm dependencies**, one process; `relay/Dockerfile`
  (`node:22-alpine`, as Harbora's own Dockerfile uses), `relay/harbora.yml`; data on a volume `/app/data` with
  atomic JSON writes and no exclusive file lock (Harbora's start-first cutover runs two containers on one volume);
  `GET /_relay/health` → 200, `/` answers < 500 (Harbora's health gate); container port 8080; Traefik's forwarded
  headers trusted only from private ranges.
- **R2 — Owner login.** Password from the env secret `RELAY_PASSWORD` (refuse to start if shorter than 12);
  `/_relay/login` → session cookie (HttpOnly, Secure, SameSite=Strict, 30 days, HMAC-signed with a key kept in
  `/app/data`); failed logins rate-limited per IP (5 per 15 min) and globally (growing delay); logout; every relay
  page under `/_relay/`; POSTs check Origin.
- **R3 — Routers.** Dashboard: routers (name, online/offline, last seen, path direct/via VPN, app version); "Add
  router" mints a device token (32 random bytes, shown once, stored as SHA-256); revoke; "Open" sets
  `relay_router=<id>` and redirects to `/`.
- **R4 — Tunnel.** The router dials `wss://<relay>/_relay/agent` with `Authorization: Bearer <token>`; one live
  link per router (the newest wins); WebSocket ping every 25 s; a link silent for 75 s is dropped.
- **R5 — Proxying.** After login, every request outside `/_relay/` goes to the selected router over its link as a
  stream: request head (method, path+query, headers minus hop-by-hop and minus the relay's own cookies, Host kept so
  the router's Origin check passes) + body; response head + body chunks streamed back (SSE works); 60 s timeout
  except `text/event-stream`; 8 MB request cap; a "router offline (last seen …)" page. Static GETs (not `/rpc`,
  not `/events`) cached per router and app version so a phone reload does not pull ~0.65 MB through the home
  uplink again.
- **R6 — Frames.** Binary WebSocket messages `[type u8][stream u32][payload]`: HELLO (JSON: name, version, path),
  REQ_HEAD (JSON), REQ_BODY, REQ_END, RES_HEAD (JSON), RES_BODY, RES_END, CANCEL. Backpressure: pause the source
  while the socket's buffered amount is over a threshold. The RFC 6455 subset (client masking, fragmentation in,
  ping/pong, close, payload cap) lives in one shared module used by both ends.
- **R7 — Router agent.** `src/server/remote/` (`ws.js`, `frames.js`, `agent.js`, `api.js`, `cloudflared.js`).
  Settings in the store: `remote: {enabled, relayUrl, name, token}` — the token write-only through every API (only
  "set" is ever returned, never logged). Executes requests only against `http://127.0.0.1:<port>` of its own server,
  injecting the UI token header; refuses `/_relay/*` and `/luci/*` paths; gzips compressible bodies when the browser
  accepts gzip; reconnects with backoff 2/5/10/30/60 s + jitter; status `{state:'off'|'connecting'|'online'|'error',
  path:'direct'|'vpn', since, lastError, relayHost}`.
- **R8 — Bypass (the control path never rides the tunnel).** The agent resolves the relay host through the direct,
  route-excluded in-country resolvers the config already has (configBuilder.js:621-630) when the tunnel is up, or
  the system resolver when it is down; it keeps the last good IPs in the store. It calls
  `service.setRemoteBypass(list)` (W1): while the gateway is up, one `ip rule` per destination (pref 8997, v4/v6,
  `to <ip/cidr> lookup main`), added and removed live, cleaned with the gateway's own rules; plus an xray routing rule
  (`domain:full:<host>`, `ip:<list>` → `direct`) ahead of user rules. The kill switch never touches it (OUTPUT).
- **R9 — Fallback.** Three direct failures in a row while the tunnel is up → dial through the tunnel (the local
  SOCKS inbound), status path `vpn`; try direct again every 10 minutes.
- **R10 — Security.** TLS verified (ca-bundle); the relay sees plaintext (it is the owner's server — documented);
  the agent can reach only the IRNetFree UI (never LuCI, SSH or another host); the router's UI token never leaves the
  router; relay cookies are never forwarded; no secret is ever logged.
- **R11 — Deployment.** Harbora app (Small), env secret `RELAY_PASSWORD`, volume `/app/data`, container port 8080,
  `harbora deploy` — only with the owner's go-ahead (hourly cost). `docs/remote.md` (English + a Persian section):
  Harbora or any Docker host, pairing a router, the Iran-shutdown note (the same image on a server inside Iran keeps
  working when international links are cut).

**Cloudflare Tunnel (second path).**

- **C1.** Prefer the feed's `cloudflared` package and its own service: LuCI's Remote tab installs it (async opkg),
  stores the tunnel token in `cloudflared`'s UCI (or, if the 23.05 package has no token option, the service runs
  `cloudflared tunnel --no-autoupdate --protocol http2 run` itself with `TUNNEL_TOKEN` in the environment, never in
  argv) and enables/disables it. W3 verifies which on 23.05.5 and 24.10.2 and documents it.
- **C2.** Its edge connections bypass the tunnel through the same `setRemoteBypass` (Cloudflare's published tunnel
  edge ranges, verified against Cloudflare's docs), and `protocol http2` (TCP) by default — UDP/QUIC from Iran is
  the first thing throttled. DNS for its edge discovery must not depend on the tunnel: a dnsmasq `server=/…/<direct
  resolver>` drop-in for the edge domains while it runs.
- **C3.** The owner creates the tunnel and its public hostname → `http://127.0.0.1:<port>` in the Cloudflare
  dashboard and protects it with Cloudflare Access; docs/remote.md walks through it. The UI token travels in the
  bookmarked URL (`?token=`), as on the LAN.

## 4. Workstreams

| branch | owner | scope |
|---|---|---|
| `feat/router-core` | Fable | §3.1, §3.2, §3.3, the facade `src/server/luciApi.js` + `/luci/*` in server.js, `setRemoteBypass`, `irnetfree-ks` init, renderer/i18n changes for S1/S4/K4/B1, main.js parity for `app:init.conn`, QEMU assertions for its parts, docs/openwrt.md |
| `feat/router-luci` | Opus | §3.4 except the facade: views, menu, ACL, rpcd plugin, build-ipk.js entries, postinst, LuCI tests and QEMU `ubus` assertions |
| `feat/remote` | Fable | §3.5: relay/, src/server/remote/*, the agent's start in server.js, docs/remote.md, tests |

Merge order into `integration/v1.16.0`: router-core → remote → luci; the QEMU job must be green on both images on the
integration branch; one quick Fable review pass; minors go to "remaining"; merge to main, tag v1.16.0, release notes in
the 3x-ui style.

## 5. Verification

- `npm test` green (the no-network preload stays), syntax.test.js covers every new file, relay unit + loopback
  end-to-end tests (page load, `/rpc` POST, SSE streaming, offline page, revoke, reconnect, rate limit).
- `openwrt (qemu armsr-armv7)` green on 24.10.2 and 23.05.5 with the new assertions (kill switch, `ubus` facade,
  netWatcher decision on a simulated IPv6 address change → "kept", page-load snapshot via `app:init`).
- Desktop and Android jobs unchanged and green.

## 6. Not in this round

Automatic failover to another server when the upstream is dead (PassWall's auto-switch) — the Test button and the
status make it visible; a dead upstream is not detected automatically yet. Per-device servers. End-to-end encryption
through the relay. Remote control from the Android/desktop apps (the browser is the client).

## 7. Owner's device checks after release

1. Leave the router UI open on the phone, background the browser for a while, come back: it shows Connected with the
   right uptime.
2. Kill switch on: `killall sing-box` over SSH → a LAN laptop has no internet until it recovers; an excluded device
   keeps internet; turn the VPN off in LuCI → everyone has internet.
3. Reboot with the VPN on and the kill switch on → no LAN internet until the tunnel is up, then it comes back by itself.
4. LuCI: switch config, toggle the VPN, change settings — the web UI shows the same thing.
5. Relay: pair the router, open the relay on mobile data, switch config and turn the VPN off/on.
6. Cloudflare Tunnel: install from LuCI, paste a token, open the public hostname.
