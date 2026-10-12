# Full server editor — design

Owner's request (2026-10-12): every field a server can have — "whatever all the clients have, the most complete" —
editable and visible, starting from VLESS Encryption. A simple view like today's and, one click away in the same
window, a professional view. The patterniha parameters stay where they are. The sample was approved first
(`.superpowers/mockups/server-editor.html`, git-ignored); this document is that sample made exact.

## 1. What the user gets

- **One window, two views.** A `Simple | Pro` switch in the edit window's head. The window opens in the view used
  last (remembered in the renderer, `localStorage`). Both views edit one draft: switching never loses a value.
- **Simple** is today's form plus what it lacked: VLESS `flow` and Encryption, VMess cipher and alterId, the
  Shadowsocks method. The anti-DPI section and the 🧩 patterniha section (`cipherSuites`, `finalmask`) stay as they
  are. A line at the end links to the Pro view.
- **Pro** has five tabs: Basics · Protocol · Transport · Security · Advanced. Under each tab's name sits the current
  choice (`VLESS`, `XHTTP`, `reality`). A tab only shows the fields of the protocol / transport / security chosen;
  Transport and Security are disabled where the protocol has none (WireGuard, Hysteria2's transport, SOCKS).
- **New server from scratch.** A `➕ Manual` entry next to the existing add buttons opens the Pro view on Basics with
  a protocol picker (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, WireGuard, SOCKS5, HTTP). Editing never changes a
  server's protocol.
- **"This device only"** tag on every field a share link cannot carry (it stays in this app's store and backups).
- **VLESS Encryption read back.** Pasting the panel's `Encryption` value shows what it is — auth X25519 or ML-KEM-768
  (post-quantum, told by the key's length), mode `native|xorpub|random`, `0-RTT|1-RTT` — or why it is not one.
- **Both languages.** Every label, hint, option and error in Persian and English (`i18n.js`).

## 2. The fields

`★` = new to the editor; `L` = "this device only". Everything else already round-trips through share links.

| Tab | Shown when | Fields |
|---|---|---|
| Basics | always | protocol (new server only), name, address, port |
| Protocol | vless | id, ★flow, ★encryption |
| | vmess | id, ★security (auto, aes-128-gcm, chacha20-poly1305, none, zero), ★alterId |
| | trojan | password |
| | shadowsocks | ★method, password, ★UDP-over-TCP L, ★plugin (SIP003, becomes the stream) |
| | hysteria2 | auth, obfs password, port hopping, ★hop interval, ★up, ★down |
| | wireguard | private key, address, peer public key, pre-shared key, allowed IPs, reserved, MTU, ★keepalive L, ★domainStrategy L, DNS |
| | socks / http | user, password; http ★headers (JSON) L |
| Transport | network = raw | ★header type (none / http), Host, path |
| | ws | Host, path, ★heartbeat L |
| | grpc | service name, authority, ★mode (gun / multi), ★user agent L, ★idle timeout L, ★health check timeout L, ★initial window L, ★permit without stream L |
| | httpupgrade | Host, path |
| | xhttp | Host, path, ★mode (auto / packet-up / stream-up / stream-one), ★extra: xPaddingBytes, noGRPCHeader, scMaxEachPostBytes, scMinPostsIntervalMs, xmux (maxConcurrency, maxConnections, cMaxReuseTimes, hMaxRequestTimes, hMaxReusableSecs, hKeepAlivePeriod), downloadSettings (JSON) |
| | kcp | ★header, ★seed, ★MTU, ★TTI L, ★uplink L, ★downlink L, ★congestion L, ★read buffer L, ★write buffer L |
| Security | tls | SNI, fingerprint, ALPN (chips), certificate pin, verify name, allow insecure, ECH, ★ECH force query L, ★min / max TLS version L, ★curve preferences L |
| | reality | SNI, fingerprint, public key, short ID, ★spiderX, ML-DSA-65 key |
| Advanced | always | engine (Xray, Xray-PattN, sing-box); ★Mux for this server L (app default / on / off, concurrency, XUDP concurrency); ★sockopt L (TCP Fast Open, MPTCP, keepalive interval / idle, congestion); anti-DPI (hide SNI, fragment, noise); 🧩 patterniha (cipherSuites, finalmask) |

Left out on purpose: `sockopt.interface`, `sockopt.mark`, `sockopt.domainStrategy` and `dialerProxy` — the app sets
them itself (TUN binding, entry-host pinning, chains), and a user value there would fight it.

## 3. Architecture

- **One field table, `src/renderer/serverFields.js`.** A UMD file: the renderer loads it as a script, the main
  process, the router service and the tests `require` it (all of `src/` ships in every package). Each field:
  `id`, `tab`, `group`, i18n `label`/`hint` keys, `kind` (`text|number|range|select|switch|json|list|chips`),
  `options`, `when` (protocols / networks / securities), `local`, `simple` (also in the Simple view), and either
  `path` (a dotted path into the outbound, or into the server record with `@`) or `special` (handled by name).
- **Generic read / write** (`getPath` / `setPath` in the same file): an empty value deletes the key, so the core's
  default applies again; numbers are written as numbers, a range like `16-32` as text, JSON as an object, a
  checkbox as `true` or a deleted key.
- **The parser stays the owner of the record.** `parser.editFields` returns every field's value (the special ones as
  today, the path ones through the table). `applyServerEdits` does what it does today, then — after `rebuildStream`
  rebuilt the stream — writes every path field whose `when` holds for the result. A path field the submit did not
  carry keeps the record's value: it is read before the rebuild and written back after it, so an edit in the Simple
  view never drops a Pro value. `rebuildStream` also keeps `sockopt` now (it dropped it).
- **`_edited` and subscriptions** need nothing new: the path fields are editFields keys, so an edit is recorded and a
  subscription refresh carries it like any other.
- **New server:** `parser.createServer(fields)` builds the protocol's skeleton (WireGuard and SOCKS/HTTP through
  `makeWireguardServer` / `makeProxyServer`, Hysteria2 through `buildHysteria2Outbound`), applies the fields with
  `applyServerEdits` and sets `raw` to its own share link. IPC `servers:create` in main and the router service,
  `createServer` in preload and the router's web API.
- **sing-box engine:** VLESS Encryption joins XHTTP and mKCP as things `singboxBuilder` refuses
  (`UnsupportedEngineConfig`), so the connect falls back to Xray instead of dialling without encryption. Android's
  `SingboxConfig` likewise.
- **Mux per server:** `server.mux` (`''` = the app's setting, `on`, `off`), `muxConcurrency`, `xudpConcurrency`.
  `on` muxes an eligible server without waiting for the test; `off` never muxes it; the numbers replace MUX's when
  set. Desktop, router and Android.

## 4. The window

- `#editModal` keeps today's form as the Simple view (its ids, its tests) and gains the Simple additions. The Pro
  view is a container rendered from the table. The draft is an object of field values: opening fills it from the
  record, each view reads and writes it, switching re-renders the other view from it.
- Validation before save: numbers, ranges (`n` or `n-m`), JSON, the Encryption format, required fields of a new
  server (address, port, the credential). A tab with an error gets a red dot and the save says which field.
- Styling in `lists.css`, the app's tokens and type scale (11 / 12 / 14 px), both themes, RTL and LTR.

## 5. Android

The same table in Kotlin (`ServerFields.kt`): same ids, paths, `when`, `local`, `simple` — a JVM test compares it
with a JSON export of the JS table, so the two cannot drift. `ServerEditor` reads and writes path fields
generically, the same preserve-across-rebuild rule. The edit sheet gains the Simple additions and a `Pro` switch that
shows the five tabs (Compose `TabRow`), and a manual "new server" entry with the protocol picker. Labels in English
(Android has no Persian strings yet).

## 6. Testing

- Every path field: written by `applyServerEdits`, read back by `editFields`, kept by a Simple-view edit, dropped
  when its `when` stops holding (a network change), carried by a share link exactly when it is not `local`.
- `createServer` for every protocol, round-tripped through its own share link.
- `validate-configs.js`: one config per protocol and transport with every field set, through `xray run -test` on
  the suggested Xray and Xray-PattN in CI.
- Renderer: the view switch keeps the draft, a tab shows only its fields, validation marks the tab, the Encryption
  read-back, the new-server picker; a real render (headless Chrome) of both views, both directions, three sizes.
- Android: the table parity test, read / write / preserve tests (CI compiles and runs them).
