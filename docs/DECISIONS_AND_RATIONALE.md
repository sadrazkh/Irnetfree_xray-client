Last verified: 2026-11-08
Scope: decisions readable from code comments, commit messages and `docs/releases/`, checked against the code at commit 3e5b74d. Dates are the first commit or tag carrying the decision. Where no reason is recorded the entry says *Unknown / reconstructed from code*.

# Decisions and rationale

Status values follow the rules: **Verified in code** means the current code does this. It does not mean the reasoning is proven.

## D-001: No runtime npm dependencies  (2026-06-26)
- **Context:** The same code runs in Electron, on a server and on an OpenWrt router.
- **Decision:** Node core modules only; `electron` and `electron-builder` are dev dependencies. The relay also has none.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** Hand-written HTTP, WebSocket, tar, QR and i18n code (`src/server/remote/ws.js`, `openwrt/tar.js`, `src/renderer/vendor`). CI runs tests without `npm ci`.
- **Do not change without reconsidering:** The ipk ships no `node_modules` (`openwrt/build-ipk.js`), and routers run Node 18 or 20.
- **Status:** Verified in code (`package.json`; `install.sh` header; `.github/workflows/test.yml` comment)

## D-002: A registry of cores, chosen per config  (2026-07-20)
- **Context:** Started with sing-box as a second core; the Xray fork joined on 2026-09-02. Official Xray refuses plaintext VLESS/Trojan to public addresses, a shape common in the configs this app receives. The fork accepts it.
- **Decision:** `ENGINES` holds official Xray, Xray-PattN, sing-box; each server can name its own, and `validateWithFallback` may move a run to the core that can carry it.
- **Alternatives considered:** A boolean or a single core. The registry comment says a boolean would not allow other config formats.
- **Consequences / limitations:** Version-gate logic grows (`xrayManager.js`). Sing-box is single-config only.
- **Do not change without reconsidering:** Effective engine decides the config format (`buildActive`).
- **Status:** Verified in code (`engines.js`, `engineChoice.js`)

## D-003: Xray stays the proxy core; sing-box is the preferred TUN forwarder  (2026-09-03)
- **Context:** tun2socks left IPv6 outside the tunnel and direct dials re-entered it.
- **Decision:** sing-box `tun` with `auto_route` forwards into Xray's SOCKS inbound; tun2socks remains a fallback.
- **Alternatives considered:** tun2socks only (rejected for those two holes, per `tunSingbox.js` header).
- **Consequences / limitations:** Extra binary; sing-box version differences need gates (`DNS_MODE_SINCE`).
- **Do not change without reconsidering:** v1.21.1 shows why `dns_mode` must be written by binary version.
- **Status:** Verified in code (`tunSingbox.js`, `makeTun`)

## D-004: Whole-system tunnel is the default  (2026-09-03)
- **Context:** Comment: "Whole-system tunnelling is the point of the app". Date reconstructed from the sing-box TUN commit.
- **Decision:** `tunMode: true`, `systemProxy: true` on desktop; a router forces `tunMode`.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** Needs admin rights. See KI-004 for the fallback behaviour that differs from the comment.
- **Do not change without reconsidering:** Windows installer is `requireAdministrator` partly for this.
- **Status:** Verified in code (`DEFAULT_SETTINGS`; `package.json` `build.win`)

## D-005: A headless service mirrors the main process; one renderer  (2026-07-15)
- **Context:** Running on a GUI-less server.
- **Decision:** `service.js` reuses `src/main/*` and exposes `invoke(channel, arg)` mirroring IPC. The browser UI is the same renderer, with `web-api.js` replacing the preload.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** Connect logic is duplicated (KI-001).
- **Do not change without reconsidering:** `window.api` must stay identical on both sides.
- **Status:** Verified in code (`service.js` and `web-api.js` headers)

## D-006: Android is a Kotlin port; CI is its only compile gate  (2026-07-18)
- **Context:** Tag v0.9.8 is a full Android client rewrite. Workflow comment: nobody working on it can compile Kotlin locally.
- **Decision:** `core/*.kt` mirror the JS with JVM tests compared to desktop pins; the editor's table is generated.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** Parity is by test only (KI-002).
- **Do not change without reconsidering:** `ServerFieldsTable.kt` is generated; `tests/serverFieldsAndroid.test.js` fails when stale.
- **Status:** Verified in code (`test.yml` job `android`; `scripts/gen-android-server-fields.js`)

## D-007: Android excludes itself from the VPN and ships its cores in the APK  (2026-07-18)
- **Context:** Core sockets must not loop into the TUN. Android 10+ will not execute downloaded files.
- **Decision:** Own package excluded; hev forwards the TUN to a local SOCKS; libv2ray in-process, PattN and sing-box as `lib*.so` subprocesses; a new core arrives with a new APK.
- **Alternatives considered:** Downloading cores (impossible, per `fetch-libs.sh` comment).
- **Consequences / limitations:** APK size; PattN and sing-box arm64 only by default.
- **Do not change without reconsidering:** `extractNativeLibs` / legacy packaging are needed to exec them.
- **Status:** Verified in code (`XrayVpnService.kt`, `fetch-libs.sh`, `build.gradle.kts`)

## D-008: The router runs the real app on Node; the package has no cores  (2026-09-23)
- **Context:** Whole-LAN tunnel using the same logic.
- **Decision:** ipk of `src/`, assets, LuCI, procd init; `node` from the feed; cores downloaded or from the feed.
- **Alternatives considered:** See `docs/superpowers/specs/2026-09-23-openwrt-port-design.md`.
- **Consequences / limitations:** Needs 256 MB RAM and 128 MB flash at least (`docs/openwrt.md`); 32-64 MB devices are out.
- **Do not change without reconsidering:** The Node 18 floor (`test.yml` openwrt job comment).
- **Status:** Verified in code (`openwrt/build-ipk.js`)

## D-009: Router gateway composes sing-box and owns DNS  (2026-09-23)
- **Context:** `auto_route` already routes forwarded LAN traffic.
- **Decision:** Add an nft table and `ip rule` around sing-box; `managesDns` keeps the leak guard out so dnsmasq stays untouched. Dead core fails closed, dead sing-box fails open until recovery.
- **Alternatives considered:** Unknown / reconstructed from code; a closing kill switch was deferred and then added in v1.16.
- **Consequences / limitations:** KI-027.
- **Do not change without reconsidering:** Verification after start: a gateway that silently is not one leaks the house.
- **Status:** Verified in code (`tunOpenwrt.js` header)

## D-010: Refuse by name, never degrade silently  (2026-09-24)
- **Context:** A chain missing its first hop would dial the exit from the ISP. A spoof that does not run is exposure.
- **Decision:** Broken chains, missing bases, unsupported engines and spoof prerequisites raise a named error in both languages.
- **Alternatives considered:** Filtering the missing hop (the earlier behaviour; replaced, per commit message on `buildPlan`).
- **Consequences / limitations:** More connects fail visibly. A dropped routing rule target still follows the default.
- **Do not change without reconsidering:** Every new requirement should get its own message.
- **Status:** Verified in code (`refuseBroken`, `baseGone`, `singboxOnlyError`, `sniSpoofError`)

## D-011: Leak guard holds across rebuilds, with receipts and a crash file  (2026-09-03)
- **Context:** Windows queries every adapter's DNS; releasing during a rebuild leaks exactly when protection is needed; overlapping connects could undo each other.
- **Decision:** `holdForReconnect` (added 2026-09-08), `engage` returns a token, `tun-state.json` written before touching an adapter. Windows holds on loopback.
- **Alternatives considered:** Peer as hold on Windows (rejected: with the TUN gone it routes out of the NIC, per `leakGuard.js` header).
- **Consequences / limitations:** Names do not resolve in the gap, by design.
- **Do not change without reconsidering:** The ordering contract written above `class LeakGuard`.
- **Status:** Verified in code (`leakGuard.js`, `connectOnce`)

## D-012: Pin the certificate on first use in place of allowInsecure  (2026-09-03)
- **Context:** Cores removed `allowInsecure`; share links still ask for it.
- **Decision:** Read the leaf at first dial, store `certPin`, write `pinnedPeerCertSha256`. Sing-box cannot keep it, so pinned records are refused or run on Xray (v1.35.1).
- **Alternatives considered:** Running unverified on sing-box with a warning was put to the owner (v1.35.1); open.
- **Consequences / limitations:** Trust on first use. Hysteria2 cannot be pinned this way (`needsInsecureCore`).
- **Do not change without reconsidering:** `pathCut` skips learning: on a path that reads names, the certificate is the real site's.
- **Status:** Verified in code (`certPin.js`, `pinnedTls`)

## D-013: The app resolves WireGuard endpoints and entry hosts itself  (2026-09-13)
- **Context:** A failed lookup inside Xray's WireGuard handler could panic the whole core.
- **Decision:** Resolve through `trustedDns` before the config is built.
- **Alternatives considered:** Leaving it to the core per engine (the earlier design, replaced; comment in `engineChoice.js`).
- **Consequences / limitations:** A name that cannot be resolved is still left to the core.
- **Do not change without reconsidering:** The DoH lookup path, which distrusts a fake-IP network.
- **Status:** Verified in code (`withWgEndpointIps`, `withEntryHostIps`)

## D-014: Local ports moved to the 30000s  (2026-10-20)
- **Context:** Other clients take the old defaults on the same machine.
- **Decision:** 30808 / 30809 / 30085; a one-time migration moves only old defaults.
- **Alternatives considered:** Not recorded.
- **Consequences / limitations:** Tools configured for old ports need updating.
- **Do not change without reconsidering:** `portsMoved` in `settingsMigrate.js`.
- **Status:** Verified in code (`DEFAULT_SETTINGS`, `settingsMigrate.js`, `docs/releases/v1.30.1.md`)

## D-015: Mux is off by default and decided per server  (2026-10-05)
- **Context:** Mux helps a CPU-limited router but not every server accepts it, and a timeout is not a refusal.
- **Decision:** `off`, `on`, or `auto` with a throwaway-core test and remembered verdicts.
- **Alternatives considered:** On by default (dropped in the review of that round, per merge message).
- **Consequences / limitations:** Benefit only after the user opts in.
- **Do not change without reconsidering:** A timeout must stay `unknown`.
- **Status:** Verified in code (`mux.js`, `mux: 'off'`)

## D-016: A group is a balancer behind a loopback; a chain with a group becomes a group of chains  (2026-10-19)
- **Context:** Xray's balancer has limits with dialing through a loopback.
- **Decision:** Group record is a loopback outbound expanded by `expandGroups`; chains with groups expand into variants (bounded).
- **Alternatives considered:** A chain through the loopback (lost a response about one run in four, `docs/releases/v1.27.0.md`).
- **Consequences / limitations:** A group on an official core older than 26.4.25 moves to a newer core or warns (`GROUP_LOOPBACK_SINCE`).
- **Do not change without reconsidering:** Never remove a balancer's fallback tag (`groupLive.js` header).
- **Status:** Verified in code (`groups.js`, `expandGroups`)

## D-017: Hop dials go through a loopback SOCKS relay  (2026-10-26)
- **Context:** Xray drops the end of a closed connection through a WebSocket hop.
- **Decision:** `relayHopDials` rewrites every TCP dial through a proxy hop to `chain-relay`.
- **Alternatives considered:** Waiting for upstream (no fix at the time, `docs/releases/v1.34.1.md`).
- **Consequences / limitations:** One more loopback inbound.
- **Do not change without reconsidering:** It must run last in `buildConfig`.
- **Status:** Verified in code (`relayHopDials`; `scripts/probe-chain-tail.js`)

## D-018: Cut the TLS hello only on evidence  (2026-11-05)
- **Context:** A server sniffing in front can redirect a Reality or pinned config to the real site.
- **Decision:** Detect (`pathReadsHello`) or react to a dead route, then split hellos; leave any config with its own dial tooling alone.
- **Alternatives considered:** Always cutting (rejected to keep ordinary connections unchanged, `helloCut.js` header).
- **Consequences / limitations:** KI-030.
- **Do not change without reconsidering:** Interval 0, so a connection opens no later.
- **Status:** Verified in code (`helloCut.js`, `cutHellos`)

## D-019: Sniffing stays on, with addresses named by rules excluded  (2026-11-05)
- **Context:** No single sniffing setting suited every host.
- **Decision:** `sniffing.ipsExcluded`, available on cores from 26.4.13; routers always keep the address.
- **Alternatives considered:** A plain on/off (table in `sniffRules.js` header).
- **Consequences / limitations:** Older core ignores the key.
- **Do not change without reconsidering:** The table in that header is measured.
- **Status:** Verified in code (`sniffRules.js`; `probe-domain-routing.js`)

## D-020: SNI spoof runs on sing-box 1.14 or not at all  (2026-11-06)
- **Context:** Only sing-box has `tls.spoof`; it needs raw packets.
- **Decision:** Per-config extension; refuses on the router, on missing rights or versions, or inside a chain, group, routing or pool.
- **Alternatives considered:** Running without the spoof (rejected, D-010).
- **Consequences / limitations:** KI-007, KI-031.
- **Do not change without reconsidering:** Off writes nothing.
- **Status:** Verified in code (`sniSpoof.js`, `refuseSniSpoof`)

## D-021: Extensions are built in; off means hidden, not deleted  (2026-10-26)
- **Context:** The owner wanted install/remove. A VPN runs with elevated rights, Android will not run downloaded code, and GitHub is unreachable on some networks.
- **Decision:** A flag per module; off hides entry points while records keep working; multi-internet and users are inert when off.
- **Alternatives considered:** Downloaded plugins (rejected for the reasons above, `docs/releases/v1.33.0.md`).
- **Consequences / limitations:** All code ships to everyone.
- **Do not change without reconsidering:** A selected item stays selectable, so a connection never changes by itself.
- **Status:** Verified in code (`modules.js` header)

## D-022: LAN user passwords are stored as given  (2026-10-26)
- **Context:** The core's SOCKS/HTTP accounts need the password in the config, and the admin must see and copy it.
- **Decision:** Plain in `store.json`; never logged.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** KI-013.
- **Do not change without reconsidering:** Hashing breaks proxy accounts.
- **Status:** Verified in code (`src/modules/lanUsers/model.js` header)

## D-023: Self-hosted relay, plaintext at the relay  (2026-10-01)
- **Context:** A router may have no static IP and sit behind CGNAT.
- **Decision:** Outbound WebSocket to a relay the owner runs; the UI token stays on the router; a separate `remote.json` keeps the device token out of backups.
- **Alternatives considered:** Cloudflare Tunnel, offered as a second path (`docs/remote.md`).
- **Consequences / limitations:** The relay sees traffic to the UI.
- **Do not change without reconsidering:** The control path must not ride the tunnel.
- **Status:** Verified in code (`relay/server.js`, `remote/agent.js`, `remote/api.js`)

## D-024: Native macOS backend is opt-in  (2026-09-10)
- **Context:** It registers a root LaunchDaemon.
- **Decision:** `native-macos` only when chosen in Settings.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** Needs macOS 13 or newer (`SMAppService`).
- **Do not change without reconsidering:** Comment: no default that would change under a Mac user who never opened this page.
- **Status:** Verified in code (`DEFAULT_SETTINGS`; `nativeMacTun.js`)

## D-025: Traffic by site reads sing-box's API only  (2026-11-02)
- **Context:** Xray has no per-name bytes; sing-box's API lists connections.
- **Decision:** Poll while on; sniff only when asked; only the registrable domain is kept; nothing leaves the machine.
- **Alternatives considered:** Xray's access log (no bytes, per `siteUsage.js` header).
- **Consequences / limitations:** KI-034.
- **Do not change without reconsidering:** The option is off by default.
- **Status:** Verified in code (`siteUsage.js`)

## D-026: Patch for fixes, minor for capabilities; tag triggers release  (2026-10-20)
- **Context:** Owner's stated version rule, first written in the v1.28.1 notes.
- **Decision:** Third number for fixes and improvements, second for new capability; a pushed `v*` tag builds all platforms; a suffixed tag is a pre-release.
- **Alternatives considered:** Not recorded.
- **Consequences / limitations:** Every merge to release gets a tag and a note in `docs/releases/`.
- **Do not change without reconsidering:** In-app update checks read latest and never a pre-release.
- **Status:** Verified in code (`release.yml`); rule text in `docs/releases/v1.28.1.md`

## D-027: Test guardrails: no network, parse everything, real cores  (2026-09-13)
- **Context:** v1.7.3 shipped a dead UI from one apostrophe no test executed; tests twice touched a live machine's proxy.
- **Decision:** `tests/syntax.test.js`, `tests/noNetwork.preload.js`, a `cores` CI job with real binaries.
- **Alternatives considered:** Unknown / reconstructed from code.
- **Consequences / limitations:** Real-device behaviour is still outside CI.
- **Do not change without reconsidering:** The block list of commands in `noNetwork.preload.js`.
- **Status:** Verified in code

## D-028: Automatic refresh updates data, not cores, by default  (2026-09-09)
- **Context:** A new core can break a working config; geo data cannot.
- **Decision:** `autoUpdateAssets: 'geo'`, weekly, never under a live tunnel, except a router's quiet-hours window.
- **Alternatives considered:** `all` is offered as a choice.
- **Consequences / limitations:** Security releases reach users by choice or by a new app version.
- **Do not change without reconsidering:** `SUGGESTED` bumps for security are the manual path.
- **Status:** Verified in code (`assetUpdater.js`)

## D-029: Persian by default; logs stay English  (2026-10-20)
- **Context:** Logs are what gets sent to the developer.
- **Decision:** Persian first with English alternative; log lines, core messages and technical labels stay untranslated.
- **Alternatives considered:** Not recorded.
- **Consequences / limitations:** Two languages in every string table.
- **Do not change without reconsidering:** Renderer keys off an untranslated product name in the error text (`connectOnce` comment).
- **Status:** Verified in code (`i18n.js`, `core/I18n.kt`, `docs/releases/v1.30.0.md`)

## D-030: Android: a rebuild that fails is tried four times with the TUN held, then ends  (2026-11-10)
- **Context:** A rebuild is a connect nobody tapped: a change of network, the stall watchdog, a group reload, a core gone for good. One that could not come up ended the VPN at once. The first fix of the v1.47.1 round retried without end with the TUN closed: every app went out around the VPN behind a notification that only said it was trying.
- **Decision:** Three more tries after waits of 30, 60 and 120 s, with the session's TUN held and the phone kept awake through them. Out of tries: the session ends with its error on screen and in a notification; or, where Android has this app as its always-on VPN, the TUN is let go and the retry goes on every 120 s. What no wait improves ends a rebuild at once: a config no core here runs, a VPN interface Android refuses, a service already destroyed. `RebuildRetry.step` in `vpn/TunnelSetup.kt`; `retryRebuild`, `fail`, `alwaysOnNow` in `vpn/XrayVpnService.kt`.
- **Alternatives considered:** End at the first failure (rejected: one attempt lost during a handover ended a session that comes up half a minute later). Retry for good with the TUN closed (rejected: a phone off the VPN for hours with nothing said). Retry for good with the TUN held (rejected: no internet at all, without end, when the server is gone).
- **Consequences / limitations:** Up to 210 s of waits with no internet before it gives up. Under always-on the later retries hold no wake lock, so a sleeping phone tries again when it wakes. KI-042.
- **Do not change without reconsidering:** Letting the TUN go during the first tries brings the leak back. The numbers were chosen in the round, not by the owner, and no phone has run them [A: that they suit real handovers].
- **Status:** Verified in code (JVM test `aRebuildIsTriedAFewTimesWithTheTunHeldAndThenEnds` in `TunnelSetupTest.kt`); the service paths never ran on a phone.
