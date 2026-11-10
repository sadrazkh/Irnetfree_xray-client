Last verified: 2026-11-08
Scope: code existence checked feature by feature in `src/`, `openwrt/`, `android/`, `native/`, `relay/`; real-world proof taken only from `docs/releases/*.md` and test/CI files, at commit 3e5b74d. Nothing was run for this pass.

# Implementation status

Labels: **[V]** Verified (evidence named), **[A]** Assumption, **[R]** Recommendation.

**Done** means the code exists and either CI proves the feature end to end on what it needs, or the repo records real use with no owed item left. **Partial** means it never ran on the real target, a piece is missing, or the release notes still list something owed. Code existence is [V] (the evidence column). "Never run" statements are [V] against the named release note: they say what was recorded, and real use that nobody wrote down may exist.

## Cross-cutting acceptance gap

| Platform | Compile / test gate | Real-world record | Status |
|---|---|---|---|
| Windows desktop | `npm test`, core gates | Owner's reports appear in the notes; recent rounds say "not run in the real app under TUN" (v1.45.1, v1.45.3) | Partial |
| macOS desktop | CI build, `native-macos.yml`, `scripts/mac-selfcheck.sh` | Device checks owed since v1.7.1 and v1.14.0; `tunSingbox.js` header: "macOS is written blind" | Partial |
| Linux desktop | CI build (AppImage, deb) | No acceptance record found | Partial |
| Android | Compiled and JVM-tested in CI only | Owner reports exist (v1.40.1, v1.44.1), yet every round from v1.25 says the new work did not run on a phone | Partial |
| OpenWrt | QEMU `armsr-armv7` on 23.05.5 and 24.10.2 | Field reports exist (v1.16.2, `mux.js` header); device checks owed in v1.33 to v1.45 | Partial |

## Desktop and shared core

| Feature | Status | Evidence [V] | Reason if Partial, or note |
|---|---|---|---|
| Link, subscription, base64 import | Done | `parser.js` `parseMany`, `subscription.js`; `tests/parser.test.js` | |
| Rotating-subscription identity | Partial | `subscription.js` `serverIdentity`; `SubRefresh.kt` | Replayed on real panel output only (v1.44.1); owner's phone check owed |
| JSON configs (Xray, sing-box), raw mode | Done | `jsonImport.js`, `buildRawConfig`; `tests/jsonImport.test.js`, `tests/jsonConnect.test.js` | |
| Server editor Simple/Pro from one table | Done | `serverFields.js`, `tests/serverFields.test.js` | |
| Engines: Xray, PattN, sing-box per config | Done | `engines.js`, `chooseEngine`, `validateWithFallback`; CI `cores` | |
| Core download, version picker, weekly geo update | Partial | `downloader.js`, `coreVersions.js`, `assetUpdater.js` | Tested against fakes (`tests/downloader*.test.js`), no real run recorded; no checksum on downloads, KI-005 |
| App self-update with SHA256 | Partial | `appUpdate.js`, `app:downloadUpdate` | No acceptance record found |
| System proxy | Partial | `sysproxy.js`, journal; `tests/sysproxy.test.js` | Real-machine check owed (v1.30.1); Linux is best-effort GNOME only |
| TUN: sing-box backend | Partial | `tunSingbox.js`; CI `tun-dns` real TUN on Linux | Real TUN on Windows and macOS not recorded for recent rounds (v1.37.0, v1.38.0, v1.45.1) |
| TUN: tun2socks fallback | Partial | `tunManager.js` | Legacy; IPv6 path not exercised on a real link (v1.7.2) |
| TUN: native macOS service | Partial | `nativeMacTun.js`, `native/macos`; opt-in | Device acceptance owed (v1.7.1) |
| Routing modes, custom rules | Done | `buildRoutingRules`, `normalizeCustomRules` | Not applied on the sing-box engine, KI-006 |
| Advanced routing, profiles, base (via), exit at base, flow tree | Done | `routingProfiles.js`, `buildConfig` advanced branch; `tests/routingProfiles.test.js`, `tests/routingUi.test.js` | |
| Drag-order of rules (v1.46.0) | Partial | `tests/routingUi.test.js` | Not tried with a real mouse in the desktop app (v1.46.0) |
| Chains, named and legacy | Done | `buildChainOutbounds`, `relayHopDials`; `probe-chain-tail.js` in CI | |
| Groups, eviction, live removal | Partial | `groups.js`, `expandGroups`, `groupLive.js`; `probe-group.js` in CI | Real servers and CDN addresses not proven (v1.27.0) |
| Proxy pool | Partial | `buildPoolConfig`; `tests/configBuilder.test.js` | Unit tests and core `-test` only; no behaviour probe or recorded real run |
| Protocols: VLESS, VMess, Trojan, SS, SOCKS, HTTP, WireGuard, Hysteria2 | Done | `parser.js`; `validate-configs.js` | |
| Corporate WireGuard through a chain | Partial | `wgEndpointHosts`, `wgResolvers`; `probe-wg-base.js` in CI | `probe-wg-chain.js` is not in CI; a real corporate link is only partly recorded (v1.7.3) |
| MASQUE, WARP over MASQUE and WireGuard | Partial | `warp.js`, `parser.js` `checkMasque`; `probe-masque.js`, `probe-warp-chain.js` | Real sign-up and connect owed (v1.25.0, v1.26.0): tests use a fake of the API |
| TUIC, AnyTLS (sing-box only) | Partial | `translateTuic`, `translateAnytls`; `probe-tuic-anytls.js` | No real server tried; pinned TUIC/AnyTLS refused until the owner decides (v1.36.0) |
| ECH, ECH outbound | Partial | `translateTls`, `applyEchOutbounds`; `probe-ech-outbound.js` (real network, CI) | A real ECH server through the ECH outbound and the Android field are not proven (v1.31.0) |
| Certificate pin on first use | Done | `certPin.js`; `tests/certPin.test.js` | sing-box refuses pinned records by design, D-012 |
| Anti-DPI: fragment, noise, masks | Partial | `applyFragments`; `validate-configs.js` | dialMode with a fragment, with noise or on a chain's later hop is not built (v1.41.0, KI-033) |
| Hello cut | Partial | `helloCut.js`, `cutHellos`; `probe-hello-cut.js` | Not run on real servers in a chain; not on an XHTTP download leg or multi-internet tests (v1.45.3, v1.45.5) |
| SNI spoof | Partial | `sniSpoof.js`, `spoofHello`; `probe-sni-spoof.js` (Linux namespaces) | Single config, Windows elevated only; never run on Windows; router refuses (KI-007) |
| Mux per server | Partial | `mux.js`; `tests/mux.test.js` | Off by default; real-network behaviour measured for one server only (`mux.js` header) |
| Domain sniffing rules | Partial | `sniffRules.js`; `probe-domain-routing.js` | Not run through a real TUN or on a phone (v1.45.1) |
| Managed DNS plan | Done | `dnsBuilder.js`; `tests/dnsBuilder.test.js`; `tun-dns-probe.js` | |
| Leak guard, standard and strict | Partial | `leakGuard.js`; `tests/leakGuard.test.js` | Windows and macOS only; Linux not supported (`engage`); device checks owed (v1.14.0) |
| Kill switch | Partial | `armKillSwitch` | Windows only on desktop; manual check owed (v1.14.0) |
| Network-change recovery | Partial | `netWatcher.js`, `runRecovery`; `tests/netWatcher.test.js` | Device checks owed (v1.14.0) |
| Per-app routing, config per app | Partial | `tunApps.js`, `tunAppTargets.js` | Real TUN with per-app targets not run (v1.38.0) |
| Process routing (IP approximation) | Partial | `procRouter.js`; `tests/procRouter.test.js` | Unit-tested; no real run recorded |
| Connections tab | Partial | `connectionsWatch.js` | Real TUN not run (v1.37.0) |
| Traffic by site | Partial | `siteUsage.js`; `probe-site-usage.js` | Sing-box TUN only; real-browsing "Other" size not measured (v1.43.0) |
| Multi-internet | Partial | `multiWan.js`, `netLinks.js`; `probe-multiwan.js` | Two real internets and real caps not proven (v1.32.0) |
| Direct ports | Partial | `directPorts.js`; `probe-direct-ports.js` | Owner's app with a direct port owed (v1.42.0) |
| LAN sharing, Windows firewall | Partial | `addLanFirewall` | No acceptance record found |
| LAN users: proxy accounts, limits, reports | Partial | `src/modules/lanUsers`; `probe-lan-users.js` | Windows hotspot with accounts owed (v1.33.0) |
| Hotspot check | Partial | `src/modules/lanUsers/hotspot.js` | "Step 2" depends on an owner test (v1.35.0) |
| Extensions | Done | `modules.js`, `tests/modules.test.js` | |
| Backup and restore | Done | `backup.js`, `tests/backup.test.js` | |
| Deep links, Android Share | Partial | `deepLink.js`, `DeepLink.kt` | Not run in the real shell or on a phone (v1.45.0) |
| Diagnostics window | Partial | `connectionDiagnostics.js`; `tests/connectionDiagnostics.test.js` | Unit-tested; no real run recorded |
| Three skins, RTL, Persian and English | Done | `skins.css`, `i18n.js` | |
| Tray, autostart | Partial | `trayMenu.js`, `autostart.js`; `tests/autostart.test.js` | Only command shapes tested; a real logon run is not recorded |

## Router (OpenWrt)

| Feature | Status | Evidence [V] | Reason if Partial, or note |
|---|---|---|---|
| Package, one-line install | Partial | `openwrt/build-ipk.js`, `install.sh`; QEMU job | armsr QEMU only in CI; other hardware "should work; not tested" in `docs/openwrt.md` |
| Gateway tunnel, device exclusion | Partial | `tunOpenwrt.js`, `openwrtNet.js`; QEMU job | Field-tested with reported fixes (v1.13, v1.16.2); recent changes not run on the router (v1.45.2) |
| Kill switch, boot intent | Partial | `killSwitchOpenwrt.js`, `irnetfree-ks.init`, `gateBootIntent` | Device check owed (v1.14.0) |
| WAN change judged by a probe | Partial | `wanWatch.js`, `tests/wanWatch.test.js` | Tested with fakes; no real WAN change recorded since it shipped |
| LuCI app | Partial | `openwrt/files/luci`; QEMU job opens each tab | Real router UI owed for WARP and others (v1.25.0) |
| Remote relay | Partial | `src/server/remote`, `relay/`; `tests/relay.test.js` | Deployment and field use not recorded |
| Cloudflare Tunnel | Partial | `remote/cloudflared.js` | Same |
| Captive portal, transparent users | Partial | `src/modules/lanUsers/router/portal.js`, `nft.js`; `probe-lan-portal.js` | Real phones and flow offload owed (v1.33.0, v1.38.1) |
| Vouchers, remembered devices, content filter | Partial | `luVouchers.js`, `model.js`; `probe-lan-users.js` | Device checks owed (v1.40.0). Per-user DNS not built |
| Speed limits | Partial | `src/modules/lanUsers/router/shaper.js`; `probe-lan-shape.js` | Policing fallback without `tc`; device checks owed (v1.39.0, v1.40.0) |
| Traffic by site, per device | Partial | `siteUsage.js` `ROUTER_LIMITS`; `probe-router-site-usage.js` | CPU load on a real router not measured (v1.44.0) |
| SNI spoof, TUIC, AnyTLS, per-app | Not started | Refused in `service.js` | SNI spoof and TUIC/AnyTLS refused by name; the router runs configs on Xray |

## Android

| Feature | Status | Evidence [V] | Reason if Partial, or note |
|---|---|---|---|
| Whole-device VPN | Partial | `XrayVpnService.kt`, `TunnelSetup.kt` | Field use reported, but stability rounds are unproven on a phone (v1.40.1, v1.44.1) |
| Three engines | Partial | `XrayCore.kt`, `XrayPattnCore.kt`, `SingboxCore.kt` | PattN and sing-box arm64 only by default; sing-box pin is older than desktop (KI-008) |
| Parser and builder parity | Partial | `core/LinkParser.kt`, `core/ConfigBuilder.kt`; `LinkParserParityTest.kt` | Hand port; a later hop's hello cut missing (v1.45.5) |
| Chains, groups, pool, profiles | Partial | `core/Groups.kt`, `RoutingProfiles.kt` | Not run on a phone (v1.29.1) |
| WARP, MASQUE, TUIC, AnyTLS | Partial | `core/Warp.kt`, `Masque.kt`, `SingboxConfig.kt` | Device run owed (v1.25.0, v1.26.0, v1.36.0) |
| Persian UI | Partial | `core/I18n.kt`, `I18nWords.kt` | Real device RTL owed (v1.30.0) |
| LAN share, per-app, tile, Always-on | Partial | `LanShareNet.kt`, `applyPerApp`, `ConnectTile.kt`, manifest | Device checks owed (v1.14.0, v1.15.0) |
| Extensions | Partial | `core/Modules.kt` | Device screen owed (v1.33.0) |
| Update check | Partial | `core/UpdateCheck.kt`, `UpdateCheckTest.kt` | JVM-tested; no phone run recorded |
| Battery-optimisation card on Home | Partial | `BatteryCard` in `ui/MainActivity.kt`, `Store.batteryCardDismissed` | No phone run recorded |
| Rebuild by itself: network change, stall watchdog, group reload, a core gone for good | Partial | `NetWatch.kt`, `StallWatch.kt`, `RebuildRetry` in `TunnelSetup.kt`; `rebuildSession`, `retryRebuild`, `coreGone` in `XrayVpnService.kt`; `NetWatchTest.kt`, `StallWatchTest.kt`, `TunnelSetupTest.kt` | JVM-tested judgement only; the service paths never ran on a phone. Limits in KI-042, KI-043 (v1.47.1) |
| hev 2.17+ upgrade | Not started | `release.yml` `HEV_TAG=2.16.0` | Needs a device (v1.40.1, v1.44.1) |
| Multi-internet, LAN users, site usage, direct ports, SNI spoof | Not started | No such code on Android (grep) | Not offered on Android by the registry or README table |
