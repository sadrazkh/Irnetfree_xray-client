Last verified: 2026-11-08
Scope: findings from reading the code at commit 3e5b74d and the limits stated in `docs/releases/`. Severity is a judgement, not a measurement. Nothing was run for this pass.

# Known issues and tech debt

Labels: **[V]** Verified (evidence named), **[A]** Assumption, **[R]** Recommendation.

## Structural debt

| ID | Issue | Evidence [V] | Severity | Proposed direction [R] |
|---|---|---|---|---|
| KI-001 | Two connect paths. `main.js` and `service.js` each have `buildPlan`, `buildActive`, `connectOnce`, `reapplyConnection`, `rebuildActiveConfig`, recovery and `DEFAULT_SETTINGS`, kept in step by hand. A fix can land in one and not the other. | Function lists of both files; `GUIDE.md` architecture section says features must be wired into both | High | Extract the shared connect sequence into `src/main` with injected platform hooks, in small steps. OQ-3 |
| KI-002 | Android is a hand port of about 26,000 lines of Kotlin. Only the editor field table is generated. | `scripts/gen-android-server-fields.js`; `core/ConfigBuilder.kt`, `core/LinkParser.kt`; parity test classes | High | Keep extending shared fixtures (`tests/fixtures/routing`) to more builder cases |
| KI-003 | Very large files: `app.js` 11,112 lines, `MainActivity.kt` 5,185, `service.js` 4,675, `main.js` 4,607. | `wc -l` | Medium | Split by page or screen when next touched |
| KI-018 | Legacy paths still live: single global chain (`chain` key, `__chain__`, `chain:get`), `routeRules` mirrored to `rp-default`, tun2socks fallback. | `buildPlan`, `mirrorToSettings`, `makeTun` | Low | Remove only after a stated store migration. Old stores depend on them |
| KI-019 | Code comments point at design notes outside the repo: `.superpowers/...`, "groups-ui/design.md", and contract references. `.superpowers` is git-ignored. | `groups.js`, `warp.js` headers; `git check-ignore` | Low | Move what matters into `docs/superpowers` or drop the pointers |

## Code and comment mismatches

| ID | Issue | Evidence [V] | Severity | Status |
|---|---|---|---|---|
| KI-004 | The comment on `tunMode` in both `DEFAULT_SETTINGS` says a connect refuses when the backend or admin rights are missing, rather than falling back to proxy-only. The code stays connected proxy-only and reports `tunError` (it throws only on a router: `OPENWRT && settings.tunMode && !myTun.isAvailable()`). | `main.js` and `service.js` `DEFAULT_SETTINGS` vs `connectOnce` ("connected proxy-only") | Medium: a user can believe the whole system is tunnelled, though `proxyOnly` is shown | Logged. Code unchanged per this pass's scope. OQ-11 |
| KI-007 | SNI spoof is offered on the router: registry `platforms: ['desktop', 'router']` and `DESKTOP_ROUTER` fields, yet `service.js` refuses it there (`sniSpoofError(..., 'router')`). The router user can set it up and then fail at connect. | `modules.js`, `serverFields.js`, `service.js` `buildActive` | Medium | Logged. OQ-4 |
| KI-008 | `fetch-libs.sh` says to bump the pins with the desktop's defaults, but sing-box is `v1.13.14` against `SUGGESTED['sing-box']` 1.14.3. | `android/scripts/fetch-libs.sh`; `coreVersions.js` | Medium: 1.14-only behaviour differs from the desktop | Logged. OQ-5 |
| KI-009 | `serverFields.js` header cites `tests/fixtures/serverFields.json`, which does not exist. | `ls tests/fixtures` | Low | Logged |
| KI-010 | `package.json` declares `MIT` but the repo has no root `LICENSE` file (only third-party licences under `bin/` and `src/renderer/vendor`). | `git ls-files` | Medium: unclear terms for a public repo | Logged. OQ-12 |
| KI-011 | Comments and notes cite sing-box 1.14.4 measurements while `SUGGESTED` and the CI matrix are 1.14.3. | `singboxBuilder.js`, `connectionsWatch.js`, `docs/releases/v1.47.0.md` vs `coreVersions.js`, `test.yml` | Low | Logged |

## Security and integrity

| ID | Issue | Evidence [V] | Severity | Proposed direction [R] |
|---|---|---|---|---|
| KI-005 | Core and geo downloads have no checksum or signature check. App update checks a SHA256 list from the same release, so it detects corruption, not a compromised release. | `downloader.js` has no hash code; `appUpdate.js` | High | Verify against published digests where upstream provides them. OQ-2 |
| KI-012 | The router's web UI is plain HTTP, binds all interfaces by default (a LuCI option limits it to the router itself), and the token travels in the page URL (`?token=`). | `openwrt/files/irnetfree.config`; `luci/view/settings.js`; `web-api.js`; `server.js` `authed` | Medium | State the trusted-LAN assumption, or move the token out of the URL. OQ-9 |
| KI-013 | Server credentials, LAN user passwords and backups are plain JSON. LAN passwords must be readable for the core's accounts (by design, D-022). | `store.js`; `model.js` header; `backup.js` | Medium | Document in user guide; consider encrypted backup. OQ-10 |
| KI-014 | Android `allowBackup="true"` and `usesCleartextTraffic="true"`. Android backup could copy the prefs file holding configs. | `AndroidManifest.xml` | Medium | Review need for each. OQ-10 |
| KI-015 | Electron `^31` (lockfile 31.7.7), `sandbox: false` in the window. [A] Electron 31 is out of upstream support by this date. | `package.json`, `package-lock.json`, `createWindow` | Medium | Plan an Electron upgrade with a CI run on all three OSes |
| KI-016 | Local SOCKS and HTTP inbounds are `noauth`; with `allowLan` they accept the LAN. Windows limits by firewall to the local subnet; other platforms have no such rule in this path. | `localInbounds`; `addLanFirewall` | Medium | Consider credentials as Android has (`LocalAuth.kt`) |
| KI-017 | macOS build: `hardenedRuntime: false`, `gatekeeperAssess: false`, signing by a custom script. | `package.json` `build.mac` | Low | Depends on distribution choice |

## Release pipeline

| ID | Issue | Evidence [V] | Severity |
|---|---|---|---|
| KI-020 | An Android release can ship without a working tunnel: `fetch-libs.sh` treats a failed `libv2ray.aar` as non-fatal and the hev build step is `continue-on-error`; no later step was found that checks the APK contains them. | `fetch-libs.sh`; `release.yml` | High |
| KI-021 | Debug APK fallback when no keystore is configured (with a key configured the job refuses it). `assembleRelease` output is `|| true`. | `release.yml` step "Collect APK" | Low |
| KI-022 | `isMinifyEnabled = false`, lint never aborts, `targetSdk` 34. | `android/app/build.gradle.kts` | Low |
| KI-023 | Probes `probe-dns-leak.js` and `probe-wg-chain.js` are not run in CI. | `test.yml` | Low |
| KI-024 | Node differs by job: 22 in tests, 20 in release builds, 18/20 on routers. `tests/syntax.test.js` parses but does not run on older Nodes. | `test.yml`, `release.yml`, `openwrt/install.sh` | Low |

## Functional limits (stated or read from code)

| ID | Limit | Evidence [V] |
|---|---|---|
| KI-006 | A server on the sing-box engine gets no routing rules: no routing mode, custom rules or advanced rules. Only `route.final: proxy`. | `buildSingboxConfig` |
| KI-025 | Reality on the sing-box engine is unproven; 1.14.4's client did not authenticate against an Xray Reality server. | `docs/releases/v1.45.5.md`; `scripts/probe-hello-cut.js` header |
| KI-026 | Desktop kill switch is Windows only; leak guard DNS override is Windows and macOS only. | `armKillSwitch`; `LeakGuard.engage` |
| KI-027 | Router: a sing-box crash lets the LAN go direct until recovery, unless the kill switch is armed (default off). | `tunOpenwrt.js` header; `killSwitch: false` |
| KI-028 | Advanced routing with a dead default still stops every name, and nothing says so on screen. | `docs/releases/v1.45.2.md` |
| KI-029 | A LAN user switched to a stored WireGuard while connected runs before that address is in the tunnel bypass, until a reconnect. | `docs/releases/v1.45.5.md` |
| KI-030 | Hello cut: not on an XHTTP download leg or multi-internet link tests; a false dead route leaves hellos cut until the next connect finds the path clean; Android cuts only a config and a chain's first hop. | `docs/releases/v1.45.3.md`, `v1.45.5.md` |
| KI-031 | SNI spoof: one config alone, Windows elevated; not ARM64 Windows; TLS over TCP only; ping measured without the spoof. | `sniSpoof.js`, `main.js` `buildActive`, `docs/releases/v1.47.0.md` |
| KI-032 | Pinned TUIC and AnyTLS are refused; pinned records Xray cannot run fail with Xray's error. | `singboxOnlyError`, `docs/releases/v1.35.1.md`, `v1.36.0.md` |
| KI-033 | dialMode is not applied through fragment or noise dialers or on a chain's later hop. | `docs/releases/v1.41.0.md` |
| KI-034 | Traffic by site is sing-box TUN only, and approximate. | `siteUsage.js` header |
| KI-035 | Speed limits use policing without `tc`, with visible sawtooth; per-user DNS was not built. | `docs/releases/v1.39.0.md`, `v1.40.0.md` |
| KI-036 | Android hev 2.16.0: a stop that can spin; failed init shows Connected until the self-check says no packets entered. | `docs/releases/v1.44.1.md`; `XrayVpnService.kt` |
| KI-037 | Android calls libv2ray by reflection, so an upstream API change surfaces at runtime, not at compile. | `build.gradle.kts` comment; `vpn/XrayCore.kt` |
| KI-038 | A kept protocol registration after uninstall; UAC on Windows when a link opens. | `docs/releases/v1.45.0.md` |
| KI-039 | The picture's rule order is per browser or window. | `docs/releases/v1.46.0.md` |
| KI-040 | Android Proxy Pool: the port fields do not show what is typed. Each keystroke is saved, but nothing redraws the screen, so the field goes back to the old number. Found by reading, not run on a device. | `PoolScreen` calls `NumFld` without `bump()`; `NumFld` passes `value` straight to `OutlinedTextField` (`ui/MainActivity.kt`) |

## Not checked in this pass

Whether `npm test`, CI or the Android build pass today; behaviour on any real device; runtime correctness of any flow above. All findings are static.
