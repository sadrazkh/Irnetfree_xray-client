Last verified: 2026-11-08
Scope: whole repository at commit 3e5b74d (branch docs/baseline), read only. No app, test or core was run for this pass.

# IRNetFree: master context

Labels used in every doc of this set: **[V]** Verified against the code, with the evidence named beside it. **[A]** Assumption. **[R]** Recommendation. History with no recorded reason is marked *Unknown / reconstructed from code*.

## What it is

A VPN client built on the Xray and sing-box cores. One product, four runtimes:

| Runtime | Where it lives | How it runs | Evidence [V] |
|---|---|---|---|
| Desktop (Windows, macOS, Linux) | `src/main`, `src/preload`, `src/renderer` | Electron main process drives the cores; renderer talks through `window.api` | `package.json` `main`, `build`; `src/main/main.js` `registerIpc` |
| Headless service (Linux server, OpenWrt router) | `src/server`, `openwrt/` | Plain Node, no Electron; serves the same renderer over HTTP + SSE | `src/server/server.js` `handle`; `src/server/service.js` `createService` |
| Android | `android/` | Kotlin + Compose, `VpnService`, a hand-written port of the parser and builders | `android/app/build.gradle.kts`; `vpn/XrayVpnService.kt` |
| Native macOS helper (opt-in) | `native/macos`, `src/main/nativeMacTun.js` | Swift LaunchDaemon behind the Electron app | `native/macos/Bridge.swift`; `DEFAULT_SETTINGS.tunBackend` comment in `main.js` |

Plus `relay/`, a small Node server that lets an owner reach a router behind NAT (`relay/server.js`) [V].

## Current state

| Fact | Value | Evidence [V] |
|---|---|---|
| Version | 1.47.3 | `package.json` `version`; tag `v1.47.3` |
| Releases | 149 git tags, first 2026-06-26, last 2026-11-10 | `git for-each-ref refs/tags` |
| Commits | 1073, of which 212 merges | `git log` |
| Tests | 181 `tests/*.test.js` (about 3,046 `test(` calls); 54 Kotlin test files (599 `@Test`) | counted with grep |
| Runtime npm dependencies | none; `electron` and `electron-builder` are dev-only | `package.json` |
| Suggested cores | Xray 26.10.31, Xray-PattN 26.11.1, sing-box 1.14.3 | `src/main/coreVersions.js` `SUGGESTED` |

**Maturity, honestly:** the code is large and heavily tested in CI against real cores (real TUN in network namespaces, a QEMU OpenWrt guest). Almost nothing shipped since v1.25 has a recorded run on a real phone or real router: the release notes list that as owed in nearly every round. See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md). This pass did not run the test suite, so its pass state today is unknown.

## Reading order

| Doc | Use it for |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components, connect path, config build (Mermaid) |
| [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) | Stores, record shapes, IPC/HTTP surfaces, tags, version gates |
| [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) | Feature by feature: Done, Partial, Not started |
| [KNOWN_ISSUES_AND_TECH_DEBT.md](KNOWN_ISSUES_AND_TECH_DEBT.md) | Bugs, limits, debt, risks |
| [DECISIONS_AND_RATIONALE.md](DECISIONS_AND_RATIONALE.md) | Why things are the way they are (D-NNN) |
| [ENVIRONMENT_AND_SETUP.md](ENVIRONMENT_AND_SETUP.md) | Build, run, test, env vars, CI |
| [PRODUCT_SPEC.md](PRODUCT_SPEC.md) | Vision, features, business rules |
| [ROADMAP.md](ROADMAP.md) | Owed work and proposed priorities |
| [GLOSSARY.md](GLOSSARY.md) | Domain terms |
| [OPEN_QUESTIONS.md](OPEN_QUESTIONS.md) | What only the owner can answer, ranked |
| [AI_WORKING_GUIDELINES.md](AI_WORKING_GUIDELINES.md) | Conventions for working in this repo |
| [CHANGELOG.md](CHANGELOG.md) | One line per release |

## Docs that already exist (linked, not repeated)

| Doc | Language | Content |
|---|---|---|
| [README.md](../README.md) / [README.en.md](../README.en.md) | fa / en | Front page, features per platform |
| [GUIDE.md](../GUIDE.md) | fa | Full user guide, settings reference, build, troubleshooting |
| [docs/openwrt.md](openwrt.md) | fa | Router install, supported hardware, operation |
| [docs/remote.md](remote.md) | en | Relay and Cloudflare Tunnel remote access |
| [docs/macos-reliability-review.md](macos-reliability-review.md) | en | macOS recovery work and its release gate |
| [docs/releases/](releases/) | en, some fa | Notes per release from v1.7.1 on (84 files), including what each round did and did not prove |
| [docs/superpowers/](superpowers/) | en | Design specs and implementation plans per round |

## Five things to know before changing anything

1. **Two hosts, one logic.** `main.js` and `service.js` each hold their own connect path. Most features must be wired into both [V: `buildPlan`, `buildActive`, `connectOnce` exist in both files]. See D-005 and KI-001.
2. **Android is a port, not shared code.** A change to `parser.js` or `configBuilder.js` usually needs its Kotlin twin [V: `core/LinkParser.kt`, `core/ConfigBuilder.kt`; header of `vpn/XrayVpnService.kt`, `core/EngineChoice.kt`]. Nobody can compile it locally: CI is the gate (`.github/workflows/test.yml` job `android`, its comment).
3. **The renderer is shared.** The same `src/renderer` runs under Electron and over HTTP; `src/preload/preload.js` and `src/server/web-api.js` must expose the same `window.api` [V: header of `web-api.js`].
4. **Refuse by name, never degrade silently.** A config that cannot run as asked is refused with a reason: lost chain member, missing core, SNI spoof without its requirements [V: `buildPlan` `refuseBroken`; `singboxOnlyError`; `sniSpoofError`]. See D-010.
5. **Off means byte-identical.** New features are written so a config with the feature off is unchanged [V: comments and code paths in `configBuilder.js` `buildConfig`, `src/main/directPorts.js`, `src/main/sniSpoof.js`; pinned by tests such as `tests/modules.test.js`].
