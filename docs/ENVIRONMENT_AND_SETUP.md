Last verified: 2026-11-08
Scope: `package.json`, `install.sh`, `openwrt/`, `android/` build files, `relay/`, `.github/workflows/`, `scripts/`, at commit 3e5b74d. Commands are read from those files; none was run for this pass.

# Environment and setup

Labels: **[V]** Verified (evidence named), **[A]** Assumption, **[R]** Recommendation. Rows name their evidence and are [V] unless tagged otherwise. User-facing install steps live in [README.md](../README.md), [GUIDE.md](../GUIDE.md) and [docs/openwrt.md](openwrt.md).

## Toolchains

| Area | Needs | Evidence |
|---|---|---|
| Desktop dev | Node.js; Electron 31 (lockfile 31.7.7), electron-builder 24.13.3 | `package.json`, `package-lock.json` |
| Tests | Node 21 or newer (`node --test` with a glob). CI uses 22 | `README.en.md`; `test.yml` comment |
| Headless server | Node, then cores | `install.sh` |
| Router | OpenWrt 23.05 (node 18) or 24.10 (node 20); 25 and SNAPSHOT are refused | `openwrt/install.sh`, `build-ipk.js` `DEPENDS` |
| Android | JDK 17, Android SDK 34, Gradle 8.7, AGP 8.5.2, Kotlin 1.9.24, Compose BOM 2024.06.00. `minSdk` 26 | `android/app/build.gradle.kts`, `android/build.gradle.kts`, wrapper properties |
| Android release native build | NDK r27c, hev-socks5-tunnel 2.16.0 from source | `release.yml` |
| Relay | Node 20 or newer, or the Docker image (`node:22-alpine`) | `relay/server.js`, `relay/Dockerfile` |
| Native macOS | Xcode `swiftc` on macOS | `native-macos.yml` |

The Gradle wrapper script is not committed; use a local Gradle 8.7 (CI does) [V: `git ls-files android` has no `gradlew`]. `GUIDE.md` says to run `gradle wrapper` once first.

## Run

```bash
npm install            # dev dependencies only
npm run get-xray       # official core and geo data into ./bin
npm start              # Electron
npm run server         # headless, see flags below
```

`bin/` tracks only `tun2socks.exe`, `wintun.dll` and helpers; cores come from `npm run get-xray` or the app's Settings → Required files [V: `.gitignore`, `git ls-files bin`].

Headless flags [V: `parseArgs` in `server.js`]: `--port` (6969), `--host` (loopback), `--token`, `--token-file`, `--data-dir`, `--no-auth`. A non-loopback bind without a token creates one. Linux one-liner flags: `install.sh` header (`--start`, `--service`, `--port`, `--host`, `--dir`).

Renderer only, no back end: `node scripts/serve-renderer.js` (also `.claude/launch.json`) [V].

## Test

| Command | What |
|---|---|
| `npm test` | All `tests/*.test.js` with `tests/noNetwork.preload.js`. Needs no core |
| `npm run validate` | Every config shape through `xray run -test`. Needs cores, or `IRNF_XRAY_EXE` |
| `npm run probe:wg`, `probe:wg-base`, `probe:masque`, `probe:warp-chain`, `probe:group`, `probe:domains` | Real-core probes |
| `node scripts/<other probe>.js` | Others in `scripts/`; several need Linux, root and network namespaces with a guard variable such as `IRNF_TUN_PROBE=1` |
| `npm run selfcheck:mac` | macOS self-check for bug reports (`scripts/mac-selfcheck.sh`) |
| `gradle testDebugUnitTest` (in `android/`, after `bash scripts/fetch-libs.sh`) | Android JVM tests |

Probes that create TUN adapters or touch routes must not run on a machine whose network matters. `tests/noNetwork.preload.js` protects `npm test` only [V: its `BLOCKED` list].

`node scripts/gen-android-server-fields.js` rewrites `ServerFieldsTable.kt`; `--check` reports staleness [V].

## Build

| Target | Command | Output |
|---|---|---|
| Windows | `npm run dist:win` | NSIS and portable, x64 |
| macOS | `npm run dist:mac` | dmg and zip, x64 and arm64; native helpers via `scripts/build-mac-native.js`, verified by `verify-mac-native.js` |
| Linux | `npm run dist:linux` | AppImage and deb, x64 |
| OpenWrt | `node openwrt/build-ipk.js [outDir]` | `irnetfree_<v>_all.ipk`; honours `SOURCE_DATE_EPOCH` |
| Android | `cd android && bash scripts/fetch-libs.sh && gradle assembleRelease` | APK |
| Relay | Docker build from repo root, `relay/Dockerfile`; `.dockerignore` limits context | Image |

`npm run gen-icons` regenerates icons (run in CI before build).

## Environment variables

| Variable | Used by | Effect |
|---|---|---|
| `IRNETFREE_DATA` | `service.js` | Data dir |
| `IRNETFREE_NO_SYSTEM_PROXY` | `service.js` | Never touch the machine's system proxy |
| `RELAY_PASSWORD`, `RELAY_DATA`, `PORT` | `relay/server.js` | Relay auth (12+ chars), data dir, port |
| `XRAY_PATH`, `XRAY_LOCATION_ASSET` | core lookup | Override binary or asset path |
| `IRNF_XRAY_EXE`, `IRNF_SINGBOX_EXE`, `IRNF_HOP_EXE`, `IRNF_XRAY_FORK` | probes | Which core |
| `IRNF_VALIDATE_DRY`, `IRNF_VALIDATE_OUT`, `IRNF_CORE_VERSION` | `validate-configs.js` | Build without a core |
| `IRNF_TUN_PROBE`, `IRNF_MW_PROBE`, `IRNF_LP_PROBE`, `IRNF_LU_PROBE`, `IRNF_LS_PROBE`, `IRNF_SPOOF_PROBE` | probes | Guards that say "yes, build namespaces" |
| `VERSION_NAME`, `VERSION_CODE`, `ANDROID_KEYSTORE_FILE`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD` | Android build | Version and release signing (or local `keystore.properties`, git-ignored) |
| `LIBV2RAY_TAG`, `PATTN_TAG`, `SINGBOX_TAG`, `GEO_TAG`, `PATTN_ABIS`, `SINGBOX_ABIS`, `HEV_SO_URL_<ABI>` | `fetch-libs.sh` | Pins and ABIs |

## CI

| Workflow | Trigger | Jobs |
|---|---|---|
| `test.yml` | Every push and PR | `test` (3 OSes), `cores`, `tun-dns`, `sni-spoof`, `multiwan`, `lan-users`, `android`, `openwrt` |
| `release.yml` | Tag `v*` or `x.y.z`; manual builds only | Desktop on 3 OSes, Android, OpenWrt; publishes to GitHub Releases; a tag with a suffix is a pre-release |
| `native-macos.yml` | PRs touching native or main code; manual | Swift validation and packaging, x64 and arm64 |

Secrets the release uses: `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`, and the keystore [V: `release.yml` step names and `env`].

Release flow [V: `release.yml`]: tag → `npm version` syncs to the tag → build → `SHA256SUMS-<os>.txt` → release. The workflow sets no release body; `docs/releases/` holds notes per version.

## Runtime footprint

| Default | Value | Evidence |
|---|---|---|
| Local ports | SOCKS 30808, HTTP 30809, stats 30085 | `DEFAULT_SETTINGS` |
| Android LAN share | 30810, 30811 for a new install | `docs/releases/v1.30.1.md` |
| Web UI | 6969 | `parseArgs`, `irnetfree.config` |
| Router UI bind | All interfaces, with a token file | `openwrt/files/irnetfree.config`, `irnetfree.init` |
| Windows | Runs as administrator | `package.json` `requestedExecutionLevel` |
