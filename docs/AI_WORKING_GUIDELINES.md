Last verified: 2026-11-08
Scope: conventions visible in the code, tests, workflows, `CLAUDE.md` and `DOCUMENTATION_RULES.md`, at commit 3e5b74d.

# AI working guidelines

Project-specific rules. Evidence is in brackets; rules marked **[R]** are recommendations, the rest are [V] as practices the repo already enforces or shows.

## Documentation

- Follow [DOCUMENTATION_RULES.md](../DOCUMENTATION_RULES.md), Mode B: update only the docs a change affects, in the same change [`CLAUDE.md`].
- Label claims Verified, Assumption or Recommendation. Do not write Verified without reading the code.
- This repo is public. Never put real hostnames, IP addresses, server or subscription names, accounts, keys, tokens, employers, or where anyone lives or is, into code, tests, commits or docs. Use generic placeholders [R].

## Before changing behaviour

| If you touch | Also check |
|---|---|
| `main.js` connect or settings logic | The matching code in `service.js` (D-005, KI-001) |
| `preload.js` | `src/server/web-api.js`, `service.js` `handlers` |
| `parser.js`, `configBuilder.js`, `dnsBuilder.js`, `engineChoice.js`, `groups.js`, `sniffRules.js`, `helloCut.js`, `mux.js` | The Kotlin twin in `android/.../core` and its test |
| `serverFields.js` or editor strings | Run `node scripts/gen-android-server-fields.js` (`tests/serverFieldsAndroid.test.js` fails when stale) |
| A setting baked into a config | Add to `RECONNECT_KEYS` in `settingsMeta.js` |
| A new config shape | Add it to `scripts/validate-configs.js`, so real cores see it |
| A core version | `SUGGESTED`, `android/scripts/fetch-libs.sh`, CI matrix in `test.yml` |
| Any new user-visible string | Both `fa` and `en` in `i18n.js`; RTL layout; Android `I18nWords.kt` where it applies |
| Anything an extension owns | `data-module` in `index.html` and the check in pickers (`modules.js` header) |

## Code style

- CommonJS, `'use strict'`, no new runtime dependency (D-001).
- Pure modules take no store or Electron; effects are injected, which is how the tests work.
- Comments explain *why*, often with the incident that caused them. Keep that style; do not strip them.
- Every new feature keeps configs byte-identical when off, and a test pins it (`tests/modules.test.js`, `configBuilder.test.js` golden guards).
- A requirement that cannot be met is refused by name in both languages (D-010).
- Every `await` in a connect path needs a staleness check (`connectOnce`).
- Errors crossing IPC keep only `message`: signal through the text, as `connectOnce` notes.

## Testing

- `npm test` must stay offline and must not touch the machine; `tests/noNetwork.preload.js` enforces it.
- `tests/syntax.test.js` parses every shipped JS file. It came from a release that shipped a dead UI (D-027).
- Android cannot be compiled locally here: push and read CI (`test.yml` job `android`). Do not claim Kotlin works from reading it.
- Do not run real TUN, firewall or route changes on a developer's own machine. Real-TUN probes are for CI namespaces [`scripts/tun-dns-probe.js`, `IRNF_TUN_PROBE` guard; `docs/releases/v1.37.0.md`].
- Do not report a device behaviour as working unless it ran there. Say what was and was not run, as the release notes do.

## Releases and commits

- Commit or push only when asked. Work on a branch [R].
- Version rule: third number for fixes and improvements, second for a new capability (D-026).
- Keep `android/app/build.gradle.kts` `versionName` fallback and `package.json` in step (both 1.47.0 at this commit).
- A `v*` tag runs `release.yml`. Add `docs/releases/v<version>.md` with what changed, what was tested, limits, and what is owed.
- Add one line to [CHANGELOG.md](CHANGELOG.md) per release.

## Known traps

- `DEFAULT_SETTINGS` exists twice, and comments in it can lag the code (KI-004).
- Sing-box-format configs have no routing rules (KI-006).
- Router code gates are spread through `service.js` on `OPENWRT` (90 uses).
- Design notes named in comments under `.superpowers` are not in the repo (KI-019).
- GUIDE.md and README are user docs in Persian and English: keep them in step when features change [R].
