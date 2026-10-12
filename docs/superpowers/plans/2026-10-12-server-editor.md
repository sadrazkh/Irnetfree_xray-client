# Full Server Editor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every field a server can have — VLESS Encryption first — editable in a Simple view (today's form, completed)
and a tabbed Pro view in the same window, plus creating a server from scratch, on desktop, the router's web UI and
Android.

**Architecture:** One field table (`src/renderer/serverFields.js`, UMD) describes each field: tab, i18n keys, kind,
`when`, `local`, `simple`, and a dotted `path` into the outbound or a `special` name. The parser keeps owning the
record: `editFields` / `applyServerEdits` handle the special fields as today and the path fields generically,
re-applying them after `rebuildStream`; `createServer` builds a skeleton and applies the fields. The renderer draws
the Pro view from the table over one draft shared with the Simple form. Android mirrors the table in Kotlin with a
parity test.

**Tech Stack:** Electron (Node 22), plain DOM renderer, `node --test`; Kotlin + Compose (CI-only compile), JUnit 4.

## Global Constraints

- Every label, hint, option and error in Persian and English (`src/renderer/i18n.js`); Android English only.
- An edit made in the Simple view never drops a Pro value; a field the submit did not carry keeps the record's value.
- An empty value deletes the key (the core's default applies again).
- Configs of servers nobody edited stay byte for byte as before (`tests/configBuilder.test.js` and the desktop pins).
- Never write `sockopt.interface`, `sockopt.mark`, `sockopt.domainStrategy` or `dialerProxy` from the editor.
- Styling only with the app's tokens and type scale (11 / 12 / 14 px); RTL and LTR; dark and light.
- Commits in the owner's name, no trailers; release v1.24.0 with an English + Persian body.

---

### Task 1: The field table

**Files:**
- Create: `src/renderer/serverFields.js`
- Test: `tests/serverFields.test.js`

**Interfaces:**
- Produces (UMD: `module.exports` under Node, `window.ServerFields` in the renderer):
  - `FIELDS: Array<{ id, tab: 'basics'|'protocol'|'transport'|'security'|'advanced', group?: string, label: string /*i18n key*/, hint?: string, kind: 'text'|'number'|'range'|'select'|'switch'|'json'|'list'|'chips'|'area', options?: string[], optionLabels?: string /*i18n prefix*/, when?: { protocols?: string[], networks?: string[], securities?: string[] }, local?: boolean, simple?: boolean, path?: string, special?: true, placeholder?: string, key: string /*the technical name shown beside the label*/ }>`
  - `PROTOCOLS`, `NETWORKS`, `SECURITIES` (per protocol), `FINGERPRINTS`
  - `fieldApplies(field, ctx: { protocol, network, security }) → boolean`
  - `getPath(record, path) → any` — `@x` reads `record.x`, otherwise `record.outbound` + dotted path; `settings.vnext.0.users.0.flow` style indices
  - `setPath(record, path, value)` — creates objects on the way; `undefined` / `''` deletes the key and prunes empty parents it created
  - `toForm(field, raw) → string|boolean` and `fromForm(field, text) → any` (numbers → Number, ranges stay text unless pure digits, json → object, list → array of trimmed, switch → true/undefined)
  - `validate(field, text) → null | i18nKey` (`edit.err.number`, `edit.err.range`, `edit.err.json`, `edit.err.encryption`)
  - `readEncryption(text) → null | { bad: i18nKey } | { auth: 'X25519'|'ML-KEM-768', mode, rtt, padded }`

- [ ] Write `tests/serverFields.test.js`: ids unique; every `path` field has `tab`, `label`, `kind`; `fieldApplies` for vless/ws/tls vs wireguard; `getPath`/`setPath` round trip incl. array indices and pruning; `fromForm` per kind; `validate` cases; `readEncryption` for the two `xray vlessenc` shapes and three bad ones; every label/hint key exists in both languages of `i18n.js` (read as text).
- [ ] Run `node --test tests/serverFields.test.js` → fails (no module).
- [ ] Write the table per spec §2 and the helpers.
- [ ] Run → passes. Commit.

### Task 2: Parser — read, write, preserve, create

**Files:**
- Modify: `src/main/parser.js` (`editFields`, `applyServerEdits`, `rebuildStream`, new `createServer`, exports)
- Test: `tests/serverEditor.test.js`

**Interfaces:**
- Consumes: Task 1 (`require('../renderer/serverFields')`).
- Produces: `editFields(server)` gains every path field (`toForm` values) and the special `flow`, `encryption`, `vmessSecurity`, `alterId`, `method`, `headerType`, `xhttpMode`, `grpcMode`, `kcpHeader`, `kcpSeed`, `spx`, `hopInterval`, `up`, `down`, `plugin`; `applyServerEdits(server, f)` writes them; `createServer(fields) → server` (throws `Error` with an i18n-able message when the protocol, address, port or credential is missing).
- Preservation rule inside `applyServerEdits`: `const kept = readPathFields(server)` before the protocol branch; after the rebuild, for every path field that applies to the result, `setPath(out, field.path, fromForm(field, f[id] != null ? f[id] : kept[id]))`; `rebuildStream` copies `cur.sockopt` onto the rebuilt stream.

- [ ] Tests: for each path field a server where it applies — apply, read back, equal; a Simple-view submit (only today's keys) keeps every Pro value; switching ws→grpc drops the ws heartbeat and keeps sockopt; `_edited` records a Pro field; `createServer` for all eight protocols round-trips through `buildShareLink` → `parseLink` for every non-`local` field; `buildShareLink` never contains a `local` field's key.
- [ ] Run → fail. Implement. Run → pass. Run `npm test` → all pass. Commit.

### Task 3: sing-box refusal, per-server Mux

**Files:**
- Modify: `src/main/singboxBuilder.js` (vless with `encryption` other than `none` → `UnsupportedEngineConfig`)
- Modify: `src/main/mux.js` (+ its callers in `src/main/main.js`, `src/server/service.js`): `server.mux` `on` → muxed when eligible without a test verdict; `off` → never; `muxConcurrency` / `xudpConcurrency` override MUX's numbers in `applyMux` (`src/main/configBuilder.js`).
- Test: `tests/singboxBuilder*.test.js`, `tests/mux.test.js`, `tests/connectPath.test.js` (parity)

- [ ] Tests first; implement; `npm test`; commit.

### Task 4: Router and IPC — create

**Files:** `src/main/main.js`, `src/server/service.js` (`servers:create`), `src/preload/preload.js`, `src/server/web-api.js` (`createServer`), `tests/connectPath.test.js` or the IPC parity test that lists handlers.

- [ ] Test the handler pair exists on both sides; implement; commit.

### Task 5: The window — Simple additions, Pro view, new server

**Files:**
- Modify: `src/renderer/index.html` (view switch in the head, `#edPro` container, Simple rows: flow, encryption + read-back, VMess cipher/alterId, SS method; `<script src="serverFields.js">` before `app.js`; the `➕ Manual` button)
- Modify: `src/renderer/app.js` (draft, `renderPro()`, tab switching, view switch with `localStorage` `irnf.editView`, validation with tab dots, `saveEdit` merging the draft, `openNewServer()` → `window.api.createServer`)
- Modify: `src/renderer/lists.css` (tabs, grid, local tag, chips, read-back chips, protocol picker)
- Modify: `src/renderer/i18n.js` (every new key, fa + en)
- Test: `tests/serverEditorUi.test.js` (vm harness like `tests/jsonUi.test.js`), `tests/editorLayout.test.js` (real render like `tests/corePickerLayout.test.js`)

- [ ] Tests first (view switch keeps the draft; tabs show only their fields; Transport disabled for WireGuard; validation marks a tab; save sends Pro fields; new-server picker; Encryption read-back). Implement. `npm test` with `IRNF_RENDER_BROWSER` set. Commit.

### Task 6: Android

**Files:**
- Create: `android/app/src/main/java/com/irnetfree/vpn/core/ServerFields.kt`
- Modify: `ServerEditor.kt` (path fields read/write/preserve, `create`), `ConfigBuilder.kt` / `Mux.kt` (per-server mux), `SingboxConfig.kt` (refuse VLESS encryption), `ui/MainActivity.kt` (Simple additions, Pro tabs, manual new server)
- Create: `tests/fixtures/serverFields.json` (written by `scripts/export-server-fields.js`, checked by a JS test so it never goes stale)
- Test: `android/app/src/test/java/com/irnetfree/vpn/core/ServerFieldsTest.kt`

- [ ] JVM tests (parity with the fixture, read/write/preserve, create); implement; push and read the `compile android` job. Commit.

### Task 7: Configs the cores accept; release

**Files:** `scripts/validate-configs.js` (every protocol × transport with every field set), `docs/releases/v1.24.0.md`, release body, `package.json` / `package-lock.json` / `android/app/build.gradle.kts` → 1.24.0.

- [ ] Local `validate-configs` on the owner's Xray 26.3.27; full `npm test`; push branch; CI green (cores on 26.9.30 and PattN, Android, OpenWrt); merge `--no-ff`; tag `v1.24.0`; release body PATCH; memory notes.
