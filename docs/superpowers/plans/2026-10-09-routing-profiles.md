# Routing profiles, via a base, the flow tree, share links — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Several saved advanced-routing profiles, targets that ride on a shared base config ("via"), an interactive flow tree, and profile/chain share links — on desktop, router and Android — with today's configs byte-identical.

**Architecture:**
- **R1 (core)**: a pure `src/main/routingProfiles.js` (model, migration, selection), via in configBuilder's registry,
  and profiles in main.js / service.js plan building and IPC.
- **R2 (sharing)**: a pure `src/main/routeShare.js` (payload, encode/decode, preview, import) plus its IPC.
- **R3 (UI)**: renderer and bridges: the profile list, via pickers, flow tree, share/import dialogs, picker rows.
- **R4 (Android)**: everything mirrored in Kotlin.

R1–R4 run in parallel on the interfaces below.

**Tech Stack:** Node 22 (`node --test`, zlib, no deps), plain-JS renderer (fa + en, RTL), Kotlin/Compose (CI-compiled), Xray.

Spec: `docs/superpowers/specs/2026-10-09-routing-profiles-design.md` (requirements, exact values). Fixtures: `tests/fixtures/routing/profile-payload.json` and `profile-link.txt` (trim the line before decoding).

## Global Constraints

- **Profile**: `{ id, name, rules: [{ type, value, target, via? }], def, defVia, useMode, base }`.
  - `id` matches `/^[\w-]+$/`; new ids are `rp-<base36 time><rand>`; the migrated one is `rp-default`.
  - `via`/`defVia` ∈ `'inherit'` (default) | `'none'` | a target (server id or `chain:<id>`).
  - `base` ∈ `null` | a target. `direct`/`block` never take a via.
- **Store key** `routingProfiles`. The settings `routeRules`/`routeDefault`/`advancedUseMode` mirror `rp-default`
  both ways.
- **Selections**: `__advanced__:<profileId>`; plain `__advanced__` = the first profile.
- **Tags**:
  - a base's outbound group: `base-<serverId>`, or a chain base `base-chain-<cid>` with hops `base-chain-<cid>-h<i>`;
  - a target through a base: `out-<serverId>@<baseKey>`, or a chain `out-chain-<cid>@<baseKey>` with hops `…-h<i>`;
  - `<baseKey>` = the base's server id, or `chain-<cid>`.
  - Its self-dialing outbound gets `sockopt.dialerProxy` = the base's exit tag.
  - Without a via: today's tags, byte-identical.
- **Mux** only on direct server targets; never on bases or anything through them.
- **Share**:
  - text `irnetfree://routing/<base64url(deflate-raw(JSON))>`;
  - payload `{ v: 1, kind: 'profile'|'chain', profile?, chains: [{ key, name, members: [serverKey] }], servers: [{ key, name, link }] }`; server keys `s<n>`, chain keys `c<n>`, targets inside the payload `sN` / `chain:cN`;
  - decoded size limit 64 KB; QR when the text is ≤ 1,700 bytes.
- **IPC channels** (main.js AND service.js — the router duplicates plan building; change both):
  - `routing:profiles` → `{ profiles }`
  - `routing:setProfiles` (profiles) → `{ ok, profiles, pendingReconnect, error? }`
  - `routing:shareProfile` (id) / `routing:shareChain` (id) → `{ ok, link, bytes, servers, error? }`
  - `routing:importPreview` (text) → `{ ok, summary: { kind, name, rules, chains, serversNew, serversExisting, unreadable: [..] }, error? }`
  - `routing:import` (text) → `{ ok, profileId?, chainId?, added: { servers, chains, profiles }, error? }`
- **Bridges** (R3 adds them to `src/preload/preload.js` AND `src/server/web-api.js`):
  - `routingProfiles()`, `setRoutingProfiles(profiles)`
  - `shareRoutingProfile(id)`, `shareChain(id)`
  - `routingImportPreview(text)`, `routingImport(text)`
- **No change** for anyone without profiles/vias: every existing config, share link and selection behaves and builds byte-identically (golden check).
- **Commits**: the owner's name, **no `Co-Authored-By` or any trailer**.
- **Never** touch this machine's network, proxy, DNS, firewall, routes or TUN; never kill IRNetFree.exe, xray.exe or sing-box.exe.
- **i18n**: never a straight `'` inside single-quoted strings (use `’`); fa + en.
- **Kotlin**: no `return` in an expression-body `fun f() = try{…}`; no `if/else if` without a final `else` as a lambda's last expression; explicit lambda parameter types; compare org.json canonically; `java.util.Base64` (not `android.util`) in pure code.
- `npm test` stays green; the network is blocked in tests.

---

### Task R1: profiles and via in the core (desktop + router main process)

**Files:**
- Create: `src/main/routingProfiles.js`, `tests/routingProfiles.test.js`
- Modify:
  - `src/main/configBuilder.js` (registry via, `planServers` / entry hosts include bases, refusal of a dangling base)
  - `src/main/engineChoice.js` (`planServers` includes bases)
  - `src/main/main.js` and `src/server/service.js`:
    - `buildPlan` for `__advanced__[:id]`;
    - the store migration at start;
    - the two `routing:profiles` IPC handlers;
    - the reconnect state for edits of the live profile/chains;
    - LuCI's `configsForLuci` lists each profile;
    - the router boot intent with either selection form.
  - `src/main/settingsMeta.js` (as needed), `src/main/backup.js` (carry and merge `routingProfiles` by id)
  - `scripts/validate-configs.js` (via shapes into the CI core gate)
- Test: `tests/configBuilder.test.js`, `tests/connectPath.test.js` (text-level where paths cannot run), `tests/backup.test.js`, `tests/validateConfigs.test.js`

**Interfaces (produce):** `routingProfiles.js` exports:
- `VIA_INHERIT = 'inherit'`, `VIA_NONE = 'none'`;
- `newProfileId()`;
- `normalizeProfile(p) → profile`: drops unknown fields, coerces types;
- `migrateProfiles({ stored, settings }) → { profiles, changed }`;
- `mirrorToSettings(profiles, settings) → settings`: rp-default → routeRules / routeDefault / advancedUseMode;
- `profileFromSettings(settings) → profile`;
- `profileIdOf(selectionId, profiles) → id | null`;
- `effectiveVia(rule | 'def', profile) → target | null`.

The plan for a profile is `{ mode: 'advanced', profileId, serversById, chainsById, chain, rules, def, defVia, base }`.

- [ ] **Step 1** — failing tests:
  - migration from today's settings: one `rp-default`, rules identical, no via;
  - mirror both ways;
  - `profileIdOf('__advanced__')` → the first profile; `profileIdOf('__advanced__:x')` → x when x exists, else null;
  - `effectiveVia`: inherit with a base → base; inherit without → null; none → null; explicit → it.
- [ ] **Step 2** — implement; green.
- [ ] **Step 3** — failing builder tests:
  - two rules to different servers through the same server base → one `base-<id>` outbound, and `out-a@b` / `out-c@b` with `dialerProxy: 'base-<id>'`;
  - a chain target through a base → its h0 dials the base;
  - a chain base → hops `base-chain-<cid>-h0…`, exit `base-chain-<cid>`;
  - the default through the base;
  - a JSON server (`tests/fixtures/json/xray-fragment.json`) through a base → no `~fragment` helper, dialing the base;
  - the same server used with and without via → both `out-<id>` and `out-<id>@<b>`;
  - a dangling base → buildConfig throws the plain message (fa/en like the missing default's);
  - mux ids never applied to `@` or `base-` tags;
  - entry hosts list the base's address, not the via target's;
  - a migrated profile (no vias) → deep-equal to today's advanced config.

  Implement; green.
- [ ] **Step 4** — main.js + service.js:
  - planning, migration, IPC, reconnect state, backup, LuCI list, boot intent;
  - tests at the level the repo tests them;
  - run the golden check of today's shapes (byte-identical).
- [ ] **Step 5** — validate-configs: add via shapes, and the CI `cores` job accepts them.
- [ ] **Step 6** — `npm test` green. Commits in the owner's name, no trailers. Push `feat/rp-core`. CI green (re-run an OpenWrt job that fails only on the mirror's opkg download).

---

### Task R2: share links (desktop + router)

**Files:**
- Create: `src/main/routeShare.js`, `tests/routeShare.test.js`
- Modify:
  - `src/main/main.js` and `src/server/service.js`: the four share IPC handlers. They read and write `servers`, `chains` and `routingProfiles` through the store as the other handlers do; a profile save mirrors through `routingProfiles.mirrorToSettings` when R1's module exists — import it lazily.

**Interfaces (produce):** `routeShare.js` exports:
- `SHARE_PREFIX = 'irnetfree://routing/'`, `MAX_DECODED = 65536`;
- `encodeShare(payload) → text`;
- `decodeShare(text) → payload` (throws `Error(reason)`);
- `profilePayload({ profile, servers, chains, linkOf }) → payload`;
- `chainPayload({ chain, servers, linkOf }) → payload`;
- `previewImport(payload, { servers, chains, profiles, parse, identityOf }) → summary`;
- `applyImport(payload, { servers, chains, profiles, parse, identityOf, newId }) → { servers, chains, profiles, added, profileId?, chainId? }` — pure: it returns new lists.
  - `parse` is parser's `parseMany`-style `(link) → server | throws`.
  - `identityOf` is subscription's `serverIdentity(s, true)`.

- [ ] **Step 1** — failing tests:
  - `decodeShare(fixture link)` deep-equals `profile-payload.json`;
  - `encodeShare(payload)` → decode round trip;
  - `profilePayload` of a store holding those servers/chains/profile → keys `s1…`, targets rewritten, the base/vias kept, only the referenced servers;
  - `chainPayload`;
  - `previewImport` into an empty store: 4 new servers, 1 chain, 5 rules; into a store already holding s1 and s3 (same identity): 2 existing, 2 new;
  - `applyImport` → new ids, chain members mapped, the profile's targets mapped to the new or reused ids, the name de-duplicated ("Work (2)") when a "Work" exists;
  - refusals: a wrong prefix, bad base64, a truncated deflate, > 64 KB decoded, `v !== 1`, an unknown `kind`, a profile target naming a missing key. Each throws with a reason and writes nothing.
- [ ] **Step 2** — implement; green.
- [ ] **Step 3** — the IPC handlers in main.js and service.js:
  - `linkOf` = `buildShareLink`;
  - `parse` = the first server of `parseMany(link)`;
  - a successful `routing:import` persists the lists, marks the reconnect state when it touches the live profile, and answers with them;
  - text tests.
- [ ] **Step 4** — `npm test` green; commit (owner, no trailers); push `feat/rp-share`; CI green.

---

### Task R3: the UI (window + the router's web UI)

**Files:**
- Modify: `src/renderer/app.js`, `src/renderer/index.html`, `src/renderer/i18n.js`, `src/renderer/lists.css` / `styles.css`, `src/preload/preload.js`, `src/server/web-api.js`
- Test: `tests/routingUi.test.js` (new, in the style of `tests/groupFastest.test.js` / `tests/jsonUi.test.js`: real app.js functions in a vm over fakes)

**Interfaces:** consumes the IPC channels and bridges in Global Constraints. Before R1 lands, a missing bridge → keep today's UI; R3's code must not break when `routingProfiles` is absent.

- [ ] **Step 1** — failing tests, then implement:
  - **Profiles on the routing page**: the list (add, rename, duplicate, delete with a confirm, set the default), the selected profile's editor.
    - Today's rule editor stays, plus each proxy rule gets a **via** picker (inherit / none / any server or chain, via `makeSearchSelect`).
    - The profile's **base** picker and the default's via picker sit next to the default target.
  - **The flow tree** for the selected profile:
    - nodes are rules (grouped when consecutive and to the same target), targets and bases;
    - edges go rule → target → base (or direct/block);
    - a base is drawn once, with every incoming edge;
    - danger styling and the reason for a dangling target or base;
    - live speed per branch while that profile is connected (the existing per-outbound stats; the new tags include `@` and `base-`);
    - clicking a node opens its editor;
    - RTL mirrored; usable at the minimum window width.
  - **The home picker**: one "🧭 <name>" row per profile that has rules or a default; selection `__advanced__:<id>`; the old `__advanced__` selection still resolves.
  - The home screen's small path shows "via <base>".
  - **Share**: "Copy link" on each profile and each chain card, warning that server details are inside; a QR when ≤ 1,700 bytes.
  - **Import**: `smartImport`, the paste handler and `looksImportable` recognise `irnetfree://routing/`. A preview dialog (`routingImportPreview`) leads to Import (`routingImport`), and the lists refresh.
  - **i18n**: fa + en for every string.
- [ ] **Step 2** — `npm test` green; commit (owner, no trailers); push `feat/rp-ui`.

---

### Task R4: Android

**Files:**
- Create: `core/RoutingProfiles.kt`, `core/RouteShare.kt`, plus JVM tests (`RoutingProfilesTest.kt`, `RouteShareTest.kt`) reading `File("../../tests/fixtures/routing/profile-link.txt")` and `profile-payload.json`
- Modify:
  - `core/Models.kt` (RoutingProfile, rule via)
  - `core/Store.kt` (`routingProfiles` + migration from the existing settings into `rp-default`, mirrored)
  - `core/Selection.kt` (`__advanced__:<id>`)
  - `core/ConfigBuilder.kt` (via with the same tags and rules; the dangling-target refusal the desktop has — Android today silently goes direct)
  - `ui/MainActivity.kt`:
    - RoutingScreen with profiles, via pickers and the vertical flow list;
    - picker rows per profile;
    - share (copy + QR ≤ 1,700) on profiles and chains;
    - import: paste or scan an `irnetfree://routing/` text → preview → import.

**Interfaces:** identical semantics, tags, payload and limits to R1/R2 (Global Constraints).

- [ ] **Step 1** — JVM tests first:
  - migration;
  - selection ids;
  - effectiveVia;
  - builder tags for every via case;
  - decode of the shared fixture equal to the payload;
  - encode/decode round trip;
  - preview/import with dedupe and the name suffix;
  - refusals.
- [ ] **Step 2** — implement; self-review the Kotlin; push `feat/rp-android`; CI `compile android` green; commits in the owner's name, no trailers.

---

### Task R5 (coordinator): integrate, verify, release

- [ ] Merge R1–R4 into `feat/routing-profiles`; `npm test`; golden byte-identical; the CI cores job.
- [ ] Live on this machine (headless server, temp data dir):
  - make two profiles and a base, check the tree, copy a profile link, import it into a second empty data dir, compare;
  - one real connect through a base on the owner's line (a throwaway core bound to Wi-Fi, the owner's app untouched).
- [ ] One quick review pass; fixes; CI green; merge to main `--no-ff`; tag `v1.20.0`; release body (3x-ui style); report in Persian.
