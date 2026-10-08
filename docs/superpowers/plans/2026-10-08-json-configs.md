# JSON configs and JSON subscriptions — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Import full Xray JSON configs (single, array, base64, subscription) and sing-box JSON as servers on every platform. Each Xray-JSON server runs inside the app ("full", the default) or exactly as written ("raw", a per-server switch).

**Architecture:**
- A new pure module `src/main/jsonImport.js` turns JSON text into server records. `parser.parseMany` calls it first.
- `configBuilder` writes a JSON server's helper outbounds next to its main outbound with namespaced tags, and builds the raw-mode config.
- main.js / service.js connect raw servers.
- The renderer shows and edits JSON servers.
- Android ports the same rules (`core/JsonImport.kt`, ConfigBuilder, edit sheet). Its JVM tests read the shared fixtures in `tests/fixtures/json/`.

**Tech Stack:** Node 22 (`node --test`, no npm deps), plain-JS renderer (fa + en, RTL), Kotlin/Compose (compiled only in CI), Xray JSON, sing-box JSON.

Spec: `docs/superpowers/specs/2026-10-08-json-configs-design.md` — the requirements, with the exact rules.
Fixtures (committed, sanitized): `tests/fixtures/json/`:
- `xray-subscription.json`: 2 info rows + 5 vless/ws/tls servers.
- `xray-fragment.json`: proxy → dialerProxy `fragment` freedom.
- `xray-chain.json`: proxy → proxySettings `hop1` → dialerProxy `frag`.
- `xray-balancer.json`: balancer `auto` over `proxy-1`/`proxy-2`.
- `xray-wireguard.json`: a single object, no routing.
- `singbox.json`: vless-reality, vmess-ws, trojan-grpc, ss, hy2, wg, socks, http, a detour, plus tuic (unsupported); also selector, urltest, direct, block and dns, which are skipped.

## Global Constraints

- The JSON server record is the link record (`id, name, protocol, address, port, outbound, raw, subId…`) plus exactly
  four fields:
  - `source: 'json'`;
  - `json` (the config object);
  - `extraOutbounds` (an array of helper outbounds, with their original tags);
  - `jsonMode: 'full' | 'raw'` (default `'full'`).

  Plus one derived field, `jsonInfo`, re-computed from `json` on import and on every save.
- `raw` of a JSON server = `JSON.stringify(config)`, the minified single config, `remarks` included.
- **Main outbound**, in order:
  1. the catch-all rule's outboundTag — the last rule with none of domain/ip/port/sourcePort/protocol/inboundTag/user/attrs, or the rule with `network: "tcp,udp"`;
  2. else the outbound tagged `proxy`;
  3. else the first outbound with a proxy protocol (vless, vmess, trojan, shadowsocks, socks, http, wireguard, hysteria).
- **Balancer**: a catch-all with `balancerTag` → one server per outbound whose tag starts with any `selector` entry, named `<remarks> · <tag>`.
- **Helpers**: the dialerProxy / proxySettings.tag closure of the main outbound, verbatim.
- **Info rows**: a config with no proxy-protocol outbound → no server, no error.
- **Full mode in buildConfig**: helper tag → `<outboundTag>~<helperTag>`, with every reference rewritten. A non-first chain hop drops its own helper dialer and its helpers.
- **Raw mode**: `json` with `inbounds` replaced by the app's local inbounds, and `log.loglevel` from Settings.
  - Single-server connects only. Elsewhere the full form is used, and the log says so once per connect.
- **sing-box JSON**: one ordinary server per supported outbound (vless, vmess, trojan, shadowsocks, hysteria2,
  wireguard, socks, http). `detour` → name suffix ` (via <tag>)`. Unsupported types → errors "unsupported protocol: <type>".
  selector/urltest/direct/block/dns are skipped silently.
- **Clash YAML** pasted → the error `Clash YAML is not supported — use the subscription link`.
- **No change** for links, base64 link subscriptions, or the configs any existing server builds. They stay byte-identical, which the golden check proves.
- **Commits**: the author is the repo's configured user (the owner). **No `Co-Authored-By` or any other trailer.**
- **Never** touch this machine's network, proxy, DNS, firewall, routes or TUN. **Never** kill IRNetFree.exe, xray.exe or
  sing-box.exe (the owner's running app; ports 10808/10809/10085/20808/20809).
- **i18n**: never put a straight `'` inside a single-quoted string in `src/renderer/i18n.js` (use `’`).
- **Kotlin** (CI is the only compiler):
  - no `return` inside an expression-body `fun f() = try {…}`;
  - no `if / else if` without a final `else` as the last expression of a lambda/`let`;
  - explicit lambda parameter types where inference is not obvious;
  - org.json keys are unordered (compare canonically).
- `npm test` stays green; the network is blocked in tests (`tests/noNetwork.preload.js`).

---

### Task J1: JSON import, the builder, raw mode (desktop + router main process)

**Files:**
- Create: `src/main/jsonImport.js`
- Modify:
  - `src/main/parser.js`: `parseMany` calls jsonImport first; `applyServerEdits`, `editFields` and `buildShareLink` for JSON servers.
  - `src/main/configBuilder.js`: helpers in full mode, plus `buildRawConfig`.
  - `src/main/subscription.js`: if needed, so a JSON subscription body is read. The reconcile passes already use `raw` and the identity.
  - `src/main/main.js` and `src/server/service.js`:
    - raw-mode connect;
    - `servers:update` answers `{ ok: false, error }` when an edit throws;
    - `servers:link` gives the pretty JSON for a JSON server.
  - `scripts/validate-configs.js`: the fixtures' full and raw configs go through the cores in CI.
- Test: `tests/jsonImport.test.js` (new), `tests/configBuilder.test.js`, `tests/parser.test.js`, `tests/subscription.test.js`, `tests/validateConfigs.test.js`

**Interfaces (produce exactly):**
- `jsonImport.js`:
  - `looksLikeJson(text) → boolean`
  - `importJson(text) → { servers, errors } | null`: `null` = not JSON at all, so parseMany goes on with links.
  - `serversFromXray(config) → server[]`
  - `serversFromSingbox(config) → { servers, errors }`
  - `mainOutboundTag(config) → string | { balancer: string[] } | null`
  - `helperClosure(config, tag) → outbound[]`
  - `jsonInfo(config) → { rules: [{ match: string, to: string }], dns: boolean, balancers: number, observatory: boolean }`: what full mode does not use. It is stored on the record as `jsonInfo`, and is the one extra derived field the UI reads.
- `parser.applyServerEdits(server, { name, jsonMode, json })` for a JSON server:
  - `json` is text or an object; on bad JSON, or no proxy outbound, it throws `Error(<reason>)`;
  - it re-derives `outbound`, `extraOutbounds`, `protocol`, `address`, `port`, `raw` and `jsonInfo`;
  - it records the edited keys in `_edited` as today.
- `parser.buildShareLink(server)` for a JSON server → `JSON.stringify(server.json, null, 2)`.
- `configBuilder.buildRawConfig(server, settings) → config`.
- `buildConfig(plan, settings)`: a JSON server in full mode contributes its helpers. For any plan whose servers are not JSON, the result is byte-identical to today.

- [ ] **Step 1 — failing tests** in `tests/jsonImport.test.js`, reading the fixtures with `fs.readFileSync(path.join(__dirname, 'fixtures/json/<f>'))`:
  - `xray-subscription.json` → 5 servers (vless, ws, tls), names DE-1…US-1, 0 errors. The info rows are not servers.
  - The same text base64-encoded → the same 5 servers.
  - `xray-fragment.json` →
    - 1 server whose `extraOutbounds` is `[fragment]`;
    - `outbound.streamSettings.sockopt.dialerProxy === 'fragment'`;
    - `jsonInfo.rules.length === 3`, `jsonInfo.dns === true`.
  - `xray-chain.json` →
    - the main outbound is the `proxy` vless-reality with mux, kept;
    - `extraOutbounds` tags are exactly `['hop1', 'frag']`.
  - `xray-balancer.json` → 2 servers, `⚖ auto · proxy-1` (vless) and `⚖ auto · proxy-2` (trojan); `jsonInfo.balancers === 1`.
  - `xray-wireguard.json` (an object, no routing) → 1 wireguard server.
  - `singbox.json` →
    - 9 servers (vless-reality, vmess-ws, trojan-grpc, ss, hy2, wg, socks-up, http-up, vless-detour named with ` (via trojan-grpc)`);
    - errors `[{ line: 'tuic', error: 'unsupported protocol: tuic' }]`;
    - each server's outbound equals what the matching share link would parse to: write the link by hand for 3 of them and compare `parseLink(link).outbound` deep-equal.
  - `importJson('proxies:\n  - name: a')` → errors `Clash YAML is not supported — use the subscription link`.
  - `importJson('vless://…')` → `null`.
  - `parseMany(text)` of each fixture → the same servers as `importJson`; `parseMany` of an existing links fixture → unchanged.
- [ ] **Step 2** — run `node --require ./tests/noNetwork.preload.js --test tests/jsonImport.test.js`. It fails: the module is missing.
- [ ] **Step 3** — implement `jsonImport.js`:
  - Server records come from `makeProxyServer`-style helpers in parser.js where they exist; for Xray JSON, build the record directly from the main outbound with the address/port reader configBuilder already has (`serverAddressOf`).
  - Wire it into `parseMany` before the WireGuard/base64 checks:
    ```js
    const j = importJson(body);
    if (j) return j;
    ```
  - Green.
- [ ] **Step 4 — failing tests in `tests/configBuilder.test.js`**:
  - `xray-fragment` in single mode → outbounds `proxy` + `proxy~fragment`, and `proxy.streamSettings.sockopt.dialerProxy === 'proxy~fragment'`.
  - The same server as an advanced-routing target (`out-<id>`) → the helper is `out-<id>~fragment`. Two JSON servers in one config → no tag collision.
  - `xray-chain` → `proxySettings.tag` rewritten to `proxy~hop1`, and hop1's dialerProxy to `proxy~frag`.
  - A JSON server as the 2nd hop of a chain → it dials through hop 1, and none of its helpers are in the config.
  - Under TUN (`directInterface`) the helpers that dial themselves get `sockopt.interface`.
  - `buildRawConfig`:
    - inbounds replaced by the app's own (the same ones buildConfig makes for the settings);
    - `log.loglevel` from settings;
    - routing, dns and balancers deep-equal to the fixture's.
  - A plan with only link servers → deep-equal to the output before the change (keep or extend the golden tests).

  Implement it, then make it green.
- [ ] **Step 5 — the connect paths** (main.js and service.js). In single mode, a JSON server with `jsonMode === 'raw'` builds with `buildRawConfig`.
  - Validation (`xray -test`) and the start stay as they are.
  - DNS/leak-guard pieces that read the config work on what it has.
  - Logged once: `Running "<name>" exactly as written (raw JSON) — the app's DNS management, leak guard and routing mode do not apply`.

  A raw server in chain/advanced/pool → full form, and the log says once: `"<name>" is set to run raw, but a chain/routing target uses its full form`.
  - `servers:update` wraps `applyServerEdits` in try/catch → `{ ok: false, error: e.message, servers }`.
  - `servers:link` → `buildShareLink` (JSON for JSON servers).

  Text-level tests in the style of `tests/connectPath.test.js` where the paths cannot run.
- [ ] **Step 6 — subscription**:
  - a JSON body (as the fixture) through the fetch/parse path → 5 servers;
  - a second refresh with one config's remarks changed → the same ids, and user edits kept (`reconcileServers`);
  - Test in `tests/subscription.test.js`.
- [ ] **Step 7** — `scripts/validate-configs.js`: add the full-mode configs of every fixture server and the raw configs of the Xray fixtures to the shapes run in CI. Update `tests/validateConfigs.test.js`.
- [ ] **Step 8** — `npm test` green. Run the before/after golden: a plan of link servers is byte-identical. Commit(s) in the owner's name with no trailers. Push `feat/json-core`. CI Tests green on all jobs; the `cores` job accepts every JSON shape.

---

### Task J2: JSON servers in the window and the router's web UI

**Files:**
- Modify: `src/renderer/app.js`, `src/renderer/index.html`, `src/renderer/i18n.js`, `src/renderer/lists.css` (or wherever the edit modal is styled)
- Test: `tests/renderer.test.js` (or a new `tests/jsonUi.test.js` in the style of `tests/groupFastest.test.js`)

**Interfaces:**
- **Consumes** (from J1; the record fields arrive through `listServers` / `importServers`):
  - `server.source === 'json'`
  - `server.json` (object)
  - `server.jsonMode` (`'full' | 'raw'`)
  - `server.jsonInfo` (`{ rules: [{ match, to }], dns, balancers, observatory }`)
  - `window.api.updateServer(id, { name, jsonMode, json })` → `{ ok, error?, server, servers }`
  - `window.api.serverLink(id)` → pretty JSON text for a JSON server
- **Produces**: i18n keys `srv.jsonBadge`, `ed.jsonMode`, `ed.jsonFull`, `ed.jsonRaw`, `ed.jsonRawHelp`, `ed.jsonEditor`, `ed.jsonCopy`, `ed.jsonNotApplied`, `ed.jsonInvalid`, `qr.tooLarge` (fa + en).

- [ ] **Step 1 — failing tests:**
  - a JSON server's card shows a `.proto-badge` / badge reading `JSON`;
  - the edit modal for a JSON server:
    - hides the link fields;
    - shows the mode switch (Full/Raw) with `ed.jsonRawHelp`, a `<textarea id="edJson">` holding the pretty JSON, a Copy JSON button, and the not-applied summary built from `jsonInfo` (the count of rules, each `match → to`, plus DNS / balancer / observatory lines when true);
  - save sends `{ name, jsonMode, json }` and shows `error` from a refused save (`ed.jsonInvalid` + the reason) without closing;
  - QR of a JSON server → the minified JSON when ≤ 2,900 bytes, else the `qr.tooLarge` message;
  - the add box passes pasted JSON to `importServers` unchanged (it already does for text — assert nothing filters `{`/`[`);
  - every new key exists in fa and en, with no straight apostrophe inside single quotes.
- [ ] **Step 2** — implement; RTL and LTR both sane; the textarea is monospace and LTR in both languages.
- [ ] **Step 3** — `npm test` green; commit (owner, no trailers); push `feat/json-ui`.

---

### Task J3: Android — the same import, builder and edit sheet

**Files:**
- Create:
  - `android/app/src/main/java/com/irnetfree/vpn/core/JsonImport.kt`
  - `android/app/src/test/java/com/irnetfree/vpn/core/JsonImportTest.kt`
- Modify:
  - `core/Models.kt`: ServerConfig gains `source`, `json`, `extraOutbounds`, `jsonMode` and `jsonInfo`, with defaults so old stores load.
  - `core/LinkParser.kt`: the parse-many entry calls JsonImport first.
  - `core/Subscriptions.kt` / `core/SubRefresh.kt`: a JSON body imports.
  - `core/ConfigBuilder.kt`: helpers with the `<tag>~<helper>` namespacing and chain rule, plus `buildRawConfig`.
  - `vpn/TunnelSetup.kt` / `vpn/XrayVpnService.kt`: a raw server runs its JSON with the app's inbound.
  - `ui/MainActivity.kt`: JSON badge; the edit sheet's mode switch, JSON text, Copy JSON and not-applied lines; copy/QR as on the desktop.
  - `core/Store.kt`: persistence of the new fields.

**Interfaces:**
- Mirror J1's rules exactly:
  - main outbound order, balancer split, helper closure, info rows;
  - sing-box mapping, error texts, `raw` text, full/raw build rules.
- The JVM tests read the shared fixtures through `File("../../tests/fixtures/json/<f>")` (the JVM test working dir is `android/app`). If that path is absent, fail with a message naming it.

- [ ] **Step 1** — JSON import tests first, with the same expectations as J1 Step 1 (counts, names, tags, errors, sing-box mapping), plus ConfigBuilder tests for the full-mode tags, the chain rule and the raw build.
- [ ] **Step 2** — implement JsonImport.kt, the model fields, the parser hook, subscriptions, ConfigBuilder, the raw run path and the UI.
- [ ] **Step 3** — self-review every Kotlin line; push `feat/json-android`; CI `compile android` green (testcases counted); commits in the owner's name, no trailers.

---

### Task J4 (coordinator): integrate, verify live, release

- [ ] Merge J1, J2 and J3 into `feat/json-configs`; `npm test`; golden byte-identical for link servers.
- [ ] Live, on this machine:
  - import the owner's subscription URL through the headless server (temp data dir, port 8766) → 38 servers and no info rows;
  - one full-mode and one raw-mode connect test of a server through a throwaway core bound to Wi-Fi (`irnf-echtest`-style), with the owner's app untouched;
  - a UI check of the badge, the edit modal and the mode switch.
- [ ] One quick review pass; CI Tests green; merge to `main` `--no-ff`; tag the next minor (`v1.19.0`); release body in the 3x-ui style; report to the owner in Persian.
