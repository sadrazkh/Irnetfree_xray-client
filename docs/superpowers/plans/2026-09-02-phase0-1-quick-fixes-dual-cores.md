# Phase 0 + 1 — Quick fixes and dual Xray cores — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the ten review fixes and make the app run a config on either the official Xray core or the patterniha fork (`xray-pattn`), chosen per config, both downloadable from Settings.

**Architecture:** Every change lives in the existing module layout: pure helpers (`src/main/assets.js`, `src/main/engineChoice.js`, `src/server/guard.js`) are new so they can be unit-tested; `main.js` and `service.js` only wire them. The engine registry (`engines.js`) already models cores as data — the fork is one more entry with a different GitHub repo and exe name. No new dependencies.

**Tech Stack:** Node 18+ core only (no npm runtime deps), Electron 31 for desktop, `node --test` for tests, PowerShell/netsh untouched in this plan.

**Model per task:** see `docs/superpowers/plans/2026-09-02-model-assignment.md` — every task here is Opus-implemented (run the orchestrating session on Opus too); tasks 9, 13, 14 get one Fable review pass at the end.

## Global Constraints

- Runtime code uses only Node core modules; `package.json` dependencies stay empty (spec §1 / README "هیچ وابستگی npm").
- Tests: `node --test "tests/*.test.js"` must stay green (114 tests today). Every task adds or keeps tests.
- Commits are in the repository owner's name only — **no `Co-Authored-By` trailer**.
- Every new `RECONNECT_KEYS` entry needs `set.<key>` in **both** `fa` and `en` blocks of `src/renderer/i18n.js` (enforced by `tests/settingsMeta.test.js`).
- `src/server/service.js` mirrors `src/main/main.js`; any handler changed in one is changed in the other.
- Android (`android/`) is **not** touched in this plan (spec phase 8).
- Exe names: official core `xray(.exe)`, fork `xray-pattn(.exe)`; fork repo `patterniha/Xray-core`, same release asset names as `XTLS/Xray-core` (`Xray-windows-64.zip`, `Xray-macos-arm64-v8a.zip`, …).
- Renderer changes are verified in the browser through the headless server (`node src/server/server.js`), which serves the identical UI — see the "Verify in browser" steps.

---

## File map

| File | Responsibility | Tasks |
|---|---|---|
| `src/renderer/styles.css` | dropdown row sizing | 1 |
| `src/server/guard.js` (new) | Host / Origin request guards (pure) | 2 |
| `src/server/server.js`, `src/server/service.js` | wire guards, `allowLan` default, engine handlers | 2, 4, 13, 15 |
| `src/main/configBuilder.js` | pool reserves `apiPort` | 3 |
| `src/main/assets.js` (new) | component presence, shared by main + service | 4 |
| `src/main/parser.js` | `http://` proxy links | 5 |
| `src/renderer/app.js` | smartImport, `saveSettings` partials, custom-rules card, geo note, engine UI | 5, 6, 7, 10, 15 |
| `src/main/downloader.js` | temp cleanup, per-engine Xray download | 8, 12 |
| `src/main/netutils.js` | SOCKS5 reply buffering | 9 |
| `src/main/engines.js` | `xray-pattn` entry, `repo`, `xrayEngines()` | 11 |
| `src/main/xrayManager.js` | per-engine version, cross-engine fallback, `validateWithFallback` | 13 |
| `src/main/engineChoice.js` (new) | which core runs a plan (pure) | 14 |
| `src/main/main.js` | engine choice, fallback, status `engine`, IPC | 4, 13, 14, 15 |
| `src/main/settingsMeta.js`, `src/renderer/i18n.js`, `src/renderer/index.html`, `src/preload/preload.js`, `src/server/web-api.js` | `defaultEngine` setting, strings, UI | 15 |
| `README.md`, `.github/workflows/test.yml` (new) | docs, CI test matrix | 16 |

---

### Task 1: Dropdown rows squash instead of scrolling

**Files:**
- Modify: `src/renderer/styles.css` (`.pool-item` ≈ line 554, `.ss-item` ≈ line 612)

**Why:** `.ss-list` and `.chain-pool` are `display:flex; flex-direction:column; max-height:…; overflow-y:auto`. Flex children default to `flex-shrink:1`, so when the content exceeds the max height the rows shrink to fit and clip their text (the owner's screenshot) instead of overflowing into the scrollbar.

- [ ] **Step 1: Add `flex: 0 0 auto` to both row classes**

In `src/renderer/styles.css`, change:

```css
.pool-item {
  display: flex; align-items: center; gap: 10px; width: 100%;
```
to
```css
.pool-item {
  display: flex; align-items: center; gap: 10px; width: 100%;
  flex: 0 0 auto;   /* .chain-pool is a flex column with max-height: never shrink rows, scroll instead */
```
and
```css
.ss-item {
  padding: 8px 10px; border-radius: 8px; cursor: pointer; font-size: 13px;
```
to
```css
.ss-item {
  flex: 0 0 auto;   /* .ss-list is a flex column with max-height: never shrink rows, scroll instead */
  padding: 8px 10px; border-radius: 8px; cursor: pointer; font-size: 13px;
```

- [ ] **Step 2: Verify in browser**

Start the headless UI with a throwaway data dir and seed 14 servers so the target dropdown overflows:

```bash
mkdir -p /tmp/irnf-ui && node src/server/server.js --port 6969 --data-dir /tmp/irnf-ui &
sleep 1
for i in $(seq 1 14); do curl -s -X POST http://127.0.0.1:6969/rpc -H 'Content-Type: application/json' \
  -d "{\"channel\":\"servers:add\",\"arg\":\"vless://00000000-0000-4000-8000-00000000000$i@srv$i.example.com:443?security=tls#Server-$i\"}" >/dev/null; done
```
Open `http://127.0.0.1:6969/` in the Browser pane → Routing → turn on "Advanced routing" → "+ Add rule" → click the target dropdown. Expected: 14 fully readable rows, list scrolls. Take a screenshot. Also open Chain → "+ New chain": the "Available servers" list scrolls with full rows. Stop the server (`kill %1`).

- [ ] **Step 3: Commit**

```bash
git add src/renderer/styles.css
git commit -m "UI: searchable dropdown and chain pool rows scroll instead of squashing"
```

---

### Task 2: Headless server — loopback-only proxy ports and cross-origin guard

**Files:**
- Create: `src/server/guard.js`
- Test: `tests/guard.test.js`
- Modify: `src/server/server.js` (request router, top of handler and the `/rpc` + `/events` branches)
- Modify: `src/server/service.js:35` (`allowLan`)

**Interfaces:**
- Produces: `hostAllowed(hostHeader, { token, noAuth }) → boolean`, `originAllowed(headers) → boolean`, `hostnameOf(hostHeader) → string`

- [ ] **Step 1: Write the failing tests**

`tests/guard.test.js`:

```js
'use strict';
/**
 * Request guards for the headless panel. Both attacks are possible in the
 * recommended setup (bound to 127.0.0.1, no token): any web page can POST to
 * /rpc cross-origin, and DNS rebinding turns "127.0.0.1" into "attacker.example".
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { hostAllowed, originAllowed, hostnameOf } = require('../src/server/guard');

test('hostnameOf strips the port and lower-cases, keeps IPv6 brackets', () => {
  assert.equal(hostnameOf('127.0.0.1:6969'), '127.0.0.1');
  assert.equal(hostnameOf('LocalHost'), 'localhost');
  assert.equal(hostnameOf('[::1]:6969'), '[::1]');
  assert.equal(hostnameOf(undefined), '');
});

test('without a token only loopback Host values are accepted', () => {
  for (const h of ['127.0.0.1:6969', 'localhost:8080', '[::1]:6969', 'localhost']) {
    assert.equal(hostAllowed(h, {}), true, h);
  }
  // DNS rebinding: the browser resolved attacker.example to 127.0.0.1
  assert.equal(hostAllowed('attacker.example:6969', {}), false);
  assert.equal(hostAllowed('', {}), false);
});

test('a token (or --no-auth) lifts the Host restriction', () => {
  assert.equal(hostAllowed('203.0.113.9:6969', { token: 'abc' }), true);
  assert.equal(hostAllowed('203.0.113.9:6969', { noAuth: true }), true);
});

test('browser requests must come from the panel’s own origin', () => {
  const host = '127.0.0.1:6969';
  assert.equal(originAllowed({ host, origin: 'http://127.0.0.1:6969' }), true);
  assert.equal(originAllowed({ host, referer: 'http://127.0.0.1:6969/?token=x' }), true);
  assert.equal(originAllowed({ host, origin: 'https://evil.example' }), false);
  assert.equal(originAllowed({ host, referer: 'not a url' }), false);
  // a forwarded port: the page was opened on 8080, so Host and Origin agree on 8080
  assert.equal(originAllowed({ host: '127.0.0.1:8080', origin: 'http://127.0.0.1:8080' }), true);
});

test('non-browser clients (no Origin/Referer) pass the origin guard', () => {
  assert.equal(originAllowed({ host: '127.0.0.1:6969' }), true);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test tests/guard.test.js`
Expected: FAIL — `Cannot find module '../src/server/guard'`

- [ ] **Step 3: Implement `src/server/guard.js`**

```js
'use strict';
/**
 * Request guards for the headless server — pure functions so they are testable
 * without binding a port.
 *
 * Two attacks these stop, both possible in the recommended setup (bound to
 * 127.0.0.1 with no token):
 *  - cross-site requests: any web page can POST to http://127.0.0.1:6969/rpc
 *    with a CORS-simple body (text/plain, no preflight) and drive the panel.
 *    Browser requests carry Origin (fetch/XHR) or Referer (EventSource); either
 *    must be the panel's own origin.
 *  - DNS rebinding: a page on attacker.example that resolves to 127.0.0.1 makes
 *    the browser send `Host: attacker.example`, which would also let it READ
 *    responses. Without a token we only accept loopback Host values.
 */
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

/** "host:port" → "host" (lower-case). IPv6 keeps its brackets: "[::1]:1" → "[::1]". */
function hostnameOf(hostHeader) {
  if (!hostHeader) return '';
  const h = String(hostHeader).trim();
  if (h.startsWith('[')) return h.slice(0, h.indexOf(']') + 1).toLowerCase();
  const i = h.lastIndexOf(':');
  return (i === -1 ? h : h.slice(0, i)).toLowerCase();
}

/**
 * A token is the authentication when one is set (public bind); --no-auth is the
 * user's explicit choice to run open. Otherwise only loopback hosts are valid —
 * the port is deliberately ignored so an `ssh -L 8080:127.0.0.1:6969` forward
 * still works.
 */
function hostAllowed(hostHeader, { token, noAuth } = {}) {
  if (token || noAuth) return true;
  return LOOPBACK.has(hostnameOf(hostHeader));
}

/** Origin (or Referer) must match the Host the request arrived on. */
function originAllowed(headers) {
  const raw = headers.origin || headers.referer;
  if (!raw) return true;                       // curl / scripts: token or loopback protects them
  let origin;
  try { origin = new URL(raw); } catch { return false; }
  return origin.host.toLowerCase() === String(headers.host || '').toLowerCase();
}

module.exports = { hostAllowed, originAllowed, hostnameOf };
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test tests/guard.test.js`
Expected: `# pass 5`

- [ ] **Step 5: Wire the guards into `src/server/server.js`**

Add the import after `const { createService } = require('./service');`:

```js
const { hostAllowed, originAllowed } = require('./guard');
```

At the very top of the request handler (first lines inside `http.createServer(async (req, res) => {`), before `const url = …`:

```js
  // DNS-rebinding guard: without a token only loopback Host values are served.
  if (!hostAllowed(req.headers.host, { token: TOKEN, noAuth: args.noAuth })) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    return res.end('forbidden host');
  }
```

In the `/rpc` branch, right after the `authed` check:

```js
    if (!originAllowed(req.headers)) return sendJson(res, 403, { error: 'cross-origin request refused' });
```

In the `/events` branch, right after its `authed` check:

```js
    if (!originAllowed(req.headers)) return sendJson(res, 403, { error: 'cross-origin request refused' });
```

- [ ] **Step 6: Make the headless proxy ports loopback-only by default**

In `src/server/service.js` replace:

```js
  allowLan: true,            // headless: listen on 0.0.0.0 so forwarded ports are reachable
```
with
```js
  allowLan: false,           // loopback only, like the desktop. `ssh -L` reaches a loopback
                             // bind fine; 0.0.0.0 would make the auth-less SOCKS port an
                             // open relay on a VPS. The user opts in under Settings → LAN.
```

- [ ] **Step 7: Verify by hand**

```bash
node src/server/server.js --port 6969 --data-dir /tmp/irnf-ui &
sleep 1
# same-origin browser request → 200
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:6969/rpc -H 'Origin: http://127.0.0.1:6969' -H 'Content-Type: application/json' -d '{"channel":"settings:get"}'
# cross-origin → 403
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:6969/rpc -H 'Origin: https://evil.example' -H 'Content-Type: text/plain' -d '{"channel":"settings:get"}'
# rebinding → 403
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:6969/rpc -H 'Host: attacker.example:6969' -d '{"channel":"settings:get"}'
kill %1
```
Expected: `200`, `403`, `403`. Then open `http://127.0.0.1:6969/` in the Browser pane: the page loads and the Logs tab receives events (EventSource passes the origin guard).

- [ ] **Step 8: Run the whole suite and commit**

Run: `node --test "tests/*.test.js"` → Expected: all pass (119).

```bash
git add src/server/guard.js src/server/server.js src/server/service.js tests/guard.test.js
git commit -m "Headless: refuse cross-origin and rebinding requests; proxy ports loopback-only by default"
```

---

### Task 3: Pool config reserves the API port

**Files:**
- Modify: `src/main/configBuilder.js:304-345` (`buildPoolConfig`)
- Modify: `src/renderer/app.js:2054-2063` (`usedPoolPorts`)
- Test: `tests/configBuilder.test.js` (pool section)

- [ ] **Step 1: Write the failing test**

Append to the `/* --- proxy pool --- */` section of `tests/configBuilder.test.js`:

```js
test('pool: a pool port equal to apiPort is skipped so the api inbound keeps its port', () => {
  const c = buildConfig(poolPlan([
    { id: 'clash', target: 'sv-trojan', socksPort: 10085 },   // == apiPort
    { id: 'ok', target: 'sv-trojan', socksPort: 60001 }
  ]), settings({ apiPort: 10085 }));

  const ports = c.inbounds.map(i => i.port);
  assert.equal(new Set(ports).size, ports.length, 'a port is bound twice');
  assert.deepEqual(c.inbounds.map(i => i.tag), ['socks-in', 'http-in', 'ps-ok', 'api']);
  assert.equal(c.inbounds.find(i => i.tag === 'api').port, 10085);
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `node --test tests/configBuilder.test.js`
Expected: FAIL — `a port is bound twice` (both `ps-clash` and `api` on 10085).

- [ ] **Step 3: Reserve `apiPort` before any entry is added**

In `buildPoolConfig`, replace:

```js
  const inbounds = [];
  const usedPorts = new Set();
```
with
```js
  const inbounds = [];
  // The api inbound is pushed last but must win: reserve its port up front so a
  // pool entry cannot take it (xray refuses to start on a duplicate bind).
  const usedPorts = new Set([parseInt(s.apiPort, 10)]);
```

- [ ] **Step 4: Mirror the reservation in the renderer’s port picker**

In `src/renderer/app.js` `usedPoolPorts()`, after the `hp` line add:

```js
  const ap = parseInt(state.settings.apiPort, 10); if (ap) set.add(ap);   // api inbound (configBuilder reserves it too)
```

- [ ] **Step 5: Run the tests and commit**

Run: `node --test tests/configBuilder.test.js` → Expected: pass.

```bash
git add src/main/configBuilder.js src/renderer/app.js tests/configBuilder.test.js
git commit -m "Pool: reserve the api port before assigning entry ports"
```

---

### Task 4: One `assetStatus()` for desktop and headless

**Files:**
- Create: `src/main/assets.js`
- Test: `tests/assets.test.js`
- Modify: `src/main/engines.js:41-45` (`engineExe` gets a platform parameter)
- Modify: `src/main/main.js:92-106` (`assetStatus`)
- Modify: `src/server/service.js:107-119` (`binDirs`/`assetStatus`)

**Interfaces:**
- Produces: `assetStatus(dirs: string[], platform?: string) → { platform, xray, 'sing-box', tun2socks, wintun, geoip, geosite }` — one boolean per engine id in `ENGINES` plus the four fixed components. (Task 11 adds `'xray-pattn'` to `ENGINES`; this function picks it up without change.)
- `engineExe(id, platform = process.platform)`

- [ ] **Step 1: Write the failing test**

`tests/assets.test.js`:

```js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { assetStatus } = require('../src/main/assets');

function withDirs(fn) {
  const a = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-bin-a-'));
  const b = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-bin-b-'));
  try { return fn(a, b); } finally { fs.rmSync(a, { recursive: true, force: true }); fs.rmSync(b, { recursive: true, force: true }); }
}

test('reports every engine and component, searching all dirs', () => {
  withDirs((a, b) => {
    fs.writeFileSync(path.join(a, 'xray.exe'), '');
    fs.writeFileSync(path.join(b, 'sing-box.exe'), '');
    fs.writeFileSync(path.join(b, 'geoip.dat'), '');
    const st = assetStatus([a, b], 'win32');
    assert.equal(st.platform, 'win32');
    assert.equal(st.xray, true);
    assert.equal(st['sing-box'], true);      // main.js reported this, service.js forgot it
    assert.equal(st.tun2socks, false);
    assert.equal(st.wintun, false);
    assert.equal(st.geoip, true);
    assert.equal(st.geosite, false);
  });
});

test('uses the platform’s executable names and treats wintun as present off Windows', () => {
  withDirs((a) => {
    fs.writeFileSync(path.join(a, 'xray'), '');
    fs.writeFileSync(path.join(a, 'tun2socks'), '');
    const st = assetStatus([a], 'darwin');
    assert.equal(st.xray, true);
    assert.equal(st.tun2socks, true);
    assert.equal(st.wintun, true);
    assert.equal(assetStatus([a], 'win32').xray, false, 'xray.exe is the Windows name');
  });
});

test('ignores empty / missing dirs', () => {
  const st = assetStatus(['', null, '/definitely/not/here'], 'linux');
  assert.equal(st.xray, false);
  assert.equal(st.geosite, false);
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `node --test tests/assets.test.js` → Expected: FAIL — `Cannot find module '../src/main/assets'`

- [ ] **Step 3: Let `engineExe` take a platform**

In `src/main/engines.js` replace:

```js
/** Executable file name for an engine on the current platform. */
function engineExe(id) {
  const e = engine(id);
  return e.exe[process.platform] || e.exe.default;
}
```
with
```js
/** Executable file name for an engine on a platform (default: the current one). */
function engineExe(id, platform = process.platform) {
  const e = engine(id);
  return e.exe[platform] || e.exe.default;
}
```

- [ ] **Step 4: Create `src/main/assets.js`**

```js
'use strict';
/**
 * Presence of each runtime component. Shared by the desktop main process and
 * the headless service so the two can never disagree about what is installed
 * (the headless copy used to omit sing-box, so the UI showed it "missing" for
 * ever after a successful download).
 */
const fs = require('fs');
const path = require('path');
const { ENGINES, engineExe } = require('./engines');

/**
 * @param {string[]} dirs  bin directories to search, writable first, bundled last
 * @param {string} [platform] process.platform value (injectable for tests)
 */
function assetStatus(dirs, platform = process.platform) {
  const has = (name) => dirs.some(d => d && fs.existsSync(path.join(d, name)));
  const win = platform === 'win32';
  const out = { platform };
  for (const id of Object.keys(ENGINES)) out[id] = has(engineExe(id, platform));
  out.tun2socks = has(win ? 'tun2socks.exe' : 'tun2socks');
  out.wintun = win ? has('wintun.dll') : true;
  out.geoip = has('geoip.dat');
  out.geosite = has('geosite.dat');
  return out;
}

module.exports = { assetStatus };
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `node --test tests/assets.test.js` → Expected: `# pass 3`

- [ ] **Step 6: Use it in `main.js`**

Add the import next to the other `./` requires:

```js
const { assetStatus: scanAssets } = require('./assets');
```

Replace the whole `assetStatus()` function (lines 92–106) with:

```js
/** Presence of each runtime component (checks writable + bundled dirs). */
function assetStatus() {
  const st = scanAssets([userBin(), bundledBinDir()]);
  // a user-located xray (store.xrayPath / XRAY_PATH) counts too
  if (xray) st.xray = st.xray || xray.binExists('xray');
  return st;
}
```
(`xray.binExists('xray')` takes an engine id from Task 13; until then `binExists()` ignores the argument — both compile.)

- [ ] **Step 7: Use it in `service.js`**

Add the import next to the other `../main/` requires:

```js
const { assetStatus: scanAssets } = require('../main/assets');
```

Replace `function binDirs() {…}` and `function assetStatus() {…}` (lines 107–119) with:

```js
  function binDirs() { return [userBinDir, bundledBinDir]; }
  function assetStatus() {
    const st = scanAssets(binDirs());
    if (xray) st.xray = st.xray || xray.binExists('xray');
    return st;
  }
```

- [ ] **Step 8: Run the suite and commit**

Run: `node --test "tests/*.test.js"` → Expected: all pass.

```bash
git add src/main/assets.js src/main/engines.js src/main/main.js src/server/service.js tests/assets.test.js
git commit -m "Share one assetStatus() between desktop and headless (sing-box was missing headless)"
```

---

### Task 5: `http://` proxy share links import again

**Files:**
- Modify: `src/main/parser.js:343-407` (`parseSocks`), `parseLink`, `parseMany`, exports
- Modify: `src/renderer/app.js:733-738` (`smartImport`)
- Test: `tests/parser.test.js`

**Interfaces:**
- Produces: `isHttpProxyLink(line) → boolean` (exported from parser.js), `parseLink('http://…')` for proxy-shaped links.

- [ ] **Step 1: Write the failing tests**

In `tests/parser.test.js` extend the import to include `buildShareLink` and `isHttpProxyLink`:

```js
const {
  parseLink, parseMany, b64decode,
  buildStreamSettings, buildWireguardOutbound,
  makeWireguardServer, makeProxyServer, applyServerEdits,
  buildShareLink, isHttpProxyLink
} = require('../src/main/parser');
```

Append to the `/* --- SOCKS --- */` section:

```js
test('http proxy share link round-trips (v2rayN shape)', () => {
  const s = makeProxyServer({ name: 'Corp', type: 'http', address: 'proxy.corp', port: '3128', username: 'u', password: 'p' });
  const link = buildShareLink(s);
  assert.match(link, /^http:\/\/[A-Za-z0-9+/=]+@proxy\.corp:3128#Corp$/);
  const back = parseLink(link);
  assert.equal(back.protocol, 'http');
  assert.equal(back.name, 'Corp');
  assert.deepEqual(back.outbound.settings.servers[0], { address: 'proxy.corp', port: 3128, users: [{ user: 'u', pass: 'p' }] });

  const open = parseLink('http://10.0.0.9:8080#Open');
  assert.equal(open.outbound.protocol, 'http');
  assert.equal(open.outbound.settings.servers[0].users, undefined);
});

test('isHttpProxyLink: only host:port shapes, never subscription URLs', () => {
  assert.equal(isHttpProxyLink('http://1.2.3.4:8080'), true);
  assert.equal(isHttpProxyLink('http://dXNlcjpwYXNz@1.2.3.4:8080#Corp'), true);
  assert.equal(isHttpProxyLink('http://panel.example.com/sub/abc123'), false);
  assert.equal(isHttpProxyLink('http://1.2.3.4:8080/?token=x'), false);
  assert.equal(isHttpProxyLink('https://1.2.3.4:8080'), false);
  assert.equal(isHttpProxyLink('http://1.2.3.4'), false);
});

test('parseMany imports http proxy links and skips subscription URLs', () => {
  const { servers } = parseMany([
    'http://dXNlcjpwYXNz@1.2.3.4:8080#Corp',
    'http://panel.example.com/sub/abc123',
    'vless://u1@a.example.com:443#A'
  ].join('\n'));
  assert.deepEqual(servers.map(s => s.protocol), ['http', 'vless']);
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `node --test tests/parser.test.js` → Expected: FAIL — `isHttpProxyLink is not a function` / `Unsupported or invalid link: http://…`

- [ ] **Step 3: Generalise `parseSocks` into `parseProxyLink`**

In `src/main/parser.js` replace the `parseSocks` function (from its doc comment down to its closing brace) with:

```js
/**
 * v2rayN shares an HTTP proxy exactly like a SOCKS one —
 * `http://[b64(user:pass)@]host:port#name` — which is also the shape of a plain
 * subscription URL's origin. A proxy link therefore has NO path and NO query.
 * (Kept in sync with the copy in src/renderer/app.js smartImport.)
 */
const HTTP_PROXY_LINK = /^http:\/\/(?:[^/?#\s@]+@)?[^/?#\s@]+:\d{1,5}(?:#\S*)?$/i;
function isHttpProxyLink(s) { return HTTP_PROXY_LINK.test(String(s || '').trim()); }

/**
 * Parse a socks:// / socks5:// / http:// proxy link. Tolerant of several shapes:
 *   scheme://host:port#name
 *   scheme://user:pass@host:port#name
 *   scheme://base64(user:pass)@host:port#name
 *   scheme://base64(user:pass@host:port)#name
 */
function parseProxyLink(link, proto) {
  const scheme = link.slice(0, link.indexOf('://') + 3);
  const body = link.slice(scheme.length);
  const hashIdx = body.indexOf('#');
  const name = hashIdx === -1 ? '' : safeDecodeURIComponent(body.slice(hashIdx + 1));
  let main = hashIdx === -1 ? body : body.slice(0, hashIdx);
  const qIdx = main.indexOf('?');
  if (qIdx !== -1) main = main.slice(0, qIdx);   // ignore any query params

  let user = '', pass = '', address, portStr;

  const splitCreds = (raw) => {
    const ci = raw.indexOf(':');
    if (ci === -1) { user = raw; pass = ''; }
    else { user = raw.slice(0, ci); pass = raw.slice(ci + 1); }
  };

  if (main.includes('@')) {
    const atIdx = main.lastIndexOf('@');
    const userInfo = main.slice(0, atIdx);
    const hostPart = main.slice(atIdx + 1);
    // userInfo may be plain "user:pass" or a base64 of it
    const decoded = userInfo.includes(':') ? userInfo : (b64decode(userInfo) || userInfo);
    splitCreds(decoded);
    [address, portStr] = splitHostPort(hostPart);
  } else {
    // whole thing may be base64(user:pass@host:port) or just host:port
    const decoded = b64decode(main);
    if (decoded && decoded.includes('@')) {
      const atIdx = decoded.lastIndexOf('@');
      splitCreds(decoded.slice(0, atIdx));
      [address, portStr] = splitHostPort(decoded.slice(atIdx + 1));
    } else {
      [address, portStr] = splitHostPort(main);
    }
  }
  const port = parseInt(portStr, 10) || (proto === 'http' ? 8080 : 1080);
  const outbound = buildProxyOutbound(proto, address, port, safeDecodeURIComponent(user), safeDecodeURIComponent(pass));
  return mkServer(name || address, proto, address, port, link, outbound);
}

function parseSocks(link) { return parseProxyLink(link, 'socks'); }
function parseHttpProxy(link) { return parseProxyLink(link, 'http'); }
```

- [ ] **Step 4: Route `http://` proxy links in `parseLink` and `parseMany`**

In `parseLink`, before the `throw`:

```js
  if (l.startsWith('http://') && isHttpProxyLink(l)) return parseHttpProxy(l);
```

In `parseMany`, replace the loop's scheme test:

```js
    if (!/^(vless|vmess|trojan|ss|socks|socks5|wireguard|wg):\/\//i.test(line)) continue;
```
with
```js
    if (!/^(vless|vmess|trojan|ss|socks|socks5|wireguard|wg):\/\//i.test(line) && !isHttpProxyLink(line)) continue;
```

Add `isHttpProxyLink` to `module.exports`:

```js
module.exports = {
  parseLink, parseMany, b64decode, isHttpProxyLink,
  buildStreamSettings, buildWireguardOutbound, makeWireguardServer, makeProxyServer, applyServerEdits,
  buildShareLink
};
```

- [ ] **Step 5: Run the parser tests**

Run: `node --test tests/parser.test.js` → Expected: pass (all, including the three new ones).

- [ ] **Step 6: Teach `smartImport` the difference**

In `src/renderer/app.js`, above `async function smartImport(text)` add:

```js
// v2rayN-style HTTP proxy share link (`http://[b64creds@]host:port#name`): no
// path, no query. Everything else that starts with http(s):// is a subscription.
// Keep in sync with HTTP_PROXY_LINK in src/main/parser.js.
const HTTP_PROXY_LINK = /^http:\/\/(?:[^/?#\s@]+@)?[^/?#\s@]+:\d{1,5}(?:#\S*)?$/i;
```

and inside `smartImport` replace:

```js
  const urlLines = lines.filter(l => /^https?:\/\//i.test(l));
  const configText = lines.filter(l => !/^https?:\/\//i.test(l)).join('\n');
```
with
```js
  const isSubUrl = (l) => /^https?:\/\//i.test(l) && !HTTP_PROXY_LINK.test(l);
  const urlLines = lines.filter(isSubUrl);
  const configText = lines.filter(l => !isSubUrl(l)).join('\n');
```

- [ ] **Step 7: Verify in browser**

Start the headless server as in Task 1, open the UI → Servers → "+ SOCKS/HTTP" → type HTTP, host `proxy.corp`, port `3128`, user `u`, pass `p` → Add. Click ⧉ on the card, then "+ افزودن", paste, Import. Expected: a second `http` server appears (not a subscription), toast "1 servers added".

- [ ] **Step 8: Commit**

```bash
git add src/main/parser.js src/renderer/app.js tests/parser.test.js
git commit -m "Parser: accept http:// proxy share links so HTTP proxies round-trip through copy/QR"
```

---

### Task 6: `saveSettings()` sends only what changed

**Files:**
- Modify: `src/renderer/app.js:289-323` (`saveSettings`) and every caller listed below

**Why:** `saveSettings()` reads all ten Settings-page inputs from the DOM on every call, so "Save routing" on the Routing page also persists a half-typed SOCKS port from the Settings page.

- [ ] **Step 1: Split form reading from saving**

Replace the `saveSettings` function (its doc comment through its closing brace) with:

```js
/** The Settings page form → settings partial. Only the "Save settings" button uses it. */
function readSettingsForm() {
  return {
    socksPort: parseInt($('#socksPort').value, 10) || 10808,
    httpPort: parseInt($('#httpPort').value, 10) || 10809,
    dns: dnsFromInput(),
    logLevel: $('#logLevel').value,
    systemProxy: $('#optSysProxy').checked,
    tunMode: $('#optTun').checked,
    allowLan: $('#optAllowLan').checked,
    killSwitch: $('#optKillSwitch').checked,
    blockAds: $('#optBlockAds').checked,
    enableSniffing: $('#optSniff').checked
  };
}
function dnsFromInput() {
  return $('#dnsInput').value.split(',').map(s => s.trim()).filter(Boolean);
}

/**
 * Persist a settings partial — ONLY the keys the caller changed. Reading the
 * whole Settings form here used to persist abandoned edits from other pages.
 *
 * Most settings are baked into the running xray config (or applied as a
 * connect-time side effect), so while connected they do NOTHING until the tunnel
 * is rebuilt. Main reports exactly which ones are in that state; we then ask the
 * user instead of leaving the UI claiming a change that isn't live.
 *
 * `silent: true` skips the prompt (the caller shows its own), but the pending
 * state is still recorded so the banner stays accurate.
 */
async function saveSettings(partial = {}, { silent = false } = {}) {
  const res = await window.api.setSettings(partial);
  // main returns { settings, pendingReconnect }; tolerate the older bare shape
  state.settings = (res && res.settings) ? res.settings : res;
  setPending((res && res.pendingReconnect) || []);

  if (!silent && state.pendingReconnect.length) await promptApplySettings();
  return state.pendingReconnect;
}
```

- [ ] **Step 2: Update every caller to pass its own key**

| Location (current code) | Replace with |
|---|---|
| `$('#btnSaveSettings').onclick` → `await saveSettings();` | `await saveSettings(readSettingsForm());` |
| `$('#optBlockAds').onchange = () => saveSettings();` | `$('#optBlockAds').onchange = () => saveSettings({ blockAds: $('#optBlockAds').checked });` |
| `$('#optSniff').onchange = () => saveSettings();` | `$('#optSniff').onchange = () => saveSettings({ enableSniffing: $('#optSniff').checked });` |
| dnsPreset: `if (v) { $('#dnsInput').value = v; saveSettings(); toast(…) }` | `if (v) { $('#dnsInput').value = v; saveSettings({ dns: dnsFromInput() }); toast(t('dns.set'), 'ok'); }` |
| optKillSwitch: `await saveSettings();` | `await saveSettings({ killSwitch: $('#optKillSwitch').checked });` |
| optAllowLan: `await saveSettings();` | `await saveSettings({ allowLan: $('#optAllowLan').checked });` |
| optTun: `await saveSettings({}, { silent: true });` | `await saveSettings({ tunMode: on }, { silent: true });` |

The remaining callers (`setLang`, routing segment, `btnSaveRules`, `optAutoUpdate`, `autoInterval`, `optAdvanced`, `optProcWatch`, `btnSaveAdv`, the mode modal) already pass a partial and stay as they are.

- [ ] **Step 3: Verify in browser**

Headless server as in Task 1. Settings → type `1080` into "SOCKS port", do **not** save. Routing → click "Bypass Iran". Then:

```bash
grep -E '"socksPort"|"routingMode"' /tmp/irnf-ui/store.json
```
Expected: `"socksPort": 10808` (unchanged) and `"routingMode": "bypass-ir"`. Now Settings → "Save settings": `socksPort` becomes 1080.

- [ ] **Step 4: Commit**

```bash
git add src/renderer/app.js
git commit -m "Renderer: saveSettings persists only the keys the caller changed"
```

---

### Task 7: Hide the custom-rules card while advanced routing is on

**Files:**
- Modify: `src/renderer/app.js` (`renderAdvanced`, ≈ line 2265)

**Why:** `configBuilder.js` ignores `customRules` in the advanced branch, but the card stays editable and even triggers the "reconnect to apply" dialog.

- [ ] **Step 1: Toggle the card from `renderAdvanced()`**

Right after `if (body) body.hidden = !state.settings.advancedRouting;` add:

```js
  // custom rules only apply to the simple modes (configBuilder ignores them under
  // advanced routing) — don't show an editor for something that has no effect
  const simple = $('#simpleRulesCard');
  if (simple) simple.hidden = !!state.settings.advancedRouting;
```

- [ ] **Step 2: Verify in browser**

Routing → toggle "Advanced routing" on: the "Custom rules" card disappears; off: it returns.

- [ ] **Step 3: Commit**

```bash
git add src/renderer/app.js
git commit -m "Routing: hide the custom-rules card under advanced routing (it is not applied there)"
```

---

### Task 8: Downloader cleans up after a non-200 response

**Files:**
- Modify: `src/main/downloader.js:37-57` (`downloadFile`), exports
- Test: `tests/downloader.test.js`

**Interfaces:**
- Produces: `downloadFile(url, dest, onProgress) → Promise<string>` exported (http:// accepted so tests can use a local server).

- [ ] **Step 1: Write the failing test**

`tests/downloader.test.js`:

```js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { downloadFile } = require('../src/main/downloader');

function serve(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, '127.0.0.1', () => resolve({ srv, port: srv.address().port }));
  });
}

test('a non-200 response rejects and leaves no temp file behind', async () => {
  const { srv, port } = await serve((req, res) => { res.writeHead(403); res.end('rate limited'); });
  const dest = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-dl-')), 'geoip.dat.tmp');
  try {
    await assert.rejects(downloadFile(`http://127.0.0.1:${port}/geoip.dat`, dest), /HTTP 403/);
    assert.equal(fs.existsSync(dest), false, 'temp file must be removed');
  } finally { srv.close(); }
});

test('a 200 response is written in full and reports progress', async () => {
  const body = Buffer.alloc(100000, 7);
  const { srv, port } = await serve((req, res) => { res.writeHead(200, { 'Content-Length': body.length }); res.end(body); });
  const dest = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-dl-')), 'file.bin');
  const seen = [];
  try {
    await downloadFile(`http://127.0.0.1:${port}/file.bin`, dest, (p) => seen.push(p));
    assert.equal(fs.readFileSync(dest).length, body.length);
    assert.equal(seen.at(-1), 100);
  } finally { srv.close(); }
});

test('redirects are followed', async () => {
  const { srv, port } = await serve((req, res) => {
    if (req.url === '/a') { res.writeHead(302, { Location: `http://127.0.0.1:${port}/b` }); return res.end(); }
    res.writeHead(200); res.end('ok');
  });
  const dest = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-dl-')), 'r.txt');
  try {
    await downloadFile(`http://127.0.0.1:${port}/a`, dest);
    assert.equal(fs.readFileSync(dest, 'utf8'), 'ok');
  } finally { srv.close(); }
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/downloader.test.js` → Expected: FAIL — `downloadFile is not a function`

- [ ] **Step 3: Rewrite `downloadFile`**

In `src/main/downloader.js` add `const http = require('http');` after the `https` require, and replace `downloadFile` with:

```js
function downloadFile(url, dest, onProgress) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    // Never leave a half-written (or empty, still-open) file behind: a 403 from
    // GitHub's rate limiter used to strand a zero-byte *.tmp with its handle open.
    const fail = (err) => { file.close(() => { try { fs.unlinkSync(dest); } catch {} reject(err); }); };
    const req = (u, depth) => {
      if (depth > 6) return fail(new Error('too many redirects'));
      const mod = u.startsWith('http:') ? http : https;   // http only for local tests
      mod.get(u, { headers: { 'User-Agent': 'IRNetFree' } }, (res) => {
        if (res.statusCode >= 300 && res.headers.location) { res.resume(); req(res.headers.location, depth + 1); return; }
        if (res.statusCode !== 200) { res.resume(); return fail(new Error('HTTP ' + res.statusCode)); }
        const total = parseInt(res.headers['content-length'] || '0', 10);
        let got = 0;
        res.on('data', (c) => {
          got += c.length;
          if (onProgress && total) onProgress(Math.min(100, Math.round((got / total) * 100)));
        });
        res.on('error', fail);
        res.pipe(file);
        file.on('finish', () => file.close(() => resolve(dest)));
      }).on('error', fail);
    };
    req(url, 0);
  });
}
```

and change the export line to:

```js
module.exports = { Downloader, downloadFile };
```

- [ ] **Step 4: Run the tests and commit**

Run: `node --test tests/downloader.test.js` → Expected: `# pass 3`

```bash
git add src/main/downloader.js tests/downloader.test.js
git commit -m "Downloader: close and remove the temp file on a non-200 response"
```

---

### Task 9: SOCKS5 handshake tolerates split replies

**Files:**
- Modify: `src/main/netutils.js:130-173` (`socks5Connect`)
- Test: `tests/netutils.test.js`

- [ ] **Step 1: Write the failing test**

`tests/netutils.test.js`:

```js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const { socks5Connect } = require('../src/main/netutils');

/** A SOCKS5 server that writes its replies in deliberately awkward pieces. */
function fakeSocks(onConnected) {
  return new Promise((resolve) => {
    const srv = net.createServer((sock) => {
      let stage = 0;
      sock.on('data', (d) => {
        if (stage === 0) {                       // greeting → reply byte by byte
          stage = 1;
          sock.write(Buffer.from([0x05]));
          setTimeout(() => sock.write(Buffer.from([0x00])), 10);
        } else if (stage === 1) {                // CONNECT → reply split, then payload glued on
          stage = 2;
          sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01]));
          setTimeout(() => sock.write(Buffer.concat([Buffer.from([1, 2, 3, 4, 0, 80]), Buffer.from('HELLO')])), 10);
          onConnected && onConnected(sock);
        }
      });
    });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, port: srv.address().port }));
  });
}

test('handshake completes when replies arrive in pieces and keeps the leftover payload', async () => {
  const { srv, port } = await fakeSocks();
  try {
    const socket = await socks5Connect('127.0.0.1', port, 'example.com', 80, 2000);
    const first = await new Promise((res) => socket.once('data', (d) => res(d.toString())));
    assert.equal(first, 'HELLO', 'bytes after the reply belong to the tunnelled stream');
    socket.destroy();
  } finally { srv.close(); }
});

test('a failed CONNECT reply rejects with its code', async () => {
  const srv = net.createServer((sock) => {
    let n = 0;
    sock.on('data', () => { n++; sock.write(n === 1 ? Buffer.from([0x05, 0x00]) : Buffer.from([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    await assert.rejects(socks5Connect('127.0.0.1', srv.address().port, 'example.com', 80, 2000), /socks connect failed code 5/);
  } finally { srv.close(); }
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/netutils.test.js` → Expected: the first test FAILS (`socks auth rejected` — the 1-byte greeting reply is misread).

- [ ] **Step 3: Rewrite `socks5Connect` with buffering**

Replace the function (doc comment through closing brace) with:

```js
/**
 * Minimal SOCKS5 CONNECT handshake (no auth). Resolves with a connected socket
 * already tunnelled to target host:port.
 *
 * Replies are accumulated: a reply can arrive split across TCP segments, or with
 * the first bytes of the tunnelled stream glued on. Reading `data[1]` of the
 * first chunk used to reject a healthy proxy as "auth rejected".
 */
function socks5Connect(proxyHost, proxyPort, destHost, destPort, timeout = 8000) {
  return new Promise((resolve, reject) => {
    const socket = new net.Socket();
    let stage = 0;
    let buf = Buffer.alloc(0);
    socket.setTimeout(timeout);
    const fail = (msg) => { socket.destroy(); reject(new Error(msg)); };

    socket.once('timeout', () => fail('socks timeout'));
    socket.once('error', (e) => reject(e));

    socket.connect(proxyPort, proxyHost, () => {
      // greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
    });

    socket.on('data', function onData(data) {
      buf = Buffer.concat([buf, data]);
      if (stage === 0) {
        if (buf.length < 2) return;
        if (buf[0] !== 0x05 || buf[1] !== 0x00) return fail('socks auth rejected');
        buf = buf.subarray(2);
        stage = 1;
        // CONNECT request, ATYP=3 (domain)
        const hostBuf = Buffer.from(destHost, 'utf8');
        socket.write(Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]),
          hostBuf,
          Buffer.from([(destPort >> 8) & 0xff, destPort & 0xff])
        ]));
        if (!buf.length) return;
      }
      if (stage === 1) {
        if (buf.length < 4) return;                       // VER REP RSV ATYP
        if (buf[1] !== 0x00) return fail('socks connect failed code ' + buf[1]);
        const atyp = buf[3];
        const need = atyp === 0x01 ? 10                    // IPv4 + port
          : atyp === 0x04 ? 22                             // IPv6 + port
          : atyp === 0x03 ? (buf.length >= 5 ? 5 + buf[4] + 2 : Infinity)   // domain
          : -1;
        if (need === -1) return fail('socks bad address type ' + atyp);
        if (buf.length < need) return;
        const rest = buf.subarray(need);
        stage = 2;
        socket.setTimeout(0);
        socket.removeListener('data', onData);
        if (rest.length) socket.unshift(rest);           // hand the stream's own bytes back
        resolve(socket);
      }
    });
  });
}
```

- [ ] **Step 4: Run the tests and commit**

Run: `node --test tests/netutils.test.js` → Expected: `# pass 2`. Then `node --test "tests/*.test.js"` → all pass.

```bash
git add src/main/netutils.js tests/netutils.test.js
git commit -m "netutils: buffer SOCKS5 replies so a split reply is not reported as a dead config"
```

---

### Task 10: Geo note only when the files are actually missing

**Files:**
- Modify: `src/renderer/app.js` (`renderComponents`, ≈ line 1180)

- [ ] **Step 1: Drive the note from `state.assets`**

At the end of `renderComponents()` (after the `for` loop) add:

```js
  // the Routing page's "download geo files" note is a static hint today and
  // shows even when both files are installed — tie it to the real state
  const note = $('#routingGeoNote');
  if (note) note.hidden = !!(a.geoip && a.geosite);
```
`renderComponents()` already runs at init, after every download, after "remove downloaded files" and on language change, so the note tracks reality.

- [ ] **Step 2: Verify in browser**

Headless server with an empty data dir: Routing shows the note. Settings → Required files → download "Routing files (geoip + geosite)" (needs internet) → the note disappears. (If offline: create `/tmp/irnf-ui/bin/geoip.dat` and `geosite.dat` as empty files, reload — note hidden.)

- [ ] **Step 3: Commit**

```bash
git add src/renderer/app.js
git commit -m "Routing: show the geo-files note only when they are missing"
```

---

### Task 11: Engine registry — `xray-pattn`

**Files:**
- Modify: `src/main/engines.js`
- Test: `tests/engines.test.js`

**Interfaces:**
- Produces: `ENGINES['xray-pattn']`, `engine(id).repo` (`'XTLS/Xray-core'` / `'patterniha/Xray-core'`), `xrayEngines() → ['xray','xray-pattn']`, `engineLabel(id) → string`.

- [ ] **Step 1: Write the failing test**

`tests/engines.test.js`:

```js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { ENGINES, DEFAULT_ENGINE, engine, engineExe, engineFormat, engineRunArgs, engineTestArgs, engineList, xrayEngines, engineLabel } = require('../src/main/engines');

test('the patterniha fork is an Xray-format engine with its own exe and repo', () => {
  const p = ENGINES['xray-pattn'];
  assert.equal(p.format, 'xray');
  assert.equal(p.repo, 'patterniha/Xray-core');
  assert.equal(engineExe('xray-pattn', 'win32'), 'xray-pattn.exe');
  assert.equal(engineExe('xray-pattn', 'darwin'), 'xray-pattn');
  assert.equal(ENGINES.xray.repo, 'XTLS/Xray-core');
});

test('both Xray engines run and test a config with the same argv', () => {
  assert.deepEqual(engineRunArgs('xray-pattn', 'c.json'), engineRunArgs('xray', 'c.json'));
  assert.deepEqual(engineTestArgs('xray-pattn', 'c.json'), ['run', '-test', '-c', 'c.json']);
  assert.equal(engineFormat('xray-pattn'), 'xray');
});

test('xrayEngines lists the Xray-format cores, default first; sing-box is not one', () => {
  assert.deepEqual(xrayEngines(), ['xray', 'xray-pattn']);
  assert.equal(DEFAULT_ENGINE, 'xray');
  assert.equal(engineFormat('sing-box'), 'sing-box');
});

test('unknown ids fall back to the default engine; labels are human', () => {
  assert.equal(engine('nope').id, 'xray');
  assert.equal(engineLabel('xray-pattn'), 'Xray-PattN (patterniha)');
  assert.deepEqual(engineList().map(e => e.id), ['xray', 'xray-pattn', 'sing-box']);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/engines.test.js` → Expected: FAIL — `xrayEngines is not a function` / repo undefined.

- [ ] **Step 3: Add the engine**

Replace the `ENGINES` object in `src/main/engines.js` with:

```js
const ENGINES = {
  xray: {
    id: 'xray',
    label: 'Xray (official)',
    format: 'xray',
    repo: 'XTLS/Xray-core',                            // GitHub releases the binary comes from
    exe: { win32: 'xray.exe', default: 'xray' },
    // CLI shape (argv builders) for this core.
    runArgs: (cfg) => ['run', '-c', cfg],
    testArgs: (cfg) => ['run', '-test', '-c', cfg]
  },
  // patterniha's fork: upstream + one change — it does not refuse plaintext
  // VLESS/Trojan to public addresses (upstream's validateOutboundTransportSecurity).
  // Same config format, same argv, same release asset names; only the exe name
  // differs so both can live in bin/ side by side.
  'xray-pattn': {
    id: 'xray-pattn',
    label: 'Xray-PattN (patterniha)',
    format: 'xray',
    repo: 'patterniha/Xray-core',
    exe: { win32: 'xray-pattn.exe', default: 'xray-pattn' },
    runArgs: (cfg) => ['run', '-c', cfg],
    testArgs: (cfg) => ['run', '-test', '-c', cfg]
  },
  'sing-box': {
    id: 'sing-box',
    label: 'sing-box (fake ClientHello / uTLS / fragment)',
    format: 'sing-box',                               // needs the sing-box translator
    exe: { win32: 'sing-box.exe', default: 'sing-box' },
    runArgs: (cfg) => ['run', '-c', cfg],
    testArgs: (cfg) => ['check', '-c', cfg]
  }
};
```

Below `engineList()` add:

```js
/** Ids of the engines that consume the Xray JSON format, default first. */
function xrayEngines() {
  return Object.values(ENGINES).filter(e => e.format === 'xray').map(e => e.id);
}

/** Human label for status lines and logs. */
function engineLabel(id) {
  return engine(id).label;
}
```

and export them:

```js
module.exports = {
  ENGINES, DEFAULT_ENGINE,
  engine, engineExe, engineFormat, engineRunArgs, engineTestArgs, engineList, xrayEngines, engineLabel
};
```

- [ ] **Step 4: Run the tests and commit**

Run: `node --test tests/engines.test.js tests/assets.test.js` → Expected: pass (assets now also reports `'xray-pattn': false`).

```bash
git add src/main/engines.js tests/engines.test.js
git commit -m "Engines: register the patterniha Xray fork as xray-pattn"
```

---

### Task 12: Download either Xray core from its own repo

**Files:**
- Modify: `src/main/downloader.js` (`download`, `getXray`, imports)
- Test: `tests/downloader.test.js`

**Interfaces:**
- Produces: `Downloader.releaseApiUrl(engineId) → string` (static, pure), `downloader.getXray(engineId = 'xray')`, `download('xray-pattn')`.

- [ ] **Step 1: Write the failing test**

Append to `tests/downloader.test.js`:

```js
const { Downloader } = require('../src/main/downloader');

test('each Xray engine downloads from its own GitHub repo', () => {
  assert.equal(Downloader.releaseApiUrl('xray'), 'https://api.github.com/repos/XTLS/Xray-core/releases/latest');
  assert.equal(Downloader.releaseApiUrl('xray-pattn'), 'https://api.github.com/repos/patterniha/Xray-core/releases/latest');
  assert.throws(() => Downloader.releaseApiUrl('sing-box'), /not an Xray-format engine/);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/downloader.test.js` → Expected: FAIL — `Downloader.releaseApiUrl is not a function`

- [ ] **Step 3: Parametrise the Xray download by engine**

In `src/main/downloader.js` add the import:

```js
const { engine, engineExe } = require('./engines');
```

Add the static helper inside the class (after `log(...)`):

```js
  /** GitHub "latest release" endpoint for an Xray-format engine. */
  static releaseApiUrl(engineId) {
    const e = engine(engineId);
    if (e.format !== 'xray' || e.id !== engineId) throw new Error('not an Xray-format engine: ' + engineId);
    return `https://api.github.com/repos/${e.repo}/releases/latest`;
  }
```

Replace the `download` switch with:

```js
  async download(component) {
    switch (component) {
      case 'xray': return this.getXray('xray');
      case 'xray-pattn': return this.getXray('xray-pattn');
      case 'sing-box': return this.getSingbox();
      case 'geo': return this.getGeo();
      case 'tun2socks': return this.getTun2socks();
      case 'wintun': return this.getWintun();
      default: throw new Error('unknown component: ' + component);
    }
  }
```

Replace `getXray()` with:

```js
  /**
   * Download an Xray-format core. Both the official core and the patterniha fork
   * publish the same asset names; the binary is placed under the engine's own exe
   * name so they coexist. Geo files inside the archive are placed too.
   */
  async getXray(engineId = 'xray') {
    const eng = engine(engineId);
    this.log(`Fetching latest ${eng.label} release info…`);
    const rel = await getJSON(Downloader.releaseApiUrl(engineId));
    const want = this.xrayAssetName();
    const asset = (rel.assets || []).find(a => a.name === want);
    if (!asset) throw new Error('asset not found: ' + want);
    const work = tmpDir(engineId);
    const zip = path.join(work, want);
    this.log(`Downloading ${want} (${eng.label} ${rel.tag_name})…`);
    await downloadFile(asset.browser_download_url, zip, (p) => this.onProgress(engineId, p));
    this.log(`Extracting ${eng.label}…`);
    unzip(zip, work);
    const inArchive = os.platform() === 'win32' ? 'xray.exe' : 'xray';   // upstream's name inside the zip
    const exe = findFile(work, inArchive);
    if (!exe) throw new Error('xray binary not found in archive');
    const out = [];
    out.push(this.place(exe, engineExe(engineId), true));
    for (const dat of ['geoip.dat', 'geosite.dat']) {
      const f = findFile(work, dat);
      if (f) out.push(this.place(f, dat));
    }
    this.cleanup(work);
    this.log(`✓ ${eng.label} integrated: ` + out.join(', '));
    return { ok: true, files: out };
  }
```

- [ ] **Step 4: Run the tests and commit**

Run: `node --test tests/downloader.test.js` → Expected: `# pass 4`

```bash
git add src/main/downloader.js tests/downloader.test.js
git commit -m "Downloader: fetch the official core or the patterniha fork from its own repo"
```

---

### Task 13: XrayManager knows two Xray cores

**Files:**
- Modify: `src/main/xrayManager.js`
- Test: `tests/xrayManager.test.js`
- Modify: `src/main/main.js`, `src/server/service.js` (callers of `_version`, `resolveBin()` for stats, `startTest`)

**Interfaces:**
- Produces on `XrayManager`:
  - `resolveEngine(engineId) → { id, bin }` — requested engine if installed, else any other Xray-format engine (logged), else `{ id:'xray', bin:null }`
  - `binExists(engineId?) → boolean` — with no id: any Xray-format engine installed
  - `version(engineId = 'xray') → Promise<string>`, cache `this._versions` (object) replaces `this._version`
  - `validateWithFallback(config, engineId) → Promise<{ ok, engine, error?, fellBack?, plaintextRejected? }>`
  - `startTest(testConfig, engineId?)`
  - `PLAINTEXT_REJECT` regex exported

- [ ] **Step 1: Write the failing tests**

`tests/xrayManager.test.js`:

```js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { XrayManager, PLAINTEXT_REJECT } = require('../src/main/xrayManager');

function withBin(files, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-xm-'));
  for (const f of files) fs.writeFileSync(path.join(dir, f), '');
  const logs = [];
  const xm = new XrayManager({ dataDir: dir, extraBinDirs: [dir], onLog: (l) => logs.push(l) });
  // never let the real bundled bin/ or XRAY_PATH leak into the test
  xm.binDirs = () => [dir];
  delete process.env.XRAY_PATH;
  try { return fn(xm, dir, logs); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
const exe = (n) => process.platform === 'win32' ? n + '.exe' : n;

test('resolveEngine returns the requested core when installed', () => {
  withBin([exe('xray'), exe('xray-pattn')], (xm) => {
    assert.equal(xm.resolveEngine('xray-pattn').id, 'xray-pattn');
    assert.equal(xm.resolveEngine('xray').id, 'xray');
    assert.equal(xm.resolveEngine(undefined).id, 'xray');
  });
});

test('resolveEngine falls back across Xray-format cores in both directions', () => {
  withBin([exe('xray-pattn')], (xm, dir, logs) => {
    const r = xm.resolveEngine('xray');
    assert.equal(r.id, 'xray-pattn');
    assert.equal(r.bin, path.join(dir, exe('xray-pattn')));
    assert.match(logs.at(-1), /not found.*using xray-pattn/);
  });
  withBin([exe('xray')], (xm) => {
    assert.equal(xm.resolveEngine('xray-pattn').id, 'xray');
    assert.equal(xm.resolveEngine('sing-box').id, 'xray', 'sing-box missing → default core');
  });
  withBin([], (xm) => assert.deepEqual(xm.resolveEngine('xray'), { id: 'xray', bin: null }));
});

test('binExists: any Xray core, or a specific one', () => {
  withBin([exe('xray-pattn')], (xm) => {
    assert.equal(xm.binExists(), true);
    assert.equal(xm.binExists('xray'), false);
    assert.equal(xm.binExists('xray-pattn'), true);
  });
});

test('validateWithFallback retries a plaintext-rejected config on the fork', async () => {
  const rejectMsg = 'vless without TLS or other encryption is prohibited unless the server address is a private IP or domain';
  assert.match(rejectMsg, PLAINTEXT_REJECT);
  await withBin([exe('xray'), exe('xray-pattn')], async (xm, dir, logs) => {
    const calls = [];
    xm.validate = async (cfg, id) => { calls.push(id); return id === 'xray' ? { ok: false, error: rejectMsg } : { ok: true }; };
    const r = await xm.validateWithFallback({}, 'xray');
    assert.deepEqual(r, { ok: true, engine: 'xray-pattn', fellBack: true });
    assert.deepEqual(calls, ['xray', 'xray-pattn']);
    assert.match(logs.at(-1), /Xray-PattN/);
  });
});

test('validateWithFallback reports a plaintext rejection when the fork is not installed', async () => {
  await withBin([exe('xray')], async (xm) => {
    xm.validate = async () => ({ ok: false, error: 'trojan without TLS is prohibited unless the server address is a private IP or domain' });
    const r = await xm.validateWithFallback({}, 'xray');
    assert.equal(r.ok, false);
    assert.equal(r.engine, 'xray');
    assert.equal(r.plaintextRejected, true);
  });
});

test('validateWithFallback passes other errors through untouched', async () => {
  await withBin([exe('xray'), exe('xray-pattn')], async (xm) => {
    xm.validate = async () => ({ ok: false, error: 'infra/conf: unknown transport' });
    const r = await xm.validateWithFallback({}, 'xray');
    assert.deepEqual(r, { ok: false, engine: 'xray', error: 'infra/conf: unknown transport', plaintextRejected: false });
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/xrayManager.test.js` → Expected: FAIL — `PLAINTEXT_REJECT` undefined / `validateWithFallback is not a function`.

- [ ] **Step 3: Implement in `src/main/xrayManager.js`**

Change the engines import to:

```js
const { DEFAULT_ENGINE, engineExe, engineRunArgs, engineTestArgs, engineLabel, xrayEngines } = require('./engines');
```

Add after the imports:

```js
/** Upstream's plaintext-outbound refusal (infra/conf/xray.go); the patterniha fork lifts it. */
const PLAINTEXT_REJECT = /without TLS.*prohibited/i;
```

In the constructor, replace nothing but note `_version` is gone: add `this._versions = {};   // engineId -> version string` after `this.running = false;`.

Replace `resolveEngine` with:

```js
  /**
   * Resolve the effective engine to run a config on. The requested one if its
   * binary is installed; otherwise any other Xray-format core (they run the same
   * config — logged, so the user sees which one actually ran); otherwise the
   * default id with bin:null. Callers use the argv/format of the core returned.
   */
  resolveEngine(engineId) {
    const wantId = engineId || DEFAULT_ENGINE;
    const wantBin = this.resolveBin(wantId);
    if (wantBin) return { id: wantId, bin: wantBin };
    for (const id of xrayEngines()) {
      if (id === wantId) continue;
      const bin = this.resolveBin(id);
      if (bin) {
        this.onLog(`Engine '${wantId}' binary (${engineExe(wantId)}) not found in bin/ — using ${id}`, 'warn');
        return { id, bin };
      }
    }
    return { id: DEFAULT_ENGINE, bin: null };
  }
```

Replace `binExists()` with:

```js
  /** Is a core installed? With no id: any Xray-format core (they run the same config). */
  binExists(engineId) {
    if (engineId) return !!this.resolveBin(engineId);
    return xrayEngines().some(id => !!this.resolveBin(id));
  }
```

Replace `version()` with:

```js
  /** Core version string (e.g. "26.9.1") for an engine, cached per engine. Empty if unavailable. */
  version(engineId = DEFAULT_ENGINE) {
    return new Promise((resolve) => {
      if (this._versions[engineId]) return resolve(this._versions[engineId]);
      const bin = this.resolveBin(engineId);
      if (!bin) return resolve('');
      let out = '';
      const proc = spawn(bin, ['version'], { cwd: path.dirname(bin), windowsHide: true, env: this.spawnEnv() });
      proc.stdout.on('data', d => { out += d.toString('utf8'); });
      proc.stderr.on('data', d => { out += d.toString('utf8'); });
      let done = false;
      const finish = () => {
        if (done) return; done = true;
        // first line looks like: "Xray 26.9.1 (Xray, Penetrates Everything.) ..."
        const m = out.match(/Xray[^\d]*(\d+\.\d+\.\d+)/i);
        this._versions[engineId] = m ? m[1] : (out.split(/\r?\n/)[0] || '').trim();
        resolve(this._versions[engineId]);
      };
      proc.on('error', () => resolve(''));
      proc.on('exit', finish);
      setTimeout(() => { try { proc.kill(); } catch {} finish(); }, 4000);
    });
  }

  /** Forget cached versions (after a download / removal). */
  forgetVersions() { this._versions = {}; }
```

After `validate(...)` add:

```js
  /**
   * Validate on the requested engine. If the OFFICIAL core rejects the config
   * only because it is plaintext VLESS/Trojan to a public address and the
   * patterniha fork is installed, validate on the fork instead — that is the one
   * thing the fork exists for. Returns { ok, engine, error?, fellBack?,
   * plaintextRejected? } so the caller knows which core to start and can tell
   * the user to install the fork when it is missing.
   */
  async validateWithFallback(config, engineId) {
    const first = this.resolveEngine(engineId);
    const r = await this.validate(config, first.id);
    if (r.ok) return { ok: true, engine: first.id };
    const plaintextRejected = PLAINTEXT_REJECT.test(r.error || '');
    if (first.id === 'xray' && plaintextRejected && this.resolveBin('xray-pattn')) {
      const again = await this.validate(config, 'xray-pattn');
      if (again.ok) {
        this.onLog(`Official core rejects this plaintext config — running it on ${engineLabel('xray-pattn')}`, 'warn');
        return { ok: true, engine: 'xray-pattn', fellBack: true };
      }
      return { ok: false, engine: 'xray-pattn', error: again.error, plaintextRejected: false };
    }
    return { ok: false, engine: first.id, error: r.error, plaintextRejected };
  }
```

Replace `startTest(testConfig)` with:

```js
  async startTest(testConfig, engineId) {
    const { bin } = this.resolveEngine(engineId);
    if (!bin) throw new Error('xray binary not found');
    const cfgPath = path.join(this.dataDir, `test-${Date.now()}.json`);
    fs.writeFileSync(cfgPath, JSON.stringify(testConfig, null, 2), 'utf8');

    const proc = spawn(bin, ['run', '-c', cfgPath], { cwd: path.dirname(bin), windowsHide: true, env: this.spawnEnv() });
    // give it a moment to bind
    await delay(500);
    return {
      proc,
      cleanup: () => {
        try { proc.kill(); } catch {}
        try {
          if (os.platform() === 'win32' && proc.pid) spawn('taskkill', ['/pid', String(proc.pid), '/t', '/f'], { windowsHide: true });
        } catch {}
        try { fs.unlinkSync(cfgPath); } catch {}
      }
    };
  }
```

Change the export to:

```js
module.exports = { XrayManager, getFreePort, PLAINTEXT_REJECT };
```

- [ ] **Step 4: Run the tests**

Run: `node --test tests/xrayManager.test.js` → Expected: `# pass 6`

- [ ] **Step 5: Update the callers of `_version` / `resolveBin()` in `main.js` and `service.js`**

In **both** files:

| Current | New |
|---|---|
| `xray._version = null;` (assets:download, assets:remove) | `xray.forgetVersions();` |
| `stats.setBin(xray.resolveBin());` (every occurrence, incl. the `StatsPoller` constructor `binPath: xray.resolveBin()`) | `stats.setBin(xray.resolveEngine().bin);` / `binPath: xray.resolveEngine().bin` |
| `if (component === 'xray') { xray.binPath = null; …` | `if (component === 'xray' \|\| component === 'xray-pattn') { xray.binPath = null; …` |
| `const names = ['xray', 'xray.exe', 'tun2socks', …` (assets:remove) | `const names = ['xray', 'xray.exe', 'xray-pattn', 'xray-pattn.exe', 'tun2socks', …` |

The `ping:real` / `ping:upload` handlers keep calling `xray.startTest(cfg)` for now; Task 14 gives them an engine.

- [ ] **Step 6: Run the suite and commit**

Run: `node --test "tests/*.test.js"` → Expected: all pass.

```bash
git add src/main/xrayManager.js src/main/main.js src/server/service.js tests/xrayManager.test.js
git commit -m "XrayManager: per-engine versions, cross-core fallback, retry plaintext configs on Xray-PattN"
```

---

### Task 14: Which core runs a plan

**Files:**
- Create: `src/main/engineChoice.js`
- Test: `tests/engineChoice.test.js`
- Modify: `src/main/main.js` (`buildActive`, `doConnect`, `rebuildActiveConfig`, `ping:real`, `ping:upload`)
- Modify: `src/server/service.js` (same four places)

**Interfaces:**
- Produces: `chooseEngine(plan, defaultEngine = 'xray') → 'xray' | 'xray-pattn' | 'sing-box'`, `testEngineFor(engineId) → 'xray' | 'xray-pattn'` (sing-box configs are latency-tested on an Xray core, as today).
- Consumes: `xray.validateWithFallback` (Task 13), plan shapes from `buildActive` (`{mode:'single', server}`, `{mode:'chain', chain}`, `{mode:'pool', entries, serversById, chainsById, chain}`, `{mode:'advanced', rules, def, serversById, chainsById, chain}`).
- `send('status', { state:'connected', …, engine })` now carries the engine id that actually runs.

- [ ] **Step 1: Write the failing test**

`tests/engineChoice.test.js`:

```js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { chooseEngine, planServers, testEngineFor } = require('../src/main/engineChoice');

const S = (id, engine) => Object.assign({ id, outbound: { protocol: 'vless' } }, engine ? { engine } : {});
const a = S('a'), b = S('b'), p = S('p', 'xray-pattn'), sb = S('sb', 'sing-box');
const byId = { a, b, p, sb };

test('single: the server’s own engine, else the default', () => {
  assert.equal(chooseEngine({ mode: 'single', server: p }), 'xray-pattn');
  assert.equal(chooseEngine({ mode: 'single', server: sb }), 'sing-box');
  assert.equal(chooseEngine({ mode: 'single', server: a }), 'xray');
  assert.equal(chooseEngine({ mode: 'single', server: a }, 'xray-pattn'), 'xray-pattn');
});

test('chain: PattN if any hop wants it, else the default', () => {
  assert.equal(chooseEngine({ mode: 'chain', chain: [a, b] }), 'xray');
  assert.equal(chooseEngine({ mode: 'chain', chain: [a, p] }), 'xray-pattn');
  assert.equal(chooseEngine({ mode: 'chain', chain: [a, sb] }), 'xray', 'sing-box is single-config only');
  assert.equal(chooseEngine({ mode: 'chain', chain: [a, b] }, 'xray-pattn'), 'xray-pattn');
});

test('pool / advanced: looks through targets, chain: targets and the default target', () => {
  const chainsById = { c1: [a, p], c2: [a, b] };
  assert.equal(chooseEngine({ mode: 'pool', entries: [{ target: 'a' }, { target: 'chain:c2' }], serversById: byId, chainsById }), 'xray');
  assert.equal(chooseEngine({ mode: 'pool', entries: [{ target: 'chain:c1' }], serversById: byId, chainsById }), 'xray-pattn');
  assert.equal(chooseEngine({ mode: 'advanced', rules: [{ target: 'direct' }, { target: 'a' }], def: 'p', serversById: byId, chainsById }), 'xray-pattn');
  assert.equal(chooseEngine({ mode: 'advanced', rules: [{ target: 'block' }], def: 'direct', serversById: byId, chainsById }), 'xray');
  assert.equal(chooseEngine({ mode: 'advanced', rules: [null, { target: 'chain' }], def: 'a', serversById: byId, chainsById, chain: [p, a] }), 'xray-pattn', 'legacy chain target');
});

test('planServers lists every server a plan can dial', () => {
  assert.deepEqual(planServers({ mode: 'advanced', rules: [{ target: 'a' }], def: 'chain:c1', serversById: byId, chainsById: { c1: [a, p] } }).map(s => s.id), ['a', 'a', 'p']);
});

test('latency tests never run on sing-box', () => {
  assert.equal(testEngineFor('sing-box'), 'xray');
  assert.equal(testEngineFor('xray-pattn'), 'xray-pattn');
  assert.equal(testEngineFor(undefined), 'xray');
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/engineChoice.test.js` → Expected: FAIL — `Cannot find module '../src/main/engineChoice'`

- [ ] **Step 3: Create `src/main/engineChoice.js`**

```js
'use strict';
/**
 * Which core runs a connection plan.
 *
 *  - single:   the server's own choice (edit form), else the default engine
 *  - chain / pool / advanced: 'xray-pattn' if the default is PattN or ANY server
 *    that participates asks for it — PattN accepts everything the official core
 *    does plus plaintext VLESS/Trojan, so a chain with one plaintext hop must run
 *    on it. Otherwise the official core.
 *  - 'sing-box' is a single-config engine only (it has no chain/pool translator).
 */

/** Every server object a plan can dial (duplicates allowed). */
function planServers(plan) {
  if (!plan) return [];
  switch (plan.mode) {
    case 'single': return plan.server ? [plan.server] : [];
    case 'chain': return plan.chain || [];
    case 'pool': return targetsServers((plan.entries || []).map(e => e && e.target), plan);
    case 'advanced': return targetsServers([...(plan.rules || []).map(r => r && r.target), plan.def], plan);
    default: return [];
  }
}

function targetsServers(targets, plan) {
  const out = [];
  for (const tg of targets) {
    if (!tg || tg === 'direct' || tg === 'block') continue;
    if (tg === 'chain') out.push(...(plan.chain || []));
    else if (String(tg).startsWith('chain:')) out.push(...((plan.chainsById || {})[String(tg).slice('chain:'.length)] || []));
    else if (plan.serversById && plan.serversById[tg]) out.push(plan.serversById[tg]);
  }
  return out;
}

function chooseEngine(plan, defaultEngine = 'xray') {
  const def = defaultEngine === 'xray-pattn' ? 'xray-pattn' : 'xray';
  if (plan && plan.mode === 'single') return (plan.server && plan.server.engine) || def;
  const wantsPattn = planServers(plan).some(s => s && s.engine === 'xray-pattn');
  return wantsPattn ? 'xray-pattn' : def;
}

/** Throwaway latency tests use an Xray-format core (buildTestConfig is Xray JSON). */
function testEngineFor(engineId) {
  return engineId === 'xray-pattn' ? 'xray-pattn' : 'xray';
}

module.exports = { chooseEngine, planServers, testEngineFor };
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `node --test tests/engineChoice.test.js` → Expected: `# pass 5`

- [ ] **Step 5: Wire it into `main.js`**

Add the import:

```js
const { chooseEngine, testEngineFor } = require('./engineChoice');
```

In `buildActive`, replace:

```js
  // Per-config core selection: honour a single server's chosen engine. Chains /
  // pool / advanced always run on the default Xray core. The EFFECTIVE engine
  // (after fallback when the binary is missing) decides the config format.
  const wantEngine = (plan.mode === 'single' && plan.server && plan.server.engine) || undefined;
  let engine = xray.resolveEngine(wantEngine).id;
```
with
```js
  // Per-config core selection (see engineChoice.js): a single server's own
  // choice, else the default engine; multi-server plans run on PattN when any
  // member needs it. The EFFECTIVE engine (after fallback when the binary is
  // missing) decides the config format.
  let engine = xray.resolveEngine(chooseEngine(plan, settings.defaultEngine)).id;
```

In `doConnect`, replace:

```js
  const check = await xray.validate(config, engine);
  if (!check.ok) {
    send('log', { line: 'Config rejected by xray: ' + check.error, level: 'error' });
    throw new Error((settings.lang === 'en' ? 'Config error: ' : 'خطای کانفیگ: ') + check.error);
  }
```
with
```js
  const check = await xray.validateWithFallback(config, engine);
  if (!check.ok) {
    send('log', { line: 'Config rejected by xray: ' + check.error, level: 'error' });
    // The official core refuses plaintext VLESS/Trojan to public addresses and the
    // fork that accepts them is not installed — say so, the renderer offers the download.
    const hint = check.plaintextRejected
      ? (settings.lang === 'en'
        ? ' — this config has no TLS; the official core refuses it. Install Xray-PattN under Settings → Required files.'
        : ' — این کانفیگ TLS ندارد و هستهٔ رسمی آن را رد می‌کند. Xray-PattN را از تنظیمات → فایل‌های موردنیاز نصب کن.')
      : '';
    const err = new Error((settings.lang === 'en' ? 'Config error: ' : 'خطای کانفیگ: ') + check.error + hint);
    err.needEngine = check.plaintextRejected ? 'xray-pattn' : undefined;
    throw err;
  }
  const runEngine = check.engine;
```
then change `await xray.start(config, engine);` (inside the `try`) to `await xray.start(config, runEngine);`, and add `engine: runEngine` to the connected status:

```js
  send('status', {
    state: 'connected', serverId, server: byId(serverId) || null, label, engine: runEngine,
    tun: tun.active, tunError, geoWarn, lan, pendingReconnect: pendingKeys()
  });
```

In `rebuildActiveConfig`, replace `await xray.start(config, engine);` with:

```js
    const check = await xray.validateWithFallback(config, engine);
    if (!check.ok) throw new Error(check.error);
    await xray.start(config, check.engine);   // start() stops the old instance first
```

In `ping:real` and `ping:upload`, replace `test = await xray.startTest(cfg);` with:

```js
      const plan = chain && chain.length >= 2 ? { mode: 'chain', chain } : { mode: 'single', server };
      test = await xray.startTest(cfg, testEngineFor(chooseEngine(plan, getSettings().defaultEngine)));
```

Add `defaultEngine: 'xray'` to `DEFAULT_SETTINGS` (after `theme: 'dark'`, with a comma).

- [ ] **Step 6: Mirror in `service.js`**

Same five edits: import (`require('../main/engineChoice')`), `buildActive` engine line, `doConnect` (`validateWithFallback`, hint, `err.needEngine`, `runEngine`, `engine: runEngine` in the connected status), `rebuildActiveConfig`, the two ping handlers, and `defaultEngine: 'xray'` in `DEFAULT_SETTINGS`.

- [ ] **Step 7: Run the suite and commit**

Run: `node --test "tests/*.test.js"` → Expected: all pass.

```bash
git add src/main/engineChoice.js src/main/main.js src/server/service.js tests/engineChoice.test.js
git commit -m "Pick the core per plan: server choice or defaultEngine, PattN when any member needs it"
```

---

### Task 15: Settings, IPC and UI for two cores

**Files:**
- Modify: `src/main/settingsMeta.js:25-34` (`RECONNECT_KEYS`)
- Modify: `tests/settingsMeta.test.js` (fixtures)
- Modify: `src/main/main.js` (`xray:version` handler), `src/server/service.js` (same)
- Modify: `src/preload/preload.js`, `src/server/web-api.js` (`xrayVersion(engineId)`)
- Modify: `src/renderer/index.html` (engine option, default-core select)
- Modify: `src/renderer/i18n.js` (both languages)
- Modify: `src/renderer/app.js` (versions, components list, default-core select, status line, plaintext hint)

- [ ] **Step 1: Make `defaultEngine` reconnect-relevant (test first)**

In `tests/settingsMeta.test.js`: add `defaultEngine: 'xray',` to `baseSettings()` (after `theme: 'dark',`), and `defaultEngine: 'xray-pattn',` to the `changes` object in "every reconnect-relevant key is detected when it changes" (after `systemProxy: false, tunMode: true`).

Run: `node --test tests/settingsMeta.test.js` → Expected: FAIL — the changes fixture no longer matches `RECONNECT_KEYS`.

- [ ] **Step 2: Add the key and its strings**

`src/main/settingsMeta.js` — extend `RECONNECT_KEYS`:

```js
  // connect-time side effects
  'systemProxy', 'tunMode',
  // which core the config is validated on and started with
  'defaultEngine'
```

`src/renderer/i18n.js` — in the **fa** block, after `'set.systemProxy': 'پروکسی سیستمی', 'set.tunMode': 'حالت TUN',` add:

```js
    'set.defaultEngine': 'هستهٔ پیش‌فرض',
    'set.defaultEngineHint': 'کانفیگ‌هایی که هسته‌ی مشخصی انتخاب نکرده‌اند، و زنجیره/استخر/روتینگ پیشرفته، روی این هسته اجرا می‌شوند. اگر عضوی PattN بخواهد، کل plan روی PattN می‌رود.',
    'comp.xrayPattn': 'هستهٔ Xray-PattN (fork پترنیها — کانفیگ بدون TLS را می‌پذیرد)',
    'engine.pattn': 'Xray-PattN (patterniha)',
    'engine.official': 'Xray (رسمی)',
    'conn.engine': 'هسته',
```
and in the **en** block after `'set.systemProxy': 'System proxy', 'set.tunMode': 'TUN mode',`:

```js
    'set.defaultEngine': 'Default core',
    'set.defaultEngineHint': 'Configs without their own core choice, and chains / pool / advanced routing, run on this core. If any member asks for PattN the whole plan runs on PattN.',
    'comp.xrayPattn': 'Xray-PattN core (patterniha fork — accepts plaintext configs)',
    'engine.pattn': 'Xray-PattN (patterniha)',
    'engine.official': 'Xray (official)',
    'conn.engine': 'core',
```

Run: `node --test tests/settingsMeta.test.js` → Expected: pass.

- [ ] **Step 3: Version IPC takes an engine**

`src/main/main.js` — replace the `xray:version` handler:

```js
  // core version string for an engine (e.g. "26.9.1")
  ipcMain.handle('xray:version', async (e, engineId) => {
    try { return { ok: true, version: await xray.version(engineId || 'xray') }; }
    catch (err) { return { ok: false, error: err.message }; }
  });
```
`src/server/service.js`:
```js
    'xray:version': async (engineId) => { try { return { ok: true, version: await xray.version(engineId || 'xray') }; } catch (e) { return { ok: false, error: e.message }; } },
```
`src/preload/preload.js`: `xrayVersion: (engineId) => ipcRenderer.invoke('xray:version', engineId),`
`src/server/web-api.js`: `xrayVersion: (engineId) => invoke('xray:version', engineId),`

- [ ] **Step 4: HTML — engine option and default-core select**

In `src/renderer/index.html`, the edit modal's `#edEngine` select becomes:

```html
            <select id="edEngine" class="select">
              <option value="xray" data-i18n="engine.official">Xray (official)</option>
              <option value="xray-pattn" data-i18n="engine.pattn">Xray-PattN (patterniha)</option>
              <option value="sing-box" data-i18n="engine.singbox">sing-box (fake ClientHello / uTLS)</option>
            </select>
```

In the Settings view, replace the empty `<div></div>` next to the language select with:

```html
            <div>
              <label class="field-label" data-i18n="set.defaultEngine">هستهٔ پیش‌فرض</label>
              <select id="defaultEngine" class="select">
                <option value="xray" data-i18n="engine.official">Xray (رسمی)</option>
                <option value="xray-pattn" data-i18n="engine.pattn">Xray-PattN (patterniha)</option>
              </select>
              <p class="hint" data-i18n="set.defaultEngineHint"></p>
            </div>
```

Update the `engine.xray` option text in `i18n.js` is no longer used by the select (it used `engine.xray`); keep the key for compatibility, the select now uses `engine.official`.

- [ ] **Step 5: Renderer — versions, component rows, default-core select, status line, download hint**

In `src/renderer/app.js`:

a) State: add `coreVersions: {},    // engineId -> version string` after `version: '',` and `activeEngine: '',   // core the live connection runs on` after `activeServerId: null,`.

b) Replace `refreshXrayVersion()` with:

```js
/* ----------------------------- core versions ----------------------------- */
const XRAY_ENGINES = ['xray', 'xray-pattn'];
async function refreshXrayVersion() {
  for (const id of XRAY_ENGINES) {
    try {
      const res = await window.api.xrayVersion(id);
      state.coreVersions[id] = (res && res.ok) ? res.version : '';
    } catch { state.coreVersions[id] = ''; }
  }
  state.xrayVersion = state.coreVersions.xray || state.coreVersions['xray-pattn'] || '';
  const el = $('#xrayVersion');
  if (el) el.textContent = state.xrayVersion ? (t('xray.version') + ': ' + state.xrayVersion) : '';
  renderComponents();
}
```

c) `COMPONENTS`:

```js
const COMPONENTS = [
  { key: 'xray', label: 'comp.xray', ver: 'xray' },
  { key: 'xray-pattn', label: 'comp.xrayPattn', ver: 'xray-pattn' },
  { key: 'sing-box', label: 'comp.singbox', has: (a) => !!a['sing-box'] },
  { key: 'geo', label: 'comp.geo', has: (a) => a.geoip && a.geosite },
  { key: 'tun2socks', label: 'comp.tun2socks' },
  { key: 'wintun', label: 'comp.wintun', winOnly: true }
];
```
and in `renderComponents()` replace the `ver` line with:

```js
    const v = c.ver && present ? state.coreVersions[c.ver] : '';
    const ver = v ? ` <span class="comp-ver">v${escapeHtml(v)}</span>` : '';
```

d) `missingEssentials()`: `if (!a.xray) list.push('xray');` → `if (!(a.xray || a['xray-pattn'])) list.push('xray');`. `COMP_LABEL` gains `'xray-pattn': 'comp.xrayPattn'`.

e) Settings form: in `applySettingsToUI()` add `$('#defaultEngine').value = s.defaultEngine || 'xray';` and next to the language handlers add:

```js
$('#defaultEngine').onchange = () => saveSettings({ defaultEngine: $('#defaultEngine').value });
```
(`readSettingsForm()` does **not** include it — the select saves itself.)

f) Status line: in `setConnUI`, after the `if/else` chain that sets `srv.textContent`, add:

```js
  if (stateStr === 'connected' && state.activeEngine) {
    srv.textContent += ` · ${t('conn.engine')}: ${state.activeEngine === 'xray-pattn' ? t('engine.pattn') : state.activeEngine === 'sing-box' ? 'sing-box' : t('engine.official')}`;
  }
```
In `window.api.onStatus`, in the `connected` branch add `state.activeEngine = d.engine || '';` before `setConnUI('connected', d.serverId);`, and in the `disconnected` branch `state.activeEngine = '';`.

g) Plaintext hint → download offer: in `connect()`'s `catch (e)`, after the toast, add:

```js
    // the official core refused a plaintext config and the fork is not installed
    if (/Xray-PattN/.test(e.message) && !(state.assets && state.assets['xray-pattn'])) openFilesModal(['xray-pattn']);
```

- [ ] **Step 6: Verify in browser**

Headless server (Task 1 command). Settings → the "Default core" select shows and persists (`grep defaultEngine /tmp/irnf-ui/store.json`). Required files lists "Xray core", "Xray-PattN core" (both "Missing" with Download), sing-box, geo, tun2socks. With internet: Download both cores → both rows show their version chips; `ls /tmp/irnf-ui/bin` shows `xray` and `xray-pattn` (or `.exe`). Servers → ✎ on a server → Core/Engine has three options; pick Xray-PattN, save, connect: the home status line ends with "core: Xray-PattN (patterniha)". Add a plaintext config (`vless://<uuid>@1.2.3.4:80?type=ws&security=none#Plain`), engine = official, remove `xray-pattn` from `bin/`, connect → toast names Xray-PattN and the Required-files modal opens on it. Take screenshots of the Required-files card and the status line.

- [ ] **Step 7: Run the suite and commit**

Run: `node --test "tests/*.test.js"` → Expected: all pass.

```bash
git add src/main/settingsMeta.js src/main/main.js src/server/service.js src/preload/preload.js src/server/web-api.js src/renderer/index.html src/renderer/i18n.js src/renderer/app.js tests/settingsMeta.test.js
git commit -m "Dual cores in the UI: per-config engine, default core setting, both versions in Required files"
```

---

### Task 16: Docs and CI test matrix

**Files:**
- Modify: `README.md` (features table, Required files table, project structure)
- Create: `.github/workflows/test.yml`

- [ ] **Step 1: README**

In the features table (`## ✨ امکانات کامل`) add a row after **پروتکل‌ها**:

```markdown
| **دو هسته‌ی Xray** | هسته‌ی رسمی (`XTLS/Xray-core`) و fork پترنیها (`patterniha/Xray-core`، کانفیگ‌های بدون TLS به آدرس عمومی را رد نمی‌کند). انتخاب per-config در فرم ویرایش، «هسته‌ی پیش‌فرض» در تنظیمات، هر دو از «فایل‌های موردنیاز» دانلود/به‌روزرسانی می‌شوند. اگر هسته‌ی رسمی کانفیگی را با خطای «without TLS» رد کند و PattN نصب باشد، خودکار روی PattN اجرا می‌شود. |
```

In the Required-files table (`## 📦 فایل‌های موردنیاز`) add after **هسته Xray**:

```markdown
| **هسته Xray-PattN** | fork پترنیها؛ برای کانفیگ‌های VLESS/Trojan بدون TLS (مثل ws روی پورت 80 پشت CDN) که هسته‌ی رسمی رد می‌کند |
```

In the project structure block add after `engines.js` is not listed — add these two lines under `main/`:

```
    engines.js       # رجیستری هسته‌ها: xray (رسمی)، xray-pattn (پترنیها)، sing-box
    engineChoice.js  # کدام هسته یک plan را اجرا می‌کند (انتخاب کانفیگ / هسته‌ی پیش‌فرض)
    assets.js        # وضعیت فایل‌های موردنیاز (مشترک دسکتاپ و headless)
```

- [ ] **Step 2: CI**

`.github/workflows/test.yml`:

```yaml
name: Tests

# Unit tests on every push and PR, on all three desktop platforms — the parser,
# config builder and engine choice must behave identically everywhere.
on:
  push:
    branches: ['**']
  pull_request:

jobs:
  test:
    name: node --test (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm test
```

- [ ] **Step 3: Commit**

```bash
git add README.md .github/workflows/test.yml
git commit -m "Docs: dual Xray cores; CI: run the unit tests on Linux, Windows and macOS"
```

---

## Self-review

**Spec coverage (phase 0 + 1):**
- Dropdown squash → T1 · headless allowLan + Origin/Host → T2 · pool apiPort → T3 · shared assetStatus → T4 · http proxy link → T5 · saveSettings partial → T6 · custom-rules card → T7 · downloader temp → T8 · socks buffering → T9 · geo note → T10.
- Engine entry + repo → T11 · per-engine download, exe naming, versions in Settings → T12, T13, T15 · selection rules (`defaultEngine`, PattN-if-any-member, sing-box single only) → T14 · missing-binary fallback → T13 · auto-recovery on "without TLS" + download offer → T13, T14, T15 · status line shows the engine → T15 · macOS parity (darwin asset names, `macPrepareBinary` via `place`) → T12 uses the existing `place()`, nothing platform-gated · CI matrix → T16.
- Deferred by design: TUN server-switch bug (phase 3), stats (phase 5), Android (phase 8).

**Placeholder scan:** none — every code step is complete; the only external dependency is internet for the download verification in T15 step 6, which has an offline path noted in T10.

**Type consistency:** `assetStatus(dirs, platform)` (T4) is used unchanged by T15 via `state.assets['xray-pattn']`; `engineExe(id, platform)` (T4) is what T11/T12 call; `resolveEngine()` returns `{id, bin}` everywhere (T13 → T14 `stats.setBin(xray.resolveEngine().bin)`); `validateWithFallback` result fields `{ok, engine, error, fellBack, plaintextRejected}` are read exactly so in T14's `doConnect`; the connected status carries `engine` (T14) and the renderer reads `d.engine` (T15); `testEngineFor`/`chooseEngine` names match between T14's module and both callers.
