# Phase B — performance — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the three things the user waits on fast — the servers list under a big subscription, "test all", and (re)connecting — and stop the app doing work nobody is watching.

**Architecture:** No new subsystems. B1 replaces two full re-renders with targeted DOM writes using `data-*` hooks the list already half has. B2 puts many latency targets into ONE throwaway core (Xray routes by `inboundTag`). B3 caches successful `-test` runs by a key that includes the core file and the geo files. B4 throttles a network probe that ran on every connect. B5 coalesces a store write. B6 slows the stats poll when the window is hidden, keeping the meter's baseline.

**Tech Stack:** Node 18+ core only, Electron 31, `node --test`. Branch `feature/phase-B` from `main` (after phase A merges). Tag: v1.4.0.

## Global Constraints

- Runtime code uses only Node core modules; `package.json` `dependencies` stays empty.
- `node --test "tests/*.test.js"` stays green and its output pristine.
- `npm run validate` must stay green on BOTH cores after B2 (a new config shape is added there).
- `src/server/service.js` mirrors `src/main/main.js`; every handler change lands in both in the same commit.
- Renderer: every string via `t()`; keys once per language; logical CSS properties only; tokens only; no inline styles; `[hidden]` hides.
- Browser verification through the headless server: `node src/server/server.js --port 3998 --data-dir %TEMP%\irnf-phaseB`. Never 10808/10809/10085; never kill `IRNetFree.exe`.
- Nothing touches the machine's real network. B2 spawns throwaway cores on loopback only, exactly like `ping:real` does today.
- Commits in the owner's name only, no `Co-Authored-By`. Do not bump the version.

Parallel batches: {B1, B4, B5, B6} · {B2, B3} (both touch `xrayManager.js`; do B3 first, then B2). Fable reviews B2 + B3 together.

---

## File map

| File | Responsibility | Tasks |
|---|---|---|
| `src/renderer/app.js` | `refreshSelection`, `applyUsageDisplays`, batched `pingMany` | B1, B2 |
| `src/main/configBuilder.js`, `tests/configBuilder.test.js` | `buildMultiTestConfig` | B2 |
| `src/main/xrayManager.js`, `tests/xrayManager.test.js` | `getFreePorts`, validation cache | B2, B3 |
| `src/main/netutils.js`, `tests/netutils.test.js` | `pLimit` | B2 |
| `src/main/main.js`, `src/server/service.js` | `ping:realMany`; stats cadence; `setLazy` for the proc cache; cert re-check stamps | B2, B4, B5, B6 |
| `src/preload/preload.js`, `src/server/web-api.js` | `pingRealMany` | B2 |
| `scripts/validate-configs.js` | the multi-target test shape | B2 |
| `src/main/certPin.js`, `tests/certPin.test.js` | `recheckDue` | B4 |
| `src/main/store.js`, `tests/store.test.js` | `setLazy`, `flush` | B5 |
| `src/main/stats.js`, `tests/stats.test.js` | `retime` | B6 |

---

### Task B1: update the list in place instead of rebuilding it

**Files:**
- Modify: `src/renderer/app.js` (`renderServers` 787–889, `selectServer` 891–899, the usage handler 3404–3410)

**Why:** `renderServers()` rebuilds every card (`innerHTML = ''`) and is called on every selection click and on every lifetime-usage event — every 5 s while connected. With a 200-server subscription that is 200 cards, 1,400 handler bindings and a scroll-position reset every 5 s. `applyPingDisplays()` already shows the right pattern: it writes into `[data-ping=…]` spans and leaves the list alone.

**Interfaces:**
- Produces (renderer): `refreshSelection()`, `applyUsageDisplays()`; cards carry `data-srv-id`, usage spans carry `data-usage` (D9 hangs on this).

- [ ] **Step 1: Hooks on the card**

In `renderServers()`:

Change `card.className = 'server-card' + …;` to also stamp the id:
```js
    card.className = 'server-card' + (isActive ? ' active' : '') + (isSel ? ' selected' : '');
    card.dataset.srvId = s.id;
```

Change the badge so it ALWAYS exists and is hidden when not selected (replace the `selBadge` const and its use):
```js
    const selBadge = `<span class="sel-badge"${isSel ? '' : ' hidden'}>✓ ${escapeHtml(t('srv.selected'))}</span>`;
```

Change the usage span to carry the id (if phase A5 already added `data-usage-id`, keep that attribute and ADD this one):
```js
      <span class="srv-usage" data-usage="${s.id}" …>${usageLabel(s.id)}</span>
```

- [ ] **Step 2: The two in-place updaters**

Add after `renderServers()`:

```js
/**
 * Selection changed: toggle the class and the badge on the cards that exist.
 * Rebuilding the whole list for one click reset the scroll position and,
 * under a large subscription, cost hundreds of nodes per keystroke.
 */
function refreshSelection() {
  const sel = state.selectedServerId;
  $$('#serverList .server-card[data-srv-id]').forEach((card) => {
    const on = card.dataset.srvId === sel;
    card.classList.toggle('selected', on);
    const badge = card.querySelector('.sel-badge');
    if (badge) badge.hidden = !on;
  });
}

/** Lifetime totals changed: rewrite the spans that show them, nothing else. */
function applyUsageDisplays() {
  $$('[data-usage]').forEach((el) => { el.innerHTML = usageLabel(el.dataset.usage); });
}
```

- [ ] **Step 3: Use them**

In `selectServer(id)` replace `renderServers();` with `refreshSelection();`.

In the usage handler (line ≈ 3405) replace
```js
    renderServers();
    renderPicker();
```
with
```js
    applyUsageDisplays();
```
(the picker shows no usage figures; it was rebuilt for nothing).

Every other `renderServers()` call stays — those callers really change the list (import, delete, subscription refresh, language switch).

- [ ] **Step 4: Contract test**

Run: `npm test` — Expected: PASS (`sel-badge`, `srv-usage`, `server-card` are still styled; no new ids).

- [ ] **Step 5: Browser proof that the list is no longer rebuilt**

Headless server on 3998 with ≥ 3 servers in the store. In the browser tool:

```js
const first = document.querySelector('#serverList .server-card');
document.querySelectorAll('#serverList .srv-info')[1].click();     // select the second card
const same = first === document.querySelector('#serverList .server-card');
const sel = document.querySelectorAll('#serverList .server-card.selected').length;
const badges = [...document.querySelectorAll('#serverList .sel-badge')].filter(b => !b.hidden).length;
({ same, sel, badges })
```
Expected: `{ same: true, sel: 1, badges: 1 }`. Then click the first card's info again and confirm the badge moved.

- [ ] **Step 6: Commit**

```bash
git add src/renderer/app.js
git commit -m "Selecting a server or receiving a usage tick no longer rebuilds the whole server list"
```

---

### Task B2: "test all" runs one throwaway core, not one per server

**Files:**
- Modify: `src/main/configBuilder.js` (after `buildTestConfig`, line 709–726; export)
- Test: `tests/configBuilder.test.js`
- Modify: `src/main/xrayManager.js` (`getFreePort` at line 390; export)
- Test: `tests/xrayManager.test.js`
- Modify: `src/main/netutils.js` (add `pLimit`; export), `tests/netutils.test.js`
- Modify: `src/main/main.js` (inside `registerIpc`, after the `ping:upload` handler, line ≈ 1830), `src/server/service.js` (after `'ping:upload'`, line ≈ 1397)
- Modify: `src/preload/preload.js:55`, `src/server/web-api.js:89`
- Modify: `src/renderer/app.js` (`pingMany`, line ≈ 1186)
- Modify: `scripts/validate-configs.js`

**Why:** `pingMany()` runs the real-delay test SEQUENTIALLY, one `startTest()` (a full core process, 500 ms bind wait, a temp config) per server. Sixty servers = sixty process starts, a minute of waiting, and "پینگ نمی‌گیره". Xray routes by `inboundTag`, so one core with N SOCKS inbounds tests N targets at once.

**Interfaces:**
- Produces: `buildMultiTestConfig(targets, ports) → config` (configBuilder); `getFreePorts(n) → Promise<number[]>` (xrayManager); `pLimit(n) → (fn) => Promise` (netutils); IPC `ping:realMany(ids[]) → { [id]: { ok, ms, error? } }`; renderer API `pingRealMany(ids)`.

- [ ] **Step 1: Failing config test**

Append to `tests/configBuilder.test.js` (add `buildMultiTestConfig` to the require on line 15):

```js
test('buildMultiTestConfig: one inbound per target, routed to its own outbound, no tag collisions', () => {
  const c = buildMultiTestConfig([VLESS_WS_TLS, [TROJAN_TCP_TLS, SS_TCP], vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' })], [40001, 40002, 40003]);
  assert.deepEqual(c.inbounds.map(i => [i.tag, i.port, i.listen, i.protocol]), [
    ['test-in-0', 40001, '127.0.0.1', 'socks'],
    ['test-in-1', 40002, '127.0.0.1', 'socks'],
    ['test-in-2', 40003, '127.0.0.1', 'socks']
  ]);
  assert.deepEqual(c.routing.rules, [
    { type: 'field', inboundTag: ['test-in-0'], outboundTag: 'test-out-0' },
    { type: 'field', inboundTag: ['test-in-1'], outboundTag: 'test-out-1' },
    { type: 'field', inboundTag: ['test-in-2'], outboundTag: 'test-out-2' }
  ]);
  const tags = c.outbounds.map(o => o.tag);
  assert.equal(new Set(tags).size, tags.length, 'every outbound tag unique');
  // the chain: exit tagged for its inbound, hop chained under the same prefix
  assert.ok(tags.includes('test-out-1') && tags.includes('test-out-1-h0'));
  assert.equal(outboundTagged(c, 'test-out-1').streamSettings.sockopt.dialerProxy, 'test-out-1-h0');
  // the fragment dialer exists and the fragmented target dials through it
  assert.ok(tags.some(t => t.startsWith('dpi-')));
  assert.equal(c.log.loglevel, 'none');
  assert.equal(tags[tags.length - 1], 'direct');
});
```

Run: `node --test tests/configBuilder.test.js` — Expected: FAIL (`buildMultiTestConfig is not a function`).

- [ ] **Step 2: Implement `buildMultiTestConfig`**

In `src/main/configBuilder.js` after `buildTestConfig` (line 726):

```js
/**
 * ONE throwaway core for MANY latency targets. Inbound i on ports[i] is routed
 * to target i by inboundTag; a target may be a server or a chain (an array).
 * "Test all" used to spawn a core per server, in sequence — sixty servers were
 * sixty process starts. Tags carry the index so a chain's hops
 * (`test-out-3-h0`) and the shared anti-DPI dialers cannot collide.
 * Same shape as buildTestConfig otherwise: no DNS plan, no interface binding
 * (a ping runs without TUN), fragments applied so the test matches reality.
 */
function buildMultiTestConfig(targets, ports) {
  const inbounds = [], outbounds = [], rules = [];
  (targets || []).forEach((target, i) => {
    const inTag = `test-in-${i}`, outTag = `test-out-${i}`;
    inbounds.push({ tag: inTag, port: ports[i], listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth', udp: false } });
    const outs = Array.isArray(target) ? buildChainOutbounds(target, outTag) : [cloneOut(target.outbound, outTag, target)];
    outbounds.push(...outs);
    rules.push({ type: 'field', inboundTag: [inTag], outboundTag: outTag });
  });
  return {
    log: { loglevel: 'none' },
    inbounds,
    outbounds: applyFragments(outbounds).concat([{ tag: 'direct', protocol: 'freedom' }]),
    routing: { rules }
  };
}
```
Add `buildMultiTestConfig` to `module.exports` (line 888).

Run: `node --test tests/configBuilder.test.js` — Expected: PASS.

- [ ] **Step 3: `getFreePorts(n)`**

In `src/main/xrayManager.js`, after `getFreePort` (line ≈ 400):

```js
/**
 * n distinct free loopback ports, held open together until all are known —
 * asking getFreePort() n times can hand the same port back twice.
 */
function getFreePorts(n) {
  return new Promise((resolve, reject) => {
    const servers = [], ports = [];
    const closeAll = () => servers.forEach((s) => { try { s.close(); } catch { /* closing */ } });
    const next = () => {
      if (ports.length >= n) { closeAll(); return resolve(ports); }
      const srv = net.createServer();
      srv.once('error', (e) => { closeAll(); reject(e); });
      srv.listen(0, '127.0.0.1', () => { servers.push(srv); ports.push(srv.address().port); next(); });
    };
    next();
  });
}
```
(`net` is already required at the top of xrayManager.js for `getFreePort`; check with `grep -n "require('net')" src/main/xrayManager.js`.) Export: `module.exports = { XrayManager, getFreePort, getFreePorts, PLAINTEXT_REJECT };`

Test — append to `tests/xrayManager.test.js` (add `getFreePorts` to the require):
```js
test('getFreePorts hands out n distinct ports', async () => {
  const ports = await getFreePorts(5);
  assert.equal(ports.length, 5);
  assert.equal(new Set(ports).size, 5);
  for (const p of ports) assert.ok(p > 0 && p < 65536);
});
```

- [ ] **Step 4: `pLimit`**

In `src/main/netutils.js` before `module.exports`:

```js
/** At most n of the wrapped calls in flight at once; the rest queue in order. */
function pLimit(n) {
  let active = 0;
  const queue = [];
  const run = async (fn, resolve, reject) => {
    active++;
    try { resolve(await fn()); } catch (e) { reject(e); } finally {
      active--;
      if (queue.length) { const [f, r, j] = queue.shift(); run(f, r, j); }
    }
  };
  return (fn) => new Promise((resolve, reject) => {
    if (active < n) run(fn, resolve, reject); else queue.push([fn, resolve, reject]);
  });
}
```
Export it: `module.exports = { tcpPing, httpThroughProxy, uploadThroughProxy, ipInfo, socks5Connect, pLimit };`

Test — append to `tests/netutils.test.js` (add `pLimit` to its require of `../src/main/netutils`):
```js
test('pLimit never runs more than n at once and preserves results', async () => {
  const limit = pLimit(2);
  let active = 0, peak = 0;
  const job = (v) => limit(async () => {
    active++; peak = Math.max(peak, active);
    await new Promise(r => setTimeout(r, 5));
    active--; return v;
  });
  const out = await Promise.all([1, 2, 3, 4, 5].map(job));
  assert.deepEqual(out, [1, 2, 3, 4, 5]);
  assert.equal(peak, 2);
});
```

- [ ] **Step 5: The handler in main.js**

Add to the requires: `buildMultiTestConfig` (line 9, from `./configBuilder`), `getFreePorts` (line 17, from `./xrayManager`), `pLimit` (line 19, from `./netutils`).

Inside `registerIpc()`, right after the `ping:upload` handler's closing `});` (line ≈ 1830):

```js
  // Real delay for MANY targets: one throwaway core per engine, up to
  // REAL_BATCH targets each (a config with 200 inbounds is slow to start and
  // one bad member would take the batch down), REAL_PARALLEL requests in
  // flight so the test site is not hammered. Returns a result per id.
  const REAL_BATCH = 20, REAL_PARALLEL = 6;
  ipcMain.handle('ping:realMany', async (e, ids) => {
    const out = {};
    const list = [...new Set((Array.isArray(ids) ? ids : []).filter(Boolean))];
    if (!xray.binExists()) { for (const id of list) out[id] = { ok: false, error: 'xray binary missing' }; return out; }
    const byEngine = new Map();
    for (const id of list) {
      const { server, chain } = resolveTarget(id);
      if (!server) { out[id] = { ok: false, error: 'not found' }; continue; }
      const isChain = chain && chain.length >= 2;
      const plan = isChain ? { mode: 'chain', chain } : { mode: 'single', server };
      const eng = testEngineFor(chooseEngine(plan, getSettings().defaultEngine));
      if (!byEngine.has(eng)) byEngine.set(eng, []);
      byEngine.get(eng).push({ id, target: isChain ? chain : server });
    }
    const limit = pLimit(REAL_PARALLEL);
    for (const [eng, targets] of byEngine) {
      for (let i = 0; i < targets.length; i += REAL_BATCH) {
        const batch = targets.slice(i, i + REAL_BATCH);
        let test = null;
        try {
          const ports = await getFreePorts(batch.length);
          test = await xray.startTest(buildMultiTestConfig(batch.map(b => b.target), ports), eng);
          await Promise.all(batch.map((b, k) => limit(async () => {
            out[b.id] = await httpThroughProxy(ports[k], { host: 'cp.cloudflare.com', port: 80, path: '/' });
          })));
        } catch (err) {
          for (const b of batch) if (!out[b.id]) out[b.id] = { ok: false, error: err.message };
        } finally {
          if (test) test.cleanup();
        }
      }
    }
    return out;
  });
```

- [ ] **Step 6: Mirror in service.js**

Requires: `buildMultiTestConfig` (line 18), `getFreePorts` (line 26), `pLimit` (line 28). In the `handlers` object after `'ping:upload'` add `'ping:realMany': async (ids) => { …same body, without the `e` parameter… },` with `const REAL_BATCH = 20, REAL_PARALLEL = 6;` declared once above the `handlers` object.

- [ ] **Step 7: Expose**

`preload.js` after line 55: `pingRealMany: (ids) => ipcRenderer.invoke('ping:realMany', ids),`
`web-api.js` after line 89: `pingRealMany: (ids) => invoke('ping:realMany', ids),`

- [ ] **Step 8: Use it in the renderer**

Replace `pingMany` (line ≈ 1186–1195) with:

```js
/** Ping many: TCP for all in parallel, then real delay for all through ONE
 * throwaway core per engine (see ping:realMany). Falls back to one core per
 * target when the backend is older than this renderer. */
async function pingMany(ids) {
  ids = [...new Set(ids.filter(Boolean))];
  if (!ids.length) return;
  toast(t('t.pingingAll'));
  ids.forEach(setPingPending);
  await Promise.all(ids.map(pingTcpOnly));
  ids.forEach((id) => setPhasePending(id, 'data-ping-real'));
  if (window.api.pingRealMany) {
    const res = await window.api.pingRealMany(ids);
    for (const id of ids) {
      state.pings[id] = Object.assign(state.pings[id] || {}, { real: res[id] || { ok: false, error: 'no result' } });
      applyPingDisplays(id);
    }
  } else {
    for (const id of ids) await pingRealOnly(id);
  }
  renderPicker();
  toast(t('t.testDone'), 'ok');
}
```

- [ ] **Step 9: Validate the new shape on both cores**

In `scripts/validate-configs.js`, find where the Xray shapes are collected (the array of `{ name, config }` built from the fixtures — `grep -n "buildTestConfig" scripts/validate-configs.js` shows the existing single-target test case). Next to it add:

```js
  { name: 'multi-test (server + chain + fragment)', config: buildMultiTestConfig([VLESS_WS_TLS, [TROJAN_TCP_TLS, SS_TCP], vlessWithMarkers('sv-frag', { _fragment: 'tlshello,100-200,10-20' })], [41001, 41002, 41003]) },
```
importing `buildMultiTestConfig` from `../src/main/configBuilder` and `vlessWithMarkers` from `../tests/fixtures` if not already imported.

Run: `npm run validate` and `set IRNF_XRAY_EXE=<path to xray-pattn.exe> && npm run validate` — Expected: the new case passes on both (`193/193` or the new total).

- [ ] **Step 10: Suite + browser**

`npm test` — PASS. Headless server on 3998 with 3+ servers: click "تست همه"; all three real-delay badges leave "..." together; the server log shows ONE `Starting xray…`-style test spawn per engine, not one per server.

- [ ] **Step 11: Commit**

```bash
git add src/main/configBuilder.js tests/configBuilder.test.js src/main/xrayManager.js tests/xrayManager.test.js src/main/netutils.js tests/netutils.test.js src/main/main.js src/server/service.js src/preload/preload.js src/server/web-api.js src/renderer/app.js scripts/validate-configs.js
git commit -m "Test all starts one throwaway core per engine instead of one per server"
```

---

### Task B3: cache successful validations

**Files:**
- Modify: `src/main/xrayManager.js` (`validate` 183–218, `forgetVersions` 169, constructor 21–35)
- Test: `tests/xrayManager.test.js`

**Why:** `validateWithFallback()` runs the core with `-test` before EVERY connect and reconnect (1–6 s, up to the safety timeout). A reconnect after a network change rebuilds the identical config; so does a server switch back to a config validated a minute ago. A validation is a fact about (core file, geo files, config bytes) — cache it on exactly those.

**Interfaces:**
- Produces: `validate()` resolves `{ ok: true, cached: true }` on a hit; `{ ok: true, unverified: true }` when the result came from the timeout or an old core without `-test` (never cached); `forgetVersions()` also clears the cache.

- [ ] **Step 1: Failing tests**

Append to `tests/xrayManager.test.js`:

```js
test('validate: an identical config on the same core is not spawned twice; forgetVersions() clears it', async () => {
  await withBin([exe('xray')], async (xm) => {
    const before = spawns.length;
    fakeSpawn = () => { const p = stubChild(); setImmediate(() => p.emit('exit', 0)); return p; };
    try {
      const cfg = { log: { loglevel: 'none' }, inbounds: [], outbounds: [] };
      assert.deepEqual(await xm.validate(cfg, 'xray'), { ok: true });
      assert.deepEqual(await xm.validate(cfg, 'xray'), { ok: true, cached: true });
      assert.equal(spawns.length - before, 1);
      // a different config is a different fact
      await xm.validate(Object.assign({}, cfg, { log: { loglevel: 'warning' } }), 'xray');
      assert.equal(spawns.length - before, 2);
      xm.forgetVersions();
      await xm.validate(cfg, 'xray');
      assert.equal(spawns.length - before, 3);
    } finally { fakeSpawn = null; }
  });
});

test('validate: a rejected config and a timed-out check are never cached', async () => {
  await withBin([exe('xray')], async (xm) => {
    const before = spawns.length;
    fakeSpawn = () => { const p = stubChild(); setImmediate(() => { p.stderr.emit('data', Buffer.from('Failed to start: bad thing')); p.emit('exit', 1); }); return p; };
    try {
      const cfg = { log: { loglevel: 'none' }, inbounds: [], outbounds: [] };
      assert.equal((await xm.validate(cfg, 'xray')).ok, false);
      assert.equal((await xm.validate(cfg, 'xray')).ok, false);
      assert.equal(spawns.length - before, 2);
    } finally { fakeSpawn = null; }
  });
});
```

Run: `node --test tests/xrayManager.test.js` — Expected: FAIL on the `cached: true` deep-equal.

- [ ] **Step 2: Implement**

Constructor (after `this._versions = {}` or wherever the version map is initialised — `grep -n "_versions" src/main/xrayManager.js`): add
```js
    /** Validations that passed, keyed by core file + geo files + config bytes. */
    this._validated = new Map();
```
`forgetVersions()` becomes:
```js
  forgetVersions() { this._versions = {}; this._validated.clear(); }
```
Add the key builder next to `validate`:
```js
  /** What a validation is a fact about: this core file, these geo files, these bytes. */
  validationKey(id, bin, config) {
    const mt = (p) => { try { return String(fs.statSync(p).mtimeMs); } catch { return '0'; } };
    const ad = this.assetDir();
    const geo = ad ? `${mt(path.join(ad, 'geoip.dat'))}/${mt(path.join(ad, 'geosite.dat'))}` : '0/0';
    const digest = crypto.createHash('sha256').update(JSON.stringify(config)).digest('hex');
    return `${id}|${bin}|${mt(bin)}|${geo}|${digest}`;
  }
```
(add `const crypto = require('crypto');` to the requires.)

In `validate()`:
- after `if (!bin) return resolve({ ok: false, error: 'core binary not found' });` add
  ```js
      const key = this.validationKey(id, bin, config);
      if (this._validated.has(key)) return resolve({ ok: true, cached: true });
  ```
- change the `finish` closure to remember only a real pass:
  ```js
      const finish = (res) => {
        if (settled) return;
        settled = true;
        try { fs.unlinkSync(cfgPath); } catch {}
        if (res.ok && !res.unverified) {
          this._validated.set(key, true);
          if (this._validated.size > 64) this._validated.delete(this._validated.keys().next().value);
        }
        resolve(res);
      };
  ```
- the "older build without -test" branch resolves `finish({ ok: true, unverified: true })`;
- the safety timeout resolves `finish({ ok: true, unverified: true })`.

`validateWithFallback` needs no change (`r.ok` is all it reads).

- [ ] **Step 3: Tests**

Run: `npm test` — Expected: PASS (existing validate tests still see `ok: true`; the first one now also sees no extra key — if an existing test uses `deepEqual` against `{ ok: true }` on a FIRST call it still passes; only repeated calls in one test would see `cached`).

- [ ] **Step 4: Commit**

```bash
git add src/main/xrayManager.js tests/xrayManager.test.js
git commit -m "A config the core already accepted is not run through -test again until the core, the geo files or the config change"
```

Fable review (with B2): the cache must never turn a `-test` failure into a pass; the key must change when a core is re-downloaded in place (mtime) and when geo files arrive (a config with geosite rules validated before the files existed was rejected — not cached — and passes after; the reverse case, files removed after a pass, changes the key through the mtime read failing to `'0'`).

---

### Task B4: do not re-check every pinned certificate on every connect

**Files:**
- Modify: `src/main/certPin.js` (`staleCertPins`, line 198; export)
- Test: `tests/certPin.test.js`
- Modify: `src/main/main.js` (`ensureCertPins`, line 526–560) and `src/server/service.js` (`ensureCertPins`, line 523)

**Why:** `ensureCertPins()` opens a TLS connection to every directly-dialled pinned server on every connect, to catch a rotated certificate. Rotation is a weekly-to-yearly event; the probe costs up to 5 s of the connect on a slow link and is repeated on every network-change recovery.

**Interfaces:**
- Produces: `recheckDue(server, now?, maxAgeMs?) → boolean` and `RECHECK_AFTER_MS` from certPin.js; records gain `certPinCheckedAt` (ms epoch).

- [ ] **Step 1: Failing test**

Append to `tests/certPin.test.js` (add `recheckDue, RECHECK_AFTER_MS` to the require):

```js
test('recheckDue: a pin checked within the window is left alone; older, missing or unpinned is due', () => {
  const now = 1_000_000_000_000;
  const fresh = { certPin: 'ab', certPinCheckedAt: now - RECHECK_AFTER_MS + 1 };
  const old = { certPin: 'ab', certPinCheckedAt: now - RECHECK_AFTER_MS - 1 };
  const never = { certPin: 'ab' };
  const unpinned = { certPinCheckedAt: now };
  assert.equal(recheckDue(fresh, now), false);
  assert.equal(recheckDue(old, now), true);
  assert.equal(recheckDue(never, now), true);
  assert.equal(recheckDue(unpinned, now), false, 'nothing to re-check without a pin');
  assert.equal(RECHECK_AFTER_MS, 6 * 3600 * 1000);
});
```

Run: `node --test tests/certPin.test.js` — Expected: FAIL.

- [ ] **Step 2: Implement**

In `src/main/certPin.js` before `staleCertPins`:

```js
/** A pin is re-verified against the live server at most this often. */
const RECHECK_AFTER_MS = 6 * 3600 * 1000;

/** Should this record's pin be checked against the server now? */
function recheckDue(server, now, maxAgeMs) {
  if (!server || !server.certPin) return false;
  const t = now == null ? Date.now() : now;
  const max = maxAgeMs == null ? RECHECK_AFTER_MS : maxAgeMs;
  const at = Number(server.certPinCheckedAt) || 0;
  return t - at >= max;
}
```
Export both: add `recheckDue, RECHECK_AFTER_MS` to `module.exports`.

- [ ] **Step 3: Use it in `ensureCertPins` (main.js)**

Replace
```js
  const stale = await staleCertPins(directServers(plan), fetchLeafPin).catch(() => []);
  if (stale.length) {
    const ids = new Set(stale.map(s => s.id));
    store.set('servers', store.get('servers', []).map(s => {
      if (!ids.has(s.id)) return s;
      const out = Object.assign({}, s);
      delete out.certPin; delete out.certPinAt;
      return out;
    }));
```
with
```js
  // Only the pins that are due: a rotation is a rare event and the probe is
  // a TLS dial per server on every connect and every recovery. The ones that
  // are checked are stamped, stale or not.
  const now = Date.now();
  const due = directServers(plan).filter(s => recheckDue(s, now));
  const stale = due.length ? await staleCertPins(due, fetchLeafPin).catch(() => []) : [];
  if (due.length) {
    const dueIds = new Set(due.map(s => s.id));
    const staleIds = new Set(stale.map(s => s.id));
    store.set('servers', store.get('servers', []).map(s => {
      if (!dueIds.has(s.id)) return s;
      const out = Object.assign({}, s, { certPinCheckedAt: now });
      if (staleIds.has(s.id)) { delete out.certPin; delete out.certPinAt; }
      return out;
    }));
```
The rest of the block (the `for (const s of stale)` log loop and the probe) stays as is. Import `recheckDue` at line 14: `const { fetchLeafPin, pinTargets, directServers, staleCertPins, PinWatch, recheckDue } = require('./certPin');`

Also stamp a NEWLY learned pin: in the same function, where the probe result is written (`certPin`, `certPinAt` are set on the stored record — `grep -n "certPinAt" src/main/main.js`), add `certPinCheckedAt: now` next to `certPinAt`.

- [ ] **Step 4: Mirror in service.js** — same edits in its `ensureCertPins` (line 523) and require (line 23).

- [ ] **Step 5: Tests**

Run: `npm test` — PASS.

- [ ] **Step 6: Commit**

```bash
git add src/main/certPin.js tests/certPin.test.js src/main/main.js src/server/service.js
git commit -m "A pinned certificate is re-checked against its server every six hours, not on every connect"
```

---

### Task B5: coalesce the process-IP cache writes

**Files:**
- Modify: `src/main/store.js` (`Store`), `tests/store.test.js`
- Modify: `src/main/main.js` (`saveProcCache` line ≈ 350; `teardownForQuit` line ≈ 2145), `src/server/service.js` (its `saveProcCache`; `shutdown` line 1471)

**Why:** every `store.set()` serialises the whole store, fsyncs a temp file and renames it (by design — durability). The process-routing watcher calls `saveProcCache()` every 20 s while connected, rewriting a store that holds every server for a cache nobody needs on disk this second.

**Interfaces:**
- Produces: `Store.setLazy(key, value, delayMs = 500)`, `Store.flush()`.

- [ ] **Step 1: Failing test**

Append to `tests/store.test.js`:

```js
test('setLazy coalesces writes; flush() and save() write what it holds', async () => {
  await withDirAsync(async ({ file }) => {
    const s = new Store(file, DEFAULTS);
    s.setLazy('procIpCache', { a: 1 }, 30);
    s.setLazy('procIpCache', { a: 2 }, 30);
    assert.equal(fs.existsSync(file), false, 'nothing written yet');
    await new Promise(r => setTimeout(r, 60));
    assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')).procIpCache, { a: 2 });
    s.setLazy('procIpCache', { a: 3 }, 30);
    assert.equal(s.flush(), true);
    assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')).procIpCache, { a: 3 });
    s.setLazy('procIpCache', { a: 4 }, 30);
    s.set('servers', []);                          // an ordinary save carries the lazy value too
    assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')).procIpCache, { a: 4 });
    await new Promise(r => setTimeout(r, 60));    // and no second write follows
  });
});
```
and the async helper next to `withDir`:
```js
async function withDirAsync(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-store-'));
  const file = path.join(dir, 'store.json');
  try { return await fn({ dir, file }); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
```

Run: `node --test tests/store.test.js` — Expected: FAIL (`s.setLazy is not a function`).

- [ ] **Step 2: Implement**

In `class Store`: constructor gets `this.lazyTimer = null;`. Add after `assign(obj)`:

```js
  /**
   * Like set(), but the write is coalesced: any number of calls inside
   * `delayMs` produce one save. For values nobody needs on disk this instant
   * (the process-IP cache is rewritten every 20 s for the life of a tunnel).
   */
  setLazy(key, value, delayMs = 500) {
    this.data[key] = value;
    if (this.lazyTimer) return true;
    this.lazyTimer = setTimeout(() => { this.lazyTimer = null; this.save(); }, delayMs);
    if (this.lazyTimer.unref) this.lazyTimer.unref();
    return true;
  }

  /** Write whatever setLazy() is still holding. Synchronous, for exit paths. */
  flush() {
    if (!this.lazyTimer) return true;
    clearTimeout(this.lazyTimer);
    this.lazyTimer = null;
    return this.save();
  }
```
At the top of `save()` add:
```js
    if (this.lazyTimer) { clearTimeout(this.lazyTimer); this.lazyTimer = null; }   // this write carries it
```

- [ ] **Step 3: Use it**

`main.js` line ≈ 350: `function saveProcCache(c) { store.setLazy('procIpCache', c); }`. In `teardownForQuit()` first line after `userDisconnecting = true;`: `try { store.flush(); } catch {}`. Also in the `process.on('exit')` handler before the win32 gate: `try { if (store) store.flush(); } catch {}`.
`service.js`: same for its `saveProcCache`; in `shutdown()` add `try { store.flush(); } catch {}` before the stats stop.

- [ ] **Step 4: Tests + commit**

`npm test` — PASS.
```bash
git add src/main/store.js tests/store.test.js src/main/main.js src/server/service.js
git commit -m "The process-IP cache no longer rewrites the whole store every twenty seconds"
```

---

### Task B6: poll the core five times slower while nobody is looking

**Files:**
- Modify: `src/main/stats.js` (`StatsPoller.start` 81–117), `tests/stats.test.js`
- Modify: `src/main/main.js` (`createWindow` 292; `stats.start(1000)` at 979)

**Why:** the poller hits `/debug/vars` every second for the life of a connection; with the window in the tray that is 3,600 HTTP requests an hour, a JSON parse each, for a number nobody sees. The usage meter works on deltas and the speeds on measured `dt`, so a slower cadence loses nothing — the baseline must simply be kept across the change.

**Interfaces:**
- Produces: `StatsPoller.retime(intervalMs)` — changes the cadence without resetting `last`/`lastPer`.

- [ ] **Step 1: Failing test**

Append to `tests/stats.test.js`:

```js
test('retime changes the cadence and keeps the baseline (no phantom speed spike)', async () => {
  const seen = [];
  const p = new StatsPoller({ onStats: (s) => seen.push(s) });
  let up = 1000;
  p.query = async () => ({ up, down: 0, per: {} });
  p.start(10);
  await new Promise(r => setTimeout(r, 25));
  up = 2000;
  p.retime(30);
  assert.equal(p.intervalMs, 30);
  await new Promise(r => setTimeout(r, 45));
  p.stop();
  const last = seen[seen.length - 1];
  // 1000 bytes over the measured gap, never 2000 over a reset baseline
  assert.ok(last.upSpeed > 0 && last.upSpeed < 1000 * 1000 / 25, 'speed computed against the kept baseline: ' + last.upSpeed);
  assert.equal(last.totalUp, 2000);
});
```

Run: `node --test tests/stats.test.js` — Expected: FAIL (`p.retime is not a function`).

- [ ] **Step 2: Refactor `start` into `start` / `arm` / `tick` / `retime`**

Replace `start(intervalMs = 1000) { … }` (lines 81–117) with:

```js
  start(intervalMs = 1000) {
    this.stop();
    this.intervalMs = intervalMs;
    this.last = { up: 0, down: 0, t: Date.now() };
    this.lastPer = {};
    this.arm();
  }

  arm() {
    this.timer = setInterval(() => this.tick(), this.intervalMs);
    if (this.timer.unref) this.timer.unref();
  }

  /**
   * Change the cadence without losing the baseline. Speeds divide by the
   * measured gap, so a slower tick reads the same bytes over a longer dt —
   * not a burst. Used to poll less while the window is hidden.
   */
  retime(intervalMs) {
    if (!intervalMs || intervalMs === this.intervalMs) return;
    this.intervalMs = intervalMs;
    if (!this.timer) return;
    clearInterval(this.timer);
    this.arm();
  }

  async tick() {
    const cur = await this.query();
    if (!cur) return;
    const now = Date.now();
    const dt = (now - this.last.t) / 1000 || 1;
    const upSpeed = Math.max(0, (cur.up - this.last.up) / dt);
    const downSpeed = Math.max(0, (cur.down - this.last.down) / dt);
    const per = {};
    for (const [tag, v] of Object.entries(cur.per || {})) {
      const prev = this.lastPer[tag] || { up: 0, down: 0 };
      per[tag] = { up: v.up, down: v.down, upSpeed: Math.max(0, (v.up - prev.up) / dt), downSpeed: Math.max(0, (v.down - prev.down) / dt) };
    }
    this.lastPer = cur.per || {};
    this.totals = { up: cur.up, down: cur.down };
    this.last = { up: cur.up, down: cur.down, t: now };
    this.onStats({ upSpeed, downSpeed, totalUp: cur.up, totalDown: cur.down, per });
  }
```
(the body of `tick()` is the old interval callback, unchanged; add `this.intervalMs = 1000;` to the constructor.)

- [ ] **Step 3: Wire the window state (main.js only — the service has no window)**

Add near the top of main.js (after `let usage = null;`):
```js
const STATS_VISIBLE_MS = 1000, STATS_HIDDEN_MS = 5000;
/** One poll a second while the numbers are on screen; one every five when they are not. */
function statsCadence() {
  const shown = mainWindow && !mainWindow.isDestroyed() && mainWindow.isVisible() && !mainWindow.isMinimized();
  return shown ? STATS_VISIBLE_MS : STATS_HIDDEN_MS;
}
```
In `createWindow()` after `mainWindow.loadFile(...)`:
```js
  for (const ev of ['show', 'hide', 'minimize', 'restore', 'focus']) {
    mainWindow.on(ev, () => { if (stats) stats.retime(statsCadence()); });
  }
```
Line 979: `stats.start(1000);` → `stats.start(statsCadence());`

Note in the commit body: `SilenceWatch` counts ticks, so a silent WireGuard is reported after ~25 s instead of ~5 s while the window is hidden; the usage save cadence is time-based and unaffected.

- [ ] **Step 4: Tests + commit**

`npm test` — PASS.
```bash
git add src/main/stats.js tests/stats.test.js src/main/main.js
git commit -m "The traffic meter polls the core every five seconds while the window is hidden, one second while it is shown"
```

---

## Phase gate

- `npm test` green, pristine; `npm run validate` green on both cores (B2 added a shape).
- Fable review of B2 + B3 diffs.
- Headless smoke on 3998: servers list stays in place across selection and usage ticks (B1 step 5); "test all" on 3 servers spawns one core.
- The owner merges `feature/phase-B` and tags v1.4.0.
