# Phase C — reliability and leak-proofing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Run this plan on Fable** — C5, C6, C8 and C9 are ★★★★.

**Goal:** Let the app PROVE on the user's own machine that nothing leaks (C1), notice a dead tunnel and recover or move on (C2), stop handing the server's name to the ISP before the tunnel is up (C3), notice a router swap the address watcher cannot see (C4), narrow the strict firewall's resolver holes to port 53 (C5), stop sing-box-format configs resolving every name off the tunnel (C6), expose the one sniffing knob the open PattN report needs (C7), run a PattN-hop / official-exit chain on two cores (C8), and give Linux a strict guard and macOS a clean DNS snapshot (C9).

**Architecture:** New pure modules with injected I/O (`selfTest.js`, `healthWatch.js`, the DoH resolver in `netutils.js`, the gateway reader in `tunPlatform.js`, `splitPlan.js`) carry the logic and are unit-tested; `main.js`/`service.js` wire them. The leak guard (`leakGuard.js`) and the two config builders change shape only where a test pins the new shape. Everything that needs a real adapter is marked **device-verified** with an exact checklist for the owner.

**Tech Stack:** Node 18+ core, Electron 31, `node --test`, Xray 26.3.27 + PattN 26.9.1 for `npm run validate`, sing-box 1.13.14 (`IRNF_SINGBOX_EXE`) for `sing-box check`. Branch `feature/phase-C` from `main`. Tag: v1.7.0 (D shipped first as v1.5.0, its D10 as v1.6.0).

## Global Constraints

- Runtime code uses only Node core modules; `package.json` `dependencies` stays empty.
- `npm test` green and pristine. `npm run validate` green on both cores (`IRNF_XRAY_EXE` for the second run); with `IRNF_SINGBOX_EXE` set, the sing-box shapes pass `sing-box check`. `node scripts/probe-dns-leak.js` 36/36 after C6 (it exercises `buildConfig`; C6 touches `resolverBypassIpsOf` only for sing-box configs, but run it anyway).
- `src/server/service.js` mirrors `src/main/main.js`, same commit.
- New settings: default in BOTH `DEFAULT_SETTINGS` (main.js ≈ 89, service.js 43); connection-baked ones go into `RECONNECT_KEYS` + `set.<key>` in both i18n blocks (`tests/settingsMeta.test.js`); renderer reads/writes them in `applySettingsToUI()` (app.js 313) and `readSettingsForm()` (476) and the row's own `onchange`.
- Renderer rules: `t()` for every string, keys once per language, logical CSS properties, tokens only, no inline styles, `[hidden]` hides. Browser checks through `node src/server/server.js --port 3997 --data-dir %TEMP%\irnf-phaseC`. Never 10808/10809/10085; never kill `IRNetFree.exe`.
- **Nothing in this plan may touch this machine's network**: no TUN start, no `netsh`/`New-NetFirewallRule`/`pfctl`/`nft`, no adapter DNS, no admin relaunch. The generated scripts are asserted as TEXT. Loopback-only child processes (as `probe-dns-leak.js` already does) are fine.
- `routing.rules` order is load-bearing; `dns` rule order too (dnsBuilder.js comments). Never reorder without a test.
- Commits in the owner's name only, no `Co-Authored-By`. Do not bump the version.

Order: C7 first (tiny, and it gates C8). Then {C1, C2, C3, C4} in parallel (independent modules; C2 and C4 both edit `startNetWatcher`/`runRecovery` — merge carefully or run C4 after C2). Then C5+C6 together. C9. C8 **only** if the owner reports the PattN failure survives C7's `routeOnly` and Sniffing-off.

---

## File map

| File | Responsibility | Tasks |
|---|---|---|
| `src/main/configBuilder.js` | `routeOnly`; `resolverBypassIpsOf` for sing-box configs; `bindDirectDials` loopback exception | C7, C6, C8 |
| `src/main/selfTest.js` (new), `tests/selfTest.test.js` | STUN, verdict table | C1 |
| `src/main/netutils.js` | `ipInfoV6`, `resolveDoh` (+ DNS wire helpers) | C1, C3 |
| `src/main/healthWatch.js` (new), `tests/healthWatch.test.js` | probe loop, `nextServerId` | C2 |
| `src/main/tunPlatform.js`, `tests/tunPlatform.test.js` | `resolveServerIps({doh})`, `parseDefaultGateway`, `defaultGateway` | C3, C4 |
| `src/main/netWatcher.js`, `tests/netWatcher.test.js` | `readSlow` gateway baseline | C4 |
| `src/main/leakGuard.js`, `tests/leakGuard.test.js` | resolver holes on :53/:443 (win + pf); Linux nftables | C5, C9 |
| `src/main/singboxBuilder.js`, `tests/singboxBuilder.test.js` | remote DNS via proxy, hijack rule | C6 |
| `src/main/splitPlan.js` (new), `tests/splitPlan.test.js`; `src/main/xrayManager.js` | two-core chains | C8 |
| `src/main/tunSingbox.js`, `tests/tunSingbox.test.js` | mac: no DNS line when the guard owns DNS | C9 |
| `src/main/main.js`, `src/server/service.js` | wiring for every task | all |
| `src/preload/preload.js`, `src/server/web-api.js` | `selfTest` | C1 |
| `src/renderer/index.html`, `app.js`, `i18n.js`, `home.css`, `settings.css` | self-test panel; health, bootstrap, routeOnly rows | C1, C2, C3, C7 |
| `src/main/settingsMeta.js` | `sniffRouteOnly`, `dnsBootstrap`, `healthCheck`, `healthAction` (health keys are read live: NOT reconnect keys) | C2, C3, C7 |

---

### Task C7: sniffing `routeOnly`

**Files:**
- Modify: `src/main/configBuilder.js:474-476` (+ `SETTINGS_DEFAULTS` line 415), `tests/configBuilder.test.js:70`
- Modify: `src/main/settingsMeta.js` (`RECONNECT_KEYS`), `src/main/main.js` + `src/server/service.js` (`DEFAULT_SETTINGS`)
- Modify: `src/renderer/index.html` (after the Sniffing row, line 446), `app.js` (313, 476), `i18n.js`

**Why:** the open report — `gitlab.hawk.tes.systems unexpectedly closed the connection` on PattN, every permutation — has one untested hypothesis: sniffing rewrites the destination to the sniffed SNI and PattN dials THAT. `routeOnly: true` uses the sniffed name for routing only and dials the original address. The user should be able to flip it without editing JSON.

- [ ] **Step 1: Failing test**

In `tests/configBuilder.test.js` next to the sniffing test (line ≈ 66–74) add:
```js
test('sniffing: routeOnly follows the setting', () => {
  const c = buildConfig(single(), settings({ enableSniffing: true, sniffRouteOnly: true }));
  assert.deepEqual(c.inbounds[0].sniffing, { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: true });
  assert.deepEqual(c.inbounds[1].sniffing, c.inbounds[0].sniffing);
});
```
Run: `node --test tests/configBuilder.test.js` — FAIL.

- [ ] **Step 2: Builder**

Line 474–476:
```js
  const sniffing = s.enableSniffing
    ? { enabled: true, destOverride: ['http', 'tls', 'quic'], routeOnly: !!s.sniffRouteOnly }
    : { enabled: false };
```
`SETTINGS_DEFAULTS` (line 415 area): add `sniffRouteOnly: false,` after `enableSniffing: true,`.

- [ ] **Step 3: Setting plumbing**

`settingsMeta.js` `RECONNECT_KEYS`: after `'enableSniffing',` add `'sniffRouteOnly',`.
`main.js` DEFAULT_SETTINGS after `enableSniffing: true,`: `sniffRouteOnly: false,` — same in `service.js`.
`i18n.js`: after `'set.defaultEngine': 'هستهٔ پیش‌فرض',` (fa) add
```js
    'set.sniffRouteOnly': 'Sniffing فقط برای روتینگ', 'sniffro.title': 'Sniffing فقط برای روتینگ (routeOnly)',
    'sniffro.sub': 'نام تشخیص‌داده‌شده فقط برای انتخاب مسیر استفاده می‌شود؛ هسته همان آدرس اصلی را می‌گیرد. اگر سایتی «connection closed» می‌دهد، این را امتحان کنید',
```
and after `'set.defaultEngine': 'Default core',` (en):
```js
    'set.sniffRouteOnly': 'Sniffing for routing only', 'sniffro.title': 'Sniffing for routing only (routeOnly)',
    'sniffro.sub': 'The sniffed name is used to pick the route only; the core dials the original address. Try this when a site closes the connection',
```
`index.html` after the Sniffing switch-row (line 446):
```html
            <div class="switch-row">
              <div><div class="switch-title" data-i18n="sniffro.title">Sniffing فقط برای روتینگ</div>
                <div class="switch-sub" data-i18n="sniffro.sub"></div></div>
              <label class="switch"><input type="checkbox" id="optSniffRouteOnly" /><span class="slider"></span></label>
            </div>
```
`app.js` `applySettingsToUI()`: `$('#optSniffRouteOnly').checked = !!s.sniffRouteOnly;` next to `optSniff`. `readSettingsForm()`: `sniffRouteOnly: $('#optSniffRouteOnly').checked,` after `enableSniffing`. Find how `#optSniff` saves (`grep -n "optSniff" src/renderer/app.js`) and mirror the same `onchange → saveSettings({...})` for `optSniffRouteOnly`.

- [ ] **Step 4: Validate + tests**

`npm test` — PASS (settingsMeta test sees `set.sniffRouteOnly` in both). `npm run validate` on both cores — PASS (add `{ sniffRouteOnly: true }` to the sniffing variants in `scripts/validate-configs.js` if it enumerates them: `grep -n enableSniffing scripts/validate-configs.js`).

- [ ] **Step 5: Commit**

```bash
git add src/main/configBuilder.js tests/configBuilder.test.js src/main/settingsMeta.js src/main/main.js src/server/service.js src/renderer/index.html src/renderer/app.js src/renderer/i18n.js scripts/validate-configs.js
git commit -m "Sniffing can be limited to routing so the core dials the original address instead of the sniffed name"
```

Tell the owner: test `gitlab.hawk.tes.systems` on PattN with (a) routeOnly on, (b) Sniffing off. Send the log. C8 waits on the answer.

---

### Task C1: the in-app leak self-test

**Files:**
- Create: `src/main/selfTest.js`, `tests/selfTest.test.js`
- Modify: `src/main/netutils.js` (add `ipInfoV6`; export), `src/main/main.js` (IPC), `src/server/service.js` (handler), `preload.js`, `web-api.js`
- Modify: `src/renderer/index.html` (hero actions line 172–176; a results panel), `app.js`, `i18n.js`, `home.css`

**Why:** every guarantee about leaks so far is a statement about configs and generated scripts; nothing has ever been measured on a real adapter. This asks the live machine four questions and shows the answers on the home page.

**Interfaces:**
- Produces: `runSelfTest(probes) → { checks: [{ id, status, detail }], leak: boolean }`, `stunMappedAddress()`, `parseStunMapped()` (selfTest.js); `ipInfoV6()` (netutils); IPC `vpn:selfTest` → the result; renderer API `selfTest()`.
- `status` ∈ `'pass' | 'leak' | 'warn' | 'info' | 'skip'`; `leak` is true iff any check is `'leak'`.

- [ ] **Step 1: Failing tests**

Create `tests/selfTest.test.js`:

```js
'use strict';
/**
 * "Is anything leaving outside the tunnel?" — the verdict table. Every probe
 * is injected, so these run with no network and pin exactly which
 * combination of answers is called a leak. A wrong "no leak" is the worst bug
 * this app can have, so the table is spelled out case by case.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { runSelfTest, parseStunMapped, stunRequest } = require('../src/main/selfTest');

const ok = (ip) => async () => ({ ok: true, ip });
const fail = async () => ({ ok: false, error: 'timeout' });
const byId = (r) => Object.fromEntries(r.checks.map(c => [c.id, c.status]));

function probes(over) {
  return Object.assign({
    mode: 'tun', ipv6: false, udpBlocked: false,
    guard: { engaged: true, peer4: '172.19.0.2', peer6: 'fdfe:dcba:9876::2', level: 'standard' },
    exitViaProxy: ok('5.5.5.5'), exitViaSystem: ok('5.5.5.5'),
    resolvers: () => ['172.19.0.2', 'fdfe:dcba:9876::2'],
    resolveNonce: async () => ({ ok: true }),
    stun: ok('5.5.5.5'), v6Exit: fail
  }, over || {});
}

test('TUN, guard on, everything through the tunnel: all pass, no leak', async () => {
  const r = await runSelfTest(probes());
  assert.deepEqual(byId(r), { exit: 'pass', 'dns-servers': 'pass', 'dns-resolve': 'pass', stun: 'pass', ipv6: 'pass' });
  assert.equal(r.leak, false);
});

test('TUN: the system route leaves with a different address than the proxy — leak', async () => {
  const r = await runSelfTest(probes({ exitViaSystem: ok('1.2.3.4') }));
  assert.equal(byId(r).exit, 'leak');
  assert.equal(r.leak, true);
});

test('TUN: an adapter still points at the ISP resolver — leak, and it names it', async () => {
  const r = await runSelfTest(probes({ resolvers: () => ['172.19.0.2', '192.168.1.1'] }));
  assert.equal(byId(r)['dns-servers'], 'leak');
  assert.match(r.checks.find(c => c.id === 'dns-servers').detail, /192\.168\.1\.1/);
});

test('TUN: STUN answers with an address that is not the exit — UDP leaves outside the tunnel', async () => {
  const r = await runSelfTest(probes({ stun: ok('1.2.3.4') }));
  assert.equal(byId(r).stun, 'leak');
});

test('TUN: STUN unreachable is not a leak', async () => {
  assert.equal(byId(await runSelfTest(probes({ stun: fail }))).stun, 'warn');
});

test('TUN, ipv6 off: an IPv6 exit reachable over the system route is a leak; ipv6 on: informational', async () => {
  assert.equal(byId(await runSelfTest(probes({ v6Exit: ok('2001:db8::1') }))).ipv6, 'leak');
  assert.equal(byId(await runSelfTest(probes({ ipv6: true, v6Exit: ok('2001:db8::1') }))).ipv6, 'info');
});

test('TUN, guard off: the resolver check is a warning, not a verdict', async () => {
  assert.equal(byId(await runSelfTest(probes({ guard: null })))['dns-servers'], 'warn');
});

test('proxy mode: system exit differs by design (info); UDP block promised and holding: pass; not holding: leak', async () => {
  const base = { mode: 'proxy', guard: null, exitViaSystem: ok('1.2.3.4') };
  const r1 = await runSelfTest(probes(Object.assign({}, base, { udpBlocked: true, stun: fail })));
  assert.deepEqual(byId(r1), { exit: 'info', 'dns-servers': 'skip', 'dns-resolve': 'skip', stun: 'pass', ipv6: 'skip' });
  assert.equal(r1.leak, false);
  const r2 = await runSelfTest(probes(Object.assign({}, base, { udpBlocked: true, stun: ok('1.2.3.4') })));
  assert.equal(byId(r2).stun, 'leak');
  const r3 = await runSelfTest(probes(Object.assign({}, base, { udpBlocked: false, stun: ok('1.2.3.4') })));
  assert.equal(byId(r3).stun, 'warn', 'not promised, so a warning that names the address');
});

test('a probe that throws is reported as warn, never as pass', async () => {
  const r = await runSelfTest(probes({ exitViaProxy: async () => { throw new Error('boom'); } }));
  assert.equal(byId(r).exit, 'warn');
});

test('parseStunMapped decodes XOR-MAPPED-ADDRESS (v4) for the matching transaction only', () => {
  const { tid } = stunRequest();
  const msg = Buffer.alloc(32);
  msg.writeUInt16BE(0x0101, 0); msg.writeUInt16BE(12, 2); msg.writeUInt32BE(0x2112A442, 4); tid.copy(msg, 8);
  msg.writeUInt16BE(0x0020, 20); msg.writeUInt16BE(8, 22); msg[24] = 0; msg[25] = 0x01;
  msg.writeUInt16BE(3478 ^ 0x2112, 26);
  msg.writeUInt32BE((0x05050505 ^ 0x2112A442) >>> 0, 28);
  assert.deepEqual(parseStunMapped(msg, tid), { family: 4, port: 3478, ip: '5.5.5.5' });
  assert.equal(parseStunMapped(msg, Buffer.alloc(12)), null, 'someone else\'s transaction');
});
```

Run: `node --test tests/selfTest.test.js` — FAIL (module missing).

- [ ] **Step 2: `src/main/selfTest.js`**

```js
'use strict';
/**
 * "Is anything leaving outside the tunnel right now?" — asked of the live
 * machine, not of a config.
 *
 * Every promise this app makes about leaks is a statement about generated
 * JSON and generated scripts. This is the one place that looks: the address
 * the world sees over the OS route versus over the proxy, which resolvers the
 * adapters actually hold, whether a name resolves at all, where a UDP packet
 * (STUN, the WebRTC question) comes out, and whether IPv6 escapes. Every probe
 * is injected so the verdict table is unit-tested; main.js supplies the real
 * ones.
 */
const dgram = require('dgram');
const crypto = require('crypto');

const STUN_HOST = 'stun.l.google.com', STUN_PORT = 19302;
const MAGIC = 0x2112A442;

/** RFC 5389 Binding Request: 20-byte header, no attributes. */
function stunRequest() {
  const tid = crypto.randomBytes(12);
  const buf = Buffer.alloc(20);
  buf.writeUInt16BE(0x0001, 0);
  buf.writeUInt16BE(0, 2);
  buf.writeUInt32BE(MAGIC, 4);
  tid.copy(buf, 8);
  return { buf, tid };
}

/** The XOR-MAPPED-ADDRESS of a Binding Success Response for `tid`, or null. */
function parseStunMapped(msg, tid) {
  if (!msg || msg.length < 20 || msg.readUInt16BE(0) !== 0x0101) return null;
  if (!msg.subarray(8, 20).equals(tid)) return null;
  const end = Math.min(msg.length, 20 + msg.readUInt16BE(2));
  let off = 20;
  while (off + 4 <= end) {
    const type = msg.readUInt16BE(off), len = msg.readUInt16BE(off + 2);
    if (type === 0x0020 && len >= 8 && off + 4 + len <= msg.length) {
      const family = msg[off + 5];
      const port = msg.readUInt16BE(off + 6) ^ (MAGIC >>> 16);
      if (family === 0x01) {
        const ip = (msg.readUInt32BE(off + 8) ^ MAGIC) >>> 0;
        return { family: 4, port, ip: [ip >>> 24, (ip >>> 16) & 255, (ip >>> 8) & 255, ip & 255].join('.') };
      }
      if (family === 0x02 && len >= 20) {
        const raw = Buffer.from(msg.subarray(off + 8, off + 24));
        const key = Buffer.concat([Buffer.from([0x21, 0x12, 0xA4, 0x42]), tid]);
        for (let i = 0; i < 16; i++) raw[i] ^= key[i];
        const parts = [];
        for (let i = 0; i < 16; i += 2) parts.push(raw.readUInt16BE(i).toString(16));
        return { family: 6, port, ip: parts.join(':') };
      }
    }
    off += 4 + ((len + 3) & ~3);
  }
  return null;
}

/** Ask a STUN server what address our UDP arrives from. Never throws. */
function stunMappedAddress({ host = STUN_HOST, port = STUN_PORT, timeoutMs = 3000 } = {}) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket('udp4');
    const { buf, tid } = stunRequest();
    let done = false;
    const finish = (r) => { if (done) return; done = true; clearTimeout(timer); try { sock.close(); } catch { /* closed */ } resolve(r); };
    const timer = setTimeout(() => finish({ ok: false, error: 'timeout' }), timeoutMs);
    sock.on('error', (e) => finish({ ok: false, error: e.message }));
    sock.on('message', (msg) => { const m = parseStunMapped(msg, tid); if (m) finish({ ok: true, ip: m.ip, port: m.port }); });
    sock.send(buf, port, host, (err) => { if (err) finish({ ok: false, error: err.message }); });
  });
}

/** Run one probe; a throw is an answer too ("could not ask"), never a pass. */
async function ask(fn) {
  try { const r = await fn(); return r && typeof r === 'object' ? r : { ok: false, error: 'no answer' }; }
  catch (e) { return { ok: false, error: (e && e.message) || String(e) }; }
}

/**
 * @param {object} p
 *   mode           'tun' | 'proxy'
 *   guard          { engaged, peer4, peer6, level } | null
 *   ipv6           the setting
 *   udpBlocked     blockUdpInProxyMode
 *   exitViaProxy() exitViaSystem() stun() v6Exit()  → { ok, ip }
 *   resolvers()    → string[] (the adapters' resolvers as the OS reports them NOW)
 *   resolveNonce(name) → { ok }  (a lookup through those resolvers)
 */
async function runSelfTest(p) {
  const tun = p.mode === 'tun';
  const checks = [];
  const put = (id, status, detail) => checks.push({ id, status, detail: detail || '' });

  const viaProxy = await ask(p.exitViaProxy);
  const viaSystem = await ask(p.exitViaSystem);
  if (!viaProxy.ok) put('exit', 'warn', 'proxy: ' + (viaProxy.error || 'no answer'));
  else if (!viaSystem.ok) put('exit', tun ? 'warn' : 'info', 'system: ' + (viaSystem.error || 'no answer'));
  else if (tun) put('exit', viaProxy.ip === viaSystem.ip ? 'pass' : 'leak', `proxy ${viaProxy.ip} · system ${viaSystem.ip}`);
  else put('exit', 'info', `proxy ${viaProxy.ip} · system ${viaSystem.ip}`);

  if (!tun) { put('dns-servers', 'skip'); put('dns-resolve', 'skip'); }
  else {
    const peers = new Set([p.guard && p.guard.peer4, p.guard && p.guard.peer6].filter(Boolean).map(String));
    let list = [];
    try { list = (p.resolvers() || []).map(String); } catch { list = []; }
    const strangers = list.filter(a => !peers.has(a.replace(/^\[|\]$/g, '').replace(/%.*$/, '')));
    if (!p.guard || !p.guard.engaged) put('dns-servers', 'warn', list.join(', '));
    else put('dns-servers', strangers.length ? 'leak' : 'pass', strangers.length ? strangers.join(', ') : list.join(', '));
    const nonce = `${crypto.randomBytes(6).toString('hex')}.irnetfree-selftest.invalid`;
    const res = await ask(() => p.resolveNonce(nonce));
    put('dns-resolve', res.ok ? 'pass' : 'warn', res.ok ? '' : (res.error || 'no answer'));
  }

  const stun = await ask(p.stun);
  if (tun) {
    if (!stun.ok) put('stun', 'warn', stun.error || 'no answer');
    else put('stun', viaProxy.ok && stun.ip === viaProxy.ip ? 'pass' : 'leak', stun.ip);
  } else if (p.udpBlocked) {
    put('stun', stun.ok ? 'leak' : 'pass', stun.ok ? stun.ip : '');
  } else {
    put('stun', stun.ok ? 'warn' : 'info', stun.ok ? stun.ip : '');
  }

  if (!tun) put('ipv6', 'skip');
  else {
    const v6 = await ask(p.v6Exit);
    if (!v6.ok) put('ipv6', 'pass', '');
    else put('ipv6', p.ipv6 ? 'info' : 'leak', v6.ip);
  }

  return { checks, leak: checks.some(c => c.status === 'leak') };
}

module.exports = { runSelfTest, stunMappedAddress, stunRequest, parseStunMapped, STUN_HOST, STUN_PORT };
```

Run: `node --test tests/selfTest.test.js` — PASS.

- [ ] **Step 3: `ipInfoV6` in netutils.js**

Before `module.exports`:
```js
/** The address the world sees over IPv6, via the OS route. `ok:false` when v6 does not leave at all. */
function ipInfoV6(timeout = 6000) {
  return new Promise((resolve) => {
    const req = http.get({ host: 'api6.ipify.org', path: '/?format=json', family: 6, timeout, headers: { 'User-Agent': 'IRNetFree' } }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => { const j = parseJsonLoose(body); resolve(j && j.ip ? { ok: true, ip: j.ip } : { ok: false, error: 'no ip' }); });
    });
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout' }); });
    req.on('error', (e) => resolve({ ok: false, error: e.code || e.message }));
  });
}
```
Export it.

- [ ] **Step 4: IPC in main.js**

Requires: `const { runSelfTest, stunMappedAddress } = require('./selfTest');`, add `ipInfoV6` to the netutils require, `const dns = require('dns');`.

In `registerIpc()` after `guard:release`:
```js
  // The live machine, asked whether anything leaves outside the tunnel. A fresh
  // dns.Resolver reads the adapters' resolvers as they are NOW (the default one
  // read them once at process start, before any guard).
  ipcMain.handle('vpn:selfTest', async () => {
    if (!xray.running || !store.get('activeServerId', null)) return { ok: false, error: 'not connected' };
    const s = getSettings();
    const st = leakGuard ? leakGuard.readState() : null;
    const r = new dns.Resolver();
    const result = await runSelfTest({
      mode: (tun && tun.active) ? 'tun' : 'proxy',
      guard: st ? { engaged: true, peer4: st.peer4, peer6: st.peer6, level: st.level } : null,
      ipv6: !!s.ipv6,
      udpBlocked: !!s.blockUdpInProxyMode,
      exitViaProxy: () => ipInfo(s.socksPort),
      exitViaSystem: () => ipInfo(null),
      resolvers: () => r.getServers(),
      resolveNonce: (name) => new Promise((res) => r.resolve4(name, (e) => {
        // NXDOMAIN / no data IS an answer — the resolver is alive; a timeout or refusal is not
        res(!e || e.code === 'ENOTFOUND' || e.code === 'ENODATA' ? { ok: true } : { ok: false, error: e.code });
      })),
      stun: () => stunMappedAddress(),
      v6Exit: () => ipInfoV6()
    });
    send('log', { line: result.leak ? 'Self-test: a leak was found — see the home page' : 'Self-test: nothing leaves outside the tunnel', level: result.leak ? 'error' : 'info' });
    return Object.assign({ ok: true }, result);
  });
```
Mirror in `service.js` as `'vpn:selfTest': async () => { …same body… },` (there `tun` is the module-level instance too).

`preload.js`: `selfTest: () => ipcRenderer.invoke('vpn:selfTest'),` — `web-api.js`: `selfTest: () => invoke('vpn:selfTest'),`.

- [ ] **Step 5: Renderer**

`index.html` hero actions (after `#btnCheckIp`, line ≈ 175): `<button class="btn ghost" id="btnSelfTest" data-i18n="btn.selfTest">تست نشتی</button>`. After the `.hero-actions` div: `<div class="selftest" id="selfTestBox" hidden></div>`.

`i18n.js` fa (after `'btn.checkIp'` line 57):
```js
    'btn.selfTest': 'تست نشتی', 'st.title': 'نتیجهٔ تست نشتی', 'st.leak': 'نشتی پیدا شد', 'st.clean': 'چیزی بیرون از تونل نمی‌رود',
    'st.exit': 'IP خروجی: مسیر سیستم در برابر پروکسی', 'st.dns-servers': 'DNS کارت‌های شبکه', 'st.dns-resolve': 'پاسخ‌گویی resolver',
    'st.stun': 'UDP / WebRTC (STUN)', 'st.ipv6': 'خروج IPv6',
    'st.pass': 'سالم', 'st.leak.s': 'نشتی', 'st.warn': 'هشدار', 'st.info': 'اطلاع', 'st.skip': 'در این حالت معنی ندارد',
    't.selfTestNeedsConn': 'اول وصل شوید',
```
en (after `'btn.checkIp': 'Check IP'`):
```js
    'btn.selfTest': 'Leak test', 'st.title': 'Leak test result', 'st.leak': 'A leak was found', 'st.clean': 'Nothing leaves outside the tunnel',
    'st.exit': 'Exit IP: system route vs proxy', 'st.dns-servers': 'Adapter DNS servers', 'st.dns-resolve': 'Resolver answers',
    'st.stun': 'UDP / WebRTC (STUN)', 'st.ipv6': 'IPv6 exit',
    'st.pass': 'OK', 'st.leak.s': 'LEAK', 'st.warn': 'warning', 'st.info': 'info', 'st.skip': 'not applicable in this mode',
    't.selfTestNeedsConn': 'Connect first',
```

`app.js` next to `$('#btnCheckIp').onclick`:
```js
$('#btnSelfTest').onclick = async () => {
  if (!state.connected) return toast(t('t.selfTestNeedsConn'), 'err');
  const box = $('#selfTestBox');
  box.hidden = false;
  box.innerHTML = `<div class="st-head">${escapeHtml(t('st.title'))} …</div>`;
  const r = await window.api.selfTest();
  if (!r || !r.ok) { box.innerHTML = `<div class="st-head bad">${escapeHtml((r && r.error) || t('t.error'))}</div>`; return; }
  const rows = r.checks.map((c) => `
    <div class="st-row">
      <span class="st-pill ${c.status}">${escapeHtml(t(c.status === 'leak' ? 'st.leak.s' : 'st.' + c.status))}</span>
      <span class="st-name">${escapeHtml(t('st.' + c.id))}</span>
      <span class="st-detail" dir="ltr">${escapeHtml(c.detail || '')}</span>
    </div>`).join('');
  box.innerHTML = `<div class="st-head ${r.leak ? 'bad' : 'good'}">${escapeHtml(r.leak ? t('st.leak') : t('st.clean'))}</div>${rows}`;
};
```
Hide the box on disconnect: in the status handler where `state.connected = false` is set (`grep -n "state.connected = false" src/renderer/app.js`), add `const stb = $('#selfTestBox'); if (stb) stb.hidden = true;`.

`home.css` (append):
```css
.selftest { margin-block-start: 10px; border: 1px solid var(--line); border-radius: var(--r2); padding: 10px 12px; font-size: 12px; }
.st-head { font-weight: 600; margin-block-end: 6px; }
.st-head.good { color: var(--ok); }
.st-head.bad { color: var(--danger); }
.st-row { display: grid; grid-template-columns: 72px 1fr auto; gap: 8px; align-items: center; padding-block: 3px; }
.st-pill { font-family: var(--mono); font-size: 11px; text-align: center; border-radius: var(--r1); padding: 1px 6px; border: 1px solid var(--line); }
.st-pill.pass { color: var(--ok); border-color: var(--ok); }
.st-pill.leak { color: var(--danger); border-color: var(--danger); font-weight: 700; }
.st-pill.warn { color: var(--warn); border-color: var(--warn); }
.st-pill.info, .st-pill.skip { color: var(--ink3); }
.st-detail { color: var(--ink3); font-family: var(--mono); }
```

- [ ] **Step 6: Tests + browser**

`npm test` — PASS (renderer contract: `btnSelfTest`, `selfTestBox`, the `st.*` keys — note `st.leak.s` is a separate key from `st.leak`). Browser on 3997, disconnected: the button toasts "Connect first"; the box stays hidden.

**Device-verified (owner, Windows, TUN + standard guard):** press تست نشتی while connected. Expected all five rows `سالم`, adapter DNS detail `172.19.0.2, fdfe:dcba:9876::2`. Then with guard `off`: `DNS کارت‌های شبکه` becomes a warning listing the ISP resolvers. In proxy mode with the UDP block on: STUN row `سالم`; off: a warning naming the real address.

- [ ] **Step 7: Commit**

```bash
git add src/main/selfTest.js tests/selfTest.test.js src/main/netutils.js src/main/main.js src/server/service.js src/preload/preload.js src/server/web-api.js src/renderer/index.html src/renderer/app.js src/renderer/i18n.js src/renderer/home.css
git commit -m "A leak test on the home page asks the live machine where its traffic, DNS, UDP and IPv6 actually leave"
```

---

### Task C2: health watch — notice a dead tunnel, rebuild it, or move to the next server

**Files:**
- Create: `src/main/healthWatch.js`, `tests/healthWatch.test.js`
- Modify: `src/main/main.js` (defaults; `doConnect` end ≈ 985; `doDisconnect` 1396; `reapplyConnection` teardown 1052; `recoverFromNetworkChange` gate 1206; `runRecovery` log 1248), `src/server/service.js` (same places)
- Modify: `index.html` (settings rows after `optNetAuto`), `app.js`, `i18n.js`

**Interfaces:**
- Produces: `class HealthWatch({ probe, onDown, intervalMs=30000, failures=3, setTimer, clearTimer })` with `start()/stop()/tick()`; `nextServerId(servers, currentId) → id|null`.
- Settings: `healthCheck: true`, `healthAction: 'reconnect' | 'next'` (read live — NOT reconnect keys; i18n rows only).

- [ ] **Step 1: Failing tests**

`tests/healthWatch.test.js`:
```js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { HealthWatch, nextServerId } = require('../src/main/healthWatch');

function harness(answers, opts) {
  const down = [];
  let tick = null, i = 0;
  const w = new HealthWatch(Object.assign({
    probe: async () => answers[Math.min(i++, answers.length - 1)],
    onDown: (why) => down.push(why),
    intervalMs: 30000, failures: 3,
    setTimer: (fn) => { tick = fn; return 'timer'; },
    clearTimer: () => { tick = null; }
  }, opts || {}));
  return { w, down, tick: () => tick && tick() };
}

test('three consecutive failures fire onDown once; a success in between resets the count', async () => {
  const h = harness([false, false, true, false, false, false, false]);
  h.w.start();
  for (let k = 0; k < 5; k++) await h.tick();
  assert.deepEqual(h.down, []);
  await h.tick();
  assert.deepEqual(h.down, ['health: 3 probes failed']);
  await h.tick();
  assert.deepEqual(h.down, ['health: 3 probes failed'], 'counter reset after firing');
});

test('a probe that throws counts as a failure; stop() forgets everything', async () => {
  const h = harness([]);
  h.w.probe = async () => { throw new Error('x'); };
  h.w.start();
  await h.tick(); await h.tick();
  h.w.stop();
  h.w.start();
  await h.tick();
  assert.deepEqual(h.down, []);
});

test('a tick that lands while onDown is still running is skipped', async () => {
  let release;
  const h = harness([false, false, false, false], { onDown: () => new Promise(r => { release = r; }) });
  h.w.start();
  await h.tick(); await h.tick();
  const p = h.tick();            // fires onDown, which is now pending
  await h.tick();                // must not probe again meanwhile
  release(); await p;
  assert.equal(h.w.busy, false);
});

test('nextServerId: next in the same subscription, wrapping; else the next server of any kind', () => {
  const servers = [
    { id: 'm1' }, { id: 'a1', subId: 'A' }, { id: 'a2', subId: 'A' }, { id: 'b1', subId: 'B' }, { id: 'a3', subId: 'A' }
  ];
  assert.equal(nextServerId(servers, 'a1'), 'a2');
  assert.equal(nextServerId(servers, 'a3'), 'a1', 'wraps inside the subscription');
  assert.equal(nextServerId(servers, 'b1'), 'a3', 'alone in its subscription: next of any kind');
  assert.equal(nextServerId(servers, 'm1'), 'a1');
  assert.equal(nextServerId([{ id: 'only' }], 'only'), null, 'nowhere to go');
  assert.equal(nextServerId(servers, 'zzz'), 'm1', 'unknown current: the first');
});
```
Run — FAIL (module missing).

- [ ] **Step 2: Implement**

`src/main/healthWatch.js`:
```js
'use strict';
/**
 * Is the tunnel still carrying traffic? The core does not die when its exit
 * stops answering — a blocked server, an expired account, a peer that went
 * away — it just stops passing bytes, and the UI says "connected" for ever.
 * netWatcher covers the machine's side of the link; this covers the far side:
 * a small request through the local proxy, every half minute, and after
 * `failures` misses in a row the owner is told. What it does then (rebuild,
 * or move to the next server) is the owner's decision, not this module's.
 */
class HealthWatch {
  constructor(opts = {}) {
    this.probe = opts.probe || (async () => true);
    this.onDown = opts.onDown || (() => {});
    this.intervalMs = opts.intervalMs || 30000;
    this.failures = opts.failures || 3;
    this.setTimer = opts.setTimer || ((fn, ms) => { const t = setInterval(fn, ms); if (t.unref) t.unref(); return t; });
    this.clearTimer = opts.clearTimer || ((h) => clearInterval(h));
    this.timer = null;
    this.fails = 0;
    this.busy = false;
    this.gen = 0;
  }
  start() { if (this.timer) return; this.fails = 0; this.timer = this.setTimer(() => this.tick(), this.intervalMs); }
  stop() { this.gen++; this.fails = 0; this.busy = false; if (this.timer) { this.clearTimer(this.timer); this.timer = null; } }
  async tick() {
    if (this.busy) return;
    this.busy = true;
    const gen = this.gen;
    let ok = false;
    try { ok = !!(await this.probe()); } catch { ok = false; }
    if (gen !== this.gen) return;             // stopped while probing
    if (ok) { this.fails = 0; this.busy = false; return; }
    this.fails++;
    if (this.fails < this.failures) { this.busy = false; return; }
    this.fails = 0;
    try { await this.onDown(`health: ${this.failures} probes failed`); } catch { /* the owner logs */ }
    if (gen === this.gen) this.busy = false;
  }
}

/** The server to try after `currentId`: next in its subscription (wrapping), else next of any kind. */
function nextServerId(servers, currentId) {
  const list = (servers || []).filter(s => s && s.id);
  if (!list.length) return null;
  const i = list.findIndex(s => s.id === currentId);
  if (i === -1) return list[0].id;
  const cur = list[i];
  const same = list.filter(s => (s.subId || '') === (cur.subId || ''));
  if (same.length > 1) { const j = same.findIndex(s => s.id === currentId); return same[(j + 1) % same.length].id; }
  if (list.length === 1) return null;
  return list[(i + 1) % list.length].id;
}

module.exports = { HealthWatch, nextServerId };
```
Run — PASS.

- [ ] **Step 3: Wire it (main.js)**

Requires: `const { HealthWatch, nextServerId } = require('./healthWatch');`. Module state: `let healthWatch = null;`. Defaults (both mirrors): `healthCheck: true, healthAction: 'reconnect',` after `autoReconnectOnNetworkChange: true,`.

Helpers next to `startNetWatcher`:
```js
function startHealthWatch() {
  stopHealthWatch();
  const s = getSettings();
  if (!s.healthCheck) return;
  healthWatch = new HealthWatch({
    // Skip (count as fine) while a rebuild is in flight — the proxy port is down on purpose then.
    probe: async () => {
      if (recovering || xrayReloading || !xray.running) return true;
      const r = await httpThroughProxy(getSettings().socksPort, { host: 'cp.cloudflare.com', port: 80, path: '/', timeout: 8000 });
      return !!(r && r.ok);
    },
    onDown: (why) => onTunnelDown(why)
  });
  healthWatch.start();
}
function stopHealthWatch() { if (healthWatch) { healthWatch.stop(); healthWatch = null; } }

/** The tunnel stopped answering: rebuild it, or move to the next server — the setting decides. */
async function onTunnelDown(why) {
  const s = getSettings();
  const cur = store.get('activeServerId', null);
  if (!cur) return;
  if (s.healthAction === 'next') {
    const next = nextServerId(store.get('servers', []), cur);
    if (next && next !== cur) {
      send('log', { line: `Tunnel is not answering (${why}) — switching to the next server`, level: 'warn' });
      if (typeof notify === 'function') notify('IRNetFree', s.lang === 'en' ? 'Tunnel stopped answering — switching server' : 'تونل جواب نمی‌دهد — سرور بعدی');
      try { await doConnect(next); } catch (e) { send('log', { line: 'Switch failed: ' + e.message, level: 'error' }); }
      return;
    }
  }
  send('log', { line: `Tunnel is not answering (${why}) — rebuilding the connection`, level: 'warn' });
  await recoverFromNetworkChange('health').catch((e) => send('log', { line: 'Health recovery failed: ' + ((e && e.message) || e), level: 'error' }));
}
```
In `recoverFromNetworkChange` change the gate `if (!getSettings().autoReconnectOnNetworkChange) return;` to
`if (!getSettings().autoReconnectOnNetworkChange && reason !== 'health') return;`.
In `runRecovery` the first log line becomes:
`send('log', { line: (reason === 'health' ? 'Tunnel stopped answering' : `Network changed (${reason})`) + ' — rebuilding the connection', level: 'warn' });`

Start/stop: at the end of `doConnect` after `if (!netWatcher) startNetWatcher();` add `startHealthWatch();`. In `doDisconnect()` after `stopNetWatcher();` add `stopHealthWatch();`. In `reapplyConnection()` inside the `try {` after `stopProcWatcher();` add `stopHealthWatch();` (doConnect restarts it). In `teardownForQuit()` add `try { stopHealthWatch(); } catch {}`.

Note: `doConnect(next)` from `onTunnelDown` switches servers under a live TUN — that is the existing "server switch under TUN" path (holdForReconnect + tun rebuild); nothing new.

- [ ] **Step 4: Mirror in service.js** — same require, state, helpers, gate change, start/stop calls (its `shutdown()` instead of `teardownForQuit`).

- [ ] **Step 5: Settings UI**

`index.html` after the `optNetAuto` switch-row (line ≈ 631):
```html
          <div class="switch-row">
            <div><div class="switch-title" data-i18n="health.title">پایش سلامت تونل</div>
              <div class="switch-sub" data-i18n="health.sub">هر ۳۰ ثانیه یک درخواست کوچک از داخل تونل؛ سه شکست پشت‌سرهم یعنی تونل مرده است</div></div>
            <label class="switch"><input type="checkbox" id="optHealth" /><span class="slider"></span></label>
          </div>
          <div class="setting-row" id="healthActionRow">
            <label class="field-label" data-i18n="health.action">وقتی تونل مرد</label>
            <select id="optHealthAction" class="select">
              <option value="reconnect" data-i18n="health.reconnect">همین سرور را دوباره بساز</option>
              <option value="next" data-i18n="health.next">سرور بعدیِ همان ساب‌اسکریپشن</option>
            </select>
          </div>
```
`i18n.js` fa (after `'netauto.sub'` line 365): `'health.title': 'پایش سلامت تونل', 'health.sub': 'هر ۳۰ ثانیه یک درخواست کوچک از داخل تونل؛ سه شکست پشت‌سرهم یعنی تونل مرده است', 'health.action': 'وقتی تونل مرد', 'health.reconnect': 'همین سرور را دوباره بساز', 'health.next': 'سرور بعدیِ همان ساب‌اسکریپشن',`
en (after `'netauto.sub'` line 739): `'health.title': 'Tunnel health watch', 'health.sub': 'A small request through the tunnel every 30 s; three misses in a row mean the tunnel is dead', 'health.action': 'When the tunnel dies', 'health.reconnect': 'Rebuild this server', 'health.next': 'Next server in the same subscription',`

`app.js`: `applySettingsToUI()`: `$('#optHealth').checked = s.healthCheck !== false; $('#optHealthAction').value = s.healthAction || 'reconnect';` — `readSettingsForm()`: `healthCheck: $('#optHealth').checked, healthAction: $('#optHealthAction').value,` — next to the `optNetAuto` onchange (`grep -n optNetAuto src/renderer/app.js`): `$('#optHealth').onchange = () => saveSettings({ healthCheck: $('#optHealth').checked }); $('#optHealthAction').onchange = () => saveSettings({ healthAction: $('#optHealthAction').value });`

`settings:set` in both mirrors: after the kill-switch reaction add
```js
    if (('healthCheck' in partial || 'healthAction' in partial) && store.get('activeServerId', null)) startHealthWatch();
```

- [ ] **Step 6: Tests + browser + commit**

`npm test` — PASS. Browser 3997: the two rows render; the select is styled (`.select` arrow present).
```bash
git add src/main/healthWatch.js tests/healthWatch.test.js src/main/main.js src/server/service.js src/renderer/index.html src/renderer/app.js src/renderer/i18n.js
git commit -m "A tunnel that stops answering is noticed within ninety seconds and rebuilt, or the next server is tried"
```
Fable review: the probe must return `true` (not `false`) while `recovering`/`xrayReloading`, or a rebuild's own gap counts toward "dead"; `onTunnelDown → doConnect(next)` must not run while a recovery holds the lock (`recovering` is checked by the probe; keep it).

---

### Task C3: DoH bootstrap for the addresses the app itself resolves

**Files:**
- Modify: `src/main/netutils.js` (`resolveDoh` + wire helpers; export), `tests/netutils.test.js`
- Modify: `src/main/tunPlatform.js` (`resolveServerIps`, line 92), `tests/tunPlatform.test.js`
- Modify: `src/main/settingsMeta.js`, both `DEFAULT_SETTINGS`, `main.js` call sites (613, 853, 928, 1078), `service.js` (616, 784, 851, 949), `index.html`, `app.js`, `i18n.js`

**Why:** `resolveServerIps()` uses `dns.lookup` — the OS resolver. Before the tunnel exists that is the ISP's resolver, so the ISP is handed the server's hostname on every connect (and the WireGuard endpoint name, for PattN). The managed plan already trusts DoH for everything else.

**Interfaces:**
- Produces: `resolveDoh(name, url, { timeoutMs=3000, family=4 }) → Promise<string[]>` (throws on failure); `resolveServerIps(addr, { ipv6, doh })` tries DoH first when `doh` is a URL, then the OS resolver.
- Setting: `dnsBootstrap: 'system' | 'doh'` (default `'system'` — the owner's call; DoH to 1.1.1.1 may itself be blocked and then costs a 3 s timeout per name before the fallback). In `RECONNECT_KEYS`.

- [ ] **Step 1: Failing tests**

Append to `tests/netutils.test.js` (add `resolveDoh` to the require; `http` is needed):
```js
test('resolveDoh: GET ?dns=<base64url>, accept dns-message, returns the A records', async () => {
  const http = require('node:http');
  let seen = null;
  const srv = http.createServer((req, res) => {
    seen = { url: req.url, accept: req.headers.accept };
    // header: id 0, QR|RD|RA, 1 question, 2 answers; question example.com A; two A answers via a pointer to offset 12
    const q = Buffer.from('076578616d706c6503636f6d0000010001', 'hex');
    const ans = (ip) => Buffer.concat([Buffer.from('c00c0001000100000e100004', 'hex'), Buffer.from(ip.split('.').map(Number))]);
    const head = Buffer.from('000081800001000200000000', 'hex');
    res.setHeader('content-type', 'application/dns-message');
    res.end(Buffer.concat([head, q, ans('93.184.216.34'), ans('93.184.216.35')]));
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  try {
    const url = `http://127.0.0.1:${srv.address().port}/dns-query`;
    assert.deepEqual(await resolveDoh('example.com', url), ['93.184.216.34', '93.184.216.35']);
    assert.match(seen.url, /^\/dns-query\?dns=[A-Za-z0-9_-]+$/);
    assert.equal(seen.accept, 'application/dns-message');
  } finally { srv.close(); }
});

test('resolveDoh: a non-200 or an unreachable server rejects', async () => {
  await assert.rejects(resolveDoh('example.com', 'http://127.0.0.1:1/dns-query'));
});
```
Run — FAIL.

- [ ] **Step 2: Implement in netutils.js**

```js
/* ------------------------------ DNS over HTTPS ------------------------------ */

function dnsEncodeName(name) {
  const parts = String(name).replace(/\.$/, '').split('.').filter(Boolean);
  return Buffer.concat([...parts.map(p => Buffer.concat([Buffer.from([p.length]), Buffer.from(p, 'ascii')])), Buffer.from([0])]);
}
function dnsQuery(name, qtype) {
  const head = Buffer.alloc(12);
  head.writeUInt16BE(0, 0);         // id 0: a stable GET body, cacheable by the resolver
  head.writeUInt16BE(0x0100, 2);    // RD
  head.writeUInt16BE(1, 4);         // one question
  return Buffer.concat([head, dnsEncodeName(name), Buffer.from([0, qtype, 0, 1])]);
}
function dnsSkipName(buf, off) {
  for (;;) {
    const len = buf[off];
    if (len === 0) return off + 1;
    if ((len & 0xc0) === 0xc0) return off + 2;   // compression pointer ends the name
    off += 1 + len;
  }
}
/** The addresses of type `qtype` (1 = A, 28 = AAAA) in a DNS response. */
function dnsAnswers(buf, qtype) {
  if (!buf || buf.length < 12) throw new Error('short DNS response');
  const qd = buf.readUInt16BE(4), an = buf.readUInt16BE(6);
  let off = 12;
  for (let i = 0; i < qd; i++) off = dnsSkipName(buf, off) + 4;
  const out = [];
  for (let i = 0; i < an; i++) {
    off = dnsSkipName(buf, off);
    const type = buf.readUInt16BE(off), len = buf.readUInt16BE(off + 8);
    const data = buf.subarray(off + 10, off + 10 + len);
    if (type === qtype && type === 1 && len === 4) out.push([...data].join('.'));
    if (type === qtype && type === 28 && len === 16) {
      const parts = []; for (let k = 0; k < 16; k += 2) parts.push(data.readUInt16BE(k).toString(16));
      out.push(parts.join(':'));
    }
    off += 10 + len;
  }
  return out;
}
/**
 * Resolve `name` at a DoH endpoint (RFC 8484 GET). `http:` is accepted so a
 * test can stand the endpoint up on loopback. Rejects on any failure; the
 * caller falls back to the OS resolver.
 */
function resolveDoh(name, url, { timeoutMs = 3000, family = 4 } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch { return reject(new Error('bad DoH url')); }
    const qtype = family === 6 ? 28 : 1;
    u.searchParams.set('dns', dnsQuery(name, qtype).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
    const mod = u.protocol === 'http:' ? http : https;
    const req = mod.get(u, { headers: { accept: 'application/dns-message', 'User-Agent': 'IRNetFree' }, timeout: timeoutMs }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        if (res.statusCode !== 200) return reject(new Error('DoH status ' + res.statusCode));
        try { resolve(dnsAnswers(Buffer.concat(chunks), qtype)); } catch (e) { reject(e); }
      });
    });
    req.on('timeout', () => req.destroy(new Error('DoH timeout')));
    req.on('error', reject);
  });
}
```
(`const https = require('https');` if not already required.) Export `resolveDoh`.

- [ ] **Step 3: `resolveServerIps` learns `doh`**

`tunPlatform.js` line 92–105 becomes:
```js
async function resolveServerIps(serverAddress, opts = {}) {
  const inputs = Array.isArray(serverAddress) ? serverAddress : [serverAddress];
  const all = [];
  for (const addr of inputs) {
    if (!addr) continue;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(addr)) { all.push(addr); continue; }
    if (opts.ipv6 && /^[0-9a-f:]+$/i.test(addr) && addr.includes(':')) { all.push(addr); continue; }
    // DoH first when asked: the name never reaches the ISP's resolver. A
    // blocked endpoint costs the timeout and falls through.
    if (opts.doh) {
      try {
        const v4 = await resolveDoh(addr, opts.doh, { family: 4 });
        const v6 = opts.ipv6 ? await resolveDoh(addr, opts.doh, { family: 6 }).catch(() => []) : [];
        if (v4.length || v6.length) { all.push(...v4, ...v6); continue; }
      } catch { /* the OS resolver below */ }
    }
    try {
      const res = await dns.lookup(addr, { family: opts.ipv6 ? 0 : 4, all: true });
      for (const r of res) if (r.address) all.push(r.address);
    } catch { /* unresolved — skip */ }
  }
  return [...new Set(all)];
}
```
with `const { resolveDoh } = require('./netutils');` at the top (check for a require cycle: netutils must not require tunPlatform — it does not).

Test — append to `tests/tunPlatform.test.js` (check its require line and add `resolveServerIps`):
```js
test('resolveServerIps: literals pass through; a DoH endpoint that fails falls back to the OS resolver for names', async () => {
  assert.deepEqual(await resolveServerIps(['1.2.3.4', '2001:db8::1'], { ipv6: true, doh: 'http://127.0.0.1:1/dns-query' }), ['1.2.3.4', '2001:db8::1']);
  const r = await resolveServerIps('localhost', { doh: 'http://127.0.0.1:1/dns-query' });
  assert.ok(r.includes('127.0.0.1'), 'fell back to the OS: ' + r);
});
```

- [ ] **Step 4: Setting + call sites**

Both `DEFAULT_SETTINGS`: `dnsBootstrap: 'system',` after `dnsDirect: […],`. `RECONNECT_KEYS`: after `'dnsDirect',` add `'dnsBootstrap',`. i18n: `'set.dnsBootstrap': 'نام سرور از طریق DoH'` / `'Resolve server names over DoH'`; rows `'boot.title': 'نام سرور را از طریق DoH پیدا کن', 'boot.sub': 'آدرس سرور قبل از بالا آمدن تونل به resolver ISP داده نمی‌شود؛ اگر DoH بسته باشد ۳ ثانیه دیرتر و با resolver سیستم وصل می‌شوید'` / `'boot.title': 'Resolve server names over DoH', 'boot.sub': 'The server name is not handed to the ISP resolver before the tunnel is up; if DoH is blocked, connecting takes 3 s longer and falls back to the system resolver'`.

`index.html` in the DNS card (after the `optDnsManaged` switch-row — `grep -n optDnsManaged src/renderer/index.html`): a switch-row with `id="optDnsBootstrap"`. `app.js`: `$('#optDnsBootstrap').checked = s.dnsBootstrap === 'doh';` / `dnsBootstrap: $('#optDnsBootstrap').checked ? 'doh' : 'system',` / onchange `saveSettings({ dnsBootstrap: … })`.

main.js helper (near `withWgEndpointIps`):
```js
/** The DoH endpoint the app resolves its own names at, or null for the OS resolver. */
function bootstrapDoh(settings) {
  if (!settings || settings.dnsBootstrap !== 'doh') return null;
  const list = Array.isArray(settings.dnsRemote) ? settings.dnsRemote : [];
  return list.find(v => /^https:\/\//i.test(String(v))) || 'https://1.1.1.1/dns-query';
}
```
Every `tunPlatform.resolveServerIps(X, { ipv6: true })` in main.js (853, 928, 1078) becomes `tunPlatform.resolveServerIps(X, { ipv6: true, doh: bootstrapDoh(settings) })` (in `reapplyConnection` use `getSettings()`); line 613 (`resolveServerIps(h)`) becomes `resolveServerIps(h, { doh: bootstrapDoh(settings) })`. Same four in service.js.

Note the TUN backends resolve the bypass list themselves (`this.bypassIps(bypassAddrs)` in tunSingbox/tunManager → they call `resolveServerIps` too: `grep -n "resolveServerIps" src/main/tunSingbox.js src/main/tunManager.js`). Pass `doh` through: add `doh` to the `opts` object `myTun.start()` receives (4th argument) and to `bypassIps(addrs, opts)`. The tun2socks backend ignores the 4th argument today — extend its `start(socksPort, serverAddress, dnsServers, opts = {})` to forward `opts.doh` to its own resolve call.

- [ ] **Step 5: Tests + commit**

`npm test` — PASS.
```bash
git add src/main/netutils.js tests/netutils.test.js src/main/tunPlatform.js tests/tunPlatform.test.js src/main/tunSingbox.js src/main/tunManager.js src/main/settingsMeta.js src/main/main.js src/server/service.js src/renderer/index.html src/renderer/app.js src/renderer/i18n.js
git commit -m "The app can resolve its own server names over DoH so the ISP never sees them before the tunnel is up"
```
Fable review: no DoH call may happen when the setting is `'system'`; the WireGuard endpoint substitution (`withWgEndpointIps`) keeps its PattN-only gate.

---

### Task C4: a router that changes under the same addresses

**Files:**
- Modify: `src/main/tunPlatform.js` (add `parseDefaultGateway`, `defaultGateway`; export), `tests/tunPlatform.test.js`
- Modify: `src/main/netWatcher.js`, `tests/netWatcher.test.js`
- Modify: `src/main/main.js` (`startNetWatcher` 1346), `src/server/service.js` (1152)

**Why:** the watcher's fingerprint is the adapters' addresses. A replaced router that hands out the same lease, or a hotspot with the same subnet, leaves every address as it was while the gateway MAC/route changed — the tunnel is dead and nothing notices.

**Interfaces:**
- Produces: `parseDefaultGateway(platform, text, { ignore }) → string` (pure), `defaultGateway() → Promise<string>`; `NetWatcher` options `readSlow: async () => string`, `slowIntervalMs` (default 15000); a change fires `onChange('gateway')`.

- [ ] **Step 1: Failing tests**

`tests/tunPlatform.test.js`:
```js
test('parseDefaultGateway: Windows route print picks the lowest-metric 0.0.0.0 row that is not the TUN', () => {
  const txt = [
    'Network Destination        Netmask          Gateway       Interface  Metric',
    '          0.0.0.0          0.0.0.0     192.168.8.1     192.168.8.63     35',
    '          0.0.0.0          0.0.0.0        On-link       172.19.0.1      0',
    '          0.0.0.0          0.0.0.0        10.0.0.1       10.0.0.5     50'
  ].join('\n');
  assert.equal(parseDefaultGateway('win32', txt, { ignore: ['172.19.0.1', '10.255.0.2'] }), '192.168.8.1');
  assert.equal(parseDefaultGateway('win32', 'nothing here'), '');
});
test('parseDefaultGateway: macOS and Linux', () => {
  assert.equal(parseDefaultGateway('darwin', '   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0'), '192.168.1.1');
  assert.equal(parseDefaultGateway('linux', 'default via 10.0.0.1 dev eth0 proto dhcp metric 100'), '10.0.0.1');
});
```
`tests/netWatcher.test.js` (extend the harness to capture a second timer by interval):
```js
test('a gateway change with unchanged addresses fires "gateway" once; the first reading is the baseline', async () => {
  const fired = [];
  const timers = {};
  const gws = ['192.168.8.1', '192.168.8.1', '10.0.0.1', '10.0.0.1'];
  let g = 0;
  const w = new NetWatcher({
    read: () => wifi, onChange: (why) => fired.push(why),
    readSlow: async () => gws[Math.min(g++, gws.length - 1)], slowIntervalMs: 15000,
    setTimer: (fn, ms) => { timers[ms] = fn; return String(ms); }, clearTimer: (h) => { delete timers[h]; }
  });
  w.start();
  await timers[15000](); assert.deepEqual(fired, [], 'first reading adopted silently');
  await timers[15000](); assert.deepEqual(fired, []);
  await timers[15000](); assert.deepEqual(fired, ['gateway']);
  await timers[15000](); assert.deepEqual(fired, ['gateway'], 'stable after the change');
  w.stop();
  assert.deepEqual(Object.keys(timers), []);
});
test('an empty gateway reading (link down) neither fires nor moves the baseline', async () => {
  const fired = []; const timers = {};
  const gws = ['192.168.8.1', '', '192.168.8.1'];
  let g = 0;
  const w = new NetWatcher({ read: () => wifi, onChange: (why) => fired.push(why), readSlow: async () => gws[Math.min(g++, 2)],
    setTimer: (fn, ms) => { timers[ms] = fn; return String(ms); }, clearTimer: (h) => { delete timers[h]; } });
  w.start();
  await timers[15000](); await timers[15000](); await timers[15000]();
  assert.deepEqual(fired, []);
  w.stop();
});
```
Run — FAIL.

- [ ] **Step 2: tunPlatform**

```js
/**
 * The default gateway out of the platform's own route listing. On Windows the
 * TUN's split routes never show as 0.0.0.0/0, but sing-box may add a metric-0
 * default on its adapter — `ignore` names the TUN interface addresses so that
 * row never counts. '' when there is no default route (link down).
 */
function parseDefaultGateway(platform, text, { ignore = [] } = {}) {
  const s = String(text || '');
  if (platform === 'win32') {
    let best = null;
    for (const m of s.matchAll(/^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+(\S+)\s+(\d+)\s*$/gm)) {
      if (m[1] === 'On-link' || ignore.includes(m[2])) continue;
      const metric = Number(m[3]);
      if (!best || metric < best.metric) best = { gw: m[1], metric };
    }
    return best ? best.gw : '';
  }
  if (platform === 'darwin') { const m = s.match(/^\s*gateway:\s*(\S+)/m); return m ? m[1] : ''; }
  const m = s.match(/^default via (\S+)/m);
  return m ? m[1] : '';
}
async function defaultGateway(platform = process.platform, ignore = ['172.19.0.1', '10.255.0.2']) {
  try {
    if (platform === 'win32') return parseDefaultGateway('win32', await run('route', ['print', '-4', '0.0.0.0']), { ignore });
    if (platform === 'darwin') return parseDefaultGateway('darwin', await run('route', ['-n', 'get', 'default']), { ignore });
    return parseDefaultGateway('linux', await run('ip', ['route', 'show', 'default']), { ignore });
  } catch { return ''; }
}
```
Export both. (`172.19.0.1` is `TUN_ADDR4` of tunSingbox, `10.255.0.2` is `TUN_ADDR` of tunManager — import the constants instead of literals if they are exported; otherwise keep the literals and a comment naming their source.)

- [ ] **Step 3: netWatcher**

Constructor additions:
```js
    this.readSlow = typeof opts.readSlow === 'function' ? opts.readSlow : null;
    this.slowIntervalMs = opts.slowIntervalMs || 15000;
    this.slowTimer = null;
    this.gwLast = null;       // the gateway the tunnel was built behind; null = not yet read
```
`start()`: after arming `this.timer` add `if (this.readSlow) this.slowTimer = this.setTimer(() => this.pollSlow(), this.slowIntervalMs);`
`stop()`: add `this.gwLast = null; if (this.slowTimer) { this.clearTimer(this.slowTimer); this.slowTimer = null; }` (before the `if (!this.timer) return;`).
`fire(reason)`: first line `this.gwLast = null;` — every recovery adopts whatever gateway it finds next; a resume or an address change would otherwise be followed by a second "gateway" rebuild for the same event.
New method:
```js
  /**
   * The slow half: the default gateway, from the OS route table. Addresses
   * are cheap to read every few seconds; a route listing is a process, so it
   * is read every quarter minute. The first reading is the baseline, an empty
   * reading (no default route: link down) is ignored, and a different one is
   * the change the address fingerprint cannot see — a swapped router handing
   * out the same lease.
   */
  async pollSlow() {
    const gen = this.gen;
    let gw = '';
    try { gw = String((await this.readSlow()) || ''); } catch { gw = ''; }
    if (gen !== this.gen || !gw) return;
    if (this.gwLast == null) { this.gwLast = gw; return; }
    if (gw === this.gwLast) return;
    this.gwLast = gw;
    this.fire('gateway');
  }
```
Run the tests — PASS.

- [ ] **Step 4: Wire**

`startNetWatcher()` in both mirrors: add `readSlow: () => tunPlatform.defaultGateway(),` to the `NetWatcher` options.

- [ ] **Step 5: Tests + commit**

`npm test` — PASS.
```bash
git add src/main/tunPlatform.js tests/tunPlatform.test.js src/main/netWatcher.js tests/netWatcher.test.js src/main/main.js src/server/service.js
git commit -m "A router that changes under the same addresses now triggers the rebuild the address watcher could not see"
```
**Device-verified:** on the owner's machine, `route print -4 0.0.0.0` while connected under TUN — confirm the parsed value is the physical gateway (log line to add for one release: `send('log', { line: 'Default gateway: ' + gw, level: 'info' })` in the first `pollSlow` reading — put it behind the `gwLast == null` branch via an `onFirst` callback if desired, or read it from the app log).

---

### Task C5: the strict guard's resolver holes are whole hosts

**Files:**
- Modify: `src/main/leakGuard.js` (`winStrictApplyScript` 353, `macPfAnchorText`, `engage` 783, `holdForReconnect` 939, constants ≈ 100), `tests/leakGuard.test.js`
- Modify: `src/main/main.js:865-880` (engage call), `src/server/service.js` (its engage call)

**Why:** the strict block's `-RemoteAddress` complement opens the direct resolvers (Shecan, a private DoH) as complete hosts on every port. A resolver host that also serves anything else, or that gets compromised, is a hole in a guard that promises "nothing but the tunnel".

**Interfaces:**
- `winStrictApplyScript({ adapters, ranges, resolverIps })`, `macPfAnchorText({ tunDevice, excludes, resolverIps })`, `engage({ …, excludes, resolverExcludes })`; state file gains `resolverExcludes`; `RESOLVER_KEEP_PORTS = ['1-52', '54-442', '444-65535']` (53 for UDP/TCP DNS, 443 for a private DoH).

- [ ] **Step 1: Failing tests**

Append to `tests/leakGuard.test.js`:
```js
test('winStrictApplyScript: resolver excludes stay open on 53 and 443 only', () => {
  const s = winStrictApplyScript({ adapters: [{ alias: 'Wi-Fi' }], ranges: ['0.0.0.0-1.1.1.0', '1.1.1.2-255.255.255.255'], resolverIps: ['178.22.122.100'] });
  const lines = s.split('\n');
  const extra = lines.filter(l => l.includes('resolver'));
  assert.equal(extra.length, 2, 'one per protocol');
  for (const l of extra) {
    assert.match(l, /-Action Block/);
    assert.match(l, /-RemoteAddress @\('178\.22\.122\.100'\)/);
    assert.match(l, /-RemotePort @\('1-52','54-442','444-65535'\)/);
  }
  assert.equal(winStrictApplyScript({ adapters: [{ alias: 'Wi-Fi' }], ranges: ['0.0.0.0-255.255.255.255'] }).includes('resolver'), false);
});
test('macPfAnchorText: resolvers pass on port 53/443 only; entry addresses pass in full', () => {
  const a = macPfAnchorText({ tunDevice: 'utun5', excludes: ['5.6.7.8', '178.22.122.100'], resolverIps: ['178.22.122.100'] });
  assert.match(a, /^pass out quick to \{ 5\.6\.7\.8, /m);
  assert.doesNotMatch(a.split('\n').find(l => l.startsWith('pass out quick to {')), /178\.22\.122\.100/);
  assert.match(a, /^pass out quick proto \{ tcp, udp \} to \{ 178\.22\.122\.100 \} port \{ 53, 443 \}$/m);
});
```
Run — FAIL.

- [ ] **Step 2: Implement**

Constants (after `UDP_KEEP_PORTS`): `const RESOLVER_KEEP_PORTS = ['1-52', '54-442', '444-65535'];`

`winStrictApplyScript`:
```js
function winStrictApplyScript({ adapters, ranges, resolverIps } = {}) {
  const list = (ranges || []).filter(Boolean);
  const resolvers = addrList(resolverIps).filter(ip => !ip.includes(':'));   // the block is v4; v6 has no route off the tunnel
  const lines = ["$ErrorActionPreference = 'Stop'", winGroupRemoveScript()];
  if (list.length) {
    for (const a of adapters || []) {
      const alias = aliasOf(a);
      for (const proto of ['TCP', 'UDP']) {
        lines.push(winBlockRule(`${FW_GROUP} strict ${proto} ${alias}`,
          `-InterfaceAlias ${psQuote(alias)} -Protocol ${proto} -RemoteAddress @(${psList(list)})`));
        // A resolver is a hole in the block above; this closes every port of it but DNS.
        if (resolvers.length) {
          lines.push(winBlockRule(`${FW_GROUP} strict ${proto} resolver ${alias}`,
            `-InterfaceAlias ${psQuote(alias)} -Protocol ${proto} -RemoteAddress @(${psList(resolvers)}) -RemotePort @(${psList(RESOLVER_KEEP_PORTS)})`));
        }
      }
    }
  }
  return lines.join('\n');
}
```
`macPfAnchorText({ tunDevice, excludes, resolverIps })`: compute `resolvers = addrList(resolverIps).filter(PF_ADDR_RE test)`, build `list` from `excludes` + `GUARD_EXCLUDES` **excluding** the resolvers, and emit after the `pass out quick to { … }` line:
```js
    ...(resolvers.length ? [`pass out quick proto { tcp, udp } to { ${resolvers.join(', ')} } port { 53, 443 }`] : []),
```
`engage(...)`: signature `engage({ level, peer4, peer6, tunAlias, backend, excludes, resolverExcludes } = {})`; state gets `resolverExcludes: addrList(resolverExcludes),`; the win strict block: `winStrictApplyScript({ adapters, ranges, resolverIps: state.resolverExcludes })`; the mac anchor: `macPfAnchorText({ tunDevice: tunAlias, excludes, resolverIps: state.resolverExcludes })`.
`holdForReconnect`: `winStrictApplyScript({ adapters, ranges, resolverIps: addrList(st.resolverExcludes) })` and `macPfAnchorText({ tunDevice: st.tunAlias, excludes: merged, resolverIps: addrList(st.resolverExcludes) })`.
`repairAtLaunch`/`release` do not read the holes; nothing to change there.

- [ ] **Step 3: Call sites**

main.js engage call (≈ 865): add `resolverExcludes: resolverBypassIpsOf(config),` after `excludes: myTun.excludeIps || []`. Same in service.js.

- [ ] **Step 4: Tests + commit**

`npm test` — PASS (the existing `winStrictApplyScript` line-count tests may need `+0` since no resolver was passed there; adjust only if they passed `resolverIps`).
```bash
git add src/main/leakGuard.js tests/leakGuard.test.js src/main/main.js src/server/service.js
git commit -m "The strict guard opens a direct resolver on DNS ports only, not as a whole host"
```
**Device-verified (strict, Windows):** `Get-NetFirewallRule -Group IRNetFree | Measure-Object` shows 4 rules per adapter; `nslookup example.com 178.22.122.100` answers; `Test-NetConnection 178.22.122.100 -Port 80` fails.

---

### Task C6: sing-box-format configs resolve every name off the tunnel

**Files:**
- Modify: `src/main/singboxBuilder.js:22-56, 190-199`, `tests/singboxBuilder.test.js`
- Modify: `src/main/configBuilder.js` (`resolverBypassIpsOf` 457), `tests/configBuilder.test.js`
- Modify: `src/main/main.js:836` (`hijacks`), `src/server/service.js` (same line)
- Modify: `scripts/validate-configs.js` (sing-box check of the new shape)

**Why:** `buildSingboxConfig` has ONE DNS server, `dns-direct`, reached without the proxy, as `final` — so under a sing-box-format config every name the user visits is resolved in cleartext at 1.1.1.1 (or whatever `dnsRemote[0]` is) from the physical NIC, and no port-53 hijack exists, so the TUN adapter's DNS had to be set to a public resolver. Both are leaks the Xray path closed a year ago.

**Interfaces:**
- New shape: `dns.servers = [dns-remote (detour proxy), dns-direct (detour direct)]`, `dns.final = 'dns-remote'`, `dns.strategy`, `route.rules = [{ action: 'sniff' }, { protocol: 'dns', action: 'hijack-dns' }]`, `route.default_domain_resolver = 'dns-direct'`. `resolverBypassIpsOf` returns the `dns-direct` IP for a sing-box config.

- [ ] **Step 1: Failing tests**

Replace the first two tests of `tests/singboxBuilder.test.js` with:
```js
test('remote DoH goes THROUGH the proxy and answers everything; dns-direct only resolves the server itself', () => {
  const c = buildSingboxConfig(VLESS_WS_TLS, { dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: ['178.22.122.100'] });
  assert.deepEqual(c.dns.servers, [
    { type: 'https', tag: 'dns-remote', server: '1.1.1.1', path: '/dns-query', detour: 'proxy' },
    { type: 'udp', tag: 'dns-direct', server: '178.22.122.100', detour: 'direct' }
  ]);
  assert.equal(c.dns.final, 'dns-remote');
  assert.equal(c.dns.strategy, 'ipv4_only');
  assert.equal(c.route.default_domain_resolver, 'dns-direct');
  assert.deepEqual(c.route.rules, [{ action: 'sniff' }, { protocol: 'dns', action: 'hijack-dns' }]);
  assert.equal(c.route.final, 'proxy');
});
test('no direct resolver configured: dns-direct is the first remote entry reached direct; ipv6 → prefer_ipv4', () => {
  const c = buildSingboxConfig(VLESS_WS_TLS, { dnsRemote: ['9.9.9.9'], dnsDirect: [], ipv6: true });
  assert.deepEqual(c.dns.servers[1], { type: 'udp', tag: 'dns-direct', server: '9.9.9.9', detour: 'direct' });
  assert.equal(c.dns.strategy, 'prefer_ipv4');
  assert.equal(buildSingboxConfig(VLESS_WS_TLS, {}).dns.servers[0].server, '1.1.1.1');
});
```
`tests/configBuilder.test.js`:
```js
test('resolverBypassIpsOf understands a sing-box config: the direct resolver IP', () => {
  const { buildSingboxConfig } = require('../src/main/singboxBuilder');
  const c = buildSingboxConfig(VLESS_WS_TLS, { dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: ['178.22.122.100'] });
  assert.deepEqual(resolverBypassIpsOf(c), ['178.22.122.100']);
});
```
Run — FAIL.

- [ ] **Step 2: Builder**

In `buildSingboxConfig` replace from `const remote = …` through the `return { … }` with:
```js
  const remote = Array.isArray(s.dnsRemote) ? s.dnsRemote : (Array.isArray(s.dns) ? s.dns : []);
  const first = String((remote.find(v => v && String(v).trim()) || '1.1.1.1')).trim();
  const directList = Array.isArray(s.dnsDirect) ? s.dnsDirect.map(v => String(v || '').trim()).filter(v => /^\d+\.\d+\.\d+\.\d+$/.test(v)) : [];
  // Two resolvers, two jobs. dns-remote answers the user's names THROUGH the
  // tunnel (it used to be asked in cleartext from the physical NIC). dns-direct
  // exists for one name only — the proxy server's own — which cannot go through
  // the proxy it is needed to reach; the TUN layer routes its address off the
  // tunnel (resolverBypassIpsOf). The hijack rule answers every port-53 packet
  // that reaches the SOCKS inbound, so the TUN adapter's DNS can point at the
  // tunnel peer exactly as it does for an Xray config.
  const dnsRemote = Object.assign(singboxDnsServer(first, 'dns-remote'), { detour: 'proxy' });
  const dnsDirect = directList.length
    ? { type: 'udp', tag: 'dns-direct', server: directList[0], detour: 'direct' }
    : Object.assign(singboxDnsServer(first, 'dns-direct'), { detour: 'direct' });

  return {
    log: { level: singboxLogLevel(s.logLevel), timestamp: false },
    dns: { servers: [dnsRemote, dnsDirect], final: 'dns-remote', strategy: s.ipv6 ? 'prefer_ipv4' : 'ipv4_only' },
    inbounds,
    outbounds: [outbound, { type: 'direct', tag: 'direct' }],
    route: {
      rules: [{ action: 'sniff' }, { protocol: 'dns', action: 'hijack-dns' }],
      final: 'proxy',
      default_domain_resolver: 'dns-direct'
    }
  };
```
`singboxDnsServer(entry, tag)`:
```js
function singboxDnsServer(entry, tag) {
  const m = entry.match(/^https(?:\+local)?:\/\/([^/:?#]+)(?::(\d+))?(\/[^?#]*)?/i);
  if (m) {
    const srv = { type: 'https', tag, server: m[1] };
    if (m[2]) srv.server_port = parseInt(m[2], 10);
    if (m[3]) srv.path = m[3];
    return srv;
  }
  return { type: 'udp', tag, server: entry };
}
```
Update the module comment: "Live traffic stats … absent" stays; remove the sentence claiming lookups are kept off the tunnel.

`configBuilder.resolverBypassIpsOf`:
```js
function resolverBypassIpsOf(config) {
  // A sing-box config: the resolver(s) dialled `direct` — their addresses must be routed off the tunnel.
  if (config && config.dns && Array.isArray(config.dns.servers) && !config.routing) {
    return config.dns.servers
      .filter(x => x && x.detour === 'direct' && /^\d+\.\d+\.\d+\.\d+$/.test(String(x.server || '')))
      .map(x => String(x.server))
      .filter((ip, i, a) => a.indexOf(ip) === i);
  }
  const rules = (config && config.routing && config.routing.rules) || [];
  …unchanged…
```

- [ ] **Step 3: main.js / service.js**

Line 836: `const hijacks = engineFormat(runEngine) !== 'sing-box';` → `const hijacks = true;   // both formats answer port 53 themselves now (sing-box: hijack-dns)` — and update the comment above it. Same in service.js.

- [ ] **Step 4: Validate with sing-box**

`scripts/validate-configs.js` runs `sing-box check` on TUN shapes when `IRNF_SINGBOX_EXE` is set (line 136–142). Add the proxy-config shape to that block: `buildSingboxConfig(VLESS_WS_TLS, { dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: ['178.22.122.100'] })` and the no-direct variant. Run: `set IRNF_SINGBOX_EXE=<userData>\bin\sing-box.exe && npm run validate` — Expected: both pass `check` (sing-box 1.13.14 accepts `action: sniff`, `action: hijack-dns`, `detour` on DNS servers, `default_domain_resolver`).

- [ ] **Step 5: Tests + commit**

`npm test`; `node scripts/probe-dns-leak.js` — 36/36.
```bash
git add src/main/singboxBuilder.js tests/singboxBuilder.test.js src/main/configBuilder.js tests/configBuilder.test.js src/main/main.js src/server/service.js scripts/validate-configs.js
git commit -m "A sing-box-format config resolves names through the tunnel and answers port 53 itself, like an Xray config"
```
**Device-verified:** a sing-box-engine config under TUN; C1's self-test shows adapter DNS = tunnel peer and the resolver answering; `sing-box` log shows `dns-remote` queries via `proxy`.

---

### Task C8: two cores for one chain — gated on the owner's answer to C7

**Files:**
- Create: `src/main/splitPlan.js`, `tests/splitPlan.test.js`
- Modify: `src/main/configBuilder.js` (`bindDirectDials` ≈ 812), `tests/configBuilder.test.js`
- Modify: `src/main/xrayManager.js` (`startAux`, `stopAux`), `tests/xrayManager.test.js`
- Modify: `src/main/main.js` (`buildActive` 477, `withWgEndpointIps` 603, `doConnect` validate/start ≈ 746–780, `doDisconnect`, `reapplyConnection`, `rebuildActiveConfig`, `teardownForQuit`), `src/server/service.js` (same)

**Why:** `chooseEngine` runs a whole chain on PattN when any member asks for it. The owner's real chain is [a hop that needs PattN] → [a corporate WireGuard that works on the official core]. Should the PattN-side WireGuard failure survive C7, the fix is to run each half on the core that works: the front core (PattN) serves the hops on a loopback SOCKS port; the back core (official) dials that port as the first hop of its own chain and owns the app's inbounds, DNS, routing and stats.

**Interfaces:**
- `splitChain(plan, defaultEngine) → { front: server[], back: server[] } | null` (null = not splittable / not needed).
- `bridgeServer(port) → server` (a synthetic SOCKS server on 127.0.0.1:port).
- `buildSplitConfigs(plan, settings, split, bridgePort) → { front: config, back: config }`.
- `XrayManager.startAux(config, engineId) → Promise<void>`, `stopAux()`; `xray.aux` = `{ proc, cfgPath, engine } | null`.
- `bindDirectDials` skips outbounds that dial loopback.

- [ ] **Step 1: Failing tests**

`tests/splitPlan.test.js`:
```js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { splitChain, bridgeServer, buildSplitConfigs } = require('../src/main/splitPlan');
const { settings, VLESS_WS_TLS, TROJAN_TCP_TLS, WG_CORP, outboundTagged } = require('./fixtures');

const pattn = (s) => Object.assign({}, s, { id: s.id + '-p', engine: 'xray-pattn' });

test('splitChain: PattN hops in front of an official-core WireGuard exit', () => {
  const sp = splitChain({ mode: 'chain', chain: [pattn(VLESS_WS_TLS), WG_CORP] }, 'xray');
  assert.deepEqual(sp.front.map(s => s.id), ['sv-vless-p']);
  assert.deepEqual(sp.back.map(s => s.id), ['sv-wgcorp']);
});
test('splitChain: nothing to split when every member wants the same core, when PattN is not a prefix, or without a WireGuard behind', () => {
  assert.equal(splitChain({ mode: 'chain', chain: [VLESS_WS_TLS, WG_CORP] }, 'xray'), null);
  assert.equal(splitChain({ mode: 'chain', chain: [pattn(VLESS_WS_TLS), pattn(WG_CORP)] }, 'xray'), null);
  assert.equal(splitChain({ mode: 'chain', chain: [VLESS_WS_TLS, pattn(TROJAN_TCP_TLS), WG_CORP] }, 'xray'), null, 'PattN not a prefix');
  assert.equal(splitChain({ mode: 'chain', chain: [pattn(VLESS_WS_TLS), TROJAN_TCP_TLS] }, 'xray'), null, 'no WireGuard: PattN runs it fine');
  assert.equal(splitChain({ mode: 'single', server: pattn(VLESS_WS_TLS) }, 'xray'), null);
  assert.equal(splitChain({ mode: 'chain', chain: [pattn(VLESS_WS_TLS), WG_CORP] }, 'xray-pattn'), null, 'default PattN: the exit wants PattN too');
});
test('buildSplitConfigs: the front serves a loopback SOCKS; the back chains through it and keeps the app inbounds', () => {
  const plan = { mode: 'chain', chain: [pattn(VLESS_WS_TLS), WG_CORP] };
  const s = settings({ socksPort: 10808, httpPort: 10809, apiPort: 10085, tunMode: true, directInterface: 'Wi-Fi' });
  const { front, back } = buildSplitConfigs(plan, s, splitChain(plan, 'xray'), 47001);
  assert.deepEqual(front.inbounds.map(i => [i.protocol, i.port, i.listen]), [['socks', 47001, '127.0.0.1'], ['http', 47002, '127.0.0.1']]);
  assert.equal(front.metrics.listen, '127.0.0.1:47003');
  assert.equal(outboundTagged(front, 'proxy').streamSettings.sockopt.interface, 'Wi-Fi', 'the hop is bound to the NIC under TUN');
  assert.deepEqual(back.inbounds.map(i => i.port), [10808, 10809]);
  const bridge = outboundTagged(back, 'proxy-h0');
  assert.equal(bridge.protocol, 'socks');
  assert.deepEqual(bridge.settings.servers[0], { address: '127.0.0.1', port: 47001 });
  assert.equal(bridge.streamSettings && bridge.streamSettings.sockopt && bridge.streamSettings.sockopt.interface, undefined, 'a loopback dial is never bound to the NIC');
  const wg = outboundTagged(back, 'proxy');
  assert.equal(wg.protocol, 'wireguard');
  assert.equal(wg.streamSettings.sockopt.dialerProxy, 'proxy-h0');
  assert.equal(back.policy.levels['0'].bufferSize, 0, 'chained WireGuard');
});
```
`tests/configBuilder.test.js`:
```js
test('bindDirectDials leaves a loopback dial unbound', () => {
  const s = settings({ directInterface: 'Wi-Fi' });
  const local = { id: 'lo', name: 'lo', protocol: 'socks', address: '127.0.0.1', port: 4700, outbound: { protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port: 4700 }] } } };
  const c = buildConfig({ mode: 'chain', chain: [local, WG_CORP] }, s);
  assert.equal(outboundTagged(c, 'proxy-h0').streamSettings && outboundTagged(c, 'proxy-h0').streamSettings.sockopt && outboundTagged(c, 'proxy-h0').streamSettings.sockopt.interface, undefined);
  assert.equal(outboundTagged(c, 'direct').streamSettings.sockopt.interface, 'Wi-Fi');
});
```
Run — FAIL.

- [ ] **Step 2: `bindDirectDials` loopback exception** (configBuilder.js ≈ 812)

```js
/** An outbound whose server is this machine: binding it to the NIC would refuse the dial. */
function dialsLoopback(o) {
  const st = (o && o.settings) || {};
  const list = [].concat(st.servers || [], st.vnext || []);
  return list.some(x => x && /^(127\.|::1$|localhost$)/i.test(String(x.address || '')));
}
function bindDirectDials(outbounds, name) {
  if (typeof name !== 'string' || !name.trim()) return outbounds;
  for (const o of outbounds) {
    if (!o || o.protocol === 'dns' || o.protocol === 'blackhole' || dialsLoopback(o)) continue;
    …unchanged…
```

- [ ] **Step 3: `src/main/splitPlan.js`**

```js
'use strict';
/**
 * Two cores for one chain.
 *
 * chooseEngine() runs a whole chain on the patterniha fork when any member
 * asks for it. The owner's chain is [a hop that needs the fork] → [a corporate
 * WireGuard that the official core carries]. When the fork cannot carry that
 * WireGuard, each half runs on the core that works:
 *
 *   app inbounds ─► BACK core (official): bridge socks ─► WireGuard exit
 *                                             │
 *                          127.0.0.1:<port> ◄─┘
 *                                             ▼
 *                   FRONT core (fork): socks-in ─► the fork's hops ─► internet
 *
 * The back core owns everything the app relies on — DNS plan, routing rules,
 * metrics, the TUN's SOCKS port. The front is a private SOCKS on loopback.
 */
const { buildConfig } = require('./configBuilder');

const BRIDGE_ID = '__bridge__';

function engineOf(server, defaultEngine) {
  return server.engine || (defaultEngine === 'xray-pattn' ? 'xray-pattn' : 'xray');
}

/** The fork's hops as a prefix, an official-core WireGuard somewhere behind them — else null. */
function splitChain(plan, defaultEngine = 'xray') {
  if (!plan || plan.mode !== 'chain' || !Array.isArray(plan.chain) || plan.chain.length < 2) return null;
  const members = plan.chain.filter(s => s && s.outbound);
  let cut = 0;
  while (cut < members.length && engineOf(members[cut], defaultEngine) === 'xray-pattn') cut++;
  if (cut === 0 || cut === members.length) return null;
  const back = members.slice(cut);
  if (back.some(s => engineOf(s, defaultEngine) === 'xray-pattn')) return null;      // interleaved
  if (!back.some(s => s.protocol === 'wireguard')) return null;                       // the fork carries the rest fine
  return { front: members.slice(0, cut), back };
}

/** A synthetic SOCKS server: the front core's inbound, as the back core's first hop. */
function bridgeServer(port) {
  return {
    id: BRIDGE_ID, name: 'bridge', protocol: 'socks', address: '127.0.0.1', port,
    outbound: { protocol: 'socks', settings: { servers: [{ address: '127.0.0.1', port }] } }
  };
}

function buildSplitConfigs(plan, settings, split, bridgePort) {
  const frontSettings = Object.assign({}, settings, {
    socksPort: bridgePort, httpPort: bridgePort + 1, apiPort: bridgePort + 2, allowLan: false,
    routingMode: 'global', blockAds: false, customRules: [], advancedRouting: false,
    // the front resolves nothing for the user; its own hops' names go to the remote list, unmanaged
    dnsManaged: false, systemProxy: false
  });
  const frontPlan = split.front.length >= 2 ? { mode: 'chain', chain: split.front } : { mode: 'single', server: split.front[0] };
  const front = buildConfig(frontPlan, frontSettings);
  const back = buildConfig(Object.assign({}, plan, { chain: [bridgeServer(bridgePort), ...split.back] }), settings);
  return { front, back };
}

module.exports = { splitChain, bridgeServer, buildSplitConfigs, BRIDGE_ID };
```
Run the tests — PASS. (If `buildConfig` for a single front hop emits `proxy` without a chain, the front test's `outboundTagged(front, 'proxy')` holds; adjust the expectation only if the tag differs and say why in the commit.)

- [ ] **Step 4: `XrayManager.startAux` / `stopAux`**

In `xrayManager.js` after `stop()`:
```js
  /**
   * A second core beside the main one (splitPlan.js). Its own process and
   * config file; its lines reach the same log with an [aux] prefix; a death is
   * reported through onStatus('aux-stopped') and the owner decides what to do.
   */
  async startAux(config, engineId) {
    await this.stopAux();
    const { id, bin } = this.resolveEngine(engineId);
    if (!bin) throw new Error(`${engineId} binary not found`);
    const cfgPath = path.join(this.dataDir, 'aux-config.json');
    fs.writeFileSync(cfgPath, JSON.stringify(config, null, 2), 'utf8');
    const proc = spawn(bin, engineRunArgs(id, cfgPath), { cwd: path.dirname(bin), windowsHide: true, env: this.spawnEnv() });
    const aux = { proc, cfgPath, engine: id };
    this.aux = aux;
    let recent = '';
    const onData = (buf, level) => {
      const text = buf.toString('utf8'); recent = (recent + text).slice(-4000);
      for (const line of text.split(/\r?\n/)) if (line.trim()) this.onLog('[aux] ' + line.trim(), level);
    };
    proc.stdout.on('data', (d) => onData(d, 'log'));
    proc.stderr.on('data', (d) => onData(d, 'warn'));
    const died = await new Promise((resolve) => {
      const t = setTimeout(() => resolve(null), 1200);
      proc.once('exit', (code) => { clearTimeout(t); resolve({ code }); });
      proc.once('error', (e) => { clearTimeout(t); resolve({ error: e.message }); });
    });
    if (died) {
      if (this.aux === aux) this.aux = null;
      try { fs.unlinkSync(cfgPath); } catch { /* gone */ }
      throw new Error(extractXrayError(recent) || died.error || `front core exited on startup (code ${died.code})`);
    }
    proc.on('exit', (code, signal) => {
      if (this.aux === aux) this.aux = null;
      this.onLog(`front core exited (code=${code} signal=${signal || '-'})`, code === 0 ? 'info' : 'error');
      this.onStatus('aux-stopped', { code, signal });
    });
    this.onLog(`Front core started: ${path.basename(bin)} on the bridge port`, 'info');
  }

  async stopAux() {
    const aux = this.aux;
    if (!aux) return;
    this.aux = null;
    await new Promise((resolve) => {
      const done = () => resolve();
      aux.proc.once('exit', done);
      try {
        if (os.platform() === 'win32') spawn('taskkill', ['/pid', String(aux.proc.pid), '/t', '/f'], { windowsHide: true });
        else aux.proc.kill('SIGTERM');
      } catch { done(); }
      setTimeout(done, 2500);
    });
    try { fs.unlinkSync(aux.cfgPath); } catch { /* gone */ }
  }
```
Constructor: `this.aux = null;`. Test (stub spawn, as the other manager tests do): `startAux` with a child that stays alive resolves and sets `xm.aux`; a child that exits within 1.2 s rejects with the extracted error; `stopAux()` clears `aux` and removes the file.

- [ ] **Step 5: Wire (main.js, mirrored in service.js)**

- Requires: `const { splitChain, buildSplitConfigs } = require('./splitPlan');`
- `buildActive(serverId, settings)`: after `const { plan, label, entryAddrs } = buildPlan(serverId, settings);` add
  ```js
  const split = splitChain(plan, settings.defaultEngine);
  ```
  When `split` is set: `engine = 'xray'` (the back core; skip `chooseEngine`), build `const bridgePort = settings.bridgePort;` — allocate it in `doConnect` BEFORE `buildActive` (`const bridgePort = await getFreePort();` and pass via `settings = Object.assign({}, settings, { bridgePort })`), then `const { front, back } = buildSplitConfigs(plan, settings, split, settings.bridgePort); config = back;` and return `{ …, split: { front, engine: 'xray-pattn' } }`.
- `withWgEndpointIps`: when `splitChain(plan, settings.defaultEngine)` is non-null return `settings` unchanged (the WireGuard runs on the official core, which resolves the endpoint itself).
- `doConnect` after `validateWithFallback(config, engine)` succeeds: if `split`, `const fc = await xray.validate(split.front, split.engine); if (!fc.ok) throw new Error('front core: ' + fc.error);` then `await xray.startAux(split.front, split.engine);` BEFORE `xray.start(config, check.engine)`. `runEngine` label: `check.engine + '+xray-pattn'`.
- `entryAddrs`: the TUN excludes must include the FRONT hop's address, not the bridge — `buildPlan` already returns the chain's real first hop as `entryAddrs` (it reads `plan.chain[0]`); confirm with a log line and keep.
- `doDisconnect`, `reapplyConnection` teardown, `teardownForQuit`, `rebuildActiveConfig` (before `xray.start`): `await xray.stopAux();` next to every `xray.stop()`. `rebuildActiveConfig` re-runs `buildActive` — it must reuse `liveBridgePort` (a module-level variable set in `doConnect`) so the running front core's port is kept, and only restart the front when `split.front` changed (compare `JSON.stringify`).
- `onStatus('aux-stopped')` in the `XrayManager` constructor's `onStatus` handler: when the app believes it is connected and `!userDisconnecting`, log `'Front core died — rebuilding the connection'` and call `recoverFromNetworkChange('front-core')` (add `'front-core'` to the health gate exception alongside `'health'`).
- Validate (`scripts/validate-configs.js`): add both halves of `buildSplitConfigs` for the fixture chain `[pattn(VLESS_WS_TLS), WG_CORP]` — the front on PattN (`IRNF_XRAY_EXE` run), the back on the official core.

- [ ] **Step 6: Probe (loopback only)**

Extend `scripts/probe-wg-chain.js` with a `IRNF_PROBE_SPLIT=1` mode: the existing rig (sing-box WireGuard responder, hop core) plus a front core on PattN and a back core on the official binary built by `buildSplitConfigs`; assert the HTTP fetch through the app inbounds succeeds. Run: `set IRNF_PROBE_SPLIT=1 && npm run probe:wg` — Expected: PASS on this machine (both binaries are in `userData/bin`).

- [ ] **Step 7: Tests + commit**

`npm test`; `npm run validate` on both cores; `npm run probe:wg` with and without `IRNF_PROBE_SPLIT`.
```bash
git add src/main/splitPlan.js tests/splitPlan.test.js src/main/configBuilder.js tests/configBuilder.test.js src/main/xrayManager.js tests/xrayManager.test.js src/main/main.js src/server/service.js scripts/validate-configs.js scripts/probe-wg-chain.js
git commit -m "A chain whose hops need the fork and whose WireGuard exit needs the official core runs on both, bridged over loopback"
```
**Device-verified:** the owner's real chain; the app log shows `Front core started`, the status label shows `xray+xray-pattn`, and `gitlab.hawk.tes.systems` opens. If it still closes the connection, the fault is not the core split — record that in the ledger.

---

### Task C9: Linux strict guard, macOS DNS snapshot order

**Files:**
- Modify: `src/main/leakGuard.js` (Linux branch in `engage`/`release`/`repairAtLaunch`; `linuxNftRuleset`, `linuxApplyScript`, `linuxReleaseScript`), `tests/leakGuard.test.js`
- Modify: `src/main/tunSingbox.js` (`startMac` 396–470, `stopMac`), `tests/tunSingbox.test.js`
- Modify: `src/main/main.js` / `src/server/service.js` (pass `skipServiceDns`)

**Why (mac):** `startMac` writes the tunnel DNS onto the primary network service inside the privileged setup script, BEFORE `leakGuard.engage()` snapshots that service's resolvers — so the snapshot records OUR peer as the "original", and `release()` restores the peer instead of the ISP's resolvers. With the guard on, the guard must be the only thing that touches service DNS.

**Why (linux):** `engage()` logs "not supported on Linux" and returns; a strict user on Linux has no firewall at all. nftables (present on every current distro) can express the same rule set: on every non-tunnel interface, drop outbound except the excludes, with resolver excludes on 53/443 only.

- [ ] **Step 1: mac — failing test**

`tests/tunSingbox.test.js`:
```js
test('buildMacSetupScript: with no dnsServers the script does not touch the service DNS', () => {
  const s = buildMacSetupScript({ bin: '/b', cfgFile: '/c', logFile: '/l', pidFile: '/p', devFile: '/d', service: 'Wi-Fi', dnsServers: [] });
  assert.doesNotMatch(s, /networksetup -setdnsservers/);
});
```
(Likely already true — the builder emits `true` for an empty list; the test pins it.)

- [ ] **Step 2: mac — implement**

`startMac(socksPort, bypassAddrs, dnsServers, opts)`: after `const dns = this.adapterDns(dnsServers, opts);` add
```js
    // With the leak guard on, the guard owns every service's DNS (and records
    // the originals first). Setting it here too would put OUR peer into that
    // snapshot as the "original" — release() would then restore the peer.
    const guardOwnsDns = !!opts.skipServiceDns;
```
and pass `dnsServers: guardOwnsDns ? [] : [...dns.v4, ...dns.v6]` to `buildMacSetupScript`, and `savedDns: guardOwnsDns ? null : savedDns` into `this.macState`. In `stopMac` (`grep -n "savedDns" src/main/tunSingbox.js`), restore the service DNS only when `this.macState.savedDns` is not null.
main.js/service.js: the `myTun.start(...)` 4th argument gains `skipServiceDns: settings.leakGuard !== 'off' && process.platform === 'darwin'`.

- [ ] **Step 3: linux — failing tests**

```js
test('linuxNftRuleset: drop everything off the tunnel except the excludes; resolvers on 53/443 only', () => {
  const r = linuxNftRuleset({ tunIf: 'tun0', excludes: ['5.6.7.8', '178.22.122.100'], resolverIps: ['178.22.122.100'] });
  assert.match(r, /^table inet irnetfree \{$/m);
  assert.match(r, /oifname "lo" accept/);
  assert.match(r, /oifname "tun0" accept/);
  assert.match(r, /ip daddr \{ 5\.6\.7\.8 \} accept/);
  assert.match(r, /ip daddr \{ 178\.22\.122\.100 \} (tcp|meta l4proto \{ tcp, udp \} th) dport \{ 53, 443 \} accept/);
  assert.match(r, /ip daddr \{ 10\.0\.0\.0\/8, 172\.16\.0\.0\/12, 192\.168\.0\.0\/16/, 'the LAN keeps working');
  assert.match(r, /type filter hook output priority 0; policy drop;/);
});
test('linuxApplyScript / linuxReleaseScript', () => {
  assert.match(linuxApplyScript('/tmp/x.nft'), /^nft -f '\/tmp\/x\.nft'$/m);
  assert.equal(linuxReleaseScript(), 'nft delete table inet irnetfree 2>/dev/null || true');
});
```
Run — FAIL.

- [ ] **Step 4: linux — implement**

In leakGuard.js (Linux section, new):
```js
/* ------------------------------ Linux: nftables ------------------------------ */
const NFT_TABLE = 'irnetfree';
/**
 * The strict guard as one nftables table: outbound policy drop on every
 * interface but loopback and the tunnel, with the same excludes the Windows
 * rules cut (entry addresses in full, resolvers on DNS ports, the private
 * ranges so the LAN and DHCP keep working). `nft delete table` removes it
 * whole — the same "by group" property the Windows rules rely on.
 */
function linuxNftRuleset({ tunIf, excludes, resolverIps } = {}) {
  const resolvers = addrList(resolverIps).filter(ip => !ip.includes(':'));
  const full = addrList(excludes).filter(ip => !ip.includes(':') && !resolvers.includes(ip));
  const lan = GUARD_EXCLUDES.filter(x => !x.includes(':'));
  const lines = [
    `table inet ${NFT_TABLE} {`,
    '  chain output {',
    '    type filter hook output priority 0; policy drop;',
    '    oifname "lo" accept',
    ...(tunIf ? [`    oifname "${tunIf}" accept`] : []),
    `    ip daddr { ${lan.join(', ')} } accept`,
    ...(full.length ? [`    ip daddr { ${full.join(', ')} } accept`] : []),
    ...(resolvers.length ? [`    ip daddr { ${resolvers.join(', ')} } meta l4proto { tcp, udp } th dport { 53, 443 } accept`] : []),
    '    ct state established,related accept',
    '  }',
    '}'
  ];
  return lines.join('\n') + '\n';
}
function linuxApplyScript(file) { return [`nft delete table inet ${NFT_TABLE} 2>/dev/null || true`, `nft -f '${file}'`].join('\n'); }
function linuxReleaseScript() { return `nft delete table inet ${NFT_TABLE} 2>/dev/null || true`; }
```
`engage()`: replace the Linux early return with: when `strict`, write the ruleset to `path.join(this.userData, 'guard.nft')`, run `this._privileged('nft', linuxApplyScript(file))` (the `_privileged` helper on Linux uses `pkexec` — see how `tunPlatform.runScriptPrivileged` behaves on linux and reuse it), write a state file `{ version: 1, level, strict: true, linux: { file }, excludes, resolverExcludes }`; the DNS override stays unsupported (log as today). `release()`/`releaseSync()`/`repairAtLaunch()`: when the state has `linux`, run `linuxReleaseScript()` (privileged) and delete the state. `holdForReconnect`: re-apply the ruleset with merged excludes. Export the three builders.

- [ ] **Step 5: Tests + commit**

`npm test` — PASS.
```bash
git add src/main/leakGuard.js tests/leakGuard.test.js src/main/tunSingbox.js tests/tunSingbox.test.js src/main/main.js src/server/service.js
git commit -m "Linux gets the strict guard as an nftables table; on macOS the guard alone touches the service DNS so its snapshot stays honest"
```
**Device-verified (owner or a tester):** macOS — connect with guard standard, then `networksetup -getdnsservers Wi-Fi` shows the peer; disconnect → the ISP resolvers are back (not the peer). Linux — strict: `sudo nft list table inet irnetfree` shows the table while connected and nothing after disconnect; `dig @178.22.122.100 example.com` works, `curl http://178.22.122.100` fails.

---

## Phase gate

- `npm test` green, pristine; `npm run validate` green on both cores and with `IRNF_SINGBOX_EXE`; `node scripts/probe-dns-leak.js` 36/36; `npm run probe:wg` 2/2 (+ the split probe if C8 shipped).
- Fable reviews: C1, C2, C3, C4 wiring (Opus-implemented); C5, C6, C8, C9 are Fable-implemented.
- The owner runs the device checklists (C1 self-test in the three modes; C5 firewall rule count; C6 sing-box config under TUN).
- Merge `feature/phase-C`, tag v1.7.0.
