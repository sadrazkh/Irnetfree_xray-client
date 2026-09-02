# Opus phases (3b, 4, 5, 6, 7) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the five design phases that do not need privileged system work: live stats that actually count, WireGuard `.conf` import, a light theme, recovery when the network changes, and standard `finalmask`/`cipherSuites`/`fp=unsafe` support.

**Architecture:** Each phase is independent. New pure modules (`netWatcher.js`, the `.conf` parser inside `parser.js`, `applyDpi` inside `configBuilder.js`) carry the logic and are unit-tested; `main.js` and `service.js` only wire them and must stay mirrored. No new dependencies.

**Tech Stack:** Node 18+ core only, Electron 31 for desktop, `node --test`.

## Global Constraints

- Runtime code uses only Node core modules; `package.json` `dependencies` stays empty.
- `node --test "tests/*.test.js"` must stay green (160 tests at branch base) **and its output must be pristine** — no warnings, no experimental Node APIs (`t.mock.timers` was removed once for exactly this).
- Commits are in the repository owner's name only — **no `Co-Authored-By` trailer**.
- Every new `RECONNECT_KEYS` entry needs `set.<key>` in **both** the `fa` and `en` blocks of `src/renderer/i18n.js` (`tests/settingsMeta.test.js` enforces it).
- `src/server/service.js` mirrors `src/main/main.js`; a change to one belongs in the other.
- Android (`android/`) is **not** touched in this plan (that is phase 8).
- The order of `routing.rules` is load-bearing — xray takes the first match. Never reorder without a test pinning the new order.
- Renderer changes are verified through the headless server (`node src/server/server.js --port <port> --data-dir <tmp>`), which serves the identical UI. **Other agents share one browser**: assert `location.port` is yours before every click, and never click destructive controls on an unverified page.
- Engine ids in play: `xray`, `xray-pattn` (both `format: 'xray'`), `sing-box`.

---

## File map

| File | Responsibility | Tasks |
|---|---|---|
| `src/main/configBuilder.js` | metrics endpoint; DPI masks | 1, 6 |
| `src/main/stats.js` | poll `/debug/vars` | 1 |
| `src/main/parser.js` | `.conf` import, `wireguard://` export, `fm`/`cs`/`fp` | 2, 5 |
| `src/renderer/app.js` | `.conf` picker, theme, engine/DPI form | 2, 3, 7 |
| `src/renderer/styles.css`, `index.html`, `i18n.js` | light theme, DPI form | 3, 7 |
| `src/main/netWatcher.js` (new) | network-change detection (pure) | 4 |
| `src/main/main.js`, `src/server/service.js` | wiring, mirrored | 1, 2, 3, 4b |
| `src/main/settingsMeta.js` | new reconnect keys | 4b |

---

### Task 1: Live stats from the metrics endpoint

**Files:**
- Modify: `src/main/configBuilder.js` (`buildConfig` ≈ line 268-285, `buildPoolConfig` ≈ 344-373, `buildRoutingRules` line 38, advanced rules line 239, pool rules line 312)
- Modify: `src/main/stats.js` (whole `query()`)
- Test: `tests/configBuilder.test.js`, `tests/stats.test.js` (new)

**Interfaces:**
- Produces: `sumOutbounds(vars) → { up, down }` exported from `src/main/stats.js` — sums `stats.outbound[tag].uplink/downlink` for every tag except `direct`, `block`, `dns-out` and any tag starting with `dpi-`.

**Why:** `StatsPoller` matches the literal counters `outbound>>>proxy>>>traffic>>>uplink/downlink`, but pool and advanced plans tag their outbounds `out-<serverId>` / `out-chain-<id>`, so the UI shows 0 B/s forever in those modes. It also spawns a child process every second. Xray's `metrics` service serves the same counters over HTTP at `/debug/vars`.

**Keep `stats: {}` and `policy.system`** — the counters only exist because of them. Only the `api` object, the `api` inbound and the `api` routing rule go away.

- [ ] **Step 1: Write the failing config tests**

In `tests/configBuilder.test.js`, replace the test `single: inbounds are socks / http / api on the configured ports` with:

```js
test('single: inbounds are socks / http only — metrics replaces the api inbound', () => {
  const c = buildConfig(single(), settings({ socksPort: 1080, httpPort: 1081, apiPort: 1085 }));

  assert.deepEqual(c.inbounds.map(i => [i.tag, i.port, i.protocol]), [
    ['socks-in', 1080, 'socks'],
    ['http-in', 1081, 'http']
  ]);
  assert.deepEqual(c.inbounds[0].settings, { auth: 'noauth', udp: true });
  // the stats endpoint is a listener, not an inbound, so nothing can collide with it
  assert.deepEqual(c.metrics, { tag: 'metrics', listen: '127.0.0.1:1085' });
  assert.equal(c.api, undefined);
  // the counters still have to be collected
  assert.deepEqual(c.stats, {});
  assert.equal(c.policy.system.statsOutboundUplink, true);
  assert.equal(c.policy.system.statsOutboundDownlink, true);
});

test('no plan emits an api routing rule any more', () => {
  const plans = [
    single(),
    { mode: 'chain', chain: [VLESS_WS_TLS, TROJAN_TCP_TLS] },
    advancedPlan({ rules: [{ type: 'domain', value: 'a.com', target: 'sv-vless' }] }),
    poolPlan([{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }])
  ];
  for (const p of plans) {
    const c = buildConfig(p, settings());
    assert.equal(c.routing.rules.some(r => r.outboundTag === 'api'), false, p.mode);
    assert.equal(c.inbounds.some(i => i.tag === 'api'), false, p.mode);
    assert.equal(c.metrics.listen, '127.0.0.1:10085', p.mode);
  }
});
```

Also fix the two existing order assertions that counted the api rule — change
`assert.deepEqual(ruleTags(c), ['api', 'block', 'direct', 'proxy']);` to
`assert.deepEqual(ruleTags(c), ['block', 'direct', 'proxy']);` and apply the same removal of the leading
`'api'` to **every** `ruleTags` assertion in the file, and to the `buildRoutingRules: the api rule is always first` test — rename it and assert instead that the FIRST rule is the ad-block or private-IP rule and the last is the `0-65535` catch-all:

```js
test('buildRoutingRules: private/LAN bypass precedes the catch-all, which is last', () => {
  for (const mode of ['global', 'bypass-ir', 'bypass-cn', 'direct']) {
    for (const geo of [true, false]) {
      const rules = buildRoutingRules(mode, true, geo);
      const priv = rules.findIndex(r => r.ip && r.ip.includes('127.0.0.0/8'));
      assert.ok(priv > -1, `${mode}/${geo}: no private bypass`);
      assert.ok(priv < rules.length - 1, `${mode}/${geo}: private bypass must not be last`);
      assert.equal(rules.at(-1).port, '0-65535', `${mode}/${geo}: no catch-all`);
      assert.equal(rules.some(r => r.outboundTag === 'api'), false, `${mode}/${geo}: api rule leaked`);
    }
  }
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `node --test tests/configBuilder.test.js`
Expected: FAIL — `c.metrics` is undefined and the api inbound is still present.

- [ ] **Step 3: Change the config builder**

In `buildRoutingRules`, delete the line `rules.push({ type: 'field', inboundTag: ['api'], outboundTag: 'api' });` (line 38).

In the advanced branch (≈ line 239) delete `{ type: 'field', inboundTag: ['api'], outboundTag: 'api' },` from the `rules` array.

In `buildPoolConfig` change

```js
  const rules = [{ type: 'field', inboundTag: ['api'], outboundTag: 'api' }];
```
to
```js
  const rules = [];
```
and delete the line that pushes the api inbound:
```js
  inbounds.push({ tag: 'api', port: s.apiPort, listen: '127.0.0.1', protocol: 'dokodemo-door', settings: { address: '127.0.0.1' } });
```
Its `usedPorts` reservation (added by an earlier task) stays — the metrics listener uses the same port and must still be unclaimable.

In `buildConfig`'s returned object, delete the `api:` line and the api inbound entry, and add `metrics`:

```js
  return {
    log: { loglevel: s.logLevel },
    // Live traffic counters over HTTP (GET /debug/vars) instead of the gRPC-only
    // StatsService: one cheap request per second instead of spawning `xray api
    // statsquery`, and it reports EVERY outbound tag — the pool and advanced
    // plans have no outbound called 'proxy', so the old query always read 0.
    metrics: { tag: 'metrics', listen: `127.0.0.1:${s.apiPort}` },
    stats: {},
    policy: { … unchanged … },
    dns: { … unchanged … },
    inbounds: [
      { tag: 'socks-in', port: s.socksPort, listen, protocol: 'socks', settings: { auth: 'noauth', udp: true }, sniffing },
      { tag: 'http-in', port: s.httpPort, listen, protocol: 'http', settings: {}, sniffing }
    ],
    outbounds,
    routing: { domainStrategy: 'IPIfNonMatch', rules }
  };
```

Make the identical `api:` → `metrics:` swap in `buildPoolConfig`'s returned object.

- [ ] **Step 4: Run the config tests**

Run: `node --test tests/configBuilder.test.js` → Expected: pass.

- [ ] **Step 5: Write the failing stats test**

`tests/stats.test.js`:

```js
'use strict';
/**
 * The traffic meter reads Xray's /debug/vars. The pool and advanced plans have
 * no outbound called 'proxy' — they tag exits 'out-<serverId>' — which is why
 * the old fixed-name query reported 0 B/s in exactly those modes.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { sumOutbounds } = require('../src/main/stats');

const vars = (outbound) => ({ stats: { outbound } });

test('sums every proxying outbound, whatever its tag', () => {
  assert.deepEqual(sumOutbounds(vars({
    'out-sv-a': { uplink: 100, downlink: 900 },
    'out-chain-c1': { uplink: 5, downlink: 50 },
    'out-chain-c1-h0': { uplink: 7, downlink: 70 }
  })), { up: 112, down: 1020 });
});

test('single-server and chain plans still work (tag "proxy")', () => {
  assert.deepEqual(sumOutbounds(vars({ proxy: { uplink: 10, downlink: 20 } })), { up: 10, down: 20 });
});

test('direct, block, dns and the DPI dialers are not proxied traffic', () => {
  assert.deepEqual(sumOutbounds(vars({
    proxy: { uplink: 10, downlink: 20 },
    direct: { uplink: 1000, downlink: 2000 },
    block: { uplink: 1, downlink: 2 },
    'dns-out': { uplink: 3, downlink: 4 },
    'dpi-1': { uplink: 5, downlink: 6 }
  })), { up: 10, down: 20 });
});

test('missing or malformed payloads read as zero, never NaN', () => {
  for (const v of [null, undefined, {}, { stats: {} }, { stats: { outbound: null } }, 'nonsense']) {
    assert.deepEqual(sumOutbounds(v), { up: 0, down: 0 }, JSON.stringify(v));
  }
  assert.deepEqual(sumOutbounds(vars({ proxy: { uplink: 'x' } })), { up: 0, down: 0 });
});
```

- [ ] **Step 6: Run to verify it fails**

Run: `node --test tests/stats.test.js` → Expected: FAIL — `sumOutbounds is not a function`.

- [ ] **Step 7: Rewrite the poller**

Replace the header comment and the `query()` method in `src/main/stats.js`. Remove the `child_process` require and add `const http = require('http');`.

```js
'use strict';
/**
 * Live traffic stats from Xray's `metrics` service: one HTTP GET of
 * /debug/vars per tick, no child process.
 *
 * Counters live under stats.outbound[<tag>].uplink/downlink. We sum every tag
 * EXCEPT the ones that are not proxied traffic (direct, block, dns-out and the
 * dpi-* dialers), because a config's exit tag depends on the plan: 'proxy' for a
 * single server or a chain, 'out-<serverId>' / 'out-chain-<id>' for the pool and
 * advanced routing. The previous implementation asked for the fixed name
 * 'outbound>>>proxy>>>traffic>>>uplink' and therefore always read 0 in those two
 * modes.
 *
 * We compute per-second deltas to show live speed.
 */
const http = require('http');

/** Outbound tags that exist but never carry user traffic through the proxy. */
const NOT_PROXY = new Set(['direct', 'block', 'dns-out']);
const isProxyTag = (tag) => !NOT_PROXY.has(tag) && !tag.startsWith('dpi-');

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

/** { up, down } summed from a parsed /debug/vars body. Never throws, never NaN. */
function sumOutbounds(vars) {
  const out = vars && vars.stats && vars.stats.outbound;
  if (!out || typeof out !== 'object') return { up: 0, down: 0 };
  let up = 0, down = 0;
  for (const tag of Object.keys(out)) {
    if (!isProxyTag(tag)) continue;
    const c = out[tag] || {};
    up += num(c.uplink);
    down += num(c.downlink);
  }
  return { up, down };
}
```

Replace the class's `query()` with:

```js
  query() {
    return new Promise((resolve) => {
      const req = http.get({ host: '127.0.0.1', port: this.apiPort, path: '/debug/vars', timeout: 3000 }, (res) => {
        if (res.statusCode !== 200) { res.resume(); return resolve(null); }
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c) => { body += c; });
        res.on('end', () => {
          try { resolve(sumOutbounds(JSON.parse(body))); } catch { resolve(null); }
        });
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
    });
  }
```

`setBin()` and `binPath` are no longer used by `query()`. Keep the method (callers pass a binary path) but make it a no-op with a comment saying the metrics endpoint needs no binary — removing it would break the mirrored call sites in `main.js` / `service.js`, which are out of this task's scope.

Change the export to:

```js
module.exports = { StatsPoller, sumOutbounds };
```

- [ ] **Step 8: Run both test files, then the suite**

Run: `node --test tests/stats.test.js tests/configBuilder.test.js` → Expected: pass.
Run: `node --test "tests/*.test.js"` → Expected: all pass, no warnings.

- [ ] **Step 9: Commit**

```bash
git add src/main/configBuilder.js src/main/stats.js tests/configBuilder.test.js tests/stats.test.js
git commit -m "Stats: read Xray's metrics endpoint so pool and advanced routing report real traffic"
```

---

### Task 2: Import a WireGuard `.conf`

**Files:**
- Modify: `src/main/parser.js` (new `parseWireguardConf`, `parseMany`, `buildShareLink`'s wireguard branch, exports)
- Test: `tests/parser.test.js`

**Interfaces:**
- Produces: `parseWireguardConf(text) → { name, endpoint, privateKey, publicKey, address, allowedIPs, presharedKey, mtu, reserved, dns }` (the shape `makeWireguardServer` already takes), throws on a missing required field; `isWireguardConf(text) → boolean`.

**Why:** the owner pastes the text form of a WireGuard config (`[Interface]` / `[Peer]`) and expects the app to build the server. Today only the manual form and a `wireguard://` link work, and `buildShareLink` falls back to `server.raw` for wireguard so a manually-added one exports nothing useful.

- [ ] **Step 1: Write the failing tests**

Add to `tests/parser.test.js` (extend the require to include `parseWireguardConf, isWireguardConf`):

```js
/* --------------------------- WireGuard .conf --------------------------- */

const WG_CONF = `[Interface]
PrivateKey = yYYF82v2u8vPXOsOokPZiEOZG664yNpHuXcmaVNMKvg=
Address = 10.1.142.13/32
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = FI/C4wFN+0e31jVk8sFJwxyMu7Hvav4vbWptZ//pnIE=
AllowedIPs = 10.0.0.1/32, 0.0.0.0/0, ::/0
Endpoint = ir.vrt-server.org:11040
PersistentKeepalive = 10`;

test('isWireguardConf recognises the INI form, not a link or a sub blob', () => {
  assert.equal(isWireguardConf(WG_CONF), true);
  assert.equal(isWireguardConf('  \n[interface]\nPrivateKey = k\n[Peer]\nPublicKey = p\nEndpoint = h:1'), true);
  assert.equal(isWireguardConf('wireguard://k@h:51820'), false);
  assert.equal(isWireguardConf('vless://u@a.com:443'), false);
  assert.equal(isWireguardConf('[Interface]\nPrivateKey = k'), false, 'a [Peer] section is required');
});

test('parseWireguardConf reads every field the form takes', () => {
  const f = parseWireguardConf(WG_CONF);
  assert.equal(f.privateKey, 'yYYF82v2u8vPXOsOokPZiEOZG664yNpHuXcmaVNMKvg=');
  assert.equal(f.publicKey, 'FI/C4wFN+0e31jVk8sFJwxyMu7Hvav4vbWptZ//pnIE=');
  assert.equal(f.endpoint, 'ir.vrt-server.org:11040');
  assert.equal(f.address, '10.1.142.13/32');
  assert.equal(f.allowedIPs, '10.0.0.1/32, 0.0.0.0/0, ::/0');
  assert.equal(f.name, 'ir.vrt-server.org');
});

test('parseWireguardConf: keys are case-insensitive, comments and CRLF tolerated', () => {
  const f = parseWireguardConf('[interface]\r\n# a comment\r\nprivatekey=K\r\naddress=10.0.0.2/32\r\nMTU = 1380\r\n\r\n[peer]\r\npublickey=P\r\nendpoint=h.example:51820\r\npresharedkey=PSK\r\n');
  assert.equal(f.privateKey, 'K');
  assert.equal(f.publicKey, 'P');
  assert.equal(f.mtu, '1380');
  assert.equal(f.presharedKey, 'PSK');
  assert.equal(f.allowedIPs, '', 'absent AllowedIPs stays empty so the builder applies its default');
});

test('parseWireguardConf rejects a config that cannot connect', () => {
  assert.throws(() => parseWireguardConf('[Interface]\nPrivateKey = K\n[Peer]\nPublicKey = P'), /Endpoint/);
  assert.throws(() => parseWireguardConf('[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = P\nEndpoint = h:1'), /PrivateKey/);
  assert.throws(() => parseWireguardConf('[Interface]\nPrivateKey = K\n[Peer]\nEndpoint = h:1'), /PublicKey/);
});

test('parseMany imports a pasted .conf as one server', () => {
  const { servers, errors } = parseMany(WG_CONF);
  assert.equal(errors.length, 0);
  assert.equal(servers.length, 1);
  const s = servers[0];
  assert.equal(s.protocol, 'wireguard');
  assert.equal(s.address, 'ir.vrt-server.org');
  assert.equal(s.port, 11040);
  assert.deepEqual(s.outbound.settings.address, ['10.1.142.13/32']);
  assert.deepEqual(s.outbound.settings.peers[0].allowedIPs, ['10.0.0.1/32', '0.0.0.0/0', '::/0']);
});

test('a wireguard server exports a real share link, not its raw text', () => {
  const s = parseMany(WG_CONF).servers[0];
  const link = buildShareLink(s);
  assert.match(link, /^wireguard:\/\//);
  const back = parseLink(link);
  assert.equal(back.address, 'ir.vrt-server.org');
  assert.equal(back.port, 11040);
  assert.equal(back.outbound.settings.secretKey, s.outbound.settings.secretKey);
  assert.equal(back.outbound.settings.peers[0].publicKey, s.outbound.settings.peers[0].publicKey);
  assert.deepEqual(back.outbound.settings.peers[0].allowedIPs, ['10.0.0.1/32', '0.0.0.0/0', '::/0']);
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `node --test tests/parser.test.js` → Expected: FAIL — `isWireguardConf is not a function`.

- [ ] **Step 3: Implement the parser**

Add to `src/main/parser.js`, above `parseWireguard`:

```js
/**
 * The text form of a WireGuard config (what every provider hands out and what a
 * `.conf` file contains). Both sections are required — an [Interface] alone is a
 * server config, not something we can dial.
 */
function isWireguardConf(text) {
  const t = String(text || '');
  return /^\s*\[interface\]/im.test(t) && /^\s*\[peer\]/im.test(t);
}

/**
 * Parse a WireGuard `.conf` into the field shape makeWireguardServer() takes.
 * Keys are case-insensitive; `#`/`;` comments and CRLF are tolerated. Only the
 * FIRST [Peer] is used — a multi-peer config is a router setup, not a client.
 * Throws naming the missing field, so the UI can say which one.
 */
function parseWireguardConf(text) {
  let section = '';
  const iface = {}, peer = {};
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.replace(/[#;].*$/, '').trim();
    if (!line) continue;
    const sec = line.match(/^\[(\w+)\]$/);
    if (sec) { section = sec[1].toLowerCase(); continue; }
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim().toLowerCase();
    const val = line.slice(eq + 1).trim();
    if (section === 'interface') { if (!(key in iface)) iface[key] = val; }
    else if (section === 'peer') { if (!(key in peer)) peer[key] = val; }   // first peer wins
  }

  const privateKey = iface.privatekey || '';
  const publicKey = peer.publickey || '';
  const endpoint = peer.endpoint || '';
  if (!privateKey) throw new Error('WireGuard config: PrivateKey is missing');
  if (!publicKey) throw new Error('WireGuard config: PublicKey is missing');
  if (!endpoint) throw new Error('WireGuard config: Endpoint is missing');

  const [host] = splitHostPort(endpoint);
  return {
    name: host || 'WireGuard',
    endpoint,
    privateKey,
    publicKey,
    address: iface.address || '',
    allowedIPs: peer.allowedips || '',
    presharedKey: peer.presharedkey || '',
    mtu: iface.mtu || '',
    reserved: iface.reserved || '',
    dns: iface.dns || ''
  };
}
```

`makeWireguardServer` already coerces `mtu` with `parseInt(fields.mtu, 10) || 51820`-style defaults, so an empty string is safe. `dns` is captured for a future setting and deliberately unused today — say so in the return's comment.

- [ ] **Step 4: Route it through `parseMany` and give wireguard a real export**

At the top of `parseMany`, before the base64 sniff:

```js
function parseMany(text) {
  let body = String(text || '').trim();

  // A pasted .conf is ONE config spanning many lines — handle it before the
  // per-line loop, which would otherwise see [Interface] and skip everything.
  if (isWireguardConf(body)) {
    try { return { servers: [makeWireguardServer(parseWireguardConf(body))], errors: [] }; }
    catch (e) { return { servers: [], errors: [{ line: '[Interface]…', error: e.message }] }; }
  }
  …unchanged…
```

In `buildShareLink`, replace the final `return server.raw || '';` with a real wireguard serialiser:

```js
  if (proto === 'wireguard') {
    const st = ob.settings || {};
    const peer = (st.peers && st.peers[0]) || {};
    const q = {
      publickey: peer.publicKey || '',
      address: (st.address || []).join(','),
      allowedips: (peer.allowedIPs || []).join(','),
      presharedkey: peer.preSharedKey || '',
      mtu: st.mtu ? String(st.mtu) : '',
      reserved: (st.reserved || []).join(',')
    };
    return `wireguard://${enc(st.secretKey || '')}@${server.address}:${server.port}?${qs(q)}${name}`;
  }
  return server.raw || '';   // unknown protocol: fall back to the imported link
```

`parseWireguard` already reads `publickey`, `address`, `presharedkey`, `mtu`, `reserved` and `allowedips` (lower-case keys), so this round-trips. Export the two new functions:

```js
module.exports = {
  parseLink, parseMany, b64decode, isHttpProxyLink,
  buildStreamSettings, buildWireguardOutbound, makeWireguardServer, makeProxyServer, applyServerEdits,
  parseWireguardConf, isWireguardConf,
  buildShareLink
};
```

- [ ] **Step 5: Run the parser tests, then the suite**

Run: `node --test tests/parser.test.js` → Expected: pass.
Run: `node --test "tests/*.test.js"` → Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/main/parser.js tests/parser.test.js
git commit -m "WireGuard: import a pasted .conf and export a real wireguard:// link"
```

---

### Task 3: `.conf` in the UI — paste, file picker, clipboard

**Files:**
- Modify: `src/renderer/app.js` (`smartImport`, the global paste handler, a new button handler)
- Modify: `src/renderer/index.html` (a "Choose .conf file" button in the WireGuard box)
- Modify: `src/renderer/i18n.js` (both languages)
- Modify: `src/main/main.js`, `src/server/service.js` (a `wg:pickConf` handler, mirrored)
- Modify: `src/preload/preload.js`, `src/server/web-api.js`

**Interfaces:**
- Consumes: `parseMany` (Task 2) already returns a wireguard server for `.conf` text, so `smartImport` needs only to stop treating multi-line non-link text as junk.
- Produces: `window.api.pickWireguardConf() → { ok, text }` — Electron opens a file dialog; the headless build returns `{ ok: false, error }` and the renderer falls back to its own `<input type="file">`.

- [ ] **Step 1: Let smartImport accept a `.conf`**

In `src/renderer/app.js` `smartImport`, the URL/config split currently drops anything that is not a link. Add, right after `if (!text) return;`:

```js
  // A pasted WireGuard .conf is one multi-line config, not a list of links —
  // hand the whole blob to parseMany (main-side) before the per-line split.
  if (/^\s*\[interface\]/im.test(text) && /^\s*\[peer\]/im.test(text)) {
    const res = await window.api.importServers(text);
    state.servers = res.servers;
    if (!state.selectedServerId && state.servers.length) state.selectedServerId = state.servers[0].id;
    renderServers(); renderPicker(); renderChains(); renderPool();
    const failed = (res.errors || []).length;
    toast(failed ? `${t('t.failed')}: ${res.errors[0].error}` : t('t.wgAdded'), failed ? 'err' : 'ok');
    return;
  }
```

In the global paste handler, the guard currently ignores anything that does not look like a link or base64. Extend its regex test so a `.conf` is accepted:

```js
  const looksImportable = /^(https?:\/\/|vless:\/\/|vmess:\/\/|trojan:\/\/|ss:\/\/|socks:\/\/|socks5:\/\/|wireguard:\/\/|wg:\/\/)/im.test(text.trim())
    || /[A-Za-z0-9+/=]{24,}/.test(text.trim())
    || (/^\s*\[interface\]/im.test(text) && /^\s*\[peer\]/im.test(text));
  if (!looksImportable) return;
```

- [ ] **Step 2: Add the file picker**

`src/renderer/index.html` — in the WireGuard box (`#wgBox`), immediately after the `<div class="wg-title" …>` line:

```html
          <div class="row-gap" style="margin-bottom:12px">
            <button class="btn ghost" id="btnWgPickConf" data-i18n="wg.pickConf">انتخاب فایل .conf</button>
            <span class="import-hint" id="wgConfHint"></span>
          </div>
```

`src/renderer/i18n.js` — add to the **fa** block near the other `wg.*` keys:

```js
    'wg.pickConf': 'انتخاب فایل .conf',
    'wg.confLoaded': 'فایل خوانده شد — فیلدها پر شدند',
    'wg.confFailed': 'فایل WireGuard خوانده نشد',
```
and to the **en** block:
```js
    'wg.pickConf': 'Choose .conf file',
    'wg.confLoaded': 'File read — fields filled in',
    'wg.confFailed': 'Could not read the WireGuard file',
```

`src/renderer/app.js` — next to the other `#btnWg*` handlers:

```js
/* Load a WireGuard .conf into the form. Electron opens a native dialog; the
   headless build has no dialog, so fall back to a hidden file input. */
$('#btnWgPickConf').onclick = async () => {
  let text = '';
  try {
    const res = await window.api.pickWireguardConf();
    if (res && res.ok) text = res.text;
    else if (res && res.canceled) return;
  } catch {}
  if (!text) text = await pickLocalFile('.conf,.txt');
  if (!text) return;
  fillWgFormFromConf(text);
};

/** Browser fallback: a throwaway <input type="file"> resolved to its text. */
function pickLocalFile(accept) {
  return new Promise((resolve) => {
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = accept;
    inp.onchange = () => {
      const f = inp.files && inp.files[0];
      if (!f) return resolve('');
      const fr = new FileReader();
      fr.onload = () => resolve(String(fr.result || ''));
      fr.onerror = () => resolve('');
      fr.readAsText(f);
    };
    inp.click();
  });
}

/** Fill the WireGuard form from .conf text. Parsing happens in main. */
async function fillWgFormFromConf(text) {
  const res = await window.api.parseWireguardConf(text);
  if (!res || !res.ok) { $('#wgConfHint').textContent = (res && res.error) || t('wg.confFailed'); return; }
  const f = res.fields;
  $('#wgName').value = f.name || '';
  $('#wgEndpoint').value = f.endpoint || '';
  $('#wgPrivate').value = f.privateKey || '';
  $('#wgPublic').value = f.publicKey || '';
  $('#wgAddress').value = f.address || '';
  $('#wgAllowed').value = f.allowedIPs || '0.0.0.0/0, ::/0';
  $('#wgPsk').value = f.presharedKey || '';
  $('#wgMtu').value = f.mtu || 1420;
  $('#wgReserved').value = f.reserved || '';
  $('#wgConfHint').textContent = t('wg.confLoaded');
}
```

- [ ] **Step 3: The two IPC handlers, mirrored**

`src/main/main.js` in `registerIpc()`, next to the other `servers:*` handlers:

```js
  // Read a WireGuard .conf the user picks, and parse .conf text into form fields.
  ipcMain.handle('wg:pickConf', async () => {
    const res = await dialog.showOpenDialog(mainWindow, {
      title: 'Select a WireGuard configuration',
      properties: ['openFile'],
      filters: [{ name: 'WireGuard', extensions: ['conf', 'txt'] }]
    });
    if (res.canceled || !res.filePaths[0]) return { ok: false, canceled: true };
    try { return { ok: true, text: fs.readFileSync(res.filePaths[0], 'utf8') }; }
    catch (e) { return { ok: false, error: e.message }; }
  });
  ipcMain.handle('wg:parseConf', (e, text) => {
    try { return { ok: true, fields: parseWireguardConf(text) }; }
    catch (err) { return { ok: false, error: err.message }; }
  });
```
Add `parseWireguardConf` to main.js's `require('./parser')` destructure.

`src/server/service.js` — same two channels, no dialog:

```js
    // headless: no native dialog; the browser picks the file itself
    'wg:pickConf': () => ({ ok: false, error: 'not available in server mode' }),
    'wg:parseConf': (text) => {
      try { return { ok: true, fields: parseWireguardConf(text) }; }
      catch (err) { return { ok: false, error: err.message }; }
    },
```
Add `parseWireguardConf` to service.js's `require('../main/parser')` destructure.

`src/preload/preload.js`:
```js
  pickWireguardConf: () => ipcRenderer.invoke('wg:pickConf'),
  parseWireguardConf: (text) => ipcRenderer.invoke('wg:parseConf', text),
```
`src/server/web-api.js`:
```js
    pickWireguardConf: () => invoke('wg:pickConf'),
    parseWireguardConf: (text) => invoke('wg:parseConf', text),
```

- [ ] **Step 4: Verify in the browser**

```bash
mkdir -p /tmp/irnf-wg && node src/server/server.js --port 7801 --data-dir /tmp/irnf-wg &
sleep 1
```
Open `http://127.0.0.1:7801/` (assert `location.port === '7801'` before every action). Servers → "+ وایرگارد" → "Choose .conf file" → the browser file dialog opens (the Electron path is unavailable headless) → pick a file containing the `WG_CONF` fixture from Task 2 → every field fills and the hint reads "File read". Then close the box, press "+ افزودن", paste the same text, Import → one wireguard server appears. Kill the server. Record what you saw.

- [ ] **Step 5: Run the suite and commit**

Run: `node --test "tests/*.test.js"` → Expected: all pass.

```bash
git add src/renderer/app.js src/renderer/index.html src/renderer/i18n.js src/main/main.js src/server/service.js src/preload/preload.js src/server/web-api.js
git commit -m "WireGuard: paste a .conf anywhere, or pick the file from the form"
```

---

### Task 4: Network-change watcher (pure module)

**Files:**
- Create: `src/main/netWatcher.js`
- Test: `tests/netWatcher.test.js`

**Interfaces:**
- Produces:
  - `fingerprint(interfaces) → string` — a stable signature of the machine's non-internal addresses; order-independent.
  - `class NetWatcher { constructor({ read, onChange, debounceMs = 2500, intervalMs = 3000, setTimer, clearTimer }) ; start() ; stop() ; poke(reason) ; get busy }` — `poke` is how external signals (Electron `powerMonitor` resume, the renderer's `online` event) enter; `setTimer`/`clearTimer` default to `setInterval`/`clearInterval` and are injectable so tests need no real clock.

**Why:** nothing in the app watches the network. On a Wi-Fi ↔ ethernet switch the TUN bypass routes still point at the old gateway, xray keeps running (so no 'stopped' event fires) and the app silently passes no traffic while showing "connected".

- [ ] **Step 1: Write the failing tests**

`tests/netWatcher.test.js`:

```js
'use strict';
/**
 * The watcher must fire ONCE per settled network change. A flapping adapter that
 * changes three times in a second must not trigger three tunnel rebuilds — each
 * rebuild tears the tunnel down and back up.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { NetWatcher, fingerprint } = require('../src/main/netWatcher');

const wifi = { 'Wi-Fi': [{ family: 'IPv4', internal: false, address: '192.168.1.20' }] };
const wifi2 = { 'Wi-Fi': [{ family: 'IPv4', internal: false, address: '192.168.1.99' }] };
const eth = { Ethernet: [{ family: 'IPv4', internal: false, address: '10.0.0.5' }] };

/** A watcher whose clock is a queue of callbacks this test fires by hand. */
function harness(reads) {
  const fired = [];
  let tick = null;
  let i = 0;
  const w = new NetWatcher({
    read: () => reads[Math.min(i, reads.length - 1)],
    onChange: (why) => fired.push(why),
    debounceMs: 2500,
    intervalMs: 3000,
    setTimer: (fn) => { tick = fn; return 'timer'; },
    clearTimer: () => { tick = null; }
  });
  return {
    w, fired,
    advance: (n = 1) => { i = Math.min(i + n, reads.length - 1); },
    tick: () => tick && tick(),
    running: () => tick !== null
  };
}

test('fingerprint ignores interface order, internal and loopback addresses', () => {
  const a = { A: [{ family: 'IPv4', internal: false, address: '1.1.1.1' }], B: [{ family: 'IPv6', internal: false, address: 'fe80::1' }] };
  const b = { B: [{ family: 'IPv6', internal: false, address: 'fe80::1' }], A: [{ family: 'IPv4', internal: false, address: '1.1.1.1' }] };
  assert.equal(fingerprint(a), fingerprint(b), 'order must not matter');
  const withLoopback = Object.assign({ lo: [{ family: 'IPv4', internal: true, address: '127.0.0.1' }] }, a);
  assert.equal(fingerprint(withLoopback), fingerprint(a), 'internal addresses must not matter');
  assert.notEqual(fingerprint(a), fingerprint(eth));
  assert.equal(fingerprint(null), fingerprint({}), 'a missing read is just "no addresses"');
});

test('a settled change fires once, after the debounce', () => {
  const h = harness([wifi, eth]);
  h.w.start();
  h.tick();                       // first poll only records the baseline
  assert.deepEqual(h.fired, []);
  h.advance();                    // network switched
  h.tick();                       // change seen — debounce starts, nothing fired yet
  assert.deepEqual(h.fired, []);
  h.tick();                       // still the same fingerprint → debounce elapses
  assert.deepEqual(h.fired, ['interfaces']);
  h.tick();                       // nothing new
  assert.deepEqual(h.fired, ['interfaces']);
});

test('a flapping adapter fires once, not once per change', () => {
  const h = harness([wifi, eth, wifi2, eth]);
  h.w.start();
  h.tick();
  h.advance(); h.tick();          // change 1
  h.advance(); h.tick();          // change 2 — restarts the debounce
  h.advance(); h.tick();          // change 3 — restarts again
  assert.deepEqual(h.fired, [], 'must not fire while it is still moving');
  h.tick();                       // settled
  assert.deepEqual(h.fired, ['interfaces']);
});

test('poke() delivers an external signal immediately and only when running', () => {
  const h = harness([wifi]);
  h.w.poke('resume');
  assert.deepEqual(h.fired, [], 'a stopped watcher must stay silent');
  h.w.start();
  h.w.poke('resume');
  assert.deepEqual(h.fired, ['resume']);
});

test('a change during an in-flight recovery is suppressed, not queued up', async () => {
  let release;
  const fired = [];
  let tick = null, i = 0;
  const reads = [wifi, eth, wifi2];
  const w = new NetWatcher({
    read: () => reads[Math.min(i, reads.length - 1)],
    onChange: (why) => { fired.push(why); return new Promise((r) => { release = r; }); },
    debounceMs: 0, intervalMs: 3000,
    setTimer: (fn) => { tick = fn; return 't'; }, clearTimer: () => { tick = null; }
  });
  w.start();
  tick();
  i = 1; tick(); tick();
  assert.deepEqual(fired, ['interfaces']);
  assert.equal(w.busy, true);
  i = 2; tick(); tick();
  assert.deepEqual(fired, ['interfaces'], 'no second call while the first is running');
  release();
  await Promise.resolve(); await Promise.resolve();
  assert.equal(w.busy, false);
});

test('stop() clears the timer and start() is idempotent', () => {
  const h = harness([wifi]);
  h.w.start();
  h.w.start();
  assert.equal(h.running(), true);
  h.w.stop();
  assert.equal(h.running(), false);
  h.tick();                        // no-op, nothing should throw
  assert.deepEqual(h.fired, []);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/netWatcher.test.js` → Expected: FAIL — `Cannot find module '../src/main/netWatcher'`.

- [ ] **Step 3: Implement**

`src/main/netWatcher.js`:

```js
'use strict';
/**
 * Watches for the machine's network changing underneath a live tunnel.
 *
 * Why this exists: a Wi-Fi ↔ ethernet switch, a new DHCP lease or a wake from
 * sleep does NOT kill xray-core — it only breaks its sockets. So the app's
 * 'stopped' path never fires, the TUN bypass routes still point at the old
 * gateway, and the UI keeps saying "connected" while nothing passes. Other
 * clients recover in seconds; this is how we do.
 *
 * The module is pure enough to test: the interface reader and the clock are
 * injected, so no test needs a real NIC or a real timer.
 */

/**
 * A stable signature of the machine's routable addresses. Interface order and
 * internal (loopback) addresses are ignored, so a re-enumeration that returns
 * the same network in a different order is NOT a change.
 */
function fingerprint(interfaces) {
  const parts = [];
  for (const name of Object.keys(interfaces || {})) {
    for (const ni of (interfaces[name] || [])) {
      if (!ni || ni.internal) continue;
      parts.push(`${name}|${ni.family}|${ni.address}`);
    }
  }
  return parts.sort().join(',');
}

class NetWatcher {
  /**
   * @param {object} opts
   *   read()            -> os.networkInterfaces()-shaped object
   *   onChange(reason)  -> 'interfaces' | 'resume' | 'online'; may return a promise
   *   debounceMs        -> how long the network must hold still before we act
   *   intervalMs        -> poll period
   *   setTimer/clearTimer -> injectable setInterval/clearInterval
   */
  constructor(opts = {}) {
    this.read = opts.read || (() => ({}));
    this.onChange = opts.onChange || (() => {});
    this.debounceMs = opts.debounceMs == null ? 2500 : opts.debounceMs;
    this.intervalMs = opts.intervalMs || 3000;
    this.setTimer = opts.setTimer || ((fn, ms) => setInterval(fn, ms));
    this.clearTimer = opts.clearTimer || ((h) => clearInterval(h));
    this.timer = null;
    this.last = null;         // fingerprint of the last settled network
    this.pending = null;      // fingerprint seen while the network is still moving
    this.settledFor = 0;      // ms the pending fingerprint has held
    this.busy = false;        // a recovery is in flight
  }

  start() {
    if (this.timer) return;
    this.last = fingerprint(this.read());
    this.pending = null;
    this.settledFor = 0;
    this.timer = this.setTimer(() => this.tick(), this.intervalMs);
  }

  stop() {
    if (!this.timer) return;
    this.clearTimer(this.timer);
    this.timer = null;
    this.pending = null;
    this.settledFor = 0;
  }

  /** One poll. Fires onChange only once the new fingerprint has held still. */
  tick() {
    const fp = fingerprint(this.read());
    if (fp === this.last) { this.pending = null; this.settledFor = 0; return; }
    if (fp !== this.pending) { this.pending = fp; this.settledFor = 0; return; }  // still moving
    this.settledFor += this.intervalMs;
    if (this.settledFor < this.debounceMs) return;
    this.last = fp;
    this.pending = null;
    this.settledFor = 0;
    this.fire('interfaces');
  }

  /** An out-of-band signal (power resume, browser 'online'). */
  poke(reason) {
    if (!this.timer) return;                 // not watching: nothing to recover
    this.last = fingerprint(this.read());    // adopt the current network as the baseline
    this.fire(reason || 'poke');
  }

  /** Run onChange, ignoring further triggers until it settles. */
  fire(reason) {
    if (this.busy) return;
    this.busy = true;
    let r;
    try { r = this.onChange(reason); } catch { this.busy = false; return; }
    if (r && typeof r.then === 'function') r.then(() => { this.busy = false; }, () => { this.busy = false; });
    else this.busy = false;
  }
}

module.exports = { NetWatcher, fingerprint };
```

- [ ] **Step 4: Run the test**

Run: `node --test tests/netWatcher.test.js` → Expected: `# pass 6`.

- [ ] **Step 5: Run the suite and commit**

Run: `node --test "tests/*.test.js"` → Expected: all pass, no warnings.

```bash
git add src/main/netWatcher.js tests/netWatcher.test.js
git commit -m "Add a debounced network-change watcher (pure, injectable clock)"
```

---

### Task 5: Reconnect when the network changes

**Files:**
- Modify: `src/main/main.js` (watcher lifecycle, recovery with backoff, `DEFAULT_SETTINGS`)
- Modify: `src/server/service.js` (same, mirrored; no `powerMonitor`)
- Modify: `src/renderer/i18n.js` (both languages), `src/renderer/index.html`, `src/renderer/app.js` (the setting's switch + the give-up banner)
- Modify: `src/main/settingsMeta.js` — **do NOT** add the new key: it is read live at recovery time, like `killSwitch`.

**Interfaces:**
- Consumes: `NetWatcher`, `fingerprint` (Task 4); the existing `reapplyConnection()` — it already tears the tunnel down, rebuilds it from current settings, holds the kill-switch block across the gap and restarts the process-route watcher.
- Produces: status event `{ state: 'reconnecting', reason, attempt }` and `{ state: 'reconnect-failed' }`; setting `autoReconnectOnNetworkChange: true`.

- [ ] **Step 1: Wire the watcher in `main.js`**

Add the import:

```js
const { NetWatcher } = require('./netWatcher');
```
Add to `DEFAULT_SETTINGS` (after `killSwitch: false,`):
```js
  // recover automatically when the machine's network changes (read live, so it
  // needs no reconnect to take effect)
  autoReconnectOnNetworkChange: true,
```
Add the module-level state next to `let procWatcher = null;`:
```js
let netWatcher = null;
let recoverTimer = null;
const RECOVER_BACKOFF_MS = [2000, 5000, 15000];
```

Add the recovery functions above `doDisconnect()`:

```js
/**
 * The machine's network changed under a live tunnel. xray does not die when that
 * happens — it just stops passing traffic, and under TUN the bypass routes still
 * point at the old gateway — so nothing else would notice. Rebuild the connection
 * from current settings; reapplyConnection() already holds the kill-switch block
 * across the gap, so this cannot leak.
 */
async function recoverFromNetworkChange(reason, attempt = 0) {
  if (!store.get('activeServerId', null) || !xray || !xray.running) return;
  if (!getSettings().autoReconnectOnNetworkChange) return;

  send('log', { line: `Network changed (${reason}) — rebuilding the connection`, level: 'warn' });
  send('status', { state: 'reconnecting', reason, attempt: attempt + 1 });

  const res = await reapplyConnection();
  if (res && res.ok) {
    send('log', { line: 'Connection restored after the network change', level: 'info' });
    return;
  }
  const delay = RECOVER_BACKOFF_MS[attempt];
  if (delay == null) {
    send('log', { line: 'Could not reconnect after the network change — giving up', level: 'error' });
    send('status', { state: 'reconnect-failed', reason });
    return;
  }
  send('log', { line: `Reconnect failed — retrying in ${delay / 1000}s`, level: 'warn' });
  clearTimeout(recoverTimer);
  recoverTimer = setTimeout(() => recoverFromNetworkChange(reason, attempt + 1), delay);
  if (recoverTimer.unref) recoverTimer.unref();
}

function startNetWatcher() {
  stopNetWatcher();
  netWatcher = new NetWatcher({
    read: () => os.networkInterfaces(),
    onChange: (why) => recoverFromNetworkChange(why)
  });
  netWatcher.start();
}

function stopNetWatcher() {
  clearTimeout(recoverTimer);
  recoverTimer = null;
  if (netWatcher) { netWatcher.stop(); netWatcher = null; }
}
```

In `doConnect()`, right after `startProcWatcher();`, add `startNetWatcher();`.
In `doDisconnect()`, right after `stopProcWatcher();`, add `stopNetWatcher();`.
In the `before-quit` handler, add `try { stopNetWatcher(); } catch {}` next to the other teardown lines.

Feed the OS signal in: inside `app.whenReady().then(() => { … })`, after `createTray();`, add

```js
  // waking from sleep is the other way the network changes under us
  try {
    const { powerMonitor } = require('electron');
    powerMonitor.on('resume', () => { if (netWatcher) netWatcher.poke('resume'); });
  } catch {}
```

Add an IPC channel so the renderer's `online` event reaches the watcher, in `registerIpc()`:

```js
  ipcMain.on('net:online', () => { if (netWatcher) netWatcher.poke('online'); });
```

- [ ] **Step 2: Mirror it in `service.js`**

Same, minus `powerMonitor` (there is no Electron). Add `const { NetWatcher } = require('../main/netWatcher');`, the same `autoReconnectOnNetworkChange: true` default, the same three module-scope variables inside `createService`, the same three functions (using this file's `send`, `getSettings`, `store`, `reapplyConnection`), the same `startNetWatcher()` / `stopNetWatcher()` calls in `doConnect` / `doDisconnect`, `try { stopNetWatcher(); } catch {}` in `shutdown()`, and the handler `'net:online': () => { if (netWatcher) netWatcher.poke('online'); }` in the `handlers` map.

- [ ] **Step 3: Renderer — the setting, the online signal, the banner**

`src/preload/preload.js`: `netOnline: () => ipcRenderer.send('net:online'),`
`src/server/web-api.js`: `netOnline: () => sendOnly('net:online'),`

`src/renderer/index.html` — in the Settings card that holds the kill switch, after the `#killStatus` div:

```html
          <div class="switch-row">
            <div><div class="switch-title" data-i18n="netauto.title">اتصال مجدد خودکار هنگام تغییر شبکه</div>
              <div class="switch-sub" data-i18n="netauto.sub">اگر اینترنت عوض شد (وای‌فای/کابل/بیدارشدن از خواب)، تونل خودکار بازسازی می‌شود</div></div>
            <label class="switch"><input type="checkbox" id="optNetAuto" /><span class="slider"></span></label>
          </div>
```

`src/renderer/i18n.js` — **fa**:
```js
    'netauto.title': 'اتصال مجدد خودکار هنگام تغییر شبکه',
    'netauto.sub': 'اگر اینترنت عوض شد (وای‌فای/کابل/بیدارشدن از خواب)، تونل خودکار بازسازی می‌شود',
    'state.reconnecting': 'شبکه عوض شد — اتصال مجدد…',
    'net.reconnected': 'اتصال بعد از تغییر شبکه برقرار شد',
    'net.failed': 'شبکه عوض شد و اتصال مجدد ناموفق بود',
```
**en**:
```js
    'netauto.title': 'Reconnect automatically when the network changes',
    'netauto.sub': 'If your internet changes (Wi-Fi/ethernet/wake from sleep) the tunnel is rebuilt automatically',
    'state.reconnecting': 'Network changed — reconnecting…',
    'net.reconnected': 'Reconnected after the network change',
    'net.failed': 'The network changed and reconnecting failed',
```

`src/renderer/app.js`:
- In `applySettingsToUI()`: `$('#optNetAuto').checked = state.settings.autoReconnectOnNetworkChange !== false;`
- Next to the other switch handlers: `$('#optNetAuto').onchange = () => saveSettings({ autoReconnectOnNetworkChange: $('#optNetAuto').checked });`
- Tell main when the browser/OS says we are back online, right after `init();` at the bottom of the file:
  ```js
  // the OS reconnected an adapter — nudge main to re-check the tunnel
  window.addEventListener('online', () => { try { window.api.netOnline(); } catch {} });
  ```
- In `window.api.onStatus`, add two branches before the final `else if (d.state === 'error')`:
  ```js
  } else if (d.state === 'reconnecting') {
    state.connecting = true;
    setConnUI('connecting', d.serverId || state.activeServerId);
    $('#connState').textContent = t('state.reconnecting');
  } else if (d.state === 'reconnect-failed') {
    state.connected = false;
    state.connecting = false;
    setConnUI('error');
    toast(t('net.failed'), 'err', 8000);
  ```
  and in the existing `connected` branch, after `setConnUI('connected', d.serverId);`, show the recovery toast only when we were recovering:
  ```js
    if (state.wasReconnecting) { toast(t('net.reconnected'), 'ok'); state.wasReconnecting = false; }
  ```
  setting `state.wasReconnecting = true;` in the `reconnecting` branch and adding `wasReconnecting: false,` to the `state` object.

- [ ] **Step 4: Verify by hand**

Unit coverage lives in Task 4. Here, prove the wiring:

```bash
mkdir -p /tmp/irnf-net && node src/server/server.js --port 7802 --data-dir /tmp/irnf-net &
sleep 1
curl -s -X POST http://127.0.0.1:7802/rpc -H 'Origin: http://127.0.0.1:7802' -H 'Content-Type: application/json' \
  -d '{"channel":"settings:get"}' | grep -o '"autoReconnectOnNetworkChange":[a-z]*'
```
Expected: `"autoReconnectOnNetworkChange":true`. Then open the UI, confirm the new switch appears under the kill switch in Settings and that toggling it writes only that key to `/tmp/irnf-net/store.json`. Stop the server.

Also confirm both files still parse: `node --check src/main/main.js && node --check src/server/service.js`, and that the two files mirror: `grep -c "netWatcher\|recoverFromNetworkChange\|autoReconnectOnNetworkChange" src/main/main.js src/server/service.js` — report both counts.

- [ ] **Step 5: Run the suite and commit**

Run: `node --test "tests/*.test.js"` → Expected: all pass (`settingsMeta` must stay green — the new key is deliberately NOT in `RECONNECT_KEYS`).

```bash
git add src/main/main.js src/server/service.js src/preload/preload.js src/server/web-api.js src/renderer/app.js src/renderer/index.html src/renderer/i18n.js
git commit -m "Rebuild the tunnel automatically when the machine's network changes"
```

---

### Task 6: Standard `finalmask` / `cipherSuites` / `fp=unsafe` in links

**Files:**
- Modify: `src/main/parser.js` (`buildStreamSettings`, `parseVless`/`parseVmess`/`parseTrojan`, `applyServerEdits`, `streamToQuery`, `buildShareLink`; delete `normalizeFinalMask`)
- Test: `tests/parser.test.js`

**Why:** upstream moved `fragment`/`noise` into `streamSettings.finalmask` (Xray ≥ 26.3.27) and the share-link standard carries `fm=` (URL-encoded compact JSON) and `cs=` (cipherSuites); `fp=unsafe` is upstream. Our parser reads non-standard `finalMask=`/`cipherSuites=` names, so links from v2rayN and PattN do not import. Worse, `normalizeFinalMask()` rewrites the standard plural form (`lengths`, `delays`) into a singular one, which the core the app downloads now **rejects**.

The `_fakesni` marker is removed: it was implemented with freedom `noises`, which only exist for UDP, so it never did anything on a TLS/TCP connection.

- [ ] **Step 1: Write the failing tests**

Add to `tests/parser.test.js`:

```js
/* --------------------------- finalmask / cs / fp --------------------------- */

const FM = '{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["3-5","6-8"],"delays":["10-20"],"maxSplit":"3-6"}}]}';

test('vless: fm= is stored verbatim — no key rewriting', () => {
  const s = parseLink(`vless://u@a.example.com:443?security=tls&fm=${encodeURIComponent(FM)}#FM`);
  const fm = s.outbound.streamSettings.finalmask;
  assert.deepEqual(fm, JSON.parse(FM), 'the core takes plural lengths/delays; rewriting them breaks it');
});

test('vless: cs= and fp=unsafe are read into tlsSettings', () => {
  const s = parseLink('vless://u@a.example.com:443?security=tls&fp=unsafe&cs=TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256');
  assert.equal(s.outbound.streamSettings.tlsSettings.fingerprint, 'unsafe');
  assert.equal(s.outbound.streamSettings.tlsSettings.cipherSuites, 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256');
});

test('the legacy long parameter names still import', () => {
  const s = parseLink(`vless://u@a.example.com:443?security=tls&finalMask=${encodeURIComponent(FM)}&cipherSuites=X`);
  assert.deepEqual(s.outbound.streamSettings.finalmask, JSON.parse(FM));
  assert.equal(s.outbound.streamSettings.tlsSettings.cipherSuites, 'X');
});

test('invalid fm JSON is ignored rather than poisoning the config', () => {
  const s = parseLink('vless://u@a.example.com:443?security=tls&fm=%7Bnot-json');
  assert.equal(s.outbound.streamSettings.finalmask, undefined);
});

test('share links export fm= and cs=, never the legacy names', () => {
  const s = parseLink(`vless://u@a.example.com:443?security=tls&sni=a.com&fm=${encodeURIComponent(FM)}&cs=SUITE&fp=unsafe#N`);
  const link = buildShareLink(s);
  assert.match(link, /[?&]fm=/);
  assert.match(link, /[?&]cs=SUITE/);
  assert.match(link, /[?&]fp=unsafe/);
  assert.equal(/finalMask=|cipherSuites=/.test(link), false);
  assert.deepEqual(parseLink(link).outbound.streamSettings.finalmask, JSON.parse(FM));
});

test('vmess carries fm and cs through its base64 payload', () => {
  const link = 'vmess://' + Buffer.from(JSON.stringify({
    v: '2', ps: 'VM', add: 'vm.example.com', port: '443', id: 'uuid', net: 'ws',
    tls: 'tls', path: '/p', fm: FM, cs: 'SUITE', fp: 'unsafe'
  }), 'utf8').toString('base64');
  const s = parseLink(link);
  assert.deepEqual(s.outbound.streamSettings.finalmask, JSON.parse(FM));
  assert.equal(s.outbound.streamSettings.tlsSettings.cipherSuites, 'SUITE');
  const back = parseLink(buildShareLink(s));
  assert.deepEqual(back.outbound.streamSettings.finalmask, JSON.parse(FM));
});

test('applyServerEdits sets and clears finalMask and cipherSuites', () => {
  const s = parseLink('vless://u@a.example.com:443?security=tls&sni=a.com');
  const on = applyServerEdits(s, { security: 'tls', sni: 'a.com', finalMask: FM, cipherSuites: 'SUITE', fp: 'unsafe' });
  assert.deepEqual(on.outbound.streamSettings.finalmask, JSON.parse(FM));
  assert.equal(on.outbound.streamSettings.tlsSettings.cipherSuites, 'SUITE');
  const off = applyServerEdits(on, { security: 'tls', sni: 'a.com', finalMask: '', cipherSuites: '', fp: 'chrome' });
  assert.equal(off.outbound.streamSettings.finalmask, undefined);
  assert.equal(off.outbound.streamSettings.tlsSettings.cipherSuites, undefined);
});

test('the dead fakeSni marker is gone', () => {
  const s = parseLink('vless://u@a.example.com:443?security=tls&fakeSni=www.google.com');
  assert.equal(s.outbound._fakesni, undefined, 'freedom noises are UDP-only — this never worked on TLS');
  assert.equal(/fakeSni/.test(buildShareLink(s)), false);
});
```

Delete the existing test `fakeSni prepends a real ClientHello record carrying the decoy name` from `tests/configBuilder.test.js` and the `_fakesni` case from `applyServerEdits: anti-DPI markers set and clear` in `tests/parser.test.js` (keep the `_fragment` / `_noise` halves).

- [ ] **Step 2: Run to verify they fail**

Run: `node --test tests/parser.test.js` → Expected: FAIL — finalmask comes back with singular `length`/`delay`, and `cs`/`fm` are unread.

- [ ] **Step 3: Change the parser**

In `buildStreamSettings`, replace the `cipherSuites` line and the whole `finalMask` block:

```js
    // patterniha-style custom TLS: `unsafe` fingerprint lets you pin cipherSuites.
    const cs = q.cs || q.cipherSuites;
    if (cs && String(cs).trim()) stream.tlsSettings.cipherSuites = String(cs).trim();
```
and
```js
  // finalMask (transport-level masking: fragment, noise, header-custom, …).
  // Stored VERBATIM: the core takes the plural `lengths`/`delays` arrays, and an
  // earlier version of this code rewrote them into the singular form, which the
  // current core rejects. `fm` is the standard share-link name; `finalMask` is
  // the long form we used to emit.
  const fmRaw = q.fm || q.finalMask;
  if (fmRaw) {
    const fm = parseFinalMask(fmRaw);
    if (fm) stream.finalmask = fm;
  }
```

Replace the whole `normalizeFinalMask` function with:

```js
/** Parse a finalMask value (JSON string or object). Returns null when unusable. */
function parseFinalMask(raw) {
  if (raw && typeof raw === 'object') return raw;
  try {
    const o = JSON.parse(String(raw));
    return (o && typeof o === 'object') ? o : null;
  } catch { return null; }
}
```

In `parseVless` / `parseTrojan`, delete the `if (q.fakeSni) outbound._fakesni = q.fakeSni;` line. In `parseVmess`, delete `if (v.fakesni) outbound._fakesni = String(v.fakesni);` and add the new keys to the `q` object it builds:

```js
    cipherSuites: v.cs || v.cipherSuites || '',
    finalMask: v.fm || v.finalMask || v.finalmask || ''
```

In `applyServerEdits`, delete the whole `if (f.fakeSni != null) { … }` block.

In `rebuildStream`'s `q`, change the two passthrough lines to:

```js
    cipherSuites: f.cipherSuites != null ? f.cipherSuites : ((cur.tlsSettings && cur.tlsSettings.cipherSuites) || ''),
    finalMask: f.finalMask != null ? f.finalMask : (cur.finalmask ? JSON.stringify(cur.finalmask) : '')
```
(unchanged in shape — they already do the right thing now that `buildStreamSettings` reads `finalMask`.)

In `streamToQuery`, emit the standard short names:

```js
  if (tls) { q.sni = tls.serverName || ''; q.fp = tls.fingerprint || ''; if (tls.allowInsecure) q.allowInsecure = '1'; if (tls.alpn) q.alpn = Array.isArray(tls.alpn) ? tls.alpn.join(',') : tls.alpn; if (tls.cipherSuites) q.cs = tls.cipherSuites; }
```
and
```js
  if (st.finalmask) q.fm = JSON.stringify(st.finalmask);
```

In `buildShareLink`, delete `if (ob._fakesni) extras.fakeSni = ob._fakesni;`, and in the vmess branch replace the `cipherSuites` / `finalMask` / `fakesni` lines with:

```js
    if (p.cs) v.cs = p.cs;
    if (p.fm) v.fm = p.fm;
```
(deleting the `extras.fakeSni` line there too).

- [ ] **Step 4: Drop the dead decoy from the config builder**

In `src/main/configBuilder.js`: delete `fakeClientHelloB64()` entirely, remove `_fakesni` from `applyFragments`'s condition, key and `delete` calls, drop the `fakeSni` parameter from `makeFragmentOutbound` and the `if (fakeSni) noises.unshift(…)` line. The function signature becomes `makeFragmentOutbound(tag, fragStr, noiseStr)` and the key `frag + '|' + noise`.

- [ ] **Step 5: Run both test files, then the suite**

Run: `node --test tests/parser.test.js tests/configBuilder.test.js` → Expected: pass.
Run: `node --test "tests/*.test.js"` → Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/main/parser.js src/main/configBuilder.js tests/parser.test.js tests/configBuilder.test.js
git commit -m "Links: standard fm= / cs= / fp=unsafe, finalmask stored verbatim, drop the dead fake-SNI decoy"
```

---

### Task 7: The edit form speaks finalmask

**Files:**
- Modify: `src/renderer/index.html` (the edit modal's DPI section)
- Modify: `src/renderer/app.js` (`readServerFields`, `openEdit`, `editSave`, delete the fakeSni helpers)
- Modify: `src/renderer/i18n.js` (both languages)

- [ ] **Step 1: Remove the dead decoy field from the modal**

In `src/renderer/index.html`, delete the whole `<div id="edFakeSniWrap"> … </div>` block (label, input `#edFakeSni`, hint `#edFakeSniHint`).

Change the finalMask label so it names the standard parameter, and add the fingerprint note. Replace the `#edPattWrap` heading and hint:

```html
        <div id="edPattWrap">
          <div class="edit-section"><span data-i18n="edit.pattTitle">🧩 finalmask / cipherSuites</span></div>
          <label class="field-label" data-i18n="edit.cipherSuites">cipherSuites (با fingerprint = unsafe)</label>
          <input type="text" id="edCipherSuites" class="input" dir="ltr" placeholder="TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256" />
          <label class="field-label" data-i18n="edit.finalMask" style="margin-top:8px;display:block">finalmask (JSON — همان چیزی که در لینک با fm می‌آید)</label>
          <textarea id="edFinalMask" class="input" dir="ltr" rows="3" spellcheck="false" placeholder='{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["3-5","6-8"],"delays":["10-20"],"maxSplit":"3-6"}}]}'></textarea>
          <p class="hint" data-i18n="edit.pattHint">دقیقاً همان JSON را بچسبان؛ برنامه دست‌کاری‌اش نمی‌کند. برای روش پترنیها: Address یک IP تمیز کلودفلر، fingerprint = unsafe، بعد cipherSuites و finalmask.</p>
        </div>
```

- [ ] **Step 2: i18n**

`src/renderer/i18n.js` — delete the keys `spoof.fakeSni` and `spoof.fakeSniHint` from **both** blocks, and update these two in **fa**:

```js
    'edit.pattTitle': '🧩 finalmask / cipherSuites',
    'edit.finalMask': 'finalmask (JSON — همان چیزی که در لینک با fm می‌آید)',
    'edit.pattHint': 'دقیقاً همان JSON را بچسبان؛ برنامه دست‌کاری‌اش نمی‌کند. برای روش پترنیها: Address یک IP تمیز کلودفلر، fingerprint = unsafe، بعد cipherSuites و finalmask.',
```
and in **en**:
```js
    'edit.pattTitle': '🧩 finalmask / cipherSuites',
    'edit.finalMask': 'finalmask (JSON — the value a link carries as fm)',
    'edit.pattHint': 'Paste the JSON exactly; the app does not rewrite it. For the patterniha method: set Address to a clean Cloudflare IP, fingerprint = unsafe, then cipherSuites and finalmask.',
```

- [ ] **Step 3: Renderer**

In `src/renderer/app.js`:
- `readServerFields`: delete the `fakeSni: ob._fakesni || '',` line.
- `openEdit`: delete `if ($('#edFakeSni')) $('#edFakeSni').value = f.fakeSni || '';`.
- `updateSpoofLabels`: delete `show('#edFakeSniWrap', on);` and the three lines that set `#edFakeSniLabel`, `#edFakeSniHint` text.
- `editSave`: delete `fakeSni: $('#edFakeSni') ? $('#edFakeSni').value.trim() : '',` from the `fields` object.
- Add a guard so a malformed finalmask is refused before it reaches main, right before the `updateServer` call in `editSave`:
  ```js
  // finalmask goes to the core untouched, so catch bad JSON here rather than
  // letting xray refuse the whole config at connect time
  const fmText = $('#edFinalMask') ? $('#edFinalMask').value.trim() : '';
  if (fmText) {
    try { JSON.parse(fmText); }
    catch { return toast(t('edit.finalMaskBad'), 'err'); }
  }
  ```
  with the strings `'edit.finalMaskBad': 'finalmask یک JSON معتبر نیست'` (fa) and `'edit.finalMaskBad': 'finalmask is not valid JSON'` (en).

- [ ] **Step 4: Verify in the browser**

Start the headless server on port 7803 with a scratch data dir (assert `location.port` before each action). Add a vless server, open ✎:
- the "Fake SNI decoy" field is gone;
- paste the plural-form JSON from the placeholder into finalmask, set fingerprint to `unsafe`, put a value in cipherSuites, Save;
- press ⧉ Copy on the card and confirm the link contains `fm=`, `cs=` and `fp=unsafe` and no `finalMask=`/`cipherSuites=`;
- paste that link back through "+ افزودن" and confirm a second server appears with the same finalmask (reopen ✎ to check the textarea);
- type `{not json` into finalmask and Save → an error toast, nothing saved.
Stop the server. Record what you saw.

- [ ] **Step 5: Run the suite and commit**

Run: `node --test "tests/*.test.js"` → Expected: all pass.

```bash
git add src/renderer/app.js src/renderer/index.html src/renderer/i18n.js
git commit -m "Edit form: finalmask JSON verbatim with a validity check, drop the dead decoy field"
```

---

### Task 8: Light theme

**Files:**
- Modify: `src/renderer/styles.css` (a `[data-theme="light"]` variable block)
- Modify: `src/renderer/index.html` (a theme select in Settings)
- Modify: `src/renderer/i18n.js` (both languages)
- Modify: `src/renderer/app.js` (apply on load and on change)
- Modify: `src/main/main.js` (follow the OS theme), `src/preload/preload.js`, `src/server/web-api.js`

**Why:** `theme: 'dark'` exists in `DEFAULT_SETTINGS` and is never read.

- [ ] **Step 1: The light palette**

At the top of `src/renderer/styles.css`, immediately after the `:root { … }` block:

```css
/* Light theme: only the surface/text ramp changes — the accent, state and
   protocol colours are shared so a screenshot of either theme is recognisable. */
[data-theme="light"] {
  --bg: #f6f8fa;
  --bg-2: #ffffff;
  --panel: #ffffff;
  --panel-2: #eef1f5;
  --border: #d6dde6;
  --text: #1b2430;
  --muted: #5b6875;
  --shadow: 0 8px 30px rgba(15,23,32,.10);
}
[data-theme="light"] .logbox { background: #ffffff; color: #1b2430; }
[data-theme="light"] .log-log { color: #5b6875; }
[data-theme="light"] ::-webkit-scrollbar-thumb { background: #cdd6e0; border-color: var(--bg); }
[data-theme="light"] ::-webkit-scrollbar-thumb:hover { background: #b6c2d0; }
[data-theme="light"] .titlebar.conn-off { background: linear-gradient(180deg, rgba(79,140,255,.10), transparent); }
[data-theme="light"] .titlebar.conn-on { background: linear-gradient(180deg, rgba(63,185,80,.12), transparent); }
```

- [ ] **Step 2: The control**

`src/renderer/index.html` — in the Settings card next to the language select, replace the empty grid cell that follows `#defaultEngine`'s `<div>` (or add a new `grid2` row if none is free):

```html
            <div>
              <label class="field-label" data-i18n="set.theme">تم</label>
              <select id="themeSelect" class="select">
                <option value="dark" data-i18n="theme.dark">تیره</option>
                <option value="light" data-i18n="theme.light">روشن</option>
                <option value="system" data-i18n="theme.system">مثل سیستم</option>
              </select>
            </div>
```

`src/renderer/i18n.js` — **fa**: `'set.theme': 'تم', 'theme.dark': 'تیره', 'theme.light': 'روشن', 'theme.system': 'مثل سیستم',`
**en**: `'set.theme': 'Theme', 'theme.dark': 'Dark', 'theme.light': 'Light', 'theme.system': 'Match system',`

- [ ] **Step 3: Apply it**

`src/renderer/app.js` — add near the other helpers:

```js
/* ----------------------------- theme ----------------------------- */
/** 'dark' | 'light' | 'system' -> the attribute the CSS keys off. */
function applyTheme(pref, systemDark) {
  const dark = pref === 'system' ? systemDark !== false : pref !== 'light';
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
}
```
In `init()`, after `window.i18n.applyI18n(...)`:
```js
  state.systemDark = data.systemDark !== false;
  applyTheme(state.settings.theme || 'dark', state.systemDark);
```
In `applySettingsToUI()`: `$('#themeSelect').value = state.settings.theme || 'dark';`
Next to the language handler:
```js
$('#themeSelect').onchange = () => {
  const theme = $('#themeSelect').value;
  applyTheme(theme, state.systemDark);
  saveSettings({ theme });
};
```
And react to the OS switching while the app is open:
```js
window.api.onSystemTheme((d) => {
  state.systemDark = !!(d && d.dark);
  if ((state.settings.theme || 'dark') === 'system') applyTheme('system', state.systemDark);
});
```

- [ ] **Step 4: Feed the OS preference in**

`src/main/main.js` — add `nativeTheme` to the `require('electron')` destructure. In `app:init`'s returned object add `systemDark: nativeTheme.shouldUseDarkColors,`. After `createWindow()`:
```js
  nativeTheme.on('updated', () => send('system-theme', { dark: nativeTheme.shouldUseDarkColors }));
```
`src/server/service.js` — in `'app:init'` add `systemDark: true,` with a comment that a headless server has no desktop theme, so `system` behaves as dark unless the user picks otherwise.

`src/preload/preload.js`: `onSystemTheme: (cb) => ipcRenderer.on('system-theme', (e, d) => cb(d)),`
`src/server/web-api.js`: `onSystemTheme: (cb) => on('system-theme', cb),`

- [ ] **Step 5: Verify in the browser**

Headless server on port 7804 (assert the port first). Settings → Theme → Light: every page (Connect, Servers, Subs, Chain, Pool, Routing, Settings, Logs) stays readable — check specifically the log box, the picker menu, the modals and the toast. Switch back to Dark. Confirm `store.json` holds only `"theme"` from that change. Take one screenshot per theme of the Connect page and one of the Logs page. Stop the server.

- [ ] **Step 6: Run the suite and commit**

Run: `node --test "tests/*.test.js"` → Expected: all pass.

```bash
git add src/renderer/styles.css src/renderer/index.html src/renderer/i18n.js src/renderer/app.js src/main/main.js src/server/service.js src/preload/preload.js src/server/web-api.js
git commit -m "Add a light theme (dark / light / follow the system)"
```

---

## Self-review

**Spec coverage:** phase 5 → T1 · phase 6 → T2, T3 · phase 3b → T4, T5 · phase 4 → T6, T7 · phase 7 → T8. Phases 2, 3 (Fable) and 8 (Android) are deliberately absent.

**Placeholder scan:** none — every step carries the code or the exact edit. The one `… unchanged …` in T1 Step 3 refers to two literal blocks in the file being edited and is bounded by the surrounding code shown.

**Type consistency:** `sumOutbounds(vars)` (T1) is exported and consumed only inside `stats.js`; `parseWireguardConf`/`isWireguardConf` (T2) are what T3's IPC handlers call; `NetWatcher`'s `{ read, onChange, debounceMs, intervalMs, setTimer, clearTimer }` (T4) is exactly what T5 constructs (T5 passes only `read` and `onChange`, relying on the documented defaults); `parseFinalMask` (T6) replaces `normalizeFinalMask` and no caller of the old name survives (T6 Step 3 removes the only two); `applyTheme(pref, systemDark)` (T8) is called from three places in the same file.

**Ordering:** T2 must land before T3 (the IPC handlers call its parser). T4 before T5. T6 before T7. T1 and T8 are independent of everything.
