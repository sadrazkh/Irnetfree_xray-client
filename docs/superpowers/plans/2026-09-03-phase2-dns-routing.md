# Phase 2 — DNS and routing that actually works — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make "bypass Iran / China" and every other geo rule work reliably, and stop plain-UDP DNS from ever leaving the machine, by moving name resolution into Xray's own resolver (DoH through the tunnel, an in-country resolver for domestic domains) and hijacking every DNS packet that reaches the core.

**Architecture:** One new pure module, `src/main/dnsBuilder.js`, decides the `dns` section and the DNS routing rules for a settings object; `configBuilder.js` splices its output into every plan shape. A second pure module, `src/main/settingsMigrate.js`, converts the old `dns` setting into the new `dnsRemote` / `dnsDirect` pair. `main.js` and `service.js` wire both and hand the TUN adapter the tunnel's own peer address as its DNS server so queries are hijacked. The renderer gets two DNS inputs and two switches.

**Tech Stack:** Node 18+ core only, Electron 31, `node --test`. A real Xray core (downloaded into `bin/`, git-ignored) validates the generated configs with `xray run -test`.

## Why (from the design spec, verified)

Xray's internal DNS currently uses plain UDP to `1.1.1.1` *through the proxy*. When the server drops UDP — common — resolution fails, `IPIfNonMatch` never yields an IP, `geoip:ir` never matches and everything goes through the proxy: "bypass Iran does nothing". In TUN mode the whole system's DNS takes that same path. The fix is what v2rayN does: DoH for remote lookups, an in-country UDP resolver pinned to domestic domains with `expectedIPs`, and a `dns` outbound that answers any port-53 packet.

## Global Constraints

- Runtime code uses **only Node core modules**; `package.json` `dependencies` stays empty.
- `node --test "tests/*.test.js"` must stay green (203 at branch base) **and its output must be pristine** — no warnings, no experimental Node APIs, no real timers or network in tests.
- Commits are in the repository owner's name only — **no `Co-Authored-By` trailer**.
- Every new `RECONNECT_KEYS` entry needs `set.<key>` in **both** `fa` and `en` blocks of `src/renderer/i18n.js` (`tests/settingsMeta.test.js` enforces it). i18n key sets must stay at exact parity.
- `src/server/service.js` mirrors `src/main/main.js`; a change to one belongs in the other.
- Android (`android/`) is **not** touched in this plan.
- **The order of `routing.rules` is load-bearing** — xray takes the first match. The DNS rules this plan adds go **first**, before the private-IP bypass, or a query to the tunnel peer would be sent "direct" instead of hijacked.
- Geo tokens (`geosite:` / `geoip:`) may only appear in a config when the geo files are present (`geoAssets`), or xray refuses to start. That applies to the `dns` section's `domains` / `expectedIPs` too.
- Renderer changes are verified through the headless server (`node src/server/server.js --port <port> --data-dir <tmp>`). **Other agents share one browser** — assert `location.port` is yours before every action; never click destructive controls on an unverified page.
- Xray field names: the resolver's expected-answer filter is `expectedIPs` (the current name; older docs said `expectIPs`).

---

## File map

| File | Responsibility | Tasks |
|---|---|---|
| `src/main/dnsBuilder.js` (new) | `dns` section, DNS routing rules, hijack outbound, TUN adapter DNS (pure) | 1 |
| `src/main/configBuilder.js` | splice the DNS plan into single/chain/advanced/pool; freedom strategy | 2 |
| `tests/fixtures.js`, `tests/configBuilder.test.js` | new settings keys; hijack-order tests | 2 |
| `src/main/settingsMigrate.js` (new) | `dns` → `dnsRemote` / `dnsDirect` (pure) | 3 |
| `src/main/settingsMeta.js`, `tests/settingsMeta.test.js` | new reconnect keys | 3 |
| `src/main/main.js`, `src/server/service.js` | defaults, migration at startup, TUN adapter DNS | 3 |
| `src/renderer/index.html`, `app.js`, `i18n.js` | two DNS inputs, two switches | 4 |
| `src/main/singboxBuilder.js`, `tests/singboxBuilder.test.js` (new) | sing-box DNS from `dnsRemote` | 5 |
| `scripts/validate-configs.js` (new, dev-only) | generate every plan shape and `xray run -test` it | 6 |

---

### Task 1: `dnsBuilder.js` — the resolver plan

**Files:**
- Create: `src/main/dnsBuilder.js`
- Test: `tests/dnsBuilder.test.js`

**Interfaces:**
- Produces:
  ```js
  buildDnsPlan(settings, { geoAssets, exitTag, dropUdpDirect = false })
    → { dns, hijackOutbound, rules, directResolverIps }
  adapterDnsServers(settings, tunnelPeer) → string[]
  DNS_DEFAULT_REMOTE, DNS_DEFAULT_DIRECT_IR, DNS_DEFAULT_DIRECT_CN, isDohUrl(s)
  ```
  - `dns` — the config's `dns` object (always present).
  - `hijackOutbound` — `{ tag:'dns-out', protocol:'dns' }` when managed, else `null`.
  - `rules` — routing rules to place **first** (`[]` when unmanaged).
  - `settings` read: `dnsManaged`, `dnsRemote`, `dnsDirect`, `ipv6`, `routingMode`, `advancedRouting`, `routeRules`; a legacy `dns` array is honoured as `dnsRemote` when `dnsRemote` is absent.
  - `exitTag` — the outbound the caller's catch-all points at (`'proxy'`, the advanced default tag, the pool primary tag, or `'direct'`).
  - `dropUdpDirect` — phase 3's strict guard hook: drop direct resolvers that are plain UDP (they would be blocked by `strict_route`). Default off.

- [ ] **Step 1: Write the failing tests**

`tests/dnsBuilder.test.js`:

```js
'use strict';
/**
 * Name resolution is where "bypass Iran does nothing" came from: the resolver
 * used plain UDP through the proxy, the server dropped it, and geoip:ir never
 * matched. These tests pin the resolver plan: DoH for the world, an in-country
 * UDP resolver pinned to domestic domains, and a hijack of every port-53 packet.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  buildDnsPlan, adapterDnsServers, isDohUrl,
  DNS_DEFAULT_REMOTE, DNS_DEFAULT_DIRECT_IR, DNS_DEFAULT_DIRECT_CN
} = require('../src/main/dnsBuilder');

const base = (over) => Object.assign({
  dnsManaged: true,
  dnsRemote: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'],
  dnsDirect: ['178.22.122.100', '185.51.200.2'],
  ipv6: false,
  routingMode: 'global',
  advancedRouting: false,
  routeRules: []
}, over || {});
const opts = (over) => Object.assign({ geoAssets: true, exitTag: 'proxy' }, over || {});

/* ----------------------------- managed: global ----------------------------- */

test('global: remote DoH only, hijack on, queries routed to the exit', () => {
  const p = buildDnsPlan(base(), opts());
  assert.deepEqual(p.dns, {
    tag: 'dns-internal',
    queryStrategy: 'UseIPv4',
    servers: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query']
  });
  assert.deepEqual(p.hijackOutbound, { tag: 'dns-out', protocol: 'dns' });
  assert.deepEqual(p.rules, [
    { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'proxy' },
    { type: 'field', port: '53', network: 'tcp,udp', outboundTag: 'dns-out' }
  ]);
  assert.deepEqual(p.directResolverIps, []);
});

test('ipv6 on switches the query strategy', () => {
  assert.equal(buildDnsPlan(base({ ipv6: true }), opts()).dns.queryStrategy, 'UseIP');
});

test('the exit tag is whatever the caller routes its catch-all to', () => {
  const adv = buildDnsPlan(base(), opts({ exitTag: 'out-sv-a' }));
  assert.equal(adv.rules[0].outboundTag, 'out-sv-a');
  const direct = buildDnsPlan(base({ routingMode: 'direct' }), opts({ exitTag: 'direct' }));
  assert.equal(direct.rules[0].outboundTag, 'direct');
});

/* ----------------------------- managed: bypass ----------------------------- */

test('bypass-ir: the direct resolver is pinned to Iranian domains and answers', () => {
  const p = buildDnsPlan(base({ routingMode: 'bypass-ir' }), opts());
  assert.deepEqual(p.dns.servers, [
    { address: '178.22.122.100', domains: ['geosite:category-ir', 'regexp:.*\\.ir$'], expectedIPs: ['geoip:ir'], skipFallback: true },
    { address: '185.51.200.2', domains: ['geosite:category-ir', 'regexp:.*\\.ir$'], expectedIPs: ['geoip:ir'], skipFallback: true },
    'https://1.1.1.1/dns-query',
    'https://8.8.8.8/dns-query'
  ]);
  // the resolver's OWN queries to the in-country server must go direct, and
  // must be decided before the port-53 hijack or they would loop into dns-out
  assert.deepEqual(p.rules, [
    { type: 'field', inboundTag: ['dns-internal'], ip: ['178.22.122.100', '185.51.200.2'], outboundTag: 'direct' },
    { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'proxy' },
    { type: 'field', port: '53', network: 'tcp,udp', outboundTag: 'dns-out' }
  ]);
  assert.deepEqual(p.directResolverIps, ['178.22.122.100', '185.51.200.2']);
});

test('bypass-ir without geo files: no geosite/geoip tokens anywhere', () => {
  const p = buildDnsPlan(base({ routingMode: 'bypass-ir' }), opts({ geoAssets: false }));
  const srv = p.dns.servers[0];
  assert.deepEqual(srv.domains, ['regexp:.*\\.ir$']);
  assert.equal('expectedIPs' in srv, false, 'geoip:ir needs geoip.dat');
  assert.equal(JSON.stringify(p).includes('geosite:'), false);
  assert.equal(JSON.stringify(p).includes('geoip:'), false);
});

test('bypass-cn uses the Chinese resolver and lists', () => {
  const p = buildDnsPlan(base({ routingMode: 'bypass-cn' }), opts());
  assert.deepEqual(p.dns.servers[0], { address: '223.5.5.5', domains: ['geosite:cn'], expectedIPs: ['geoip:cn'], skipFallback: true });
  assert.deepEqual(p.directResolverIps, ['223.5.5.5']);
});

test('an empty dnsDirect falls back to the built-in in-country resolver', () => {
  const p = buildDnsPlan(base({ routingMode: 'bypass-ir', dnsDirect: [] }), opts());
  assert.equal(p.dns.servers[0].address, DNS_DEFAULT_DIRECT_IR[0]);
});

/* ----------------------------- managed: advanced ----------------------------- */

test('advanced: a geosite:category-ir → direct rule brings the Iranian resolver along', () => {
  const p = buildDnsPlan(base({
    advancedRouting: true,
    routeRules: [{ type: 'domain', value: 'geosite:category-ir', target: 'direct' }]
  }), opts({ exitTag: 'out-sv-a' }));
  assert.equal(p.dns.servers[0].address, '178.22.122.100');
  assert.deepEqual(p.dns.servers[0].domains, ['geosite:category-ir', 'regexp:.*\\.ir$']);
});

test('advanced: geosite:cn → direct brings the Chinese resolver; other geosites bring nothing', () => {
  const cn = buildDnsPlan(base({ advancedRouting: true, routeRules: [{ type: 'domain', value: 'geosite:cn', target: 'direct' }] }), opts({ exitTag: 'x' }));
  assert.equal(cn.dns.servers[0].address, '223.5.5.5');
  const other = buildDnsPlan(base({ advancedRouting: true, routeRules: [{ type: 'domain', value: 'geosite:google', target: 'direct' }] }), opts({ exitTag: 'x' }));
  assert.equal(typeof other.dns.servers[0], 'string', 'no known expectedIPs for that list');
  const notDirect = buildDnsPlan(base({ advancedRouting: true, routeRules: [{ type: 'domain', value: 'geosite:category-ir', target: 'out-sv-a' }] }), opts({ exitTag: 'x' }));
  assert.equal(typeof notDirect.dns.servers[0], 'string', 'only direct targets need an in-country answer');
});

/* ----------------------------- resolver shapes ----------------------------- */

test('a DoH direct resolver is not routable by IP: no direct rule for it, no hijack loop', () => {
  const p = buildDnsPlan(base({ routingMode: 'bypass-ir', dnsDirect: ['https://free.shecan.ir/dns-query'] }), opts());
  assert.equal(p.dns.servers[0].address, 'https://free.shecan.ir/dns-query');
  assert.deepEqual(p.directResolverIps, []);
  assert.equal(p.rules[0].ip, undefined, 'first rule is the exit rule, not an ip rule');
  assert.equal(p.rules.length, 2);
});

test('a DoH URL with an IP host is routable by that IP', () => {
  const p = buildDnsPlan(base({ routingMode: 'bypass-ir', dnsDirect: ['https://178.22.122.100/dns-query'] }), opts());
  assert.deepEqual(p.directResolverIps, ['178.22.122.100']);
});

test('dropUdpDirect (strict guard): UDP direct resolvers are dropped, DoH ones kept', () => {
  const p = buildDnsPlan(base({ routingMode: 'bypass-ir', dnsDirect: ['178.22.122.100', 'https://free.shecan.ir/dns-query'] }), opts({ dropUdpDirect: true }));
  assert.equal(p.dns.servers.filter(s => typeof s === 'object').length, 1);
  assert.equal(p.dns.servers[0].address, 'https://free.shecan.ir/dns-query');
});

test('blank and duplicate entries are ignored; at least one remote server always remains', () => {
  const p = buildDnsPlan(base({ dnsRemote: [' ', '', 'https://1.1.1.1/dns-query', 'https://1.1.1.1/dns-query'] }), opts());
  assert.deepEqual(p.dns.servers, ['https://1.1.1.1/dns-query']);
  const none = buildDnsPlan(base({ dnsRemote: [] }), opts());
  assert.deepEqual(none.dns.servers, DNS_DEFAULT_REMOTE);
});

/* ----------------------------- unmanaged (legacy) ----------------------------- */

test('dnsManaged off: the user’s list verbatim, no hijack, no rules', () => {
  const p = buildDnsPlan(base({ dnsManaged: false, dnsRemote: ['9.9.9.9', 'https://8.8.8.8/dns-query'], routingMode: 'bypass-ir' }), opts());
  assert.deepEqual(p.dns, { queryStrategy: 'UseIPv4', servers: ['9.9.9.9', 'https://8.8.8.8/dns-query'] });
  assert.equal(p.hijackOutbound, null);
  assert.deepEqual(p.rules, []);
  assert.deepEqual(p.directResolverIps, []);
});

test('a legacy `dns` array still works as the remote list', () => {
  const p = buildDnsPlan({ dnsManaged: false, dns: ['9.9.9.9'] }, opts());
  assert.deepEqual(p.dns.servers, ['9.9.9.9']);
});

/* ----------------------------- TUN adapter DNS ----------------------------- */

test('adapterDnsServers: managed → the tunnel peer (so queries are hijacked), else the remote IPs', () => {
  assert.deepEqual(adapterDnsServers(base(), '10.255.0.1'), ['10.255.0.1']);
  assert.deepEqual(adapterDnsServers(base({ dnsManaged: false, dnsRemote: ['9.9.9.9', 'https://1.1.1.1/dns-query', '8.8.8.8'] }), '10.255.0.1'), ['9.9.9.9', '8.8.8.8']);
  assert.deepEqual(adapterDnsServers(base({ dnsManaged: false, dnsRemote: ['https://1.1.1.1/dns-query'] }), '10.255.0.1'), ['1.1.1.1', '8.8.8.8'], 'URLs cannot be adapter DNS — fall back');
});

test('isDohUrl', () => {
  assert.equal(isDohUrl('https://1.1.1.1/dns-query'), true);
  assert.equal(isDohUrl('https+local://dns.google/dns-query'), true);
  assert.equal(isDohUrl('1.1.1.1'), false);
  assert.equal(isDohUrl('tcp://1.1.1.1'), false);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/dnsBuilder.test.js` → Expected: FAIL — `Cannot find module '../src/main/dnsBuilder'`.

- [ ] **Step 3: Implement `src/main/dnsBuilder.js`**

```js
'use strict';
/**
 * The resolver plan: what Xray's built-in DNS looks like for a settings object,
 * plus the routing rules that make it safe.
 *
 * Why this exists. The old config listed plain UDP resolvers (1.1.1.1) and let
 * them ride through the proxy. When the server dropped UDP — common — every
 * lookup failed, `IPIfNonMatch` never produced an IP, `geoip:ir` never matched,
 * and "bypass Iran" silently became "everything through the proxy". In TUN mode
 * the whole system's DNS took the same doomed path.
 *
 * The plan, mirroring what v2rayN does:
 *   - remote lookups over DoH (TCP/443), routed to the tunnel exit;
 *   - in bypass modes, an in-country UDP resolver pinned to domestic domains,
 *     with `expectedIPs` so a poisoned answer is discarded, reached DIRECT;
 *   - a `dns` outbound that answers ANY port-53 packet entering the core, so
 *     system DNS in TUN mode never leaves the machine in plain text.
 *
 * Everything here is pure; configBuilder splices the result into each plan.
 */

const DNS_DEFAULT_REMOTE = ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'];
/** Shecan — the usual in-country resolver; a user can pick another preset. */
const DNS_DEFAULT_DIRECT_IR = ['178.22.122.100', '185.51.200.2'];
/** AliDNS for the China bypass — not user-configurable (the setting is Iran-centric). */
const DNS_DEFAULT_DIRECT_CN = ['223.5.5.5'];

const DNS_TAG = 'dns-internal';
const HIJACK_TAG = 'dns-out';

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

function isDohUrl(s) {
  return /^https(\+local)?:\/\//i.test(String(s || '').trim());
}

/** "8.8.8.8" → "8.8.8.8"; "https://1.1.1.1/dns-query" → "1.1.1.1"; a hostname → null. */
function resolverIp(entry) {
  const e = String(entry || '').trim();
  if (IPV4.test(e)) return e;
  const m = e.match(/^[a-z+]+:\/\/([^/:?#]+)/i);
  if (m && IPV4.test(m[1])) return m[1];
  return null;
}

function cleanList(list) {
  const out = [];
  for (const raw of Array.isArray(list) ? list : []) {
    const v = String(raw == null ? '' : raw).trim();
    if (v && !out.includes(v)) out.push(v);
  }
  return out;
}

/**
 * Which in-country resolver set a plan needs, if any: 'ir' | 'cn' | null.
 * Simple modes follow routingMode; advanced routing needs one only when a
 * domain rule sends the matching geosite list DIRECT (a rule that sends
 * category-ir through a config wants the exit's view of DNS, not Iran's).
 */
function directRegion(s) {
  if (s.advancedRouting) {
    let region = null;
    for (const r of s.routeRules || []) {
      if (!r || r.type !== 'domain' || r.target !== 'direct') continue;
      const v = String(r.value || '').toLowerCase();
      if (v.includes('geosite:category-ir')) return 'ir';
      if (v.includes('geosite:cn')) region = region || 'cn';
    }
    return region;
  }
  if (s.routingMode === 'bypass-ir') return 'ir';
  if (s.routingMode === 'bypass-cn') return 'cn';
  return null;
}

/**
 * @param {object} settings  dnsManaged, dnsRemote, dnsDirect, ipv6, routingMode, advancedRouting, routeRules
 * @param {object} opts      geoAssets (bool), exitTag (string), dropUdpDirect (bool, phase-3 strict guard)
 */
function buildDnsPlan(settings, opts) {
  const s = settings || {};
  const o = Object.assign({ geoAssets: true, exitTag: 'proxy', dropUdpDirect: false }, opts || {});
  const queryStrategy = s.ipv6 ? 'UseIP' : 'UseIPv4';

  // the remote list; a legacy `dns` array (pre-migration store) counts
  let remote = cleanList(s.dnsRemote != null ? s.dnsRemote : s.dns);
  if (!remote.length) remote = DNS_DEFAULT_REMOTE.slice();

  if (s.dnsManaged === false) {
    // Legacy behaviour: the user's servers as given, nothing intercepted.
    return { dns: { queryStrategy, servers: remote }, hijackOutbound: null, rules: [], directResolverIps: [] };
  }

  const servers = [];
  const directResolverIps = [];

  const region = directRegion(s);
  if (region) {
    let direct = region === 'cn' ? DNS_DEFAULT_DIRECT_CN.slice() : cleanList(s.dnsDirect);
    if (!direct.length) direct = (region === 'cn' ? DNS_DEFAULT_DIRECT_CN : DNS_DEFAULT_DIRECT_IR).slice();
    // strict guard: plain UDP is blocked off the tunnel, keep DoH only
    if (o.dropUdpDirect) direct = direct.filter(isDohUrl);

    // Only the tokens the installed files can back. Without geo files the
    // literal TLD regexp is all that is safe; expectedIPs needs geoip.dat.
    const domains = region === 'ir'
      ? (o.geoAssets ? ['geosite:category-ir', 'regexp:.*\\.ir$'] : ['regexp:.*\\.ir$'])
      : (o.geoAssets ? ['geosite:cn'] : ['regexp:.*\\.cn$']);
    const expected = region === 'ir' ? ['geoip:ir'] : ['geoip:cn'];

    for (const address of direct.slice(0, 2)) {
      const srv = { address, domains: domains.slice() };
      if (o.geoAssets) srv.expectedIPs = expected.slice();
      srv.skipFallback = true;   // never ask the domestic resolver about the rest of the world
      servers.push(srv);
      const ip = resolverIp(address);
      if (ip && !directResolverIps.includes(ip)) directResolverIps.push(ip);
    }
  }

  for (const r of remote) servers.push(r);

  // Rule order matters: the resolver's own traffic is tagged with dns.tag and
  // must be decided BEFORE the port-53 hijack, or its UDP query to the
  // in-country server would be captured by dns-out and loop.
  const rules = [];
  if (directResolverIps.length) rules.push({ type: 'field', inboundTag: [DNS_TAG], ip: directResolverIps.slice(), outboundTag: 'direct' });
  rules.push({ type: 'field', inboundTag: [DNS_TAG], outboundTag: o.exitTag });
  rules.push({ type: 'field', port: '53', network: 'tcp,udp', outboundTag: HIJACK_TAG });

  return {
    dns: { tag: DNS_TAG, queryStrategy, servers },
    hijackOutbound: { tag: HIJACK_TAG, protocol: 'dns' },
    rules,
    directResolverIps
  };
}

/**
 * What the TUN adapter's DNS servers should be. Managed: the tunnel's own peer
 * address — every query then enters the TUN and is hijacked by dns-out.
 * Unmanaged: the plain-IP entries of the remote list (URLs cannot be adapter
 * DNS servers), falling back to public resolvers.
 */
function adapterDnsServers(settings, tunnelPeer) {
  const s = settings || {};
  if (s.dnsManaged !== false) return [tunnelPeer];
  const ips = cleanList(s.dnsRemote != null ? s.dnsRemote : s.dns).filter(v => IPV4.test(v));
  return ips.length ? ips.slice(0, 2) : ['1.1.1.1', '8.8.8.8'];
}

module.exports = {
  buildDnsPlan, adapterDnsServers, isDohUrl, resolverIp,
  DNS_DEFAULT_REMOTE, DNS_DEFAULT_DIRECT_IR, DNS_DEFAULT_DIRECT_CN, DNS_TAG, HIJACK_TAG
};
```

- [ ] **Step 4: Run the tests**

Run: `node --test tests/dnsBuilder.test.js` → Expected: `# pass 16`.

- [ ] **Step 5: Commit**

```bash
git add src/main/dnsBuilder.js tests/dnsBuilder.test.js
git commit -m "Add the resolver plan: DoH remote, in-country direct resolver, port-53 hijack"
```

---

### Task 2: Splice the resolver plan into every config

**Files:**
- Modify: `src/main/configBuilder.js` (`FREEDOM`, `buildConfig`, `buildPoolConfig`, imports)
- Modify: `tests/fixtures.js` (`settings()` defaults)
- Modify: `tests/configBuilder.test.js`

**Interfaces:**
- Consumes: `buildDnsPlan`, `DNS_TAG` (Task 1).
- Produces: every config now carries `dns.tag`, a `dns-out` outbound and DNS rules first in `routing.rules` when `dnsManaged` is on; `freedom` uses `UseIPv4` unless `ipv6`.

- [ ] **Step 1: Update the fixture and write the failing tests**

`tests/fixtures.js` — replace `dns: ['1.1.1.1', '8.8.8.8'],` in `settings()` with:

```js
    // The routing-order tests below keep DNS management OFF so the rule lists
    // stay readable; the resolver plan itself is pinned in dnsBuilder.test.js
    // and by the "managed" tests here, which prepend it explicitly.
    dnsManaged: false,
    dnsRemote: ['1.1.1.1', '8.8.8.8'],
    dnsDirect: [],
    ipv6: false,
```

`tests/configBuilder.test.js` — replace the test `dns and log level come from settings` with:

```js
test('dns and log level come from settings (unmanaged: the list verbatim)', () => {
  const c = buildConfig(single(), settings({ dnsRemote: ['9.9.9.9'], logLevel: 'debug' }));
  assert.deepEqual(c.dns, { servers: ['9.9.9.9'], queryStrategy: 'UseIPv4' });
  assert.equal(c.log.loglevel, 'debug');
  assert.equal(c.outbounds.some(o => o.tag === 'dns-out'), false);
});

test('ipv6 off keeps the direct outbound on IPv4; on lets it use both', () => {
  const off = buildConfig(single(), settings());
  assert.equal(outboundTagged(off, 'direct').settings.domainStrategy, 'UseIPv4');
  const on = buildConfig(single(), settings({ ipv6: true }));
  assert.equal(outboundTagged(on, 'direct').settings.domainStrategy, 'UseIP');
  assert.equal(on.dns.queryStrategy, 'UseIP');
});
```

and add a new section at the end of the file:

```js
/* ----------------------------- managed DNS ----------------------------- */

const MANAGED = { dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: ['178.22.122.100'] };
const DNS_RULES_GLOBAL = [
  { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'proxy' },
  { type: 'field', port: '53', network: 'tcp,udp', outboundTag: 'dns-out' }
];

test('managed single: the DNS rules come FIRST, then the usual list', () => {
  const c = buildConfig(single(), settings(Object.assign({ blockAds: false }, MANAGED)));
  assert.deepEqual(c.routing.rules.slice(0, 2), DNS_RULES_GLOBAL);
  // the rest is exactly what the unmanaged config produces
  const plain = buildConfig(single(), settings({ blockAds: false }));
  assert.deepEqual(c.routing.rules.slice(2), plain.routing.rules);
  assert.deepEqual(c.dns.tag, 'dns-internal');
  assert.ok(c.outbounds.some(o => o.tag === 'dns-out' && o.protocol === 'dns'));
});

test('the hijack precedes the private-IP bypass, or a query to the tunnel peer would go direct', () => {
  const c = buildConfig(single(), settings(MANAGED));
  const hijack = c.routing.rules.findIndex(r => r.outboundTag === 'dns-out');
  const priv = c.routing.rules.findIndex(r => r.ip && r.ip.includes('10.0.0.0/8'));
  assert.ok(hijack > -1 && priv > -1);
  assert.ok(hijack < priv);
});

test('managed bypass-ir: the in-country resolver rides direct and the domestic rules still follow', () => {
  const c = buildConfig(single(), settings(Object.assign({ routingMode: 'bypass-ir', blockAds: false }, MANAGED)));
  assert.deepEqual(c.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], ip: ['178.22.122.100'], outboundTag: 'direct' });
  assert.deepEqual(c.routing.rules[1], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'proxy' });
  assert.equal(c.routing.rules[2].outboundTag, 'dns-out');
  assert.equal(c.dns.servers[0].address, '178.22.122.100');
  assert.deepEqual(c.dns.servers[0].expectedIPs, ['geoip:ir']);
});

test('managed bypass-ir without geo files carries no geo token at all', () => {
  const c = buildConfig(single(), settings(Object.assign({ routingMode: 'bypass-ir', geoAssets: false }, MANAGED)));
  assert.equal(JSON.stringify(c).includes('geosite:'), false);
  assert.equal(JSON.stringify(c).includes('geoip:'), false);
});

test('managed direct mode: the resolver’s traffic goes direct too', () => {
  const c = buildConfig(single(), settings(Object.assign({ routingMode: 'direct' }, MANAGED)));
  assert.deepEqual(c.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'direct' });
});

test('managed chain: same rules, exit is the chain’s proxy tag', () => {
  const c = buildConfig({ mode: 'chain', chain: [VLESS_WS_TLS, TROJAN_TCP_TLS] }, settings(Object.assign({ blockAds: false }, MANAGED)));
  assert.deepEqual(c.routing.rules.slice(0, 2), DNS_RULES_GLOBAL);
  assert.deepEqual(c.outbounds.map(o => o.tag), ['proxy-h0', 'proxy', 'direct', 'block', 'dns-out']);
});

test('managed advanced: the resolver follows the default target, before the user rules', () => {
  const c = buildConfig(advancedPlan({
    rules: [{ type: 'domain', value: 'a.com', target: 'sv-trojan' }],
    def: 'sv-vless'
  }), settings(Object.assign({ blockAds: false }, MANAGED)));
  assert.deepEqual(c.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'out-sv-vless' });
  assert.equal(c.routing.rules[1].outboundTag, 'dns-out');
  assert.deepEqual(c.routing.rules[2].domain, ['a.com']);
  assert.ok(c.outbounds.some(o => o.tag === 'dns-out'));
});

test('managed advanced: a category-ir → direct rule gets the in-country resolver', () => {
  const c = buildConfig(advancedPlan({
    rules: [{ type: 'domain', value: 'geosite:category-ir', target: 'direct' }],
    def: 'sv-vless'
  }), settings(Object.assign({ blockAds: false }, MANAGED)));
  assert.equal(c.dns.servers[0].address, '178.22.122.100');
  assert.deepEqual(c.routing.rules[0].ip, ['178.22.122.100']);
});

test('managed pool: the resolver follows the primary exit; per-inbound rules are untouched', () => {
  const c = buildConfig(poolPlan([{ id: 'e1', target: 'sv-trojan', socksPort: 60001 }]), settings(MANAGED));
  assert.deepEqual(c.routing.rules[0], { type: 'field', inboundTag: ['dns-internal'], outboundTag: 'out-sv-vless' });
  assert.equal(c.routing.rules[1].outboundTag, 'dns-out');
  const e1 = c.routing.rules.find(r => r.inboundTag && r.inboundTag.includes('ps-e1'));
  assert.equal(e1.outboundTag, 'out-sv-trojan');
  assert.ok(c.outbounds.some(o => o.tag === 'dns-out'));
  assert.equal(c.dns.tag, 'dns-internal');
});

test('buildTestConfig is untouched by DNS management (no hijack, no tag)', () => {
  const c = buildTestConfig(VLESS_WS_TLS, 47130);
  assert.equal(c.dns, undefined);
  assert.equal(c.outbounds.some(o => o.tag === 'dns-out'), false);
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `node --test tests/configBuilder.test.js` → Expected: FAIL — `c.dns` still has the old shape, no `dns-out`.

- [ ] **Step 3: Change the builder**

Add the import at the top of `src/main/configBuilder.js`:

```js
const { buildDnsPlan } = require('./dnsBuilder');
```

Replace the `FREEDOM` constant with a factory (keep `BLACKHOLE` as is):

```js
/**
 * The direct outbound. IPv4-only unless the user turned IPv6 on: with no v6
 * route in the tunnel, an AAAA answer would just make the app try an address
 * it cannot reach.
 */
function freedom(s) {
  return { tag: 'direct', protocol: 'freedom', settings: { domainStrategy: s.ipv6 ? 'UseIP' : 'UseIPv4' } };
}
```

and replace every `Object.assign({}, FREEDOM)` in the file with `freedom(s)` (there are three: two in `buildConfig`, one in `buildPoolConfig`).

In `buildConfig`'s defaults object, replace `dns: ['1.1.1.1', '8.8.8.8'],` with:

```js
    dnsManaged: true,
    dnsRemote: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'],
    dnsDirect: ['178.22.122.100', '185.51.200.2'],
    ipv6: false,
```

In the advanced branch, after `const defTag = reg.tagFor(plan.def);` compute the plan and prepend its rules; in the simple branch the exit is `proxy` (or `direct` in direct mode). Restructure the end of both branches so a single `dnsPlan` is in scope:

```js
  let outbounds, rules, exitTag;

  if (plan.mode === 'advanced') {
    … (unchanged up to defTag) …
    const defTag = reg.tagFor(plan.def);
    exitTag = defTag;
    reg.add(freedom(s));
    reg.add(Object.assign({}, BLACKHOLE));
    outbounds = reg.outs;
    rules = [
      ...(s.blockAds && geo ? [{ type: 'field', domain: ['geosite:category-ads-all'], outboundTag: 'block' }] : []),
      ...advRules,
      { type: 'field', ip: PRIVATE_IPS.slice(), outboundTag: 'direct' },
      { type: 'field', port: '0-65535', outboundTag: defTag }
    ];
  } else {
    const proxyOutbounds = plan.mode === 'chain'
      ? buildChainOutbounds(plan.chain, 'proxy')
      : [cloneOut(plan.server.outbound, 'proxy')];
    outbounds = [...proxyOutbounds, freedom(s), Object.assign({}, BLACKHOLE)];
    exitTag = s.routingMode === 'direct' ? 'direct' : 'proxy';
    const base = buildRoutingRules(s.routingMode, s.blockAds, geo);
    const tail = base.pop();
    rules = [...base, ...normalizeCustomRules(s.customRules, geo), tail];
  }

  // Name resolution (see dnsBuilder.js). Its rules go FIRST: the port-53 hijack
  // must beat the private-IP bypass, or a query to the tunnel peer 10.255.0.1
  // would be sent "direct" into nowhere instead of being answered.
  const dnsPlan = buildDnsPlan(s, { geoAssets: geo, exitTag });
  if (dnsPlan.hijackOutbound) outbounds.push(dnsPlan.hijackOutbound);
  rules = [...dnsPlan.rules, ...rules];
```

(Keep the existing NOTE comment about user rules preceding the private bypass in the advanced branch.) Then in the returned object replace `dns: { servers: s.dns, queryStrategy: 'UseIP' },` with `dns: dnsPlan.dns,`.

`buildPoolConfig`: after `const primaryTag = reg.tagFor(plan.primary);` nothing changes until the outbound assembly. Replace

```js
  reg.add(Object.assign({}, FREEDOM));
  reg.add(Object.assign({}, BLACKHOLE));
  const outbounds = applyFragments((reg.outs || []).map(sanitizeWgOutbound));
```
with
```js
  reg.add(freedom(s));
  reg.add(Object.assign({}, BLACKHOLE));
  const dnsPlan = buildDnsPlan(s, { geoAssets: s.geoAssets !== false, exitTag: primaryTag });
  if (dnsPlan.hijackOutbound) reg.add(dnsPlan.hijackOutbound);
  const outbounds = applyFragments((reg.outs || []).map(sanitizeWgOutbound));
```
and make the DNS rules lead:

```js
  // Resolver rules first (see buildConfig), then private/LAN direct, THEN
  // per-inbound routing, THEN a catch-all to the primary exit.
  rules.push(...dnsPlan.rules);
  rules.push({ type: 'field', ip: PRIVATE_IPS.slice(), outboundTag: 'direct' });
  rules.push(...perInboundRules);
  rules.push({ type: 'field', port: '0-65535', outboundTag: primaryTag });
```
and `dns: dnsPlan.dns,` in its returned object.

`applyFragments` skips outbounds without markers, so the `dns-out` outbound passes through it untouched.

- [ ] **Step 4: Run the builder tests, then the suite**

Run: `node --test tests/configBuilder.test.js` → Expected: pass.
Run: `node --test "tests/*.test.js"` → Expected: all pass, pristine.

- [ ] **Step 5: Commit**

```bash
git add src/main/configBuilder.js tests/fixtures.js tests/configBuilder.test.js
git commit -m "Configs carry the resolver plan: DoH remote, direct in-country resolver, port-53 hijack first"
```

---

### Task 3: Settings — new keys, migration, TUN adapter DNS

**Files:**
- Create: `src/main/settingsMigrate.js`
- Test: `tests/settingsMigrate.test.js`
- Modify: `src/main/settingsMeta.js:25-36`, `tests/settingsMeta.test.js`
- Modify: `src/main/main.js` (`DEFAULT_SETTINGS`, startup migration, `tun.start` call), `src/server/service.js` (same)
- Modify: `src/main/tunManager.js` (export `TUN_GW`)

**Interfaces:**
- Produces: `migrateSettings(raw) → { settings, changed }` (pure). Old `dns` → `dnsRemote` (known public IPs become their DoH URL, unknown IPs stay UDP) and, when the old list held a known Iranian preset, → `dnsDirect`. Removes `dns`. Idempotent.
- `RECONNECT_KEYS`: `'dns'` replaced by `'dnsManaged', 'dnsRemote', 'dnsDirect', 'ipv6'`.
- `tun.start(socksPort, entryAddrs, adapterDnsServers(settings, TUN_GW))`.

- [ ] **Step 1: Write the failing tests**

`tests/settingsMigrate.test.js`:

```js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { migrateSettings } = require('../src/main/settingsMigrate');

test('a stored `dns` list becomes dnsRemote, public IPs upgraded to DoH', () => {
  const { settings, changed } = migrateSettings({ dns: ['1.1.1.1', '8.8.8.8'], socksPort: 1080 });
  assert.equal(changed, true);
  assert.equal('dns' in settings, false);
  assert.deepEqual(settings.dnsRemote, ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query']);
  assert.equal(settings.socksPort, 1080, 'other keys untouched');
});

test('an unknown resolver stays as plain UDP', () => {
  const { settings } = migrateSettings({ dns: ['10.0.0.53', '9.9.9.9'] });
  assert.deepEqual(settings.dnsRemote, ['10.0.0.53', 'https://9.9.9.9/dns-query']);
});

test('a stored Iranian preset moves to dnsDirect, and the remote list gets the default', () => {
  const { settings } = migrateSettings({ dns: ['178.22.122.100', '185.51.200.2'] });
  assert.deepEqual(settings.dnsDirect, ['178.22.122.100', '185.51.200.2']);
  assert.deepEqual(settings.dnsRemote, ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query']);
});

test('a mixed list splits by role', () => {
  const { settings } = migrateSettings({ dns: ['78.157.42.100', '8.8.8.8'] });
  assert.deepEqual(settings.dnsDirect, ['78.157.42.100']);
  assert.deepEqual(settings.dnsRemote, ['https://8.8.8.8/dns-query']);
});

test('already migrated: nothing changes, same object back', () => {
  const input = { dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: [] };
  const r = migrateSettings(input);
  assert.equal(r.changed, false);
  assert.equal(r.settings, input);
});

test('dns present alongside dnsRemote: dns is dropped, dnsRemote wins', () => {
  const { settings, changed } = migrateSettings({ dns: ['8.8.8.8'], dnsRemote: ['https://9.9.9.9/dns-query'] });
  assert.equal(changed, true);
  assert.deepEqual(settings.dnsRemote, ['https://9.9.9.9/dns-query']);
  assert.equal('dns' in settings, false);
});

test('odd shapes never throw', () => {
  for (const raw of [null, undefined, {}, { dns: null }, { dns: 'x' }, { dns: [null, 3, ''] }]) {
    assert.doesNotThrow(() => migrateSettings(raw), JSON.stringify(raw));
  }
  assert.deepEqual(migrateSettings({ dns: [null, 3, ''] }).settings.dnsRemote, ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query']);
});
```

`tests/settingsMeta.test.js` — in `baseSettings()` replace `dns: ['1.1.1.1', '8.8.8.8'],` with

```js
    dnsManaged: true,
    dnsRemote: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'],
    dnsDirect: ['178.22.122.100', '185.51.200.2'],
    ipv6: false,
```
in the `changes` fixture replace `dns: ['9.9.9.9'],` with `dnsManaged: false, dnsRemote: ['https://9.9.9.9/dns-query'], dnsDirect: ['78.157.42.100'], ipv6: true,`; and in the deep-copy test replace `live.dns.push('8.8.4.4');` with `live.dnsRemote.push('https://8.8.4.4/dns-query');` and its expectation `['dns', 'routeRules']` with `['dnsRemote', 'routeRules']`.

- [ ] **Step 2: Run to verify they fail**

Run: `node --test tests/settingsMigrate.test.js tests/settingsMeta.test.js` → Expected: FAIL — module missing; `changes` fixture no longer matches `RECONNECT_KEYS`.

- [ ] **Step 3: Implement the migration**

`src/main/settingsMigrate.js`:

```js
'use strict';
/**
 * One-time settings migration for the resolver rework (phase 2).
 *
 * The old store held a single `dns` list of plain-UDP resolvers. The new model
 * has two lists with different jobs: `dnsRemote` (the world, over DoH through
 * the tunnel) and `dnsDirect` (the in-country resolver for bypass modes). A
 * known public resolver is upgraded to its DoH endpoint — the whole point of
 * the rework is that plain UDP through the proxy is what broke bypass — and a
 * known Iranian resolver goes where it belongs. Anything else is kept as is.
 *
 * Pure and idempotent: returns the SAME object when there is nothing to do.
 */

const DOH_FOR = {
  '1.1.1.1': 'https://1.1.1.1/dns-query', '1.0.0.1': 'https://1.0.0.1/dns-query',
  '8.8.8.8': 'https://8.8.8.8/dns-query', '8.8.4.4': 'https://8.8.4.4/dns-query',
  '9.9.9.9': 'https://9.9.9.9/dns-query', '149.112.112.112': 'https://149.112.112.112/dns-query',
  '94.140.14.14': 'https://94.140.14.14/dns-query', '94.140.15.15': 'https://94.140.15.15/dns-query',
  '208.67.222.222': 'https://208.67.222.222/dns-query', '208.67.220.220': 'https://208.67.220.220/dns-query'
};

/** Resolvers that only make sense as the in-country (direct) server. */
const IRANIAN = new Set([
  '178.22.122.100', '185.51.200.2',      // Shecan
  '78.157.42.100', '78.157.42.101',      // Electro
  '10.202.10.202', '10.202.10.102',      // Begzar
  '10.202.10.10', '10.202.10.11'         // 403.online
]);

const DEFAULT_REMOTE = ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'];

function migrateSettings(raw) {
  if (!raw || typeof raw !== 'object' || !('dns' in raw)) return { settings: raw, changed: false };

  const next = Object.assign({}, raw);
  const old = Array.isArray(raw.dns) ? raw.dns.map(v => String(v == null ? '' : v).trim()).filter(Boolean) : [];
  delete next.dns;

  if (next.dnsRemote == null) {
    const remote = [], direct = [];
    for (const ip of old) {
      if (IRANIAN.has(ip)) direct.push(ip);
      else remote.push(DOH_FOR[ip] || ip);
    }
    next.dnsRemote = remote.length ? remote : DEFAULT_REMOTE.slice();
    if (direct.length && next.dnsDirect == null) next.dnsDirect = direct;
  }
  return { settings: next, changed: true };
}

module.exports = { migrateSettings };
```

- [ ] **Step 4: The reconnect keys**

`src/main/settingsMeta.js` — replace `'dns', 'logLevel', 'enableSniffing',` with:

```js
  'dnsManaged', 'dnsRemote', 'dnsDirect', 'ipv6', 'logLevel', 'enableSniffing',
```

The i18n strings for those four keys are added in Task 4; until then `tests/settingsMeta.test.js`'s i18n-drift test fails — that is expected and is why Tasks 3 and 4 land back to back. (If you run the suite now, that one test is the only red.)

- [ ] **Step 5: Wire main.js and service.js**

Both files, `DEFAULT_SETTINGS`: replace `dns: ['1.1.1.1', '8.8.8.8'],` with

```js
  // name resolution (see dnsBuilder.js): remote over DoH through the tunnel,
  // an in-country resolver for bypass modes, every port-53 packet answered by
  // the core. `dnsManaged:false` restores the old "use these servers" behaviour.
  dnsManaged: true,
  dnsRemote: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'],
  dnsDirect: ['178.22.122.100', '185.51.200.2'],
  ipv6: false,
```

Both files, imports: `const { migrateSettings } = require('./settingsMigrate');` (service.js: `'../main/settingsMigrate'`), `const { adapterDnsServers } = require('./dnsBuilder');` (service.js: `'../main/dnsBuilder'`), and add `TUN_GW` to the `require('./tunManager')` destructure in both.

`src/main/tunManager.js` — export the peer address: change the export line to `module.exports = { TunManager, isOwnTunInterface, TUN_GW };`.

Both files, next to `migrateServers()`, add:

```js
/**
 * Convert a pre-phase-2 `dns` setting into `dnsRemote` / `dnsDirect`. Runs
 * before anything reads settings, writes only when something changed.
 */
function migrateSettingsStore() {
  const raw = store.get('settings', null);
  const { settings, changed } = migrateSettings(raw);
  if (changed) store.set('settings', settings);
}
```
and call `migrateSettingsStore();` immediately after `migrateServers();` at startup (main.js `app.whenReady`, service.js `createService`).

Both files, the TUN start: replace `await tun.start(settings.socksPort, entryAddrs, settings.dns);` with

```js
        // Managed DNS: the adapter's resolver is the tunnel's own peer, so
        // every system query enters the TUN and is answered by dns-out. Nothing
        // leaves the machine as plain UDP to the ISP.
        await tun.start(settings.socksPort, entryAddrs, adapterDnsServers(settings, TUN_GW));
```

- [ ] **Step 6: Verify**

Run: `node --test tests/settingsMigrate.test.js tests/dnsBuilder.test.js tests/configBuilder.test.js` → Expected: pass.
Run: `node --check src/main/main.js && node --check src/server/service.js`.
Mirror check: `grep -c "migrateSettingsStore\|adapterDnsServers\|TUN_GW" src/main/main.js src/server/service.js` — report both counts (they should match).

Migration end to end on the headless server:
```bash
mkdir -p /tmp/irnf-dns && printf '{"settings":{"dns":["178.22.122.100","8.8.8.8"],"socksPort":10808}}' > /tmp/irnf-dns/store.json
node src/server/server.js --port 7821 --data-dir /tmp/irnf-dns &
sleep 1
curl -s -X POST http://127.0.0.1:7821/rpc -H 'Origin: http://127.0.0.1:7821' -H 'Content-Type: application/json' -d '{"channel":"settings:get"}' | grep -o '"dns[A-Za-z]*":[^}]*\]' 
```
Expected: `dnsRemote` = `["https://8.8.8.8/dns-query"]`, `dnsDirect` = `["178.22.122.100"]`, no `dns` key. Stop the server.

- [ ] **Step 7: Commit**

```bash
git add src/main/settingsMigrate.js tests/settingsMigrate.test.js src/main/settingsMeta.js tests/settingsMeta.test.js src/main/main.js src/server/service.js src/main/tunManager.js
git commit -m "Settings: dnsManaged/dnsRemote/dnsDirect/ipv6, migrate the old dns list, TUN adapter DNS = tunnel peer"
```

---

### Task 4: The Settings page

**Files:**
- Modify: `src/renderer/index.html` (the DNS block in Settings)
- Modify: `src/renderer/app.js` (`applySettingsToUI`, `syncDnsPreset` → `syncPreset`, `readSettingsForm`, `dnsFromInput`, preset handlers)
- Modify: `src/renderer/i18n.js` (both blocks)

**Interfaces:**
- Consumes: settings keys `dnsManaged`, `dnsRemote`, `dnsDirect`, `ipv6` (Task 3).
- Produces: i18n keys `set.dnsRemote`, `set.dnsDirect`, `set.dnsManaged`, `set.ipv6` (the reconnect-dialog names), `dnsm.title`, `dnsm.sub`, `ipv6.title`, `ipv6.sub`, `dns.remoteHint`, `dns.directHint`; `set.dns` is removed from both blocks.

- [ ] **Step 1: Markup**

In `src/renderer/index.html`, replace the DNS cell (`<label … data-i18n="set.dns">` through its `<input … id="dnsInput" …/>` and closing `</div>`) with:

```html
            <div>
              <label class="field-label" data-i18n="set.dnsRemote">DNS خارجی (از داخل تونل)</label>
              <select id="dnsRemotePreset" class="select" style="margin-bottom:8px">
                <option value="" data-i18n="dns.custom">سفارشی…</option>
                <option value="https://1.1.1.1/dns-query,https://1.0.0.1/dns-query">Cloudflare — DoH</option>
                <option value="https://8.8.8.8/dns-query,https://8.8.4.4/dns-query">Google — DoH</option>
                <option value="https://9.9.9.9/dns-query,https://149.112.112.112/dns-query">Quad9 — DoH</option>
                <option value="https://94.140.14.14/dns-query,https://94.140.15.15/dns-query">AdGuard — DoH</option>
                <option value="1.1.1.1,1.0.0.1">Cloudflare — UDP</option>
                <option value="8.8.8.8,8.8.4.4">Google — UDP</option>
              </select>
              <input type="text" id="dnsRemoteInput" class="input" dir="ltr" placeholder="https://1.1.1.1/dns-query, https://8.8.8.8/dns-query" />
              <p class="hint" data-i18n="dns.remoteHint"></p>
            </div>
```

Then, after the `grid2` row that holds it (the one ending with the log-level select), add a new row and two switches:

```html
          <div class="grid2">
            <div>
              <label class="field-label" data-i18n="set.dnsDirect">DNS داخلی (برای دور زدن ایران)</label>
              <select id="dnsDirectPreset" class="select" style="margin-bottom:8px">
                <option value="" data-i18n="dns.custom">سفارشی…</option>
                <option value="178.22.122.100,185.51.200.2">Shecan (شکن)</option>
                <option value="78.157.42.100,78.157.42.101">Electro (الکترو)</option>
                <option value="10.202.10.202,10.202.10.102">begzar (بگذر)</option>
                <option value="10.202.10.10,10.202.10.11">403.online</option>
              </select>
              <input type="text" id="dnsDirectInput" class="input" dir="ltr" placeholder="178.22.122.100, 185.51.200.2" />
              <p class="hint" data-i18n="dns.directHint"></p>
            </div>
            <div></div>
          </div>
          <div class="switch-row">
            <div><div class="switch-title" data-i18n="dnsm.title">مدیریت DNS توسط برنامه</div>
              <div class="switch-sub" data-i18n="dnsm.sub"></div></div>
            <label class="switch"><input type="checkbox" id="optDnsManaged" /><span class="slider"></span></label>
          </div>
          <div class="switch-row">
            <div><div class="switch-title" data-i18n="ipv6.title">IPv6</div>
              <div class="switch-sub" data-i18n="ipv6.sub"></div></div>
            <label class="switch"><input type="checkbox" id="optIpv6" /><span class="slider"></span></label>
          </div>
```

- [ ] **Step 2: Strings**

`src/renderer/i18n.js` — in **fa**, replace `'set.dns': 'DNS (با کاما)',` with:

```js
    'set.dnsRemote': 'DNS خارجی (از داخل تونل)', 'set.dnsDirect': 'DNS داخلی (دور زدن ایران)',
    'set.dnsManaged': 'مدیریت DNS توسط برنامه', 'set.ipv6': 'IPv6',
    'dns.remoteHint': 'برای همه‌ی دنیا؛ از داخل تونل می‌رود. DoH (https://…) توصیه می‌شود چون سرورهایی که UDP را می‌بندند دیگر DNS را نمی‌شکنند.',
    'dns.directHint': 'فقط در حالت «دور زدن ایران» استفاده می‌شود: دامنه‌های ایرانی از این‌جا و مستقیم resolve می‌شوند و جواب باید IP ایرانی باشد.',
    'dnsm.title': 'مدیریت DNS توسط برنامه',
    'dnsm.sub': 'روشن: هر DNS ای که به هسته برسد همین‌جا جواب داده می‌شود (هیچ DNS خامی بیرون نمی‌رود). خاموش: DNS هر جا که سیستم/برنامه‌ها بفرستند می‌رود؛ محافظت در برابر نشتی ضعیف‌تر است.',
    'ipv6.title': 'IPv6',
    'ipv6.sub': 'خاموش (پیش‌فرض): فقط جواب‌های IPv4 استفاده می‌شود تا برنامه‌ها سراغ آدرسی نروند که تونل ندارد.',
```

and in **en**, replace `'set.dns': 'DNS (comma-separated)',` with:

```js
    'set.dnsRemote': 'Remote DNS (through the tunnel)', 'set.dnsDirect': 'Domestic DNS (bypass Iran)',
    'set.dnsManaged': 'DNS managed by the app', 'set.ipv6': 'IPv6',
    'dns.remoteHint': 'For the rest of the world, sent through the tunnel. DoH (https://…) is recommended: a server that drops UDP can no longer break DNS.',
    'dns.directHint': 'Used only in "Bypass Iran": Iranian domains are resolved here, directly, and the answer must be an Iranian IP.',
    'dnsm.title': 'DNS managed by the app',
    'dnsm.sub': 'On: every DNS query that reaches the core is answered here (no plain DNS ever leaves). Off: DNS goes wherever your apps/OS send it; leak protection is weaker.',
    'ipv6.title': 'IPv6',
    'ipv6.sub': 'Off (default): only IPv4 answers are used, so apps never try an address the tunnel does not carry.',
```

- [ ] **Step 3: Renderer logic**

In `src/renderer/app.js`:

`applySettingsToUI()` — replace `$('#dnsInput').value = (s.dns || ['1.1.1.1', '8.8.8.8']).join(',');` with

```js
  $('#dnsRemoteInput').value = (s.dnsRemote || []).join(', ');
  $('#dnsDirectInput').value = (s.dnsDirect || []).join(', ');
  $('#optDnsManaged').checked = s.dnsManaged !== false;
  $('#optIpv6').checked = !!s.ipv6;
```
and replace the trailing `syncDnsPreset();` with `syncPreset('#dnsRemotePreset', '#dnsRemoteInput'); syncPreset('#dnsDirectPreset', '#dnsDirectInput');`.

Replace `syncDnsPreset()` with a generic version:

```js
/** Reflect an input's value in its preset dropdown (or "custom"). */
function syncPreset(selSel, inputSel) {
  const sel = $(selSel);
  if (!sel) return;
  const cur = ($(inputSel).value || '').replace(/\s/g, '');
  const match = Array.from(sel.options).find(o => o.value && o.value.replace(/\s/g, '') === cur);
  sel.value = match ? match.value : '';
}
```

`readSettingsForm()` — replace `dns: dnsFromInput(),` with:

```js
    dnsRemote: listFromInput('#dnsRemoteInput'),
    dnsDirect: listFromInput('#dnsDirectInput'),
    dnsManaged: $('#optDnsManaged').checked,
    ipv6: $('#optIpv6').checked,
```
and replace `dnsFromInput()` with:

```js
function listFromInput(sel) {
  return $(sel).value.split(',').map(s => s.trim()).filter(Boolean);
}
```

Replace the two DNS handlers (`$('#dnsPreset').onchange` … `$('#dnsInput').oninput`) with:

```js
/* DNS presets — pick a provider to fill the input, or type a custom value */
$('#dnsRemotePreset').onchange = () => {
  const v = $('#dnsRemotePreset').value;
  if (v) { $('#dnsRemoteInput').value = v.split(',').join(', '); saveSettings({ dnsRemote: listFromInput('#dnsRemoteInput') }); toast(t('dns.set'), 'ok'); }
};
$('#dnsRemoteInput').oninput = () => syncPreset('#dnsRemotePreset', '#dnsRemoteInput');
$('#dnsDirectPreset').onchange = () => {
  const v = $('#dnsDirectPreset').value;
  if (v) { $('#dnsDirectInput').value = v.split(',').join(', '); saveSettings({ dnsDirect: listFromInput('#dnsDirectInput') }); toast(t('dns.set'), 'ok'); }
};
$('#dnsDirectInput').oninput = () => syncPreset('#dnsDirectPreset', '#dnsDirectInput');
$('#optDnsManaged').onchange = () => saveSettings({ dnsManaged: $('#optDnsManaged').checked });
$('#optIpv6').onchange = () => saveSettings({ ipv6: $('#optIpv6').checked });
```

- [ ] **Step 4: Verify in the browser**

```bash
mkdir -p /tmp/irnf-dnsui && node src/server/server.js --port 7822 --data-dir /tmp/irnf-dnsui &
```
Open `http://127.0.0.1:7822/` (assert `location.port === '7822'` before every action). Settings shows: Remote DNS with the DoH default and its preset reading "Cloudflare — DoH"… wait, the default is `1.1.1.1` + `8.8.8.8`, which matches no preset, so the dropdown reads "Custom…" — that is correct. Pick "Google — DoH" → input fills, `store.json` gains only `dnsRemote`. Pick "Electro" in Domestic → only `dnsDirect` changes. Toggle "DNS managed by the app" off → only `dnsManaged`. Toggle IPv6 → only `ipv6`. Switch language to English and back: every new label translates. Run the i18n parity check and report the count. Stop the server.

- [ ] **Step 5: Run the suite and commit**

Run: `node --test "tests/*.test.js"` → Expected: all pass (the settingsMeta i18n-drift test is green now).

```bash
git add src/renderer/index.html src/renderer/app.js src/renderer/i18n.js
git commit -m "Settings: remote (DoH) and domestic DNS, DNS-managed and IPv6 switches"
```

---

### Task 5: sing-box engine follows `dnsRemote`

**Files:**
- Modify: `src/main/singboxBuilder.js:33-44`
- Test: `tests/singboxBuilder.test.js` (new)

- [ ] **Step 1: Write the failing test**

`tests/singboxBuilder.test.js`:

```js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildSingboxConfig } = require('../src/main/singboxBuilder');
const { VLESS_WS_TLS } = require('./fixtures');

test('a DoH remote resolver becomes an https DNS server', () => {
  const c = buildSingboxConfig(VLESS_WS_TLS, { dnsRemote: ['https://1.1.1.1/dns-query'] });
  assert.deepEqual(c.dns.servers[0], { type: 'https', tag: 'dns-direct', server: '1.1.1.1', path: '/dns-query' });
  assert.equal(c.dns.final, 'dns-direct');
});

test('a plain IP stays udp; the legacy dns list still works; nothing → 1.1.1.1', () => {
  assert.deepEqual(buildSingboxConfig(VLESS_WS_TLS, { dnsRemote: ['9.9.9.9'] }).dns.servers[0], { type: 'udp', tag: 'dns-direct', server: '9.9.9.9' });
  assert.equal(buildSingboxConfig(VLESS_WS_TLS, { dns: ['8.8.8.8'] }).dns.servers[0].server, '8.8.8.8');
  assert.equal(buildSingboxConfig(VLESS_WS_TLS, {}).dns.servers[0].server, '1.1.1.1');
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests/singboxBuilder.test.js` → Expected: FAIL — `type` is `udp` for the URL and `server` is the whole URL.

- [ ] **Step 3: Implement**

In `src/main/singboxBuilder.js` replace the `dnsServer` line and the `dns:` block:

```js
  // First remote resolver, in sing-box's own shape (DoH → https, IP → udp).
  const remote = Array.isArray(s.dnsRemote) ? s.dnsRemote : (Array.isArray(s.dns) ? s.dns : []);
  const first = String((remote.find(v => v && String(v).trim()) || '1.1.1.1')).trim();
  const dnsServer = singboxDnsServer(first);
```
with the `dns:` object becoming `{ servers: [dnsServer], final: 'dns-direct' }`, and add the helper near the other helpers:

```js
/** One resolver entry → a sing-box 1.12+ DNS server object. */
function singboxDnsServer(entry) {
  const m = entry.match(/^https(?:\+local)?:\/\/([^/:?#]+)(?::(\d+))?(\/[^?#]*)?/i);
  if (m) {
    const srv = { type: 'https', tag: 'dns-direct', server: m[1] };
    if (m[2]) srv.server_port = parseInt(m[2], 10);
    if (m[3]) srv.path = m[3];
    return srv;
  }
  return { type: 'udp', tag: 'dns-direct', server: entry };
}
```

- [ ] **Step 4: Run and commit**

Run: `node --test tests/singboxBuilder.test.js` → `# pass 2`. Suite green.

```bash
git add src/main/singboxBuilder.js tests/singboxBuilder.test.js
git commit -m "sing-box engine: derive its resolver from dnsRemote (DoH → https)"
```

---

### Task 6: Validate every generated config against the real core

**Files:**
- Create: `scripts/validate-configs.js` (dev-only; add `"validate": "node scripts/validate-configs.js"` to `package.json` `scripts`)

**Why:** nothing in the unit tests proves the core *accepts* `dns.tag`, a `dns` outbound, `expectedIPs`, `skipFallback`, DoH server strings or the `inboundTag` rules. The `bin/` folder is git-ignored and `scripts/download-xray.js` fetches the current release with its geo files, so a real `xray run -test` is available on this machine.

- [ ] **Step 1: The script**

```js
'use strict';
/**
 * Generate every plan shape × DNS mode × geo state and run `xray run -test` on
 * each. This is the only check that proves the CORE accepts what configBuilder
 * emits (dns.tag, the dns outbound, expectedIPs, DoH strings, inboundTag
 * rules) — the unit tests only pin our own output. Needs bin/xray(.exe)
 * (`npm run get-xray`).
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { buildConfig } = require('../src/main/configBuilder');
const F = require('../tests/fixtures');

const exe = path.join(__dirname, '..', 'bin', process.platform === 'win32' ? 'xray.exe' : 'xray');
if (!fs.existsSync(exe)) { console.error('no core at ' + exe + ' — run: npm run get-xray'); process.exit(2); }

const single = { mode: 'single', server: F.VLESS_WS_TLS };
const chain = { mode: 'chain', chain: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS] };
const advanced = {
  mode: 'advanced', serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS },
  chainsById: { c1: [F.VLESS_WS_TLS, F.TROJAN_TCP_TLS] }, chain: [],
  rules: [{ type: 'domain', value: 'geosite:category-ir', target: 'direct' }, { type: 'ip', value: '10.20.0.0/16', target: 'chain:c1' }],
  def: 'sv-vless'
};
const pool = {
  mode: 'pool', entries: [{ id: 'e1', target: 'sv-trojan', socksPort: 60001, httpPort: 60002 }], primary: 'sv-vless',
  serversById: { 'sv-vless': F.VLESS_WS_TLS, 'sv-trojan': F.TROJAN_TCP_TLS }, chainsById: {}, chain: []
};

const plans = { single, chain, advanced, pool };
const dnsModes = {
  managed: { dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'], dnsDirect: ['178.22.122.100', '185.51.200.2'] },
  managedDohDirect: { dnsManaged: true, dnsRemote: ['https://1.1.1.1/dns-query'], dnsDirect: ['https://178.22.122.100/dns-query'] },
  unmanaged: { dnsManaged: false, dnsRemote: ['1.1.1.1', '8.8.8.8'] }
};
const routing = ['global', 'bypass-ir', 'bypass-cn', 'direct'];

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-validate-'));
const assetDir = path.dirname(exe);
let failed = 0, total = 0;
for (const [pn, plan] of Object.entries(plans)) {
  for (const [dn, dns] of Object.entries(dnsModes)) {
    for (const geoAssets of [true, false]) {
      for (const routingMode of (pn === 'advanced' || pn === 'pool' ? ['global'] : routing)) {
        for (const ipv6 of [false, true]) {
          total++;
          const cfg = buildConfig(plan, F.settings(Object.assign({ routingMode, geoAssets, ipv6 }, dns)));
          const file = path.join(work, `${pn}-${dn}-${routingMode}-geo${geoAssets}-v6${ipv6}.json`);
          fs.writeFileSync(file, JSON.stringify(cfg, null, 2));
          const r = spawnSync(exe, ['run', '-test', '-c', file], {
            env: Object.assign({}, process.env, { XRAY_LOCATION_ASSET: assetDir, V2RAY_LOCATION_ASSET: assetDir }),
            encoding: 'utf8', timeout: 15000, windowsHide: true
          });
          if (r.status === 0) { console.log('ok   ' + path.basename(file)); continue; }
          failed++;
          console.log('FAIL ' + path.basename(file));
          console.log('     ' + ((r.stdout || '') + (r.stderr || '')).trim().split(/\r?\n/).slice(-3).join('\n     '));
        }
      }
    }
  }
}
console.log(`\n${total - failed}/${total} configs accepted by ${path.basename(exe)}`);
process.exit(failed ? 1 : 0);
```

Note `geoAssets:false` configs are validated with the geo files still present — that is fine; it proves the token-free output is valid on its own.

- [ ] **Step 2: Get the core and run it**

```bash
npm run get-xray
node scripts/validate-configs.js
```
Expected: every line `ok`, then `N/N configs accepted`. **If any config is rejected, the core's message names the field — fix `dnsBuilder.js` / `configBuilder.js` (with a unit test pinning the corrected shape), not the script, and re-run until clean.** Record the core version (`bin/xray.exe version`) and the full ok/FAIL list in the commit message body.

- [ ] **Step 3: Headless smoke with the real core**

```bash
mkdir -p /tmp/irnf-live && cp bin/xray.exe bin/geoip.dat bin/geosite.dat /tmp/irnf-live/ 2>/dev/null; mkdir -p /tmp/irnf-live/bin && cp bin/xray* bin/geo*.dat /tmp/irnf-live/bin/
node src/server/server.js --port 7823 --data-dir /tmp/irnf-live &
sleep 1
curl -s -X POST http://127.0.0.1:7823/rpc -H 'Origin: http://127.0.0.1:7823' -H 'Content-Type: application/json' -d '{"channel":"servers:add","arg":"vless://11111111-1111-4111-8111-111111111111@127.0.0.1:65000?security=none&type=tcp#Local"}' >/dev/null
curl -s -X POST http://127.0.0.1:7823/rpc -H 'Origin: http://127.0.0.1:7823' -H 'Content-Type: application/json' -d '{"channel":"settings:set","arg":{"routingMode":"bypass-ir","systemProxy":false}}' >/dev/null
ID=$(curl -s -X POST http://127.0.0.1:7823/rpc -H 'Origin: http://127.0.0.1:7823' -H 'Content-Type: application/json' -d '{"channel":"servers:list"}' | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
curl -s -X POST http://127.0.0.1:7823/rpc -H 'Origin: http://127.0.0.1:7823' -H 'Content-Type: application/json' -d "{\"channel\":\"connect\",\"arg\":\"$ID\"}"
```
Expected: `{"result":true}` — the core started on the managed bypass-ir config (the server itself is a dummy; only the start matters). Then `grep -c '"dns-out"' /tmp/irnf-live/config.json` → 2 (outbound + rule). Disconnect (`{"channel":"disconnect"}`) and stop the server.

- [ ] **Step 4: Commit**

```bash
git add scripts/validate-configs.js package.json
git commit -m "Validate every generated config shape against the real core (npm run validate)"
```

---

## Self-review

**Spec coverage (phase 2):** DoH remote + in-country direct + expectedIPs + skipFallback → T1 · hijack outbound + rule first in all four plans → T2 · `dnsManaged` master switch with legacy behaviour → T1, T3, T4 · `dnsRemote`/`dnsDirect`/`ipv6` settings + migration + `RECONNECT_KEYS` + i18n → T3, T4 · TUN adapter DNS = tunnel peer when managed → T3 · freedom `UseIPv4` → T2 · advanced-routing direct resolver for category-ir/cn → T1, T2 · strict-guard hook (`dropUdpDirect`) → T1 · sing-box engine follows the new setting → T5 · real-core validation in place of the live repro (no real server config is available; the design's "reproduce first" is replaced by "prove the core accepts every shape") → T6.

**Placeholder scan:** none.

**Type consistency:** `buildDnsPlan(settings, { geoAssets, exitTag, dropUdpDirect })` returns `{ dns, hijackOutbound, rules, directResolverIps }` and T2 reads exactly those; `adapterDnsServers(settings, tunnelPeer)` and `TUN_GW` are what T3 passes to `tun.start`; the i18n keys T4 adds are exactly the four `set.<key>` names T3 puts in `RECONNECT_KEYS`; `listFromInput` replaces `dnsFromInput` at both call sites.

**Ordering:** T1 → T2 → T3 → T4 (T3's i18n-drift test is red until T4 lands). T5 is independent of T3/T4. T6 last.
