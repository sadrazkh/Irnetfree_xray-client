# IRNetFree on OpenWrt — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `irnetfree_<v>_all.ipk` — the headless IRNetFree service (same Node code, same UI) running on an OpenWrt 24.10 router (Google Wifi AC-1304 first), with every device behind the router going through the tunnel transparently and chosen devices (by MAC) going direct.

**Architecture:** `src/server/service.js` already mirrors `main.js` without Electron. This adds one TUN backend, `TunOpenwrt`, which composes the existing `TunSingbox` (sing-box `auto_route` captures forwarded LAN traffic on Linux by default — verified in sing-tun's `rules()`) and adds an nft table + one `ip rule` for MAC exclusions; the service selects it when `/etc/openwrt_release` exists. Packaging is a Node script writing the ipk (a gzipped tar) with an `ustar` writer of our own; CI boots OpenWrt in QEMU and asserts the gateway comes up. Spec: `docs/superpowers/specs/2026-09-23-openwrt-port-design.md`.

**Tech Stack:** Node 20 (the OpenWrt feed's `node`), sing-box + Xray/Xray-PattN binaries, nftables (`nft`), busybox `ip`, procd/uci, LuCI JS view; tests with `node:test`; GitHub Actions with `qemu-system-arm` (OpenWrt 24.10.2 `armsr/armv7`).

## Global Constraints

- Commits in the owner's name only, **no `Co-Authored-By`**. Tag `v1.13.0` ships; merges do not.
- `src/main/` for Windows/macOS is not touched except: two NEW files (`tunOpenwrt.js`, `openwrtNet.js`), the three asset pickers in `downloader.js` (existing rows byte-identical), one default line in `main.js` `DEFAULT_SETTINGS`. Final check: `git diff --stat v1.12.0..v1.13.0 -- src/main/` lists exactly those four.
- Runtime code uses Node core only (no npm dependencies).
- Renderer strings go through `t()` / `data-i18n`, defined exactly once in `fa` and once in `en` in `src/renderer/i18n.js`; **never an apostrophe inside a single-quoted string** (`tests/syntax.test.js` is why).
- New settings default in BOTH `DEFAULT_SETTINGS` (`src/main/main.js` and `src/server/service.js`).
- Every shell file that runs on the router is **POSIX sh (busybox ash)**: no `[[`, `function`, arrays, `$'…'`, `==` inside `[ ]`, `source`, `&>`, `declare`.
- `npm test` green (currently 796) after every task; the QEMU job green before the tag.
- Nobody has a router: CI (QEMU) is the only place the package runs before the owner's AC-1304. Do not claim device behaviour that CI did not show.

---

## File map

| File | Responsibility | Tasks |
|---|---|---|
| `src/main/openwrtNet.js` (new) | `isOpenwrt`, MAC validation, lease/neigh parsing, device merge, nft ruleset text, `ip rule` argv; readers with injected I/O | 1, 2 |
| `src/main/tunOpenwrt.js` (new) | `TunOpenwrt`: composes `TunSingbox`; nft table + bypass rule around it; verify; live `setBypassMacs` | 3 |
| `src/main/downloader.js` | Linux arch table for the three asset pickers (`arm` → armv7 assets) | 4 |
| `src/main/main.js` | `DEFAULT_SETTINGS.lanBypassMacs = []` | 5 |
| `src/server/service.js` | flavor, `makeTun` → `TunOpenwrt`, `/usr/bin` in bin dirs, `bypassMacs` into `tun.start`, `net:lanDevices`, live apply in `settings:set`, `app:init` fields | 5 |
| `src/server/web-api.js` | `lanDevices` | 5 |
| `src/renderer/{index.html,app.js,i18n.js,settings.css}` | devices card, inspector row, hide desktop-only rows on the router | 6 |
| `openwrt/tar.js`, `openwrt/build-ipk.js` (new) | ustar writer/reader; the ipk builder | 7 |
| `openwrt/files/*` (new) | init script, uci config, uci-defaults, control scripts, LuCI menu/acl/view | 7 |
| `openwrt/ci/guest-smoke.sh`, `openwrt/ci/qemu-smoke.js` (new) | the QEMU integration test | 8 |
| `.github/workflows/test.yml`, `.github/workflows/release.yml` | QEMU job; ipk build + publish job | 8 |
| `docs/openwrt.md`, `README.md`, `docs/releases/v1.13.0.md`, versions | install guide, release | 9 |
| `tests/openwrtNet.test.js`, `tests/tunOpenwrt.test.js`, `tests/downloader.openwrt.test.js`, `tests/serviceOpenwrt.test.js`, `tests/openwrtPackage.test.js`, `tests/renderer.test.js` (+1), `tests/releaseWorkflow.test.js` (+1), `tests/syntax.test.js` (DIRS) | pins | 1–8 |

Order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9. Tasks 4 and 6 do not depend on 3; everything else is sequential.

---

### Task 1: `openwrtNet.js` — the pure helpers

**Files:**
- Create: `src/main/openwrtNet.js`
- Test: `tests/openwrtNet.test.js`

**Interfaces:**
- Produces (consumed by Tasks 2, 3, 5):
  - `BYPASS_MARK = 0x1f1e`, `BYPASS_RULE_PREF = 8999`, `NFT_TABLE = 'inet irnetfree'`
  - `isOpenwrt(env = process.env, exists = fs.existsSync): boolean`
  - `normalizeMac(s): string|null`, `validMacs(list): string[]` (lower-case, de-duplicated, order kept)
  - `parseDhcpLeases(text): [{ expires:number, mac, ip, name }]`
  - `parseNeigh(text): [{ ip, mac, online:boolean }]`
  - `mergeDevices(leases, neigh): [{ mac, ip, name, online }]` (online first, then name, then mac)
  - `buildNftRuleset({ lanIf, macs, mark }): string` (text for `nft -f`)
  - `bypassRuleArgs(verb: 'add'|'del', mark = BYPASS_MARK, pref = BYPASS_RULE_PREF): string[][]` (argv for `ip`, v4 then v6)

- [ ] **Step 1: Write the failing tests**

`tests/openwrtNet.test.js`:

```js
'use strict';
/**
 * The OpenWrt gateway's pure half: what the router's files and commands are
 * parsed into, and the exact kernel tables the backend writes. Nothing here
 * touches the machine — the same lines run on Windows, where the owner works.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('../src/main/openwrtNet');

test('isOpenwrt: the release file, or the env override the tests and QEMU use', () => {
  assert.equal(net.isOpenwrt({}, () => false), false);
  assert.equal(net.isOpenwrt({}, (p) => p === '/etc/openwrt_release'), true);
  assert.equal(net.isOpenwrt({ IRNETFREE_PLATFORM: 'openwrt' }, () => false), true);
  assert.equal(net.isOpenwrt({ IRNETFREE_PLATFORM: 'linux' }, () => false), false);
  // a throwing existsSync is "no"
  assert.equal(net.isOpenwrt({}, () => { throw new Error('EACCES'); }), false);
});

test('MACs: lower-cased, validated, de-duplicated, order kept — never interpolated raw into nft', () => {
  assert.equal(net.normalizeMac('AA:BB:CC:DD:EE:FF'), 'aa:bb:cc:dd:ee:ff');
  assert.equal(net.normalizeMac(' aa:bb:cc:dd:ee:ff '), 'aa:bb:cc:dd:ee:ff');
  assert.equal(net.normalizeMac('aa-bb-cc-dd-ee-ff'), null);
  assert.equal(net.normalizeMac('aa:bb:cc:dd:ee'), null);
  assert.equal(net.normalizeMac('aa:bb:cc:dd:ee:ff }; flush ruleset; #'), null);
  assert.equal(net.normalizeMac(null), null);
  assert.deepEqual(net.validMacs(['AA:BB:CC:DD:EE:FF', 'bad', 'aa:bb:cc:dd:ee:ff', '02:00:00:00:00:01']),
    ['aa:bb:cc:dd:ee:ff', '02:00:00:00:00:01']);
  assert.deepEqual(net.validMacs(undefined), []);
  assert.deepEqual(net.validMacs('aa:bb:cc:dd:ee:ff'), [], 'a string is not a list');
});

test('dhcp.leases: busybox dnsmasq lines, * for a nameless client, junk skipped', () => {
  const text = [
    '1758650000 aa:bb:cc:dd:ee:01 192.168.1.23 sadra-phone 01:aa:bb:cc:dd:ee:01',
    '1758650100 AA:BB:CC:DD:EE:02 192.168.1.40 * *',
    'duid 00:01:00:01:2b:...',
    '',
    'not a lease line'
  ].join('\n');
  assert.deepEqual(net.parseDhcpLeases(text), [
    { expires: 1758650000, mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.23', name: 'sadra-phone' },
    { expires: 1758650100, mac: 'aa:bb:cc:dd:ee:02', ip: '192.168.1.40', name: '' }
  ]);
  assert.deepEqual(net.parseDhcpLeases(''), []);
  assert.deepEqual(net.parseDhcpLeases(undefined), []);
});

test('ip neigh: REACHABLE/STALE/DELAY/PROBE/PERMANENT are online, FAILED/INCOMPLETE are not', () => {
  const text = [
    '192.168.1.23 lladdr aa:bb:cc:dd:ee:01 REACHABLE',
    '192.168.1.40 lladdr aa:bb:cc:dd:ee:02 STALE',
    '192.168.1.41 lladdr aa:bb:cc:dd:ee:03 FAILED',
    '192.168.1.42  INCOMPLETE',
    'fe80::1 lladdr aa:bb:cc:dd:ee:01 router REACHABLE'
  ].join('\n');
  assert.deepEqual(net.parseNeigh(text), [
    { ip: '192.168.1.23', mac: 'aa:bb:cc:dd:ee:01', online: true },
    { ip: '192.168.1.40', mac: 'aa:bb:cc:dd:ee:02', online: true },
    { ip: '192.168.1.41', mac: 'aa:bb:cc:dd:ee:03', online: false },
    { ip: 'fe80::1', mac: 'aa:bb:cc:dd:ee:01', online: true }
  ]);
});

test('mergeDevices: one row per MAC, the lease names it, the neighbour table says it is here', () => {
  const leases = net.parseDhcpLeases([
    '1 aa:bb:cc:dd:ee:01 192.168.1.23 sadra-phone *',
    '1 aa:bb:cc:dd:ee:02 192.168.1.40 * *',
    '1 aa:bb:cc:dd:ee:04 192.168.1.50 old-laptop *'
  ].join('\n'));
  const neigh = net.parseNeigh([
    '192.168.1.23 lladdr aa:bb:cc:dd:ee:01 REACHABLE',
    'fe80::1 lladdr aa:bb:cc:dd:ee:01 REACHABLE',
    '192.168.1.40 lladdr aa:bb:cc:dd:ee:02 FAILED',
    '192.168.1.99 lladdr aa:bb:cc:dd:ee:03 STALE'
  ].join('\n'));
  assert.deepEqual(net.mergeDevices(leases, neigh), [
    // online first (by name, then mac), then the rest by name
    { mac: 'aa:bb:cc:dd:ee:03', ip: '192.168.1.99', name: '', online: true },
    { mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.23', name: 'sadra-phone', online: true },
    { mac: 'aa:bb:cc:dd:ee:02', ip: '192.168.1.40', name: '', online: false },
    { mac: 'aa:bb:cc:dd:ee:04', ip: '192.168.1.50', name: 'old-laptop', online: false }
  ]);
  assert.deepEqual(net.mergeDevices([], []), []);
});

test('the nft ruleset: atomic replace, one set, one mangle rule; byte-exact', () => {
  const two = net.buildNftRuleset({ lanIf: 'br-lan', macs: ['AA:BB:CC:DD:EE:01', 'aa:bb:cc:dd:ee:02', 'garbage'] });
  assert.equal(two, [
    'table inet irnetfree',
    'delete table inet irnetfree',
    'table inet irnetfree {',
    '  set bypass_macs { type ether_addr; elements = { aa:bb:cc:dd:ee:01, aa:bb:cc:dd:ee:02 }; }',
    '  chain pre {',
    '    type filter hook prerouting priority mangle; policy accept;',
    '    iifname "br-lan" ether saddr @bypass_macs meta mark set 0x1f1e counter',
    '  }',
    '}',
    ''
  ].join('\n'));
  // no exclusions: the set still exists, so a later add has something to add to
  const none = net.buildNftRuleset({ lanIf: 'br-lan', macs: [] });
  assert.match(none, /set bypass_macs \{ type ether_addr; \}/);
  assert.doesNotMatch(none, /elements/);
  // defaults: br-lan and the shared mark
  assert.equal(net.buildNftRuleset(), none);
  // an interface name is a token, never a quote-breaker
  assert.match(net.buildNftRuleset({ lanIf: 'br-lan" } ; flush ruleset; "' }), /iifname "br-lanflushruleset"/);
  assert.match(net.buildNftRuleset({ lanIf: '' }), /iifname "br-lan"/);
  assert.match(net.buildNftRuleset({ mark: 0x2a }), /mark set 0x2a counter/);
});

test('the bypass rule sits before every sing-box rule and points marked packets at main', () => {
  assert.deepEqual(net.bypassRuleArgs('add'), [
    ['-4', 'rule', 'add', 'pref', '8999', 'fwmark', '0x1f1e', 'lookup', 'main'],
    ['-6', 'rule', 'add', 'pref', '8999', 'fwmark', '0x1f1e', 'lookup', 'main']
  ]);
  assert.deepEqual(net.bypassRuleArgs('del')[0], ['-4', 'rule', 'del', 'pref', '8999', 'fwmark', '0x1f1e', 'lookup', 'main']);
  assert.ok(net.BYPASS_RULE_PREF < 9000, 'sing-box starts its rules at iproute2_rule_index 9000');
  assert.throws(() => net.bypassRuleArgs('flush'), /add or del/);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test tests/openwrtNet.test.js`
Expected: FAIL — `Cannot find module '../src/main/openwrtNet'`

- [ ] **Step 3: Write the module**

`src/main/openwrtNet.js`:

```js
'use strict';
/**
 * OpenWrt: the LAN behind the router as a list of devices, and the two kernel
 * tables the gateway backend writes around sing-box (see tunOpenwrt.js).
 *
 * How the exclusion works. sing-box's `auto_route` on Linux ends its rule set
 * with `not iif lo → lookup 2022`, so every packet the router FORWARDS from the
 * LAN is routed into the TUN — that is what makes the router the tunnel for
 * every device without touching any of them. A device the user wants direct
 * needs its packets to escape that rule: the nft chain below marks packets by
 * source MAC, and one `ip rule` with a LOWER preference than sing-box's (8999
 * against its 9000+) sends marked packets to the main table, i.e. out the WAN
 * with fw4's normal NAT. Nothing about sing-box's own tables is edited.
 *
 * Everything in this file is pure or takes its I/O as parameters, so the tests
 * run where the owner works (Windows) and the only thing left to prove on a
 * router is that the kernel accepts the text — which the QEMU job does.
 */
const fs = require('fs');

/** Packets from excluded devices carry this mark; matches nothing sing-box uses. */
const BYPASS_MARK = 0x1f1e;
/** Below sing-box's default `iproute2_rule_index` (9000): evaluated before its rules. */
const BYPASS_RULE_PREF = 8999;
const NFT_TABLE = 'inet irnetfree';

/**
 * Are we on an OpenWrt box? `/etc/openwrt_release` is the distro's own marker.
 * The env override is for the unit tests and for images built from another
 * root (a QEMU test image, a container) — never set it on a desktop.
 */
function isOpenwrt(env = process.env, exists = fs.existsSync) {
  if (env.IRNETFREE_PLATFORM === 'openwrt') return true;
  try { return !!exists('/etc/openwrt_release'); } catch { return false; }
}

const MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;

/** `aa:bb:cc:dd:ee:ff` lower-cased, or null. The only shape that ever reaches nft. */
function normalizeMac(s) {
  const m = String(s == null ? '' : s).trim().toLowerCase();
  return MAC_RE.test(m) ? m : null;
}

/** The user's list, cleaned: invalid entries dropped, duplicates dropped, order kept. */
function validMacs(list) {
  const out = [];
  const seen = new Set();
  for (const x of (Array.isArray(list) ? list : [])) {
    const m = normalizeMac(x);
    if (!m || seen.has(m)) continue;
    seen.add(m);
    out.push(m);
  }
  return out;
}

/**
 * dnsmasq's /tmp/dhcp.leases: `<expiry> <mac> <ip> <hostname|*> <client-id|*>`.
 * A line that does not start with a number and a MAC (the `duid` line, blanks)
 * is skipped.
 */
function parseDhcpLeases(text) {
  const out = [];
  for (const raw of String(text || '').split(/\r?\n/)) {
    const f = raw.trim().split(/\s+/);
    if (f.length < 3) continue;
    const mac = normalizeMac(f[1]);
    if (!mac || !/^\d+$/.test(f[0])) continue;
    out.push({ expires: parseInt(f[0], 10), mac, ip: f[2], name: (f[3] && f[3] !== '*') ? f[3] : '' });
  }
  return out;
}

/** Neighbour states that mean "this device answered recently". */
const ONLINE = new Set(['REACHABLE', 'STALE', 'DELAY', 'PROBE', 'PERMANENT']);

/** `ip neigh show dev <lan>`: `<ip> lladdr <mac> [router] <STATE>`; lines with no MAC skipped. */
function parseNeigh(text) {
  const out = [];
  for (const raw of String(text || '').split(/\r?\n/)) {
    const f = raw.trim().split(/\s+/);
    if (f.length < 2) continue;
    const i = f.indexOf('lladdr');
    const mac = i > 0 ? normalizeMac(f[i + 1]) : null;
    if (!mac) continue;
    out.push({ ip: f[0], mac, online: ONLINE.has(f[f.length - 1]) });
  }
  return out;
}

/**
 * One row per MAC. The lease names it and gives its address; the neighbour
 * table says whether it is here now (any online entry wins, so a device seen
 * on v4 and v6 is online once). A device only in the neighbour table (static
 * IP, no lease) is still a device. Online first, then by name, then by MAC —
 * the order the list is shown in.
 */
function mergeDevices(leases, neigh) {
  const byMac = new Map();
  for (const l of leases || []) byMac.set(l.mac, { mac: l.mac, ip: l.ip || '', name: l.name || '', online: false });
  for (const n of neigh || []) {
    const cur = byMac.get(n.mac) || { mac: n.mac, ip: '', name: '', online: false };
    // prefer a v4 address for display; a v6-only neighbour keeps its v6
    if (!cur.ip || (cur.ip.includes(':') && !n.ip.includes(':'))) cur.ip = n.ip;
    cur.online = cur.online || n.online;
    byMac.set(n.mac, cur);
  }
  return [...byMac.values()].sort((a, b) =>
    (Number(b.online) - Number(a.online)) || a.name.localeCompare(b.name) || a.mac.localeCompare(b.mac));
}

/**
 * The text for `nft -f`. The first two lines make the load an atomic replace:
 * `table` creates it if missing (so `delete` cannot fail), `delete` drops the
 * old contents, and the block recreates it — one transaction, no window with
 * no table. An empty exclusion list still declares the set, so a later
 * `add element` has something to add to.
 */
function buildNftRuleset({ lanIf = 'br-lan', macs = [], mark = BYPASS_MARK } = {}) {
  const list = validMacs(macs);
  const ifName = String(lanIf == null ? '' : lanIf).replace(/[^A-Za-z0-9_.-]/g, '') || 'br-lan';
  const hex = '0x' + Number(mark).toString(16);
  const elements = list.length ? ` elements = { ${list.join(', ')} };` : '';
  return [
    `table ${NFT_TABLE}`,
    `delete table ${NFT_TABLE}`,
    `table ${NFT_TABLE} {`,
    `  set bypass_macs { type ether_addr;${elements} }`,
    '  chain pre {',
    '    type filter hook prerouting priority mangle; policy accept;',
    `    iifname "${ifName}" ether saddr @bypass_macs meta mark set ${hex} counter`,
    '  }',
    '}',
    ''
  ].join('\n');
}

/** argv for busybox `ip`, v4 then v6: the one rule that lets marked packets out through main. */
function bypassRuleArgs(verb, mark = BYPASS_MARK, pref = BYPASS_RULE_PREF) {
  if (verb !== 'add' && verb !== 'del') throw new Error('bypassRuleArgs: verb must be add or del');
  const hex = '0x' + Number(mark).toString(16);
  return ['-4', '-6'].map(fam => [fam, 'rule', verb, 'pref', String(pref), 'fwmark', hex, 'lookup', 'main']);
}

module.exports = {
  BYPASS_MARK, BYPASS_RULE_PREF, NFT_TABLE,
  isOpenwrt, normalizeMac, validMacs, parseDhcpLeases, parseNeigh, mergeDevices,
  buildNftRuleset, bypassRuleArgs
};
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test tests/openwrtNet.test.js`
Expected: `# pass 7`, `# fail 0`

- [ ] **Step 5: Commit**

```bash
git add src/main/openwrtNet.js tests/openwrtNet.test.js
git commit -m "openwrt: the LAN as devices, and the nft/ip-rule text that lets a device around the tunnel (pure)"
```

---

### Task 2: `openwrtNet.js` — the readers (`lanInterface`, `lanDevices`)

**Files:**
- Modify: `src/main/openwrtNet.js` (append before `module.exports`, extend exports)
- Test: `tests/openwrtNet.test.js` (append)

**Interfaces:**
- Consumes: Task 1's parsers; `run(cmd, args) → Promise<string>` in the shape of `tunPlatform.run`.
- Produces (Task 5 uses both):
  - `lanInterface(run): Promise<string>` — `ubus call network.interface.lan status` → `.l3_device`, else `'br-lan'`; never throws.
  - `lanDevices({ readFile, run, lanIf }): Promise<[{ mac, ip, name, online }]>` — never throws; missing file / failing command → that source contributes nothing.

- [ ] **Step 1: Append the failing tests**

Append to `tests/openwrtNet.test.js`:

```js
test('lanInterface: ubus names the LAN device; anything else means br-lan', async () => {
  const ubus = async (cmd, args) => {
    assert.equal(cmd, 'ubus');
    assert.deepEqual(args, ['call', 'network.interface.lan', 'status']);
    return JSON.stringify({ up: true, l3_device: 'br-lan0', device: 'br-lan0' });
  };
  assert.equal(await net.lanInterface(ubus), 'br-lan0');
  assert.equal(await net.lanInterface(async () => 'not json'), 'br-lan');
  assert.equal(await net.lanInterface(async () => JSON.stringify({ up: false })), 'br-lan');
  assert.equal(await net.lanInterface(async () => { throw new Error('ubus: not found'); }), 'br-lan');
});

test('lanDevices: leases + neighbours, each source optional, and the exact commands used', async () => {
  const calls = [];
  const devices = await net.lanDevices({
    lanIf: 'br-lan',
    readFile: async (p) => { calls.push(['read', p]); return '1 aa:bb:cc:dd:ee:01 192.168.1.23 phone *\n'; },
    run: async (cmd, args) => { calls.push([cmd, ...args]); return '192.168.1.23 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n192.168.1.9 lladdr aa:bb:cc:dd:ee:09 STALE\n'; }
  });
  assert.deepEqual(calls, [['read', '/tmp/dhcp.leases'], ['ip', 'neigh', 'show', 'dev', 'br-lan']]);
  assert.deepEqual(devices, [
    { mac: 'aa:bb:cc:dd:ee:01', ip: '192.168.1.23', name: 'phone', online: true },
    { mac: 'aa:bb:cc:dd:ee:09', ip: '192.168.1.9', name: '', online: true }
  ]);
  // no lease file yet (fresh router), neighbour command missing: an empty list, not an error
  assert.deepEqual(await net.lanDevices({
    readFile: async () => { throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); },
    run: async () => { throw new Error('ip: not found'); }
  }), []);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test tests/openwrtNet.test.js`
Expected: FAIL — `net.lanInterface is not a function`

- [ ] **Step 3: Add the readers**

Insert before `module.exports` in `src/main/openwrtNet.js`:

```js
/**
 * The LAN's L3 device, as netifd names it (`br-lan` on every stock image, but
 * a renamed or VLAN'd LAN says otherwise). `run` is tunPlatform.run's shape.
 * Never throws: a router with no ubus answer still gets the default.
 */
async function lanInterface(run) {
  try {
    const out = await run('ubus', ['call', 'network.interface.lan', 'status']);
    const j = JSON.parse(out);
    if (j && typeof j.l3_device === 'string' && j.l3_device) return j.l3_device;
  } catch { /* fall through */ }
  return 'br-lan';
}

/**
 * The devices behind the router right now: DHCP leases (names, addresses) and
 * the neighbour table on the LAN device (who is actually here). Either source
 * may be missing — a fresh router has no lease file yet — and contributes
 * nothing then. Never throws.
 */
async function lanDevices({ readFile = (p) => fs.promises.readFile(p, 'utf8'), run, lanIf = 'br-lan' } = {}) {
  let leases = [];
  try { leases = parseDhcpLeases(await readFile('/tmp/dhcp.leases')); } catch { /* no leases yet */ }
  let neigh = [];
  try { if (run) neigh = parseNeigh(await run('ip', ['neigh', 'show', 'dev', lanIf])); } catch { /* no neighbour table */ }
  return mergeDevices(leases, neigh);
}
```

and extend the export list: `buildNftRuleset, bypassRuleArgs, lanInterface, lanDevices`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test tests/openwrtNet.test.js`
Expected: `# pass 9`, `# fail 0`

- [ ] **Step 5: Commit**

```bash
git add src/main/openwrtNet.js tests/openwrtNet.test.js
git commit -m "openwrt: read the LAN device from ubus and the devices from leases + neighbours, with the I/O injected"
```

---

### Task 3: `TunOpenwrt` — the gateway backend

**Files:**
- Create: `src/main/tunOpenwrt.js`
- Test: `tests/tunOpenwrt.test.js`

**Interfaces:**
- Consumes: `TunSingbox` (`src/main/tunSingbox.js`: `start(socksPort, bypassAddrs, dnsServers, opts)`, `stop()`, `cleanupSync()`, `isAvailable()`, `isElevated()`, `physicalInterface()`, `interfaceName`, `dnsPeer`, `dnsPeer6`, `excludeIps`, `active`, `lang`), Task 1/2 helpers, `tunPlatform.run`.
- Produces (Task 5 drives it through the same contract as the other backends):
  - `class TunOpenwrt` with `backendId = 'openwrt'`, `managesDns = true`, `interfaceName`, `dnsPeer`, `dnsPeer6`, `active`, `excludeIps`, `lang`
  - `isAvailable()`, `isElevated()`, `prepare(o)`, `physicalInterface()`
  - `start(socksPort, bypassAddrs, dnsServers, opts)` — reads `opts.bypassMacs`
  - `stop()`, `cleanupSync()`, `setBypassMacs(macs): Promise<void>`
  - constructor `opts` extras for tests: `inner`, `run(cmd, args)`, `runSync(cmd, args)`, `writeFile(path, text)`, `lanInterface()`, `which(name)`, `tmpDir`

`managesDns = true` is deliberate: the service reads it as "the backend owns DNS, do not engage the leak guard" (`if (!tun?.managesDns) leakGuard.holdForReconnect…`, `myTun.active && !myTun.managesDns && …engage`). The router's dnsmasq must be left alone; the port-53 route into the tunnel is the guard here.

- [ ] **Step 1: Write the failing tests**

`tests/tunOpenwrt.test.js`:

```js
'use strict';
/**
 * The OpenWrt gateway backend, with the sing-box backend and every command
 * faked: the tests pin the ORDER of the steps (nft table, ip rules, sing-box,
 * verify), the rollback at each failure, the live set replacement that never
 * touches the tunnel, and that DNS is declared the backend's own.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { TunOpenwrt } = require('../src/main/tunOpenwrt');
const net = require('../src/main/openwrtNet');

/** A fake TunSingbox: records calls; `failStart` makes start() throw. */
function fakeInner({ available = true, failStart = false } = {}) {
  return {
    calls: [],
    active: false,
    excludeIps: [],
    interfaceName: 'IRNetFree',
    dnsPeer: '172.19.0.2',
    dnsPeer6: 'fdfe:dcba:9876::2',
    lang: 'fa',
    isAvailable: () => available,
    isElevated: () => true,
    prepare: async (o) => { },
    physicalInterface: async () => ({ name: 'eth0', ifIndex: null, gateway: '192.168.1.2' }),
    async start(socksPort, bypass, dns, opts) {
      this.calls.push(['start', socksPort, bypass, opts]);
      if (failStart) throw new Error('sing-box exited immediately');
      this.active = true; this.excludeIps = ['1.2.3.4/32'];
    },
    async stop() { this.calls.push(['stop']); this.active = false; this.excludeIps = []; },
    cleanupSync() { this.calls.push(['cleanupSync']); }
  };
}

/** A fake command runner: `answers` maps a regex over "cmd args…" to stdout or an Error. */
function fakeRun(answers = []) {
  const lines = [];
  const run = async (cmd, args) => {
    const line = [cmd, ...args].join(' ');
    lines.push(line);
    for (const [re, out] of answers) if (re.test(line)) { if (out instanceof Error) throw out; return out; }
    return '';
  };
  return { run, lines };
}

const RULES_OK = '0:\tfrom all lookup local\n9000:\tfrom all to 172.19.0.0/30 lookup 2022\n9002:\tnot from all iif lo lookup 2022\n32766:\tfrom all lookup main\n';

function make(opts = {}) {
  const inner = opts.inner || fakeInner();
  const { run, lines } = fakeRun(opts.answers || [[/^ip rule show/, RULES_OK]]);
  const writes = [];
  const logs = [];
  const tun = new TunOpenwrt({
    inner, run,
    runSync: (cmd, args) => { lines.push('SYNC ' + [cmd, ...args].join(' ')); },
    writeFile: (p, text) => { writes.push([p, text]); },
    lanInterface: async () => 'br-lan',
    which: (name) => opts.which ? opts.which(name) : true,
    onLog: (line, level) => logs.push([level, line]),
    lang: 'en', tmpDir: '/tmp/irnf-test'
  });
  return { tun, inner, lines, writes, logs };
}

test('contract: the fields the service reads, and DNS declared as the backend’s own', () => {
  const { tun } = make();
  assert.equal(tun.backendId, 'openwrt');
  assert.equal(tun.managesDns, true, 'the leak guard must not touch the router’s resolver');
  assert.equal(tun.interfaceName, 'IRNetFree');
  assert.equal(tun.dnsPeer, '172.19.0.2');
  assert.equal(tun.dnsPeer6, 'fdfe:dcba:9876::2');
  assert.equal(tun.active, false);
  assert.deepEqual(tun.excludeIps, []);
});

test('isAvailable: sing-box present AND nft on PATH', () => {
  assert.equal(make().tun.isAvailable(), true);
  assert.equal(make({ inner: fakeInner({ available: false }) }).tun.isAvailable(), false);
  assert.equal(make({ which: (n) => n !== 'nft' }).tun.isAvailable(), false);
});

test('start: nft table, then the bypass rules, then sing-box, then verify — in that order, with the MACs', async () => {
  const { tun, inner, lines, writes, logs } = make();
  await tun.start(10808, ['1.2.3.4'], ['172.19.0.2'], { ipv6: false, strict: false, apps: null, bypassMacs: ['AA:BB:CC:DD:EE:01', 'bad'] });
  assert.equal(tun.active, true);
  assert.deepEqual(tun.excludeIps, ['1.2.3.4/32'], 'the live bypass list is the inner backend’s');
  // the ruleset went to a file and nft read it
  assert.equal(writes.length, 1);
  assert.equal(writes[0][0], '/tmp/irnf-test/irnetfree-nft.conf');
  assert.equal(writes[0][1], net.buildNftRuleset({ lanIf: 'br-lan', macs: ['aa:bb:cc:dd:ee:01'] }));
  assert.deepEqual(lines, [
    'nft -f /tmp/irnf-test/irnetfree-nft.conf',
    'ip -4 rule del pref 8999 fwmark 0x1f1e lookup main',   // idempotent: clear a leftover first
    'ip -6 rule del pref 8999 fwmark 0x1f1e lookup main',
    'ip -4 rule add pref 8999 fwmark 0x1f1e lookup main',
    'ip -6 rule add pref 8999 fwmark 0x1f1e lookup main',
    'ip link show IRNetFree',
    'ip rule show'
  ]);
  assert.deepEqual(inner.calls[0], ['start', 10808, ['1.2.3.4'], { ipv6: false, strict: false, apps: null, bypassMacs: ['AA:BB:CC:DD:EE:01', 'bad'] }]);
  assert.equal(inner.lang, 'en', 'the language the service set is handed down');
  assert.ok(logs.some(([, l]) => /Gateway up on br-lan.*1 excluded/.test(l)), JSON.stringify(logs));
  // a second start is a no-op while active
  await tun.start(10808, [], [], {});
  assert.equal(inner.calls.filter(c => c[0] === 'start').length, 1);
});

test('start fails at nft: nothing else runs, the error names the step', async () => {
  const { tun, inner, lines } = make({ answers: [[/^nft -f/, new Error('nft: command not found')]] });
  await assert.rejects(tun.start(10808, [], [], {}), /Gateway did not come up \(nft\): nft: command not found/);
  assert.equal(tun.active, false);
  assert.equal(inner.calls.length, 0, 'sing-box was never started');
  // rollback still clears what might be there
  assert.ok(lines.includes('ip -4 rule del pref 8999 fwmark 0x1f1e lookup main'));
  assert.ok(lines.includes('nft delete table inet irnetfree'));
});

test('start fails inside sing-box: the table and rules are rolled back', async () => {
  const { tun, inner, lines } = make({ inner: fakeInner({ failStart: true }) });
  await assert.rejects(tun.start(10808, [], [], {}), /\(sing-box\): sing-box exited immediately/);
  assert.equal(tun.active, false);
  assert.deepEqual(inner.calls.map(c => c[0]), ['start', 'stop']);
  assert.equal(lines[lines.length - 1], 'nft delete table inet irnetfree');
  assert.ok(lines.filter(l => l === 'ip -4 rule del pref 8999 fwmark 0x1f1e lookup main').length >= 2, 'cleared before add, and again on rollback');
});

test('verify: no TUN device, or no sing-box rule, is a failure with the rule dump in it', async () => {
  const noLink = make({ answers: [[/^ip link show IRNetFree/, new Error('Device "IRNetFree" does not exist.')]] });
  await assert.rejects(noLink.tun.start(10808, [], [], {}), /\(verify\): Device "IRNetFree" does not exist/);
  assert.deepEqual(noLink.inner.calls.map(c => c[0]), ['start', 'stop']);

  const noRule = make({ answers: [[/^ip rule show/, '0:\tfrom all lookup local\n32766:\tfrom all lookup main\n']] });
  await assert.rejects(noRule.tun.start(10808, [], [], {}), /\(verify\): sing-box laid no policy route[\s\S]*32766/);
});

test('setBypassMacs while active replaces the set and leaves the tunnel alone; while inactive it only remembers', async () => {
  const { tun, inner, lines, writes } = make();
  await tun.setBypassMacs(['aa:bb:cc:dd:ee:02']);
  assert.equal(lines.length, 0, 'nothing runs before the tunnel is up');
  await tun.start(10808, [], [], { bypassMacs: [] });
  const before = inner.calls.length;
  lines.length = 0; writes.length = 0;
  await tun.setBypassMacs(['aa:bb:cc:dd:ee:03', 'AA:BB:CC:DD:EE:03']);
  assert.deepEqual(lines, ['nft -f /tmp/irnf-test/irnetfree-nft.conf']);
  assert.match(writes[0][1], /elements = \{ aa:bb:cc:dd:ee:03 \};/);
  assert.equal(inner.calls.length, before, 'sing-box untouched');
  assert.equal(tun.active, true);
});

test('stop: sing-box first, then the rules and the table; a second stop is a no-op', async () => {
  const { tun, inner, lines } = make();
  await tun.start(10808, [], [], {});
  lines.length = 0;
  await tun.stop();
  assert.equal(tun.active, false);
  assert.deepEqual(tun.excludeIps, []);
  assert.deepEqual(inner.calls.map(c => c[0]), ['start', 'stop']);
  assert.deepEqual(lines, [
    'ip -4 rule del pref 8999 fwmark 0x1f1e lookup main',
    'ip -6 rule del pref 8999 fwmark 0x1f1e lookup main',
    'nft delete table inet irnetfree'
  ]);
  lines.length = 0;
  await tun.stop();
  assert.deepEqual(lines, []);
});

test('stop keeps going when a delete fails (nothing to delete is the common case)', async () => {
  const { tun, lines } = make({ answers: [
    [/^ip rule show/, RULES_OK],
    [/^ip -4 rule del/, new Error('RTNETLINK answers: No such file or directory')],
    [/^nft delete/, new Error('Error: No such file or directory')]
  ] });
  await tun.start(10808, [], [], {});
  await tun.stop();
  assert.ok(lines.includes('ip -6 rule del pref 8999 fwmark 0x1f1e lookup main'));
  assert.ok(lines.includes('nft delete table inet irnetfree'));
});

test('cleanupSync: the synchronous best effort for process exit, inner first', () => {
  const { tun, inner, lines } = make();
  tun.cleanupSync();
  assert.deepEqual(inner.calls, [['cleanupSync']]);
  assert.deepEqual(lines, [
    'SYNC ip -4 rule del pref 8999 fwmark 0x1f1e lookup main',
    'SYNC ip -6 rule del pref 8999 fwmark 0x1f1e lookup main',
    'SYNC nft delete table inet irnetfree'
  ]);
});

test('the pass-throughs the service calls', async () => {
  const { tun } = make();
  assert.equal(tun.isElevated(), true);
  assert.deepEqual(await tun.physicalInterface(), { name: 'eth0', ifIndex: null, gateway: '192.168.1.2' });
  await tun.prepare({ strict: false });   // must not throw
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test tests/tunOpenwrt.test.js`
Expected: FAIL — `Cannot find module '../src/main/tunOpenwrt'`

- [ ] **Step 3: Write the backend**

`src/main/tunOpenwrt.js`:

```js
'use strict';
/**
 * TUN mode on an OpenWrt router: the router is the tunnel for every device
 * behind it.
 *
 * This backend COMPOSES the sing-box one (tunSingbox.js) rather than changing
 * it: sing-box's `auto_route` already routes forwarded LAN traffic into the TUN
 * on Linux (sing-tun's rule set ends in `not iif lo → lookup 2022`), and every
 * port-53 packet with it — so dnsmasq's upstream queries and every client's
 * hard-coded resolver end up at Xray's dns-out without a line of DNS config.
 * What a router adds is around that:
 *
 *   1. an nft table of ours (openwrtNet.buildNftRuleset) that marks packets
 *      from EXCLUDED devices by source MAC, and
 *   2. one `ip rule` (pref 8999, before sing-box's 9000+) that sends marked
 *      packets to the main table — out the WAN, with fw4's normal NAT;
 *   3. a check, after sing-box is up, that the TUN device exists and the
 *      policy route is really there — a gateway that silently is not one
 *      leaks the whole house.
 *
 * Order on start: table → rules → sing-box → verify; any failure rolls back
 * in reverse and the error names the step. The exclusion list is replaced
 * LIVE (atomic nft reload) without touching the tunnel.
 *
 * `managesDns = true`: the service then leaves the leak guard out. The guard
 * rewrites adapter resolvers; on a router the resolver is dnsmasq, which must
 * stay exactly as it is — the port-53 route above is the guard here.
 *
 * Fail-closed on a dead core, fail-open on a dead sing-box: routes into the
 * TUN survive an Xray crash (traffic stops, nothing leaks); a sing-box crash
 * removes its own routes and the LAN goes direct until the service's recovery
 * rebuilds it. A kill switch that closes that window is deliberately not in
 * this version (spec §9).
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const platform = require('./tunPlatform');
const { TunSingbox } = require('./tunSingbox');
const net = require('./openwrtNet');

/** sing-box's default `iproute2_table_index`; its rules must mention it. */
const SINGBOX_TABLE = 2022;
const VERIFY_WAIT_MS = 4000;

function defaultWhich(name) {
  return String(process.env.PATH || '').split(path.delimiter).some(d => d && fs.existsSync(path.join(d, name)));
}

class TunOpenwrt {
  constructor(opts = {}) {
    this.inner = opts.inner || new TunSingbox(opts);
    this.run = opts.run || platform.run;
    this.runSync = opts.runSync || ((cmd, args) => execFileSync(cmd, args, { stdio: 'ignore', timeout: 5000 }));
    this.writeFile = opts.writeFile || ((p, text) => fs.writeFileSync(p, text, { mode: 0o600 }));
    this.lanInterface = opts.lanInterface || (() => net.lanInterface(this.run));
    this.which = opts.which || defaultWhich;
    this.onLog = opts.onLog || (() => {});
    this.lang = opts.lang || 'fa';
    this.tmpDir = opts.tmpDir || os.tmpdir();

    this.backendId = 'openwrt';
    this.managesDns = true;
    this.interfaceName = this.inner.interfaceName;
    this.dnsPeer = this.inner.dnsPeer;
    this.dnsPeer6 = this.inner.dnsPeer6;
    this.active = false;
    this.excludeIps = [];
    this.macs = [];
    this.lanIf = 'br-lan';
    this.mark = net.BYPASS_MARK;
  }

  msg(fa, en) { return this.lang === 'en' ? en : fa; }

  isAvailable() { return this.inner.isAvailable() && this.which('nft'); }
  isElevated() { return this.inner.isElevated(); }
  prepare(o) { return typeof this.inner.prepare === 'function' ? this.inner.prepare(o) : undefined; }
  physicalInterface() { return this.inner.physicalInterface(); }

  /* ----------------------------- the router's two tables ----------------------------- */

  /** Atomic replace of our nft table with the given exclusions. */
  async applyTable(macs) {
    const file = path.join(this.tmpDir, 'irnetfree-nft.conf');
    this.writeFile(file, net.buildNftRuleset({ lanIf: this.lanIf, macs, mark: this.mark }));
    await this.run('nft', ['-f', file]);
  }

  /** The bypass rule, added after clearing any leftover so a restart never doubles it. */
  async addRules() {
    await this.delRules();
    for (const args of net.bypassRuleArgs('add', this.mark)) await this.run('ip', args);
  }

  async delRules() {
    for (const args of net.bypassRuleArgs('del', this.mark)) {
      try { await this.run('ip', args); } catch { /* not there — the common case */ }
    }
  }

  async deleteTable() {
    try { await this.run('nft', ['delete', 'table', 'inet', 'irnetfree']); } catch { /* not there */ }
  }

  /** The device exists and sing-box's policy route is in place — else the LAN is not tunnelled. */
  async verify() {
    const deadline = Date.now() + VERIFY_WAIT_MS;
    let lastErr = null;
    for (;;) {
      try { await this.run('ip', ['link', 'show', this.interfaceName]); lastErr = null; break; }
      catch (e) { lastErr = e; if (Date.now() >= deadline) break; await platform.delay(250); }
    }
    if (lastErr) throw lastErr;
    const rules = await this.run('ip', ['rule', 'show']);
    if (!new RegExp(`lookup ${SINGBOX_TABLE}\\b`).test(rules)) {
      throw new Error(`sing-box laid no policy route (ip rule):\n${String(rules).trim()}`);
    }
  }

  async rollback() {
    try { await this.inner.stop(); } catch { /* best effort */ }
    await this.delRules();
    await this.deleteTable();
  }

  /* ----------------------------- public API ----------------------------- */

  /**
   * @param socksPort   Xray's local SOCKS inbound
   * @param bypassAddrs server addresses kept off the tunnel (route_exclude_address)
   * @param dnsServers  ignored here, as on Linux: dnsmasq is left alone
   * @param opts        { ipv6, strict, apps, bypassMacs } — bypassMacs is the router's own
   */
  async start(socksPort, bypassAddrs, dnsServers, opts = {}) {
    if (this.active) return;
    const o = opts || {};
    this.inner.lang = this.lang;
    this.lanIf = await this.lanInterface();
    this.macs = net.validMacs(o.bypassMacs);
    let step = 'nft';
    try {
      await this.applyTable(this.macs);
      step = 'ip rule';
      await this.addRules();
      step = 'sing-box';
      await this.inner.start(socksPort, bypassAddrs, dnsServers, o);
      step = 'verify';
      await this.verify();
    } catch (e) {
      await this.rollback();
      throw new Error(this.msg(
        `گیت‌وی بالا نیامد (${step}): ${e.message}`,
        `Gateway did not come up (${step}): ${e.message}`));
    }
    this.active = true;
    this.excludeIps = this.inner.excludeIps;
    this.onLog(`Gateway up on ${this.lanIf}: every device behind the router goes through the tunnel; ${this.macs.length} excluded by MAC`, 'info');
  }

  /** Replace the exclusions under a live tunnel; the tunnel is not touched. */
  async setBypassMacs(macs) {
    this.macs = net.validMacs(macs);
    if (!this.active) return;
    await this.applyTable(this.macs);
    this.onLog(`Gateway: ${this.macs.length} device(s) excluded by MAC`, 'info');
  }

  async stop() {
    if (!this.active && !this.inner.active) return;
    this.active = false;
    this.excludeIps = [];
    try { await this.inner.stop(); }
    finally {
      await this.delRules();
      await this.deleteTable();
    }
    this.onLog('Gateway stopped: the LAN goes direct.', 'info');
  }

  /** Synchronous best effort for process exit. */
  cleanupSync() {
    try { this.inner.cleanupSync(); } catch { /* best effort */ }
    for (const args of net.bypassRuleArgs('del', this.mark)) { try { this.runSync('ip', args); } catch { /* not there */ } }
    try { this.runSync('nft', ['delete', 'table', 'inet', 'irnetfree']); } catch { /* not there */ }
  }
}

module.exports = { TunOpenwrt, SINGBOX_TABLE };
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test tests/tunOpenwrt.test.js`
Expected: `# pass 11`, `# fail 0`. Then `npm test` — every earlier test still green (the new module is not yet required by anything).

- [ ] **Step 5: Commit**

```bash
git add src/main/tunOpenwrt.js tests/tunOpenwrt.test.js
git commit -m "openwrt: the gateway backend — sing-box TUN for the whole LAN, an nft set and one ip rule for the devices that go direct"
```

---

### Task 4: the Linux arch table in the downloader

**Files:**
- Modify: `src/main/downloader.js:154-165` and `:181-186` (the three pickers)
- Test: `tests/downloader.openwrt.test.js`

**Interfaces:**
- Consumes: nothing new. `os.arch()` returns `'arm'` on the AC-1304 (32-bit ARMv7), `'arm64'`, `'mips'`, `'mipsel'` elsewhere.
- Produces: the same three methods with the same signatures; new return values for `arm`/`mips`/`mipsel` on `linux`. Existing rows byte-identical (the darwin test pins them).

- [ ] **Step 1: Write the failing tests**

`tests/downloader.openwrt.test.js`:

```js
'use strict';
/**
 * Which release asset the downloader picks on a router. The Google Wifi
 * AC-1304 is 32-bit ARMv7 (`os.arch()` → 'arm'); nobody here can download on
 * it, so the names are pinned against what the three upstream release pages
 * publish — copied verbatim from patterniha/Xray-core v26.9.13 (identical
 * names on XTLS/Xray-core), sing-box and xjasonlyu/tun2socks.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Downloader } = require('../src/main/downloader');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-dl-openwrt-'));
const dl = new Downloader({ destDir: dir });
test.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });

// Real asset names from the release pages (2026-09-23).
const XRAY_ASSETS = ['Xray-linux-32.zip', 'Xray-linux-64.zip', 'Xray-linux-arm32-v5.zip', 'Xray-linux-arm32-v6.zip',
  'Xray-linux-arm32-v7a.zip', 'Xray-linux-arm64-v8a.zip', 'Xray-linux-mips32.zip', 'Xray-linux-mips32le.zip',
  'Xray-linux-mips64.zip', 'Xray-linux-mips64le.zip'];
const SB_ASSETS = ['sing-box-1.12.4-linux-amd64.tar.gz', 'sing-box-1.12.4-linux-amd64v3.tar.gz', 'sing-box-1.12.4-linux-arm64.tar.gz',
  'sing-box-1.12.4-linux-armv5.tar.gz', 'sing-box-1.12.4-linux-armv6.tar.gz', 'sing-box-1.12.4-linux-armv7.tar.gz',
  'sing-box-1.12.4-linux-mips.tar.gz', 'sing-box-1.12.4-linux-mipsle.tar.gz', 'sing-box-1.12.4-linux-mips64.tar.gz',
  'sing-box-1.12.4-linux-armv7.tar.gz.sha256', 'sing-box-1.12.4-android-armv7.tar.gz'];
const T2S_ASSETS = ['tun2socks-linux-amd64.zip', 'tun2socks-linux-arm64.zip', 'tun2socks-linux-armv5.zip', 'tun2socks-linux-armv6.zip',
  'tun2socks-linux-armv7.zip', 'tun2socks-linux-mips.zip', 'tun2socks-linux-mipsle.zip', 'tun2socks-linux-mips64.zip'];

test('Xray / Xray-PattN: an ARMv7 router asks for arm32-v7a; mips routers for mips32/mips32le', () => {
  assert.equal(dl.xrayAssetName('linux', 'arm'), 'Xray-linux-arm32-v7a.zip');
  assert.equal(dl.xrayAssetName('linux', 'mips'), 'Xray-linux-mips32.zip');
  assert.equal(dl.xrayAssetName('linux', 'mipsel'), 'Xray-linux-mips32le.zip');
  for (const a of ['arm', 'mips', 'mipsel', 'arm64', 'x64']) assert.ok(XRAY_ASSETS.includes(dl.xrayAssetName('linux', a)), a);
  // the rows that existed did not move
  assert.equal(dl.xrayAssetName('linux', 'x64'), 'Xray-linux-64.zip');
  assert.equal(dl.xrayAssetName('linux', 'arm64'), 'Xray-linux-arm64-v8a.zip');
  assert.equal(dl.xrayAssetName('linux', 'ppc64'), 'Xray-linux-64.zip', 'an arch with no row falls back to 64, as before');
  assert.equal(dl.xrayAssetName('win32', 'x64'), 'Xray-windows-64.zip');
  assert.equal(dl.xrayAssetName('darwin', 'arm64'), 'Xray-macos-arm64-v8a.zip');
});

test('sing-box: linux-armv7 for the router, and only that file in the release', () => {
  const pick = (platform, arch) => SB_ASSETS.filter(a => dl.singboxAssetPattern(platform, arch).test(a));
  assert.deepEqual(pick('linux', 'arm'), ['sing-box-1.12.4-linux-armv7.tar.gz'], 'not the .sha256, not android');
  assert.deepEqual(pick('linux', 'mips'), ['sing-box-1.12.4-linux-mips.tar.gz']);
  assert.deepEqual(pick('linux', 'mipsel'), ['sing-box-1.12.4-linux-mipsle.tar.gz']);
  assert.deepEqual(pick('linux', 'arm64'), ['sing-box-1.12.4-linux-arm64.tar.gz']);
  assert.deepEqual(pick('linux', 'x64'), ['sing-box-1.12.4-linux-amd64.tar.gz'], 'amd64v3 is a different build');
});

test('tun2socks: linux-armv7 / mips / mipsle, and the binary inside is named like the zip', () => {
  assert.equal(dl.tun2socksAssetName('linux', 'arm'), 'tun2socks-linux-armv7.zip');
  assert.equal(dl.tun2socksAssetName('linux', 'mips'), 'tun2socks-linux-mips.zip');
  assert.equal(dl.tun2socksAssetName('linux', 'mipsel'), 'tun2socks-linux-mipsle.zip');
  for (const a of ['arm', 'mips', 'mipsel', 'arm64', 'x64']) assert.ok(T2S_ASSETS.includes(dl.tun2socksAssetName('linux', a)), a);
  assert.equal(dl.tun2socksAssetName('linux', 'x64'), 'tun2socks-linux-amd64.zip');
  assert.equal(dl.tun2socksAssetName('win32', 'arm64'), 'tun2socks-windows-arm64.zip');
  assert.equal(dl.tun2socksAssetName('darwin', 'x64'), 'tun2socks-darwin-amd64.zip');
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test tests/downloader.openwrt.test.js`
Expected: FAIL — `'Xray-linux-64.zip' !== 'Xray-linux-arm32-v7a.zip'`

- [ ] **Step 3: Add the table and use it in the three pickers**

In `src/main/downloader.js`, add above the `class Downloader` line (find `class Downloader`):

```js
/**
 * Linux release-asset arch tokens per Node `os.arch()`. Routers: the Google
 * Wifi AC-1304 (OpenWrt, see tunOpenwrt.js) is 32-bit ARMv7 — `arm` — and
 * the two mips rows are what the small routers would need; they are a
 * mapping, not a supported target. amd64/arm64 rows are what they always were.
 */
const LINUX_ARCH = {
  xray: { x64: '64', arm64: 'arm64-v8a', arm: 'arm32-v7a', mips: 'mips32', mipsel: 'mips32le' },
  singbox: { x64: 'amd64', arm64: 'arm64', arm: 'armv7', mips: 'mips', mipsel: 'mipsle' },
  tun2socks: { x64: 'amd64', arm64: 'arm64', arm: 'armv7', mips: 'mips', mipsel: 'mipsle' }
};
```

Replace the three methods:

```js
  xrayAssetName(platform = os.platform(), arch = os.arch()) {
    if (platform === 'win32') return arch === 'arm64' ? 'Xray-windows-arm64-v8a.zip' : 'Xray-windows-64.zip';
    if (platform === 'darwin') return arch === 'arm64' ? 'Xray-macos-arm64-v8a.zip' : 'Xray-macos-64.zip';
    return `Xray-linux-${LINUX_ARCH.xray[arch] || '64'}.zip`;
  }

  tun2socksAssetName(platform = os.platform(), arch = os.arch()) {
    const a = arch === 'arm64' ? 'arm64' : 'amd64';
    if (platform === 'win32') return `tun2socks-windows-${a}.zip`;
    if (platform === 'darwin') return `tun2socks-darwin-${a}.zip`;
    return `tun2socks-linux-${LINUX_ARCH.tun2socks[arch] || 'amd64'}.zip`;
  }
```

and

```js
  /** Regex matching a platform's sing-box release asset (version varies). */
  singboxAssetPattern(platform = os.platform(), arch = os.arch()) {
    const a = arch === 'arm64' ? 'arm64' : 'amd64';
    if (platform === 'win32') return new RegExp(`sing-box-.*-windows-${a}\\.zip$`, 'i');
    if (platform === 'darwin') return new RegExp(`sing-box-.*-darwin-${a}\\.tar\\.gz$`, 'i');
    return new RegExp(`sing-box-.*-linux-${LINUX_ARCH.singbox[arch] || 'amd64'}\\.tar\\.gz$`, 'i');
  }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test tests/downloader.openwrt.test.js tests/downloader.darwin.test.js tests/downloader.test.js`
Expected: all pass (the darwin file pins that nothing else moved).

- [ ] **Step 5: Commit**

```bash
git add src/main/downloader.js tests/downloader.openwrt.test.js
git commit -m "downloader: the arm32-v7a / mips assets a router asks for; amd64 and arm64 rows unchanged"
```

---

### Task 5: wire the service — flavor, backend, bin dirs, devices RPC, live exclusions

**Files:**
- Modify: `src/server/service.js` (imports ~line 49; `DEFAULT_SETTINGS` ~line 110; `createService` ~line 141; `binDirs()` line 210; `makeTun()` lines 225-243; `XrayManager` line 248; the `tun.start(...)` call line 943-945; `app:init` lines 1521-1542; `settings:set` lines 1611-1627; `net:lanInfo` line 1721)
- Modify: `src/main/main.js:179` (one line after `autoConnect: false,`)
- Modify: `src/server/web-api.js:115` (after `lanInfo`)
- Test: `tests/serviceOpenwrt.test.js`

**Interfaces:**
- Consumes: Task 1/2 (`isOpenwrt`, `lanInterface`, `lanDevices`, `validMacs`), Task 3 (`TunOpenwrt`).
- Produces (Task 6 reads them):
  - `app:init` → `flavor: 'openwrt' | null`, `tunBackendId: string`
  - RPC `net:lanDevices` → `[{ mac, ip, name, online }]` (`[]` off OpenWrt)
  - `settings.lanBypassMacs: string[]` (validated on write; live-applied while connected)
  - `window.api.lanDevices()` in `web-api.js`

- [ ] **Step 1: Write the failing test**

`tests/serviceOpenwrt.test.js`:

```js
'use strict';
/**
 * The headless service on a router. The env override stands in for
 * /etc/openwrt_release (no router here), so this pins the wiring: which
 * backend makeTun() picks, what app:init tells the renderer, the validated
 * exclusion list, and that the device RPC is harmless where there is no LAN
 * to read. The service's timers are unref'd, so shutdown() is enough to let
 * the runner exit.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createService, DEFAULT_SETTINGS } = require('../src/server/service');
const { DEFAULT_SETTINGS: DESKTOP_DEFAULTS } = require('../src/main/main');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-svc-openwrt-'));
// no subscription timer, no asset updater: nothing to keep the process alive
fs.writeFileSync(path.join(dir, 'store.json'), JSON.stringify({ settings: { autoUpdateSubs: false, autoUpdateAssets: 'off' } }));
const service = createService({ dataDir: dir });
test.after(async () => { await service.shutdown(); try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });

test('both DEFAULT_SETTINGS carry lanBypassMacs = []', () => {
  assert.deepEqual(DEFAULT_SETTINGS.lanBypassMacs, []);
  assert.deepEqual(DESKTOP_DEFAULTS.lanBypassMacs, []);
});

test('app:init says flavor openwrt and that the gateway backend is the one that will run', async () => {
  const init = await service.invoke('app:init');
  assert.equal(init.flavor, 'openwrt');
  assert.equal(init.tunBackendId, 'openwrt');
  assert.equal(init.platform, process.platform, 'platform stays what Node says; flavor is the router');
  assert.deepEqual(init.settings.lanBypassMacs, []);
});

test('settings:set validates the exclusion list and keeps it out of the reconnect keys', async () => {
  const res = await service.invoke('settings:set', { lanBypassMacs: ['AA:BB:CC:DD:EE:FF', 'not a mac', 'aa:bb:cc:dd:ee:ff'] });
  assert.deepEqual(res.settings.lanBypassMacs, ['aa:bb:cc:dd:ee:ff']);
  assert.deepEqual(res.pendingReconnect, [], 'applied live, never a "reconnect to apply"');
  assert.deepEqual((await service.invoke('settings:get')).lanBypassMacs, ['aa:bb:cc:dd:ee:ff']);
});

test('net:lanDevices answers a list even where there are no leases and no LAN', async () => {
  const devices = await service.invoke('net:lanDevices');
  assert.ok(Array.isArray(devices));
  for (const d of devices) assert.match(d.mac, /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test tests/serviceOpenwrt.test.js`
Expected: FAIL — `lanBypassMacs` undefined / `flavor` undefined.

- [ ] **Step 3: Wire the service**

`src/server/service.js` — after `const { AssetUpdater } = require('../main/assetUpdater');` add:

```js
// OpenWrt: the router as the LAN's tunnel — the gateway backend and the device
// list (docs/superpowers/specs/2026-09-23-openwrt-port-design.md). main.js is
// deliberately NOT given this: Electron never runs on a router.
const { isOpenwrt, lanInterface, lanDevices, validMacs } = require('../main/openwrtNet');
const { TunOpenwrt } = require('../main/tunOpenwrt');
```

In `DEFAULT_SETTINGS`, after `  autoConnect: false,`:

```js
  // OpenWrt gateway: the devices (by MAC) that go around the tunnel. Applied
  // live to the running gateway — deliberately NOT a reconnect key.
  lanBypassMacs: [],
```

In `createService`, after `const bundledBinDir = path.join(__dirname, '..', '..', 'bin');`:

```js
  // OpenWrt: `opkg install xray-core sing-box` puts the official cores in
  // /usr/bin. Searched LAST — a core downloaded into userBinDir still wins.
  const OPENWRT = isOpenwrt();
  const systemBinDirs = OPENWRT ? ['/usr/bin'] : [];
```

`binDirs()`:

```js
  function binDirs() { return [userBinDir, bundledBinDir, ...systemBinDirs]; }
```

`makeTun()` — the `opts` object's `extraDirs: [userBinDir]` becomes `extraDirs: [userBinDir, ...systemBinDirs]`, and directly after the `opts` object (before the `if (process.platform === 'darwin' …` line):

```js
    // On a router the backend is not a choice: the gateway wraps sing-box and
    // adds the device exclusions. `tunBackend` is ignored here.
    if (OPENWRT) return (selected = new TunOpenwrt(opts));
```

`XrayManager`: `extraBinDirs: [userBinDir],` → `extraBinDirs: [userBinDir, ...systemBinDirs],`.

The TUN start call (the object on the line after `tunAdapterDns,`):

```js
            { ipv6: !!settings.ipv6, strict: settings.leakGuard === 'strict', apps: tunApps, bypassMacs: settings.lanBypassMacs });   // tun2socks ignores the 4th; only the router reads bypassMacs
```

`settings:set` — after the `autoUpdateSubs` block, before `let error = null;`:

```js
      // The gateway's exclusions change under a live tunnel without rebuilding
      // it: the nft set is replaced, sing-box is not touched (TunOpenwrt).
      if ('lanBypassMacs' in partial) {
        next.lanBypassMacs = validMacs(next.lanBypassMacs);
        store.set('settings', next);
        if (tun && tun.active && typeof tun.setBypassMacs === 'function') {
          tun.setBypassMacs(next.lanBypassMacs).catch(e => send('log', { line: 'Gateway exclusions not applied: ' + e.message, level: 'error' }));
        }
      }
```

After the `'net:lanInfo'` handler line:

```js
    // OpenWrt: the devices behind the router (DHCP leases + neighbour table) — the exclusion list's source
    'net:lanDevices': async () => {
      if (!OPENWRT) return [];
      const lanIf = await lanInterface(tunPlatform.run);
      return lanDevices({ run: tunPlatform.run, lanIf });
    },
```

`app:init` — after `platform: process.platform,`:

```js
      // the router flavour of Linux, and the backend a connect would build (the
      // renderer shows the device list and hides the desktop-only rows on it)
      flavor: OPENWRT ? 'openwrt' : null,
      tunBackendId: makeTun(getSettings(), { quiet: true }).backendId,
```

`src/main/main.js` — after `  autoConnect: false,` (line 179, inside `DEFAULT_SETTINGS`):

```js
  // OpenWrt gateway only (service.js); here so both DEFAULT_SETTINGS agree
  lanBypassMacs: [],
```

`src/server/web-api.js` — after `    lanInfo: () => invoke('net:lanInfo'),`:

```js
    lanDevices: () => invoke('net:lanDevices'),
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `node --test tests/serviceOpenwrt.test.js` → `# pass 4`. Then `npm test` → everything green (the `settingsMeta` tests confirm `lanBypassMacs` is not a reconnect key by absence; the renderer contract test does not yet know the new keys — that is Task 6).

- [ ] **Step 5: Commit**

```bash
git add src/server/service.js src/server/web-api.js src/main/main.js tests/serviceOpenwrt.test.js
git commit -m "service: on OpenWrt the gateway backend runs, /usr/bin cores count, the device list is an RPC, and the exclusions apply live"
```

---

### Task 6: the renderer — devices card, inspector row, router-only chrome

**Files:**
- Modify: `src/renderer/i18n.js` (fa block: after the `'ping.upload'` entry at line 481; en block: after the `'ping.upload'` entry at line 959)
- Modify: `src/renderer/index.html:675` (after `<div class="tun-status" id="lanInfo"></div>`) and `:763` (inspector Protection group)
- Modify: `src/renderer/app.js:295` (state), `:336` (init), `:2375-2385` (`missingEssentials`), `:1868-1891` (`renderInspector`), new functions after `updateLanInfo` (~line 898)
- Modify: `src/renderer/settings.css` (append)
- Test: `tests/renderer.test.js` (append one test)

**Interfaces:**
- Consumes: `data.flavor`, `window.api.lanDevices()`, `state.settings.lanBypassMacs` (Task 5); `saveSettings(partial, { silent })`, `renderInspector()`, `escapeHtml`, `toast`, `t` (existing).
- Produces: ids `gwRow`, `gwList`, `btnGwRefresh`, `insGatewayRow`, `insGateway`; i18n keys `gw.title`, `gw.sub`, `gw.refresh`, `gw.direct`, `gw.none`, `gw.hint`, `gw.online`, `gw.offline`, `gw.saved`, `gw.insWhole`, `gw.insDirect`, `ins.gateway`; functions `applyFlavor()`, `renderLanDevices()`.

- [ ] **Step 1: Append the failing test**

Append to `tests/renderer.test.js`:

```js
/**
 * The OpenWrt gateway (v1.13.0): the device list under LAN sharing and the
 * inspector's gateway row. Hidden until the service reports flavor=openwrt —
 * on the desktop these must never show — and every string of theirs is a key
 * in both languages, including the ones only t() ever sees.
 */
test('the OpenWrt device list and gateway row exist, hidden by default, and are fully translated', () => {
  for (const id of ['gwRow', 'gwList', 'btnGwRefresh', 'insGatewayRow', 'insGateway']) {
    assert.ok(htmlIds.has(id), `#${id} is missing`);
  }
  const between = HTML.slice(HTML.indexOf('id="lanInfo"'), HTML.indexOf('id="optKillSwitch"'));
  assert.ok(between.includes('id="gwRow"'), 'the device list sits under LAN sharing, before the kill switch');
  assert.match(HTML, /id="gwRow" hidden/, 'hidden until flavor=openwrt');
  assert.match(HTML, /id="insGatewayRow" hidden/, 'hidden until flavor=openwrt');
  assert.match(APP, /state\.flavor = data\.flavor \|\| null/);

  const keys = new Set();
  for (const m of HTML.matchAll(/data-i18n(?:-ph|-title)?="(gw\.[^"]+|ins\.gateway)"/g)) keys.add(m[1]);
  for (const m of APP.matchAll(/\bt\(\s*'(gw\.[^']+)'/g)) keys.add(m[1]);
  assert.ok(keys.size >= 10, `expected the whole card to be translated, found ${keys.size} keys`);
  const bad = [...keys].filter((k) => (I18N.split(`'${k}':`).length - 1) !== 2).sort();
  assert.deepEqual(bad, [], 'these keys are not defined exactly once in each of fa and en');

  // the classes the list is built from exist in the stylesheet
  for (const cls of ['gw-list', 'gw-item', 'gw-dot', 'gw-name', 'gw-meta', 'gw-direct', 'gw-check']) {
    assert.ok(CSS.includes('.' + cls), `.${cls} has no style`);
  }
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test tests/renderer.test.js`
Expected: FAIL — `#gwRow is missing`

- [ ] **Step 3: Strings**

`src/renderer/i18n.js`, fa block — turn the `'ping.upload': '…'` line (line 481) into `'ping.upload': '…',` and add after it:

```js

    /* OpenWrt gateway (the router is the tunnel for the LAN) */
    'gw.title': 'دستگاه‌های شبکه', 'gw.sub': 'هر دستگاهی که به این روتر وصل است از تونل می‌رود؛ آن‌هایی که علامت می‌زنی مستقیم می‌روند.',
    'gw.refresh': 'تازه‌سازی', 'gw.direct': 'مستقیم (بدون تونل)',
    'gw.none': 'دستگاهی پیدا نشد — دستگاه‌ها وقتی از روتر IP بگیرند این‌جا ظاهر می‌شوند.',
    'gw.hint': 'دستگاه مستثنا هم نام‌ها را از DNS روتر می‌پرسد، یعنی از داخل تونل؛ فقط ترافیک خودش مستقیم می‌رود.',
    'gw.online': 'آنلاین', 'gw.offline': 'آفلاین', 'gw.saved': 'فهرست دستگاه‌های مستقیم ذخیره شد',
    'ins.gateway': 'گیت‌وی', 'gw.insWhole': 'کل شبکه از تونل', 'gw.insDirect': '{n} دستگاه مستقیم'
```

en block — same at the `'ping.upload'` line (959):

```js

    /* OpenWrt gateway (the router is the tunnel for the LAN) */
    'gw.title': 'Devices on this network', 'gw.sub': 'Every device connected to this router goes through the tunnel; the ones you tick go direct.',
    'gw.refresh': 'Refresh', 'gw.direct': 'Direct (not through the tunnel)',
    'gw.none': 'No devices found — they appear here once they get an address from the router.',
    'gw.hint': 'An excluded device still resolves names through the router, i.e. through the tunnel; only its own traffic goes direct.',
    'gw.online': 'online', 'gw.offline': 'offline', 'gw.saved': 'Direct-device list saved',
    'ins.gateway': 'Gateway', 'gw.insWhole': 'whole network', 'gw.insDirect': '{n} direct'
```

(No apostrophes anywhere in these — that is deliberate.)

- [ ] **Step 4: Markup**

`src/renderer/index.html` — after `<div class="tun-status" id="lanInfo"></div>`:

```html
          <!-- OpenWrt only (state.flavor === 'openwrt'): the devices behind the
               router and which of them go around the tunnel. Filled by
               renderLanDevices(); a tick saves lanBypassMacs and applies live. -->
          <div class="setting-row" id="gwRow" hidden>
            <div class="field-label" data-i18n="gw.title">دستگاه‌های شبکه</div>
            <p class="hint" data-i18n="gw.sub"></p>
            <div class="row-gap">
              <button class="btn ghost" type="button" id="btnGwRefresh" data-i18n="gw.refresh">تازه‌سازی</button>
            </div>
            <div class="gw-list" id="gwList"></div>
            <p class="hint" data-i18n="gw.hint"></p>
          </div>
```

In the inspector's Protection group, after the `insIpv6` row:

```html
        <div class="ins-row" id="insGatewayRow" hidden><span class="ins-label" data-i18n="ins.gateway">گیت‌وی</span><span class="ins-val" id="insGateway">—</span></div>
```

- [ ] **Step 5: Styles**

Append to `src/renderer/settings.css`:

```css
/* ----------------------------- OpenWrt: the devices behind the router ----------------------------- */
#view-settings .gw-list { display: flex; flex-direction: column; gap: 6px; margin: 8px 0; }
#view-settings .gw-item { display: flex; align-items: center; gap: 10px; padding: 8px 10px; border: 1px solid var(--line); border-radius: var(--r6); cursor: pointer; }
#view-settings .gw-item:hover { border-color: var(--softline); }
#view-settings .gw-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--dim); flex: none; }
#view-settings .gw-dot.on { background: var(--ok); }
#view-settings .gw-name { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--ink); }
#view-settings .gw-meta { font-family: var(--mono); font-size: 11px; color: var(--ink3); direction: ltr; flex: none; }
#view-settings .gw-direct { font-size: 12px; color: var(--ink2); flex: none; }
#view-settings .gw-check { flex: none; }
```

- [ ] **Step 6: Behaviour**

`src/renderer/app.js`:

After `state.platform = data.platform || …;` (line 295):

```js
  // the router flavour of Linux: the device list shows, the desktop-only rows go
  state.flavor = data.flavor || null;
```

In the init sequence, after `updateKillStatus();` (line 336):

```js
  applyFlavor();
```

After `updateLanInfo()` (after line 898) add:

```js
/**
 * OpenWrt: the router IS the tunnel for the LAN, so the switches that only
 * mean something on a desktop go (system proxy, login item, Windows kill
 * switch, the TUN backend choice — fixed there, per-app routing — no process
 * behind a forwarded packet) and the device list comes.
 */
function applyFlavor() {
  const rt = state.flavor === 'openwrt';
  $('#gwRow').hidden = !rt;
  $('#insGatewayRow').hidden = !rt;
  for (const id of ['optSysProxy', 'optLaunchAtLogin', 'optKillSwitch']) {
    const row = $('#' + id).closest('.switch-row');
    if (row) row.hidden = rt;
  }
  $('#killStatus').hidden = rt;
  $('#tunBackendRow').hidden = rt;
  $('#tunAppRow').hidden = rt;
  if (rt) renderLanDevices();
}

/** The devices behind the router, each with its "direct" tick. */
async function renderLanDevices() {
  const host = $('#gwList');
  if (!host || state.flavor !== 'openwrt' || !window.api.lanDevices) return;
  let devices = [];
  try { devices = (await window.api.lanDevices()) || []; } catch { devices = []; }
  const bypass = new Set((state.settings.lanBypassMacs || []).map(m => String(m).toLowerCase()));
  // an excluded device that is not on the network right now still shows, so it can be un-excluded
  for (const mac of bypass) if (!devices.some(d => d.mac === mac)) devices.push({ mac, ip: '', name: '', online: false });
  host.innerHTML = '';
  if (!devices.length) {
    const p = document.createElement('p');
    p.className = 'hint';
    p.textContent = t('gw.none');
    host.appendChild(p);
    return;
  }
  for (const d of devices) {
    const row = document.createElement('label');
    row.className = 'gw-item';
    row.innerHTML =
      `<span class="gw-dot${d.online ? ' on' : ''}" title="${escapeHtml(t(d.online ? 'gw.online' : 'gw.offline'))}"></span>` +
      `<span class="gw-name">${escapeHtml(d.name || d.mac)}</span>` +
      `<span class="gw-meta">${escapeHtml(d.ip || '')}${d.ip ? ' · ' : ''}${escapeHtml(d.mac)}</span>` +
      `<span class="gw-direct">${escapeHtml(t('gw.direct'))}</span>` +
      `<input type="checkbox" class="gw-check"${bypass.has(d.mac) ? ' checked' : ''} />`;
    row.querySelector('.gw-check').onchange = async (e) => {
      const next = new Set(bypass);
      if (e.target.checked) next.add(d.mac); else next.delete(d.mac);
      // not a reconnect key: the service replaces the nft set under the live tunnel
      await saveSettings({ lanBypassMacs: [...next] }, { silent: true });
      toast(t('gw.saved'), 'ok');
      renderLanDevices();
    };
    host.appendChild(row);
  }
}
$('#btnGwRefresh').onclick = () => renderLanDevices();
```

In `renderInspector()`, before the closing `}` (after the `insRouting` block):

```js
  if (state.flavor === 'openwrt') {
    const n = (s.lanBypassMacs || []).length;
    set('#insGateway', t('gw.insWhole') + (n ? ' · ' + t('gw.insDirect').replace('{n}', n) : ''), s.tunMode ? 'on' : 'off');
  }
```

In `missingEssentials()`, the tun2socks line becomes (sing-box is the router's backend; tun2socks never runs there):

```js
  if (want && !a.tun2socks && state.flavor !== 'openwrt') list.push('tun2socks');
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `npm test`
Expected: all green, including `renderer.test.js` (ids, keys exactly once per language, classes) and `syntax.test.js` (the new strings parse).

- [ ] **Step 8: Look at it**

`node scripts/serve-renderer.js` (the dev-only static server, `.claude/launch.json` → port 8765) does not carry a service, so the card stays hidden there; the visual check happens in Task 8's QEMU UI port or on the owner's router. Confirm at least that the settings view still renders with `#gwRow` hidden (open http://127.0.0.1:8765/, Settings) and nothing shifted.

- [ ] **Step 9: Commit**

```bash
git add src/renderer/i18n.js src/renderer/index.html src/renderer/app.js src/renderer/settings.css tests/renderer.test.js
git commit -m "renderer: on a router, the devices behind it with a direct tick each, a gateway line in the inspector, and no desktop-only switches"
```

---

### Task 7: the package — `tar.js`, `build-ipk.js`, the router-side files

**Files:**
- Create: `openwrt/tar.js`, `openwrt/build-ipk.js`
- Create: `openwrt/files/irnetfree.init`, `openwrt/files/irnetfree.config`, `openwrt/files/99-irnetfree.defaults`, `openwrt/files/control/postinst`, `openwrt/files/control/prerm`, `openwrt/files/luci/menu.json`, `openwrt/files/luci/acl.json`, `openwrt/files/luci/irnetfree.js`
- Modify: `tests/syntax.test.js:20` (`DIRS` gains `'openwrt'`)
- Test: `tests/openwrtPackage.test.js`

**Interfaces:**
- Produces:
  - `openwrt/tar.js`: `tar(entries, { mtime }) → Buffer`, `untar(buf) → [{ name, mode, type, data }]`, `tgz`, `untgz` — entries `{ name, data?: Buffer|string, mode?, dir?: boolean }`, names WITHOUT a leading `./` (the writer adds it).
  - `openwrt/build-ipk.js`: `buildIpk({ root, outDir, version, mtime }) → { out, files, control, installed }`; CLI `node openwrt/build-ipk.js <outDir>`; constants `PKG = 'irnetfree'`, `DEPENDS`, `PREFIX = 'usr/lib/irnetfree'`.
  - The ipk layout Task 8 installs: `/usr/lib/irnetfree/{src,assets,package.json}`, `/etc/init.d/irnetfree`, `/etc/config/irnetfree`, `/etc/uci-defaults/99-irnetfree`, the three LuCI files.

An ipk is a gzipped tar of `./debian-binary` (`2.0\n`), `./control.tar.gz` and `./data.tar.gz`; opkg accepts exactly that. The writer is ours so the build runs the same on the owner's Windows box and on the runner, with no `tar` flag differences and fixed owner/mtime.

- [ ] **Step 1: Write the failing tests**

`tests/openwrtPackage.test.js`:

```js
'use strict';
/**
 * The OpenWrt package, built into a temp dir and read back with our own tar
 * reader: the three members opkg expects, the control fields, every file the
 * router side needs with the right mode, and — because ash is not bash — a
 * scan of every script that runs on the router for bashisms.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { tar, untar, tgz, untgz } = require('../openwrt/tar');
const { buildIpk, PKG, DEPENDS, PREFIX } = require('../openwrt/build-ipk');

const ROOT = path.join(__dirname, '..');
const VERSION = require('../package.json').version;

test('tar: ustar headers a real tar reads, round-trips through our reader, deterministic', () => {
  const a = tar([{ name: 'd', dir: true }, { name: 'd/x.txt', data: 'hi\n', mode: 0o644 }, { name: 'd/run', data: '#!/bin/sh\n', mode: 0o755 }], { mtime: 0 });
  const b = tar([{ name: 'd', dir: true }, { name: 'd/x.txt', data: 'hi\n', mode: 0o644 }, { name: 'd/run', data: '#!/bin/sh\n', mode: 0o755 }], { mtime: 0 });
  assert.ok(a.equals(b), 'same input, same bytes');
  assert.equal(a.length % 512, 0);
  const back = untar(a);
  assert.deepEqual(back.map(e => [e.name, e.type, e.mode]), [['./d/', '5', 0o755], ['./d/x.txt', '0', 0o644], ['./d/run', '0', 0o755]]);
  assert.equal(back[1].data.toString(), 'hi\n');
  // ustar magic + a checksum the C tools accept
  assert.equal(a.subarray(257, 263).toString(), 'ustar\0');
  const sum = [...a.subarray(0, 512)].reduce((n, b, i) => n + (i >= 148 && i < 156 ? 32 : b), 0);
  assert.equal(parseInt(a.subarray(148, 154).toString(), 8), sum);
  assert.deepEqual(untgz(tgz([{ name: 'f', data: 'x' }])).map(e => e.name), ['./f']);
  assert.throws(() => tar([{ name: 'x'.repeat(100), data: '' }]), /too long/);
  // the system tar, where there is one, agrees
  const sys = spawnSync('tar', ['-tf', '-'], { input: a, encoding: 'utf8' });
  if (sys.status === 0) assert.deepEqual(sys.stdout.trim().split(/\r?\n/), ['./d/', './d/x.txt', './d/run']);
});

const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-ipk-'));
test.after(() => { try { fs.rmSync(outDir, { recursive: true, force: true }); } catch {} });
const built = buildIpk({ root: ROOT, outDir, mtime: 0 });
const outer = untgz(fs.readFileSync(built.out));
const byName = (list) => Object.fromEntries(list.map(e => [e.name, e]));
const outerMap = byName(outer);
const control = byName(untgz(outerMap['./control.tar.gz'].data));
const data = byName(untgz(outerMap['./data.tar.gz'].data));

test('the ipk is what opkg expects: debian-binary, control, data — and is named after the version', () => {
  assert.equal(path.basename(built.out), `${PKG}_${VERSION}_all.ipk`);
  assert.deepEqual(outer.map(e => e.name), ['./debian-binary', './control.tar.gz', './data.tar.gz']);
  assert.equal(outerMap['./debian-binary'].data.toString(), '2.0\n');
});

test('control: the fields, the dependencies the router needs, conffiles, and the standard OpenWrt scripts', () => {
  const c = control['./control'].data.toString();
  assert.match(c, /^Package: irnetfree$/m);
  assert.match(c, new RegExp(`^Version: ${VERSION.replace(/\./g, '\\.')}$`, 'm'));
  assert.match(c, /^Architecture: all$/m);
  assert.match(c, /^Section: net$/m);
  assert.match(c, /^Depends: node, kmod-tun, nftables, unzip, ca-bundle$/m);
  assert.deepEqual(DEPENDS, ['node', 'kmod-tun', 'nftables', 'unzip', 'ca-bundle']);
  const installed = Object.values(data).filter(e => e.type === '0').reduce((n, e) => n + e.data.length, 0);
  assert.match(c, new RegExp(`^Installed-Size: ${installed}$`, 'm'));
  assert.equal(control['./conffiles'].data.toString(), '/etc/config/irnetfree\n');
  for (const s of ['./postinst', './prerm']) {
    assert.equal(control[s].mode, 0o755, s);
    assert.match(control[s].data.toString(), /^#!\/bin\/sh\n/);
    assert.match(control[s].data.toString(), /\/lib\/functions\.sh/, `${s} defers to OpenWrt's default_* helper`);
  }
});

test('data: the app under /usr/lib/irnetfree, the service files, the LuCI files — right modes, no junk', () => {
  const files = Object.keys(data).filter(n => data[n].type === '0');
  for (const must of [
    `./${PREFIX}/src/server/server.js`, `./${PREFIX}/src/server/service.js`, `./${PREFIX}/src/main/tunOpenwrt.js`,
    `./${PREFIX}/src/renderer/index.html`, `./${PREFIX}/assets/logo.svg`, `./${PREFIX}/package.json`,
    './etc/init.d/irnetfree', './etc/config/irnetfree', './etc/uci-defaults/99-irnetfree',
    './usr/share/luci/menu.d/luci-app-irnetfree.json', './usr/share/rpcd/acl.d/luci-app-irnetfree.json',
    './www/luci-static/resources/view/irnetfree.js'
  ]) assert.ok(files.includes(must), `${must} is not in the package`);
  assert.equal(data['./etc/init.d/irnetfree'].mode, 0o755);
  assert.equal(data['./etc/uci-defaults/99-irnetfree'].mode, 0o755);
  assert.equal(data['./etc/config/irnetfree'].mode, 0o644);
  assert.equal(data[`./${PREFIX}/src/server/server.js`].mode, 0o644);
  assert.ok(!files.some(n => /node_modules|\.map$|\.test\.js$/.test(n)), 'no dev files ship');
  // every file's directory exists as an entry, in order, so opkg never has to invent one
  for (const n of files) {
    const dir = n.slice(0, n.lastIndexOf('/') + 1);
    if (dir !== './') assert.ok(data[dir] && data[dir].type === '5', `no directory entry for ${dir}`);
  }
  assert.equal(data[`./${PREFIX}/src/server/server.js`].data.toString(), fs.readFileSync(path.join(ROOT, 'src/server/server.js')).toString(), 'shipped verbatim');
});

/** ash is not bash: the constructs that silently do the wrong thing there. */
const BASHISMS = [
  [/\[\[/, '[[ ]]'],
  [/^\s*function\s+\w+\s*\(?/m, 'function keyword'],
  [/\$\{\w+\[[@*0-9]/, 'arrays'],
  [/\$'/, "$'…' quoting"],
  [/\[ [^\]\n]*[^=!]==[^=]/, '== inside [ ]'],
  [/\bdeclare\b|\btypeset\b/, 'declare'],
  [/^\s*source\s/m, 'source (use .)'],
  [/&>/, '&> redirection'],
  [/\bpushd\b|\bpopd\b/, 'pushd/popd'],
  [/<<<\s/, 'here-string']
];
for (const [rel, name] of [
  ['./etc/init.d/irnetfree', 'the init script'], ['./etc/uci-defaults/99-irnetfree', 'the uci-defaults script'],
  ['CONTROL:./postinst', 'postinst'], ['CONTROL:./prerm', 'prerm']
]) {
  test(`${name} is POSIX sh: no bashisms`, () => {
    const src = (rel.startsWith('CONTROL:') ? control[rel.slice(8)] : data[rel]).data.toString();
    assert.match(src, /^#!\/bin\/sh( \/etc\/rc\.common)?\n/, 'a /bin/sh shebang');
    for (const [re, what] of BASHISMS) assert.doesNotMatch(src, re, what);
  });
}

test('the init script: procd, the token, the exact command line, POSIX', () => {
  const s = data['./etc/init.d/irnetfree'].data.toString();
  assert.match(s, /^#!\/bin\/sh \/etc\/rc\.common\n/);
  assert.match(s, /^USE_PROCD=1$/m);
  assert.match(s, /^START=95$/m);
  assert.match(s, /config_load irnetfree/);
  assert.match(s, /head -c 16 \/dev\/urandom \| hexdump -ve '1\/1 "%02x"' > "\$data_dir\/token"/);
  assert.match(s, /procd_set_param command \/usr\/bin\/node --max-old-space-size=160 "\$APP" --host "\$bind" --port "\$port" --data-dir "\$data_dir" --token "\$\(cat "\$data_dir\/token"\)"/);
  assert.match(s, /procd_set_param env IRNETFREE_PLATFORM=openwrt/);
  assert.match(s, /procd_set_param respawn/);
  assert.match(s, /procd_add_reload_trigger irnetfree/);
});

test('uci config and uci-defaults: the four options, the firewall zone, idempotent', () => {
  const cfg = data['./etc/config/irnetfree'].data.toString();
  for (const opt of ["option enabled '1'", "option port '6969'", "option bind '0.0.0.0'", "option data_dir '/etc/irnetfree'"]) assert.ok(cfg.includes(opt), opt);
  const d = data['./etc/uci-defaults/99-irnetfree'].data.toString();
  assert.match(d, /uci -q get firewall\.irnetfree >\/dev\/null \|\| \{/, 'runs once: a second install finds the zone');
  for (const line of ["set firewall.irnetfree=zone", "set firewall.irnetfree.name='irnetfree'", "add_list firewall.irnetfree.device='IRNetFree'",
    "set firewall.irnetfree.input='REJECT'", "set firewall.irnetfree.output='ACCEPT'", "set firewall.irnetfree.forward='REJECT'", "set firewall.irnetfree.masq='0'",
    "set firewall.irnetfree_lan=forwarding", "set firewall.irnetfree_lan.src='lan'", "set firewall.irnetfree_lan.dest='irnetfree'", 'commit firewall']) {
    assert.ok(d.includes(line), line);
  }
  assert.match(d, /^exit 0\s*$/m, 'uci-defaults must exit 0 or it is kept and re-run forever');
});

test('LuCI: the menu points at the view, the ACL grants the token and nothing else, the view is a LuCI module', () => {
  const menu = JSON.parse(data['./usr/share/luci/menu.d/luci-app-irnetfree.json'].data.toString());
  assert.deepEqual(menu['admin/services/irnetfree'].action, { type: 'view', path: 'irnetfree' });
  assert.deepEqual(menu['admin/services/irnetfree'].depends, { acl: ['luci-app-irnetfree'] });
  const acl = JSON.parse(data['./usr/share/rpcd/acl.d/luci-app-irnetfree.json'].data.toString());
  assert.deepEqual(Object.keys(acl['luci-app-irnetfree'].read.file), ['/etc/irnetfree/token']);
  assert.deepEqual(acl['luci-app-irnetfree'].read.uci, ['irnetfree']);
  assert.equal(acl['luci-app-irnetfree'].write, undefined, 'the page changes nothing');
  const view = data['./www/luci-static/resources/view/irnetfree.js'].data.toString();
  assert.match(view, /^'use strict';\n'require view';\n'require fs';\n'require uci';/);
  assert.match(view, /fs\.read\('\/etc\/irnetfree\/token'\)/);
  assert.match(view, /'\?token=' \+ encodeURIComponent\(token\)/);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `node --test tests/openwrtPackage.test.js`
Expected: FAIL — `Cannot find module '../openwrt/tar'`

- [ ] **Step 3: The tar writer/reader**

`openwrt/tar.js`:

```js
'use strict';
/**
 * A ustar writer and reader in Node core — all an ipk needs (an ipk is a
 * gzipped tar of debian-binary + control.tar.gz + data.tar.gz). Ours, so the
 * package builds identically on the owner's Windows box and on the runner:
 * owner 0:0, a fixed mtime, no `tar` flag that differs between GNU and BSD.
 *
 * Limits, checked: names under 100 bytes (ours are), sizes under 8 GiB.
 */
const zlib = require('zlib');

/** `%0<len-1>o\0` — the octal field shape ustar uses for mode/uid/gid/size/mtime. */
function oct(n, len) { return n.toString(8).padStart(len - 1, '0') + '\0'; }

function header({ name, size, mode, type, mtime }) {
  if (Buffer.byteLength(name, 'utf8') > 99) throw new Error('tar name too long: ' + name);
  const h = Buffer.alloc(512);
  h.write(name, 0, 'utf8');
  h.write(oct(mode, 8), 100);
  h.write(oct(0, 8), 108);            // uid
  h.write(oct(0, 8), 116);            // gid
  h.write(oct(size, 12), 124);
  h.write(oct(mtime, 12), 136);
  h.write('        ', 148);           // checksum: spaces while summing
  h.write(type, 156);                 // '0' file, '5' directory
  h.write('ustar\0', 257);
  h.write('00', 263);
  h.write('root', 265);
  h.write('root', 297);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return h;
}

/**
 * entries: [{ name, data?: Buffer|string, mode?, dir?: true }] — names without
 * the leading './' (added here, the way opkg's own packages look). Directories
 * get a trailing slash. Two 512-byte zero blocks end the archive.
 */
function tar(entries, { mtime = 0 } = {}) {
  const parts = [];
  for (const e of entries) {
    const dir = !!e.dir;
    const data = dir ? Buffer.alloc(0) : (Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data == null ? '' : String(e.data), 'utf8'));
    const name = './' + e.name.replace(/^\.?\//, '') + (dir && !e.name.endsWith('/') ? '/' : '');
    parts.push(header({ name, size: data.length, mode: e.mode == null ? (dir ? 0o755 : 0o644) : e.mode, type: dir ? '5' : '0', mtime }));
    if (!dir) {
      parts.push(data);
      const rem = data.length % 512;
      if (rem) parts.push(Buffer.alloc(512 - rem));
    }
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

function field(h, off, len) { return h.subarray(off, off + len).toString('utf8').replace(/\0[\s\S]*$/, '').trim(); }

/** The entries of an uncompressed tar: [{ name, mode, type, data }]. */
function untar(buf) {
  const out = [];
  let off = 0;
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h.every(b => b === 0)) break;
    const size = parseInt(field(h, 124, 12), 8) || 0;
    out.push({ name: field(h, 0, 100), mode: parseInt(field(h, 100, 8), 8), type: String.fromCharCode(h[156]) || '0', data: buf.subarray(off + 512, off + 512 + size) });
    off += 512 + Math.ceil(size / 512) * 512;
  }
  return out;
}

const tgz = (entries, o) => zlib.gzipSync(tar(entries, o), { level: 9 });
const untgz = (buf) => untar(zlib.gunzipSync(buf));

module.exports = { tar, untar, tgz, untgz };
```

- [ ] **Step 4: The builder**

`openwrt/build-ipk.js`:

```js
#!/usr/bin/env node
'use strict';
/**
 * Build `irnetfree_<version>_all.ipk` — the OpenWrt package.
 *
 *   node openwrt/build-ipk.js [outDir]        (default: dist/)
 *
 * What goes in: the app exactly as checked out (src/, assets/, package.json —
 * the service reads its version from it) under /usr/lib/irnetfree, the procd
 * init script, the uci config, a uci-defaults script that adds the firewall
 * zone once, and three static LuCI files. What stays out: node itself (a feed
 * package, `Depends:`), every core binary (downloaded on the router, or the
 * feed's xray-core/sing-box in /usr/bin), node_modules (the runtime needs
 * none), tests, source maps.
 *
 * Architecture `all`: nothing in here is compiled. `Installed-Size` is the
 * byte total of the files, which is what opkg's free-space check reads.
 */
const fs = require('fs');
const path = require('path');
const { tgz } = require('./tar');

const ROOT = path.join(__dirname, '..');
const PKG = 'irnetfree';
const PREFIX = 'usr/lib/irnetfree';
/** kmod-tun: the TUN device; nftables: `nft`; unzip: the Downloader's zip step; ca-bundle: TLS to GitHub. */
const DEPENDS = ['node', 'kmod-tun', 'nftables', 'unzip', 'ca-bundle'];

/** Files under `dir`, relative POSIX paths, sorted; dev files skipped. */
function walk(dir, rel = '') {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
    const r = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) { out.push(...walk(path.join(dir, entry.name), r)); continue; }
    if (!entry.isFile() || /\.map$|\.test\.js$/.test(entry.name)) continue;
    out.push({ rel: r, abs: path.join(dir, entry.name) });
  }
  return out;
}

function buildIpk({ root = ROOT, outDir = path.join(ROOT, 'dist'), version, mtime = Number(process.env.SOURCE_DATE_EPOCH) || 0 } = {}) {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const ver = version || pkg.version;
  const data = [];
  const dirs = new Set();
  const ensureDir = (d) => {
    if (!d || d === '.' || dirs.has(d)) return;
    ensureDir(path.posix.dirname(d));
    dirs.add(d);
    data.push({ name: d, dir: true, mode: 0o755 });
  };
  const file = (name, abs, mode) => {
    if (!fs.existsSync(abs)) throw new Error(`build-ipk: missing ${abs}`);
    ensureDir(path.posix.dirname(name));
    data.push({ name, data: fs.readFileSync(abs), mode });
  };

  for (const top of ['src', 'assets']) for (const f of walk(path.join(root, top))) file(`${PREFIX}/${top}/${f.rel}`, f.abs, 0o644);
  file(`${PREFIX}/package.json`, path.join(root, 'package.json'), 0o644);

  const F = (n) => path.join(root, 'openwrt', 'files', n);
  file('etc/init.d/irnetfree', F('irnetfree.init'), 0o755);
  file('etc/config/irnetfree', F('irnetfree.config'), 0o644);
  file('etc/uci-defaults/99-irnetfree', F('99-irnetfree.defaults'), 0o755);
  file('usr/share/luci/menu.d/luci-app-irnetfree.json', F('luci/menu.json'), 0o644);
  file('usr/share/rpcd/acl.d/luci-app-irnetfree.json', F('luci/acl.json'), 0o644);
  file('www/luci-static/resources/view/irnetfree.js', F('luci/irnetfree.js'), 0o644);

  const installed = data.reduce((n, e) => n + (e.data ? e.data.length : 0), 0);
  const control = [
    `Package: ${PKG}`,
    `Version: ${ver}`,
    'Architecture: all',
    'Section: net',
    'Priority: optional',
    'Maintainer: IRNetFree <irnetfree@users.noreply.github.com>',
    `Depends: ${DEPENDS.join(', ')}`,
    `Installed-Size: ${installed}`,
    'Description: IRNetFree as the router: every device behind it goes through the tunnel (Xray, Xray-PattN, sing-box). Web UI on port 6969; LuCI: Services > IRNetFree.',
    ''
  ].join('\n');
  const ctl = [
    { name: 'control', data: control, mode: 0o644 },
    { name: 'conffiles', data: '/etc/config/irnetfree\n', mode: 0o644 },
    { name: 'postinst', data: fs.readFileSync(F('control/postinst')), mode: 0o755 },
    { name: 'prerm', data: fs.readFileSync(F('control/prerm')), mode: 0o755 }
  ];
  const outer = tgz([
    { name: 'debian-binary', data: '2.0\n', mode: 0o644 },
    { name: 'control.tar.gz', data: tgz(ctl, { mtime }), mode: 0o644 },
    { name: 'data.tar.gz', data: tgz(data, { mtime }), mode: 0o644 }
  ], { mtime });

  fs.mkdirSync(outDir, { recursive: true });
  const out = path.join(outDir, `${PKG}_${ver}_all.ipk`);
  fs.writeFileSync(out, outer);
  return { out, files: data.filter(e => !e.dir).map(e => e.name), control, installed };
}

if (require.main === module) {
  const r = buildIpk({ outDir: process.argv[2] ? path.resolve(process.argv[2]) : undefined });
  console.log(`${r.out}  (${r.files.length} files, ${(r.installed / 1048576).toFixed(1)} MB installed)`);
}

module.exports = { buildIpk, PKG, DEPENDS, PREFIX };
```

- [ ] **Step 5: The router-side files**

`openwrt/files/irnetfree.init` (tabs, POSIX sh):

```sh
#!/bin/sh /etc/rc.common
# IRNetFree on OpenWrt: the headless service (node) as a procd service.
# The UI is http://<router>:<port>/?token=<token>; LuCI -> Services -> IRNetFree
# shows that link. Config: /etc/config/irnetfree. Log: logread -e irnetfree

START=95
STOP=10
USE_PROCD=1

APP=/usr/lib/irnetfree/src/server/server.js

start_service() {
	local enabled port bind data_dir
	config_load irnetfree
	config_get_bool enabled main enabled 1
	config_get port main port 6969
	config_get bind main bind 0.0.0.0
	config_get data_dir main data_dir /etc/irnetfree
	[ "$enabled" = 1 ] || return 0
	mkdir -p "$data_dir/bin"
	# One token for the web UI, made once, root-readable only. server.js refuses a
	# non-loopback bind without a token; this is what stands between the LAN and
	# the tunnel's controls.
	if [ ! -s "$data_dir/token" ]; then
		umask 077
		head -c 16 /dev/urandom | hexdump -ve '1/1 "%02x"' > "$data_dir/token"
	fi
	procd_open_instance
	procd_set_param command /usr/bin/node --max-old-space-size=160 "$APP" --host "$bind" --port "$port" --data-dir "$data_dir" --token "$(cat "$data_dir/token")"
	procd_set_param env IRNETFREE_PLATFORM=openwrt HOME=/root
	procd_set_param respawn
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}

service_triggers() {
	procd_add_reload_trigger irnetfree
}
```

`openwrt/files/irnetfree.config`:

```
config irnetfree 'main'
	option enabled '1'
	option port '6969'
	option bind '0.0.0.0'
	option data_dir '/etc/irnetfree'
```

`openwrt/files/99-irnetfree.defaults`:

```sh
#!/bin/sh
# Runs once, at install (default_postinst runs every uci-defaults script the
# package ships, then deletes it). A firewall zone for the tunnel device so fw4
# forwards the LAN into it — explicit, rather than relying on the lan zone's
# forward policy. Idempotent: a re-install finds the zone and leaves it.
uci -q get firewall.irnetfree >/dev/null || {
	uci -q batch <<-EOF
		set firewall.irnetfree=zone
		set firewall.irnetfree.name='irnetfree'
		set firewall.irnetfree.input='REJECT'
		set firewall.irnetfree.output='ACCEPT'
		set firewall.irnetfree.forward='REJECT'
		set firewall.irnetfree.masq='0'
		add_list firewall.irnetfree.device='IRNetFree'
		set firewall.irnetfree_lan=forwarding
		set firewall.irnetfree_lan.src='lan'
		set firewall.irnetfree_lan.dest='irnetfree'
		commit firewall
	EOF
	[ -x /etc/init.d/firewall ] && /etc/init.d/firewall reload >/dev/null 2>&1
}
exit 0
```

`openwrt/files/control/postinst` and `prerm` — what the OpenWrt SDK generates for every package: `default_postinst` enables + starts the init script and runs the uci-defaults; `default_prerm` stops + disables it.

```sh
#!/bin/sh
[ "${IPKG_NO_SCRIPT}" = "1" ] && exit 0
[ -s "${IPKG_INSTROOT}/lib/functions.sh" ] || exit 0
. "${IPKG_INSTROOT}/lib/functions.sh"
default_postinst "$0" "$@"
```

```sh
#!/bin/sh
[ -s "${IPKG_INSTROOT}/lib/functions.sh" ] || exit 0
. "${IPKG_INSTROOT}/lib/functions.sh"
default_prerm "$0" "$@"
```

`openwrt/files/luci/menu.json`:

```json
{
	"admin/services/irnetfree": {
		"title": "IRNetFree",
		"order": 90,
		"action": { "type": "view", "path": "irnetfree" },
		"depends": { "acl": [ "luci-app-irnetfree" ] }
	}
}
```

`openwrt/files/luci/acl.json`:

```json
{
	"luci-app-irnetfree": {
		"description": "Grant access to the IRNetFree page",
		"read": {
			"file": { "/etc/irnetfree/token": [ "read" ] },
			"uci": [ "irnetfree" ]
		}
	}
}
```

`openwrt/files/luci/irnetfree.js` (a LuCI client-side view; the `'require …'` strings are LuCI's module directives):

```js
'use strict';
'require view';
'require fs';
'require uci';

// The one job of this page: hand the operator the link to the IRNetFree UI
// with the token this router generated — the token file is root-only and
// this page sits behind LuCI's own login. Nothing here changes anything.
return view.extend({
	load: function () {
		return Promise.all([
			fs.read('/etc/irnetfree/token').catch(function () { return ''; }),
			uci.load('irnetfree')
		]);
	},
	render: function (data) {
		var token = (data[0] || '').trim();
		var port = uci.get('irnetfree', 'main', 'port') || '6969';
		var url = 'http://' + window.location.hostname + ':' + port + '/' + (token ? '?token=' + encodeURIComponent(token) : '');
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, 'IRNetFree'),
			E('p', {}, 'The tunnel for every device behind this router. Its own page runs on port ' + port + '; the button opens it with the access token this router generated.'),
			E('p', {}, E('a', { 'class': 'btn cbi-button cbi-button-apply', 'href': url, 'target': '_blank', 'rel': 'noopener' }, 'Open IRNetFree')),
			token ? '' : E('p', { 'class': 'alert-message warning' }, 'No token yet: start the service (/etc/init.d/irnetfree start) and reload this page.')
		]);
	},
	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
```

`tests/syntax.test.js` line 20:

```js
const DIRS = ['src/main', 'src/renderer', 'src/server', 'scripts', 'openwrt'];
```

- [ ] **Step 6: Build once by hand, run the tests**

Run: `node openwrt/build-ipk.js dist` → prints `…/dist/irnetfree_1.12.0_all.ipk  (N files, ~1.5 MB installed)` (the version is whatever `package.json` says at that point).
Run: `node --test tests/openwrtPackage.test.js` → `# pass 11` (the 4 bashism tests included). Then `npm test` → green, and `syntax.test.js` now lists `parses: openwrt/…` lines.

- [ ] **Step 7: Commit**

```bash
git add openwrt tests/openwrtPackage.test.js tests/syntax.test.js
git commit -m "openwrt: the package — an ipk built in Node (our own ustar), the procd service, the uci config, the firewall zone once, a LuCI page with the link"
```

---

### Task 8: CI — OpenWrt in QEMU, and the ipk in the release

**Files:**
- Create: `openwrt/ci/guest-smoke.sh` (POSIX sh, runs INSIDE the guest), `openwrt/ci/qemu-smoke.js` (Node, runs on the runner)
- Modify: `.github/workflows/test.yml` (new job `openwrt`), `.github/workflows/release.yml` (new job `openwrt`)
- Test: `tests/releaseWorkflow.test.js` (append), `tests/openwrtPackage.test.js` (append: the guest script is POSIX)

**Interfaces:**
- Consumes: the ipk from Task 7; the service's RPC (`app:init`, `servers:addProxy`, `settings:set`, `connect`, `disconnect`) over `POST /rpc?token=…`; `/etc/irnetfree/token` from the init script.
- Produces: a green `openwrt (qemu armsr-armv7)` job on every push; `irnetfree_<v>_all.ipk` + `SHA256SUMS-openwrt.txt` on every tagged release.

Why the serial console and not ssh: a fresh OpenWrt has no root password and dropbear's blank-password policy is not ours to depend on. QEMU's `-nographic` puts the serial console on stdio; the driver waits for OpenWrt's "press Enter" line, then runs each command followed by an `echo <marker>rc=$?` and waits for that marker. The package and the guest script reach the guest over HTTP from a tiny server on the runner (slirp exposes the host at `192.168.1.2`; OpenWrt's default LAN is static `192.168.1.1`, so the user network is put on that subnet).

- [ ] **Step 1: The guest script**

`openwrt/ci/guest-smoke.sh`:

```sh
#!/bin/sh
# Runs INSIDE the OpenWrt guest (busybox ash), started by qemu-smoke.js after
# it has put the ipk and this file in /tmp. Installs the package the way a user
# would, then asks the gateway to come up against a SOCKS upstream that does not
# exist — no internet is needed for what is asserted: the TUN device, sing-box's
# policy route, our nft table with the excluded MAC, the fw4 zone, and that a
# change of the exclusion list does not restart the tunnel. Prints SMOKE OK last.
set -eu
say() { echo; echo "== $*"; }

say "feeds"
opkg update >/dev/null

say "packages (node is the big one)"
opkg install node kmod-tun nftables unzip ca-bundle sing-box xray-core curl jq >/dev/null

say "install irnetfree"
opkg install /tmp/irnetfree.ipk
/etc/init.d/irnetfree enabled || { echo "postinst did not enable the service"; exit 1; }
uci -q get firewall.irnetfree.name | grep -qx irnetfree || { echo "uci-defaults did not add the firewall zone"; exit 1; }
[ -s /etc/irnetfree/token ] || { echo "no token was generated"; exit 1; }

say "service up"
i=0
until curl -fs -o /dev/null http://127.0.0.1:6969/web-api.js; do
	i=$((i+1))
	[ $i -lt 150 ] || { echo "the UI did not come up"; logread | tail -60; exit 1; }
	sleep 2
done
TOKEN="$(cat /etc/irnetfree/token)"
rpc() { curl -fs -X POST "http://127.0.0.1:6969/rpc?token=$TOKEN" -H 'Content-Type: application/json' -d "$1"; }

say "flavor and backend"
rpc '{"channel":"app:init"}' | jq -e '.result.flavor == "openwrt" and .result.tunBackendId == "openwrt"' >/dev/null

say "a server that needs no internet"
ID="$(rpc '{"channel":"servers:addProxy","arg":{"type":"socks","address":"127.0.0.1","port":1,"name":"ci-dummy"}}' | jq -r '.result.server.id')"
[ -n "$ID" ] && [ "$ID" != null ] || { echo "servers:addProxy returned no id"; exit 1; }
rpc '{"channel":"settings:set","arg":{"tunMode":true,"routingMode":"global","blockAds":false,"dnsManaged":false,"lanBypassMacs":["02:00:00:00:00:01"]}}' \
	| jq -e '.result.settings.lanBypassMacs == ["02:00:00:00:00:01"]' >/dev/null

say "connect"
rpc "{\"channel\":\"connect\",\"arg\":\"$ID\"}" > /tmp/connect.json || true
cat /tmp/connect.json; echo
i=0
until ip link show IRNetFree >/dev/null 2>&1; do
	i=$((i+1))
	[ $i -lt 90 ] || { echo "no TUN device after connect"; logread | tail -80; exit 1; }
	sleep 1
done

say "assert: sing-box routes, our rule, our table, the zone"
ip rule show
ip rule show | grep -q 'lookup 2022' || { echo "sing-box laid no policy route"; exit 1; }
ip rule show | grep -q '^8999:' || { echo "the bypass rule is missing"; exit 1; }
nft list table inet irnetfree
nft list table inet irnetfree | grep -q '02:00:00:00:00:01' || { echo "the excluded MAC is not in the set"; exit 1; }
nft list ruleset | grep -q 'oifname "IRNetFree"' || { echo "fw4 has no rule for the IRNetFree device"; exit 1; }

say "the exclusion list changes live"
PID="$(pidof sing-box)"
rpc '{"channel":"settings:set","arg":{"lanBypassMacs":["02:00:00:00:00:02"]}}' >/dev/null
sleep 2
nft list table inet irnetfree | grep -q '02:00:00:00:00:02' || { echo "the new MAC is missing"; exit 1; }
if nft list table inet irnetfree | grep -q '02:00:00:00:00:01'; then echo "the old MAC is still there"; exit 1; fi
[ "$(pidof sing-box)" = "$PID" ] || { echo "the tunnel was restarted for a set change"; exit 1; }

say "disconnect"
rpc '{"channel":"disconnect"}' >/dev/null
sleep 3
if ip link show IRNetFree >/dev/null 2>&1; then echo "the TUN device is still there"; exit 1; fi
if nft list table inet irnetfree >/dev/null 2>&1; then echo "the nft table is still there"; exit 1; fi
if ip rule show | grep -q '^8999:'; then echo "the bypass rule is still there"; exit 1; fi

say "SMOKE OK"
```

- [ ] **Step 2: The driver**

`openwrt/ci/qemu-smoke.js`:

```js
#!/usr/bin/env node
'use strict';
/**
 * Boot OpenWrt (armsr/armv7) in QEMU and run openwrt/ci/guest-smoke.sh inside
 * it over the serial console.
 *
 *   node openwrt/ci/qemu-smoke.js --kernel <initramfs-kernel.bin> --ipk <irnetfree_x_all.ipk>
 *
 * The console is driven by markers: every command is followed by
 * `echo <marker>rc=$?`, and the driver waits for the marker to read the exit
 * code. The guest fetches the package and the script from a one-file HTTP
 * server here (slirp shows the host as 192.168.1.2). Exit 0 only when the
 * guest script exited 0 and printed SMOKE OK. Everything the guest prints is
 * streamed to stdout, so a red job has the whole story in its log.
 */
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

function arg(name, def) { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : def; }
const KERNEL = arg('--kernel');
const IPK = arg('--ipk');
const QEMU = arg('--qemu', 'qemu-system-arm');
const HOST_IP = '192.168.1.2';
const DNS_IP = '192.168.1.3';
if (!KERNEL || !IPK) { console.error('usage: qemu-smoke.js --kernel <bin> --ipk <ipk>'); process.exit(2); }

/* ----------------------------- the files the guest fetches ----------------------------- */
const FILES = { '/irnetfree.ipk': IPK, '/guest-smoke.sh': path.join(__dirname, 'guest-smoke.sh') };
const srv = http.createServer((req, res) => {
  const f = FILES[req.url.split('?')[0]];
  if (!f) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': fs.statSync(f).size });
  fs.createReadStream(f).pipe(res);
});

/* ----------------------------- the serial console ----------------------------- */
class Console {
  constructor(proc) {
    this.proc = proc; this.buf = ''; this.waiters = [];
    proc.stdout.on('data', d => this.feed(d));
    proc.stderr.on('data', d => this.feed(d));
  }
  feed(d) {
    const s = d.toString('utf8');
    process.stdout.write(s);
    this.buf += s;
    if (this.buf.length > 4e6) this.buf = this.buf.slice(-2e6);
    for (const w of [...this.waiters]) {
      const m = w.re.exec(this.buf);
      if (m) { this.waiters.splice(this.waiters.indexOf(w), 1); clearTimeout(w.timer); w.resolve(m); }
    }
  }
  waitFor(re, ms) {
    return new Promise((resolve, reject) => {
      const m = re.exec(this.buf);
      if (m) return resolve(m);
      const w = { re, resolve };
      w.timer = setTimeout(() => { this.waiters.splice(this.waiters.indexOf(w), 1); reject(new Error(`timed out after ${ms} ms waiting for ${re}`)); }, ms);
      this.waiters.push(w);
    });
  }
  send(s) { this.proc.stdin.write(s); }
}

let n = 0;
/** Run one shell line in the guest; resolve with its exit code. */
async function sh(con, cmd, ms) {
  const mark = `IRNF_${++n}_`;
  con.send(`${cmd}; echo ${mark}rc=$?\n`);
  const m = await con.waitFor(new RegExp(`${mark}rc=(\\d+)`), ms);
  return Number(m[1]);
}
function step(name, rc) { if (rc !== 0) throw new Error(`${name} failed with exit code ${rc}`); }

(async () => {
  await new Promise(r => srv.listen(0, '0.0.0.0', r));
  const port = srv.address().port;
  const qemu = spawn(QEMU, [
    '-M', 'virt', '-cpu', 'cortex-a15', '-smp', '2', '-m', '768', '-nographic', '-no-reboot',
    '-kernel', KERNEL,
    '-netdev', `user,id=n0,net=192.168.1.0/24,host=${HOST_IP},dns=${DNS_IP}`,
    '-device', 'virtio-net-pci,netdev=n0'
  ], { stdio: ['pipe', 'pipe', 'pipe'] });
  qemu.on('error', (e) => { console.error(`\ncould not start ${QEMU}: ${e.message}`); process.exit(1); });
  const con = new Console(qemu);
  let rc = 1;
  try {
    await con.waitFor(/Please press Enter to activate this console/, 300000);
    con.send('\n');
    step('shell', await sh(con, 'true', 60000));
    step('route to the host', await sh(con, `ip route add default via ${HOST_IP} && echo nameserver ${DNS_IP} > /etc/resolv.conf`, 30000));
    step('fetch', await sh(con, `wget -q -O /tmp/irnetfree.ipk http://${HOST_IP}:${port}/irnetfree.ipk && wget -q -O /tmp/guest-smoke.sh http://${HOST_IP}:${port}/guest-smoke.sh`, 120000));
    rc = await sh(con, 'sh /tmp/guest-smoke.sh 2>&1', 25 * 60000);
    if (rc !== 0) console.error(`\nguest-smoke.sh exited ${rc}`);
    else if (!/SMOKE OK/.test(con.buf)) { console.error('\nthe guest script exited 0 but never printed SMOKE OK'); rc = 1; }
  } catch (e) {
    console.error('\n' + e.message);
    rc = 1;
  } finally {
    try { con.send('poweroff\n'); } catch { /* gone already */ }
    setTimeout(() => { try { qemu.kill('SIGKILL'); } catch { /* gone */ } }, 8000).unref();
    srv.close();
  }
  process.exitCode = rc;
})();
```

- [ ] **Step 3: The test job**

Append to `.github/workflows/test.yml` (after the `android` job):

```yaml
  openwrt:
    # The OpenWrt package runs nowhere but a router, and nobody working on it
    # has one on the desk. So an OpenWrt 24.10 armsr image boots in QEMU (TCG,
    # slow), the package installs on top of the feed's node, and the gateway is
    # asked to come up against a SOCKS upstream that does not exist: the TUN
    # device, sing-box's policy route, our nft table and the fw4 zone are what
    # is asserted — not internet. openwrt/ci/guest-smoke.sh is the checklist.
    name: openwrt (qemu armsr-armv7)
    runs-on: ubuntu-latest
    timeout-minutes: 40
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
      - name: Install QEMU
        run: sudo apt-get update && sudo apt-get install -y qemu-system-arm
      - name: Build the package
        run: node openwrt/build-ipk.js dist
      - name: Fetch the OpenWrt image
        run: curl -fsSL -o /tmp/openwrt-kernel.bin https://downloads.openwrt.org/releases/24.10.2/targets/armsr/armv7/openwrt-24.10.2-armsr-armv7-generic-initramfs-kernel.bin
      - name: Boot, install, connect, assert
        run: node openwrt/ci/qemu-smoke.js --kernel /tmp/openwrt-kernel.bin --ipk "$(ls dist/irnetfree_*_all.ipk)"
```

- [ ] **Step 4: The release job**

Append to `.github/workflows/release.yml` (after the `android` job):

```yaml
  openwrt:
    # The router package: architecture `all` (nothing compiled), built by
    # openwrt/build-ipk.js from the same checkout as the desktop installers.
    name: Build OpenWrt package
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Sync version to tag
        if: startsWith(github.ref, 'refs/tags/')
        shell: bash
        run: npm version --no-git-tag-version --allow-same-version "${GITHUB_REF_NAME#v}"

      - name: Build ipk
        shell: bash
        run: |
          node openwrt/build-ipk.js dist
          cd dist
          sha256sum irnetfree_*_all.ipk > SHA256SUMS-openwrt.txt
          cat SHA256SUMS-openwrt.txt
          echo "OpenWrt package: $(ls irnetfree_*_all.ipk) ($(du -h irnetfree_*_all.ipk | cut -f1))" >> "$GITHUB_STEP_SUMMARY"

      - name: Upload package artifact
        uses: actions/upload-artifact@v4
        with:
          name: IRNetFree-OpenWrt
          path: |
            dist/irnetfree_*_all.ipk
            dist/SHA256SUMS-openwrt.txt
          if-no-files-found: error

      - name: Publish package to GitHub Release
        if: startsWith(github.ref, 'refs/tags/')
        uses: softprops/action-gh-release@v2
        with:
          files: |
            dist/irnetfree_*_all.ipk
            dist/SHA256SUMS-openwrt.txt
          fail_on_unmatched_files: true
```

- [ ] **Step 5: Pin both workflows and the guest script**

Append to `tests/releaseWorkflow.test.js`:

```js
/**
 * The OpenWrt package rides the release (v1.13.0): its own job, the version
 * synced to the tag like the desktop build, the ipk and its checksum published
 * — and, unlike the desktop artefacts, a MISSING ipk fails the job: there is
 * nothing to fall back to.
 */
test('the release workflow builds and publishes the OpenWrt package', () => {
  const job = YML.slice(YML.indexOf('\n  openwrt:\n'));
  assert.ok(job.length > 0, 'release.yml has an openwrt job');
  assert.match(job, /name: Build OpenWrt package/);
  assert.match(job, /npm version --no-git-tag-version --allow-same-version "\$\{GITHUB_REF_NAME#v\}"/, 'the ipk carries the tag version');
  assert.match(job, /node openwrt\/build-ipk\.js dist/);
  assert.match(job, /sha256sum irnetfree_\*_all\.ipk > SHA256SUMS-openwrt\.txt/);
  assert.match(job, /uses: softprops\/action-gh-release@v2/);
  assert.match(job, /dist\/irnetfree_\*_all\.ipk/);
  assert.match(job, /fail_on_unmatched_files: true/, 'no ipk, no green release');
});

test('the test workflow boots OpenWrt in QEMU and runs the smoke', () => {
  const tests = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'test.yml'), 'utf8');
  const job = tests.slice(tests.indexOf('\n  openwrt:\n'));
  assert.ok(job.length > 0, 'test.yml has an openwrt job');
  assert.match(job, /qemu-system-arm/);
  assert.match(job, /openwrt-24\.10\.2-armsr-armv7-generic-initramfs-kernel\.bin/);
  assert.match(job, /node openwrt\/build-ipk\.js dist/);
  assert.match(job, /node openwrt\/ci\/qemu-smoke\.js --kernel \/tmp\/openwrt-kernel\.bin --ipk/);
  assert.match(job, /timeout-minutes: \d+/, 'TCG is slow; a hang must not run for six hours');
});
```

Append to `tests/openwrtPackage.test.js` (the same `BASHISMS` table applies):

```js
test('the QEMU guest script is POSIX sh and ends with the marker the driver looks for', () => {
  const src = fs.readFileSync(path.join(ROOT, 'openwrt', 'ci', 'guest-smoke.sh'), 'utf8');
  assert.match(src, /^#!\/bin\/sh\n/);
  for (const [re, what] of BASHISMS) assert.doesNotMatch(src, re, what);
  assert.match(src, /^set -eu$/m);
  assert.match(src, /say "SMOKE OK"\s*$/, 'the last line is the success marker');
  // the driver's own contract with it
  const drv = fs.readFileSync(path.join(ROOT, 'openwrt', 'ci', 'qemu-smoke.js'), 'utf8');
  assert.match(drv, /SMOKE OK/);
  assert.match(drv, /Please press Enter to activate this console/);
});
```

- [ ] **Step 6: Run the unit tests, then push and watch the QEMU job**

Run: `npm test` → green (workflow pins, POSIX scan, the driver parses under `syntax.test.js`).

Commit and push to `main` as a compile-check commit (the pattern the Android work used):

```bash
git add openwrt/ci .github/workflows/test.yml .github/workflows/release.yml tests/releaseWorkflow.test.js tests/openwrtPackage.test.js
git commit -m "wip: OpenWrt in QEMU as the CI gate, and the ipk in the release (first run)"
git push origin main
```

Watch `Tests` → `openwrt (qemu armsr-armv7)` with `node "$TEMP/irnf-ci-status.js" main`. Expected on the first run: it may be red. Read the console log in the job output (the guest's own words are there) and fix in order of likelihood, each as its own commit:

| Symptom in the log | Likely cause | Fix |
|---|---|---|
| never reaches "press Enter" | wrong machine/CPU or kernel path | `-M virt -cpu cortex-a15` is OpenWrt's own QEMU recipe for armsr/armv7; check the kernel downloaded (6.6 MB) |
| `opkg update` fails | no route/DNS in the guest | the `ip route add default via 192.168.1.2` step; slirp's DNS is `.3` |
| `kmod-tun` not found | kernel version mismatch between image and the kmods feed | pin the image and the feed to the SAME 24.10.2 (they are); else `opkg install kmod-tun` from `targets/armsr/armv7/kmods/<kver>/` |
| `ip: rule: unknown` | busybox `ip` without the rule applet | add `ip-tiny` to `DEPENDS` (Task 7) and to the guest's `opkg install` |
| `nft -f` rejects the file | syntax | the file is printed in the log; fix `buildNftRuleset` and its byte-exact test together |
| no `IRNetFree` device | sing-box did not start | `logread` tail is in the log: usually the config; compare with `buildTunConfig` |
| `oifname "IRNetFree"` absent | fw4 did not pick up the zone | `default_postinst` ran uci-defaults? (`uci get firewall.irnetfree` is asserted first); else `fw4 reload` in the defaults script |

- [ ] **Step 7: Commit the green state**

When the job is green:

```bash
git commit --allow-empty -m "openwrt: the QEMU gate is green — package installs, gateway comes up, exclusions apply live, teardown is clean"
git push origin main
```

(or fold the last fix into a non-empty commit with that message.)

---

### Task 9: the install guide, the release notes, v1.13.0

**Files:**
- Create: `docs/openwrt.md` (Persian), `docs/releases/v1.13.0.md`
- Modify: `README.md` (TOC line after the Android entry at line ~48; a new section after the Android section, before `## 🚀 انتشار خودکار`)
- Modify: `package.json:3`, `package-lock.json:3` and `:9` (NOT the `verror` entry further down), `android/app/build.gradle.kts:34` (`versionName` follows the desktop version by convention)

**Interfaces:** none new. Everything here is words and the version.

- [ ] **Step 1: The install guide**

`docs/openwrt.md`:

```markdown
# IRNetFree روی OpenWrt — روتر، تونلِ همهٔ دستگاه‌ها

از **v1.13.0**. همان برنامه (همان UI، همان منطق: ساب، زنجیره، پول، روتینگ، PattN، fastest) روی روتر
اجرا می‌شود و **هر دستگاهی که به روتر وصل است بدون هیچ تنظیمی از تونل می‌رود** — تلویزیون، کنسول، گوشیِ مهمان.
دستگاه‌هایی که بخواهی، با MAC، مستقیم می‌روند.

## روتر مناسب

- OpenWrt **24.10** (بستهٔ `node` در فید رسمی از همین نسخه هست).
- حداقل **256MB RAM** و **128MB فضا** (خودِ Node ~۳۶ مگ نصب می‌شود، هسته‌ها ۲۰–۴۰ مگ هرکدام؛ در اجرا ~۱۰۰–۱۵۰ مگ RAM).
- اولین هدف: **Google Wifi نسل اول (AC-1304)** — ipq40xx، ARMv7 چهارهسته، 512MB/4GB. صفحهٔ دستگاه در ویکی OpenWrt:
  `google_wifi` زیر `ipq40xx/chromium`؛ اول `squashfs-factory.bin` بعد برای به‌روزرسانی `sysupgrade.bin`.
- روترهای ۳۲–۶۴ مگی (MIPS ارزان) هدف نیستند: Node در آن‌ها جا نمی‌شود.

## نصب

```sh
# روی روتر (ssh root@192.168.1.1)
opkg update
opkg install node kmod-tun nftables unzip ca-bundle
# فایل ipk را از صفحهٔ ریلیز بگیر و روی روتر بگذار، مثلاً:
#   scp irnetfree_1.13.0_all.ipk root@192.168.1.1:/tmp/
opkg install /tmp/irnetfree_1.13.0_all.ipk
```

نصب، سرویس را فعال و اجرا می‌کند و یک zone فایروال به نام `irnetfree` برای دستگاه تونل می‌سازد (یک‌بار).

## باز کردن UI

- **LuCI → Services → IRNetFree → Open IRNetFree** — لینک با توکن را می‌دهد.
- یا دستی: `cat /etc/irnetfree/token` و بعد `http://192.168.1.1:6969/?token=<توکن>`.

توکن بدون LuCI هم لازم است: سرویس روی `0.0.0.0` گوش می‌دهد و بدون توکن هیچ درخواستی را جواب نمی‌دهد.

## هسته‌ها

**تنظیمات → فایل‌های موردنیاز** همان دانلودر دسکتاپ است و برای ARMv7 فایل درست را می‌گیرد
(`Xray-linux-arm32-v7a`, `sing-box-…-linux-armv7`). دو راه دیگر:

- `opkg install xray-core sing-box` — هسته‌های رسمی از فید؛ برنامه `/usr/bin` را هم می‌گردد.
- بدون دسترسی به گیت‌هاب از روتر: فایل را روی کامپیوتر بگیر و `scp` کن به `/etc/irnetfree/bin/`
  (نام فایل‌ها: `xray`، `xray-pattn`، `sing-box`؛ `chmod +x`). **PattN فقط از گیت‌هاب** می‌آید (در فید نیست).

## استفاده

1. ساب یا لینک را اضافه کن (مثل دسکتاپ). حالت TUN پیش‌فرض روشن است — روی روتر یعنی «کل شبکه».
2. **وصل شو.** از این لحظه هر دستگاه پشت روتر از تونل می‌رود. DNS همهٔ دستگاه‌ها هم از تونل جواب می‌گیرد
   (dnsmasq روتر دست نمی‌خورد؛ بستهٔ پورت ۵۳ به تونل می‌رود و هستهٔ خود برنامه جواب می‌دهد).
3. **تنظیمات → اجازه به شبکه محلی → دستگاه‌های شبکه**: فهرست دستگاه‌ها (از DHCP و جدول همسایه‌ها).
   تیک «مستقیم» یعنی آن دستگاه از تونل نمی‌رود؛ بی‌قطعی اعمال می‌شود.
4. «اتصال خودکار» را روشن کن تا بعد از ریبوت روتر خودش وصل شود.

## چک کردن روی دستگاه (چیزی که CI نمی‌تواند ببیند)

```sh
logread -e irnetfree | tail -50      # لاگ سرویس
ip link show IRNetFree               # دستگاه تونل بالاست؟
ip rule show | grep -E '2022|8999'   # قواعد sing-box و قاعدهٔ استثنا
nft list table inet irnetfree        # MACهای مستقیم
```

- گوشی بدون هیچ پروکسی → سایتِ فیلترشده باز شود؛ `ipwho.is` IP سرور را نشان دهد.
- دستگاهِ تیک‌خورده → IP واقعی خودت.
- `free -m` قبل و بعد از اتصال: مصرف RAM را در همین صفحهٔ ایشو گزارش کن؛ CI فقط در QEMU اندازه گرفته.

## چه چیزی هنوز نیست

- **کیل‌سوییچ**: اگر sing-box بیفتد، route ها می‌روند و شبکه تا بازیابی خودکار مستقیم می‌شود (اگر xray بیفتد، ترافیک
  می‌ماند و نشت نمی‌کند). «بستن WAN وقتی تونل نیست» در نسخهٔ بعد.
- سرور متفاوت برای هر دستگاه؛ روترهای کوچک؛ بسته‌بندی `apk` برای OpenWrt 25.

## حذف

```sh
/etc/init.d/irnetfree stop
opkg remove irnetfree
rm -rf /etc/irnetfree                      # داده‌ها و هسته‌ها
uci -q delete firewall.irnetfree; uci -q delete firewall.irnetfree_lan; uci commit firewall; fw4 reload
```
```

- [ ] **Step 2: README**

In the TOC, after the Android line, add:

```markdown
- [نسخه OpenWrt (روتر)](#-نسخه-openwrt-روتر)
```

After the Android section (before `## 🚀 انتشار خودکار (GitHub Actions Release)`), add:

```markdown
## 🛜 نسخه OpenWrt (روتر)

از **v1.13.0** همین برنامه روی روتر OpenWrt هم می‌رود — نه یک بازنویسی: `src/server/` (نسخهٔ headless) با
`node` از فید رسمی OpenWrt اجرا می‌شود، همان UI روی `http://<روتر>:6969` بالا می‌آید و **هر دستگاه پشت روتر بدون
هیچ تنظیمی از تونل می‌رود**. دستگاه‌های انتخابی با MAC مستقیم می‌روند (تنظیمات → دستگاه‌های شبکه).

- بک‌اند: `src/main/tunOpenwrt.js` — همان TUN sing-box دسکتاپ (روی لینوکس `auto_route` ترافیک فورواردشده را
  هم می‌گیرد) + یک جدول nftables برای استثناها. DNS روتر دست نمی‌خورد؛ پورت ۵۳ از تونل جواب می‌گیرد.
- بسته: `irnetfree_<v>_all.ipk` در هر ریلیز (`openwrt/build-ipk.js`)؛ وابسته به `node kmod-tun nftables unzip ca-bundle`.
- تست: CI یک OpenWrt واقعی را در QEMU بوت می‌کند، بسته را نصب و گیت‌وی را بالا می‌آورد (`openwrt/ci/`).
- هدف اول: **Google Wifi AC-1304**؛ هر روتر ≥256MB RAM / ≥128MB فضا.

راهنمای نصب و چک روی دستگاه: [`docs/openwrt.md`](docs/openwrt.md).
```

- [ ] **Step 3: Release notes**

`docs/releases/v1.13.0.md`:

```markdown
# v1.13.0 — OpenWrt: the router is the tunnel

A new platform. Windows, macOS and Android are unchanged in behaviour:
`git diff --stat v1.12.0..v1.13.0 -- src/main/` lists only the two new files
(`tunOpenwrt.js`, `openwrtNet.js`), the Linux arch rows in `downloader.js`,
and one default line in `main.js`.

## What it is

`irnetfree_1.13.0_all.ipk` installs the headless service on an OpenWrt 24.10
router (Google Wifi AC-1304 first; anything with ≥256 MB RAM and ≥128 MB
storage). The same UI, on `http://<router>:6969` with a token (LuCI →
Services → IRNetFree has the link). Every device behind the router goes
through the tunnel with no configuration on the device; devices you tick go
direct. PattN, sing-box, chains, pool, routing, subscriptions, fastest — the
same code, so the same features.

## How

`TunOpenwrt` composes the sing-box TUN backend: on Linux sing-box's
`auto_route` ends in `not iif lo → lookup 2022`, so forwarded LAN traffic —
and every port-53 packet — is routed into the TUN; the router's dnsmasq is
never touched. Around it: an nft table that marks packets from excluded MACs,
and one `ip rule` (pref 8999, before sing-box's 9000+) that sends marked
packets out the WAN. The exclusion list is replaced live; the tunnel is not
restarted for it. The start is verified (device present, policy route
present) and rolled back otherwise.

## Package

Built by `openwrt/build-ipk.js` — a Node script with its own ustar writer, so
the ipk is byte-identical on Windows and on the runner. procd init script
(respawn, `logread`), uci config, a uci-defaults script that adds the
`irnetfree` firewall zone once, three static LuCI files. Depends on `node
kmod-tun nftables unzip ca-bundle`; the cores are downloaded on the router or
taken from `opkg install xray-core sing-box` (`/usr/bin` is searched).

## Tested

- `npm test`: the nft text, the `ip rule` argv, lease/neighbour parsing, the
  backend's order and rollback with sing-box faked, the arch table, the
  service wiring, the ipk's contents and modes, every router-side script for
  bashisms, both workflows.
- CI boots OpenWrt 24.10.2 (armsr/armv7) in QEMU, installs node and the
  package, connects to a dead SOCKS upstream, and asserts the TUN device,
  sing-box's routes, our table with the excluded MAC, the fw4 zone, a live
  set change with the same sing-box pid, and a clean teardown.
- On the real AC-1304: the owner's, per `docs/openwrt.md`.

## Not in this version

Kill switch (block WAN while the tunnel is down), a server per device, small
MIPS routers, OpenWrt 25 `apk` packaging.
```

- [ ] **Step 4: Version**

`package.json` `"version": "1.13.0"`; `package-lock.json` lines 3 and 9 only (line ~3931 is the `verror` package and stays); `android/app/build.gradle.kts` `versionName … ?: "1.13.0"`. Check:

```bash
grep -n '"version": "1.13.0"' package.json package-lock.json
grep -n '1.13.0' android/app/build.gradle.kts
npm test
```

Expected: 3 matches (1 + 2), the gradle line, and `npm test` green with the new total.

- [ ] **Step 5: Commit, push, wait for `Tests` (including the QEMU job), tag**

```bash
git add docs/openwrt.md docs/releases/v1.13.0.md README.md package.json package-lock.json android/app/build.gradle.kts
git commit -m "v1.13.0 — OpenWrt: the router is the tunnel for every device behind it, with the devices you choose going direct"
git push origin main
node "$TEMP/irnf-ci-status.js" main      # all five jobs green
git tag -a v1.13.0 -m "OpenWrt: the router as the tunnel for the whole LAN"
git push origin v1.13.0
node "$TEMP/irnf-ci-status.js" v1.13.0   # Build & Release: all five jobs green
```

- [ ] **Step 6: Verify the release and the constraint**

```bash
git diff --stat v1.12.0..v1.13.0 -- src/main/
```

Expected: exactly `downloader.js`, `main.js` (1 line), `openwrtNet.js`, `tunOpenwrt.js`. The release page lists `irnetfree_1.13.0_all.ipk` (~1.5 MB) and `SHA256SUMS-openwrt.txt` next to the desktop and Android files. Report to the owner in Persian: the release URL, what to install on the AC-1304 (the three `opkg` lines), where the link is (LuCI → Services → IRNetFree), how the exclusions work, what CI proved and what only the device can (RAM, a real site through a phone), and that nothing on Windows/macOS/Android changed.

---

## Self-review against the spec

| Spec section | Task |
|---|---|
| §4.1 platform detection, parsers, nft text, rule argv, readers | 1, 2 |
| §4.2 `TunOpenwrt` contract, order, verify, rollback, live set, `managesDns` | 3 |
| §4.3 service wiring (`makeTun`, `/usr/bin`, `bypassMacs`, `net:lanDevices`, live apply, `flavor`) | 5 |
| §4.4 arch table | 4 |
| §4.5 package, init, uci, defaults, LuCI, release job | 7, 8 |
| §4.6 renderer card, inspector line, hidden rows, tun2socks not required | 6 |
| §4.7 install guide, README | 9 |
| §5 connect sequence | 3 + 5 (no new code; asserted end-to-end in 8) |
| §6 error handling | 3 (rollback, verify) + 8 (table of symptoms) |
| §7.1 unit tests | 1–8 |
| §7.2 QEMU job | 8 |
| §8 constraints (owner commits, `src/main` diff, Node core, i18n, both defaults) | Global Constraints; 5; 9 step 6 |
| §9 not in v1 | 9 (guide + notes say so) |
| §10 risks | 8 step 6 table |

Names used across tasks, checked: `isOpenwrt`, `validMacs`, `lanInterface`, `lanDevices`, `buildNftRuleset`, `bypassRuleArgs`, `BYPASS_MARK`, `BYPASS_RULE_PREF` (1→2→3→5); `TunOpenwrt.setBypassMacs`, `backendId = 'openwrt'`, `managesDns` (3→5→8); `flavor`, `tunBackendId`, `lanBypassMacs`, `net:lanDevices`, `window.api.lanDevices` (5→6→8); `buildIpk`, `PKG`, `DEPENDS`, `PREFIX`, `tar/untar/tgz/untgz` (7→8); `SMOKE OK`, `Please press Enter to activate this console` (8's script ↔ driver ↔ test).
