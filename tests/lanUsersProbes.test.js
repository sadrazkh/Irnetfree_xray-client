'use strict';
/**
 * scripts/probe-lan-users.js (the users' proxy accounts, loopback, CI's `cores`
 * job) and scripts/probe-lan-portal.js (the router's transparent mode in
 * network namespaces, CI's `lan-users` job) — kept honest here without a core
 * or root: they refuse to run anywhere but CI, they never take the app's own
 * ports, what they hand the builder is the store's shape (contract B), their
 * own readers (the nft counters, the login form) read what they say, and the
 * jobs run them on both suggested cores.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const SCRIPTS = path.join(__dirname, '..', 'scripts');
const U = require('../scripts/probe-lan-users');
const L = require('../scripts/probe-lan-portal');
const { normalizeMac } = require('../src/main/openwrtNet');

const YML = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'test.yml'), 'utf8').replace(/\r\n/g, '\n');
/** One job of test.yml, as text: from `  <name>:` to the next job. */
function job(name) {
  const at = YML.indexOf(`\n  ${name}:\n`);
  assert.ok(at >= 0, `test.yml has a ${name} job`);
  const rest = YML.slice(at + 1);
  const end = rest.slice(1).search(/\n {2}[a-z][\w-]*:\n/);
  return end === -1 ? rest : rest.slice(0, end + 1);
}
const ports = (P) => [].concat(...Object.values(P));

test('both probes run only in CI: without their flag (and, for the router one, Linux and root) they refuse before touching anything', () => {
  for (const [file, flag] of [['probe-lan-users.js', 'IRNF_LU_PROBE'], ['probe-lan-portal.js', 'IRNF_LP_PROBE']]) {
    const r = spawnSync(process.execPath, [path.join(SCRIPTS, file)], {
      encoding: 'utf8', env: Object.assign({}, process.env, { [flag]: '' }), timeout: 15000
    });
    assert.equal(r.status, 2, file);
    assert.match(r.stderr, /CI only/, file);
  }
});

test('the probes’ ports: never the app’s own, nor the users’ defaults — on the default base and on every base CI gives them', () => {
  for (const [M, file] of [[U, 'probe-lan-users.js'], [L, 'probe-lan-portal.js']]) {
    for (const p of [10808, 10809, 10085, 30808, 30809, 30085, 30820, 30821, 30822]) assert.ok(M.APP_PORTS.includes(p), `${file}: ${p} is the app's`);
    const bases = [M.BASE, ...[...YML.matchAll(new RegExp(`IRNF_PROBE_PORT=(\\d+)[^\\n]*scripts/${file.replace('.', '\\.')}`, 'g'))].map((m) => Number(m[1]))];
    assert.ok(bases.length >= 2, `${file}: CI runs it on a second base`);
    for (const base of bases) {
      for (const p of ports(M.P)) assert.equal(M.APP_PORTS.includes(p - M.BASE + base), false, `${file}: port ${p - M.BASE + base} on base ${base}`);
    }
  }
  // the users' own ports in the store are the probe's, not the defaults
  assert.deepEqual([U.probeLanUsers().config.proxy.port, U.probeLanUsers().config.proxy.httpPort], [U.P.luSocks, U.P.luHttp]);
  assert.equal(L.probeLanUsers().config.transparent.portalPort, L.P.portal);
});

test('what the probes hand the builder is the store’s shape (contract B): every user key, valid names and passwords, the inactive ones that must be refused', () => {
  const KEYS = ['enabled', 'expiresAt', 'id', 'maxDevices', 'name', 'password', 'quotaGb', 'quotaPeriod', 'target', 'username'];
  for (const lu of [U.probeLanUsers(), U.probeLanUsers(false), L.probeLanUsers()]) {
    assert.deepEqual(Object.keys(lu).sort(), ['config', 'devices', 'users']);
    assert.deepEqual(Object.keys(lu.config.proxy).sort(), ['enabled', 'httpPort', 'port']);
    assert.deepEqual(Object.keys(lu.config.transparent).sort(), ['enabled', 'portalPort', 'sessionHours', 'unassigned']);
    const names = new Set();
    for (const u of lu.users) {
      assert.deepEqual(Object.keys(u).sort(), KEYS, u.username);
      assert.match(u.username, /^[A-Za-z0-9._-]{1,32}$/);
      assert.ok(u.password.length >= 4, u.username);
      assert.match(u.id, /^usr-/);
      assert.ok(['day', 'month', 'none'].includes(u.quotaPeriod));
      assert.equal(names.has(u.username), false, 'usernames are unique');
      names.add(u.username);
    }
    for (const d of lu.devices) assert.equal(normalizeMac(d.mac), d.mac, 'a MAC as the store keeps it');
  }
  // the loopback probe: the active users are accounts, carol (disabled) and gina (expired) must be refused
  const lu = U.probeLanUsers();
  const by = Object.fromEntries(lu.users.map((u) => [u.username, u]));
  assert.deepEqual(U.ACTIVE.map((n) => by[n].enabled && !by[n].expiresAt), U.ACTIVE.map(() => true));
  assert.equal(by.carol.enabled, false);
  assert.ok(by.gina.expiresAt > 0 && by.gina.expiresAt < Date.now(), 'gina expired');
  assert.notEqual(by.alice.target, by.bob.target, 'two users, two servers');
  assert.equal(U.probeLanUsers(false).config.proxy.enabled, false);
  assert.equal(U.probeLanUsers().config.transparent.enabled, false, 'transparent mode is the router’s');
  // the router probe: transparent on, the proxy accounts off; A is alice's, B nobody's; the push trips her cap
  const r = L.probeLanUsers();
  assert.equal(r.config.transparent.enabled, true);
  assert.equal(r.config.transparent.unassigned, 'login');
  assert.equal(r.config.proxy.enabled, false, 'transparent mode must not need the proxy accounts');
  assert.deepEqual(r.devices.map((d) => [d.mac, d.userId]), [[L.DEV.a.mac, 'usr-alice']]);
  const alice = r.users.find((u) => u.username === 'alice');
  assert.ok(alice.quotaGb * 1024 * 1024 * 1024 < 0.9 * L.PUSH, 'what A downloads is past alice’s cap');
  assert.equal(L.usageOf(alice, L.PUSH).over, true);
  assert.equal(L.usageOf(alice, 1000).over, false);
});

test('the router probe’s devices: fixed, locally administered MACs, two addresses in the LAN, links named within the kernel’s 15 characters', () => {
  const devs = Object.values(L.DEV);
  assert.equal(new Set(devs.map((d) => d.mac)).size, devs.length);
  for (const d of devs) {
    assert.equal(normalizeMac(d.mac), d.mac);
    assert.equal(parseInt(d.mac.slice(0, 2), 16) & 3, 2, 'locally administered, unicast');
    assert.ok(d.ip.startsWith(L.LAN_IP.split('.').slice(0, 3).join('.') + '.') && d.ip !== L.LAN_IP);
  }
  for (const n of [L.LAN_IF, L.WAN.dev, L.WAN.peer, ...devs.flatMap((d) => [d.dev, d.port])]) assert.ok(n.length <= 15, n);
  assert.equal(new Set(Object.values(L.NS)).size, 4, 'four namespaces of its own');
});

test('module off is inert in both probes’ configs: the config of before, byte for byte (the gate CI also runs)', () => {
  const c = U.buildProbeConfigs();
  assert.equal(JSON.stringify(c.off), JSON.stringify(c.none));
  assert.equal(JSON.stringify(c.proxyOff), JSON.stringify(c.none));
  const r = L.buildPureConfigs();
  assert.equal(JSON.stringify(r.off), JSON.stringify(r.before));
  // and the users' part is only ever read from what the builder wrote
  assert.deepEqual(U.luInbounds(c.none), []);
  assert.deepEqual(L.tpInbounds(r.before), []);
});

test('the probes’ own readers: a user’s inbound and counter, the nft counters per device, the login form', () => {
  const cfg = { inbounds: [
    { tag: 'socks-in', protocol: 'socks', port: 1 },
    { tag: 'lu-socks', protocol: 'socks', port: U.P.luSocks, settings: { auth: 'password', accounts: [{ user: 'alice', pass: 'a' }, { user: 'bob', pass: 'b' }] } },
    { tag: 'lu-http', protocol: 'http', port: U.P.luHttp, settings: { accounts: [{ user: 'alice', pass: 'a' }] } }
  ] };
  assert.deepEqual(U.luInbounds(cfg).map((i) => i.tag), ['lu-socks', 'lu-http']);
  assert.equal(U.inboundFor(cfg, 'socks', 'bob', U.P.luSocks).tag, 'lu-socks');
  assert.equal(U.inboundFor(cfg, 'socks', 'carol', U.P.luSocks).port, U.P.luSocks, 'someone in no account list dials the shared port');
  assert.deepEqual(U.counterOf({ stats: { user: { alice: { uplink: 3, downlink: 7 } } } }, { username: 'alice', id: 'usr-alice' }, cfg), { key: 'stats.user.alice', up: 3, down: 7 });
  assert.equal(U.counterOf({ stats: { user: {} } }, { username: 'carol', id: 'usr-carol' }, cfg), null);

  const nft = { nftables: [
    { counter: { name: 'dev_02_1a_00_00_00_a1', packets: 3, bytes: 300 } },
    { rule: { chain: 'fwd', handle: 7, expr: [{ match: { op: '==', left: { payload: { protocol: 'ip', field: 'daddr' } }, right: L.DEV.a.ip } }, { counter: { packets: 1, bytes: 1000 } }] } },
    { set: { name: 'devs', elem: [{ elem: { val: L.DEV.b.mac, counter: { packets: 2, bytes: 50 } } }] } },
    { rule: { chain: 'pre', handle: 3, expr: [{ match: { right: '@bypass_macs' } }, { counter: { packets: 9, bytes: 999 } }] } },
    { set: { name: 'blocked', elem: [L.DEV.a.mac] } }
  ] };
  const b = L.macBytes(nft, Object.values(L.DEV));
  assert.equal(b[L.DEV.a.mac].bytes, 1300, 'a named counter and a rule by its address');
  assert.equal(b[L.DEV.b.mac].bytes, 50, 'a set element’s own counter');
  assert.deepEqual(L.nftSets(nft), { devs: [L.DEV.b.mac], blocked: [L.DEV.a.mac] });

  const page = { ok: true, status: 200, via: `http://${L.LAN_IP}:${L.P.portal}/`,
    body: '<form method="post" action="/login"><input type="hidden" name="t" value="x"><input name="u" type="text"><input type="password" name="p"></form>' };
  assert.deepEqual(L.loginForm(page), { url: `http://${L.LAN_IP}:${L.P.portal}/login`, host: L.LAN_IP, port: L.P.portal, path: '/login', method: 'POST', user: 'u', pass: 'p', hidden: [['t', 'x']] });
  // a page served in place of the request (DNAT'd): a relative action goes back where the page came from
  assert.equal(L.loginForm({ ok: true, status: 200, base: `http://${L.TARGET}/`, body: '<form><input name=user><input type=password name=pass></form>' }).url, `http://${L.TARGET}/login`);
  assert.equal(L.loginForm({ ok: true, status: 200, body: 'S1' }), null, 'a server’s page is no login page');
});

test('CI: the `cores` job runs the users’ loopback probe on the suggested Xray, then Xray-PattN on its own ports, the second whatever the first did', () => {
  const j = job('cores');
  const step = j.slice(j.indexOf('- name: LAN users'));
  assert.ok(step.length > 20, 'a LAN users step');
  // the command lines, not the comment that names the script
  const runs = step.split('\n').filter((l) => /^\s+IRNF_LU_PROBE=1 .*scripts\/probe-lan-users\.js/.test(l));
  assert.equal(runs.length, 2, 'one run per core, each with IRNF_LU_PROBE=1');
  assert.match(runs[0], /IRNF_XRAY_EXE="\$RUNNER_TEMP\/x\/xray" node scripts\/probe-lan-users\.js \|\| rc=1/);
  assert.match(runs[1], /IRNF_XRAY_EXE="\$RUNNER_TEMP\/p\/xray" IRNF_PROBE_PORT=\d+ node scripts\/probe-lan-users\.js \|\| rc=1/);
  assert.match(step, /if: \$\{\{ !cancelled\(\) \}\}\n\s+timeout-minutes: \d+/);
});

test('CI: the `lan-users` job runs the router probe with sudo on both sing-box lines, the suggested Xray then Xray-PattN, the second whatever the first did', () => {
  const j = job('lan-users');
  assert.match(j, /runs-on: ubuntu-latest/);
  assert.match(j, /timeout-minutes: \d+/);
  assert.match(j, /singbox: \['1\.13\.14', '1\.14\.3'\]/);
  assert.match(j, /fail-fast: false/);
  for (const read of ['SUGGESTED.xray', "SUGGESTED['xray-pattn']"]) assert.ok(j.includes(`require('./src/main/coreVersions').${read}`), read);
  assert.match(j, /sing-box-\$SV-linux-amd64\.tar\.gz/);
  assert.match(j, /command -v nft/, 'nft is there before the probe asks for it');
  const runs = j.split('\n').filter((l) => /^\s+run: .*scripts\/probe-lan-portal\.js/.test(l));
  assert.equal(runs.length, 2, 'one run per core');
  for (const l of runs) assert.match(l, /sudo IRNF_LP_PROBE=1 .*IRNF_SINGBOX_EXE="\$RUNNER_TEMP\/s\/sing-box" .*"\$\(command -v node\)" scripts\/probe-lan-portal\.js/);
  assert.match(runs[0], /IRNF_XRAY_EXE="\$RUNNER_TEMP\/x\/xray"/);
  assert.match(runs[1], /IRNF_XRAY_EXE="\$RUNNER_TEMP\/p\/xray" .*IRNF_PROBE_PORT=\d+/);
  assert.match(j, /if: \$\{\{ !cancelled\(\) \}\}\n\s+timeout-minutes: \d+\n\s+run: sudo [^\n]*\$RUNNER_TEMP\/p\/xray/, 'the PattN run also after a failure');
});
