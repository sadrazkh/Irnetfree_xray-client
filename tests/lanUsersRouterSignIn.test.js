'use strict';
/**
 * The users module's router half, v1.40: a sign-in by a card's code (a
 * voucher, activated on its first sign-in through the users module's hook),
 * devices remembered by a sign-in (theirs for good, through the hook that the
 * admin's own pick takes), a top-up request from the status page, what the
 * status page is handed, the speeds through the shaper (tc takes them: the
 * table polices none; it cannot: the table polices them as v1.39), and a
 * MAC-NAT repeater's addresses — the controller over the fakes, its page
 * replaced by one that hands back the api it was given (no socket, no HTML:
 * router/portal.js has its own test) and its shaper by one that answers what
 * the test says.
 *
 * The hooks here do what the service's do: they write the store and then ask
 * the controller for a refresh — AWAITED, so a controller that called them
 * from inside its serial section would wait on itself; the hooks give up after
 * two seconds and say so, rather than hang the run.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const plan = require('../src/modules/lanUsers/router/plan');
const { createLanRouter } = require('../src/modules/lanUsers/router');
const { makeProxyServer } = require('../src/main/parser');
const { memFs, fakeLan, fakeGateway, fakeMeter } = require('./lanUsersRouterFakes');

const A = 'aa:bb:cc:dd:ee:01', B = 'aa:bb:cc:dd:ee:02', C = 'aa:bb:cc:dd:ee:03', R = 'aa:bb:cc:dd:ee:0a', X = 'aa:bb:cc:dd:ee:0c';
const P1 = 'aa:bb:cc:dd:ee:b1', P2 = 'aa:bb:cc:dd:ee:b2';
const T0 = Date.UTC(2026, 9, 29, 12, 0, 0);
const H = 3600000;
const SRV1 = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.10', port: 1080, name: 'home' }), { id: 'srv-1' });
const SRV2 = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.20', port: 1080, name: 'office' }), { id: 'srv-2' });
/** Three cards of one batch (model.js VOUCHER_ALPHABET: no I, L, O, 0, 1). */
const CODE1 = 'HK7M-29PW', CODE2 = 'ABCD-EFGH', CODE3 = 'QRST-UVWX';
const UNTIL = T0 / 1000 + 86400;

function store() {
  return {
    config: {
      transparent: { enabled: true, unassigned: 'login', sessionHours: 24, portalPort: 30822 },
      portal: { note: 'Pay by the 5th', contact: '0912 000 0000', requests: true },
      shaping: { down: 20000, up: 5000, smooth: true }
    },
    users: [
      { id: 'usr-ali', username: 'ali', password: 'pass-ali', name: 'Ali', target: 'srv-2', remember: true, enabled: true, maxDevices: 2 },
      { id: 'usr-sara', username: 'sara', password: 'pass-sara', name: 'Sara', target: 'srv-2', enabled: true, priority: 'high' },
      { id: 'usr-v1', username: CODE1, password: CODE1, name: 'Cards #1', target: 'srv-2', enabled: true, maxDevices: 1, voucher: { batch: 'bat-1', hours: 2, activatedAt: 0 } },
      { id: 'usr-v2', username: CODE2, password: CODE2, name: 'Cards #2', target: 'srv-2', enabled: true, maxDevices: 1, expiresAt: T0 - 1000, voucher: { batch: 'bat-1', hours: 2, activatedAt: T0 - 3 * H } },
      // a card that remembers devices: a contradiction the model forbids — the router must still never remember a card's device
      { id: 'usr-v3', username: CODE3, password: CODE3, name: 'Cards #3', target: 'srv-2', enabled: true, maxDevices: 1, remember: true, voucher: { batch: 'bat-1', hours: 0, activatedAt: 0 } }
    ],
    devices: []
  };
}

/**
 * The users module as the service hands it to the router (setMeter): the
 * meter's calls, and the three hooks over the test's own store — each writing
 * it and asking the controller for a refresh, as ipc.js's onChange does.
 */
function usersModule(st, clock, refresh, { hooks = true } = {}) {
  const base = fakeMeter();
  const calls = [];
  const requests = {};
  let holds = {};
  let speeds = {};
  const changed = async () => {
    await Promise.race([refresh(), new Promise((_, reject) => setTimeout(() => reject(new Error('the hook waited two seconds on the controller\'s refresh — a hook called from inside its serial section')), 2000).unref())]);
  };
  const baseUsage = base.usage.bind(base);
  const m = Object.assign(base, {
    calls, requests,
    setHolds(h) { holds = h; }, setSpeeds(s) { speeds = s; },
    speeds: () => speeds,
    usage() {
      const out = baseUsage();
      for (const [id, h] of Object.entries(holds)) out[id] = Object.assign({ bytes: 0, quotaBytes: 0 }, out[id], h);
      for (const [id, req] of Object.entries(requests)) (out[id] = out[id] || { bytes: 0, quotaBytes: 0, over: false }).request = req;
      return out;
    }
  });
  if (!hooks) return m;
  return Object.assign(m, {
    async assignDevice({ mac, userId, name }) {
      calls.push(['assign', mac, userId, name]);
      const have = st.devices.find((d) => d.mac === mac);
      if (have) Object.assign(have, { userId, remembered: true, at: clock() });
      else st.devices.push({ mac, name, userId, blocked: false, remembered: true, at: clock() });
      await changed();
      return true;
    },
    async activateVoucher(id) {
      calls.push(['activate', id]);
      const u = st.users.find((x) => x.id === id);
      if (!u || !u.voucher || u.voucher.activatedAt > 0) return false;
      u.voucher.activatedAt = clock();
      if (u.voucher.hours > 0) u.expiresAt = clock() + u.voucher.hours * H;
      await changed();
      return true;
    },
    request(id, { mac, at }) {
      calls.push(['request', id, mac]);
      if (requests[id]) return false;
      requests[id] = { at };
      return true;
    }
  });
}

/** A controller with the mode on over the fakes; `shaperMode`: what its shaper answers. */
async function setup({ st = store(), neigh = `192.168.1.23 lladdr ${A} REACHABLE\n192.168.1.24 lladdr ${B} REACHABLE\n192.168.1.25 lladdr ${C} REACHABLE\n`,
  leases = `${UNTIL} ${A} 192.168.1.23 phone-ali *\n${UNTIL} ${B} 192.168.1.24 laptop-b *\n`, shaperMode = 'police', hooks = true } = {}) {
  let clock = T0;
  const lan = fakeLan({ neigh, leases });
  const files = memFs();
  const logs = [];
  const shaperCalls = [];
  let api = null;
  let r = null;
  const meter = usersModule(st, () => clock, () => r.refresh(), { hooks });
  r = createLanRouter({
    openwrt: true, dataDir: '/etc/irnetfree', tmpDir: '/tmp', fs: files, run: lan.run, readFile: lan.readFile,
    getSettings: () => ({ modules: { lanUsers: true }, socksPort: 47808, httpPort: 47809, apiPort: 47885 }),
    getLanUsers: () => st, records: () => ({ servers: [SRV1, SRV2], groups: [], chains: [] }),
    getFreePorts: async (n) => Array.from({ length: n }, (_, i) => 41001 + i),
    log: (line, level) => logs.push([level, line]), now: () => clock, meter,
    // the page: its api alone, no socket
    createPortal: (o) => { api = o.api; return { host: o.host, port: o.port, listening: true, start: async () => ({ host: o.host, port: o.port }), stop: async () => {} }; },
    // the shaper: what the test says it is
    createShaper: (o) => {
      shaperCalls.push(['create', o.lanIf]);
      return {
        apply: async (d) => { shaperCalls.push(['apply', JSON.parse(JSON.stringify(d))]); return { mode: shaperMode, missing: shaperMode === 'tc' ? [] : ['tc-tiny', 'kmod-sched-core', 'kmod-ifb'] }; },
        stop: async () => { shaperCalls.push(['stop']); },
        info: () => ({ mode: shaperMode, missing: shaperMode === 'tc' ? [] : ['tc-tiny', 'kmod-sched-core', 'kmod-ifb'], line: { down: 1, up: 1 } })
      };
    },
    portalListen: { host: '127.0.0.1', port: 1 }, tickMs: 3600000
  });
  const tp = await r.prepare();
  const config = { inbounds: [{ tag: 'socks-in', port: 47808, sniffing: { enabled: true } }], outbounds: [{ tag: 'proxy', protocol: 'socks' }, { tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }], routing: { rules: [{ type: 'field', port: '0-65535', outboundTag: 'proxy' }] } };
  r.applyXray(config, { serverId: 'srv-1', plan: { mode: 'single', server: SRV1 }, settings: { lanUsersTp: tp, directInterface: 'eth0' } });
  const opts = await r.gatewayOptions(tp);
  const gw = fakeGateway();
  await r.gatewayUp(gw);
  assert.ok(api, 'the page was started with the controller\'s api');
  const table = () => (gw.loads.length ? gw.loads[gw.loads.length - 1] : opts.nft);
  const file = (tag) => JSON.parse(files.get(`/tmp/irnetfree-lu/${tag}.json`)).rules;
  return { r, st, lan, files, logs, meter, api, gw, opts, tp, shaperCalls, table, file, tick: (ms) => { clock += ms; }, now: () => clock };
}

/* ------------------------------ remembered devices ------------------------------ */

test('remember: a sign-in as a user who remembers devices makes the device theirs for good through the hook — the admin\'s binding in the next table, its hostname on the record; a user without it is a session; a card never', async () => {
  const s = await setup();
  try {
    const ok = await s.api.signIn({ mac: A, username: 'ali', password: 'pass-ali' });
    assert.equal(ok.ok, true);
    assert.deepEqual(s.meter.calls, [['assign', A, 'usr-ali', 'phone-ali']], 'the hook, once, with the hostname from the scan');
    assert.deepEqual(s.st.devices, [{ mac: A, name: 'phone-ali', userId: 'usr-ali', blocked: false, remembered: true, at: T0 }]);
    assert.deepEqual([s.table().allowed, s.table().authorized], [[A], []], 'the hook\'s refresh ran (no deadlock): the admin\'s set, not the session\'s');
    assert.deepEqual(ok.status.via, 'admin');
    assert.equal(ok.status.remembered, true);
    assert.ok(s.logs.some(([, l]) => l === `Users: ${A} is "ali"'s for good — remembered by its sign-in`), JSON.stringify(s.logs));
    // a second sign-in of a device that is the admin's already: nothing to assign again
    assert.equal((await s.api.signIn({ mac: A, username: 'ali', password: 'pass-ali' })).ok, true);
    assert.equal(s.meter.calls.length, 1);
    // sara does not remember: a session, no record
    const sara = await s.api.signIn({ mac: B, username: 'sara', password: 'pass-sara' });
    assert.equal(sara.status.via, 'login');
    assert.equal(s.st.devices.length, 1);
    assert.deepEqual(s.table().authorized, [{ mac: B, timeoutS: 86400 }]);
    // a card that "remembers" (a record the model forbids): never through the hook
    const card = await s.api.signIn({ mac: C, code: CODE3 });
    assert.equal(card.ok, true, JSON.stringify(card));
    assert.deepEqual(s.meter.calls.filter((c) => c[0] === 'assign').length, 1, 'no assignment for a card');
    assert.equal(card.status.via, 'login');
    // maxDevices counts the remembered one: ali's second device signs in, a third is refused
    s.lan.neigh += `192.168.1.26 lladdr ${X} REACHABLE\n192.168.1.27 lladdr ${R} REACHABLE\n`;
    assert.equal((await s.api.signIn({ mac: X, username: 'ali', password: 'pass-ali' })).ok, true);
    assert.deepEqual(await s.api.signIn({ mac: R, username: 'ali', password: 'pass-ali' }), { ok: false, code: 'maxDevices', max: 2 });
  } finally { await s.r.stop(); }
});

test('remember without the hook (an older users module): the sign-in is a session, said once in the log', async () => {
  const s = await setup({ hooks: false });
  try {
    const ok = await s.api.signIn({ mac: A, username: 'ali', password: 'pass-ali' });
    assert.equal(ok.ok, true);
    assert.equal(ok.status.via, 'login');
    assert.deepEqual(s.st.devices, []);
    await s.api.signIn({ mac: B, username: 'ali', password: 'pass-ali' });
    assert.equal(s.logs.filter(([lvl, l]) => lvl === 'warn' && /offers the router no assignDevice\(\)/.test(l)).length, 1);
  } finally { await s.r.stop(); }
});

/* ------------------------------ vouchers ------------------------------ */

test('voucher: a card\'s code signs a device in — typed as a phone types it — activates the card (the hook: activatedAt, expiry) and ends the session with the card; the code is never logged', async () => {
  const s = await setup();
  try {
    const ok = await s.api.signIn({ mac: C, code: 'hk7m 29pw' });
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.deepEqual(s.meter.calls, [['activate', 'usr-v1']]);
    const v1 = s.st.users.find((u) => u.id === 'usr-v1');
    assert.deepEqual([v1.voucher.activatedAt, v1.expiresAt], [T0, T0 + 2 * H]);
    assert.deepEqual(s.r.sessions[C], { userId: 'usr-v1', until: T0 + 2 * H, at: T0 }, 'the session ends with the card, not after the configured 24 h');
    assert.deepEqual(s.table().authorized, [{ mac: C, timeoutS: 7200 }]);
    assert.deepEqual(s.file('lu-tp-3'), [{ source_ip_cidr: ['192.168.1.25/32'] }], 'the card\'s own inbound (usr-v1 is the third by id)');
    assert.deepEqual(ok.status.voucher, { hours: 2, activatedAt: T0, expiresAt: T0 + 2 * H });
    assert.equal(ok.status.expiresAt, T0 + 2 * H);
    assert.equal(ok.status.name, 'Cards #1');
    const text = JSON.stringify(s.logs);
    assert.ok(!text.includes('HK7M') && !text.includes('hk7m'), 'the code is the card\'s password: never in the log — ' + text);
    assert.ok(s.logs.some(([, l]) => l === `Users: ${C} signed in with a card ("Cards #1") for 2 h`), text);
    // a second sign-in of the same card from the same device: already active, nothing to activate
    assert.equal((await s.api.signIn({ mac: C, code: CODE1 })).ok, true);
    assert.equal(s.meter.calls.length, 1);
    // another device on the same card: its one device is taken
    assert.deepEqual(await s.api.signIn({ mac: B, code: CODE1 }), { ok: false, code: 'maxDevices', max: 1 });
    // the card's time passes: its session ended with it, the device meets the gate again, and the card is refused as expired
    s.tick(2 * H + 1);
    await s.r.tick();
    assert.deepEqual([s.r.sessions, s.table().authorized], [{}, []]);
    assert.deepEqual(await s.api.signIn({ mac: C, code: CODE1 }), { ok: false, code: 'expired' });
  } finally { await s.r.stop(); }
});

test('voucher: a wrong code, a code outside the alphabet, an expired card, a spent card — refused as the page already says it; nothing activated', async () => {
  const s = await setup();
  try {
    assert.deepEqual(await s.api.signIn({ mac: B, code: 'ZZZZ-ZZZZ' }), { ok: false, code: 'bad', why: 'code' });
    assert.deepEqual(await s.api.signIn({ mac: B, code: 'HK7M-29PL' }), { ok: false, code: 'bad', why: 'code' }, 'L is not in the alphabet: no such card, the same answer');
    assert.deepEqual(await s.api.signIn({ mac: B, code: '' , username: '', password: '' }), { ok: false, code: 'bad', why: 'user' }, 'an empty code is no code: the username path');
    const said = s.logs.filter(([, l]) => /was refused/.test(l)).map(([, l]) => l);
    assert.equal(said.length, 3);
    assert.match(said[0], /refused \(no card with that code\)$/);
    assert.ok(!said[0].includes('ZZZZ') && !said[1].includes('29PL'), 'never the code itself');
    assert.deepEqual(await s.api.signIn({ mac: B, code: CODE2 }), { ok: false, code: 'expired' });
    s.meter.setHolds({ 'usr-v1': { hold: 'all', why: 'total', holdUntil: 0, over: true } });
    assert.deepEqual(await s.api.signIn({ mac: B, code: CODE1 }), { ok: false, code: 'total' }, 'spent: the meter\'s one-off total limit holds it');
    assert.deepEqual(s.meter.calls, [], 'no activation for a refusal');
    assert.deepEqual(s.r.sessions, {});
  } finally { await s.r.stop(); }
});

test('voucher: a card with no time limit, and one signed in by its username and password (the code twice) — activated the same; without the hook the session still ends with the card\'s hours', async () => {
  const s = await setup();
  try {
    const noLimit = await s.api.signIn({ mac: C, code: CODE3 });
    assert.equal(noLimit.ok, true);
    const v3 = s.st.users.find((u) => u.id === 'usr-v3');
    assert.deepEqual([v3.voucher.activatedAt, v3.expiresAt || 0], [T0, 0], 'no hours: activated, never expires');
    assert.deepEqual(s.r.sessions[C], { userId: 'usr-v3', until: T0 + 24 * H, at: T0 }, 'the configured session hours');
    assert.deepEqual(noLimit.status.voucher, { hours: 0, activatedAt: T0, expiresAt: 0 });
    const byName = await s.api.signIn({ mac: B, username: CODE1, password: CODE1 });
    assert.equal(byName.ok, true, JSON.stringify(byName));
    assert.deepEqual(s.meter.calls, [['activate', 'usr-v3'], ['activate', 'usr-v1']]);
  } finally { await s.r.stop(); }
  const t = await setup({ hooks: false });
  try {
    const ok = await t.api.signIn({ mac: C, code: CODE1 });
    assert.equal(ok.ok, true);
    assert.deepEqual(t.r.sessions[C], { userId: 'usr-v1', until: T0 + 2 * H, at: T0 }, 'the card\'s hours counted from now');
    assert.equal(t.st.users.find((u) => u.id === 'usr-v1').voucher.activatedAt, 0, 'nothing wrote the store: the meter\'s first bytes will');
    assert.equal(t.logs.filter(([lvl, l]) => lvl === 'warn' && /offers the router no activateVoucher\(\)/.test(l)).length, 1);
  } finally { await t.r.stop(); }
});

/* ------------------------------ a top-up request, the status page ------------------------------ */

test('request: the status page asks for a top-up — sent once, then "already"; nobody\'s device, requests off, or no hook: refused with why; the status carries it with the note and contact', async () => {
  const s = await setup();
  try {
    assert.deepEqual(await s.api.requestTopUp(B), { ok: false, code: 'nouser' });
    await s.api.signIn({ mac: B, username: 'sara', password: 'pass-sara' });
    assert.deepEqual(await s.api.requestTopUp(B), { ok: true, code: 'sent' });
    assert.deepEqual(await s.api.requestTopUp(B), { ok: true, code: 'already' });
    assert.deepEqual(s.meter.calls.filter((c) => c[0] === 'request'), [['request', 'usr-sara', B], ['request', 'usr-sara', B]]);
    assert.deepEqual(s.meter.requests, { 'usr-sara': { at: T0 } });
    assert.ok(s.logs.some(([, l]) => l === `Users: "Sara" asked for a top-up from ${B}`));
    const st = await s.api.statusOf(B);
    assert.deepEqual([st.request, st.note, st.contact, st.requests, st.expiresAt, st.voucher, st.remembered, st.schedule], [{ at: T0 }, 'Pay by the 5th', '0912 000 0000', true, 0, null, false, null]);
    s.st.users.find((u) => u.id === 'usr-sara').schedule = { days: [1, 2], from: '08:00', to: '20:00' };
    assert.deepEqual((await s.api.statusOf(B)).schedule, { days: [1, 2], from: '08:00', to: '20:00' }, 'the allowed hours, for the page');
    const notCode = await s.api.signIn({ mac: C, username: 'sara', password: 'pass-sara', code: { not: 'a string' } });
    assert.equal(notCode.ok, true, 'a code that is no string is no code: the username and password decide');
    s.st.config.portal.requests = false;
    assert.deepEqual(await s.api.requestTopUp(B), { ok: false, code: 'off' });
    assert.equal((await s.api.statusOf(B)).requests, false);
  } finally { await s.r.stop(); }
  const t = await setup({ hooks: false });
  try {
    await t.api.signIn({ mac: B, username: 'sara', password: 'pass-sara' });
    assert.deepEqual(await t.api.requestTopUp(B), { ok: false, code: 'off' });
    assert.equal(t.logs.filter(([lvl, l]) => lvl === 'warn' && /offers the router no request\(\)/.test(l)).length, 1);
    assert.equal((await t.api.statusOf(B)).request, null);
  } finally { await t.r.stop(); }
});

/* ------------------------------ the shaper ------------------------------ */

test('shaping: with smooth limits the decision\'s classes go to the shaper once per change; tc taking them, the table polices no speed; a change applies again; the shaper stops with the gateway', async () => {
  const st = store();
  st.devices = [{ mac: A, userId: 'usr-ali' }, { mac: B, userId: 'usr-sara' }];
  const s = await setup({ st, shaperMode: 'tc' });
  try {
    s.meter.setSpeeds({ 'usr-ali': { down: 2000, up: 500, why: ['base'] } });
    await s.r.tick();
    const shape = { line: { down: 20000, up: 5000 }, classes: [{ mac: A, ips: ['192.168.1.23'], down: 2000, up: 500, prio: 'normal' }, { mac: B, ips: ['192.168.1.24'], down: 0, up: 0, prio: 'high' }] };
    assert.deepEqual(s.shaperCalls, [['create', 'br-lan'], ['apply', { line: { down: 20000, up: 5000 }, classes: [{ mac: B, ips: ['192.168.1.24'], down: 0, up: 0, prio: 'high' }] }], ['apply', shape]],
      'the gateway\'s start (sara\'s priority alone), then ali\'s speed');
    assert.deepEqual(s.r.decision.nft.rates, [{ mac: A, ips: ['192.168.1.23'], down: 2000, up: 500 }], 'the decision still names the speed');
    assert.deepEqual(s.table().rates, [], 'tc took it: the table polices nothing');
    assert.deepEqual(s.r.shaperInfo(), { mode: 'tc', missing: [], line: { down: 20000, up: 5000 } });
    await s.r.tick();
    assert.equal(s.shaperCalls.length, 3, 'nothing changed: not applied again');
    s.meter.setSpeeds({ 'usr-ali': { down: 1000, up: 0, why: ['hours'] } });
    await s.r.tick();
    assert.equal(s.shaperCalls.length, 4);
    assert.deepEqual(s.shaperCalls[3][1].classes[0], { mac: A, ips: ['192.168.1.23'], down: 1000, up: 0, prio: 'normal' });
    assert.deepEqual(s.table().rates, []);
    assert.ok(s.logs.some(([, l]) => /the speeds are shaped with tc/.test(l)));
    // the admin turns smooth limits off: the shaper is stopped, the table polices as v1.39
    st.config.shaping.smooth = false;
    await s.r.tick();
    assert.deepEqual(s.shaperCalls[4], ['stop']);
    assert.deepEqual(s.table().rates, [{ mac: A, ips: ['192.168.1.23'], down: 1000, up: 0 }]);
    assert.deepEqual(s.r.shaperInfo(), { mode: 'police', missing: [], line: { down: 20000, up: 5000 } });
    st.config.shaping.smooth = true;
    await s.r.tick();
    assert.deepEqual(s.shaperCalls.slice(5).map((c) => c[0]), ['create', 'apply'], 'made again');
    await s.r.stop();
    assert.deepEqual(s.shaperCalls[s.shaperCalls.length - 1], ['stop'], 'stopped with the gateway');
    assert.deepEqual(s.r.shaperInfo(), { mode: 'off', missing: [], line: { down: 20000, up: 5000 } });
  } finally { await s.r.stop(); }
});

test('shaping: when the shaper cannot (no tc: mode police with the packages to install), the table polices exactly as v1.39; the first table of the gateway too', async () => {
  const st = store();
  st.devices = [{ mac: A, userId: 'usr-ali' }, { mac: B, userId: 'usr-sara' }];
  const s = await setup({ st, shaperMode: 'police' });
  try {
    s.meter.setSpeeds({ 'usr-ali': { down: 2000, up: 500, why: ['base'] } });
    await s.r.tick();
    assert.deepEqual(s.table().rates, [{ mac: A, ips: ['192.168.1.23'], down: 2000, up: 500 }]);
    assert.deepEqual(s.r.shaperInfo(), { mode: 'police', missing: ['tc-tiny', 'kmod-sched-core', 'kmod-ifb'], line: { down: 20000, up: 5000 } });
    assert.ok(s.logs.some(([, l]) => /policed in the table — tc is not there \(install tc-tiny kmod-sched-core kmod-ifb\)/.test(l)), JSON.stringify(s.logs));
    const text = require('../src/main/openwrtNet').buildNftRuleset({ lanUsers: s.table() });
    assert.ok(text.includes(`    iifname "br-lan" ether saddr ${A} limit rate over 63 kbytes/second burst 64 kbytes counter drop\n`), text);
  } finally { await s.r.stop(); }
  // the gateway's first table, with a speed from the start and tc
  const st2 = store();
  st2.devices = [{ mac: A, userId: 'usr-ali' }];
  const meterSpeeds = { 'usr-ali': { down: 2000, up: 500 } };
  const t = await setup({ st: st2, shaperMode: 'tc' });
  try {
    // the meter's speeds existed before the start in a real service; here the start saw none — so a tick with them is the first table that carries the speed
    t.meter.setSpeeds(meterSpeeds);
    await t.r.tick();
    assert.deepEqual(t.table().rates, []);
  } finally { await t.r.stop(); }
});

/* ------------------------------ case C in the controller ------------------------------ */

test('case C: a repeater\'s addresses (leases naming phones never on the wire) are the repeater\'s — its user\'s rule-set, counter, speed and pins; a device taking one of them while the repeater is online gets nothing; the repeater gone, the address is the taker\'s own', async () => {
  const st = store();
  st.devices = [{ mac: R, name: 'extender', userId: 'usr-sara' }];
  const leases = `${UNTIL} ${P1} 192.168.1.21 phone-d *\n${UNTIL} ${P2} 192.168.1.22 phone-e *\n`;
  const s = await setup({ st, leases, neigh: `192.168.1.21 lladdr ${R} REACHABLE\n192.168.1.22 lladdr ${R} STALE\n` });
  try {
    s.meter.setSpeeds({ 'usr-sara': { down: 3000, up: 1000 } });
    await s.r.tick();
    const t = s.table();
    assert.deepEqual(t.allowed, [R]);
    assert.deepEqual(t.ipmac, [{ mac: R, ips: ['192.168.1.21', '192.168.1.22'] }], 'both addresses pinned to the repeater');
    assert.deepEqual(t.rates, [{ mac: R, ips: ['192.168.1.21', '192.168.1.22'], down: 3000, up: 1000 }], 'its user\'s speed polices both');
    const ctr = Object.fromEntries(t.counters.map((c) => [c.mac, c.ips]));
    assert.deepEqual([ctr[R], ctr[P1], ctr[P2]], [['192.168.1.21', '192.168.1.22'], [], []], 'the bytes are the repeater\'s; the phones\' MACs count nothing');
    assert.deepEqual(s.file('lu-tp-2'), [{ source_ip_cidr: ['192.168.1.21/32', '192.168.1.22/32'] }], 'sara\'s inbound routes both (usr-sara is the second by id)');
    // X (nobody's) takes .21 while the repeater still answers for .22: the lease's claim holds for the repeater's user — no, the LEASE is the phone's;
    // the repeater is not the lease holder, so .21 goes to whoever answers for it — X — and X is nobody's: no pin, nothing of sara's
    s.lan.neigh = `192.168.1.21 lladdr ${X} REACHABLE\n192.168.1.22 lladdr ${R} STALE\n`;
    await s.r.tick();
    assert.deepEqual(s.table().ipmac, [{ mac: R, ips: ['192.168.1.22'] }]);
    assert.deepEqual(s.file('lu-tp-2'), [{ source_ip_cidr: ['192.168.1.22/32'] }]);
    assert.deepEqual(Object.fromEntries(s.table().counters.map((c) => [c.mac, c.ips]))[X], ['192.168.1.21'], 'the address is X\'s own now — and X meets the gate by its MAC');
    // the repeater's own lease: an address IT holds the lease of stays its while it is online, whoever answers for it
    s.lan.leases = leases + `${UNTIL} ${R} 192.168.1.30 extender *\n`;
    s.lan.neigh = `192.168.1.30 lladdr ${X} REACHABLE\n192.168.1.22 lladdr ${R} STALE\n`;
    await s.r.tick();
    assert.deepEqual(s.table().ipmac, [{ mac: R, ips: ['192.168.1.30', '192.168.1.22'] }], 'the repeater is online (.22): its leased .30 stays its, X\'s packets from it are dropped');
    assert.deepEqual(Object.fromEntries(s.table().counters.map((c) => [c.mac, c.ips]))[X], []);
    // the repeater gone (no entry of its own anywhere): its leased .30 is whoever answers for it — X, nobody's
    s.lan.neigh = `192.168.1.30 lladdr ${X} REACHABLE\n`;
    await s.r.tick();
    assert.deepEqual(s.table().ipmac, []);
    assert.deepEqual(s.file('lu-tp-2'), []);
  } finally { await s.r.stop(); }
});
