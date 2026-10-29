'use strict';
/**
 * Users and devices, round 2 (v1.40.0) — the core: the record's new fields
 * (remember, priority, filter, voucher; a device's remembered / at; the
 * portal's note and the shaping line), voucher codes, the meter's months,
 * requests, first use and backup state, and the channels and hooks over them
 * (vouchers in batches, a batch deleted, a request dismissed, the module's own
 * backup and restore, assignDevice / activateVoucher / request) — over plain
 * objects: nothing spawned, nothing bound.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const M = require('../src/modules/lanUsers/model');
const { createLanUsersMeter } = require('../src/modules/lanUsers/meter');

const GIB = 1024 ** 3;
const HOUR = 3600000;
const at = (y, mo, d, h = 12) => new Date(y, mo - 1, d, h, 0, 0).getTime();
const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const user = (id, username, over) => Object.assign({ id, username, password: 'pw-' + username, name: '', target: '', quotaGb: 0, quotaPeriod: 'month', expiresAt: 0, maxDevices: 0, enabled: true }, over);
const card = (id, code, over) => user(id, code, Object.assign({ password: code, maxDevices: 1, voucher: { batch: 'vb-1', hours: 2, activatedAt: 0 } }, over));

/* ------------------------------ the model ------------------------------ */

test('model: a record of before reads as the defaults — remember off, priority normal, no filter, no voucher; a device not remembered; the portal and the shaping line', () => {
  const lu = M.normalizeLanUsers({ users: [user('usr-a', 'ali')], devices: [{ mac: 'aa:bb:cc:dd:ee:01', userId: 'usr-a' }] });
  const u = lu.users[0];
  assert.deepEqual([u.remember, u.priority, u.filter, u.voucher], [false, 'normal', null, null]);
  assert.deepEqual(lu.devices[0], { mac: 'aa:bb:cc:dd:ee:01', name: '', userId: 'usr-a', blocked: false, remembered: false, at: 0 });
  assert.deepEqual(lu.config.portal, { note: '', contact: '', requests: true });
  assert.deepEqual(lu.config.shaping, { down: 0, up: 0, smooth: true });
  // a normalized record normalizes to itself
  assert.deepEqual(M.normalizeLanUsers(lu), lu);
});

test('model: the new fields as stored — priority one of three, remember never for a voucher, a remembered device only while bound', () => {
  const lu = M.normalizeLanUsers({
    users: [user('usr-a', 'ali', { remember: true, priority: 'high' }), user('usr-b', 'bob', { priority: 'urgent', remember: 'yes' }), card('usr-v', 'ABCD-EFGH', { remember: true })],
    devices: [{ mac: 'aa:bb:cc:dd:ee:01', userId: 'usr-a', remembered: true, at: 1700000000000 }, { mac: 'aa:bb:cc:dd:ee:02', userId: 'usr-gone', remembered: true, at: 5 }, { mac: 'aa:bb:cc:dd:ee:03', name: 'tv', remembered: true, at: 5 }]
  });
  assert.deepEqual(lu.users.map((u) => [u.remember, u.priority]), [[true, 'high'], [false, 'normal'], [false, 'normal']]);
  assert.deepEqual(lu.devices.map((d) => [d.userId, d.remembered, d.at]), [['usr-a', true, 1700000000000], ['', false, 0], ['', false, 0]]);
});

test('model: the portal’s note and contact — one line, no control characters, cut to 300 / 64; requests on unless false; the shaping line in kbps, smooth unless false', () => {
  const c = M.normalizeConfig({ portal: { note: ' Pay by\r\nthe 5th\u0007 ', contact: 'x'.repeat(80), requests: 'no' }, shaping: { down: '20000', up: -3, smooth: 0 } });
  assert.deepEqual(c.portal, { note: 'Pay by the 5th', contact: 'x'.repeat(64), requests: true });
  assert.deepEqual(c.shaping, { down: 20000, up: 0, smooth: true });
  assert.deepEqual(M.normalizeConfig({ portal: { requests: false }, shaping: { smooth: false } }).portal.requests, false);
  assert.equal(M.normalizeConfig({ portal: { note: 'n'.repeat(400) } }).portal.note.length, 300);
});

test('model: a filter as stored — the categories in their order, unknown ones (gambling too) dropped; names lowercased, read from an address, each once, at most 200; null when it blocks nothing', () => {
  assert.deepEqual(M.FILTER_CATEGORIES, ['adult', 'social', 'games', 'ads']);
  const f = M.normalizeFilter({ block: ['ads', 'gambling', 'adult', 'ads', 'nope'], safeSearch: true, domains: ['Example.COM', 'https://www.bet.example/path?q', 'full:WWW.a.com', 'keyword:Casino', 'domain:b.ir', '*.c.org', 'a b', '', 'example.com'] });
  assert.deepEqual(f, { block: ['adult', 'ads'], safeSearch: true, domains: ['example.com', 'www.bet.example', 'full:www.a.com', 'keyword:casino', 'b.ir', 'c.org'] });
  assert.equal(M.normalizeFilter({ block: [], safeSearch: false, domains: [] }), null);
  assert.equal(M.normalizeFilter({ block: ['gambling'] }), null, 'a stored gambling alone blocks nothing');
  assert.equal(M.normalizeFilter('junk'), null);
  assert.deepEqual(M.normalizeFilter({ domains: 'a.com\nb.com, c.com\r\n' }).domains, ['a.com', 'b.com', 'c.com'], 'the text box’s lines');
  const many = Array.from({ length: 250 }, (_, i) => `d${i}.example`);
  assert.equal(M.normalizeFilter({ domains: many }).domains.length, M.FILTER_DOMAINS_MAX);
  // a name in another script: its punycode, what the core matches
  assert.equal(M.filterDomainOf('\u0645\u062b\u0627\u0644.\u0627\u06cc\u0631\u0627\u0646'), 'xn--mgbh0fb.xn--mgba3a4f16a');
  for (const bad of ['', '...', 'a b', 'x'.repeat(254), 'keyword:', 'full:a b', 'keyword:a.b/c', 7]) assert.equal(M.filterDomainOf(bad), null, JSON.stringify(bad));
});

test('model: validateUserDetail refuses a filter, a priority and a voucher with their code and part', () => {
  const ok = user('usr-a', 'ali');
  const check = (over) => M.validateUserDetail(Object.assign({}, ok, over), []);
  assert.equal(check({ filter: { block: ['adult'], safeSearch: true, domains: ['a.com', '', 'full:b.com'] }, priority: 'low', remember: true }), null);
  assert.equal(check({ filter: null, priority: null }), null);
  for (const [over, error, detail] of [
    [{ filter: 'x' }, 'filter', undefined], [{ filter: { safeSearch: 'yes' } }, 'filter', undefined],
    [{ filter: { block: ['gambling'] } }, 'filter', 'category'], [{ filter: { block: 'adult' } }, 'filter', 'category'],
    [{ filter: { domains: ['ok.com', 'not ok'] } }, 'filter', 'domain'], [{ filter: { domains: 5 } }, 'filter', 'domains'],
    [{ filter: { domains: Array.from({ length: 201 }, (_, i) => `d${i}.ir`) } }, 'filter', 'domains'],
    [{ priority: 'urgent' }, 'priority', undefined],
    [{ voucher: 'x' }, 'voucher', 'shape'], [{ voucher: { batch: '"><b>' } }, 'voucher', 'batch'],
    [{ voucher: { batch: 'vb-1', hours: 9000 } }, 'voucher', 'hours'], [{ voucher: { batch: 'vb-1', activatedAt: -1 } }, 'voucher', 'activatedAt'],
    [{ voucher: { batch: 'vb-1' }, remember: true }, 'voucher', 'remember']
  ]) assert.deepEqual(check(over), detail ? { error, detail } : { error }, JSON.stringify(over));
});

test('model: voucher codes — XXXX-XXXX from the 31 letters a card can be read by, every letter as likely; normalizeCode reads what people type', () => {
  assert.equal(M.VOUCHER_ALPHABET, 'ABCDEFGHJKMNPQRSTUVWXYZ23456789');
  for (let i = 0; i < 200; i++) {
    const c = M.voucherCode();
    assert.match(c, /^[ABCDEFGHJKMNPQRSTUVWXYZ2-9]{4}-[ABCDEFGHJKMNPQRSTUVWXYZ2-9]{4}$/);
    assert.ok(M.USERNAME.test(c) && M.PASSWORD.test(c), 'a code is a username and a password the proxy takes');
  }
  // a byte at or above 248 is thrown away, never folded in
  let calls = 0;
  const rnd = () => (++calls === 1 ? Buffer.alloc(16, 250) : Buffer.from([0, 1, 2, 3, 4, 5, 6, 30, 31, 32, 33, 34, 35, 36, 37, 38]));
  assert.equal(M.voucherCode(rnd), 'ABCD-EFG9');
  assert.throws(() => M.voucherCode(() => Buffer.alloc(16, 255)), /random/);
  assert.equal(M.normalizeCode(' abcd efgh '), 'ABCD-EFGH');
  assert.equal(M.normalizeCode('ABCDEFGH'), 'ABCD-EFGH');
  assert.equal(M.normalizeCode('abcd\u2013efgh'), 'ABCD-EFGH', 'a dash a phone made typographic');
  assert.equal(M.normalizeCode('\u06f2\u06f3\u06f4\u06f5-\u200fabcd'), '2345-ABCD', 'Persian digits, a right-to-left mark');
  for (const bad of ['ABCD-EFGI', 'ABCD-EFG0', 'ABC-DEFGH', 'ABCD--EFGH', 'ABCDEFGHJ', '', null, 12345678]) assert.equal(M.normalizeCode(bad), null, String(bad));
});

test('model: a voucher is an ordinary user — active until it expires, unused / active / expired / used by the meter’s word', () => {
  const now = at(2026, 10, 29);
  const v = card('usr-v', 'ABCD-EFGH', { limits: [{ kind: 'total', period: 'none', gb: 1 }] });
  assert.equal(M.isVoucher(M.normalizeUser(v)), true);
  assert.equal(M.isVoucher(M.normalizeUser(user('usr-a', 'ali'))), false);
  assert.equal(M.voucherState(user('usr-a', 'ali'), now), null);
  assert.equal(M.voucherState(v, now), 'unused');
  const on = Object.assign({}, v, { voucher: { batch: 'vb-1', hours: 2, activatedAt: now - HOUR }, expiresAt: now + HOUR });
  assert.equal(M.voucherState(on, now), 'active');
  assert.equal(M.voucherState(on, now + 2 * HOUR), 'expired');
  assert.equal(M.voucherState(Object.assign({}, v, { expiresAt: now - 1 }), now), 'expired', 'the admin’s expiry passed unused');
  const spent = { 'usr-v': { over: true, why: 'total', meters: [{ kind: 'total', period: 'none', over: true }] } };
  assert.equal(M.voucherState(on, now, { usage: spent }), 'used');
  assert.equal(M.voucherState(on, { now, over: ['usr-v'] }), 'used', 'the options as the second argument');
  assert.equal(M.voucherState(Object.assign({}, on, { enabled: false }), now, { over: ['usr-v'] }), 'active', 'off by the admin is not spent');
  // the accounts take it as any user: code / code, until its time is up
  assert.deepEqual(M.activeUsers({ users: [on] }, { now }).map((u) => [u.username, u.password]), [['ABCD-EFGH', 'ABCD-EFGH']]);
  assert.deepEqual(M.activeUsers({ users: [on] }, { now: now + 2 * HOUR }), []);
});

/* ------------------------------ the meter ------------------------------ */

function meter(store, o) {
  const seen = { logs: [], first: [] };
  let t = (o && o.t) || at(2026, 10, 25);
  const m = createLanUsersMeter(Object.assign({
    usage: {}, users: () => store, canReload: () => true, pending: () => [], reload: async () => true,
    log: (l) => seen.logs.push(l.line), now: () => t, onFirstUse: (id) => seen.first.push(id)
  }, o));
  return { m, seen, set: (v) => { t = v; } };
}

test('meter: months — VPN and direct per month of the user’s own month, the running one always there, the last 13 kept, saved as lanUsersMonths', () => {
  const store = { users: [user('usr-a', 'ali', { routing: 'bypass-ir' }), user('usr-j', 'jaleh', { quotaCalendar: 'jalali' })] };
  const h = meter(store, { t: at(2026, 9, 10) });
  h.m.addBytes('usr-a', 1000);
  h.set(at(2026, 10, 25));
  h.m.addBytes('usr-a', 500);
  h.m.addBytes('usr-j', 7);
  const u = h.m.usage();
  assert.deepEqual(u['usr-a'].months, [
    { key: '2026-09', from: at(2026, 9, 1, 0), to: at(2026, 10, 1, 0), vpn: 1000, direct: 0 },
    { key: '2026-10', from: at(2026, 10, 1, 0), to: at(2026, 11, 1, 0), vpn: 500, direct: 0 }
  ]);
  assert.deepEqual(u['usr-j'].months.map((r) => [r.key, r.vpn]), [['j1405-08', 7]], 'a Persian month for a Persian calendar');
  assert.deepEqual(u['usr-a'].request, null);
  assert.deepEqual(h.m.savedMonths()['usr-a'], [{ key: '2026-09', vpn: 1000, direct: 0 }, { key: '2026-10', vpn: 500, direct: 0 }]);
  // a user with nothing yet: the running month, empty
  const fresh = meter({ users: [user('usr-b', 'bob')] }).m.usage()['usr-b'].months;
  assert.deepEqual(fresh.map((r) => [r.key, r.vpn, r.direct]), [['2026-10', 0, 0]]);
  // fifteen months: the oldest go
  const long = meter(store, { t: at(2025, 8, 5) });
  for (let i = 0; i < 15; i++) { long.set(new Date(2025, 7 + i, 5, 12).getTime()); long.m.addBytes('usr-a', 1); }
  const keys = long.m.usage()['usr-a'].months.map((r) => r.key);
  assert.equal(keys.length, 13);
  assert.deepEqual([keys[0], keys[12]], ['2025-10', '2026-10']);
});

test('meter: months — a renew day changed mid-month carries the running row on under its new key; a file of before starts from the month buckets', () => {
  const store = { users: [user('usr-a', 'ali')] };
  const h = meter(store, { t: at(2026, 10, 20) });
  h.m.addBytes('usr-a', 100);
  store.users[0] = user('usr-a', 'ali', { quotaResetDay: 15 });
  assert.deepEqual(h.m.usage()['usr-a'].months.map((r) => [r.key, r.vpn]), [['2026-10@15', 100]], 'shown under the new key at once');
  h.m.addBytes('usr-a', 50);
  assert.deepEqual(h.m.usage()['usr-a'].months.map((r) => [r.key, r.vpn]), [['2026-10@15', 150]]);
  // the usage file of v1.39: no lanUsersMonths — this month from its buckets
  const usage2 = { 'usr-a': { total: { month: { period: '2026-10', bytes: 30 } }, vpn: { month: { period: '2026-10', bytes: 20 } }, direct: { month: { period: '2026-10', bytes: 10 } } } };
  const old = meter({ users: [user('usr-a', 'ali')] }, { usage2 });
  assert.deepEqual(old.m.usage()['usr-a'].months.map((r) => [r.key, r.vpn, r.direct]), [['2026-10', 20, 10]]);
  assert.equal(old.m.dirty, true, 'written at the next save');
  assert.equal(meter({ users: [user('usr-a', 'ali')] }, { usage2, months: {} }).m.usage()['usr-a'].months[0].vpn, 0, 'a file with months is read as it is');
});

test('meter: requests — one pending per user, said in the log; answered by a top-up, a reset or a dismiss; gone with the user', () => {
  const store = { users: [user('usr-a', 'ali', { limits: [{ kind: 'total', period: 'month', gb: 1 }] }), user('usr-b', 'bob')] };
  const h = meter(store);
  assert.equal(h.m.request('usr-a', { mac: 'AA-BB-CC-DD-EE-01', at: 1234 }), true);
  assert.equal(h.m.request('usr-a', { mac: 'aa:bb:cc:dd:ee:02' }), false, 'one pending already');
  assert.equal(h.m.request('usr-ghost', {}), false);
  assert.deepEqual(h.m.usage()['usr-a'].request, { at: 1234 });
  assert.deepEqual(h.m.savedRequests(), { 'usr-a': { at: 1234, mac: 'aa:bb:cc:dd:ee:01' } });
  assert.match(h.seen.logs.join('\n'), /“ali” asks for a top-up/);
  assert.equal(h.m.topUp('usr-a', 'total', 'month', 1), null);
  assert.equal(h.m.usage()['usr-a'].request, null, 'a top-up answers it');
  h.m.request('usr-a', {});
  h.m.resetUsage('usr-a');
  assert.equal(h.m.usage()['usr-a'].request, null, 'a reset answers it');
  h.m.request('usr-b', {});
  assert.deepEqual(h.m.usage()['usr-b'].request, { at: at(2026, 10, 25) }, 'at: now');
  assert.equal(h.m.dismissRequest('usr-b'), true);
  assert.equal(h.m.dismissRequest('usr-b'), false);
  h.m.request('usr-b', {});
  h.m.forget('usr-b');
  assert.deepEqual(h.m.savedRequests(), {});
  // read back from the file, junk dropped
  assert.deepEqual(meter(store, { requests: { 'usr-a': { at: 99, mac: 'x' }, 'bad id!': { at: 1 }, 'usr-b': { at: 0 } } }).m.savedRequests(), { 'usr-a': { at: 99, mac: '' } });
});

test('meter: a voucher’s first bytes are said to onFirstUse once — until its activatedAt shows; a person’s account never', () => {
  const store = { users: [card('usr-v', 'ABCD-EFGH'), user('usr-a', 'ali')] };
  const h = meter(store);
  h.m.addBytes('usr-v', 10);
  h.m.addBytes('usr-v', 10);
  h.m.addBytes('usr-a', 10);
  assert.deepEqual(h.seen.first, ['usr-v']);
  store.users[0] = card('usr-v', 'ABCD-EFGH', { voucher: { batch: 'vb-1', hours: 2, activatedAt: at(2026, 10, 25) } });
  h.m.addBytes('usr-v', 10);
  assert.deepEqual(h.seen.first, ['usr-v'], 'started: nothing more to say');
  // the admin sets it back to unused: its next first bytes are said again
  store.users[0] = card('usr-v', 'ABCD-EFGH');
  h.m.addBytes('usr-v', 10);
  assert.deepEqual(h.seen.first, ['usr-v', 'usr-v']);
  // an onFirstUse that throws is said, never the meter's error
  const bad = meter({ users: [card('usr-v', 'ABCD-EFGH')] }, { onFirstUse: () => { throw new Error('disk full'); } });
  bad.m.addBytes('usr-v', 10);
  assert.match(bad.seen.logs.join('\n'), /could not be written — disk full/);
});

test('meter: exportState / importState — merge keeps the larger count per period, day and month (twice is once); replace takes the backup’s; only the ids named', () => {
  const store = { users: [user('usr-a', 'ali', { routing: 'bypass-ir', limits: [{ kind: 'total', period: 'none', gb: 5 }] }), user('usr-b', 'bob')] };
  const src = meter(store);
  src.m.addBytes('usr-a', 3000);
  src.m.addBytes('usr-b', 70);
  src.m.request('usr-a', { at: 5 });
  const state = src.m.exportState();
  assert.deepEqual(Object.keys(state).sort(), ['history', 'months', 'requests', 'usage2']);
  assert.deepEqual(JSON.parse(JSON.stringify(state)), state, 'plain JSON');
  const monthOf = (m, id) => m.usage()[id].meters.find((x) => x.kind === 'total' && x.period === 'month').bytes;
  const dst = meter(store);
  dst.m.addBytes('usr-a', 1000);
  dst.m.importState(state, { mode: 'merge' });
  assert.equal(monthOf(dst.m, 'usr-a'), 3000, 'the larger count of the same month');
  assert.equal(dst.m.usage()['usr-a'].meters.find((x) => x.period === 'none').bytes, 3000, 'and of the one-off limit');
  assert.equal(dst.m.usage()['usr-a'].months[0].vpn, 3000);
  assert.equal(dst.m.usage()['usr-a'].history[0].vpn, 3000);
  assert.deepEqual(dst.m.usage()['usr-a'].request, { at: 5 });
  dst.m.importState(state, { mode: 'merge' });
  assert.equal(monthOf(dst.m, 'usr-a'), 3000, 'restoring twice is restoring once');
  const only = meter(store);
  only.m.importState(state, { mode: 'merge', ids: ['usr-b'] });
  assert.deepEqual([monthOf(only.m, 'usr-a'), monthOf(only.m, 'usr-b')], [0, 70]);
  const rep = meter(store);
  rep.m.addBytes('usr-a', 9000);
  rep.m.importState({ usage2: {}, history: {}, months: {}, requests: {} }, { mode: 'replace', ids: ['usr-a'] });
  assert.equal(monthOf(rep.m, 'usr-a'), 0, 'replace: none in the backup is none here');
  assert.equal(rep.m.dirty, true);
  // junk is dropped, as from the usage file
  const junk = meter(store);
  junk.m.importState({ usage2: 'x', history: { 'usr-a': 'nope' }, months: { 'usr-a': [{ key: '2026-10-01', vpn: 1 }] }, requests: [] }, { mode: 'merge' });
  assert.deepEqual(junk.m.usage()['usr-a'].months.map((r) => r.vpn), [0]);
});

/* ------------------------------ the channels and the router's hooks ------------------------------ */

const NOW = at(2026, 10, 29, 12);
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
/** registerLanUsers over plain objects: the store, the usage file, the log — nothing spawned, nothing bound. */
function bare(data, extra) {
  const { registerLanUsers } = require('../src/modules/lanUsers/ipc');
  const usage = {};
  const seen = { logs: [], changes: [], reloads: 0 };
  let t = NOW;
  const reg = registerLanUsers(Object.assign({
    store: { get: (k, d) => (k in data ? data[k] : d), set: (k, v) => { data[k] = v; } },
    usageStore: { get: (k, d) => (k in usage ? usage[k] : d), setLazy: (k, v) => { usage[k] = v; } },
    getSettings: () => ({ lang: 'en', modules: { lanUsers: true } }),
    platform: 'desktop', firewall: { sync() {} }, now: () => t, log: (l) => seen.logs.push(l.line),
    onChange: (lu, what) => { seen.changes.push(what); },
    queueReload: async () => { seen.reloads++; return true; }
  }, extra || {}));
  const user$ = (arg) => reg.handlers['lanusers:user'](arg);
  return { reg, data, usage, seen, user: user$, set: (v) => { t = v; } };
}

test('lanusers:user vouchers: count cards of a new batch — the code its username and password, the GB a one-off total limit, 1 device unless said, "<label> #n"; codes unique among every username', async () => {
  // the fake random source: the first code it makes is a username already here
  const codes = ['ABCD-EFGH', 'ABCD-EFGH', 'JKMN-PQRS', 'TUVW-XYZ2'];
  const bytesOf = (c) => Buffer.from(c.replace('-', '').split('').map((ch) => M.VOUCHER_ALPHABET.indexOf(ch)).concat(Array(8).fill(255)));
  let i = 0;
  const h = bare({ lanUsers: { users: [user('usr-a', 'abcd-efgh')] } }, { randomBytes: () => bytesOf(codes[Math.min(i++, codes.length - 1)]) });
  const r = await h.user({ op: 'vouchers', batch: { count: 2, hours: 2, gb: 1.5, target: 'direct', routing: 'bypass-ir', name: 'Cafe' } });
  assert.equal(r.ok, true);
  assert.match(r.batch.id, /^vb-[0-9a-f]{10}$/);
  assert.deepEqual(r.batch.codes, ['JKMN-PQRS', 'TUVW-XYZ2'], 'a code that is a username here (case aside) is never handed out');
  const cards = r.users.filter((u) => u.voucher);
  assert.deepEqual(cards.map((u) => [u.username, u.password, u.name, u.maxDevices, u.target, u.routing, u.expiresAt, u.enabled, u.remember]),
    [['JKMN-PQRS', 'JKMN-PQRS', 'Cafe #1', 1, 'direct', 'bypass-ir', 0, true, false], ['TUVW-XYZ2', 'TUVW-XYZ2', 'Cafe #2', 1, 'direct', 'bypass-ir', 0, true, false]]);
  assert.deepEqual(cards[0].limits, [{ kind: 'total', period: 'none', gb: 1.5, action: 'cut' }]);
  assert.deepEqual(cards[0].voucher, { batch: r.batch.id, hours: 2, activatedAt: 0, madeAt: NOW });
  assert.deepEqual(r.pendingReconnect, [], 'nothing connected: nothing pending');
  // no GB: no limit; devices per card as asked; no label: no name
  const r2 = await bare({ lanUsers: {} }).user({ op: 'vouchers', batch: { count: 3, hours: 0, maxDevices: 2 } });
  assert.deepEqual(r2.users.map((u) => [u.limits.length, u.maxDevices, u.name, u.voucher.hours]), [[0, 2, '', 0], [0, 2, '', 0], [0, 2, '', 0]]);
  assert.equal(new Set(r2.batch.codes).size, 3);
});

test('lanusers:user vouchers: refused as batch with its part, or as the user it would make (target, routing, speed); nothing saved', async () => {
  const h = bare({ lanUsers: { users: [] } });
  for (const [batch, error, detail] of [
    [{ count: 0 }, 'batch', 'count'], [{ count: 201 }, 'batch', 'count'], [{ count: 1.5 }, 'batch', 'count'], [{}, 'batch', 'count'],
    [{ count: 1, hours: 9000 }, 'batch', 'hours'], [{ count: 1, hours: -1 }, 'batch', 'hours'], [{ count: 1, gb: -1 }, 'batch', 'gb'],
    [{ count: 1, name: 'x'.repeat(65) }, 'batch', 'name'], [{ count: 1, target: 'chain:' }, 'target', undefined],
    [{ count: 1, routing: 'profile:rp-gone' }, 'routing', 'profile'], [{ count: 1, speed: { down: 0 } }, 'speed', 'base'], [{ count: 1, maxDevices: -1 }, 'maxDevices', undefined]
  ]) {
    const r = await h.user({ op: 'vouchers', batch });
    assert.deepEqual([r.ok, r.error, r.detail], [false, error, detail], JSON.stringify(batch));
  }
  assert.deepEqual(h.data.lanUsers.users, []);
  // a long label keeps its number
  const long = await h.user({ op: 'vouchers', batch: { count: 1, name: 'n'.repeat(64) } });
  assert.equal(long.users[0].name, 'n'.repeat(61) + ' #1');
});

test('lanusers:user deleteBatch: the batch’s cards (only the never used ones with `unused`), their usage forgotten and their devices unbound; dismissRequest', async () => {
  const used = { batch: 'vb-1', hours: 2, activatedAt: NOW - HOUR };
  const h = bare({ lanUsers: {
    users: [card('usr-v1', 'ABCD-EFGH'), card('usr-v2', 'JKMN-PQRS', { voucher: used }), card('usr-v3', 'TUVW-XYZ2', { voucher: { batch: 'vb-2', hours: 0, activatedAt: 0 } }), user('usr-a', 'ali')],
    devices: [{ mac: 'aa:bb:cc:dd:ee:01', userId: 'usr-v1' }, { mac: 'aa:bb:cc:dd:ee:02', userId: 'usr-v2', name: 'Phone' }]
  } });
  h.reg.addBytes('usr-v2', 5000);
  const a = await h.user({ op: 'deleteBatch', batch: { id: 'vb-1' }, unused: true });
  assert.deepEqual([a.ok, a.removed, a.users.map((u) => u.id)], [true, 1, ['usr-v2', 'usr-v3', 'usr-a']]);
  assert.deepEqual(a.devices.map((d) => [d.mac, d.userId]), [['aa:bb:cc:dd:ee:02', 'usr-v2']], 'the unused card’s device, with nothing else to say, goes');
  const b = await h.user({ op: 'deleteBatch', batch: { id: 'vb-1' } });
  assert.deepEqual([b.removed, b.users.map((u) => u.id)], [1, ['usr-v3', 'usr-a']]);
  assert.deepEqual(b.devices, [{ mac: 'aa:bb:cc:dd:ee:02', name: 'Phone', userId: '', blocked: false, remembered: false, at: 0 }]);
  assert.equal(b.usage['usr-v2'], undefined, 'their usage forgotten');
  assert.equal((await h.user({ op: 'deleteBatch', batch: { id: 'vb-1' } })).error, 'notFound');
  assert.equal((await h.user({ op: 'deleteBatch', batch: {} })).error, 'notFound');
  // a request: asked through the hook, saved at once, dismissed by the admin
  assert.equal(h.reg.request('usr-a', { mac: 'aa:bb:cc:dd:ee:09' }), true);
  assert.equal(h.reg.request('usr-a', { mac: 'aa:bb:cc:dd:ee:09' }), false);
  assert.deepEqual(h.usage.lanUsersRequests, { 'usr-a': { at: NOW, mac: 'aa:bb:cc:dd:ee:09' } }, 'in the usage file at once');
  assert.deepEqual((await h.reg.handlers['lanusers:get']()).usage['usr-a'].request, { at: NOW });
  const d = await h.user({ op: 'dismissRequest', user: { id: 'usr-a' } });
  assert.deepEqual([d.ok, d.usage['usr-a'].request, d.pendingReconnect], [true, null, []]);
  assert.deepEqual(h.usage.lanUsersRequests, {});
  assert.equal((await h.user({ op: 'dismissRequest', user: { id: 'usr-ghost' } })).error, 'notFound');
});

test('lanusers:config: the portal’s note, contact and requests and the shaping line merge like the rest; refused as portal / shaping with the part', async () => {
  const h = bare({ lanUsers: {} });
  const cfg = (p) => h.reg.handlers['lanusers:config'](p);
  const a = await cfg({ portal: { note: 'Pay by the 5th\nthanks', contact: '0912 000 0000' } });
  assert.deepEqual(a.config.portal, { note: 'Pay by the 5th thanks', contact: '0912 000 0000', requests: true });
  const b = await cfg({ shaping: { down: '50000', up: 10000 }, portal: { requests: false } });
  assert.deepEqual([b.config.shaping, b.config.portal.note, b.config.portal.requests], [{ down: 50000, up: 10000, smooth: true }, 'Pay by the 5th thanks', false]);
  assert.deepEqual((await cfg({ shaping: { down: '', smooth: false } })).config.shaping, { down: 0, up: 10000, smooth: false });
  for (const [part, error, detail] of [
    [{ portal: { note: 'n'.repeat(301) } }, 'portal', 'note'], [{ portal: { contact: 5 } }, 'portal', 'contact'], [{ portal: { requests: 'no' } }, 'portal', 'requests'],
    [{ shaping: { down: -1 } }, 'shaping', 'down'], [{ shaping: { up: 1.5 } }, 'shaping', 'up'], [{ shaping: { up: 'fast' } }, 'shaping', 'up'], [{ shaping: { smooth: 1 } }, 'shaping', 'smooth']
  ]) {
    const r = await cfg(part);
    assert.deepEqual([r.ok, r.error, r.detail], [false, error, detail], JSON.stringify(part));
  }
  assert.equal(h.data.lanUsers.config.shaping.smooth, false, 'nothing saved by a refusal');
});

test('activateVoucher (the router’s first sign-in): activatedAt now, expiresAt hours on — never past the admin’s expiry — written once; no reload', async () => {
  const h = bare({ lanUsers: { config: { proxy: { enabled: true, port: 30820, httpPort: 30821 } }, users: [
    card('usr-v', 'ABCD-EFGH'), card('usr-w', 'JKMN-PQRS', { expiresAt: NOW + HOUR }), card('usr-x', 'TUVW-XYZ2', { voucher: { batch: 'vb-1', hours: 0, activatedAt: 0 } }),
    card('usr-old', 'BCDE-FGHJ', { expiresAt: NOW - 1 }), card('usr-off', 'CDEF-GHJK', { enabled: false }), user('usr-a', 'ali')
  ] } }, { running: () => true, canReload: () => true });
  await h.reg.forBuild({ modules: { lanUsers: true } });
  const byId = (id) => h.data.lanUsers.users.find((u) => u.id === id);
  assert.equal(await h.reg.activateVoucher('usr-v'), true);
  assert.deepEqual([byId('usr-v').voucher.activatedAt, byId('usr-v').expiresAt], [NOW, NOW + 2 * HOUR]);
  assert.equal(await h.reg.activateVoucher('usr-v'), false, 'started already: nothing written again');
  assert.equal(await h.reg.activateVoucher('usr-w'), true);
  assert.equal(byId('usr-w').expiresAt, NOW + HOUR, 'the admin’s earlier expiry stands');
  assert.equal(await h.reg.activateVoucher('usr-x'), true);
  assert.equal(byId('usr-x').expiresAt, 0, 'no hours: no time limit');
  for (const id of ['usr-old', 'usr-off', 'usr-a', 'usr-ghost']) assert.equal(await h.reg.activateVoucher(id), false, id);
  assert.equal(byId('usr-old').voucher.activatedAt, 0, 'expired unused: never started');
  await wait(400);
  assert.deepEqual(h.seen.changes, ['user'], 'the router told once, a moment later');
  assert.equal(h.seen.reloads, 0, 'nothing the core runs changed');
  assert.equal(M.voucherState(byId('usr-v'), NOW), 'active');
  assert.equal(M.voucherState(byId('usr-v'), NOW + 3 * HOUR), 'expired');
});

test('a voucher’s first bytes anywhere (a desktop proxy account) start it — once, after the tick', async () => {
  const h = bare({ lanUsers: { users: [card('usr-v', 'ABCD-EFGH')] } });
  h.reg.meter.built({ active: ['usr-v'], over: [], byName: { 'ABCD-EFGH': 'usr-v' } });
  h.reg.tick({ stats: { user: { 'ABCD-EFGH': { uplink: 0, downlink: 0 } } } });
  h.set(NOW + 1000);
  h.reg.tick({ stats: { user: { 'ABCD-EFGH': { uplink: 10, downlink: 500 } } } });
  assert.equal(h.data.lanUsers.users[0].voucher.activatedAt, 0, 'never inside the tick');
  await wait(0);
  assert.deepEqual([h.data.lanUsers.users[0].voucher.activatedAt, h.data.lanUsers.users[0].expiresAt], [NOW + 1000, NOW + 1000 + 2 * HOUR]);
  h.reg.tick({ stats: { user: { 'ABCD-EFGH': { uplink: 20, downlink: 900 } } } });
  await wait(0);
  assert.equal(h.data.lanUsers.users[0].voucher.activatedAt, NOW + 1000, 'once');
  assert.equal(h.seen.logs.filter((l) => /voucher ABCD-EFGH is in use/.test(l)).length, 1);
});

test('assignDevice (the router’s sign-in with remember on): the device becomes theirs — remembered, at, the scan’s name when it had none; never for a voucher, a blocked device or another’s', async () => {
  const h = bare({ lanUsers: {
    users: [user('usr-a', 'ali', { remember: true, maxDevices: 2 }), user('usr-b', 'bob'), card('usr-v', 'ABCD-EFGH'), user('usr-c', 'cat', { remember: true, maxDevices: 1 })],
    devices: [{ mac: 'aa:bb:cc:dd:ee:02', name: 'TV', blocked: true }, { mac: 'aa:bb:cc:dd:ee:03', userId: 'usr-b' }, { mac: 'aa:bb:cc:dd:ee:04', name: 'Laptop' }, { mac: 'aa:bb:cc:dd:ee:05', userId: 'usr-c' }]
  } });
  const dev = (mac) => h.data.lanUsers.devices.find((d) => d.mac === mac);
  assert.equal(await h.reg.assignDevice({ mac: 'AA-BB-CC-DD-EE-01', userId: 'usr-a', name: 'ali-phone' }), true);
  assert.deepEqual(dev('aa:bb:cc:dd:ee:01'), { mac: 'aa:bb:cc:dd:ee:01', name: 'ali-phone', userId: 'usr-a', blocked: false, remembered: true, at: NOW });
  assert.equal(await h.reg.assignDevice({ mac: 'aa:bb:cc:dd:ee:04', userId: 'usr-a', name: 'scan-name' }), true);
  assert.deepEqual([dev('aa:bb:cc:dd:ee:04').name, dev('aa:bb:cc:dd:ee:04').userId], ['Laptop', 'usr-a'], 'the admin’s name kept');
  assert.equal(await h.reg.assignDevice({ mac: 'aa:bb:cc:dd:ee:01', userId: 'usr-a' }), true, 'theirs already');
  for (const [a, why] of [
    [{ mac: 'aa:bb:cc:dd:ee:06', userId: 'usr-a' }, 'their device limit (2) reached'],
    [{ mac: 'aa:bb:cc:dd:ee:07', userId: 'usr-b' }, 'remember off'],
    [{ mac: 'aa:bb:cc:dd:ee:07', userId: 'usr-v' }, 'a voucher'],
    [{ mac: 'aa:bb:cc:dd:ee:02', userId: 'usr-c' }, 'blocked by the admin'],
    [{ mac: 'aa:bb:cc:dd:ee:03', userId: 'usr-c' }, 'another’s'],
    [{ mac: 'zz', userId: 'usr-c' }, 'no MAC'],
    [{ mac: 'aa:bb:cc:dd:ee:08', userId: 'usr-ghost' }, 'no such user']
  ]) assert.equal(await h.reg.assignDevice(a), false, why);
  await wait(400);
  assert.deepEqual(h.seen.changes, ['device'], 'two sign-ins, one look by the router');
  // the admin's pick of another user replaces the sign-in's
  const r = await h.reg.handlers['lanusers:device']({ mac: 'aa:bb:cc:dd:ee:01', userId: 'usr-b' });
  assert.deepEqual(r.devices.find((d) => d.mac === 'aa:bb:cc:dd:ee:01'), { mac: 'aa:bb:cc:dd:ee:01', name: 'ali-phone', userId: 'usr-b', blocked: false, remembered: false, at: 0 });
  // the device limit counts the admin's own picks too
  await h.reg.assignDevice({ mac: 'aa:bb:cc:dd:ee:09', userId: 'usr-c' });
  assert.equal(dev('aa:bb:cc:dd:ee:09'), undefined, 'cat has her one device already');
});

test('lanusers:backup: the Users module alone — kind, version, when, the app, the platform, the record (passwords and all) and the meter’s state', async () => {
  const h = bare({ lanUsers: { users: [user('usr-a', 'ali'), card('usr-v', 'ABCD-EFGH')], devices: [{ mac: 'aa:bb:cc:dd:ee:01', userId: 'usr-a' }] } }, { appVersion: '1.40.0' });
  h.reg.addBytes('usr-a', 1234);
  const r = await h.reg.handlers['lanusers:backup']();
  assert.equal(r.ok, true);
  const b = r.bundle;
  assert.deepEqual([b.kind, b.version, b.at, b.app, b.platform], ['irnetfree-lanusers', 1, NOW, '1.40.0', 'desktop']);
  assert.deepEqual(b.lanUsers, M.normalizeLanUsers(h.data.lanUsers));
  assert.equal(b.lanUsers.users[0].password, 'pw-ali');
  assert.equal(b.meter.usage2['usr-a'].total.month.bytes, 1234);
  assert.deepEqual(JSON.parse(JSON.stringify(b)), b, 'a file as it is');
});

test('lanusers:restore merge: users by id (updated), new ones added (vouchers apart), a username taken here by another skipped; devices by MAC; the usage the larger; twice is once', async () => {
  const src = bare({ lanUsers: {
    config: { proxy: { enabled: true, port: 40000, httpPort: 40001 } },
    users: [user('usr-a', 'ali', { name: 'theirs' }), user('usr-b', 'bob'), user('usr-x', 'SARA'), card('usr-v', 'ABCD-EFGH')],
    devices: [{ mac: 'aa:bb:cc:dd:ee:01', userId: 'usr-b', name: 'Bob phone' }, { mac: 'aa:bb:cc:dd:ee:02', userId: 'usr-x' }, { mac: 'aa:bb:cc:dd:ee:03', userId: 'usr-a', remembered: true, at: 7 }]
  } });
  src.reg.addBytes('usr-a', 5000);
  src.reg.addBytes('usr-b', 300);
  const bundle = (await src.reg.handlers['lanusers:backup']()).bundle;
  const h = bare({ lanUsers: { users: [user('usr-a', 'ali', { name: 'here' }), user('usr-s', 'sara')], devices: [{ mac: 'aa:bb:cc:dd:ee:02', userId: 'usr-s', name: 'Sara tab' }] } });
  h.reg.addBytes('usr-a', 100);
  const restore = (arg) => h.reg.handlers['lanusers:restore'](arg);
  const r = await restore({ bundle, mode: 'merge' });
  assert.equal(r.ok, true);
  assert.deepEqual([r.added, r.updated, r.skipped], [{ users: 1, devices: 2, vouchers: 1 }, { users: 1, devices: 1 }, { users: 1 }]);
  assert.deepEqual(r.users.map((u) => [u.id, u.username, u.name]), [['usr-a', 'ali', 'theirs'], ['usr-s', 'sara', ''], ['usr-b', 'bob', ''], ['usr-v', 'ABCD-EFGH', '']]);
  assert.deepEqual(r.devices.map((d) => [d.mac, d.userId, d.name, d.remembered]), [['aa:bb:cc:dd:ee:02', 'usr-s', 'Sara tab', false], ['aa:bb:cc:dd:ee:01', 'usr-b', 'Bob phone', false], ['aa:bb:cc:dd:ee:03', 'usr-a', '', true]],
    'a device bound to the user it skipped keeps its binding (and its name) here');
  assert.equal(r.config.proxy.port, 30820, 'this machine’s config stays');
  assert.equal(r.usage['usr-a'].bytes, 5000, 'the larger count');
  assert.equal(r.usage['usr-b'].bytes, 300);
  assert.equal(r.usage['usr-x'], undefined, 'a skipped user’s usage never comes');
  assert.ok(h.usage.lanUsersUsage2['usr-b'] && h.usage.lanUsersMonths['usr-b'], 'in the usage file at once');
  assert.deepEqual(r.pendingReconnect, []);
  const again = await restore({ bundle });
  assert.deepEqual([again.users.length, again.devices.length, again.usage['usr-a'].bytes], [4, 3, 5000], 'restoring twice is restoring once (merge is the default)');
  // a machine that never had users takes the backup's config too
  const fresh = bare({});
  assert.equal((await fresh.reg.handlers['lanusers:restore']({ bundle })).config.proxy.port, 40000);
});

test('lanusers:restore replace: the record as given — its config only if its ports are free here — their usage the backup’s, the users it lacks forgotten; a bad bundle refused as backup with the part', async () => {
  const bundle = { kind: 'irnetfree-lanusers', version: 1, at: 1, app: '1.40.0', platform: 'openwrt',
    lanUsers: { config: { proxy: { enabled: true, port: 41000, httpPort: 0 }, portal: { note: 'hi' } }, users: [user('usr-a', 'ali'), card('usr-v', 'ABCD-EFGH')], devices: [{ mac: 'aa:bb:cc:dd:ee:01', userId: 'usr-v' }] },
    meter: { usage2: { 'usr-a': { total: { month: { period: '2026-10', bytes: 77 } } } } } };
  const h = bare({ lanUsers: { users: [user('usr-a', 'ali', { name: 'here' }), user('usr-z', 'zed')], devices: [{ mac: 'aa:bb:cc:dd:ee:09', userId: 'usr-z' }] } });
  h.reg.addBytes('usr-a', 9000);
  h.reg.addBytes('usr-z', 50);
  const r = await h.reg.handlers['lanusers:restore']({ bundle, mode: 'replace' });
  assert.deepEqual([r.ok, r.added, r.updated, r.skipped], [true, { users: 0, devices: 1, vouchers: 1 }, { users: 1, devices: 0 }, { users: 0 }]);
  assert.deepEqual(r.users.map((u) => [u.id, u.name]), [['usr-a', ''], ['usr-v', '']]);
  assert.deepEqual(r.devices.map((d) => d.mac), ['aa:bb:cc:dd:ee:01']);
  assert.deepEqual([r.config.proxy.port, r.config.portal.note], [41000, 'hi']);
  assert.equal(r.usage['usr-a'].bytes, 77, 'the backup’s usage, not the larger');
  assert.equal(h.reg.meter.savedUsage2()['usr-z'], undefined, 'a user it lacks: gone with their bytes');
  // its ports clash with the app's own: this machine's config stays
  const clash = bare({ lanUsers: {} }, { getSettings: () => ({ lang: 'en', modules: { lanUsers: true }, socksPort: 41000 }) });
  const c = await clash.reg.handlers['lanusers:restore']({ bundle, mode: 'replace' });
  assert.deepEqual([c.ok, c.config.proxy.port, c.users.length], [true, 30820, 2]);
  assert.match(clash.seen.logs.join('\n'), /its ports are taken here/);
  for (const [arg, detail] of [
    [{}, 'kind'], [{ bundle: { kind: 'irnetfree-backup' } }, 'kind'], [{ bundle: Object.assign({}, bundle, { version: 2 }) }, 'version'],
    [{ bundle: Object.assign({}, bundle, { version: '1' }) }, 'version'], [{ bundle: Object.assign({}, bundle, { lanUsers: [] }) }, 'shape'],
    [{ bundle: Object.assign({}, bundle, { lanUsers: { users: 'x' } }) }, 'shape'], [{ bundle: Object.assign({}, bundle, { meter: 5 }) }, 'shape'], [{ bundle, mode: 'wipe' }, 'shape']
  ]) {
    const x = await h.reg.handlers['lanusers:restore'](arg);
    assert.deepEqual([x.ok, x.error, x.detail], [false, 'backup', detail], JSON.stringify(arg).slice(0, 80));
  }
});

test('while connected: a filter edit is a reload (its rules are the user’s in the config), a priority or remember edit is not; cards made are one', async () => {
  const h = bare({ lanUsers: { config: { proxy: { enabled: true, port: 30820, httpPort: 30821 } }, users: [user('usr-a', 'ali')] } }, { running: () => true, canReload: () => true });
  await h.reg.forBuild({ modules: { lanUsers: true } });
  assert.deepEqual((await h.user({ op: 'update', user: { id: 'usr-a', priority: 'high', remember: true } })).pendingReconnect, []);
  assert.equal((await h.user({ op: 'update', user: { id: 'usr-a', filter: { block: ['ads'] } } })).pendingReconnect, true);
  await h.reg.forBuild({ modules: { lanUsers: true } });
  assert.equal((await h.user({ op: 'vouchers', batch: { count: 5 } })).pendingReconnect, true, 'five new accounts');
  await wait(700);
  assert.equal(h.seen.reloads, 1, 'a run of edits is one reload');
});

test('the desktop’s proxy accounts take a voucher as username = code, password = code — and drop it when its time is up', async () => {
  const { applyLanUsers } = require('../src/modules/lanUsers/xray');
  const on = card('usr-v', 'ABCD-EFGH', { voucher: { batch: 'vb-1', hours: 2, activatedAt: NOW - HOUR }, expiresAt: NOW + HOUR });
  const h = bare({ lanUsers: { config: { proxy: { enabled: true, port: 30820, httpPort: 30821 } }, users: [user('usr-a', 'ali'), on] } });
  const accounts = async () => {
    const lu = await h.reg.forBuild({ modules: { lanUsers: true } });
    const cfg = applyLanUsers({ inbounds: [], outbounds: [{ tag: 'proxy', protocol: 'freedom' }], routing: { rules: [] } }, lu, {});
    const socks = (cfg.inbounds || []).find((i) => i.tag === 'lu-socks');
    return socks ? socks.settings.accounts : [];
  };
  assert.deepEqual(await accounts(), [{ user: 'ali', pass: 'pw-ali' }, { user: 'ABCD-EFGH', pass: 'ABCD-EFGH' }]);
  h.set(NOW + 2 * HOUR);
  assert.deepEqual(await accounts(), [{ user: 'ali', pass: 'pw-ali' }]);
  assert.equal(h.reg.meter.holdOf('usr-v').why, 'expired', 'held as any expired user');
});

test('lanusers:get carries `shaper` only where service.js hands the router’s in; the wiring — six channels, the bridges, the router’s hooks', async () => {
  const { registerLanUsers, CHANNELS } = require('../src/modules/lanUsers/ipc');
  const reg = (shaper) => registerLanUsers({ store: { get: (k, d) => d, set() {} }, getSettings: () => ({ modules: { lanUsers: true } }), platform: 'desktop', firewall: { sync() {} }, shaper });
  const info = { mode: 'police', missing: ['tc-tiny', 'kmod-sched-core', 'kmod-ifb'], line: { down: 0, up: 0 } };
  assert.deepEqual((await reg(() => info).handlers['lanusers:get']()).shaper, info);
  assert.equal((await reg(() => { throw new Error('x'); }).handlers['lanusers:get']()).shaper, null);
  assert.ok(!('shaper' in await reg(undefined).handlers['lanusers:get']()));
  assert.deepEqual(CHANNELS, ['lanusers:get', 'lanusers:config', 'lanusers:user', 'lanusers:device', 'lanusers:backup', 'lanusers:restore']);
  const preload = R('src', 'preload', 'preload.js');
  const web = R('src', 'server', 'web-api.js');
  for (const [name, ch, arg] of [['lanUsersBackup', 'lanusers:backup', ''], ['lanUsersRestore', 'lanusers:restore', 'arg']]) {
    const call = arg ? `'${ch}', ${arg}` : `'${ch}'`;
    assert.ok(preload.includes(`${name}: (${arg}) => ipcRenderer.invoke(${call}),`), `preload ${name}`);
    assert.ok(web.includes(`${name}: (${arg}) => invoke(${call}),`), `web-api ${name}`);
  }
  const svc = R('src', 'server', 'service.js');
  for (const hook of ['assignDevice: (a) => lanUsers.assignDevice(a),', 'activateVoucher: (id) => lanUsers.activateVoucher(id),', 'request: (id, r) => lanUsers.request(id, r)']) assert.ok(svc.includes(hook), hook);
  assert.match(svc, /shaper: OPENWRT \? \(\) => \(typeof lanRouter\.shaperInfo === 'function' \? lanRouter\.shaperInfo\(\) : null\) : undefined,/);
  assert.match(R('src', 'main', 'main.js'), /appVersion: app\.getVersion\(\),/);
});
