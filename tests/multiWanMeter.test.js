'use strict';
/**
 * Several internets' data caps (src/main/multiWanMeter.js): what each internet
 * carried this period, from the stats tick's raw counters and the running
 * config's group map / split list; a link over its cap → the skip list and ONE
 * reload; a new period → back, and one reload; the pending-settings wait; the
 * retry; the usage the window shows; the internets list the window gets. And
 * settingsMeta: a cap alone never asks for a reconnect, anything else in
 * multiWan does.
 *
 * Every clock is the test's own; nothing here touches the network.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const M = require('../src/main/multiWanMeter');
const { normalizeMultiWan } = require('../src/main/multiWan');
const { pendingReconnectKeys, snapshotApplied } = require('../src/main/settingsMeta');

const GIB = 1024 ** 3;
const at = (y, mo, d, h = 12) => new Date(y, mo - 1, d, h, 0, 0).getTime();   // local time, as the periods are

/* ------------------------------ periods ------------------------------ */

test('periods: a month is YYYY-MM, a day YYYY-MM-DD, local time; an uncapped link counts by the month', () => {
  const t = at(2026, 10, 25, 23);
  assert.equal(M.periodKey('month', t), '2026-10');
  assert.equal(M.periodKey('day', t), '2026-10-25');
  assert.equal(M.periodKey('none', t), '2026-10');
  assert.equal(M.periodStart('month', t), at(2026, 10, 1, 0));
  assert.equal(M.periodEnd('month', t), at(2026, 11, 1, 0));
  assert.equal(M.periodStart('day', t), at(2026, 10, 25, 0));
  assert.equal(M.periodEnd('day', t), at(2026, 10, 26, 0));
  assert.equal(M.periodEnd('month', at(2026, 12, 31)), at(2027, 1, 1, 0), 'December rolls into the next year');
});

test('a cap is in bytes (the app’s binary GB), only with a period to count it in', () => {
  assert.equal(M.capBytes({ quotaGb: 3, quotaPeriod: 'day' }), 3 * GIB);
  assert.equal(M.capBytes({ quotaGb: 1.5, quotaPeriod: 'month' }), Math.round(1.5 * GIB));
  assert.equal(M.capBytes({ quotaGb: 3, quotaPeriod: 'none' }), 0, 'no period: no cap');
  assert.equal(M.capBytes({ quotaGb: 0, quotaPeriod: 'month' }), 0);
  assert.equal(M.capBytes(null), 0);
});

test('an entry moved to a new period: a day keeps its bytes into its own month; anything else starts at nothing', () => {
  const e = { period: '2026-10-25', bytes: 500 };
  assert.equal(M.rollEntry(e, '2026-10-25'), e, 'the same period: the same entry');
  assert.deepEqual(M.rollEntry(e, '2026-10'), { period: '2026-10', bytes: 500 }, 'today was this month too');
  assert.deepEqual(M.rollEntry({ period: '2026-10', bytes: 900 }, '2026-10-25'), { period: '2026-10-25', bytes: 0 }, 'a month says nothing of today');
  assert.deepEqual(M.rollEntry({ period: '2026-09-30', bytes: 900 }, '2026-10'), { period: '2026-10', bytes: 0 });
  assert.deepEqual(M.rollEntry(null, '2026-10'), { period: '2026-10', bytes: 0 });
});

test('what was saved is read back each entry of its type; junk is dropped', () => {
  assert.deepEqual(M.normalizeUsage({
    'Wi-Fi': { period: '2026-10', bytes: 12.7 },
    usb: { period: '2026-10-25', bytes: -4 },
    bad1: { period: 'October', bytes: 1 },
    bad2: 'x',
    '': { period: '2026-10', bytes: 1 }
  }), { 'Wi-Fi': { period: '2026-10', bytes: 13 }, usb: { period: '2026-10-25', bytes: 0 } });
  assert.deepEqual(M.normalizeUsage(null), {});
});

/* ------------------------------ the quota ------------------------------ */

/** The group map expandGroups writes for a balanced outbound `proxy` over Wi-Fi ×2 and the phone ×1 (multiWan.js's member ids). */
const MAP = [{ tag: 'proxy', groupId: 'mw:proxy', name: 'DE', strategy: 'roundRobin', fallback: null,
  members: [{ id: 'srv-1#Wi-Fi', name: 'DE · Wi-Fi' }, { id: 'srv-1#Wi-Fi', name: 'DE · Wi-Fi' }, { id: 'srv-1#usb', name: 'DE · phone' }] }];
/** /debug/vars as the core answers it: raw per-tag counters, before any folding. */
const vars = (c) => ({ stats: { outbound: Object.fromEntries(Object.entries(c).map(([tag, [up, down]]) => [tag, { uplink: up, downlink: down }])) } });

function mw(over = {}) {
  return normalizeMultiWan(Object.assign({
    enabled: true, mode: 'balance',
    links: [
      { id: 'Wi-Fi', iface: 'Wi-Fi', name: 'Wi-Fi — Home', role: 'use', weight: 2, quotaGb: 0, quotaPeriod: 'none' },
      { id: 'usb', iface: 'Ethernet 3', name: 'Phone (USB)', role: 'use', weight: 2, quotaGb: 3, quotaPeriod: 'day' }
    ]
  }, over));
}

/** A quota over fakes: the clock, the settings, the live connection, the reloads and the log are the test's. */
function harness(opts = {}) {
  const h = {
    t: opts.t || at(2026, 10, 25),
    settings: opts.settings || mw(),
    live: opts.live === undefined ? mw() : opts.live,
    pending: [],
    canReload: true,
    reloads: [],
    reloadAnswer: true,
    logs: [],
    notes: []
  };
  h.q = M.createMultiWanQuota({
    usage: opts.usage || {},
    settings: () => h.settings,
    live: () => h.live,
    canReload: () => h.canReload,
    pending: () => h.pending,
    reload: async (why) => { h.reloads.push(why); return h.reloadAnswer; },
    log: (l) => h.logs.push(l),
    notify: (n) => h.notes.push(n),
    now: () => h.t
  });
  h.flush = () => new Promise((r) => setImmediate(r));
  return h;
}

test('a tick counts each internet’s bytes from the members’ `#link` ids — weight copies of one link add up under that link', () => {
  const h = harness();
  h.q.reset([]);
  h.q.tick(vars({ 'proxy~gm0': [100, 1000], 'proxy~gm1': [50, 500], 'proxy~gm2': [7, 70], direct: [9, 9] }), MAP, null);
  const u = h.q.usage();
  assert.equal(u['Wi-Fi'].bytes, 1650, 'both copies of Wi-Fi, up and down');
  assert.equal(u.usb.bytes, 77);
  assert.equal(u['Wi-Fi'].period, '2026-10', 'uncapped: by the month');
  assert.equal(u.usb.period, '2026-10-25', 'a daily cap: by the day');
  assert.equal(h.q.dirty, true);
});

test('the next tick adds only what is new, and its rates are bytes per second over the measured gap', () => {
  const h = harness();
  h.q.reset([]);
  h.q.tick(vars({ 'proxy~gm0': [100, 1000], 'proxy~gm2': [0, 0] }), MAP, null);
  assert.deepEqual(h.q.rates()['Wi-Fi'], { up: 0, down: 0 }, 'a first reading has no rate yet');
  h.t += 2000;
  h.q.tick(vars({ 'proxy~gm0': [300, 5000], 'proxy~gm2': [10, 30] }), MAP, null);
  assert.equal(h.q.usage()['Wi-Fi'].bytes, 5300);
  assert.deepEqual(h.q.rates()['Wi-Fi'], { up: 100, down: 2000 });
  assert.deepEqual(h.q.rates().usb, { up: 5, down: 15 });
});

test('a reading below the last is a fresh core counting from zero: all of it is new; reset() says so outright', () => {
  const h = harness();
  h.q.reset([]);
  h.q.tick(vars({ 'proxy~gm0': [0, 1000] }), MAP, null);
  h.t += 1000;
  h.q.tick(vars({ 'proxy~gm0': [0, 400] }), MAP, null);   // the core restarted under us
  assert.equal(h.q.usage()['Wi-Fi'].bytes, 1400);
  h.q.reset([]);   // a rebuild: the next reading is a new core's, whatever its size
  h.t += 1000;
  h.q.tick(vars({ 'proxy~gm0': [0, 2000] }), MAP, null);
  assert.equal(h.q.usage()['Wi-Fi'].bytes, 3400);
  h.q.stop();
  assert.deepEqual(h.q.rates(), {}, 'no core: nothing moving');
});

test('split mode: the builder’s split list counts the XHTTP outbound’s upload on one internet and its download on the other', () => {
  const h = harness({ settings: mw({ mode: 'split', split: { up: 'usb', down: 'Wi-Fi' } }) });
  h.q.reset([]);
  h.q.tick(vars({ proxy: [40, 9000] }), null, [{ tag: 'proxy', up: 'usb', down: 'Wi-Fi' }]);
  const u = h.q.usage();
  assert.equal(u.usb.bytes, 40);
  assert.equal(u['Wi-Fi'].bytes, 9000);
});

test('nothing to read (no group map, no split list, a failed poll) counts nothing', () => {
  const h = harness();
  h.q.reset([]);
  h.q.tick(vars({ proxy: [1, 1] }), null, null);
  h.q.tick(null, MAP, null);
  assert.equal(h.q.dirty, false);
  assert.equal(h.q.usage()['Wi-Fi'].bytes, 0);
});

test('a link over its cap: in skip(), said in the log and a notification, and ONE reload however many ticks follow', async () => {
  const h = harness();
  h.q.reset([]);
  const big = 3 * GIB + 5;
  h.q.tick(vars({ 'proxy~gm2': [5, big - 5] }), MAP, null);
  assert.deepEqual(h.q.skip(), ['usb']);
  await h.flush();
  assert.equal(h.reloads.length, 1);
  assert.match(h.reloads[0], /without the internets over their cap/);
  const said = h.logs.filter((l) => /reached its cap/.test(l.line));
  assert.equal(said.length, 1);
  assert.match(said[0].line, /“Phone \(USB\)” reached its cap \(3 GB today\) — set aside until tomorrow/);
  assert.equal(said[0].level, 'warn');
  assert.deepEqual(h.notes, [{ name: 'Phone (USB)', capGb: 3, period: 'day', until: at(2026, 10, 26, 0), calendar: 'gregorian' }]);
  // the reload has not landed yet (its reset is what says so): later ticks ask nothing more meanwhile
  for (let i = 0; i < 5; i++) { h.t += 1000; h.q.tick(vars({ 'proxy~gm2': [5, big] }), MAP, null); }
  await h.flush();
  assert.equal(h.reloads.length, 1, 'a retry waits RETRY_MS');
  // the rebuild ran: the core was built without it
  h.q.reset(['usb']);
  h.t += 60000;
  h.q.tick(vars({ 'proxy~gm0': [1, 1] }), MAP, null);
  await h.flush();
  assert.equal(h.reloads.length, 1, 'built as it should be: nothing to do');
  assert.equal(h.logs.filter((l) => /reached its cap/.test(l.line)).length, 1, 'said once');
});

test('a new period brings it back: the log says so, and one reload puts it in again', async () => {
  const h = harness({ usage: { usb: { period: '2026-10-25', bytes: 4 * GIB } } });
  assert.deepEqual(h.q.skip(), ['usb'], 'over its cap today, from what was saved');
  h.q.reset(['usb']);   // connected without it
  h.q.tick(vars({ 'proxy~gm0': [1, 1] }), MAP, null);
  await h.flush();
  assert.equal(h.reloads.length, 0);
  h.t = at(2026, 10, 26, 0) + 1000;   // past midnight
  h.q.tick(vars({ 'proxy~gm0': [2, 2] }), MAP, null);
  await h.flush();
  assert.deepEqual(h.q.skip(), []);
  assert.equal(h.q.usage().usb.bytes, 0, 'a new day counts from nothing');
  assert.equal(h.q.usage().usb.period, '2026-10-26');
  assert.equal(h.reloads.length, 1);
  assert.match(h.reloads[0], /every internet back/);
  assert.ok(h.logs.some((l) => /“Phone \(USB\)” is back in use/.test(l.line) && l.level === 'info'), JSON.stringify(h.logs));
});

test('a link capped by the Persian month from the 15th: its period, its renew day in the log and the notice, back on 15 Azar', async () => {
  const persian = mw({ links: [mw().links[0], Object.assign({}, mw().links[1], { quotaGb: 3, quotaPeriod: 'month', quotaCalendar: 'jalali', quotaResetDay: 15 })] });
  const h = harness({ t: at(2026, 11, 20), settings: persian, live: persian });   // 29 Aban 1405
  assert.deepEqual(persian.links[1].quotaCalendar, 'jalali', 'normalized, the link keeps its month');
  h.q.reset([]);
  h.q.tick(vars({ 'proxy~gm2': [5, 3 * GIB] }), MAP, null);
  const u = h.q.usage().usb;
  assert.deepEqual([u.period, u.since, u.until], ['j1405-08@15', at(2026, 11, 6, 0), at(2026, 12, 6, 0)], '15 Aban – 15 Azar');
  assert.deepEqual(h.q.skip(), ['usb']);
  await h.flush();
  const said = h.logs.filter((l) => /reached its cap/.test(l.line));
  assert.equal(said[0].line, 'Multi-internet: “Phone (USB)” reached its cap (3 GB this month) — set aside until 6 December (15 Azar); the connection goes on the other internets');
  assert.deepEqual(h.notes, [{ name: 'Phone (USB)', capGb: 3, period: 'month', until: at(2026, 12, 6, 0), calendar: 'jalali' }]);
  h.q.reset(['usb']);
  h.t = at(2026, 12, 1);   // the Gregorian month turned: not this cap's
  h.q.tick(vars({ 'proxy~gm0': [1, 1] }), MAP, null);
  assert.deepEqual(h.q.skip(), ['usb'], 'still set aside on 1 December');
  h.t = at(2026, 12, 6, 0) + 1000;
  h.q.tick(vars({ 'proxy~gm0': [1, 1] }), MAP, null);
  await h.flush();
  assert.deepEqual(h.q.skip(), []);
  assert.equal(h.q.usage().usb.period, 'j1405-09@15');
  assert.deepEqual(M.normalizeUsage({ usb: { period: 'j1405-08@15', bytes: 1 }, wan: { period: '2026-10@31', bytes: 2 }, bad: { period: 'all', bytes: 3 } }),
    { usb: { period: 'j1405-08@15', bytes: 1 }, wan: { period: '2026-10@31', bytes: 2 } }, 'a link never counts for good');
});

test('a cap raised while set aside brings it back the same way — caps are read live', async () => {
  const h = harness({ usage: { usb: { period: '2026-10-25', bytes: 4 * GIB } } });
  h.q.reset(['usb']);
  h.settings = mw({ links: [mw().links[0], Object.assign({}, mw().links[1], { quotaGb: 10 })] });
  h.q.tick(vars({ 'proxy~gm0': [1, 1] }), MAP, null);
  await h.flush();
  assert.deepEqual(h.q.skip(), []);
  assert.equal(h.reloads.length, 1);
});

test('pending settings: the set-aside waits for them (said once), then reloads once they are applied', async () => {
  const h = harness();
  h.pending = ['routingMode'];
  h.q.reset([]);
  h.q.tick(vars({ 'proxy~gm2': [0, 4 * GIB] }), MAP, null);
  h.t += 20000;
  h.q.tick(vars({ 'proxy~gm2': [0, 4 * GIB] }), MAP, null);
  await h.flush();
  assert.equal(h.reloads.length, 0, 'a reload would take the pending change live behind the user’s back');
  assert.equal(h.logs.filter((l) => /waits for your pending settings/.test(l.line)).length, 1);
  h.pending = [];
  h.t += 20000;
  h.q.tick(vars({ 'proxy~gm2': [0, 4 * GIB] }), MAP, null);
  await h.flush();
  assert.equal(h.reloads.length, 1);
});

test('a reload that did not happen is asked again — no sooner than RETRY_MS', async () => {
  const h = harness();
  h.reloadAnswer = false;   // a connect came first, say
  h.q.reset([]);
  h.q.tick(vars({ 'proxy~gm2': [0, 4 * GIB] }), MAP, null);
  await h.flush();
  assert.equal(h.reloads.length, 1);
  h.t += M.RETRY_MS - 1;
  h.q.tick(vars({ 'proxy~gm2': [0, 4 * GIB] }), MAP, null);
  await h.flush();
  assert.equal(h.reloads.length, 1);
  h.t += 1;
  h.q.tick(vars({ 'proxy~gm2': [0, 4 * GIB] }), MAP, null);
  await h.flush();
  assert.equal(h.reloads.length, 2);
});

test('nothing is reloaded while busy (canReload) or when the running core is not on several internets', async () => {
  const busy = harness();
  busy.canReload = false;
  busy.q.reset([]);
  busy.q.tick(vars({ 'proxy~gm2': [0, 4 * GIB] }), MAP, null);
  await busy.flush();
  assert.equal(busy.reloads.length, 0);
  assert.equal(busy.logs.filter((l) => /reached its cap/.test(l.line)).length, 1, 'the cap is still said');

  const off = harness({ live: mw({ enabled: false }) });
  off.q.reset([]);
  off.q.tick(vars({ 'proxy~gm2': [0, 4 * GIB] }), MAP, null);
  await off.flush();
  assert.equal(off.reloads.length, 0);
  assert.deepEqual(off.q.skip(), ['usb'], 'counted all the same: the next connect leaves it out');

  const none = harness({ live: null });   // disconnected
  none.q.reset(null);
  none.q.tick(vars({ 'proxy~gm2': [0, 4 * GIB] }), MAP, null);
  await none.flush();
  assert.equal(none.reloads.length, 0);
});

test('every internet over its cap: said once — the connection then goes the system’s own way', async () => {
  const both = mw({ links: mw().links.map((l) => Object.assign({}, l, { quotaGb: 1, quotaPeriod: 'day' })) });
  const h = harness({ settings: both, live: both });
  h.q.reset([]);
  h.q.tick(vars({ 'proxy~gm0': [0, 2 * GIB], 'proxy~gm2': [0, 2 * GIB] }), MAP, null);
  h.t += 1000;
  h.q.tick(vars({ 'proxy~gm0': [0, 2 * GIB], 'proxy~gm2': [0, 2 * GIB] }), MAP, null);
  await h.flush();
  assert.deepEqual(h.q.skip(), ['Wi-Fi', 'usb']);
  assert.equal(h.logs.filter((l) => /every internet is over its cap/.test(l.line)).length, 1);
});

test('the window’s usage: bytes, the period and its bounds, the cap in bytes, over or not — for every configured link', () => {
  const h = harness({ usage: { usb: { period: '2026-10-25', bytes: 2 * GIB } } });
  const u = h.q.usage();
  assert.deepEqual(u.usb, { bytes: 2 * GIB, period: '2026-10-25', since: at(2026, 10, 25, 0), until: at(2026, 10, 26, 0), quotaBytes: 3 * GIB, over: false });
  assert.deepEqual(u['Wi-Fi'], { bytes: 0, period: '2026-10', since: at(2026, 10, 1, 0), until: at(2026, 11, 1, 0), quotaBytes: 0, over: false });
});

test('saving: dirty after counting, due every 30 s, the saved copy is a copy', () => {
  const h = harness();
  h.q.reset([]);
  assert.equal(h.q.dueForSave(), false);
  h.q.tick(vars({ 'proxy~gm0': [1, 1] }), MAP, null);
  assert.equal(h.q.dueForSave(h.t + M.SAVE_EVERY_MS - 1), false);
  assert.equal(h.q.dueForSave(h.t + M.SAVE_EVERY_MS), true);
  const saved = h.q.saved();
  saved['Wi-Fi'].bytes = 0;
  assert.equal(h.q.usage()['Wi-Fi'].bytes, 2);
  h.q.markSaved();
  assert.equal(h.q.dirty, false);
});

/* ------------------------------ the internets list ------------------------------ */

test('mergeLinks: configured first in their order (one not connected now stays, present: false), then the newly found; the configured name wins; the last test rides along', () => {
  const listed = [
    { id: 'Ethernet 3', iface: 'Ethernet 3', name: 'Remote NDIS', kind: 'usb', address: '192.168.42.129', gateway: '192.168.42.1', metric: 25 },
    { id: 'Wi-Fi', iface: 'Wi-Fi', name: 'Wi-Fi', kind: 'wifi', address: '192.168.1.34', gateway: '192.168.1.1', metric: 35 }
  ];
  const cfg = normalizeMultiWan({ links: [{ id: 'Wi-Fi', iface: 'Wi-Fi', name: 'Wi-Fi — Home' }, { id: 'eth0', iface: 'eth0', name: 'Office cable' }] });
  const tests = { 'Wi-Fi': { ok: true, downMbps: 48.2, upMbps: 3.1 } };
  const out = M.mergeLinks(listed, cfg, tests);
  assert.deepEqual(out.map((l) => [l.id, l.present, l.configured]), [['Wi-Fi', true, true], ['eth0', false, true], ['Ethernet 3', true, false]]);
  assert.equal(out[0].name, 'Wi-Fi — Home');
  assert.equal(out[0].sysName, 'Wi-Fi');
  assert.equal(out[0].address, '192.168.1.34');
  assert.deepEqual(out[0].test, tests['Wi-Fi']);
  assert.equal(out[1].kind, 'other');
  assert.equal(out[1].address, '');
  assert.equal(out[2].kind, 'usb');
  assert.equal(out[2].test, null);
  assert.deepEqual(M.mergeLinks(null, null), []);
});

/* ------------------------------ settingsMeta ------------------------------ */

test('a cap alone never asks for a reconnect — the quota applies it; the rest of multiWan does', () => {
  const base = { multiWan: mw() };
  const applied = snapshotApplied(base);
  const capOnly = mw({ links: [mw().links[0], Object.assign({}, mw().links[1], { quotaGb: 20, quotaPeriod: 'month' })] });
  assert.deepEqual(pendingReconnectKeys(applied, { multiWan: capOnly }), []);
  assert.deepEqual(pendingReconnectKeys(applied, { multiWan: mw({ mode: 'failover' }) }), ['multiWan']);
  assert.deepEqual(pendingReconnectKeys(applied, { multiWan: mw({ links: [mw().links[0], Object.assign({}, mw().links[1], { role: 'backup' })] }) }), ['multiWan']);
  assert.deepEqual(pendingReconnectKeys(applied, { multiWan: mw({ links: [mw().links[0], Object.assign({}, mw().links[1], { weight: 3 })] }) }), ['multiWan']);
  assert.deepEqual(pendingReconnectKeys(applied, { multiWan: mw({ enabled: false }) }), ['multiWan']);
  // the snapshot keeps the caps (a reload builds from it; the quota reads the live ones)
  assert.equal(applied.multiWan.links[1].quotaGb, 3);
});
