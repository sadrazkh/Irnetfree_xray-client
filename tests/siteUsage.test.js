'use strict';
/**
 * Traffic by site (src/main/siteUsage.js): a connection's bytes in the right row, every
 * byte the API's totals moved accounted for, nothing recorded unless it was asked for
 * and the TUN sniffs. scripts/probe-site-usage.js says the same on a real sing-box.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const S = require('../src/main/siteUsage');
const { buildTunConfig } = require('../src/main/tunSingbox');

const WATCH = { port: 41000, secret: 'abcdef0123456789abcdef0123456789' };
const T0 = new Date(2026, 10, 2, 12, 0, 0).getTime();

const conn = (id, host, up, down, start, extra = {}) => ({
  id, upload: up, download: down, start: new Date(start).toISOString(),
  metadata: Object.assign({ host, destinationIP: '1.2.3.4', destinationPort: '443', processPath: '' }, extra)
});

/** A meter on a scripted API: each tick reads the next snapshot. */
function rig(over = {}) {
  const state = { snaps: [], at: T0, saved: null };
  const meter = S.createSiteUsage(Object.assign({
    enabled: () => true, connected: () => true, tun: () => ({ watch: WATCH, sniffs: true }),
    load: () => null, save: (v) => { state.saved = JSON.parse(JSON.stringify(v)); },
    fetch: async () => state.snaps.shift(), now: () => state.at
  }, over));
  const read = async (connections, uploadTotal, downloadTotal, stepMs = 2000) => {
    state.snaps.push({ connections, uploadTotal, downloadTotal });
    await meter.tick();
    state.at += stepMs;
  };
  return { state, meter, read };
}
const rowOf = (report, key) => report.rows.find((r) => r.key === key);

test('serviceOfHost: several domains are one service, the most specific suffix wins, a look-alike is not it', () => {
  for (const h of ['www.youtube.com', 'rr3---sn-abc.googlevideo.com', 'i.ytimg.com', 'youtu.be', 'YOUTUBEI.GOOGLEAPIS.COM.']) assert.equal(S.serviceOfHost(h), 'youtube', h);
  for (const h of ['www.instagram.com', 'scontent.cdninstagram.com']) assert.equal(S.serviceOfHost(h), 'instagram', h);
  assert.equal(S.serviceOfHost('fonts.googleapis.com'), 'google', 'Google keeps what is left of its names');
  assert.equal(S.serviceOfHost('notyoutube.com'), '');
  assert.equal(S.serviceOfHost('youtube.com.evil.example'), '');
  assert.equal(S.serviceOfHost(''), '');
});

test('registrable: the site, not the host; a country\'s second level stays with it', () => {
  assert.equal(S.registrable('a.b.example.com'), 'example.com');
  assert.equal(S.registrable('www.aparat.com'), 'aparat.com');
  assert.equal(S.registrable('cdn.site.co.ir'), 'site.co.ir');
  assert.equal(S.registrable('site.ir'), 'site.ir');
  assert.equal(S.registrable('www.foo.ir'), 'foo.ir');
  assert.equal(S.registrable('localhost'), 'localhost');
});

test('bucketOf: a service, a site, Telegram by its addresses, a program, and what is left', () => {
  assert.equal(S.bucketOf({ host: 'www.youtube.com', destinationPort: '443' }), 's:youtube');
  assert.equal(S.bucketOf({ host: 'WWW.Aparat.com', destinationPort: '443' }), 'd:aparat.com');
  assert.equal(S.bucketOf({ host: '', destinationIP: '149.154.167.51', destinationPort: '443' }), 's:telegram');
  assert.equal(S.bucketOf({ host: '', destinationIP: '2001:67c:4e8:f004::9', destinationPort: '443' }), 's:telegram');
  assert.equal(S.bucketOf({ host: '', destinationIP: '8.8.4.4', processPath: 'C:\\Games\\game.exe' }), 'a:game.exe');
  assert.equal(S.bucketOf({ host: '1.1.1.1', destinationIP: '1.1.1.1' }), 'u', 'an address in the name is no name');
  assert.equal(S.bucketOf({ destinationIP: '8.8.8.8', destinationPort: '53' }), 's:dns');
  assert.equal(S.bucketOf(null), 'u');
});

test('describe says what a row is', () => {
  assert.deepEqual(S.describe('s:youtube'), { kind: 'service', name: 'YouTube' });
  assert.deepEqual(S.describe('s:dns'), { kind: 'service', name: 'DNS' });
  assert.deepEqual(S.describe('d:aparat.com'), { kind: 'site', name: 'aparat.com' });
  assert.deepEqual(S.describe('a:game.exe'), { kind: 'app', name: 'game.exe' });
  assert.deepEqual(S.describe('u'), { kind: 'other', name: '' });
});

test('the first read is only a baseline; then each connection adds what it moved since, to its own row', async () => {
  const { meter, read } = rig();
  await read([conn('a', 'www.youtube.com', 100, 5000, T0 - 60000)], 100, 5000);
  assert.deepEqual(meter.report('today').rows, [], 'what it carried before anyone was counting is not counted');
  await read([conn('a', 'www.youtube.com', 150, 8000, T0 - 60000)], 150, 8000);
  const r = meter.report('today');
  assert.deepEqual([rowOf(r, 's:youtube').up, rowOf(r, 's:youtube').down], [50, 3000]);
  assert.equal(rowOf(r, 's:youtube').name, 'YouTube');
  assert.deepEqual(r.total, { up: 50, down: 3000, total: 3050 });
});

test('a new connection counts from its first byte; one older than the last read but unseen counts from now on', async () => {
  const { state, meter, read } = rig();
  await read([], 0, 0);
  await read([conn('new', 'www.instagram.com', 10, 900, state.at - 500), conn('old', 'site.example', 7, 70, T0 - 5000)], 17, 970);
  const r = meter.report('today');
  assert.equal(rowOf(r, 's:instagram').down, 900);
  assert.equal(rowOf(r, 'd:site.example'), undefined, 'its bytes are not known to be new');
  assert.deepEqual([rowOf(r, 'u').up, rowOf(r, 'u').down], [7, 70], 'the totals moved, so they land in Other');
});

test('a connection that opens while a read\'s answer travels counts from its first byte at the next read', async () => {
  const { state, meter } = rig({ fetch: async () => { const snap = state.snaps.shift(); state.at += 20; return snap; } });
  state.snaps.push({ connections: [], uploadTotal: 0, downloadTotal: 0 });
  await meter.tick();
  const opened = T0 + 10;   // after the read began, before its answer arrived
  state.snaps.push({ connections: [conn('a', 'www.youtube.com', 0, 5000, opened)], uploadTotal: 0, downloadTotal: 5000 });
  await meter.tick();
  const r = meter.report('today');
  assert.equal(rowOf(r, 's:youtube').down, 5000);
  assert.equal(rowOf(r, 'u'), undefined);
});

test('what the totals moved past the listed connections lands in Other, so the sum is what moved', async () => {
  const { meter, read } = rig();
  await read([conn('a', 'www.youtube.com', 0, 0, T0)], 0, 0);
  await read([conn('a', 'www.youtube.com', 0, 1000, T0)], 40, 1500);
  const r = meter.report('today');
  assert.equal(rowOf(r, 's:youtube').down, 1000);
  assert.deepEqual([rowOf(r, 'u').up, rowOf(r, 'u').down], [40, 500]);
  assert.deepEqual(r.total, { up: 40, down: 1500, total: 1540 });
});

test('a connection keeps its row and never counts backwards; the API\'s totals going backwards add nothing', async () => {
  const { meter, read } = rig();
  await read([conn('a', 'www.youtube.com', 0, 100, T0 - 1)], 0, 100);
  await read([conn('a', '', 0, 300, T0 - 1)], 0, 300);
  await read([conn('a', 'www.youtube.com', 0, 200, T0 - 1)], 0, 50);
  const r = meter.report('today');
  assert.equal(rowOf(r, 's:youtube').down, 200);
  assert.equal(rowOf(r, 'u'), undefined);
});

test('a new tunnel starts over: its ids and its totals are its own', async () => {
  let watch = WATCH;
  const { meter, read } = rig({ tun: () => ({ watch, sniffs: true }) });
  await read([conn('a', 'www.youtube.com', 0, 100, T0)], 0, 100);
  await read([conn('a', 'www.youtube.com', 0, 200, T0)], 0, 200);
  watch = { port: 41001, secret: '0123456789abcdef0123456789abcdef' };
  await read([conn('a', 'www.youtube.com', 0, 5, T0)], 0, 5);
  assert.equal(rowOf(meter.report('today'), 's:youtube').down, 100);
});

test('nothing is read or recorded unless it is on, connected, and the running TUN sniffs; each reason is said', async () => {
  let enabled = false, connected = true, tun = { watch: WATCH, sniffs: true };
  const { meter, state } = rig({ enabled: () => enabled, connected: () => connected, tun: () => tun, fetch: async () => { state.reads++; return { connections: [], uploadTotal: 0, downloadTotal: 0 }; } });
  state.reads = 0;
  const st = async () => { await meter.tick(); return meter.status(); };
  assert.equal(await st(), 'off');
  enabled = true;
  connected = false;
  assert.equal(await st(), 'notConnected');
  connected = true;
  tun = null;
  assert.equal(await st(), 'noTun');
  tun = { watch: null, backendId: 'tun2socks' };
  assert.equal(await st(), 'tun2socks');
  tun = { watch: null, native: true };
  assert.equal(await st(), 'native');
  tun = { watch: WATCH, sniffs: false };
  assert.equal(await st(), 'reconnect', 'turned on, but this tunnel was built without the sniff');
  assert.equal(state.reads, 0);
  tun = { watch: WATCH, sniffs: true };
  assert.equal(await st(), 'recording');
  assert.equal(state.reads, 1);
});

test('a read that fails loses nothing: the next one\'s totals and bytes cover the gap', async () => {
  const { state, meter } = rig({ fetch: async () => { const n = state.snaps.shift(); if (n === 'down') throw new Error('no answer'); return n; } });
  state.snaps.push({ connections: [conn('a', 'www.youtube.com', 0, 100, T0 - 1)], uploadTotal: 0, downloadTotal: 100 }, 'down', { connections: [conn('a', 'www.youtube.com', 0, 900, T0 - 1)], uploadTotal: 0, downloadTotal: 900 });
  await meter.tick();
  await meter.tick();
  await meter.tick();
  assert.equal(rowOf(meter.report('today'), 's:youtube').down, 800);
});

test('the ranges: today, 7 and 30 days by the calendar, all of it; biggest first', async () => {
  const day = 86400000;
  const { meter, state, read } = rig();
  const at = (d) => { state.at = T0 - d * day; };
  const moved = async (d, id, host, down) => { at(d); await read([], 0, 0); at(d); await read([conn(id, host, 0, down, state.at)], 0, down); };
  await moved(40, 'a', 'old.example', 40);
  await moved(10, 'b', 'month.example', 30);
  await moved(3, 'c', 'week.example', 20);
  at(0);
  await moved(0, 'd', 'www.youtube.com', 10);
  state.at = T0;
  const keys = (range) => meter.report(range).rows.map((r) => r.key);
  assert.deepEqual(keys('today'), ['s:youtube']);
  assert.deepEqual(keys('7'), ['d:week.example', 's:youtube']);
  assert.deepEqual(keys('30'), ['d:month.example', 'd:week.example', 's:youtube']);
  assert.deepEqual(keys('all'), ['d:old.example', 'd:month.example', 'd:week.example', 's:youtube']);
  assert.equal(meter.report('junk').range, '7');
});

test('saved per day, read back as it was; junk in the store is dropped; old days go; clear empties it', async () => {
  const { meter, state, read } = rig();
  await read([conn('a', 'www.youtube.com', 0, 0, T0)], 0, 0);
  await read([conn('a', 'www.youtube.com', 5, 50, T0)], 5, 50);
  meter.flush();
  const today = S.dayOf(T0);
  assert.deepEqual(state.saved.days[today]['s:youtube'], [5, 50]);

  const again = rig({ load: () => state.saved });
  assert.equal(rowOf(again.meter.report('today'), 's:youtube').down, 50);

  assert.deepEqual(S.readDays({ days: { 'not-a-day': { 's:x': [1, 2] }, '2026-01-01': { 's:x': [1, -5], 'bad key': [1, 2], 'd:y': 'no', u: [3] } } }), { '2026-01-01': Object.assign(Object.create(null), { 's:x': [1, 0], u: [3, 0] }) });
  for (const junk of [null, 3, 'x', {}, { days: 5 }]) assert.deepEqual(S.readDays(junk), {});

  const ancient = rig({ load: () => ({ days: { '2020-01-01': { 'd:old.example': [1, 1] } } }) });
  assert.equal(ancient.meter.report('all').rows.length, 1);
  await ancient.read([], 0, 0);
  assert.equal(ancient.meter.report('all').rows.length, 0, `kept at most ${S.KEEP_DAYS} days`);

  assert.deepEqual(meter.clear(), { ok: true });
  assert.deepEqual(meter.report('all').rows, []);
  assert.deepEqual(state.saved, { days: {} });
});

test('a day has a ceiling: past it a new site joins Other, what is known keeps its row', async () => {
  const { meter, state, read } = rig();
  const many = Array.from({ length: S.MAX_KEYS_PER_DAY + 5 }, (_, i) => conn('c' + i, `s${i}.example`, 0, 1, state.at + 1000));
  await read([], 0, 0);
  await read(many, 0, many.length);
  const r = meter.report('today');
  assert.equal(r.rows.length + r.more, S.MAX_KEYS_PER_DAY + 1, 'and Other');
  assert.equal(r.total.down, many.length, 'not a byte is lost');
  assert.ok(rowOf(r, 'u').down >= 5);
});

/* ------------------------------------ the TUN's config ------------------------------------ */

test('the sniff: first of the rules, with the API only, and the config of before without it', () => {
  const plain = buildTunConfig({ socksPort: 30808, watch: WATCH });
  assert.equal(plain.route.rules, undefined);
  assert.deepEqual(buildTunConfig({ socksPort: 30808, watch: WATCH, sniff: false }), plain);
  assert.deepEqual(buildTunConfig({ socksPort: 30808, sniff: true }), buildTunConfig({ socksPort: 30808 }), 'no API to read it from: not written');

  const on = buildTunConfig({ socksPort: 30808, watch: WATCH, sniff: true });
  assert.deepEqual(on.route.rules, [{ action: 'sniff' }]);
  assert.equal(on.route.final, 'socks-out');
  assert.equal(on.inbounds[0].sniff, undefined);

  const apps = buildTunConfig({ socksPort: 30808, watch: WATCH, sniff: true, apps: { mode: 'exclude', names: ['chrome.exe'] } });
  assert.deepEqual(apps.route.rules[0], { action: 'sniff' });
  assert.deepEqual(apps.route.rules[1], { port: 53, outbound: 'socks-out' }, 'the rules of before follow, in their order');

  const legacy = buildTunConfig({ socksPort: 30808, watch: WATCH, sniff: 'legacy' });
  assert.equal(legacy.inbounds[0].sniff, true, 'before 1.11, the inbound\'s own');
  assert.equal(legacy.route.rules, undefined);
});

/* ------------------------------------ the page ------------------------------------ */

test('the Logs page has the tab, the page script loads before app.js, and every string is in both languages', () => {
  const dir = path.join(__dirname, '..', 'src', 'renderer');
  const html = fs.readFileSync(path.join(dir, 'index.html'), 'utf8');
  assert.match(html, /id="logsTabSites"[^>]*aria-controls="sitesPage"/);
  assert.match(html, /<div class="sites" id="sitesPage" role="tabpanel" aria-labelledby="logsTabSites" hidden><\/div>/);
  const scripts = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
  assert.ok(scripts.indexOf('i18n.js') < scripts.indexOf('siteUsage.js') && scripts.indexOf('siteUsage.js') < scripts.indexOf('app.js'), scripts.join(', '));

  const page = fs.readFileSync(path.join(dir, 'siteUsage.js'), 'utf8');
  const i18n = fs.readFileSync(path.join(dir, 'i18n.js'), 'utf8');
  const keys = new Set([...page.matchAll(/'(su\.[A-Za-z0-9.]+)'/g)].map((m) => m[1]));
  assert.ok(keys.size >= 18);
  for (const key of keys) {
    if (key === 'su.why.') continue;
    assert.equal(i18n.split(`'${key}':`).length - 1, 2, key);
  }
  assert.equal(i18n.split(`'logs.tabSites':`).length - 1, 2);
  assert.equal(i18n.split(`'set.siteUsage':`).length - 1, 2);
  assert.equal(/innerHTML/.test(page), false, 'names come from the network: text nodes only');
});

test('every class the page draws has a style', () => {
  const dir = path.join(__dirname, '..', 'src', 'renderer');
  const page = fs.readFileSync(path.join(dir, 'siteUsage.js'), 'utf8');
  const css = fs.readFileSync(path.join(dir, 'settings.css'), 'utf8');
  for (const cls of new Set([...page.matchAll(/\bsu-[a-z-]+/g)].map((m) => m[0]))) assert.match(css, new RegExp(`\\.${cls}\\b`), cls);
});
