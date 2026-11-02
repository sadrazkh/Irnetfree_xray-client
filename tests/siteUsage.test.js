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

/* ------------------------------------ a router: device by device, and light ------------------------------------ */

const PHONE = { id: 'aa:aa:aa:aa:aa:01', name: 'phone' };
const LAPTOP = { id: 'aa:aa:aa:aa:aa:02', name: 'laptop' };
const lanConn = (id, host, source, up, down, start) => conn(id, host, up, down, start, { sourceIP: source });
const TABLE = S.deviceTable([{ mac: 'AA:AA:AA:AA:AA:01', name: 'phone', ips: ['10.0.0.2', '2001:db8::2'] }, { mac: 'aa:aa:aa:aa:aa:02', name: 'laptop', ips: ['10.0.0.3'] }, null, {}]);
const routerRig = (over = {}) => rig(Object.assign({ router: true, limits: S.ROUTER_LIMITS, device: (m) => S.deviceOfSource(TABLE, m.sourceIP) }, over));

test('deviceOfSource: by any of a device\'s addresses, the router itself, and an address not known yet', () => {
  assert.deepEqual(S.deviceOfSource(TABLE, '10.0.0.2'), PHONE);
  assert.deepEqual(S.deviceOfSource(TABLE, '2001:DB8::2'), PHONE);
  assert.deepEqual(S.deviceOfSource(TABLE, '::ffff:10.0.0.3'), LAPTOP);
  for (const own of ['172.19.0.1', 'fdfe:dcba:9876::1', '127.0.0.1', '::1', '', null]) assert.deepEqual(S.deviceOfSource(TABLE, own), { id: S.ROUTER_DEVICE, name: '' }, String(own));
  assert.deepEqual(S.deviceOfSource(TABLE, '10.0.0.9'), { id: '10.0.0.9', name: '', unknown: true });
});

test('each device has its own rows, and the house has them all', async () => {
  const { meter, read, state } = routerRig();
  await read([], 0, 0);
  const t = state.at;
  await read([lanConn('a', 'www.youtube.com', '10.0.0.2', 10, 1000, t + 1), lanConn('b', 'www.aparat.com', '10.0.0.3', 5, 300, t + 1)], 15, 1300);
  const house = meter.report('today');
  assert.deepEqual(house.rows.map((r) => r.key), ['s:youtube', 'd:aparat.com']);
  assert.deepEqual(house.devices, [
    { id: PHONE.id, name: 'phone', up: 10, down: 1000, total: 1010 },
    { id: LAPTOP.id, name: 'laptop', up: 5, down: 300, total: 305 }
  ]);
  assert.equal(house.device, '');
  const phone = meter.report({ range: 'today', device: PHONE.id });
  assert.deepEqual(phone.rows.map((r) => [r.key, r.down]), [['s:youtube', 1000]]);
  assert.equal(phone.device, PHONE.id);
  assert.deepEqual(phone.total, { up: 10, down: 1000, total: 1010 });
  assert.equal(meter.report({ range: 'today', device: LAPTOP.id }).rows[0].key, 'd:aparat.com');
  assert.deepEqual(meter.report({ range: 'today', device: 'aa:bb:cc:dd:ee:ff' }).rows, [], 'a device with nothing');
  assert.equal(meter.report({ range: 'today', device: '<script>' }).device, '', 'what is not a device reads as the house');
});

test('a connection keeps its device, and what no connection explains stays with the house', async () => {
  const { meter, read, state } = routerRig();
  await read([], 0, 0);
  const t = state.at;
  await read([lanConn('a', 'www.youtube.com', '10.0.0.2', 0, 100, t + 1)], 0, 500);
  await read([lanConn('a', 'www.youtube.com', '10.0.0.3', 0, 300, t + 1)], 0, 700);
  const r = meter.report('today');
  assert.equal(r.total.down, 700);
  assert.equal(rowOf(r, 'u').down, 400);
  assert.deepEqual(r.devices.map((d) => [d.id, d.down]), [[PHONE.id, 300]], 'Other belongs to nobody');
});

test('the router\'s own traffic is a device of its own', async () => {
  const { meter, read, state } = routerRig();
  await read([], 0, 0);
  await read([lanConn('a', 'downloads.openwrt.org', '172.19.0.1', 0, 50, state.at + 1)], 0, 50);
  assert.deepEqual(meter.report('today').devices, [{ id: 'router', name: '', up: 0, down: 50, total: 50 }]);
});

test('without a device function there are no per-device figures and the answer has no device keys', async () => {
  const { meter, read, state } = rig();
  await read([], 0, 0);
  await read([lanConn('a', 'www.youtube.com', '10.0.0.2', 0, 50, state.at + 1)], 0, 50);
  const r = meter.report({ range: 'today', device: PHONE.id });
  assert.equal('devices' in r, false);
  assert.equal('cost' in r, false);
  assert.equal(rowOf(r, 's:youtube').down, 50, 'and it reads as the house');
  meter.flush();
  assert.deepEqual(Object.keys(state.saved), ['days']);
});

test('the device list is read again only now and then, sooner for an address it does not know, and a failed read harms nothing', async () => {
  let reads = 0, fail = false;
  const { state, read } = routerRig({ refreshDevices: async () => { reads++; if (fail) throw new Error('no ubus'); } });
  await read([], 0, 0, 1000);
  assert.equal(reads, 1, 'the first read of all');
  await read([], 0, 0, 1000);
  assert.equal(reads, 1);
  state.at += S.ROUTER_LIMITS.deviceRefreshMs;
  await read([], 0, 0, 1000);
  assert.equal(reads, 2);
  await read([lanConn('a', 'x.example', '10.0.0.9', 0, 1, state.at + 1)], 0, 1, 16000);
  assert.equal(reads, 2, 'the unknown address is seen by this read');
  fail = true;
  await read([lanConn('a', 'x.example', '10.0.0.9', 0, 1, state.at)], 0, 1, 1000);
  assert.equal(reads, 3, 'asked again sooner');
  await read([lanConn('a', 'x.example', '10.0.0.9', 0, 2, state.at)], 0, 2, 1000);
  assert.equal(reads, 3);
});

test('a router\'s ceilings: few rows a day per device, few devices; old device days go before the house\'s', async () => {
  const { meter, read, state } = routerRig();
  await read([], 0, 0);
  const manySites = Array.from({ length: S.ROUTER_LIMITS.maxDeviceKeys + 4 }, (_, i) => lanConn('s' + i, `s${i}.example`, '10.0.0.2', 0, 1, state.at + 1));
  await read(manySites, 0, manySites.length);
  const phone = meter.report({ range: 'today', device: PHONE.id });
  assert.equal(phone.rows.length, S.ROUTER_LIMITS.maxDeviceKeys + 1, 'and Other');
  assert.equal(phone.total.down, manySites.length, 'not a byte is lost');

  const crowd = routerRig({ device: (m) => ({ id: m.sourceIP, name: '' }) });
  await crowd.read([], 0, 0);
  const manyDevices = Array.from({ length: S.ROUTER_LIMITS.maxDevices + 3 }, (_, i) => lanConn('d' + i, 'x.example', `10.1.0.${i + 1}`, 0, 1, crowd.state.at + 1));
  await crowd.read(manyDevices, 0, manyDevices.length);
  const r = crowd.meter.report('today');
  assert.equal(r.devices.length, S.ROUTER_LIMITS.maxDevices);
  assert.equal(r.total.down, manyDevices.length, 'the house has them all');

  const day = 86400000;
  const old = routerRig({ load: () => ({ days: { [S.dayOf(T0 - 20 * day)]: { 'd:a.example': [1, 1] } }, devices: { [S.dayOf(T0 - 20 * day)]: { [PHONE.id]: { 'd:a.example': [1, 1] } }, [S.dayOf(T0)]: { [LAPTOP.id]: { 'd:b.example': [1, 1] } } }, names: { [PHONE.id]: 'phone', [LAPTOP.id]: 'laptop' } }) });
  await old.read([], 0, 0);
  const all = old.meter.report('all');
  assert.deepEqual(all.rows.map((x) => x.key), ['d:a.example'], 'the house keeps 31 days');
  assert.deepEqual(all.devices.map((x) => [x.id, x.name]), [[LAPTOP.id, 'laptop']], 'a device 14');
  old.meter.flush();
  assert.deepEqual(Object.keys(old.state.saved.names), [LAPTOP.id], 'a name goes with its device');
});

test('flash: a router saves at most every 30 minutes, whatever moves', async () => {
  let saves = 0;
  const { state, read } = routerRig({ save: () => { saves++; } });
  await read([], 0, 0);
  const t = state.at;
  await read([lanConn('a', 'x.example', '10.0.0.2', 0, 1, t + 1)], 0, 1);
  assert.equal(saves, 1, 'the first moves it from zero');
  for (let i = 2; i < 40; i++) await read([lanConn('a', 'x.example', '10.0.0.2', 0, i, t + 1)], 0, i, 5000);
  assert.equal(saves, 1, '38 reads of 5 s each');
  state.at += S.ROUTER_LIMITS.saveMs;
  await read([lanConn('a', 'x.example', '10.0.0.2', 0, 99, t + 1)], 0, 99);
  assert.equal(saves, 2);
});

test('reads back off when they get expensive: at most 2 % of the time, at most a minute apart', async () => {
  let cost = 0;
  const { state, meter } = routerRig({ fetch: async () => { state.at += cost; return { connections: [], uploadTotal: 0, downloadTotal: 0 }; } });
  assert.equal(meter.nextDelay(), 5000, 'nothing read yet');
  cost = 20;
  await meter.tick();
  assert.equal(meter.nextDelay(), 5000, '20 ms is within its share');
  cost = 400;
  await meter.tick();
  assert.equal(meter.nextDelay(), 20000);
  cost = 5000;
  await meter.tick();
  assert.equal(meter.nextDelay(), 60000);
  const r = meter.report('today');
  assert.deepEqual(r.cost, { conns: 0, ms: 5000, everyMs: 60000 });
  assert.equal(rig().meter.nextDelay(), S.POLL_MS, 'a desktop reads at its own pace');
});

test('a router with no API says reconnect, not tun2socks; off, a report has no cost and no read happens', async () => {
  let enabled = true, reads = 0;
  const m = S.createSiteUsage({ router: true, limits: S.ROUTER_LIMITS, device: () => PHONE, enabled: () => enabled, connected: () => true, tun: () => ({ watch: null }), fetch: async () => { reads++; return { connections: [], uploadTotal: 0, downloadTotal: 0 }; } });
  assert.equal(m.status(), 'reconnect');
  await m.tick();
  enabled = false;
  assert.equal(m.status(), 'off');
  await m.tick();
  assert.equal(reads, 0);
  assert.equal(m.report('today').cost, null);
});

test('the timer: one read at a time, and it stops', async () => {
  const m = S.createSiteUsage({ limits: { pollMs: 5 } });
  m.start();
  m.start();
  await new Promise((r) => setTimeout(r, 30));
  m.stop();
  m.stop();
});

test('readDevices and readNames keep what reads', () => {
  const day = '2026-11-02';
  assert.deepEqual(Object.keys(S.readDevices({ devices: { [day]: { 'aa:bb': { 's:x': [1, 2] }, router: { u: [3, 4] }, '10.0.0.2': { 'd:y': [5, 6] }, '<bad>': { 's:x': [1, 1] }, __proto__: {} } } })[day]).sort(), ['10.0.0.2', 'aa:bb', 'router']);
  for (const junk of [null, 3, {}, { devices: 4 }, { devices: { nope: {} } }]) assert.deepEqual(S.readDevices(junk), {});
  assert.deepEqual(Object.assign({}, S.readNames({ names: { 'aa:bb': 'x', router: 5, '<bad>': 'y' } })), { 'aa:bb': 'x' });
  assert.deepEqual(Object.assign({}, S.readNames(null)), {});
});

test('the router\'s config: the API and the sniff only with the option, and never a process lookup', () => {
  const { TunSingbox } = require('../src/main/tunSingbox');
  const written = (opts) => {
    const t = new TunSingbox({ composedBy: 'openwrt', platform: 'linux' });
    t.singboxPath = () => 'sing-box';
    t.singboxVersion = () => '1.14.3';
    const { cfgFile } = t.writeConfig(30808, [], opts, 'IRNetFree');
    const cfg = JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
    t.removeWork();
    return { cfg, watch: t.watch, sniffs: t.sniffs };
  };
  const off = written({ watch: WATCH });
  assert.equal(off.cfg.experimental, undefined, 'off: no API, whatever is handed in');
  assert.equal(off.watch, null);
  assert.equal(off.sniffs, false);
  const on = written({ watch: WATCH, sniff: true });
  assert.deepEqual(on.cfg.route.rules[0], { action: 'sniff' });
  assert.equal(on.cfg.experimental.clash_api.external_controller, '127.0.0.1:' + WATCH.port);
  assert.equal(on.cfg.route.find_process, undefined);
  assert.deepEqual(on.watch, WATCH);
  assert.equal(on.sniffs, true);
  const { TunOpenwrt } = require('../src/main/tunOpenwrt');
  const gw = Object.create(TunOpenwrt.prototype);
  gw.inner = { watch: WATCH, sniffs: true };
  assert.deepEqual([gw.watch, gw.sniffs], [WATCH, true]);
  gw.inner = {};
  assert.deepEqual([gw.watch, gw.sniffs], [null, false]);
});

test('the device addresses: every address a device answers from, leases and neighbours together', async () => {
  const { lanDeviceAddresses } = require('../src/main/openwrtNet');
  const list = await lanDeviceAddresses({
    readFile: async () => '1800000000 aa:aa:aa:aa:aa:01 192.168.1.5 phone 01:aa\n',
    run: async () => '192.168.1.5 lladdr aa:aa:aa:aa:aa:01 REACHABLE\nfe80::1 lladdr aa:aa:aa:aa:aa:01 STALE\n192.168.1.9 lladdr aa:aa:aa:aa:aa:02 REACHABLE\n'
  });
  const byMac = new Map(list.map((d) => [d.mac, d]));
  assert.equal(byMac.get('aa:aa:aa:aa:aa:01').name, 'phone');
  assert.deepEqual(byMac.get('aa:aa:aa:aa:aa:01').ips.sort(), ['192.168.1.5', 'fe80::1']);
  assert.deepEqual(byMac.get('aa:aa:aa:aa:aa:02').ips, ['192.168.1.9']);
  assert.deepEqual(await lanDeviceAddresses({ readFile: async () => { throw new Error('none'); } }), []);
});
