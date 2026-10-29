'use strict';
/**
 * Users and devices — the four channels lanusers:get / config / user / device
 * in the router's service (the real service over the gateway fakes: its LAN
 * address and its devices are the test's, nothing is listed or spawned), the
 * build they feed (the users' proxy on the router's LAN address), a change
 * while connected applied with one reload, a cap reached through the real
 * stats poller (a fake /debug/vars on a loopback port of the OS's choosing),
 * main.js's wiring read as text, and the two bridges.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const H = require('./serviceHarness');

process.setMaxListeners(60);
test.after(() => H.cleanupDirs());

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const { SERVER, SERVER_B, until } = H;
const GIB = 1024 ** 3;
const at = (y, mo, d, h = 12) => new Date(y, mo - 1, d, h, 0, 0).getTime();
const LAN = JSON.stringify({ l3_device: 'br-lan', 'ipv4-address': [{ address: '192.168.1.1', mask: 24 }] });
const user = (id, username, over) => Object.assign({ id, username, password: 'pw-' + username, name: '', target: '', quotaGb: 0, quotaPeriod: 'month', expiresAt: 0, maxDevices: 0, enabled: true }, over);

/** A router whose LAN is 192.168.1.1/24 (ubus) and whose devices answering now are the test's. */
function start(store = {}, extra = {}) {
  const settings = Object.assign({ modules: { lanUsers: true } }, store.settings || {});
  return H.start(Object.assign({}, store, { settings }), Object.assign({
    lanRun: async (cmd, args) => {
      if (cmd === 'ubus' && args.join(' ') === 'call network.interface.lan status') return LAN;
      throw new Error(`no ${cmd} here`);
    },
    lanDevices: async () => [{ mac: 'AA:BB:CC:DD:EE:01', ip: '192.168.1.50', hostname: 'phone' }, { mac: 'aa:bb:cc:dd:ee:02', ip: '192.168.1.51', name: 'tv', online: false }]
  }, extra));
}
const PROXY_ON = { config: { proxy: { enabled: true, port: 30820, httpPort: 30821 } } };

test('router: lanusers:get answers the contract’s shape — openwrt, its LAN address, the devices answering now with their user', async (t) => {
  const s = start({ lanUsers: Object.assign({ users: [user('usr-a', 'ali')], devices: [{ mac: 'aa:bb:cc:dd:ee:01', userId: 'usr-a', name: 'Ali phone' }] }, PROXY_ON) });
  t.after(() => s.service.shutdown());
  const res = await s.service.invoke('lanusers:get');
  assert.deepEqual(Object.keys(res).sort(), ['config', 'deviceUsage', 'devices', 'lanAddresses', 'live', 'ok', 'online', 'platform', 'portal', 'shaper', 'usage', 'users']);
  assert.equal(res.portal, null, 'the sign-in page is up only while connected in login mode');
  assert.ok(res.shaper === null || typeof res.shaper === 'object', 'the router’s shaper (router/index.js shaperInfo), or null');
  assert.equal(res.ok, true);
  assert.equal(res.platform, 'openwrt');
  assert.deepEqual(res.lanAddresses, ['192.168.1.1']);
  assert.deepEqual(res.online, { 'aa:bb:cc:dd:ee:01': { ip: '192.168.1.50', hostname: 'phone', userId: 'usr-a' } }, 'online only; bound to its user');
  assert.equal(res.users[0].password, 'pw-ali', 'the admin sees it');
  assert.deepEqual(res.usage['usr-a'], Object.assign({}, res.usage['usr-a'], { bytes: 0, quotaBytes: 0, over: false }));
  assert.match(res.usage['usr-a'].period, /^\d{4}-\d{2}$/);
  assert.deepEqual(res.live, {});
  assert.deepEqual(res.deviceUsage, {});
});

test('router: lanusers:user — add without an id (one is made), update with the whole user, delete by id (its devices unbound); refusals save nothing and say a code', async (t) => {
  const s = start({ lanUsers: { devices: [] } });
  t.after(() => s.service.shutdown());
  const added = await s.service.invoke('lanusers:user', { op: 'add', user: { username: 'ali', password: 'secret1', name: 'Ali', quotaGb: '5', quotaPeriod: 'day' } });
  assert.equal(added.ok, true);
  assert.match(added.id, /^usr-[0-9a-f]{10}$/);
  assert.deepEqual(added.pendingReconnect, [], 'nothing connected: nothing pending');
  assert.deepEqual(added.users.map((u) => [u.id, u.username, u.quotaGb, u.quotaPeriod, u.enabled]), [[added.id, 'ali', 5, 'day', true]]);
  for (const [u, code] of [[{ username: 'ALI', password: 'secret2' }, 'usernameTaken'], [{ username: 'a b', password: 'secret2' }, 'username'], [{ username: 'reza', password: 'abc' }, 'password'], [{ username: 'reza', password: 'secret2', quotaGb: -1 }, 'quota'], [{ username: 'reza', password: 'secret2', quotaPeriod: 'week' }, 'quota']]) {
    const r = await s.service.invoke('lanusers:user', { op: 'add', user: u });
    assert.equal(r.ok, false, JSON.stringify(u));
    assert.equal(r.error, code, JSON.stringify(u));
    assert.equal(r.users.length, 1, 'nothing saved');
  }
  const whole = Object.assign({}, added.users[0], { name: 'Ali R', target: 'direct', enabled: false });
  const upd = await s.service.invoke('lanusers:user', { op: 'update', user: whole });
  assert.deepEqual([upd.ok, upd.users[0].name, upd.users[0].target, upd.users[0].enabled, upd.users[0].password], [true, 'Ali R', 'direct', false, 'secret1']);
  assert.equal((await s.service.invoke('lanusers:user', { op: 'update', user: { id: 'usr-ghost0000', username: 'x', password: 'secret1' } })).error, 'notFound');
  await s.service.invoke('lanusers:device', { mac: 'aa:bb:cc:dd:ee:01', userId: added.id });
  const del = await s.service.invoke('lanusers:user', { op: 'delete', user: { id: added.id } });
  assert.deepEqual(del.users, []);
  assert.deepEqual(del.devices, [], 'its device, with nothing left to say, goes too');
  assert.equal((await s.service.invoke('lanusers:user', { op: 'nope', user: {} })).error, 'op');
  const raw = JSON.parse(fs.readFileSync(path.join(s.dir, 'store.json'), 'utf8'));
  assert.deepEqual(raw.lanUsers.users, [], 'on disk, in the store’s own key');
});

test('router: lanusers:config merges nested parts; a bad, clashing or taken port and bad hours are refused with their codes', async (t) => {
  const s = start();
  t.after(() => s.service.shutdown());
  const a = await s.service.invoke('lanusers:config', { proxy: { enabled: true } });
  assert.deepEqual(a.config.proxy, { enabled: true, port: 30820, httpPort: 30821 });
  const b = await s.service.invoke('lanusers:config', { transparent: { unassigned: 'block' } });
  assert.equal(b.config.proxy.enabled, true, 'the other part kept');
  assert.equal(b.config.transparent.unassigned, 'block');
  assert.equal(b.config.transparent.sessionHours, 24);
  for (const [part, code, detail] of [
    [{ proxy: { port: 'x' } }, 'port', undefined],
    [{ proxy: { port: 30821 } }, 'port', 'portClash'],
    [{ proxy: { port: H.PORTS.socksPort } }, 'port', 'portInUse'],
    [{ transparent: { sessionHours: 0 } }, 'hours', 'sessionHours'],
    [{ transparent: { unassigned: 'open' } }, 'unassigned', undefined]
  ]) {
    const r = await s.service.invoke('lanusers:config', part);
    assert.deepEqual([r.ok, r.error, r.detail], [false, code, detail], JSON.stringify(part));
  }
  assert.equal((await s.service.invoke('lanusers:get')).config.proxy.port, 30820, 'nothing saved');
});

test('router: lanusers:device binds a MAC to a user (up to their device limit), blocks and names it; a bad MAC or an unknown user is refused', async (t) => {
  const s = start({ lanUsers: { users: [user('usr-a', 'ali', { maxDevices: 1 })] } });
  t.after(() => s.service.shutdown());
  const r = await s.service.invoke('lanusers:device', { mac: 'AA-BB-CC-DD-EE-01', userId: 'usr-a', name: 'Phone' });
  assert.deepEqual(r.devices, [{ mac: 'aa:bb:cc:dd:ee:01', name: 'Phone', userId: 'usr-a', blocked: false, remembered: false, at: 0 }]);
  assert.equal((await s.service.invoke('lanusers:device', { mac: 'aa:bb:cc:dd:ee:02', userId: 'usr-a' })).error, 'maxDevices');
  assert.equal((await s.service.invoke('lanusers:device', { mac: 'aa:bb:cc:dd:ee:02', userId: 'usr-ghost' })).error, 'user');
  assert.equal((await s.service.invoke('lanusers:device', { mac: 'zz' })).error, 'mac');
  const b = await s.service.invoke('lanusers:device', { mac: 'aa:bb:cc:dd:ee:02', blocked: true });
  assert.deepEqual(b.devices.map((d) => [d.mac, d.blocked]), [['aa:bb:cc:dd:ee:01', false], ['aa:bb:cc:dd:ee:02', true]]);
});

test('router: the connect builds the users’ proxy on the LAN address; a user added while connected is applied with ONE reload', async (t) => {
  const s = start({ lanUsers: Object.assign({ users: [user('usr-a', 'ali', { target: SERVER_B.id })] }, PROXY_ON) });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const x = s.state.xray;
  const cfg = x.starts[0].config;
  const socks = cfg.inbounds.find((i) => i.tag === 'lu-socks');
  assert.deepEqual([socks.listen, socks.port, socks.settings.accounts], ['192.168.1.1', 30820, [{ user: 'ali', pass: 'pw-ali' }]], 'the router’s LAN address, never 0.0.0.0');
  assert.equal(cfg.routing.rules.find((r) => r.user && r.user[0] === 'ali').outboundTag, 'lu-out-' + SERVER_B.id);
  const r = await s.service.invoke('lanusers:user', { op: 'add', user: { username: 'sara', password: 'secret9' } });
  assert.equal(r.pendingReconnect, true, 'the running core is being rebuilt');
  await s.service.invoke('lanusers:user', { op: 'add', user: { username: 'reza', password: 'secret8' } });
  await until(() => x.starts.length === 2, 'the reload');
  await new Promise((res) => setTimeout(res, 900));
  assert.equal(x.starts.length, 2, 'two edits in a row: one reload');
  assert.deepEqual(x.starts[1].config.inbounds.find((i) => i.tag === 'lu-socks').settings.accounts.map((a) => a.user), ['ali', 'sara', 'reza']);
  assert.deepEqual((await s.service.invoke('lanusers:user', { op: 'update', user: { id: 'usr-a', name: 'only a label' } })).pendingReconnect, [], 'a name is no reload');
});

test('router: a user over their cap is turned off with ONE reload through the real stats tick, said in the log; the next day they are back', async (t) => {
  let users = {};
  const metrics = http.createServer((req, res) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ stats: { outbound: {}, user: users } })); });
  await new Promise((r) => metrics.listen(0, '127.0.0.1', r));
  t.after(() => metrics.close());
  let now = at(2026, 10, 25, 12);
  const s = start({
    settings: { apiPort: metrics.address().port },
    lanUsers: Object.assign({ users: [user('usr-a', 'ali', { quotaGb: 1, quotaPeriod: 'day' }), user('usr-b', 'sara')] }, PROXY_ON)
  }, { now: () => now, timing: Object.assign({}, H.fakes.deps(H.fakes.makeState()).timing, { routerStatsMs: 40 }) });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const x = s.state.xray;
  users = { ali: { uplink: 1000, downlink: 2 * GIB }, sara: { uplink: 10, downlink: 500 } };
  await until(() => x.starts.length === 2, 'the reload without the user over their cap');
  users = {};   // a fresh core counts from zero
  assert.ok(s.logs.some((l) => /Users: “ali” reached their cap \(1 GB today\)/.test(l.line)), JSON.stringify(s.logs.map((l) => l.line)));
  assert.deepEqual(x.starts[1].config.inbounds.find((i) => i.tag === 'lu-socks').settings.accounts.map((a) => a.user), ['sara']);
  const live = await s.service.invoke('lanusers:get');
  assert.equal(live.usage['usr-a'].over, true);
  assert.equal(live.usage['usr-b'].bytes, 510);
  assert.ok(s.events.some(([ch, p]) => ch === 'stats' && p.lanUsers && p.lanUsers.usage), 'the stats event carries lanUsers');
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(x.starts.length, 2, 'one reload, not one a tick');
  now = at(2026, 10, 26, 0) + 5000;
  await until(() => x.starts.length === 3, 'the reload with her back');
  assert.ok(s.logs.some((l) => /“ali” is back/.test(l.line)));
  await s.service.invoke('disconnect');
  await s.service.shutdown();
  const saved = JSON.parse(fs.readFileSync(path.join(s.dir, 'usage.json'), 'utf8'));
  assert.ok(saved.lanUsersUsage && saved.lanUsersUsage['usr-b'], 'written beside the totals, never the main store');
  assert.equal(JSON.parse(fs.readFileSync(path.join(s.dir, 'store.json'), 'utf8')).lanUsersUsage, undefined);
});

test('router: module not installed — the connect’s config has no users’ inbound even with the proxy on', async (t) => {
  const s = start({ settings: { modules: {}, modulesMigrated: true }, lanUsers: Object.assign({ users: [user('usr-a', 'ali')] }, PROXY_ON) });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.ok(!s.state.xray.starts[0].config.inbounds.some((i) => i.tag.startsWith('lu-')));
});

/* ------------------------------ main.js and service.js, as text ------------------------------ */

const MAIN = R('src', 'main', 'main.js');
const SVC = R('src', 'server', 'service.js');
function fnOf(src, name) {
  const at0 = src.search(new RegExp(`\\n\\s*(async )?function ${name}\\(`));
  assert.ok(at0 > -1, `no function ${name}`);
  let depth = 0, j = src.indexOf('{', src.indexOf(')', at0));
  for (; j < src.length; j++) { if (src[j] === '{') depth++; else if (src[j] === '}' && --depth === 0) break; }
  return src.slice(at0, j + 1);
}

test('desktop and router: the connect and the reload build with lanUsers after multiWanSkip; the tick feeds the meter; the stats event carries it', () => {
  for (const [f, src] of [['main.js', MAIN], ['service.js', SVC]]) {
    for (const fn of ['connectOnce', 'rebuildActiveConfig']) {
      const body = fnOf(src, fn);
      // (v1.39.0: forBuild(settings, more) — the routing profiles and the geo files beside the settings)
      const i = body.indexOf('lanUsers.forBuild(settings');
      assert.ok(i > body.indexOf('multiWanSkip: mwSkip') && i < body.indexOf('buildActive(serverId, settings)'), `${f} ${fn}`);
      if (f === 'main.js') assert.ok(body.includes('lanUsers.forBuild(settings, lanUsersBuildInput())'), `${f} ${fn}: the profiles and geo handed in`);
    }
    assert.match(src, /mwQuota\.tick\(vars, stats\.groupMap, liveMwSplit\);\n\s*\/\/[^\n]*\n\s*(if \(lanUsers\) )?lanUsers\.tick\(vars\);/, `${f}: next to the quota`);
    assert.match(src, /if \(luLive\) s\.lanUsers = luLive;/, `${f}: the stats event`);
    assert.match(src, /require\('\.\.\/modules\/lanUsers\/ipc'\)/, `${f}: the require`);
  }
  // the desktop: right after multiwan:test, over ipcMain
  const reg = fnOf(MAIN, 'registerIpc');
  assert.ok(reg.indexOf('lanUsers = registerLanUsers({') > reg.indexOf("ipcMain.handle('multiwan:test'"));
  assert.match(reg, /handle: \(channel, fn\) => ipcMain\.handle\(channel, \(e, arg\) => fn\(arg\)\),/);
  // the router: its table takes the same handlers right after multiwan:test
  assert.ok(SVC.indexOf('...lanUsers.handlers,') > SVC.indexOf("'multiwan:test': async (ids) => {"));
  assert.match(SVC, /platform: OPENWRT \? 'router' : 'server', run: lanRun,/);
});

test('the cap notice says the day it renews: 1 Azar for a Persian month, 10 Aban for the Gregorian 1 Nov (Persian); the date in English', () => {
  const { registerLanUsers } = require('../src/modules/lanUsers/ipc');
  const said = (lang, over) => {
    let now = at(2026, 10, 26);
    const data = { lanUsers: { users: [user('usr-a', 'ali', Object.assign({ quotaGb: 1 }, over))] } };
    const texts = [];
    const reg = registerLanUsers({
      store: { get: (k, d) => (k in data ? data[k] : d), set: (k, v) => { data[k] = v; } },
      getSettings: () => ({ lang, modules: { lanUsers: true } }),
      platform: 'server', firewall: { sync() {} }, now: () => now, notify: (text) => texts.push(text)
    });
    reg.meter.built({ active: ['usr-a'], over: [], byName: { ali: 'usr-a' } });
    reg.tick({ stats: { user: { ali: { uplink: 0, downlink: 0 } } } });
    now += 1000;
    reg.tick({ stats: { user: { ali: { uplink: 0, downlink: 2 * GIB } } } });
    return texts;
  };
  assert.deepEqual(said('fa', { quotaCalendar: 'jalali' }), ['«ali» به سقف 1 گیگابایتِ ماهانه رسید — تا 1 آذر قطع است']);
  assert.deepEqual(said('en', { quotaCalendar: 'jalali' }), ['“ali” reached their 1 GB monthly cap — off until 22 November (1 Azar)']);
  assert.deepEqual(said('fa', {}), ['«ali» به سقف 1 گیگابایتِ ماهانه رسید — تا 10 آبان قطع است']);
  assert.deepEqual(said('en', { quotaResetDay: 15 }), ['“ali” reached their 1 GB monthly cap — off until 15 November']);
  assert.deepEqual(said('fa', { quotaPeriod: 'day' }), ['«ali» به سقف 1 گیگابایتِ روزانه رسید — تا فردا قطع است'], 'a day: tomorrow, as before');
  assert.deepEqual(said('en', { quotaPeriod: 'none' }), ['“ali” reached their 1 GB cap — off until it is raised']);
});

test('lanusers:user refuses a calendar or renew day the model does not know, as a cap’s error; a good one is stored', async (t) => {
  const s = start({ lanUsers: { users: [user('usr-a', 'ali')] } });
  t.after(() => s.service.shutdown());
  for (const [patch, detail] of [[{ quotaCalendar: 'lunar' }, 'quotaCalendar'], [{ quotaResetDay: 40 }, 'quotaResetDay']]) {
    const r = await s.service.invoke('lanusers:user', { op: 'update', user: Object.assign({ id: 'usr-a' }, patch) });
    assert.deepEqual([r.ok, r.error, r.detail], [false, 'quota', detail]);
  }
  const ok = await s.service.invoke('lanusers:user', { op: 'update', user: { id: 'usr-a', quotaCalendar: 'jalali', quotaResetDay: 15 } });
  assert.deepEqual([ok.ok, ok.users[0].quotaCalendar, ok.users[0].quotaResetDay], [true, 'jalali', 15]);
  assert.match(ok.usage['usr-a'].period, /^j\d{4}-\d{2}(@15)?$/);
  const back = await s.service.invoke('lanusers:user', { op: 'update', user: { id: 'usr-a', quotaCalendar: 'gregorian', quotaResetDay: 1 } });
  assert.equal('quotaCalendar' in back.users[0] || 'quotaResetDay' in back.users[0], false, 'the Gregorian 1st is stored as nothing, as before');
});

test('both bridges expose the same four calls', () => {
  const preload = R('src', 'preload', 'preload.js');
  const web = R('src', 'server', 'web-api.js');
  for (const [name, ch, arg] of [['lanUsersGet', 'lanusers:get', ''], ['lanUsersConfig', 'lanusers:config', 'partial'], ['lanUsersUser', 'lanusers:user', 'change'], ['lanUsersDevice', 'lanusers:device', 'change']]) {
    const call = arg ? `'${ch}', ${arg}` : `'${ch}'`;
    assert.ok(preload.includes(`${name}: (${arg}) => ipcRenderer.invoke(${call}),`), `preload ${name}`);
    assert.ok(web.includes(`${name}: (${arg}) => invoke(${call}),`), `web-api ${name}`);
  }
});

test('the addresses to give people: the Windows hotspot first; never the app’s own TUN adapters (sing-box’s 172.19.0.1 was offered)', () => {
  const { lanCandidates, HOTSPOT_IP } = require('../src/modules/lanUsers/ipc');
  assert.equal(HOTSPOT_IP, '192.168.137.1');
  const v4 = (address) => ({ family: 'IPv4', address, internal: false });
  const ifs = {
    IRNetFree: [v4('172.19.0.1')],
    XrayTun: [v4('10.255.0.2')],
    Ethernet: [v4('10.0.0.5'), v4('169.254.52.192')],
    'Wi-Fi': [v4('192.168.8.191')],
    'Local Area Connection* 10': [v4('192.168.137.1')],
    'Loopback Pseudo-Interface 1': [{ family: 'IPv4', address: '127.0.0.1', internal: true }]
  };
  assert.deepEqual(lanCandidates(ifs), ['192.168.137.1', '192.168.8.191', '10.0.0.5']);
});

test('lanusers:get carries `hotspot` only where main.js hands a hotspot check in (a Windows desktop); a check that throws is null, never the page\'s error', async () => {
  const { registerLanUsers } = require('../src/modules/lanUsers/ipc');
  const reg = (hotspot) => registerLanUsers({
    store: { get: (k, d) => d, set() {} },
    getSettings: () => ({ lang: 'en', modules: { lanUsers: true } }),
    platform: 'desktop', firewall: { sync() {} }, hotspot
  });
  const seen = { on: true, address: '192.168.137.1', tun: true, error: '', devices: [{ ip: '192.168.137.45', mac: 'a2:4b:11:0c:9e:07', seen: true, lastSeen: 1, open: 1, bytes: 10 }] };
  assert.deepEqual((await reg({ read: async () => seen }).handlers['lanusers:get']()).hotspot, seen);
  assert.equal((await reg({ read: async () => { throw new Error('arp'); } }).handlers['lanusers:get']()).hotspot, null);
  assert.ok(!('hotspot' in await reg(undefined).handlers['lanusers:get']()), 'no check: the payload of before');
});

test('lanusers:get carries `portal` only where service.js hands the router\'s sign-in page in; one that throws is null', async () => {
  const { registerLanUsers } = require('../src/modules/lanUsers/ipc');
  const reg = (portal) => registerLanUsers({
    store: { get: (k, d) => d, set() {} },
    getSettings: () => ({ lang: 'en', modules: { lanUsers: true } }),
    platform: 'router', run: async () => { throw new Error('no ubus here'); }, devices: async () => ({}), portal
  });
  const up = { url: 'http://192.168.2.1:30822/', name: 'login.lan', nameUrl: 'http://login.lan:30822/' };
  assert.deepEqual((await reg(() => up).handlers['lanusers:get']()).portal, up);
  assert.equal((await reg(() => null).handlers['lanusers:get']()).portal, null, 'not up');
  assert.equal((await reg(() => { throw new Error('gone'); }).handlers['lanusers:get']()).portal, null);
  assert.ok(!('portal' in await reg(undefined).handlers['lanusers:get']()), 'no page: the payload of before');
});

/* ------------------------------ v1.39.0: limits by kind, routing, top-ups, the build's holds and profiles ------------------------------ */

const F = require('./fixtures');
/** registerLanUsers over plain objects: the store, the usage file, the notices — nothing spawned, nothing bound. */
function bare(data, o = {}) {
  const { registerLanUsers } = require('../src/modules/lanUsers/ipc');
  const usage = o.usage || {};
  const texts = [];
  let t = o.now || at(2026, 10, 26, 12);
  const reg = registerLanUsers(Object.assign({
    store: { get: (k, d) => (k in data ? data[k] : d), set: (k, v) => { data[k] = v; } },
    usageStore: { get: (k, d) => (k in usage ? usage[k] : d), setLazy: (k, v) => { usage[k] = v; } },
    getSettings: () => ({ lang: o.lang || 'en', modules: { lanUsers: true } }),
    platform: 'desktop', firewall: { sync() {} }, now: () => t, notify: (text) => texts.push(text)
  }, o.extra || {}));
  return { reg, data, usage, texts, set: (v) => { t = v; } };
}
const PROFILES = [
  { id: 'rp-lu', name: 'Work', rules: [{ type: 'domain', value: 'corp.example', target: 'sv-ss' }, { type: 'ip', value: '203.0.113.9', target: 'direct' }], def: 'sv-trojan', defVia: 'inherit', useMode: false, base: null },
  { id: 'rp-other', name: 'Other', rules: [{ type: 'domain', value: 'x.example', target: 'sv-vless' }], def: 'sv-trojan', defVia: 'inherit', useMode: false, base: null }
];

test('lanusers:user carries the new fields, refuses them with their code and part, and a profile the app does not have; an older page’s cap edit lands in the limits', async () => {
  const h = bare({ routingProfiles: PROFILES, lanUsers: { users: [user('usr-a', 'ali', { quotaGb: 2, quotaPeriod: 'day' })] } });
  const call = (arg) => h.reg.handlers['lanusers:user'](arg);
  const ok = await call({ op: 'update', user: { id: 'usr-a', limits: [{ kind: 'vpn', period: 'day', gb: 1 }, { kind: 'total', period: 'month', gb: 20 }], routing: 'profile:rp-lu', schedule: { days: [6, 0], from: '08:00', to: '22:00' }, speed: { down: 4000 } } });
  assert.equal(ok.ok, true);
  const u = ok.users[0];
  assert.deepEqual([u.limits, u.quotaGb, u.quotaPeriod, u.routing, u.schedule, u.speed, u.speedHours], [
    [{ kind: 'total', period: 'month', gb: 20, action: 'cut' }, { kind: 'vpn', period: 'day', gb: 1, action: 'cut' }], 20, 'month', 'profile:rp-lu', { days: [0, 6], from: '08:00', to: '22:00' }, { down: 4000, up: 0 }, []]);
  for (const [patch, error, detail] of [
    [{ limits: [{ kind: 'vpn', period: 'day', gb: -1 }] }, 'limits', 'gb'], [{ routing: 'bypass-cn' }, 'routing', 'mode'], [{ routing: 'profile:rp-gone' }, 'routing', 'profile'],
    [{ schedule: { days: [1], from: '8', to: '9' } }, 'schedule', 'from'], [{ speed: { down: 0 } }, 'speed', 'base'], [{ quotaPeriod: 'week' }, 'quota', 'quotaPeriod']
  ]) {
    const r = await call({ op: 'update', user: Object.assign({ id: 'usr-a' }, patch) });
    assert.deepEqual([r.ok, r.error, r.detail], [false, error, detail], JSON.stringify(patch));
  }
  assert.equal(h.data.lanUsers.users[0].routing, 'profile:rp-lu', 'nothing saved');
  // the page of before: the whole user as it had it, its cap changed — the mirror's limit follows, the others stay
  const old = Object.assign({}, h.data.lanUsers.users[0], { quotaGb: 5, quotaPeriod: 'day' });
  const r = await call({ op: 'update', user: old });
  assert.deepEqual(r.users[0].limits, [{ kind: 'total', period: 'day', gb: 5, action: 'cut' }, { kind: 'vpn', period: 'day', gb: 1, action: 'cut' }]);
  assert.deepEqual([r.users[0].quotaGb, r.users[0].quotaPeriod], [5, 'day']);
});

test('lanusers:user topUp and resetUsage: more of one limit this period (saved at once), every period back to nothing; refused as notFound / topUp with the part', async () => {
  const h = bare({ lanUsers: { users: [user('usr-a', 'ali', { routing: 'bypass-ir', limits: [{ kind: 'vpn', period: 'day', gb: 1 }] })] } });
  h.reg.addBytes('usr-a', 1.5 * GIB);
  const call = (arg) => h.reg.handlers['lanusers:user'](arg);
  let p = await h.reg.handlers['lanusers:get']();
  assert.deepEqual([p.usage['usr-a'].hold, p.usage['usr-a'].why, p.usage['usr-a'].holdUntil], ['vpn', 'vpn', at(2026, 10, 27, 0)]);
  const vpnDay = (q) => q.usage['usr-a'].meters.find((m) => m.kind === 'vpn' && m.period === 'day');
  p = await call({ op: 'topUp', user: { id: 'usr-a' }, kind: 'vpn', period: 'day', gb: 1 });
  assert.equal(p.ok, true);
  assert.deepEqual([vpnDay(p).bytes, vpnDay(p).capBytes, vpnDay(p).extraBytes, vpnDay(p).pct, p.usage['usr-a'].hold], [1.5 * GIB, GIB, GIB, 75, null]);
  assert.equal(h.usage.lanUsersUsage2['usr-a'].extra['vpn:day'].bytes, GIB, 'in the usage file at once');
  assert.ok(h.usage.lanUsersHistory['usr-a'] && h.usage.lanUsersUsage['usr-a'], 'the history, and the old key for older apps');
  for (const [arg, error, detail] of [
    [{ op: 'topUp', user: { id: 'usr-ghost' }, kind: 'vpn', period: 'day', gb: 1 }, 'notFound', undefined],
    [{ op: 'topUp', user: { id: 'usr-a' }, kind: 'direct', period: 'day', gb: 1 }, 'topUp', 'limit'],
    [{ op: 'topUp', user: { id: 'usr-a' }, kind: 'vpn', period: 'day', gb: 0 }, 'topUp', 'gb'],
    [{ op: 'resetUsage', user: { id: 'usr-ghost' } }, 'notFound', undefined]
  ]) {
    const r = await call(arg);
    assert.deepEqual([r.ok, r.error, r.detail], [false, error, detail], JSON.stringify(arg));
  }
  p = await call({ op: 'resetUsage', user: { id: 'usr-a' } });
  assert.deepEqual([p.ok, vpnDay(p).bytes, vpnDay(p).extraBytes], [true, 0, 0]);
  assert.deepEqual(p.usage['usr-a'].history, [{ day: '2026-10-26', vpn: 1.5 * GIB, direct: 0 }], 'the history kept');
  assert.deepEqual(Object.keys(p.usage['usr-a']).sort(), ['bytes', 'history', 'hold', 'holdUntil', 'meters', 'months', 'over', 'period', 'quotaBytes', 'request', 'since', 'speed', 'until', 'why']);
});

test('forBuild: partial holds, only the profiles the users ride, their targets’ records, geo as the caller says — and the config blocks the held class', async () => {
  const { buildConfig } = require('../src/main/configBuilder');
  const h = bare({
    servers: [F.TROJAN_TCP_TLS, F.SS_TCP, F.VLESS_WS_TLS], routingProfiles: PROFILES,
    lanUsers: { config: { proxy: { enabled: true, port: 30820, httpPort: 30821 } }, users: [
      user('usr-a', 'ali', { target: 'sv-trojan', routing: 'profile:rp-lu', limits: [{ kind: 'vpn', period: 'day', gb: 1 }] }),
      user('usr-b', 'sara', { routing: 'bypass-ir', limits: [{ kind: 'total', period: 'day', gb: 1 }] }),
      user('usr-c', 'reza', { routing: 'profile:rp-gone' })
    ] }
  });
  h.reg.addBytes('usr-a', 2 * GIB);
  h.reg.addBytes('usr-b', 2 * GIB);
  const lu = await h.reg.forBuild({ modules: { lanUsers: true } }, { geo: false, routingProfiles: PROFILES });
  assert.deepEqual(lu.holds, { 'usr-a': 'vpn' }, 'partial holds only');
  assert.deepEqual(lu.over, ['usr-b'], 'sara is off entirely');
  assert.deepEqual(Object.keys(lu.profilesById), ['rp-lu'], 'only the profiles the users ride, never one that is gone');
  assert.equal(lu.geo, false);
  assert.ok(lu.serversById['sv-ss'], 'a profile’s target is looked up too');
  assert.equal('geo' in await h.reg.forBuild({ modules: { lanUsers: true } }), false, 'not said: the builder’s own geoAssets decides');
  const cfg = buildConfig({ mode: 'single', server: F.VLESS_WS_TLS }, F.settings({ modules: { lanUsers: true }, lanUsers: lu }));
  const ali = cfg.routing.rules.filter((r) => r.user && r.user[0] === 'ali');
  assert.deepEqual(ali.map((r) => [r.domain || r.ip || null, r.outboundTag]), [[['corp.example'], 'block'], [['203.0.113.9'], 'lu-d-usr-a'], [null, 'block']], 'the VPN held: only her direct route works');
  assert.deepEqual(cfg.inbounds.find((i) => i.tag === 'lu-socks').settings.accounts.map((a) => a.user), ['ali', 'reza']);
});

test('a partial hold that comes while connected is a change the core must take: the next edit (or tick) asks the reload', async () => {
  let reloads = 0;
  const h = bare({ lanUsers: { config: { proxy: { enabled: true, port: 30820, httpPort: 30821 } }, users: [user('usr-a', 'ali', { routing: 'bypass-ir', limits: [{ kind: 'vpn', period: 'day', gb: 1 }] })] } }, {
    extra: { running: () => true, canReload: () => true, queueReload: async () => { reloads++; return true; } }
  });
  await h.reg.forBuild({ modules: { lanUsers: true } });
  const name = (n) => h.reg.handlers['lanusers:user']({ op: 'update', user: { id: 'usr-a', name: n } });
  assert.deepEqual((await name('A')).pendingReconnect, [], 'a name is no reload');
  h.reg.addBytes('usr-a', 2 * GIB);
  assert.equal((await name('B')).pendingReconnect, true, 'her VPN held: the core is rebuilt');
  await new Promise((r) => setTimeout(r, 700));
  assert.equal(reloads, 1);
});

test('the limit notices: a VPN or direct one says which half still works, 80 % what is left, a slow one that it slowed — Persian and English', () => {
  const said = (lang, limit, bytes, over) => {
    const h = bare({ lanUsers: { users: [user('usr-a', 'ali', Object.assign({ routing: 'bypass-ir', limits: [limit] }, over))] } }, { lang });
    h.reg.addBytes('usr-a', bytes);
    return h.texts;
  };
  assert.deepEqual(said('en', { kind: 'vpn', period: 'day', gb: 1 }, 2 * GIB), ['“ali” reached their 1 GB daily VPN cap — the VPN is off until tomorrow; direct sites still work']);
  assert.deepEqual(said('fa', { kind: 'vpn', period: 'day', gb: 1 }, 2 * GIB), ['«ali» به سقف 1 گیگابایتِ روزانهٔ VPN رسید — VPN تا فردا قطع است؛ سایت‌های مستقیم کار می‌کنند']);
  assert.deepEqual(said('en', { kind: 'vpn', period: 'day', gb: 1 }, 2 * GIB, { routing: '' }), ['“ali” reached their 1 GB daily VPN cap — off until tomorrow'], 'nothing goes direct: off entirely');
  assert.deepEqual(said('en', { kind: 'direct', period: 'none', gb: 1 }, 2 * GIB, { target: 'direct' }), ['“ali” reached their 1 GB direct cap — off until it is raised']);
  assert.deepEqual(said('en', { kind: 'total', period: 'day', gb: 10 }, 8.5 * GIB), ['“ali” has used 80% of their 10 GB daily limit — 1.5 GB left']);
  assert.deepEqual(said('fa', { kind: 'total', period: 'day', gb: 10 }, 8.5 * GIB), ['«ali» 80٪ از سقف 10 گیگابایتِ روزانه را مصرف کرده — 1.5 گیگابایت مانده']);
  assert.deepEqual(said('en', { kind: 'total', period: 'day', gb: 2, action: 'slow', down: 1000, up: 500 }, 3 * GIB), ['“ali” used their 2 GB daily allowance — slowed to ↓1 Mbps ↑500 kbps until tomorrow']);
  assert.deepEqual(said('fa', { kind: 'total', period: 'day', gb: 2, action: 'slow', down: 1000 }, 3 * GIB), ['«ali» سهمیهٔ 2 گیگابایتِ روزانه را مصرف کرد — سرعتش تا فردا کم شد (↓1 Mbps)']);
});

test('router: forBuild’s routerTp — the router’s own inbounds count as routed (holds, profiles, the reload signature) but are not the build’s tp; a VPN limit with routing "" there stops the VPN only', async () => {
  let reloads = 0;
  const data = { routingProfiles: PROFILES, lanUsers: { config: { transparent: { enabled: true } }, users: [
    user('usr-a', 'ali', { target: 'sv-ss', limits: [{ kind: 'vpn', period: 'day', gb: 1 }] }),
    user('usr-b', 'bob', { target: 'sv-ss', routing: 'profile:rp-lu' })
  ] } };
  const h = bare(data, { extra: { platform: 'router', running: () => true, canReload: () => true, queueReload: async () => { reloads++; return true; } } });
  h.reg.addBytes('usr-a', 2 * GIB);
  const routerTp = [{ tag: 'lu-tp-1', port: 41001, userId: 'usr-a', target: 'sv-ss' }, { tag: 'lu-tp-2', port: 41002, userId: 'usr-b', target: 'sv-ss' }];
  const b = await h.reg.forBuild({ modules: { lanUsers: true } }, { routerTp, geo: true });
  assert.deepEqual(b.tp, [], 'the router writes its own inbounds (router/xrayTargets.js): the builder adds none');
  assert.deepEqual(b.holds, { 'usr-a': 'vpn' }, 'the router’s own routing sends something direct: the VPN alone is held');
  assert.deepEqual(b.over, []);
  assert.deepEqual(Object.keys(b.profilesById), ['rp-lu']);
  assert.equal(b.geo, true);
  routerTp[0].outboundTag = 'lu-tp-1-out';   // what the router marks on its entries after the build is no change of the users’
  const call = (arg) => h.reg.handlers['lanusers:user'](arg);
  const same = await call({ op: 'update', user: { id: 'usr-b', name: 'Bob B' } });
  assert.deepEqual(same.pendingReconnect, [], 'a rename: nothing for the core');
  const moved = await call({ op: 'update', user: { id: 'usr-b', target: 'sv-trojan' } });
  assert.equal(moved.pendingReconnect, true, 'a transparent user’s new config: the core reloads (their inbound is theirs)');
});
