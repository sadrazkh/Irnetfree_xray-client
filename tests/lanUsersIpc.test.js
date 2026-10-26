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
  assert.deepEqual(Object.keys(res).sort(), ['config', 'deviceUsage', 'devices', 'lanAddresses', 'live', 'ok', 'online', 'platform', 'usage', 'users']);
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
  assert.deepEqual(r.devices, [{ mac: 'aa:bb:cc:dd:ee:01', name: 'Phone', userId: 'usr-a', blocked: false }]);
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
      const i = body.indexOf('lanUsers.forBuild(settings)');
      assert.ok(i > body.indexOf('multiWanSkip: mwSkip') && i < body.indexOf('buildActive(serverId, settings)'), `${f} ${fn}`);
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
