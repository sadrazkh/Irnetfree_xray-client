'use strict';
/**
 * The sign-in page of the users module's transparent mode, as a device meets
 * it: a real HTTP server on 127.0.0.1 (a port the kernel picks), the whole
 * controller behind it over a fake LAN (`ip neigh` says 127.0.0.1 is the
 * device aa:bb:cc:dd:ee:01), a fake gateway that records every table load and
 * a file system in memory. Pinned: the page itself (Persian and English,
 * right to left, nothing external), the redirect of a captive check, a
 * sign-in that lets the device through for its hours and puts it on its
 * user's config, the refusals (wrong password, expired, over the cap, the
 * device limit, another page's form), the 5-tries limit, status and sign-out.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createLanRouter } = require('../src/modules/lanUsers/router');
const { checkPassword, postedFromElsewhere } = require('../src/modules/lanUsers/router/portal');
const { makeProxyServer } = require('../src/main/parser');
const { memFs, fakeLan, fakeGateway, fakeMeter } = require('./lanUsersRouterFakes');

const A = 'aa:bb:cc:dd:ee:01', B = 'aa:bb:cc:dd:ee:02';
const T0 = Date.UTC(2026, 9, 26, 12, 0, 0);
const SRV1 = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.10', port: 1080, name: 'home' }), { id: 'srv-1' });
const SRV2 = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.20', port: 1080, name: 'office' }), { id: 'srv-2' });
const USERS = [
  { id: 'usr-ali', username: 'ali', password: 'pass-ali', name: 'Ali', target: 'srv-2', quotaGb: 0, quotaPeriod: 'none', expiresAt: 0, maxDevices: 2, enabled: true },
  { id: 'usr-sara', username: 'sara', password: 'pass-sara', name: 'Sara', target: '', maxDevices: 1, enabled: true },
  { id: 'usr-old', username: 'old', password: 'pass-old', name: 'Old', target: '', expiresAt: T0 - 1000, enabled: true },
  { id: 'usr-cap', username: 'cap', password: 'pass-cap', name: 'Capped', target: '', enabled: true }
];

/** A controller with its page up, over the fakes. `over`: the meter's caps (bytes) — usr-cap is already over its own. */
async function setup({ neigh = `127.0.0.1 lladdr ${A} REACHABLE\n192.168.1.40 lladdr ${B} REACHABLE\n` } = {}) {
  let clock = T0;
  const lan = fakeLan({ neigh });
  const files = memFs();
  const meter = fakeMeter({ 'usr-cap': 10 });
  meter.feedDevices({ 'usr-cap': { up: 5, down: 5, bytes: 10 } });
  const logs = [];
  const store = { config: { transparent: { enabled: true, unassigned: 'login', sessionHours: 2, portalPort: 30822 } }, users: USERS, devices: [{ mac: B, userId: 'usr-sara' }] };
  const r = createLanRouter({
    openwrt: true, dataDir: '/etc/irnetfree', tmpDir: '/tmp', fs: files, run: lan.run, readFile: lan.readFile,
    getSettings: () => ({ modules: { lanUsers: true }, socksPort: 47808, httpPort: 47809, apiPort: 47885 }),
    getLanUsers: () => store, records: () => ({ servers: [SRV1, SRV2], groups: [], chains: [] }),
    getFreePorts: async (n) => Array.from({ length: n }, (_, i) => 41001 + i),
    log: (line, level) => logs.push([level, line]), now: () => clock, meter,
    portalListen: { host: '127.0.0.1', port: 0 }, tickMs: 3600000
  });
  const tp = await r.prepare();
  const config = { inbounds: [{ tag: 'socks-in', port: 47808, sniffing: { enabled: true } }], outbounds: [{ tag: 'proxy', protocol: 'socks' }, { tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }], routing: { rules: [{ type: 'field', port: '0-65535', outboundTag: 'proxy' }] } };
  r.applyXray(config, { serverId: 'srv-1', plan: { mode: 'single', server: SRV1 }, settings: { lanUsersTp: tp, directInterface: 'eth0' } });
  const opts = await r.gatewayOptions(tp);
  const gw = fakeGateway();
  await r.gatewayUp(gw);
  const port = r.portal.port;
  const req = (method, path, { body = '', headers = {} } = {}) => new Promise((resolve, reject) => {
    const q = http.request({ host: '127.0.0.1', port, method, path, headers: Object.assign({ Host: `127.0.0.1:${port}`, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }, headers) }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { text += d; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
    });
    q.on('error', reject);
    q.end(body);
  });
  const signIn = (username, password, headers) => req('POST', '/login', { body: new URLSearchParams({ username, password }).toString(), headers });
  return { r, lan, files, meter, logs, gw, opts, port, req, signIn, tick: (ms) => { clock += ms; } };
}

test('the page: Persian and English, right to left, no script and nothing from outside — the device has no internet yet', async () => {
  const s = await setup();
  try {
    const res = await s.req('GET', '/');
    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /text\/html; charset=utf-8/);
    assert.equal(res.headers.connection, 'close', 'a kept-alive socket would stay redirected here after the sign-in');
    assert.match(res.text, /<html lang="fa" dir="rtl">/);
    for (const s2 of ['ورود به اینترنت', 'Sign in to use the internet', 'نام کاربری', 'Username', 'رمز عبور', 'Password', 'action="/login"']) assert.ok(res.text.includes(s2), s2);
    assert.doesNotMatch(res.text, /<script|src=|href=|https?:\/\/(?!www\.w3)/i);
    assert.match(res.headers['content-security-policy'], /default-src 'none'/);
    assert.equal(res.headers['referrer-policy'], 'same-origin', 'no-referrer made Chrome post the page\'s own form with Origin "null"');
  } finally { await s.r.stop(); }
});

test('the form as browsers post it: Origin "null" from the page itself signs in (v1.38.0 refused every one); another site\'s form does not', async () => {
  const s = await setup();
  try {
    // Chrome under v1.38.0's Referrer-Policy: no-referrer — the shape the owner's router got
    const chrome = await s.signIn('ali', 'pass-ali', { Origin: 'null', 'Sec-Fetch-Site': 'same-origin' });
    assert.equal(chrome.status, 200, chrome.text);
    assert.match(chrome.text, /You are connected/);
    await s.req('POST', '/logout', { headers: { Origin: `http://127.0.0.1:${s.port}`, 'Sec-Fetch-Site': 'same-origin' } });
    assert.deepEqual(s.r.sessions, {});
    for (const [site, origin] of [['cross-site', 'http://evil.example'], ['same-site', `http://127.0.0.1:${s.port + 1}`], ['cross-site', 'null']]) {
      const r = await s.signIn('ali', 'pass-ali', { Origin: origin, 'Sec-Fetch-Site': site });
      assert.equal(r.status, 403, `${site} ${origin}`);
      assert.deepEqual(s.r.sessions, {});
    }
    assert.ok(s.logs.some(([, l]) => /refused a form posted from another page \(Sec-Fetch-Site cross-site, Origin http:\/\/evil\.example\)/.test(l)), JSON.stringify(s.logs));
    // a browser without fetch metadata: its Origin decides, and "null" says nothing either way
    assert.equal((await s.signIn('ali', 'pass-ali', { Origin: 'null' })).status, 200);
  } finally { await s.r.stop(); }
});

test('postedFromElsewhere: fetch metadata first, then the Origin', () => {
  const own = 'http://192.168.2.1:30822';
  const f = (h) => postedFromElsewhere(h, own);
  assert.equal(f({}), false, 'no word from the client (curl, an old browser)');
  assert.equal(f({ 'sec-fetch-site': 'same-origin', origin: 'null' }), false);
  assert.equal(f({ 'sec-fetch-site': 'none' }), false);
  assert.equal(f({ 'sec-fetch-site': 'same-site', origin: 'http://192.168.2.1' }), true, 'the router\'s admin page is not this page');
  assert.equal(f({ 'sec-fetch-site': 'cross-site', origin: 'null' }), true);
  assert.equal(f({ origin: 'HTTP://192.168.2.1:30822' }), false);
  assert.equal(f({ origin: 'http://evil.example' }), true);
  assert.equal(f({ origin: 'null' }), false);
});

test('a captive check for any other host (DNAT\'d here) is sent to the page\'s own address', async () => {
  const s = await setup();
  try {
    const res = await s.req('GET', '/hotspot-detect.html', { headers: { Host: 'captive.apple.com' } });
    assert.equal(res.status, 302);
    assert.equal(res.headers.location, `http://127.0.0.1:${s.port}/`);
  } finally { await s.r.stop(); }
});

test('sign-in: a wrong password is refused; the right one lets the device through for its hours, on its user\'s config, and is kept across a restart', async () => {
  const s = await setup();
  try {
    const before = s.gw.loads.length;
    const bad = await s.signIn('ali', 'nope');
    assert.equal(bad.status, 401);
    assert.match(bad.text, /Wrong username or password/);
    assert.equal(s.gw.loads.length, before, 'nothing changed in the table');
    const noUser = await s.signIn('nobody', 'pass-ali');
    assert.equal(noUser.status, 401, 'no such user: the same answer');
    const ok = await s.signIn('ali', 'pass-ali');
    assert.equal(ok.status, 200);
    assert.match(ok.text, /You are connected/);
    assert.match(ok.text, /Ali \(ali\)/);
    const load = s.gw.loads[s.gw.loads.length - 1];
    assert.deepEqual(load.authorized, [{ mac: A, timeoutS: 7200 }], 'the session\'s two hours, in the kernel\'s own timeout');
    assert.deepEqual(load.allowed, [B], 'the admin\'s device stays let through');
    // the rule-set of ali's config (srv-2 → lu-tp-1) now carries the device's address, written before the table let it through
    assert.equal(s.opts.singbox.targets[0].path, '/tmp/irnetfree-lu/lu-tp-1.json');
    assert.deepEqual(JSON.parse(s.files.get('/tmp/irnetfree-lu/lu-tp-1.json')), { version: 1, rules: [{ source_ip_cidr: ['127.0.0.1/32'] }] });
    const saved = JSON.parse(s.files.get('/etc/irnetfree/lan-sessions.json'));
    assert.deepEqual(saved[A], { userId: 'usr-ali', until: T0 + 7200000, at: T0 });
    assert.ok(!JSON.stringify(s.logs).includes('pass-ali'), 'a password is never logged');
    // status, then sign-out
    const st = await s.req('GET', '/status');
    assert.match(st.text, /Ali \(ali\)/);
    assert.match(st.text, /action="\/logout"/);
    assert.match(st.text, /2 h more/);
    const out = await s.req('POST', '/logout');
    assert.equal(out.status, 303);
    assert.deepEqual(s.gw.loads[s.gw.loads.length - 1].authorized, []);
    assert.deepEqual(JSON.parse(s.files.get('/tmp/irnetfree-lu/lu-tp-1.json')).rules, []);
    assert.deepEqual(s.r.sessions, {});
    assert.match((await s.req('GET', '/')).text, /action="\/login"/);
  } finally { await s.r.stop(); }
});

test('refusals: expired, over its cap this period, the device limit, another page\'s form', async () => {
  const s = await setup();
  try {
    const exp = await s.signIn('old', 'pass-old');
    assert.equal(exp.status, 403);
    assert.match(exp.text, /This account has expired/);
    const cap = await s.signIn('cap', 'pass-cap');
    assert.match(cap.text, /used up its data for this period/);
    const max = await s.signIn('sara', 'pass-sara');
    assert.equal(max.status, 403);
    assert.match(max.text, /maximum number of devices \(1\)/, 'sara\'s one device is the admin\'s laptop');
    const cross = await s.signIn('ali', 'pass-ali', { Origin: 'http://evil.example' });
    assert.equal(cross.status, 403);
    assert.deepEqual(s.r.sessions, {});
  } finally { await s.r.stop(); }
});

test('at most 5 failed tries in 5 minutes per device — the 6th is refused even with the right password; the window passes', async () => {
  const s = await setup();
  try {
    for (let i = 0; i < 5; i++) assert.equal((await s.signIn('ali', 'wrong' + i)).status, 401);
    const sixth = await s.signIn('ali', 'pass-ali');
    assert.equal(sixth.status, 429);
    assert.match(sixth.text, /Too many tries/);
    assert.equal(sixth.headers['retry-after'], '300');
    assert.deepEqual(s.r.sessions, {});
    s.tick(5 * 60 * 1000 + 1);
    assert.equal((await s.signIn('ali', 'pass-ali')).status, 200);
  } finally { await s.r.stop(); }
});

test('a device the router cannot name by its address is told so — no sign-in for nobody', async () => {
  const s = await setup({ neigh: `192.168.1.40 lladdr ${B} REACHABLE\n` });
  try {
    assert.match((await s.req('GET', '/')).text, /could not be identified/);
    const res = await s.signIn('ali', 'pass-ali');
    assert.equal(res.status, 403);
    assert.deepEqual(s.r.sessions, {});
  } finally { await s.r.stop(); }
});

test('checkPassword: equal or not, whatever the lengths', () => {
  assert.equal(checkPassword('pass-ali', 'pass-ali'), true);
  assert.equal(checkPassword('pass-ali', 'pass-alI'), false);
  assert.equal(checkPassword('', 'x'.repeat(500)), false);
  assert.equal(checkPassword('', ''), true);
});

test('a phone\'s typing: a capital first letter is the same username; the router\'s log says which of the two was wrong, never the password', async () => {
  const s = await setup();
  try {
    assert.equal((await s.signIn('nobody', 'pass-ali')).status, 401);
    assert.equal((await s.signIn('ali', 'pass-alI')).status, 401);
    const said = s.logs.map((l) => l[1]).filter((l) => /was refused/.test(l));
    assert.match(said[0], /no user "nobody" on this router — users are made on the router's own Users page; the desktop app's are not here/);
    assert.match(said[1], /the password does not match "ali"'s/);
    assert.ok(!JSON.stringify(s.logs).includes('pass-al'), 'a password is never logged');
    const ok = await s.signIn('Ali', 'pass-ali');
    assert.equal(ok.status, 200, 'the keyboard\'s capital A is still ali');
    assert.match(ok.text, /Ali \(ali\)/);
    // the page asks the keyboard not to change what is typed, in both boxes
    await s.req('POST', '/logout');
    const page = (await s.req('GET', '/')).text;
    assert.match(page, /<input id="u" name="username" dir="ltr" autocomplete="username" autocapitalize="none" autocorrect="off" spellcheck="false"/);
    assert.match(page, /<input id="p" name="password" type="password" dir="ltr" autocomplete="current-password" autocapitalize="none" autocorrect="off" spellcheck="false"/);
  } finally { await s.r.stop(); }
});

test('judgeSignIn: Persian or Arabic-Indic digits, a zero-width mark, a fullwidth letter are what the admin meant — a password\'s own case still counts', () => {
  const { judgeSignIn } = require('../src/modules/lanUsers/router/plan');
  const lu = { users: [{ id: 'u-s', username: 'sadra', password: 'Kx7m29pL', enabled: true }, { id: 'u-f', username: 'farsi', password: 'رمز۱۲۳', enabled: true }] };
  const at = (username, password) => judgeSignIn({ lu, mac: 'aa:bb:cc:dd:ee:09', username, password, checkPassword });
  assert.equal(at('sadra', 'Kx7m29pL').ok, true);
  assert.equal(at('SADRA ', 'Kx7m۲۹pL').ok, true, 'Persian digits from a Persian keyboard\'s number row');
  assert.equal(at('sadra', 'Kx7m٢٩pL').ok, true, 'Arabic-Indic digits');
  assert.equal(at('sa\u200cdra', 'Kx7m\u200c29pL').ok, true, 'a zero-width non-joiner the keyboard slipped in');
  assert.equal(at('ｓａｄｒａ', 'Kx7m29pL').ok, true, 'fullwidth letters (NFKC)');
  assert.equal(at('farsi', 'رمز123').ok, true, 'a stored password in Persian digits takes Latin ones too');
  assert.deepEqual(at('sadra', 'kx7m29pl'), { ok: false, code: 'bad', why: 'password' }, 'a password\'s case is still its own');
  assert.deepEqual(at('sara', 'Kx7m29pL'), { ok: false, code: 'bad', why: 'user' });
  assert.deepEqual(at('', ''), { ok: false, code: 'bad', why: 'user' });
});
