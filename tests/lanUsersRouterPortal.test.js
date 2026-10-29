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
 * v1.40 (the page alone, over a fake controller in the contract's shapes — the
 * controller's half is router/index.js): the two ways as CSS-only tabs, ?u= and
 * ?code= filled in and escaped, a card's code and its refusals, "request a
 * top-up", and the fuller status page.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createLanRouter } = require('../src/modules/lanUsers/router');
const { checkPassword, postedFromElsewhere } = require('../src/modules/lanUsers/router/portal');
const { makeProxyServer } = require('../src/main/parser');
const { memFs, fakeLan, fakeGateway, fakeMeter } = require('./lanUsersRouterFakes');

/** The English line under a Persian one, as the page writes it. */
const EN = (s) => `<span class="en" lang="en" dir="ltr">${s}</span>`;
/** The left-to-right mark the page puts before an amount in a Persian line ("‎2.00 GB"). */
const LRM = '‎';

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
async function setup({ neigh = `127.0.0.1 lladdr ${A} REACHABLE\n192.168.1.40 lladdr ${B} REACHABLE\n`, meter: given = null } = {}) {
  let clock = T0;
  const lan = fakeLan({ neigh });
  const files = memFs();
  const meter = given || fakeMeter({ 'usr-cap': 10 });
  if (!given) meter.feedDevices({ 'usr-cap': { up: 5, down: 5, bytes: 10 } });
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
    for (const s2 of ['ورود به اینترنت', 'Sign in to use the internet', 'نام کاربری', 'Username', 'رمز عبور', 'Password', 'کد کارت', 'Card code', 'action="/login"']) assert.ok(res.text.includes(s2), s2);
    assert.doesNotMatch(res.text, /src=|href=|https?:\/\/|@import|url\(/i, 'nothing fetched: no font, no image, no stylesheet');
    // one inline script (the show-password eye), allowed by its hash — nothing else may run
    const scripts = [...res.text.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
    assert.equal(scripts.length, 1);
    assert.equal(scripts[0][1], '', 'no src, no attribute');
    const hash = 'sha256-' + require('node:crypto').createHash('sha256').update(scripts[0][2], 'utf8').digest('base64');
    assert.ok(res.headers['content-security-policy'].includes(`script-src '${hash}'`), res.headers['content-security-policy']);
    assert.match(res.headers['content-security-policy'], /default-src 'none'/);
    assert.match(res.headers['content-security-policy'], /form-action 'self'/);
    assert.equal(res.headers['x-frame-options'], 'DENY');
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

test('the page\'s short name: login.lan on the router\'s DNS while it is up (dnsmasq told to read it), sent to the address, said after a sign-in, gone with the page', async () => {
  const s = await setup();
  try {
    const hosts = '/tmp/hosts/irnetfree-portal';
    assert.equal(s.files.get(hosts), '127.0.0.1 login.lan\n', 'a line in dnsmasq\'s hosts directory');
    assert.ok(s.lan.calls.includes('killall -HUP dnsmasq'), JSON.stringify(s.lan.calls));
    assert.deepEqual(s.r.portalInfo(), { url: `http://127.0.0.1:${s.port}/`, name: 'login.lan', nameUrl: `http://login.lan:${s.port}/` });
    // the name lands on the page by its address: one origin for the form
    const byName = await s.req('GET', '/', { headers: { Host: `login.lan:${s.port}` } });
    assert.equal(byName.status, 302);
    assert.equal(byName.headers.location, `http://127.0.0.1:${s.port}/`);
    // a signed-in device is no longer sent here: the status says where to come back to
    const ok = await s.signIn('ali', 'pass-ali');
    assert.match(ok.text, /To come back to this page \(to sign out or see your usage\), bookmark:/);
    assert.ok(ok.text.includes(`<span class="addr">http://login.lan:${s.port}/</span><span class="addr">http://127.0.0.1:${s.port}/</span>`), ok.text);
    const huped = s.lan.calls.filter((c) => c === 'killall -HUP dnsmasq').length;
    await s.r.stop();
    assert.equal(s.files.get(hosts), undefined, 'the name goes with the page');
    assert.equal(s.lan.calls.filter((c) => c === 'killall -HUP dnsmasq').length, huped + 1);
    assert.equal(s.r.portalInfo(), null);
  } finally { await s.r.stop(); }
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
    assert.ok(ok.text.includes(`<h1>سلام، Ali${EN('Hello, Ali')}</h1>`), ok.text);
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
    assert.match(st.text, /Hello, Ali/);
    assert.match(st.text, /<meta http-equiv="refresh" content="60;url=\/">/, 'it refreshes itself — to "/", never a reload of a POST');
    assert.doesNotMatch(st.text, /<script/i, 'the status page runs nothing');
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
    assert.match(ok.text, /Hello, Ali/);
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

/* ------------------------------ v1.39: the limits, the holds, the speed ------------------------------ */

test('whenText: within a day the time, within the week a weekday and the time, further a date in the user\'s calendar (the router\'s local time)', () => {
  const { whenText } = require('../src/modules/lanUsers/router/portal');
  const now = new Date(2026, 9, 29, 10, 0).getTime();
  assert.deepEqual(whenText(new Date(2026, 9, 29, 12, 0).getTime(), now, ''), ['12:00', '12:00']);
  assert.deepEqual(whenText(new Date(2026, 9, 31, 8, 0).getTime(), now, ''), ['شنبه 08:00', 'Saturday 08:00']);
  assert.deepEqual(whenText(new Date(2026, 10, 22, 0, 0).getTime(), now, 'jalali'), ['1 آذر', '22 November (1 Azar)'], 'a limit renews at midnight: the date alone');
});

test('the status page: each limit as a bar ("kind · period", used / cap, left), the one closest to its end as the ring, the speed and why, a hold of one class and until when; no limit — today and this month', () => {
  const { statusPage } = require('../src/modules/lanUsers/router/portal');
  const GiB = 1024 ** 3;
  const now = new Date(2026, 9, 29, 10, 0).getTime();
  const html = statusPage({
    name: 'Ali', username: 'ali', via: 'admin', held: null, part: 'vpn', holdUntil: new Date(2026, 9, 30, 0, 0).getTime(), calendar: '',
    meters: [{ kind: 'vpn', period: 'day', bytes: 1.5 * GiB, capBytes: GiB, extraBytes: 0.5 * GiB, until: 0, over: true }, { kind: 'total', period: 'month', bytes: 0.4 * GiB, capBytes: 10 * GiB, extraBytes: 0, until: 0, over: false }],
    speed: { down: 2000, up: 512, why: ['hours', { after: 2, period: 'day' }] }
  }, now, []);
  // every limit as a bar: its name, used / whole (the top-up in it), the bar, what is left
  assert.ok(html.includes(`<span>VPN · امروز${EN('VPN · today')}</span><span class="num">1.50 / 1.50 GB</span>`), html);
  assert.ok(html.includes(`<div class="bar bad" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="100" aria-label="VPN · امروز · VPN · today"><i style="width:100%"></i></div><p class="lim-f">تمام شده${EN('used up')}</p>`), html);
  assert.ok(html.includes(`<span>کل · این ماه${EN('Total · this month')}</span><span class="num">0.40 / 10.00 GB</span>`), html);
  assert.ok(html.includes(`aria-valuenow="4" aria-label="کل · این ماه · Total · this month"><i style="width:4%"></i></div><p class="lim-f">${LRM}9.60 GB مانده${EN('9.60 GB left')}</p>`), html);
  // the ring: the one that stops the device first
  assert.match(html, /<div class="ring bad" style="--p:100" role="progressbar"[^>]*aria-label="VPN · امروز · VPN · today"><div class="ring-in"><b>تمام شده<\/b>/);
  assert.ok(html.includes(`<span class="rate">↓ 2 Mbps ↑ 512 kbps</span><span class="why">ساعت‌های اوج، بعد از ${LRM}2 GB امروز${EN('peak hours, after 2 GB today')}</span>`), html);
  assert.ok(html.includes(`VPN تا 00:00 قطع است — سایت‌های مستقیم کار می‌کنند.${EN('The VPN is off until 00:00 — direct sites still work.')}`), html);
  assert.ok(html.includes('<p class="msg warn" role="alert">'), 'one class off: a warning, not a refusal');
  assert.ok(html.includes(`<p class="state warn" role="status"><span class="dot"></span><span>بخشی از اینترنت شما قطع است${EN('Part of your internet is paused')}</span></p>`), html);
  assert.ok(!html.includes('Used this period'), 'the limits stand in for the one cap\'s row');
  assert.ok(html.includes(`<p class="muted">${'این دستگاه را مدیر شبکه به این حساب داده است.'}`) && !html.includes('action="/logout"'), 'the admin\'s device: no sign-out');
  const none = statusPage({ name: 'Sara', username: 'sara', via: 'admin', totals: { day: 0.25 * GiB, month: 3 * GiB } }, now, []);
  assert.ok(none.includes(`<div class="stat"><div class="k">مصرف امروز${EN('Used today')}</div><b>0.25 GB</b></div>`) && none.includes(`<div class="stat"><div class="k">مصرف این ماه${EN('Used this month')}</div><b>3.00 GB</b></div>`), none);
  assert.ok(none.includes(`<p class="state" role="status"><span class="dot"></span><span>به اینترنت وصل هستید${EN('You are connected')}</span></p>`), none);
  const late = statusPage({ name: 'Sara', username: 'sara', via: 'admin', held: 'schedule', holdUntil: new Date(2026, 9, 29, 12, 0).getTime() }, now, []);
  assert.ok(late.includes(`خارج از ساعت‌های مجاز — از 12:00 دوباره${EN('Outside your allowed hours — back at 12:00')}`), late);
  assert.ok(late.includes('<p class="state bad" role="status">') && late.includes('This device’s internet is paused'), late);
  const off = statusPage({ name: 'Sara', username: 'sara', via: 'admin', held: 'total', holdUntil: 0 }, now, []);
  assert.ok(off.includes(`حجم این حساب تمام شده است.${EN('This account’s data is used up.')}`), 'a limit that never renews: no "again from"');
});

test('a sign-in outside the allowed hours: refused with when they begin again', async () => {
  const { createPortal } = require('../src/modules/lanUsers/router/portal');
  const now = new Date(2026, 9, 29, 10, 0).getTime();
  const p = createPortal({ host: '127.0.0.1', port: 0, now: () => now, api: {
    macOf: async () => A, statusOf: async () => null, signOut: async () => false,
    signIn: async () => ({ ok: false, code: 'schedule', until: new Date(2026, 9, 29, 16, 30).getTime() })
  } });
  const { port } = await p.start();
  try {
    const body = 'username=ali&password=pw12';
    const res = await new Promise((resolve, reject) => {
      const q = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/login', headers: { Host: `127.0.0.1:${port}`, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body), 'Sec-Fetch-Site': 'same-origin' } }, (r) => {
        let text = ''; r.setEncoding('utf8'); r.on('data', (d) => { text += d; }); r.on('end', () => resolve({ status: r.statusCode, text }));
      });
      q.on('error', reject);
      q.end(body);
    });
    assert.equal(res.status, 403);
    assert.ok(res.text.includes(`خارج از ساعت‌های مجاز — از 16:30 دوباره${EN('Outside your allowed hours — back at 16:30')}`), res.text);
  } finally { await p.stop(); }
});

test('the controller hands the page the meter\'s limits, the hold of one class and the speed (statusOf)', async () => {
  const GiB = 1024 ** 3;
  const meters = [
    { kind: 'total', period: 'day', bytes: 1, capBytes: 0, extraBytes: 0, over: false },
    { kind: 'direct', period: 'month', bytes: 0.5 * GiB, capBytes: GiB, extraBytes: 0, until: 0, over: false },
    { kind: 'vpn', period: 'day', bytes: 3 * GiB, capBytes: 2 * GiB, extraBytes: 0, until: 0, over: true }
  ];
  const meter = {
    feedDevices() {},
    usage: () => ({ 'usr-sara': { bytes: 0, quotaBytes: 0, over: false, hold: 'direct', why: 'direct', holdUntil: T0 + 3600000, meters, speed: null } }),
    speeds: () => ({ 'usr-sara': { down: 1000, up: 0, why: ['after:vpn:day'] } })
  };
  // the request comes from 127.0.0.1: make it Sara's (the admin's) laptop
  const s = await setup({ neigh: `127.0.0.1 lladdr ${B} REACHABLE\n`, meter });
  try {
    const page = await s.req('GET', '/');
    assert.equal(page.status, 200);
    assert.ok(page.text.includes(`<span>مستقیم · این ماه${EN('Direct · this month')}</span><span class="num">0.50 / 1.00 GB</span>`), page.text);
    assert.ok(page.text.includes(`<p class="lim-f">${LRM}0.50 GB مانده${EN('0.50 GB left')}</p>`), page.text);
    assert.ok(page.text.includes(`<span>VPN · امروز${EN('VPN · today')}</span>`) && !page.text.includes('کل · امروز'), 'only the limits that are set');
    assert.ok(page.text.includes(`<span class="rate">↓ 1 Mbps</span><span class="why">بعد از ${LRM}2 GB امروز${EN('after 2 GB today')}</span>`), page.text);
    assert.ok(page.text.includes('Direct traffic is off until ') && page.text.includes('ترافیک مستقیم تا '), 'until when, in the router’s own time');
  } finally { await s.r.stop(); }
});

/* ------------------------------ v1.40: a card's code, the top-up request, the fuller status page ------------------------------ */

const GiB = 1024 ** 3;
const NOW = new Date(2026, 9, 29, 10, 0).getTime();

/**
 * The page alone over a fake controller in the contract's shapes (router/index.js's portalApi is
 * ROUTER's): `api` overrides any of macOf / statusOf / signIn / signOut / requestTopUp. `calls`:
 * what the page asked of it.
 */
async function page40(api = {}) {
  const { createPortal } = require('../src/modules/lanUsers/router/portal');
  let clock = NOW;
  const calls = { signIn: [], request: [], signOut: [] };
  const logs = [];
  const p = createPortal({
    host: '127.0.0.1', port: 0, now: () => clock, log: (line, level) => logs.push([level, line]),
    api: Object.assign({
      macOf: async () => A,
      statusOf: async () => null,
      signIn: async (x) => { calls.signIn.push(x); return { ok: false, code: 'bad' }; },
      signOut: async (mac) => { calls.signOut.push(mac); return true; },
      requestTopUp: async (mac) => { calls.request.push(mac); return { ok: true, code: 'sent' }; }
    }, typeof api === 'function' ? api(calls) : api)
  });
  const { port } = await p.start();
  const req = (method, path, { body = '', headers = {} } = {}) => new Promise((resolve) => {
    const q = http.request({ host: '127.0.0.1', port, method, path, headers: Object.assign({ Host: `127.0.0.1:${port}`, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }, headers) }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { text += d; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
    });
    q.on('error', (e) => resolve({ status: 0, error: e.code || e.message, text: '' }));
    q.end(body);
  });
  const post = (path, fields, headers = { 'Sec-Fetch-Site': 'same-origin', Origin: `http://127.0.0.1:${port}` }) => req('POST', path, { body: new URLSearchParams(fields).toString(), headers });
  return { p, port, calls, logs, req, post, tick: (ms) => { clock += ms; }, stop: () => p.stop() };
}

/** The value of an input, as the page writes it (null when it has none). */
const valueOf = (html, id) => { const m = new RegExp(`<input id="${id}"[^>]*>`).exec(html); const v = m && / value="([^"]*)"/.exec(m[0]); return v ? v[1] : null; };
const checked = (html, id) => new RegExp(`<input type="radio" name="way" id="${id}"[^>]* checked>`).test(html);

test('the sign-in page: two ways as tabs that need no script — the username\'s form first (the one the probe posts to), the code\'s second, each posting only its own fields', async () => {
  const s = await page40();
  try {
    const html = (await s.req('GET', '/')).text;
    const at = (x) => html.indexOf(x);
    assert.ok(at('id="w-user"') < at('id="w-code"') && at('id="w-code"') < at('class="seg"') && at('class="seg"') < at('<form id="f-user"') && at('<form id="f-user"') < at('<form id="f-code"'), 'the radios, then the tabs, then the forms: siblings for :checked ~');
    assert.ok(checked(html, 'w-user') && !checked(html, 'w-code'), 'the username\'s tab by default');
    assert.ok(html.includes('#w-user:checked~#f-code,#w-code:checked~#f-user{display:none}'), 'CSS alone switches the tab');
    assert.ok(html.includes(`<label for="w-user">نام کاربری و رمز${EN('Username &amp; password')}</label><label for="w-code">کد کارت${EN('Card code')}</label>`), html);
    assert.match(html, /<form id="f-code" method="post" action="\/login" class="code">\n<div class="field"><label for="c">کد کارت<span class="en-i" lang="en" dir="ltr">Card code<\/span><\/label>\n<input id="c" name="code" type="text" dir="ltr" autocomplete="off" autocapitalize="characters"/);
    assert.ok(!/<input[^>]*type="hidden"/.test(html), 'no hidden field: the probe would post it along');
    // the show-password eye: in the page but hidden — only the script shows it, so no script, no dead button
    assert.match(html, /<button type="button" id="eye" class="eye" aria-controls="p" aria-pressed="false" aria-label="نمایش رمز · Show password"[^>]* hidden>/);
    // scripts/probe-lan-portal.js reads the page as the gateway probe does: the first form, its text and password fields
    const { loginForm } = require('../scripts/probe-lan-portal');
    const f = loginForm({ ok: true, status: 200, via: `http://127.0.0.1:${s.port}/`, body: html });
    assert.deepEqual([f.path, f.method, f.user, f.pass, f.hidden], ['/login', 'POST', 'username', 'password', []]);
  } finally { await s.stop(); }
});

test('?u= and ?code= fill the page in — a sign-in card\'s QR, a voucher card\'s QR — escaped, cut, and ?code= opens the code\'s tab', async () => {
  const s = await page40();
  try {
    const u = (await s.req('GET', '/?u=sara')).text;
    assert.equal(valueOf(u, 'u'), 'sara');
    assert.ok(checked(u, 'w-user'));
    assert.match(u, /<input id="p" name="password"[^>]* autofocus>/, 'the username given: straight to the password');
    const c = (await s.req('GET', '/?code=k7mp-29qx')).text;
    assert.equal(valueOf(c, 'c'), 'k7mp-29qx', 'as typed: the controller normalises it (model.normalizeCode)');
    assert.ok(checked(c, 'w-code') && !checked(c, 'w-user'), 'the code\'s tab open');
    const both2 = (await s.req('GET', `/?u=${encodeURIComponent('ali')}&code=${encodeURIComponent('ABCD-2345')}`)).text;
    assert.ok(valueOf(both2, 'u') === 'ali' && valueOf(both2, 'c') === 'ABCD-2345' && checked(both2, 'w-code'));
    // markup in either is text
    const evil = (await s.req('GET', `/?u=${encodeURIComponent('"><script>alert(1)</script>')}&code=${encodeURIComponent('<img src=x onerror=alert(1)>')}`)).text;
    assert.equal(valueOf(evil, 'u'), '&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;');
    assert.equal(valueOf(evil, 'c'), '&lt;img src=x onerror=alert(1)&gt;');
    assert.equal((evil.match(/<script/g) || []).length, 1, 'only the page\'s own script');
    assert.ok(!evil.includes('<img'));
    const long = (await s.req('GET', `/?u=${'x'.repeat(500)}`)).text;
    assert.equal(valueOf(long, 'u'), 'x'.repeat(64), 'never more than a username can be');
    const ctrl = (await s.req('GET', '/?u=a%0d%0aSet-Cookie:x')).text;
    assert.equal(valueOf(ctrl, 'u'), 'aSet-Cookie:x', 'no control characters');
    // a device with a user sees its status, whatever the query says
    const signed = await page40({ statusOf: async () => ({ name: 'Ali', username: 'ali', via: 'admin' }) });
    try { assert.match((await signed.req('GET', '/?code=ABCD-2345')).text, /You are connected/); } finally { await signed.stop(); }
  } finally { await s.stop(); }
});

test('a card\'s code signs in: the controller gets the code alone; its refusals in a card\'s words; codes count in the 5 tries; an empty code is no try', async () => {
  let signed = null;
  const s = await page40((calls) => ({
    statusOf: async () => signed,
    signIn: async (x) => {
      calls.signIn.push(x);
      if (x.code === 'K7MP-29QX') { signed = { name: 'Cafe #4', username: 'K7MP-29QX', via: 'login', until: NOW + 3 * 3600e3, voucher: { hours: 3, activatedAt: NOW, expiresAt: NOW + 3 * 3600e3 }, meters: [] }; return { ok: true, status: signed }; }
      if (x.code === 'OLD1-CODE') return { ok: false, code: 'expired' };
      if (x.code === 'USED-CODE') return { ok: false, code: 'over' };
      if (x.code === 'BUSY-CODE') return { ok: false, code: 'maxDevices', max: 1 };
      return { ok: false, code: 'bad' };
    }
  }));
  try {
    const old = await s.post('/login', { code: 'OLD1-CODE' });
    assert.equal(old.status, 403);
    assert.ok(old.text.includes(`زمان این کارت تمام شده است.${EN('This card’s time is up.')}`), old.text);
    assert.ok(checked(old.text, 'w-code') && valueOf(old.text, 'c') === 'OLD1-CODE', 'back on the code\'s tab, the code as typed');
    assert.match((await s.post('/login', { code: 'USED-CODE' })).text, /This card’s data is used up\./);
    assert.match((await s.post('/login', { code: 'BUSY-CODE' })).text, /This card is already in use on another device\./);
    const bad = await s.post('/login', { code: 'NOPE-NOPE' });
    assert.equal(bad.status, 401);
    assert.match(bad.text, /This code is not valid\./);
    assert.doesNotMatch(bad.text, /Wrong username or password/);
    assert.deepEqual(s.calls.signIn, ['OLD1-CODE', 'USED-CODE', 'BUSY-CODE', 'NOPE-NOPE'].map((code) => ({ mac: A, username: '', password: '', code })), 'the code alone — no username, no password');
    assert.equal(s.p.triesLeft(A), 1, 'four tries spent');
    // an empty code: said so, not asked, not counted
    const empty = await s.post('/login', { code: '   ' });
    assert.equal(empty.status, 400);
    assert.equal(s.calls.signIn.length, 4);
    assert.equal(s.p.triesLeft(A), 1);
    // the fifth wrong one closes the window — for codes and passwords alike
    assert.equal((await s.post('/login', { username: 'ali', password: 'nope' })).status, 401);
    const shut = await s.post('/login', { code: 'K7MP-29QX' });
    assert.equal(shut.status, 429);
    assert.match(shut.text, /Too many tries/);
    assert.equal((await s.post('/login', { username: 'ali', password: 'pw' })).status, 429);
    assert.equal(s.calls.signIn.length, 5, 'nothing asked while the window is shut');
    s.tick(5 * 60 * 1000 + 1);
    const ok = await s.post('/login', { code: 'K7MP-29QX' });
    assert.equal(ok.status, 200);
    assert.ok(ok.text.includes(`<h1>کارت اینترنت${EN('Internet card')}</h1><span class="chip">K7MP-29QX</span>`), ok.text);
    assert.equal(s.p.triesLeft(A), 5, 'a sign-in clears the tries');
    // the username form still sends what it always has: no code key at all
    assert.deepEqual(s.calls.signIn[4], { mac: A, username: 'ali', password: 'nope' });
  } finally { await s.stop(); }
});

test('"request a top-up": the page\'s own post asks the controller (sent, then already — and when); off; another page\'s post and another host are refused; no account, no request', async () => {
  let request = null;
  let answer = 'sent';
  const st = () => ({ name: 'Ali', username: 'ali', via: 'login', until: NOW + 3600e3, meters: [{ kind: 'total', period: 'month', bytes: GiB, capBytes: 2 * GiB, extraBytes: 0, over: false }], requests: true, request });
  const s = await page40((calls) => ({
    statusOf: async () => st(),
    requestTopUp: async (mac) => { calls.request.push(mac); if (answer === 'sent') request = { at: NOW - 5 * 60e3 }; return { ok: answer === 'sent' || answer === 'already', code: answer }; }
  }));
  try {
    const before = (await s.req('GET', '/')).text;
    assert.ok(before.includes(`<form class="req" method="post" action="/request"><button type="submit" class="btn soft">`), before);
    assert.ok(before.includes('درخواست حجم بیشتر') && before.includes('Request a top-up'));
    // another page's post, another host: nothing asked
    const cross = await s.post('/request', {}, { 'Sec-Fetch-Site': 'cross-site', Origin: 'http://evil.example' });
    assert.equal(cross.status, 403);
    const elsewhere = await s.req('POST', '/request', { headers: { Host: 'evil.example', 'Sec-Fetch-Site': 'same-origin' } });
    assert.equal(elsewhere.status, 302);
    assert.deepEqual(s.calls.request, []);
    assert.ok(s.logs.some(([, l]) => /refused a form posted from another page/.test(l)));
    // sent
    const sent = await s.post('/request', {});
    assert.equal(sent.status, 200);
    assert.deepEqual(s.calls.request, [A]);
    assert.ok(sent.text.includes(`درخواست شما فرستاده شد.${EN('Your request has been sent.')}`), sent.text);
    assert.ok(sent.text.includes(`درخواست حجم بیشتر فرستاده شده — 09:55${EN('Top-up requested — 09:55')}`), 'pending, and since when');
    assert.ok(!sent.text.includes('action="/request"'), 'no second button while one is pending');
    // already
    answer = 'already';
    const again = await s.post('/request', {});
    assert.equal(again.status, 200);
    assert.ok(again.text.includes(`درخواست شما پیش‌تر فرستاده شده است — 09:55${EN('You have already asked — 09:55')}`), again.text);
    // off on this network
    answer = 'off'; request = null;
    const off = await s.post('/request', {});
    assert.equal(off.status, 403);
    assert.match(off.text, /Top-up requests are off on this network\./);
    assert.match(off.text, /You are connected/, 'still the status page');
  } finally { await s.stop(); }
  // a device with no account: the sign-in page says so; a controller of before (no requestTopUp): off
  const none = await page40({ requestTopUp: async () => ({ ok: false, code: 'nouser' }) });
  try {
    const r = await none.post('/request', {});
    assert.equal(r.status, 403);
    assert.match(r.text, /This device is not signed in to an account\./);
    assert.match(r.text, /action="\/login"/);
  } finally { await none.stop(); }
  const old = await page40({ requestTopUp: undefined, statusOf: async () => ({ name: 'Ali', username: 'ali', via: 'admin', requests: true }) });
  try { assert.match((await old.post('/request', {})).text, /Top-up requests are off on this network\./); } finally { await old.stop(); }
});

test('a body over the size cap is never read into a sign-in', async () => {
  const s = await page40();
  try {
    const r = await s.req('POST', '/login', { body: 'username=ali&password=' + 'x'.repeat(5000), headers: { 'Sec-Fetch-Site': 'same-origin' } });
    assert.notEqual(r.status, 200);
    assert.deepEqual(s.calls.signIn, []);
  } finally { await s.stop(); }
});

test('the status page of an account: the greeting, three limits (the ring the one closest to its end), its time left and the date, the session, the speed, the allowed hours, the admin\'s note and a phone to call, a pending request', () => {
  const { statusPage } = require('../src/modules/lanUsers/router/portal');
  const html = statusPage({
    name: 'علی رضایی', username: 'ali', via: 'login', until: NOW + 2 * 3600e3, held: null, part: null, holdUntil: 0, calendar: 'jalali',
    meters: [
      { kind: 'total', period: 'month', bytes: 12.4 * GiB, capBytes: 20 * GiB, extraBytes: 0, until: 0, over: false },
      { kind: 'vpn', period: 'day', bytes: 1.62 * GiB, capBytes: 2 * GiB, extraBytes: 0, until: 0, over: false },
      { kind: 'direct', period: 'month', bytes: 3.1 * GiB, capBytes: 10 * GiB, extraBytes: 0, until: 0, over: false }
    ],
    speed: { down: 4000, up: 1000, why: ['hours'] },
    expiresAt: new Date(2026, 10, 22, 0, 0).getTime(), voucher: null,
    schedule: { days: [6, 0, 1, 2, 3], from: '08:00', to: '23:30' },
    note: 'اینترنت پنجشنبه‌ها برای نگهداری قطع است.', contact: '0912 345 6789',
    requests: true, request: { at: new Date(2026, 9, 29, 9, 15).getTime() }
  }, NOW, ['http://login.lan:30822/', 'http://192.168.1.1:30822/']);
  assert.ok(html.includes(`<h1>سلام، علی رضایی${EN('Hello, علی رضایی')}</h1><span class="chip">ali</span>`), html);
  assert.ok(html.includes(`<span>به اینترنت وصل هستید${EN('You are connected')}</span>`));
  // the ring: VPN today, 81 % used, a warning's colour; what is left in the middle
  assert.ok(html.includes(`<div class="ring warn" style="--p:81" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="81" aria-label="VPN · امروز · VPN · today"><div class="ring-in"><b class="ltr">0.38 GB</b><span class="s">مانده از ${LRM}2.00 GB</span>${EN('left of 2.00 GB')}</div></div>`), html);
  assert.equal((html.match(/<div class="lim">/g) || []).length, 3, 'every limit as a bar');
  assert.ok(html.includes(`<div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="62"`) && html.includes(`<div class="bar warn" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="81"`) && html.includes('aria-valuenow="31"'));
  // the account's time: a countdown and the date (midnight: the date alone, in the user's calendar)
  assert.ok(html.includes(`<div class="k">اعتبار حساب<span class="en-i" lang="en" dir="ltr">Account valid for</span></div><div class="v">23 روز مانده — تا 1 آذر${EN('23 days left — until 22 November (1 Azar)')}</div>`), html);
  assert.ok(html.includes(`زمان باقی‌ماندهٔ ورود`) && html.includes('2 h more'), 'the session ends before the account: said');
  assert.ok(html.includes(`<span class="rate">↓ 4 Mbps ↑ 1 Mbps</span><span class="why">ساعت‌های اوج${EN('peak hours')}</span>`), html);
  assert.ok(html.includes(`<div class="v">شنبه تا چهارشنبه، 08:00 تا 23:30${EN('Saturday to Wednesday, 08:00–23:30')}</div>`), html);
  assert.ok(html.includes('<p dir="auto">اینترنت پنجشنبه‌ها برای نگهداری قطع است.</p>'), html);
  assert.ok(html.includes('<a class="tel" href="tel:09123456789">') && html.includes('<b>0912 345 6789</b>'), 'a phone number: a call away');
  assert.ok(html.includes(`<p class="pending" role="status">`) && html.includes(`درخواست حجم بیشتر فرستاده شده — 09:15${EN('Top-up requested — 09:15')}`), html);
  assert.ok(!html.includes('action="/request"'), 'one request at a time');
  assert.ok(html.includes('action="/logout"'));
  assert.ok(html.includes('<span class="addr">http://login.lan:30822/</span><span class="addr">http://192.168.1.1:30822/</span>'));
  assert.ok(html.includes('<meta http-equiv="refresh" content="60;url=/">'));
});

test('the status page of a card: its time left (the session gives way to it), its one amount as the ring, the request button, a contact that is no number stays text; no request for what cannot run out, none when the admin turned them off', () => {
  const { statusPage } = require('../src/modules/lanUsers/router/portal');
  const card = {
    name: 'Cafe 3h #4', username: 'K7MP-29QX', via: 'login', until: NOW + 3 * 3600e3, calendar: '',
    meters: [{ kind: 'total', period: 'none', bytes: 0.35 * GiB, capBytes: GiB, extraBytes: 0, until: 0, over: false }],
    expiresAt: NOW + 138 * 60e3, voucher: { hours: 3, activatedAt: NOW - 42 * 60e3, expiresAt: NOW + 138 * 60e3 },
    note: '', contact: '@cafe_wifi', requests: true, request: null
  };
  const html = statusPage(card, NOW, []);
  assert.ok(html.includes(`<h1>کارت اینترنت${EN('Internet card')}</h1><span class="chip">K7MP-29QX</span>`), html);
  assert.ok(html.includes(`<div class="k">زمان کارت<span class="en-i" lang="en" dir="ltr">Card time</span></div><div class="v">2 ساعت و 18 دقیقه مانده — تا 12:18${EN('2 h 18 min left — until 12:18')}</div>`), html);
  assert.ok(!html.includes('Signed in for'), 'the card runs out before the session: its time is the one that counts');
  assert.ok(!html.includes('Account valid for'), 'a card says its own time, not the account\'s');
  assert.ok(html.includes('<div class="ring" style="--p:35"') && html.includes(`<span class="s">مانده از ${LRM}1.00 GB</span>`), html);
  assert.ok(!html.includes('class="lims"'), 'one limit: the ring says it all');
  assert.ok(html.includes('<p class="tel">') && html.includes('<b dir="auto">@cafe_wifi</b>') && !html.includes('href="tel:'), 'no number: text');
  assert.ok(html.includes('action="/request"'));
  assert.ok(!statusPage(Object.assign({}, card, { requests: false }), NOW, []).includes('action="/request"'), 'requests off: no button');
  const free = statusPage({ name: 'Office', username: 'office', via: 'admin', totals: { day: 1, month: 2 }, requests: true }, NOW, []);
  assert.ok(!free.includes('action="/request"'), 'no limit, no end: nothing to top up');
  // an unused card (activation is the controller's — a status before it): its hours from the first use
  const unused = statusPage(Object.assign({}, card, { voucher: { hours: 3, activatedAt: 0, expiresAt: 0 }, expiresAt: 0 }), NOW, []);
  assert.ok(unused.includes(`3 ساعت از اولین استفاده${EN('3 h from the first use')}`), unused);
});

test('every value on the status page is text: a name, a username, a note, a contact with markup in them', () => {
  const { statusPage } = require('../src/modules/lanUsers/router/portal');
  const html = statusPage({ name: '<img src=x>', username: '"><script>x</script>', via: 'login', note: '<a href="http://evil">x</a>', contact: '"><svg onload=alert(1)>', expiresAt: NOW + 86400e3, requests: true }, NOW, ['http://x/"><b>']);
  assert.ok(!/<img|<script|<a href="http|<svg onload/.test(html), html);
  assert.ok(html.includes('سلام، &lt;img src=x&gt;') && html.includes('<span class="chip">&quot;&gt;&lt;script&gt;x&lt;/script&gt;</span>'));
  assert.ok(html.includes('<span class="addr">http://x/&quot;&gt;&lt;b&gt;</span>'));
  assert.ok(html.includes('<b dir="auto">&quot;&gt;&lt;svg onload=alert(1)&gt;</b>'), 'no number: text, escaped');
  assert.ok(html.includes('&lt;a href=&quot;http://evil&quot;&gt;x&lt;/a&gt;'));
});

test('durText, pastText, scheduleText, telOf: the words of the status page', () => {
  const { durText, pastText, scheduleText, telOf } = require('../src/modules/lanUsers/router/portal');
  const M = 60e3, H = 3600e3, D = 86400e3;
  assert.deepEqual(durText(30e3), ['1 دقیقه', '1 min'], 'never less than a minute');
  assert.deepEqual(durText(45 * M), ['45 دقیقه', '45 min']);
  assert.deepEqual(durText(2 * H + 5 * M), ['2 ساعت و 5 دقیقه', '2 h 5 min']);
  assert.deepEqual(durText(12 * H + 40 * M), ['12 ساعت', '12 h'], 'ten hours or more: no minutes');
  assert.deepEqual(durText(D + 3 * H), ['1 روز و 3 ساعت', '1 day 3 h']);
  assert.deepEqual(durText(9 * D + 5 * H), ['9 روز', '9 days'], 'a week or more: days');
  const now = new Date(2026, 9, 29, 10, 0).getTime();
  assert.deepEqual(pastText(new Date(2026, 9, 29, 8, 5).getTime(), now, ''), ['08:05', '08:05']);
  assert.deepEqual(pastText(new Date(2026, 9, 27, 21, 0).getTime(), now, ''), ['سه‌شنبه 21:00', 'Tuesday 21:00']);
  assert.deepEqual(pastText(new Date(2026, 9, 10, 9, 30).getTime(), now, 'jalali'), ['18 مهر 09:30', '10 October (18 Mehr) 09:30']);
  assert.equal(scheduleText(null), null);
  assert.equal(scheduleText({ days: [], from: '08:00', to: '17:00' }), null);
  assert.deepEqual(scheduleText({ days: [0, 1, 2, 3, 4, 5, 6], from: '00:00', to: '00:00' }), ['هر روز، تمام روز', 'Every day, all day']);
  assert.deepEqual(scheduleText({ days: [1, 3], from: '22:00', to: '06:00' }), ['دوشنبه، چهارشنبه، 22:00 تا 06:00', 'Monday, Wednesday, 22:00–06:00']);
  assert.deepEqual(scheduleText({ days: [6, 0, 1, 5], from: '09:00', to: '17:00' }), ['شنبه تا دوشنبه، جمعه، 09:00 تا 17:00', 'Saturday to Monday, Friday, 09:00–17:00'], 'the week from Saturday');
  assert.equal(telOf('0912 345 6789'), '09123456789');
  assert.equal(telOf('+98 (21) 8888-1234'), '+982188881234');
  assert.equal(telOf('۰۹۱۲۳۴۵۶۷۸۹'), '09123456789', 'Persian digits');
  assert.equal(telOf('٠٩١٢'), '0912', 'Arabic-Indic digits');
  assert.equal(telOf('@cafe_wifi'), null);
  assert.equal(telOf('call 0912'), null);
  assert.equal(telOf('12'), null, 'too short for a number');
  assert.equal(telOf('1'.repeat(20)), null, 'too long for a number');
});
