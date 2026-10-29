'use strict';
/**
 * The sign-in page of the users module's transparent mode: a small HTTP
 * server on the router's LAN address and its own port (`portalPort`, never
 * the admin UI's). In login mode every unassigned device's plain-http request
 * is redirected here by the gateway (router/nft.js's DNAT) — the request a
 * phone or a laptop makes to find out whether it is behind a sign-in page —
 * so it opens by itself, as at a hotel. Whatever host the device asked for,
 * the answer is a redirect to this server's own address, so the form always
 * posts here. Its https (tcp/443) lands here too: no page can stand in for
 * another site's https without a certificate warning, but a TLS hello met by
 * plain HTTP fails at once as "not a secure connection" — the error browsers
 * take as a sign-in page in the way (Chrome then opens this page in a tab of
 * its own) — where a refusal would only say the site cannot be reached.
 *
 *   GET  (any path) — the sign-in form, or, for a device that belongs to a
 *                     user, its status: the account, its limits as counted
 *                     ("VPN · today: 0.40 GB / 1.00 GB — 0.60 GB left"; with
 *                     none, today's and this month's use), its speed now and
 *                     why, the session's time left, why it is held if it is —
 *                     and until when ("outside your allowed hours — back at
 *                     08:00"), or which class alone is off — and the page's
 *                     own addresses to bookmark (`name` first)
 *   POST /login     — username + password (constant-time), the user active,
 *                     its device limit; then the device joins `authorized` for
 *                     the session's hours and rides its user's config
 *   POST /logout    — the sign-in ends (an admin's assignment stays)
 *
 * At most 5 failed tries in 5 minutes per device (by MAC — its address can be
 * changed at will, its MAC would be a new device to the gateway). Persian and
 * English on one page, right to left; no script, no external asset — the
 * device has no internet yet, and a page that needs some would never load.
 *
 * The decisions are the controller's (router/index.js → plan.js
 * judgeSignIn); this file is the HTTP and the page. `api`:
 *   macOf(ip) → mac | null          signIn({ mac, username, password }) → { ok, code?, max?, status? }
 *   statusOf(mac) → status | null   signOut(mac) → boolean
 */
const http = require('http');
const crypto = require('crypto');
const { dayText } = require('../../../main/jalali');

const TRIES = 5;
const WINDOW_MS = 5 * 60 * 1000;
const MAX_BODY = 4096;
const GIB = 1024 * 1024 * 1024;

/**
 * The password check, in constant time: both sides hashed first, so neither
 * their lengths nor the first byte that differs shows in how long it takes.
 */
function checkPassword(given, stored) {
  const a = crypto.createHash('sha256').update(String(given == null ? '' : given), 'utf8').digest();
  const b = crypto.createHash('sha256').update(String(stored == null ? '' : stored), 'utf8').digest();
  return crypto.timingSafeEqual(a, b);
}

/**
 * Was this form posted from another page? The browser's own word first —
 * Sec-Fetch-Site, which every current one sends — then its Origin. An Origin
 * of "null" says nothing either way: under `Referrer-Policy: no-referrer`
 * (this page's until v1.38.1) Chrome posts the page's own form with Origin
 * "null", and every sign-in was refused. It passes: a forged post can at most
 * sign a device in or out, a false refusal keeps it off the internet.
 */
function postedFromElsewhere(headers, ownOrigin) {
  const site = String(headers['sec-fetch-site'] || '').toLowerCase();
  if (site) return site !== 'same-origin' && site !== 'none';
  const o = String(headers.origin || '').toLowerCase();
  return !!o && o !== 'null' && o !== String(ownOrigin).toLowerCase();
}

/** A header as a log may show it: printable, short. */
const shown = (v) => (v == null || v === '' ? '—' : String(v).replace(/[^\x20-\x7e]/g, '?').slice(0, 80));

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/** Persian first, English under it (left to right). */
const T = {
  title: ['ورود به اینترنت', 'Sign in to use the internet'],
  intro: ['نام کاربری و رمزی را که مدیر شبکه به شما داده وارد کنید.', 'Enter the username and password the network’s admin gave you.'],
  username: ['نام کاربری', 'Username'],
  password: ['رمز عبور', 'Password'],
  signIn: ['ورود', 'Sign in'],
  connected: ['به اینترنت وصل هستید', 'You are connected'],
  account: ['حساب', 'Account'],
  used: ['مصرف این دوره', 'Used this period'],
  noCap: ['بدون سقف', 'no cap'],
  session: ['زمان باقی‌ماندهٔ ورود', 'Signed in for'],
  assignedHere: ['این دستگاه را مدیر شبکه به این حساب داده است.', 'The network’s admin has assigned this device to this account.'],
  signOut: ['خروج', 'Sign out'],
  again: ['برای برگشتن به این صفحه (خروج یا دیدن مصرف) این نشانی را نشانه‌گذاری کنید:', 'To come back to this page (to sign out or see your usage), bookmark:'],
  bad: ['نام کاربری یا رمز عبور درست نیست.', 'Wrong username or password.'],
  disabled: ['این حساب غیرفعال است.', 'This account is disabled.'],
  expired: ['اعتبار این حساب تمام شده است.', 'This account has expired.'],
  over: ['حجم این حساب برای این دوره تمام شده است.', 'This account has used up its data for this period.'],
  // a hold's reason (the meter's), with when it lifts ({n}) — the `0` one when it lifts only by the admin's hand
  schedule: ['خارج از ساعت‌های مجاز — از {n} دوباره', 'Outside your allowed hours — back at {n}'],
  schedule0: ['خارج از ساعت‌های مجاز', 'Outside your allowed hours'],
  total: ['حجم این حساب تمام شده — از {n} دوباره', 'This account’s data is used up — again from {n}'],
  total0: ['حجم این حساب تمام شده است.', 'This account’s data is used up.'],
  vpn: ['حجم VPN این حساب تمام شده — از {n} دوباره', 'This account’s VPN data is used up — again from {n}'],
  vpn0: ['حجم VPN این حساب تمام شده است.', 'This account’s VPN data is used up.'],
  direct: ['حجم ترافیک مستقیم این حساب تمام شده — از {n} دوباره', 'This account’s direct data is used up — again from {n}'],
  direct0: ['حجم ترافیک مستقیم این حساب تمام شده است.', 'This account’s direct data is used up.'],
  // one class off, the other still working (the status page)
  partVpn: ['VPN تا {n} قطع است — سایت‌های مستقیم کار می‌کنند.', 'The VPN is off until {n} — direct sites still work.'],
  partVpn0: ['VPN قطع است — سایت‌های مستقیم کار می‌کنند.', 'The VPN is off — direct sites still work.'],
  partDirect: ['ترافیک مستقیم تا {n} قطع است — VPN کار می‌کند.', 'Direct traffic is off until {n} — the VPN still works.'],
  partDirect0: ['ترافیک مستقیم قطع است — VPN کار می‌کند.', 'Direct traffic is off — the VPN still works.'],
  // the limits, as rows: "kind · period: used / cap — left"
  kindTotal: ['کل', 'Total'],
  kindVpn: ['VPN', 'VPN'],
  kindDirect: ['مستقیم', 'Direct'],
  periodDay: ['امروز', 'today'],
  periodMonth: ['این ماه', 'this month'],
  periodNone: ['یک‌باره', 'one-off'],
  left: ['{n} مانده', '{n} left'],
  usedUp: ['تمام شده', 'used up'],
  today: ['مصرف امروز', 'Used today'],
  thisMonth: ['مصرف این ماه', 'Used this month'],
  speed: ['سرعت', 'Speed'],
  speedBase: ['سقف سرعت', 'speed limit'],
  speedHours: ['ساعت‌های اوج', 'peak hours'],
  speedAfter: ['بعد از {n}', 'after {n}'],
  maxDevices: ['این حساب به بیشترین تعداد دستگاهش رسیده است ({n}).', 'This account is already on its maximum number of devices ({n}).'],
  assigned: ['مدیر شبکه این دستگاه را به حساب دیگری داده است.', 'The network’s admin has assigned this device to another account.'],
  rate: ['تلاش‌های زیاد — چند دقیقهٔ دیگر دوباره امتحان کنید.', 'Too many tries — try again in a few minutes.'],
  nomac: ['دستگاه شما در شبکه شناخته نشد — یک بار وای‌فای را قطع و وصل کنید و دوباره امتحان کنید.', 'Your device could not be identified on the network — reconnect to the Wi-Fi and try again.'],
  off: ['ورود در این شبکه فعال نیست.', 'Sign-in is not enabled on this network.'],
  error: ['خطایی پیش آمد — دوباره امتحان کنید.', 'Something went wrong — try again.'],
  hours: ['{n} ساعت دیگر', '{n} h more'],
  minutes: ['{n} دقیقهٔ دیگر', '{n} min more']
};

/** `n`: one value for both lines, or [Persian, English] — a date, a weekday. */
function both(key, n) {
  const [fa, en] = T[key] || T.error;
  const [nf, ne] = Array.isArray(n) ? n : [n, n];
  const put = (s, v) => s.replace('{n}', v == null ? '' : String(v));
  return `${esc(put(fa, nf))}<span class="en" lang="en" dir="ltr">${esc(put(en, ne))}</span>`;
}

/** The two halves of a pair, as text (for a value inside another line). */
const pair = (key, n) => {
  const [fa, en] = T[key] || T.error;
  const [nf, ne] = Array.isArray(n) ? n : [n, n];
  return [fa.replace('{n}', nf == null ? '' : String(nf)), en.replace('{n}', ne == null ? '' : String(ne))];
};

const WEEK_FA = ['یکشنبه', 'دوشنبه', 'سه‌شنبه', 'چهارشنبه', 'پنجشنبه', 'جمعه', 'شنبه'];
const WEEK_EN = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const DAY_MS = 24 * 3600 * 1000;
const pad2 = (n) => String(n).padStart(2, '0');

/**
 * When a hold lifts, as the page says it — [Persian, English], the router's
 * local time: within a day '08:00'; within the week a weekday and the time;
 * further a date in the user's calendar (jalali.dayText: the Persian month in
 * Persian), with the time unless it is midnight (a limit renews at one).
 */
function whenText(ms, now, calendar) {
  const d = new Date(ms);
  const hm = `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  if (ms - now < DAY_MS) return [hm, hm];
  const midnight = d.getHours() === 0 && d.getMinutes() === 0;
  if (ms - now < 7 * DAY_MS && !midnight) return [`${WEEK_FA[d.getDay()]} ${hm}`, `${WEEK_EN[d.getDay()]} ${hm}`];
  const fa = dayText(ms, 'fa', calendar), en = dayText(ms, 'en', calendar);
  return midnight ? [fa, en] : [`${fa} ${hm}`, `${en} ${hm}`];
}

/** A hold's message: its reason's line with when it lifts, or the line without (`<code>0`) — a code with no such pair as it is. */
function holdMessage(code, until, now, calendar) {
  if (T[code + '0']) return until > now ? message(code, 'bad', whenText(until, now, calendar)) : message(code + '0', 'bad');
  return message(code, 'bad');
}

/** kbps as the page writes a speed: '512 kbps', '2 Mbps', '1.5 Mbps'. */
const rateText = (k) => (k >= 1000 ? `${Math.round(k / 100) / 10} Mbps` : `${k} kbps`);

const CSS = [
  ':root{color-scheme:light dark;--bg:#f4f6f8;--card:#fff;--fg:#1d2733;--muted:#5f6b7a;--line:#d5dbe2;--accent:#1f6feb;--bad:#c62828;--ok:#2e7d32}',
  '@media (prefers-color-scheme:dark){:root{--bg:#0f141a;--card:#18202a;--fg:#e6edf3;--muted:#9aa7b4;--line:#2c3744;--accent:#4c8dff;--bad:#ef5350;--ok:#66bb6a}}',
  '*{box-sizing:border-box}',
  'body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,-apple-system,"Segoe UI",Tahoma,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:16px}',
  'main{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:24px;width:100%;max-width:380px}',
  'h1{font-size:20px;margin:0 0 8px}p{margin:0 0 8px}',
  '.en{display:block;color:var(--muted);font-size:13px;direction:ltr;text-align:left;font-weight:normal}',
  'label{display:block;margin:14px 0 6px}',
  'input{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit;font:inherit;direction:ltr}',
  'button{margin-top:18px;width:100%;padding:11px;border:0;border-radius:8px;background:var(--accent);color:#fff;font:inherit;cursor:pointer}',
  '.msg{margin:14px 0 0;padding:10px 12px;border-radius:8px;border:1px solid}.bad{color:var(--bad);border-color:var(--bad)}.ok{color:var(--ok);border-color:var(--ok)}',
  'dl{margin:12px 0 0}dt{color:var(--muted);font-size:14px}dd{margin:0 0 10px}',
  '.back{margin-top:16px;font-size:14px}.addr{display:block;direction:ltr;text-align:left;font-family:ui-monospace,Consolas,monospace;font-size:15px;margin:4px 0 0;user-select:all}'
].join('\n');

function page(body) {
  return '<!doctype html>\n<html lang="fa" dir="rtl">\n<head>\n<meta charset="utf-8">\n' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">\n' +
    `<title>${esc(T.title[0])} · ${esc(T.title[1])}</title>\n<style>\n${CSS}\n</style>\n</head>\n<body>\n<main>\n${body}\n</main>\n</body>\n</html>\n`;
}

function message(code, kind, n) {
  return `<p class="msg ${kind === 'ok' ? 'ok' : 'bad'}" role="${kind === 'ok' ? 'status' : 'alert'}">${both(code, n)}</p>`;
}

function loginPage(msg) {
  return page([
    `<h1>${both('title')}</h1>`,
    `<p>${both('intro')}</p>`,
    '<form method="post" action="/login">',
    `<label for="u">${both('username')}</label>`,
    '<input id="u" name="username" dir="ltr" autocomplete="username" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="64" required>',
    `<label for="p">${both('password')}</label>`,
    '<input id="p" name="password" type="password" dir="ltr" autocomplete="current-password" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="256" required>',
    `<button type="submit">${esc(T.signIn[0])} · ${esc(T.signIn[1])}</button>`,
    '</form>',
    msg || ''
  ].join('\n'));
}

const gb = (bytes) => (Math.max(0, Number(bytes) || 0) / GIB).toFixed(2) + ' GB';

function timeLeft(ms) {
  const m = Math.max(1, Math.round(ms / 60000));
  return m >= 120 ? both('hours', Math.round(m / 60)) : both('minutes', m);
}

const KIND_KEY = { total: 'kindTotal', vpn: 'kindVpn', direct: 'kindDirect' };
const PERIOD_KEY = { day: 'periodDay', month: 'periodMonth', none: 'periodNone' };

/** One limit as a row: "VPN · today" / "0.40 GB / 1.00 GB — 0.60 GB left" (its top-up in the amount). */
function meterRow(m) {
  const [kf, ke] = pair(KIND_KEY[m.kind] || 'kindTotal');
  const [pf, pe] = pair(PERIOD_KEY[m.period] || 'periodMonth');
  const full = (Number(m.capBytes) || 0) + (Number(m.extraBytes) || 0);
  const rest = full - (Number(m.bytes) || 0);
  const tail = m.over || rest <= 0 ? both('usedUp') : both('left', gb(rest));
  return `<dt>${esc(kf)} · ${esc(pf)}<span class="en" lang="en" dir="ltr">${esc(ke)} · ${esc(pe)}</span></dt><dd>${gb(m.bytes)} / ${gb(full)} — ${tail}</dd>`;
}

/** The speed now and why: "↓ 2 Mbps ↑ 1 Mbps" / "peak hours, after 2 GB today". */
function speedRow(sp) {
  const rate = [sp.down ? `↓ ${rateText(sp.down)}` : '', sp.up ? `↑ ${rateText(sp.up)}` : ''].filter(Boolean).join(' ');
  const whys = (Array.isArray(sp.why) ? sp.why : []).map((w) => {
    if (w === 'base') return pair('speedBase');
    if (w === 'hours') return pair('speedHours');
    if (w && typeof w === 'object' && Number(w.after) > 0) {
      const [pf, pe] = pair(PERIOD_KEY[w.period] || 'periodMonth');
      return pair('speedAfter', [`${w.after} GB ${pf}`, `${w.after} GB ${pe}`]);
    }
    return null;
  }).filter(Boolean);
  const why = whys.length ? ` — ${esc(whys.map(x => x[0]).join('، '))}<span class="en" lang="en" dir="ltr">${esc(whys.map(x => x[1]).join(', '))}</span>` : '';
  return `<dt>${both('speed')}</dt><dd><span dir="ltr">${esc(rate)}</span>${why}</dd>`;
}

/**
 * `st`: { name, username, via, until?, held?, part?, holdUntil?, calendar?,
 * usage?: { bytes, quotaBytes }, meters?: [{ kind, period, bytes, capBytes,
 * extraBytes, until, over }], totals?: { day, month }, speed?: { down, up,
 * why } } (router/index.js statusOf). `meters` — the limits that are set —
 * stand in for the one cap's usage; with no limit, `totals`; a meter of
 * before has neither, and its one cap shows as it always has.
 * `back`: this page's addresses to bookmark (its short name's first), since a
 * device that is signed in is no longer sent here by itself.
 */
function statusPage(st, now, back = []) {
  const rows = [`<dt>${both('account')}</dt><dd>${esc(st.name || st.username)}${st.name && st.username ? ` (${esc(st.username)})` : ''}</dd>`];
  if (Array.isArray(st.meters) && st.meters.length) rows.push(...st.meters.map(meterRow));
  else if (st.totals) rows.push(`<dt>${both('today')}</dt><dd>${gb(st.totals.day)}</dd>`, `<dt>${both('thisMonth')}</dt><dd>${gb(st.totals.month)}</dd>`);
  else {
    const u = st.usage || null;
    const used = u ? (u.quotaBytes > 0 ? `${gb(u.bytes)} / ${gb(u.quotaBytes)}` : `${gb(u.bytes)} — ${both('noCap')}`) : both('noCap');
    rows.push(`<dt>${both('used')}</dt><dd>${used}</dd>`);
  }
  if (st.speed && (st.speed.down || st.speed.up)) rows.push(speedRow(st.speed));
  if (st.via === 'login' && st.until) rows.push(`<dt>${both('session')}</dt><dd>${timeLeft(st.until - now)}</dd>`);
  const parts = [
    st.held ? `<h1>${both('title')}</h1>` : `<h1>${both('connected')}</h1>`,
    `<dl>\n${rows.join('\n')}\n</dl>`
  ];
  if (st.held) parts.push(holdMessage(st.held, Number(st.holdUntil) || 0, now, st.calendar));
  else if (st.part === 'vpn' || st.part === 'direct') parts.push(holdMessage(st.part === 'vpn' ? 'partVpn' : 'partDirect', Number(st.holdUntil) || 0, now, st.calendar));
  if (st.via === 'admin') parts.push(`<p>${both('assignedHere')}</p>`);
  else parts.push(`<form method="post" action="/logout"><button type="submit">${esc(T.signOut[0])} · ${esc(T.signOut[1])}</button></form>`);
  if (back.length) parts.push(`<p class="back">${both('again')}${back.map((a) => `<span class="addr">${esc(a)}</span>`).join('')}</p>`);
  return page(parts.join('\n'));
}

/** `name`: the page's short name on the router's DNS (router/index.js PORTAL_NAME), or null when it is not there. */
function createPortal({ host, port, api, now = Date.now, log = () => {}, name = null } = {}) {
  const fails = new Map();   // device key → times of its failed tries in the window
  let server = null;
  let bound = { host, port };

  const origin = () => `http://${bound.host}:${bound.port}`;
  // a request to the short name is redirected to the address (the one origin the form posts to)
  const back = () => [name ? `http://${name}:${bound.port}/` : null, origin() + '/'].filter(Boolean);
  const send = (res, code, html, extra = {}) => {
    res.writeHead(code, Object.assign({
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      Connection: 'close',             // a kept-alive socket would stay DNAT'd here after the sign-in
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'same-origin',   // never 'no-referrer': its own form would post Origin "null"
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"
    }, extra));
    res.end(html);
  };
  const redirect = (res, to, code = 302) => {
    res.writeHead(code, { Location: to, 'Cache-Control': 'no-store', Connection: 'close', 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('');
  };

  /** Failed tries of `key` still inside the window (old ones forgotten). */
  function recent(key) {
    const t = now();
    const list = (fails.get(key) || []).filter(x => t - x < WINDOW_MS);
    if (list.length) fails.set(key, list); else fails.delete(key);
    return list;
  }
  function fail(key) {
    if (fails.size > 2000) fails.clear();   // a flood of made-up MACs cannot grow it without bound
    fails.set(key, [...recent(key), now()]);
  }

  async function readBody(req) {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      req.on('data', (c) => {
        size += c.length;
        if (size > MAX_BODY) { reject(Object.assign(new Error('too large'), { status: 413 })); req.destroy(); return; }
        chunks.push(c);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      req.on('error', reject);
    });
  }

  async function handle(req, res) {
    const hostHeader = String(req.headers.host || '').toLowerCase();
    const mine = `${bound.host}:${bound.port}`.toLowerCase();
    // a device's own captive check (captive.apple.com, connectivitycheck…) lands here by DNAT: send it to the page's own address
    if (hostHeader !== mine) return redirect(res, origin() + '/');
    const url = String(req.url || '/').split('?')[0];
    const ip = req.socket && req.socket.remoteAddress;
    if (req.method === 'GET' || req.method === 'HEAD') {
      const mac = await api.macOf(ip);
      const st = mac ? await api.statusOf(mac) : null;
      return send(res, 200, st ? statusPage(st, now(), back()) : loginPage(mac ? '' : message('nomac', 'bad')));
    }
    if (req.method !== 'POST' || (url !== '/login' && url !== '/logout')) return send(res, 404, loginPage());
    // a form posted from any other page is not this device's own sign-in
    if (postedFromElsewhere(req.headers, origin())) {
      log(`Users: the sign-in page refused a form posted from another page (Sec-Fetch-Site ${shown(req.headers['sec-fetch-site'])}, Origin ${shown(req.headers.origin)})`, 'warn');
      return send(res, 403, loginPage(message('error', 'bad')));
    }
    let form;
    try { form = new URLSearchParams(await readBody(req)); }
    catch (e) { return send(res, e.status || 400, loginPage(message('error', 'bad'))); }
    const mac = await api.macOf(ip);
    if (!mac) return send(res, 403, loginPage(message('nomac', 'bad')));
    if (url === '/logout') {
      await api.signOut(mac);
      return redirect(res, origin() + '/', 303);
    }
    if (recent(mac).length >= TRIES) return send(res, 429, loginPage(message('rate', 'bad')), { 'Retry-After': '300' });
    const r = await api.signIn({ mac, username: form.get('username') || '', password: form.get('password') || '' });
    if (!r || !r.ok) {
      fail(mac);
      const code = r && T[r.code] ? r.code : 'error';
      // a hold says when it lifts ("back at 08:00"); the rest as they always have
      const msg = T[code + '0'] ? holdMessage(code, Number(r.until) || 0, now(), r.calendar) : message(code, 'bad', r && r.max);
      return send(res, code === 'bad' ? 401 : 403, loginPage(msg));
    }
    fails.delete(mac);
    const st = r.status || await api.statusOf(mac);
    return send(res, 200, st ? statusPage(st, now(), back()) : loginPage());
  }

  return {
    get port() { return bound.port; },
    get host() { return bound.host; },
    get listening() { return !!server; },
    start() {
      if (server) return Promise.resolve(bound);
      return new Promise((resolve, reject) => {
        const srv = http.createServer((req, res) => {
          handle(req, res).catch((e) => {
            log(`Users: the sign-in page failed a request: ${e.message}`, 'warn');
            try { send(res, 500, loginPage(message('error', 'bad'))); } catch { /* the socket is gone */ }
          });
        });
        srv.headersTimeout = 10000;
        srv.requestTimeout = 15000;
        srv.keepAliveTimeout = 1000;
        srv.maxHeadersCount = 50;
        srv.once('error', (e) => { reject(e); });
        srv.listen(port, host, () => {
          srv.removeAllListeners('error');
          srv.on('error', (e) => log(`Users: the sign-in page: ${e.message}`, 'warn'));
          srv.unref();             // never what keeps the service's process alive
          server = srv;
          bound = { host, port: srv.address().port };
          resolve(bound);
        });
      });
    },
    stop() {
      const srv = server;
      server = null;
      if (!srv) return Promise.resolve();
      return new Promise((resolve) => {
        srv.close(() => resolve());
        if (typeof srv.closeAllConnections === 'function') srv.closeAllConnections();
      });
    },
    /** For the tests: the failed tries a device has left in the window. */
    triesLeft(mac) { return Math.max(0, TRIES - recent(mac).length); }
  };
}

module.exports = { createPortal, checkPassword, postedFromElsewhere, loginPage, statusPage, whenText, T, TRIES, WINDOW_MS };
