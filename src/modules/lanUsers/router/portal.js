'use strict';
/**
 * The sign-in page of the users module's transparent mode: a small HTTP
 * server on the router's LAN address and its own port (`portalPort`, never
 * the admin UI's). In login mode every unassigned device's plain-http request
 * is redirected here by the gateway (router/nft.js's DNAT) — the request a
 * phone or a laptop makes to find out whether it is behind a sign-in page —
 * so it opens by itself, as at a hotel. Whatever host the device asked for,
 * the answer is a redirect to this server's own address, so the form always
 * posts here.
 *
 *   GET  (any path) — the sign-in form, or, for a device that belongs to a
 *                     user, its status: the account, this period's usage, the
 *                     session's time left, and why it is held if it is
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
  bad: ['نام کاربری یا رمز عبور درست نیست.', 'Wrong username or password.'],
  disabled: ['این حساب غیرفعال است.', 'This account is disabled.'],
  expired: ['اعتبار این حساب تمام شده است.', 'This account has expired.'],
  over: ['حجم این حساب برای این دوره تمام شده است.', 'This account has used up its data for this period.'],
  maxDevices: ['این حساب به بیشترین تعداد دستگاهش رسیده است ({n}).', 'This account is already on its maximum number of devices ({n}).'],
  assigned: ['مدیر شبکه این دستگاه را به حساب دیگری داده است.', 'The network’s admin has assigned this device to another account.'],
  rate: ['تلاش‌های زیاد — چند دقیقهٔ دیگر دوباره امتحان کنید.', 'Too many tries — try again in a few minutes.'],
  nomac: ['دستگاه شما در شبکه شناخته نشد — یک بار وای‌فای را قطع و وصل کنید و دوباره امتحان کنید.', 'Your device could not be identified on the network — reconnect to the Wi-Fi and try again.'],
  off: ['ورود در این شبکه فعال نیست.', 'Sign-in is not enabled on this network.'],
  error: ['خطایی پیش آمد — دوباره امتحان کنید.', 'Something went wrong — try again.'],
  hours: ['{n} ساعت دیگر', '{n} h more'],
  minutes: ['{n} دقیقهٔ دیگر', '{n} min more']
};

function both(key, n) {
  const [fa, en] = T[key] || T.error;
  const put = (s) => s.replace('{n}', n == null ? '' : String(n));
  return `${esc(put(fa))}<span class="en" lang="en" dir="ltr">${esc(put(en))}</span>`;
}

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
  'dl{margin:12px 0 0}dt{color:var(--muted);font-size:14px}dd{margin:0 0 10px}'
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
    '<input id="u" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="64" required>',
    `<label for="p">${both('password')}</label>`,
    '<input id="p" name="password" type="password" autocomplete="current-password" maxlength="256" required>',
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

/** `st`: { name, username, via, until?, held?, usage?: { bytes, quotaBytes } }. */
function statusPage(st, now) {
  const rows = [`<dt>${both('account')}</dt><dd>${esc(st.name || st.username)}${st.name && st.username ? ` (${esc(st.username)})` : ''}</dd>`];
  const u = st.usage || null;
  const used = u ? (u.quotaBytes > 0 ? `${gb(u.bytes)} / ${gb(u.quotaBytes)}` : `${gb(u.bytes)} — ${both('noCap')}`) : both('noCap');
  rows.push(`<dt>${both('used')}</dt><dd>${used}</dd>`);
  if (st.via === 'login' && st.until) rows.push(`<dt>${both('session')}</dt><dd>${timeLeft(st.until - now)}</dd>`);
  const parts = [
    st.held ? `<h1>${both('title')}</h1>` : `<h1>${both('connected')}</h1>`,
    `<dl>\n${rows.join('\n')}\n</dl>`
  ];
  if (st.held) parts.push(message(st.held, 'bad'));
  if (st.via === 'admin') parts.push(`<p>${both('assignedHere')}</p>`);
  else parts.push(`<form method="post" action="/logout"><button type="submit">${esc(T.signOut[0])} · ${esc(T.signOut[1])}</button></form>`);
  return page(parts.join('\n'));
}

function createPortal({ host, port, api, now = Date.now, log = () => {} } = {}) {
  const fails = new Map();   // device key → times of its failed tries in the window
  let server = null;
  let bound = { host, port };

  const origin = () => `http://${bound.host}:${bound.port}`;
  const send = (res, code, html, extra = {}) => {
    res.writeHead(code, Object.assign({
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      Connection: 'close',             // a kept-alive socket would stay DNAT'd here after the sign-in
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
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
      return send(res, 200, st ? statusPage(st, now()) : loginPage(mac ? '' : message('nomac', 'bad')));
    }
    if (req.method !== 'POST' || (url !== '/login' && url !== '/logout')) return send(res, 404, loginPage());
    // a form posted from any other page is not this device's own sign-in
    if (req.headers.origin && String(req.headers.origin).toLowerCase() !== origin().toLowerCase()) return send(res, 403, loginPage(message('error', 'bad')));
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
      return send(res, code === 'bad' ? 401 : 403, loginPage(message(code, 'bad', r && r.max)));
    }
    fails.delete(mac);
    const st = r.status || await api.statusOf(mac);
    return send(res, 200, st ? statusPage(st, now()) : loginPage());
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

module.exports = { createPortal, checkPassword, loginPage, statusPage, TRIES, WINDOW_MS };
