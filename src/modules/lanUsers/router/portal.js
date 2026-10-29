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
 *   GET  (any path) — the sign-in form, two ways as tabs: a username and a
 *                     password, or a card's code (a voucher: one code for
 *                     both). `?u=<username>` and `?code=<code>` fill them in —
 *                     what the Users page's sign-in card and a voucher card's
 *                     QR open — and `?code=` opens the code's tab. For a device
 *                     that belongs to a user, its status instead: a greeting,
 *                     the limit closest to its end as a ring and every limit
 *                     as a bar (used / left), the account's or the card's time
 *                     left (a countdown and the date), the session's, the speed
 *                     now and why, the allowed hours, why it is held if it is —
 *                     and until when ("outside your allowed hours — back at
 *                     08:00"), or which class alone is off — the admin's note
 *                     and contact (a `tel:` link when it is a phone number),
 *                     "request a top-up", and the page's own addresses to
 *                     bookmark (`name` first). It refreshes itself every minute.
 *   POST /login     — `username` + `password` (constant-time), or `code`; the
 *                     user active, its device limit; then the device joins
 *                     `authorized` for the session's hours and rides its
 *                     user's config
 *   POST /logout    — the sign-in ends (an admin's assignment stays)
 *   POST /request   — "request a top-up": the admin sees it on the Users page
 *
 * At most 5 failed tries in 5 minutes per device (by MAC — its address can be
 * changed at will, its MAC would be a new device to the gateway), codes and
 * passwords alike. Persian first and English under it, right to left; nothing
 * from outside — the device has no internet yet, and a page that needs some
 * would never load (no font, no image: the icons are inline SVG). No script is
 * needed either — a captive sign-in window may run none: the tabs are two
 * radio inputs and CSS (`:checked ~`), the status refreshes by a meta refresh.
 * One small inline script, allowed by its hash in the CSP and nothing else is,
 * adds the show-password eye where scripts run.
 *
 * The decisions are the controller's (router/index.js → plan.js
 * judgeSignIn); this file is the HTTP and the page. `api`:
 *   macOf(ip) → mac | null          signIn({ mac, username, password } | { mac, username: '', password: '', code })
 *                                     → { ok, code?, max?, until?, calendar?, status? }
 *   statusOf(mac) → status | null   signOut(mac) → boolean
 *   requestTopUp(mac) → { ok, code: 'sent' | 'already' | 'off' | 'nouser' }   (absent: requests are off)
 */
const http = require('http');
const crypto = require('crypto');
const { dayText } = require('../../../main/jalali');

const TRIES = 5;
const WINDOW_MS = 5 * 60 * 1000;
const MAX_BODY = 4096;
const GIB = 1024 * 1024 * 1024;
/** What the page echoes of a typed username or code (?u=, ?code=, a refused form): cut, never trusted. */
const MAX_TYPED = 64;
/** The status page reloads itself this often (seconds): the counters, the time left, a hold that lifted. */
const REFRESH_S = 60;

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

/** A typed value the page may echo: no control characters, at most MAX_TYPED. */
const typed = (v) => String(v == null ? '' : v).replace(/[\x00-\x1f\x7f]/g, '').trim().slice(0, MAX_TYPED);

/**
 * An amount for a Persian line ('2.00 GB'): a left-to-right mark in front, so
 * the number and its unit stay one left-to-right run — without it the right-
 * to-left line shows "GB 2.00". (A mark, not an isolate: every browser has it.)
 */
const lrm = (s) => '‎' + s;

/** Persian first, English under it (left to right). */
const T = {
  title: ['ورود به اینترنت', 'Sign in to use the internet'],
  intro: ['با نام کاربری و رمز، یا با کد کارتی که مدیر شبکه به شما داده وارد شوید.', 'Sign in with the username and password — or the card code — the network’s admin gave you.'],
  // the two ways, as tabs
  wayUser: ['نام کاربری و رمز', 'Username & password'],
  wayCode: ['کد کارت', 'Card code'],
  username: ['نام کاربری', 'Username'],
  password: ['رمز عبور', 'Password'],
  showPassword: ['نمایش رمز', 'Show password'],
  code: ['کد کارت', 'Card code'],
  codeHint: ['کد روی کارت را با خط تیره یا بدون آن بنویسید.', 'Type the code on the card — with or without the dash.'],
  signIn: ['ورود', 'Sign in'],
  connected: ['به اینترنت وصل هستید', 'You are connected'],
  heldTitle: ['اینترنت این دستگاه فعلاً قطع است', 'This device’s internet is paused'],
  partTitle: ['بخشی از اینترنت شما قطع است', 'Part of your internet is paused'],
  hello: ['سلام، {n}', 'Hello, {n}'],
  card: ['کارت اینترنت', 'Internet card'],
  account: ['حساب', 'Account'],
  used: ['مصرف این دوره', 'Used this period'],
  noCap: ['بدون سقف', 'no cap'],
  session: ['زمان باقی‌ماندهٔ ورود', 'Signed in for'],
  assignedHere: ['این دستگاه را مدیر شبکه به این حساب داده است.', 'The network’s admin has assigned this device to this account.'],
  signOut: ['خروج', 'Sign out'],
  again: ['برای برگشتن به این صفحه (خروج یا دیدن مصرف) این نشانی را نشانه‌گذاری کنید:', 'To come back to this page (to sign out or see your usage), bookmark:'],
  refreshing: ['این صفحه هر دقیقه خودش به‌روز می‌شود.', 'This page updates itself every minute.'],
  bad: ['نام کاربری یا رمز عبور درست نیست.', 'Wrong username or password.'],
  disabled: ['این حساب غیرفعال است.', 'This account is disabled.'],
  expired: ['اعتبار این حساب تمام شده است.', 'This account has expired.'],
  over: ['حجم این حساب برای این دوره تمام شده است.', 'This account has used up its data for this period.'],
  // the same refusals for a card's code
  badCode: ['این کد درست نیست.', 'This code is not valid.'],
  codeExpired: ['زمان این کارت تمام شده است.', 'This card’s time is up.'],
  codeOver: ['حجم این کارت تمام شده است.', 'This card’s data is used up.'],
  codeMax: ['این کارت روی دستگاه دیگری در حال استفاده است.', 'This card is already in use on another device.'],
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
  // the limits, as bars: "kind · period", "used / cap", "left"
  kindTotal: ['کل', 'Total'],
  kindVpn: ['VPN', 'VPN'],
  kindDirect: ['مستقیم', 'Direct'],
  periodDay: ['امروز', 'today'],
  periodMonth: ['این ماه', 'this month'],
  periodNone: ['یک‌باره', 'one-off'],
  left: ['{n} مانده', '{n} left'],
  leftOf: ['مانده از {n}', 'left of {n}'],
  usedUp: ['تمام شده', 'used up'],
  limits: ['سقف‌های مصرف', 'Data limits'],
  today: ['مصرف امروز', 'Used today'],
  thisMonth: ['مصرف این ماه', 'Used this month'],
  // the time an account or a card has left: "3 days 4 h left — until 1 Azar"
  timeAccount: ['اعتبار حساب', 'Account valid for'],
  timeCard: ['زمان کارت', 'Card time'],
  untilAt: ['تا {n}', 'until {n}'],
  fromFirstUse: ['{n} ساعت از اولین استفاده', '{n} h from the first use'],
  dDay: ['{n} روز', '{n} day'],
  dDays: ['{n} روز', '{n} days'],
  dH: ['{n} ساعت', '{n} h'],
  dMin: ['{n} دقیقه', '{n} min'],
  and: [' و ', ' '],
  speed: ['سرعت', 'Speed'],
  speedBase: ['سقف سرعت', 'speed limit'],
  speedHours: ['ساعت‌های اوج', 'peak hours'],
  speedAfter: ['بعد از {n}', 'after {n}'],
  // the allowed hours: "Saturday to Wednesday, 08:00–22:00"
  allowed: ['ساعت‌های مجاز', 'Allowed hours'],
  everyDay: ['هر روز', 'Every day'],
  allDay: ['تمام روز', 'all day'],
  dayTo: [' تا ', ' to '],
  timeTo: [' تا ', '–'],
  comma: ['، ', ', '],
  // the admin's word and the top-up request
  noteTitle: ['پیام مدیر شبکه', 'From the network’s admin'],
  contact: ['تماس با مدیر شبکه', 'Contact the network’s admin'],
  reqButton: ['درخواست حجم بیشتر', 'Request a top-up'],
  reqHint: ['مدیر شبکه درخواست شما را در صفحهٔ کاربران می‌بیند.', 'The network’s admin sees it on the Users page.'],
  reqSent: ['درخواست شما فرستاده شد.', 'Your request has been sent.'],
  reqAlready: ['درخواست شما پیش‌تر فرستاده شده است — {n}', 'You have already asked — {n}'],
  reqPending: ['درخواست حجم بیشتر فرستاده شده — {n}', 'Top-up requested — {n}'],
  reqOff: ['درخواست حجم در این شبکه فعال نیست.', 'Top-up requests are off on this network.'],
  reqNouser: ['این دستگاه به حسابی وصل نیست.', 'This device is not signed in to an account.'],
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

/** A [Persian, English] pair as the page writes one: Persian, English under it. */
const two = ([fa, en]) => `${esc(fa)}<span class="en" lang="en" dir="ltr">${esc(en)}</span>`;

/** A label: Persian, English after it on the same line (smaller) — a field's, a fact's. */
const inl = (key) => `${esc(T[key][0])}<span class="en-i" lang="en" dir="ltr">${esc(T[key][1])}</span>`;

/** Pairs joined by a pair: [[fa, en], …] with T[sep] → [fa, en]. */
const joinPairs = (list, sep) => [list.map((x) => x[0]).join(T[sep][0]), list.map((x) => x[1]).join(T[sep][1])];

const WEEK_FA = ['یکشنبه', 'دوشنبه', 'سه‌شنبه', 'چهارشنبه', 'پنجشنبه', 'جمعه', 'شنبه'];
const WEEK_EN = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
/** The week as it runs in Iran: Saturday first (the allowed hours' days, in that order). */
const WEEK_ORDER = [6, 0, 1, 2, 3, 4, 5];
const DAY_MS = 24 * 3600 * 1000;
const pad2 = (n) => String(n).padStart(2, '0');
const hmOf = (d) => `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;

/**
 * When a hold lifts, as the page says it — [Persian, English], the router's
 * local time: within a day '08:00'; within the week a weekday and the time;
 * further a date in the user's calendar (jalali.dayText: the Persian month in
 * Persian), with the time unless it is midnight (a limit renews at one).
 */
function whenText(ms, now, calendar) {
  const d = new Date(ms);
  const hm = hmOf(d);
  if (ms - now < DAY_MS) return [hm, hm];
  const midnight = d.getHours() === 0 && d.getMinutes() === 0;
  if (ms - now < 7 * DAY_MS && !midnight) return [`${WEEK_FA[d.getDay()]} ${hm}`, `${WEEK_EN[d.getDay()]} ${hm}`];
  const fa = dayText(ms, 'fa', calendar), en = dayText(ms, 'en', calendar);
  return midnight ? [fa, en] : [`${fa} ${hm}`, `${en} ${hm}`];
}

/** When something happened (a top-up request) — [Persian, English]: today the time, this week a weekday, before that a date. */
function pastText(ms, now, calendar) {
  const d = new Date(ms);
  const hm = hmOf(d);
  if (d.toDateString() === new Date(now).toDateString()) return [hm, hm];
  if (now - ms < 6 * DAY_MS) return [`${WEEK_FA[d.getDay()]} ${hm}`, `${WEEK_EN[d.getDay()]} ${hm}`];
  return [`${dayText(ms, 'fa', calendar)} ${hm}`, `${dayText(ms, 'en', calendar)} ${hm}`];
}

/**
 * A span of time as the page counts it down — [Persian, English]: a week or
 * more in days, a day or more in days and hours, under ten hours in hours and
 * minutes ('3 days 4 h', '2 h 20 min', '12 min'). Never less than a minute.
 */
function durText(ms) {
  const m = Math.max(1, Math.round(ms / 60000));
  const d = Math.floor(m / 1440), h = Math.floor((m % 1440) / 60), mm = m % 60;
  const parts = [];
  if (d) parts.push(pair(d === 1 ? 'dDay' : 'dDays', d));
  if (h && d < 7) parts.push(pair('dH', h));
  if (mm && !d && h < 10) parts.push(pair('dMin', mm));
  return joinPairs(parts, 'and');
}

/**
 * The allowed hours (model.js `schedule`: { days, from, to }, local time) in
 * words — [Persian, English] — or null when there is none to say: the days in
 * the week's order, three or more in a row as a range ("Saturday to
 * Wednesday"), all seven as "every day"; from === to is all day.
 */
function scheduleText(w) {
  if (!w || typeof w !== 'object' || !Array.isArray(w.days)) return null;
  const on = WEEK_ORDER.filter((d) => w.days.includes(d));
  if (!on.length || typeof w.from !== 'string' || typeof w.to !== 'string') return null;
  let days;
  if (on.length === 7) days = pair('everyDay');
  else {
    const runs = [];
    for (const d of on) {
      const last = runs[runs.length - 1];
      if (last && WEEK_ORDER.indexOf(d) === WEEK_ORDER.indexOf(last[last.length - 1]) + 1) last.push(d); else runs.push([d]);
    }
    const said = [];
    for (const r of runs) {
      if (r.length >= 3) said.push(joinPairs([[WEEK_FA[r[0]], WEEK_EN[r[0]]], [WEEK_FA[r[r.length - 1]], WEEK_EN[r[r.length - 1]]]], 'dayTo'));
      else for (const d of r) said.push([WEEK_FA[d], WEEK_EN[d]]);
    }
    days = joinPairs(said, 'comma');
  }
  const time = w.from === w.to ? pair('allDay') : joinPairs([[w.from, w.from], [w.to, w.to]], 'timeTo');
  return joinPairs([days, time], 'comma');
}

/**
 * The admin's contact as a `tel:` number when it reads as a phone number
 * (Persian or Arabic-Indic digits too; spaces, dashes, dots and brackets
 * between them; a leading +), else null — then it shows as text.
 */
function telOf(contact) {
  const s = String(contact == null ? '' : contact)
    .replace(/[۰-۹]/g, (c) => String(c.charCodeAt(0) - 0x6f0))
    .replace(/[٠-٩]/g, (c) => String(c.charCodeAt(0) - 0x660)).trim();
  if (!/^\+?[0-9][0-9 ().-]{2,24}$/.test(s)) return null;
  const digits = s.replace(/[^0-9]/g, '');
  if (digits.length < 3 || digits.length > 15) return null;
  return (s[0] === '+' ? '+' : '') + digits;
}

/**
 * A hold's message: its reason's line with when it lifts, or the line without
 * (`<code>0`) — a code with no such pair as it is. `kind`: 'bad' (held), 'warn'
 * (one class off, the other still working).
 */
function holdMessage(code, until, now, calendar, kind = 'bad') {
  if (T[code + '0']) return until > now ? message(code, kind, whenText(until, now, calendar)) : message(code + '0', kind);
  return message(code, kind);
}

/** kbps as the page writes a speed: '512 kbps', '2 Mbps', '1.5 Mbps'. */
const rateText = (k) => (k >= 1000 ? `${Math.round(k / 100) / 10} Mbps` : `${k} kbps`);

/* ------------------------------ the look ------------------------------ */

/** The page's icons: inline SVG (24 × 24, the text's colour) — no file to fetch. */
const ICONS = {
  wifi: '<path d="M2.5 9.5a14 14 0 0 1 19 0"/><path d="M5.8 13a9.2 9.2 0 0 1 12.4 0"/><path d="M9.1 16.4a4.4 4.4 0 0 1 5.8 0"/><circle cx="12" cy="19.6" r="1.1" fill="currentColor" stroke="none"/>',
  hourglass: '<path d="M6 3h12M6 21h12"/><path d="M7.5 3v3.2a4.5 4.5 0 0 0 9 0V3"/><path d="M7.5 21v-3.2a4.5 4.5 0 0 1 9 0V21"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.2 2"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16.5 6.5l2.5 2.5M14 9l2 2"/>',
  bolt: '<path d="M13 2.5L4.5 13.5H11l-1 8 8.5-11H12l1-8z"/>',
  chat: '<path d="M4 5h16v11H9l-5 4z"/><path d="M8 9.5h8M8 12.5h5"/>',
  phone: '<path d="M5 3.5h3.6l1.8 4.6-2.3 1.4a11.5 11.5 0 0 0 6.4 6.4l1.4-2.3 4.6 1.8V19a2 2 0 0 1-2 2A17.5 17.5 0 0 1 3 5.5a2 2 0 0 1 2-2z"/>',
  eye: '<path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z"/><circle cx="12" cy="12" r="3"/><path d="M4 4l16 16"/>',
  check: '<circle cx="12" cy="12" r="9"/><path d="M8 12.3l2.7 2.7L16 9.6"/>',
  alert: '<circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5"/><circle cx="12" cy="16.4" r="1" fill="currentColor" stroke="none"/>',
  plus: '<circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/>',
  out: '<path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4"/><path d="M10 8l-4 4 4 4M6 12h9"/>',
  pin: '<path d="M7 3h10v5l2 4H5l2-4z"/><path d="M12 12v9"/>'
};
const icon = (name, size = 20, cls = '') => `<svg class="i${cls ? ' ' + cls : ''}" viewBox="0 0 24 24" width="${size}" height="${size}" aria-hidden="true" focusable="false" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICONS[name]}</svg>`;

const CSS = [
  // the colours: the app's own (its orange), light and dark as the device is set
  ':root{color-scheme:light dark;--bg:#f2f4f7;--glow:rgba(184,80,13,.11);--card:#fff;--fg:#141a22;--muted:#5b6574;--line:#e1e5eb;--field:#f6f7f9;--track:#e8ecf1;',
  '--accent:#b8500d;--accent-fg:#fff;--accent-soft:rgba(184,80,13,.1);--ok:#0f7d52;--ok-soft:rgba(15,125,82,.1);--warn:#9a6200;--warn-soft:rgba(176,112,0,.12);',
  '--bad:#c0392b;--bad-soft:rgba(192,57,43,.09);--shadow:0 1px 2px rgba(16,24,40,.05),0 14px 36px rgba(16,24,40,.08)}',
  '@media (prefers-color-scheme:dark){:root{--bg:#0b0d11;--glow:rgba(255,143,77,.13);--card:#151a21;--fg:#eef1f5;--muted:#9aa5b3;--line:#262d37;--field:#10141a;--track:#262d37;',
  '--accent:#ff8f4d;--accent-fg:#1d0e04;--accent-soft:rgba(255,143,77,.13);--ok:#4ade9b;--ok-soft:rgba(74,222,155,.11);--warn:#f0b955;--warn-soft:rgba(240,185,85,.12);',
  '--bad:#ff6b6b;--bad-soft:rgba(255,107,107,.12);--shadow:0 1px 2px rgba(0,0,0,.3),0 18px 44px rgba(0,0,0,.38)}}',
  '*{box-sizing:border-box}',
  'html{-webkit-text-size-adjust:100%;text-size-adjust:100%}',
  'body{margin:0;min-height:100vh;display:flex;flex-direction:column;padding:28px 16px 32px;background-color:var(--bg);background-image:radial-gradient(1100px 460px at 50% -160px,var(--glow),transparent 70%);background-repeat:no-repeat;',
  'color:var(--fg);font:16px/1.65 Vazirmatn,Vazir,system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans Arabic",Tahoma,sans-serif}',
  'main{width:100%;max-width:440px;margin:auto;background:var(--card);border:1px solid var(--line);border-radius:22px;box-shadow:var(--shadow);padding:28px 22px 24px}',
  '.wide{max-width:470px}',
  'h1{font-size:22px;line-height:1.4;margin:16px 0 0;font-weight:800;letter-spacing:-.01em}',
  'h2{font-size:15px;line-height:1.5;margin:0;font-weight:700}',
  'p{margin:0}',
  '.en{display:block;color:var(--muted);font-size:13px;line-height:1.5;direction:ltr;text-align:right;font-weight:400;letter-spacing:0}',
  // the page runs right to left: the English after a label sits on its left, the gap on its right
  '.en-i{color:var(--muted);font-size:13px;font-weight:400;margin-right:.55em;letter-spacing:0}',
  '.center{text-align:center}.center .en{text-align:center}',
  '.mark{display:inline-flex;width:56px;height:56px;border-radius:18px;align-items:center;justify-content:center;background:var(--accent-soft);color:var(--accent)}',
  '.intro{margin-top:10px;color:var(--muted);font-size:15px}',
  '.vh{position:absolute;width:1px;height:1px;margin:-1px;padding:0;border:0;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}',
  // the two ways: radio inputs and CSS, no script
  '.ways{position:relative}',
  '.seg{display:grid;grid-template-columns:1fr 1fr;gap:4px;padding:4px;margin:22px 0 2px;background:var(--track);border-radius:16px}',
  '.seg label{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:54px;padding:6px 8px;border-radius:12px;cursor:pointer;color:var(--muted);font-weight:700;font-size:15px;line-height:1.35;text-align:center;-webkit-tap-highlight-color:transparent}',
  '.seg label .en{text-align:center;font-size:12px;font-weight:500}',
  '#w-user:checked~.seg label[for=w-user],#w-code:checked~.seg label[for=w-code]{background:var(--card);color:var(--fg);box-shadow:0 1px 3px rgba(16,24,40,.14)}',
  '#w-user:focus-visible~.seg label[for=w-user],#w-code:focus-visible~.seg label[for=w-code]{outline:2px solid var(--accent);outline-offset:2px}',
  '#w-user:checked~#f-code,#w-code:checked~#f-user{display:none}',
  // fields and buttons: big enough for a thumb
  '.field{margin-top:18px}',
  '.field>label{display:block;font-weight:700;font-size:15px;margin-bottom:8px}',
  'input[type=text],input[type=password]{display:block;width:100%;height:54px;padding:0 16px;border:1.5px solid var(--line);border-radius:14px;background:var(--field);color:var(--fg);font:inherit;font-size:17px;direction:ltr;text-align:left;-webkit-appearance:none;appearance:none;transition:border-color .15s,box-shadow .15s}',
  'input[type=text]:focus,input[type=password]:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 4px var(--accent-soft);background:var(--card)}',
  '.pw{position:relative}.pw input{padding-left:58px}',
  '.eye{position:absolute;left:5px;top:5px;width:44px;height:44px;display:flex;align-items:center;justify-content:center;border:0;border-radius:11px;background:transparent;color:var(--muted);cursor:pointer}',
  '.eye[hidden],.eye .i2,.eye.on .i1{display:none}.eye.on .i2{display:block}',
  '.eye:focus-visible{outline:2px solid var(--accent)}',
  '.code input{height:62px;font:600 24px/1 ui-monospace,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;letter-spacing:.16em;text-align:center;text-transform:uppercase}',
  '.code input::placeholder{color:var(--muted);opacity:.45;letter-spacing:.16em}',
  '.hint{margin-top:8px;font-size:13px;color:var(--muted)}.hint .en{font-size:12px}',
  '.btn{display:flex;flex-direction:column;align-items:center;justify-content:center;width:100%;min-height:56px;margin-top:22px;padding:8px 16px;border:0;border-radius:15px;background:var(--accent);color:var(--accent-fg);font:inherit;font-weight:800;font-size:17px;line-height:1.3;cursor:pointer;text-decoration:none;-webkit-tap-highlight-color:transparent}',
  '.btn .en{color:inherit;opacity:.82;text-align:center;font-size:12.5px;font-weight:500}',
  '.btn:focus-visible{outline:3px solid var(--accent);outline-offset:3px}',
  '.btn:active{transform:translateY(1px)}',
  '.btn.ghost{background:transparent;color:var(--fg);border:1.5px solid var(--line)}.btn.ghost .en{color:var(--muted);opacity:1}',
  '.btn.soft{background:var(--accent-soft);color:var(--accent)}',
  '.row{display:flex;align-items:center;justify-content:center;gap:10px}',
  // messages: a tinted box with a thin edge of its tone, the text in the page's own colour
  '.msg{display:flex;gap:10px;align-items:flex-start;margin:20px 0 0;padding:12px 14px;border-radius:14px;border:1px solid transparent;font-size:15px;line-height:1.55;color:var(--fg)}',
  '.msg>.i{flex:none;margin-top:2px}',
  '.msg.bad{background:var(--bad-soft);border-color:var(--bad)}.msg.bad>.i{color:var(--bad)}',
  '.msg.ok{background:var(--ok-soft);border-color:var(--ok)}.msg.ok>.i{color:var(--ok)}',
  '.msg.warn{background:var(--warn-soft);border-color:var(--warn)}.msg.warn>.i{color:var(--warn)}',
  // the status page
  '.who{display:flex;align-items:center;gap:14px}.who .mark{flex:none;width:52px;height:52px;border-radius:16px}.who h1{margin:0;font-size:21px}.who>div{min-width:0}',
  '.chip{display:inline-block;margin-top:6px;padding:2px 12px;border-radius:999px;background:var(--track);font:600 13px/1.8 ui-monospace,"SF Mono",Menlo,Consolas,monospace;direction:ltr;unicode-bidi:isolate}',
  '.state{display:flex;align-items:center;gap:12px;margin-top:18px;padding:12px 16px;border-radius:16px;background:var(--ok-soft);font-weight:700;line-height:1.45}',
  '.state .en{font-weight:500}',
  '.dot{flex:none;width:12px;height:12px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 5px var(--ok-soft)}',
  '.state.bad{background:var(--bad-soft)}.state.bad .dot{background:var(--bad);box-shadow:0 0 0 5px var(--bad-soft)}',
  '.state.warn{background:var(--warn-soft)}.state.warn .dot{background:var(--warn);box-shadow:0 0 0 5px var(--warn-soft)}',
  '.usage{margin-top:16px;padding:20px 16px 16px;border-radius:18px;background:var(--field);border:1px solid var(--line);text-align:center}',
  '.ring{--p:0;--c:var(--ok);position:relative;width:176px;height:176px;margin:0 auto;border-radius:50%;background:var(--track);background:conic-gradient(var(--c) calc(var(--p) * 1%),var(--track) 0)}',
  '.ring::after{content:"";position:absolute;top:15px;right:15px;bottom:15px;left:15px;border-radius:50%;background:var(--field)}',
  '.ring.warn{--c:var(--warn)}.ring.bad{--c:var(--bad)}',
  '.ring-in{position:absolute;top:15px;right:15px;bottom:15px;left:15px;z-index:1;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:0 12px;line-height:1.35}',
  '.ring-in b{font-size:27px;font-weight:800;direction:ltr;unicode-bidi:isolate;letter-spacing:-.01em}',
  '.ring-in .s{font-size:13px;color:var(--muted)}.ring-in .en{text-align:center;font-size:12px}',
  '.ring-cap{margin-top:12px;font-weight:700}.ring-cap .en{text-align:center}',
  '.stats{display:grid;grid-template-columns:1fr 1fr;gap:10px;text-align:start}',
  '.stat{padding:14px;border-radius:14px;background:var(--card);border:1px solid var(--line)}',
  '.stat .k{font-size:13px;color:var(--muted);line-height:1.45}.stat .k .en{font-size:12px}',
  '.stat b{display:block;margin-top:6px;font-size:20px;direction:ltr;text-align:right;unicode-bidi:isolate}',
  '.nocap{margin-top:10px;font-size:13px;color:var(--muted)}.nocap .en{text-align:center}',
  '.lims{margin-top:18px}',
  '.lims h2{color:var(--muted);font-size:13px;font-weight:700;margin-bottom:4px}',
  '.lim{padding:12px 0;border-top:1px solid var(--line)}.lim:first-of-type{border-top:0}',
  '.lim-h{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;font-size:15px;font-weight:700;line-height:1.45}',
  '.lim-h .en{font-size:12px;font-weight:400}',
  '.num{direction:ltr;unicode-bidi:isolate;white-space:nowrap;font-variant-numeric:tabular-nums;color:var(--muted);font-weight:600;font-size:14px}',
  '.bar{height:10px;margin-top:8px;border-radius:999px;background:var(--track);overflow:hidden}',
  '.bar>i{display:block;height:100%;min-width:3px;border-radius:999px;background:var(--ok)}',
  '.bar.warn>i{background:var(--warn)}.bar.bad>i{background:var(--bad)}',
  '.lim-f{margin-top:6px;font-size:13px;color:var(--muted)}.lim-f .en{display:inline;margin-right:.6em;font-size:12px}',
  '.facts{list-style:none;margin:18px 0 0;padding:0}',
  '.facts li{display:flex;gap:14px;align-items:flex-start;padding:12px 0;border-top:1px solid var(--line)}.facts li:first-child{border-top:0}',
  '.ic{flex:none;width:40px;height:40px;border-radius:12px;display:flex;align-items:center;justify-content:center;background:var(--accent-soft);color:var(--accent)}',
  '.fact{min-width:0;flex:1}',
  '.fact .k{font-size:13px;color:var(--muted);line-height:1.5}',
  '.fact .v{margin-top:2px;font-weight:700;line-height:1.5;overflow-wrap:anywhere}.fact .v .en{font-weight:500}',
  '.rate{display:block;direction:ltr;text-align:right;unicode-bidi:isolate;font-size:17px}',
  '.why{display:block;color:var(--muted);font-weight:500;font-size:14px}.why .en{font-size:12.5px}',
  '.ltr{direction:ltr;unicode-bidi:isolate}',
  '.note{margin-top:18px;padding:16px;border-radius:16px;background:var(--field);border:1px solid var(--line)}',
  '.note h2{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px}',
  '.note p{margin-top:8px;font-size:16px;line-height:1.7;overflow-wrap:anywhere}',
  '.tel{display:flex;align-items:center;gap:12px;margin-top:12px;padding:10px 14px;min-height:52px;border-radius:14px;background:var(--card);border:1px solid var(--line);color:var(--fg);text-decoration:none}',
  '.tel .ic{width:34px;height:34px;border-radius:10px;background:var(--ok-soft);color:var(--ok)}',
  '.who-k{display:flex;flex-direction:column;min-width:0}.who-k .k{font-size:13px;color:var(--muted);line-height:1.4}.who-k .k .en{font-size:12px}',
  '.tel b{margin-top:2px;direction:ltr;text-align:right;unicode-bidi:isolate;font-size:17px;letter-spacing:.02em;overflow-wrap:anywhere}',
  'a.tel:focus-visible{outline:3px solid var(--accent);outline-offset:2px}',
  '.req{margin-top:18px}.req .btn{margin-top:0}.req .hint{text-align:center}.req .hint .en{text-align:center}',
  '.pending{display:flex;gap:10px;align-items:flex-start;padding:12px 14px;border-radius:14px;background:var(--ok-soft);font-size:15px}.pending>.i{flex:none;margin-top:2px;color:var(--ok)}',
  '.muted{margin-top:18px;color:var(--muted);font-size:14px}',
  '.back{margin-top:22px;padding-top:18px;border-top:1px dashed var(--line);font-size:14px;color:var(--muted)}',
  '.addr{display:block;margin-top:8px;padding:8px 12px;border-radius:10px;background:var(--field);border:1px solid var(--line);color:var(--fg);direction:ltr;text-align:left;font:14px/1.5 ui-monospace,"SF Mono",Menlo,Consolas,monospace;overflow-wrap:anywhere;-webkit-user-select:all;user-select:all}',
  '.foot{margin-top:16px;font-size:12px;color:var(--muted);text-align:center}.foot .en{text-align:center;font-size:11.5px}',
  '@media (max-width:370px){main{padding:24px 16px 20px;border-radius:18px}.ring{width:168px;height:168px}.ring-in b{font-size:24px}}',
  '@media (prefers-reduced-motion:reduce){*{transition:none!important}}'
].join('\n');

/**
 * The page's one script: the show-password eye (the button is in the page,
 * `hidden`, and shown only here — where no script runs, there is no dead
 * button). Allowed by its hash in the CSP; nothing else on the page may run.
 */
const SCRIPT = '(function(){var p=document.getElementById("p"),b=document.getElementById("eye");if(!p||!b)return;b.hidden=false;' +
  'b.addEventListener("click",function(){var s=p.type==="password";p.type=s?"text":"password";b.setAttribute("aria-pressed",s?"true":"false");' +
  'b.className=s?"eye on":"eye";p.focus();});})();';
const SCRIPT_HASH = 'sha256-' + crypto.createHash('sha256').update(SCRIPT, 'utf8').digest('base64');
/** Nothing from anywhere; the inline styles; the one script by its hash; forms only to this page. */
const CSP = `default-src 'none'; style-src 'unsafe-inline'; script-src '${SCRIPT_HASH}'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`;

/** `opts`: title (a T key), refresh (s, 0 = none), script (the eye's), wide (the status page's card). */
function page(body, { title = 'title', refresh = 0, script = false, wide = false } = {}) {
  return '<!doctype html>\n<html lang="fa" dir="rtl">\n<head>\n<meta charset="utf-8">\n' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">\n' +
    '<meta name="color-scheme" content="light dark">\n' +
    '<meta name="theme-color" content="#f2f4f7" media="(prefers-color-scheme: light)">\n' +
    '<meta name="theme-color" content="#0b0d11" media="(prefers-color-scheme: dark)">\n' +
    // to "/" by name: after POST /login the address is /login, and a reload of it would ask to post again
    (refresh ? `<meta http-equiv="refresh" content="${refresh};url=/">\n` : '') +
    `<title>${esc(T[title][0])} · ${esc(T[title][1])}</title>\n<style>\n${CSS}\n</style>\n</head>\n<body>\n` +
    `<main${wide ? ' class="wide"' : ''}>\n${body}\n</main>\n${script ? `<script>${SCRIPT}</script>\n` : ''}</body>\n</html>\n`;
}

const MSG_ICON = { ok: 'check', warn: 'alert', bad: 'alert' };
function message(code, kind, n) {
  const k = kind === 'ok' || kind === 'warn' ? kind : 'bad';
  return `<p class="msg ${k}" role="${k === 'ok' ? 'status' : 'alert'}">${icon(MSG_ICON[k])}<span>${both(code, n)}</span></p>`;
}

/**
 * The sign-in form: the username and password's tab first (the first form in
 * the page: scripts/probe-lan-portal.js loginForm posts to it), the code's
 * second — each its own form, so each posts only its own fields. `fill`:
 * { u, code, way: 'user' | 'code' } — what ?u= / ?code= or a refused form
 * typed (escaped here, like every value); `way` defaults to the code's tab
 * when there is a code.
 */
function loginPage(msg, fill = {}) {
  const u = typed(fill.u), code = typed(fill.code);
  const way = fill.way === 'code' || fill.way === 'user' ? fill.way : (code ? 'code' : 'user');
  const sel = (w) => (way === w ? ' checked' : '');
  return page([
    `<header class="center"><span class="mark">${icon('wifi', 30)}</span>`,
    `<h1>${both('title')}</h1>`,
    `<p class="intro">${both('intro')}</p></header>`,
    msg || '',
    '<div class="ways">',
    `<input type="radio" name="way" id="w-user" class="vh" aria-controls="f-user"${sel('user')}>`,
    `<input type="radio" name="way" id="w-code" class="vh" aria-controls="f-code"${sel('code')}>`,
    `<div class="seg"><label for="w-user">${both('wayUser')}</label><label for="w-code">${both('wayCode')}</label></div>`,
    '<form id="f-user" method="post" action="/login">',
    `<div class="field"><label for="u">${inl('username')}</label>`,
    `<input id="u" name="username" dir="ltr" autocomplete="username" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="${MAX_TYPED}" required type="text"${u ? ` value="${esc(u)}"` : ''}></div>`,
    `<div class="field"><label for="p">${inl('password')}</label><div class="pw">`,
    `<input id="p" name="password" type="password" dir="ltr" autocomplete="current-password" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="256" required${u && way === 'user' ? ' autofocus' : ''}>`,
    `<button type="button" id="eye" class="eye" aria-controls="p" aria-pressed="false" aria-label="${esc(T.showPassword[0])} · ${esc(T.showPassword[1])}" title="${esc(T.showPassword[0])} · ${esc(T.showPassword[1])}" hidden>${icon('eye', 22, 'i1')}${icon('eyeOff', 22, 'i2')}</button>`,
    '</div></div>',
    `<button type="submit" class="btn">${both('signIn')}</button>`,
    '</form>',
    '<form id="f-code" method="post" action="/login" class="code">',
    `<div class="field"><label for="c">${inl('code')}</label>`,
    `<input id="c" name="code" type="text" dir="ltr" autocomplete="off" autocapitalize="characters" autocorrect="off" spellcheck="false" maxlength="${MAX_TYPED}" placeholder="XXXX-XXXX" aria-describedby="c-hint" required${code ? ` value="${esc(code)}"` : ''}>`,
    `<p class="hint" id="c-hint">${both('codeHint')}</p></div>`,
    `<button type="submit" class="btn">${both('signIn')}</button>`,
    '</form>',
    '</div>'
  ].join('\n'), { script: true });
}

const gb = (bytes) => (Math.max(0, Number(bytes) || 0) / GIB).toFixed(2) + ' GB';
/** '0.40 / 1.00 GB': one unit for the pair. */
const gbOf = (used, full) => `${(Math.max(0, Number(used) || 0) / GIB).toFixed(2)} / ${gb(full)}`;

function timeLeft(ms) {
  const m = Math.max(1, Math.round(ms / 60000));
  return m >= 120 ? both('hours', Math.round(m / 60)) : both('minutes', m);
}

const KIND_KEY = { total: 'kindTotal', vpn: 'kindVpn', direct: 'kindDirect' };
const PERIOD_KEY = { day: 'periodDay', month: 'periodMonth', none: 'periodNone' };

/** One limit as numbers: its name ([fa, en]), used, the whole (its top-up in it), what is left, the share used (0–100), over. */
function meterOf(m) {
  const [kf, ke] = pair(KIND_KEY[m.kind] || 'kindTotal');
  const named = m.period === null ? pair('used') : (() => { const [pf, pe] = pair(PERIOD_KEY[m.period] || 'periodMonth'); return [`${kf} · ${pf}`, `${ke} · ${pe}`]; })();
  const used = Math.max(0, Number(m.bytes) || 0);
  const full = (Number(m.capBytes) || 0) + (Number(m.extraBytes) || 0);
  const rest = full - used;
  const over = !!m.over || rest <= 0;
  const share = over ? 100 : Math.max(0, Math.min(100, Math.round((used / full) * 100)));
  return { named, used, full, rest, over, share, tone: over ? 'bad' : share >= 80 ? 'warn' : '' };
}

/** The share as a progressbar's words, for a screen reader: "VPN · امروز · VPN · today". */
const ariaOf = (named) => esc(`${named[0]} · ${named[1]}`);

/** The limit closest to its end, as a ring: what is left in the middle. */
function ringOf(m) {
  const x = meterOf(m);
  const [of, oe] = pair('leftOf', [lrm(gb(x.full)), gb(x.full)]);
  const mid = x.over
    ? `<b>${esc(T.usedUp[0])}</b><span class="en" lang="en" dir="ltr">${esc(T.usedUp[1])}</span><span class="s ltr">${gbOf(x.used, x.full)}</span>`
    : `<b class="ltr">${gb(x.rest)}</b><span class="s">${esc(of)}</span><span class="en" lang="en" dir="ltr">${esc(oe)}</span>`;
  return `<div class="ring${x.tone ? ' ' + x.tone : ''}" style="--p:${x.share}" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${x.share}" aria-label="${ariaOf(x.named)}">` +
    `<div class="ring-in">${mid}</div></div>\n<p class="ring-cap">${two(x.named)}</p>`;
}

/** One limit as a bar: "VPN · today" and "0.40 / 1.00 GB", the bar, "0.60 GB left". */
function meterRow(m) {
  const x = meterOf(m);
  const tail = x.over ? both('usedUp') : both('left', [lrm(gb(x.rest)), gb(x.rest)]);
  return `<div class="lim"><div class="lim-h"><span>${two(x.named)}</span><span class="num">${gbOf(x.used, x.full)}</span></div>` +
    `<div class="bar${x.tone ? ' ' + x.tone : ''}" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${x.share}" aria-label="${ariaOf(x.named)}"><i style="width:${x.share}%"></i></div>` +
    `<p class="lim-f">${tail}</p></div>`;
}

/** The speed now ("↓ 2 Mbps ↑ 1 Mbps") and, on the lines under it, why ("peak hours, after 2 GB today"). */
function speedValue(sp) {
  const rate = [sp.down ? `↓ ${rateText(sp.down)}` : '', sp.up ? `↑ ${rateText(sp.up)}` : ''].filter(Boolean).join(' ');
  const whys = (Array.isArray(sp.why) ? sp.why : []).map((w) => {
    if (w === 'base') return pair('speedBase');
    if (w === 'hours') return pair('speedHours');
    if (w && typeof w === 'object' && Number(w.after) > 0) {
      const [pf, pe] = pair(PERIOD_KEY[w.period] || 'periodMonth');
      return pair('speedAfter', [`${lrm(w.after + ' GB')} ${pf}`, `${w.after} GB ${pe}`]);
    }
    return null;
  }).filter(Boolean);
  const why = whys.length ? `<span class="why">${esc(whys.map(x => x[0]).join('، '))}<span class="en" lang="en" dir="ltr">${esc(whys.map(x => x[1]).join(', '))}</span></span>` : '';
  return `<span class="rate">${esc(rate)}</span>${why}`;
}

/** A fact of the status page: an icon, its label (Persian · English), its value. */
const fact = (ic, key, value) => `<li><span class="ic">${icon(ic)}</span><div class="fact"><div class="k">${inl(key)}</div><div class="v">${value}</div></div></li>`;

/** "3 days 4 h left — until 1 Azar" (a countdown and the date). */
function leftUntil(until, now, calendar) {
  const [df, de] = durText(until - now);
  const [wf, we] = whenText(until, now, calendar);
  const [lf, le] = pair('left', [df, de]);
  const [uf, ue] = pair('untilAt', [wf, we]);
  return two([`${lf} — ${uf}`, `${le} — ${ue}`]);
}

/** The status's usage block: the ring and the bars — or, with no limit, today and this month; a meter of before, its one cap. */
function usageBlock(st) {
  let meters = Array.isArray(st.meters) ? st.meters.filter((m) => m && (Number(m.capBytes) || 0) + (Number(m.extraBytes) || 0) > 0) : [];
  if (!meters.length && !st.totals && st.usage && Number(st.usage.quotaBytes) > 0) {
    meters = [{ kind: 'total', period: null, bytes: st.usage.bytes, capBytes: st.usage.quotaBytes, extraBytes: 0, over: !!st.usage.over }];
  }
  if (meters.length) {
    // the ring: the one closest to its end (the one that stops this device first)
    const main = meters.reduce((a, m) => (meterOf(m).share > meterOf(a).share ? m : a), meters[0]);
    const out = [`<section class="usage" aria-label="${esc(T.limits[0])} · ${esc(T.limits[1])}">${ringOf(main)}</section>`];
    if (meters.length > 1) out.push(`<section class="lims"><h2>${inl('limits')}</h2>\n${meters.map(meterRow).join('\n')}\n</section>`);
    return out.join('\n');
  }
  const stat = (key, bytes) => `<div class="stat"><div class="k">${both(key)}</div><b>${gb(bytes)}</b></div>`;
  if (st.totals) {
    return `<section class="usage"><div class="stats">${stat('today', st.totals.day)}${stat('thisMonth', st.totals.month)}</div><p class="nocap">${both('noCap')}</p></section>`;
  }
  const u = st.usage || null;
  return `<section class="usage"><div class="stats" style="grid-template-columns:1fr">${stat('used', u ? u.bytes : 0)}</div><p class="nocap">${both('noCap')}</p></section>`;
}

/**
 * `st`: { name, username, via, until?, held?, part?, holdUntil?, calendar?,
 * usage?: { bytes, quotaBytes }, meters?: [{ kind, period, bytes, capBytes,
 * extraBytes, until, over }], totals?: { day, month }, speed?: { down, up,
 * why }, expiresAt? (0 = never), voucher?: { hours, activatedAt, expiresAt } |
 * null, schedule?: { days, from, to } | null, note?, contact?, requests?
 * (allowed), request?: { at } | null } (router/index.js statusOf). `meters` —
 * the limits that are set — stand in for the one cap's usage; with no limit,
 * `totals`; a meter of before has neither, and its one cap shows as it always
 * has. `back`: this page's addresses to bookmark (its short name's first),
 * since a device that is signed in is no longer sent here by itself.
 * `notice`: a message on top (a top-up request's answer).
 */
function statusPage(st, now, back = [], notice = '') {
  const voucher = st.voucher && typeof st.voucher === 'object' ? st.voucher : null;
  const name = String(st.name || st.username || '');
  const parts = [];
  // who: a greeting, the username (the code, for a card) under it when the name does not already say it
  const chip = st.username && (voucher || String(st.username).toLowerCase() !== name.toLowerCase()) ? `<span class="chip">${esc(st.username)}</span>` : '';
  parts.push(`<header class="who"><span class="mark">${icon('wifi', 26)}</span><div>${voucher ? `<h1>${both('card')}</h1>` : `<h1>${both('hello', name)}</h1>`}${chip}</div></header>`);
  // the state: connected, paused, or one class off
  const part = !st.held && (st.part === 'vpn' || st.part === 'direct');
  const tone = st.held ? 'bad' : part ? 'warn' : '';
  parts.push(`<p class="state${tone ? ' ' + tone : ''}" role="status"><span class="dot"></span><span>${both(st.held ? 'heldTitle' : part ? 'partTitle' : 'connected')}</span></p>`);
  if (st.held) parts.push(holdMessage(st.held, Number(st.holdUntil) || 0, now, st.calendar));
  else if (part) parts.push(holdMessage(st.part === 'vpn' ? 'partVpn' : 'partDirect', Number(st.holdUntil) || 0, now, st.calendar, 'warn'));
  if (notice) parts.push(notice);
  parts.push(usageBlock(st));
  // the facts: time left (the card's, else the account's), the session, the speed, the allowed hours
  const facts = [];
  let ends = 0;   // when the card's or the account's time is up (0: never)
  if (voucher && Number(voucher.hours) > 0) {
    const until = Number(voucher.expiresAt) || 0;
    if (until > now) { ends = until; facts.push(fact('hourglass', 'timeCard', leftUntil(until, now, st.calendar))); }
    else if (!(Number(voucher.activatedAt) > 0)) facts.push(fact('hourglass', 'timeCard', both('fromFirstUse', Number(voucher.hours))));
  } else if (!voucher && Number(st.expiresAt) > now) {
    ends = Number(st.expiresAt);
    facts.push(fact('hourglass', 'timeAccount', leftUntil(ends, now, st.calendar)));
  }
  // the session's hours — unless the card or the account runs out first (then that is the time that counts)
  if (st.via === 'login' && st.until && !(ends && ends <= st.until)) facts.push(fact('key', 'session', timeLeft(st.until - now)));
  if (st.speed && (st.speed.down || st.speed.up)) facts.push(fact('bolt', 'speed', speedValue(st.speed)));
  const hours = scheduleText(st.schedule);
  if (hours) facts.push(fact('clock', 'allowed', two(hours)));
  if (facts.length) parts.push(`<ul class="facts">\n${facts.join('\n')}\n</ul>`);
  // the admin's word: the note, the contact (a call away when it is a number)
  const note = String(st.note || '').trim(), contact = String(st.contact || '').trim();
  if (note || contact) {
    const tel = contact ? telOf(contact) : null;
    const inner = `<span class="ic">${icon('phone', 18)}</span><span class="who-k"><span class="k">${both('contact')}</span><b${tel ? '' : ' dir="auto"'}>${esc(contact)}</b></span>`;
    const reach = !contact ? '' : tel ? `<a class="tel" href="tel:${esc(tel)}">${inner}</a>` : `<p class="tel">${inner}</p>`;
    parts.push(`<section class="note"><h2>${icon('chat', 18)}${inl('noteTitle')}</h2>${note ? `<p dir="auto">${esc(note)}</p>` : ''}${reach}</section>`);
  }
  // "request a top-up": sent already (and when), or the button — for an account that can run out of something
  const pending = st.request && Number(st.request.at) > 0 ? Number(st.request.at) : 0;
  const canRunOut = (Array.isArray(st.meters) && st.meters.length > 0) || (st.usage && Number(st.usage.quotaBytes) > 0) || Number(st.expiresAt) > 0 || !!voucher;
  if (pending) parts.push(`<div class="req"><p class="pending" role="status">${icon('check')}<span>${both('reqPending', pastText(pending, now, st.calendar))}</span></p></div>`);
  else if (st.requests && canRunOut) {
    parts.push(`<form class="req" method="post" action="/request"><button type="submit" class="btn soft"><span class="row">${icon('plus')}<span>${esc(T.reqButton[0])}</span></span><span class="en" lang="en" dir="ltr">${esc(T.reqButton[1])}</span></button><p class="hint">${both('reqHint')}</p></form>`);
  }
  if (st.via === 'admin') parts.push(`<p class="muted">${both('assignedHere')}</p>`);
  else parts.push(`<form method="post" action="/logout"><button type="submit" class="btn ghost"><span class="row">${icon('out')}<span>${esc(T.signOut[0])}</span></span><span class="en" lang="en" dir="ltr">${esc(T.signOut[1])}</span></button></form>`);
  if (back.length) parts.push(`<p class="back">${both('again')}${back.map((a) => `<span class="addr">${esc(a)}</span>`).join('')}</p>`);
  parts.push(`<p class="foot">${both('refreshing')}</p>`);
  return page(parts.join('\n'), { title: st.held ? 'heldTitle' : 'connected', refresh: REFRESH_S, wide: true });
}

/** A refusal's T key: a code's own words for a code sign-in ("This code is not valid"), the account's otherwise. */
const CODE_WORDS = { bad: 'badCode', expired: 'codeExpired', over: 'codeOver', total: 'codeOver', maxDevices: 'codeMax' };
/** A top-up request's answer: its message and kind. */
const REQUEST_WORDS = { sent: ['reqSent', 'ok'], already: ['reqAlready', 'ok'], off: ['reqOff', 'bad'], nouser: ['reqNouser', 'bad'] };

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
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'same-origin',   // never 'no-referrer': its own form would post Origin "null"
      'Content-Security-Policy': CSP
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

  /** POST /login: a username and a password, or a card's code (the form's `code` field says which). */
  async function login(res, mac, form) {
    const byCode = form.has('code');
    const code = byCode ? typed(form.get('code')) : '';
    const username = byCode ? '' : String(form.get('username') || '');
    const fill = byCode ? { way: 'code', code } : { way: 'user', u: username };
    // an empty code is no guess: told so, not counted
    if (byCode && !code) return send(res, 400, loginPage(message('badCode', 'bad'), fill));
    if (recent(mac).length >= TRIES) return send(res, 429, loginPage(message('rate', 'bad'), fill), { 'Retry-After': '300' });
    const r = await api.signIn(byCode ? { mac, username: '', password: '', code } : { mac, username, password: form.get('password') || '' });
    if (!r || !r.ok) {
      fail(mac);
      const said = r && T[r.code] ? r.code : 'error';
      // a hold says when it lifts ("back at 08:00"); a code's refusals in a code's words; the rest as they always have
      const words = byCode && CODE_WORDS[said];
      const msg = words ? message(words, 'bad') : T[said + '0'] ? holdMessage(said, Number(r.until) || 0, now(), r.calendar) : message(said, 'bad', r && r.max);
      return send(res, said === 'bad' ? 401 : 403, loginPage(msg, fill));
    }
    fails.delete(mac);
    const st = r.status || await api.statusOf(mac);
    return send(res, 200, st ? statusPage(st, now(), back()) : loginPage());
  }

  /** POST /request: "request a top-up" — the controller's answer said on top of the status. */
  async function request(res, mac) {
    const r = typeof api.requestTopUp === 'function' ? await api.requestTopUp(mac) : { ok: false, code: 'off' };
    const [key, kind] = REQUEST_WORDS[r && r.code] || ['error', 'bad'];
    const st = await api.statusOf(mac);
    if (!st) return send(res, 403, loginPage(message('reqNouser', 'bad')));
    const at = st.request && Number(st.request.at) > 0 ? pastText(Number(st.request.at), now(), st.calendar) : null;
    const notice = key === 'reqAlready' && !at ? message('reqSent', 'ok') : message(key, kind, at);
    return send(res, kind === 'ok' ? 200 : 403, statusPage(st, now(), back(), notice));
  }

  async function handle(req, res) {
    const hostHeader = String(req.headers.host || '').toLowerCase();
    const mine = `${bound.host}:${bound.port}`.toLowerCase();
    // a device's own captive check (captive.apple.com, connectivitycheck…) lands here by DNAT: send it to the page's own address
    if (hostHeader !== mine) return redirect(res, origin() + '/');
    const [url, query = ''] = String(req.url || '/').split('?');
    const ip = req.socket && req.socket.remoteAddress;
    if (req.method === 'GET' || req.method === 'HEAD') {
      const mac = await api.macOf(ip);
      const st = mac ? await api.statusOf(mac) : null;
      if (st) return send(res, 200, statusPage(st, now(), back()));
      // ?u= / ?code=: a sign-in card's or a voucher card's QR — filled in, escaped
      let q;
      try { q = new URLSearchParams(query); } catch { q = new URLSearchParams(); }
      return send(res, 200, loginPage(mac ? '' : message('nomac', 'bad'), { u: q.get('u'), code: q.get('code') }));
    }
    if (req.method !== 'POST' || (url !== '/login' && url !== '/logout' && url !== '/request')) return send(res, 404, loginPage());
    // a form posted from any other page is not this device's own sign-in (nor its request, nor its sign-out)
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
    if (url === '/request') return request(res, mac);
    return login(res, mac, form);
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

module.exports = {
  createPortal, checkPassword, postedFromElsewhere, loginPage, statusPage, whenText, pastText, durText, scheduleText, telOf,
  T, TRIES, WINDOW_MS, SCRIPT, SCRIPT_HASH, CSP
};
