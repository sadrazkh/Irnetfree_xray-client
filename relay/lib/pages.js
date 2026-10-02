'use strict';
/**
 * The relay's own pages — login, the routers dashboard (with a freshly minted
 * token shown once), the router-offline page and the error page — small,
 * server-rendered, no script (the CSP allows none), English or Persian by
 * the `lang` cookie (`?lang=fa` / `?lang=en` on any relay page sets it).
 */

const STR = {
  en: {
    title: 'IRNetFree relay',
    login: 'Sign in', password: 'Password', signIn: 'Sign in',
    wrong: 'Wrong password.',
    tooMany: 'Too many attempts — try again in {m} min.',
    routers: 'Routers', addRouter: 'Add router', name: 'Name (e.g. Home)', add: 'Add',
    online: 'Online', offline: 'Offline', direct: 'direct', vpn: 'via VPN',
    lastSeen: 'last seen', never: 'never', justNow: 'just now', minAgo: '{n} min ago', hAgo: '{n} h ago', dAgo: '{n} d ago',
    open: 'Open', revoke: 'Revoke', logout: 'Log out', selected: 'selected', app: 'app',
    tokenTitle: 'Device token for {name}',
    tokenOnce: 'Shown once. On the router: LuCI → Services → IRNetFree → Remote access — paste it as the device token, enter this relay\'s address, enable.',
    noRouters: 'No routers yet. Add one, then pair it from LuCI.',
    offlineTitle: 'Router offline',
    offlineText: '{name} is not connected to this relay right now ({lastSeen}: {seen}).',
    offlineHint: 'The router dials this relay by itself. Check that it has internet and that remote access is enabled in LuCI; this page reloads every 10 s.',
    back: 'Routers', lang: 'فارسی',
    forbidden: 'Forbidden', notFound: 'Not found', tooLarge: 'The request is too large', timeout: 'The router did not answer in time',
    gone: 'The router went away while answering', noRouter: 'Choose a router first'
  },
  fa: {
    title: 'رله‌ی IRNetFree',
    login: 'ورود', password: 'رمز عبور', signIn: 'ورود',
    wrong: 'رمز اشتباه است.',
    tooMany: 'تلاش‌های زیاد — {m} دقیقهٔ دیگر دوباره امتحان کن.',
    routers: 'روترها', addRouter: 'افزودن روتر', name: 'نام (مثلاً خانه)', add: 'افزودن',
    online: 'آنلاین', offline: 'آفلاین', direct: 'مستقیم', vpn: 'از داخل VPN',
    lastSeen: 'آخرین اتصال', never: 'هرگز', justNow: 'همین الان', minAgo: '{n} دقیقه پیش', hAgo: '{n} ساعت پیش', dAgo: '{n} روز پیش',
    open: 'باز کردن', revoke: 'لغو توکن', logout: 'خروج', selected: 'انتخاب‌شده', app: 'نسخه',
    tokenTitle: 'توکن دستگاه برای {name}',
    tokenOnce: 'فقط همین یک بار نشان داده می‌شود. روی روتر: LuCI ← Services ← IRNetFree ← Remote access — این را به‌عنوان توکن دستگاه بچسبان، آدرس همین رله را بنویس و فعال کن.',
    noRouters: 'هنوز روتری نیست. یکی اضافه کن، بعد از LuCI جفتش کن.',
    offlineTitle: 'روتر آفلاین است',
    offlineText: '{name} الان به این رله وصل نیست ({lastSeen}: {seen}).',
    offlineHint: 'روتر خودش به این رله وصل می‌شود. مطمئن شو اینترنت دارد و دسترسی از راه دور در LuCI فعال است؛ این صفحه هر ۱۰ ثانیه تازه می‌شود.',
    back: 'روترها', lang: 'English',
    forbidden: 'مجاز نیست', notFound: 'پیدا نشد', tooLarge: 'درخواست خیلی بزرگ است', timeout: 'روتر به‌موقع جواب نداد',
    gone: 'روتر وسط جواب دادن قطع شد', noRouter: 'اول یک روتر انتخاب کن'
  }
};

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const normLang = (l) => (l === 'fa' ? 'fa' : 'en');
const t = (lang, key, vars = {}) => String(STR[normLang(lang)][key] || STR.en[key] || key).replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));

/** "5 min ago", "never" — for last-seen times. */
function ago(lang, when, now) {
  if (!when) return t(lang, 'never');
  const s = Math.max(0, Math.round((now - when) / 1000));
  if (s < 60) return t(lang, 'justNow');
  if (s < 3600) return t(lang, 'minAgo', { n: Math.round(s / 60) });
  if (s < 86400) return t(lang, 'hAgo', { n: Math.round(s / 3600) });
  return t(lang, 'dAgo', { n: Math.round(s / 86400) });
}

const CSS = `
:root{color-scheme:dark light}
body{margin:0;font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Vazirmatn",Tahoma,sans-serif;background:#0f1419;color:#e6edf3}
main{max-width:640px;margin:0 auto;padding:28px 20px 48px}
h1{font-size:22px;margin:0 0 20px}h2{font-size:17px;margin:28px 0 10px}
a{color:#58a6ff}form{margin:0}
input[type=text],input[type=password]{font:inherit;padding:9px 12px;border:1px solid #30363d;border-radius:8px;background:#161b22;color:inherit;width:100%;box-sizing:border-box}
button{font:inherit;padding:8px 14px;border:1px solid #30363d;border-radius:8px;background:#21262d;color:inherit;cursor:pointer}
button.primary{background:#238636;border-color:#2ea043;color:#fff}button.danger{color:#ff7b72}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:10px 0}
.card{border:1px solid #30363d;border-radius:12px;padding:14px 16px;margin:12px 0;background:#161b22}
.muted{color:#8b949e;font-size:14px}.err{color:#ff7b72;margin:10px 0}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:#8b949e;margin-inline-end:6px}.dot.on{background:#3fb950}
code.token{display:block;word-break:break-all;user-select:all;-webkit-user-select:all;font-size:15px;padding:12px;background:#0d1117;border:1px dashed #58a6ff;border-radius:8px;margin:10px 0}
.top{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:8px}.top .muted a{margin-inline-start:10px}
`;

function layout(lang, title, body, { refresh = null } = {}) {
  const l = normLang(lang);
  return `<!DOCTYPE html>
<html lang="${l}" dir="${l === 'fa' ? 'rtl' : 'ltr'}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'">
${refresh ? `<meta http-equiv="refresh" content="${Number(refresh)}">\n` : ''}<title>${esc(title)}</title>
<style>${CSS}</style>
</head>
<body><main>
${body}
</main></body>
</html>
`;
}

const langLink = (lang, page) => `<a href="${esc(page)}?lang=${normLang(lang) === 'fa' ? 'en' : 'fa'}">${esc(t(lang, 'lang'))}</a>`;

/** Both languages on the login page: nobody has chosen one yet. */
function loginPage({ lang = 'en', error = null, retryMin = null } = {}) {
  const l = normLang(lang);
  let err = '';
  if (error === 'wrong') err = `<p class="err">${esc(t('en', 'wrong'))} — ${esc(t('fa', 'wrong'))}</p>`;
  else if (error === 'tooMany') err = `<p class="err">${esc(t('en', 'tooMany', { m: retryMin }))} — ${esc(t('fa', 'tooMany', { m: retryMin }))}</p>`;
  const body = `<div class="top"><h1>${esc(t(l, 'title'))}</h1><span class="muted">${langLink(l, '/_relay/login')}</span></div>
<form method="post" action="/_relay/login" class="card">
<label for="pw">${esc(t('en', 'password'))} · ${esc(t('fa', 'password'))}</label>
<div class="row"><input id="pw" type="password" name="password" autocomplete="current-password" autofocus required></div>
${err}
<div class="row"><button class="primary" type="submit">${esc(t('en', 'signIn'))} · ${esc(t('fa', 'signIn'))}</button></div>
</form>`;
  return layout(l, t(l, 'title'), body);
}

/**
 * @param {{ lang, now, routers: Array<{id,name,online,path,version,lastSeen,selected}>, newToken: null|{id,name,token} }} p
 */
function dashboardPage({ lang = 'en', now, routers = [], newToken = null }) {
  const l = normLang(lang);
  const rows = routers.map((r) => `<li class="card" data-router-id="${esc(r.id)}">
<div class="row"><span class="dot${r.online ? ' on' : ''}"></span><strong>${esc(r.name)}</strong>
<span class="muted">${r.online ? esc(t(l, 'online')) + (r.path ? ' · ' + esc(t(l, r.path === 'vpn' ? 'vpn' : 'direct')) : '') : esc(t(l, 'offline'))}${r.version ? ' · ' + esc(t(l, 'app')) + ' ' + esc(r.version) : ''}</span>
${r.selected ? `<span class="muted">(${esc(t(l, 'selected'))})</span>` : ''}</div>
<div class="row muted">${esc(t(l, 'lastSeen'))}: ${esc(r.online ? t(l, 'justNow') : ago(l, r.lastSeen, now))}</div>
<div class="row">
<form method="post" action="/_relay/routers/${esc(r.id)}/open"><button class="primary" type="submit">${esc(t(l, 'open'))}</button></form>
<form method="post" action="/_relay/routers/${esc(r.id)}/revoke"><button class="danger" type="submit">${esc(t(l, 'revoke'))}</button></form>
</div></li>`).join('\n');
  const token = newToken ? `<div class="card">
<h2>${esc(t(l, 'tokenTitle', { name: newToken.name }))}</h2>
<code class="token" data-token="${esc(newToken.token)}">${esc(newToken.token)}</code>
<p class="muted">${esc(t(l, 'tokenOnce'))}</p>
</div>` : '';
  const body = `<div class="top"><h1>${esc(t(l, 'routers'))}</h1>
<span class="muted"><form method="post" action="/_relay/logout" style="display:inline"><button type="submit">${esc(t(l, 'logout'))}</button></form>${langLink(l, '/_relay/')}</span></div>
${token}
${routers.length ? `<ul style="list-style:none;padding:0;margin:0">${rows}</ul>` : `<p class="muted">${esc(t(l, 'noRouters'))}</p>`}
<h2>${esc(t(l, 'addRouter'))}</h2>
<form method="post" action="/_relay/routers" class="card">
<div class="row"><input type="text" name="name" maxlength="40" placeholder="${esc(t(l, 'name'))}" required></div>
<div class="row"><button class="primary" type="submit">${esc(t(l, 'add'))}</button></div>
</form>`;
  return layout(l, t(l, 'routers'), body, { refresh: newToken ? null : 15 });
}

function offlinePage({ lang = 'en', name, lastSeen, now }) {
  const l = normLang(lang);
  const body = `<h1>${esc(t(l, 'offlineTitle'))}</h1>
<div class="card"><p>${esc(t(l, 'offlineText', { name: name || '?', lastSeen: t(l, 'lastSeen'), seen: ago(l, lastSeen, now) }))}</p>
<p class="muted">${esc(t(l, 'offlineHint'))}</p>
<p><a href="/_relay/">${esc(t(l, 'back'))}</a></p></div>`;
  return layout(l, t(l, 'offlineTitle'), body, { refresh: 10 });
}

function errorPage({ lang = 'en', key = 'notFound', status = 404 }) {
  const l = normLang(lang);
  const body = `<h1>${esc(status)} — ${esc(t(l, key))}</h1><p><a href="/_relay/">${esc(t(l, 'back'))}</a></p>`;
  return layout(l, t(l, key), body);
}

module.exports = { loginPage, dashboardPage, offlinePage, errorPage, ago, t, esc, normLang, STR };
