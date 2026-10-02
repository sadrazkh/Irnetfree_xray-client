'use strict';
/**
 * The web UI on the router (flavor 'openwrt') after the owner's first install
 * of v1.16.0 (field report §3, items 1, 2, 6, 8, 10, 17, 18, 19) — and the
 * desktop, which must look exactly as it did except for the server-edit toast
 * (18) and the Hide-SNI wording (19).
 *
 * Everything runs app.js's own functions against a fake page: every element is
 * created on first use and remembers what was done to it, so a test reads back
 * what the user would see (t() returns the key, so the assertions name keys).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('node:vm');

const R = (f) => fs.readFileSync(path.join(__dirname, '..', 'src', 'renderer', f), 'utf8');
const HTML = R('index.html');
const APP = R('app.js');
const I18N = R('i18n.js');
const CSS = ['styles.css', 'home.css', 'lists.css', 'routing.css', 'settings.css', 'skins.css'].map(R).join('\n');

/** A top-level (async) function of app.js, as source. */
function fnSource(name) {
  let start = APP.indexOf(`\nfunction ${name}(`);
  if (start === -1) start = APP.indexOf(`\nasync function ${name}(`);
  assert.ok(start > -1, `app.js has no function ${name}`);
  let depth = 0, j = APP.indexOf('{', APP.indexOf(')', start));
  for (; j < APP.length; j++) {
    if (APP[j] === '{') depth++;
    else if (APP[j] === '}' && --depth === 0) break;
  }
  return APP.slice(start, j + 1);
}
/** A top-level `const NAME = [ … ];` of app.js, as source. */
function constSource(name) {
  const m = APP.match(new RegExp(`\\nconst ${name} = [\\[{][\\s\\S]*?\\n[\\]}];`));
  assert.ok(m, `app.js has no const ${name}`);
  return m[0];
}

/** One language's value of a key, from i18n.js (fa is the first table, en the second). */
function str(lang, key) {
  const enAt = I18N.indexOf('\n  en: {');
  assert.ok(enAt > 0, 'i18n.js has no en table');
  const part = lang === 'fa' ? I18N.slice(0, enAt) : I18N.slice(enAt);
  const m = part.match(new RegExp(`'${key.replace(/\./g, '\\.')}': '((?:[^'\\\\]|\\\\.)*)'`));
  assert.ok(m, `${lang} has no '${key}'`);
  return m[1].replace(/\\'/g, "'");
}
const definedOnceEach = (k) => assert.equal(I18N.split(`'${k}':`).length - 1, 2, `'${k}' is not defined exactly once in each of fa and en`);

/** The fake page. Elements are keyed by selector; closest()/querySelector() key off their element. */
function fakePage() {
  const els = new Map();
  let made = 0;
  const mk = (key) => {
    const cls = new Set();
    return {
      key, hidden: false, textContent: '', title: '', className: '', innerHTML: '', disabled: false,
      checked: false, value: '', tabIndex: 0, attrs: {}, dataset: {}, style: {}, children: [], scrolled: null,
      classList: {
        add: (...c) => c.forEach((x) => cls.add(x)),
        remove: (...c) => c.forEach((x) => cls.delete(x)),
        toggle: (c, on) => { const v = on === undefined ? !cls.has(c) : !!on; if (v) cls.add(c); else cls.delete(c); return v; },
        contains: (c) => cls.has(c)
      },
      setAttribute(k, v) { this.attrs[k] = String(v); },
      getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; },
      removeAttribute(k) { delete this.attrs[k]; },
      closest(sel) { return get(key + ' <' + sel); },
      querySelector(sel) { return get(key + ' ' + sel); },
      appendChild(c) { this.children.push(c); return c; },
      append(...c) { this.children.push(...c); },
      scrollIntoView(o) { this.scrolled = o || {}; },
      top: 0, scrollTop: 0,
      getBoundingClientRect() { return { top: this.top, height: 0 }; },
      click() { this.clicked = (this.clicked || 0) + 1; if (this.onclick) this.onclick(); }
    };
  };
  const get = (key) => { if (!els.has(key)) els.set(key, mk(key)); return els.get(key); };
  const document = {
    createElement: (tag) => mk(`<${tag}#${++made}>`),
    querySelector: (sel) => get('document ' + sel)
  };
  return { $: (sel) => get(String(sel)), $$: () => [], document, get };
}

/** app.js's functions in a context of their own over a fresh fake page. */
function harness({ flavor = 'openwrt', settings = {}, extra = {}, fns = [], prelude = '' } = {}) {
  const page = fakePage();
  const calls = [];
  const ctx = vm.createContext(Object.assign({
    state: {
      flavor, settings, platform: flavor === 'openwrt' ? 'linux' : 'win32', elevated: true, tunAvailable: true,
      assets: {}, coreVersions: {}, connected: false, connecting: false, activeServerId: null, pendingReconnect: [],
      servers: [], chains: [], chain: [], pool: []
    },
    $: page.$, $$: page.$$, document: page.document,
    t: (k) => k,
    toast: (msg, kind) => calls.push(['toast', msg, kind || '']),
    showView: (v) => calls.push(['view', v]),
    renderLanDevices: () => calls.push(['lanDevices']),
    updateGuardRows: () => {},
    renderModeOptions: () => calls.push(['modeOptions']),
    openFilesModal: (missing) => calls.push(['filesModal', missing.join(',')]),
    clearTimeout: () => {}, setTimeout: () => 1
  }, extra));
  vm.runInContext([prelude, ...fns.map((f) => (f.startsWith('\nconst ') ? f : fnSource(f)))].join('\n'), ctx);
  return { ctx, page, calls, el: page.$ };
}

/* ------------------------------------ strings ------------------------------------ */

test('the router strings are the field report’s, in both languages', () => {
  const want = {
    'ins.gateway': ['تونل کل شبکه', 'Whole-network tunnel'],
    'gw.insWhole': ['روشن — همهٔ دستگاه‌ها', 'on — every device'],
    'gw.insDirect': ['{n} دستگاه مستقیم', '{n} go direct'],
    'gw.insOff': ['خاموش — VPN قطع است', 'off — the VPN is off'],
    'gw.insHint': [
      'روتر «گیت‌وی» (دروازهٔ) شبکه است: هر دستگاهی که با وای‌فای یا کابل به این روتر وصل شود، بدون هیچ تنظیمی روی خودِ دستگاه از تونل VPN می‌رود. این یک وضعیت است، نه گزینه — روی روتر همیشه همین است. برای این‌که دستگاهی مستقیم برود: تنظیمات ← دستگاه‌های شبکه.',
      'The router is the network\'s gateway: every device on its Wi-Fi or cable goes through the VPN tunnel with no setup on the device. This is a status, not an option — on a router it is always on. To let a device go direct: Settings → Devices on this network.'],
    'mode.router': ['کل شبکه', 'Whole network'],
    'mode.routerSub': ['همهٔ دستگاه‌های پشت روتر', 'every device behind the router'],
    'mode.routerNote': [
      'روی روتر، تونل همیشه برای کل شبکه است — هر دستگاهی که به این روتر وصل شود از VPN می‌رود. پایین‌تر فقط می‌توانی دستگاه‌هایی را که نباید از تونل بروند مستثنا کنی.',
      'On a router the tunnel is always for the whole network — every device connected to this router goes through the VPN. Below you can only exclude devices that should go direct.'],
    'tun.routerReady': ['✓ تونل کل شبکه آماده است', '✓ Whole-network tunnel ready'],
    'tun.routerUnavailable': [
      '⚠ sing-box روی روتر نیست — تونل کل شبکه بدون آن بالا نمی‌آید. از «فایل‌های موردنیاز» دانلودش کن یا: opkg install sing-box',
      '⚠ sing-box is not on the router — the whole-network tunnel cannot start without it. Download it under Required files, or: opkg install sing-box'],
    'gw.quic': ['رد کردن QUIC (UDP 443) از شبکه', 'Refuse QUIC (UDP 443) from the LAN'],
    'gw.remote': [
      'دسترسی از بیرون خانه: LuCI ← Services ← IRNetFree ← دسترسی از راه دور (راهنما: docs/remote.md)',
      'Access from outside the home: LuCI → Services → IRNetFree → Remote access (guide: docs/remote.md)'],
    't.serverUpdatedLive': [
      'سرور به‌روزرسانی شد — روی اتصالِ فعلی هنوز اعمال نشده؛ «اتصال مجدد» را بزن.',
      'Server updated — not applied to the live connection yet; press Reconnect.'],
    'spoof.hideSni': ['🕵 پنهان‌کردن SNI از DPI (فرگمنت TLS)', '🕵 Hide SNI from DPI (TLS fragment)'],
    'spoof.hideSniFinalmask': [
      'این سرور ClientHello را از قبل با finalmask (پترنیها) تکه می‌کند؛ روشن‌کردن این کلید یک فرگمنت دوم (freedom) هم اضافه می‌کند — معمولاً لازم نیست.',
      'This server already fragments its ClientHello with finalmask (patterniha); turning this on adds a second (freedom) fragmenter — usually not needed.']
  };
  for (const [k, [fa, en]] of Object.entries(want)) {
    definedOnceEach(k);
    assert.equal(str('fa', k), fa, `fa ${k}`);
    assert.equal(str('en', k), en, `en ${k}`);
  }
  // Hide SNI is tried, not prescribed: the CDN hint no longer tells everyone to turn it on
  assert.ok(str('fa', 'spoof.frontHint').endsWith(' اگر بدون آن وصل نمی‌شود، «پنهان‌کردن SNI» را امتحان کن.'), str('fa', 'spoof.frontHint'));
  assert.ok(str('en', 'spoof.frontHint').endsWith(' If it does not connect without it, try “Hide SNI” below.'), str('en', 'spoof.frontHint'));
  assert.doesNotMatch(str('fa', 'spoof.frontHint'), /را روشن کن/);
  assert.doesNotMatch(str('en', 'spoof.frontHint'), /turn on "Hide SNI"/);
  // the markup's own fallback text is the new wording too
  assert.match(HTML, /data-i18n="gw\.quic">رد کردن QUIC \(UDP 443\) از شبکه</);
  assert.match(HTML, /id="edHideSniLabel">🕵 Hide SNI from DPI \(TLS fragment\)<\/span>/, 'the Hide SNI fallback says TLS fragment');
});

/* -------------------------- 1 + 2: the inspector's gateway row -------------------------- */

test('2: the gateway row is a button that explains itself and opens Settings at the device list', () => {
  const tag = HTML.match(/<button[^>]*id="insGatewayRow"[^>]*>/);
  assert.ok(tag, '#insGatewayRow is a <button>');
  assert.match(tag[0], /type="button"/);
  assert.match(tag[0], /class="ins-row[^"]*"/);
  assert.match(tag[0], /data-i18n-title="gw\.insHint"/, 'the hint is its tooltip');
  assert.match(HTML, /id="insGatewayRow" hidden/, 'still hidden until flavor=openwrt');
  // the value is Persian on a Persian page: not forced left-to-right
  const val = HTML.match(/<span class="([^"]*)" id="insGateway">/);
  assert.ok(val && /\bins-text\b/.test(val[1]), '#insGateway carries .ins-text');
  const rule = CSS.match(/\.ins-val\.ins-text\s*\{([^}]*)\}/);
  assert.ok(rule, 'no .ins-val.ins-text rule');
  assert.match(rule[1], /direction:\s*inherit/);
  assert.match(CSS, /button\.ins-row\s*\{[^}]*width:\s*100%/, 'the button spans the row like the other rows');
  // the explanation is the first line of the device list's row, right under its
  // title (the settings grid pins a row's title to its first line, so the
  // markup keeps the order the eye sees)
  const gw = HTML.slice(HTML.indexOf('id="gwRow" hidden>') + 'id="gwRow" hidden>'.length);
  assert.match(gw, /^\s*<div class="field-label" data-i18n="gw\.title">[^<]*<\/div>\s*(<!--[^>]*-->\s*)?<p class="hint" data-i18n="gw\.insHint"><\/p>/,
    'gw.insHint is the first line of #gwRow, under its title');

  // the click
  assert.match(APP, /\$\('#insGatewayRow'\)\.onclick = \(\) => openSettingAt\('#gwRow'\);/);
  const h = harness({ fns: ['openSettingAt'] });
  const column = h.el('#gwRow').closest('.content');
  column.top = 52; column.scrollTop = 100;
  h.el('#gwRow').top = 900;
  h.ctx.openSettingAt('#gwRow');
  assert.deepEqual(h.calls, [['view', 'settings']]);
  assert.equal(column.scrollTop, 100 + 900 - 52 - 12, 'the content column scrolls the row to its top');
  // scrollIntoView would also scroll the page itself and push the frameless
  // window's title bar out of view (measured: 52 px with block "start")
  assert.equal(h.el('#gwRow').scrolled, null, 'no scrollIntoView');
  assert.equal(h.page.get('document .settings-chip[data-category="all"]').clicked, undefined, 'a visible card needs no un-filtering');
  // a category chip or a search that hides the card is undone first
  const h2 = harness({ fns: ['openSettingAt'] });
  h2.el('#gwRow').closest('.card').hidden = true;
  h2.ctx.openSettingAt('#gwRow');
  assert.equal(h2.page.get('document .settings-chip[data-category="all"]').clicked, 1);
});

test('1: the inspector says what the gateway is doing — on for every device, how many go direct, off while the VPN is off', () => {
  const fns = ['renderInspector'];
  const up = harness({ fns, settings: { tunMode: true, lanBypassMacs: ['aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66'] } });
  up.ctx.state.connected = true;
  up.ctx.renderInspector();
  assert.equal(up.el('#insGateway').textContent, 'gw.insWhole · gw.insDirect');
  assert.ok(up.el('#insGateway').classList.contains('on'));
  const none = harness({ fns, settings: { tunMode: true } });
  none.ctx.state.connected = true;
  none.ctx.renderInspector();
  assert.equal(none.el('#insGateway').textContent, 'gw.insWhole');
  const off = harness({ fns, settings: { tunMode: true } });
  off.ctx.renderInspector();
  assert.equal(off.el('#insGateway').textContent, 'gw.insOff', 'not a bare "off" any more');
  assert.ok(off.el('#insGateway').classList.contains('off'));
  // the desktop never touches it
  const desk = harness({ flavor: null, fns, settings: { tunMode: true } });
  desk.ctx.state.connected = true;
  desk.ctx.renderInspector();
  assert.equal(desk.el('#insGateway').textContent, '');
  // "{n}" is filled in
  const n = harness({ fns, settings: { tunMode: true, lanBypassMacs: ['a', 'b'] }, extra: { t: (k) => (k === 'gw.insDirect' ? '{n} go direct' : k) } });
  n.ctx.state.connected = true;
  n.ctx.renderInspector();
  assert.equal(n.el('#insGateway').textContent, 'gw.insWhole · 2 go direct');
});

/* ------------------------------ 6 + 17: the router's Settings ------------------------------ */

const FLAVOR_ROWS = ['#udpBlockRow', '#leakGuardRow'];

test('6/17: on the router Settings drop the desktop TUN controls, explain the whole-network tunnel and point at LuCI for remote access', () => {
  // the markup: the explanation sits where the TUN switch was, the remote-access pointer with the router rows
  assert.match(HTML, /<p class="hint" id="tunRouterNote" data-i18n="mode\.routerNote" hidden><\/p>/);
  const afterTun = HTML.slice(HTML.indexOf('id="optTun"'), HTML.indexOf('id="tunStatus"'));
  assert.ok(afterTun.includes('id="tunRouterNote"'), 'the explanation replaces the TUN switch, above the status line');
  assert.match(HTML, /id="gwRemoteRow" hidden/);
  const remote = HTML.slice(HTML.indexOf('id="gwRemoteRow"'), HTML.indexOf('id="optKillSwitch"'));
  assert.ok(remote.includes('data-i18n="gw.remote"'), 'the pointer is in the router block, before the kill switch');

  const h = harness({ fns: ['applyFlavor'] });
  h.ctx.applyFlavor();
  for (const id of FLAVOR_ROWS) assert.equal(h.el(id).hidden, true, `${id} is a desktop control`);
  assert.equal(h.el('#optTun').closest('.switch-row').hidden, true, 'no TUN switch: on a router the tunnel is the network');
  assert.equal(h.el('#tunRouterNote').hidden, false);
  assert.equal(h.el('#gwRemoteRow').hidden, false);
  assert.equal(h.el('#gwRow').hidden, false);
  assert.equal(h.el('#insGatewayRow').hidden, false);

  // the desktop: every one of them as it was
  const d = harness({ flavor: null, fns: ['applyFlavor'] });
  d.ctx.applyFlavor();
  for (const id of FLAVOR_ROWS) assert.equal(d.el(id).hidden, false, `${id} stays on the desktop`);
  assert.equal(d.el('#optTun').closest('.switch-row').hidden, false);
  assert.equal(d.el('#tunRouterNote').hidden, true);
  assert.equal(d.el('#gwRemoteRow').hidden, true);
  assert.equal(d.el('#gwRow').hidden, true);
  assert.equal(d.el('#insGatewayRow').hidden, true);
});

test('6: on the router the mode card is "Whole network", explains itself and opens nothing; the desktop keeps Proxy / TUN and its picker', () => {
  const fns = ['setModeWidget', 'openModeModal'];
  const r = harness({ fns, settings: { tunMode: true } });
  r.ctx.setModeWidget();
  assert.equal(r.el('#modeLabel').textContent, 'mode.router');
  assert.equal(r.el('#modeSub').textContent, 'mode.routerSub');
  assert.equal(r.el('#modeCard').title, 'mode.routerNote');
  assert.equal(r.el('#modeCard').getAttribute('aria-disabled'), 'true');
  assert.ok(r.el('#modeCard').classList.contains('mode-card-fixed'));
  r.el('#modeModal').hidden = true;
  r.ctx.openModeModal();
  assert.equal(r.el('#modeModal').hidden, true, 'the picker stays shut');
  assert.ok(!r.calls.some((c) => c[0] === 'modeOptions'), 'the Proxy/TUN picker does not open on a router');
  // even a router store that still says proxy shows the whole network: there is no other mode there
  const p = harness({ fns, settings: { tunMode: false } });
  p.ctx.setModeWidget();
  assert.equal(p.el('#modeLabel').textContent, 'mode.router');

  for (const [tunMode, label, sub] of [[true, 'mode.tun', 'mode.tunSub'], [false, 'mode.proxy', 'mode.proxySub']]) {
    const d = harness({ flavor: null, fns, settings: { tunMode } });
    d.el('#modeModal').hidden = true;
    d.ctx.setModeWidget();
    assert.equal(d.el('#modeLabel').textContent, label);
    assert.equal(d.el('#modeSub').textContent, sub);
    assert.equal(d.el('#modeCard').title, 'mode.pick');
    assert.equal(d.el('#modeCard').getAttribute('aria-disabled'), null);
    assert.ok(!d.el('#modeCard').classList.contains('mode-card-fixed'));
    d.ctx.openModeModal();
    assert.equal(d.el('#modeModal').hidden, false, 'the desktop picker opens');
    assert.ok(d.calls.some((c) => c[0] === 'modeOptions'));
  }
  assert.match(CSS, /\.mode-card-fixed[^{]*\{[^}]*cursor:\s*default/, 'a card that does nothing does not look clickable');
});

test('6/8: the router’s TUN status line speaks of the whole network — ready, or sing-box missing — and never of admin rights', () => {
  const fns = ['updateTunStatus', 'updateAdminBtn'];
  const ready = harness({ fns, settings: { tunMode: true } });
  ready.ctx.state.elevated = false;
  ready.ctx.updateTunStatus();
  assert.equal(ready.el('#tunStatus').textContent, 'tun.routerReady');
  assert.equal(ready.el('#tunStatus').className, 'tun-status ok');
  assert.equal(ready.el('#btnRunAdmin').hidden, true, 'no "relaunch as admin" on a router');
  const missing = harness({ fns, settings: { tunMode: true } });
  missing.ctx.state.tunAvailable = false;
  missing.ctx.updateTunStatus();
  assert.equal(missing.el('#tunStatus').textContent, 'tun.routerUnavailable');
  assert.equal(missing.el('#tunStatus').className, 'tun-status warn');

  // the desktop's four states, word for word as before
  const cases = [
    [{ tunAvailable: false, elevated: true, tunMode: true }, 'tun.unavailable', 'tun-status warn', true],
    [{ tunAvailable: true, elevated: false, tunMode: true }, 'tun.needAdmin', 'tun-status warn', false],
    [{ tunAvailable: true, elevated: true, tunMode: true }, 'tun.ready', 'tun-status ok', true],
    [{ tunAvailable: true, elevated: true, tunMode: false }, 'tun.off', 'tun-status', true]
  ];
  for (const [s, text, cls, adminHidden] of cases) {
    const d = harness({ flavor: null, fns, settings: { tunMode: s.tunMode } });
    d.ctx.state.tunAvailable = s.tunAvailable;
    d.ctx.state.elevated = s.elevated;
    d.ctx.updateTunStatus();
    assert.equal(d.el('#tunStatus').textContent, text);
    assert.equal(d.el('#tunStatus').className, cls);
    assert.equal(d.el('#btnRunAdmin').hidden, adminHidden, `admin button for ${JSON.stringify(s)}`);
  }
});

/* ------------------------------ 8: sing-box on a fresh router ------------------------------ */

test('8: a router without sing-box asks for it at load, like a missing xray; the desktop prompts as before', () => {
  const fns = ['anyXrayCore', 'missingEssentials', 'maybePromptMissingFiles'];
  const fresh = harness({ fns, settings: { tunMode: true } });
  fresh.ctx.state.assets = { platform: 'linux', xray: true, geoip: true, geosite: true, 'sing-box': false, tun2socks: false };
  fresh.ctx.state.tunAvailable = false;
  assert.deepEqual([...fresh.ctx.missingEssentials()], ['sing-box']);
  fresh.ctx.maybePromptMissingFiles();
  assert.deepEqual(fresh.calls, [['filesModal', 'sing-box']], 'the modal opens for sing-box alone');
  // the label it shows exists
  assert.match(constSource('COMP_LABEL'), /'sing-box': 'comp\.singbox'/);
  // with the tunnel available nothing is asked
  const fine = harness({ fns, settings: { tunMode: true } });
  fine.ctx.state.assets = { platform: 'linux', xray: true, geoip: true, geosite: true, 'sing-box': true };
  fine.ctx.missingEssentials();
  fine.ctx.maybePromptMissingFiles();
  assert.deepEqual(fine.calls, []);
  // sing-box there but the tunnel still unavailable (no nft): downloading sing-box again would not help
  const nft = harness({ fns, settings: { tunMode: true } });
  nft.ctx.state.assets = { platform: 'linux', xray: true, geoip: true, geosite: true, 'sing-box': true };
  nft.ctx.state.tunAvailable = false;
  assert.deepEqual([...nft.ctx.missingEssentials()], []);

  // desktop: tun2socks / wintun listed while TUN is on, sing-box never, the modal only for xray
  const d = harness({ flavor: null, fns, settings: { tunMode: true } });
  d.ctx.state.assets = { platform: 'win32', xray: true, geoip: true, geosite: true, 'sing-box': false, tun2socks: false, wintun: false };
  d.ctx.state.tunAvailable = false;
  assert.deepEqual([...d.ctx.missingEssentials()], ['tun2socks', 'wintun']);
  d.ctx.maybePromptMissingFiles();
  assert.deepEqual(d.calls, [], 'no prompt on the desktop unless the core is missing');
  const d2 = harness({ flavor: null, fns, settings: { tunMode: true } });
  d2.ctx.state.assets = { platform: 'win32', geoip: true, geosite: true, tun2socks: true, wintun: true };
  d2.ctx.maybePromptMissingFiles();
  assert.deepEqual(d2.calls, [['filesModal', 'xray']]);
});

test('8: the router’s Required files list has no tun2socks or wintun, and its TUN note is the router’s; the desktop list is whole', () => {
  const fns = ['escapeHtml', 'renderComponents', constSource('COMPONENTS')];
  const rows = (h) => h.el('#compList').children.map((r) => r.innerHTML).join('\n');
  const r = harness({ fns });
  r.ctx.state.assets = { platform: 'linux', xray: true, 'sing-box': false, tun2socks: false, tunReady: false };
  r.ctx.state.tunAvailable = false;
  r.ctx.renderComponents();
  const routerRows = rows(r);
  assert.match(routerRows, /comp\.singbox/);
  assert.doesNotMatch(routerRows, /comp\.tun2socksLegacy/);
  assert.doesNotMatch(routerRows, /comp\.wintun/);
  assert.equal(r.el('#compTunNote').hidden, false);
  assert.equal(r.el('#compTunNote').getAttribute('data-i18n'), 'tun.routerUnavailable');
  assert.equal(r.el('#compTunNote').textContent, 'tun.routerUnavailable');
  // a router that has tun2socks but no sing-box cannot run the gateway: the note still shows
  const r2 = harness({ fns });
  r2.ctx.state.assets = { platform: 'linux', xray: true, 'sing-box': false, tun2socks: true, tunReady: true };
  r2.ctx.state.tunAvailable = false;
  r2.ctx.renderComponents();
  assert.equal(r2.el('#compTunNote').hidden, false);
  const r3 = harness({ fns });
  r3.ctx.state.assets = { platform: 'linux', xray: true, 'sing-box': true, tunReady: true };
  r3.ctx.renderComponents();
  assert.equal(r3.el('#compTunNote').hidden, true);

  const d = harness({ flavor: null, fns });
  d.ctx.state.assets = { platform: 'win32', xray: true, tunReady: false };
  d.ctx.renderComponents();
  const deskRows = rows(d);
  for (const k of ['comp.xray', 'comp.singbox', 'comp.tun2socksLegacy', 'comp.wintun']) assert.match(deskRows, new RegExp(k.replace('.', '\\.')));
  assert.equal(d.el('#compTunNote').hidden, false);
  assert.equal(d.el('#compTunNote').getAttribute('data-i18n'), null, 'the desktop note keeps its markup key');
});

/* -------------------------- 18: an edit of the server that is live -------------------------- */

test('18: a server is "live" when the connection up right now is built from it — alone, in a chain, the pool or the advanced plan', () => {
  const h = harness({ fns: ['serverInLivePlan'] });
  const s = h.ctx.state;
  s.servers = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
  s.chains = [{ id: 'k1', members: ['a', 'b'] }];
  s.chain = ['c', 'b'];
  s.pool = [{ target: 'c', enabled: true }, { target: 'chain:k1', enabled: true }, { target: 'x', enabled: false }];
  const live = (activeServerId, id, connected = true) => { s.activeServerId = activeServerId; s.connected = connected; return h.ctx.serverInLivePlan(id); };
  assert.equal(live('a', 'a'), true);
  assert.equal(live('a', 'b'), false);
  assert.equal(live('a', 'a', false), false, 'nothing is live while disconnected');
  assert.equal(live('k1', 'b'), true, 'a chain member');
  assert.equal(live('k1', 'c'), false);
  assert.equal(live('__chain__', 'c'), true, 'the legacy chain');
  assert.equal(live('__pool__', 'c'), true, 'a pool target');
  assert.equal(live('__pool__', 'a'), true, 'a member of a pool chain');
  s.pool[0].enabled = false;
  assert.equal(live('__pool__', 'c'), false, 'a disabled pool entry is not running');
  s.settings = { routeRules: [{ target: 'chain:k1' }, { target: 'direct' }], routeDefault: 'c' };
  assert.equal(live('__advanced__', 'a'), true, 'an advanced rule’s chain');
  assert.equal(live('__advanced__', 'c'), true, 'the advanced default');
  s.settings = { routeRules: [] };
  assert.equal(live('__advanced__', 'a'), true, 'no default: the first server, as the service builds it');
  assert.equal(live('__advanced__', 'b'), false);
});

test('18: saving an edit of the live server says it is not applied yet and offers Reconnect — on the desktop and on the router alike', async () => {
  for (const flavor of ['openwrt', null]) {
    const run = async (activeServerId) => {
      const fresh = harness({
        flavor,
        fns: ['serverInLivePlan', 'toastAction', 'saveEdit'],
        prelude: 'var editOriginal = { protocol: "vless" }; var editClearPin = false;',
        extra: {
          collectEditFields: () => ({ name: 'x' }),
          renderServers() {}, renderPicker() {}, renderChains() {}, renderPool() {}, renderAdvanced() {},
          closeEdit() {},
          doReconnect: () => { fresh.calls.push(['reconnect']); },
          window: { api: { updateServer: async () => ({ ok: true, servers: [{ id: 's1' }, { id: 's2' }] }) } }
        }
      });
      Object.assign(fresh.ctx.state, { editingId: 's1', connected: true, activeServerId, servers: [{ id: 's1' }, { id: 's2' }] });
      await fresh.ctx.saveEdit();
      return fresh;
    };
    const live = await run('s1');
    const toast = live.el('#toast');
    assert.ok(toast.className.includes('has-action'), `${flavor}: the toast carries an action: ${toast.className}`);
    assert.ok(toast.className.includes('warn'));
    const [text, btn] = toast.children;
    assert.equal(text.textContent, 't.serverUpdatedLive');
    assert.equal(btn.textContent, 'btn.reconnect');
    assert.ok(!live.calls.some((c) => c[0] === 'toast'), 'not the plain toast');
    btn.onclick();
    assert.ok(live.calls.some((c) => c[0] === 'reconnect'), 'the action is the leak-free reconnect');
    assert.ok(!toast.className.includes('show'), 'and the toast goes');
    // another server than the live one: the plain toast, as before
    const other = await run('s2');
    assert.deepEqual(other.calls, [['toast', 't.serverUpdated', 'ok']]);
  }
  assert.match(APP, /\$\('#editSave'\)\.onclick = saveEdit;/);
  // the toast is click-through only while it has no button, and the long one is
  // centred on the physical left edge — the logical inset is the right edge in
  // Persian, and translateX is physical: it started off the window's left side
  assert.match(CSS, /\.toast\.has-action\.show\s*\{\s*pointer-events:\s*auto/, 'clickable while it shows');
  assert.doesNotMatch(CSS, /\.toast\.has-action\s*\{[^}]*pointer-events:\s*auto/, 'a faded toast must not swallow clicks');
  const rule = CSS.match(/\.toast\.has-action\s*\{([^}]*)\}/);
  assert.ok(rule, 'no .toast.has-action rule');
  assert.match(rule[1], /inset-inline-start:\s*auto/);
  assert.match(rule[1], /(^|[\s;])left:\s*50%/);
});

/* ------------------------------ 19: Hide SNI tells the truth ------------------------------ */

test('19: a server that already fragments with finalmask says so under the Hide SNI switch', () => {
  assert.match(HTML, /<p class="hint warn" id="edHideSniFmNote" data-i18n="spoof\.hideSniFinalmask" hidden><\/p>/);
  const after = HTML.slice(HTML.indexOf('id="edHideSniRow"'), HTML.indexOf('id="edPathRow"'));
  assert.ok(after.includes('id="edHideSniFmNote"'), 'the note sits right under the switch');
  assert.match(APP, /\$\('#edFinalMask'\)\.oninput = updateHideSniNote/, 'it follows the finalmask field as it is typed');

  const fns = ['show', 'updateHideSniNote', 'updateSpoofLabels'];
  const form = (sec, fm) => {
    const h = harness({ flavor: null, fns, prelude: 'var editOriginal = { protocol: "vless" };' });
    h.el('#edSecurity').value = sec;
    h.el('#edNetwork').value = 'ws';
    h.el('#edFinalMask').value = fm;
    h.ctx.updateSpoofLabels();
    return h;
  };
  const fm = '{"tcp":[{"type":"fragment","settings":{"packets":"tlshello"}}]}';
  assert.equal(form('tls', fm).el('#edHideSniFmNote').hidden, false);
  assert.equal(form('reality', fm).el('#edHideSniFmNote').hidden, false);
  assert.equal(form('tls', '   ').el('#edHideSniFmNote').hidden, true, 'no finalmask, no note');
  assert.equal(form('none', fm).el('#edHideSniFmNote').hidden, true, 'no TLS, no switch, no note');
  const h = form('tls', fm);
  assert.equal(h.el('#edHideSniLabel').textContent, 'spoof.hideSni');
  h.el('#edFinalMask').value = '';
  h.ctx.updateHideSniNote();
  assert.equal(h.el('#edHideSniFmNote').hidden, true, 'cleared in the form: gone at once');
});
