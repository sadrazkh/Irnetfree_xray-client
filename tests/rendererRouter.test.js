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
      replaceChildren(...c) { this.children = c; },
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

  const location = { protocol: 'http:', hostname: '192.168.1.1' };
  const h = harness({ fns: ['applyFlavor', 'renderRemotePointer'], extra: { location } });
  h.ctx.applyFlavor();
  for (const id of FLAVOR_ROWS) assert.equal(h.el(id).hidden, true, `${id} is a desktop control`);
  assert.equal(h.el('#optTun').closest('.switch-row').hidden, true, 'no TUN switch: on a router the tunnel is the network');
  assert.equal(h.el('#tunRouterNote').hidden, false);
  assert.equal(h.el('#gwRemoteRow').hidden, false);
  assert.equal(h.el('#gwRemote').children.length, 1, 'the pointer is rendered (t() here returns the bare key: plain text)');
  assert.equal(h.el('#gwRow').hidden, false);
  assert.equal(h.el('#insGatewayRow').hidden, false);

  // the desktop: every one of them as it was
  const d = harness({ flavor: null, fns: ['applyFlavor', 'renderRemotePointer'], extra: { location } });
  d.ctx.applyFlavor();
  assert.equal(d.el('#gwRemote').children.length, 0, 'nothing rendered into a hidden row');
  for (const id of FLAVOR_ROWS) assert.equal(d.el(id).hidden, false, `${id} stays on the desktop`);
  assert.equal(d.el('#optTun').closest('.switch-row').hidden, false);
  assert.equal(d.el('#tunRouterNote').hidden, true);
  assert.equal(d.el('#gwRemoteRow').hidden, true);
  assert.equal(d.el('#gwRow').hidden, true);
  assert.equal(d.el('#insGatewayRow').hidden, true);
});

test('6: on the router the mode card is "Whole network", explains itself and opens the device list — never the Proxy/TUN picker; the desktop keeps Proxy / TUN and its picker', () => {
  const fns = ['setModeWidget', 'openModeModal', 'openSettingAt'];
  const r = harness({ fns, settings: { tunMode: true } });
  r.ctx.setModeWidget();
  assert.equal(r.el('#modeLabel').textContent, 'mode.router');
  assert.equal(r.el('#modeSub').textContent, 'mode.routerSub');
  // The Home screen has no device list "below" the card: its tooltip is the
  // gateway's own explanation (which names where the device list is), not
  // mode.routerNote, whose "Below you can only exclude…" points at Settings.
  assert.equal(r.el('#modeCard').title, 'gw.insHint');
  // A control that does nothing is what the owner reported in LuCI: the card
  // is a real button on the router too, and it goes where the one router
  // choice is — which devices go direct.
  assert.equal(r.el('#modeCard').getAttribute('aria-disabled'), null);
  assert.ok(!r.el('#modeCard').classList.contains('mode-card-fixed'));
  r.el('#modeModal').hidden = true;
  r.ctx.openModeModal();
  assert.equal(r.el('#modeModal').hidden, true, 'the picker stays shut');
  assert.ok(!r.calls.some((c) => c[0] === 'modeOptions'), 'the Proxy/TUN picker does not open on a router');
  assert.deepEqual(r.calls, [['view', 'settings']], 'a click opens Settings (at the device list)');
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
    assert.ok(!d.calls.some((c) => c[0] === 'view'), 'and nothing else');
  }
});

test('6/8: the router’s TUN status line speaks of the whole network — ready, or sing-box missing — and never of admin rights', () => {
  const fns = ['updateTunStatus', 'updateAdminBtn', 'routerTunMissingKey'];
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
  // The router's tunnel is sing-box AND nft (TunOpenwrt.isAvailable): with
  // sing-box there, the missing piece is nft — telling the user to download
  // sing-box again would fix nothing (and missingEssentials does not ask for it).
  const noNft = harness({ fns, settings: { tunMode: true } });
  noNft.ctx.state.tunAvailable = false;
  noNft.ctx.state.assets = { platform: 'linux', 'sing-box': true };
  noNft.ctx.updateTunStatus();
  assert.equal(noNft.el('#tunStatus').textContent, 'tun.routerNoNft');
  assert.equal(noNft.el('#tunStatus').className, 'tun-status warn');

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
  const fns = ['escapeHtml', 'renderComponents', 'routerTunMissingKey', constSource('COMPONENTS')];
  const rows = (h) => h.el('#compList').children.map((r) => r.innerHTML).join('\n');
  const r = harness({ fns });
  r.ctx.state.assets = { platform: 'linux', xray: true, 'sing-box': false, tun2socks: false, tunReady: false };
  r.ctx.state.tunAvailable = false;
  r.ctx.renderComponents();
  const routerRows = rows(r);
  // sing-box on a router is the whole-network tunnel, not "the TUN mode's backend"
  assert.match(routerRows, /comp\.singboxRouter/);
  assert.doesNotMatch(routerRows, /comp\.singbox</);
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
  // sing-box present, the tunnel still unavailable: the note names nft
  const r4 = harness({ fns });
  r4.ctx.state.assets = { platform: 'linux', xray: true, 'sing-box': true, tunReady: true };
  r4.ctx.state.tunAvailable = false;
  r4.ctx.renderComponents();
  assert.equal(r4.el('#compTunNote').hidden, false);
  assert.equal(r4.el('#compTunNote').getAttribute('data-i18n'), 'tun.routerNoNft');
  assert.equal(r4.el('#compTunNote').textContent, 'tun.routerNoNft');

  const d = harness({ flavor: null, fns });
  d.ctx.state.assets = { platform: 'win32', xray: true, tunReady: false };
  d.ctx.renderComponents();
  const deskRows = rows(d);
  for (const k of ['comp.xray', 'comp.singbox<', 'comp.tun2socksLegacy', 'comp.wintun']) assert.match(deskRows, new RegExp(k.replace('.', '\\.')));
  assert.doesNotMatch(deskRows, /comp\.singboxRouter/, 'the desktop keeps its own sing-box label');
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
  s.pool = [{ target: 'c', enabled: true, socksPort: 20001 }, { target: 'chain:k1', enabled: true, socksPort: 20002 },
    { target: 'x', enabled: false, socksPort: 20003 }, { target: 'b', enabled: true, socksPort: 0 }];
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
  // main and the service build the pool from `enabled && socksPort`: an
  // enabled entry with no port never started
  s.pool[1].enabled = false;
  assert.equal(live('__pool__', 'b'), false, 'an enabled pool entry without a port is not running');
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
  // centred on the physical left edge — a logical inset is the right edge in
  // Persian, and translateX is physical: it started off the window's left side.
  // Every toast is centred so (the plain one too, v1.16.3): the button's rule
  // adds no inset of its own (tests/bannerLayout.test.js renders both)
  assert.match(CSS, /\.toast\.has-action\.show\s*\{\s*pointer-events:\s*auto/, 'clickable while it shows');
  assert.doesNotMatch(CSS, /\.toast\.has-action\s*\{[^}]*pointer-events:\s*auto/, 'a faded toast must not swallow clicks');
  const rule = CSS.match(/\.toast\.has-action\s*\{([^}]*)\}/);
  assert.ok(rule, 'no .toast.has-action rule');
  assert.doesNotMatch(rule[1], /inset-inline|(^|[\s;])(left|right):/);
  const base = CSS.match(/\n\.toast\s*\{([^}]*)\}/);
  assert.ok(base, 'no .toast rule');
  assert.match(base[1], /(^|[\s;])left:\s*50%/);
  assert.doesNotMatch(base[1], /inset-inline/);
});

/**
 * servers:update now answers { live, pendingReconnect } (fix/v1161-core: an
 * edit of a server the live plan dials is the pending key 'servers'). The
 * service judges against the plan it actually built; the renderer's own
 * reading (serverInLivePlan) is only for a main that does not say.
 */
test('18 (review): a save takes the service’s word — its "live" verdict and its pending list — and reads the plan itself only for a main that says neither', async () => {
  const run = async ({ reply, activeServerId = 's1' }) => {
    const h = harness({
      fns: ['serverInLivePlan', 'toastAction', 'setPending', 'saveEdit'],
      prelude: 'var editOriginal = { protocol: "vless" }; var editClearPin = false;',
      extra: {
        collectEditFields: () => ({ name: 'x' }),
        renderServers() {}, renderPicker() {}, renderChains() {}, renderPool() {}, renderAdvanced() {}, closeEdit() {},
        renderPendingBanner: () => h.calls.push(['banner', [...h.ctx.state.pendingReconnect].join(',')]),
        doReconnect: () => {},
        window: { api: { updateServer: async () => Object.assign({ ok: true, servers: [{ id: 's1' }, { id: 's2' }] }, reply) } }
      }
    });
    Object.assign(h.ctx.state, { editingId: 's1', connected: true, activeServerId, servers: [{ id: 's1' }, { id: 's2' }] });
    await h.ctx.saveEdit();
    return h;
  };
  const withAction = (h) => h.el('#toast').className.includes('has-action');

  // live, and 'servers' pending: the lasting banner comes at once, beside the toast
  const live = await run({ reply: { live: true, pendingReconnect: ['servers'] } });
  assert.ok(withAction(live));
  assert.deepEqual([...live.ctx.state.pendingReconnect], ['servers']);
  assert.ok(live.calls.some((c) => c[0] === 'banner' && c[1] === 'servers'), 'the pending banner is refreshed with it');

  // the service says not live (say, a pool entry it never started): believed over the renderer's reading
  const notLive = await run({ reply: { live: false, pendingReconnect: [] } });
  assert.ok(!withAction(notLive));
  assert.deepEqual(notLive.calls.filter((c) => c[0] === 'toast'), [['toast', 't.serverUpdated', 'ok']]);

  // and live by the service's word where the renderer would not have said so
  const svcOnly = await run({ reply: { live: true, pendingReconnect: ['servers'] }, activeServerId: 's2' });
  assert.ok(withAction(svcOnly));

  // an older main (neither field): the renderer's own reading, and the pending list left alone
  const old = await run({ reply: {} });
  assert.ok(withAction(old));
  assert.ok(!old.calls.some((c) => c[0] === 'banner'), 'no list in the reply: the banner is not touched');
  const oldOther = await run({ reply: {}, activeServerId: 's2' });
  assert.ok(!withAction(oldOther));
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

/* ------------------------------------ review round ------------------------------------ */

/** i18n.js itself in a context of its own: t() exactly as the page runs it, in one language. */
function realT(lang) {
  const window = {};
  vm.runInContext(I18N, vm.createContext({ window, document: { documentElement: {}, querySelectorAll: () => [] } }));
  window.i18n.applyI18n(lang);
  return window.i18n.t;
}

test('review: every key the pending list can hold has a name in fa and en — "servers" (an edit of the live server) included', () => {
  const { RECONNECT_KEYS } = require('../src/main/settingsMeta');
  // pendingKeys() adds keys beyond the settings: 'servers' (fix/v1161-core),
  // and whatever main or the service push there in future
  const extra = new Set(['servers']);
  for (const f of ['src/main/main.js', 'src/server/service.js']) {
    const src = fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
    const body = (src.match(/function pendingKeys\(\) \{[\s\S]*?\n\s*\}/) || [''])[0];
    for (const m of body.matchAll(/keys\.push\('([^']+)'\)/g)) extra.add(m[1]);
  }
  for (const k of extra) definedOnceEach('set.' + k);
  for (const lang of ['fa', 'en']) {
    const h = harness({ fns: ['pendingLabels'], extra: { t: realT(lang) } });
    h.ctx.state.pendingReconnect = [...RECONNECT_KEYS, ...extra];
    const labels = [...h.ctx.pendingLabels()];
    labels.forEach((l, i) => assert.ok(!/^set\./.test(l), `${lang}: '${h.ctx.state.pendingReconnect[i]}' shows as the raw key "${l}"`));
  }
  assert.equal(str('fa', 'set.servers'), 'ویرایش سرورِ متصل');
  assert.equal(str('en', 'set.servers'), 'Edit of the connected server');
});

test('review: on the router the inspector has no TUN row and no Leak guard row — unless a stored "strict" is still live, and then Settings shows the guard so it can be lowered', () => {
  // the rows carry ids to hide them by
  assert.match(HTML, /<div class="ins-row" id="insTunRow"><span class="ins-label" data-i18n="ins\.tun">[^<]*<\/span><span class="ins-val" id="insTun">/);
  assert.match(HTML, /<div class="ins-row" id="insGuardRow"><span class="ins-label" data-i18n="ins\.guard">[^<]*<\/span><span class="ins-val" id="insGuard">/);
  const fns = ['applyFlavor', 'renderInspector'];
  const extra = { renderRemotePointer() {} };
  for (const leakGuard of [undefined, 'off', 'standard']) {
    const r = harness({ fns, extra, settings: { tunMode: true, leakGuard } });
    r.ctx.applyFlavor();
    r.ctx.state.connected = true;
    r.ctx.renderInspector();
    assert.equal(r.el('#insTunRow').hidden, true, 'the whole-network row stands for it');
    assert.equal(r.el('#insGuardRow').hidden, true, `no guard row at ${leakGuard}: nothing on the router answers it`);
    assert.equal(r.el('#leakGuardRow').hidden, true);
  }
  // A router store holding "strict" (a desktop backup restored before the
  // router kept its own guard) still reaches sing-box's strict_route: it shows,
  // in the inspector and in Settings, where it can be set back.
  const s = harness({ fns, extra, settings: { tunMode: true, leakGuard: 'strict' } });
  s.ctx.applyFlavor();
  s.ctx.renderInspector();
  assert.equal(s.el('#insTunRow').hidden, true);
  assert.equal(s.el('#insGuardRow').hidden, false);
  assert.equal(s.el('#leakGuardRow').hidden, false);
  // lowered in Settings: the inspector row goes with the save's render
  s.ctx.state.settings = { tunMode: true, leakGuard: 'standard' };
  s.ctx.renderInspector();
  assert.equal(s.el('#insGuardRow').hidden, true);

  // the desktop: both rows, at every level, as before
  for (const leakGuard of ['off', 'standard', 'strict']) {
    const d = harness({ flavor: null, fns, extra, settings: { tunMode: true, leakGuard } });
    d.ctx.applyFlavor();
    d.ctx.renderInspector();
    assert.equal(d.el('#insTunRow').hidden, false);
    assert.equal(d.el('#insGuardRow').hidden, false);
    assert.equal(d.el('#leakGuardRow').hidden, false);
    assert.equal(d.el('#insGuard').textContent, leakGuard);
  }
});

test('review: while the router reconnects or waits for the WAN the gateway row says so — not "off — the VPN is off"', () => {
  const fns = ['renderInspector'];
  const rec = harness({ fns, settings: { tunMode: true } });
  // status 'reconnecting' / 'waiting': connected false, connecting true
  rec.ctx.state.connecting = true;
  rec.ctx.renderInspector();
  assert.equal(rec.el('#insGateway').textContent, 'state.connecting');
  assert.ok(!rec.el('#insGateway').classList.contains('off'), 'neither off…');
  assert.ok(!rec.el('#insGateway').classList.contains('on'), '…nor on');
  // and back to off once nothing is in flight
  rec.ctx.state.connecting = false;
  rec.ctx.renderInspector();
  assert.equal(rec.el('#insGateway').textContent, 'gw.insOff');
  assert.ok(rec.el('#insGateway').classList.contains('off'));
});

test('review: the router strings this round adds, in both languages', () => {
  const want = {
    'tun.routerNoNft': [
      '⚠ nft (nftables) روی روتر نیست — تونل کل شبکه بدون آن بالا نمی‌آید: opkg install nftables',
      '⚠ nft (nftables) is not on the router — the whole-network tunnel cannot start without it: opkg install nftables'],
    'lan.routerTitle': ['باز کردن پورت‌های پراکسی SOCKS/HTTP روی شبکه', 'Open the SOCKS/HTTP proxy ports to the LAN'],
    'lan.routerSub': [
      'لازم نیست — همهٔ دستگاه‌ها از قبل از تونل می‌روند؛ فقط برای برنامه‌ای که خودش پراکسی می‌خواهد.',
      'Not needed — every device already goes through the tunnel; only for an app that asks for a proxy itself.'],
    'comp.singboxRouter': ['هستهٔ sing-box (تونل کل شبکه)', 'sing-box core (the whole-network tunnel)']
  };
  for (const [k, [fa, en]] of Object.entries(want)) {
    definedOnceEach(k);
    assert.equal(str('fa', k), fa, `fa ${k}`);
    assert.equal(str('en', k), en, `en ${k}`);
  }
});

test('review: on the router the Allow LAN row says what it does there — the proxy ports, not the tunnel; the desktop keeps its words', () => {
  const extra = { renderRemotePointer() {} };
  const r = harness({ fns: ['applyFlavor'], extra });
  r.ctx.applyFlavor();
  const row = r.el('#optAllowLan').closest('.switch-row');
  assert.equal(row.hidden, false, 'the row stays: the ports are real');
  assert.equal(row.querySelector('.switch-title').getAttribute('data-i18n'), 'lan.routerTitle');
  assert.equal(row.querySelector('.switch-title').textContent, 'lan.routerTitle');
  assert.equal(row.querySelector('.switch-sub').getAttribute('data-i18n'), 'lan.routerSub');
  assert.equal(row.querySelector('.switch-sub').textContent, 'lan.routerSub');
  const d = harness({ flavor: null, fns: ['applyFlavor'], extra });
  d.ctx.applyFlavor();
  const drow = d.el('#optAllowLan').closest('.switch-row');
  assert.equal(drow.querySelector('.switch-title').getAttribute('data-i18n'), 'lan.title');
  assert.equal(drow.querySelector('.switch-title').textContent, 'lan.title');
  assert.equal(drow.querySelector('.switch-sub').getAttribute('data-i18n'), 'lan.sub');
  // the markup's own keys are the desktop's, so the desktop reads exactly as before
  assert.match(HTML, /<div class="switch-title" data-i18n="lan\.title">/);
  assert.match(HTML, /<div class="switch-sub" data-i18n="lan\.sub">/);
});

test('review: the router’s Required-files prompt names sing-box for the whole-network tunnel; the desktop’s is unchanged', () => {
  const fns = ['escapeHtml', 'compLabel', 'openFilesModal', constSource('COMP_LABEL')];
  const r = harness({ fns });
  r.ctx.openFilesModal(['sing-box']);
  assert.match(r.el('#filesList').children[0].innerHTML, /comp\.singboxRouter</);
  const d = harness({ flavor: null, fns });
  d.ctx.openFilesModal(['xray', 'sing-box']);
  const desk = d.el('#filesList').children.map((c) => c.innerHTML).join('\n');
  assert.match(desk, /comp\.xray</);
  assert.match(desk, /comp\.singbox</);
  assert.doesNotMatch(desk, /comp\.singboxRouter/);
  // the download loop says the same name
  assert.match(APP, /\$\('#filesProgress'\)\.textContent = `\$\{t\('t\.downloading'\)\} \$\{t\(compLabel\(key\)\)\}…`;/);
});

test('17 (review): the remote-access pointer links LuCI’s Remote access page on this router, and the guide', () => {
  assert.match(HTML, /<p class="hint" id="gwRemote" data-i18n="gw\.remote"><\/p>/);
  const loc = { protocol: 'http:', hostname: '192.168.86.1', port: '6969', host: '192.168.86.1:6969' };
  for (const lang of ['en', 'fa']) {
    const text = str(lang, 'gw.remote');
    const h = harness({ fns: ['renderRemotePointer'], extra: { t: () => text, location: loc } });
    h.el('#gwRemote').children.push('stale');   // a language switch renders it again
    h.ctx.renderRemotePointer();
    const parts = h.el('#gwRemote').children;
    assert.equal(parts.map((c) => (typeof c === 'string' ? c : c.textContent)).join(''), text, `${lang}: the words are the string, verbatim`);
    const links = parts.filter((c) => typeof c !== 'string');
    assert.equal(links.length, 2, `${lang}: two links`);
    assert.ok(links[0].textContent.startsWith('LuCI ') && !links[0].textContent.includes('('), `${lang}: the LuCI path is the first link: ${links[0].textContent}`);
    assert.equal(links[0].href, 'http://192.168.86.1/cgi-bin/luci/admin/services/irnetfree/remote', 'LuCI on this router — its own port, not the web UI’s');
    assert.equal(links[1].textContent, 'docs/remote.md');
    assert.equal(links[1].href, 'https://github.com/sadrazkh/Irnetfree_xray-client/blob/main/docs/remote.md');
    for (const a of links) {
      assert.equal(a.target, '_blank');
      assert.equal(a.rel, 'noopener');
    }
  }
  // a string without the expected places is shown as plain text, never mangled
  const plain = harness({ fns: ['renderRemotePointer'], extra: { t: () => 'something else', location: loc } });
  plain.ctx.renderRemotePointer();
  assert.deepEqual([...plain.el('#gwRemote').children], ['something else']);
  // rendered where the row shows, and again after a language switch (applyI18n resets it to plain text)
  assert.match(fnSource('applyFlavor'), /if \(rt\) renderRemotePointer\(\);/);
  assert.match(fnSource('setLang'), /if \(state\.flavor === 'openwrt'\) renderRemotePointer\(\);/);
  // the page has no other link: without a rule it is the browser's dark blue on the dark panel (seen in a render)
  assert.match(CSS, /\.hint a\s*\{[^}]*color:\s*var\(--accentInk\)/);
});
