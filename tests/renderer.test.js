'use strict';
/**
 * The contract between the markup, the stylesheet and app.js.
 *
 * app.js reaches into the DOM by id, styles elements by class, and every string
 * on screen comes from a `data-i18n` key. None of that is type-checked and none
 * of it fails loudly: a redesign that renames one id leaves a button that does
 * nothing, a dropped CSS class leaves an unreadable control, a missing i18n key
 * shows the raw key to the user. All three are silent in a browser.
 *
 * So this file pins the contract. It is what makes it safe to replace the whole
 * visual layer: the look may change completely, these hooks may not.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const R = (f) => fs.readFileSync(path.join(__dirname, '..', 'src', 'renderer', f), 'utf8');
const HTML = R('index.html');
const APP = R('app.js');
// The diagnostics dialog is built entirely in JS, so none of its strings and
// none of its classes reach index.html — it has to be read on its own.
const DIAG = R('diagnostics.js');
// the stylesheet is split by surface (styles/home/lists/routing/settings/skins);
// the contract is against all of it, so read them as one
const CSS_FILES = ['styles.css', 'home.css', 'lists.css', 'routing.css', 'settings.css', 'skins.css', 'diagnostics.css'];
const CSS = CSS_FILES.map(R).join(String.fromCharCode(10));
const I18N = R('i18n.js');

const htmlIds = new Set([...HTML.matchAll(/id="([^"]+)"/g)].map((m) => m[1]));

/** Every id app.js looks up, however it looks it up. */
function idsAppUses() {
  const ids = new Set();
  for (const m of APP.matchAll(/\$\(\s*['"`]#([A-Za-z0-9_-]+)['"`]/g)) ids.add(m[1]);
  for (const m of APP.matchAll(/getElementById\(\s*['"`]([A-Za-z0-9_-]+)['"`]/g)) ids.add(m[1]);
  for (const m of APP.matchAll(/querySelector(?:All)?\(\s*['"`]#([A-Za-z0-9_-]+)/g)) ids.add(m[1]);
  // Built at runtime, not in the markup: the view sections are addressed as
  // '#view-' + name, and the throughput caption is created by the traffic-path
  // builder (and is read defensively, so its absence is never a fault).
  ids.delete('view-');
  ids.delete('pathCapIn');
  return ids;
}

test('every element app.js reaches for exists in the markup', () => {
  const missing = [...idsAppUses()].filter((id) => !htmlIds.has(id)).sort();
  assert.deepEqual(missing, [], 'app.js would silently do nothing for these ids');
});

test('every nav item has the view it switches to', () => {
  const views = [...HTML.matchAll(/data-view="([^"]+)"/g)].map((m) => m[1]);
  assert.ok(views.length >= 8, `expected the full nav, found ${views.length}`);
  for (const v of views) {
    assert.ok(htmlIds.has('view-' + v), `data-view="${v}" has no #view-${v} section`);
  }
});

test('the routing mode buttons cover every mode the builder understands', () => {
  const modes = new Set([...HTML.matchAll(/data-mode="([^"]+)"/g)].map((m) => m[1]));
  for (const m of ['global', 'bypass-ir', 'bypass-cn', 'direct']) {
    assert.ok(modes.has(m), `no button for routing mode "${m}"`);
  }
});

test('every string on screen resolves in both languages', () => {
  const keys = new Set();
  for (const a of ['data-i18n', 'data-i18n-ph', 'data-i18n-title']) {
    for (const m of HTML.matchAll(new RegExp(a + '="([^"]+)"', 'g'))) keys.add(m[1]);
  }
  assert.ok(keys.size > 200, `expected the markup to be fully translated, found ${keys.size} keys`);
  // The diagnostics dialog has no markup to scan: every one of its strings is a
  // 'diag.…' key handed to t(), tel() or say(), so the keys ARE the contract.
  const diag = new Set([...DIAG.matchAll(/'(diag\.[A-Za-z0-9.]+)'/g)].map((m) => m[1]));
  assert.ok(diag.size >= 30, `expected the whole dialog to be translated, found ${diag.size} keys`);
  for (const k of diag) keys.add(k);
  const bad = [...keys].filter((k) => (I18N.split(`'${k}':`).length - 1) !== 2).sort();
  assert.deepEqual(bad, [], 'these keys are not defined exactly once in each of fa and en');
});

/**
 * The OpenWrt gateway (v1.13.0): the device list under LAN sharing and the
 * inspector's gateway row. Hidden until the service reports flavor=openwrt —
 * on the desktop these must never show — and every string of theirs is a key
 * in both languages, including the ones only t() ever sees.
 */
test('the OpenWrt device list and gateway row exist, hidden by default, and are fully translated', () => {
  for (const id of ['gwRow', 'gwList', 'btnGwRefresh', 'insGatewayRow', 'insGateway', 'gwQuicRow', 'optLanBlockQuic']) {
    assert.ok(htmlIds.has(id), `#${id} is missing`);
  }
  assert.match(HTML, /id="gwQuicRow" hidden/, 'the QUIC switch is a router thing');
  const between = HTML.slice(HTML.indexOf('id="lanInfo"'), HTML.indexOf('id="optKillSwitch"'));
  assert.ok(between.includes('id="gwRow"'), 'the device list sits under LAN sharing, before the kill switch');
  assert.match(HTML, /id="gwRow" hidden/, 'hidden until flavor=openwrt');
  assert.match(HTML, /id="insGatewayRow" hidden/, 'hidden until flavor=openwrt');
  assert.match(APP, /state\.flavor = data\.flavor \|\| null/);

  const keys = new Set();
  for (const m of HTML.matchAll(/data-i18n(?:-ph|-title)?="(gw\.[^"]+|ins\.gateway)"/g)) keys.add(m[1]);
  for (const m of APP.matchAll(/\bt\(\s*'(gw\.[^']+)'/g)) keys.add(m[1]);
  assert.ok(keys.size >= 10, `expected the whole card to be translated, found ${keys.size} keys`);
  const bad = [...keys].filter((k) => (I18N.split(`'${k}':`).length - 1) !== 2).sort();
  assert.deepEqual(bad, [], 'these keys are not defined exactly once in each of fa and en');

  // the classes the list is built from exist in the stylesheet
  for (const cls of ['gw-list', 'gw-item', 'gw-dot', 'gw-name', 'gw-meta', 'gw-direct', 'gw-check']) {
    assert.ok(CSS.includes('.' + cls), `.${cls} has no style`);
  }
});

/**
 * v1.16.1 (field report items 1-2): the owner could not tell what the
 * inspector's "Gateway" row was, nor select it — it looked like the switches
 * around it and was two bare spans. With flavor=openwrt it is a button whose
 * tooltip says what it means and whose click opens the device list; the whole
 * router layout is pinned in tests/rendererRouter.test.js.
 */
test('flavor=openwrt: the inspector gateway row is a button that explains itself and opens the device list', () => {
  assert.match(HTML, /<button type="button" class="ins-row" id="insGatewayRow" hidden data-i18n-title="gw\.insHint">/);
  assert.match(APP, /\$\('#insGatewayRow'\)\.onclick = \(\) => openSettingAt\('#gwRow'\);/);
  const vm = require('node:vm');
  const els = {};
  const node = (id) => els[id] || (els[id] = { id, hidden: true, textContent: '', checked: false,
    setAttribute() {}, closest: () => null, querySelector: () => null });
  const $ = (sel) => node(String(sel).replace(/^#/, ''));
  const ctx = vm.createContext({ state: { flavor: 'openwrt', settings: {} }, $, t: (k) => k, renderLanDevices: () => {}, renderRemotePointer: () => {} });
  vm.runInContext(fnSource('applyFlavor'), ctx);
  ctx.applyFlavor();
  assert.equal(els.insGatewayRow.hidden, false, 'shown on the router');
  assert.equal(els.gwRow.hidden, false, 'with the device list it opens');
  ctx.state.flavor = null;
  ctx.applyFlavor();
  assert.equal(els.insGatewayRow.hidden, true, 'never on the desktop');
});

/**
 * The dialog's own controls. styles.css resets `button { background:none;
 * border:0 }` and gives inputs `color: inherit`, so a class-less <button> in
 * there rendered as bare padded text and its <input>s as near-white text on the
 * UA's white box. They have to opt into the shared classes like every other
 * control, and nothing may write a visible string past t().
 */
test('the diagnostics dialog uses the shared controls and no hard-coded strings', () => {
  const buttons = [...DIAG.matchAll(/tel\('button', '[^']+', '([^']+)'\)/g)].map((m) => m[1]);
  assert.equal(buttons.length, 6, 'the dialog has six buttons');
  assert.equal(buttons.filter((c) => c === 'btn primary').length, 1, 'only Test is the primary action');
  for (const cls of buttons) assert.match(cls, /^btn( |$)/, `a class-less button renders as bare text: "${cls}"`);
  assert.equal([...DIAG.matchAll(/el\('input', null, '([^']+)'\)/g)].map((m) => m[1]).length, 2);
  assert.doesNotMatch(DIAG, /el\('input', null, '(?!input')/, 'an unstyled input is white on white');

  // el() writes its second argument verbatim; tel() sends it through t(). A
  // quoted word there is therefore untranslated English on screen. The \b is
  // load-bearing: without it the pattern matches the "el(" inside "tel(".
  assert.doesNotMatch(DIAG, /\bel\('(?:p|h3|li|span|h2|button)', '[A-Za-z]/,
    'a visible string written straight into el() never reaches t()');

  // Neither the direction nor the language is the dialog's to decide: it is a
  // panel of the page, and the page is RTL in Persian.
  assert.doesNotMatch(DIAG, /\.dir\s*=|\.lang\s*=/, 'the dialog must follow the page direction');

  // One idempotent teardown, run by the button AND the event — the `close`
  // event alone did not arrive in every Chromium, and the panel could then
  // never be reopened.
  assert.match(DIAG, /close\.onclick = \(\) => teardown\(\)/);
  assert.match(DIAG, /addEventListener\('close', \(\) => teardown\(\)\)/);
  assert.match(DIAG, /function teardown\(\) \{\s*if \(!panel\) return;/);
});

/**
 * Per-app routing under the sing-box TUN (D10) — the row in the TUN card.
 *
 * Three things can go wrong silently here and nowhere else catches them: an id
 * app.js drives that the markup never grew, a mode the config builder does not
 * understand (the tunnel would then be built from a value nothing routes on),
 * and `tunapp.pickNone` — the one string of this row that never reaches the
 * markup, because it only ever appears in a toast, so the whole-markup i18n
 * test above cannot see it.
 */
test('the TUN card carries the per-app routing controls, in both languages', () => {
  for (const id of ['tunAppRow', 'optTunAppMode', 'tunAppModeCards', 'tunAppsBlock',
    'optTunApps', 'tunAppsPick', 'btnTunAppsPick', 'tunAppStrictNote', 'tunAppNeedsSingbox']) {
    assert.ok(htmlIds.has(id), `#${id} is missing from the TUN card`);
  }

  // it belongs to the tunnel's own card, between the backend and the guard
  const between = HTML.slice(HTML.indexOf('id="tunBackendRow"'), HTML.indexOf('id="leakGuardRow"'));
  assert.ok(between.includes('id="tunAppRow"'),
    'the per-app row is not in the TUN card, after the backend row');

  // exactly the modes the sing-box config builder understands
  const from = HTML.slice(HTML.indexOf('id="optTunAppMode"'));
  const select = from.slice(0, from.indexOf('</select>'));
  const modes = [...select.matchAll(/<option value="([^"]*)"/g)].map((m) => m[1]);
  assert.deepEqual(modes, ['off', 'exclude', 'only']);

  const keys = new Set();
  for (const m of HTML.matchAll(/data-i18n(?:-ph|-title)?="(tunapp\.[^"]+)"/g)) keys.add(m[1]);
  for (const m of APP.matchAll(/\bt\(\s*'(tunapp\.[^']+)'/g)) keys.add(m[1]);
  assert.ok(keys.size >= 10, `expected the whole row to be translated, found ${keys.size} keys`);
  const bad = [...keys].filter((k) => (I18N.split(`'${k}':`).length - 1) !== 2).sort();
  assert.deepEqual(bad, [], 'these keys are not defined exactly once in each of fa and en');
});

/**
 * Classes app.js puts on elements it creates. A stylesheet that no longer
 * styles one of them leaves a live control invisible or unreadable, which no
 * other test would catch. The baseline is what the shipped stylesheet already
 * covers — this asserts a redesign does not drop any of them.
 */
test('the stylesheet still covers every class app.js builds elements with', () => {
  const cls = new Set();
  for (const m of APP.matchAll(/className\s*=\s*['"`]([^`"'${]+)['"`]/g)) {
    String(m[1]).split(/\s+/).forEach((c) => c && cls.add(c));
  }
  for (const m of APP.matchAll(/class="([^"${]+)"/g)) {
    String(m[1]).split(/\s+/).forEach((c) => c && cls.add(c));
  }
  for (const m of APP.matchAll(/classList\.(?:add|toggle|remove)\(\s*['"`]([A-Za-z0-9_-]+)['"`]/g)) cls.add(m[1]);

  const styled = (c) => new RegExp('\\.' + c.replace(/[-]/g, '\\-') + '(?![A-Za-z0-9_-])').test(CSS);
  // Only the ones the shipped stylesheet already covers are load-bearing; the
  // rest inherit their look from a base class and always did.
  const baseline = [...cls].filter(styled);
  assert.ok(baseline.length > 100, `expected a broad baseline, found ${baseline.length}`);
  const dropped = baseline.filter((c) => !styled(c));
  assert.deepEqual(dropped, [], 'these classes lost their styling');
});

test('the shell keeps the parts the window is built from', () => {
  // Frameless window: our own minimise / maximise / close, and the drag region.
  for (const id of ['btnMin', 'btnMax', 'btnClose']) {
    assert.ok(htmlIds.has(id), `window control #${id} is gone`);
  }
  assert.match(CSS, /-webkit-app-region\s*:\s*drag/, 'nothing can drag the frameless window any more');
  assert.match(CSS, /-webkit-app-region\s*:\s*no-drag/, 'controls inside the title bar would be undraggable');
});

test('both themes and both writing directions are still styled', () => {
  assert.match(CSS, /\[data-theme="light"\]/, 'the light theme is gone');
  assert.match(CSS, /:root/, 'the dark theme tokens are gone');
  // RTL is the primary language: the layout must be written in logical
  // properties, not left/right, or Persian comes out mirrored.
  const logical = (CSS.match(/(?:margin|padding|border|inset)-inline/g) || []).length;
  assert.ok(logical >= 20, `expected logical properties throughout, found ${logical}`);
});

test('the markup carries no inline style attributes', () => {
  // An inline style bypasses the tokens, the three skins and the RTL logical
  // properties, and nothing else in this file can see it.
  const inline = [...HTML.matchAll(/ style="([^"]*)"/g)].map((m) => m[1]);
  assert.deepEqual(inline, []);
});

/**
 * The traffic path has to survive a narrow window. The owner's report was a
 * throughput caption printed on top of the "This device" node: the caption was
 * absolutely positioned and centred on a link that flexbox had shrunk to 56px,
 * while the caption itself needed 115px, so it escaped onto its neighbour — and
 * the panel scrolled sideways instead of reflowing, hiding the rest.
 *
 * Measured in the browser at 900px (the window's own minimum) across all three
 * skins and all three path shapes after the fix: no overlap, no overflow, no
 * scrollbar, nothing truncated. These assertions pin the properties that make
 * that true, because none of them can be checked without a layout engine.
 */
test('the traffic path reflows instead of scrolling, and its caption cannot escape its link', () => {
  const rule = (selector) => {
    const i = CSS.indexOf(selector + ' {');
    assert.ok(i !== -1, `no rule for ${selector}`);
    return CSS.slice(i, CSS.indexOf('}', i));
  };

  const panel = rule('.path-panel');
  assert.match(panel, /flex-wrap:\s*wrap/, 'the panel must wrap; a single row clips at 900px');
  assert.doesNotMatch(panel, /overflow-x:\s*auto/, 'wrapping replaces the sideways scrollbar');

  const link = rule('.path-link');
  assert.match(link, /flex-direction:\s*column/, 'the caption sits above the line, in flow');
  assert.match(link, /min-width:\s*auto/,
    'a numeric min-width lets flexbox shrink the link under its own caption — the original bug');

  // The caption must take part in layout: positioned out of flow, its width
  // says nothing about the link's, and it lands on whatever is next to it.
  const cap = rule('.path-cap');
  assert.doesNotMatch(cap, /position:\s*absolute/);
});

/* --------------------------- stored values in the markup --------------------------- */

/** Every `${…}` on one line, braces balanced. */
function interpolations(line) {
  const out = [];
  for (let i = line.indexOf('${'); i !== -1; i = line.indexOf('${', i + 2)) {
    let depth = 0, j = i + 1;
    for (; j < line.length; j++) {
      if (line[j] === '{') depth++;
      else if (line[j] === '}' && --depth === 0) break;
    }
    out.push(line.slice(i + 2, j).trim());
  }
  return out;
}

// A backup is a file someone can hand you; servers, chains, pool entries,
// subscriptions and settings come out of it and are drawn with innerHTML. So a
// line that builds markup may interpolate a record's field only through
// escapeHtml() — or through a helper that escapes (or only ever yields
// numbers), or as the condition of a ternary between two literals.
test('no stored value reaches innerHTML unescaped', () => {
  const SAFE_CALL = /^(escapeHtml|usageLabel|subUsageHtml|processOptions|fmtBytes|fmtSpeed|fmtDuration|fmtMs|t)\(/;
  const LITERAL_TERNARY = /^[^?`]+\?\s*('[^']*'|"[^"]*")\s*:\s*('[^']*'|"[^"]*")$/;
  const RECORD = /(^|[^.\w$])(s|sub|chain|entry|info|server|srv|c|d|e|g|p|u)\.\w|^(id|value)$/;
  let seen = 0;
  const bad = [];
  APP.split(/\r?\n/).forEach((line, n) => {
    if (!/<\/?[a-z]/i.test(line)) return;
    for (const e of interpolations(line)) {
      seen++;
      if (SAFE_CALL.test(e) || LITERAL_TERNARY.test(e)) continue;
      if (RECORD.test(e)) bad.push(`app.js:${n + 1}: \${${e}}`);
    }
  });
  assert.ok(seen > 60, `expected to scan the markup builders, saw ${seen} interpolations`);
  assert.deepEqual(bad, [], 'escape these with escapeHtml()');
});

test('escapeHtml covers every character that can leave an attribute or a text node', () => {
  const escapeHtml = appFunction('escapeHtml');
  assert.equal(escapeHtml(`"><img src=x onerror='a&b'>`), '&quot;&gt;&lt;img src=x onerror=&#39;a&amp;b&#39;&gt;');
  assert.equal(escapeHtml(443), '443');
});

/* --------------------------- the edit form's transports --------------------------- */

/** A top-level `function name(…) {…}` from app.js, compiled on its own (it must not need the DOM). */
function appFunction(name) {
  const start = APP.indexOf(`\nfunction ${name}(`);
  assert.ok(start > -1, `app.js has no function ${name}`);
  let depth = 0, j = APP.indexOf('{', start);
  for (; j < APP.length; j++) {
    if (APP[j] === '{') depth++;
    else if (APP[j] === '}' && --depth === 0) break;
  }
  return new Function(`${APP.slice(start, j + 1)}; return ${name};`)();
}

test('the edit form offers every transport the parser builds, httpupgrade included', () => {
  const sel = HTML.match(/<select id="edNetwork"[^>]*>([\s\S]*?)<\/select>/);
  assert.ok(sel, 'no #edNetwork select');
  const opts = [...sel[1].matchAll(/value="([^"]+)"/g)].map((m) => m[1]);
  for (const n of ['tcp', 'ws', 'grpc', 'h2', 'xhttp', 'kcp', 'httpupgrade']) assert.ok(opts.includes(n), `no <option> for ${n}`);
  const front = APP.match(/const frontable = \[([^\]]+)\]/);
  assert.ok(front && /'httpupgrade'/.test(front[1]), 'httpupgrade rides a CDN like ws: its Host field must show');
});

/**
 * The edit form's own code — readServerFields, fillEditForm, collectEditFields
 * and the noise/select helpers — run against a fake DOM whose <select>s behave
 * like a browser's: a value with no matching <option> reads back as ''. The
 * options are the ones index.html has.
 */
function editFormHarness() {
  const vm = require('node:vm');
  const selectOptions = (id) => {
    const m = HTML.match(new RegExp(`<select id="${id}"[^>]*>([\\s\\S]*?)</select>`));
    return m ? [...m[1].matchAll(/value="([^"]*)"/g)].map((x) => x[1]) : null;
  };
  const els = new Map();
  const makeOption = (value) => {
    const o = { value, textContent: value, dataset: {}, parent: null };
    o.remove = () => { if (o.parent) o.parent.options.splice(o.parent.options.indexOf(o), 1); };
    return o;
  };
  const el = (id) => {
    if (els.has(id)) return els.get(id);
    const opts = selectOptions(id);
    const e = { id, hidden: false, checked: false, textContent: '', title: '', style: {}, dataset: {} };
    if (opts) {
      e.options = [];
      let v = '';
      e.appendChild = (o) => { o.parent = e; e.options.push(o); };
      opts.forEach((x) => e.appendChild(makeOption(x)));
      e.querySelectorAll = (q) => (q === 'option[data-own]' ? e.options.filter((o) => o.dataset.own) : []);
      Object.defineProperty(e, 'value', {
        get: () => v,
        set: (x) => { v = e.options.some((o) => o.value === String(x)) ? String(x) : ''; }
      });
    } else {
      let v = '';
      Object.defineProperty(e, 'value', { get: () => v, set: (x) => { v = String(x == null ? '' : x); } });
    }
    els.set(id, e);
    return e;
  };
  const $ = (sel) => (typeof sel === 'string' && sel[0] === '#' ? el(sel.slice(1)) : null);
  const document = { createElement: () => makeOption('') };
  const ctx = vm.createContext({ $, document });
  const src = (name) => {
    const start = APP.indexOf(`\nfunction ${name}(`);
    assert.ok(start > -1, `app.js has no function ${name}`);
    let depth = 0, j = APP.indexOf('{', start);
    for (; j < APP.length; j++) {
      if (APP[j] === '{') depth++;
      else if (APP[j] === '}' && --depth === 0) break;
    }
    return APP.slice(start, j + 1);
  };
  const consts = APP.match(/^const NOISE_PRESET_KEYS = .*;$/m);
  assert.ok(consts, 'no NOISE_PRESET_KEYS in app.js');
  vm.runInContext([consts[0], ...['readServerFields', 'fillEditForm', 'collectEditFields', 'setNoiseFields', 'readNoiseField',
    'syncNoiseCustom', 'show', 'selectValue'].map(src)].join('\n'), ctx);
  return ctx;
}

test('a no-op save through the real edit form records nothing, for every shape the parser builds', () => {
  const { parseLink, applyServerEdits } = require('../src/main/parser');
  const form = editFormHarness();
  const b64 = (s) => Buffer.from(s).toString('base64');
  const legacyHu = parseLink('vless://u@h.example.com:443?type=httpupgrade&security=tls&sni=cdn.example.com&path=%2Fup&host=cdn.example.com#HU');
  delete legacyHu.outbound.streamSettings.httpupgradeSettings;   // stored before httpupgrade had settings
  const shapes = {
    'xhttp+reality': parseLink('vless://11111111-2222-3333-4444-555555555555@x.example.com:443?type=xhttp&security=reality&sni=www.speedtest.net&fp=chrome&pbk=PUBKEY&sid=ab12&spx=%2Fs&path=%2Fxh&mode=packet-up&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D#XH'),
    grpc: parseLink('vless://u@g.example.com:443?type=grpc&serviceName=svc&mode=multi&security=tls&sni=g.example.com&alpn=h2#G'),
    'tcp+http': parseLink('vless://u@t.example.com:80?type=tcp&headerType=http&path=%2Fa&host=t.com#T'),
    h2: parseLink('vless://u@h.example.com:443?type=h2&path=%2Fp&host=a.com,b.com&security=tls#H2'),
    'httpupgrade legacy': legacyHu,
    kcp: parseLink('vless://u@k.example.com:443?type=kcp&headerType=srtp&seed=S#K'),
    'ws+tls': parseLink('trojan://pw@b.example.com:443?security=tls&sni=b.example.com&type=ws&path=%2Ftr&host=b.example.com&allowInsecure=1#W'),
    'vmess ws': parseLink('vmess://' + b64(JSON.stringify({ v: '2', ps: 'VM', add: 'vm.example.com', port: '443', id: 'uuid-vm', aid: '0', net: 'ws', path: '/vm', host: 'vm.example.com', tls: 'tls' }))),
    ss: parseLink('ss://' + b64('aes-256-gcm:secret') + '@ss.example.com:8388#SS'),
    socks: parseLink('socks://user:pass@1.2.3.4:1080#S'),
    http: parseLink('http://dXNlcjpwYXNz@1.2.3.4:8080#H'),
    wireguard: parseLink('wireguard://K@wg.example.com:51820?publickey=P&presharedkey=PSK&address=10.0.0.5%2F32&allowedips=10.0.0.0%2F8,192.168.0.0%2F16&mtu=1380&reserved=1,2,3&dns=192.168.60.1,tes.systems#WG'),
    'fp qq': parseLink('vless://u@q.example.com:443?type=ws&security=tls&sni=q.example.com&fp=qq&path=%2Fq#Q'),
    'fp 360': parseLink('vless://u@q.example.com:443?type=ws&security=tls&sni=q.example.com&fp=360&path=%2Fq#Q'),
    'noise fakehello': parseLink('vless://u@n.example.com:443?security=tls&sni=n.example.com&noise=fakehello&fragment=tlshello,100-200,10-20#N'),
    'noise FakeTLS': parseLink('vless://u@n.example.com:443?security=tls&sni=n.example.com&noise=FakeTLS#N'),
    'engine outside the options': parseLink('vless://u@e.example.com:443?security=tls&sni=e.example.com&engine=xray-custom#E')
  };
  for (const [name, rec] of Object.entries(shapes)) {
    form.fillEditForm(form.readServerFields(rec), rec.protocol);
    const fields = form.collectEditFields(rec, false);
    const out = applyServerEdits(rec, fields);
    assert.equal('_edited' in out, false, `${name}: recorded ${JSON.stringify(out._edited)}`);
    if (name === 'httpupgrade legacy') continue;   // the rebuild repairs it — unrecorded, so the refresh still owns it
    assert.deepEqual(out, rec, `${name}: a no-op save changed the server`);
  }
});

/* --------------------------- the connection snapshot (v1.16 S1 / S4) --------------------------- */

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
/** The body of a `window.api.onX((d) => { … });` handler, as a named function. */
function handlerSource(name) {
  const head = `window.api.${name}((d) => {`;
  const start = APP.indexOf(head);
  assert.ok(start > -1, `app.js has no ${name} handler`);
  const end = APP.indexOf('\n});', start);
  // `var`: a vm script's top-level let/const never becomes a property of its context
  return `var ${name} = (d) => {${APP.slice(start + head.length, end)}\n};`;
}
const STRINGS = { 'state.reconnectingN': 'Reconnecting… (attempt {n})', 'state.waiting': 'Waiting for internet… (attempt {n})', 't.disconnected': 'Disconnected' };

/** applyConnSnapshot and the status handlers over a fake page: what they paint and what they say. */
function snapshotHarness(flavor = 'openwrt') {
  const vm = require('node:vm');
  const calls = [];
  const els = new Map();
  const el = (id) => {
    if (!els.has(id)) els.set(id, { id, textContent: '', hidden: false, className: '', title: '', classList: { add() {}, remove() {}, toggle() {} }, setAttribute() {} });
    return els.get(id);
  };
  const ctx = vm.createContext({
    state: { connected: false, connecting: false, activeServerId: null, activeEngine: '', selectedServerId: null, lastServerId: null, settings: {}, flavor, servers: [], pendingReconnect: [], wasReconnecting: false, lan: null },
    $: (sel) => el(String(sel).replace(/^#/, '')),
    t: (k) => STRINGS[k] || k,
    toast: (msg, kind) => calls.push('toast:' + (kind || '') + ':' + msg),
    setConnUI: (s) => calls.push('ui:' + s),
    appendLog: (line) => calls.push('log:' + line),
    renderServers: () => {}, renderPicker: () => {}, renderPendingBanner: () => {}, setPending: () => {}, setModeWidget: () => {},
    updateLanInfo: () => {}, hideGeo: () => {}, resetTraffic: () => {}, checkIp: () => {}, quickPing: (id) => calls.push('quickPing:' + id), updateAdminBtn: () => {},
    reconnectingKey: () => 'state.reconnecting', failedKey: () => 'net.failed',
    // timers run at once, so what a handler defers (the quick ping, the IP check) is seen
    setInterval: () => 1, clearInterval: () => {}, setTimeout: (fn) => { try { fn(); } catch {} return 1; }, Date,
    window: { api: {} }
  });
  vm.runInContext(['var uptimeTimer = null;', 'var uptimeFrom = 0;', fnSource('startUptime'), fnSource('attemptText'),
    fnSource('applyKillSwitchState'), fnSource('applyConnSnapshot'),
    // what a 'connected' status says besides the state (v1.16.3, tests/windowsVisibility.test.js)
    fnSource('connIssuesFrom'), fnSource('noticeText'), fnSource('connectToasts'), fnSource('toastSeries'),
    handlerSource('onStatus'), handlerSource('onXrayStatus')].join('\n'), ctx);
  return { ctx, calls, el };
}

test('S1: a page loaded while the tunnel is up starts connected, with the uptime from the service and no toast — idempotently', () => {
  const h = snapshotHarness();
  const since = Date.now() - 65000;
  const up = { state: 'connected', serverId: 's1', engine: 'xray', since, reason: null, attempt: 0, killSwitch: { enabled: false, armed: false, blocking: false } };
  h.ctx.applyConnSnapshot(up);
  assert.equal(h.ctx.state.connected, true);
  assert.equal(h.ctx.state.connecting, false);
  assert.equal(h.ctx.state.activeServerId, 's1');
  assert.equal(h.ctx.state.activeEngine, 'xray');
  assert.equal(h.ctx.uptimeFrom, since, 'the clock counts from when the service says the tunnel came up');
  assert.deepEqual(h.calls, ['ui:connected'], 'no toast, no log line');
  // the same snapshot again (an events reconnect): nothing new is said
  h.ctx.applyConnSnapshot(up);
  assert.deepEqual(h.calls, ['ui:connected', 'ui:connected']);
  assert.equal(h.ctx.uptimeFrom, since);

  h.ctx.applyConnSnapshot({ state: 'reconnecting', serverId: 's1', attempt: 2, reason: 'core-exited' });
  assert.equal(h.ctx.state.connected, false);
  assert.equal(h.ctx.state.connecting, true);
  assert.equal(h.el('connState').textContent, 'Reconnecting… (attempt 2)');
  h.ctx.applyConnSnapshot({ state: 'waiting', serverId: 's1', attempt: 3 });
  assert.equal(h.el('connState').textContent, 'Waiting for internet… (attempt 3)');
  h.ctx.applyConnSnapshot({ state: 'disconnected', serverId: null, since: null });
  assert.equal(h.ctx.state.connected, false);
  assert.equal(h.ctx.state.connecting, false);
  assert.equal(h.calls.at(-1), 'ui:disconnected');
  assert.ok(!h.calls.some((c) => c.startsWith('toast:')), 'a snapshot never toasts: ' + h.calls.join(', '));
  // a snapshot with nothing in it changes nothing
  h.ctx.applyConnSnapshot(null);
  assert.equal(h.calls.filter((c) => c.startsWith('ui:')).length, 5);
});

test('S4: on the router a reconnecting status shows the attempt, a waiting status the boot retry, and a core stop that is being rebuilt paints nothing', () => {
  const h = snapshotHarness();
  h.ctx.onStatus({ state: 'connected', serverId: 's1', engine: 'xray' });
  assert.equal(h.ctx.state.connected, true);
  h.ctx.onStatus({ state: 'reconnecting', serverId: 's1', reason: 'core-exited', attempt: 2, retryInMs: 5000 });
  assert.equal(h.ctx.state.connecting, true);
  assert.equal(h.el('connState').textContent, 'Reconnecting… (attempt 2)');
  assert.ok(!h.calls.some((c) => /^toast:err/.test(c)), 'no red toast: ' + h.calls.join(', '));
  h.ctx.onStatus({ state: 'waiting', serverId: 's1', attempt: 4, retryInMs: 15000 });
  assert.equal(h.el('connState').textContent, 'Waiting for internet… (attempt 4)');
  assert.equal(h.ctx.state.connecting, true);
  // the core died under a live connection and the service is rebuilding: not a disconnect
  h.ctx.onStatus({ state: 'connected', serverId: 's1', engine: 'xray' });
  const before = h.calls.length;
  h.ctx.onXrayStatus({ state: 'stopped', info: { code: null, signal: 'SIGKILL' }, rebuilding: true });
  assert.equal(h.ctx.state.connected, true, 'still connected until the service says otherwise');
  assert.equal(h.calls.length, before, 'nothing painted, nothing toasted');
  // …while a final stop (no rebuild coming) still paints disconnected with its toast
  h.ctx.onXrayStatus({ state: 'stopped', info: { code: 0 } });
  assert.equal(h.ctx.state.connected, false);
  assert.ok(h.calls.includes('ui:disconnected') && h.calls.some((c) => c.startsWith('toast:err')));
  // the desktop keeps its own wording for a recovery (no attempt in the text)
  const d = snapshotHarness(null);
  d.ctx.onStatus({ state: 'reconnecting', serverId: 's1', reason: 'interfaces', attempt: 1 });
  assert.equal(d.el('connState').textContent, 'state.reconnecting');
});

test('S6: the router does not start a test core for the quick ping after every connect; the desktop still does', () => {
  const router = snapshotHarness('openwrt');
  router.ctx.onStatus({ state: 'connected', serverId: 's1', engine: 'xray' });
  assert.ok(!router.calls.some((c) => c.startsWith('quickPing:')), router.calls.join(', '));
  const desktop = snapshotHarness(null);
  desktop.ctx.onStatus({ state: 'connected', serverId: 's1', engine: 'xray' });
  assert.ok(desktop.calls.includes('quickPing:s1'), desktop.calls.join(', '));
});

/* --------------------------- the router's kill switch (v1.16 K1/K4) --------------------------- */

test('K1/K4: on the router the kill switch row shows with router wording, the banner says the LAN is blocked, and its action is the disconnect', () => {
  // the row is no longer among the desktop-only rows hidden on the router
  const flavor = fnSource('applyFlavor');
  assert.doesNotMatch(flavor, /'optKillSwitch'/, 'the kill switch row is not hidden on the router any more');
  assert.match(flavor, /kill\.routerTitle/);
  assert.match(flavor, /kill\.routerSub/);
  assert.match(flavor, /kill\.routerBlocked/);
  assert.match(flavor, /kill\.routerOff/);
  // the banner's "Turn the VPN off" is the disconnect (which disarms), as before
  assert.match(APP, /\$\('#killDisarm'\)\.onclick = async \(\) => \{[\r\n]+[\s\S]*?await window\.api\.disconnect\(\);/);
  // the strings, in both languages
  const keys = ['kill.routerTitle', 'kill.routerSub', 'kill.routerBlocked', 'kill.routerOff', 'kill.routerArmed'];
  for (const k of keys) assert.equal(I18N.split(`'${k}':`).length - 1, 2, k);
  assert.match(I18N, /'kill\.routerBlocked': '⛔ LAN internet is blocked until the VPN is back'/);
  assert.match(I18N, /'kill\.routerOff': 'Turn the VPN off'/);
  assert.match(I18N, /'kill\.routerTitle': 'Kill switch'/);

  // the state from a snapshot or a killswitch event paints the banner and the status line
  const vm = require('node:vm');
  const els = new Map();
  const el = (id) => { if (!els.has(id)) els.set(id, { id, textContent: '', hidden: true, className: '' }); return els.get(id); };
  const calls = [];
  const ctx = vm.createContext({
    state: { flavor: 'openwrt', settings: { killSwitch: true }, platform: 'linux', elevated: true },
    $: (sel) => el(String(sel).replace(/^#/, '')),
    t: (k) => k,
    toast: (msg, kind) => calls.push('toast:' + kind + ':' + msg)
  });
  vm.runInContext([fnSource('applyKillSwitchState'), fnSource('updateKillStatus')].join('\n'), ctx);
  ctx.applyKillSwitchState({ enabled: true, armed: true, blocking: true });
  assert.equal(el('killBanner').hidden, false, 'blocking: the banner shows');
  assert.equal(ctx.state.killEngaged, true);
  assert.equal(el('killStatus').textContent, 'kill.routerBlocked');
  ctx.applyKillSwitchState({ enabled: true, armed: true, blocking: false });
  assert.equal(el('killBanner').hidden, true);
  assert.equal(el('killStatus').textContent, 'kill.routerArmed');
  ctx.applyKillSwitchState({ enabled: true, armed: false, blocking: false });
  assert.equal(el('killStatus').textContent, '');
  // the desktop's kill switch events are not the router's
  ctx.state.flavor = null;
  ctx.applyKillSwitchState({ enabled: true, armed: true, blocking: true });
  assert.equal(el('killBanner').hidden, true, 'nothing of the router’s on the desktop');
  // the event handler: the router's wording in the toast
  const h = vm.createContext({
    state: { flavor: 'openwrt', settings: {}, killEngaged: false },
    $: (sel) => el(String(sel).replace(/^#/, '')),
    t: (k) => k,
    toast: (msg, kind) => calls.push('toast:' + kind + ':' + msg),
    window: { api: {} }
  });
  vm.runInContext([fnSource('applyKillSwitchState'), fnSource('updateKillStatus'), handlerSource('onKillSwitch')].join('\n'), h);
  h.onKillSwitch({ engaged: true, router: true, enabled: true, armed: true, blocking: true });
  assert.ok(calls.includes('toast:err:kill.routerBlocked'), calls.join(', '));
  assert.equal(el('killBanner').hidden, false);
});

/* --------------------------- "Connect when the router starts" (v1.16 B1) --------------------------- */

test('B1: on the router the autoConnect row says what it does — "Connect when the router starts" with its hint; the desktop keeps the old text', () => {
  for (const k of ['autoconn.routerTitle', 'autoconn.routerSub']) assert.equal(I18N.split(`'${k}':`).length - 1, 2, k);
  assert.match(I18N, /'autoconn\.routerTitle': 'Connect when the router starts'/);
  assert.match(I18N, /'autoconn\.routerSub': 'After a reboot or power cut the VPN comes back as it was'/);
  assert.match(I18N, /'autoconn\.routerTitle': 'با روشن شدن روتر وصل شو'/);
  assert.match(I18N, /'autoconn\.routerSub': 'بعد از ریبوت یا قطع برق، VPN همان‌طور که بود برمی‌گردد'/);
  // the desktop strings stay
  assert.match(I18N, /'autoconn\.title': 'Connect automatically'/);
  assert.match(I18N, /'autoconn\.title': 'اتصال خودکار'/);

  // applyFlavor relabels the row through data-i18n (so a language switch keeps the wording) — run against a fake page
  const vm = require('node:vm');
  const relabelled = {};
  const node = (id) => ({ id, hidden: false, checked: false, textContent: '', attrs: {},
    setAttribute(k, v) { this.attrs[k] = v; relabelled[this.id] = v; }, closest() { return rows[this.id] || null; }, querySelector(sel) { return (rows[this.id] && rows[this.id].parts[sel]) || null; } });
  const rows = {};
  const row = (id) => { const title = node(id + ':title'); const sub = node(id + ':sub'); rows[id] = { hidden: false, parts: { '.switch-title': title, '.switch-sub': sub }, querySelector(sel) { return this.parts[sel] || null; } }; return rows[id]; };
  for (const id of ['optSysProxy', 'optLaunchAtLogin', 'optDnsManaged', 'optKillSwitch', 'optAutoConnect']) row(id);
  const els = {};
  const $ = (sel) => {
    const m = /^#([A-Za-z0-9_-]+)(?: (.+))?$/.exec(sel);
    if (!m) return null;
    if (m[2]) return node(m[1] + ' ' + m[2]);
    return els[m[1]] || (els[m[1]] = node(m[1]));
  };
  const ctx = vm.createContext({ state: { flavor: 'openwrt', settings: {} }, $, t: (k) => k, renderLanDevices: () => {}, renderRemotePointer: () => {} });
  vm.runInContext(fnSource('applyFlavor'), ctx);
  ctx.applyFlavor();
  assert.equal(relabelled['optAutoConnect:title'], 'autoconn.routerTitle');
  assert.equal(relabelled['optAutoConnect:sub'], 'autoconn.routerSub');
  assert.equal(rows.optAutoConnect.parts['.switch-title'].textContent, 'autoconn.routerTitle');
  assert.equal(rows.optAutoConnect.hidden, false, 'the row stays');
  ctx.state.flavor = null;
  ctx.applyFlavor();
  assert.equal(relabelled['optAutoConnect:title'], 'autoconn.title', 'the desktop gets its own wording back');
  assert.equal(relabelled['optAutoConnect:sub'], 'autoconn.sub');
});

test('S4: the attempt strings exist in both languages, verbatim', () => {
  for (const k of ['state.reconnectingN', 'state.waiting']) assert.equal(I18N.split(`'${k}':`).length - 1, 2, k);
  assert.match(I18N, /'state\.reconnectingN': 'Reconnecting… \(attempt \{n\}\)'/);
  assert.match(I18N, /'state\.reconnectingN': 'اتصال مجدد… \(تلاش \{n\}\)'/);
  assert.match(I18N, /'state\.waiting': 'Waiting for internet… \(attempt \{n\}\)'/);
  assert.match(I18N, /'state\.waiting': 'منتظر اینترنت… \(تلاش \{n\}\)'/);
});

test('the edit form reads an httpupgrade path and Host, and shows a stored raw server as tcp', () => {
  const readServerFields = appFunction('readServerFields');
  const rec = (streamSettings) => ({
    protocol: 'vless', name: 'x', address: 'a.example.com', port: 443,
    outbound: { protocol: 'vless', settings: { vnext: [{ users: [{ id: 'u' }] }] }, streamSettings }
  });
  const hu = readServerFields(rec({ network: 'httpupgrade', security: 'tls', httpupgradeSettings: { path: '/up', host: 'cdn.example.com' }, tlsSettings: { serverName: 'cdn.example.com' } }));
  assert.deepEqual([hu.network, hu.path, hu.host], ['httpupgrade', '/up', 'cdn.example.com']);
  const raw = readServerFields(rec({ network: 'raw', security: 'none', tcpSettings: { header: { type: 'http', request: { path: ['/a'], headers: { Host: ['t.com'] } } } } }));
  assert.deepEqual([raw.network, raw.path, raw.host], ['tcp', '/a', 't.com']);
});
