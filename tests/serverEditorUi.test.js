'use strict';
/**
 * The full server editor, the window's side (app.js over serverFields.js): the
 * draft both views share, what each field shows when, what a save refuses,
 * what it sends; every label in both languages; the markup and its wiring.
 * docs/superpowers/specs/2026-10-12-server-editor-design.md.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const SF = require('../src/renderer/serverFields');
const { parseLink, applyServerEdits, editFields } = require('../src/main/parser');

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const APP = R('src', 'renderer', 'app.js');
const HTML = R('src', 'renderer', 'index.html');
const I18N = R('src', 'renderer', 'i18n.js');
const LISTS = R('src', 'renderer', 'lists.css');

function fnSource(name) {
  const start = APP.indexOf(`\nfunction ${name}(`) > -1 ? APP.indexOf(`\nfunction ${name}(`) : APP.indexOf(`\nasync function ${name}(`);
  assert.ok(start > -1, `app.js has no function ${name}`);
  const eol = APP.indexOf('\n', start + 1);
  if (/\}\s*$/.test(APP.slice(start + 1, eol))) return APP.slice(start, eol);
  const end = APP.indexOf('\n}\n', eol);
  return APP.slice(start, end + 2);
}
/** Both languages' tables, as the renderer has them. */
function i18n() {
  const ctx = { window: {}, document: { documentElement: {}, querySelectorAll: () => [] } };
  vm.runInNewContext(I18N, ctx);
  return (lang, key) => { ctx.window.i18n.applyI18n(lang); return ctx.window.i18n.t(key); };
}

const ENC = 'mlkem768x25519plus.native.0rtt.p7sTtcQlhzr21By6QMbFOEFjtHJa8dquXhK7pboK9GE';
const UUID = '2c0f0d9a-6b3a-4f0e-9a1f-8c2b4d6e7a10';

/** The editor's draft functions, over the real table and the real readServerFields. */
function harness(lang = 'en') {
  const tr = i18n();
  const toasts = [];
  const ctx = vm.createContext({
    window: { ServerFields: SF }, t: (k) => tr(lang, k), toast: (m, k) => toasts.push([m, k]),
    state: { servers: [] }, crypto: require('node:crypto').webcrypto, JSON, String, Array, Object, Number, Uint8Array
  });
  vm.runInContext([
    "let editDraft = null; let editView = 'pro'; let editTab = 'protocol'; let editNew = false; let editBad = null; let editOriginal = null; let editClearPin = false;",
    "const PROTO_NAMES = { vless: 'VLESS', vmess: 'VMess', trojan: 'Trojan', shadowsocks: 'Shadowsocks', hysteria2: 'Hysteria2', wireguard: 'WireGuard', socks: 'SOCKS5', http: 'HTTP' };",
    ...['sfTable', 'readServerFields', 'draftOf', 'newDraft', 'draftCtx', 'fieldShown', 'fieldLabel', 'optionLabel', 'draftProblem', 'draftFields', 'newUuid'].map(fnSource)
  ].join('\n'), ctx);
  ctx.setDraft = (d) => vm.runInContext('editDraft = ' + JSON.stringify(d), ctx);
  ctx.draft = () => vm.runInContext('editDraft', ctx);
  ctx.setNew = (v) => vm.runInContext('editNew = ' + !!v, ctx);
  return { ctx, toasts };
}

test('draftOf: a record’s values in the table’s names — what parser.editFields says — for every protocol', () => {
  const { ctx } = harness();
  const links = [
    `vless://${UUID}@de.example.com:443?encryption=${ENC}&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=ab12&spx=%2Fs#R`,
    `vless://${UUID}@de.example.com:443?encryption=none&type=xhttp&path=%2Fx&host=h.example&mode=stream-one&security=tls&sni=h.example&alpn=h2,http/1.1#X`,
    `trojan://pw@fr.example.com:443?type=grpc&serviceName=svc&authority=cdn.example&mode=multi&security=tls&sni=fr.example.com#G`,
    'hysteria2://auth@h.example.com:443/?sni=h.example.com&obfs=salamander&obfs-password=op&mport=20000-30000&hopInterval=45#H'
  ];
  for (const link of links) {
    const s = applyServerEdits(parseLink(link), { wsHeartbeat: '30', tcpFastOpen: true, mux: 'off' });
    const d = ctx.draftOf(s);
    const want = editFields(s);
    for (const k of Object.keys(want)) {
      if (['serviceName', 'name', 'engine'].includes(k)) continue;
      const field = SF.FIELDS.find((f) => f.id === k);
      const norm = (v) => (field && field.kind === 'switch' ? !!v : String(v == null ? '' : v));
      assert.equal(norm(d[k]), norm(want[k]), `${link.slice(0, 12)}… ${k}`);
    }
  }
});

test('the fields a draft shows: by protocol, transport and security; TCP’s Host and path only with its HTTP header', () => {
  const { ctx } = harness();
  const shown = (d) => { ctx.setDraft(d); return SF.FIELDS.filter((f) => ctx.fieldShown(f)).map((f) => f.id); };
  const tcp = shown(Object.assign(ctx.newDraft('vless'), { network: 'tcp', headerType: 'none' }));
  assert.ok(!tcp.includes('host') && !tcp.includes('path'));
  assert.ok(shown(Object.assign(ctx.newDraft('vless'), { network: 'tcp', headerType: 'http' })).includes('host'));
  const wg = shown(ctx.newDraft('wireguard'));
  assert.ok(wg.includes('privateKey') && wg.includes('wgKeepAlive') && !wg.includes('network') && !wg.includes('sni'));
  const reality = shown(Object.assign(ctx.newDraft('vless'), { security: 'reality' }));
  assert.ok(reality.includes('pbk') && reality.includes('spx') && !reality.includes('alpn'));
  const hy2 = shown(ctx.newDraft('hysteria2'));
  assert.ok(hy2.includes('sni') && hy2.includes('alpn') && hy2.includes('hopInterval') && !hy2.includes('fp'));
});

test('labels by protocol and transport; options labelled where they need it, else themselves', () => {
  const { ctx } = harness('en');
  const by = (id) => SF.FIELDS.find((f) => f.id === id);
  ctx.setDraft(Object.assign(ctx.newDraft('trojan'), { network: 'grpc' }));
  assert.equal(ctx.fieldLabel(by('host')), 'Authority');
  assert.equal(ctx.fieldLabel(by('path')), 'Service name');
  ctx.setDraft(ctx.newDraft('hysteria2'));
  assert.equal(ctx.fieldLabel(by('password')), 'Password (auth)');
  ctx.setDraft(ctx.newDraft('wireguard'));
  assert.equal(ctx.fieldLabel(by('address')), 'Endpoint host');
  assert.equal(ctx.optionLabel(by('mux'), 'on'), 'On');
  assert.equal(ctx.optionLabel(by('mux'), ''), 'The app’s setting');
  assert.equal(ctx.optionLabel(by('flow'), 'xtls-rprx-vision'), 'xtls-rprx-vision');
  assert.equal(ctx.optionLabel(by('flow'), ''), '— none —');
  assert.equal(ctx.optionLabel(by('fp'), 'chrome'), 'chrome');
});

test('a save refuses, naming the field and its tab: a bad number or range, bad JSON, a bad or empty Encryption, a new server’s missing basics', () => {
  const { ctx } = harness();
  const d = (o) => Object.assign(ctx.newDraft('vless'), { address: 'a.example', uuid: UUID }, o);
  ctx.setDraft(d({ network: 'xhttp', xmuxMaxConcurrency: '16 to 32' }));
  assert.deepEqual(JSON.parse(JSON.stringify(ctx.draftProblem())), { id: 'xmuxMaxConcurrency', tab: 'transport', why: 'edit.err.range' });
  ctx.setDraft(d({ network: 'ws', wsHeartbeat: '3.5' }));
  assert.equal(ctx.draftProblem().why, 'edit.err.number');
  ctx.setDraft(d({ finalMask: '{"tcp":' }));
  assert.equal(ctx.draftProblem().id, 'finalMask');
  ctx.setDraft(d({ encryption: 'mlkem768x25519plus.plain.0rtt.' + 'k'.repeat(43) }));
  assert.equal(ctx.draftProblem().why, 'edit.err.encMode');
  ctx.setDraft(d({ _encOn: true, encryption: '' }));
  assert.equal(ctx.draftProblem().id, 'encryption');
  ctx.setDraft(d({ encryption: ENC }));
  assert.equal(ctx.draftProblem(), null);
  ctx.setNew(true);
  ctx.setDraft(Object.assign(ctx.newDraft('trojan'), { address: 'tr.example' }));
  assert.deepEqual(JSON.parse(JSON.stringify(ctx.draftProblem())), { id: 'password', tab: 'protocol', why: 'edit.err.required' });
  ctx.setDraft(ctx.newDraft('vless'));
  assert.equal(ctx.draftProblem().id, 'address');
  ctx.setNew(false);
});

test('what a save sends: the whole draft in the parser’s names — none for an empty Encryption, the path as gRPC’s service name', () => {
  const { ctx } = harness();
  ctx.setDraft(Object.assign(ctx.newDraft('vless'), { _encOn: false, encryption: '', path: 'svc' }));
  const f = ctx.draftFields();
  assert.equal(f.encryption, 'none');
  assert.equal(f.serviceName, 'svc');
  assert.equal('_encOn' in f, false);
  assert.equal('protocol' in f, false, 'an edit never changes the protocol');
  assert.match(ctx.newUuid(), /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test('every label, hint, group heading and labelled option of the table — and the window’s own strings — in Persian and English', () => {
  const tr = i18n();
  const keys = [];
  for (const f of SF.FIELDS) {
    keys.push('sf.' + f.id);
    if (f.hint) keys.push(`sf.${f.id}.hint`);
    if (f.group) keys.push('sfg.' + f.group);
    if (f.optionLabels) for (const o of f.options) if (f.optionLabels === 'all' || !o) keys.push(`sfo.${f.id}.${o || '_'}`);
  }
  for (const n of SF.NETWORKS) keys.push('sfo.network.' + n);
  for (const s of ['none', 'tls', 'reality']) keys.push('sfo.security.' + s);
  for (const p of SF.PROTOCOLS) keys.push('sfp.' + p);
  for (const tab of SF.TABS) keys.push('edit.tab.' + tab);
  for (const k of ['edit.err.number', 'edit.err.range', 'edit.err.json', 'edit.err.encPrefix', 'edit.err.encMode', 'edit.err.encRtt', 'edit.err.encKey',
    'edit.err.required', 'edit.err.in', 'edit.view.simple', 'edit.view.pro', 'edit.local', 'edit.localTip', 'edit.localNote', 'edit.moreInPro', 'edit.proLink',
    'edit.newTitle', 'btn.addManual', 'edit.protoFixed', 'edit.protoPick', 'edit.noTransport', 'edit.noSecurity', 'edit.noTls', 'edit.genUuid',
    'edit.enc.auth', 'edit.enc.mode', 'edit.enc.pq', 't.serverCreated', 'sfo.encMode.none', 'sfo.encMode.mlkem', 'sf.encryptionValue']) keys.push(k);
  for (const k of new Set(keys)) {
    for (const lang of ['fa', 'en']) {
      const v = tr(lang, k);
      assert.notEqual(v, k, `${lang} has no '${k}'`);
      assert.ok(v.trim(), `${lang} '${k}' is empty`);
    }
  }
});

test('the markup: the view switch, the Simple and Pro containers, the table loaded before app.js, the Manual button; wired', () => {
  assert.match(HTML, /<div class="seg ed-view" id="edView"[\s\S]*?data-edit-view="simple"[\s\S]*?data-edit-view="pro"/);
  assert.match(HTML, /<div class="ed-simple" id="edSimple">/);
  assert.match(HTML, /<div class="ed-simple-extra" id="edSimpleExtra" hidden><\/div>/);
  assert.match(HTML, /<div class="ed-pro" id="edPro" hidden>\s*<nav class="ed-tabs" id="edTabs" role="tablist"><\/nav>\s*<div class="ed-pane" id="edProPane" role="tabpanel"><\/div>/);
  assert.ok(HTML.indexOf('<script src="serverFields.js"></script>') > -1 && HTML.indexOf('<script src="serverFields.js"></script>') < HTML.indexOf('<script src="app.js"></script>'));
  assert.match(HTML, /id="btnManualOpen" data-i18n="btn\.addManual"/);
  assert.match(APP, /for \(const b of document\.querySelectorAll\('#edView \[data-edit-view\]'\)\) b\.onclick = \(\) => setEditView\(b\.dataset\.editView\);/);
  assert.match(APP, /if \(\$\('#btnManualOpen'\)\) \$\('#btnManualOpen'\)\.onclick = openNewServer;/);
  assert.match(fnSource('saveEdit'), /if \(editNew\) return saveNewServer\(\);/);
  assert.match(fnSource('saveNewServer'), /window\.api\.createServer\(fields\)/);
  // the view used last is remembered; a new server never changes it
  assert.match(fnSource('setEditView'), /if \(!editNew\) \{ try \{ localStorage\.setItem\(EDIT_VIEW_KEY, v\);/);
});

test('the editor’s styles: logical sides only (RTL and LTR), the app’s tokens, the 11 / 12 px scale', () => {
  const start = LISTS.indexOf('/* ------------------------------ the server editor');
  const end = LISTS.indexOf('/* ----------------------------- subscriptions');
  assert.ok(start > -1 && end > start);
  const block = LISTS.slice(start, end);
  assert.doesNotMatch(block, /margin-(left|right)|padding-(left|right)|[^-](left|right):\s*\d|text-align:\s*(left|right)/);
  assert.doesNotMatch(block, /#[0-9a-f]{3,6}\b/i, 'colours from the tokens only');
  const sizes = new Set([...block.matchAll(/(\d+(?:\.\d+)?)px var\(--(?:mono|ui)\)|font-size:\s*(\d+(?:\.\d+)?)px/g)].map((m) => m[1] || m[2]));
  assert.deepEqual([...sizes].sort(), ['11', '12']);
});
