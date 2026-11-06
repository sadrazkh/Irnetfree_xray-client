'use strict';
/**
 * SNI spoof, per config (src/main/sniSpoof.js; the «جعل SNI» extension): the
 * helpers — names, the random pick, the sing-box version, the rights, the
 * refusals in both languages —, the editor's three fields and what a save
 * refuses, the record round trip through the parser (written when on, gone
 * when off, never in a share link, kept by a backup), the extension's gate
 * (off by default, Android left out, the generated Kotlin table without the
 * fields), and the wiring of main.js, service.js and app.js read as text. The
 * builder's fields are in singboxBuilder.test.js, the engine in
 * engineChoice.test.js; the wire is scripts/probe-sni-spoof.js (CI, root).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const SP = require('../src/main/sniSpoof');
const SF = require('../src/renderer/serverFields');
const MODS = require('../src/renderer/modules');
const { parseLink, applyServerEdits, buildShareLink } = require('../src/main/parser');
const { buildSingboxConfig } = require('../src/main/singboxBuilder');
const backup = require('../src/main/backup');

const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const MAIN = R('src', 'main', 'main.js');
const SVC = R('src', 'server', 'service.js');
const APP = R('src', 'renderer', 'app.js');
const I18N = R('src', 'renderer', 'i18n.js');
const KT = R('android', 'app', 'src', 'main', 'java', 'com', 'irnetfree', 'vpn', 'core', 'ServerFieldsTable.kt');
const YML = R('.github', 'workflows', 'test.yml');
const PROBE = R('scripts', 'probe-sni-spoof.js');

function i18n() {
  const ctx = { window: {}, document: { documentElement: {}, querySelectorAll: () => [] } };
  vm.runInNewContext(I18N, ctx);
  return (lang, key) => { ctx.window.i18n.applyI18n(lang); return ctx.window.i18n.t(key); };
}
const LINK = 'vless://11111111-1111-1111-1111-111111111111@a.example.com:443?type=ws&host=a.example.com&path=/ws&security=tls&sni=a.example.com&fp=chrome#one';
const spoofed = (over) => Object.assign(parseLink(LINK), { sniSpoof: true, sniSpoofNames: ['www.example.com', 'cdn.example.net'] }, over || {});
const ON = { modules: { sniSpoof: true } };

/* ------------------------------------ the helpers ------------------------------------ */

test('names: trimmed, lower-cased, no empties or doubles; a list or a comma string; a hostname and never an IP, a URL or a path', () => {
  assert.deepEqual(SP.spoofNamesOf({ sniSpoofNames: [' WWW.Example.com ', '', 'cdn.example.net', 'www.example.com'] }), ['www.example.com', 'cdn.example.net']);
  assert.deepEqual(SP.spoofNamesOf({ sniSpoofNames: 'a.example, b.example  c.example' }), ['a.example', 'b.example', 'c.example']);
  assert.deepEqual(SP.spoofNamesOf({}), []);
  assert.deepEqual(SP.spoofNamesOf(null), []);
  for (const ok of ['www.example.com', 'example', 'a-b.example.net.', 'xn--mgbh0fb.example']) assert.equal(SP.validSpoofName(ok), true, ok);
  for (const bad of ['', '1.2.3.4', '2001:db8::1', 'https://www.example.com', 'www.example.com/x', 'a b.example', 'user@example.com', 'x'.repeat(254)]) assert.equal(SP.validSpoofName(bad), false, bad);
  // the editor's rule is the same one (serverFields.spoofNameOk)
  for (const n of ['www.example.com', '1.2.3.4', 'https://x.example', 'a b']) assert.equal(SF.spoofNameOk(n), SP.validSpoofName(n), n);
});

test('the method: sing-box’s five, the first its default; anything else is the default', () => {
  assert.deepEqual(SP.SPOOF_METHODS, ['wrong-sequence', 'wrong-checksum', 'wrong-ack', 'wrong-md5', 'wrong-timestamp']);
  assert.equal(SP.DEFAULT_METHOD, 'wrong-sequence');
  assert.equal(SP.spoofMethodOf({ sniSpoofMethod: 'wrong-md5' }), 'wrong-md5');
  assert.equal(SP.spoofMethodOf({ sniSpoofMethod: ' Wrong-ACK ' }), 'wrong-ack');
  for (const v of ['', undefined, 'nonsense', 42]) assert.equal(SP.spoofMethodOf({ sniSpoofMethod: v }), 'wrong-sequence', String(v));
});

test('wantsSniSpoof is the record’s switch AND a name; spoofsSni adds the extension installed in the settings', () => {
  assert.equal(SP.wantsSniSpoof(spoofed()), true);
  assert.equal(SP.wantsSniSpoof(spoofed({ sniSpoof: false })), false);
  assert.equal(SP.wantsSniSpoof(spoofed({ sniSpoof: 'true' })), false, 'a string is not the switch');
  assert.equal(SP.wantsSniSpoof(spoofed({ sniSpoofNames: [] })), false);
  assert.equal(SP.wantsSniSpoof(null), false);
  assert.equal(SP.spoofsSni(spoofed(), ON), true);
  assert.equal(SP.spoofsSni(spoofed(), {}), false, 'no extension');
  assert.equal(SP.spoofsSni(spoofed(), { modules: { antiDpi: true } }), false);
  assert.equal(SP.spoofsSni(spoofed(), { modules: { sniSpoof: 'yes' } }), false);
  assert.equal(SP.spoofsSni(spoofed({ sniSpoof: false }), ON), false);
});

test('the pick: one of the names, by the number given, any of them otherwise; the TLS fields only when the connect spoofs', () => {
  const names = ['a.example', 'b.example', 'c.example'];
  assert.equal(SP.pickSpoofName(names, 0), 'a.example');
  assert.equal(SP.pickSpoofName(names, 0.34), 'b.example');
  assert.equal(SP.pickSpoofName(names, 0.999), 'c.example');
  assert.equal(SP.pickSpoofName(names, 1), 'c.example', 'never past the end');
  assert.equal(SP.pickSpoofName([], 0), '');
  const seen = new Set();
  for (let i = 0; i < 60; i++) seen.add(SP.pickSpoofName(names));
  assert.ok(seen.size >= 2 && [...seen].every((n) => names.includes(n)), 'random picks land on the names, more than one of them');
  assert.deepEqual(SP.spoofTlsFields(spoofed(), ON, 0), { spoof: 'www.example.com' });
  assert.deepEqual(SP.spoofTlsFields(spoofed({ sniSpoofMethod: 'wrong-checksum' }), ON, 0.9), { spoof: 'cdn.example.net', spoof_method: 'wrong-checksum' });
  assert.equal(SP.spoofTlsFields(spoofed(), {}), null);
  assert.equal(SP.spoofTlsFields(spoofed({ sniSpoof: false }), ON), null);
});

test('singboxSpoofs: 1.14.0 and newer; an unknown version is no', () => {
  for (const v of ['1.14.0', '1.14.3', 'sing-box version 1.14.4', '1.15.0-alpha.1', '2.0.0']) assert.equal(SP.singboxSpoofs(v), true, v);
  for (const v of ['1.13.14', '1.12.0', '0.9.9', '', null, 'x']) assert.equal(SP.singboxSpoofs(v), false, String(v));
  assert.deepEqual(SP.SINGBOX_SPOOF_SINCE, [1, 14]);
});

test('spoofElevated: Administrator on Windows, root elsewhere', () => {
  assert.equal(SP.spoofElevated('win32', () => true), true);
  assert.equal(SP.spoofElevated('win32', () => false), false);
  assert.equal(SP.spoofElevated('linux', () => true, () => 0), true);
  assert.equal(SP.spoofElevated('linux', () => true, () => 1000), false, 'the Windows answer is not asked on Linux');
  assert.equal(SP.spoofElevated('darwin', () => true, () => 501), false, 'macOS: root, not the osascript escalation TUN has');
  assert.equal(SP.spoofElevated('linux', () => false, () => { throw new Error('x'); }), false);
});

test('the refusals name the config and say what to do, in both languages', () => {
  const s = { name: 'My config' };
  for (const why of ['missing', 'old', 'admin', 'router', 'carry', 'arm64', 'other']) {
    const fa = SP.sniSpoofError(s, why, 'fa', why === 'admin' ? 'win32' : 'detail');
    const en = SP.sniSpoofError(s, why, 'en', why === 'admin' ? 'win32' : 'detail');
    assert.ok(fa.includes('My config') && /[؀-ۿ]/.test(fa), why + ' fa');
    assert.ok(en.includes('My config') && !/[؀-ۿ]/.test(en), why + ' en');
  }
  assert.match(SP.sniSpoofError(s, 'missing', 'en'), /sing-box.*1\.14.*Required files/);
  assert.match(SP.sniSpoofError(s, 'old', 'en', '1.13.14'), /\(1\.13\.14\).*older than 1\.14/);
  assert.match(SP.sniSpoofError(s, 'admin', 'en', 'win32'), /Administrator.*relaunch/);
  assert.match(SP.sniSpoofError(s, 'admin', 'en', 'linux'), /root.*CAP_NET_RAW/);
  assert.match(SP.sniSpoofError(s, 'admin', 'fa', 'darwin'), /root/);
  assert.match(SP.sniSpoofError(s, 'carry', 'en', 'xhttp transport not supported'), /cannot carry this config \(xhttp transport not supported\)/);
  assert.match(SP.sniSpoofError(s, 'router', 'fa'), /روتر/);
  assert.match(SP.sniSpoofError(null, 'missing', 'en'), /"config"/);
});

/* ------------------------------------ the editor ------------------------------------ */

test('the table: three fields in Security, the SNI spoof extension’s, this device’s, desktop and router only, for TLS/REALITY on the stream protocols and AnyTLS', () => {
  const by = (id) => SF.FIELDS.find((f) => f.id === id);
  const sw = by('sniSpoof'), names = by('sniSpoofNames'), method = by('sniSpoofMethod');
  assert.deepEqual([sw.tab, sw.group, sw.kind, sw.path, sw.module, sw.local, sw.simple, sw.hint], ['security', 'sniSpoof', 'switch', '@sniSpoof', 'sniSpoof', true, true, true]);
  assert.deepEqual([names.kind, names.path, names.module, names.local, names.simple], ['list', '@sniSpoofNames', 'sniSpoof', true, true]);
  assert.deepEqual([method.kind, method.path, method.module, method.optionLabels], ['select', '@sniSpoofMethod', 'sniSpoof', true]);
  assert.deepEqual(method.options, ['', ...SP.SPOOF_METHODS], 'the empty one is sing-box’s default');
  for (const f of [sw, names, method]) {
    assert.deepEqual(f.platforms, ['desktop', 'router'], f.id);
    assert.deepEqual(f.when, { protocols: ['vless', 'vmess', 'trojan', 'shadowsocks', 'anytls'], securities: ['tls', 'reality'] }, f.id);
    assert.equal(SF.fieldOnPlatform(f, 'android'), false);
    assert.equal(SF.fieldOnPlatform(f, 'desktop'), true);
  }
  assert.equal(SF.fieldOnPlatform(by('sni'), 'android'), true, 'a field without platforms is everywhere');
  // the three in a row, after the REALITY fields
  const ids = SF.FIELDS.map((f) => f.id);
  assert.deepEqual(ids.slice(ids.indexOf('sniSpoof'), ids.indexOf('sniSpoof') + 3), ['sniSpoof', 'sniSpoofNames', 'sniSpoofMethod']);
  assert.ok(ids.indexOf('sniSpoof') > ids.indexOf('pqv'));
  // where they apply
  assert.equal(SF.fieldApplies(sw, { protocol: 'vless', network: 'ws', security: 'tls' }), true);
  assert.equal(SF.fieldApplies(sw, { protocol: 'trojan', network: 'tcp', security: 'reality' }), true);
  assert.equal(SF.fieldApplies(sw, { protocol: 'anytls', network: 'tcp', security: 'tls' }), true);
  assert.equal(SF.fieldApplies(sw, { protocol: 'vless', network: 'tcp', security: 'none' }), false);
  for (const p of ['hysteria2', 'tuic', 'masque', 'wireguard', 'socks', 'http']) assert.equal(SF.fieldApplies(sw, { protocol: p, network: 'tcp', security: 'tls' }), false, p);
  // the names field refuses what sing-box would: an IP, a URL
  assert.equal(SF.validate(names, 'www.example.com, cdn.example.net'), null);
  assert.equal(SF.validate(names, ''), null);
  assert.equal(SF.validate(names, 'www.example.com, 1.2.3.4'), 'edit.err.sniSpoofName');
  assert.equal(SF.validate(names, 'https://www.example.com'), 'edit.err.sniSpoofName');
  // the form's values as the record keeps them: a list, a boolean, a string; empty deletes the key
  assert.deepEqual(SF.fromForm(names, 'a.example, b.example'), ['a.example', 'b.example']);
  assert.equal(SF.fromForm(names, ''), undefined);
  assert.equal(SF.fromForm(sw, false), undefined);
  assert.equal(SF.fromForm(sw, true), true);
  assert.equal(SF.fromForm(method, ''), undefined);
});

test('sniSpoofRefusal: TLS over TCP and a name, or the save says why; off, nothing is asked', () => {
  const tls = (network, protocol = 'vless', security = 'tls') => ({ protocol, network, security });
  const on = { sniSpoof: true, sniSpoofNames: 'www.example.com' };
  for (const n of ['tcp', 'ws', 'grpc', 'httpupgrade']) assert.equal(SF.sniSpoofRefusal(tls(n), on), null, n);
  assert.equal(SF.sniSpoofRefusal(tls('tcp', 'vless', 'reality'), on), null);
  assert.equal(SF.sniSpoofRefusal(tls('tcp', 'anytls'), on), null, 'AnyTLS: TLS over TCP by nature');
  assert.deepEqual(SF.sniSpoofRefusal(tls('xhttp'), on), { id: 'sniSpoof', why: 'edit.err.sniSpoofTransport' });
  assert.deepEqual(SF.sniSpoofRefusal(tls('kcp'), on), { id: 'sniSpoof', why: 'edit.err.sniSpoofTransport' });
  assert.deepEqual(SF.sniSpoofRefusal(tls('tcp', 'vless', 'none'), on), { id: 'sniSpoof', why: 'edit.err.sniSpoofTls' });
  assert.deepEqual(SF.sniSpoofRefusal(tls('tcp', 'hysteria2'), on), { id: 'sniSpoof', why: 'edit.err.sniSpoofTransport' }, 'QUIC: no TCP segment to forge');
  assert.deepEqual(SF.sniSpoofRefusal(tls('ws'), { sniSpoof: true, sniSpoofNames: ' , ' }), { id: 'sniSpoofNames', why: 'edit.err.sniSpoofNames' });
  assert.equal(SF.sniSpoofRefusal(tls('xhttp'), { sniSpoof: false, sniSpoofNames: 'x' }), null, 'off: nothing is asked');
  assert.equal(SF.sniSpoofRefusal(tls('xhttp'), null), null);
  // the window asks it where it refuses a save (draftProblem), and only while the field is on show
  assert.match(APP, /function draftProblem\(\)[\s\S]*?const spoofFld = F\.FIELDS\.find\(\(x\) => x\.id === 'sniSpoof'\);\s*if \(spoofFld && fieldShown\(spoofFld\)\) \{\s*const r = F\.sniSpoofRefusal\(draftCtx\(\), d\);\s*if \(r\) return \{ id: r\.id, tab: 'security', why: r\.why \};/);
});

test('the record round trip: the parser writes the three keys from the form and removes them when off; a share link never carries them; a backup keeps them', () => {
  const base = parseLink(LINK);
  const on = applyServerEdits(base, { sniSpoof: true, sniSpoofNames: 'www.example.com, cdn.example.net', sniSpoofMethod: 'wrong-checksum' });
  assert.equal(on.sniSpoof, true);
  assert.deepEqual(on.sniSpoofNames, ['www.example.com', 'cdn.example.net']);
  assert.equal(on.sniSpoofMethod, 'wrong-checksum');
  assert.equal(JSON.stringify(on.outbound), JSON.stringify(base.outbound), 'nothing of it in the outbound: the core never sees these keys');
  // the switch off (or the names emptied) deletes the keys — the record is the plain one again
  const off = applyServerEdits(on, { sniSpoof: false, sniSpoofNames: '', sniSpoofMethod: '' });
  assert.deepEqual(['sniSpoof', 'sniSpoofNames', 'sniSpoofMethod'].filter((k) => k in off), []);
  // an edit that does not mention them keeps them (a field the submit did not carry)
  const kept = applyServerEdits(on, { name: 'renamed' });
  assert.deepEqual([kept.sniSpoof, kept.sniSpoofNames, kept.sniSpoofMethod], [true, ['www.example.com', 'cdn.example.net'], 'wrong-checksum']);
  // a protocol change to one that has no TLS over TCP drops them (applyPathFields: a field that no longer applies)
  const plain = applyServerEdits(on, { security: 'none' });
  assert.equal('sniSpoof' in plain, false);
  // the share link is the same with and without them: no link key exists, none is invented
  assert.equal(buildShareLink(on), buildShareLink(base));
  assert.doesNotMatch(buildShareLink(on), /spoof/i);
  // a backup keeps the whole record: exported with the keys, imported with them
  const bundle = backup.exportBundle({ version: '1.46.0', store: { servers: [on], subscriptions: [], chains: [], pool: [], routingProfiles: [], groups: [], settings: {} } });
  const merged = backup.importBundle(bundle, { servers: [], subscriptions: [], chains: [], pool: [], routingProfiles: [], groups: [], settings: {} });
  const got = merged.next.servers.find((s) => s.id === on.id);
  assert.ok(got, 'the server came through the backup');
  assert.deepEqual([got.sniSpoof, got.sniSpoofNames, got.sniSpoofMethod], [true, ['www.example.com', 'cdn.example.net'], 'wrong-checksum']);
  // …and the builder writes them for that record
  assert.equal(buildSingboxConfig(on, Object.assign({ sniSpoofRandom: 0 }, ON)).outbounds[0].tls.spoof, 'www.example.com');
});

test('every string of the fields, the errors and the window’s own, in Persian and English', () => {
  const tr = i18n();
  const keys = ['sf.sniSpoof', 'sf.sniSpoof.hint', 'sf.sniSpoofNames', 'sf.sniSpoofNames.hint', 'sf.sniSpoofMethod', 'sf.sniSpoofMethod.hint', 'sfg.sniSpoof', 'sfo.sniSpoofMethod._',
    'edit.err.sniSpoofName', 'edit.err.sniSpoofNames', 'edit.err.sniSpoofTls', 'edit.err.sniSpoofTransport', 'sniSpoof.needSingbox', 'sniSpoof.oldSingbox', 'sniSpoof.relaunchConfirm'];
  for (const k of keys) {
    for (const lang of ['fa', 'en']) {
      const v = tr(lang, k);
      assert.ok(v && v !== k, `${lang} ${k}`);
      if (lang === 'fa') assert.match(v, /[؀-ۿ]/, k);
    }
  }
  assert.match(tr('en', 'sf.sniSpoof.hint'), /sing-box.*1\.14.*administrator/i);
  assert.match(tr('fa', 'sf.sniSpoofMethod.hint'), /wrong-sequence.*wrong-checksum.*wrong-ack.*wrong-md5.*wrong-timestamp/);
});

/* ------------------------------------ the extension ------------------------------------ */

test('the extension: off by default, security, desktop and router, needs nothing; Android has no such thing and its generated table has no such field', () => {
  const m = MODS.moduleOf('sniSpoof');
  assert.deepEqual([m.category, m.platforms, m.requires, m.icon], ['security', ['desktop', 'router'], [], '🎭']);
  assert.equal(MODS.available('sniSpoof', 'android'), false);
  assert.equal(MODS.isOn({ modules: {} }, 'sniSpoof'), false, 'a fresh store: off');
  assert.equal(MODS.isOn({ modulesMigrated: true, modules: MODS.migrateModules({ modulesMigrated: false }, { servers: [spoofed()] }) }, 'sniSpoof'), true, 'a store from before that uses it gets it on, once');
  assert.deepEqual(MODS.migrateModules({}, { servers: [parseLink(LINK)] }), {}, '…one that does not: nothing');
  assert.deepEqual(MODS.setModule({}, 'sniSpoof', true, 'android'), { modules: {}, error: 'unavailable' });
  assert.deepEqual(MODS.setModule({}, 'sniSpoof', true, 'desktop'), { modules: { sniSpoof: true } });
  assert.doesNotMatch(KT, /sniSpoof/, 'Android’s table is generated without the fields');
  assert.match(KT, /id = "pqv"/, '…and still has the rest');
  // the CSS rule that hides what the extension offers while it is off
  assert.match(R('src', 'renderer', 'styles.css'), /body\[data-mod-sni-spoof="off"\] \[data-module="sniSpoof"\]/);
});

/* ------------------------------------ the wiring (read as text) ------------------------------------ */

test('main.js and service.js: a spoofing connect needs sing-box 1.14 with the rights, runs on sing-box by the extension, and never falls back to Xray; the router refuses it by name', () => {
  for (const [name, src] of [['main.js', MAIN], ['service.js', SVC]]) {
    assert.match(src, /require\('\.\.?\/(?:main\/)?sniSpoof'\)/, name + ' requires sniSpoof.js');
    assert.match(src, /const spoofing = plan\.mode === 'single' && !isGroupRecord\(plan\.server\) && !rawServer && spoofsSni\(plan\.server, settings\) \? plan\.server : null;/, name);
    assert.match(src, /if \(!sbBin\) throw new Error\(sniSpoofError\(spoofing, 'missing', settings\.lang\)\);/, name);
    assert.match(src, /if \(!singboxSpoofs\(sbVersion\)\) throw new Error\(sniSpoofError\(spoofing, 'old', settings\.lang, sbVersion\)\);/, name);
    assert.match(src, /if \(!spoofElevated\(process\.platform, \(\) => tunPlatform\.isElevated\(\)\)\) throw new Error\(sniSpoofError\(spoofing, 'admin', settings\.lang, process\.platform\)\);/, name);
    assert.match(src, /chooseEngine\(plan, settings\.defaultEngine, \{ sniSpoof: MODS\.isOn\(settings, 'sniSpoof'\) \}\)/, name + ': the engine by the extension');
    assert.match(src, /if \(spoofing\) throw new Error\(sniSpoofError\(spoofing, 'carry', settings\.lang, e\.message\)\);\s*send\('log', \{ line: `sing-box: \$\{e\.message\} — using Xray`/, name + ': refused before the fallback');
    assert.match(src, /SNI spoof: a forged ClientHello with "\$\{spoofTls\.spoof\}"/, name + ': the name picked, in the log');
    // the gate stands before the engine is chosen
    assert.ok(src.indexOf('const spoofing = plan.mode') < src.indexOf("chooseEngine(plan, settings.defaultEngine, { sniSpoof"), name);
  }
  assert.match(SVC, /if \(OPENWRT\) throw new Error\(sniSpoofError\(spoofing, 'router', settings\.lang\)\);/);
  assert.match(MAIN, /if \(process\.platform === 'win32' && process\.arch === 'arm64'\) throw new Error\(sniSpoofError\(spoofing, 'arm64', settings\.lang\)\);/);
});

test('app.js: the admin question before a spoofing connect on Windows, the Required files dialog when the extension is installed without sing-box 1.14, and on a connect refused for it', () => {
  assert.match(APP, /if \(serverSpoofsSni\(id\) && !state\.elevated && state\.platform === 'win32'\) \{\s*if \(await promptRelaunchAdmin\('sniSpoof\.relaunchConfirm'\)\) return;/);
  assert.match(APP, /async function promptRelaunchAdmin\(why\) \{[\s\S]*?window\.confirm\(t\(why \|\| 'tun\.relaunchConfirm'\)\)/);
  assert.match(APP, /function serverSpoofsSni\(id\) \{[\s\S]*?M\.isOn\(state\.settings, 'sniSpoof'\)[\s\S]*?s\.sniSpoof !== true[\s\S]*?sniSpoofNames/);
  assert.match(APP, /afterSniSpoofInstalled\(modsBefore, res\.modules\);/);
  assert.match(APP, /function afterSniSpoofInstalled\(before, modules\) \{[\s\S]*?if \(!have\) \{ toast\(t\('sniSpoof\.needSingbox'\), 'warn'\); openFilesModal\(\['sing-box'\]\); return; \}\s*if \(v && !singboxSpoofsVersion\(v\)\) \{ toast\(t\('sniSpoof\.oldSingbox'\)\.replace\('\{v\}', v\), 'warn'\); openFilesModal\(\['sing-box'\]\); \}/);
  assert.match(APP, /else if \(\/sing-box\/\.test\(e\.message\) && !\(state\.assets && state\.assets\['sing-box'\]\)\) openFilesModal\(\['sing-box'\]\);/);
  // the window's version rule is sniSpoof.js's
  const fn = /function singboxSpoofsVersion\(v\) \{([\s\S]*?)\n\}/.exec(APP);
  assert.ok(fn, 'singboxSpoofsVersion');
  const f = new Function('v', fn[1]);
  for (const v of ['1.14.0', '1.13.14', '1.15.2', '']) assert.equal(f(v), SP.singboxSpoofs(v), v);
});

test('the probe: registered on its port base, root-gated, both methods and a control, in the workflow with the suggested sing-box', () => {
  assert.match(PROBE, /IRNF_PROBE_PORT \|\| 25100/);
  assert.match(PROBE, /process\.env\.IRNF_SPOOF_PROBE !== '1' \|\| process\.platform !== 'linux' \|\| !process\.getuid \|\| process\.getuid\(\) !== 0/);
  assert.match(PROBE, /singboxSpoofs\(version\)/, 'an older sing-box is a skip, not a failure');
  for (const s of ["clientConfig(true, 'wrong-sequence')", "clientConfig(true, 'wrong-checksum')", 'clientConfig(false)']) assert.ok(PROBE.includes(s), s);
  assert.doesNotMatch(PROBE, /0\.0\.0\.0/, 'nothing bound to every address');
  assert.match(YML, /sni-spoof:\n[\s\S]*?run: sudo IRNF_SPOOF_PROBE=1 IRNF_SINGBOX_EXE="\$RUNNER_TEMP\/s\/sing-box" "\$\(command -v node\)" scripts\/probe-sni-spoof\.js/);
  assert.match(YML, /SUGGESTED\['sing-box'\]"\)\n\s*echo "sing-box \$SV"/);
  assert.match(YML, /apt-get install -y tcpdump ethtool/);
  // the suggested sing-box has the spoof
  assert.equal(SP.singboxSpoofs(require('../src/main/coreVersions').SUGGESTED['sing-box']), true);
});

test('after the review: a spoofing server inside a chain, a routing or the pool is refused by name, and the plan builds as before with the extension off', () => {
  const { buildConfig } = require('../src/main/configBuilder');
  const S = { socksPort: 1, httpPort: 2, apiPort: 3, geoAssets: false, blockAds: false, enableSniffing: true, routingMode: 'global', modules: { sniSpoof: true }, lang: 'en' };
  const sp = Object.assign(spoofed(), { id: 'spoofer0000000000' });
  const other = Object.assign(parseLink(LINK.replace('a.example.com:443', 'b.example.com:443')), { id: 'other00000000000' });
  assert.throws(() => buildConfig({ mode: 'chain', chain: [other, sp], name: 'c' }, S), /SNI spoof on, which runs only when it is connected on its own/);
  const adv = { mode: 'advanced', serversById: { [sp.id]: sp, [other.id]: other }, chainsById: {}, chain: [], rules: [{ type: 'domain', value: 'a.test', target: sp.id, via: 'none' }], def: other.id, base: null, defVia: 'inherit', useMode: false };
  assert.throws(() => buildConfig(adv, S), /connected on its own/);
  // stored, but used by no rule: nothing is refused
  assert.doesNotThrow(() => buildConfig(Object.assign({}, adv, { rules: [] }), S));
  // the extension off: the record's switch means nothing, the plan builds as before
  assert.doesNotThrow(() => buildConfig({ mode: 'chain', chain: [other, sp], name: 'c' }, Object.assign({}, S, { modules: {} })));
  assert.match(SP.sniSpoofError(sp, 'plan', 'fa'), /تنها وصل شود/);
  assert.match(SP.sniSpoofError(sp, 'version', 'en'), /did not say its version/);
});

test('after the review: a spoofing config that carries patterniha masks is refused by sing-box, never run without them', () => {
  const S = { socksPort: 1, httpPort: 0, modules: { sniSpoof: true } };
  for (const over of [{ _noise: 'random' }, { streamSettings: { finalmask: { tcp: [{ type: 'merge' }] } } }, { streamSettings: { sockopt: { dialMode: 'x' } } }]) {
    const s = spoofed();
    if (over._noise) s.outbound._noise = over._noise;
    if (over.streamSettings) Object.assign(s.outbound.streamSettings, over.streamSettings);
    assert.throws(() => buildSingboxConfig(s, S), /patterniha masks/);
  }
  assert.doesNotThrow(() => buildSingboxConfig(spoofed(), S));
});
