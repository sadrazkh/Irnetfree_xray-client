'use strict';
/**
 * A link handed to the app from outside. Any web page can make a browser open
 * one, so it may only ever be a subscription, a config or a routing share, and
 * nothing is written or connected without the window asking first. Android's
 * DeepLinkTest.kt runs the same cases.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { parseDeepLink, linkFromArgv, classify, PROTOCOL } = require('../src/main/deepLink');

const ROOT = path.join(__dirname, '..');
const read = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8');
const enc = encodeURIComponent;

test('a subscription: by path or by query, with its host and only that to show', () => {
  const url = 'https://sub.example.com/api/secret-token?x=1';
  for (const link of [`irnetfree://import/${enc(url)}`, `irnetfree://import?url=${enc(url)}`, `irnetfree://import/?url=${enc(url)}`, `IRNETFREE://IMPORT/${enc(url)}`]) {
    assert.deepEqual(parseDeepLink(link), { kind: 'sub', text: url, host: 'sub.example.com', name: '' }, link);
  }
});

test('a subscription can bring its name', () => {
  const url = 'https://sub.example.com/a';
  assert.equal(parseDeepLink(`irnetfree://import?url=${enc(url)}&name=${enc('My panel')}`).name, 'My panel');
  assert.equal(parseDeepLink(`irnetfree://import?url=${enc(url)}&name=${enc('x'.repeat(90))}`).name.length, 60);
  // after import/ it is all the text: a query the sender left unencoded is the link's own
  assert.equal(parseDeepLink('irnetfree://import/vless://a@b.example:1?type=ws&name=x').text, 'vless://a@b.example:1?type=ws&name=x');
});

test('a config link of every scheme the app reads, named by its remark', () => {
  for (const scheme of ['vless', 'vmess', 'trojan', 'ss', 'socks', 'socks5', 'wireguard', 'wg', 'tuic', 'anytls', 'hysteria2', 'hy2']) {
    const link = `${scheme}://secret@host.example:443?a=b#${enc('🇩🇪 Berlin')}`;
    const got = parseDeepLink(`irnetfree://import/${enc(link)}`);
    assert.equal(got.kind, 'config', scheme);
    assert.equal(got.scheme, scheme);
    assert.equal(got.text, link);
    assert.equal(got.name, '🇩🇪 Berlin');
  }
});

test('an HTTP proxy link is no subscription (parser.isHttpProxyLink), and not among what a link may bring', () => {
  assert.equal(parseDeepLink(`irnetfree://import/${enc('http://user:pass@proxy.example:8080#P')}`), null);
  assert.equal(parseDeepLink(`irnetfree://import/${enc('vless://')}`), null, 'a scheme with nothing after it');
});

test('a routing share link goes through unchanged, to its own preview', () => {
  assert.deepEqual(parseDeepLink('irnetfree://routing/abc_DEF-123'), { kind: 'routing', text: 'irnetfree://routing/abc_DEF-123' });
  assert.equal(parseDeepLink('IRNETFREE://ROUTING/abc').text, 'irnetfree://routing/abc');
  assert.equal(parseDeepLink('irnetfree://routing/'), null, 'with nothing in it');
});

test('nothing else: another scheme, several lines, too long, control characters, a broken encoding', () => {
  for (const bad of [
    '', null, undefined, 'irnetfree://', 'irnetfree://import', 'irnetfree://import/', 'irnetfree://settings/x', 'https://evil.example/x',
    `irnetfree://import/${enc('file:///etc/passwd')}`,
    `irnetfree://import/${enc('javascript:alert(1)')}`,
    `irnetfree://import/${enc('intent://x#Intent;end')}`,
    `irnetfree://import/${enc('content://x/y')}`,
    `irnetfree://import/${enc('vless://a@b:1\nvless://c@d:2')}`,
    `irnetfree://import/${enc('https://a.example/\u0007')}`,
    `irnetfree://import/${enc('vless://' + 'a'.repeat(9000))}`,
    'irnetfree://import/%E0%A4%A',
    'irnetfree://import?name=x',
    'irnetfree://import?url=',
    `irnetfree://import/${enc('https://')}`,
    'irnetfree://import/plain words',
    `irnetfree://routing/${'a'.repeat(70000)}`
  ]) assert.equal(parseDeepLink(bad), null, String(bad).slice(0, 60));
});

test('what is shown never carries a credential or the secret path', () => {
  const sub = classify('https://sub.example.com/secret-token');
  assert.equal(sub.host, 'sub.example.com');
  assert.ok(!sub.host.includes('secret'));
  const cfg = classify('vless://11111111-2222@host.example:443#Name');
  assert.equal(cfg.name, 'Name');
  assert.equal(cfg.scheme, 'vless');
});

test('a launch names its link among its arguments, and only that one counts', () => {
  assert.equal(linkFromArgv(['app.exe', '--hidden', 'irnetfree://import/x']), 'irnetfree://import/x');
  assert.equal(linkFromArgv(['app.exe', 'IRNETFREE://routing/y']), 'IRNETFREE://routing/y');
  assert.equal(linkFromArgv(['app.exe', '--flag=irnetfree://import/x', 'https://a.example']), null);
  assert.equal(linkFromArgv(null), null);
});

test('the app takes the scheme: registered at start, in the package, the three ways a link arrives', () => {
  assert.equal(PROTOCOL, 'irnetfree');
  const pkg = JSON.parse(read('package.json'));
  assert.deepEqual(pkg.build.protocols, [{ name: 'IRNetFree link', schemes: ['irnetfree'] }]);
  const main = read('src/main/main.js');
  assert.match(main, /app\.on\('open-url'/);
  assert.match(main, /app\.on\('second-instance', \(e, argv\) => \{\s*const link = linkFromArgv\(argv\);/);
  assert.match(main, /const launchLink = linkFromArgv\(process\.argv\);/);
  assert.match(main, /process\.env\.PORTABLE_EXECUTABLE_FILE \|\| process\.execPath/, 'a portable build runs from a temp folder');
  assert.match(main, /if \(!app\.isPackaged\) return;/, 'a dev run never takes the scheme');
  // a link waits until the page is up: it may come before there is a window
  assert.match(main, /ipcMain\.handle\('links:take', \(\) => pendingLinks\.splice\(0\)\)/);
  assert.match(read('src/renderer/app.js'), /init\(\)\.then\(\(\) => \{\s*if \(window\.api\.onDeepLink\) window\.api\.onDeepLink\(takeDeepLinks\);\s*return takeDeepLinks\(\);/);
});

test('the window asks before anything is written, and nothing connects', () => {
  const app = read('src/renderer/app.js');
  const start = app.indexOf('async function offerDeepLink(link)');
  const body = app.slice(start, app.indexOf('async function takeDeepLinks', start));
  assert.ok(start > 0);
  assert.match(body, /if \(!window\.confirm\(/);
  assert.ok(body.indexOf('window.confirm') < body.indexOf('smartImport'), 'the question comes first');
  assert.doesNotMatch(body, /connect\(/);
  assert.match(body, /openRoutingImport\(link\.text\)/, 'a routing link has its own preview');
  // it says the host of a subscription, never its URL
  assert.match(body, /link\.kind === 'sub' \? link\.host :/);
});
