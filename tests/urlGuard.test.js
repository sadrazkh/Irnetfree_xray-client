'use strict';
/**
 * The window shows one page of our own, and hands the OS only web links.
 *
 * `open:external` passed ANY string to shell.openExternal — file:, smb:,
 * ms-settings:, a custom protocol handler — and the window had neither a
 * will-navigate guard nor a window-open handler, so a link in a log line or a
 * server name could take the app's own window somewhere else, with the preload
 * bridge still attached.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { isWebUrl, isAppPage } = require('../src/main/urlGuard');

test('isWebUrl: http and https only', () => {
  for (const ok of ['https://github.com/sadrazkh/Irnetfree_xray-client/releases/latest', 'http://example.com/', 'HTTPS://EXAMPLE.COM/x?y#z']) {
    assert.equal(isWebUrl(ok), true, ok);
  }
  for (const bad of [
    'file:///C:/Windows/System32/calc.exe', 'javascript:alert(1)', 'ms-settings:network-proxy', 'smb://10.0.0.1/share',
    'data:text/html,<b>x</b>', 'vbscript:msgbox', '//example.com/', 'example.com', '', null, undefined, 42, { href: 'https://x' },
    'https//missing-colon'
  ]) {
    assert.equal(isWebUrl(bad), false, String(bad));
  }
});

test('isAppPage: the app’s own page, with any hash or query — nothing else', () => {
  const page = path.join(__dirname, '..', 'src', 'renderer', 'index.html');
  const own = pathToFileURL(page).href;
  assert.equal(isAppPage(own, page), true);
  assert.equal(isAppPage(own + '#settings', page), true);
  assert.equal(isAppPage(own + '?x=1', page), true);
  assert.equal(isAppPage(pathToFileURL(path.join(path.dirname(page), 'other.html')).href, page), false);
  assert.equal(isAppPage(pathToFileURL(path.join(__dirname, 'index.html')).href, page), false, 'the same name elsewhere is not our page');
  assert.equal(isAppPage('https://evil.example/index.html', page), false);
  assert.equal(isAppPage('not a url', page), false);
  assert.equal(isAppPage(own, ''), false);
});

test('isAppPage: Windows and macOS paths compare case-insensitively, Linux exactly', () => {
  const page = path.join(__dirname, '..', 'src', 'renderer', 'index.html');
  const upper = pathToFileURL(page).href.replace(/index\.html$/, 'INDEX.html');
  assert.equal(isAppPage(upper, page, 'win32'), true);
  assert.equal(isAppPage(upper, page, 'darwin'), true);
  assert.equal(isAppPage(upper, page, 'linux'), false);
});
