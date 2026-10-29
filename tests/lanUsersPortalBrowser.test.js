'use strict';
/**
 * The router's sign-in page in a real browser. v1.33.0–v1.38.0 refused every
 * sign-in from Chrome: the page's `Referrer-Policy: no-referrer` made Chrome
 * post its own form with `Origin: null`, the portal took that for another
 * page's form and answered 403 «Something went wrong» — while every test here
 * posted with Node's http client, which sends what the test says. Only a
 * browser says what a browser sends; this drives one (headless, a throwaway
 * profile, over the DevTools protocol):
 *
 *   - the form, filled and submitted as a person would, signs in;
 *   - https to the page's port (where the gateway sends a device's tcp/443,
 *     router/nft.js) fails as ERR_SSL_PROTOCOL_ERROR — the error Chrome takes
 *     for a sign-in page in the way — not as a refusal.
 *
 * Runs where renderCheck.findBrowser finds one: CI, or IRNF_RENDER_BROWSER.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { createPortal } = require('../src/modules/lanUsers/router/portal');
const { findBrowser } = require('./renderCheck');

const BROWSER = findBrowser();
const MAC = 'aa:bb:cc:dd:ee:01';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A headless browser with its DevTools endpoint: { cdp(method, params), evaluate(expr), end() } on its first tab. */
async function openBrowser() {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-portal-'));
  const child = spawn(BROWSER, [
    '--headless=new', '--disable-gpu', '--no-sandbox', '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--disable-background-networking', '--disable-component-update', '--disable-sync',
    '--disable-default-apps', '--mute-audio', '--use-mock-keychain', '--password-store=basic',
    `--user-data-dir=${profile}`, '--remote-debugging-port=0', 'about:blank'
  ], { stdio: 'ignore', windowsHide: true, detached: process.platform !== 'win32' });
  const exited = new Promise((resolve) => child.once('close', resolve));
  child.once('error', () => { /* seen as no DevToolsActivePort below */ });
  let ws = null;
  const end = async () => {
    try { if (ws) ws.close(); } catch { /* closed */ }
    try { if (process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL'); else child.kill(); } catch { /* gone */ }
    await Promise.race([exited, sleep(5000)]);
    try { fs.rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 }); } catch { /* a temp dir */ }
  };
  try {
    let port = null, browserPath = null;
    for (let i = 0; i < 300 && !port; i++) {
      await sleep(100);
      try { [port, browserPath] = fs.readFileSync(path.join(profile, 'DevToolsActivePort'), 'utf8').split('\n'); } catch { /* not yet */ }
    }
    if (!port) throw new Error(`${BROWSER} gave no DevTools port in 30 s`);
    const tabs = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    const tab = tabs.find((t) => t.type === 'page');
    if (!tab) throw new Error(`no tab in ${JSON.stringify(tabs)} (browser at ${browserPath})`);
    ws = new WebSocket(tab.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = () => reject(new Error('the DevTools socket failed')); });
    let id = 0;
    const waiting = new Map();
    const events = [];
    ws.onmessage = (e) => {
      const m = JSON.parse(e.data);
      if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); } else if (m.method) events.push(m);
    };
    const cdp = (method, params = {}) => new Promise((resolve, reject) => {
      const n = ++id;
      const t = setTimeout(() => { waiting.delete(n); reject(new Error(`${method}: no answer in 20 s`)); }, 20000);
      waiting.set(n, (m) => { clearTimeout(t); if (m.error) reject(new Error(`${method}: ${m.error.message}`)); else resolve(m.result); });
      ws.send(JSON.stringify({ id: n, method, params }));
    });
    const evaluate = async (expression) => (await cdp('Runtime.evaluate', { expression, returnByValue: true })).result.value;
    await cdp('Page.enable');
    await cdp('Network.enable');
    return { cdp, evaluate, events, end };
  } catch (e) {
    await end();
    throw e;
  }
}

/** Until `fn` gives something (or 10 s): its last answer. */
async function until(fn, ms = 10000) {
  const t0 = Date.now();
  let last;
  while (Date.now() - t0 < ms) {
    last = await fn();
    if (last) return last;
    await sleep(150);
  }
  return last;
}

test('a real browser signs in through the page, and its https to the page fails as a protocol error, not a refusal', { skip: BROWSER ? false : 'no browser (CI, or IRNF_RENDER_BROWSER)', timeout: 120000 }, async () => {
  let signed = null;
  const tries = [];
  const logs = [];
  const portal = createPortal({
    host: '127.0.0.1', port: 0, log: (line) => logs.push(line),
    api: {
      macOf: async () => MAC,
      statusOf: async () => signed,
      signIn: async ({ mac, username, password }) => {
        tries.push({ mac, username, password });
        if (username !== 'sadra' || password !== 'pass-1') return { ok: false, code: 'bad' };
        signed = { name: 'Sadra', username: 'sadra', via: 'login', until: Date.now() + 2 * 3600e3, usage: { bytes: 0, quotaBytes: 0 } };
        return { ok: true, status: signed };
      },
      signOut: async () => { signed = null; return true; }
    }
  });
  const { port } = await portal.start();
  const b = await openBrowser();
  try {
    const nav = await b.cdp('Page.navigate', { url: `http://127.0.0.1:${port}/` });
    assert.ok(!nav.errorText, nav.errorText);
    assert.ok(await until(() => b.evaluate('!!document.getElementById("p")')), 'the sign-in form');
    await b.evaluate(`document.getElementById('u').value = 'sadra'; document.getElementById('p').value = 'pass-1'; document.querySelector('button[type=submit]').click(); true`);
    const text = await until(async () => { const t = await b.evaluate('document.body ? document.body.innerText : ""'); return /You are connected|went wrong|Wrong/.test(t || '') ? t : null; });
    const posted = b.events.filter((e) => e.method === 'Network.responseReceived' && /\/login$/.test(e.params.response.url)).map((e) => e.params.response.status);
    assert.match(String(text), /You are connected/, `the page after the sign-in: ${JSON.stringify(text)} · POST /login → ${posted.join(', ')} · ${logs.join(' | ')}`);
    assert.deepEqual(posted, [200]);
    assert.deepEqual(tries, [{ mac: MAC, username: 'sadra', password: 'pass-1' }], 'what was typed is what the controller judged');

    // a device's https, once the gateway sends its tcp/443 here: plain HTTP answers the TLS hello
    const tls = await b.cdp('Page.navigate', { url: `https://127.0.0.1:${port}/` });
    assert.equal(tls.errorText, 'net::ERR_SSL_PROTOCOL_ERROR');
  } finally {
    await b.end();
    await portal.stop();
  }
});
