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
 *     for a sign-in page in the way — not as a refusal;
 *   - the show-password eye works (the page's one script, allowed by its hash
 *     in the CSP — a CSP that blocked it would leave the eye hidden);
 *   - "request a top-up" on the status page posts and is answered;
 *   - with scripts OFF (a captive sign-in window may run none): ?code= opens
 *     the code's tab, a click on a tab switches the forms (CSS alone), and the
 *     code's form signs in with the code alone.
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

/** The page's text once it says one of `re` (or 10 s): the body's innerText. */
const pageSays = (b, re) => until(async () => { const t = await b.evaluate('document.body ? document.body.innerText : ""'); return re.test(t || '') ? t : null; });

/** A real click at an element's middle (a person's tap — no script of the page's involved). */
async function tap(b, selector) {
  const r = await b.evaluate(`(() => { const e = document.querySelector(${JSON.stringify(selector)}); if (!e) return null; e.scrollIntoView({ block: 'center' }); const x = e.getBoundingClientRect(); return { x: x.left + x.width / 2, y: x.top + x.height / 2 }; })()`);
  assert.ok(r, `no ${selector} on the page`);
  for (const type of ['mousePressed', 'mouseReleased']) await b.cdp('Input.dispatchMouseEvent', { type, x: r.x, y: r.y, button: 'left', clickCount: 1 });
}

test('a real browser signs in through the page, and its https to the page fails as a protocol error, not a refusal', { skip: BROWSER ? false : 'no browser (CI, or IRNF_RENDER_BROWSER)', timeout: 120000 }, async () => {
  let signed = null;
  let request = null;
  const tries = [];
  const requests = [];
  const logs = [];
  const portal = createPortal({
    host: '127.0.0.1', port: 0, log: (line) => logs.push(line),
    api: {
      macOf: async () => MAC,
      statusOf: async () => (signed ? Object.assign({}, signed, { request }) : null),
      signIn: async (x) => {
        tries.push(x);
        if (x.code === 'K7MP-29QX') {
          signed = { name: 'Cafe #1', username: 'K7MP-29QX', via: 'login', until: Date.now() + 2 * 3600e3, voucher: { hours: 2, activatedAt: Date.now(), expiresAt: Date.now() + 2 * 3600e3 }, meters: [], requests: true };
          return { ok: true, status: signed };
        }
        if (x.code !== undefined || x.username !== 'sadra' || x.password !== 'pass-1') return { ok: false, code: 'bad' };
        signed = { name: 'Sadra', username: 'sadra', via: 'login', until: Date.now() + 2 * 3600e3, meters: [{ kind: 'total', period: 'month', bytes: 1e9, capBytes: 5e9, extraBytes: 0, over: false }], requests: true };
        return { ok: true, status: signed };
      },
      signOut: async () => { signed = null; request = null; return true; },
      requestTopUp: async (mac) => { requests.push(mac); request = { at: Date.now() }; return { ok: true, code: 'sent' }; }
    }
  });
  const { port } = await portal.start();
  const b = await openBrowser();
  try {
    const nav = await b.cdp('Page.navigate', { url: `http://127.0.0.1:${port}/` });
    assert.ok(!nav.errorText, nav.errorText);
    assert.ok(await until(() => b.evaluate('!!document.getElementById("p")')), 'the sign-in form');
    // the eye: shown by the page's one script (its hash in the CSP), it turns the password into text and back
    assert.equal(await until(() => b.evaluate('document.getElementById("eye").hidden === false')), true, `the eye stayed hidden: the CSP blocked the script? ${logs.join(' | ')}`);
    await b.evaluate(`document.getElementById('p').value = 'pass-1'; true`);
    await tap(b, '#eye');
    assert.equal(await b.evaluate('document.getElementById("p").type + " " + document.getElementById("eye").getAttribute("aria-pressed")'), 'text true');
    await tap(b, '#eye');
    assert.equal(await b.evaluate('document.getElementById("p").type'), 'password');
    assert.equal(await b.evaluate('getComputedStyle(document.getElementById("f-code")).display'), 'none', 'the code\'s form hidden behind its tab');

    await b.evaluate(`document.getElementById('u').value = 'sadra'; document.querySelector('button[type=submit]').click(); true`);
    const text = await pageSays(b, /You are connected|went wrong|Wrong/);
    const posted = b.events.filter((e) => e.method === 'Network.responseReceived' && /\/login$/.test(e.params.response.url)).map((e) => e.params.response.status);
    assert.match(String(text), /You are connected/, `the page after the sign-in: ${JSON.stringify(text)} · POST /login → ${posted.join(', ')} · ${logs.join(' | ')}`);
    assert.deepEqual(posted, [200]);
    assert.deepEqual(tries, [{ mac: MAC, username: 'sadra', password: 'pass-1' }], 'what was typed is what the controller judged');

    // "request a top-up": the status page's own form posts, the page says so and holds no second button
    await tap(b, 'form[action="/request"] button');
    const asked = await pageSays(b, /request has been sent|went wrong/);
    assert.match(String(asked), /Your request has been sent\./, `${JSON.stringify(asked)} · ${logs.join(' | ')}`);
    assert.match(String(asked), /Top-up requested — \d\d:\d\d/);
    assert.deepEqual(requests, [MAC]);
    assert.equal(await b.evaluate('!!document.querySelector(\'form[action="/request"]\')'), false);
    await tap(b, 'form[action="/logout"] button');
    assert.ok(await until(() => b.evaluate('!!document.getElementById("p")')), 'signed out: the form again');

    // no script at all, as in a captive sign-in window that runs none
    await b.cdp('Emulation.setScriptExecutionDisabled', { value: true });
    await b.cdp('Page.navigate', { url: `http://127.0.0.1:${port}/?code=k7mp-29qx` });
    assert.ok(await until(() => b.evaluate('!!document.getElementById("c") && document.readyState === "complete"')));
    assert.equal(await b.evaluate('[document.getElementById("w-code").checked, getComputedStyle(document.getElementById("f-code")).display, getComputedStyle(document.getElementById("f-user")).display, document.getElementById("c").value, document.getElementById("eye").hidden].join(" ")'),
      'true block none k7mp-29qx true', '?code=: the code\'s tab open, filled in; no script, no eye');
    await tap(b, 'label[for="w-user"]');
    assert.equal(await b.evaluate('getComputedStyle(document.getElementById("f-user")).display + " " + getComputedStyle(document.getElementById("f-code")).display'), 'block none', 'a tap on a tab switches the forms — CSS alone');
    await tap(b, 'label[for="w-code"]');
    assert.equal(await b.evaluate('getComputedStyle(document.getElementById("f-code")).display'), 'block');
    await b.evaluate(`document.getElementById('c').value = 'K7MP-29QX'; true`);
    await tap(b, '#f-code button[type=submit]');
    const card = await pageSays(b, /Internet card|went wrong|not valid/);
    assert.match(String(card), /Internet card/, `${JSON.stringify(card)} · ${logs.join(' | ')}`);
    assert.deepEqual(tries[1], { mac: MAC, username: '', password: '', code: 'K7MP-29QX' }, 'the code\'s form posts the code alone');
    await b.cdp('Emulation.setScriptExecutionDisabled', { value: false });

    // a device's https, once the gateway sends its tcp/443 here: plain HTTP answers the TLS hello
    const tls = await b.cdp('Page.navigate', { url: `https://127.0.0.1:${port}/` });
    assert.equal(tls.errorText, 'net::ERR_SSL_PROTOCOL_ERROR');
  } finally {
    await b.end();
    await portal.stop();
  }
});
