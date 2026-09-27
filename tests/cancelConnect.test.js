'use strict';
/**
 * Cancel while connecting (v1.15 D1).
 *
 * A connect that hangs — a dead server, no network — used to be something the
 * power button could only wait out: it did nothing while connecting. Now the
 * power button, every ▶ and the tray's Disconnect are the connect's Cancel: they
 * call the disconnect, which bumps connGen, and the connect in flight gives way
 * at its next step. What is pinned here is that giving way really ends where a
 * disconnect ends — nothing the cancelled connect started is left running, and
 * nothing is said after the 'disconnected' that could put a window back on
 * "Connecting…" or "Connected".
 *
 * Driven for real through the headless service (the router's web UI is the same
 * renderer on it) with the cores faked; main.js needs Electron, so its mirror of
 * the same steps is pinned as text, and the one piece it has alone (the kill
 * switch a settings rebuild arms) is compiled on its own against fakes.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createService } = require('../src/server/service');
const { makeProxyServer } = require('../src/main/parser');
const fakes = require('./gatewayFakes');

process.setMaxListeners(40);   // every service registers its own exit hook

const A = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.10', port: 1080, name: 'A' }), { id: 'srv-a' });
const B = Object.assign(makeProxyServer({ type: 'socks', address: '192.0.2.11', port: 1080, name: 'B' }), { id: 'srv-b' });
// ports nothing listens on here: the stats poller dials apiPort, and the owner's own app holds the defaults
const BASE = { autoUpdateSubs: false, autoUpdateAssets: 'off', autoConnect: false, tunMode: true, lang: 'en',
  routingMode: 'global', blockAds: false, socksPort: 47818, httpPort: 47819, apiPort: 47895 };

const dirs = [];
test.after(() => { for (const d of dirs) { try { fs.rmSync(d, { recursive: true, force: true }); } catch {} } });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(pred, what, ms = 4000) {
  const deadline = Date.now() + ms;
  while (!pred()) {
    if (Date.now() > deadline) throw new Error('timed out waiting for: ' + what);
    await sleep(2);
  }
}
/** A promise the test resolves by hand. */
function gate() { let open; const p = new Promise((r) => { open = r; }); return { p, open }; }

/**
 * A core manager with XrayManager's own timing where a cancel can land:
 * start() stops a running core first and spawns only after its exit; stop()
 * ends the process it finds AT THE CALL, so two stops of one process both wait
 * for its exit, and the one that asked first goes on first. `ctl.validate` holds
 * the validation, `ctl.exit` the exit of every process asked to stop.
 */
function coreFactory(state, ctl) {
  return (o) => {
    let pid = 5000;
    const x = {
      running: false, proc: null, binPath: null, starts: [], stopCalls: 0,
      resolveEngine: (id) => ({ id: id === 'sing-box' || id === 'xray-pattn' ? id : 'xray', bin: '/fake/' + (id || 'xray') }),
      resolveBin: (id) => '/fake/' + (id || 'xray'),
      binExists: () => true,
      anyBin: () => '/fake/xray',
      version: async () => '26.1.1',
      forgetVersions() {},
      validate: async () => ({ ok: true }),
      async validateWithFallback(config, engine) {
        if (ctl.validate) await ctl.validate.p;
        return { ok: true, engine };
      },
      async start(config, engine) {
        if (x.running) await x.stop();
        const proc = { pid: ++pid, alive: true, kill() {} };
        proc.exited = new Promise((r) => { proc.gone = r; });
        x.proc = proc;
        x.running = true;
        x.starts.push({ config, engine, proc });
        state.events.push('xray:start');
        o.onStatus('running', { pid: proc.pid });
        return x.running && x.proc === proc;
      },
      async stop() {
        x.stopCalls++;
        const p = x.proc;
        if (!p) { x.running = false; return; }
        if (!p.stopping) {
          p.stopping = true;
          (ctl.exit ? ctl.exit.p : Promise.resolve()).then(() => {
            p.alive = false;
            // like the real exit handler: a late exit never clears a newer process
            if (x.proc === p) { x.proc = null; x.running = false; o.onStatus('stopped', { code: 0, signal: 'SIGTERM' }); }
            p.gone();
          });
        }
        await p.exited;
      },
      startTest: async () => { throw new Error('no test cores here'); }
    };
    state.xray = x;
    return x;
  };
}

/** A router service on a fresh data dir with servers A and B; statuses recorded. */
function start(settings = {}, ctl = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-cancel-'));
  dirs.push(dir);
  fs.writeFileSync(path.join(dir, 'store.json'), JSON.stringify({
    servers: [A, B], routerDefaultsApplied: true, settings: Object.assign({}, BASE, settings)
  }));
  const state = fakes.makeState();
  const proxy = [];
  const service = createService({
    dataDir: dir,
    deps: fakes.deps(state, { xray: coreFactory(state, ctl), setSystemProxy: async (on) => { proxy.push(on); } })
  });
  const statuses = [];
  service.onEvent((ch, p) => { if (ch === 'status') statuses.push(p); });
  return { service, state, statuses, proxy, ctl };
}
const states = (s) => s.statuses.map((x) => x.state);

test('a connect cancelled while it hangs ends disconnected — nothing started, nothing said after', async (t) => {
  const s = start({}, { validate: gate() });
  t.after(() => s.service.shutdown());
  const connecting = s.service.invoke('connect', A.id);
  await until(() => states(s).includes('connecting'), '"connecting"');
  await s.service.invoke('disconnect');                 // the Cancel
  s.ctl.validate.open();                                // the hung step comes back after all
  assert.deepEqual(await connecting, { ok: false, stale: true }, 'a cancelled connect is neither a success nor an error');
  await sleep(30);
  assert.deepEqual(states(s), ['connecting', 'disconnected'], 'nothing after the disconnect can put the window back');
  assert.equal(s.state.xray.starts.length, 0, 'no core was started');
  assert.equal(s.state.events.includes('gateway:start'), false, 'no gateway was built');
  assert.equal((await s.service.invoke('app:init')).activeServerId, null);
});

test('a connect cancelled while its gateway comes up takes the gateway and the core down with it', async (t) => {
  const s = start({}, {});
  t.after(() => s.service.shutdown());
  const held = gate();
  s.state.gatewayGate = held.p;
  const connecting = s.service.invoke('connect', A.id);
  await until(() => s.state.events.includes('gateway:start'), 'the gateway starting');
  await s.service.invoke('disconnect');
  held.open();
  assert.deepEqual(await connecting, { ok: false, stale: true });
  await sleep(30);
  assert.equal(states(s).includes('connected'), false);
  assert.equal(states(s).at(-1), 'disconnected');
  assert.equal(s.state.xray.running, false, 'no core left running');
  assert.ok(s.state.gateways.every((g) => !g.active), 'no gateway left up');
  assert.equal(s.proxy.at(-1), false, 'the system proxy ends restored');
  assert.equal((await s.service.invoke('app:init')).activeServerId, null);
});

test('cancelling a server switch while the old core is on its way out leaves no core running', async (t) => {
  // start() stops the old core and spawns the new one only after its exit; the
  // disconnect's own stop waits on that same exit, and is released in the same
  // tick — AFTER the switch's, which spawns the new core first. The disconnect
  // has then already done its teardown: the new core outlived the Cancel,
  // holding the SOCKS port with the window saying "disconnected".
  const s = start({ tunMode: false }, {});
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', A.id);
  assert.equal(states(s).at(-1), 'connected');
  s.ctl.exit = gate();
  const switching = s.service.invoke('connect', B.id);
  await until(() => s.state.xray.stopCalls === 1, 'the switch stopping A');
  const cancel = s.service.invoke('disconnect');
  await until(() => s.state.xray.stopCalls === 2, 'the disconnect waiting on the same exit');
  s.ctl.exit.open();
  await cancel;
  assert.deepEqual(await switching, { ok: false, stale: true });
  await sleep(30);
  assert.equal(s.state.xray.starts.length, 2, 'B was spawned — after the disconnect’s teardown');
  assert.equal(s.state.xray.running, false, 'and stopped again: nothing of the cancelled switch is left running');
  assert.equal(states(s).at(-1), 'disconnected');
  assert.equal(states(s).lastIndexOf('connected') < states(s).lastIndexOf('disconnected'), true);
  assert.equal((await s.service.invoke('app:init')).activeServerId, null);
});

test('a switch overtaken by a newer connect leaves that connect’s core alone', async (t) => {
  // Only a disconnect is undone by the call it overtook: a newer connect owns
  // the core it finds (its own start() stops the old one first).
  const s = start({ tunMode: false }, {});
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', A.id);
  s.ctl.validate = gate();
  const first = s.service.invoke('connect', B.id);
  await until(() => states(s).filter((x) => x === 'connecting').length === 2, 'the switch to B validating');
  const held = s.ctl.validate;
  s.ctl.validate = null;
  const second = await s.service.invoke('connect', A.id);   // the user picked A again meanwhile
  assert.equal(second.ok, true);
  held.open();
  assert.deepEqual(await first, { ok: false, stale: true });
  await sleep(30);
  assert.equal(s.state.xray.running, true, 'the newer connect’s core is still up');
  assert.equal(states(s).at(-1), 'connected');
  assert.equal((await s.service.invoke('app:init')).activeServerId, A.id);
});

/* ------------------------ main.js: the same steps, as text ------------------------ */

// CRLF on a Windows checkout (core.autocrlf): the patterns below are written with \n.
const R = (...p) => fs.readFileSync(path.join(__dirname, '..', ...p), 'utf8').replace(/\r\n/g, '\n');
const MAIN = R('src', 'main', 'main.js');
const SERVICE = R('src', 'server', 'service.js');
function slice(source, label, startAt, end) {
  const a = source.indexOf(startAt);
  assert.notEqual(a, -1, `${label}: ${startAt} is gone`);
  const b = source.indexOf(end, a + startAt.length);
  assert.notEqual(b, -1, `${label}: nothing ends ${startAt}`);
  return source.slice(a, b + end.length);
}
const CONNECT = {
  'main.js': slice(MAIN, 'main.js', 'async function connectOnce(serverId, opts = {}) {', '\n  return { ok: true, tunError };\n}'),
  'service.js': slice(SERVICE, 'service.js', 'async function connectOnce(serverId, opts = {}) {', '\n    return { ok: true, tunError };\n  }')
};

test('both mirrors: a disconnect marks the generation it leaves, before it awaits anything', () => {
  for (const [label, src, end] of [['main.js', MAIN, '\n}\n'], ['service.js', SERVICE, '\n  }\n']]) {
    const body = slice(src, label, 'async function doDisconnect() {', end);
    assert.match(body, /connGen\+\+;\n\s*disconnectGen = connGen;\n/, label);
    assert.ok(body.indexOf('disconnectGen = connGen;') < body.indexOf('await '), `${label}: marked before the first await`);
  }
  assert.match(MAIN, /^let disconnectGen = 0;$/m);
  assert.match(SERVICE, /^ {2}let disconnectGen = 0;$/m);
  // nothing else moves it: a connect only ever moves connGen away from it
  for (const [label, src] of [['main.js', MAIN], ['service.js', SERVICE]]) {
    assert.equal([...src.matchAll(/disconnectGen = /g)].length, 2, `${label}: declared once, set only by the disconnect`);
  }
});

test('both mirrors: past the core’s start every gate gives way, and only a disconnect’s overtaking stops the core this call started', () => {
  for (const [label, body] of Object.entries(CONNECT)) {
    const started = body.indexOf('if (await xray.start(config, runEngine)) ownCore = xray.proc;');
    assert.notEqual(started, -1, `${label}: the core this call started is no longer kept`);
    const after = body.slice(started);
    // the only bare abandonments left after it: the start's own catch (a core
    // that died on start — nothing left to stop) and giveWay's answer
    assert.equal([...after.matchAll(/return abandoned;/g)].length, 2, `${label}: a gate after the start that does not give way`);
    assert.ok([...after.matchAll(/return giveWay\(/g)].length >= 4, `${label}: every gate after the start gives way`);
    const give = slice(body, label, 'const giveWay = async (', 'return abandoned;');
    assert.match(give, /if \(connGen === disconnectGen/, `${label}: a newer connect owns what it finds`);
    assert.match(give, /ownCore && xray\.proc === ownCore/, `${label}: only the core this call started, while it is still the one running`);
    assert.ok(body.indexOf('const giveWay = async (') > started, `${label}: defined once the core is known`);
    // the proxy mode's UDP block hands its receipt over like the guard's engage does
    assert.match(body, /const udp = await leakGuard\.engageUdpBlock\(\{ excludes: udpExcludes \}\);/, label);
    assert.match(body, /guardToken = \(udp && udp\.token\) \|\| guardToken;/, label);
  }
  // the desktop's quiet stop is its reload flag; the service's its counter (as abortGateway's)
  assert.match(slice(CONNECT['main.js'], 'main.js', 'const giveWay = async (', 'return abandoned;'), /xrayReloading = true;[^\n]*\n\s*try \{ await xray\.stop\(\); \}/);
  assert.match(slice(CONNECT['service.js'], 'service.js', 'const giveWay = async (', 'return abandoned;'), /quietStops\+\+;\n\s*try \{ await xray\.stop\(\); \}[^\n]*finally \{ quietStops--; \}/);
});

test('main.js: a server switch’s kill switch is lifted again when a disconnect overtook it, and so is a LAN rule added after the disconnect’s removal', () => {
  const body = CONNECT['main.js'];
  const give = slice(body, 'main.js', 'const giveWay = async (', 'return abandoned;');
  assert.match(give, /if \(armedHere\) \{\n\s*try \{ await disarmKillSwitch\(\); \}[^\n]*\n\s*send\('killswitch', \{ engaged: false \}\);/);
  // the TUN gate and the last gate both hand the switch's block over
  assert.equal([...body.matchAll(/return giveWay\(switchArmed\);/g)].length, 2);
  assert.match(body, /if \(stale\(\)\) \{\n\s*if \(settings\.allowLan && connGen === disconnectGen\) \{ try \{ await removeLanFirewall\(\); \} catch \{\} \}\n\s*return giveWay\(switchArmed\);/);
});

/**
 * main.js's reapplyConnection() against fakes (main.js needs Electron): a
 * disconnect — or a newer connect — lands while the kill switch is being armed.
 */
function reapplyUnderCancel({ overtaker }) {
  const calls = [];
  const sent = [];
  const env = {
    calls,
    overtaker,
    store: { get: (k, d) => (k === 'activeServerId' ? 'srv1' : d) },
    xray: { running: true, stop: async () => { calls.push('xray.stop'); } },
    getSettings: () => ({ killSwitch: true, systemProxy: true, lang: 'en' }),
    send: (ch, p) => sent.push([ch, p]),
    stats: { stop() {} },
    usage: null,
    usageStore: null,
    leakGuard: null,
    tun: { managesDns: true },
    tunPlatform: { resolveServerIps: async () => [] },
    buildPlan: () => ({ entryAddrs: [] }),
    lastEntryHostIps: new Map(),
    stopAllTuns: async () => { calls.push('stopAllTuns'); },
    setSystemProxy: async (on) => { calls.push('setSystemProxy:' + on); },
    removeLanFirewall: async () => {},
    doConnect: async () => { calls.push('doConnect'); return { ok: true }; }
  };
  const make = new Function('env', `
    let xrayReloading = false, connGen = 1, disconnectGen = 0, appliedSettings = {}, killEngaged = false;
    const { store, xray, getSettings, send, stats, usage, usageStore, leakGuard, tun, tunPlatform,
            buildPlan, lastEntryHostIps, stopAllTuns, setSystemProxy, removeLanFirewall, doConnect } = env;
    const stopProcWatcher = () => {};
    // the arm is a netsh round trip: the overtaker lands inside it
    async function armKillSwitch() {
      env.calls.push('arm');
      connGen++;
      if (env.overtaker === 'disconnect') disconnectGen = connGen;
      killEngaged = true;
      return { ok: true, added: true };
    }
    async function disarmKillSwitch() { env.calls.push('disarm'); killEngaged = false; }
    ${slice(MAIN, 'main.js', 'async function reapplyConnection(opts = {}) {', '\n}')}
    return { reapply: reapplyConnection, killEngaged: () => killEngaged };
  `);
  return Object.assign(make(env), { calls, sent });
}

test('main.js: a Cancel during a rebuild’s kill-switch arm is the last word — no "connecting" after it, and no block left behind', async () => {
  const h = reapplyUnderCancel({ overtaker: 'disconnect' });
  assert.deepEqual(await h.reapply(), { ok: false, stale: true });
  assert.deepEqual(h.sent.filter(([ch]) => ch === 'status'), [], 'a "connecting" here put the window back on Connecting… for good');
  assert.deepEqual(h.calls, ['arm', 'disarm'], 'nothing torn down or rebuilt — and the block the arm put in after the disconnect is lifted');
  assert.equal(h.killEngaged(), false);
  assert.deepEqual(h.sent.filter(([ch]) => ch === 'killswitch').map(([, p]) => p.engaged), [false]);
});

test('main.js: a newer connect landing in the same arm owns the kill switch — the rebuild only steps aside', async () => {
  const h = reapplyUnderCancel({ overtaker: 'connect' });
  assert.deepEqual(await h.reapply(), { ok: false, stale: true });
  assert.deepEqual(h.calls, ['arm']);
  assert.deepEqual(h.sent, []);
});

test('main.js: the tray’s Disconnect is the Cancel while connecting, and a connect started from the tray ends on a status', () => {
  const tray = slice(MAIN, 'main.js', 'function trayMenuTemplate() {', '\n}');
  assert.match(tray, /const stop = trayStopItem\(\{ active: !!active, state: lastStatus, en \}\);/);
  assert.match(tray, /\{ label: stop\.label, enabled: stop\.enabled, click: \(\) => \{ bootCancelled = true; doDisconnect\(\); \} \}/);
  assert.match(tray, /if \(connGen !== disconnectGen\) send\('status', \{ state: 'error', message: e\.message \}\);/,
    'a failed tray connect left the window on "Connecting…" — unless a disconnect (its Cancel) overtook it');
  const send = slice(MAIN, 'main.js', 'function send(channel, payload) {', '\n}');
  assert.match(send, /if \(channel === 'status' && payload && payload\.state\) lastStatus = payload\.state;/);
  assert.ok(send.indexOf('lastStatus = payload.state') < send.indexOf('refreshTray()'), 'recorded before the tray is rebuilt from it');
  assert.match(MAIN, /^let lastStatus = 'disconnected';$/m);
});
