'use strict';
/**
 * Mux, decided per server by a test (spec 2026-10-05 §4, src/main/mux.js).
 *
 * The router's field report: after a few hours every LAN flow was its own
 * TLS+ECH+WebSocket handshake, and hundreds of them died in the same
 * milliseconds. Measured on the owner's line, mux carried the same server's
 * connections at ~150 ms each instead of 0.6-3.7 s — on a server that takes
 * it. So `auto` asks each eligible server once and remembers the answer.
 *
 * What is pinned here: which outbounds may carry mux at all, what a server's
 * fingerprint is made of (an edited server, or a refreshed subscription with
 * new parameters, is a new server), how long a verdict is trusted, what each
 * mode asks for, and the probe itself — with a fake runner: no core is
 * started and nothing leaves this machine.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const mux = require('../src/main/mux');
const { MUX, muxEligible, muxFingerprint, freshVerdict, planMux, probeMux } = mux;
const { buildTestConfig } = require('../src/main/configBuilder');
const { parseLink } = require('../src/main/parser');
const { server, VLESS_WS_TLS, TROJAN_TCP_TLS, SS_TCP, WG_BAD_MASK } = require('./fixtures');

const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;
const clone = (v) => JSON.parse(JSON.stringify(v));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A server record whose outbound is `vless`/`vmess`/`trojan` over `network`, with `edit` applied to a copy. */
function shaped(id, protocol, network, edit) {
  const settings = protocol === 'trojan'
    ? { servers: [{ address: 'w.example.com', port: 443, password: 'pw-' + id }] }
    : { vnext: [{ address: 'w.example.com', port: 443, users: [protocol === 'vless' ? { id: 'uuid-' + id, encryption: 'none', flow: '' } : { id: 'uuid-' + id, alterId: 0, security: 'auto' }] }] };
  const streamSettings = { network, security: 'tls', tlsSettings: { serverName: 'w.example.com', fingerprint: 'chrome' } };
  if (network === 'ws') streamSettings.wsSettings = { path: '/ws', headers: { Host: 'w.example.com' } };
  if (network === 'httpupgrade') streamSettings.httpupgradeSettings = { path: '/up', host: 'w.example.com' };
  if (network === 'grpc') streamSettings.grpcSettings = { serviceName: 'svc', multiMode: false };
  if (network === 'xhttp') streamSettings.xhttpSettings = { path: '/x', host: '', mode: 'auto' };
  if (network === 'h2') streamSettings.httpSettings = { path: '/', host: [] };
  const s = server(id, 'Server ' + id, protocol, 'w.example.com', 443, { protocol, settings, streamSettings });
  if (edit) edit(s);
  return s;
}

const UUID = '11111111-2222-3333-4444-555555555555';

/* ----------------------------- the mux object ----------------------------- */

test('MUX is the spec’s object, frozen: concurrency 8, XUDP 16, UDP 443 left to its own way', () => {
  assert.deepEqual(MUX, { enabled: true, concurrency: 8, xudpConcurrency: 16, xudpProxyUDP443: 'skip' });
  assert.equal(Object.isFrozen(MUX), true);
  assert.throws(() => { MUX.concurrency = 1; }, TypeError);
});

/* ----------------------------- eligibility ----------------------------- */

test('muxEligible: VLESS without flow, VMess and Trojan — over ws or httpupgrade only', () => {
  const table = [
    ['vless ws', shaped('a', 'vless', 'ws'), true],
    ['vless httpupgrade', shaped('a', 'vless', 'httpupgrade'), true],
    ['vmess ws', shaped('a', 'vmess', 'ws'), true],
    ['vmess httpupgrade', shaped('a', 'vmess', 'httpupgrade'), true],
    ['trojan ws', shaped('a', 'trojan', 'ws'), true],
    ['trojan httpupgrade', shaped('a', 'trojan', 'httpupgrade'), true],
    ['the fixtures’ VLESS ws+tls', VLESS_WS_TLS, true],
    // a flow is Vision: it is never muxed, whatever the transport says
    ['vless ws with flow=xtls-rprx-vision', shaped('a', 'vless', 'ws', (s) => { s.outbound.settings.vnext[0].users[0].flow = 'xtls-rprx-vision'; }), false],
    // gRPC, XHTTP and H2 multiplex already
    ['vless grpc', shaped('a', 'vless', 'grpc'), false],
    ['vmess grpc', shaped('a', 'vmess', 'grpc'), false],
    ['vless xhttp', shaped('a', 'vless', 'xhttp'), false],
    ['trojan h2', shaped('a', 'trojan', 'h2'), false],
    ['trojan tcp', TROJAN_TCP_TLS, false],
    ['shadowsocks', SS_TCP, false],
    ['wireguard', WG_BAD_MASK, false]
  ];
  for (const [what, s, want] of table) assert.equal(muxEligible(s.outbound), want, what);
  // an outbound with no transport is raw TCP; nothing at all is nothing
  assert.equal(muxEligible({ protocol: 'vless', settings: {} }), false);
  assert.equal(muxEligible(null), false);
  assert.equal(muxEligible(undefined), false);
});

test('muxEligible on what the parser makes of real links: ws and httpupgrade yes; Vision, REALITY-raw, gRPC, mKCP, Hysteria2, Shadowsocks over ws no', () => {
  const vmess = 'vmess://' + Buffer.from(JSON.stringify({ v: '2', ps: 'vm', add: 'v.example', port: '443', id: UUID, aid: '0', net: 'ws', type: 'none', host: 'v.example', path: '/vm', tls: 'tls', sni: 'v.example' })).toString('base64');
  const links = [
    ['vless://' + UUID + '@104.21.44.18:2087?encryption=none&type=ws&host=h.example&path=/&security=tls&sni=h.example&ech=cloudflare-ech.com+udp://1.1.1.1#ech-ws', true],
    ['vless://' + UUID + '@u.example:443?encryption=none&type=httpupgrade&host=u.example&path=/up&security=tls&sni=u.example#hu', true],
    ['trojan://pw@t.example:443?type=ws&host=t.example&path=/tr&security=tls&sni=t.example#tr-ws', true],
    [vmess, true],
    ['vless://' + UUID + '@r.example:443?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=www.example.com&pbk=' + Buffer.alloc(32, 9).toString('base64url') + '&sid=ab#vision', false],
    ['vless://' + UUID + '@g.example:443?type=grpc&serviceName=svc&security=tls&sni=g.example#grpc', false],
    ['vless://' + UUID + '@k.example:443?type=kcp&headerType=none#kcp', false],
    ['hysteria2://pw@h.example:443/?sni=h.example#hy2', false],
    ['ss://' + Buffer.from('chacha20-ietf-poly1305:pw').toString('base64') + '@s.example:443?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Btls%3Bhost%3Dws.example%3Bpath%3D%2Fws#ss-ws', false]
  ];
  for (const [link, want] of links) {
    const s = parseLink(link);
    assert.equal(muxEligible(s.outbound), want, `${s.name}: ${s.outbound.protocol} over ${s.outbound.streamSettings && s.outbound.streamSettings.network}`);
  }
});

/* ----------------------------- the fingerprint ----------------------------- */

test('muxFingerprint: stable — a copy, a new name or a new record id are the same server', () => {
  const s = shaped('fp', 'vless', 'ws');
  const fp = muxFingerprint(s);
  assert.match(fp, /^[0-9a-f]{16,64}$/);
  assert.equal(muxFingerprint(clone(s)), fp);
  assert.equal(muxFingerprint(Object.assign(clone(s), { name: 'renamed' })), fp, 'the name is a label');
  assert.equal(muxFingerprint(Object.assign(clone(s), { id: 'refreshed-id' })), fp, 'a subscription refresh hands out new ids');
  // the port written as a string is the same port
  const str = clone(s); str.outbound.settings.vnext[0].port = '443';
  assert.equal(muxFingerprint(str), fp);
});

test('muxFingerprint changes with what the server is: address, port, id/password, network, path, host, security, SNI', () => {
  const base = shaped('fp', 'vless', 'ws');
  const edits = {
    address: (s) => { s.outbound.settings.vnext[0].address = 'other.example.com'; },
    port: (s) => { s.outbound.settings.vnext[0].port = 8443; },
    id: (s) => { s.outbound.settings.vnext[0].users[0].id = UUID; },
    network: (s) => { s.outbound.streamSettings.network = 'httpupgrade'; s.outbound.streamSettings.httpupgradeSettings = { path: '/ws', host: 'w.example.com' }; delete s.outbound.streamSettings.wsSettings; },
    path: (s) => { s.outbound.streamSettings.wsSettings.path = '/other'; },
    host: (s) => { s.outbound.streamSettings.wsSettings.headers.Host = 'cdn.example.com'; },
    security: (s) => { s.outbound.streamSettings.security = 'none'; },
    sni: (s) => { s.outbound.streamSettings.tlsSettings.serverName = 'sni.example.com'; },
    protocol: (s) => { s.outbound.protocol = 'vmess'; }
  };
  const seen = new Set([muxFingerprint(base)]);
  for (const [what, edit] of Object.entries(edits)) {
    const s = clone(base);
    edit(s);
    const fp = muxFingerprint(s);
    assert.ok(!seen.has(fp), `${what} must change the fingerprint`);
    seen.add(fp);
  }
  // Trojan's password, and httpupgrade's own path and host
  const tr = shaped('t', 'trojan', 'ws');
  const tr2 = clone(tr); tr2.outbound.settings.servers[0].password = 'another';
  assert.notEqual(muxFingerprint(tr), muxFingerprint(tr2));
  const hu = shaped('h', 'vless', 'httpupgrade');
  const hu2 = clone(hu); hu2.outbound.streamSettings.httpupgradeSettings.path = '/elsewhere';
  const hu3 = clone(hu); hu3.outbound.streamSettings.httpupgradeSettings.host = 'cdn.example.com';
  assert.equal(new Set([muxFingerprint(hu), muxFingerprint(hu2), muxFingerprint(hu3)]).size, 3);
});

/* ----------------------------- verdicts and their age ----------------------------- */

test('freshVerdict: ok for 7 days, unsupported for 1 — and nothing else is a verdict', () => {
  const now = 100 * DAY;
  assert.equal(freshVerdict({ verdict: 'ok', at: now }, now), 'ok');
  assert.equal(freshVerdict({ verdict: 'ok', at: now - 7 * DAY + 1 }, now), 'ok');
  assert.equal(freshVerdict({ verdict: 'ok', at: now - 7 * DAY }, now), null, 'seven days old: tested again');
  assert.equal(freshVerdict({ verdict: 'unsupported', at: now - DAY + 1 }, now), 'unsupported');
  assert.equal(freshVerdict({ verdict: 'unsupported', at: now - DAY }, now), null, 'a day old: tested again');
  assert.equal(freshVerdict({ verdict: 'unsupported', at: now - 2 * DAY }, now), null);
  assert.equal(freshVerdict({ verdict: 'unknown', at: now, retryAfter: now + HOUR }, now), null, 'an inconclusive test is no verdict');
  assert.equal(freshVerdict({ verdict: 'ok', at: now + DAY }, now), null, 'a verdict from the future (a clock set back) is not trusted');
  for (const junk of [null, undefined, {}, { verdict: 'ok' }, { verdict: 'ok', at: 'yesterday' }, 'ok', 7]) {
    assert.equal(freshVerdict(junk, now), null, JSON.stringify(junk));
  }
  assert.equal(mux.OK_TTL_MS, 7 * DAY);
  assert.equal(mux.UNSUPPORTED_TTL_MS, DAY);
  assert.equal(mux.RETRY_UNKNOWN_MS, HOUR);
});

/* ----------------------------- what each mode asks for ----------------------------- */

test('planMux: off — nothing, whatever is remembered', () => {
  const a = shaped('a', 'vless', 'ws');
  const cache = { [muxFingerprint(a)]: { verdict: 'ok', at: 10 } };
  assert.deepEqual(planMux({ mode: 'off', servers: [a], cache, now: 20 }), { muxIds: [], toProbe: [] });
});

test('planMux: on — every eligible server, untested', () => {
  const a = shaped('a', 'vless', 'ws');
  const b = shaped('b', 'trojan', 'httpupgrade');
  const cache = { [muxFingerprint(b)]: { verdict: 'unsupported', at: 10 } };
  const plan = planMux({ mode: 'on', servers: [a, TROJAN_TCP_TLS, b, SS_TCP], cache, now: 20 });
  assert.deepEqual(plan, { muxIds: ['a', 'b'], toProbe: [] });
});

test('planMux: auto — a fresh ok is muxed, a fresh unsupported is not, the rest are tested', () => {
  const now = 50 * DAY;
  const ok = shaped('ok', 'vless', 'ws');
  const no = shaped('no', 'vmess', 'ws');
  const stale = shaped('stale', 'trojan', 'ws');
  const fresh = shaped('new', 'vless', 'httpupgrade');
  const cache = {
    [muxFingerprint(ok)]: { verdict: 'ok', at: now - DAY },
    [muxFingerprint(no)]: { verdict: 'unsupported', at: now - 12 * HOUR },
    [muxFingerprint(stale)]: { verdict: 'ok', at: now - 8 * DAY }
  };
  const plan = planMux({ mode: 'auto', servers: [ok, no, stale, fresh, TROJAN_TCP_TLS, ok], cache, now });
  assert.deepEqual(plan.muxIds, ['ok']);
  assert.deepEqual(plan.toProbe.map((s) => s.id), ['stale', 'new'], 'once each, ineligible ones never');
  // an unset or unknown mode is the default, off (the owner's choice): nothing tested, nothing muxed
  assert.deepEqual(planMux({ servers: [ok, fresh], cache, now }), { muxIds: [], toProbe: [] });
  assert.deepEqual(planMux({ mode: 'sometimes', servers: [ok, fresh], cache, now }), { muxIds: [], toProbe: [] });
  assert.deepEqual(planMux({ mode: 'auto', servers: [fresh], cache: undefined, now }).toProbe.map((s) => s.id), ['new'], 'no cache yet');
});

test('planMux: a recovery’s connect never tests — a remembered ok, marked for a re-test or expired, still muxes; nothing else does', () => {
  // The review (I1): a rebuild after a drop tested inside the outage — on a
  // router the LAN offline (or direct) for those seconds, behind Windows' kill
  // switch a test that could never reach the server, and a slow line's
  // timeout turned mux off in the very storm it was added for.
  const now = 50 * DAY;
  const recheck = shaped('recheck', 'vless', 'ws');
  const expired = shaped('expired', 'vmess', 'ws');
  const no = shaped('no', 'trojan', 'ws');
  const unknown = shaped('unknown', 'vless', 'httpupgrade');
  const untested = shaped('untested', 'trojan', 'httpupgrade');
  const cache = {
    [muxFingerprint(recheck)]: { verdict: 'ok', at: now - 2 * DAY, recheck: true },
    [muxFingerprint(expired)]: { verdict: 'ok', at: now - 9 * DAY },
    [muxFingerprint(no)]: { verdict: 'unsupported', at: now - 3 * DAY },
    [muxFingerprint(unknown)]: { verdict: 'unknown', at: now - 2 * HOUR, retryAfter: now - HOUR }
  };
  const servers = [recheck, expired, no, unknown, untested];
  assert.deepEqual(planMux({ mode: 'auto', servers, cache, now, recovery: true }), { muxIds: ['recheck', 'expired'], toProbe: [] });
  // the next connect the user or the boot makes tests every one of them
  const user = planMux({ mode: 'auto', servers, cache, now });
  assert.deepEqual(user.muxIds, []);
  assert.deepEqual(user.toProbe.map((s) => s.id), ['recheck', 'expired', 'no', 'unknown', 'untested']);
});

test('planMux: no test before retryAfter — meanwhile the verdict an inconclusive test kept decides', () => {
  const now = 50 * DAY;
  const keptOk = shaped('kept-ok', 'vless', 'ws');
  const keptNo = shaped('kept-no', 'vmess', 'ws');
  const unknown = shaped('unknown', 'trojan', 'ws');
  const servers = [keptOk, keptNo, unknown];
  const cache = {
    [muxFingerprint(keptOk)]: { verdict: 'ok', at: now - 9 * DAY, recheck: true, retryAfter: now + 30 * 60 * 1000 },
    [muxFingerprint(keptNo)]: { verdict: 'unsupported', at: now - 2 * DAY, retryAfter: now + 1 },
    [muxFingerprint(unknown)]: { verdict: 'unknown', at: now - 10 * 60 * 1000, retryAfter: now + 50 * 60 * 1000 }
  };
  assert.deepEqual(planMux({ mode: 'auto', servers, cache, now }), { muxIds: ['kept-ok'], toProbe: [] });
  // the hour over: tested again
  assert.deepEqual(planMux({ mode: 'auto', servers, cache, now: now + HOUR }).toProbe.map((s) => s.id), ['kept-ok', 'kept-no', 'unknown']);
});

test('muxMode: off unless auto or on — a settings file without the key reads Off', () => {
  assert.deepEqual(['auto', 'on', 'off', undefined, null, '', 'ON', 'Auto', true].map(mux.muxMode), ['auto', 'on', 'off', 'off', 'off', 'off', 'off', 'off', 'off']);
});

test('decideMux with no mode, or one it does not know, is off: nothing tested, nothing said', async () => {
  const a = shaped('a', 'vless', 'ws');
  const lines = [];
  for (const mode of [undefined, 'sometimes']) {
    const res = await mux.decideMux({ mode, servers: [a], cache: {}, now: 1, probe: async () => { throw new Error('off tests nothing'); }, log: (l) => lines.push(l) });
    assert.deepEqual(res, { muxIds: [], learnt: [] });
  }
  assert.deepEqual(lines, []);
});

/* ----------------------------- the probe ----------------------------- */

const proxyOf = (config) => config.outbounds.find((o) => o.tag === 'proxy');

/**
 * A fake of what probeMux is handed: free ports, the REAL test-config builder,
 * cores that only record themselves, and requests answered from `mux` / `plain`
 * in order — true: it answered; false (or nothing left): the connection was
 * closed; an object: that very reply. `startThrows` fails every start,
 * `startThrowsFor` the starts of one kind ('mux' / 'plain'); `exited` names a
 * kind whose core has already exited (its proc's exitCode). `events` is the
 * order things happened in.
 */
function fakeRunner(opts = {}) {
  const r = { starts: [], cleanups: 0, requests: [], events: [], muxAnswers: (opts.mux || []).slice(), plainAnswers: (opts.plain || []).slice() };
  let port = 46100;
  r.deps = {
    getFreePort: async () => port++,
    buildTestConfig: (target, p) => buildTestConfig(target, p),
    startTest: async (config) => {
      if (opts.startDelayMs) await sleep(opts.startDelayMs);
      const kind = proxyOf(config).mux ? 'mux' : 'plain';
      if (opts.startThrows || opts.startThrowsFor === kind) throw new Error('spawn xray ENOENT');
      const proc = { pid: 4000 + r.starts.length, exitCode: opts.exited === kind ? 23 : null, signalCode: null };
      const core = { config, proc, port: config.inbounds[0].port, muxed: kind === 'mux', cleaned: 0 };
      core.cleanup = () => { core.cleaned++; r.cleanups++; r.events.push('cleanup ' + kind); };
      r.starts.push(core);
      r.events.push('start ' + kind);
      return core;
    },
    httpThroughProxy: async (p, o) => {
      const core = r.starts.find((c) => c.port === p);
      const kind = core && core.muxed ? 'mux' : 'plain';
      r.requests.push({ port: p, kind, opts: o });
      r.events.push('request ' + kind);
      if (opts.hang) return new Promise(() => {});
      if (opts.requestThrows) throw new Error('boom');
      if (opts.answerMs) await sleep(opts.answerMs);
      r.events.push('answered ' + kind);
      const a = (kind === 'mux' ? r.muxAnswers : r.plainAnswers).shift();
      if (a && typeof a === 'object') return a;
      return a ? { ok: true, ms: 120, status: 204 } : { ok: false, ms: -1, error: 'closed' };
    }
  };
  if (opts.timeoutMs) r.deps.timeoutMs = opts.timeoutMs;
  return r;
}
const TIMED_OUT = { ok: false, ms: -1, error: 'timeout' };
const REFUSED_PORT = { ok: false, ms: -1, error: 'connect ECONNREFUSED 127.0.0.1:46100' };

test('probeMux: two requests through one muxed core both answer — ok; one core, cleaned up', async () => {
  const r = fakeRunner({ mux: [true, true] });
  assert.equal(await probeMux(shaped('p', 'vless', 'ws'), r.deps), 'ok');
  assert.equal(r.starts.length, 1);
  assert.deepEqual(proxyOf(r.starts[0].config).mux, MUX, 'the throwaway core’s proxy outbound carries the mux object');
  assert.notEqual(proxyOf(r.starts[0].config).mux, MUX, 'a copy: the frozen object never goes into a config');
  assert.deepEqual(r.requests.map((q) => q.kind), ['mux', 'mux'], 'two requests, both through the muxed core');
  assert.deepEqual(r.events, ['start mux', 'request mux', 'answered mux', 'request mux', 'answered mux', 'cleanup mux'], 'one after the other');
  assert.equal(r.cleanups, 1);
  // what ping:real asks, inside the budget
  for (const q of r.requests) {
    assert.equal(q.opts.host, 'cp.cloudflare.com');
    assert.equal(q.opts.port, 80);
    assert.ok(q.opts.timeout > 0 && q.opts.timeout <= mux.PROBE_MS, `timeout ${q.opts.timeout}`);
  }
  assert.equal(mux.PROBE_MS, 8000);
});

test('probeMux: mux fails and a plain core answers — unsupported; both cores cleaned up', async () => {
  const r = fakeRunner({ mux: [false], plain: [true] });
  assert.equal(await probeMux(shaped('p', 'trojan', 'ws'), r.deps), 'unsupported');
  assert.deepEqual(r.starts.map((c) => c.muxed), [true, false]);
  assert.equal(proxyOf(r.starts[1].config).mux, undefined, 'the control runs without mux');
  assert.deepEqual(r.requests.map((q) => q.kind), ['mux', 'plain'], 'a failed first request ends the mux half; ONE control request');
  assert.equal(r.cleanups, 2);
  assert.ok(r.events.indexOf('cleanup mux') < r.events.indexOf('start plain'), 'the muxed core is gone before the control starts');
});

test('probeMux: the second request through the mux connection fails — that is a failure too', async () => {
  const r = fakeRunner({ mux: [true, false], plain: [true] });
  assert.equal(await probeMux(shaped('p', 'vmess', 'ws'), r.deps), 'unsupported');
  assert.deepEqual(r.requests.map((q) => q.kind), ['mux', 'mux', 'plain']);
  assert.equal(r.cleanups, 2);
});

test('probeMux: neither answers — unreachable (nothing to learn); every core cleaned up', async () => {
  const r = fakeRunner({ mux: [false], plain: [false] });
  assert.equal(await probeMux(shaped('p', 'vless', 'httpupgrade'), r.deps), 'unreachable');
  assert.equal(r.starts.length, 2);
  assert.equal(r.cleanups, 2);
});

test('probeMux: a failing dependency is unreachable, never a throw — and what was started is cleaned up', async () => {
  const noCore = fakeRunner({ startThrows: true });
  assert.equal(await probeMux(shaped('p', 'vless', 'ws'), noCore.deps), 'unreachable');
  assert.equal(noCore.cleanups, 0, 'nothing started, nothing to clean');
  const broken = fakeRunner({ requestThrows: true });
  assert.equal(await probeMux(shaped('p', 'vless', 'ws'), broken.deps), 'unreachable');
  assert.equal(broken.cleanups, broken.starts.length);
  assert.equal(broken.starts.length, 2);
  const badConfig = fakeRunner();
  badConfig.deps.buildTestConfig = () => { throw new Error('no outbound'); };
  assert.equal(await probeMux(shaped('p', 'vless', 'ws'), badConfig.deps), 'unreachable');
});

test('probeMux: never longer than its budget — a request that hangs ends as unreachable, its core cleaned up', async () => {
  const r = fakeRunner({ hang: true, timeoutMs: 120 });
  const t0 = Date.now();
  assert.equal(await probeMux(shaped('p', 'vless', 'ws'), r.deps), 'unreachable');
  const took = Date.now() - t0;
  assert.ok(took < 1000, `took ${took} ms for a 120 ms budget`);
  assert.equal(r.cleanups, r.starts.length, 'every core that was started is cleaned up');
  assert.ok(r.starts.length >= 1);
  for (const q of r.requests) assert.ok(q.opts.timeout <= 120, `a request may not outlive the probe: ${q.opts.timeout}`);
});

test('probeMux: a core that only comes up after the deadline is cleaned up at once and never used', async () => {
  const r = fakeRunner({ startDelayMs: 400, timeoutMs: 40 });
  const t0 = Date.now();
  assert.equal(await probeMux(shaped('p', 'vless', 'ws'), r.deps), 'unreachable');
  assert.ok(Date.now() - t0 < 350, 'answered at the deadline, not when the core came up');
  await sleep(500);
  assert.equal(r.starts.length, 1, 'the late core, and no second one after it');
  assert.equal(r.cleanups, 1);
  assert.deepEqual(r.requests, [], 'nothing was asked through it');
});

test('probeMux: a mux that runs out of its share, on a line the control proves working, is unknown — never unsupported', async () => {
  // The owner's line (live run, Xray 26.3.27, the ECH server): the mux attempt
  // used up its 5 s on a slow moment, the control asked after it answered, and
  // that TIMEOUT was read as "refuses mux" — mux off for three days exactly
  // where it is needed. A slow line says nothing about the server; the control
  // still runs, to tell a working line (unknown) from nothing reachable.
  const r = fakeRunner({ plain: [true], timeoutMs: 400 });
  r.deps.httpThroughProxy = async (p, o) => {
    const core = r.starts.find((c) => c.port === p);
    r.requests.push({ port: p, kind: core.muxed ? 'mux' : 'plain', opts: o });
    if (core.muxed) return new Promise((resolve) => setTimeout(() => resolve({ ok: false, ms: -1, error: 'timeout' }), o.timeout));
    return { ok: true, ms: 50, status: 204 };
  };
  const t0 = Date.now();
  assert.equal(await probeMux(shaped('p', 'vless', 'ws'), r.deps), 'unknown');
  assert.ok(Date.now() - t0 < 390, 'within the budget');
  assert.deepEqual(r.requests.map((q) => q.kind), ['mux', 'plain']);
  assert.ok(r.requests[0].opts.timeout <= 250, `the mux half keeps its 5/8 share: ${r.requests[0].opts.timeout}`);
  assert.ok(r.requests[1].opts.timeout > 0, 'the control gets the rest');
  assert.equal(r.starts.length, 2);
  assert.equal(r.cleanups, 2);
});

test('probeMux: mux timed out or refused, and the control does not answer either — unreachable', async () => {
  // Nothing reachable — the WAN not up yet on a router's first boot connect,
  // the server down: no verdict to keep, nothing to remember, tested again by
  // the next connect (the boot loop's next attempt).
  for (const [muxed, control] of [[TIMED_OUT, false], [TIMED_OUT, TIMED_OUT], [false, false], [false, TIMED_OUT], [REFUSED_PORT, false]]) {
    const r = fakeRunner({ exited: muxed === REFUSED_PORT ? 'mux' : undefined, mux: [muxed], plain: [control] });
    assert.equal(await probeMux(shaped('p', 'vless', 'ws'), r.deps), 'unreachable', JSON.stringify([muxed, control]));
    assert.equal(r.cleanups, r.starts.length);
  }
});

test('probeMux: mux times out and the control answers — unknown, never unsupported', async () => {
  for (const timedOut of [TIMED_OUT, { ok: false, ms: -1, error: 'socks timeout' }, { ok: false, ms: -1, error: 'ETIMEDOUT' }]) {
    const r = fakeRunner({ mux: [timedOut], plain: [true] });
    assert.equal(await probeMux(shaped('p', 'vless', 'ws'), r.deps), 'unknown', timedOut.error);
    assert.equal(r.cleanups, r.starts.length);
  }
  // …the second request through the mux connection timing out is no answer either
  const second = fakeRunner({ mux: [true, TIMED_OUT], plain: [true] });
  assert.equal(await probeMux(shaped('p', 'vless', 'ws'), second.deps), 'unknown');
});

test('probeMux: mux closed (a definitive no) and the control answers — unsupported; any other definitive no likewise', async () => {
  const definitive = [
    { ok: false, ms: -1, error: 'closed' },                      // the server dropped the muxed stream
    { ok: false, ms: -1, error: 'ECONNRESET' },                  // reset
    { ok: false, ms: -1, error: 'socks connect failed code 5' }, // the core refused the request
    { ok: false, ms: 80, status: 503 }                           // answered, with an error status
  ];
  for (const no of definitive) {
    const r = fakeRunner({ mux: [no], plain: [true] });
    assert.equal(await probeMux(shaped('p', 'trojan', 'ws'), r.deps), 'unsupported', JSON.stringify(no));
    assert.deepEqual(r.requests.map((q) => q.kind), ['mux', 'plain']);
    assert.equal(r.cleanups, 2);
  }
  // …and the control not answering makes it unreachable, whatever the mux said
  for (const control of [false, TIMED_OUT]) {
    const r = fakeRunner({ mux: [false], plain: [control] });
    assert.equal(await probeMux(shaped('p', 'trojan', 'ws'), r.deps), 'unreachable', JSON.stringify(control));
  }
});

test('probeMux: the muxed core does not start and the control answers — unsupported (the config with mux is what failed)', async () => {
  const r = fakeRunner({ startThrowsFor: 'mux', plain: [true] });
  assert.equal(await probeMux(shaped('p', 'vless', 'ws'), r.deps), 'unsupported');
  assert.deepEqual(r.starts.map((c) => c.muxed), [false], 'only the control core came up');
  assert.equal(r.cleanups, 1);
  // a core that exited (its config refused) answers its port with a refusal: the same "did not start"
  const exited = fakeRunner({ exited: 'mux', mux: [REFUSED_PORT], plain: [true] });
  assert.equal(await probeMux(shaped('p', 'vless', 'ws'), exited.deps), 'unsupported');
  assert.deepEqual(exited.requests.map((q) => q.kind), ['mux', 'plain'], 'not asked again: it is gone');
});

test('probeMux: a core still starting (its port refused, the core alive) is asked again — not a refusal', async () => {
  // startTest gives a core 500 ms. On a router's slow CPU the first core after
  // a boot runs from a cold binary: a refused port then is a core not yet
  // listening — taken for "refuses mux", a control on the now warm binary would
  // have made it unsupported for three days.
  const r = fakeRunner({ mux: [REFUSED_PORT, REFUSED_PORT, true, true] });
  assert.equal(await probeMux(shaped('p', 'vless', 'ws'), r.deps), 'ok');
  assert.deepEqual(r.requests.map((q) => q.kind), ['mux', 'mux', 'mux', 'mux']);
  assert.equal(r.starts.length, 1);
  // …and one that never opens its port within the mux share is a timeout: unknown, the control answering
  const never = fakeRunner({ mux: Array(100).fill(REFUSED_PORT), plain: [true], timeoutMs: 400 });
  assert.equal(await probeMux(shaped('p', 'vless', 'ws'), never.deps), 'unknown');
  assert.deepEqual(never.starts.map((c) => c.muxed), [true, false]);
  assert.equal(never.cleanups, 2);
});

/* ----------------------------- one connect’s decision ----------------------------- */

test('decideMux: remembered answers stand, the rest are tested — one line per server; an unknown is learnt too (for its retry hour)', async () => {
  const now = 30 * DAY;
  const ok = shaped('ok', 'vless', 'ws');
  const no = shaped('no', 'vmess', 'ws');
  const fresh = shaped('fresh', 'trojan', 'ws');
  const refuses = shaped('refuses', 'vless', 'httpupgrade');
  const silent = shaped('silent', 'vless', 'ws', (s) => { s.outbound.streamSettings.wsSettings.path = '/silent'; });
  const cache = { [muxFingerprint(ok)]: { verdict: 'ok', at: now - DAY }, [muxFingerprint(no)]: { verdict: 'unsupported', at: now - 12 * HOUR } };
  const answers = { fresh: 'ok', refuses: 'unsupported', silent: 'unknown' };
  const probed = [];
  const lines = [];
  const res = await mux.decideMux({
    mode: 'auto', servers: [ok, no, fresh, TROJAN_TCP_TLS, refuses, silent], cache, now,
    probe: async (s) => { probed.push(s.id); return answers[s.id]; },
    log: (line, level) => lines.push([level, line])
  });
  assert.deepEqual(probed.sort(), ['fresh', 'refuses', 'silent']);
  assert.deepEqual(res.muxIds, ['ok', 'fresh']);
  assert.deepEqual(res.learnt, [
    { fp: muxFingerprint(fresh), verdict: 'ok' },
    { fp: muxFingerprint(refuses), verdict: 'unsupported' },
    { fp: muxFingerprint(silent), verdict: 'unknown' }
  ]);
  assert.deepEqual(lines, [
    ['info', 'Mux on for Server ok (tested: works)'],
    ['info', 'Mux off for Server no (this server does not accept it)'],
    ['info', 'Mux on for Server fresh (tested: works)'],
    ['info', 'Mux off for Server refuses (this server does not accept it)'],
    ['warn', 'Mux: Server silent did not answer through mux in time — connecting without it']
  ]);
  // within its retry hour the remembered unknown is not tested again — said once more, quietly
  const memo = mux.rememberVerdicts(cache, res.learnt, now);
  const again = [];
  const res2 = await mux.decideMux({
    mode: 'auto', servers: [silent], cache: memo, now: now + 10 * 60 * 1000,
    probe: async () => { throw new Error('not within the hour'); },
    log: (line, level) => again.push([level, line])
  });
  assert.deepEqual(res2, { muxIds: [], learnt: [] });
  assert.deepEqual(again, [['info', 'Mux: Server silent did not answer through mux in time — connecting without it']]);
});

test('decideMux: a probe that throws, or answers nonsense, is unreachable — nothing learnt', async () => {
  const a = shaped('a', 'vless', 'ws');
  const b = shaped('b', 'vless', 'httpupgrade');
  const lines = [];
  const res = await mux.decideMux({
    mode: 'auto', servers: [a, b], cache: {}, now: 1,
    probe: async (s) => { if (s.id === 'a') throw new Error('boom'); return 'maybe'; },
    log: (line, level) => lines.push([level, line])
  });
  assert.deepEqual(res, { muxIds: [], learnt: [] });
  assert.deepEqual(lines.map(([level]) => level), ['warn', 'warn']);
  assert.ok(lines.every(([, l]) => /did not answer either way — connecting without it$/.test(l)));
});

test('decideMux + probeMux: a mux timeout beside a control that answers is an unknown with its retry hour stamped', async () => {
  const now = 30 * DAY;
  const s = shaped('slow', 'vless', 'ws');
  const res = await mux.decideMux({
    mode: 'auto', servers: [s], cache: {}, now,
    probe: (server) => probeMux(server, fakeRunner({ mux: [TIMED_OUT], plain: [true] }).deps),
    log: () => {}
  });
  assert.deepEqual(res.learnt, [{ fp: muxFingerprint(s), verdict: 'unknown' }]);
  assert.deepEqual(mux.rememberVerdicts({}, res.learnt, now)[muxFingerprint(s)], { verdict: 'unknown', at: now, retryAfter: now + HOUR });
});

test('decideMux + probeMux: mux failed or timed out and the control failed too — nothing learnt, the cache is the same object, the next connect tests again', async () => {
  // A router's first boot connect before its WAN is up: remembered as unknown
  // for an hour, every later rebuild — which never tests — went without mux
  // until the next boot. Nothing reachable is nothing learnt.
  const now = 30 * DAY;
  const fresh = shaped('fresh', 'vless', 'ws');
  const marked = shaped('marked', 'vmess', 'ws');
  const cache = { [muxFingerprint(marked)]: { verdict: 'ok', at: now - 3 * DAY, recheck: true } };
  for (const [muxed, control] of [[false, false], [TIMED_OUT, false], [TIMED_OUT, TIMED_OUT]]) {
    const lines = [];
    const res = await mux.decideMux({
      mode: 'auto', servers: [fresh, marked], cache, now,
      probe: (server) => probeMux(server, fakeRunner({ mux: [muxed], plain: [control] }).deps),
      log: (line, level) => lines.push([level, line])
    });
    assert.deepEqual(res.learnt, [], JSON.stringify([muxed, control]));
    assert.equal(mux.rememberVerdicts(cache, res.learnt, now), cache, 'no store write');
    assert.deepEqual(res.muxIds, ['marked'], 'the ok from before stands for this connect');
    assert.deepEqual(lines, [
      ['warn', 'Mux: Server fresh did not answer either way — connecting without it'],
      ['info', 'Mux on for Server marked (tested before: works — this test did not answer)']
    ]);
    // the next connect — the boot loop's next attempt — tests both again
    assert.deepEqual(planMux({ mode: 'auto', servers: [fresh, marked], cache, now: now + 1000 }).toProbe.map((x) => x.id), ['fresh', 'marked']);
  }
});

test('decideMux: a recovery’s connect never tests — a re-test mark is kept as ok and muxed; nothing usable goes without', async () => {
  const now = 30 * DAY;
  const marked = shaped('marked', 'vless', 'ws');
  const fresh = shaped('fresh', 'vmess', 'ws');
  const lines = [];
  const cache = { [muxFingerprint(marked)]: { verdict: 'ok', at: now - 3 * DAY, recheck: true } };
  const res = await mux.decideMux({
    mode: 'auto', servers: [marked, fresh], cache, now, recovery: true,
    probe: async () => { throw new Error('a rebuild never tests'); },
    log: (line, level) => lines.push([level, line])
  });
  assert.deepEqual(res, { muxIds: ['marked'], learnt: [] });
  assert.deepEqual(lines, [
    ['info', 'Mux on for Server marked (tested: works)'],
    ['info', 'Mux: Server fresh not tested yet — connecting without it']
  ]);
});

test('decideMux: an inconclusive re-test keeps mux on — the ok it had stands, the unknown only earns a retry hour', async () => {
  const now = 30 * DAY;
  const marked = shaped('marked', 'vless', 'ws');
  const expired = shaped('expired', 'vmess', 'ws');
  const lines = [];
  const cache = {
    [muxFingerprint(marked)]: { verdict: 'ok', at: now - 3 * DAY, recheck: true },
    [muxFingerprint(expired)]: { verdict: 'unsupported', at: now - 2 * DAY }
  };
  const res = await mux.decideMux({
    mode: 'auto', servers: [marked, expired], cache, now,
    probe: async () => 'unknown',
    log: (line, level) => lines.push([level, line])
  });
  assert.deepEqual(res.muxIds, ['marked'], 'mux stays on');
  assert.deepEqual(res.learnt, [{ fp: muxFingerprint(marked), verdict: 'unknown' }, { fp: muxFingerprint(expired), verdict: 'unknown' }]);
  assert.deepEqual(lines, [
    ['info', 'Mux on for Server marked (tested before: works — this test did not answer)'],
    ['info', 'Mux off for Server expired (this server does not accept it)']
  ]);
});

test('decideMux: `parallel` caps the probes at once — one at a time for the router', async () => {
  const servers = [];
  for (let i = 0; i < 4; i++) servers.push(shaped('r' + i, 'vless', 'ws'));
  let inFlight = 0, most = 0;
  const res = await mux.decideMux({
    mode: 'auto', servers, cache: {}, now: 1, parallel: 1,
    probe: async () => { inFlight++; most = Math.max(most, inFlight); await sleep(10); inFlight--; return 'ok'; },
    log: () => {}
  });
  assert.equal(most, 1);
  assert.equal(res.muxIds.length, 4);
});

test('decideMux: at most three probes at once, each server once — two records of one server are one probe', async () => {
  const servers = [];
  for (let i = 0; i < 7; i++) servers.push(shaped('s' + i, 'vless', 'ws'));
  const twin = Object.assign(clone(servers[0]), { id: 'twin', name: 'twin' });
  let inFlight = 0, most = 0;
  const probed = [];
  const res = await mux.decideMux({
    mode: 'auto', servers: [...servers, twin], cache: {}, now: 1,
    probe: async (s) => { probed.push(s.id); inFlight++; most = Math.max(most, inFlight); await sleep(15); inFlight--; return 'ok'; },
    log: () => {}
  });
  assert.equal(most, mux.PROBE_PARALLEL);
  assert.equal(mux.PROBE_PARALLEL, 3);
  assert.equal(probed.length, 7, 'the twin shares its server’s probe');
  assert.deepEqual(res.muxIds, [...servers.map((s) => s.id), 'twin']);
  assert.equal(res.learnt.length, 7);
});

test('decideMux: on muxes every eligible server untested and silently; off does nothing', async () => {
  const a = shaped('a', 'vless', 'ws');
  const lines = [];
  const probe = async () => { throw new Error('no probe in this mode'); };
  assert.deepEqual(await mux.decideMux({ mode: 'on', servers: [a, TROJAN_TCP_TLS], cache: {}, now: 1, probe, log: (l) => lines.push(l) }), { muxIds: ['a'], learnt: [] });
  assert.deepEqual(await mux.decideMux({ mode: 'off', servers: [a], cache: {}, now: 1, probe, log: (l) => lines.push(l) }), { muxIds: [], learnt: [] });
  assert.deepEqual(lines, []);
});

/* ----------------------------- the store’s memory ----------------------------- */

test('rememberVerdicts: newest wins, the input is never changed, at most 500 entries — the oldest go', () => {
  const cache = {};
  for (let i = 0; i < 500; i++) cache['fp' + i] = { verdict: 'ok', at: 1000 + i };
  const before = clone(cache);
  const next = mux.rememberVerdicts(cache, [{ fp: 'new1', verdict: 'ok' }, { fp: 'new2', verdict: 'unsupported' }, { fp: 'fp499', verdict: 'unsupported' }], 9999);
  assert.deepEqual(cache, before, 'a new object');
  assert.equal(Object.keys(next).length, 500);
  assert.equal(mux.CACHE_MAX, 500);
  assert.deepEqual(next.new1, { verdict: 'ok', at: 9999 });
  assert.deepEqual(next.new2, { verdict: 'unsupported', at: 9999 });
  assert.deepEqual(next.fp499, { verdict: 'unsupported', at: 9999 }, 'a server tested again carries its new verdict');
  assert.equal('fp0' in next, false, 'the oldest dropped');
  assert.equal('fp1' in next, false);
  assert.equal('fp2' in next, true);
  // a store that holds junk instead of a map starts over
  assert.deepEqual(mux.rememberVerdicts(null, [{ fp: 'x', verdict: 'ok' }], 5), { x: { verdict: 'ok', at: 5 } });
  assert.deepEqual(mux.rememberVerdicts([], [{ fp: 'x', verdict: 'ok' }], 5), { x: { verdict: 'ok', at: 5 } });
});

test('rememberVerdicts: an unknown never replaces an ok or unsupported verdict — it keeps it (expired or marked included) and stamps a retry hour; with nothing before, it is remembered as unknown', () => {
  const now = 40 * DAY;
  const cache = {
    marked: { verdict: 'ok', at: now - 3 * DAY, recheck: true },
    expiredOk: { verdict: 'ok', at: now - 9 * DAY },
    expiredNo: { verdict: 'unsupported', at: now - 2 * DAY },
    gone: { verdict: 'unknown', at: now - 2 * HOUR, retryAfter: now - HOUR }
  };
  const before = clone(cache);
  const next = mux.rememberVerdicts(cache, ['marked', 'expiredOk', 'expiredNo', 'gone', 'fresh'].map((fp) => ({ fp, verdict: 'unknown' })), now);
  assert.deepEqual(next.marked, { verdict: 'ok', at: now - 3 * DAY, recheck: true, retryAfter: now + HOUR }, 'still ok: mux stays on, tested again after the hour');
  assert.deepEqual(next.expiredOk, { verdict: 'ok', at: now - 9 * DAY, retryAfter: now + HOUR });
  assert.deepEqual(next.expiredNo, { verdict: 'unsupported', at: now - 2 * DAY, retryAfter: now + HOUR });
  assert.deepEqual(next.gone, { verdict: 'unknown', at: now, retryAfter: now + HOUR });
  assert.deepEqual(next.fresh, { verdict: 'unknown', at: now, retryAfter: now + HOUR });
  assert.deepEqual(cache, before, 'a new object');
  // a definitive answer clears the mark and the retry hour
  const settled = mux.rememberVerdicts(next, [{ fp: 'marked', verdict: 'ok' }, { fp: 'expiredNo', verdict: 'ok' }, { fp: 'gone', verdict: 'unsupported' }], now + 2 * HOUR);
  assert.deepEqual(settled.marked, { verdict: 'ok', at: now + 2 * HOUR });
  assert.deepEqual(settled.expiredNo, { verdict: 'ok', at: now + 2 * HOUR });
  assert.deepEqual(settled.gone, { verdict: 'unsupported', at: now + 2 * HOUR });
});

test('rememberVerdicts: nothing to remember — no answers, an unreachable, junk — is the same object (no store write)', () => {
  const cache = { a: { verdict: 'ok', at: 1 } };
  assert.equal(mux.rememberVerdicts(cache, [], 5), cache);
  assert.equal(mux.rememberVerdicts(cache, [{ fp: 'a', verdict: 'unreachable' }, { fp: 'b', verdict: 'unreachable' }], 5), cache);
  assert.equal(mux.rememberVerdicts(cache, [{ fp: 'a', verdict: 'maybe' }, null, { verdict: 'ok' }], 5), cache);
  assert.deepEqual(cache, { a: { verdict: 'ok', at: 1 } });
});

test('markRecheck: a drop marks the ok verdicts of what it muxed for a re-test — kept as ok; nothing to mark is the same object (no store write)', () => {
  const now = 40 * DAY;
  const cache = {
    a: { verdict: 'ok', at: now - 2 * DAY },
    b: { verdict: 'ok', at: now - 5 * 60 * 1000 },
    done: { verdict: 'ok', at: now - DAY, recheck: true },
    no: { verdict: 'unsupported', at: now - HOUR },
    unknown: { verdict: 'unknown', at: now - HOUR, retryAfter: now }
  };
  const before = clone(cache);
  const next = mux.markRecheck(cache, ['a', 'b', 'done', 'no', 'unknown', 'zz', 'a']);
  assert.deepEqual(next.a, { verdict: 'ok', at: now - 2 * DAY, recheck: true });
  assert.deepEqual(next.b, { verdict: 'ok', at: now - 5 * 60 * 1000, recheck: true }, 'however young: a drop is a drop');
  assert.deepEqual(next.done, cache.done);
  assert.deepEqual(next.no, cache.no, 'only an ok is marked');
  assert.deepEqual(next.unknown, cache.unknown);
  assert.equal('zz' in next, false);
  assert.deepEqual(cache, before, 'a new object; the input is untouched');
  // nothing to mark — already marked, not an ok, not remembered: the very same object, so the caller writes nothing
  assert.equal(mux.markRecheck(cache, ['done', 'no', 'unknown', 'zz']), cache);
  assert.equal(mux.markRecheck(cache, []), cache);
  assert.equal(mux.markRecheck(next, ['a', 'b']), next, 'a second drop writes nothing more');
});

/* ----------------------------- which servers a plan asks about ----------------------------- */

test('muxCandidates: the servers a plan dials as targets of their own — never a chain’s hops', () => {
  const a = shaped('a', 'vless', 'ws');
  const b = shaped('b', 'trojan', 'ws');
  const c = shaped('c', 'vmess', 'ws');
  const serversById = { a, b, c };
  const chainsById = { c1: [a, b] };
  assert.deepEqual(mux.muxCandidates({ mode: 'single', server: a }).map((s) => s.id), ['a']);
  assert.deepEqual(mux.muxCandidates({ mode: 'chain', chain: [a, b] }), []);
  const advanced = {
    mode: 'advanced', serversById, chainsById, chain: [a],
    rules: [{ type: 'domain', value: 'x.com', target: 'b' }, { type: 'ip', value: '10.0.0.0/8', target: 'chain:c1' }, { type: 'port', value: '22', target: 'chain' },
      { type: 'domain', value: 'y.com', target: 'direct' }, { type: 'domain', value: 'z.com', target: 'block' }, { type: 'domain', value: 'w.com', target: 'gone' }, { type: 'domain', value: 'v.com', target: 'b' }, null],
    def: 'c'
  };
  assert.deepEqual(mux.muxCandidates(advanced).map((s) => s.id), ['b', 'c'], 'server targets and the default, once each');
  const pool = { mode: 'pool', serversById, chainsById, chain: [], primary: 'a', entries: [{ id: 'e1', target: 'a' }, { id: 'e2', target: 'chain:c1' }, { id: 'e3', target: 'c' }] };
  assert.deepEqual(mux.muxCandidates(pool).map((s) => s.id), ['a', 'c']);
  assert.deepEqual(mux.muxCandidates(null), []);
});
