'use strict';
/**
 * A path that reads names in TLS hellos (helloCut.js): what gets a cut hello and what is left alone, that an ordinary
 * connection's config does not change by a byte, that every kind of config in one plan keeps its own way of dialling, and
 * the check itself. The real thing, on real cores behind a real reader, is scripts/probe-hello-cut.js.
 */
const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const { HELLO_CUT, cutHellos, takesCut, certNames, pathReadsHello } = require('../src/main/helloCut');
const { buildConfig, buildTestConfig, buildMultiTestConfig } = require('../src/main/configBuilder');
const { latencyTest } = require('../src/main/latencyTest');
const { parseLink } = require('../src/main/parser');
const H = require('./serviceHarness');

const ID = '11111111-1111-1111-1111-111111111111';
const link = (q, name) => `vless://${ID}@192.0.2.1:443?${q}#${name}`;
const srv = (id, q) => Object.assign(parseLink(link(q, id)), { id });
const PINNED = srv('aaaaaaaaaaaaaaaa', 'type=xhttp&security=tls&sni=cover.test&pcs=' + 'a'.repeat(64));
const REALITY = srv('bbbbbbbbbbbbbbbb', 'type=tcp&security=reality&sni=cover.test&pbk=' + 'A'.repeat(43) + '&sid=&fp=chrome');
const OWN_FRAG = srv('cccccccccccccccc', 'type=ws&security=tls&sni=cdn.test&fragment=1-3,5-9,20-30');
const MASKED = (() => {
  const s = srv('dddddddddddddddd', 'type=ws&security=tls&sni=cdn.test');
  s.outbound.streamSettings.finalmask = { tcp: [{ type: 'fragment', settings: { packets: 'tlshello', length: '10-20', delay: '1-2' } }] };
  return s;
})();
const SETTINGS = { socksPort: 1, httpPort: 2, apiPort: 3, geoAssets: false, blockAds: false, enableSniffing: true, routingMode: 'global' };
const single = (server, extra) => buildConfig({ mode: 'single', server }, Object.assign({}, SETTINGS, extra));
const dialerOf = (c, o) => c.outbounds.find((x) => x.tag === o.streamSettings.sockopt.dialerProxy);

test('a hello over TCP takes the cut; what says how it dials, and what has no such hello, does not', () => {
  const st = (over, o = {}) => Object.assign({ protocol: 'vless', streamSettings: Object.assign({ network: 'tcp', security: 'tls' }, over) }, o);
  for (const network of ['tcp', 'raw', 'ws', 'grpc', 'httpupgrade', 'xhttp', 'splithttp', 'h2']) assert.equal(takesCut(st({ network })), true, network);
  assert.equal(takesCut(st({ security: 'reality' })), true);
  assert.equal(takesCut(st({}, { _fragment: 'tlshello,10-20,1-2' })), false, 'its own fragment');
  assert.equal(takesCut(st({}, { _noise: 'random' })), false, 'its own noise');
  assert.equal(takesCut(st({ finalmask: { tcp: [] } })), false, 'a final mask');
  assert.equal(takesCut(st({ sockopt: { dialMode: 'x' } })), false, 'a dial mode');
  assert.equal(takesCut(st({ sockopt: { dialerProxy: 'hop' } })), false, 'a hop in front of it');
  assert.equal(takesCut(st({ tlsSettings: { echConfigList: 'x' } })), false, 'ECH');
  assert.equal(takesCut(st({ tlsSettings: { alpn: ['h3'] } })), false, 'QUIC');
  assert.equal(takesCut(st({ security: 'none' })), false, 'no TLS');
  for (const network of ['kcp', 'mkcp', 'quic', 'hysteria']) assert.equal(takesCut(st({ network })), false, network);
  assert.equal(takesCut({ protocol: 'wireguard', settings: {} }), false);
  assert.equal(takesCut(null), false);
  assert.deepEqual(cutHellos(null), null);
});

test('off, the config is what it always was, to the byte', () => {
  for (const s of [PINNED, REALITY, OWN_FRAG, MASKED]) {
    assert.equal(JSON.stringify(single(s, { cutHello: false })), JSON.stringify(single(s)));
  }
  const whole = single(PINNED);
  assert.equal(whole.outbounds.some((o) => o.settings && o.settings.fragment), false);
});

test('on, a server dials through a dialer that cuts into records with no pause, on its own', () => {
  for (const s of [PINNED, REALITY]) {
    const c = single(s, { cutHello: true });
    const proxy = c.outbounds.find((o) => o.protocol === 'vless');
    const d = dialerOf(c, proxy);
    assert.equal(d.protocol, 'freedom');
    assert.deepEqual(d.settings.fragment, { packets: 'tlshello', length: '100-200', interval: '0-0' });
    assert.equal(HELLO_CUT, 'tlshello,100-200,0');
    assert.equal(c.outbounds.some((o) => '_fragment' in o), false, 'the marker is not left for the core');
  }
});

test('one plan of many kinds: each keeps its own, and only the plain ones are cut', () => {
  const WG = Object.assign(parseLink('wireguard://' + encodeURIComponent('A'.repeat(43) + '=') + '@198.51.100.1:51820?publickey=' + encodeURIComponent('B'.repeat(43) + '=') + '&address=10.0.0.2/32#wg'), { id: 'eeeeeeeeeeeeeeee' });
  const all = [PINNED, REALITY, OWN_FRAG, MASKED, WG];
  const plan = {
    mode: 'advanced', serversById: Object.fromEntries(all.map((s) => [s.id, s])), chainsById: {}, chain: [],
    rules: [
      { type: 'domain', value: 'a.test', target: REALITY.id, via: 'none' },
      { type: 'domain', value: 'b.test', target: OWN_FRAG.id, via: 'none' },
      { type: 'domain', value: 'c.test', target: MASKED.id, via: 'none' },
      { type: 'ip', value: '10.0.0.0/8', target: WG.id }
    ],
    def: PINNED.id, base: PINNED.id, defVia: 'inherit', useMode: true
  };
  const c = buildConfig(plan, Object.assign({}, SETTINGS, { cutHello: true }));
  const byName = (name) => c.outbounds.find((o) => String(o.tag).startsWith('out-' + name) && !String(o.tag).includes('@'));
  const dial = (o) => (o.streamSettings && o.streamSettings.sockopt && o.streamSettings.sockopt.dialerProxy) || '';
  const fragOf = (o) => { const d = c.outbounds.find((x) => x.tag === dial(o)); return d && d.settings && d.settings.fragment; };

  assert.deepEqual(fragOf(byName(REALITY.id)), { packets: 'tlshello', length: '100-200', interval: '0-0' }, 'Reality is cut');
  assert.deepEqual(fragOf(byName(OWN_FRAG.id)), { packets: '1-3', length: '5-9', interval: '20-30' }, 'its own fragment stands');
  assert.equal(dial(byName(MASKED.id)), '', 'a final mask dials as it did');
  assert.deepEqual(byName(MASKED.id).streamSettings.finalmask, MASKED.outbound.streamSettings.finalmask);
  const hop = c.outbounds.find((o) => o.protocol === 'wireguard');
  assert.ok(hop, 'the WireGuard is there');
  assert.equal(hop.settings.fragment, undefined);
  assert.equal(new Set(c.outbounds.filter((o) => /^dpi-/.test(o.tag)).map((o) => JSON.stringify(o.settings.fragment))).size, 2, 'a dialer per way of cutting');
});

test('a chain cuts its first hop; the next hop rides on the one before it, as it did', () => {
  const c = buildConfig({ mode: 'chain', chain: [PINNED, REALITY], name: 'c' }, Object.assign({}, SETTINGS, { cutHello: true }));
  const hops = c.outbounds.filter((o) => o.protocol === 'vless');
  assert.equal(hops.length, 2);
  const first = hops.find((o) => /^dpi-/.test(o.streamSettings.sockopt && o.streamSettings.sockopt.dialerProxy || ''));
  const next = hops.find((o) => o !== first);
  assert.ok(first, 'the first hop has the dialer');
  assert.equal(next.streamSettings.sockopt.dialerProxy, first.tag);
});

test('a test measures what the live core would do', () => {
  const cut = buildTestConfig(PINNED, 9, { cutHello: true });
  assert.ok(cut.outbounds.some((o) => o.settings && o.settings.fragment && o.settings.fragment.interval === '0-0'));
  const whole = buildTestConfig(PINNED, 9);
  assert.equal(whole.outbounds.some((o) => o.settings && o.settings.fragment), false);
  const many = buildMultiTestConfig([PINNED, REALITY], [9, 10], { cutHello: true });
  assert.equal(many.outbounds.filter((o) => o.protocol === 'vless').every((o) => /^dpi-/.test(o.streamSettings.sockopt.dialerProxy)), true);
  assert.equal(buildMultiTestConfig([PINNED], [9]).outbounds.some((o) => o.settings && o.settings.fragment), false);
  const t = latencyTest(PINNED, 9, { cutHello: true });
  assert.ok(t.config.outbounds.some((o) => o.settings && o.settings.fragment));
  assert.equal(latencyTest(PINNED, 9, {}).config.outbounds.some((o) => o.settings && o.settings.fragment), false);
});

test('a certificate names a site by its exact name or one wildcard label', () => {
  const c = { subjectaltname: 'DNS:*.google.com, DNS:google.com, IP Address:1.1.1.1' };
  assert.equal(certNames(c, 'www.google.com'), true);
  assert.equal(certNames(c, 'google.com'), true);
  assert.equal(certNames(c, 'WWW.GOOGLE.COM'), true);
  assert.equal(certNames(c, 'a.b.google.com'), false);
  assert.equal(certNames(c, 'www.googleXcom'), false);
  assert.equal(certNames({ subjectaltname: 'DNS:cloudflare-dns.com, DNS:one.one.one.one' }, 'www.google.com'), false);
  assert.equal(certNames({}, 'www.google.com'), false);
  assert.equal(certNames(null, 'www.google.com'), false);
});

/** connect() for the check: each sample answers as told, once it is asked. */
function fakeConnect(answers, seen = []) {
  return ({ host, servername, rejectUnauthorized }) => {
    seen.push({ host, servername, rejectUnauthorized });
    const a = answers[host];
    const s = new EventEmitter();
    s.destroyed = false;
    s.destroy = () => { s.destroyed = true; };
    s.getPeerCertificate = () => a.cert;
    seen[seen.length - 1].sock = s;
    if (a.fail) setImmediate(() => s.emit('error', new Error('reset')));
    else if (!a.hang) setImmediate(() => s.emit('secureConnect'));
    return s;
  };
}
const AS_GOOGLE = { cert: { subjectaltname: 'DNS:*.google.com' } };
const AS_CLOUDFLARE = { cert: { subjectaltname: 'DNS:*.cloudflare.com' } };
const AS_ITSELF = { cert: { subjectaltname: 'DNS:one.one.one.one' } };

test('the check: a certificate naming the site asked for proves it, one of its own proves the opposite', async () => {
  const seen = [];
  assert.equal(await pathReadsHello({ connect: fakeConnect({ '1.1.1.1': AS_GOOGLE, '8.8.8.8': { hang: true } }, seen), timeoutMs: 100 }), true);
  assert.deepEqual(seen.map((s) => [s.host, s.servername, s.rejectUnauthorized]), [['1.1.1.1', 'www.google.com', false], ['8.8.8.8', 'www.cloudflare.com', false]]);
  assert.equal(seen[1].sock.destroyed, true, 'the other one is not left open');
  assert.equal(await pathReadsHello({ connect: fakeConnect({ '1.1.1.1': AS_ITSELF, '8.8.8.8': AS_ITSELF }), timeoutMs: 100 }), false);
  assert.equal(await pathReadsHello({ connect: fakeConnect({ '1.1.1.1': AS_ITSELF, '8.8.8.8': AS_CLOUDFLARE }), timeoutMs: 100 }), true, 'one that reads is enough');
});

test('the check: when nothing answers nothing is known, and it never waits past its limit', async () => {
  assert.equal(await pathReadsHello({ connect: fakeConnect({ '1.1.1.1': { fail: true }, '8.8.8.8': { fail: true } }), timeoutMs: 100 }), null);
  const t0 = Date.now();
  assert.equal(await pathReadsHello({ connect: fakeConnect({ '1.1.1.1': { hang: true }, '8.8.8.8': { hang: true } }), timeoutMs: 40 }), null);
  assert.ok(Date.now() - t0 < 1000);
  assert.equal(await pathReadsHello({ connect: fakeConnect({ '1.1.1.1': AS_ITSELF, '8.8.8.8': { hang: true } }), timeoutMs: 40 }), false, 'an address that answered as itself is an answer');
  assert.equal(await pathReadsHello({ connect: () => { throw new Error('blocked'); }, timeoutMs: 40 }), null);
  assert.equal(await pathReadsHello({ samples: [] }), null);
});

/** The cut dialers in what the fake core was last started with. */
const dialersOf = (s) => {
  const last = s.state.xray.starts[s.state.xray.starts.length - 1];
  return ((last && last.config && last.config.outbounds) || []).filter((o) => /^dpi-/.test(o.tag));
};

test('the router\'s service: the check decides what the core runs, and a null keeps the last answer', async (t) => {
  let answer = true;
  const asked = [];
  const SERVER = Object.assign(parseLink(link('type=tcp&security=tls&sni=cover.test&pcs=' + 'a'.repeat(64), 'p')), { id: 'pppppppppppppppp' });
  const s = H.start({ settings: {}, servers: [SERVER] }, { pathReadsHello: async () => { asked.push(1); return answer; } });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.equal(asked.length, 1);
  assert.equal(dialersOf(s).length, 1, 'the path reads: cut');
  await s.service.invoke('disconnect');
  answer = null;
  await s.service.invoke('connect', SERVER.id);
  assert.equal(dialersOf(s).length, 1, 'nothing answered: the last answer stands');
  await s.service.invoke('disconnect');
  answer = false;
  await s.service.invoke('connect', SERVER.id);
  assert.equal(dialersOf(s).length, 0, 'it no longer reads: whole again');
});

test('the router\'s service: a route that dies under a live connection is cut once, by a reload', async (t) => {
  let up = false;
  const SERVER = Object.assign(parseLink(link('type=tcp&security=tls&sni=cover.test&pcs=' + 'a'.repeat(64), 'p')), { id: 'pppppppppppppppp' });
  const s = H.start({ settings: {}, servers: [SERVER] }, {
    pathReadsHello: async () => false,
    probeTunnel: async () => up,
    timing: { routeWatchFirstMs: 1, routeWatchEveryMs: 5, routeWatchRecheckMs: 2 }
  });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  await H.until(() => dialersOf(s).length === 1, 'the reload with a cut hello');
  up = true;
  const notices = () => s.events.filter(([ch]) => ch === 'route-health').map(([, p]) => p.notice);
  await H.until(() => notices().length === 2 && notices()[1] === null, 'the warning taken back');
});
