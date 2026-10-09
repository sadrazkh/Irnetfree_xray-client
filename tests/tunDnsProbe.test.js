'use strict';
/**
 * scripts/tun-dns-probe.js — the real-TUN DNS check CI runs (test.yml, job
 * `tun-dns`) — kept honest here without a TUN: its tiny DNS codec, the configs
 * it hands the cores, and that it refuses to run anywhere but CI (it makes a
 * network namespace and a TUN).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const P = require('../scripts/tun-dns-probe');

test('the probe’s DNS codec: a query, the fake ISP’s answer, the answer read back', () => {
  const q = P.query('intranet.tes.systems', 7);
  assert.equal(P.readName(q, 12).name, 'intranet.tes.systems');
  const { name, reply } = P.ispAnswer(q);
  assert.equal(name, 'intranet.tes.systems');
  assert.deepEqual(P.parseAnswer(reply), { rcode: 0, a: [P.ISP_ANSWER] });
  const aaaa = Buffer.from(q);
  aaaa.writeUInt16BE(28, q.length - 4);
  assert.deepEqual(P.parseAnswer(P.ispAnswer(aaaa).reply), { rcode: 0, a: [] }, 'no AAAA from the fake ISP');
});

test('the probe’s configs: the app’s own — Xray answers the WireGuard’s private names, port 53 is hijacked to its DNS; sing-box gets dns_mode by version', () => {
  const old = P.buildProbeConfigs('1.13.14');
  const now = P.buildProbeConfigs('1.14.3');
  assert.equal(old.mode, null);
  assert.equal('dns_mode' in old.sbFixed.inbounds[0], false, '1.13: the config of before');
  assert.equal(now.mode, 'disabled');
  assert.equal(now.sbFixed.inbounds[0].dns_mode, 'disabled');
  assert.equal('dns_mode' in now.sbControl.inbounds[0], false, 'the control is v1.21.0’s config');
  assert.equal(now.sbForced.inbounds[0].dns_mode, 'disabled');
  for (const c of [old, now]) {
    assert.equal(c.sbFixed.outbounds[0].server_port, c.xray.inbounds.find((i) => i.protocol === 'socks').port, 'sing-box hands everything to Xray’s SOCKS');
    assert.equal(c.xray.inbounds.find((i) => i.protocol === 'socks').settings.udp, true);
    assert.ok(c.xray.routing.rules.some((r) => r.port === '53' && r.outboundTag === 'dns-out'), 'port 53 → Xray’s DNS');
    assert.ok(c.xray.routing.rules.some((r) => (r.ip || []).includes('192.168.60.1')), 'the corporate WireGuard’s private resolver');
    for (const [n, ip] of Object.entries(P.NAMES)) assert.equal(c.xray.dns.hosts[n], ip);
    assert.equal('metrics' in c.xray, false);
  }
  // the TUN's peer — the adapter's resolver the app sets — is the address it asks
  assert.equal(P.PEER, require('../src/main/tunSingbox').TUN_PEER4);
});

test('the probe runs only in CI: without Linux, root and IRNF_TUN_PROBE=1 it refuses before touching anything', () => {
  const r = spawnSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'tun-dns-probe.js')], {
    encoding: 'utf8', env: Object.assign({}, process.env, { IRNF_TUN_PROBE: '' }), timeout: 15000
  });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /CI only/);
});
