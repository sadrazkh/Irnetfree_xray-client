'use strict';
/**
 * coreCompat: one config, written for the core that runs it.
 *
 * The version boundaries are where the shape changed in XTLS/Xray-core's own
 * sources (and the patterniha fork's, whose numbers follow upstream's); every
 * form below was run through `xray run -test` on 26.3.27, 26.5.9, 26.6.1,
 * 26.7.11, 26.9.9, 26.9.30 and the fork's 26.9.9, 26.9.13 and 26.10.3.
 * android/.../core/CoreCompat.kt is the same table and MUST agree.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { adaptForCore, needsCoreVersion } = require('../src/main/coreCompat');

const cfg = (streamSettings, extra) => ({
  log: { loglevel: 'warning' },
  outbounds: [Object.assign({ tag: 'proxy', protocol: 'vless', settings: {}, streamSettings }, extra), { tag: 'direct', protocol: 'freedom' }]
});
const ss = (c) => c.outbounds[0].streamSettings;
const KCP = { network: 'kcp', security: 'none', kcpSettings: { header: { type: 'srtp' }, seed: 'SEED', mtu: 1350 } };

test('nothing to adapt: the very same object comes back, and no version is needed', () => {
  const c = cfg({ network: 'ws', security: 'tls', wsSettings: { path: '/' } });
  assert.equal(needsCoreVersion(c), false);
  assert.equal(adaptForCore(c, '26.3.27'), c);
  assert.equal(needsCoreVersion(cfg(KCP)), true);
  assert.equal(needsCoreVersion(cfg({ network: 'hysteria' })), true);
});

test('mKCP up to 26.1.23: the link\'s header and seed stay in kcpSettings', () => {
  const c = cfg(KCP);
  assert.equal(adaptForCore(c, '26.1.23'), c);
});

test('mKCP 26.1.31 – 26.5.x: header-* and mkcp-aes128gcm / mkcp-original masks, the keys removed', () => {
  const out = adaptForCore(cfg(KCP), '26.3.27');
  assert.deepEqual(ss(out), {
    network: 'kcp', security: 'none', kcpSettings: { mtu: 1350 },
    finalmask: { udp: [{ type: 'mkcp-aes128gcm', settings: { password: 'SEED' } }, { type: 'header-srtp' }] }
  });
  const plain = adaptForCore(cfg({ network: 'kcp', kcpSettings: { header: { type: 'none' }, seed: '' } }), '26.5.9');
  assert.deepEqual(ss(plain).finalmask, { udp: [{ type: 'mkcp-original' }] });
  const wechat = adaptForCore(cfg({ network: 'kcp', kcpSettings: { header: { type: 'wechat-video' }, seed: '' } }), '26.5.9');
  assert.deepEqual(ss(wechat).finalmask.udp, [{ type: 'mkcp-original' }, { type: 'header-wechat' }]);
});

test('mKCP from 26.6.1: one mkcp-legacy mask each, encryption first, header last', () => {
  for (const v of ['26.6.1', '26.9.30', '26.10.3', '']) {
    const out = adaptForCore(cfg(KCP), v);
    assert.deepEqual(ss(out).kcpSettings, { mtu: 1350 }, v);
    assert.deepEqual(ss(out).finalmask.udp, [
      { type: 'mkcp-legacy', settings: { value: 'SEED' } },
      { type: 'mkcp-legacy', settings: { header: 'srtp' } }
    ], v);
  }
  const plain = adaptForCore(cfg({ network: 'kcp', kcpSettings: { header: { type: 'none' }, seed: '' } }), '26.9.30');
  assert.deepEqual(ss(plain).finalmask, { udp: [{ type: 'mkcp-legacy' }] });
});

test('mKCP masks a link brought (fm) win over its header/seed and are translated both ways', () => {
  const linkMasks = { network: 'kcp', kcpSettings: { header: { type: 'none' }, seed: '' }, finalmask: { udp: [{ type: 'mkcp-legacy', settings: { value: 'P' } }, { type: 'mkcp-legacy', settings: { header: 'dtls' } }, { type: 'noise', settings: { x: 1 } }] } };
  assert.deepEqual(ss(adaptForCore(cfg(linkMasks), '26.3.27')).finalmask.udp, [
    { type: 'mkcp-aes128gcm', settings: { password: 'P' } }, { type: 'header-dtls' }, { type: 'noise', settings: { x: 1 } }
  ]);
  const old = { network: 'kcp', kcpSettings: {}, finalmask: { udp: [{ type: 'mkcp-original' }, { type: 'header-dns', settings: { domain: 'd.example' } }] } };
  assert.deepEqual(ss(adaptForCore(cfg(old), '26.9.30')).finalmask.udp, [
    { type: 'mkcp-legacy' }, { type: 'mkcp-legacy', settings: { header: 'dns', value: 'd.example' } }
  ]);
  // and an old core gets them back as kcpSettings
  const back = ss(adaptForCore(cfg(old), '26.1.23'));
  assert.deepEqual(back.kcpSettings, { header: { type: 'dns', domain: 'd.example' } });
  assert.equal(back.finalmask, undefined);
});

const HY = (fm) => ({
  network: 'hysteria', security: 'tls', tlsSettings: { serverName: 'h.example' },
  hysteriaSettings: { version: 2, auth: 'pw' }, finalmask: fm
});
const HOP = { type: 'udphop', settings: { mode: 'intervalLocal,intervalRemote', interval: '30', remotePorts: '20000-30000' } };
const SAL = { type: 'salamander', settings: { password: 'OB' } };

test('hysteria from 26.9.9: the udphop mask as stored; an old quicParams.udpHop is moved into one', () => {
  const c = cfg(HY({ udp: [SAL, HOP] }), { protocol: 'hysteria' });
  assert.equal(adaptForCore(c, '26.9.9'), c);
  assert.equal(adaptForCore(c, '26.10.3'), c);
  const old = cfg(HY({ udp: [SAL], quicParams: { brutalUp: '50 mbps', udpHop: { ports: '1000-2000', interval: '20' } } }));
  assert.deepEqual(ss(adaptForCore(old, '26.9.30')).finalmask, {
    udp: [SAL, { type: 'udphop', settings: { mode: 'intervalLocal,intervalRemote', interval: '20', remotePorts: '1000-2000' } }],
    quicParams: { brutalUp: '50 mbps' }
  });
});

test('hysteria 26.3.23 – 26.9.8: the hopping goes to quicParams.udpHop', () => {
  for (const v of ['26.3.27', '26.7.11', '26.9.8']) {
    const out = ss(adaptForCore(cfg(HY({ udp: [SAL, HOP], quicParams: { brutalDown: '100 mbps' } })), v));
    assert.deepEqual(out.finalmask, { udp: [SAL], quicParams: { brutalDown: '100 mbps', udpHop: { ports: '20000-30000', interval: '30' } } }, v);
  }
  const only = ss(adaptForCore(cfg(HY({ udp: [HOP] })), '26.7.11'));
  assert.deepEqual(only.finalmask, { quicParams: { udpHop: { ports: '20000-30000', interval: '30' } } });
});

test('hysteria before 26.3.23: hopping and bandwidth are hysteriaSettings\'', () => {
  const out = ss(adaptForCore(cfg(HY({ udp: [SAL, HOP], quicParams: { brutalUp: '10 mbps', brutalDown: '20 mbps' } })), '26.2.6'));
  assert.deepEqual(out.hysteriaSettings, { version: 2, auth: 'pw', udphop: { ports: '20000-30000', interval: '30' }, up: '10 mbps', down: '20 mbps' });
  assert.deepEqual(out.finalmask, { udp: [SAL] });
});

test('adaptForCore never changes its input', () => {
  const c = cfg(KCP);
  const before = JSON.stringify(c);
  adaptForCore(c, '26.9.30');
  adaptForCore(c, '26.3.27');
  assert.equal(JSON.stringify(c), before);
});
