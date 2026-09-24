'use strict';
/**
 * Values read back from a user-writable file never reach a root script as
 * anything but an IP literal (audit 2026-09-24, M7 — the part in these files).
 *
 * The leak guard's state file (userData/tun-state.json) and the tunnel
 * journals (userData/mac-*-tun-sessions/…/session.json) are owned by the user,
 * and what they hold is written into shell scripts that run as root. The guard's
 * tunnel peers went in raw: `macApplyScript([{ name: 'Wi-Fi' }], '1.1.1.1; id >
 * /tmp/pwn')` was a root command, and the 30 s DNS refresh reads the peers back
 * from that file. Now: a peer must be an IP literal or the whole apply is
 * refused, and it is quoted anyway; a recorded resolver, bypass address or
 * gateway that is not an IP literal is dropped. Nothing here runs a script.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { LeakGuard, macApplyScript, macRestoreScript, macReleaseScript, STATE_FILE } = require('../src/main/leakGuard');
const { buildMacSetupScript, buildMacTeardownScript } = require('../src/main/tunSingbox');
const { TunManager } = require('../src/main/tunManager');

const PEER4 = '172.19.0.2', PEER6 = 'fdfe:dcba:9876::2';
const EVIL = '1.1.1.1; id > /tmp/pwn';

test('macApplyScript: a peer that is not an IP literal refuses the whole apply', () => {
  assert.throws(() => macApplyScript([{ name: 'Wi-Fi' }], EVIL), /not an IP address/);
  assert.throws(() => macApplyScript([{ name: 'Wi-Fi' }], PEER4, '$(id)'), /not an IP address/);
  assert.throws(() => macApplyScript([{ name: 'Wi-Fi' }], 'dns.google'), /not an IP address/);
  assert.throws(() => macApplyScript([{ name: 'Wi-Fi' }], null, null), /no tunnel resolver/);
});

test('macApplyScript: the peers are quoted like every other value in a root script', () => {
  const s = macApplyScript([{ name: 'Wi-Fi' }, { name: "Owner's LAN" }], PEER4, PEER6);
  assert.ok(s.includes(`networksetup -setdnsservers 'Wi-Fi' '${PEER4}' '${PEER6}' || FAIL=1`));
  assert.ok(s.includes(`networksetup -setdnsservers 'Owner'\\''s LAN' '${PEER4}' '${PEER6}' || FAIL=1`));
  assert.ok(macApplyScript([{ name: 'Wi-Fi' }], PEER4, null).includes(`networksetup -setdnsservers 'Wi-Fi' '${PEER4}' || FAIL=1`));
});

test('macRestoreScript / macReleaseScript: a recorded resolver that is not an IP literal is dropped', () => {
  const services = [{ name: 'Wi-Fi', dns: ['192.168.60.1', "1.1.1.1'; touch /tmp/pwned; echo '", 'fe80::1%en0'] }, { name: 'LAN', dns: ['$(id)'] }];
  for (const s of [macRestoreScript(services), macReleaseScript(services, { firewall: true })]) {
    assert.ok(s.includes("networksetup -setdnsservers 'Wi-Fi' '192.168.60.1' 'fe80::1%en0' || FAIL=1"));
    assert.ok(s.includes("networksetup -setdnsservers 'LAN' Empty || FAIL=1"), 'nothing valid left: back to DHCP');
    assert.doesNotMatch(s, /pwned|\$\(id\)/);
  }
});

/** The guard against a fake Mac: every script it would run as root is recorded, none runs. */
function harness() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-inputs-'));
  const privileged = [];
  const guard = new LeakGuard({
    userData: dir, platform: 'darwin',
    run: async () => 'Wi-Fi\t192.168.60.1\n',
    runScriptPrivileged: async (p) => { privileged.push(fs.readFileSync(p, 'utf8')); return ''; },
    runSync: () => ''
  });
  return { guard, dir, privileged, statePath: path.join(dir, STATE_FILE) };
}

test('engage refuses a bad peer before the state file or any root script', async (t) => {
  const h = harness();
  t.after(() => fs.rmSync(h.dir, { recursive: true, force: true }));
  await assert.rejects(h.guard.engage({ level: 'standard', peer4: EVIL }), /not an IP address/);
  assert.equal(h.privileged.length, 0);
  assert.equal(fs.existsSync(h.statePath), false);
});

test('the DNS refresh refuses a tampered peer read back from the state file', async (t) => {
  const h = harness();
  t.after(() => fs.rmSync(h.dir, { recursive: true, force: true }));
  const { token } = await h.guard.engage({ level: 'standard', peer4: PEER4, peer6: PEER6 });
  assert.equal(h.privileged.length, 1);
  const st = JSON.parse(fs.readFileSync(h.statePath, 'utf8'));
  st.peer4 = EVIL;
  fs.writeFileSync(h.statePath, JSON.stringify(st));
  await assert.rejects(h.guard.refresh({ token }), /not an IP address/);
  assert.equal(h.privileged.length, 1, 'no root script ran');
});

test('sing-box scripts: the setup refuses a resolver that is not an IP; the teardown drops a tampered saved one', () => {
  const W = '/tmp/w';
  const args = { bin: W + '/sing-box', cfgFile: W + '/c.json', logFile: W + '/l', pidFile: W + '/p', devFile: W + '/d', service: 'Wi-Fi' };
  assert.throws(() => buildMacSetupScript({ ...args, dnsServers: [PEER4, EVIL] }), /not an IP address/);
  assert.ok(buildMacSetupScript({ ...args, dnsServers: [PEER4, PEER6] }).includes(`networksetup -setdnsservers 'Wi-Fi' '${PEER4}' '${PEER6}' || exit 14`));
  const down = buildMacTeardownScript({ ...args, pid: 42, savedDns: ['9.9.9.9', "8.8.8.8'; id; '"] });
  assert.ok(down.includes("networksetup -setdnsservers 'Wi-Fi' '9.9.9.9' || exit 25"));
  assert.doesNotMatch(down, /; id;/);
  assert.ok(buildMacTeardownScript({ ...args, pid: 42, savedDns: ['$(id)'] }).includes("networksetup -setdnsservers 'Wi-Fi' 'Empty' || exit 25"));
});

test('tun2socks teardown: a tampered bypass address, gateway or saved resolver never reaches the root script', () => {
  const m = new TunManager({});
  const work = '/tmp/w';
  m.macState = {
    work, pidFile: work + '/p', identityFile: work + '/i', dnsFile: work + '/d', routesFile: work + '/r',
    expectedCommand: '/bin/tun2socks', service: 'Wi-Fi', savedDns: ['9.9.9.9', '$(id)'],
    gateway: '192.168.1.1', bypassIps: ['203.0.113.7', '1.2.3.4; id']
  };
  const s = m.macTeardownScript();
  assert.ok(s.includes("route -n delete -host '203.0.113.7' '192.168.1.1'"));
  assert.doesNotMatch(s, /1\.2\.3\.4; id|\$\(id\)/);
  assert.ok(s.includes("networksetup -setdnsservers 'Wi-Fi' '9.9.9.9' || exit 25"));
  m.macState.gateway = '192.168.1.1; id';
  assert.doesNotMatch(m.macTeardownScript(), /route -n delete|; id/, 'no route line without a real gateway');
  m.macState.savedDns = ['$(id)'];
  assert.ok(m.macTeardownScript().includes("networksetup -setdnsservers 'Wi-Fi' Empty || exit 25"));
});
