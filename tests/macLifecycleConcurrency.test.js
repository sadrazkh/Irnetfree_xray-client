'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { TunSingbox, buildMacSetupScript, buildMacTeardownScript } = require('../src/main/tunSingbox');

test('mac disconnect waits for pending setup before deleting state', async () => {
  const tun = new TunSingbox({ platform: 'darwin' });
  let release, stopped = 0;
  tun.startMac = async () => { await new Promise(r => { release = r; }); tun.active = true; };
  tun.stopMac = async () => { stopped++; tun.active = false; };
  const start = tun.start(10808, [], []);
  const stop = tun.stop();
  await Promise.resolve();
  assert.equal(stopped, 0);
  release();
  await Promise.all([start, stop]);
  assert.equal(stopped, 1);
  assert.equal(tun.active, false);
});

test('overlapping mac starts share one setup and block a second instance', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-concurrency-'));
  const tun = new TunSingbox({ platform: 'darwin', userData: dir });
  const other = new TunSingbox({ platform: 'darwin', userData: dir });
  let release, count = 0;
  tun.startMac = async () => { count++; await new Promise(r => { release = r; }); };
  try {
    const a = tun.start(1, [], []), b = tun.start(1, [], []);
    await assert.rejects(other.start(1, [], []), /Another tunnel operation/);
    await assert.rejects(other.recoverMacSessions(), /Another tunnel operation/);
    release(); await Promise.all([a, b]);
    assert.equal(count, 1);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('recovery rejects a journal redirect before privileged execution', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-invalid-journal-'));
  const tun = new TunSingbox({ platform: 'darwin', userData: dir });
  const {work, cfgFile} = tun.writeConfig(10808, [], {}, null);
  fs.writeFileSync(path.join(work, 'session.json'), JSON.stringify({work, cfgFile, bin:'/bin/sing-box', savedDns:[], logFile:path.join(dir,'outside')}));
  try { await assert.rejects(tun.recoverMacSessions(), /Invalid tunnel recovery path/); assert.ok(fs.existsSync(work)); }
  finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('generated mac scripts parse as Bash with spaces, quotes and IPv6', () => {
  const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : '/bin/bash';
  if (!fs.existsSync(bash)) return;
  const opts = {bin:"/Applications/Client's App/sing-box", cfgFile:'/tmp/long path/config', pidFile:'/tmp/long path/pid', logFile:'/tmp/log', devFile:'/tmp/dev', service:"Owner's Wi-Fi", savedDns:['::1'], dnsServers:['172.19.0.2','fdfe:dcba:9876::2']};
  for (const script of [buildMacSetupScript(opts), buildMacTeardownScript(opts)]) {
    const result = spawnSync(bash, ['-n'], { input: script, encoding:'utf8', windowsHide:true });
    assert.equal(result.status, 0, result.stderr || String(result.error));
  }
});
