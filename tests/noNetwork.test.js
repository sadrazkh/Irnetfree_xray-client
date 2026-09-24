'use strict';
/**
 * The suite runs with tests/noNetwork.preload.js loaded (package.json → npm
 * test): no test may run a command that changes the network, the proxy, the
 * firewall or the processes of the machine running it. This proves the guard
 * is in place — and checks that FIRST, so run without it this file fails
 * before it calls anything.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const cp = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const guarded = ['execFile', 'execFileSync', 'spawn', 'spawnSync', 'exec', 'execSync'].every((fn) => cp[fn].irnfGuard === true);

test('npm test loads the no-network guard ahead of every test file', () => {
  assert.equal(guarded, true, 'run the suite through `npm test` (node --require ./tests/noNetwork.preload.js --test …)');
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.match(pkg.scripts.test, /--require \.\/tests\/noNetwork\.preload\.js --test "tests\/\*\.test\.js"/);
});

test('the guard refuses network commands on every entry point, whatever the path or extension', { skip: !guarded }, async () => {
  // read-only arguments, belt and braces — the guard refuses before anything runs
  assert.throws(() => cp.execFileSync('reg', ['query', 'HKCU\\Software\\IRNetFree-guard-test']), /EIRNF_GUARD|tried to run the real "reg"/);
  assert.throws(() => cp.execFileSync('C:\\Windows\\System32\\NETSH.EXE', ['show', 'helper']), /"netsh"/);
  assert.throws(() => cp.spawnSync('/usr/sbin/networksetup', ['-listallnetworkservices']), /"networksetup"/);
  assert.throws(() => cp.execSync('route print'), /"route"/);
  const err = await new Promise((resolve) => cp.execFile('powershell', ['-NoProfile', '-Command', '$PSVersionTable'], (e) => resolve(e)));
  assert.equal(err && err.code, 'EIRNF_GUARD');
  const child = cp.spawn('taskkill', ['/pid', '1']);
  const spawned = await new Promise((resolve) => child.on('error', resolve));
  assert.equal(spawned.code, 'EIRNF_GUARD');
});

test('command names are read the same on every OS, Windows paths included', () => {
  // CI caught it: on Linux path.basename leaves 'C:\\…\\NETSH.EXE' whole
  const { commandName } = require('./noNetwork.preload.js');
  assert.equal(commandName('C:\\Windows\\System32\\NETSH.EXE'), 'netsh');
  assert.equal(commandName('/usr/sbin/networksetup'), 'networksetup');
  assert.equal(commandName('reg.exe'), 'reg');
  assert.equal(commandName('route print'), 'route');
  assert.equal(commandName('/opt/homebrew/bin/node'), 'node', 'not on the list, so it runs');
});

test('a shell running one of OUR privileged script files is refused; a syntax check or a repo script is not', () => {
  const os = require('node:os');
  const { blocked } = require('./noNetwork.preload.js');
  const tmp = os.tmpdir();
  // leakGuard._privileged, the TUN backends' setup/teardown scripts
  assert.equal(blocked('/bin/bash', [path.join(tmp, 'irnf-lg-abc', 'restore.sh')]), true);
  assert.equal(blocked('bash', [path.join('/Users/a/Library/Application Support/IRNetFree', 'mac-tun-sessions', 'irnf-sb-1', 'teardown.sh')]), true);
  assert.equal(blocked('sh', [path.join(tmp, 'x', 'setup.sh')]), true);
  assert.equal(blocked('bash', ['-n', path.join(tmp, 'irnf-lg-abc', 'restore.sh')]), false, 'bash -n executes nothing');
  assert.equal(blocked('bash', ['--noprofile', '--norc', '-eo', 'pipefail', path.join(__dirname, '..', 'scripts', 'x.sh')]), false, 'a repo script');
  assert.equal(blocked('node', [path.join(tmp, 'a.sh')]), false);
});

test('the failed child a refused spawn returns can be unref’d and ref’d like a real one', { skip: !guarded }, () => {
  const child = cp.spawn('reg', ['query', 'HKCU\\Software\\IRNetFree-guard-test']);
  child.on('error', () => {});
  assert.equal(typeof child.unref, 'function');
  assert.equal(typeof child.ref, 'function');
  assert.doesNotThrow(() => { child.unref(); child.ref(); });
});

test('everything else still runs', { skip: !guarded }, () => {
  assert.equal(cp.execFileSync(process.execPath, ['-e', 'process.stdout.write("ok")'], { encoding: 'utf8' }), 'ok');
});
