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

test('everything else still runs', { skip: !guarded }, () => {
  assert.equal(cp.execFileSync(process.execPath, ['-e', 'process.stdout.write("ok")'], { encoding: 'utf8' }), 'ok');
});
