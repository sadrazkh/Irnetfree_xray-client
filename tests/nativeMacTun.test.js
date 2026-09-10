'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { NativeMacTun, runNative } = require('../src/main/nativeMacTun');

function fixture(overrides = {}) {
  const calls = [];
  const tun = new NativeMacTun({
    platform: 'darwin', nativePath: '/Application/Contents/MacOS/IRNetFreeNative', exists: () => true,
    osRelease: '23.5.0',
    resolveServerIps: async () => ['203.0.113.1', '2001:db8::1'],
    physicalInterface: async () => 'en0',
    run: async (command, payload) => {
      calls.push({ command, payload });
      if (command === 'status') return { ok: true, status: 'enabled', active: false };
      if (command === 'stop') return { ok: true, active: false };
      return { ok: true, active: true, device: 'utun12', sessionId: 'session-1' };
    }, ...overrides
  });
  return { tun, calls };
}
const connect = tun => tun.start(10808, ['proxy.example'], ['172.19.0.2'], { ipv6: true });

test('native bridge confined to macOS and packaged binary', () => {
  assert.equal(fixture().tun.isAvailable(), true);
  assert.equal(fixture({ platform: 'win32' }).tun.isAvailable(), false);
  assert.equal(fixture({ exists: () => false }).tun.isAvailable(), false);
});

/**
 * SMAppService is macOS 13. The app itself runs on 10.15+ and the compatibility
 * backend with it, so the version is a property of THIS backend, not of the
 * build — a Big Sur user must still get the sing-box TUN, and must not be told
 * to enable a service the OS cannot register.
 */
test('the native backend needs macOS 13 (Darwin 22); older Macs keep the compatibility backend', () => {
  assert.equal(fixture({ osRelease: '21.6.0' }).tun.isAvailable(), false, 'macOS 12');
  assert.equal(fixture({ osRelease: '19.6.0' }).tun.isAvailable(), false, 'macOS 10.15');
  assert.equal(fixture({ osRelease: '22.1.0' }).tun.isAvailable(), true, 'macOS 13');
  assert.equal(fixture({ osRelease: '24.0.0' }).tun.isAvailable(), true, 'macOS 15');
  // an unreadable release is not a licence to try: below the bar, like any other
  for (const junk of ['unknown', 'darwin', '0']) {
    assert.equal(fixture({ osRelease: junk }).tun.isAvailable(), false, junk);
  }
});

test('native start sends constrained network request, owns DNS and heartbeats session', async () => {
  const { tun, calls } = fixture();
  await connect(tun);
  assert.equal(await tun.physicalInterface(), 'en0');
  assert.equal(tun.managesDns, true);
  assert.equal(tun.interfaceName, 'utun12');
  assert.deepEqual(calls[1], { command: 'start', payload: {
    socksPort: 10808, excludeIps: ['203.0.113.1', '2001:db8::1'], dnsServers: ['172.19.0.2'], strict: false, ipv6: true
  } });
  await tun.checkHealth();
  assert.deepEqual(calls[2], { command: 'heartbeat', payload: { sessionId: 'session-1' } });
  await tun.stop();
  assert.equal(tun.active, false);
  assert.equal(tun.hasPendingMacRecovery(), false);
});

test('strict mode rejects before native commands; DNS invalid rejects before mutation', async () => {
  const { tun, calls } = fixture();
  await assert.rejects(tun.prepare({ strict: true }), /compatibility backend/);
  await assert.rejects(tun.start(1080, [], ['bad;dns']), /DNS server/);
  assert.equal(calls.length, 0);
});

/**
 * Registering the daemon installs a root LaunchDaemon. That is a decision the
 * user makes in Settings, never a side effect of pressing Connect — so an
 * unregistered service is a refusal that names the switch, and the bridge is
 * asked for its status and nothing else.
 */
test('connect never registers the service; it points at the Settings switch', async () => {
  const calls = [];
  const { tun } = fixture({ run: async command => {
    calls.push(command);
    return { ok: true, status: command === 'status' ? 'notRegistered' : 'requiresApproval' };
  } });
  await assert.rejects(connect(tun), /Enable the macOS tunnel service first/);
  assert.deepEqual(calls, ['status']);
  assert.equal(tun.active, false);
});

test('a registered service still awaits background approval and never starts fallback', async () => {
  const calls = [];
  const { tun } = fixture({ run: async command => {
    calls.push(command);
    return { ok: true, status: 'requiresApproval' };
  } });
  await assert.rejects(connect(tun), /System Settings/);
  assert.deepEqual(calls, ['status']);
  assert.equal(tun.active, false);
});

test('stop failure preserves session for retry', async () => {
  const { tun } = fixture();
  await connect(tun);
  const run = tun.run;
  tun.run = async () => ({ ok: false, active: true, error: 'private secret' });
  await assert.rejects(tun.stop(), /retained/);
  assert.equal(tun.active, true);
  assert.equal(tun.sessionId, 'session-1');
  assert.equal(tun.hasPendingMacRecovery(), true);
  tun.run = run;
  await tun.stop();
});

test('stop queued during start waits and cleans up exact session', async () => {
  const { tun, calls } = fixture();
  await Promise.all([connect(tun), tun.stop()]);
  assert.deepEqual(calls.map(c => c.command), ['status', 'start', 'stop']);
  assert.equal(calls[2].payload.sessionId, 'session-1');
  assert.equal(tun.active, false);
});

test('duplicate connect starts one session and later reconnect creates a fresh one', async () => {
  const { tun, calls } = fixture();
  await Promise.all([connect(tun), connect(tun)]);
  assert.equal(calls.filter(c => c.command === 'start').length, 1);
  await tun.stop();
  await connect(tun);
  assert.equal(calls.filter(c => c.command === 'start').length, 2);
  await tun.stop();
});

test('recovery stops an existing helper session after app restart', async () => {
  const calls = [];
  const { tun } = fixture({ run: async (command, request) => {
    calls.push({ command, request });
    return command === 'status' ? { ok: true, status: 'enabled', active: true } : { ok: true, active: false };
  } });
  await tun.recoverMacSessions();
  assert.deepEqual(calls, [{ command: 'status', request: {} }, { command: 'stop', request: {} }]);
  assert.equal(tun.hasPendingMacRecovery(), false);
});

test('invalid readiness response cannot mark connected and remains recoverable', async () => {
  const { tun } = fixture();
  const run = tun.run;
  tun.run = async (command, request) => command === 'start' ? { ok: true, active: true, device: 'en0', sessionId: 'session-1' } : run(command, request);
  await assert.rejects(connect(tun), /did not become ready/);
  assert.equal(tun.active, false);
  assert.equal(tun.hasPendingMacRecovery(), true);
  await tun.stop();
});

test('start failure retains uncertain session and recovery issues stop', async () => {
  const { tun } = fixture();
  const run = tun.run;
  tun.run = async (cmd, args) => cmd === 'start' ? Promise.reject(new Error('timeout')) : run(cmd, args);
  await assert.rejects(connect(tun), /timeout/);
  assert.equal(tun.hasPendingMacRecovery(), true);
  await tun.recoverMacSessions();
  assert.equal(tun.hasPendingMacRecovery(), false);
});

test('health failure notifies once and retains state until confirmed stop', async () => {
  let notifications = 0;
  const { tun } = fixture({ onUnexpectedExit: () => { notifications++; } });
  await connect(tun);
  const run = tun.run;
  tun.run = async (command, payload) => command === 'heartbeat' ? { ok: true, active: true, sessionId: 'stale' } : run(command, payload);
  await tun.checkHealth();
  await tun.checkHealth();
  assert.equal(notifications, 1);
  assert.equal(tun.active, true);
  await tun.stop();
});

test('sync cleanup sends only owned session and does not unregister', async () => {
  let args;
  const { tun } = fixture({ execSync: (...values) => { args = values; } });
  await connect(tun);
  tun.cleanupSync();
  assert.deepEqual(args[1], ['stop']);
  assert.deepEqual(JSON.parse(args[2].input), { sessionId: 'session-1' });
  await tun.stop();
});

function fakeProcess() {
  const proc = new EventEmitter();
  proc.stdout = new EventEmitter();
  proc.stderr = new EventEmitter();
  proc.stdin = new EventEmitter();
  proc.stdin.end = () => {};
  proc.kill = () => { proc.killed = true; };
  return proc;
}
test('CLI uses argv and stdin; malformed output never exposes raw diagnostics', async () => {
  const proc = fakeProcess();
  const request = runNative('/native', 'start', { socksPort: 1080 }, { spawnImpl: (exe, args, options) => {
    assert.equal(exe, '/native');
    assert.deepEqual(args, ['start']);
    assert.equal(options.shell, undefined);
    return proc;
  } });
  proc.stdout.emit('data', Buffer.from('secret credentials'));
  proc.emit('close', 1);
  await assert.rejects(request, error => /invalid response/.test(error.message) && !/secret/.test(error.message));
});

test('CLI timeout and oversized output terminate bridge with bounded errors', async () => {
  const proc = fakeProcess();
  await assert.rejects(runNative('/native', 'status', {}, { timeout: 5, spawnImpl: () => proc }), /timed out/);
  assert.equal(proc.killed, true);
  const other = fakeProcess();
  const request = runNative('/native', 'status', {}, { spawnImpl: () => other });
  other.stdout.emit('data', Buffer.alloc(65537));
  await assert.rejects(request, /size limit/);
  assert.equal(other.killed, true);
});

test('recovery does not register unused service and retries pending DNS cleanup', async () => {
  const absent = fixture({run: async command => { assert.equal(command, 'status'); return {ok:true,status:'notRegistered'}; }});
  await absent.tun.recoverMacSessions();
  const calls=[];
  const pending = fixture({run: async command => { calls.push(command); return command === 'status' ? {ok:true,status:'enabled',active:false,recoveryPending:true} : {ok:true,active:false}; }});
  await pending.tun.recoverMacSessions();
  assert.deepEqual(calls,['status','stop']);
});
