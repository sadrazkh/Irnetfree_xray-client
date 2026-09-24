'use strict';
/**
 * Loaded ahead of every test file (`npm test` → node --require …): no test may
 * change the network, the proxy, the firewall or the processes of the machine
 * running it. The owner runs the suite on the laptop their live VPN runs on,
 * and twice a test reached the real thing — a service shutdown that ran
 * `reg add … ProxyEnable 0`, and a proxy test whose fakes the code under test
 * ignored, which rewrote the machine's ProxyServer.
 *
 * Every child_process entry point refuses the commands below: a sync call
 * throws, an async one answers with an error (and a spawn with a child that
 * fails) — never a run. A test that fakes child_process itself replaces these
 * wrappers, and whatever it lets fall through lands back here.
 */
const cp = require('child_process');
const { EventEmitter } = require('events');

const BLOCKED = new Set([
  'reg', 'netsh', 'route', 'powershell', 'pwsh', 'ipconfig', 'taskkill', 'schtasks', 'sc',
  'networksetup', 'scutil', 'pfctl', 'osascript', 'launchctl', 'dscacheutil', 'killall',
  'gsettings', 'ip', 'nft', 'iptables', 'resolvectl', 'nmcli', 'sysctl', 'uci', 'sudo'
]);

/**
 * 'C:\\Windows\\System32\\reg.exe' → 'reg'; '/usr/sbin/networksetup' → 'networksetup'.
 * Both separators on every OS: path.basename on Linux leaves a Windows path whole.
 */
function commandName(cmd) {
  const first = String(cmd == null ? '' : cmd).trim().split(/\s+/)[0] || '';
  return first.split(/[\\/]/).pop().replace(/\.(exe|cmd|bat)$/i, '').toLowerCase();
}

/**
 * A shell handed one of OUR privileged script files — leakGuard's
 * `irnf-lg-*` restore scripts, the TUN backends' `irnf-sb-*` / `irnf-tun-*`
 * work dirs (in the temp dir or userData/mac-tun-sessions) — runs routes, pf
 * and networksetup as whoever runs the test. Recognised by those names only:
 * a test's own script in tmp (releaseWorkflow's `irnf-rel-*` checksum step) is
 * not ours, and a `-n` syntax check executes nothing.
 */
const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash']);
const norm = (p) => String(p).replace(/\\/g, '/').toLowerCase();
function privilegedScript(cmd, args) {
  if (!SHELLS.has(commandName(cmd))) return false;
  const list = (Array.isArray(args) ? args : []).map(String);
  if (list.includes('-n')) return false;
  return list.some((a) => /\.sh$/i.test(a) && /\/mac-tun-sessions\/|\/irnf-(lg|sb|tun)-/.test(norm(a)));
}

/** The command (and its argv, or the words of a shell command line) is one no test may run. */
function blocked(cmd, args) {
  if (BLOCKED.has(commandName(cmd))) return true;
  if (Array.isArray(args)) return privilegedScript(cmd, args);
  const words = String(cmd == null ? '' : cmd).trim().split(/\s+/);
  return privilegedScript(words[0], words.slice(1));
}
const refusal = (cmd) => Object.assign(new Error(`tests/noNetwork.preload.js: a test tried to run the real "${commandName(cmd)}" — fake it`), { code: 'EIRNF_GUARD' });

function failedChild(cmd) {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.stdin = { write() {}, end() {} };
  child.pid = undefined;
  child.kill = () => false;
  child.unref = () => child;
  child.ref = () => child;
  // 'error' only to someone listening: execFile/exec already answered through
  // the callback, and an unheard 'error' would crash the test process instead
  process.nextTick(() => {
    if (child.listenerCount('error')) child.emit('error', refusal(cmd));
    child.emit('exit', null, null);
    child.emit('close', null, null);
  });
  return child;
}

const real = {};
for (const fn of ['execFile', 'execFileSync', 'spawn', 'spawnSync', 'exec', 'execSync']) real[fn] = cp[fn];
const argvOf = (rest) => (Array.isArray(rest[0]) ? rest[0] : []);

cp.execFile = function (cmd, ...rest) {
  if (!blocked(cmd, argvOf(rest))) return real.execFile.call(this, cmd, ...rest);
  const cb = [...rest].reverse().find((a) => typeof a === 'function');
  process.nextTick(() => { if (cb) cb(refusal(cmd), '', ''); });
  return failedChild(cmd);
};
cp.exec = function (command, ...rest) {
  if (!blocked(command)) return real.exec.call(this, command, ...rest);
  const cb = [...rest].reverse().find((a) => typeof a === 'function');
  process.nextTick(() => { if (cb) cb(refusal(command), '', ''); });
  return failedChild(command);
};
cp.spawn = function (cmd, ...rest) {
  return blocked(cmd, argvOf(rest)) ? failedChild(cmd) : real.spawn.call(this, cmd, ...rest);
};
for (const fn of ['execFileSync', 'spawnSync']) {
  cp[fn] = function (cmd, ...rest) {
    if (blocked(cmd, argvOf(rest))) throw refusal(cmd);
    return real[fn].call(this, cmd, ...rest);
  };
}
cp.execSync = function (command, ...rest) {
  if (blocked(command)) throw refusal(command);
  return real.execSync.call(this, command, ...rest);
};
for (const fn of Object.keys(real)) cp[fn].irnfGuard = true;

module.exports = { BLOCKED, commandName, blocked };
