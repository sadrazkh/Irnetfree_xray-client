'use strict';
/**
 * System-wide proxy control.
 *  - Windows: writes "Internet Settings" registry keys + notifies WinINet.
 *  - macOS:   networksetup for each network service.
 *  - Linux:   gsettings (GNOME) best-effort.
 *
 * We set an HTTP/HTTPS system proxy pointing at the local Xray HTTP inbound,
 * with a sensible bypass list for local addresses.
 */

const { execFile } = require('child_process');
const os = require('os');

function run(cmd, args) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { windowsHide: true }, (err, stdout, stderr) => {
      if (err) return reject(new Error((stderr || err.message || '').toString().trim()));
      resolve((stdout || '').toString().trim());
    });
  });
}

const WIN_REG = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
const WIN_BYPASS = '<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;172.30.*;172.31.*;192.168.*';

async function enableWindows(host, httpPort) {
  const proxyServer = `${host}:${httpPort}`;
  await run('reg', ['add', WIN_REG, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '1', '/f']);
  await run('reg', ['add', WIN_REG, '/v', 'ProxyServer', '/t', 'REG_SZ', '/d', proxyServer, '/f']);
  await run('reg', ['add', WIN_REG, '/v', 'ProxyOverride', '/t', 'REG_SZ', '/d', WIN_BYPASS, '/f']);
  await refreshWindows();
}

async function disableWindows() {
  await run('reg', ['add', WIN_REG, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '0', '/f']);
  await refreshWindows().catch(() => {});
}

// Notify WinINet that settings changed so apps pick it up without restart.
function refreshWindows() {
  const ps = [
    '$sig = @"',
    '[System.Runtime.InteropServices.DllImport("wininet.dll", SetLastError=true)]',
    'public static extern bool InternetSetOption(IntPtr h, int o, IntPtr b, int l);',
    '"@',
    'try {',
    '  $t = Add-Type -MemberDefinition $sig -Name N -Namespace W -PassThru -ErrorAction Stop',
    '  [void]$t::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)', // INTERNET_OPTION_SETTINGS_CHANGED
    '  [void]$t::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)', // INTERNET_OPTION_REFRESH
    '} catch {}'
  ].join('\n');
  return run('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps]);
}

/* --------------------------- macOS --------------------------- */

/**
 * Service names out of `networksetup -listallnetworkservices`. The output opens
 * with a legend — "An asterisk (*) denotes that a network service is
 * disabled." — and lists a disabled service with that asterisk in front. The
 * legend goes and the asterisk comes off, so what is left are the names
 * networksetup takes as arguments. Matched by content, not by position: the
 * old `slice(1)` would have eaten the first real service had the legend ever
 * been missing. Pure, so a test pins it — nobody here has a Mac to watch it.
 */
function parseMacServices(out) {
  return String(out == null ? '' : out).split(/\r?\n/)
    .map(s => s.trim())
    .filter(s => s && !/^An asterisk \(\*\) denotes/i.test(s))
    .map(s => s.replace(/^\*\s*/, ''));
}

async function macServices(exec) {
  return parseMacServices(await exec('networksetup', ['-listallnetworkservices']));
}

/**
 * SOCKS, HTTP and HTTPS proxy on every network service. A service that refuses
 * is skipped, but when NONE took the setting the call fails — which is what
 * happens for a user who is not an administrator, since networksetup demands
 * that for writes. Every error used to be swallowed per command, so that case
 * ended in a "System proxy enabled" log line over a machine whose proxy had
 * not changed at all. `exec` is injectable for the tests.
 */
async function enableMac(host, socksPort, httpPort, exec = run) {
  const services = await macServices(exec);
  let applied = 0;
  let lastError = null;
  for (const svc of services) {
    try {
      await exec('networksetup', ['-setsocksfirewallproxy', svc, host, String(socksPort)]);
      await exec('networksetup', ['-setsocksfirewallproxystate', svc, 'on']);
      await exec('networksetup', ['-setwebproxy', svc, host, String(httpPort)]);
      await exec('networksetup', ['-setwebproxystate', svc, 'on']);
      await exec('networksetup', ['-setsecurewebproxy', svc, host, String(httpPort)]);
      await exec('networksetup', ['-setsecurewebproxystate', svc, 'on']);
      applied++;
    } catch (e) {
      lastError = e;
    }
  }
  if (!applied) {
    if (!services.length) throw new Error('networksetup lists no network service to set the proxy on');
    throw new Error('networksetup refused the proxy on every network service'
      + (lastError && lastError.message ? ` (${lastError.message})` : '')
      + ' — on macOS changing the system proxy needs an administrator account');
  }
}

/** Best-effort, as before: a disable must never be the thing that fails a disconnect. */
async function disableMac(exec = run) {
  const services = await macServices(exec);
  for (const svc of services) {
    await exec('networksetup', ['-setsocksfirewallproxystate', svc, 'off']).catch(() => {});
    await exec('networksetup', ['-setwebproxystate', svc, 'off']).catch(() => {});
    await exec('networksetup', ['-setsecurewebproxystate', svc, 'off']).catch(() => {});
  }
}

/* --------------------------- Linux (GNOME) --------------------------- */
async function enableLinux(host, httpPort) {
  await run('gsettings', ['set', 'org.gnome.system.proxy', 'mode', 'manual']).catch(() => {});
  for (const p of ['http', 'https']) {
    await run('gsettings', ['set', `org.gnome.system.proxy.${p}`, 'host', host]).catch(() => {});
    await run('gsettings', ['set', `org.gnome.system.proxy.${p}`, 'port', String(httpPort)]).catch(() => {});
  }
}
async function disableLinux() {
  await run('gsettings', ['set', 'org.gnome.system.proxy', 'mode', 'none']).catch(() => {});
}

/* --------------------------- public API --------------------------- */
async function setSystemProxy(enabled, opts = {}) {
  const host = opts.host || '127.0.0.1';
  const httpPort = opts.httpPort || 10809;
  const socksPort = opts.socksPort || 10808;
  const platform = os.platform();

  if (enabled) {
    if (platform === 'win32') return enableWindows(host, httpPort);
    if (platform === 'darwin') return enableMac(host, socksPort, httpPort);
    return enableLinux(host, httpPort);
  } else {
    if (platform === 'win32') return disableWindows();
    if (platform === 'darwin') return disableMac();
    return disableLinux();
  }
}

module.exports = { setSystemProxy, parseMacServices, enableMac, disableMac };
