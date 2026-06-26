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
async function macServices() {
  const out = await run('networksetup', ['-listallnetworkservices']);
  return out.split('\n').slice(1).map(s => s.replace(/^\*/, '').trim()).filter(Boolean);
}

async function enableMac(host, socksPort, httpPort) {
  const services = await macServices();
  for (const svc of services) {
    await run('networksetup', ['-setsocksfirewallproxy', svc, host, String(socksPort)]).catch(() => {});
    await run('networksetup', ['-setsocksfirewallproxystate', svc, 'on']).catch(() => {});
    await run('networksetup', ['-setwebproxy', svc, host, String(httpPort)]).catch(() => {});
    await run('networksetup', ['-setwebproxystate', svc, 'on']).catch(() => {});
    await run('networksetup', ['-setsecurewebproxy', svc, host, String(httpPort)]).catch(() => {});
    await run('networksetup', ['-setsecurewebproxystate', svc, 'on']).catch(() => {});
  }
}

async function disableMac() {
  const services = await macServices();
  for (const svc of services) {
    await run('networksetup', ['-setsocksfirewallproxystate', svc, 'off']).catch(() => {});
    await run('networksetup', ['-setwebproxystate', svc, 'off']).catch(() => {});
    await run('networksetup', ['-setsecurewebproxystate', svc, 'off']).catch(() => {});
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

module.exports = { setSystemProxy };
