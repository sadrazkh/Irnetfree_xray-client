'use strict';
/**
 * Users and devices on Windows: the firewall opening for the users' proxy.
 *
 * The proxy listens on every address (xray.js — the Wi-Fi's and the Mobile
 * Hotspot's alike), but Windows Firewall still drops what other devices send
 * to its ports, as it does for LAN sharing (main.js addLanFirewall). Unlike
 * LAN sharing's, this proxy asks a password, and the people it is for are on
 * the PC's own hotspot — a network Windows puts in the Public profile — so the
 * opening is every profile, but only from the local subnet. Its own rule names,
 * so turning one feature off never closes the other's ports.
 *
 * TCP only: a SOCKS5 UDP ASSOCIATE answers on a port the core picks per
 * session, which no port rule can name — UDP through the proxy reaches the PC
 * only where the firewall lets it.
 *
 * sync() is called on every build (ipc.js forBuild) and changes the rules only
 * when what they should be changed — the first call in a process always once.
 * Never throws; what failed is in the log.
 */
const { execFile } = require('child_process');

const RULES = { socks: 'IRNetFree LAN users SOCKS', http: 'IRNetFree LAN users HTTP' };

function netsh(args, exec) {
  return new Promise((resolve, reject) => {
    (exec || execFile)('netsh', args, { windowsHide: true }, (err, so, se) => {
      if (err) return reject(new Error(String(se || err.message || '').trim()));
      resolve(String(so || ''));
    });
  });
}

/**
 * @param {object} [o] { exec (child_process.execFile's shape — a test's fake), log({ line, level }), platform }
 * → { sync(ports | null) → Promise }: `ports` = { port, httpPort } to open, null to close.
 */
function createFirewall(o) {
  const opts = o || {};
  const log = typeof opts.log === 'function' ? opts.log : () => {};
  const platform = opts.platform || process.platform;
  let applied;   // the key last applied; undefined: nothing yet in this process
  let chain = Promise.resolve();

  async function remove() {
    for (const name of Object.values(RULES)) {
      try { await netsh(['advfirewall', 'firewall', 'delete', 'rule', `name=${name}`], opts.exec); } catch { /* not there */ }
    }
  }

  async function apply(ports) {
    await remove();
    if (!ports) return;
    const add = (name, port) => netsh(['advfirewall', 'firewall', 'add', 'rule', `name=${name}`,
      'dir=in', 'action=allow', 'protocol=TCP', `localport=${port}`, 'profile=any', 'remoteip=localsubnet'], opts.exec);
    try {
      await add(RULES.socks, ports.port);
      if (ports.httpPort) await add(RULES.http, ports.httpPort);
      log({ line: `Users: the firewall lets the local network reach the users' proxy on ${ports.port}${ports.httpPort ? '/' + ports.httpPort : ''}`, level: 'info' });
    } catch (e) {
      log({ line: 'Users: the firewall rule for the users\' proxy failed (run as admin to allow it): ' + e.message, level: 'warn' });
    }
  }

  return {
    sync(ports) {
      if (platform !== 'win32') return Promise.resolve();
      const p = ports && ports.port ? { port: ports.port, httpPort: ports.httpPort || 0 } : null;
      const key = p ? `${p.port}/${p.httpPort}` : 'off';
      if (key === applied) return chain;
      applied = key;
      chain = chain.then(() => apply(p)).catch(() => {});
      return chain;
    }
  };
}

module.exports = { RULES, createFirewall };
