'use strict';
/**
 * Cloudflare Tunnel as the second remote path (spec §3.5 C1–C3): the feed's
 * `cloudflared` package and its own procd service, driven through its UCI
 * config — /etc/config/cloudflared, section type `cloudflared` (named
 * `config` in the package's default file), options `enabled`, `token`,
 * `protocol` (the package's own default is http2); its init runs
 * `cloudflared tunnel --no-autoupdate … run --token <T>` (the token in argv is
 * the package's choice, not ours: we hand it to `uci batch` on stdin).
 * https://github.com/openwrt/packages/tree/openwrt-23.05/net/cloudflared
 * Verified on the CI images: 23.05.5 ships 2024.4.1-2 (its default config lists
 * `token ''` and `protocol 'http2'`), 24.10.2 ships 2025.5.0 (its default config
 * lists only config/origincert/logfile; the init reads the rest). `uci show`
 * omits empty-valued options, so the section is found by its type, never by
 * the presence of a `token` line.
 *
 * Kept out of the tunnel the same way the relay is: its edge addresses go to
 * `service.setRemoteBypass('cloudflared', …)` and a dnsmasq drop-in sends the
 * edge domains to the config's direct resolvers while it runs. `protocol`
 * is pinned to http2 (TCP 7844): QUIC has been throttled or blocked on
 * Iranian ISPs since mid-2025. cloudflared cannot use a SOCKS/HTTP proxy for
 * its own tunnel connections, so unlike the relay link it has no "via VPN"
 * fallback — direct only, which the status says.
 *
 * The pure parts (the bypass list, the drop-in text, the UCI batch, the
 * spawn shapes) are testable without a router; everything that touches the
 * system goes through an injectable `run`.
 */
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

/**
 * The edge cloudflared dials, from Cloudflare's "Tunnel with firewall" page:
 * https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/configure-tunnels/tunnel-with-firewall/
 *   region1.v2.argotunnel.com → 198.41.192.{7,27,37,47,57,67,77,107,167,227}
 *   region2.v2.argotunnel.com → 198.41.200.{13,23,33,43,53,63,73,113,193,233}
 *   IPv6: 2606:4700:a0::1–10 and 2606:4700:a8::1–10; port 7844 (TCP for http2);
 *   TLS names h2.cftunnel.com / quic.cftunnel.com; optional 443 to
 *   api.cloudflare.com and update.argotunnel.com.
 * Edge discovery is a DNS SRV lookup of _v2-origintunneld._tcp.argotunnel.com
 * through the local resolver (falling back to DNS-over-TLS at 1.1.1.1:853):
 * https://github.com/cloudflare/cloudflared/blob/master/edgediscovery/allregions/discovery.go
 * — hence the dnsmasq drop-in for argotunnel.com and cftunnel.com. 1.1.1.1 is
 * deliberately NOT in the bypass list: that would send all of the router's
 * 1.1.1.1 traffic around the tunnel.
 */
const EDGE = Object.freeze({
  domains: Object.freeze(['argotunnel.com', 'cftunnel.com']),
  hosts: Object.freeze(['region1.v2.argotunnel.com', 'region2.v2.argotunnel.com', 'h2.cftunnel.com', 'quic.cftunnel.com', 'api.cloudflare.com', 'update.argotunnel.com']),
  cidrs: Object.freeze(['198.41.192.0/24', '198.41.200.0/24', '2606:4700:a0::/123', '2606:4700:a8::/123'])
});

/**
 * Where dnsmasq reads drop-ins differs per release — 23.05: `conf-dir=/tmp/dnsmasq.d`;
 * 24.10: one dir per instance, `conf-dir=/tmp/dnsmasq.<cfg>.d` (seen on the CI
 * images) — so the dirs are read off the config dnsmasq's init generated
 * (/var/etc/dnsmasq.conf.<cfg>), and 23.05's is the fallback when none is found.
 */
const DROP_IN_NAME = 'irnetfree-cloudflared.conf';
const DROP_IN = '/tmp/dnsmasq.d/' + DROP_IN_NAME;
const DNSMASQ_GENERATED = '/var/etc';
const BIN = '/usr/bin/cloudflared';
const INIT = '/etc/init.d/cloudflared';
const DNSMASQ_INIT = '/etc/init.d/dnsmasq';
const PROTOCOL = 'http2';
const TOKEN_RE = /^[A-Za-z0-9+/=_-]{40,4096}$/;
const STATUS_CACHE_MS = 15000;

const bypassList = () => ({ hosts: EDGE.hosts.slice(), cidrs: EDGE.cidrs.slice() });
const isTunnelToken = (s) => typeof s === 'string' && TOKEN_RE.test(s);

/** `server=/<edge domain>/<direct resolver>` for every pair — what dnsmasq reads from its conf-dir. */
function dnsmasqDropIn(resolvers) {
  const ips = (resolvers || []).filter((r) => /^[0-9a-f.:]+$/i.test(String(r)));
  const lines = ['# IRNetFree: Cloudflare Tunnel edge discovery must not depend on the VPN tunnel'];
  for (const d of EDGE.domains) for (const ip of ips) lines.push(`server=/${d}/${ip}`);
  return lines.join('\n') + '\n';
}

/** The `uci batch` text (stdin, never argv): enable or disable, the token, the protocol pinned to http2. */
function uciBatch({ section = 'config', token = null, enabled }) {
  const q = (v) => "'" + String(v).replace(/'/g, '') + "'";
  const lines = [`set cloudflared.${section}.enabled=${q(enabled ? 1 : 0)}`];
  if (token) lines.push(`set cloudflared.${section}.token=${q(token)}`);
  lines.push(`set cloudflared.${section}.protocol=${q(PROTOCOL)}`);
  lines.push('commit cloudflared');
  return lines.join('\n') + '\n';
}

/** The `conf-dir=` directories of every generated dnsmasq config (a `,filter` suffix dropped); 23.05's dir when none. */
function dnsmasqConfDirs(fsImpl = fs, generatedDir = DNSMASQ_GENERATED) {
  const dirs = [];
  try {
    for (const name of fsImpl.readdirSync(generatedDir)) {
      if (!/^dnsmasq\.conf\./.test(name)) continue;
      let text = '';
      try { text = String(fsImpl.readFileSync(path.posix.join(generatedDir, name), 'utf8')); } catch { continue; }
      for (const m of text.matchAll(/^conf-dir=([^\s,]+)/gm)) if (!dirs.includes(m[1])) dirs.push(m[1]);
    }
  } catch { /* no generated config: dnsmasq not managed by OpenWrt's init here */ }
  if (!dirs.length) dirs.push(path.posix.dirname(DROP_IN));
  return dirs;
}

/** The section of type `cloudflared` in `uci show cloudflared` output (the package names it `config`). */
function sectionOf(uciShow) {
  const m = /^cloudflared\.([A-Za-z0-9_@\[\]]+)=cloudflared$/m.exec(String(uciShow || ''));
  return m ? m[1] : 'config';
}

/** The spawn shape of the fallback the spec names (no feed package with a token option): the token in the env, never in argv. */
const runArgs = () => ({ cmd: BIN, args: ['tunnel', '--no-autoupdate', '--protocol', PROTOCOL, 'run'], envKey: 'TUNNEL_TOKEN' });

/** execFile as a promise: { code, stdout, stderr }; stdin from `input`; never throws. */
function defaultRun(cmd, args, { input = null, timeoutMs = 120000 } = {}) {
  return new Promise((resolve) => {
    let child;
    try {
      child = execFile(cmd, args, { timeout: timeoutMs, maxBuffer: 4 << 20 }, (err, stdout, stderr) => {
        resolve({ code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stdout: String(stdout || ''), stderr: String(stderr || '') + (err && typeof err.code !== 'number' ? ' ' + err.message : '') });
      });
    } catch (e) { return resolve({ code: 1, stdout: '', stderr: e.message }); }
    if (input != null && child.stdin) { try { child.stdin.end(input); } catch { /* gone */ } }
  });
}

/**
 * @param {object} o
 * @param {Function} [o.run]        (cmd, args, {input}) → Promise<{code, stdout, stderr}>
 * @param {object} [o.fsImpl]       existsSync / writeFileSync / unlinkSync / mkdirSync
 * @param {object} [o.service]      directResolvers?, setRemoteBypass?, getSettings (dnsDirect)
 * @param {Function} [o.log]
 */
function createCloudflared(o = {}) {
  const run = o.run || defaultRun;
  const fsImpl = o.fsImpl || fs;
  const service = o.service || {};
  const log = o.log || (() => {});
  const generatedDir = o.dnsmasqGeneratedDir || DNSMASQ_GENERATED;
  const bin = o.binPath || BIN;
  const now = o.now || Date.now;
  let installing = false;
  let lastInstall = null;     // { ok, at, error }
  let versionCache = null;
  let dropInsWritten = [];    // the files written at the last apply on, removed at apply off
  let probed = null;          // { at, running, lastLine } — LuCI polls every 3 s; pidof + logread are forks on a Cortex-A7 (review M6)

  const installed = () => { try { return fsImpl.existsSync(bin); } catch { return false; } };

  function resolvers() {
    try { if (typeof service.directResolvers === 'function') { const r = service.directResolvers(); if (Array.isArray(r) && r.length) return r; } } catch { /* fall through */ }
    try { const s = typeof service.getSettings === 'function' ? service.getSettings() : null; if (s && Array.isArray(s.dnsDirect) && s.dnsDirect.length) return s.dnsDirect; } catch { /* none */ }
    return ['178.22.122.100', '185.51.200.2'];
  }

  async function bypass(on) {
    if (typeof service.setRemoteBypass !== 'function') return;
    try { await service.setRemoteBypass('cloudflared', on ? bypassList() : { hosts: [], cidrs: [] }); }
    catch (e) { log('cloudflared: the bypass was not applied: ' + e.message, 'warn'); }
  }

  /** The drop-in into every conf-dir dnsmasq reads (on), or out of every one it was ever written to (off). */
  function writeDropIn(on) {
    const dirs = dnsmasqConfDirs(fsImpl, generatedDir);
    try {
      if (on) {
        const text = dnsmasqDropIn(resolvers());
        dropInsWritten = [];
        for (const d of dirs) {
          const file = path.posix.join(d, DROP_IN_NAME);
          fsImpl.mkdirSync(d, { recursive: true });
          fsImpl.writeFileSync(file, text);
          dropInsWritten.push(file);
        }
        return true;
      }
      const files = new Set([...dropInsWritten, ...dirs.map((d) => path.posix.join(d, DROP_IN_NAME)), DROP_IN]);
      for (const file of files) if (fsImpl.existsSync(file)) fsImpl.unlinkSync(file);
      dropInsWritten = [];
      return true;
    } catch (e) { log('cloudflared: the dnsmasq drop-in was not ' + (on ? 'written' : 'removed') + ': ' + e.message, 'warn'); return false; }
  }

  async function section() {
    const r = await run('uci', ['-q', 'show', 'cloudflared']);
    return sectionOf(r.stdout);
  }

  /** Write the settings into the package's UCI and start or stop its service, the bypass and the drop-in with it. */
  async function apply({ enabled, token }) {
    if (!installed()) { log('cloudflared: not installed — nothing applied' + (enabled ? ' (install it from the Remote access page)' : ''), enabled ? 'warn' : 'info'); return { ok: false, error: 'not installed' }; }
    const on = !!enabled && !!token;
    if (enabled && !token) log('cloudflared: enabled without a tunnel token — not started', 'warn');
    const sec = await section();
    probed = null;    // whatever this changes, the next status probes again
    const uci = await run('uci', ['-q', 'batch'], { input: uciBatch({ section: sec, token: on ? token : null, enabled: on }) });
    if (uci.code !== 0) { log('cloudflared: uci refused the settings: ' + (uci.stderr || uci.code).toString().trim(), 'error'); return { ok: false, error: 'uci' }; }
    if (on) {
      await bypass(true);
      writeDropIn(true);
      await run(DNSMASQ_INIT, ['reload']);
      await run(INIT, ['enable']);
      const r = await run(INIT, ['restart']);
      log(r.code === 0 ? 'cloudflared: started (protocol http2, direct only — it cannot ride the VPN)' : 'cloudflared: its service did not start: ' + (r.stderr || r.code).toString().trim(), r.code === 0 ? 'info' : 'error');
      return { ok: r.code === 0 };
    }
    await run(INIT, ['stop']);
    await run(INIT, ['disable']);
    writeDropIn(false);
    await run(DNSMASQ_INIT, ['reload']);
    await bypass(false);
    log('cloudflared: stopped');
    return { ok: true };
  }

  async function version() {
    if (versionCache || !installed()) return versionCache;
    const r = await run(bin, ['--version'], { timeoutMs: 20000 });
    versionCache = r.code === 0 ? String(r.stdout || r.stderr).trim().split('\n')[0].slice(0, 80) : null;
    return versionCache;
  }

  async function status() {
    const isInstalled = installed();
    let running = false;
    let lastLine = null;
    if (isInstalled) {
      if (!probed || now() - probed.at >= STATUS_CACHE_MS) {
        running = (await run('pidof', ['cloudflared'])).code === 0;
        const lr = await run('sh', ['-c', 'logread -e cloudflared 2>/dev/null | tail -n 1']);
        lastLine = lr.code === 0 ? (lr.stdout.trim().split('\n').pop() || null) : null;
        probed = { at: now(), running, lastLine };
      } else {
        ({ running, lastLine } = probed);
      }
    }
    return { installed: isInstalled, running, lastLine, version: isInstalled ? await version() : null, installing, lastInstall, path: 'direct', viaVpn: false };
  }

  /** `opkg update && opkg install cloudflared`, in the background; progress in the log. */
  function install(afterInstall) {
    if (installing) return { accepted: true, already: true };
    installing = true;
    versionCache = null;
    probed = null;
    log('cloudflared: installing from the feed (opkg update && opkg install cloudflared)…');
    (async () => {
      const up = await run('opkg', ['update'], { timeoutMs: 300000 });
      if (up.code !== 0) log('cloudflared: opkg update failed: ' + (up.stderr || up.stdout).trim().split('\n').pop(), 'warn');
      const inst = await run('opkg', ['install', 'cloudflared'], { timeoutMs: 600000 });
      const ok = inst.code === 0 && installed();
      lastInstall = { ok, at: Date.now(), error: ok ? null : (inst.stderr || inst.stdout).trim().split('\n').pop() || ('exit ' + inst.code) };
      log(ok ? `cloudflared: installed (${(await version()) || 'version unknown'})` : 'cloudflared: install failed: ' + lastInstall.error, ok ? 'info' : 'error');
      installing = false;
      if (ok && typeof afterInstall === 'function') { try { await afterInstall(); } catch (e) { log('cloudflared: ' + e.message, 'warn'); } }
    })();
    return { accepted: true };
  }

  return { installed, apply, status, install, version, get installing() { return installing; } };
}

module.exports = { EDGE, DROP_IN, DROP_IN_NAME, DNSMASQ_GENERATED, BIN, PROTOCOL, bypassList, dnsmasqDropIn, dnsmasqConfDirs, uciBatch, sectionOf, runArgs, isTunnelToken, createCloudflared, defaultRun };
