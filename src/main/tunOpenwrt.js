'use strict';
/**
 * TUN mode on an OpenWrt router: the router is the tunnel for every device
 * behind it.
 *
 * This backend COMPOSES the sing-box one (tunSingbox.js) rather than changing
 * it: sing-box's `auto_route` already routes forwarded LAN traffic into the TUN
 * on Linux (sing-tun's rule set ends in `not iif lo → lookup 2022`), and every
 * port-53 packet with it — so dnsmasq's upstream queries and every client's
 * hard-coded resolver end up at Xray's dns-out without a line of DNS config.
 * What a router adds is around that:
 *
 *   1. an nft table of ours (openwrtNet.buildNftRuleset) that marks packets
 *      from EXCLUDED devices by source MAC, and
 *   2. one `ip rule` (pref 8999, before sing-box's 9000+) that sends marked
 *      packets to the main table — out the WAN, with fw4's normal NAT;
 *   3. a check, after sing-box is up, that the TUN device exists and the
 *      policy route is really there — a gateway that silently is not one
 *      leaks the whole house.
 *
 * Order on start: table → rules → sing-box → verify; any failure rolls back
 * in reverse and the error names the step. The exclusion list is replaced
 * LIVE (atomic nft reload) without touching the tunnel.
 *
 * `managesDns = true`: the service then leaves the leak guard out. The guard
 * rewrites adapter resolvers; on a router the resolver is dnsmasq, which must
 * stay exactly as it is — the port-53 route above is the guard here.
 *
 * Fail-closed on a dead core, fail-open on a dead sing-box: routes into the
 * TUN survive an Xray crash (traffic stops, nothing leaks); a sing-box crash
 * removes its own routes and the LAN goes direct until the service's recovery
 * rebuilds it. A kill switch that closes that window is deliberately not in
 * this version (spec §9).
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const platform = require('./tunPlatform');
const { TunSingbox } = require('./tunSingbox');
const net = require('./openwrtNet');

/** sing-box's default `iproute2_table_index`; its rules must mention it. */
const SINGBOX_TABLE = 2022;
const VERIFY_WAIT_MS = 4000;

function defaultWhich(name) {
  return String(process.env.PATH || '').split(path.delimiter).some(d => d && fs.existsSync(path.join(d, name)));
}

class TunOpenwrt {
  constructor(opts = {}) {
    this.inner = opts.inner || new TunSingbox(opts);
    this.run = opts.run || platform.run;
    this.runSync = opts.runSync || ((cmd, args) => execFileSync(cmd, args, { stdio: 'ignore', timeout: 5000 }));
    this.writeFile = opts.writeFile || ((p, text) => fs.writeFileSync(p, text, { mode: 0o600 }));
    this.lanInterface = opts.lanInterface || (() => net.lanInterface(this.run));
    this.which = opts.which || defaultWhich;
    this.onLog = opts.onLog || (() => {});
    this.lang = opts.lang || 'fa';
    this.tmpDir = opts.tmpDir || os.tmpdir();

    this.backendId = 'openwrt';
    this.managesDns = true;
    this.interfaceName = this.inner.interfaceName;
    this.dnsPeer = this.inner.dnsPeer;
    this.dnsPeer6 = this.inner.dnsPeer6;
    this.active = false;
    this.excludeIps = [];
    this.macs = [];
    this.lanIf = 'br-lan';
    this.mark = net.BYPASS_MARK;
  }

  msg(fa, en) { return this.lang === 'en' ? en : fa; }

  isAvailable() { return this.inner.isAvailable() && this.which('nft'); }
  isElevated() { return this.inner.isElevated(); }
  prepare(o) { return typeof this.inner.prepare === 'function' ? this.inner.prepare(o) : undefined; }
  physicalInterface() { return this.inner.physicalInterface(); }

  /* ----------------------------- the router's two tables ----------------------------- */

  /** Atomic replace of our nft table with the given exclusions. */
  async applyTable(macs) {
    // a router path is a POSIX path, whatever the tests run on
    const file = path.posix.join(this.tmpDir, 'irnetfree-nft.conf');
    this.writeFile(file, net.buildNftRuleset({ lanIf: this.lanIf, macs, mark: this.mark }));
    await this.run('nft', ['-f', file]);
  }

  /** The bypass rule, added after clearing any leftover so a restart never doubles it. */
  async addRules() {
    await this.delRules();
    for (const args of net.bypassRuleArgs('add', this.mark)) await this.run('ip', args);
  }

  async delRules() {
    for (const args of net.bypassRuleArgs('del', this.mark)) {
      try { await this.run('ip', args); } catch { /* not there — the common case */ }
    }
  }

  async deleteTable() {
    try { await this.run('nft', ['delete', 'table', 'inet', 'irnetfree']); } catch { /* not there */ }
  }

  /** The device exists and sing-box's policy route is in place — else the LAN is not tunnelled. */
  async verify() {
    const deadline = Date.now() + VERIFY_WAIT_MS;
    let lastErr = null;
    for (;;) {
      try { await this.run('ip', ['link', 'show', this.interfaceName]); lastErr = null; break; }
      catch (e) { lastErr = e; if (Date.now() >= deadline) break; await platform.delay(250); }
    }
    if (lastErr) throw lastErr;
    const rules = await this.run('ip', ['rule', 'show']);
    if (!new RegExp(`lookup ${SINGBOX_TABLE}\\b`).test(rules)) {
      throw new Error(`sing-box laid no policy route (ip rule):\n${String(rules).trim()}`);
    }
  }

  async rollback() {
    try { await this.inner.stop(); } catch { /* best effort */ }
    await this.delRules();
    await this.deleteTable();
  }

  /* ----------------------------- public API ----------------------------- */

  /**
   * @param socksPort   Xray's local SOCKS inbound
   * @param bypassAddrs server addresses kept off the tunnel (route_exclude_address)
   * @param dnsServers  ignored here, as on Linux: dnsmasq is left alone
   * @param opts        { ipv6, strict, apps, bypassMacs } — bypassMacs is the router's own
   */
  async start(socksPort, bypassAddrs, dnsServers, opts = {}) {
    if (this.active) return;
    const o = opts || {};
    this.inner.lang = this.lang;
    this.lanIf = await this.lanInterface();
    this.macs = net.validMacs(o.bypassMacs);
    let step = 'nft';
    try {
      await this.applyTable(this.macs);
      step = 'ip rule';
      await this.addRules();
      step = 'sing-box';
      await this.inner.start(socksPort, bypassAddrs, dnsServers, o);
      step = 'verify';
      await this.verify();
    } catch (e) {
      await this.rollback();
      throw new Error(this.msg(
        `گیت‌وی بالا نیامد (${step}): ${e.message}`,
        `Gateway did not come up (${step}): ${e.message}`));
    }
    this.active = true;
    this.excludeIps = this.inner.excludeIps;
    this.onLog(`Gateway up on ${this.lanIf}: every device behind the router goes through the tunnel; ${this.macs.length} excluded by MAC`, 'info');
  }

  /** Replace the exclusions under a live tunnel; the tunnel is not touched. */
  async setBypassMacs(macs) {
    this.macs = net.validMacs(macs);
    if (!this.active) return;
    await this.applyTable(this.macs);
    this.onLog(`Gateway: ${this.macs.length} device(s) excluded by MAC`, 'info');
  }

  async stop() {
    if (!this.active && !this.inner.active) return;
    this.active = false;
    this.excludeIps = [];
    try { await this.inner.stop(); }
    finally {
      await this.delRules();
      await this.deleteTable();
    }
    this.onLog('Gateway stopped: the LAN goes direct.', 'info');
  }

  /** Synchronous best effort for process exit. */
  cleanupSync() {
    try { this.inner.cleanupSync(); } catch { /* best effort */ }
    for (const args of net.bypassRuleArgs('del', this.mark)) { try { this.runSync('ip', args); } catch { /* not there */ } }
    try { this.runSync('nft', ['delete', 'table', 'inet', 'irnetfree']); } catch { /* not there */ }
  }
}

module.exports = { TunOpenwrt, SINGBOX_TABLE };
