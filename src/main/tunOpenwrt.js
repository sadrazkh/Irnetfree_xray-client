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
/**
 * How long the device and the policy route get to appear after sing-box
 * reports itself up. Its `auto_route` lays the rules a moment AFTER the tun
 * device exists; on a slow CPU (an emulated one in CI) that moment was over
 * four seconds once, and a verify that reads `ip rule` too early tears down a
 * gateway that was about to be fine.
 */
const VERIFY_WAIT_MS = 15000;

function defaultWhich(name) {
  return String(process.env.PATH || '').split(path.delimiter).some(d => d && fs.existsSync(path.join(d, name)));
}

class TunOpenwrt {
  constructor(opts = {}) {
    this.inner = opts.inner || new TunSingbox(opts);
    this.run = opts.run || platform.run;
    this.runSync = opts.runSync || ((cmd, args) => execFileSync(cmd, args, { stdio: 'ignore', timeout: 5000 }));
    this.writeFile = opts.writeFile || ((p, text) => fs.writeFileSync(p, text, { mode: 0o600 }));
    this.lanStatus = opts.lanStatus || (() => net.lanStatus(this.run));
    this.which = opts.which || defaultWhich;
    this.onLog = opts.onLog || (() => {});
    this.lang = opts.lang || 'fa';
    this.tmpDir = opts.tmpDir || os.tmpdir();
    this.verifyWaitMs = opts.verifyWaitMs || VERIFY_WAIT_MS;

    this.backendId = 'openwrt';
    this.managesDns = true;
    this.interfaceName = this.inner.interfaceName;
    this.dnsPeer = this.inner.dnsPeer;
    this.dnsPeer6 = this.inner.dnsPeer6;
    this.active = false;
    this.excludeIps = [];
    this.macs = [];
    this.blockQuic = false;    // refuse UDP 443 from the LAN (settings.lanBlockQuic)
    this.lanIf = 'br-lan';
    this.probe = null;         // a LAN client address for the route check in verify()
    this.mark = net.BYPASS_MARK;
  }

  msg(fa, en) { return this.lang === 'en' ? en : fa; }

  isAvailable() { return this.inner.isAvailable() && this.which('nft'); }
  isElevated() { return this.inner.isElevated(); }
  prepare(o) { return typeof this.inner.prepare === 'function' ? this.inner.prepare(o) : undefined; }
  physicalInterface() { return this.inner.physicalInterface(); }

  /* ----------------------------- the router's two tables ----------------------------- */

  /** Atomic replace of our nft table with the given exclusions (and the QUIC refusal, when on). */
  async applyTable(macs) {
    // a router path is a POSIX path, whatever the tests run on
    const file = path.posix.join(this.tmpDir, 'irnetfree-nft.conf');
    this.writeFile(file, net.buildNftRuleset({ lanIf: this.lanIf, macs, mark: this.mark, blockQuic: this.blockQuic }));
    await this.run('nft', ['-f', file]);
  }

  /** Every `ip rule` of ours, in the order they are added: main-first, then the bypass. */
  ruleSets(verb) { return [...net.mainFirstRuleArgs(verb), ...net.bypassRuleArgs(verb, this.mark)]; }

  /** Our rules, added after clearing any leftover so a restart never doubles them. */
  async addRules() {
    await this.delRules();
    for (const args of this.ruleSets('add')) await this.run('ip', args);
  }

  /**
   * Delete by preference, repeatedly, until the kernel says there is none left:
   * a leftover from an older version (other selectors, same preference) goes
   * too, and a doubled rule from an unclean exit cannot survive.
   */
  async delRules() {
    for (const args of this.ruleSets('del')) {
      for (let i = 0; i < 4; i++) {
        try { await this.run('ip', args); } catch { break; }   // "not there" — the common case
      }
    }
  }

  async deleteTable() {
    try { await this.run('nft', ['delete', 'table', 'inet', 'irnetfree']); } catch { /* not there */ }
  }

  /**
   * The device exists AND sing-box's policy route is in place — else the LAN
   * is not tunnelled. Both are polled under one deadline: the rules arrive a
   * moment after the device.
   */
  async verify() {
    const deadline = Date.now() + this.verifyWaitMs;
    let lastErr = null;
    for (;;) {
      try {
        await this.run('ip', ['link', 'show', this.interfaceName]);
        const rules = await this.run('ip', ['rule', 'show']);
        if (new RegExp(`lookup ${SINGBOX_TABLE}\\b`).test(rules)) break;
        lastErr = new Error(`sing-box laid no policy route (ip rule):\n${String(rules).trim()}`);
      } catch (e) { lastErr = e; }
      if (Date.now() >= deadline) throw lastErr;
      await platform.delay(250);
    }
    // The check that would have caught v1.13.2: the router's own packets to a
    // LAN client must NOT be routed into the tunnel. Refusing here costs a log
    // line; going active would cost the whole house its network.
    if (this.probe) {
      const out = String(await this.run('ip', ['route', 'get', this.probe]));
      if (new RegExp(`\\bdev ${this.interfaceName}\\b`).test(out)) {
        throw new Error(`the router's own traffic to its LAN (${this.probe}) would enter the tunnel:\n${out.trim()}`);
      }
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
    const lan = await this.lanStatus();
    this.lanIf = lan.device;
    this.probe = net.lanProbeAddress(lan.address, lan.mask);
    this.macs = net.validMacs(o.bypassMacs);
    this.blockQuic = !!o.blockQuic;
    let step = 'nft';
    try {
      await this.applyTable(this.macs);
      step = 'ip rule';
      await this.addRules();
      step = 'sing-box';
      // gso: the tun reads and writes whole batches of segments instead of one
      // packet per syscall — on a 700 MHz Cortex-A7 that is the cheapest
      // throughput there is. Linux only, which a router is.
      await this.inner.start(socksPort, bypassAddrs, dnsServers, Object.assign({}, o, { gso: true }));
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

  /** Turn the QUIC refusal on or off under a live tunnel; the tunnel is not touched. */
  async setBlockQuic(on) {
    this.blockQuic = !!on;
    if (!this.active) return;
    await this.applyTable(this.macs);
    this.onLog(`Gateway: QUIC (UDP 443) from the LAN is ${this.blockQuic ? 'refused — browsers use TCP' : 'allowed'}`, 'info');
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
    for (const args of this.ruleSets('del')) {
      for (let i = 0; i < 4; i++) { try { this.runSync('ip', args); } catch { break; } }
    }
    try { this.runSync('nft', ['delete', 'table', 'inet', 'irnetfree']); } catch { /* not there */ }
  }
}

module.exports = { TunOpenwrt, SINGBOX_TABLE };
