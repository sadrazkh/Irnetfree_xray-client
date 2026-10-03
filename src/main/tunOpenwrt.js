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
 *      leaks the whole house;
 *   4. at pref 8997, what the router's own control path needs off the
 *      tunnel: the remote control's destinations (setBypass), and this
 *      process's own DNS to the in-country resolvers (layOwnDirect).
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
 * rebuilds it. This class watches for that exit itself (`active` follows
 * sing-box, `onUnexpectedExit` tells the service); the service watches Xray.
 * A kill switch that closes the window is deliberately not in this version
 * (spec §9).
 *
 * One ordering rule on the way down: rule 8998 goes only once the IRNetFree
 * device is gone. Harmless without sing-box, it is what keeps the router's own
 * LAN replies off a split table 2022 — deleting it under a live one is the
 * v1.13.2 outage again.
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
/** How long the IRNetFree device gets to disappear after sing-box is told to stop. */
const LINK_GONE_WAIT_MS = 5000;
/**
 * The gateway's UDP session lifetime (sing-box's tun `udp_timeout`, seconds).
 * Every LAN UDP flow is a SOCKS UDP ASSOCIATE to the core — a TCP control
 * connection and a UDP socket in sing-box, a listener per association in
 * Xray ≥ 26.6 — held until the session expires: 5 minutes by default. The
 * owner's AC-1304 (field log, v1.16.1): DoH through the exit timed out, the
 * core answered nothing, dnsmasq's retries reused each query's port, and on
 * sing-box 1.11/1.12 (the 23.05 and 24.10 feeds) a second packet resets a
 * session to that default — so every retried query held two descriptors for
 * five minutes, until sing-box hit "too many open files" and no device could
 * browse. 120 s drains them in two.
 *
 * Not lower: RFC 4787 REQ-5 (a UDP mapping lives at least 2 minutes), and on
 * the system stack the same timer ends a TCP connection that is idle both
 * ways — 60 s would cut 60-second keepalives. Not a shorter DNS-only timeout
 * either: sing-box ≥ 1.11 already gives port 53 ten seconds, a `route-options`
 * rule exists only from 1.11 (an older sing-box refuses the whole config) and
 * 1.11/1.12 drop it on the next packet anyway. The integer form is read as
 * seconds by every sing-box from 1.7.8 to 1.14. The real fix is the
 * descriptor limit (irnetfree.init: procd `limits nofile`); this keeps what
 * piles up under it short-lived.
 */
const ROUTER_UDP_TIMEOUT_S = 120;

function defaultWhich(name) {
  return String(process.env.PATH || '').split(path.delimiter).some(d => d && fs.existsSync(path.join(d, name)));
}

/** Block the thread for `ms` — only for the exit hook, where nothing can be awaited. */
function sleepSync(ms) {
  try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); } catch { /* no wait: poll faster */ }
}

/** The real uids of every running process named `name` (/proc/<pid>/comm, /proc/<pid>/status); [] off Linux. */
function procUidsOf(name, fsImpl = fs) {
  const uids = new Set();
  let pids = [];
  try { pids = fsImpl.readdirSync('/proc').filter(p => /^\d+$/.test(p)); } catch { return []; }
  for (const pid of pids) {
    try {
      if (String(fsImpl.readFileSync(`/proc/${pid}/comm`, 'utf8')).trim() !== name) continue;
      const m = /^Uid:\s+(\d+)/m.exec(String(fsImpl.readFileSync(`/proc/${pid}/status`, 'utf8')));
      if (m) uids.add(Number(m[1]));
    } catch { /* gone meanwhile */ }
  }
  return [...uids];
}

/**
 * Does dnsmasq forward as `uid`? Only when EVERY process by that name runs as
 * it. On OpenWrt not all of them are the forwarder: procd jails dnsmasq, and
 * the jail (ujail, named after it) stays root as the parent of the real one,
 * which drops to its own user (--user=dnsmasq) — what the QEMU job saw on 23.05
 * and 24.10 (run 37067447979: a root "dnsmasq" whose child runs as 453). A
 * dnsmasq that drops no privileges leaves every one of them root. None
 * running: not shared.
 */
function forwardsAs(uids, uid) {
  return uids.length > 0 && uids.every(u => u === uid);
}

/**
 * argv for `ip`: this process's OWN DNS (UDP 53) to one in-country resolver by
 * the main table, at the remote control's preference (8997, swept with it).
 * `uidrange`: only this process's user — dnsmasq runs as its own (OpenWrt
 * starts it `--user=dnsmasq`), so its upstream, and with it every LAN
 * device's query, stays in the tunnel. `iif lo`: only what the router itself
 * sends. Without it the rule would take the LAN out again: the kernel looks up
 * a FORWARDED packet's route with uid 0 (no socket — root of the namespace),
 * so `uidrange 0-0` alone matches every LAN device's DNS to these addresses.
 */
function ownDirectRuleArgs(verb, cidr, uid) {
  const fam = cidr.includes(':') ? '-6' : '-4';
  return [fam, 'rule', verb, 'pref', String(net.REMOTE_BYPASS_PREF), 'iif', 'lo', 'uidrange', `${uid}-${uid}`, 'to', cidr, 'ipproto', 'udp', 'dport', '53', 'lookup', 'main'];
}

class TunOpenwrt {
  constructor(opts = {}) {
    // The inner backend is built WITHOUT the caller's onUnexpectedExit: this
    // class reports sing-box's exit itself (watchInner), and a pass-through
    // would fire twice once TunSingbox reports its own exits.
    const innerOpts = Object.assign({}, opts, { composedBy: 'openwrt' });
    delete innerOpts.onUnexpectedExit;
    this.inner = opts.inner || new TunSingbox(innerOpts);
    this.onUnexpectedExit = opts.onUnexpectedExit || (() => {});
    this.run = opts.run || platform.run;
    this.runSync = opts.runSync || ((cmd, args) => execFileSync(cmd, args, { stdio: 'ignore', timeout: 5000 }));
    this.writeFile = opts.writeFile || ((p, text) => fs.writeFileSync(p, text, { mode: 0o600 }));
    this.lanStatus = opts.lanStatus || (() => net.lanStatus(this.run));
    this.which = opts.which || defaultWhich;
    this.onLog = opts.onLog || (() => {});
    this.lang = opts.lang || 'fa';
    this.tmpDir = opts.tmpDir || os.tmpdir();
    this.verifyWaitMs = opts.verifyWaitMs || VERIFY_WAIT_MS;
    this.linkWaitMs = opts.linkWaitMs || LINK_GONE_WAIT_MS;
    // who this service runs as, and who another process runs as (layOwnDirect)
    this.uid = opts.uid != null ? opts.uid : (typeof process.getuid === 'function' ? process.getuid() : 0);
    this.uidsOf = opts.uidsOf || ((name) => procUidsOf(name));

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
    this.bypassCidrs = [];     // the remote control's destinations, routed past the tunnel (setBypass)
    this.laid = false;         // our table / rules may be in the kernel
    this.watchGen = 0;         // bumped by every exit we cause: only a newer watch may report
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

  /**
   * Every `ip rule` of ours, in the order they are added: main-first, then
   * the bypass. A deletion also sweeps the remote control's destination
   * rules (pref 8997) — they are laid one per cidr (setBypass), but a
   * teardown, and the next start's clearing of a killed run's leftovers,
   * must take every one of them by preference alone.
   */
  ruleSets(verb) {
    const sets = [...net.mainFirstRuleArgs(verb), ...net.bypassRuleArgs(verb, this.mark)];
    return verb === 'del' ? [...sets, ...net.remoteBypassSweepArgs()] : sets;
  }

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
  /** How many times a deletion by preference is repeated: the two singletons a few, the per-destination 8997 rules until none is left. */
  delCap(args) { return args[4] === String(net.REMOTE_BYPASS_PREF) ? 64 : 4; }

  async delRules() {
    for (const args of this.ruleSets('del')) {
      const cap = this.delCap(args);
      for (let i = 0; i < cap; i++) {
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
    this.watchGen++;
    const proc = this.inner.proc || null;
    try { await this.inner.stop(); } catch { /* best effort */ }
    await this.unlay(proc);
  }

  /** Resolves true once `ip link show IRNetFree` fails (no device), false at the deadline. */
  async linkGone(ms) {
    const deadline = Date.now() + ms;
    for (;;) {
      try { await this.run('ip', ['link', 'show', this.interfaceName]); } catch { return true; }
      if (Date.now() >= deadline) return false;
      await platform.delay(200);
    }
  }

  linkGoneSync(ms) {
    const deadline = Date.now() + ms;
    for (;;) {
      try { this.runSync('ip', ['link', 'show', this.interfaceName]); } catch { return true; }
      if (Date.now() >= deadline) return false;
      sleepSync(100);
    }
  }

  /**
   * Our rules and table, removed — the rules only once sing-box's device is
   * gone (see the header). A sing-box that outlives its SIGTERM gets a SIGKILL
   * first; a device that still will not go keeps our rules, which the next
   * start (or the next service start) clears.
   */
  async unlay(proc) {
    let gone = await this.linkGone(this.linkWaitMs);
    if (!gone && proc) {
      try { proc.kill('SIGKILL'); } catch { /* gone meanwhile */ }
      gone = await this.linkGone(this.linkWaitMs);
    }
    if (gone) await this.delRules();
    else this.onLog(`The ${this.interfaceName} device is still there after sing-box was stopped — the router's rules stay until it is gone (harmless without sing-box; the next start clears them)`, 'error');
    await this.deleteTable();
    this.laid = !gone;
    return gone;
  }

  /**
   * At service start: what a killed service left behind (our rules, our
   * table — the QUIC refusal among them) goes, once no IRNetFree device is
   * left. The caller has already ended its orphaned cores.
   */
  clearLeftovers() {
    this.laid = true;
    return this.unlay(null);
  }

  /**
   * sing-box dying on its own (OOM, a panic) takes its routes with it: the LAN
   * goes direct while everything above still says "gateway up". `active`
   * follows the inner's liveness and the service is told, so it can rebuild.
   * An exit this class caused (stop, rollback, exit hook) bumped the
   * generation first and is not reported.
   */
  watchInner() {
    const gen = ++this.watchGen;
    const exited = this.inner.exited;
    if (!exited || typeof exited.then !== 'function') return;
    exited.then((info) => {
      if (gen !== this.watchGen || !this.active || this.inner.active) return;
      this.active = false;
      this.excludeIps = [];
      const why = (info && info.error) || `code=${info && info.code != null ? info.code : '-'} signal=${(info && info.signal) || '-'}`;
      this.onLog(`Gateway down: sing-box exited on its own (${why}) — the LAN goes direct until the tunnel is rebuilt`, 'error');
      try {
        this.onUnexpectedExit(new Error(this.msg(`sing-box گیت‌وی بسته شد (${why})`, `the gateway's sing-box exited (${why})`)));
      } catch (e) { this.onLog('Gateway recovery: ' + e.message, 'error'); }
    }, () => { /* never rejects; nothing to report if it does */ });
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
    this.laid = true;
    try {
      await this.applyTable(this.macs);
      step = 'ip rule';
      await this.addRules();
      step = 'sing-box';
      // (GSO on the tun — batches of segments per read/write — is something
      // sing-box ≥ 1.11 turns on by itself on Linux; the option that once asked
      // for it is refused by 1.12, which CI found out for us.)
      // udpTimeout: the router's UDP session lifetime (ROUTER_UDP_TIMEOUT_S)
      await this.inner.start(socksPort, bypassAddrs, dnsServers, Object.assign({}, o, { udpTimeout: ROUTER_UDP_TIMEOUT_S }));
      step = 'verify';
      await this.verify();
    } catch (e) {
      await this.rollback();
      // "the whole-network tunnel": «گیت‌وی» alone was a word the owner could
      // not place (field report G1) — the router IS the gateway, this is what it does
      throw new Error(this.msg(
        `تونل کل شبکه بالا نیامد (${step}): ${e.message}`,
        `The whole-network tunnel did not come up (${step}): ${e.message}`));
    }
    this.active = true;
    this.excludeIps = this.inner.excludeIps;
    this.watchInner();
    this.onLog(`Whole-network tunnel (gateway) up on ${this.lanIf}: every device behind the router goes through the VPN; ${this.macs.length} excluded by MAC`, 'info');
    // the remote control's destinations, remembered while the gateway was down (setBypass)
    for (const c of this.bypassCidrs) await this.layBypass(c);
    await this.layOwnDirect(o.ownDirect);
  }

  /**
   * The in-country resolvers the core dials `direct` (`o.ownDirect`) are IN
   * the whole-LAN tunnel since v1.16.1 — cut out of it, dnsmasq's upstream and
   * every LAN device's query to them left by the ISP in plain text (field
   * report D3). The router's OWN lookups through them must not need the
   * tunnel, though: the relay link resolves its relay there, and is the way in
   * when the VPN is broken (remote/agent.js). So this process's UDP 53 to
   * them goes by the main table (ownDirectRuleArgs) — unless dnsmasq runs as
   * the same user, when that rule would take its upstream out again: then
   * nothing is laid, and the log says so. The core's own query needs none
   * (its `direct` dial is bound to the WAN device), nor does a dnsmasq server
   * line bound to it (cloudflared.js). Laid after verify, swept with every
   * 8997 rule on the way down.
   */
  async layOwnDirect(list) {
    const cidrs = net.normalizeCidrs(list);
    if (!cidrs.length) return;
    let shared = false;
    try { shared = forwardsAs(this.uidsOf('dnsmasq'), this.uid); } catch { /* unknown: not shared */ }
    if (shared) {
      this.onLog(`dnsmasq runs as uid ${this.uid}, like this service — the router's own lookups through the in-country resolvers (${cidrs.join(', ')}) stay in the tunnel; a route for them would take dnsmasq's upstream out of it too`, 'warn');
      return;
    }
    for (const c of cidrs) {
      try { await this.run('ip', ownDirectRuleArgs('add', c, this.uid)); }
      catch (e) { this.onLog(`Own DNS: could not route ${c} past the tunnel: ${e.message}`, 'error'); }
    }
  }

  /**
   * The destinations the remote control uses (the relay, Cloudflare's tunnel
   * edge — service.setRemoteBypass): one `to <cidr> lookup main` rule each at
   * pref 8997, before every rule of ours and sing-box's, so the router's own
   * dials to them leave by the WAN whatever the tunnel does (node cannot mark
   * its sockets, so this is by destination). Live under a running gateway:
   * what left the list is removed, what joined is added, the rest untouched;
   * with the gateway down the list is only remembered and laid by the next
   * start. A rule the kernel refuses is logged — never a gateway failure.
   */
  async setBypass(list) {
    const next = net.normalizeCidrs(list);
    const prev = this.bypassCidrs;
    this.bypassCidrs = next;
    if (!this.active) return;
    for (const c of prev) {
      if (next.includes(c)) continue;
      try { await this.run('ip', net.remoteBypassRuleArgs('del', c)); } catch { /* already gone */ }
    }
    for (const c of next) if (!prev.includes(c)) await this.layBypass(c);
  }

  async layBypass(cidr) {
    try { await this.run('ip', net.remoteBypassRuleArgs('add', cidr)); }
    catch (e) { this.onLog(`Remote bypass: could not route ${cidr} past the tunnel: ${e.message}`, 'error'); }
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

  /** Also after sing-box died on its own: our rules and table are still there then. */
  async stop() {
    if (!this.active && !this.inner.active && !this.laid) return;
    this.watchGen++;            // the exit from here on is one we asked for
    this.active = false;
    this.excludeIps = [];
    const proc = this.inner.proc || null;
    try { await this.inner.stop(); }
    finally { await this.unlay(proc); }
    this.onLog('Gateway stopped: the LAN goes direct.', 'info');
  }

  /** Synchronous best effort for process exit — the same order: sing-box, its device gone, then our rules. */
  cleanupSync() {
    if (!this.active && !this.inner.active && !this.laid && !this.inner.proc) return;
    this.watchGen++;
    const proc = this.inner.proc || null;
    try { this.inner.cleanupSync(); } catch { /* best effort */ }
    let gone = this.linkGoneSync(this.linkWaitMs);
    if (!gone && proc) {
      try { proc.kill('SIGKILL'); } catch { /* gone meanwhile */ }
      gone = this.linkGoneSync(1000);
    }
    if (gone) {
      for (const args of this.ruleSets('del')) {
        const cap = this.delCap(args);
        for (let i = 0; i < cap; i++) { try { this.runSync('ip', args); } catch { break; } }
      }
    }
    try { this.runSync('nft', ['delete', 'table', 'inet', 'irnetfree']); } catch { /* not there */ }
    this.active = false;
    this.laid = !gone;
  }
}

module.exports = { TunOpenwrt, SINGBOX_TABLE, ROUTER_UDP_TIMEOUT_S, ownDirectRuleArgs, procUidsOf, forwardsAs };
