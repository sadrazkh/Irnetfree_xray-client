'use strict';
/**
 * Users on the router: smooth speed limits and a priority per user, with tc
 * (v1.40) — the shaper. v1.39 polices a device's speed in the gateway's nft
 * table (router/nft.js `rates`: `limit rate over … drop`): what goes over the
 * rate is DROPPED, TCP backs off, climbs, is dropped again — a sawtooth the
 * user feels as a jerky download that never quite reaches its rate. Shaping
 * QUEUES instead: packets wait their turn and leave at the rate, so a cap is
 * met smoothly — and a queue can be ordered, which is what a user's priority
 * is. router/index.js hands every decision here (plan.decide's `shape`) when
 * config.shaping.smooth is on; when this answers mode 'tc' the table gets no
 * police rates, when it answers 'police' (something is missing) the table
 * polices exactly as v1.39 did. Nothing is installed by the app: `missing`
 * names the OpenWrt packages, the Users page shows the opkg line.
 *
 * What it builds — every handle is 1f1e: (the app's mark, 0x1f1e), so what is
 * ours is told from anyone else's at a glance, and nothing with another handle
 * is ever touched:
 *
 *   download  an HTB root on the LAN device's egress (`lanIf`, br-lan): what
 *             leaves the router towards a device — the internet's download to
 *             it (forwarded from the tunnel; with sing-box's system stack a
 *             LAN connection is terminated on the tun and its download still
 *             leaves by br-lan) and the router's own replies — classified by
 *             DESTINATION address;
 *   upload    an `ingress` qdisc on the LAN device, every packet redirected
 *             (act_mirred) to an IFB device of ours (`ifb`, ifb-lu) that
 *             carries the same HTB tree — a device's upload must be queued
 *             before it reaches the tunnel, and ingress itself cannot queue —
 *             classified by SOURCE address. The IFB hands the packet back to
 *             the LAN device's receive path when its turn comes.
 *
 *   1f1e:        htb — `default 20` with a line, `default 0` without one (unclassified traffic is then
 *   │            "direct": untouched)
 *   ├─ 1f1e:1    the line (config.shaping.down / up): rate = ceil = the line — what every class below borrows from
 *   │  ├─ 1f1e:20   default: unassigned devices and users of normal priority without a cap — prio 1, fq_codel
 *   │  ├─ 1f1e:101  device 1: ceil its cap (or the line), prio 0 high / 1 normal / 2 low, fq_codel
 *   │  └─ 1f1e:102  device 2 …
 *   └─ direct       the router's own traffic — its replies to the LAN (download) and what the LAN asks of
 *                   it (upload): DNS, LuCI, this app's UI, the sign-in page — by the router's own addresses
 *                   on the LAN device, `flowid 1f1e:0`. HTB's direct queue is dequeued before every class
 *                   (sch_htb.c htb_dequeue: "direct packets as high prio (!)") and is never under the line:
 *                   the router stays quick whatever its users do, and v1.39 never policed its own replies
 *                   either (the table's rates are in the forward chain). Sized by `direct_qlen 1000`
 *                   explicitly: HTB takes the device's tx_queue_len otherwise (htb_init), 32 on an IFB.
 *
 * Rates. HTB's `rate` is what a class is guaranteed, `ceil` what it may borrow
 * up to; a parent lends to its lowest-`prio` children first and to equal ones
 * by `quantum`. A child under its own rate sends without asking its parent,
 * so the children's rates must not add up to more than the parent's for the
 * parent's ceil to hold. Hence, under a line, every class is guaranteed a
 * SHARE — the line divided among the classes, the default one counted — and
 * borrows up to its cap or the line: a capped class's rate is its share or
 * its cap, whichever is smaller (a cap above the line is the line). Under
 * contention the line fills, the high classes get the slack first, a low one
 * keeps its share: nobody is starved. Without a line (0) there is nothing to
 * borrow from: a cap is rate = ceil = the cap straight under the root, and a
 * priority cannot apply — info() says so (`prio`), the Users page explains.
 * Every class gets its `quantum` explicitly (its rate in bytes/s ÷ 10, within
 * one packet … 200000): the kernel's own choice is logged as a warning at
 * both ends ("quantum of class … is big/small", htb_change_class), skipped
 * only for an explicit one.
 *
 * Addresses. A device is its addresses (v4 /32, v6 /128 — never a link-local
 * v6: nothing from the internet reaches one), one u32 filter each, the same
 * addresses the table pins to its MAC. The router's own come from `ip -o addr
 * show dev <lanIf>` at each build (link-local included: DNS over v6 asks
 * there) — without them its replies fall into the default class, still prio 1
 * under the line, and that is said once.
 *
 * What is needed on OpenWrt, and how its absence is told (verified in the
 * openwrt-23.05 and openwrt-24.10 trees, 2026-10-29):
 *   tc-tiny (or tc-full)   the `tc` binary — iproute2 6.3 / 6.11; both PROVIDES tc, both DEPENDS
 *                          +kmod-sched-core (package/network/utils/iproute2/Makefile). tc-tiny only
 *                          lacks the iptables/ipset/bpf extensions; htb, u32, mirred, fq_codel are core.
 *   kmod-sched-core        sch_htb, sch_ingress, cls_u32, act_mirred (and hfsc, tbf, fw, flow, route,
 *                          basic, matchall, gact, skbedit) — SCHED_MODULES_CORE in
 *                          package/kernel/linux/modules/netsupport.mk, both releases.
 *   kmod-ifb               drivers/net/ifb.ko (netdevices.mk; `numifbs=0`, so it makes no device by
 *                          itself — we add ours).
 *   fq_codel needs nothing: CONFIG_NET_SCH_FQ_CODEL=y, the default qdisc of every OpenWrt kernel
 *   (target/linux/generic/config-5.15 and config-6.6); HTB, ingress, u32, mirred and IFB are "not set"
 *   there, so a default image has none of them — nor tc.
 * The pieces are found out by using them: a build runs its commands in order
 * and the first refusal names what is missing (tc not found → tc-tiny, and
 * the kernel modules by their files; a qdisc, filter or action the kernel
 * does not know → kmod-sched-core; an IFB that cannot be made → kmod-ifb;
 * the IFB is tried on its own after a scheduler failure, so one answer names
 * every package). Whatever failed is torn down, mode is 'police', and the
 * same description is tried again at most every RETRY_MS (the admin installs
 * the packages; the next decision after that minute finds them). Another
 * shaper's root or ingress on the LAN device (SQM, qosify…) is left alone:
 * mode 'police' with `busy` saying whose.
 *
 * Idempotent: a description is applied only when it changed (the cleaned
 * description's JSON); a change tears our tree down and builds it anew (a few
 * commands, a moment unshaped — the table reloads the same way). Teardown
 * deletes the root by handle (the kernel refuses a root delete whose handle
 * is another's: sch_api.c tc_get_qdisc "Invalid handle"), and the ingress
 * only when our IFB exists (no one else names a device ifb-lu; the IFB is
 * kept as that mark whenever the ingress cannot be confirmed gone) — a tree a
 * crashed service left behind is ours by the same marks and goes the same
 * way. No class left, or stop(): everything down, nothing of ours remains.
 *
 * Pure parts (tested byte for byte on the owner's Windows; the kernel's word
 * comes from scripts/probe-lan-shape.js in CI and the QEMU smoke): cleanShape,
 * shapeCommands, parseQdiscs, parseAddrs.
 */
const os = require('os');
const nodeFs = require('fs');
const nodeNet = require('net');
const { countable } = require('./nft');

/** Every qdisc and class of ours carries this major handle (0x1f1e: the app's own mark elsewhere). */
const HANDLE = '1f1e';
const LINE_MINOR = '1';
const DEFAULT_MINOR = '20';
/** Device classes count up from here: 1f1e:101, 1f1e:102 … */
const DEVICE_MINOR_FROM = 0x100;
const DIRECT_QLEN = 1000;
/** A speed's ceiling, kbps (model.js KBPS_MAX: 10 Gbit/s). */
const KBPS_MAX = 10000000;
/** The least a class is guaranteed, kbps (HTB wants a rate above zero). */
const MIN_KBPS = 8;
/** HTB's quantum in bytes: one full packet … what the kernel itself caps a computed one at. */
const QUANTUM_MIN = 1514, QUANTUM_MAX = 200000;
const PRIORITIES = ['high', 'normal', 'low'];
const PRIO = { high: 0, normal: 1, low: 2 };
/** Filter preferences: the router's own first, then the devices; a preference holds one protocol. */
const PREF = { router4: 1, router6: 2, device4: 10, device6: 11, redirect: 10 };
/** A fallback is tried again, with the same description, no sooner than this. */
const RETRY_MS = 60000;
const CMD_TIMEOUT_MS = 15000;
const PACKAGES = { tc: 'tc-tiny', sched: 'kmod-sched-core', ifb: 'kmod-ifb' };
/** kmod-sched-core's modules this tree needs (its files on OpenWrt: /lib/modules/<release>/<name>.ko). */
const SCHED_MODULES = ['sch_htb', 'sch_ingress', 'cls_u32', 'act_mirred'];

const MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;
const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

/** A speed as the tree takes it: a whole number of kbps in 1..KBPS_MAX, or 0 (none). */
function kbpsOf(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n < 1) return 0;
  return Math.min(Math.round(n), KBPS_MAX);
}

const macOf = (s) => {
  const m = String(s == null ? '' : s).trim().toLowerCase();
  return MAC_RE.test(m) ? m : null;
};

/** HTB's quantum for a class of this rate: its bytes per second ÷ 10, within one packet … the kernel's own ceiling. */
function quantumOf(kbps) {
  return Math.min(QUANTUM_MAX, Math.max(QUANTUM_MIN, Math.floor(kbps * 125 / 10)));
}

/**
 * The description (plan.decide's `shape`: { line: { down, up }, classes:
 * [{ mac, ips, down, up, prio }] }) cleaned to what the tree is built from:
 * the line's speeds whole kbps or 0; the classes by MAC (one shape, each
 * once, sorted — the same devices give the same tree), their addresses those
 * a counter keys on (router/nft.js countable: v4, or a v6 that is not
 * link-local), each in one class only (the lower MAC keeps a shared one — as
 * the table keeps a pinned address for its first device), their speeds whole
 * kbps or 0, `prio` one of PRIORITIES (else 'normal'). A class with no
 * address, or with neither a cap nor a priority of note, is nothing to shape
 * and is left out.
 */
function cleanShape(desc) {
  const d = isObj(desc) ? desc : {};
  const l = isObj(d.line) ? d.line : {};
  const line = { down: kbpsOf(l.down), up: kbpsOf(l.up) };
  const rows = [];
  for (const c of Array.isArray(d.classes) ? d.classes : []) {
    const mac = isObj(c) ? macOf(c.mac) : null;
    if (!mac || rows.some(r => r.mac === mac)) continue;
    rows.push({ mac, c });
  }
  rows.sort((a, b) => (a.mac < b.mac ? -1 : a.mac > b.mac ? 1 : 0));
  const seen = new Set();
  const classes = [];
  for (const { mac, c } of rows) {
    const ips = [];
    for (const raw of Array.isArray(c.ips) ? c.ips : []) {
      const ip = countable(raw);
      if (!ip || seen.has(ip)) continue;
      seen.add(ip);
      ips.push(ip);
    }
    const down = kbpsOf(c.down), up = kbpsOf(c.up);
    const prio = PRIORITIES.includes(c.prio) ? c.prio : 'normal';
    if (!ips.length || (!down && !up && prio === 'normal')) continue;
    classes.push({ mac, ips, down, up, prio });
  }
  return { line, classes };
}

const tcStep = (piece, args, ok) => Object.assign({ piece, cmd: 'tc', args }, ok ? { ok } : {});
const ipStep = (piece, args, ok) => Object.assign({ piece, cmd: 'ip', args }, ok ? { ok } : {});

/**
 * One direction's tree on `dev`: `dir` 'down' (the LAN device: a device is
 * the destination, the router the source) or 'up' (the IFB: the other way
 * round). `routerIps`: the router's own addresses on the LAN device → the
 * direct queue. Without a line only capped devices get a class; with one,
 * every class (a device with just a priority too) sits under the line.
 */
function treeSteps(dev, dir, d, routerIps) {
  const line = d.line[dir];
  const devs = line ? d.classes : d.classes.filter(c => c[dir] > 0);
  const byDst = dir === 'down';
  const root = `${HANDLE}:`;
  const out = [];
  const cls = (parent, id, rate, ceil, prio) => tcStep('sched', ['class', 'add', 'dev', dev, 'parent', parent, 'classid', id, 'htb',
    'rate', `${rate}kbit`, 'ceil', `${ceil}kbit`, ...(prio == null ? [] : ['prio', String(prio)]), 'quantum', String(quantumOf(rate))]);
  const leaf = (id) => tcStep('sched', ['qdisc', 'add', 'dev', dev, 'parent', id, 'fq_codel']);
  const filter = (ip, side, id, pref4, pref6) => {
    const v6 = ip.includes(':');
    return tcStep('sched', ['filter', 'add', 'dev', dev, 'parent', root, 'protocol', v6 ? 'ipv6' : 'ip', 'prio', String(v6 ? pref6 : pref4),
      'u32', 'match', v6 ? 'ip6' : 'ip', side, v6 ? `${ip}/128` : `${ip}/32`, 'flowid', id]);
  };
  out.push(tcStep('sched', ['qdisc', 'add', 'dev', dev, 'root', 'handle', root, 'htb', 'default', line ? DEFAULT_MINOR : '0', 'direct_qlen', String(DIRECT_QLEN)]));
  // the share every class under the line is guaranteed: the line among them and the default class
  const share = line ? Math.max(MIN_KBPS, Math.floor(line / (devs.length + 1))) : 0;
  if (line) {
    out.push(cls(root, `${HANDLE}:${LINE_MINOR}`, line, line, null));
    out.push(cls(`${HANDLE}:${LINE_MINOR}`, `${HANDLE}:${DEFAULT_MINOR}`, share, line, PRIO.normal));
    out.push(leaf(`${HANDLE}:${DEFAULT_MINOR}`));
  }
  // the router's own traffic: the direct queue (X:0), before every class — even without a line, where a
  // capped device's class would otherwise take the router's replies to it
  for (const ip of routerIps) out.push(filter(ip, byDst ? 'src' : 'dst', `${HANDLE}:0`, PREF.router4, PREF.router6));
  devs.forEach((c, i) => {
    const id = `${HANDLE}:${(DEVICE_MINOR_FROM + i + 1).toString(16)}`;
    const cap = c[dir];
    if (line) {
      const ceil = cap ? Math.min(cap, line) : line;
      out.push(cls(`${HANDLE}:${LINE_MINOR}`, id, Math.min(share, ceil), ceil, PRIO[c.prio]));
    } else {
      out.push(cls(root, id, cap, cap, null));
    }
    out.push(leaf(id));
    for (const ip of c.ips) out.push(filter(ip, byDst ? 'dst' : 'src', id, PREF.device4, PREF.device6));
  });
  return out;
}

/**
 * Every command of a build, in order, each with the piece it needs (`tc`
 * itself is asked first by the shaper; 'sched' = kmod-sched-core, 'ifb' =
 * kmod-ifb) and, where a failure is fine, `ok` (a regex on its message):
 * the download tree on the LAN device, the IFB made and up, the upload tree
 * on it, then — last, so no packet reaches an IFB without its tree — the
 * ingress qdisc and the redirect of everything into the IFB (u32 on
 * `protocol all` matching every packet, as sqm-scripts does it). Both
 * directions always, whatever has work: the pieces are then all tried, and
 * one answer names every package.
 */
function shapeCommands(d, { lanIf = 'br-lan', ifb = 'ifb-lu', routerIps = [] } = {}) {
  const ips = (Array.isArray(routerIps) ? routerIps : []).filter(ip => typeof ip === 'string' && ip);
  return [
    ...treeSteps(lanIf, 'down', d, ips),
    ipStep('ifb', ['link', 'add', ifb, 'type', 'ifb'], /File exists/i),
    ipStep('ifb', ['link', 'set', ifb, 'up']),
    ...treeSteps(ifb, 'up', d, ips),
    tcStep('sched', ['qdisc', 'add', 'dev', lanIf, 'handle', 'ffff:', 'ingress']),
    tcStep('sched', ['filter', 'add', 'dev', lanIf, 'parent', 'ffff:', 'protocol', 'all', 'prio', String(PREF.redirect), 'u32', 'match', 'u32', '0', '0',
      'action', 'mirred', 'egress', 'redirect', 'dev', ifb])
  ];
}

/**
 * `tc qdisc show dev X` → [{ kind, handle, root, ingress }]: `qdisc noqueue
 * 0: root refcnt 2` (a bridge's own), `qdisc htb 1f1e: root …` (ours),
 * `qdisc ingress ffff: parent ffff:fff1 …` or clsact (an ingress hook, whose
 * ever), `qdisc fq_codel 8001: parent 1f1e:20 …` (a leaf). A root with handle
 * 0 is the kernel's default (qdisc_create_dflt gives none) — anything else
 * at the root was put there by someone.
 */
function parseQdiscs(text) {
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = /^qdisc (\S+) ([0-9a-f]+): (root|parent \S+)/i.exec(line.trim());
    if (!m) continue;
    const kind = m[1].toLowerCase();
    out.push({ kind, handle: m[2].toLowerCase().replace(/^0+(?=.)/, ''), root: m[3] === 'root', ingress: kind === 'ingress' || kind === 'clsact' });
  }
  return out;
}

/** `ip -o addr show dev X` → the device's own addresses, v4 and v6 (link-local kept), each once. */
function parseAddrs(text) {
  const out = [];
  for (const m of String(text || '').matchAll(/\binet6? ([0-9a-f.:]+)\/\d+/gi)) {
    const ip = m[1].toLowerCase();
    if (nodeNet.isIP(ip) && !out.includes(ip)) out.push(ip);
  }
  return out;
}

/** The binary itself is not there: execFile's ENOENT, or `ip netns exec`'s word for the same. */
const isMissingBinary = (e) => /ENOENT|exec of .* failed|No such file or directory/i.test(String(e && e.message || e));
/** A kernel piece is not there — not a typo of ours, not a device missing. */
const looksMissing = (piece, e) => {
  const m = String(e && e.message || e);
  if (piece === 'ifb') return /not supported|Unknown device type|not found|No such file/i.test(m);
  return /unknown|not found|not supported|Failed to load|No such file/i.test(m);
};
const firstLine = (s) => String(s == null ? '' : s).split(/\r?\n/)[0].trim().slice(0, 200);

/**
 * `run(cmd, args, { timeout })` → Promise<string>, rejecting with the
 * command's stderr (the router's tunPlatform.run); `log(msg, level)`;
 * `lanIf` the LAN device; `ifb` the name of our IFB; `now`; `fs` and
 * `release` (os.release) for the module files when tc is missing.
 */
function createShaper({ run = null, log = () => {}, lanIf = 'br-lan', ifb = 'ifb-lu', now = Date.now, fs = nodeFs, release = () => os.release() } = {}) {
  let mode = 'off';
  let missing = [];
  let busy = null;
  let why = null;
  let line = { down: 0, up: 0 };
  let lastKey = null;
  let triedAt = 0;
  let saidVerdict = null;
  let saidNoAddrs = false;
  let chain = Promise.resolve();

  const exec = (cmd, args) => run(cmd, args, { timeout: CMD_TIMEOUT_MS });
  const tryExec = async (cmd, args) => { try { await exec(cmd, args); return true; } catch { return false; } };
  const hasIfb = () => tryExec('ip', ['link', 'show', 'dev', ifb]);

  /** One at a time: an apply and a stop each read and change the same devices. */
  function serial(fn) {
    const p = chain.then(fn, fn);
    chain = p.catch(() => {});
    return p;
  }

  /**
   * Our tree down, and only ours: the root by its handle, the ingress and
   * the IFB when the IFB is there. The redirect names the device, so the
   * ingress goes first and the device after (its tree goes with it) — and
   * the device stays when the ingress cannot be confirmed gone (no tc at this
   * moment: the package removed under a running tree): it is the mark by
   * which the ingress is known as ours, and the next teardown with tc back
   * takes both. Without it the ingress would look like another shaper's for
   * good.
   */
  async function teardown() {
    if (!run) return;
    await tryExec('tc', ['qdisc', 'del', 'dev', lanIf, 'root', 'handle', `${HANDLE}:`]);
    if (!(await hasIfb())) return;
    if (!(await tryExec('tc', ['qdisc', 'del', 'dev', lanIf, 'ingress']))) {
      // nothing to delete, or no tc to ask with: only a listing that shows no ingress lets the mark go
      let listing = null;
      try { listing = await exec('tc', ['qdisc', 'show', 'dev', lanIf]); } catch { /* no tc */ }
      if (listing == null || parseQdiscs(listing).some(q => q.ingress)) return;
    }
    await tryExec('ip', ['link', 'del', ifb]);
  }

  /** Is this module there to load: loaded now, its file (OpenWrt's flat /lib/modules/<release>/), or built in. */
  function kmodPresent(name) {
    const rel = String(release() || '');
    try { fs.accessSync(`/sys/module/${name}`); return true; } catch { /* not loaded */ }
    try { fs.accessSync(`/lib/modules/${rel}/${name}.ko`); return true; } catch { /* no file */ }
    try { if (fs.readFileSync(`/lib/modules/${rel}/modules.builtin`, 'utf8').includes(`/${name}.ko`)) return true; } catch { /* no list */ }
    return false;
  }

  /** Can an IFB be made (kmod-ifb): tried and removed at once — one already there (ours, kept as a mark) is left as it is. */
  async function ifbWorks() {
    try { await exec('ip', ['link', 'add', ifb, 'type', 'ifb']); } catch (e) { return /File exists/i.test(e.message); }
    await tryExec('ip', ['link', 'del', ifb]);
    return true;
  }

  async function ownAddresses() {
    try { return parseAddrs(await exec('ip', ['-o', 'addr', 'show', 'dev', lanIf])); } catch (e) {
      if (!saidNoAddrs) log(`Users: the router’s own addresses on ${lanIf} could not be read (${firstLine(e.message)}) — its replies share the default class`, 'warn');
      saidNoAddrs = true;
      return [];
    }
  }

  /** The tree built for `d`: { ok } or what stood in the way: { pieces: Set<'tc'|'sched'|'ifb'>, busy, why }. */
  async function build(d) {
    const v = { ok: false, pieces: new Set(), busy: null, why: null };
    let listing;
    try { listing = await exec('tc', ['qdisc', 'show', 'dev', lanIf]); } catch (e) {
      if (!isMissingBinary(e)) { v.why = `tc qdisc show dev ${lanIf}: ${firstLine(e.message)}`; return v; }
      // no tc: the kernel's pieces by their files (nothing can be tried), the IFB for real
      v.pieces.add('tc');
      if (SCHED_MODULES.some(m => !kmodPresent(m))) v.pieces.add('sched');
      if (!(await ifbWorks())) v.pieces.add('ifb');
      v.why = `no tc on this router`;
      return v;
    }
    const qdiscs = parseQdiscs(listing);
    const root = qdiscs.find(q => q.root && q.handle !== '0');
    if (root) { v.busy = 'root'; v.why = `another shaper holds ${lanIf}’s root (${root.kind} ${root.handle}:)`; return v; }
    const ing = qdiscs.find(q => q.ingress);
    if (ing) { v.busy = 'ingress'; v.why = `another shaper holds ${lanIf}’s ingress (${ing.kind})`; return v; }
    const routerIps = await ownAddresses();
    let ifbTried = false;
    for (const s of shapeCommands(d, { lanIf, ifb, routerIps })) {
      if (s.piece === 'ifb') ifbTried = true;
      try { await exec(s.cmd, s.args); } catch (e) {
        if (s.ok && s.ok.test(e.message)) continue;
        v.why = `${[s.cmd, ...s.args].join(' ')}: ${firstLine(e.message)}`;
        if (looksMissing(s.piece, e)) v.pieces.add(s.piece);
        // the IFB is independent of the schedulers: tried on its own, so one answer names every package
        if (s.piece !== 'ifb' && !ifbTried && !(await ifbWorks())) v.pieces.add('ifb');
        return v;
      }
    }
    v.ok = true;
    return v;
  }

  function setVerdict(v, d) {
    mode = v.ok ? 'tc' : 'police';
    missing = v.ok ? [] : ['tc', 'sched', 'ifb'].filter(p => v.pieces.has(p)).map(p => PACKAGES[p]);
    busy = v.ok ? null : v.busy;
    why = v.ok ? null : v.why;
    const said = JSON.stringify([mode, missing, busy]);
    if (said === saidVerdict) return;
    saidVerdict = said;
    if (v.ok) {
      const n = d.classes.length;
      log(`Users: speeds are shaped with tc on ${lanIf} (HTB; the upload through ${ifb}) — ${n} device class${n === 1 ? '' : 'es'}${d.line.down || d.line.up ? `, line ${d.line.down}/${d.line.up} kbps` : ', no line speed: priorities cannot apply'}`, 'info');
    } else if (missing.length) {
      log(`Users: smooth speed limits need ${missing.join(', ')} — \`opkg install ${missing.join(' ')}\`; until then speeds are policed in the table as before`, 'warn');
    } else {
      log(`Users: speeds are policed in the table as before — ${why}`, 'warn');
    }
  }

  function info() {
    return {
      mode, missing: missing.slice(), line: { down: line.down, up: line.up },
      // whether a priority can apply each way: shaping, under a line
      prio: { down: mode === 'tc' && line.down > 0, up: mode === 'tc' && line.up > 0 },
      busy, why, lanIf, ifb
    };
  }

  async function applyNow(desc) {
    const d = cleanShape(desc);
    const key = JSON.stringify(d);
    const t = now();
    // the same description: nothing to do — unless we fell back and a minute passed (packages may be there now)
    if (key === lastKey && (mode === 'tc' || t - triedAt < RETRY_MS)) return info();
    lastKey = key;
    line = d.line;
    triedAt = t;
    if (!run) { setVerdict({ ok: false, pieces: new Set(), busy: null, why: 'no command runner' }, d); return info(); }
    await teardown();
    const v = await build(d);
    // nothing to shape (a probe of the pieces, then), or a build that failed halfway: nothing of ours stays
    if (!v.ok || !d.classes.length) await teardown();
    setVerdict(v, d);
    return info();
  }

  async function stopNow() {
    await teardown();
    mode = 'off';
    lastKey = null;
    busy = null;
    why = null;
    saidVerdict = null;
  }

  return {
    /** The description applied (when it changed) → info(). */
    apply: (desc) => serial(() => applyNow(desc)),
    /** Everything of ours down; mode 'off'. */
    stop: () => serial(stopNow),
    info
  };
}

module.exports = {
  createShaper, cleanShape, shapeCommands, parseQdiscs, parseAddrs, quantumOf,
  HANDLE, LINE_MINOR, DEFAULT_MINOR, DEVICE_MINOR_FROM, DIRECT_QLEN, PRIO, PREF, PRIORITIES, PACKAGES, SCHED_MODULES, RETRY_MS, KBPS_MAX, MIN_KBPS
};
