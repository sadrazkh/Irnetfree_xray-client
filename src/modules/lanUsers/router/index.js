'use strict';
/**
 * Users on the router — transparent mode (contract §B, "Router transparent
 * mode"): every device behind the router belongs to a user without a proxy
 * setting on the device. Built into the OpenWrt service (src/server/service.js)
 * only; off — the module not installed, or the mode not on — nothing of this
 * runs and the gateway is exactly what it was.
 *
 * What it adds around the whole-LAN tunnel (src/main/tunOpenwrt.js):
 *   - in the gateway's nft table (router/nft.js): blocked devices, the gate
 *     for unassigned ones (the sign-in page, or nothing), the portal's
 *     redirect, a byte counter per device — replaced live by an atomic load of
 *     the table (TunOpenwrt.setLanUsers), never touching the tunnel;
 *   - in the core (router/xrayTargets.js): one loopback SOCKS inbound
 *     `lu-tp-<n>` per config a user has, routed to that config;
 *   - in sing-box (tunSingbox buildTunConfig's `lanRoutes`): a socks outbound
 *     to each of them and a route rule over a local rule-set FILE of the
 *     source addresses of the devices that ride it;
 *   - the sign-in page (router/portal.js) on the LAN address;
 *   - every TICK_MS: the counters read (`nft -j list table`) and handed to the
 *     users meter, the devices read again (leases + neighbours), and what
 *     changed applied — a user over its cap is held, the new period lets it
 *     through again.
 *
 * Matching by address, not by MAC — what sing-box can do, read in its source
 * (SagerNet/sing-box v1.14.3 and v1.13.14, 2026-10-26):
 *   - `source_mac_address` exists from 1.14.0 only
 *     (route/rule/rule_item_source_mac_address.go). It is filled from a
 *     neighbour resolver keyed by the packet's source address — the kernel's
 *     neighbour table and the DHCP leases (route/route.go:547-551,
 *     prepareMatchMetadata; route/neighbor_resolver_linux.go) — started on its
 *     own when a route rule names it (route/router.go:66, needFindNeighbor). So
 *     on 1.14 it WOULD match a forwarded LAN packet on the TUN.
 *   - 1.13.14 has none of it (no rule item, no resolver: the key is an unknown
 *     field and the config is refused), and the router's feed cores are 1.11
 *     and 1.12.
 *   - It is no headless rule (option/rule_set.go's DefaultHeadlessRule has no
 *     such field in 1.14.3): only route.rules may carry it, and every sign-in
 *     would rewrite them — a sing-box restart, the whole house offline.
 *   `source_ip_cidr` IS a headless rule item in 1.11.9, 1.12.9, 1.13.14 and
 *   1.14.3, and a LOCAL rule-set file is reloaded by sing-box itself when it
 *   changes (route/rule/rule_set_local.go: fswatch on the file, 64-71 in
 *   1.11.9–1.13.14, 63-70 in 1.14.3; fswatch fires on Create/Write of the
 *   path, so a write-and-rename lands). So: by source address, from the leases
 *   and the neighbour table, one file per config, rewritten when a device signs
 *   in or changes address — and the gate itself stays by MAC, in nft.
 *
 * Who belongs to whom (plan.js): the admin's choice in the devices list for
 * good; a sign-in on the portal for its session's hours (kept in
 * `<data dir>/lan-sessions.json`, so a restart signs nobody out).
 *
 * Integration points (service.js, the gateway's region): prepare() before the
 * config is built, applyXray() at the end of buildActive, gatewayOptions() and
 * entryAddrs() into the gateway's start, gatewayUp() after it. For the users'
 * IPC: setMeter(meter) (it must offer `feedDevices({ [userId]: { up, down,
 * bytes } })` beside `usage()`), refresh() after an edit, online() (with each
 * device's up/down bytes/s), deviceUsage() and pendingReconnect() for
 * `lanusers:get`.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('../../../main/openwrtNet');
const { groupRecordsById } = require('../../../main/groups');
const { scanDevices, macOfIp } = require('./devices');
const plan = require('./plan');
const { parseCounters } = require('./nft');
const { applyTransparentTargets } = require('./xrayTargets');
const { createPortal, checkPassword } = require('./portal');

/** How often the counters, the devices and the caps are looked at. */
const TICK_MS = 10000;
const SESSIONS_FILE = 'lan-sessions.json';
/** Each device's bytes this period, beside the sign-ins — written at most this often (flash). */
const DEVICE_USAGE_FILE = 'lan-device-usage.json';
const DEVICE_USAGE_SAVE_MS = 5 * 60 * 1000;

const pad = (n) => String(n).padStart(2, '0');
/** The period a byte counts in: 'YYYY-MM-DD' for a daily cap, 'YYYY-MM' otherwise (multiWanMeter's periods, local time). */
function periodKey(period, at) {
  const d = new Date(at);
  const month = `${d.getFullYear()}-${pad(d.getMonth() + 1)}`;
  return period === 'day' ? `${month}-${pad(d.getDate())}` : month;
}

function createLanRouter(o = {}) {
  const openwrt = !!o.openwrt;
  const dataDir = o.dataDir || null;
  const tmpDir = String(o.tmpDir || os.tmpdir()).replace(/\\/g, '/');
  const run = o.run || null;
  const readFile = o.readFile || ((p) => fs.promises.readFile(p, 'utf8'));
  const fsx = o.fs || fs;
  const getSettings = o.getSettings || (() => ({}));
  const getLanUsers = o.getLanUsers || (() => null);
  const records = o.records || (() => ({ servers: [], groups: [], chains: [] }));
  const log = o.log || (() => {});
  const now = o.now || Date.now;
  const getFreePorts = o.getFreePorts || null;
  const tickMs = o.tickMs || TICK_MS;
  const portalFactory = o.createPortal || createPortal;
  // the tests' 127.0.0.1:0 instead of the LAN address and the configured port
  const portalListen = o.portalListen || null;
  let meter = o.meter || null;

  // a router path is a POSIX path, whatever the tests run on
  const ruleDir = path.posix.join(tmpDir, 'irnetfree-lu');
  const fileOf = (tag) => path.posix.join(ruleDir, `${tag}.json`);

  let live = [];            // the inbounds the running gateway routes devices to: [{ tag, port, target, outboundTag, gone }]
  let builtOn = false;      // the running gateway was built with transparent mode
  let tun = null;           // the gateway, while it is up WITH the mode
  let gw = null;            // the gateway, while it is up at all
  let lan = { device: 'br-lan', address: null, mask: null };
  let scan = [];
  let sessions = loadSessions();
  let lastDecision = null;
  let lastKey = null;       // the nft description the table carries (plan.nftKey)
  let lastFiles = {};       // tag → the rule-set text on disk
  let prevCounters = {};    // mac → { up, down } at the last read
  let prevGen = -1;         // the table load (TunOpenwrt.tableGen) those were read from
  let deviceBytes = {};     // mac → { up, down } while this gateway runs
  let rates = {};           // mac → { up, down } bytes/s over the last read
  let readAt = 0;           // when the counters were last read
  let devUsage = loadDevUsage();   // mac → { period, bytes }: this period's bytes per device
  let devUsageDirty = false;
  let devUsageSavedAt = now();
  let portal = null;
  let portalAt = null;
  let timer = null;
  let saidNoMeter = false;
  let saidRaw = false;
  let saidPort = null;
  let overSaid = new Set();

  /* ------------------------------ state ------------------------------ */

  const lu = () => plan.readLanUsers(getLanUsers());
  const wanted = () => openwrt && plan.transparentWanted(getSettings(), lu());
  const usageNow = () => {
    try { return (meter && typeof meter.usage === 'function' && meter.usage()) || {}; } catch { return {}; }
  };
  const nameOf = (id) => { const u = lu().users.find(x => x.id === id); return u ? (u.name || u.username || id) : id; };

  function sessionsFile() { return dataDir ? path.join(dataDir, SESSIONS_FILE) : null; }
  function loadSessions() {
    const f = sessionsFile();
    if (!f) return {};
    try {
      const j = JSON.parse(fsx.readFileSync(f, 'utf8'));
      const out = {};
      for (const [mac, s] of Object.entries(j && typeof j === 'object' ? j : {})) {
        const m = net.normalizeMac(mac);
        if (m && s && typeof s.userId === 'string' && Number(s.until) > 0) out[m] = { userId: s.userId, until: Number(s.until), at: Number(s.at) || 0 };
      }
      return out;
    } catch { return {}; }
  }
  function saveSessions() {
    const f = sessionsFile();
    if (!f) return;
    try {
      fsx.writeFileSync(f + '.tmp', JSON.stringify(sessions), { mode: 0o600 });
      fsx.renameSync(f + '.tmp', f);
    } catch (e) { log(`Users: the sign-ins could not be saved: ${e.message}`, 'warn'); }
  }
  function devUsageFile() { return dataDir ? path.join(dataDir, DEVICE_USAGE_FILE) : null; }
  function loadDevUsage() {
    const f = devUsageFile();
    if (!f) return {};
    try {
      const j = JSON.parse(fsx.readFileSync(f, 'utf8'));
      const out = {};
      for (const [mac, v] of Object.entries(j && typeof j === 'object' ? j : {})) {
        const m = net.normalizeMac(mac);
        if (m && v && typeof v.period === 'string' && Number(v.bytes) >= 0) out[m] = { period: v.period, bytes: Number(v.bytes) };
      }
      return out;
    } catch { return {}; }
  }
  /** Lazily (`force`: now) — a router's data dir is flash. */
  function saveDevUsage(force = false) {
    const f = devUsageFile();
    if (!f || !devUsageDirty || (!force && now() - devUsageSavedAt < DEVICE_USAGE_SAVE_MS)) return;
    try {
      fsx.writeFileSync(f + '.tmp', JSON.stringify(devUsage), { mode: 0o600 });
      fsx.renameSync(f + '.tmp', f);
      devUsageDirty = false;
      devUsageSavedAt = now();
    } catch (e) { log(`Users: the devices' usage could not be saved: ${e.message}`, 'warn'); }
  }

  /** Sessions over, or of a user that is gone: forgotten (the kernel let their elements go already). */
  function pruneSessions() {
    const ids = new Set(lu().users.map(u => u.id));
    let changed = false;
    for (const [mac, s] of Object.entries(sessions)) {
      if (s.until > now() && ids.has(s.userId)) continue;
      delete sessions[mac];
      changed = true;
    }
    if (changed) saveSessions();
  }

  /** Servers (with groups beside them) and chains by id, as service.js buildPlan has them; a chain short of a member is left out. */
  function recordsById() {
    const r = records() || {};
    const serversById = {};
    for (const s of Array.isArray(r.servers) ? r.servers : []) if (s && s.id) serversById[s.id] = s;
    Object.assign(serversById, groupRecordsById(r.groups || [], Object.assign({}, serversById)));
    const chainsById = {};
    for (const c of Array.isArray(r.chains) ? r.chains : []) {
      if (!c || !c.id || !Array.isArray(c.members)) continue;
      const members = c.members.map(id => serversById[id]);
      if (!members.length || members.some(m => !m)) continue;
      chainsById[c.id] = members;
    }
    return { serversById, chainsById };
  }

  /* ------------------------------ the gateway's start ------------------------------ */

  /**
   * Before a connect builds its config: a free loopback port for every config
   * a user has (plan.routedTargets) — [] when the mode is off. The list rides
   * the connect's settings (`lanUsersTp`) to applyXray and gatewayOptions, so
   * a reload under a running gateway (which carries none) keeps its own.
   */
  async function prepare() {
    if (!wanted()) return [];
    const targets = plan.routedTargets(lu());
    if (!targets.length || typeof getFreePorts !== 'function') return [];
    const s = getSettings();
    const own = new Set([s.socksPort, s.httpPort, s.apiPort].map(Number));
    const ports = (await getFreePorts(targets.length + own.size)).filter(p => !own.has(p)).slice(0, targets.length);
    return targets.map((target, i) => ({ tag: `lu-tp-${i + 1}`, port: ports[i], target })).filter(e => Number.isInteger(e.port));
  }

  /**
   * At the end of buildActive: the inbounds into the core's config (in
   * place) — the connect's own list, or, in a reload, the running gateway's.
   * A raw JSON config runs as written: nothing goes into it, and its
   * devices ride it.
   */
  function applyXray(config, { serverId = null, plan: p = null, settings = {}, raw = false } = {}) {
    if (!openwrt || !config) return null;
    const tp = Array.isArray(settings.lanUsersTp) ? settings.lanUsersTp : live;
    if (!tp.length) return null;
    if (raw) {
      for (const e of tp) e.outboundTag = null;
      if (!saidRaw) log('Users: this connection runs a JSON config as written — the users’ own configs cannot be added to it, so their devices ride it', 'warn');
      saidRaw = true;
      return null;
    }
    const r = applyTransparentTargets(config, tp, { serverId, plan: p, records: recordsById(), directInterface: settings.directInterface, groupSkip: settings.groupSkip });
    for (const e of tp) {
      const a = r.applied.find(x => x.tag === e.tag);
      e.outboundTag = a ? a.outboundTag : null;
      e.gone = !!(a && a.gone);
      e.entryAddrs = a ? a.entryAddrs : [];
      if (e.gone) log(`Users: the config "${e.target}" no longer exists (removed, or replaced by a subscription update) — its users' devices ride the router's own connection until they get another`, 'warn');
    }
    return r;
  }

  /** What the gateway must keep off the tunnel for these configs: the first hop of each one built here. */
  function entryAddrs(tp) {
    const out = [];
    for (const e of Array.isArray(tp) ? tp : []) for (const a of (e && e.entryAddrs) || []) if (a && !out.includes(a)) out.push(a);
    return out;
  }

  /**
   * Right before the gateway starts (a connect): the decision for now, the
   * rule-set files written (sing-box refuses a start without them), and the
   * gateway's `lanUsers` option — { nft, singbox } — or null when the mode is
   * off: then the gateway's start options do not carry the key at all.
   */
  async function gatewayOptions(tp) {
    if (!openwrt) return null;
    builtOn = wanted();
    live = builtOn ? (Array.isArray(tp) ? tp : []).filter(e => e && e.outboundTag) : [];
    if (!builtOn) { lastDecision = null; return null; }
    lan = run ? await net.lanStatus(run) : lan;
    scan = await scanDevices({ readFile, run, lanIf: lan.device, now: now() });
    pruneSessions();
    const d = decideNow();
    lastFiles = {};
    removeStaleFiles();
    writeRuleSets(d.ruleSets);
    lastKey = plan.nftKey(d.nft, untilMap());
    prevCounters = {};
    prevGen = -1;
    return { nft: d.nft, singbox: { targets: live.map(e => ({ tag: e.tag, port: e.port, path: fileOf(e.tag) })) }, exclude: entryAddrs(live) };
  }

  /**
   * After the gateway came up: with the mode, the sign-in page and the ticks;
   * without it, only remembered (pendingReconnect: the mode turned on later).
   */
  async function gatewayUp(gateway) {
    if (!openwrt) return;
    // never a gateway failure: the tunnel is up, and the page or a tick can only be said
    try {
      gw = gateway && gateway.active ? gateway : null;
      if (!builtOn || !gw) { await serial(down); return; }
      tun = gateway;
      deviceBytes = {};
      clearInterval(timer);
      timer = setInterval(() => { tick().catch(() => {}); }, tickMs);
      if (timer.unref) timer.unref();
      const l = lu();
      log(`Users: every device is decided by MAC — ${live.length} user config(s) routed by the gateway, unassigned devices: ${l.transparent.unassigned}`, 'info');
      await serial(() => syncPortal());
    } catch (e) { log(`Users: ${e.message}`, 'warn'); }
  }

  /* ------------------------------ the ticks ------------------------------ */

  let chain = Promise.resolve();
  /** One at a time: a tick, a sign-in and a sign-out each read and replace the same table. */
  function serial(fn) {
    const p = chain.then(fn, fn);
    chain = p.catch(() => {});
    return p;
  }

  function untilMap() {
    const out = {};
    for (const [mac, s] of Object.entries(sessions)) out[mac] = s.until;
    return out;
  }

  function decideNow() {
    const l = lu();
    // the redirect's target: the LAN address the page listens on (no v4 LAN address: no redirect, the gate still holds)
    const portalAddr = l.transparent.unassigned === 'login' && lan.address ? { ip: lan.address, port: l.transparent.portalPort } : null;
    lastDecision = plan.decide({ lu: l, sessions, scan, usage: usageNow(), now: now(), tp: live, portal: portalAddr });
    return lastDecision;
  }

  function removeStaleFiles() {
    let names = [];
    try { names = fsx.readdirSync(ruleDir); } catch { return; }
    const keep = new Set(live.map(e => `${e.tag}.json`));
    for (const n of names) {
      if (!/^lu-tp-\d+\.json$/.test(n) || keep.has(n)) continue;
      try { fsx.unlinkSync(path.posix.join(ruleDir, n)); } catch { /* gone meanwhile */ }
    }
  }

  /** Each inbound's devices into its file — written only when it changed, by a rename sing-box's watch sees as one event. */
  function writeRuleSets(ruleSets) {
    for (const e of live) {
      const text = plan.ruleSetText(ruleSets[e.tag] || []);
      if (lastFiles[e.tag] === text) continue;
      const file = fileOf(e.tag);
      try {
        fsx.mkdirSync(ruleDir, { recursive: true });
        fsx.writeFileSync(file + '.tmp', text);
        fsx.renameSync(file + '.tmp', file);
        lastFiles[e.tag] = text;
      } catch (err) { log(`Users: the device list ${file} could not be written: ${err.message}`, 'error'); }
    }
  }

  /**
   * The table's counters since the last read, per device and per user, to
   * the meter. A table loaded since (by us or by an exclusions edit) counts
   * from zero again: then what it says is all new.
   */
  async function readCounters() {
    if (!tun || !tun.active || !run) return;
    let text;
    try { text = await run('nft', ['-j', 'list', 'table', 'inet', 'irnetfree']); } catch { return; }
    const cur = parseCounters(text);
    const fresh = tun.tableGen !== prevGen;
    const bound = (lastDecision && lastDecision.bound) || {};
    const byUser = {};
    const t = now();
    const secs = readAt ? (t - readAt) / 1000 : 0;
    // a second read in the same moment (the one before a table load) keeps the rates of the first
    if (secs > 0) { readAt = t; rates = {}; } else if (!readAt) readAt = t;
    const users = new Map(lu().users.map(u => [u.id, u]));
    for (const [mac, c] of Object.entries(cur)) {
      const p = fresh ? null : prevCounters[mac];
      const up = p && c.up >= p.up ? c.up - p.up : c.up;
      const down = p && c.down >= p.down ? c.down - p.down : c.down;
      if (secs > 0) rates[mac] = { up: Math.round(up / secs), down: Math.round(down / secs) };
      if (!up && !down) continue;
      const db = deviceBytes[mac] || (deviceBytes[mac] = { up: 0, down: 0 });
      db.up += up; db.down += down;
      const b = bound[mac];
      // this period's bytes per device (its user's period: a daily cap counts by the day), for the devices list
      const key = periodKey(b && users.get(b.userId) ? users.get(b.userId).quotaPeriod : 'month', t);
      const pu = devUsage[mac] && devUsage[mac].period === key ? devUsage[mac] : (devUsage[mac] = { period: key, bytes: 0 });
      pu.bytes += up + down;
      devUsageDirty = true;
      if (!b) continue;
      const u = byUser[b.userId] || (byUser[b.userId] = { up: 0, down: 0, bytes: 0 });
      u.up += up; u.down += down; u.bytes += up + down;
    }
    prevCounters = cur;
    prevGen = tun.tableGen;
    if (!Object.keys(byUser).length) return;
    if (meter && typeof meter.feedDevices === 'function') {
      try { meter.feedDevices(byUser); } catch (e) { log(`Users: the meter refused the devices' bytes: ${e.message}`, 'warn'); }
    } else if (!saidNoMeter) {
      saidNoMeter = true;
      log('Users: no users meter takes the devices’ bytes — the caps of users on transparent devices are not counted', 'warn');
    }
  }

  /** The decision into the files and the table — the files first, so a device let through already rides its config. */
  async function applyDecision(d) {
    writeRuleSets(d.ruleSets);
    const key = plan.nftKey(d.nft, untilMap());
    if (key === lastKey || !tun || !tun.active) return;
    await readCounters();          // what the table counted until now: the load starts its counters again
    await tun.setLanUsers(d.nft);
    lastKey = key;
    prevCounters = {};
    prevGen = tun.tableGen;
  }

  /** A user reaching its cap, and coming back at the new period, said once each. */
  function sayTransitions() {
    const usage = usageNow();
    const over = new Set(lu().users.filter(u => usage[u.id] && usage[u.id].over).map(u => u.id));
    for (const id of over) if (!overSaid.has(id)) log(`Users: "${nameOf(id)}" reached its data cap — its devices are held until the new period`, 'warn');
    for (const id of overSaid) if (!over.has(id)) log(`Users: "${nameOf(id)}" has data again — its devices are back`, 'info');
    overSaid = over;
  }

  async function syncPortal() {
    const l = lu();
    const host = portalListen ? portalListen.host : lan.address;
    const port = portalListen ? portalListen.port : l.transparent.portalPort;
    const want = !!(builtOn && tun && tun.active && l.transparent.unassigned === 'login' && host);
    const at = want ? `${host}:${port}` : null;
    if (portal && at === portalAt) return;
    if (portal) { const p = portal; portal = null; portalAt = null; await p.stop(); }
    if (!want) return;
    const s = getSettings();
    if (!portalListen && [s.socksPort, s.httpPort, s.apiPort].map(Number).includes(port)) {
      if (saidPort !== port) log(`Users: the sign-in page's port ${port} is one of the app's own — choose another under Users`, 'error');
      saidPort = port;
      return;
    }
    const p = portalFactory({ host, port, api: portalApi, now, log });
    try {
      const where = await p.start();
      portal = p;
      portalAt = at;
      log(`Users: the sign-in page is on http://${where.host}:${where.port}`, 'info');
    } catch (e) { log(`Users: the sign-in page could not listen on ${host}:${port}: ${e.message}`, 'error'); }
  }

  async function down() {
    saveDevUsage(true);
    rates = {};
    clearInterval(timer);
    timer = null;
    tun = null;
    if (gw && !gw.active) gw = null;
    if (portal) { const p = portal; portal = null; portalAt = null; await p.stop(); }
  }

  async function tickBody() {
    if (!tun || !tun.active || !builtOn) return down();
    await readCounters();
    scan = await scanDevices({ readFile, run, lanIf: lan.device, now: now() });
    pruneSessions();
    await applyDecision(decideNow());
    sayTransitions();
    saveDevUsage();
    await syncPortal();
  }

  function tick() {
    return serial(() => tickBody().catch((e) => log(`Users: ${e.message}`, 'warn')));
  }

  /* ------------------------------ the portal's questions ------------------------------ */

  function statusOf(mac) {
    const l = lu();
    const b = plan.bindingsOf(l, sessions, now())[mac];
    if (!b) return null;
    const user = l.users.find(u => u.id === b.userId);
    if (!user) return null;
    const usage = usageNow();
    const u = usage[user.id] || null;
    return {
      name: String(user.name || ''), username: String(user.username || ''), via: b.via, until: b.until || 0,
      held: plan.inactiveReason(user, { now: now(), usage }),
      usage: u ? { bytes: Number(u.bytes) || 0, quotaBytes: Number(u.quotaBytes) || 0 } : null
    };
  }

  const portalApi = {
    async macOf(ip) {
      let mac = macOfIp(scan, ip);
      if (!mac) {
        // a device that arrived since the last tick: asked again before it is called unknown
        scan = await scanDevices({ readFile, run, lanIf: lan.device, now: now() });
        mac = macOfIp(scan, ip);
      }
      return mac;
    },
    async statusOf(mac) { return statusOf(mac); },
    signIn({ mac, username, password }) {
      return serial(async () => {
        const l = lu();
        if (!builtOn || l.transparent.unassigned !== 'login') return { ok: false, code: 'off' };
        const r = plan.judgeSignIn({ lu: l, sessions, usage: usageNow(), now: now(), mac, username, password, checkPassword });
        if (!r.ok) {
          log(`Users: a sign-in from ${mac} was refused (${r.code})`, 'info');
          return r;
        }
        sessions[mac] = { userId: r.user.id, until: now() + l.transparent.sessionHours * 3600000, at: now() };
        saveSessions();
        log(`Users: ${mac} signed in as "${r.user.username}" for ${l.transparent.sessionHours} h`, 'info');
        await applyDecision(decideNow());   // now, not at the next tick: the device is waiting on the page
        return { ok: true, status: statusOf(mac) };
      });
    },
    signOut(mac) {
      return serial(async () => {
        if (!sessions[mac]) return false;
        delete sessions[mac];
        saveSessions();
        log(`Users: ${mac} signed out`, 'info');
        await applyDecision(decideNow());
        return true;
      });
    }
  };

  /* ------------------------------ for the users' IPC ------------------------------ */

  /** The devices as the router sees them: { [mac]: { ip, ips, hostname, online, userId, via, until, held, bytes } }. */
  function online() {
    const d = lastDecision;
    const bound = d ? d.bound : plan.bindingsOf(lu(), sessions, now());
    const out = {};
    const row = (mac, r) => {
      const b = bound[mac] || null;
      out[mac] = {
        ip: (r && r.ip) || '', ips: r && Array.isArray(r.ips) ? r.ips.slice() : [], hostname: (r && r.hostname) || '', online: !!(r && r.online),
        userId: b ? b.userId : '', via: b ? b.via : '', until: (b && b.until) || 0,
        held: (d && d.held[mac]) || null, bytes: Object.assign({ up: 0, down: 0 }, deviceBytes[mac]),
        // bytes/s over the last read of the counters (the Users page's live column)
        up: (rates[mac] && rates[mac].up) || 0, down: (rates[mac] && rates[mac].down) || 0
      };
    };
    for (const r of scan) row(r.mac, r);
    for (const mac of Object.keys(bound)) if (!out[mac]) row(mac, null);
    return out;
  }

  /**
   * `{ [mac]: bytes this period }` for the devices list (lanusers:get's
   * `deviceUsage`): each device in its user's period, a past period's count
   * left out — it is a new period's zero.
   */
  function deviceUsage() {
    const users = new Map(lu().users.map(u => [u.id, u]));
    const bound = plan.bindingsOf(lu(), sessions, now());
    const out = {};
    for (const [mac, v] of Object.entries(devUsage)) {
      const b = bound[mac];
      const key = periodKey(b && users.get(b.userId) ? users.get(b.userId).quotaPeriod : 'month', now());
      if (v.period === key) out[mac] = v.bytes;
    }
    return out;
  }

  /**
   * Does the running gateway need a reconnect for the users' changes: the
   * mode turned on or off, or the set of configs users have changed (a new
   * one needs its inbound and its sing-box outbound). Who has which config,
   * blocks, sign-ins, the unassigned policy, the session hours, the page's
   * port: all live.
   */
  function pendingReconnect() {
    if (!openwrt || !gw || !gw.active) return false;   // no gateway up: the next connect builds it as the users are then
    const want = wanted();
    if (want !== builtOn) return true;
    if (!want) return false;
    return JSON.stringify(plan.routedTargets(lu())) !== JSON.stringify(live.map(e => e.target).sort());
  }

  /** After an edit of users or devices: applied now rather than at the next tick. */
  function refresh() {
    if (!tun || !tun.active || !builtOn) return Promise.resolve();
    return tick();
  }

  return {
    prepare, applyXray, entryAddrs, gatewayOptions, gatewayUp, refresh, online, pendingReconnect, deviceUsage,
    setMeter(m) { meter = m || null; saidNoMeter = false; },
    stop: () => serial(down),
    /** For the tests: one tick now, and what the last one decided. */
    tick, get decision() { return lastDecision; }, get portal() { return portal; }, get sessions() { return Object.assign({}, sessions); }
  };
}

module.exports = { createLanRouter, TICK_MS, SESSIONS_FILE };
