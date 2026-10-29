'use strict';
/**
 * Users and devices («کاربران», module `lanUsers`): the channels the window
 * talks through, the build's input, the meter's feed and the router's hooks —
 * one module for the desktop (main.js, over ipcMain and the preload) and the
 * router (service.js, over its invoke table and web-api.js).
 *
 *   lanusers:get    → { ok, config, users, devices, usage, live, online, deviceUsage, platform, lanAddresses }
 *   lanusers:config (a part of the config, nested: { proxy: { enabled } }) → that + { pendingReconnect }
 *   lanusers:user   ({ op: 'add', user } — no id, one is made; { op: 'update', user } — the whole
 *                   user, or a part with its id; { op: 'delete', user: { id } };
 *                   { op: 'topUp', user: { id }, kind, period, gb } — more of that limit for its
 *                   current period only (meter.js topUp); { op: 'resetUsage', user: { id } } — the
 *                   user's current periods back to nothing, the history kept; both answer a
 *                   request of theirs;
 *                   v1.40: { op: 'vouchers', batch: { count 1–200, hours 0–8760, gb (0: none), target,
 *                   routing, maxDevices (default 1), name (the batch's label), speed? } } — `count`
 *                   one-time cards (model.js: a voucher is a user whose username and password are its
 *                   code), answered with `batch: { id, codes }`; { op: 'deleteBatch', batch: { id },
 *                   unused } — that batch's cards (only the never used ones when `unused`), their usage
 *                   forgotten, answered with `removed`; { op: 'dismissRequest', user: { id } })
 *                                                                    → that + { pendingReconnect, id }
 *   lanusers:device ({ mac, userId?, blocked?, name? })              → that + { pendingReconnect }
 *   lanusers:backup () → { ok, bundle } — the Users module alone: { kind: 'irnetfree-lanusers',
 *                   version: 1, at, app, platform, lanUsers: <the store's record, passwords and all>,
 *                   meter: <meter.js exportState()> }
 *   lanusers:restore ({ bundle, mode: 'merge' | 'replace' }) → that + { pendingReconnect, added: { users,
 *                   devices, vouchers }, updated: { users, devices }, skipped: { users } } — merge: a
 *                   user by id (updated), else new (added) unless their username is another's here
 *                   (skipped: this machine's is kept), a device by MAC, the config this machine's (the
 *                   backup's on a machine that had none), the usage the larger count; replace: the
 *                   record as given (its config only if its ports are free here), their usage the
 *                   backup's, the users it lacks forgotten
 *
 * The router's hooks (what registerLanUsers returns; service.js hands them to
 * router/index.js through setMeter): assignDevice — a device that signed in
 * as a user who has `remember` on becomes theirs; activateVoucher — a card's
 * first sign-in starts it; request — a top-up asked for on the status page.
 * A voucher's first bytes anywhere (meter.js onFirstUse) start it too.
 *
 * `usage`: meter.js's usage(), per user — the fields of before (bytes, period,
 * since, until, quotaBytes, over: the mirror cap's) and v1.39's meters (each
 * kind × day / month / one-off), hold / why / holdUntil, the 30-day history and
 * the speed; `users` carry limits / routing / schedule / speed / speedHours
 * (model.js); `live`: bytes/s per user while
 * connected; `online` (router): { [mac]: { ip, hostname, userId, up?, down? } }
 * of the devices answering now, {} on the desktop; `deviceUsage` (router):
 * { [mac]: bytes } this period; `platform`: 'openwrt' on the router, 'desktop'
 * elsewhere; `lanAddresses`: where people point their proxy at; `portal`
 * (router, transparent mode): where its sign-in page is — { url, name?,
 * nameUrl? } while it is up, null while not.
 *
 * A refusal saves nothing and answers `ok: false` and `error`, a code the page
 * words as 'lu.err.<code>': a user's (model.validateUserDetail — quotaPeriod,
 * quotaCalendar and quotaResetDay come as quota, `detail` says which; limits,
 * routing, schedule and speed with their `detail`, model.js lists them; a
 * routing profile that is not there is routing / profile), port
 * (bad, clashing or one the app already uses; `detail` says
 * which), hours, unassigned, notFound, op, mac, user, maxDevices, topUp
 * (`detail` limit — the user has no such limit — or gb); v1.40's filter,
 * priority and voucher (model.js), batch (`detail` count | hours | gb | name
 * | codes), portal (note | contact | requests), shaping (down | up | smooth)
 * and backup (kind | version | shape).
 *
 * `pendingReconnect`: [] — the running core already lets in, and routes, what
 * the store says (or nothing runs); true — it does not, and it is being
 * rebuilt: ONE reload (queueReload) a moment after the last of a run of edits,
 * as the multi-internet caps apply theirs; the keys waiting for Apply — other
 * settings are pending and the reload waits for them (a rebuild would take some
 * of them live), said once in the log. A change made while the core was busy
 * (a connect, a recovery) is picked up by the next stats tick.
 *
 * main.js / service.js put forBuild()'s answer into the build settings as
 * `lanUsers` (next to multiWanSkip) and feed tick(vars) next to the
 * multi-internet quota. Nothing here runs a command on its own but the
 * firewall's netsh on Windows (firewall.js) and the router's address and
 * device reads (`run`, the router's command runner).
 */
const os = require('os');
const model = require('./model');
const { createLanUsersMeter } = require('./meter');
const { profileTargets } = require('./xray');
const { migrateProfiles } = require('../../main/routingProfiles');
const { createFirewall } = require('./firewall');
const { recordsForTargets } = require('../../main/targetOutbounds');
const { wgEndpointHosts } = require('../../main/configBuilder');
const { lanStatus } = require('../../main/openwrtNet');
const { isOwnTunInterface } = require('../../main/tunPlatform');
const { dayText } = require('../../main/jalali');

const CHANNELS = ['lanusers:get', 'lanusers:config', 'lanusers:user', 'lanusers:device', 'lanusers:backup', 'lanusers:restore'];
/** A run of edits (a user added, then another) is one reload this long after the last. */
const RELOAD_DELAY_MS = 600;
/** The router's hooks (a sign-in, a card's first use) apply their change at most this often: a run of them is one look. */
const HOOK_DELAY_MS = 300;
/** The most cards one batch makes. */
const BATCH_MAX = 200;
/** The Users module's own backup file. */
const BACKUP_KIND = 'irnetfree-lanusers';
const BACKUP_VERSION = 1;
/** A change the core could not take when it was made is asked again no sooner than this. */
const RETRY_MS = 15000;
/** The router's LAN address is read again after this long. */
const LAN_TTL_MS = 60000;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
/** A moment as the log says it, local time: '2026-10-29 18:05'. */
const localText = (ms) => { const d = new Date(ms); const p = (n) => String(n).padStart(2, '0'); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`; };
const TUN_LOCAL_IP = '10.255.0.2';   // the app's own TUN adapter — never a LAN address
/** The address Windows gives its Mobile Hotspot (Internet Connection Sharing's): where the people the accounts are for connect. */
const { HOTSPOT_IP } = require('./hotspot');

/**
 * This machine's LAN IPv4 addresses: the Windows hotspot's first, then the
 * usual home/office ranges (as main.js lanIp ranks them). Never one of the
 * app's own TUN adapters: sing-box's (172.19.0.1, on the adapter it names
 * IRNetFree) was offered as an address to give people, and no device can
 * reach it.
 */
function lanCandidates(ifs) {
  const all = ifs || os.networkInterfaces();
  const out = [];
  for (const name of Object.keys(all || {})) {
    if (isOwnTunInterface(name)) continue;
    for (const ni of all[name] || []) {
      if (!ni || (ni.family !== 'IPv4' && ni.family !== 4) || ni.internal) continue;
      if (ni.address === TUN_LOCAL_IP || ni.address.startsWith('169.254.')) continue;
      if (!out.includes(ni.address)) out.push(ni.address);
    }
  }
  const score = (a) => (a === HOTSPOT_IP ? 4 : a.startsWith('192.168.') ? 3 : /^172\.(1[6-9]|2\d|3[01])\./.test(a) ? 2 : a.startsWith('10.') ? 1 : 0);
  return out.sort((x, y) => score(y) - score(x));
}
const isPrivate = (a) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(a);

/** The router's devices module (USERS-ROUTER), whatever it calls its read; null when there is none. */
function devicesModule() {
  try { return require('./router/devices'); } catch { return null; }
}

/** A list or a map of devices → { [mac]: { ip, hostname } } of the ones answering now. */
function onlineMap(list) {
  const out = {};
  const rows = Array.isArray(list) ? list : (isObj(list) ? Object.entries(list).map(([mac, d]) => Object.assign({ mac }, d)) : []);
  for (const d of rows) {
    if (!isObj(d) || d.online === false) continue;
    const mac = model.normalizeMac(d.mac);
    if (!mac) continue;
    out[mac] = { ip: typeof d.ip === 'string' ? d.ip : '', hostname: typeof d.hostname === 'string' ? d.hostname : (typeof d.name === 'string' ? d.name : '') };
  }
  return out;
}

/**
 * @param {object} o
 *   handle(channel, fn)   the desktop's ipcMain registration (fn takes the argument); the
 *                         router spreads `.handlers` into its invoke table instead
 *   store                 the main store (the `lanUsers` key; servers, groups, chains for the targets)
 *   getSettings()         the settings (`modules.lanUsers`, `lang`, the app's own ports)
 *   usageStore            the usage file (`lanUsersUsage`, beside the per-config totals)
 *   platform              'desktop' | 'router' | 'server' (a headless service on a plain Linux)
 *   running()             connected now, with a core of ours up
 *   canReload()           connected and quiet (no connect, recovery or disconnect in flight)
 *   pending()             the keys waiting for Apply
 *   queueReload(why)      → Promise<boolean>: the one reload queue
 *   run(cmd, args)        the router's command runner (its LAN address over ubus, the device list)
 *   resolveHost(name, o)  trustedDns.resolveHost's shape: a user's WireGuard endpoint name → { ips }
 *   devices()             → the devices answering now (default: router/devices.js) — a test's fake
 *   transparentInbounds(lu) → [{ tag | n, port, target }]: the router's transparent mode (USERS-ROUTER)
 *   onChange(lu, what)    after every saved change ('config' | 'user' | 'device') — the router's nft
 *   deviceUsage()         → { [mac]: bytes this period } — the router's own count (default: this meter's)
 *   firewall              { sync(ports | null) } (default: firewall.js on Windows' desktop)
 *   portal()              → { url, name?, nameUrl? } | null (router/index.js portalInfo): the payload's
 *                         `portal`, the router's alone
 *   hotspot               { read() } (hotspot.js, a Windows desktop's alone): the payload's
 *                         `hotspot` — the devices on the PC's hotspot and whether the tunnel saw them
 *   shaper()              → { mode, missing, line } | null (router/index.js shaperInfo): the payload's
 *                         `shaper`, the router's alone
 *   appVersion            the app's version, written into a backup
 *   randomBytes(n)        the voucher codes' random source (default crypto.randomBytes) — a test's own
 *   log({ line, level }), notify(text), now()
 * → { handlers, forBuild(buildSettings, more?), tick(vars), statsLive, addBytes, tickDevices, overIds, holds, speeds, activeUsers, payload, flush, meter,
 *     assignDevice({ mac, userId, name }), activateVoucher(userId), request(userId, { mac }) }
 */
function registerLanUsers(o) {
  const opts = o || {};
  const store = opts.store;
  const getSettings = typeof opts.getSettings === 'function' ? opts.getSettings : () => ({});
  const platform = opts.platform || 'desktop';
  const log = typeof opts.log === 'function' ? opts.log : () => {};
  const now = typeof opts.now === 'function' ? opts.now : () => Date.now();
  const usageStore = opts.usageStore || null;
  const running = typeof opts.running === 'function' ? opts.running : () => false;
  const canReload = typeof opts.canReload === 'function' ? opts.canReload : running;
  const pending = typeof opts.pending === 'function' ? opts.pending : () => [];
  const queueReload = typeof opts.queueReload === 'function' ? opts.queueReload : async () => false;
  const firewall = opts.firewall || (platform === 'desktop' ? createFirewall({ log }) : null);
  const isEn = () => (getSettings() || {}).lang === 'en';

  const read = () => model.normalizeLanUsers(store.get('lanUsers', null));
  const write = (lu) => store.set('lanUsers', lu);
  const installed = () => { const s = getSettings() || {}; return !!(s.modules && s.modules.lanUsers); };

  /* ------------------------------ one reload ------------------------------ */
  let reloadTimer = null;
  let reloadWhy = '';
  let waiters = [];
  /** A reload a moment from now; every ask until then is the same one. → Promise<boolean> (never rejects). */
  function requestReload(why, delay) {
    reloadWhy = why || reloadWhy;
    return new Promise((resolve) => {
      waiters.push(resolve);
      if (reloadTimer) return;
      reloadTimer = setTimeout(async () => {
        reloadTimer = null;
        const done = waiters;
        waiters = [];
        let r = false;
        try { r = canReload() ? !!(await queueReload(reloadWhy)) : false; }
        catch (e) { log({ line: 'Users: the reload failed — ' + ((e && e.message) || e), level: 'warn' }); }
        for (const w of done) w(r);
      }, delay == null ? RELOAD_DELAY_MS : delay);
      if (reloadTimer.unref) reloadTimer.unref();
    });
  }

  /**
   * The limit notice (meter.js notify): a monthly limit says the day it
   * renews, as their month has it — '1 آذر' in Persian. A total limit reached
   * reads as the cap notice always has; a VPN or direct one says which half
   * still works; 80 % says what is left; a 'slow' one says it slowed.
   */
  const noticeText = (n) => {
    const day = n.period === 'day';
    const all = n.period === 'none';
    const en = isEn();
    const kind = n.kind === 'vpn' || n.kind === 'direct' ? n.kind : 'total';
    const date = day || all ? '' : dayText(n.until, en ? 'en' : 'fa', n.calendar);
    const untilEn = day ? 'until tomorrow' : (all ? 'until it is raised' : (date ? 'until ' + date : 'until next month'));
    const untilFa = day ? 'تا فردا' : (all ? 'تا وقتی سقف بالا برود' : (date ? 'تا ' + date : 'تا ماه بعد'));
    const perEn = day ? ' daily' : (all ? '' : ' monthly');
    const perFa = day ? 'روزانه' : (all ? '' : 'ماهانه');
    const kindEn = kind === 'vpn' ? ' VPN' : (kind === 'direct' ? ' direct' : '');
    const kindFa = kind === 'vpn' ? 'VPN' : (kind === 'direct' ? 'مستقیم' : '');
    // «۱ گیگابایتِ روزانه» / «… روزانهٔ VPN» / «… کل»
    const whatFa = kind === 'total' ? (perFa || 'کل') : (perFa ? perFa + 'ٔ ' + kindFa : kindFa);
    const left = Math.round(((Number(n.leftBytes) || 0) / 1024 ** 3) * 100) / 100;
    const rate = (k) => (k >= 1000 ? Math.round(k / 100) / 10 + ' Mbps' : k + ' kbps');
    if (Number(n.pct) > 0 && n.pct < 100) {
      return en
        ? `“${n.name}” has used 80% of their ${n.capGb} GB${perEn}${kindEn} limit — ${left} GB left`
        : `«${n.name}» 80٪ از سقف ${n.capGb} گیگابایتِ ${whatFa} را مصرف کرده — ${left} گیگابایت مانده`;
    }
    if (n.action === 'slow') {
      const speed = [n.down ? '↓' + rate(n.down) : '', n.up ? '↑' + rate(n.up) : ''].filter(Boolean).join(' ');
      return en
        ? `“${n.name}” used their ${n.capGb} GB${perEn}${kindEn} allowance — slowed to ${speed} ${untilEn}`
        : `«${n.name}» سهمیهٔ ${n.capGb} گیگابایتِ ${whatFa} را مصرف کرد — سرعتش ${untilFa} کم شد (${speed})`;
    }
    if (kind === 'vpn' && n.hold !== 'all') {
      return en
        ? `“${n.name}” reached their ${n.capGb} GB${perEn} VPN cap — the VPN is off ${untilEn}; direct sites still work`
        : `«${n.name}» به سقف ${n.capGb} گیگابایتِ ${whatFa} رسید — VPN ${untilFa} قطع است؛ سایت‌های مستقیم کار می‌کنند`;
    }
    if (kind === 'direct' && n.hold !== 'all') {
      return en
        ? `“${n.name}” reached their ${n.capGb} GB${perEn} direct cap — direct sites are off ${untilEn}; the VPN still works`
        : `«${n.name}» به سقف ${n.capGb} گیگابایتِ ${whatFa} رسید — ترافیک مستقیم ${untilFa} قطع است؛ VPN کار می‌کند`;
    }
    return en
      ? `“${n.name}” reached their ${n.capGb} GB${perEn}${kindEn} cap — off ${untilEn}`
      : `«${n.name}» به سقف ${n.capGb} گیگابایتِ ${whatFa} رسید — ${untilFa} قطع است`;
  };

  const meter = createLanUsersMeter({
    usage: usageStore ? usageStore.get('lanUsersUsage', {}) : {},
    usage2: usageStore ? usageStore.get('lanUsersUsage2', null) : null,
    history: usageStore ? usageStore.get('lanUsersHistory', {}) : {},
    months: usageStore ? usageStore.get('lanUsersMonths', null) : null,
    requests: usageStore ? usageStore.get('lanUsersRequests', {}) : {},
    deviceUsage: usageStore ? usageStore.get('lanDeviceUsage', {}) : {},
    users: () => store.get('lanUsers', null),
    canReload, pending,
    reload: (why) => requestReload(why, 0),
    log,
    notify: typeof opts.notify === 'function' ? (n) => opts.notify(noticeText(n)) : null,
    now,
    // the router's routing '' is its own, which sends some traffic direct: a VPN limit there stops the VPN only
    baseHasDirect: platform === 'router',
    // a card's first bytes (a desktop's proxy account, a router's device): started once — after the tick, never inside it
    onFirstUse: (id) => { Promise.resolve().then(() => activateVoucher(id)).catch((e) => log({ line: 'Users: a voucher could not be started — ' + ((e && e.message) || e), level: 'warn' })); }
  });

  /* ------------------------------ where the proxy listens ------------------------------ */
  let lanRead = { at: -Infinity, address: '' };
  /** The router's LAN address (ubus), cached; '' when it cannot be read. */
  async function routerLan(fresh) {
    if (!fresh && now() - lanRead.at < LAN_TTL_MS) return lanRead.address;
    let address = '';
    try { address = (await lanStatus(opts.run)).address || ''; } catch { address = ''; }
    lanRead = { at: now(), address };
    return address;
  }
  /** Where people point their proxy at. */
  async function lanList() {
    if (platform === 'router') { const a = await routerLan(false); return a ? [a] : []; }
    return lanCandidates();
  }
  /**
   * The address the users' proxy binds. The desktop: every address, as LAN
   * sharing binds — the Wi-Fi's and the hotspot's at once (the firewall keeps it
   * to the local subnet). The router: its LAN address, never the WAN side. A
   * headless service elsewhere: its first private address — never every one of
   * a machine on the open internet. '' when there is none: no proxy this time.
   */
  async function listenAddress() {
    if (platform === 'desktop') return '0.0.0.0';
    if (platform === 'router') return routerLan(true);
    return lanCandidates().find(isPrivate) || '';
  }

  /* ------------------------------ the build ------------------------------ */
  let lastListen = '';
  let lastTp = [];
  let lastRouterTp = [];   // the router's own transparent inbounds (forBuild's `routerTp`), copied
  let liveSig = null;   // what the running core was built with (forBuild's), null: nothing built in this process
  let lastAsk = -Infinity;
  const saidOnce = new Set();
  const once = (key, line, level) => { if (saidOnce.has(key)) return; saidOnce.add(key); log({ line, level: level || 'warn' }); };

  /** The records the targets name, as buildPlan makes them: groups as records beside the servers; a chain that lost a member is null (targetOutbounds.js). */
  function recordsFor(targets) {
    return recordsForTargets(targets, { servers: store.get('servers', []), groups: store.get('groups', []), chains: store.get('chains', []) });
  }

  /** The WireGuard endpoint names of those records, resolved — a name that does not resolve is left out (xray.js then blocks that user rather than risk the core). */
  const wgCache = new Map();
  async function resolveWg(records) {
    const hosts = wgEndpointHosts({ mode: 'pool', serversById: records.serversById, chainsById: records.chainsById });
    const map = {};
    if (!hosts.length || typeof opts.resolveHost !== 'function') return map;
    const s = getSettings() || {};
    await Promise.all(hosts.map(async (h) => {
      let ip = '';
      try {
        const r = await opts.resolveHost(h, { ipv6: !!s.ipv6, doh: s.dnsRemote });
        ip = (r && Array.isArray(r.ips) && r.ips[0]) || '';
      } catch { ip = ''; }
      if (ip) wgCache.set(h, ip);
      else ip = wgCache.get(h) || '';
      if (ip) map[h] = ip;
      else once('wg:' + h, `Users: the WireGuard endpoint ${h} of a user's config does not resolve — that user is blocked until it does`);
    }));
    return map;
  }

  /** Who may use the proxy now, by the meter's holds. */
  function activeNow(lu, t) {
    return model.activeUsers(lu, { now: t == null ? now() : t, over: meter.overIds() });
  }

  /**
   * The routing profiles as the store has them (routingProfiles.migrateProfiles,
   * never written here) — what the signature reads, so a build and the check
   * after it always compare the same thing.
   */
  function profilesNow() {
    try { return migrateProfiles({ stored: store.get('routingProfiles', null), settings: getSettings() || {} }).profiles; } catch { return []; }
  }

  /** The users whose rules a build writes: the active ones (the accounts), then the transparent inbounds' users. */
  function routedOf(lu, active, tp) {
    const out = active.slice();
    for (const e of Array.isArray(tp) ? tp : []) {
      const u = e && typeof e.userId === 'string' ? lu.users.find((x) => x.id === e.userId) : null;
      if (u && !out.some((x) => x.id === u.id)) out.push(u);
    }
    return out;
  }

  /** A hold the core must apply itself: 'vpn' | 'direct' (an 'all' one keeps the user out of the accounts instead), else null. */
  const partOf = (h) => (h && (h.hold === 'vpn' || h.hold === 'direct') ? h.hold : null);

  /** What a build would let in and where to, as one string: a difference is a reload. */
  function signature(on, lu, listen, tp, t) {
    if (!on) return 'off';
    const proxyOn = lu.config.proxy.enabled && !!listen;
    if (!proxyOn && !tp.length) return 'off';
    const holds = meter.holds();
    const active = proxyOn ? activeNow(lu, t) : [];
    const routed = routedOf(lu, active, tp);
    const users = active.map((u) => [u.id, u.username, u.password, u.target]);
    // v1.39: each routed user's config, routing and partial hold, and the profiles they ride as they are now
    // (the config too: a router's transparent inbound is its user's, so a new config is a reload);
    // v1.40: and their filter — its rules are theirs in the config (xray.js)
    const routes = routed.map((u) => [u.id, u.target, u.routing, partOf(holds[u.id]), u.filter || null]);
    const profiles = profilesNow();
    const used = [...new Set(routed.map((u) => model.profileIdOf(u.routing)).filter(Boolean))].sort()
      .map((id) => { const p = profiles.find((x) => x && x.id === id); return [id, p ? Object.assign({}, p, { name: null }) : null]; });   // a rename changes no config
    return JSON.stringify([proxyOn ? listen : '', proxyOn ? lu.config.proxy : null, users, tp, routes, used]);
  }
  const currentSig = () => signature(installed(), read(), lastListen, lastTp.concat(lastRouterTp));

  /**
   * The build's `settings.lanUsers` (xray.js says what each part is for), or
   * null — not installed, or nothing on: the builder then leaves the config as
   * it always was. Called right before every build (the connect and every
   * reload) with the settings that build uses — whether the module is
   * installed is theirs to say; what it hands is what the running core is
   * held to.
   *
   * `more` (optional): { routingProfiles — the app's routing profiles, as the
   * caller keeps them (default: the store's, migrated); geo — whether
   * geoip.dat / geosite.dat are there (absent: not said, and the builder's own
   * geoAssets decides); routerTp — the router's own transparent inbounds
   * ([{ tag, port, userId, target }], router/index.js tpFor), which it writes
   * into the config itself (router/xrayTargets.js, after the build): their
   * users count as routed here — their holds, the profiles they ride, the
   * reload signature, the meter's scope — but are not in the answer's `tp`,
   * so the builder adds nothing for them }. main.js hands the first two; the
   * router's service all three.
   */
  async function forBuild(buildSettings, more) {
    const extra = isObj(more) ? more : {};
    try {
      const raw = store.get('lanUsers', null);
      const lu = model.normalizeLanUsers(raw);
      const bs = isObj(buildSettings) ? buildSettings : (getSettings() || {});
      const on = !!(bs.modules && bs.modules.lanUsers);
      const proxyOn = on && lu.config.proxy.enabled;
      // a store that never had users never touches the firewall
      if (firewall && raw != null) firewall.sync(proxyOn ? lu.config.proxy : null);
      let tp = [];
      if (on && typeof opts.transparentInbounds === 'function') {
        try { tp = await opts.transparentInbounds(lu) || []; } catch (e) { log({ line: 'Users: the transparent mode’s inbounds could not be read — ' + ((e && e.message) || e), level: 'warn' }); }
      }
      lastTp = Array.isArray(tp) ? tp : [];
      // a copy: the router marks its entries up after the build (their outbound), which is no change of the users'
      lastRouterTp = on && Array.isArray(extra.routerTp)
        ? extra.routerTp.filter((e) => isObj(e) && typeof e.tag === 'string').map((e) => ({ tag: e.tag, port: e.port, userId: e.userId || '', target: e.target || '' }))
        : [];
      const allTp = lastTp.concat(lastRouterTp);
      lastListen = proxyOn ? await listenAddress() : '';
      if (proxyOn && !lastListen) once('nolisten', platform === 'router'
        ? 'Users: the router’s LAN address could not be read — the users’ proxy is off until it can be'
        : 'Users: this machine has no private network address — the users’ proxy is off');
      const t = now();
      liveSig = signature(on, lu, lastListen, allTp, t);
      if (liveSig === 'off') { meter.built(null); return null; }
      const over = meter.overIds();
      const holdsNow = meter.holds();
      const active = proxyOn && lastListen ? activeNow(lu, t) : [];
      const routed = routedOf(lu, active, allTp);
      // the routing profiles the routed users ride — one that is gone is their routing '' (said once)
      const profiles = Array.isArray(extra.routingProfiles) ? extra.routingProfiles : profilesNow();
      const profilesById = {};
      for (const u of routed) {
        const pid = model.profileIdOf(u.routing);
        if (!pid || profilesById[pid]) continue;
        const p = profiles.find((x) => x && x.id === pid);
        if (p) profilesById[pid] = p;
        else once('profile:' + u.id + ':' + pid, `Users: the routing profile of “${u.name || u.username}” no longer exists — all of their traffic goes to their config until another routing is picked`);
      }
      const viaProfiles = [].concat(...Object.values(profilesById).map(profileTargets));
      const targets = [...new Set(active.map((u) => u.target).concat(lastTp.map((e) => (e && e.target) || ''), viaProfiles))];
      const records = recordsFor(targets);
      for (const u of active) {
        const tg = u.target;
        const gone = tg && tg !== 'direct' && tg !== 'block' && (tg.indexOf('chain:') === 0 ? !records.chainsById[tg.slice('chain:'.length)] : !records.serversById[tg]);
        if (gone) once('gone:' + u.id + ':' + tg, `Users: the config of “${u.name || u.username}” no longer exists (removed, or replaced by a subscription update) — blocked until another is picked`);
      }
      const wgEndpointIps = await resolveWg(records);
      // the holds the core applies itself (a class blocked); an 'all' one is `over`
      const holds = {};
      for (const u of routed) { const h = partOf(holdsNow[u.id]); if (h) holds[u.id] = h; }
      meter.built({
        active: active.map((u) => u.id), over, byName: Object.fromEntries(active.map((u) => [u.username, u.id])),
        holds: holdsNow, scope: routed.map((u) => u.id), proxy: !!(proxyOn && lastListen)
      });
      return Object.assign({
        config: lu.config, users: lu.users, devices: lu.devices, over, holds, profilesById, now: t, listen: lastListen,
        serversById: records.serversById, chainsById: records.chainsById, wgEndpointIps, tp: lastTp
      }, typeof extra.geo === 'boolean' ? { geo: extra.geo } : {});
    } catch (e) {
      log({ line: 'Users: the users’ proxy could not be prepared — ' + ((e && e.message) || e), level: 'warn' });
      meter.built(null);
      return null;
    }
  }

  /**
   * The running core is behind the store: one reload, unless other settings
   * wait for Apply (said once). → what the window passes on as
   * `pendingReconnect`: [] nothing to do; true a reload is under way; the
   * keys waiting for Apply — the reload that takes them takes this too.
   */
  function catchUp(why) {
    if (liveSig === null || !running() || currentSig() === liveSig) return [];
    const keys = pending();
    if (keys.length) {
      once('pending:' + currentSig(), 'Users: your change waits for the pending settings — apply them (or reconnect) and the core reloads', 'info');
      return keys.slice();
    }
    lastAsk = now();
    requestReload(why || 'Users: the core reloaded with the users’ changes');
    return true;
  }

  /* ------------------------------ the window's answer ------------------------------ */
  async function online() {
    if (platform !== 'router') return {};
    let list = [];
    try {
      if (typeof opts.devices === 'function') list = await opts.devices();
      else {
        const dev = devicesModule();
        const fn = dev && (dev.onlineDevices || dev.listDevices || dev.devices || dev.lanDevices);
        list = typeof fn === 'function' ? await fn({ run: opts.run }) : [];
      }
    } catch { list = []; }
    const map = onlineMap(list);
    const bound = new Map(read().devices.map((d) => [d.mac, d.userId]));
    const rates = meter.deviceRates();
    for (const [mac, d] of Object.entries(map)) {
      d.userId = bound.get(mac) || '';
      if (rates[mac]) Object.assign(d, rates[mac]);   // bytes/s, while the transparent mode counts it
    }
    return map;
  }

  async function payload(extra) {
    const lu = read();
    const [on, lans] = await Promise.all([online().catch(() => ({})), lanList().catch(() => [])]);
    // a Windows desktop's hotspot check: only where main.js hands one in, so every other payload is as it was
    const hotspot = opts.hotspot && typeof opts.hotspot.read === 'function'
      ? { hotspot: await Promise.resolve(opts.hotspot.read()).catch(() => null) } : {};
    // the router's sign-in page: only where service.js hands its controller in
    let portal = {};
    if (typeof opts.portal === 'function') { try { portal = { portal: opts.portal() || null }; } catch { portal = { portal: null }; } }
    // …and its shaper (tc, or the policing it falls back to): only where service.js hands it in
    let shaper = {};
    if (typeof opts.shaper === 'function') { try { shaper = { shaper: opts.shaper() || null }; } catch { shaper = { shaper: null }; } }
    return Object.assign({
      ok: true,
      config: lu.config,
      users: lu.users,
      devices: lu.devices,
      usage: meter.usage(),
      live: running() ? meter.rates() : {},
      online: on,
      deviceUsage: platform === 'router' ? (typeof opts.deviceUsage === 'function' ? opts.deviceUsage() : meter.deviceUsage()) : {},
      // the window's name for where it runs: the router's build, or the desktop's (a headless service too)
      platform: platform === 'router' ? 'openwrt' : 'desktop',
      lanAddresses: lans
    }, hotspot, portal, shaper, extra || {});
  }

  /** A saved change handed to the router (its nft, its rule sets, its portal); a failure is said, never thrown. */
  async function changed(what) {
    if (typeof opts.onChange !== 'function') return;
    try { await opts.onChange(read(), what); } catch (e) { log({ line: 'Users: applying the change failed — ' + ((e && e.message) || e), level: 'warn' }); }
  }

  async function saved(what, extra) {
    await changed(what);
    return payload(Object.assign({ pendingReconnect: catchUp() }, extra || {}));
  }

  /**
   * A change one of the router's hooks saved (a remembered device, a card
   * started): applied a moment later, a run of them once — never awaited by
   * the hook, so a caller inside the router's own queue cannot wait on the
   * tick that queue holds back.
   */
  let hookTimer = null;
  let hookWhat = '';
  function changedSoon(what) {
    hookWhat = hookWhat === 'device' ? hookWhat : what;
    if (hookTimer) return;
    hookTimer = setTimeout(() => {
      hookTimer = null;
      const w = hookWhat;
      hookWhat = '';
      changed(w).then(() => catchUp()).catch(() => {});
    }, HOOK_DELAY_MS);
    if (hookTimer.unref) hookTimer.unref();
  }
  /** The window's codes are the page's 'lu.err.<code>' strings: a period (its calendar, its renew day) is part of the cap, a port clash a port. */
  const CODE = { quotaPeriod: 'quota', quotaCalendar: 'quota', quotaResetDay: 'quota', sessionHours: 'hours', portClash: 'port', portInUse: 'port' };
  /** `detail`: which part (model.validateUserDetail's, a top-up's); a code folded into another (CODE) is its own detail. */
  const refused = (error, detail) => payload({ ok: false, pendingReconnect: [], error: CODE[error] || error, ...(detail ? { detail } : (CODE[error] ? { detail: error } : {})) });
  /** A user about to be saved → refused with the first thing wrong with it, or null. */
  const userRefusal = (raw, others) => { const r = model.validateUserDetail(raw, others); return r ? refused(r.error, r.detail) : null; };
  /** A routing profile the user names that the app does not have: refused as routing / profile. */
  const profileMissing = (raw) => {
    const pid = model.profileIdOf(raw.routing);
    return pid && !profilesNow().some((p) => p && p.id === pid);
  };

  /**
   * An older page's edit of the cap of before (quotaGb / quotaPeriod, `limits`
   * left as they were): into the limits — the mirror's total limit replaced.
   * null when the quota did not change, or the page said its limits itself.
   */
  function quotaEdit(have, given) {
    const gb = 'quotaGb' in given ? (Number(given.quotaGb) > 0 ? Number(given.quotaGb) : 0) : have.quotaGb;
    const period = 'quotaPeriod' in given && model.PERIODS.includes(given.quotaPeriod) ? given.quotaPeriod : have.quotaPeriod;
    if (gb === have.quotaGb && (period === have.quotaPeriod || !gb)) return null;
    if ('limits' in given && JSON.stringify(model.normalizeLimits(given.limits)) !== JSON.stringify(have.limits)) return null;
    const mirror = have.limits.find((l) => l.kind === 'total');
    const rest = have.limits.filter((l) => l !== mirror && !(l.kind === 'total' && l.period === period));
    return rest.concat(gb > 0 ? [{ kind: 'total', period, gb, action: 'cut' }] : []);
  }

  /** A rate as the window sends it: blank or 0 ("not said"), or whole kbps 1–KBPS_MAX. */
  const rateOk = (v) => v == null || v === '' || v === 0 || v === '0'
    || ((typeof v === 'number' || (typeof v === 'string' && /^\s*\d+\s*$/.test(v))) && Number.isInteger(Number(v)) && Number(v) >= 1 && Number(v) <= model.KBPS_MAX);
  /** A line of text as the window sends it: nothing, or a string of at most `max` once its line breaks are spaces. */
  const lineOk = (v, max) => v == null || (typeof v === 'string' && v.replace(/[\r\n\t]+/g, ' ').trim().length <= max);

  /** A config about to be saved → the first thing wrong with it (a code, or [code, detail]), or null. */
  function configError(c) {
    const po = isObj(c.portal) ? c.portal : {};
    if (!lineOk(po.note, model.PORTAL_NOTE_MAX)) return ['portal', 'note'];
    if (!lineOk(po.contact, model.PORTAL_CONTACT_MAX)) return ['portal', 'contact'];
    if (po.requests != null && typeof po.requests !== 'boolean') return ['portal', 'requests'];
    const sh = isObj(c.shaping) ? c.shaping : {};
    if (!rateOk(sh.down)) return ['shaping', 'down'];
    if (!rateOk(sh.up)) return ['shaping', 'up'];
    if (sh.smooth != null && typeof sh.smooth !== 'boolean') return ['shaping', 'smooth'];
    const p = c.proxy;
    const t = c.transparent;
    if (model.portOf(p.port) === null) return 'port';
    if (!(p.httpPort === 0 || p.httpPort === '0') && model.portOf(p.httpPort) === null) return 'port';
    if (model.portOf(t.portalPort) === null) return 'port';
    const hours = Number(t.sessionHours);
    if (!Number.isInteger(hours) || hours < 1 || hours > 720) return 'sessionHours';
    if (!model.UNASSIGNED.includes(t.unassigned)) return 'unassigned';
    const mine = [model.portOf(p.port), Number(p.httpPort) ? model.portOf(p.httpPort) : null, platform === 'router' ? model.portOf(t.portalPort) : null].filter(Boolean);
    if (new Set(mine).size !== mine.length) return 'portClash';
    const s = getSettings() || {};
    const theirs = new Set([s.socksPort, s.httpPort, s.apiPort].map(model.portOf).filter(Boolean));
    for (const e of Array.isArray(store.get('pool', [])) ? store.get('pool', []) : []) {
      for (const k of ['socksPort', 'httpPort']) { const v = model.portOf(e && e[k]); if (v) theirs.add(v); }
    }
    if (mine.some((x) => theirs.has(x))) return 'portInUse';
    return null;
  }

  /* ------------------------------ v1.40: cards, devices by sign-in, the backup ------------------------------ */

  /** The devices with those users' bindings gone; a device with nothing else to say (no name, not blocked) is not kept. */
  const unbound = (devices, ids) => devices
    .map((d) => (ids.has(d.userId) ? Object.assign({}, d, { userId: '', remembered: false, at: 0 }) : d))
    .filter((d) => d.userId || d.blocked || d.name);

  /**
   * One device changed — the devices list's pick (lanusers:device) or a
   * sign-in's (assignDevice: `how.remembered`). → null once saved, else the
   * refusal's code. A pick of another user (or of none) replaces what a
   * sign-in remembered: the admin's word is the last.
   */
  function changeDevice(a, how) {
    const mac = model.normalizeMac(a.mac);
    if (!mac) return 'mac';
    const cur = read();
    const have = cur.devices.find((d) => d.mac === mac) || { mac, name: '', userId: '', blocked: false, remembered: false, at: 0 };
    const next = Object.assign({}, have);
    if ('userId' in a) {
      const uid = typeof a.userId === 'string' ? a.userId : '';
      const user = uid ? cur.users.find((u) => u.id === uid) : null;
      if (uid && !user) return 'user';
      if (user && user.maxDevices > 0 && have.userId !== uid && cur.devices.filter((d) => d.userId === uid && d.mac !== mac).length >= user.maxDevices) return 'maxDevices';
      const bySignIn = !!(how && how.remembered && uid);
      if (have.userId !== uid || bySignIn) Object.assign(next, { remembered: bySignIn, at: bySignIn ? now() : 0 });
      next.userId = uid;
    }
    if ('blocked' in a) next.blocked = a.blocked === true;
    if ('name' in a) next.name = model.normalizeDevice({ mac, name: a.name }).name;
    // a device that says nothing any more (no user, not blocked, no name) is not kept
    const keep = next.userId || next.blocked || next.name;
    const rest = cur.devices.filter((d) => d.mac !== mac);
    write(Object.assign({}, cur, { devices: keep ? (cur.devices.some((d) => d.mac === mac) ? cur.devices.map((d) => (d.mac === mac ? next : d)) : rest.concat([next])) : rest }));
    return null;
  }

  /**
   * The cards a batch asks for: `count` users, each a voucher of a new batch
   * — its code its username and its password, the batch's config, routing,
   * speed and devices per card (1 unless it says), its GB a one-off total
   * limit, `name` '<label> #<n>'. → { users, batch: { id, codes } } or
   * { error, detail }. The codes are unique among every username here.
   */
  function batchOf(b, cur) {
    const num = (v, def) => (v == null || v === '' ? def : Number(v));
    const count = num(b.count, NaN);
    if (!Number.isInteger(count) || count < 1 || count > BATCH_MAX) return { error: 'batch', detail: 'count' };
    const hours = num(b.hours, 0);
    if (!Number.isInteger(hours) || hours < 0 || hours > model.VOUCHER_HOURS_MAX) return { error: 'batch', detail: 'hours' };
    const gb = num(b.gb, 0);
    if (!Number.isFinite(gb) || gb < 0 || gb > model.QUOTA_MAX_GB) return { error: 'batch', detail: 'gb' };
    if (b.name != null && (typeof b.name !== 'string' || b.name.trim().length > model.NAME_MAX)) return { error: 'batch', detail: 'name' };
    const label = model.cleanName(b.name);
    const batches = new Set(cur.users.map((u) => u.voucher && u.voucher.batch).filter(Boolean));
    let id = model.newBatchId();
    while (batches.has(id)) id = model.newBatchId();
    const taken = new Set(cur.users.map((u) => u.username.toLowerCase()));
    const codes = [];
    for (let tries = 0; codes.length < count && tries < count * 20; tries++) {
      const code = model.voucherCode(opts.randomBytes);
      if (taken.has(code.toLowerCase())) continue;
      taken.add(code.toLowerCase());
      codes.push(code);
    }
    if (codes.length < count) return { error: 'batch', detail: 'codes' };
    const ids = new Set(cur.users.map((u) => u.id));
    const made = now();
    const users = codes.map((code, i) => {
      let uid = model.newUserId();
      while (ids.has(uid)) uid = model.newUserId();
      ids.add(uid);
      const suffix = ' #' + (i + 1);
      return {
        id: uid, username: code, password: code,
        name: label ? label.slice(0, model.NAME_MAX - suffix.length).trim() + suffix : '',
        target: b.target == null ? '' : b.target,
        routing: b.routing == null ? '' : b.routing,
        limits: gb > 0 ? [{ kind: 'total', period: 'none', gb, action: 'cut' }] : [],
        speed: b.speed == null ? null : b.speed,
        expiresAt: 0, maxDevices: num(b.maxDevices, 1), enabled: true,
        voucher: { batch: id, hours, activatedAt: 0, madeAt: made }
      };
    });
    return { users, batch: { id, codes } };
  }

  /**
   * A backup's record (normalized) laid over this machine's → { next, counts,
   * ids, configKept } — `ids` the users whose usage comes with them. The
   * rules are the header's.
   */
  function restoreRecord(cur, theirs, mode, hadNone) {
    const counts = { added: { users: 0, devices: 0, vouchers: 0 }, updated: { users: 0, devices: 0 }, skipped: { users: 0 } };
    const here = new Set(cur.users.map((u) => u.id));
    const macs = new Set(cur.devices.map((d) => d.mac));
    const addOne = (u) => { if (u.voucher) counts.added.vouchers++; else counts.added.users++; };
    if (mode === 'replace') {
      for (const u of theirs.users) if (here.has(u.id)) counts.updated.users++; else addOne(u);
      for (const d of theirs.devices) if (macs.has(d.mac)) counts.updated.devices++; else counts.added.devices++;
      // its ports clash with this machine's own (or are taken here): this machine's config stays
      const configKept = !!configError(theirs.config);
      return { next: { config: configKept ? cur.config : theirs.config, users: theirs.users, devices: theirs.devices }, counts, ids: theirs.users.map((u) => u.id), configKept };
    }
    const users = cur.users.slice();
    const ids = [];
    for (const u of theirs.users) {
      const lower = u.username.toLowerCase();
      if (!model.credentialsOk(u) || users.some((x) => x.id !== u.id && x.username.toLowerCase() === lower)) { counts.skipped.users++; continue; }
      const i = users.findIndex((x) => x.id === u.id);
      if (i >= 0) { users[i] = u; counts.updated.users++; } else { users.push(u); addOne(u); }
      ids.push(u.id);
    }
    const known = new Set(users.map((u) => u.id));
    const devices = cur.devices.slice();
    for (const d of theirs.devices) {
      const i = devices.findIndex((x) => x.mac === d.mac);
      const have = i >= 0 ? devices[i] : null;
      // bound to a user this merge left out: the binding it has here (or none); no name in the backup: the one here
      const next = Object.assign({}, d, !d.userId || known.has(d.userId) ? {}
        : (have ? { userId: have.userId, remembered: have.remembered, at: have.at } : { userId: '', remembered: false, at: 0 }),
      !d.name && have && have.name ? { name: have.name } : {});
      if (have) { devices[i] = next; counts.updated.devices++; } else { devices.push(next); counts.added.devices++; }
    }
    return { next: { config: hadNone ? theirs.config : cur.config, users, devices }, counts, ids, configKept: !hadNone };
  }

  const handlers = {
    'lanusers:get': () => payload(),

    'lanusers:config': (partial) => {
      const p = isObj(partial) ? partial : {};
      const cur = read();
      const merged = {
        proxy: Object.assign({}, cur.config.proxy, isObj(p.proxy) ? p.proxy : {}),
        transparent: Object.assign({}, cur.config.transparent, isObj(p.transparent) ? p.transparent : {}),
        portal: Object.assign({}, cur.config.portal, isObj(p.portal) ? p.portal : {}),
        shaping: Object.assign({}, cur.config.shaping, isObj(p.shaping) ? p.shaping : {})
      };
      const err = configError(merged);
      if (err) return Array.isArray(err) ? refused(err[0], err[1]) : refused(err);
      write(Object.assign({}, cur, { config: model.normalizeConfig(merged) }));
      return saved('config');
    },

    'lanusers:user': (arg) => {
      const a = isObj(arg) ? arg : {};
      const given = isObj(a.user) ? a.user : {};
      const cur = read();
      if (a.op === 'add') {
        const id = typeof given.id === 'string' && model.ID.test(given.id) && !cur.users.some((u) => u.id === given.id) ? given.id : model.newUserId();
        const raw = Object.assign({ name: '', target: '', quotaGb: 0, quotaPeriod: 'month', expiresAt: 0, maxDevices: 0, enabled: true }, given, { id });
        const bad = userRefusal(raw, cur.users);
        if (bad) return bad;
        if (profileMissing(raw)) return refused('routing', 'profile');
        write(Object.assign({}, cur, { users: cur.users.concat([model.normalizeUser(raw)]) }));
        return saved('user', { id });
      }
      if (a.op === 'update') {
        const have = cur.users.find((u) => u.id === given.id);
        if (!have) return refused('notFound');
        const raw = Object.assign({}, have, given, { id: have.id });
        const limits = quotaEdit(have, given);
        if (limits) raw.limits = limits;
        const bad = userRefusal(raw, cur.users);
        if (bad) return bad;
        // a profile already named and since deleted does not stop another edit: the build treats it as ''
        if (raw.routing !== have.routing && profileMissing(raw)) return refused('routing', 'profile');
        write(Object.assign({}, cur, { users: cur.users.map((u) => (u.id === have.id ? model.normalizeUser(raw) : u)) }));
        return saved('user', { id: have.id });
      }
      if (a.op === 'topUp' || a.op === 'resetUsage') {
        if (!cur.users.some((u) => u.id === given.id)) return refused('notFound');
        const err = a.op === 'topUp' ? meter.topUp(given.id, a.kind, a.period, a.gb) : meter.resetUsage(given.id);
        if (err) return err === 'notFound' ? refused('notFound') : refused('topUp', err);
        // the usage file at once (a top-up is the admin's word), and a hold it lifts the core's next
        flush(true);
        return saved('user', { id: given.id });
      }
      if (a.op === 'delete') {
        if (!cur.users.some((u) => u.id === given.id)) return refused('notFound');
        meter.forget(given.id);
        write(Object.assign({}, cur, {
          users: cur.users.filter((u) => u.id !== given.id),
          // their devices unbound — one with nothing else to say (no name, not blocked) is not kept
          devices: unbound(cur.devices, new Set([given.id]))
        }));
        return saved('user', { id: given.id });
      }
      if (a.op === 'vouchers') {
        const made = batchOf(isObj(a.batch) ? a.batch : {}, cur);
        if (made.error) return refused(made.error, made.detail);
        // every card is the first but for its code: one check says it for all of them
        const bad = userRefusal(made.users[0], cur.users);
        if (bad) return bad;
        if (profileMissing(made.users[0])) return refused('routing', 'profile');
        write(Object.assign({}, cur, { users: cur.users.concat(made.users.map((u) => model.normalizeUser(u))) }));
        log({ line: `Users: ${made.users.length} voucher${made.users.length === 1 ? '' : 's'} made (batch ${made.batch.id})`, level: 'info' });
        return saved('user', { batch: made.batch });
      }
      if (a.op === 'deleteBatch') {
        const bid = isObj(a.batch) && typeof a.batch.id === 'string' ? a.batch.id : '';
        const cards = bid ? cur.users.filter((u) => u.voucher && u.voucher.batch === bid) : [];
        if (!cards.length) return refused('notFound');
        // `unused`: only the cards never signed in with and never used (a used one's history stays)
        const gone = new Set(cards.filter((u) => !(a.unused === true && u.voucher.activatedAt > 0)).map((u) => u.id));
        for (const id of gone) meter.forget(id);
        write(Object.assign({}, cur, { users: cur.users.filter((u) => !gone.has(u.id)), devices: unbound(cur.devices, gone) }));
        return saved('user', { removed: gone.size });
      }
      if (a.op === 'dismissRequest') {
        if (!cur.users.some((u) => u.id === given.id)) return refused('notFound');
        meter.dismissRequest(given.id);
        flush(true);
        // nothing for the core or the router: the page's answer alone
        return payload({ pendingReconnect: catchUp(), id: given.id });
      }
      return refused('op');
    },

    'lanusers:device': (arg) => {
      const err = changeDevice(isObj(arg) ? arg : {});
      return err ? refused(err) : saved('device');
    },

    'lanusers:backup': () => ({
      ok: true,
      bundle: {
        kind: BACKUP_KIND, version: BACKUP_VERSION, at: now(),
        app: typeof opts.appVersion === 'string' ? opts.appVersion : '',
        platform: platform === 'router' ? 'openwrt' : 'desktop',
        lanUsers: read(),
        meter: meter.exportState()
      }
    }),

    'lanusers:restore': (arg) => {
      const a = isObj(arg) ? arg : {};
      const b = a.bundle;
      if (!isObj(b) || b.kind !== BACKUP_KIND) return refused('backup', 'kind');
      if (!Number.isInteger(b.version) || b.version < 1 || b.version > BACKUP_VERSION) return refused('backup', 'version');
      const mode = a.mode == null ? 'merge' : a.mode;
      const lu = b.lanUsers;
      if (!isObj(lu) || (lu.users != null && !Array.isArray(lu.users)) || (lu.devices != null && !Array.isArray(lu.devices))
        || (b.meter != null && !isObj(b.meter)) || (mode !== 'merge' && mode !== 'replace')) return refused('backup', 'shape');
      const hadNone = store.get('lanUsers', null) == null;
      const cur = read();
      const r = restoreRecord(cur, model.normalizeLanUsers(lu), mode, hadNone);
      const next = model.normalizeLanUsers(r.next);
      const kept = new Set(next.users.map((u) => u.id));
      // replace: the users the backup lacks go, and their bytes with them
      if (mode === 'replace') for (const u of cur.users) if (!kept.has(u.id)) meter.forget(u.id);
      meter.importState(isObj(b.meter) ? b.meter : {}, { mode, ids: r.ids.filter((id) => kept.has(id)) });
      write(next);
      flush(true);
      const c = r.counts;
      log({ line: `Users: restored from a backup (${mode}) — ${c.added.users} users, ${c.added.vouchers} vouchers and ${c.added.devices} devices added, ${c.updated.users} users and ${c.updated.devices} devices updated`
        + (c.skipped.users ? `, ${c.skipped.users} skipped (their username is another’s here, or their password one the proxy refuses)` : '')
        + (mode === 'replace' && r.configKept ? '; its ports are taken here, so this machine’s settings stay' : ''), level: 'info' });
      return saved('restore', c);
    }
  };

  if (typeof opts.handle === 'function') for (const ch of CHANNELS) opts.handle(ch, handlers[ch]);

  /**
   * The usage into the usage file, lazily (a write half a second later, or
   * with the totals' if that comes first): by kind (`lanUsersUsage2`), the
   * 30 days (`lanUsersHistory`), the months (`lanUsersMonths`), the top-ups
   * asked for (`lanUsersRequests`), and the old key still — an older app on
   * the same file counts on from it.
   */
  function flush(force) {
    if (!usageStore || !meter.dirty || (!force && !meter.dueForSave())) return;
    usageStore.setLazy('lanUsersUsage2', meter.savedUsage2());
    usageStore.setLazy('lanUsersHistory', meter.savedHistory());
    usageStore.setLazy('lanUsersMonths', meter.savedMonths());
    usageStore.setLazy('lanUsersRequests', meter.savedRequests());
    usageStore.setLazy('lanUsersUsage', meter.saved());
    if (platform === 'router') usageStore.setLazy('lanDeviceUsage', meter.savedDevices());
    meter.markSaved();
  }

  /* ------------------------------ the router's hooks ------------------------------ */

  /**
   * A device that signed in on the router's page as a user with `remember` on
   * becomes theirs for good: bound to them, `remembered`, `at` now, named by
   * the scan's hostname when it had no name — through the devices list's own
   * path (changeDevice), the router told a moment later (changedSoon). →
   * Promise<boolean>: true when the device is theirs (now, or already); false
   * when it cannot be — no such user, a voucher, `remember` off, the device
   * bound to someone else or blocked by the admin, their device limit reached.
   */
  async function assignDevice(arg) {
    const a = isObj(arg) ? arg : {};
    const mac = model.normalizeMac(a.mac);
    const cur = read();
    const u = cur.users.find((x) => x.id === a.userId);
    if (!mac || !u || !u.remember || u.voucher) return false;
    const have = cur.devices.find((d) => d.mac === mac);
    if (have && have.blocked) return false;
    if (have && have.userId) return have.userId === u.id;
    const name = model.cleanName(a.name);
    if (changeDevice(Object.assign({ mac, userId: u.id }, name && !(have && have.name) ? { name } : {}), { remembered: true })) return false;
    log({ line: `Users: a device (${mac}) signed in as “${u.name || u.username}” and is theirs from now on`, level: 'info' });
    changedSoon('device');
    return true;
  }

  /**
   * A voucher's first sign-in (the router) or first bytes (meter.js
   * onFirstUse): `activatedAt` now and — with hours — `expiresAt` that many
   * hours on (never later than an expiry the admin set), written once. →
   * Promise<boolean>: true when it was started now; false when there is no
   * such voucher, it was started already (a second call — a sign-in and its
   * own first bytes — writes nothing), it is switched off, or its expiry
   * passed unused. Nothing the core runs changes (the expiry is the meter's
   * to apply when it comes): no reload.
   */
  async function activateVoucher(userId) {
    const cur = read();
    const u = cur.users.find((x) => x.id === userId);
    const t = now();
    if (!u || !u.voucher || u.voucher.activatedAt > 0 || u.enabled === false || model.isExpired(u, t)) return false;
    const until = u.voucher.hours > 0 ? t + u.voucher.hours * 3600000 : 0;
    const expiresAt = until && u.expiresAt > 0 ? Math.min(until, u.expiresAt) : (until || u.expiresAt);
    const next = Object.assign({}, u, { expiresAt, voucher: Object.assign({}, u.voucher, { activatedAt: t }) });
    write(Object.assign({}, cur, { users: cur.users.map((x) => (x.id === u.id ? next : x)) }));
    log({ line: `Users: voucher ${u.username} is in use${expiresAt ? ' — until ' + localText(expiresAt) : ''}`, level: 'info' });
    changedSoon('user');
    return true;
  }

  /** A top-up asked for on the router's status page (meter.js request), saved at once. → true new, false one pending already. */
  function request(userId, r) {
    const fresh = meter.request(userId, isObj(r) ? r : {});
    if (fresh) flush(true);
    return fresh;
  }

  return {
    handlers,
    forBuild,
    /** One stats poll: the per-user counters, the save, and a change the core has not caught up with. */
    tick(vars) {
      try {
        meter.tick(vars);
        flush(false);
        // the router's LAN address found after the connect, read again now and then
        if (platform === 'router' && installed() && read().config.proxy.enabled && !lastListen && now() - lanRead.at >= LAN_TTL_MS) {
          routerLan(true).then((a) => { if (a) lastListen = a; }).catch(() => {});
        }
        if (now() - lastAsk >= RETRY_MS && canReload()) catchUp();
      } catch (e) {
        once('tick:' + ((e && e.message) || e), 'Users: the usage meter failed — ' + ((e && e.message) || e));
      }
    },
    /**
     * For the stats event, beside its multiWan: { live, usage } while the
     * running core carries users — the open page paints from it without asking
     * again — else null (the event stays as it always was).
     */
    statsLive() {
      if (liveSig === null || liveSig === 'off' || !running()) return null;
      return { live: meter.rates(), usage: meter.usage(), ...(platform === 'router' ? { devices: meter.deviceRates(), deviceUsage: meter.deviceUsage() } : {}) };
    },
    addBytes: (userId, bytes) => meter.addBytes(userId, bytes),
    tickDevices: (totals) => meter.tickDevices(totals),
    overIds: () => meter.overIds(),
    /** Every user with a hold now (meter.js holds()): { [userId]: { hold, why, until } }. */
    holds: () => meter.holds(),
    /** Every user with a speed now (meter.js speeds()): { [userId]: { down, up, why } } kbps — the router applies them in nft. */
    speeds: () => meter.speeds(),
    activeUsers: () => activeNow(read()),
    payload,
    flush: () => flush(true),
    meter,
    // the router's (service.js hands them to router/index.js through setMeter)
    assignDevice,
    activateVoucher,
    request
  };
}

module.exports = { CHANNELS, RELOAD_DELAY_MS, RETRY_MS, HOOK_DELAY_MS, BATCH_MAX, BACKUP_KIND, BACKUP_VERSION, HOTSPOT_IP, registerLanUsers, lanCandidates, onlineMap };
