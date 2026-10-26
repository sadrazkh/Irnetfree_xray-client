'use strict';
/**
 * Users and devices («کاربران», module `lanUsers`): the four channels the
 * window talks through, the build's input, and the meter's feed — one module
 * for the desktop (main.js, over ipcMain and the preload) and the router
 * (service.js, over its invoke table and web-api.js).
 *
 *   lanusers:get    → { ok, config, users, devices, usage, live, online, deviceUsage, platform, lanAddresses }
 *   lanusers:config (a part of the config, nested: { proxy: { enabled } }) → that + { pendingReconnect }
 *   lanusers:user   ({ op: 'add', user } — no id, one is made; { op: 'update', user } — the whole
 *                   user, or a part with its id; { op: 'delete', user: { id } }) → that + { pendingReconnect, id }
 *   lanusers:device ({ mac, userId?, blocked?, name? })              → that + { pendingReconnect }
 *
 * `usage`: meter.js's, per user this period; `live`: bytes/s per user while
 * connected; `online` (router): { [mac]: { ip, hostname, userId, up?, down? } }
 * of the devices answering now, {} on the desktop; `deviceUsage` (router):
 * { [mac]: bytes } this period; `platform`: 'openwrt' on the router, 'desktop'
 * elsewhere; `lanAddresses`: where people point their proxy at.
 *
 * A refusal saves nothing and answers `ok: false` and `error`, a code the page
 * words as 'lu.err.<code>': a user's (model.validateUser — quotaPeriod comes
 * as quota), port (bad, clashing or one the app already uses; `detail` says
 * which), hours, unassigned, notFound, op, mac, user, maxDevices.
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
const { createFirewall } = require('./firewall');
const { groupRecordsById } = require('../../main/groups');
const { wgEndpointHosts } = require('../../main/configBuilder');
const { lanStatus } = require('../../main/openwrtNet');

const CHANNELS = ['lanusers:get', 'lanusers:config', 'lanusers:user', 'lanusers:device'];
/** A run of edits (a user added, then another) is one reload this long after the last. */
const RELOAD_DELAY_MS = 600;
/** A change the core could not take when it was made is asked again no sooner than this. */
const RETRY_MS = 15000;
/** The router's LAN address is read again after this long. */
const LAN_TTL_MS = 60000;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const TUN_LOCAL_IP = '10.255.0.2';   // the app's own TUN adapter — never a LAN address

/** This machine's LAN IPv4 addresses, the usual home/office ranges first (as main.js lanIp ranks them). */
function lanCandidates(ifs) {
  const all = ifs || os.networkInterfaces();
  const out = [];
  for (const name of Object.keys(all || {})) {
    for (const ni of all[name] || []) {
      if (!ni || (ni.family !== 'IPv4' && ni.family !== 4) || ni.internal) continue;
      if (ni.address === TUN_LOCAL_IP || ni.address.startsWith('169.254.')) continue;
      if (!out.includes(ni.address)) out.push(ni.address);
    }
  }
  const score = (a) => (a.startsWith('192.168.') ? 3 : /^172\.(1[6-9]|2\d|3[01])\./.test(a) ? 2 : a.startsWith('10.') ? 1 : 0);
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
 *   firewall              { sync(ports | null) } (default: firewall.js on Windows' desktop)
 *   log({ line, level }), notify(text), now()
 * → { handlers, forBuild(buildSettings), tick(vars), statsLive, addBytes, tickDevices, overIds, activeUsers, payload, flush, meter }
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

  const noticeText = (n) => {
    const day = n.period === 'day';
    const all = n.period === 'none';
    return isEn()
      ? `“${n.name}” reached their ${n.capGb} GB${day ? ' daily' : (all ? '' : ' monthly')} cap — off ${day ? 'until tomorrow' : (all ? 'until it is raised' : 'until next month')}`
      : `«${n.name}» به سقف ${n.capGb} گیگابایتِ ${day ? 'روزانه' : (all ? 'کل' : 'ماهانه')} رسید — ${day ? 'تا فردا' : (all ? 'تا وقتی سقف بالا برود' : 'تا ماه بعد')} قطع است`;
  };

  const meter = createLanUsersMeter({
    usage: usageStore ? usageStore.get('lanUsersUsage', {}) : {},
    deviceUsage: usageStore ? usageStore.get('lanDeviceUsage', {}) : {},
    users: () => store.get('lanUsers', null),
    canReload, pending,
    reload: (why) => requestReload(why, 0),
    log,
    notify: typeof opts.notify === 'function' ? (n) => opts.notify(noticeText(n)) : null,
    now
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
  let liveSig = null;   // what the running core was built with (forBuild's), null: nothing built in this process
  let lastAsk = -Infinity;
  const saidOnce = new Set();
  const once = (key, line, level) => { if (saidOnce.has(key)) return; saidOnce.add(key); log({ line, level: level || 'warn' }); };

  /** The records the targets name, as buildPlan makes them: groups as records beside the servers; a chain that lost a member is null. */
  function recordsFor(targets) {
    const servers = store.get('servers', []);
    const all = {};
    for (const s of Array.isArray(servers) ? servers : []) if (s && s.id) all[s.id] = s;
    const groups = store.get('groups', []);
    Object.assign(all, groupRecordsById(Array.isArray(groups) ? groups : [], Object.assign({}, all)));
    const chains = store.get('chains', []);
    const serversById = {};
    const chainsById = {};
    for (const t of targets) {
      if (!t || t === 'direct' || t === 'block') continue;
      if (t.indexOf('chain:') === 0) {
        const cid = t.slice('chain:'.length);
        const c = (Array.isArray(chains) ? chains : []).find((x) => x && x.id === cid);
        const ids = c && Array.isArray(c.members) ? c.members : [];
        chainsById[cid] = ids.length && ids.every((id) => all[id]) ? ids.map((id) => all[id]) : null;
        continue;
      }
      if (all[t]) serversById[t] = all[t];
    }
    return { serversById, chainsById };
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

  /** Who may use the proxy now, by the meter's caps. */
  function activeNow(lu, t) {
    return model.activeUsers(lu, { now: t == null ? now() : t, over: meter.overIds() });
  }

  /** What a build would let in and where to, as one string: a difference is a reload. */
  function signature(on, lu, listen, tp, t) {
    if (!on) return 'off';
    const proxyOn = lu.config.proxy.enabled && !!listen;
    if (!proxyOn && !tp.length) return 'off';
    const users = proxyOn ? activeNow(lu, t).map((u) => [u.id, u.username, u.password, u.target]) : [];
    return JSON.stringify([proxyOn ? listen : '', proxyOn ? lu.config.proxy : null, users, tp]);
  }
  const currentSig = () => signature(installed(), read(), lastListen, lastTp);

  /**
   * The build's `settings.lanUsers` (xray.js says what each part is for), or
   * null — not installed, or nothing on: the builder then leaves the config as
   * it always was. Called right before every build (the connect and every
   * reload) with the settings that build uses — whether the module is
   * installed is theirs to say; what it hands is what the running core is
   * held to.
   */
  async function forBuild(buildSettings) {
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
      lastListen = proxyOn ? await listenAddress() : '';
      if (proxyOn && !lastListen) once('nolisten', platform === 'router'
        ? 'Users: the router’s LAN address could not be read — the users’ proxy is off until it can be'
        : 'Users: this machine has no private network address — the users’ proxy is off');
      const t = now();
      liveSig = signature(on, lu, lastListen, lastTp, t);
      if (liveSig === 'off') { meter.built(null); return null; }
      const over = meter.overIds();
      const active = proxyOn && lastListen ? activeNow(lu, t) : [];
      const targets = [...new Set(active.map((u) => u.target).concat(lastTp.map((e) => (e && e.target) || '')))];
      const records = recordsFor(targets);
      for (const u of active) {
        const tg = u.target;
        const gone = tg && tg !== 'direct' && tg !== 'block' && (tg.indexOf('chain:') === 0 ? !records.chainsById[tg.slice('chain:'.length)] : !records.serversById[tg]);
        if (gone) once('gone:' + u.id + ':' + tg, `Users: the config of “${u.name || u.username}” no longer exists (removed, or replaced by a subscription update) — blocked until another is picked`);
      }
      const wgEndpointIps = await resolveWg(records);
      meter.built({ active: active.map((u) => u.id), over, byName: Object.fromEntries(active.map((u) => [u.username, u.id])) });
      return {
        config: lu.config, users: lu.users, devices: lu.devices, over, now: t, listen: lastListen,
        serversById: records.serversById, chainsById: records.chainsById, wgEndpointIps, tp: lastTp
      };
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
    return Object.assign({
      ok: true,
      config: lu.config,
      users: lu.users,
      devices: lu.devices,
      usage: meter.usage(),
      live: running() ? meter.rates() : {},
      online: on,
      deviceUsage: platform === 'router' ? meter.deviceUsage() : {},
      // the window's name for where it runs: the router's build, or the desktop's (a headless service too)
      platform: platform === 'router' ? 'openwrt' : 'desktop',
      lanAddresses: lans
    }, extra || {});
  }

  async function saved(what, extra) {
    if (typeof opts.onChange === 'function') {
      try { await opts.onChange(read(), what); } catch (e) { log({ line: 'Users: applying the change failed — ' + ((e && e.message) || e), level: 'warn' }); }
    }
    return payload(Object.assign({ pendingReconnect: catchUp() }, extra || {}));
  }
  /** The window's codes are the page's 'lu.err.<code>' strings: a period is part of the cap, a port clash a port. */
  const CODE = { quotaPeriod: 'quota', sessionHours: 'hours', portClash: 'port', portInUse: 'port' };
  const refused = (error) => payload({ ok: false, pendingReconnect: [], error: CODE[error] || error, ...(CODE[error] ? { detail: error } : {}) });

  /** A config about to be saved → the first thing wrong with it, or null. */
  function configError(c) {
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

  const handlers = {
    'lanusers:get': () => payload(),

    'lanusers:config': (partial) => {
      const p = isObj(partial) ? partial : {};
      const cur = read();
      const merged = {
        proxy: Object.assign({}, cur.config.proxy, isObj(p.proxy) ? p.proxy : {}),
        transparent: Object.assign({}, cur.config.transparent, isObj(p.transparent) ? p.transparent : {})
      };
      const err = configError(merged);
      if (err) return refused(err);
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
        const err = model.validateUser(raw, cur.users);
        if (err) return refused(err);
        write(Object.assign({}, cur, { users: cur.users.concat([model.normalizeUser(raw)]) }));
        return saved('user', { id });
      }
      if (a.op === 'update') {
        const have = cur.users.find((u) => u.id === given.id);
        if (!have) return refused('notFound');
        const raw = Object.assign({}, have, given, { id: have.id });
        const err = model.validateUser(raw, cur.users);
        if (err) return refused(err);
        write(Object.assign({}, cur, { users: cur.users.map((u) => (u.id === have.id ? model.normalizeUser(raw) : u)) }));
        return saved('user', { id: have.id });
      }
      if (a.op === 'delete') {
        if (!cur.users.some((u) => u.id === given.id)) return refused('notFound');
        meter.forget(given.id);
        write(Object.assign({}, cur, {
          users: cur.users.filter((u) => u.id !== given.id),
          // their devices unbound — one with nothing else to say (no name, not blocked) is not kept
          devices: cur.devices.map((d) => (d.userId === given.id ? Object.assign({}, d, { userId: '' }) : d)).filter((d) => d.userId || d.blocked || d.name)
        }));
        return saved('user', { id: given.id });
      }
      return refused('op');
    },

    'lanusers:device': (arg) => {
      const a = isObj(arg) ? arg : {};
      const mac = model.normalizeMac(a.mac);
      if (!mac) return refused('mac');
      const cur = read();
      const have = cur.devices.find((d) => d.mac === mac) || { mac, name: '', userId: '', blocked: false };
      const next = Object.assign({}, have);
      if ('userId' in a) {
        const uid = typeof a.userId === 'string' ? a.userId : '';
        const user = uid ? cur.users.find((u) => u.id === uid) : null;
        if (uid && !user) return refused('user');
        if (user && user.maxDevices > 0 && have.userId !== uid && cur.devices.filter((d) => d.userId === uid && d.mac !== mac).length >= user.maxDevices) return refused('maxDevices');
        next.userId = uid;
      }
      if ('blocked' in a) next.blocked = a.blocked === true;
      if ('name' in a) next.name = model.normalizeDevice({ mac, name: a.name }).name;
      // a device that says nothing any more (no user, not blocked, no name) is not kept
      const keep = next.userId || next.blocked || next.name;
      const rest = cur.devices.filter((d) => d.mac !== mac);
      write(Object.assign({}, cur, { devices: keep ? (cur.devices.some((d) => d.mac === mac) ? cur.devices.map((d) => (d.mac === mac ? next : d)) : rest.concat([next])) : rest }));
      return saved('device');
    }
  };

  if (typeof opts.handle === 'function') for (const ch of CHANNELS) opts.handle(ch, handlers[ch]);

  /** The usage into the usage file, lazily (a write half a second later, or with the totals' if that comes first). */
  function flush(force) {
    if (!usageStore || !meter.dirty || (!force && !meter.dueForSave())) return;
    usageStore.setLazy('lanUsersUsage', meter.saved());
    if (platform === 'router') usageStore.setLazy('lanDeviceUsage', meter.savedDevices());
    meter.markSaved();
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
    activeUsers: () => activeNow(read()),
    payload,
    flush: () => flush(true),
    meter
  };
}

module.exports = { CHANNELS, RELOAD_DELAY_MS, RETRY_MS, registerLanUsers, lanCandidates, onlineMap };
