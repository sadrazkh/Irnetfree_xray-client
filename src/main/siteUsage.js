'use strict';
/**
 * Traffic by site: how much of what this machine moved went to YouTube, how much to
 * Instagram (the Logs page's «مصرف سایت‌ها» tab, src/renderer/siteUsage.js). 2026-11-02,
 * the owner: "roughly where is my traffic going".
 *
 * Only sing-box's TUN can say. Xray counts per outbound and per user, never per name,
 * and its access log has names without bytes. sing-box's loopback API
 * (connectionsWatch.js) lists every open connection with its bytes. It knows a
 * connection's name only if it sniffs, which the TUN does not do by default: with
 * `settings.siteUsage` on, a connect adds the sniff (tunSingbox.js `sniff`), so the
 * option is a reconnect key and nothing changes while it is off. The sniff only
 * reads the name; the destination stays the address, so routing does not change.
 *
 * Every POLL_MS: each connection's bytes since the last read go to its bucket. What
 * the API's running totals moved that no listed connection explains (connections that
 * opened and closed between two reads, the last bytes of those that ended) goes to
 * `u`, the row that says "other". So the figures are payload as the apps see it, and
 * roughly right; the tunnel's own overhead is not in them.
 *
 * Buckets: `s:<id>` a known service (SERVICES, several domains as one name), `d:<name>`
 * any other site by its registrable domain, `a:<program>` a connection with no name (a
 * bare address, no TLS), `u` the rest. Saved per local day in usage.json, nothing
 * leaves the machine, and only the registrable domain is kept, never a full host.
 *
 * On a router (2026-11-02, the owner: "by device too, with a switch, and not much load
 * on the CPU, RAM or memory"), `limits` is ROUTER_LIMITS and `device` names the device
 * behind a connection from its source address, so each device has its rows too. There
 * the API itself exists only while the option is on. Each read costs little: a read
 * every 5 s, further apart if reading ever takes over 2 % of the time (maxReadShare,
 * with many connections on a slow CPU); a write to flash every 30 minutes, and at a
 * stop; fewer days and rows kept. A power cut loses the last half hour of figures.
 */
const net = require('net');
const { fetchSnapshot, appOf } = require('./connectionsWatch');

/** Often, because a connection that opens and ends between two reads has no name to count under. */
const POLL_MS = 1000;
const SAVE_MS = 30000;
/** A day holds at most this many rows; past it, a new site joins `u`. */
const MAX_KEYS_PER_DAY = 500;
const KEEP_DAYS = 92;
/** The most rows a report sends; the page shows fewer. */
const MAX_ROWS = 300;
const RANGE_DAYS = { today: 1, 7: 7, 30: 30 };
/** A desktop's. A router's are ROUTER_LIMITS; 0 for maxReadShare: every pollMs, however long a read takes. */
const DESKTOP_LIMITS = { pollMs: POLL_MS, maxPollMs: POLL_MS, maxReadShare: 0, saveMs: SAVE_MS, keepDays: KEEP_DAYS, maxKeys: MAX_KEYS_PER_DAY, deviceKeepDays: 0, maxDeviceKeys: 0, maxDevices: 0, deviceRefreshMs: 0 };
const ROUTER_LIMITS = {
  pollMs: 5000, maxPollMs: 60000, maxReadShare: 0.02,
  saveMs: 30 * 60 * 1000, keepDays: 31, maxKeys: 200,
  deviceKeepDays: 14, maxDeviceKeys: 30, maxDevices: 64, deviceRefreshMs: 2 * 60 * 1000
};
/** An unknown address asks for the device list again, but not more often than this. */
const DEVICE_RETRY_MS = 15000;
/** Where the router itself is seen from inside the tunnel: the TUN's own addresses (tunSingbox.js), loopback. */
const LOCAL_SOURCES = new Set(['', '172.19.0.1', 'fdfe:dcba:9876::1', '127.0.0.1', '::1']);
const ROUTER_DEVICE = 'router';
const DEVICE_ID = /^([0-9a-f:.]{1,64}|router)$/;

/** Known services: the domains that are really one thing to the person watching it. */
const SERVICES = [
  ['youtube', 'YouTube', ['youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com', 'youtube-nocookie.com', 'youtubei.googleapis.com', 'ggpht.com', 'yt.be']],
  ['instagram', 'Instagram', ['instagram.com', 'cdninstagram.com', 'ig.me']],
  ['facebook', 'Facebook', ['facebook.com', 'fb.com', 'fb.me', 'fbcdn.net', 'facebook.net', 'fbsbx.com', 'messenger.com']],
  ['whatsapp', 'WhatsApp', ['whatsapp.com', 'whatsapp.net', 'wa.me']],
  ['telegram', 'Telegram', ['telegram.org', 'telegram.me', 't.me', 'telesco.pe', 'tdesktop.com', 'tg.dev', 'cdn-telegram.org']],
  ['x', 'X (Twitter)', ['x.com', 'twitter.com', 'twimg.com', 't.co']],
  ['tiktok', 'TikTok', ['tiktok.com', 'tiktokcdn.com', 'tiktokv.com', 'tiktokcdn-us.com', 'byteoversea.com', 'ibytedtos.com', 'ibyteimg.com', 'muscdn.com', 'ttwstatic.com']],
  ['netflix', 'Netflix', ['netflix.com', 'nflxvideo.net', 'nflximg.net', 'nflximg.com', 'nflxso.net', 'nflxext.com']],
  ['spotify', 'Spotify', ['spotify.com', 'scdn.co', 'spotifycdn.com', 'spotifycdn.net']],
  ['twitch', 'Twitch', ['twitch.tv', 'ttvnw.net', 'jtvnw.net', 'twitchcdn.net']],
  ['discord', 'Discord', ['discord.com', 'discord.gg', 'discord.media', 'discordapp.com', 'discordapp.net']],
  ['reddit', 'Reddit', ['reddit.com', 'redd.it', 'redditmedia.com', 'redditstatic.com']],
  ['linkedin', 'LinkedIn', ['linkedin.com', 'licdn.com']],
  ['pinterest', 'Pinterest', ['pinterest.com', 'pinimg.com']],
  ['snapchat', 'Snapchat', ['snapchat.com', 'sc-cdn.net', 'snap-dev.net', 'sc-static.net']],
  ['zoom', 'Zoom', ['zoom.us', 'zoom.com', 'zoomgov.com']],
  ['chatgpt', 'ChatGPT', ['openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com']],
  ['claude', 'Claude', ['anthropic.com', 'claude.ai', 'claude.com']],
  ['github', 'GitHub', ['github.com', 'githubusercontent.com', 'githubassets.com', 'github.io', 'ghcr.io']],
  ['steam', 'Steam', ['steampowered.com', 'steamcontent.com', 'steamstatic.com', 'steamcommunity.com', 'steamserver.net']],
  ['apple', 'Apple', ['apple.com', 'icloud.com', 'icloud-content.com', 'mzstatic.com', 'aaplimg.com', 'cdn-apple.com', 'apple-dns.net']],
  ['microsoft', 'Microsoft / Windows', ['microsoft.com', 'windowsupdate.com', 'windows.com', 'msftconnecttest.com', 'msedge.net', 'live.com', 'office.com', 'office.net', 'office365.com', 'msn.com', 'bing.com', 'azureedge.net', 'onedrive.com', 'sharepoint.com', 'skype.com', 'xboxlive.com', 'xbox.com', 'trafficmanager.net', 'azure.com']],
  ['amazon', 'Amazon / Prime', ['amazon.com', 'primevideo.com', 'aiv-cdn.net', 'media-amazon.com', 'ssl-images-amazon.com', 'amazonvideo.com']],
  // after YouTube's: the most specific suffix wins, so these keep what is left of Google's
  ['google', 'Google', ['google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'gvt1.com', 'gvt2.com', 'doubleclick.net', 'google-analytics.com', 'googlesyndication.com', 'googletagmanager.com', 'googleadservices.com', 'android.com', 'gmail.com']]
];
const NAME_OF = new Map(SERVICES.map(([id, name]) => [id, name]));
NAME_OF.set('dns', 'DNS');
const SUFFIX = new Map();
for (const [id, , hosts] of SERVICES) for (const h of hosts) SUFFIX.set(h, id);

/** Telegram's apps dial bare addresses, with no name to sniff: its published ranges. */
const TELEGRAM_V4 = ['91.108.4.0/22', '91.108.8.0/22', '91.108.12.0/22', '91.108.16.0/22', '91.108.20.0/22', '91.108.56.0/22', '95.161.64.0/20', '149.154.160.0/20'];
const TELEGRAM_V6 = ['2001:67c:4e8:', '2001:b28:f23c:', '2001:b28:f23d:', '2001:b28:f23f:'];
const ip4Int = (ip) => ip.split('.').reduce((a, b) => a * 256 + Number(b), 0);
const TELEGRAM_RANGES = TELEGRAM_V4.map((c) => {
  const [base, bits] = c.split('/');
  const start = ip4Int(base);
  return [start, start + 2 ** (32 - Number(bits))];
});

const num = (v) => { const n = Number(v); return Number.isFinite(n) && n > 0 ? n : 0; };
const cleanHost = (h) => String(h == null ? '' : h).trim().toLowerCase().replace(/\.$/, '');

/** The known service a name belongs to, the most specific suffix first; '' when none. */
function serviceOfHost(host) {
  const labels = cleanHost(host).split('.');
  for (let i = 0; i < labels.length - 1; i++) {
    const id = SUFFIX.get(labels.slice(i).join('.'));
    if (id) return id;
  }
  return '';
}

/** The second-level names that are a country's public suffix (`aparat.co.ir` is one site, not `co.ir`). */
const SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'ac', 'gov', 'edu', 'id', 'sch', 'or', 'ne', 'go']);

/** `a.b.example.com` → `example.com`; `www.site.co.ir` → `site.co.ir`. */
function registrable(host) {
  const labels = cleanHost(host).split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const tld = labels[labels.length - 1], second = labels[labels.length - 2];
  return labels.slice(tld.length === 2 && SECOND_LEVEL.has(second) ? -3 : -2).join('.');
}

function ipServiceOf(ip) {
  const a = String(ip || '').toLowerCase();
  if (net.isIPv4(a)) {
    const n = ip4Int(a);
    return TELEGRAM_RANGES.some(([s, e]) => n >= s && n < e) ? 'telegram' : '';
  }
  return TELEGRAM_V6.some((p) => a.startsWith(p)) ? 'telegram' : '';
}

/** A connection's bucket from what the API says about it (connectionsWatch.js has the shape). */
function bucketOf(meta) {
  const m = meta && typeof meta === 'object' ? meta : {};
  if (Number(m.destinationPort) === 53) return 's:dns';
  const host = cleanHost(m.host);
  if (host && !net.isIP(host)) {
    const id = serviceOfHost(host);
    return id ? 's:' + id : 'd:' + registrable(host).slice(0, 100);
  }
  const id = ipServiceOf(host || m.destinationIP);
  if (id) return 's:' + id;
  const app = appOf(m.processPath);
  return app ? 'a:' + app.slice(0, 100) : 'u';
}

/** A bucket as the page shows it: { kind: 'service'|'site'|'app'|'other', name }. */
function describe(key) {
  const k = String(key);
  if (k.startsWith('s:')) return { kind: 'service', name: NAME_OF.get(k.slice(2)) || k.slice(2) };
  if (k.startsWith('d:')) return { kind: 'site', name: k.slice(2) };
  if (k.startsWith('a:')) return { kind: 'app', name: k.slice(2) };
  return { kind: 'other', name: '' };
}

/** A local calendar day as 'YYYY-MM-DD': what "today" means to the person reading it. */
function dayOf(ms) {
  const d = new Date(ms);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

/** The store's copy, only what reads: { 'YYYY-MM-DD': { key: [up, down] } }. */
function readDays(raw) {
  const out = {};
  if (!raw || typeof raw !== 'object' || !raw.days || typeof raw.days !== 'object') return out;
  for (const [day, rows] of Object.entries(raw.days)) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day) || !rows || typeof rows !== 'object') continue;
    const clean = Object.create(null);
    for (const [k, v] of Object.entries(rows)) {
      if (!/^([sda]:.{1,120}|u)$/.test(k) || !Array.isArray(v)) continue;
      clean[k] = [num(v[0]), num(v[1])];
    }
    out[day] = clean;
  }
  return out;
}

/** The saved per-device figures, only what reads: { 'YYYY-MM-DD': { device: { key: [up, down] } } }. */
function readDevices(raw) {
  const out = {};
  if (!raw || typeof raw !== 'object' || !raw.devices || typeof raw.devices !== 'object') return out;
  for (const [day, devs] of Object.entries(raw.devices)) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day) || !devs || typeof devs !== 'object') continue;
    const clean = Object.create(null);
    for (const [id, rows] of Object.entries(devs)) {
      if (DEVICE_ID.test(id)) clean[id] = readDays({ days: { [day]: rows } })[day] || Object.create(null);
    }
    out[day] = clean;
  }
  return out;
}

/** The device names kept beside the figures: a device off the network keeps its name. */
function readNames(raw) {
  const out = Object.create(null);
  const names = raw && typeof raw === 'object' && raw.names && typeof raw.names === 'object' ? raw.names : {};
  for (const [id, name] of Object.entries(names)) {
    if (DEVICE_ID.test(id) && typeof name === 'string' && name) out[id] = name.slice(0, 64);
  }
  return out;
}

/** A device list ([{ mac, name, ips }]) as a lookup by address → { id, name }. */
function deviceTable(list) {
  const table = new Map();
  for (const d of Array.isArray(list) ? list : []) {
    if (!d || typeof d.mac !== 'string' || !d.mac) continue;
    const entry = { id: d.mac.toLowerCase(), name: typeof d.name === 'string' ? d.name : '' };
    for (const ip of Array.isArray(d.ips) ? d.ips : []) if (typeof ip === 'string' && ip) table.set(ip.toLowerCase(), entry);
  }
  return table;
}

/** Whose connection this is, from its source address: the router's own, a known device, or an address not yet known. */
function deviceOfSource(table, source) {
  const ip = String(source == null ? '' : source).toLowerCase().replace(/^::ffff:/, '');
  if (LOCAL_SOURCES.has(ip)) return { id: ROUTER_DEVICE, name: '' };
  return (table && table.get(ip)) || { id: ip, name: '', unknown: true };
}

/**
 * @param {object} o
 *   enabled()    settings.siteUsage
 *   connected()  is a connection up
 *   tun()        the live tunnel (`watch`, `sniffs`, `backendId`, `native`), or null
 *   load()       the saved object, save(obj) to keep it
 *   fetch(watch) the API's snapshot (a test's fake); now()
 *   limits       ROUTER_LIMITS on a router; absent: DESKTOP_LIMITS
 *   router       the tunnel's API exists only with the option on, so its absence means "reconnect"
 *   device(meta) { id, name, unknown? } of a connection (a router's); absent: no per-device figures
 *   refreshDevices() reads the list device() answers from, at most every deviceRefreshMs
 * → { start, stop, tick, report(range | { range, device }), clear, flush, status }
 */
function createSiteUsage(o) {
  const opts = Object.assign({ enabled: () => false, connected: () => false, tun: () => null, load: () => null, save: () => {}, fetch: (w) => fetchSnapshot(w) }, o || {});
  const now = typeof opts.now === 'function' ? opts.now : () => Date.now();
  const limits = Object.assign({}, DESKTOP_LIMITS, opts.limits);
  const perDevice = typeof opts.device === 'function';
  const saved = opts.load();
  const days = readDays(saved);
  const devices = perDevice ? readDevices(saved) : {};
  const names = perDevice ? readNames(saved) : Object.create(null);
  let last = null;       // { secret, at, conns: Map(id → { up, down, key, dev }), up, down } of the read before
  let dirty = false, savedAt = 0, busy = false, timer = null, stopped = true;
  let prunedDay = '', devicesAt = 0, wantDevices = false;
  let cost = null;       // the last read: { conns, ms }, what the page shows a router's owner

  function add(key, up, down, t) {
    if (!(up > 0 || down > 0)) return;
    const day = dayOf(t);
    const rows = days[day] || (days[day] = Object.create(null));
    if (!rows[key] && Object.keys(rows).length >= limits.maxKeys) key = 'u';
    const row = rows[key] || (rows[key] = [0, 0]);
    row[0] += up;
    row[1] += down;
    dirty = true;
  }

  /** The same under one device; a device past the day's ceiling stays in the house's figures only. */
  function addDevice(dev, key, up, down, t) {
    if (!dev || !(up > 0 || down > 0)) return;
    const day = dayOf(t);
    const devs = devices[day] || (devices[day] = Object.create(null));
    if (!devs[dev.id] && Object.keys(devs).length >= limits.maxDevices) return;
    const rows = devs[dev.id] || (devs[dev.id] = Object.create(null));
    if (!rows[key] && Object.keys(rows).length >= limits.maxDeviceKeys) key = 'u';
    const row = rows[key] || (rows[key] = [0, 0]);
    row[0] += up;
    row[1] += down;
    if (dev.name && names[dev.id] !== dev.name) names[dev.id] = dev.name.slice(0, 64);
  }

  /** Old days out, once a day: the walk is not worth a read's time. */
  function prune(t) {
    const today = dayOf(t);
    if (today === prunedDay) return;
    prunedDay = today;
    const oldest = dayOf(t - limits.keepDays * 86400000);
    for (const day of Object.keys(days)) if (day < oldest) { delete days[day]; dirty = true; }
    if (!perDevice) return;
    const oldestDevice = dayOf(t - limits.deviceKeepDays * 86400000);
    for (const day of Object.keys(devices)) if (day < oldestDevice) { delete devices[day]; dirty = true; }
    const seen = new Set();
    for (const devs of Object.values(devices)) for (const id of Object.keys(devs)) seen.add(id);
    for (const id of Object.keys(names)) if (!seen.has(id)) delete names[id];
  }

  function flush() {
    if (!dirty) return;
    dirty = false;
    savedAt = now();
    try { opts.save(perDevice ? { days, devices, names } : { days }); } catch { /* the figures are a convenience; the next save tries again */ }
  }

  /** Why nothing is being recorded, or 'recording'. */
  function status() {
    if (!opts.enabled()) return 'off';
    if (!opts.connected()) return 'notConnected';
    const tun = opts.tun();
    if (!tun) return 'noTun';
    if (!tun.watch) return opts.router ? 'reconnect' : (tun.native ? 'native' : 'tun2socks');
    return tun.sniffs ? 'recording' : 'reconnect';
  }

  /** One read of the API, into the buckets. The first read of a tunnel is only the baseline. */
  function account(snap, secret, t) {
    const conns = new Map();
    let attrUp = 0, attrDown = 0;
    for (const c of snap.connections) {
      if (!c || typeof c.id !== 'string' || !c.id) continue;
      const up = num(c.upload), down = num(c.download);
      const prev = last && last.secret === secret ? last.conns.get(c.id) : null;
      const key = prev ? prev.key : bucketOf(c.metadata);
      const dev = !perDevice ? null : prev ? prev.dev : opts.device(c.metadata || {});
      if (dev && dev.unknown) wantDevices = true;
      conns.set(c.id, { up, down, key, dev });
      if (!last || last.secret !== secret) continue;
      // seen before: what it moved since; new since then: all of it; older but unseen: from now on
      const fresh = !prev && (Date.parse(c.start) || 0) >= last.at;
      const dUp = prev ? Math.max(0, up - prev.up) : fresh ? up : 0;
      const dDown = prev ? Math.max(0, down - prev.down) : fresh ? down : 0;
      add(key, dUp, dDown, t);
      addDevice(dev, key, dUp, dDown, t);
      attrUp += dUp;
      attrDown += dDown;
    }
    if (last && last.secret === secret) {
      add('u', Math.max(0, snap.uploadTotal - last.up - attrUp), Math.max(0, snap.downloadTotal - last.down - attrDown), t);
    }
    last = { secret, at: t, conns, up: snap.uploadTotal, down: snap.downloadTotal };
  }

  async function tick() {
    if (busy) return;
    if (status() !== 'recording') {
      last = null;
      if (dirty) flush();
      return;
    }
    busy = true;
    try {
      const watch = opts.tun().watch;
      // before the read: a connection that opens while the answer travels is new to the next read, not "older but unseen"
      const t = now();
      if (perDevice && opts.refreshDevices && t - devicesAt >= (wantDevices ? DEVICE_RETRY_MS : limits.deviceRefreshMs)) {
        devicesAt = t;
        wantDevices = false;
        try { await opts.refreshDevices(); } catch { /* the addresses stand in until the next try */ }
      }
      const snap = await opts.fetch(watch);
      account(snap, watch.secret, t);
      prune(t);
      cost = { conns: snap.connections.length, ms: Math.max(0, now() - t) };
      if (dirty && t - savedAt >= limits.saveMs) flush();
    } catch { /* the API is silent for a moment: the next read's totals still cover it */ } finally {
      busy = false;
    }
  }

  /** How long until the next read: pollMs, or longer if reading takes more than its share of the time. */
  function nextDelay() {
    if (!limits.maxReadShare || !cost) return limits.pollMs;
    return Math.min(limits.maxPollMs, Math.max(limits.pollMs, cost.ms / limits.maxReadShare));
  }

  /** The devices seen in the period, busiest first: what the page's picker lists. */
  function deviceRows(from) {
    const sums = new Map();
    for (const [day, devs] of Object.entries(devices)) {
      if (day < from) continue;
      for (const [id, rows] of Object.entries(devs)) {
        const s = sums.get(id) || [0, 0];
        for (const v of Object.values(rows)) { s[0] += v[0]; s[1] += v[1]; }
        sums.set(id, s);
      }
    }
    return [...sums].map(([id, [up, down]]) => ({ id, name: names[id] || '', up, down, total: up + down }))
      .sort((a, b) => b.total - a.total || a.id.localeCompare(b.id, 'en'));
  }

  /** The rows of a day to sum: the house's, or one device's. */
  const rowsOfDay = (day, device) => (device ? (devices[day] && devices[day][device]) || null : days[day]);

  /** 'today', '7', '30', 'all', or { range, device } for one device's rows. */
  function report(req) {
    const q = req && typeof req === 'object' ? req : { range: req };
    const range = q.range;
    const r = Object.prototype.hasOwnProperty.call(RANGE_DAYS, range) || range === 'all' ? String(range) : '7';
    const device = perDevice && typeof q.device === 'string' && DEVICE_ID.test(q.device) ? q.device : '';
    const t = now();
    const from = r === 'all' ? '' : dayOf(t - (RANGE_DAYS[r] - 1) * 86400000);
    const sums = new Map();
    let first = '';
    for (const day of Object.keys(device ? devices : days)) {
      const dayRows = rowsOfDay(day, device);
      if (day < from || !dayRows) continue;
      if (!first || day < first) first = day;
      for (const [k, v] of Object.entries(dayRows)) {
        const s = sums.get(k) || [0, 0];
        s[0] += v[0];
        s[1] += v[1];
        sums.set(k, s);
      }
    }
    const rows = [...sums].map(([key, [up, down]]) => Object.assign({ key, up, down, total: up + down }, describe(key)))
      .sort((a, b) => b.total - a.total || a.key.localeCompare(b.key, 'en'));
    const total = rows.reduce((s, x) => ({ up: s.up + x.up, down: s.down + x.down, total: s.total + x.total }), { up: 0, down: 0, total: 0 });
    const out = { range: r, status: status(), since: first, total, rows: rows.slice(0, MAX_ROWS), more: Math.max(0, rows.length - MAX_ROWS) };
    if (perDevice) Object.assign(out, { device, devices: deviceRows(from), deviceDays: limits.deviceKeepDays, cost: cost && out.status === 'recording' ? { conns: cost.conns, ms: cost.ms, everyMs: Math.round(nextDelay()) } : null });
    return out;
  }

  function clear() {
    for (const day of Object.keys(days)) delete days[day];
    for (const day of Object.keys(devices)) delete devices[day];
    for (const id of Object.keys(names)) delete names[id];
    last = null;
    dirty = true;
    flush();
    return { ok: true };
  }

  function schedule() {
    if (stopped) return;
    timer = setTimeout(() => { tick().finally(schedule); }, nextDelay());
    if (timer.unref) timer.unref();
  }
  function start() {
    if (!stopped) return;
    stopped = false;
    schedule();
  }
  function stop() {
    stopped = true;
    if (timer) clearTimeout(timer);
    timer = null;
    flush();
  }

  return { start, stop, tick, report, clear, flush, status, nextDelay };
}

module.exports = { createSiteUsage, bucketOf, describe, serviceOfHost, registrable, ipServiceOf, dayOf, readDays, readDevices, readNames, deviceTable, deviceOfSource, ROUTER_LIMITS, DESKTOP_LIMITS, ROUTER_DEVICE, POLL_MS, MAX_KEYS_PER_DAY, KEEP_DAYS };
