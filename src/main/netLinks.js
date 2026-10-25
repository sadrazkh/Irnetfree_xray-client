'use strict';
/**
 * Multi-internet (v1.32.0): which internets this machine has right now, and
 * how fast each one is through the server.
 *
 * An "internet" (a link) is a network interface holding an IPv4 default route
 * that is up. Xray can bind any outbound to one of them
 * (`streamSettings.sockopt.interface`: Windows IP_UNICAST_IF by the adapter's
 * alias, macOS IP_BOUND_IF by the BSD device, Linux/OpenWrt SO_BINDTODEVICE by
 * the dev), and for that the interface needs a default route of its own: a
 * bound socket is routed by the routes OF THAT INTERFACE only. Windows keeps
 * one per connected adapter with a gateway, macOS a scoped one per active
 * service, Linux one per dev that DHCP (or netifd) gave a metric. So the
 * default routes are the list — never our own TUN adapters, which are not a
 * way out of the machine.
 *
 *  - listLinks({ platform, run }) → [{ id, iface, name, kind, address, gateway, metric }],
 *    the OS's preferred first. `iface` is exactly what sockopt.interface takes;
 *    `id` is the same string (the settings key a link is remembered by).
 *  - speedTest({ link, server, buildTestConfig, … }) → { id, ok, rttMs, downMbps, upMbps, error }:
 *    a throwaway core whose every self-dialling outbound is bound to the link,
 *    and through its SOCKS a latency, a download and an upload against
 *    Cloudflare's speed endpoints.
 *  - testAll({ links, … }): one link after another — two at once would share
 *    the machine's bandwidth (and the server's) and both numbers would lie.
 *
 * Every command here only reads. `run` (tunPlatform.run's shape) and the other
 * I/O are injectable, so the tests feed recorded outputs of each OS.
 */

const os = require('os');
const fs = require('fs');
const path = require('path');
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const { spawn } = require('child_process');
const tunPlatform = require('./tunPlatform');
const { isOpenwrt } = require('./openwrtNet');
const { socks5Connect } = require('./netutils');
const { echQueryOf } = require('./configBuilder');
const { engineRunArgs } = require('./engines');

const KINDS = Object.freeze(['wifi', 'ethernet', 'cellular', 'usb', 'other']);

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
/** PowerShell 5.1 unwraps a one-element array into the object; junk is nothing. */
const list = (v) => (Array.isArray(v) ? v : (isObj(v) ? [v] : [])).filter(isObj);
const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
const str = (v) => (v == null ? '' : String(v)).trim();

// ---------------------------------------------------------------- Windows ---

/**
 * One PowerShell for everything Windows knows about its internets: the very
 * default-route rows the gateway pick reads (tunPlatform.DEFAULT_ROUTE_ROWS_PS,
 * `$out`), every adapter (its description and media type tell Wi-Fi from a
 * phone's USB tethering — "Remote NDIS based Internet Sharing Device"), the
 * IPv4 addresses, and the connection profiles (a Wi-Fi profile is named after
 * its SSID — the cheap way to say which Wi-Fi it is). Read-only cmdlets only.
 */
const LINKS_PS = [
  tunPlatform.DEFAULT_ROUTE_ROWS_PS,
  '$ads = @()',
  'foreach ($a in @(Get-NetAdapter)) {',
  '$ads += [pscustomobject]@{ ifIndex = [int]$a.ifIndex; name = [string]$a.Name; desc = [string]$a.InterfaceDescription;'
    + ' media = [string]$a.MediaType; phys = [string]$a.PhysicalMediaType; medium = [int]$a.NdisPhysicalMedium; status = [string]$a.Status }',
  '}',
  '$ips = @()',
  'foreach ($p in @(Get-NetIPAddress -AddressFamily IPv4)) {',
  '$ips += [pscustomobject]@{ ifIndex = [int]$p.InterfaceIndex; ip = [string]$p.IPAddress; state = [string]$p.AddressState }',
  '}',
  '$cps = @()',
  'foreach ($c in @(Get-NetConnectionProfile)) { $cps += [pscustomobject]@{ ifIndex = [int]$c.InterfaceIndex; name = [string]$c.Name } }',
  'ConvertTo-Json -InputObject ([pscustomobject]@{ routes = @($out); adapters = @($ads); addrs = @($ips); profiles = @($cps) }) -Depth 4 -Compress'
].join('\n');

/**
 * What kind of internet a Windows adapter is. The description comes first: a
 * phone's USB tethering is an 802.3 adapter to Windows ("Remote NDIS…", an
 * iPhone's "Apple Mobile Device Ethernet"), and a VPN's TAP is 802.3 too.
 * NdisPhysicalMedium: 8 wireless WAN, 9 native 802.11, 10 Bluetooth, 14 802.3.
 */
function kindWin(a) {
  if (!isObj(a)) return 'other';
  const desc = str(a.desc);
  const media = `${str(a.media)} ${str(a.phys)}`;
  const medium = num(a.medium);
  if (/remote ndis|rndis|apple mobile device ethernet|usb tether|android/i.test(desc)) return 'usb';
  if (/bluetooth/i.test(desc + ' ' + media) || medium === 10) return 'other';
  if (/tap-windows|wintun|wireguard|openvpn|data channel offload|\bvpn\b|tunnel/i.test(desc)) return 'other';
  if (/wireless wan|mobile broadband|\bwwan\b|cellular|\blte\b|\b5g\b/i.test(media + ' ' + desc) || medium === 8) return 'cellular';
  if (/802\.11|wireless lan/i.test(media) || medium === 9 || /wi-?fi|wireless|802\.11|wlan/i.test(desc)) return 'wifi';
  if (/802\.3/.test(media) || medium === 14 || /ethernet|gigabit|\blan\b|gbe\b/i.test(desc)) return 'ethernet';
  return 'other';
}

/** An interface's address to show: a Preferred one that is not link-local, else any. */
function pickAddressWin(rows) {
  const v4 = list(rows).filter((r) => net.isIPv4(str(r.ip)));
  const good = (r) => !str(r.ip).startsWith('169.254.');
  const best = v4.find((r) => good(r) && /^preferred$/i.test(str(r.state))) || v4.find(good) || v4[0];
  return best ? str(best.ip) : '';
}

/**
 * The parsed LINKS_PS answer → links. Rows are chosen exactly as the gateway
 * pick chooses them (connected interfaces, never our TUN — liveDefaultRoutesWin),
 * plus on-link defaults (PPPoE, mobile broadband: no next hop, still a way
 * out). An adapter Windows reports as anything but Up is not one.
 */
function linksFromWin(data) {
  const d = isObj(data) ? data : {};
  const routes = tunPlatform.liveDefaultRoutesWin(list(d.routes), { onLink: true });
  const adapters = new Map(list(d.adapters).map((a) => [num(a.ifIndex), a]));
  const addrs = new Map();
  for (const r of list(d.addrs)) {
    const k = num(r.ifIndex);
    if (!addrs.has(k)) addrs.set(k, []);
    addrs.get(k).push(r);
  }
  const profiles = new Map(list(d.profiles).map((p) => [num(p.ifIndex), str(p.name)]));
  const out = [];
  const seen = new Set();
  for (const r of routes) {
    const iface = str(r.alias);
    if (!iface || seen.has(iface)) continue;   // a second gateway on the same adapter: the better one came first
    const idx = num(r.ifIndex);
    const a = adapters.get(idx) || null;      // a PPP connection is not a "net adapter": no facts, still a link
    if (a && str(a.status) && !/^up$/i.test(str(a.status))) continue;
    seen.add(iface);
    const kind = kindWin(a);
    const profile = profiles.get(idx) || '';
    // the Wi-Fi's SSID, a mobile network's operator: what the profile is named after
    const name = (kind === 'wifi' || kind === 'cellular') && profile && profile !== iface ? `${iface} — ${profile}` : iface;
    out.push({
      id: iface, iface, name, kind,
      address: pickAddressWin(addrs.get(idx)),
      gateway: str(r.nextHop) === '0.0.0.0' ? '' : str(r.nextHop),
      metric: num(r.routeMetric) + num(r.ifMetric)   // what Windows itself compares
    });
  }
  return out;
}

async function listWin(run, timeout) {
  const outText = String(await run('powershell', tunPlatform.psArgs(LINKS_PS), { timeout }) || '');
  const at = outText.indexOf('{');
  let data = null;
  try { data = at === -1 ? null : JSON.parse(outText.slice(at).trim()); } catch { data = null; }
  return linksFromWin(data);
}

// ------------------------------------------------------------------ macOS ---

/**
 * `netstat -rn -f inet` → the default routes, in the table's order:
 * [{ dev, gateway, scoped }]. The column holding the device is read from the
 * header (Big Sur dropped Refs/Use). `I` in the flags is RTF_IFSCOPE: the
 * scoped default every secondary service keeps — exactly what IP_BOUND_IF
 * routes by. `link#N` is an on-link default (no gateway). Down routes, the
 * loopback and our own utun are no way out.
 */
function parseNetstatDefaults(text) {
  const lines = String(text || '').split(/\r?\n/);
  let col = 3;
  const out = [];
  for (const raw of lines) {
    const t = raw.trim().split(/\s+/);
    if (t[0] === 'Destination' && t.includes('Netif')) { col = t.indexOf('Netif'); continue; }
    if (t[0] !== 'default' || t.length < 3) continue;
    const flags = t[2] || '';
    const dev = t[col] || '';
    if (!dev || !flags.includes('U') || /^lo\d*$/.test(dev) || tunPlatform.isOwnTunInterface(dev)) continue;
    out.push({ dev, gateway: net.isIPv4(t[1]) ? t[1] : '', scoped: flags.includes('I') });
  }
  return out;
}

/** `networksetup -listallhardwareports` → { en0: 'Wi-Fi', en7: 'iPhone USB', … }. */
function parseHardwarePorts(text) {
  const out = {};
  let port = '';
  for (const raw of String(text || '').split(/\r?\n/)) {
    const p = /^Hardware Port:\s*(.+?)\s*$/.exec(raw);
    if (p) { port = p[1]; continue; }
    const d = /^Device:\s*(\S+)/.exec(raw);
    if (d && port) { if (!out[d[1]]) out[d[1]] = port; port = ''; }
  }
  return out;
}

/** `networksetup -listnetworkserviceorder` → the devices in the user's service order. */
function parseServiceOrder(text) {
  const out = [];
  for (const raw of String(text || '').split(/\r?\n/)) {
    const m = /Device:\s*([^)\s]+)\)/.exec(raw);
    if (m && !out.includes(m[1])) out.push(m[1]);
  }
  return out;
}

/** A macOS hardware port's kind: the phone first ("iPhone USB"), a LAN dongle is still ethernet. */
function kindMac(port, dev) {
  const p = str(port);
  if (/iphone|ipad|android|tether|rndis|\bncm\b/i.test(p)) return 'usb';
  if (/wi-?fi|airport|wlan|wireless/i.test(p)) return 'wifi';
  if (/bluetooth/i.test(p)) return 'other';
  if (/modem|mobile|wwan|\blte\b|cellular|\b[345]g\b/i.test(p)) return 'cellular';
  if (/ethernet|\blan\b|thunderbolt|gigabit/i.test(p)) return 'ethernet';
  if (/usb/i.test(p)) return 'usb';
  return /^en\d+$/.test(str(dev)) && !p ? 'ethernet' : 'other';
}

/** os.networkInterfaces()[dev] → its first non-internal IPv4 ('' when none). */
function nodeAddress(interfaces, dev) {
  let all = {};
  try { all = (typeof interfaces === 'function' ? interfaces() : interfaces) || {}; } catch { all = {}; }
  const rows = Array.isArray(all[dev]) ? all[dev] : [];
  const v4 = rows.find((r) => r && (r.family === 'IPv4' || r.family === 4) && !r.internal && net.isIPv4(str(r.address)));
  return v4 ? str(v4.address) : '';
}

/**
 * macOS has no metric to show: the order is the OS's — the unscoped default
 * (the primary service) first, then the scoped ones in the user's service
 * order — and `metric` is the place in it.
 */
async function listMac(run, interfaces, timeout) {
  const routes = parseNetstatDefaults(await run('netstat', ['-rn', '-f', 'inet'], { timeout }));
  let ports = {};
  try { ports = parseHardwarePorts(await run('networksetup', ['-listallhardwareports'], { timeout })); } catch { ports = {}; }
  let order = [];
  try { order = parseServiceOrder(await run('networksetup', ['-listnetworkserviceorder'], { timeout })); } catch { order = []; }
  const rank = (dev) => { const i = order.indexOf(dev); return i === -1 ? order.length : i; };
  const sorted = routes.map((r, i) => Object.assign({ i }, r))
    .sort((a, b) => (Number(a.scoped) - Number(b.scoped)) || (rank(a.dev) - rank(b.dev)) || (a.i - b.i));
  const out = [];
  for (const r of sorted) {
    if (out.some((l) => l.iface === r.dev)) continue;
    const port = ports[r.dev] || '';
    out.push({ id: r.dev, iface: r.dev, name: port || r.dev, kind: kindMac(port, r.dev), address: nodeAddress(interfaces, r.dev), gateway: r.gateway, metric: out.length });
  }
  return out;
}

// --------------------------------------------------------- Linux, OpenWrt ---

/**
 * `ip -4 route show default` (iproute2 — OpenWrt's package depends on
 * ip-full) → [{ dev, gateway, metric, src }], every line: two DHCP'd
 * internets are two `default via` lines with their metrics, a multipath
 * default is one line with a `nexthop` line per way out. A `linkdown` or
 * `dead` route is an interface without carrier. Our own TUN is dropped.
 */
function parseIpDefaultRoutes(text) {
  const out = [];
  let parent = null;
  for (const raw of String(text || '').split(/\r?\n/)) {
    if (!raw.trim()) continue;
    const t = raw.trim().split(/\s+/);
    const val = (k) => { const i = t.indexOf(k); return i > -1 ? t[i + 1] : undefined; };
    const via = () => { const v = val('via'); return v === 'inet' || v === 'inet6' ? t[t.indexOf('via') + 2] : v; };
    const add = (metric, src) => {
      const dev = str(val('dev')).replace(/@.*$/, '');
      if (!dev || t.includes('linkdown') || t.includes('dead') || tunPlatform.isOwnTunInterface(dev)) return;
      const gw = str(via());
      out.push({ dev, gateway: net.isIPv4(gw) ? gw : '', metric, src: net.isIPv4(str(val('src'))) ? str(val('src')) : src });
    };
    if (!/^\s/.test(raw)) {
      parent = t[0] === 'default' ? { metric: num(val('metric')), src: net.isIPv4(str(val('src'))) ? str(val('src')) : '' } : null;
      if (parent && val('dev')) add(parent.metric, parent.src);
    } else if (parent && t[0] === 'nexthop') {
      add(parent.metric, parent.src);
    }
  }
  return out;
}

/** `ip -4 -o addr show` → { dev: firstGlobalIPv4 }. */
function parseIpAddrs(text) {
  const out = {};
  for (const raw of String(text || '').split(/\r?\n/)) {
    const t = raw.trim().split(/\s+/);
    const i = t.indexOf('inet');
    if (i < 1) continue;
    const dev = str(t[1]).replace(/:$/, '').replace(/@.*$/, '');
    const ip = str(t[i + 1]).split('/')[0];
    if (!dev || !net.isIPv4(ip)) continue;
    const global = /\bscope global\b/.test(raw);
    if (!out[dev] || (global && !out[dev].global)) out[dev] = { ip, global };
  }
  return Object.fromEntries(Object.entries(out).map(([k, v]) => [k, v.ip]));
}

/** The OpenWrt protocols whose device is a mobile modem. */
const CELL_PROTOS = /^(qmi|mbim|3g|ncm|modemmanager|wwan|directip|uqmi)$/i;

/**
 * A Linux dev's kind: the driver behind it first (sysfs, when there is one —
 * a phone's tethering is rndis_host / cdc_ncm / ipheth, a modem qmi_wwan /
 * cdc_mbim), then what the kernel calls it (DEVTYPE wlan/wwan), then OpenWrt's
 * protocol for it, then the name (wl* wifi, ww* cellular, usb* tethering).
 */
function kindLinux(dev, sys, proto) {
  const d = str(dev);
  const s = isObj(sys) ? sys : {};
  const drv = str(s.driver);
  const devtype = str(s.devtype).toLowerCase();
  if (/^(qmi_wwan|cdc_mbim|huawei_cdc_ncm|sierra_net|option)$/.test(drv) || devtype === 'wwan') return 'cellular';
  if (devtype === 'wlan' || s.wireless) return 'wifi';
  if (/^(rndis_host|cdc_ether|cdc_ncm|cdc_eem|ipheth)$/.test(drv)) return 'usb';
  if (CELL_PROTOS.test(str(proto))) return 'cellular';
  if (/^pppoe/i.test(str(proto)) || /^pppoe-/.test(d)) return 'ethernet';
  if (/^(ww|rmnet|ccmni|mhi|3g-)/.test(d)) return 'cellular';
  if (/^(wl|wlan|ath\d|ra\d|mlan|phy\d+-sta)/.test(d)) return 'wifi';
  if (/^(usb|rndis)\d*/.test(d) || /^en\w*u\d+/.test(d)) return 'usb';
  if (/^(eth|en|lan|wan|br-)/.test(d)) return 'ethernet';
  return 'other';
}

/** What sysfs says about a dev (Linux only); {} wherever it says nothing. Never throws. */
function readSysNet(dev) {
  const d = str(dev);
  if (!/^[A-Za-z0-9_.:@-]+$/.test(d) || d.includes('..')) return {};
  const base = `/sys/class/net/${d}`;
  const out = {};
  try { const m = /^DEVTYPE=(\S+)/m.exec(fs.readFileSync(`${base}/uevent`, 'utf8')); if (m) out.devtype = m[1]; } catch { /* none */ }
  try { out.wireless = fs.existsSync(`${base}/wireless`) || fs.existsSync(`${base}/phy80211`); } catch { /* none */ }
  try { out.driver = path.basename(fs.readlinkSync(`${base}/device/driver`)); } catch { /* virtual: no driver */ }
  return out;
}

/**
 * netifd's names for the devs (`ubus call network.interface dump`): dev →
 * { name, proto }. The interface holding the IPv4 default wins (wan, not wan6,
 * on a shared device). A modem protocol puts its addresses on a dynamic
 * `<name>_4` interface — the user knows it as `<name>`, and its protocol is
 * the parent's.
 */
function logicalByDev(dump) {
  const ifaces = isObj(dump) ? list(dump.interface) : [];
  const byName = new Map(ifaces.map((i) => [str(i.interface), i]));
  const out = new Map();
  for (const i of ifaces) {
    const name = str(i.interface);
    const dev = str(i.l3_device) || str(i.device);
    if (!name || !dev || dev.startsWith('/') || name === 'loopback') continue;
    const def4 = list(i.route).some((r) => net.isIPv4(str(r.target)) && num(r.mask) === 0);
    const m = /^(.+)_[46]$/.exec(name);
    const parent = m && byName.get(m[1]);
    const entry = { name: parent ? m[1] : name, proto: str(parent ? parent.proto : i.proto) || str(i.proto), def4 };
    const cur = out.get(dev);
    if (!cur || (def4 && !cur.def4)) out.set(dev, entry);
  }
  return out;
}

async function listLinux(run, { openwrt, sysInfo, timeout }) {
  const routes = parseIpDefaultRoutes(await run('ip', ['-4', 'route', 'show', 'default'], { timeout }));
  let addrs = {};
  try { addrs = parseIpAddrs(await run('ip', ['-4', '-o', 'addr', 'show'], { timeout })); } catch { addrs = {}; }
  let names = new Map();
  if (openwrt) {
    try { names = logicalByDev(JSON.parse(await run('ubus', ['call', 'network.interface', 'dump'], { timeout }))); } catch { names = new Map(); }
  }
  const sorted = routes.map((r, i) => Object.assign({ i }, r)).sort((a, b) => (a.metric - b.metric) || (a.i - b.i));
  const out = [];
  for (const r of sorted) {
    if (out.some((l) => l.iface === r.dev)) continue;   // a second default on the same dev: the better one came first
    const logical = names.get(r.dev);
    let sys = {};
    try { sys = (sysInfo ? sysInfo(r.dev) : {}) || {}; } catch { sys = {}; }
    out.push({
      id: r.dev, iface: r.dev,
      name: logical ? logical.name : r.dev,
      kind: kindLinux(r.dev, sys, logical && logical.proto),
      address: r.src || addrs[r.dev] || '',
      gateway: r.gateway,
      metric: r.metric
    });
  }
  return out;
}

/**
 * Every internet this machine could leave by right now, the OS's preferred
 * first. Never throws: a failing command is an empty list.
 *
 * opts: platform (os.platform(); 'openwrt' is accepted too), run (tunPlatform.run's
 * shape), openwrt (default: platform linux and /etc/openwrt_release — the
 * router runs this same code), interfaces (os.networkInterfaces, macOS
 * addresses), sysInfo (dev → sysfs facts, Linux kinds), timeoutMs per command.
 */
async function listLinks(opts = {}) {
  const platform = opts.platform || os.platform();
  const run = typeof opts.run === 'function' ? opts.run : tunPlatform.run;
  const timeout = opts.timeoutMs > 0 ? opts.timeoutMs : 15000;
  try {
    if (platform === 'win32') return await listWin(run, timeout);
    if (platform === 'darwin') return await listMac(run, opts.interfaces || os.networkInterfaces, timeout);
    const openwrt = typeof opts.openwrt === 'boolean' ? opts.openwrt : (platform === 'openwrt' || (platform === 'linux' && isOpenwrt()));
    // sysfs is only this machine's to read: a Linux list asked for on another OS (the tests) goes by names
    const sysInfo = typeof opts.sysInfo === 'function' ? opts.sysInfo : (os.platform() === 'linux' ? readSysNet : null);
    return await listLinux(run, { openwrt, sysInfo, timeout });
  } catch {
    return [];
  }
}

// ------------------------------------------------------------- speed test ---

/** Protocols that never open a socket of their own. */
const NO_DIAL = new Set(['dns', 'blackhole', 'loopback']);

/**
 * Bind every dial the config's core makes ITSELF to `iface`, in place: each
 * outbound without a sockopt.dialerProxy (the server, a chain's first hop, the
 * dpi-* fragment dialers, `direct`, an ech-* outbound), an XHTTP downlink's own
 * dial (`extra.downloadSettings.sockopt` — the downlink dials with it), and an
 * ECH config fetched from DNS (`echSockopt`). A hop behind another hop dials
 * through it and is left alone — as configBuilder.bindDirectDials does under
 * TUN, except that here an interface already set is replaced: the test is of
 * THIS link.
 */
function bindToInterface(config, iface) {
  const name = str(iface);
  const outs = isObj(config) && Array.isArray(config.outbounds) ? config.outbounds : [];
  if (!name) return config;
  const bind = (holder, key) => {
    const so = isObj(holder[key]) ? holder[key] : {};
    if (so.dialerProxy) return;
    holder[key] = Object.assign({}, so, { interface: name });
  };
  for (const o of outs) {
    if (!isObj(o) || NO_DIAL.has(o.protocol)) continue;
    const ss = isObj(o.streamSettings) ? o.streamSettings : (o.streamSettings = {});
    bind(ss, 'sockopt');
    for (const k of ['xhttpSettings', 'splithttpSettings']) {
      const extra = isObj(ss[k]) && isObj(ss[k].extra) ? ss[k].extra : null;
      if (extra && isObj(extra.downloadSettings)) bind(extra.downloadSettings, 'sockopt');
    }
    const t = ss.tlsSettings;
    if (isObj(t) && echQueryOf(t.echConfigList)) bind(t, 'echSockopt');
  }
  return config;
}

/** Cloudflare's speed test endpoints: no account, no cookie, sizes by query. */
const SPEED_HOST = 'speed.cloudflare.com';
const RTT_PATH = '/__down?bytes=0';
const DOWN_BYTES = 4000000;
const UP_BYTES = 2000000;
/** The upload goes as four POSTs: each one the server answers is a measured part, so a slow link still gets a number. */
const UP_PART = 500000;
/** One link's whole budget, core start to the last byte. */
const SPEED_TIMEOUT_MS = 25000;
/** Phases inside it: the connect + latency, the download's box, what the upload keeps for itself. */
const CONNECT_MS = 10000;
const DOWN_BOX_MS = 10000;
const UP_RESERVE_MS = 8000;
const RETRY_MS = 150;
const UA = 'IRNetFree-speedtest';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const round1 = (v) => (typeof v === 'number' && Number.isFinite(v) ? Math.round(v * 10) / 10 : null);
const errText = (e) => str((e && (e.message || e.code)) || e) || 'failed';

/**
 * The chunked body's payload bytes, counted as they arrive (nothing is kept):
 * push(buf) → { bytes, done }. Enough of RFC 9112 §7.1 for a speed test.
 */
function chunkedCounter() {
  let state = 'size';
  let line = '';
  let left = 0;
  let done = false;
  return {
    push(buf) {
      let i = 0;
      let bytes = 0;
      while (i < buf.length && !done) {
        if (state === 'size' || state === 'trailer') {
          const nl = buf.indexOf(0x0a, i);
          const end = nl === -1 ? buf.length : nl;
          line += buf.toString('latin1', i, end);
          if (line.length > 4096) throw new Error('bad chunked body');
          if (nl === -1) { i = buf.length; break; }
          i = nl + 1;
          const l = line.replace(/\r$/, '');
          line = '';
          if (state === 'trailer') { if (l === '') done = true; continue; }
          const n = parseInt(l.split(';')[0].trim(), 16);
          if (!Number.isFinite(n) || n < 0) throw new Error('bad chunked body');
          if (n === 0) state = 'trailer'; else { left = n; state = 'data'; }
        } else if (state === 'data') {
          const take = Math.min(left, buf.length - i);
          bytes += take; left -= take; i += take;
          if (left === 0) state = 'crlf';
        } else {   // the CRLF after a chunk's data
          const nl = buf.indexOf(0x0a, i);
          if (nl === -1) { i = buf.length; break; }
          i = nl + 1;
          state = 'size';
        }
      }
      return { bytes, done };
    }
  };
}

/**
 * HTTP/1.1 over one TLS socket, kept alive between requests: the latency is
 * a request on a WARM connection (the handshakes through the proxy are not a
 * round trip), and the download and upload ride the same connection's grown
 * window. A body is counted, never kept. request() → { status, headAt, endAt,
 * bodyBytes, lateBytes (body bytes after the head's own packet — what a speed
 * is measured over), timedOut, reusable }. `partial`: running out of time
 * with the head in is an answer (what arrived so far); otherwise a timeout
 * is an error. `headOnly`: only the head's time matters (the latency, an
 * upload's answer) — a body that would only end with the connection is not
 * waited for. After a timeout, an error or a non-reusable answer the
 * connection is closed.
 */
class HttpConn {
  constructor(socket) {
    this.socket = socket;
    this.dead = false;
    // an 'error' with no listener would be thrown as an uncaught exception
    socket.on('error', (e) => { this.dead = true; this.lastError = e; });
    socket.on('close', () => { this.dead = true; });
  }

  close() {
    this.dead = true;
    try { this.socket.destroy(); } catch { /* gone */ }
  }

  request({ method = 'GET', path: p = '/', host = SPEED_HOST, body = null, deadline, partial = false, headOnly = false }) {
    return new Promise((resolve, reject) => {
      if (this.dead) { reject(new Error((this.lastError && errText(this.lastError)) || 'connection closed')); return; }
      const s = this.socket;
      let done = false;
      let head = Buffer.alloc(0);
      let res = null;
      let framing = 'none';
      let left = 0;
      let counter = null;
      let bodyBytes = 0;
      let lateBytes = 0;
      const finish = (err, timedOut) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        s.removeListener('data', onData);
        s.removeListener('close', onClose);
        s.removeListener('error', onError);
        const reusable = !!(res && res.keepAlive && !err && !timedOut && framing !== 'close');
        if (!reusable) this.close();
        if (err) { reject(err); return; }
        if (timedOut && !(partial && res)) { reject(new Error('timeout')); return; }
        resolve({ status: res.status, headAt: res.headAt, endAt: Date.now(), bodyBytes, lateBytes, timedOut: !!timedOut, reusable });
      };
      const consume = (buf, inHead) => {
        if (framing === 'length') {
          const take = Math.min(left, buf.length);
          left -= take; bodyBytes += take; if (!inHead) lateBytes += take;
          if (left === 0) finish(null);
        } else if (framing === 'chunked') {
          const r = counter.push(buf);
          bodyBytes += r.bytes; if (!inHead) lateBytes += r.bytes;
          if (r.done) finish(null);
        } else if (framing === 'close') {
          bodyBytes += buf.length; if (!inHead) lateBytes += buf.length;
        } else {
          finish(null);
        }
      };
      const onHead = () => {
        for (;;) {
          const at = head.indexOf('\r\n\r\n');
          if (at === -1) { if (head.length > 65536) finish(new Error('bad answer')); return; }
          const lines = head.subarray(0, at).toString('latin1').split('\r\n');
          const rest = head.subarray(at + 4);
          const m = /^HTTP\/(\d)\.(\d)\s+(\d{3})/.exec(lines[0] || '');
          if (!m) { finish(new Error('bad answer')); return; }
          const status = Number(m[3]);
          if (status >= 100 && status < 200) { head = Buffer.from(rest); continue; }   // 100 Continue: the real head follows
          const h = {};
          for (const l of lines.slice(1)) { const c = l.indexOf(':'); if (c > 0) h[l.slice(0, c).trim().toLowerCase()] = l.slice(c + 1).trim(); }
          const conn = str(h.connection).toLowerCase();
          const keepAlive = m[1] === '1' && m[2] === '1' ? conn !== 'close' : conn === 'keep-alive';
          res = { status, headAt: Date.now(), keepAlive };
          head = null;
          if (method === 'HEAD' || status === 204 || status === 304) framing = 'none';
          else if (/chunked/i.test(str(h['transfer-encoding']))) { framing = 'chunked'; counter = chunkedCounter(); }
          else if (/^\d+$/.test(str(h['content-length']))) { framing = 'length'; left = Number(h['content-length']); }
          else framing = 'close';
          if (framing === 'length' && left === 0) { finish(null); return; }
          if (framing === 'none' || (framing === 'close' && headOnly)) { finish(null); return; }   // the latter closes the connection
          if (rest.length) consume(rest, true);
          return;
        }
      };
      const onData = (chunk) => {
        if (done) return;
        try {
          if (!res) { head = Buffer.concat([head, chunk]); onHead(); return; }
          consume(chunk, false);
        } catch (e) { finish(e); }
      };
      const onClose = () => {
        if (res && framing === 'close') finish(null);   // a close-delimited body ends here
        else finish(new Error((this.lastError && errText(this.lastError)) || 'connection closed'));
      };
      const onError = (e) => finish(e);
      const timer = setTimeout(() => finish(null, true), Math.max(0, num(deadline) - Date.now()));
      s.on('data', onData);
      s.on('close', onClose);
      s.on('error', onError);
      const lines = [`${method} ${p} HTTP/1.1`, `Host: ${host}`, `User-Agent: ${UA}`, 'Accept: */*', `Referer: https://${host}/`, 'Connection: keep-alive'];
      if (body) lines.push('Content-Type: application/octet-stream', `Content-Length: ${body.length}`);
      try {
        s.write(lines.join('\r\n') + '\r\n\r\n');
        if (body) s.write(body);
      } catch (e) { finish(e); }
    });
  }
}

/**
 * The real way in: SOCKS5 CONNECT on the test core's port to host:443 (the
 * name goes to the proxy — nothing is looked up here), then TLS with the
 * certificate checked as any HTTPS client checks it.
 */
function socksTls({ port, host, timeoutMs }) {
  return socks5Connect('127.0.0.1', port, host, 443, Math.max(1, timeoutMs)).then((raw) => new Promise((resolve, reject) => {
    let s;
    try { s = tls.connect({ socket: raw, servername: host, ALPNProtocols: ['http/1.1'] }); } catch (e) { raw.destroy(); reject(e); return; }
    const timer = setTimeout(() => fail(new Error('timeout')), Math.max(1, timeoutMs));
    const fail = (e) => { clearTimeout(timer); s.removeListener('secureConnect', ok); s.destroy(); reject(e); };
    const ok = () => { clearTimeout(timer); s.removeListener('error', fail); s.removeListener('close', closed); resolve(s); };
    const closed = () => fail(new Error('connection closed'));
    s.once('secureConnect', ok);
    s.once('error', fail);
    s.once('close', closed);
  }));
}

/**
 * The three measurements through the test core's SOCKS on `port`, written
 * into `acc` as each one finishes (a hard timeout outside keeps what is
 * there): rttMs — a tiny request on a warm connection; downMbps — 4 MB
 * from `__down`, time-boxed: what arrived in the box is the speed; upMbps —
 * 2 MB to `__up` as four parts, each part's time less one round trip (the
 * answer's way back), the parts that were answered in time counted. A failed
 * phase names itself in `acc.error` and the next still runs; with no latency
 * nothing else can work and it stops there. `connect` and `track` are for the
 * caller: the transport (tests: a fake) and every socket opened (to destroy).
 */
async function measureThroughSocks({ port, deadline, acc, track = () => {}, isAlive = () => true, connect = socksTls }) {
  const open = async (until) => {
    for (;;) {
      const left = until - Date.now();
      if (left <= 0) throw new Error('timeout');
      try {
        const s = await connect({ port, host: SPEED_HOST, timeoutMs: left });
        track(s);
        return new HttpConn(s);
      } catch (e) {
        // the core's port refusing: a core still starting, not an answer (mux.probeMux)
        if (/ECONNREFUSED/.test(String((e && (e.code || e.message)) || '')) && isAlive() && Date.now() + RETRY_MS < until) { await sleep(RETRY_MS); continue; }
        throw e;
      }
    }
  };
  const okStatus = (r) => { if (!(r.status >= 200 && r.status < 400)) throw new Error('HTTP ' + r.status); return r; };
  let conn = null;
  const drop = () => { if (conn) conn.close(); conn = null; };
  const ready = async (until) => { if (!conn || conn.dead) conn = await open(until); return conn; };

  try {   // 1. latency: one request to warm the connection, the next one timed
    const until = Math.min(deadline, Date.now() + CONNECT_MS);
    const warm = okStatus(await (await ready(until)).request({ path: RTT_PATH, deadline: until, headOnly: true }));
    if (!warm.reusable) drop();
    const c = await ready(until);
    const t = Date.now();
    const r = okStatus(await c.request({ path: RTT_PATH, deadline: until, headOnly: true }));
    acc.rttMs = r.headAt - t;
    if (!r.reusable) drop();
  } catch (e) {
    drop();
    acc.error = 'latency: ' + errText(e);
    return;
  }

  try {   // 2. download, in its box — leaving the upload its share of the budget
    const now = Date.now();
    const until = Math.min(deadline, now + DOWN_BOX_MS, Math.max(now + 2000, deadline - UP_RESERVE_MS));
    const r = okStatus(await (await ready(until)).request({ path: `/__down?bytes=${DOWN_BYTES}`, deadline: until, partial: true }));
    const secs = (r.endAt - r.headAt) / 1000;
    if (!(r.lateBytes > 0 && secs > 0)) throw new Error(r.timedOut ? 'timeout' : 'no data');
    acc.downMbps = (r.lateBytes * 8) / secs / 1e6;
    if (!r.reusable) drop();
  } catch (e) {
    drop();
    if (!acc.error) acc.error = 'download: ' + errText(e);
  }

  try {   // 3. upload, in what is left
    const until = deadline - 250;
    const part = crypto.randomBytes(UP_PART);   // random: nothing on the way can compress it into a better number
    const rtt = (acc.rttMs || 0) / 1000;
    let bytes = 0;
    let secs = 0;
    let lastError = null;
    for (let sent = 0; sent < UP_BYTES && Date.now() < until; sent += UP_PART) {
      let r;
      try {
        const c = await ready(until);
        const t = Date.now();
        r = okStatus(await c.request({ method: 'POST', path: '/__up', body: part, deadline: until, headOnly: true }));
        const el = (r.headAt - t) / 1000;
        secs += Math.max(el - rtt, el / 2);
        bytes += part.length;
      } catch (e) { lastError = e; drop(); break; }
      if (!r.reusable) drop();
    }
    if (!(bytes > 0 && secs > 0)) throw lastError || new Error('timeout');
    acc.upMbps = (bytes * 8) / secs / 1e6;
  } catch (e) {
    if (!acc.error) acc.error = 'upload: ' + errText(e);
  } finally {
    drop();
  }
}

let coreSeq = 0;
/**
 * A throwaway core straight from a binary, for a caller without an
 * XrayManager. The app passes `startTest` (xray.startTest: the engine's own
 * argv, the config adapted to the core's version, a file the router's orphan
 * sweep knows); this is the same shape — { proc, cleanup } — with none of that.
 */
async function spawnTestCore(xrayBin, config, dataDir) {
  if (!xrayBin || !fs.existsSync(xrayBin)) throw new Error('xray binary missing');
  const file = path.join(dataDir || os.tmpdir(), `test-mw-${process.pid}-${Date.now()}-${++coreSeq}.json`);
  fs.writeFileSync(file, JSON.stringify(config), 'utf8');
  const proc = spawn(xrayBin, engineRunArgs('xray', file), { cwd: path.dirname(xrayBin), windowsHide: true, stdio: 'ignore' });
  const failed = new Promise((_, reject) => proc.once('error', (e) => { try { fs.unlinkSync(file); } catch { /* gone */ } reject(e); }));
  failed.catch(() => {});   // a late failure must not become an unhandled rejection
  await Promise.race([sleep(500), failed]);
  return {
    proc,
    cleanup: () => {
      try { proc.kill(); } catch { /* gone */ }
      try { fs.unlinkSync(file); } catch { /* gone */ }
    }
  };
}

/**
 * One link's speed through the server. Never throws.
 *
 * opts:
 *  - link: { id, iface } (a listLinks entry or a configured link)
 *  - server: the record buildTestConfig takes (a server, a chain array, a group record)
 *  - buildTestConfig(server, port) → an Xray config with a SOCKS inbound on port
 *  - startTest(config) → { proc, cleanup } — the app's xray.startTest; else
 *    xrayBin (+ dataDir) to spawn the core directly
 *  - port | ports (a number or [number]): the SOCKS port; else a free one
 *  - timeoutMs: the hard budget (25 s); the core is killed when it ends, whatever happened
 *  - measure | fetch: the measurement through the SOCKS (tests: a fake) —
 *    ({ port, deadline, acc, track, isAlive }) → fills acc or returns { rttMs, downMbps, upMbps, error }
 *
 * → { id, ok, rttMs, downMbps, upMbps, error }: numbers rounded to 0.1 (null
 * where that part did not finish); ok only when all three were measured;
 * error (null when ok) names the first part that failed.
 */
async function speedTest(opts = {}) {
  const link = isObj(opts.link) ? opts.link : {};
  const iface = str(link.iface);
  const id = str(link.id) || iface;
  const out = { id, ok: false, rttMs: null, downMbps: null, upMbps: null, error: null };
  if (!iface) return Object.assign(out, { error: 'no interface' });
  if (!opts.server) return Object.assign(out, { error: 'no server' });
  if (typeof opts.buildTestConfig !== 'function') return Object.assign(out, { error: 'no test config' });

  const budget = opts.timeoutMs > 0 ? opts.timeoutMs : SPEED_TIMEOUT_MS;
  const deadline = Date.now() + budget;
  const measure = typeof opts.measure === 'function' ? opts.measure : (typeof opts.fetch === 'function' ? opts.fetch : measureThroughSocks);
  const acc = { rttMs: null, downMbps: null, upMbps: null, error: null };
  const sockets = new Set();
  let over = false;
  let core = null;
  let timedOut = false;
  const clean = () => {
    const c = core;
    core = null;
    if (c) { try { c.cleanup(); } catch { /* already gone */ } }
  };

  const work = (async () => {
    const given = Array.isArray(opts.ports) ? opts.ports[0] : opts.ports;
    const port = Number(opts.port) > 0 ? Number(opts.port) : (Number(given) > 0 ? Number(given) : await require('./xrayManager').getFreePort());
    const config = bindToInterface(opts.server && opts.buildTestConfig(opts.server, port), iface);
    if (!isObj(config)) throw new Error('no test config');
    let started;
    try {
      started = typeof opts.startTest === 'function' ? await opts.startTest(config) : await spawnTestCore(opts.xrayBin, config, opts.dataDir);
    } catch (e) {
      throw new Error('the core did not start: ' + errText(e));
    }
    core = started || null;
    if (over) { clean(); return; }   // came up after the deadline: never used
    const proc = core && core.proc;
    const isAlive = () => !(proc && (proc.exitCode != null || proc.signalCode != null));
    const r = await measure({ port, deadline, acc, isAlive, track: (s) => { sockets.add(s); if (over) { try { s.destroy(); } catch { /* gone */ } } } });
    if (isObj(r)) for (const k of ['rttMs', 'downMbps', 'upMbps', 'error']) if (r[k] != null && acc[k] == null) acc[k] = r[k];
  })().catch((e) => { if (!acc.error) acc.error = errText(e); });

  let timer = null;
  const expired = new Promise((resolve) => { timer = setTimeout(() => { timedOut = true; resolve(); }, budget); });
  try {
    await Promise.race([work, expired]);
  } finally {
    over = true;
    clearTimeout(timer);
    for (const s of sockets) { try { s.destroy(); } catch { /* gone */ } }
    clean();
  }
  out.rttMs = round1(acc.rttMs);
  out.downMbps = round1(acc.downMbps);
  out.upMbps = round1(acc.upMbps);
  out.ok = out.rttMs != null && out.downMbps != null && out.upMbps != null;
  out.error = out.ok ? null : (acc.error || (timedOut ? 'timeout' : 'failed'));
  return out;
}

/**
 * Every link, one after another — never two at once: they would share the
 * machine's (and the server's) bandwidth. → results in the links' order;
 * `onResult(result)` as each one finishes, for a UI that fills in as it goes.
 */
async function testAll(opts = {}) {
  const { links, onResult } = opts;
  const rest = Object.assign({}, opts);
  delete rest.links;
  delete rest.onResult;
  const results = [];
  for (const link of Array.isArray(links) ? links : []) {
    const r = await speedTest(Object.assign({}, rest, { link }));
    results.push(r);
    if (typeof onResult === 'function') { try { onResult(r); } catch { /* the UI's business */ } }
  }
  return results;
}

module.exports = {
  KINDS, LINKS_PS, SPEED_HOST, DOWN_BYTES, UP_BYTES, UP_PART, SPEED_TIMEOUT_MS,
  listLinks, speedTest, testAll, bindToInterface, measureThroughSocks,
  // the parsers, for the tests
  linksFromWin, kindWin, parseNetstatDefaults, parseHardwarePorts, parseServiceOrder, kindMac,
  parseIpDefaultRoutes, parseIpAddrs, kindLinux, logicalByDev, chunkedCounter, HttpConn
};
