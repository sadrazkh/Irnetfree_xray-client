'use strict';
/**
 * Direct ports: local SOCKS or HTTP ports that leave outside the VPN.
 * 2026-11-02 (the owner: "leave a port open for outside the VPN, so a tool like
 * the scanner can use it; several of them"). While the app is connected, what
 * enters one of these leaves by the machine's own internet.
 *
 *  - Under TUN a plain dial would enter the tunnel, so the outbound is bound to
 *    the physical interface, as every direct dial is (bindDirectDials). Without
 *    TUN the OS's route is already outside.
 *  - No sniffing: the core must dial what it was asked to. Sniffing replaces an
 *    address with the name in the first bytes, which makes every address answer
 *    for a name, and a scanner measures nothing.
 *  - The rule goes first and names only these inbounds, so it touches nothing
 *    else, and neither the private bypass nor the port-53 hijack reaches them.
 *  - AsIs: a name is the OS's to resolve. `direct`'s UseIPv4 asks the core's DNS,
 *    whose queries ride the exit.
 *  - Loopback only, and no password. A port for other devices already exists: a
 *    LAN user with a direct route (src/modules/lanUsers).
 *
 * Off (the empty list, the default): every config is byte-identical to before.
 */

const OUT_TAG = 'dp-direct';
const TYPES = new Set(['socks', 'http']);
/** The most a list may hold: each is a listener of the core's. */
const MAX_PORTS = 16;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const portOf = (v) => (Number.isInteger(v) && v >= 1 && v <= 65535 ? v : null);

/** The list as saved, cleaned: { port, type } rows, a port once, at most MAX_PORTS. */
function normalizeDirectPorts(raw) {
  const out = [];
  const seen = new Set();
  for (const row of Array.isArray(raw) ? raw : []) {
    if (!isObj(row)) continue;
    const port = portOf(Number(row.port));
    if (!port || seen.has(port)) continue;
    seen.add(port);
    out.push({ port, type: TYPES.has(row.type) ? row.type : 'socks' });
    if (out.length >= MAX_PORTS) break;
  }
  return out;
}

/** The ports the config's other listeners hold. */
function takenPorts(s) {
  const out = new Set();
  for (const k of ['socksPort', 'httpPort', 'apiPort', 'apiCtlPort', 'chainRelayPort']) {
    const p = portOf(Number(s[k]));
    if (p) out.add(p);
  }
  const proxy = isObj(s.lanUsers) && isObj(s.lanUsers.config) && isObj(s.lanUsers.config.proxy) ? s.lanUsers.config.proxy : null;
  if (proxy) for (const k of ['port', 'httpPort']) { const p = portOf(Number(proxy[k])); if (p) out.add(p); }
  for (const e of isObj(s.lanUsers) && Array.isArray(s.lanUsers.tp) ? s.lanUsers.tp : []) { const p = portOf(Number(e && e.port)); if (p) out.add(p); }
  return out;
}

/**
 * directPortsOf(settings, inboundPorts) → { rows, clashing }: the rows this config
 * can open, and the ports it cannot because something else in it holds them.
 * `inboundPorts` are the ports of inbounds already built (a pool's, a per-app one's).
 */
function directPortsOf(settings, inboundPorts = []) {
  const s = isObj(settings) ? settings : {};
  const taken = takenPorts(s);
  for (const p of inboundPorts) if (portOf(p)) taken.add(p);
  const rows = [], clashing = [];
  for (const row of normalizeDirectPorts(s.directPorts)) (taken.has(row.port) ? clashing : rows).push(row);
  return { rows, clashing: clashing.map((r) => r.port) };
}

/** The lines a connect says in the log: which ports are open, and which were not. Empty without any. */
function directPortsNotes(settings, inboundPorts = []) {
  const { rows, clashing } = directPortsOf(settings, inboundPorts);
  const lines = [];
  if (rows.length) lines.push(`Direct ports, outside the VPN: ${rows.map((r) => `127.0.0.1:${r.port} (${r.type.toUpperCase()})`).join(', ')}`);
  for (const p of clashing) lines.push(`Direct port ${p} not opened: another of the app's ports holds it`);
  return lines;
}

/** What a connect says about them, on the config but never written to disk (as config.lanUsersNotes). */
function noteOn(config, settings, inboundPorts) {
  const lines = directPortsNotes(settings, inboundPorts);
  if (lines.length) Object.defineProperty(config, 'directPortsNotes', { value: lines, enumerable: false, configurable: true, writable: true });
}

/** Their inbounds, outbound and rule in an Xray config, in place. No rows: the config is not touched. */
function applyDirectPorts(config, settings) {
  const s = isObj(settings) ? settings : {};
  const inbounds = Array.isArray(config.inbounds) ? config.inbounds : [];
  const held = inbounds.map((i) => i && i.port);
  noteOn(config, s, held);
  const { rows } = directPortsOf(s, held);
  if (!rows.length) return config;
  const tags = rows.map((r) => `dp-${r.port}`);
  rows.forEach((r, i) => {
    inbounds.push({
      tag: tags[i], port: r.port, listen: '127.0.0.1', protocol: r.type,
      settings: r.type === 'socks' ? { auth: 'noauth', udp: true } : {}
    });
  });
  config.inbounds = inbounds;
  const name = typeof s.directInterface === 'string' ? s.directInterface.trim() : '';
  const out = { tag: OUT_TAG, protocol: 'freedom', settings: { domainStrategy: 'AsIs' } };
  if (name) out.streamSettings = { sockopt: { interface: name } };
  config.outbounds = (Array.isArray(config.outbounds) ? config.outbounds : []).concat([out]);
  const routing = isObj(config.routing) ? config.routing : (config.routing = {});
  routing.rules = [{ type: 'field', inboundTag: tags, outboundTag: OUT_TAG }].concat(Array.isArray(routing.rules) ? routing.rules : []);
  return config;
}

/** The same for a config sing-box runs whole (TUIC, AnyTLS), in place. */
function applyDirectPortsSingbox(config, settings) {
  const s = isObj(settings) ? settings : {};
  const held = config.inbounds.map((i) => i && i.listen_port);
  noteOn(config, s, held);
  const { rows } = directPortsOf(s, held);
  if (!rows.length) return config;
  const tags = rows.map((r) => `dp-${r.port}`);
  rows.forEach((r, i) => config.inbounds.push({ type: r.type, tag: tags[i], listen: '127.0.0.1', listen_port: r.port }));
  const name = typeof s.directInterface === 'string' ? s.directInterface.trim() : '';
  config.outbounds.push(Object.assign({ type: 'direct', tag: OUT_TAG }, name ? { bind_interface: name } : {}));
  config.route.rules = [{ inbound: tags, outbound: OUT_TAG }].concat(config.route.rules || []);
  return config;
}

module.exports = { normalizeDirectPorts, directPortsOf, directPortsNotes, applyDirectPorts, applyDirectPortsSingbox, OUT_TAG, MAX_PORTS };
