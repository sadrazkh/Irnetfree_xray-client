'use strict';
/**
 * Deterministic fixtures for the config-builder tests.
 *
 * These outbounds are hand-written, NOT produced by parser.js, on purpose: the
 * two layers are tested independently, so a parser change can't silently
 * reshape the golden configs (and a golden failure always points at the layer
 * that actually changed).
 *
 * Ids are fixed strings (the real ones come from crypto.randomBytes) so the
 * generated configs are byte-stable and can be compared against golden files.
 */

/** Minimal server record — exactly the shape main.js keeps in its store. */
function server(id, name, protocol, address, port, outbound) {
  return { id, name, protocol, address, port, raw: `${protocol}://${address}:${port}`, outbound };
}

const VLESS_WS_TLS = server('sv-vless', 'VLESS WS', 'vless', 'a.example.com', 443, {
  protocol: 'vless',
  settings: {
    vnext: [{ address: 'a.example.com', port: 443, users: [{ id: 'uuid-a', encryption: 'none', flow: '' }] }]
  },
  streamSettings: {
    network: 'ws',
    security: 'tls',
    wsSettings: { path: '/ws', headers: { Host: 'a.example.com' } },
    tlsSettings: { serverName: 'a.example.com', allowInsecure: false, fingerprint: 'chrome' }
  }
});

const TROJAN_TCP_TLS = server('sv-trojan', 'Trojan', 'trojan', 'b.example.com', 443, {
  protocol: 'trojan',
  settings: { servers: [{ address: 'b.example.com', port: 443, password: 'pw' }] },
  streamSettings: {
    network: 'tcp',
    security: 'tls',
    tlsSettings: { serverName: 'b.example.com', allowInsecure: false, fingerprint: 'chrome' }
  }
});

const SS_TCP = server('sv-ss', 'Shadowsocks', 'shadowsocks', 'c.example.com', 8388, {
  protocol: 'shadowsocks',
  settings: { servers: [{ address: 'c.example.com', port: 8388, method: 'aes-256-gcm', password: 'secret', uot: true }] },
  streamSettings: { network: 'tcp' }
});

/** WireGuard with a deliberately wrong (/24) interface mask — must be coerced to /32. */
const WG_BAD_MASK = server('sv-wg', 'WireGuard', 'wireguard', 'd.example.com', 51820, {
  protocol: 'wireguard',
  settings: {
    secretKey: 'privkey',
    address: ['10.13.13.2/24'],
    peers: [{ publicKey: 'pubkey', endpoint: 'd.example.com:51820', allowedIPs: ['0.0.0.0/0', '::/0'] }],
    mtu: 1420
  },
  streamSettings: { sockopt: {} }
});

/** Same VLESS config, but carrying the TLS-fragment + noise anti-DPI markers. */
function vlessWithMarkers(id, markers) {
  const s = JSON.parse(JSON.stringify(VLESS_WS_TLS));
  s.id = id;
  s.name = 'VLESS ' + id;
  Object.assign(s.outbound, markers);
  return s;
}

/** The settings object main.js passes to buildConfig, with test-friendly defaults. */
function settings(over) {
  return Object.assign({
    socksPort: 10808,
    httpPort: 10809,
    allowLan: false,
    routingMode: 'global',
    blockAds: true,
    enableSniffing: true,
    dns: ['1.1.1.1', '8.8.8.8'],
    logLevel: 'warning',
    apiPort: 10085,
    customRules: [],
    geoAssets: true
  }, over || {});
}

/** Pull the routing rules out of a built config, as [outboundTag, …] for order checks. */
function ruleTags(config) {
  return config.routing.rules.map(r => r.outboundTag);
}

/** Find an outbound by tag. */
function outboundTagged(config, tag) {
  return config.outbounds.find(o => o.tag === tag);
}

module.exports = {
  server, settings, ruleTags, outboundTagged, vlessWithMarkers,
  VLESS_WS_TLS, TROJAN_TCP_TLS, SS_TCP, WG_BAD_MASK
};
