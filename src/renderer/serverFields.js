'use strict';
/**
 * Every field the server editor shows — one table for the window (app.js draws
 * the Pro view from it), the record (parser.js reads and writes through it),
 * the router (service.js uses that parser) and Android (ServerFields.kt mirrors
 * it; tests/fixtures/serverFields.json is the copy its test compares with).
 * docs/superpowers/specs/2026-10-12-server-editor-design.md.
 *
 * A field is either `special` — the parser's own code reads and writes it, as
 * it always has (name, address, the credential, the transport and TLS basics)
 * — or has a `path`: a dotted path into the outbound (`settings.vnext.0.users.0.flow`)
 * or, with `@`, into the server record itself (`@mux`). Path fields are read and
 * written generically here: an empty value deletes the key, so the core's own
 * default applies again.
 *
 *   tab      basics | protocol | transport | security | advanced
 *   group    a heading inside the tab (i18n `sfg.<group>`)
 *   kind     text | number | range | select | switch | json | list | chips |
 *            uuid | encryption | protocol | network | security | seg
 *   when     { protocols, networks, securities } — shown and written only then
 *   local    a share link cannot carry it: it stays on this device
 *   simple   also in the Simple view
 *   key      the technical name shown beside the label
 *   options  values; a value shows as itself, but with `optionLabels` the empty
 *            one is labelled `sfo.<id>._` — and with `optionLabels: 'all'`
 *            every one, `sfo.<id>.<value>`
 *   emptyAs  what an empty value is written as, instead of deleting the key
 *
 * Labels are `sf.<id>`, hints `sf.<id>.hint` (when `hint: true`), both
 * languages in i18n.js.
 *
 * Loaded as a plain script by the renderer (window.ServerFields) and required
 * by Node; it touches neither the DOM nor the file system.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.ServerFields = api;
}(typeof self !== 'undefined' ? self : this, function () {

  const STREAM = ['vless', 'vmess', 'trojan', 'shadowsocks'];
  const PROTOCOLS = ['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'wireguard', 'socks', 'http'];
  /** The transports the editor offers, in the core's own names (`tcp` is RAW). */
  const NETWORKS = ['tcp', 'ws', 'grpc', 'httpupgrade', 'xhttp', 'kcp'];
  const FINGERPRINTS = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', '360', 'qq', 'random', 'randomized', 'unsafe'];
  const SS_METHODS = ['2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305',
    'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305', 'none'];

  /** The securities a protocol takes; none at all → the Security tab is off. */
  function securitiesOf(protocol) {
    if (protocol === 'vless' || protocol === 'trojan') return ['none', 'tls', 'reality'];
    if (protocol === 'vmess' || protocol === 'shadowsocks') return ['none', 'tls'];
    if (protocol === 'hysteria2') return ['tls'];
    return [];
  }
  const hasTransport = (protocol) => STREAM.includes(protocol);

  const XH = 'streamSettings.xhttpSettings.extra.';
  const GR = 'streamSettings.grpcSettings.';
  const KC = 'streamSettings.kcpSettings.';
  const TL = 'streamSettings.tlsSettings.';
  const SO = 'streamSettings.sockopt.';
  const U0 = 'settings.vnext.0.users.0.';

  const on = (protocols, networks, securities) => {
    const w = {};
    if (protocols) w.protocols = protocols;
    if (networks) w.networks = networks;
    if (securities) w.securities = securities;
    return w;
  };
  const RANGE = 'range';

  const FIELDS = [
    /* -------------------------------- basics -------------------------------- */
    { id: 'protocol', tab: 'basics', kind: 'protocol', special: true, key: 'protocol' },
    { id: 'name', tab: 'basics', kind: 'text', special: true, key: 'remark', simple: true, span: 2 },
    { id: 'address', tab: 'basics', kind: 'text', special: true, key: 'address', simple: true },
    { id: 'port', tab: 'basics', kind: 'number', special: true, key: 'port', simple: true },

    /* ------------------------------- protocol ------------------------------- */
    { id: 'uuid', tab: 'protocol', kind: 'uuid', special: true, key: 'id', when: on(['vless', 'vmess']), simple: true, span: 2 },
    { id: 'flow', tab: 'protocol', kind: 'select', path: U0 + 'flow', key: 'flow', when: on(['vless']), simple: true,
      options: ['', 'xtls-rprx-vision', 'xtls-rprx-vision-udp443'], optionLabels: true, hint: true },
    { id: 'encryption', tab: 'protocol', kind: 'encryption', path: U0 + 'encryption', key: 'encryption', when: on(['vless']),
      simple: true, emptyAs: 'none', span: 2, hint: true },
    { id: 'vmessSecurity', tab: 'protocol', kind: 'select', path: U0 + 'security', key: 'security', when: on(['vmess']),
      simple: true, emptyAs: 'auto', options: ['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero'] },
    { id: 'alterId', tab: 'protocol', kind: 'number', path: U0 + 'alterId', key: 'alterId', when: on(['vmess']), simple: true, emptyAs: 0, hint: true },
    { id: 'username', tab: 'protocol', kind: 'text', special: true, key: 'user', when: on(['socks', 'http']), simple: true },
    { id: 'password', tab: 'protocol', kind: 'text', special: true, key: 'password', when: on(['trojan', 'shadowsocks', 'hysteria2', 'socks', 'http']), simple: true, span: 2 },
    { id: 'method', tab: 'protocol', kind: 'select', path: 'settings.servers.0.method', key: 'method', when: on(['shadowsocks']),
      simple: true, options: SS_METHODS },
    { id: 'uot', tab: 'protocol', kind: 'switch', path: 'settings.servers.0.uot', key: 'uot', when: on(['shadowsocks']), local: true },
    { id: 'plugin', tab: 'protocol', kind: 'text', special: true, key: 'plugin', when: on(['shadowsocks']), span: 2, hint: true,
      placeholder: 'obfs-local;obfs=http;obfs-host=bing.com' },
    { id: 'obfsPassword', tab: 'protocol', kind: 'text', special: true, key: 'obfs-password', when: on(['hysteria2']), simple: true },
    { id: 'mport', tab: 'protocol', kind: 'text', special: true, key: 'mport', when: on(['hysteria2']), simple: true, placeholder: '20000-30000' },
    { id: 'hopInterval', tab: 'protocol', kind: RANGE, special: true, key: 'hopInterval', when: on(['hysteria2']), placeholder: '30' },
    { id: 'up', tab: 'protocol', kind: 'text', special: true, key: 'up', when: on(['hysteria2']), placeholder: '50 mbps' },
    { id: 'down', tab: 'protocol', kind: 'text', special: true, key: 'down', when: on(['hysteria2']), placeholder: '200 mbps' },
    { id: 'privateKey', tab: 'protocol', kind: 'text', special: true, key: 'secretKey', when: on(['wireguard']), simple: true, span: 2 },
    { id: 'localAddress', tab: 'protocol', kind: 'list', special: true, key: 'address', when: on(['wireguard']), simple: true },
    { id: 'publicKey', tab: 'protocol', kind: 'text', special: true, key: 'publicKey', when: on(['wireguard']), simple: true },
    { id: 'presharedKey', tab: 'protocol', kind: 'text', special: true, key: 'preSharedKey', when: on(['wireguard']), simple: true },
    { id: 'allowedIPs', tab: 'protocol', kind: 'list', special: true, key: 'allowedIPs', when: on(['wireguard']), simple: true, placeholder: '0.0.0.0/0, ::/0' },
    { id: 'reserved', tab: 'protocol', kind: 'list', special: true, key: 'reserved', when: on(['wireguard']), simple: true, placeholder: '0,0,0' },
    { id: 'mtu', tab: 'protocol', kind: 'number', special: true, key: 'mtu', when: on(['wireguard']), simple: true, placeholder: '1420' },
    { id: 'wgKeepAlive', tab: 'protocol', kind: 'number', path: 'settings.peers.0.keepAlive', key: 'keepAlive', when: on(['wireguard']), local: true, placeholder: '25' },
    { id: 'wgDomainStrategy', tab: 'protocol', kind: 'select', path: 'settings.domainStrategy', key: 'domainStrategy', when: on(['wireguard']), local: true,
      options: ['', 'ForceIP', 'ForceIPv4', 'ForceIPv6', 'ForceIPv4v6', 'ForceIPv6v4'], optionLabels: true },
    { id: 'dns', tab: 'protocol', kind: 'list', special: true, key: 'dns', when: on(['wireguard']), simple: true, span: 2, hint: true,
      placeholder: '192.168.60.1, corp.example' },
    { id: 'httpHeaders', tab: 'protocol', kind: 'json', path: 'settings.headers', key: 'headers', when: on(['http']), local: true, span: 2,
      placeholder: '{"User-Agent": "…"}' },

    /* ------------------------------- transport ------------------------------ */
    { id: 'network', tab: 'transport', kind: 'network', special: true, key: 'network', when: on(STREAM), simple: true, span: 2 },
    { id: 'headerType', tab: 'transport', kind: 'select', special: true, key: 'headerType', when: on(STREAM, ['tcp']), options: ['none', 'http'] },
    { id: 'host', tab: 'transport', kind: 'text', special: true, key: 'host', when: on(STREAM, ['tcp', 'ws', 'grpc', 'httpupgrade', 'xhttp']), simple: true },
    { id: 'path', tab: 'transport', kind: 'text', special: true, key: 'path', when: on(STREAM, ['tcp', 'ws', 'grpc', 'httpupgrade', 'xhttp']), simple: true },
    { id: 'wsHeartbeat', tab: 'transport', kind: 'number', path: 'streamSettings.wsSettings.heartbeatPeriod', key: 'heartbeatPeriod',
      when: on(STREAM, ['ws']), local: true, placeholder: '0' },
    { id: 'grpcMode', tab: 'transport', kind: 'seg', special: true, key: 'mode', when: on(STREAM, ['grpc']), options: ['gun', 'multi'], span: 2 },
    { id: 'grpcUserAgent', tab: 'transport', kind: 'text', path: GR + 'user_agent', key: 'user_agent', when: on(STREAM, ['grpc']), local: true, span: 2 },
    { id: 'grpcIdleTimeout', tab: 'transport', kind: 'number', path: GR + 'idle_timeout', key: 'idle_timeout', when: on(STREAM, ['grpc']), local: true, placeholder: '60' },
    { id: 'grpcHealthTimeout', tab: 'transport', kind: 'number', path: GR + 'health_check_timeout', key: 'health_check_timeout', when: on(STREAM, ['grpc']), local: true, placeholder: '20' },
    { id: 'grpcInitialWindow', tab: 'transport', kind: 'number', path: GR + 'initial_windows_size', key: 'initial_windows_size', when: on(STREAM, ['grpc']), local: true, placeholder: '0' },
    { id: 'grpcPermitWithoutStream', tab: 'transport', kind: 'switch', path: GR + 'permit_without_stream', key: 'permit_without_stream', when: on(STREAM, ['grpc']), local: true },
    { id: 'xhttpMode', tab: 'transport', kind: 'seg', special: true, key: 'mode', when: on(STREAM, ['xhttp']), options: ['auto', 'packet-up', 'stream-up', 'stream-one'], span: 2 },
    { id: 'xPaddingBytes', tab: 'transport', group: 'extra', kind: RANGE, path: XH + 'xPaddingBytes', key: 'xPaddingBytes', when: on(STREAM, ['xhttp']), placeholder: '100-1000' },
    { id: 'noGRPCHeader', tab: 'transport', group: 'extra', kind: 'switch', path: XH + 'noGRPCHeader', key: 'noGRPCHeader', when: on(STREAM, ['xhttp']) },
    { id: 'scMaxEachPostBytes', tab: 'transport', group: 'extra', kind: RANGE, path: XH + 'scMaxEachPostBytes', key: 'scMaxEachPostBytes', when: on(STREAM, ['xhttp']), placeholder: '1000000' },
    { id: 'scMinPostsIntervalMs', tab: 'transport', group: 'extra', kind: RANGE, path: XH + 'scMinPostsIntervalMs', key: 'scMinPostsIntervalMs', when: on(STREAM, ['xhttp']), placeholder: '30' },
    { id: 'xmuxMaxConcurrency', tab: 'transport', group: 'xmux', kind: RANGE, path: XH + 'xmux.maxConcurrency', key: 'maxConcurrency', when: on(STREAM, ['xhttp']), placeholder: '16-32' },
    { id: 'xmuxMaxConnections', tab: 'transport', group: 'xmux', kind: RANGE, path: XH + 'xmux.maxConnections', key: 'maxConnections', when: on(STREAM, ['xhttp']), placeholder: '0' },
    { id: 'xmuxCMaxReuseTimes', tab: 'transport', group: 'xmux', kind: RANGE, path: XH + 'xmux.cMaxReuseTimes', key: 'cMaxReuseTimes', when: on(STREAM, ['xhttp']), placeholder: '0' },
    { id: 'xmuxHMaxRequestTimes', tab: 'transport', group: 'xmux', kind: RANGE, path: XH + 'xmux.hMaxRequestTimes', key: 'hMaxRequestTimes', when: on(STREAM, ['xhttp']), placeholder: '600-900' },
    { id: 'xmuxHMaxReusableSecs', tab: 'transport', group: 'xmux', kind: RANGE, path: XH + 'xmux.hMaxReusableSecs', key: 'hMaxReusableSecs', when: on(STREAM, ['xhttp']), placeholder: '1800-3000' },
    { id: 'xmuxHKeepAlivePeriod', tab: 'transport', group: 'xmux', kind: 'number', path: XH + 'xmux.hKeepAlivePeriod', key: 'hKeepAlivePeriod', when: on(STREAM, ['xhttp']), placeholder: '0' },
    { id: 'downloadSettings', tab: 'transport', group: 'xmux', kind: 'json', path: XH + 'downloadSettings', key: 'downloadSettings', when: on(STREAM, ['xhttp']), span: 2, hint: true,
      placeholder: '{"address": "…", "port": 443, "network": "xhttp", …}' },
    { id: 'kcpHeader', tab: 'transport', kind: 'select', special: true, key: 'header', when: on(STREAM, ['kcp']), options: ['none', 'srtp', 'utp', 'wechat-video', 'dtls', 'wireguard', 'dns'] },
    { id: 'kcpSeed', tab: 'transport', kind: 'text', special: true, key: 'seed', when: on(STREAM, ['kcp']) },
    { id: 'kcpMtu', tab: 'transport', kind: 'number', path: KC + 'mtu', key: 'mtu', when: on(STREAM, ['kcp']), placeholder: '1350' },
    { id: 'kcpTti', tab: 'transport', kind: 'number', path: KC + 'tti', key: 'tti', when: on(STREAM, ['kcp']), local: true, placeholder: '50' },
    { id: 'kcpUplink', tab: 'transport', kind: 'number', path: KC + 'uplinkCapacity', key: 'uplinkCapacity', when: on(STREAM, ['kcp']), local: true, placeholder: '5' },
    { id: 'kcpDownlink', tab: 'transport', kind: 'number', path: KC + 'downlinkCapacity', key: 'downlinkCapacity', when: on(STREAM, ['kcp']), local: true, placeholder: '20' },
    { id: 'kcpCongestion', tab: 'transport', kind: 'switch', path: KC + 'congestion', key: 'congestion', when: on(STREAM, ['kcp']), local: true },
    { id: 'kcpReadBuffer', tab: 'transport', kind: 'number', path: KC + 'readBufferSize', key: 'readBufferSize', when: on(STREAM, ['kcp']), local: true, placeholder: '2' },
    { id: 'kcpWriteBuffer', tab: 'transport', kind: 'number', path: KC + 'writeBufferSize', key: 'writeBufferSize', when: on(STREAM, ['kcp']), local: true, placeholder: '2' },

    /* ------------------------------- security ------------------------------- */
    { id: 'security', tab: 'security', kind: 'security', special: true, key: 'security', when: on(STREAM), simple: true, span: 2 },
    { id: 'sni', tab: 'security', kind: 'text', special: true, key: 'serverName', when: on(STREAM.concat('hysteria2'), null, ['tls', 'reality']), simple: true },
    { id: 'fp', tab: 'security', kind: 'select', special: true, key: 'fingerprint', when: on(STREAM, null, ['tls', 'reality']), simple: true, options: FINGERPRINTS },
    { id: 'alpn', tab: 'security', kind: 'chips', special: true, key: 'alpn', when: on(STREAM.concat('hysteria2'), null, ['tls']), options: ['h3', 'h2', 'http/1.1'], span: 2, hint: true },
    { id: 'pcs', tab: 'security', group: 'certificate', kind: 'text', special: true, key: 'pinnedPeerCertSha256', when: on(STREAM.concat('hysteria2'), null, ['tls']), simple: true, placeholder: 'e3b0c442…, …' },
    { id: 'vcn', tab: 'security', group: 'certificate', kind: 'text', special: true, key: 'verifyPeerCertByName', when: on(STREAM.concat('hysteria2'), null, ['tls']), simple: true, placeholder: 'real.example.com' },
    { id: 'allowInsecure', tab: 'security', group: 'certificate', kind: 'switch', special: true, key: 'allowInsecure', when: on(STREAM.concat('hysteria2'), null, ['tls']), simple: true, span: 2, hint: true },
    { id: 'ech', tab: 'security', group: 'ech', kind: 'text', special: true, key: 'echConfigList', when: on(STREAM.concat('hysteria2'), null, ['tls']), simple: true, span: 2, hint: true,
      placeholder: 'cloudflare-ech.com+udp://1.1.1.1' },
    { id: 'echForceQuery', tab: 'security', group: 'ech', kind: 'select', path: TL + 'echForceQuery', key: 'echForceQuery', when: on(STREAM.concat('hysteria2'), null, ['tls']), local: true,
      options: ['', 'none', 'half', 'full'], optionLabels: true },
    { id: 'minVersion', tab: 'security', group: 'ech', kind: 'select', path: TL + 'minVersion', key: 'minVersion', when: on(STREAM.concat('hysteria2'), null, ['tls']), local: true,
      options: ['', '1.0', '1.1', '1.2', '1.3'], optionLabels: true },
    { id: 'maxVersion', tab: 'security', group: 'ech', kind: 'select', path: TL + 'maxVersion', key: 'maxVersion', when: on(STREAM.concat('hysteria2'), null, ['tls']), local: true,
      options: ['', '1.0', '1.1', '1.2', '1.3'], optionLabels: true },
    { id: 'curvePreferences', tab: 'security', group: 'ech', kind: 'list', path: TL + 'curvePreferences', key: 'curvePreferences', when: on(STREAM.concat('hysteria2'), null, ['tls']), local: true, span: 2,
      placeholder: 'X25519MLKEM768, X25519' },
    { id: 'pbk', tab: 'security', kind: 'text', special: true, key: 'publicKey · pbk', when: on(STREAM, null, ['reality']), simple: true, span: 2 },
    { id: 'sid', tab: 'security', kind: 'text', special: true, key: 'shortId · sid', when: on(STREAM, null, ['reality']), simple: true },
    { id: 'spx', tab: 'security', kind: 'text', special: true, key: 'spiderX · spx', when: on(STREAM, null, ['reality']), placeholder: '/' },
    { id: 'pqv', tab: 'security', kind: 'text', special: true, key: 'mldsa65Verify · pqv', when: on(STREAM, null, ['reality']), simple: true, span: 2 },

    /* ------------------------------- advanced ------------------------------- */
    { id: 'engine', tab: 'advanced', kind: 'select', special: true, key: 'engine', simple: true, options: ['xray', 'xray-pattn', 'sing-box'], optionLabels: 'all', hint: true },
    { id: 'mux', tab: 'advanced', group: 'mux', kind: 'select', path: '@mux', key: 'mux', when: on(['vless', 'vmess', 'trojan']), local: true,
      options: ['', 'on', 'off'], optionLabels: 'all', hint: true },
    { id: 'muxConcurrency', tab: 'advanced', group: 'mux', kind: 'number', path: '@muxConcurrency', key: 'concurrency', when: on(['vless', 'vmess', 'trojan']), local: true, placeholder: '8' },
    { id: 'xudpConcurrency', tab: 'advanced', group: 'mux', kind: 'number', path: '@xudpConcurrency', key: 'xudpConcurrency', when: on(['vless', 'vmess', 'trojan']), local: true, placeholder: '16' },
    { id: 'tcpFastOpen', tab: 'advanced', group: 'sockopt', kind: 'switch', path: SO + 'tcpFastOpen', key: 'tcpFastOpen', when: on(STREAM), local: true },
    { id: 'tcpMptcp', tab: 'advanced', group: 'sockopt', kind: 'switch', path: SO + 'tcpMptcp', key: 'tcpMptcp', when: on(STREAM), local: true },
    { id: 'tcpKeepAliveInterval', tab: 'advanced', group: 'sockopt', kind: 'number', path: SO + 'tcpKeepAliveInterval', key: 'tcpKeepAliveInterval', when: on(STREAM), local: true, placeholder: '0' },
    { id: 'tcpKeepAliveIdle', tab: 'advanced', group: 'sockopt', kind: 'number', path: SO + 'tcpKeepAliveIdle', key: 'tcpKeepAliveIdle', when: on(STREAM), local: true, placeholder: '0' },
    { id: 'tcpCongestion', tab: 'advanced', group: 'sockopt', kind: 'select', path: SO + 'tcpCongestion', key: 'tcpCongestion', when: on(STREAM), local: true,
      options: ['', 'bbr', 'cubic', 'reno'], optionLabels: true },
    { id: 'fragment', tab: 'advanced', group: 'dpi', kind: 'text', special: true, key: 'fragment', simple: true, placeholder: 'tlshello,100-200,10-20', hint: true },
    { id: 'noise', tab: 'advanced', group: 'dpi', kind: 'text', special: true, key: 'noise', simple: true, placeholder: 'rand:50-100:0;base64:FgMBAAA=:10-20', hint: true },
    { id: 'cipherSuites', tab: 'advanced', group: 'pattn', kind: 'text', special: true, key: 'cipherSuites · cs', when: on(STREAM), simple: true, span: 2,
      placeholder: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256' },
    { id: 'finalMask', tab: 'advanced', group: 'pattn', kind: 'json', special: true, key: 'finalmask · fm', when: on(STREAM), simple: true, span: 2, hint: true,
      placeholder: '{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["3-5"],"delays":["10-20"]}}]}' }
  ];

  const TABS = ['basics', 'protocol', 'transport', 'security', 'advanced'];

  /** The record's protocol, transport and security, in the table's terms. */
  function contextOf(server) {
    const ob = (server && server.outbound) || {};
    const st = ob.streamSettings || {};
    const protocol = (server && server.protocol) || ob.protocol || '';
    let network = String(st.network || 'tcp').toLowerCase();
    if (network === 'raw') network = 'tcp';
    else if (network === 'splithttp') network = 'xhttp';
    else if (network === 'mkcp') network = 'kcp';
    return { protocol: protocol === 'hysteria' ? 'hysteria2' : protocol, network, security: String(st.security || 'none').toLowerCase() };
  }

  /** Does the field belong to this protocol / transport / security? */
  function fieldApplies(field, ctx) {
    const w = field.when;
    if (!w) return true;
    const c = ctx || {};
    if (w.protocols && !w.protocols.includes(c.protocol)) return false;
    if (w.networks && !(hasTransport(c.protocol) && w.networks.includes(c.network))) return false;
    if (w.securities) {
      const sec = c.protocol === 'hysteria2' ? 'tls' : c.security;
      if (!w.securities.includes(sec)) return false;
    }
    return true;
  }

  const isPlain = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
  const segs = (path) => String(path).split('.');

  /** `@x` → server.x; otherwise the outbound, along the dotted path (numbers index arrays). */
  function getPath(server, path) {
    if (!server) return undefined;
    if (path[0] === '@') return server[path.slice(1)];
    let cur = server.outbound;
    for (const k of segs(path)) {
      if (cur == null || typeof cur !== 'object') return undefined;
      cur = cur[/^\d+$/.test(k) ? Number(k) : k];
    }
    return cur;
  }

  /**
   * Write `value` at `path`, making the objects (and arrays, for a numeric
   * step) on the way. `undefined` deletes the key, and an object it leaves
   * empty three or more steps down (`extra`, `xmux`) goes too — the containers
   * the core reads (`sockopt`, `kcpSettings`, …) stay as they are.
   */
  function setPath(server, path, value) {
    if (path[0] === '@') {
      const k = path.slice(1);
      if (value === undefined) delete server[k]; else server[k] = value;
      return;
    }
    if (!isPlain(server.outbound)) server.outbound = {};
    const ks = segs(path);
    const trail = [server.outbound];
    let cur = server.outbound;
    for (let i = 0; i < ks.length - 1; i++) {
      const k = /^\d+$/.test(ks[i]) ? Number(ks[i]) : ks[i];
      if (cur[k] == null || typeof cur[k] !== 'object') {
        if (value === undefined) return;   // nothing there to delete
        cur[k] = /^\d+$/.test(ks[i + 1]) ? [] : {};
      }
      cur = cur[k];
      trail.push(cur);
    }
    const leaf = /^\d+$/.test(ks[ks.length - 1]) ? Number(ks[ks.length - 1]) : ks[ks.length - 1];
    if (value !== undefined) { cur[leaf] = value; return; }
    if (Array.isArray(cur)) cur.splice(leaf, 1); else delete cur[leaf];
    for (let i = trail.length - 1; i >= 3; i--) {
      if (isPlain(trail[i]) && !Object.keys(trail[i]).length) {
        const parent = trail[i - 1];
        const k = /^\d+$/.test(ks[i - 1]) ? Number(ks[i - 1]) : ks[i - 1];
        if (isPlain(parent)) delete parent[k];
      } else break;
    }
  }

  /** A stored value as the form shows it: text, or a boolean for a switch. */
  function toForm(field, raw) {
    if (field.kind === 'switch') return raw === true || raw === 'true';
    if (raw == null) return '';
    if (field.kind === 'json') return typeof raw === 'string' ? raw : JSON.stringify(raw);
    if (field.kind === 'list' || field.kind === 'chips') return Array.isArray(raw) ? raw.join(', ') : String(raw);
    return String(raw);
  }

  /** What the form's value is written as; `undefined` deletes the key (or `emptyAs`). */
  function fromForm(field, v) {
    const empty = field.emptyAs !== undefined ? field.emptyAs : undefined;
    if (field.kind === 'switch') return v === true || v === 'true' ? true : undefined;
    const s = typeof v === 'string' ? v.trim() : (v == null ? '' : String(v));
    if (!s) return empty;
    switch (field.kind) {
      case 'number': return Number(s);
      case RANGE: return /^\d+$/.test(s) ? Number(s) : s;
      case 'json': return JSON.parse(s);
      case 'list': case 'chips': {
        const a = s.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);
        return a.length ? a : empty;
      }
      default: return s;
    }
  }

  /** Why the form's value cannot be written (an i18n key), or null. */
  function validate(field, v) {
    if (field.kind === 'switch') return null;
    const s = typeof v === 'string' ? v.trim() : (v == null ? '' : String(v));
    if (!s) return null;
    if (field.kind === 'number' && !/^\d+$/.test(s)) return 'edit.err.number';
    if (field.kind === RANGE && !/^\d+(-\d+)?$/.test(s)) return 'edit.err.range';
    if (field.kind === 'json') {
      try { if (!isPlain(JSON.parse(s))) return 'edit.err.json'; } catch { return 'edit.err.json'; }
    }
    if (field.kind === 'encryption') { const r = readEncryption(s); if (r && r.bad) return r.bad; }
    return null;
  }

  /**
   * A VLESS Encryption value (the panel's "Encryption", the client's half):
   * `mlkem768x25519plus.<native|xorpub|random>.<0rtt|1rtt>[.padding…].<key>[.<key>…]`.
   * The last key's length tells the auth: an X25519 public key is 32 bytes
   * (43 in base64url), ML-KEM-768's is 1184. null for `none`.
   */
  function readEncryption(v) {
    const s = String(v == null ? '' : v).trim();
    if (!s || s === 'none') return null;
    const p = s.split('.');
    if (p[0] !== 'mlkem768x25519plus') return { bad: 'edit.err.encPrefix' };
    if (!['native', 'xorpub', 'random'].includes(p[1])) return { bad: 'edit.err.encMode' };
    if (!['0rtt', '1rtt'].includes(p[2])) return { bad: 'edit.err.encRtt' };
    const rest = p.slice(3);
    const key = rest[rest.length - 1] || '';
    if (!/^[A-Za-z0-9_-]{40,}$/.test(key) || rest.some((x) => !/^[A-Za-z0-9_-]+$/.test(x))) return { bad: 'edit.err.encKey' };
    return { auth: key.length > 200 ? 'ML-KEM-768' : 'X25519', mode: p[1], rtt: p[2], padded: rest.length > 1 };
  }

  /**
   * The SIP002 plugin a Shadowsocks stream stands for (parser.ssStream's
   * inverse); '' for plain TCP. Here so the window shows it as the share link
   * writes it.
   */
  function ssPluginOf(st) {
    if (!st) return '';
    const esc = (s) => String(s).replace(/[\\;=,]/g, '\\$&');
    if (st.network === 'ws' && st.wsSettings) {
      const host = (st.wsSettings.headers && (st.wsSettings.headers.Host || st.wsSettings.headers.host)) || '';
      const parts = ['v2ray-plugin', 'mode=websocket'];
      if (st.security === 'tls') parts.push('tls');
      if (host) parts.push('host=' + esc(host));
      parts.push('path=' + esc(st.wsSettings.path || '/'), 'mux=0');
      return parts.join(';');
    }
    const h = st.tcpSettings && st.tcpSettings.header;
    if ((!st.network || st.network === 'tcp' || st.network === 'raw') && h && h.type === 'http') {
      const rq = h.request || {};
      const host = [].concat((rq.headers && rq.headers.Host) || [])[0] || '';
      const uri = [].concat(rq.path || [])[0] || '/';
      return 'obfs-local;obfs=http' + (host ? ';obfs-host=' + esc(host) : '') + (uri !== '/' ? ';obfs-uri=' + esc(uri) : '');
    }
    return '';
  }

  /**
   * The special fields the parser builds the outbound from, read off a record
   * (parser.editFields and the window both show these): TCP's header, gRPC's
   * and XHTTP's mode, mKCP's header and seed, REALITY's spiderX; Hysteria2's
   * hop interval and bandwidth; a Shadowsocks plugin.
   */
  function specialsOf(server) {
    const ob = (server && server.outbound) || {};
    const st = ob.streamSettings || {};
    const ctx = contextOf(server);
    const out = {};
    if (hasTransport(ctx.protocol)) {
      const rs = st.realitySettings || {};
      Object.assign(out, {
        headerType: st.tcpSettings && st.tcpSettings.header && st.tcpSettings.header.type === 'http' ? 'http' : 'none',
        grpcMode: st.grpcSettings && st.grpcSettings.multiMode ? 'multi' : 'gun',
        xhttpMode: (st.xhttpSettings && st.xhttpSettings.mode) || 'auto',
        kcpHeader: (st.kcpSettings && st.kcpSettings.header && st.kcpSettings.header.type) || 'none',
        kcpSeed: (st.kcpSettings && st.kcpSettings.seed) || '',
        spx: rs.spiderX || ''
      });
    }
    if (ctx.protocol === 'shadowsocks') out.plugin = ssPluginOf(st);
    if (ctx.protocol === 'hysteria2') {
      const fm = st.finalmask || {};
      const hop = (Array.isArray(fm.udp) ? fm.udp : []).find((m) => m && m.type === 'udphop');
      const qp = fm.quicParams || {};
      out.hopInterval = hop && hop.settings && hop.settings.interval != null ? String(hop.settings.interval) : '';
      out.up = qp.brutalUp || '';
      out.down = qp.brutalDown || '';
    }
    return out;
  }

  const PATH_FIELDS = FIELDS.filter((f) => f.path);

  /** Every path field's stored value, by id (raw, as the record has it). */
  function readPathFields(server) {
    const out = {};
    for (const f of PATH_FIELDS) out[f.id] = getPath(server, f.path);
    return out;
  }

  /**
   * Write the path fields onto `server` (after the parser rebuilt what it
   * owns): a submitted value wins, else `kept` — what the record had before the
   * rebuild — so a field the submit did not carry stays as it was. A field that
   * does not apply to the result (a ws heartbeat on a gRPC server) is left out.
   */
  function applyPathFields(server, f, kept) {
    const ctx = contextOf(server);
    for (const field of PATH_FIELDS) {
      const at = getPath(server, field.path);
      if (!fieldApplies(field, ctx)) {
        if (at !== undefined) setPath(server, field.path, undefined);
        continue;
      }
      // the record's own value, untouched, unless the form says something else
      const was = kept ? kept[field.id] : at;
      let value = was;
      const sent = f && f[field.id] != null;
      if (sent && toForm(field, f[field.id]) !== toForm(field, was)) value = fromForm(field, f[field.id]);
      if (JSON.stringify(value) === JSON.stringify(at)) continue;
      setPath(server, field.path, value);
    }
  }

  return {
    FIELDS, TABS, PROTOCOLS, NETWORKS, FINGERPRINTS, SS_METHODS, PATH_FIELDS,
    securitiesOf, hasTransport, contextOf, fieldApplies,
    getPath, setPath, toForm, fromForm, validate, readEncryption, readPathFields, applyPathFields, specialsOf, ssPluginOf
  };
}));
