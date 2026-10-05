'use strict';
/**
 * One config, the core that runs it.
 *
 * The 2026 cores moved two transports' settings around, release by release,
 * and each move refuses (or silently drops) the shape before it:
 *
 *  - mKCP. Up to 26.1.23 the header and the seed are `kcpSettings.header` /
 *    `.seed`. From 26.1.31 the core REFUSES those two keys ("mkcp header &
 *    seed removed") and takes them as finalmask udp masks: `header-<type>`
 *    plus `mkcp-original` (no seed) or `mkcp-aes128gcm` (the seed as its
 *    password). From 26.6.1 those masks are gone again, folded into one type,
 *    `mkcp-legacy` ({ header } or { value }). From 26.9.30 the old keys are
 *    merely ignored — and a server reached without its seed is never reached.
 *  - Hysteria's port hopping. Up to 26.3.x it is `hysteriaSettings.udphop`;
 *    from 26.3.23 `finalmask.quicParams.udpHop`; from 26.9.9 a udp mask of its
 *    own, `udphop` — and each newer core ignores the older key without a word,
 *    so the hopping just stops.
 *
 * A stored record keeps a link's own terms (kcp: `kcpSettings.header`/`seed`)
 * or the NEWEST core's form (hysteria: the `udphop` mask). Which core runs a
 * config is only known when it is started — the official core, the patterniha
 * fork, a version the user picked in Required files — so this runs then, on
 * the finished config, with that core's version. Masks a link brought in its
 * own `fm` are translated the same way. The patterniha fork's version numbers
 * follow upstream's (it is upstream plus a patch), so one table serves both.
 *
 * Pure: the input is never changed; with nothing to do the same object comes
 * back. An unknown version ('' — the core could not be asked) is taken as the
 * newest: the shape every current download speaks.
 */

const KCP_MASKS_SINCE = '26.1.31';
const KCP_LEGACY_MASK_SINCE = '26.6.1';
const QUIC_PARAMS_SINCE = '26.3.23';
const UDPHOP_MASK_SINCE = '26.9.9';

/** "24.12.31" below "26.3.27", compared as numbers. No x.y.z in it (unknown) is never below anything. */
function below(v, min) {
  const parse = (s) => { const m = /(\d+)\.(\d+)\.(\d+)/.exec(String(s || '')); return m ? m.slice(1, 4).map(Number) : null; };
  const a = parse(v), b = parse(min);
  if (!a || !b) return false;
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i];
  return false;
}

/** A link's mKCP header type → the core's name for it ('' = none). */
const KCP_HEADERS = { srtp: 'srtp', utp: 'utp', 'wechat-video': 'wechat', wechat: 'wechat', dtls: 'dtls', wireguard: 'wireguard', dns: 'dns' };
function kcpHeaderName(t) {
  return KCP_HEADERS[String(t == null ? '' : t).trim().toLowerCase()] || '';
}

const clone = (o) => JSON.parse(JSON.stringify(o));
const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

/**
 * An mKCP mask in neutral terms: { crypto: 'original' } / { crypto: 'aes', password }
 * / { header, value }. null for any other mask (noise, header-custom, …).
 */
function readKcpMask(m) {
  if (!isObj(m)) return null;
  const s = isObj(m.settings) ? m.settings : {};
  if (m.type === 'mkcp-original') return { crypto: 'original' };
  if (m.type === 'mkcp-aes128gcm') return { crypto: 'aes', password: String(s.password || '') };
  if (m.type === 'mkcp-legacy') {
    if (s.header) return { header: kcpHeaderName(s.header) || String(s.header).toLowerCase(), value: String(s.value || '') };
    return s.value ? { crypto: 'aes', password: String(s.value) } : { crypto: 'original' };
  }
  const h = /^header-(dns|dtls|srtp|utp|wechat|wireguard)$/.exec(String(m.type || ''));
  if (h) return { header: h[1], value: h[1] === 'dns' ? String(s.domain || '') : '' };
  return null;
}

/** A neutral mKCP mask in the form `version` takes. */
function writeKcpMask(k, version) {
  if (!below(version, KCP_LEGACY_MASK_SINCE)) {
    if (k.crypto === 'original') return { type: 'mkcp-legacy' };
    if (k.crypto === 'aes') return { type: 'mkcp-legacy', settings: { value: k.password } };
    const settings = { header: k.header };
    if (k.header === 'dns' && k.value) settings.value = k.value;
    return { type: 'mkcp-legacy', settings };
  }
  if (k.crypto === 'original') return { type: 'mkcp-original' };
  if (k.crypto === 'aes') return { type: 'mkcp-aes128gcm', settings: { password: k.password } };
  return k.header === 'dns' && k.value
    ? { type: 'header-dns', settings: { domain: k.value } }
    : { type: 'header-' + k.header };
}

/** mKCP: the link's header and seed, and any mKCP masks, in the form this core takes. Mutates `ss`; true when it changed. */
function adaptKcp(ss, version) {
  const ks = isObj(ss.kcpSettings) ? ss.kcpSettings : null;
  const fm = isObj(ss.finalmask) ? ss.finalmask : null;
  const udp = fm && Array.isArray(fm.udp) ? fm.udp : [];
  const hasLegacyKeys = !!ks && ('header' in ks || 'seed' in ks);
  const masks = udp.map(readKcpMask);
  if (!hasLegacyKeys && !masks.some(Boolean)) return false;

  if (below(version, KCP_MASKS_SINCE)) {
    // Before finalmask: the masks' content goes back into kcpSettings.
    if (!masks.some(Boolean)) return false;
    const k = ss.kcpSettings = Object.assign({}, ks);
    for (const m of masks) {
      if (!m) continue;
      if (m.crypto === 'aes') k.seed = m.password;
      else if (m.header) k.header = m.header === 'dns' && m.value ? { type: 'dns', domain: m.value } : { type: m.header === 'wechat' ? 'wechat-video' : m.header };
    }
    const rest = udp.filter((_, i) => !masks[i]);
    if (rest.length) ss.finalmask = Object.assign({}, fm, { udp: rest });
    else if (fm) {
      const others = Object.assign({}, fm); delete others.udp;
      if (Object.keys(others).length) ss.finalmask = others; else delete ss.finalmask;
    }
    return true;
  }

  // The link's own header and seed, as masks — unless the link already brought
  // its masks (`fm`), which say the same thing in the server's own words.
  let list = udp.slice();
  if (hasLegacyKeys) {
    const header = kcpHeaderName(ks.header && typeof ks.header === 'object' ? ks.header.type : ks.header);
    const domain = ks.header && typeof ks.header === 'object' ? String(ks.header.domain || '') : '';
    const seed = String(ks.seed == null ? '' : ks.seed);
    const k = Object.assign({}, ks);
    delete k.header; delete k.seed;
    ss.kcpSettings = k;
    if (!masks.some(Boolean)) {
      // applied first to what is sent: the encryption, then the header
      const synth = [seed ? { type: 'mkcp-aes128gcm', settings: { password: seed } } : { type: 'mkcp-original' }];
      if (header) synth.push(header === 'dns' && domain ? { type: 'header-dns', settings: { domain } } : { type: 'header-' + header });
      list = [...synth, ...list];
    }
  }
  list = list.map((m) => { const k = readKcpMask(m); return k ? writeKcpMask(k, version) : m; });
  ss.finalmask = Object.assign({}, fm, { udp: list });
  return true;
}

/** Hysteria: port hopping (and the bandwidth) where this core reads them. Mutates `ss`; true when it changed. */
function adaptHysteria(ss, version) {
  const fm = isObj(ss.finalmask) ? ss.finalmask : null;
  if (!fm) return false;
  const udp = Array.isArray(fm.udp) ? fm.udp : [];
  const qp = isObj(fm.quicParams) ? fm.quicParams : null;
  const hopIdx = udp.findIndex(m => isObj(m) && m.type === 'udphop');
  const hopMask = hopIdx === -1 ? null : udp[hopIdx];
  const oldHop = qp && isObj(qp.udpHop) ? qp.udpHop : null;
  // the hopping in neutral terms, from whichever form the config has it in
  let hop = null;
  if (hopMask) {
    const s = isObj(hopMask.settings) ? hopMask.settings : {};
    hop = { ports: s.remotePorts, interval: s.interval };
  } else if (oldHop) {
    hop = { ports: oldHop.ports, interval: oldHop.interval };
  }

  if (!below(version, UDPHOP_MASK_SINCE)) {
    if (!oldHop) return false;
    const q = Object.assign({}, qp); delete q.udpHop;
    const out = Object.assign({}, fm);
    if (Object.keys(q).length) out.quicParams = q; else delete out.quicParams;
    if (!hopMask && hop && hop.ports != null && hop.ports !== '') {
      out.udp = [...udp, { type: 'udphop', settings: { mode: 'intervalLocal,intervalRemote', interval: hop.interval != null ? String(hop.interval) : '30', remotePorts: hop.ports } }];
    }
    ss.finalmask = out;
    return true;
  }

  if (!hopMask) return false;
  const out = Object.assign({}, fm, { udp: udp.filter((_, i) => i !== hopIdx) });
  if (!out.udp.length) delete out.udp;
  const legacy = { ports: hop.ports };
  if (hop.interval != null && hop.interval !== '') legacy.interval = hop.interval;
  if (!below(version, QUIC_PARAMS_SINCE)) {
    out.quicParams = Object.assign({}, qp, { udpHop: legacy });
  } else {
    // Before quicParams the hopping and the bandwidth were hysteriaSettings'.
    const hs = ss.hysteriaSettings = Object.assign({}, ss.hysteriaSettings, { udphop: legacy });
    if (qp) {
      if (qp.brutalUp) hs.up = qp.brutalUp;
      if (qp.brutalDown) hs.down = qp.brutalDown;
      if (qp.congestion) hs.congestion = qp.congestion;
      delete out.quicParams;
    }
  }
  if (Object.keys(out).length) ss.finalmask = out; else delete ss.finalmask;
  return true;
}

/**
 * The config, in the form the core of `version` takes. Every outbound with a
 * streamSettings is looked at; anything else is left as it is.
 */
function adaptForCore(config, version) {
  if (!config || !Array.isArray(config.outbounds)) return config;
  const touches = (o) => {
    const ss = o && o.streamSettings;
    if (!isObj(ss)) return false;
    const net = String(ss.network || '').toLowerCase();
    return net === 'kcp' || net === 'mkcp' || net === 'hysteria';
  };
  if (!config.outbounds.some(touches)) return config;
  const out = clone(config);
  let changed = false;
  for (const o of out.outbounds) {
    if (!touches(o)) continue;
    const ss = o.streamSettings;
    const net = String(ss.network || '').toLowerCase();
    if (net === 'hysteria') changed = adaptHysteria(ss, version) || changed;
    else changed = adaptKcp(ss, version) || changed;
  }
  return changed ? out : config;
}

/** Does this config hold anything adaptForCore may rewrite? (Callers skip asking the core its version otherwise.) */
function needsCoreVersion(config) {
  return !!config && Array.isArray(config.outbounds) && config.outbounds.some((o) => {
    const ss = o && o.streamSettings;
    const net = ss && String(ss.network || '').toLowerCase();
    return net === 'kcp' || net === 'mkcp' || net === 'hysteria';
  });
}

module.exports = {
  adaptForCore, needsCoreVersion, kcpHeaderName,
  KCP_MASKS_SINCE, KCP_LEGACY_MASK_SINCE, QUIC_PARAMS_SINCE, UDPHOP_MASK_SINCE
};
