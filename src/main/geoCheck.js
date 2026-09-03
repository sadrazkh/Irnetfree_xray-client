'use strict';
/**
 * Are the geo codes a routing rule names actually IN the installed data files?
 *
 * The data files carry a fixed set of codes, and the core refuses the WHOLE
 * config over a single unknown one:
 *
 *   infra/conf: code not found in geosite.dat: IR
 *
 * — which reads like "the geo files are missing" even though they are perfectly
 * fine. (`geosite:ir` does not exist; the Iranian domain list is
 * `geosite:category-ir`. `geoip:ir` does exist. Nothing in the message says
 * which of the user's rules is at fault, and one bad token in an advanced rule
 * takes the whole connection with it.)
 *
 * The files are protobuf and the codes in them change with every release, so
 * the only honest authority on what exists is the core itself: build a config
 * whose only content is the tokens in question and ask it. That is one spawn,
 * and the answer names a code — so a failure is retried without the token it
 * named until nothing is left to complain about.
 */

const GEO_TOKEN = /^(geoip|geosite):[A-Za-z0-9_.\-@]+$/;
/** The core's message for a code the data file does not carry. */
const MISSING_CODE = /code not found in (geoip|geosite)\.dat:\s*([^\s>]+)/i;

/** Every geo token in a rule list (advanced routing rules or custom rules). */
function geoTokensOf(rules) {
  const out = [];
  for (const r of Array.isArray(rules) ? rules : []) {
    if (!r) continue;
    const raw = r.value != null ? r.value : [r.domain, r.ip].filter(Boolean).join(',');
    for (const v of String(raw || '').split(/[,\s]+/)) {
      const t = v.trim();
      if (GEO_TOKEN.test(t) && !out.includes(t)) out.push(t);
    }
  }
  return out;
}

/**
 * A config that carries nothing but these tokens, so the core's verdict is
 * about them and nothing else. Ports are never bound (`run -test` only reads
 * the file), so they cannot clash with a live instance.
 */
function buildGeoProbeConfig(tokens) {
  const domain = tokens.filter(t => /^geosite:/i.test(t));
  const ip = tokens.filter(t => /^geoip:/i.test(t));
  const rules = [];
  if (domain.length) rules.push({ type: 'field', domain: domain.slice(), outboundTag: 'direct' });
  if (ip.length) rules.push({ type: 'field', ip: ip.slice(), outboundTag: 'direct' });
  return {
    log: { loglevel: 'warning' },
    inbounds: [{ port: 1, listen: '127.0.0.1', protocol: 'socks', settings: { auth: 'noauth' } }],
    outbounds: [{ tag: 'direct', protocol: 'freedom' }],
    routing: { rules }
  };
}

/** The code the core named, mapped back to the user's token. `null` otherwise. */
function tokenFromError(error, tokens) {
  const m = MISSING_CODE.exec(String(error || ''));
  if (!m) return null;
  const want = `${m[1]}:${m[2]}`.toLowerCase();
  return (tokens || []).find(t => t.toLowerCase() === want) || null;
}

/**
 * Which of `tokens` the installed files do not carry.
 *
 * @param {(config: object) => Promise<{ok: boolean, error?: string}>} validate
 *        `xray.validate` — the core, with the app's own asset path.
 * @returns {Promise<{ checked: boolean, bad: string[], error: string|null }>}
 *          `checked:false` means the question could not be answered (no core
 *          installed, no geo files) — a caller must not report a rule as broken
 *          on the strength of that.
 */
async function checkGeoTokens(tokens, validate) {
  const list = (tokens || []).filter(t => GEO_TOKEN.test(t));
  if (!list.length) return { checked: true, bad: [], error: null };

  const bad = [];
  let remaining = list.slice();
  // Every round removes the one code the core named, so this ends: at worst
  // once per token, plus the final clean run.
  for (let i = 0; i <= list.length; i++) {
    const r = await validate(buildGeoProbeConfig(remaining));
    if (r && r.ok) return { checked: true, bad, error: null };
    const token = tokenFromError(r && r.error, remaining);
    if (!token) {
      // Something else is wrong (no geo files at all, no core, a broken build)
      // — not a verdict about the user's tokens.
      return { checked: false, bad: [], error: (r && r.error) || 'unknown' };
    }
    bad.push(token);
    remaining = remaining.filter(t => t !== token);
    if (!remaining.length) return { checked: true, bad, error: null };
  }
  return { checked: true, bad, error: null };
}

/**
 * The sentence to add to the core's own rejection when it is about a missing
 * code, so "geo files missing" does not become the user's conclusion.
 */
function geoCodeHint(error, lang) {
  const m = MISSING_CODE.exec(String(error || ''));
  if (!m) return '';
  const token = `${m[1]}:${m[2]}`.toLowerCase();
  const known = token === 'geosite:ir' ? 'geosite:category-ir' : null;
  if (lang === 'en') {
    return ` — the geo files are fine, but they carry no code "${token}". Fix that rule under Routing`
      + (known ? ` (the Iranian domain list is "${known}").` : '.');
  }
  return ` — فایل‌های geo سالم‌اند، ولی کدی به نام «${token}» در آن‌ها نیست. آن قانون را در بخش روتینگ اصلاح کن`
    + (known ? ` (فهرست دامنه‌های ایران «${known}» است).` : '.');
}

module.exports = { geoTokensOf, buildGeoProbeConfig, tokenFromError, checkGeoTokens, geoCodeHint, GEO_TOKEN, MISSING_CODE };
