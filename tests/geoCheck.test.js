'use strict';
/**
 * A routing rule may name a geo code the installed data files do not carry —
 * `geosite:ir` is the one the app itself used to suggest, and it does not
 * exist (the Iranian domain list is `geosite:category-ir`). The core then
 * refuses the ENTIRE config with "code not found in geosite.dat: IR", which
 * every user reads as "my geo files are missing".
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const {
  geoTokensOf, buildGeoProbeConfig, tokenFromError, checkGeoTokens, geoCodeHint
} = require('../src/main/geoCheck');

/* ----------------------------- picking the tokens ----------------------------- */

test('geoTokensOf finds the geo codes in advanced rules and in custom rules alike', () => {
  assert.deepEqual(geoTokensOf([
    { type: 'domain', value: 'geosite:category-ir, geosite:ir' },
    { type: 'ip', value: 'geoip:ir' },
    { type: 'domain', value: 'example.com' },              // not a geo token
    { type: 'ip', value: '192.168.0.0/16' },
    { domain: 'geosite:cn', outboundTag: 'direct' },       // the custom-rule shape
    { ip: 'geoip:cn,1.2.3.0/24', outboundTag: 'direct' }
  ]), ['geosite:category-ir', 'geosite:ir', 'geoip:ir', 'geosite:cn', 'geoip:cn']);
  assert.deepEqual(geoTokensOf([]), []);
  assert.deepEqual(geoTokensOf(null), []);
  assert.deepEqual(geoTokensOf([{ value: 'geosite:category-ir' }, { value: 'geosite:category-ir' }]),
    ['geosite:category-ir'], 'each token once');
  assert.deepEqual(geoTokensOf([{ value: 'ext:custom.dat:ir' }, { value: 'regexp:.*\\.ir$' }]), [],
    'only geoip:/geosite: are ours to check');
});

test('the probe config carries the tokens and nothing else', () => {
  const c = buildGeoProbeConfig(['geosite:cn', 'geoip:ir', 'geosite:category-ir']);
  assert.deepEqual(c.routing.rules, [
    { type: 'field', domain: ['geosite:cn', 'geosite:category-ir'], outboundTag: 'direct' },
    { type: 'field', ip: ['geoip:ir'], outboundTag: 'direct' }
  ]);
  // one outbound, no proxy, nothing that could fail for another reason
  assert.deepEqual(c.outbounds, [{ tag: 'direct', protocol: 'freedom' }]);
  assert.deepEqual(buildGeoProbeConfig([]).routing.rules, []);
});

test('tokenFromError maps the code the core names back to the user’s token', () => {
  const tokens = ['geosite:category-ir', 'geosite:ir', 'geoip:ir'];
  assert.equal(tokenFromError('infra/conf: code not found in geosite.dat: IR', tokens), 'geosite:ir');
  assert.equal(tokenFromError('code not found in geoip.dat: IR', tokens), 'geoip:ir',
    'the file the core names is what tells the two apart');
  assert.equal(tokenFromError('failed to read geoip.dat', tokens), null, 'a different failure is not a token');
  assert.equal(tokenFromError('', tokens), null);
});

/* ----------------------------- asking the core ----------------------------- */

/** A stand-in core that knows exactly these codes. */
function coreWith(known) {
  return async (config) => {
    const rules = config.routing.rules;
    for (const r of rules) {
      for (const t of [...(r.domain || []), ...(r.ip || [])]) {
        if (known.includes(t)) continue;
        const [kind, code] = t.split(':');
        return { ok: false, error: `infra/conf: code not found in ${kind}.dat: ${code.toUpperCase()}` };
      }
    }
    return { ok: true };
  };
}

test('checkGeoTokens names every code the files do not carry, not just the first', async () => {
  const core = coreWith(['geosite:category-ir', 'geoip:ir', 'geosite:cn']);
  assert.deepEqual(
    await checkGeoTokens(['geosite:category-ir', 'geosite:ir', 'geoip:ir', 'geosite:nowhere'], core),
    { checked: true, bad: ['geosite:ir', 'geosite:nowhere'], error: null });
  assert.deepEqual(await checkGeoTokens(['geosite:cn', 'geoip:ir'], core),
    { checked: true, bad: [], error: null });
  assert.deepEqual(await checkGeoTokens([], core), { checked: true, bad: [], error: null });
});

test('checkGeoTokens spends one core run per bad token, plus the clean one', async () => {
  let runs = 0;
  const core = coreWith(['geoip:ir']);
  const counted = async (c) => { runs++; return core(c); };
  await checkGeoTokens(['geoip:ir'], counted);
  assert.equal(runs, 1, 'all good: asked once');
  runs = 0;
  await checkGeoTokens(['geoip:ir', 'geosite:a', 'geosite:b'], counted);
  assert.equal(runs, 3, 'two bad tokens: two rejections and the run that finally passes');
});

test('a failure that is not about a code is not a verdict on the user’s rules', async () => {
  const broken = async () => ({ ok: false, error: 'xray binary not found' });
  assert.deepEqual(await checkGeoTokens(['geosite:category-ir'], broken),
    { checked: false, bad: [], error: 'xray binary not found' },
    'with no core to ask, no rule may be called broken');
  const noFiles = async () => ({ ok: false, error: 'infra/conf: failed to read geosite.dat' });
  assert.equal((await checkGeoTokens(['geosite:cn'], noFiles)).checked, false);
});

/* ----------------------------- what the user is told ----------------------------- */

test('geoCodeHint turns the core’s line into something a user can act on', () => {
  const err = 'infra/conf: code not found in geosite.dat: IR';
  const en = geoCodeHint(err, 'en');
  assert.match(en, /geo files are fine/);
  assert.match(en, /geosite:ir/);
  assert.match(en, /geosite:category-ir/, 'the code that DOES exist is named');
  const fa = geoCodeHint(err, 'fa');
  assert.match(fa, /geosite:category-ir/);
  assert.equal(fa.includes('geo'), true);
  // an unknown code with no obvious replacement still gets the "files are fine" half
  assert.match(geoCodeHint('code not found in geoip.dat: XZ', 'en'), /no code "geoip:xz"/);
  assert.equal(geoCodeHint('something else entirely', 'en'), '', 'nothing to add');
});
