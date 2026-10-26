'use strict';
/**
 * A group on a core whose loopback still copies through a pipe of its own:
 * official Xray before 26.4.25 (XTLS/Xray-core#6005) drops the end of a
 * download through it. The other Xray core when it is new enough, else it
 * runs and the connect says what to update (owner, 2026-10-26) — from the
 * builder's own configs to the line in the connect log, desktop and router.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const G = require('../src/main/groups');
const B = require('../src/main/configBuilder');
const { parseLink } = require('../src/main/parser');
const { XrayManager, runsGroup } = require('../src/main/xrayManager');

const UUID = '2c0f0d9a-6b3a-4f0e-9a1f-8c2b4d6e7a10';
const srv = (id, l) => Object.assign(parseLink(l), { id });
const CDN = srv('cdn', `vless://${UUID}@cdn.example.com:443?type=ws&security=tls&path=%2Fw#CDN`);
const DE = srv('de', `vless://${UUID}@de.example.net:443?type=ws&security=tls&path=%2Fd#DE`);
const NL = srv('nl', `trojan://pw@nl.example.net:443?security=tls&sni=nl.example.net#NL`);
const byId = { cdn: CDN, de: DE, nl: NL };
const GRP = G.groupRecord({ id: 'grp-g', name: 'G', members: ['cdn', 'de'] }, byId);
const SETTINGS = { socksPort: 47208, httpPort: 47209, apiPort: 47285, routingMode: 'global', blockAds: false, geoAssets: false, dnsManaged: false, logLevel: 'warning' };

/** Stand-in cores: `versions[id]` is what `<core> version` says; -test passes on every installed one. */
function manager(versions) {
  const m = new XrayManager({ dataDir: os.tmpdir(), onLog: (line) => m.logs.push(line) });
  m.logs = [];
  m.resolveBin = (id = 'xray') => (id in versions ? path.join(os.tmpdir(), id) : null);
  m.version = async (id = 'xray') => versions[id] || '';
  m.validate = async (cfg, id) => (id in versions ? { ok: true } : { ok: false, error: `no ${id}` });
  return m;
}

const CONFIGS = {
  'a group selected': () => B.buildConfig({ mode: 'single', server: GRP }, SETTINGS),
  'a chain through a group': () => B.buildConfig({ mode: 'chain', chain: [NL, GRP] }, SETTINGS),
  'a group as a route target': () => B.buildConfig({ mode: 'advanced', serversById: Object.assign({}, byId, { 'grp-g': GRP }), chainsById: {}, chain: [],
    rules: [{ type: 'domain', value: 'example.org', target: 'grp-g' }], def: 'de' }, SETTINGS)
};

test('every config the builder makes with a group runs one; a plain server or chain does not', () => {
  for (const [what, build] of Object.entries(CONFIGS)) assert.equal(runsGroup(build()), true, what);
  assert.equal(runsGroup(B.buildConfig({ mode: 'single', server: DE }, SETTINGS)), false);
  assert.equal(runsGroup(B.buildConfig({ mode: 'chain', chain: [NL, DE] }, SETTINGS)), false);
  // what the core reads never carries the map
  assert.equal(runsGroup(JSON.parse(JSON.stringify(CONFIGS['a group selected']()))), false);
});

test('the builder’s group configs on Xray 26.3.27: moved to a new Xray-PattN, else run there with the version it needs', async () => {
  for (const [what, build] of Object.entries(CONFIGS)) {
    const moved = manager({ xray: '26.3.27', 'xray-pattn': '26.10.22' });
    assert.deepEqual(await moved.validateWithFallback(build(), 'xray'), { ok: true, engine: 'xray-pattn', fellBack: true }, what);
    assert.match(moved.logs.at(-1), /^This config runs a group, and Xray \(official\) 26\.3\.27 can cut short the end of a download through it/, what);
    const stays = manager({ xray: '26.3.27' });
    assert.deepEqual(await stays.validateWithFallback(build(), 'xray'), { ok: true, engine: 'xray', groupCoreOld: true, coreVersion: '26.3.27', need: '26.4.25' }, what);
    const current = manager({ xray: '26.10.21' });
    assert.deepEqual(await current.validateWithFallback(build(), 'xray'), { ok: true, engine: 'xray' }, what);
  }
});

test('the connect says it in the log — a warning, in the user’s language, right after the core is chosen — desktop and router', () => {
  const read = (f) => fs.readFileSync(path.join(__dirname, '..', f), 'utf8').replace(/\r\n/g, '\n');
  for (const f of ['src/main/main.js', 'src/server/service.js']) {
    const src = read(f);
    const at = src.indexOf('if (check.groupCoreOld) {');
    assert.ok(at > 0, f);
    assert.match(src.slice(src.lastIndexOf('const runEngine = check.engine;', at), at), /^const runEngine = check\.engine;\n(\s*\/\/[^\n]*\n)*\s*$/, f + ': straight after the core is chosen');
    let end = src.indexOf('{', at), depth = 0;
    do { if (src[end] === '{') depth++; else if (src[end] === '}') depth--; end++; } while (depth > 0);
    const body = src.slice(at, end);
    assert.match(body, /This config runs a group, and Xray \$\{check\.coreVersion\} can cut short the end of a download through it \(fixed in \$\{check\.need\}\) — update Xray under Settings → Required files/, f);
    assert.match(body, /این کانفیگ گروه دارد و Xray \$\{check\.coreVersion\} ممکن است انتهای دانلودی را که از گروه می‌گذرد ببُرد \(از \$\{check\.need\} درست شده\)/, f);
    assert.match(body, /level: 'warn'/, f);
    assert.doesNotMatch(body, /throw/, f + ': not a refusal');
  }
});
