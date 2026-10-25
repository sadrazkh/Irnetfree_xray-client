'use strict';
/**
 * scripts/probe-multiwan.js — two internets at once on real links, which CI
 * runs (test.yml, job `multiwan`) — kept honest here without root: it refuses
 * to run anywhere but CI (it makes network namespaces and links), it never
 * takes the app's own ports, and the job runs it on both suggested cores.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const PROBE = path.join(__dirname, '..', 'scripts', 'probe-multiwan.js');

test('the probe runs only in CI: without Linux, root and IRNF_MW_PROBE=1 it refuses before touching anything', () => {
  const r = spawnSync(process.execPath, [PROBE], {
    encoding: 'utf8', env: Object.assign({}, process.env, { IRNF_MW_PROBE: '' }), timeout: 15000
  });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /CI only/);
});

test('the probe’s ports and links: never the app’s own ports; failover’s primary is the link the OS would not pick', () => {
  const M = require('../scripts/probe-multiwan');
  for (const p of Object.values(M.P)) assert.equal(M.APP_PORTS.includes(p), false, `port ${p}`);
  assert.ok(M.A.metric < M.B.metric, 'A is the route the OS prefers');
  assert.equal(M.MW.failover.links[0].iface, M.B.dev, 'riding the primary must be the binding’s doing, not the routing table’s');
  assert.equal(M.MW.off.enabled, false);
  // both split lines, so each leg is once on the link the OS would not pick
  assert.deepEqual([M.MW.splitUpB.split, M.MW.splitUpA.split], [{ up: M.B.dev, down: M.A.dev }, { up: M.A.dev, down: M.B.dev }]);
  for (const mw of Object.values(M.MW)) {
    for (const l of mw.links) assert.deepEqual(Object.keys(l).sort(), ['id', 'iface', 'name', 'quotaGb', 'quotaPeriod', 'role', 'weight']);
  }
});

test('CI’s `multiwan` job runs the probe with sudo on the suggested Xray and Xray-PattN, each on its own ports, the second whatever the first did', () => {
  const yml = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'test.yml'), 'utf8').replace(/\r\n/g, '\n');
  const at = yml.indexOf('\n  multiwan:\n');
  assert.ok(at >= 0, 'test.yml has a multiwan job');
  const rest = yml.slice(at + 1);
  const end = rest.slice(1).search(/\n {2}[a-z][\w-]*:\n/);
  const job = end === -1 ? rest : rest.slice(0, end + 1);
  assert.match(job, /runs-on: ubuntu-latest/);
  assert.match(job, /timeout-minutes: \d+/);
  for (const read of ['SUGGESTED.xray', "SUGGESTED['xray-pattn']"]) {
    assert.ok(job.includes(`require('./src/main/coreVersions').${read}`), `the version is read from the table: ${read}`);
  }
  const runs = job.split('\n').filter((l) => /^\s+run: .*scripts\/probe-multiwan\.js/.test(l));
  assert.equal(runs.length, 2, 'one run per core');
  for (const l of runs) assert.match(l, /sudo IRNF_MW_PROBE=1 .*"\$\(command -v node\)" scripts\/probe-multiwan\.js/);
  assert.match(runs[0], /IRNF_XRAY_EXE="\$RUNNER_TEMP\/x\/xray"/);
  assert.match(runs[1], /IRNF_XRAY_EXE="\$RUNNER_TEMP\/p\/xray" IRNF_PROBE_PORT=\d+/);
  assert.match(job, /if: \$\{\{ !cancelled\(\) \}\}\n\s+timeout-minutes: \d+\n\s+run: sudo [^\n]*\$RUNNER_TEMP\/p\/xray/, 'the PattN run also after a failure');
});
