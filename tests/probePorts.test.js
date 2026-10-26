'use strict';
/**
 * The probes' fixed ports stay out of Linux's ephemeral range (32768–60999,
 * the CI runner's default). Inside it, a port a probe listens on can already
 * be the local end of some live loopback connection ("bind: address already in
 * use" — probe-warp-chain's 40112 was held across both its rounds), and a
 * connect to a port nobody listens on can reach ITSELF (TCP self-connect): the
 * dead member of probe-group answered now and then, and one fetch in nine got
 * nothing. Each probe's ports (its base + every `BASE + n`) also never overlap
 * another run's in the workflow, nor touch the app's own ports.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const EPHEMERAL_LOW = 32768;
const APP_PORTS = [10085, 10808, 10809, 30085, 30808, 30809, 30820, 30821, 30822];

function probe(name) {
  const src = fs.readFileSync(path.join(ROOT, 'scripts', name), 'utf8');
  const m = /IRNF_PROBE_PORT \|\| (\d+)/.exec(src);
  const offsets = [...src.matchAll(/BASE \+ (\d+)/g)].map((x) => Number(x[1]));
  return { base: m ? Number(m[1]) : null, span: offsets.length ? Math.max(...offsets) : 0 };
}

const probes = fs.readdirSync(path.join(ROOT, 'scripts')).filter((f) => /^probe-.*\.js$/.test(f));

test('every probe’s default ports are below the ephemeral range, above the privileged ones, clear of the app’s', () => {
  for (const f of probes) {
    const { base, span } = probe(f);
    if (base == null) continue;
    assert.ok(base >= 1024 && base + span < EPHEMERAL_LOW, `${f}: ${base}..${base + span}`);
    for (const p of APP_PORTS) assert.ok(p < base || p > base + span, `${f}: ${base}..${base + span} holds the app's ${p}`);
  }
});

test('the workflow’s probe runs: below the ephemeral range, and no two runs’ ports overlap', () => {
  const yml = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'test.yml'), 'utf8');
  const runs = [];
  for (const line of yml.split(/\r?\n/)) {
    const s = /scripts\/(probe-[\w-]+\.js)/.exec(line);
    if (!s || /^\s*#/.test(line)) continue;
    const { base, span } = probe(s[1]);
    const o = /IRNF_PROBE_PORT=(\d+)/.exec(line);
    const b = o ? Number(o[1]) : base;
    if (b == null) continue;
    runs.push({ name: s[1], from: b, to: b + span });
  }
  assert.ok(runs.length >= 8, 'the probe steps were found: ' + runs.map((r) => r.name).join(', '));
  for (const r of runs) assert.ok(r.from >= 1024 && r.to < EPHEMERAL_LOW, `${r.name}: ${r.from}..${r.to}`);
  for (let i = 0; i < runs.length; i++) {
    for (let j = i + 1; j < runs.length; j++) {
      const a = runs[i], b = runs[j];
      assert.ok(a.to < b.from || b.to < a.from, `${a.name} ${a.from}..${a.to} overlaps ${b.name} ${b.from}..${b.to}`);
    }
  }
});
