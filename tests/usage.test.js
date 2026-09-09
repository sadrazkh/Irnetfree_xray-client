'use strict';
/**
 * Lifetime traffic per config.
 *
 * The core's counters are cumulative SINCE THE CORE STARTED, so every reconnect
 * throws the numbers away and the app could only ever answer "how much this
 * session". The owner wants the other question — how much has gone through this
 * server / chain / pool entry, ever — which means turning a resetting counter
 * into a running total without losing bytes at the reset and without counting
 * any byte twice.
 *
 * These tests exist because both mistakes are invisible in normal use: a lost
 * kilobyte at each reconnect and a doubled one look identical to a number that
 * is simply "a bit off", and nobody can tell which by looking at it.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  tagMapFor, idForTag, DIRECT_ID,
  accumulate, nextSample, normalizeTotals, usageOf, grandTotal, pruneTotals, UsageMeter
} = require('../src/main/usage');

const srv = (id, name) => ({ id, name: name || id, address: id + '.example', outbound: { protocol: 'vless', tag: 'x' } });

/* --------------------------- which tag counts what --------------------------- */

test('a single server exits through "proxy", so proxy counts that server', () => {
  const s = srv('sv-a');
  assert.deepEqual(tagMapFor({ mode: 'single', server: s }, 'sv-a'), {
    proxy: 'sv-a',
    direct: DIRECT_ID
  });
});

test('a single plan whose server lost its id still counts against the connect target', () => {
  // buildPlan() is handed the id the user clicked; the server object is only
  // where it looked it up. One of the two is always there.
  const s = { address: 'a.example', outbound: {} };
  assert.equal(tagMapFor({ mode: 'single', server: s }, 'sv-a').proxy, 'sv-a');
  assert.equal(tagMapFor({ mode: 'single' }, undefined).proxy, undefined, 'nothing to attribute to');
});

test('a named chain exits through "proxy" too, and counts as the CHAIN not its last hop', () => {
  // The user picked a chain; "how much went through my chain" is the question.
  // Its exit hop is a server that may also be used on its own, and the two
  // must not share a total.
  const plan = { mode: 'chain', chain: [srv('sv-a'), srv('sv-b')], name: 'Double' };
  assert.equal(tagMapFor(plan, 'ch-1').proxy, 'chain:ch-1');
});

test('the legacy global chain has no id of its own', () => {
  const plan = { mode: 'chain', chain: [srv('sv-a'), srv('sv-b')] };
  assert.equal(tagMapFor(plan, '__chain__').proxy, 'chain');
  assert.equal(tagMapFor(plan).proxy, 'chain');
});

test('inner chain hops are never in the map — they carry the same bytes wrapped', () => {
  // buildChainOutbounds tags hops `<exit>-h<i>`; the exit already counts the
  // payload, so counting a hop as well would double every chained byte.
  const plan = { mode: 'chain', chain: [srv('sv-a'), srv('sv-b'), srv('sv-c')] };
  for (const tag of Object.keys(tagMapFor(plan, 'ch-1'))) {
    assert.ok(!/-h\d+$/.test(tag), 'hop tag leaked into the map: ' + tag);
  }
});

test('advanced routing: every rule target and the default, each under its own id', () => {
  const plan = {
    mode: 'advanced',
    serversById: { 'sv-a': srv('sv-a'), 'sv-b': srv('sv-b') },
    chainsById: { c1: [srv('sv-a'), srv('sv-b')] },
    rules: [
      { type: 'domain', value: 'x.com', target: 'sv-a' },
      { type: 'ip', value: '10.0.0.0/8', target: 'chain:c1' },
      { type: 'port', value: '25', target: 'block' },
      { type: 'domain', value: 'y.com', target: 'direct' }
    ],
    def: 'sv-b'
  };
  assert.deepEqual(tagMapFor(plan, '__advanced__'), {
    'out-sv-a': 'sv-a',
    'out-chain-c1': 'chain:c1',
    'out-sv-b': 'sv-b',
    direct: DIRECT_ID
  });
});

test('advanced routing: a target that no longer exists lands on direct, exactly as the config does', () => {
  // makeRegistry().tagFor() falls back to 'direct' for an unknown server and
  // for a chain with no usable members. Attributing those bytes to the deleted
  // id would invent usage for a config that is not carrying anything.
  const plan = {
    mode: 'advanced',
    serversById: {},
    chainsById: { c1: [] },
    rules: [
      { type: 'domain', value: 'x.com', target: 'sv-gone' },
      { type: 'domain', value: 'y.com', target: 'chain:c1' }
    ],
    def: 'direct'
  };
  assert.deepEqual(tagMapFor(plan, '__advanced__'), { direct: DIRECT_ID });
});

test('advanced routing: a one-member chain keeps the chain id (the config keeps the tag)', () => {
  const plan = {
    mode: 'advanced', serversById: {}, chainsById: { c1: [srv('sv-a')] },
    rules: [{ type: 'domain', value: 'x.com', target: 'chain:c1' }], def: 'direct'
  };
  assert.equal(tagMapFor(plan, '__advanced__')['out-chain-c1'], 'chain:c1');
});

test('the pool counts every entry apart, and the primary as well', () => {
  const plan = {
    mode: 'pool',
    entries: [
      { id: 'p1', target: 'sv-a', socksPort: 60001 },
      { id: 'p2', target: 'chain:c1', socksPort: 60002 },
      { id: 'p3', target: 'sv-a', socksPort: 60003 }   // same exit as p1: one tag
    ],
    primary: 'sv-b',
    serversById: { 'sv-a': srv('sv-a'), 'sv-b': srv('sv-b') },
    chainsById: { c1: [srv('sv-a'), srv('sv-b')] }
  };
  assert.deepEqual(tagMapFor(plan, '__pool__'), {
    'out-sv-a': 'sv-a',
    'out-chain-c1': 'chain:c1',
    'out-sv-b': 'sv-b',
    direct: DIRECT_ID
  });
});

test('a config whose id happens to look like a chain hop is still counted', () => {
  // 'out-sv-h0' reads as a hop by name. The map is built from the target, not
  // by parsing the tag back, so it cannot be fooled — the tag really is that
  // server's exit and its bytes are that server's.
  const plan = {
    mode: 'advanced', serversById: { 'sv-h0': srv('sv-h0') }, chainsById: {},
    rules: [{ type: 'domain', value: 'x.com', target: 'sv-h0' }], def: 'direct'
  };
  assert.equal(tagMapFor(plan, '__advanced__')['out-sv-h0'], 'sv-h0');
});

test('direct is always countable — a bypass user wants to see what went past the tunnel', () => {
  for (const plan of [
    { mode: 'single', server: srv('sv-a') },
    { mode: 'chain', chain: [srv('sv-a'), srv('sv-b')] },
    { mode: 'pool', entries: [], primary: 'sv-a', serversById: { 'sv-a': srv('sv-a') } }
  ]) assert.equal(tagMapFor(plan, 'sv-a').direct, DIRECT_ID);
});

test('block is never counted — a blackholed request used nobody\'s bandwidth', () => {
  const plan = {
    mode: 'advanced', serversById: {}, chainsById: {},
    rules: [{ type: 'domain', value: 'ads', target: 'block' }], def: 'block'
  };
  assert.equal('block' in tagMapFor(plan, '__advanced__'), false);
});

test('the old plan shapes normalize the same way buildConfig normalizes them', () => {
  // an array is the legacy chain; a bare object with an outbound is one server
  assert.equal(tagMapFor([srv('sv-a'), srv('sv-b')], '__chain__').proxy, 'chain');
  assert.equal(tagMapFor(srv('sv-a'), 'sv-a').proxy, 'sv-a');
});

test('garbage in place of a plan produces a map, not an exception', () => {
  for (const p of [null, undefined, 0, 'nonsense', { mode: 'martian' }]) {
    assert.deepEqual(tagMapFor(p, 'sv-a'), { direct: DIRECT_ID }, JSON.stringify(p));
  }
});

/* ------------------------- the tag → id direction alone ------------------------- */

test('idForTag is the inverse of the renderer\'s outboundTagFor', () => {
  assert.equal(idForTag('out-sv-a'), 'sv-a');
  assert.equal(idForTag('out-chain-c1'), 'chain:c1');
  assert.equal(idForTag('out-chain'), 'chain');
  assert.equal(idForTag('direct'), DIRECT_ID);
});

test('idForTag refuses the tags that must never be counted', () => {
  // 'proxy' depends on the plan and only tagMapFor knows it; hops double-count;
  // block and the DNS/DPI dialers are not anybody's usage.
  for (const t of ['proxy', 'proxy-h0', 'out-chain-c1-h0', 'block', 'dns-out', 'dpi-1', '', null, undefined]) {
    assert.equal(idForTag(t), null, String(t));
  }
});

/* ------------------------------- the accumulator ------------------------------- */

const MAP = { proxy: 'sv-a', direct: DIRECT_ID };
const per = (o) => o;   // reads better at the call sites below
const at = (t) => ({ now: t });

test('the ordinary tick adds the difference', () => {
  const t = accumulate(per({ proxy: { up: 100, down: 200 } }), per({ proxy: { up: 150, down: 500 } }),
    MAP, { 'sv-a': { up: 1000, down: 2000, lastUsed: 1 } }, at(9));
  assert.deepEqual(t, { 'sv-a': { up: 1050, down: 2300, lastUsed: 9 } });
});

test('the first tick after a connect counts the whole counter', () => {
  // There is no previous sample and the core's counter started at zero when it
  // did, so everything it reports is new.
  const t = accumulate(null, per({ proxy: { up: 40, down: 60 } }), MAP, {}, at(9));
  assert.deepEqual(t, { 'sv-a': { up: 40, down: 60, lastUsed: 9 } });
});

test('a counter that went DOWN means the core restarted: the new value is the delta, in full', () => {
  // This is the whole point. The previous core had carried 5 MB; the new one
  // reports 300 bytes. Subtracting would give a negative — clamping that to
  // zero would throw away the 300 bytes the new core had already carried by
  // the time of this first poll, on every single reconnect.
  const t = accumulate(per({ proxy: { up: 5e6, down: 9e6 } }), per({ proxy: { up: 300, down: 700 } }),
    MAP, { 'sv-a': { up: 5e6, down: 9e6, lastUsed: 1 } }, at(9));
  assert.deepEqual(t, { 'sv-a': { up: 5e6 + 300, down: 9e6 + 700, lastUsed: 9 } });
});

test('a total never goes backwards, whatever the counters do', () => {
  let t = { 'sv-a': { up: 10, down: 10, lastUsed: 1 } };
  for (const cur of [{ up: 0, down: 0 }, { up: -5, down: -5 }, { up: 3, down: 3 }, { up: 1, down: 1 }]) {
    const before = t['sv-a'];
    t = accumulate({ proxy: { up: 99, down: 99 } }, { proxy: cur }, MAP, t, at(9));
    assert.ok(t['sv-a'].up >= before.up && t['sv-a'].down >= before.down, JSON.stringify(cur));
  }
});

test('a tag that vanishes for one tick and comes back is not counted twice', () => {
  // /debug/vars can omit an outbound that has not moved; if the previous sample
  // forgot it, its whole counter would look new the moment it reappeared.
  let sample = { proxy: { up: 1000, down: 1000 } };
  let totals = accumulate(null, sample, MAP, {}, at(1));
  const gap = {};                                    // the tag is missing this tick
  totals = accumulate(sample, gap, MAP, totals, at(2));
  sample = nextSample(sample, gap);
  totals = accumulate(sample, { proxy: { up: 1200, down: 1200 } }, MAP, totals, at(3));
  assert.deepEqual(totals, { 'sv-a': { up: 1200, down: 1200, lastUsed: 3 } });
});

test('unmapped tags are ignored — hops, block and anything the plan does not own', () => {
  const t = accumulate({}, per({
    proxy: { up: 10, down: 10 },
    'proxy-h0': { up: 999, down: 999 },
    block: { up: 999, down: 999 },
    'out-sv-z': { up: 999, down: 999 }
  }), MAP, {}, at(9));
  assert.deepEqual(t, { 'sv-a': { up: 10, down: 10, lastUsed: 9 } });
});

test('garbage in the counters adds nothing and never poisons a total', () => {
  const base = { 'sv-a': { up: 500, down: 500, lastUsed: 1 } };
  for (const cur of [{ up: 'x', down: null }, { up: NaN, down: undefined }, {}, null, 'nope']) {
    const t = accumulate({ proxy: { up: 100, down: 100 } }, { proxy: cur }, MAP, base, at(9));
    assert.deepEqual(t, base, JSON.stringify(cur));
  }
  assert.deepEqual(accumulate(null, null, MAP, base, at(9)), base);
});

test('lastUsed moves only when bytes actually moved', () => {
  const first = accumulate(null, { proxy: { up: 5, down: 5 } }, MAP, {}, at(100));
  const idle = accumulate({ proxy: { up: 5, down: 5 } }, { proxy: { up: 5, down: 5 } }, MAP, first, at(200));
  assert.equal(idle['sv-a'].lastUsed, 100);
  assert.equal(idle, first, 'an idle tick returns the totals untouched — that is the "no need to save" signal');
});

test('the totals handed in are never mutated', () => {
  const before = { 'sv-a': { up: 1, down: 1, lastUsed: 1 } };
  const frozen = JSON.parse(JSON.stringify(before));
  const after = accumulate(null, { proxy: { up: 9, down: 9 } }, MAP, before, at(9));
  assert.deepEqual(before, frozen, 'the caller may still be holding the old object');
  assert.notEqual(after, before);
});

test('a pool moves several configs at once, each into its own record', () => {
  const map = { 'out-sv-a': 'sv-a', 'out-chain-c1': 'chain:c1', direct: DIRECT_ID };
  const t = accumulate(
    { 'out-sv-a': { up: 10, down: 10 }, 'out-chain-c1': { up: 20, down: 20 }, direct: { up: 30, down: 30 } },
    { 'out-sv-a': { up: 15, down: 11 }, 'out-chain-c1': { up: 60, down: 20 }, direct: { up: 30, down: 90 } },
    map, {}, at(9));
  assert.deepEqual(t, {
    'sv-a': { up: 5, down: 1, lastUsed: 9 },
    'chain:c1': { up: 40, down: 0, lastUsed: 9 },
    direct: { up: 0, down: 60, lastUsed: 9 }
  });
});

test('two tags that mean the same config land in one record', () => {
  const map = { proxy: 'sv-a', 'out-sv-a': 'sv-a' };
  const t = accumulate({}, { proxy: { up: 10, down: 0 }, 'out-sv-a': { up: 5, down: 0 } }, map, {}, at(9));
  assert.deepEqual(t, { 'sv-a': { up: 15, down: 0, lastUsed: 9 } });
});

test('a plan that changed while connected does not hand the new config the old one\'s bytes', () => {
  // A settings apply rebuilds the config: 'proxy' now means a different server
  // and the core restarted, so its counter fell. The new server is credited
  // with what the NEW core carried — not with the whole previous session.
  const totals = accumulate(
    { proxy: { up: 8e6, down: 8e6 } },              // sv-a's session, before the apply
    { proxy: { up: 120, down: 340 } },              // the fresh core, now meaning sv-b
    { proxy: 'sv-b' }, { 'sv-a': { up: 8e6, down: 8e6, lastUsed: 1 } }, at(9));
  assert.deepEqual(totals, {
    'sv-a': { up: 8e6, down: 8e6, lastUsed: 1 },
    'sv-b': { up: 120, down: 340, lastUsed: 9 }
  });
});

test('a plan that changed WITHOUT a core restart misattributes one tick, not a session', () => {
  // The counter did not fall, so there is no way to tell the bytes apart; the
  // difference is the honest answer and it is one poll wide. Taking the raw
  // counter here would have given sv-b the entire session.
  const totals = accumulate({ proxy: { up: 8e6, down: 8e6 } }, { proxy: { up: 8e6 + 50, down: 8e6 + 50 } },
    { proxy: 'sv-b' }, {}, at(9));
  assert.deepEqual(totals, { 'sv-b': { up: 50, down: 50, lastUsed: 9 } });
});

test('nextSample keeps only what a delta needs, and forgets nothing', () => {
  const s = nextSample({ proxy: { up: 5, down: 5 }, gone: { up: 1, down: 2 } },
    { proxy: { up: 9, down: 9, upSpeed: 4, downSpeed: 4 }, fresh: { up: 'x', down: 3 } });
  assert.deepEqual(s, {
    proxy: { up: 9, down: 9 },      // the speeds the poller adds are not carried
    gone: { up: 1, down: 2 },       // absent this tick — held, or it would look new later
    fresh: { up: 0, down: 3 }
  });
  assert.deepEqual(nextSample(null, null), {});
});

/* ------------------------------- what gets stored ------------------------------- */

test('what came off disk is sanitized before it is trusted', () => {
  assert.deepEqual(normalizeTotals({
    'sv-a': { up: 10, down: 20, lastUsed: 5 },
    'sv-down-only': { up: 0, down: 7, lastUsed: 'soon' },
    'sv-bad': { up: 'x', down: -3, lastUsed: 1 },
    'sv-zero': { up: 0, down: 0, lastUsed: 7 },
    'sv-null': null,
    '': { up: 9, down: 9 }
  }), {
    'sv-a': { up: 10, down: 20, lastUsed: 5 },
    'sv-down-only': { up: 0, down: 7, lastUsed: 0 }
  });
  for (const raw of [null, undefined, 'nonsense', 42, ['a']]) assert.deepEqual(normalizeTotals(raw), {}, String(raw));
});

test('a record carrying no bytes is not kept — nothing ever writes one', () => {
  // accumulate() only ever writes a record when bytes moved, so an all-zero (or
  // unreadable) one in the file is damage or a hand edit. Dropping it keeps the
  // store small and loses no fact: a missing record and an empty record answer
  // the same thing.
  assert.deepEqual(usageOf(normalizeTotals({ 'sv-zero': { up: 0, down: 0, lastUsed: 7 } }), 'sv-zero'),
    usageOf({}, 'sv-zero'));
});

test('usageOf answers for an id nobody has used yet', () => {
  const t = { 'sv-a': { up: 1, down: 2, lastUsed: 3 } };
  assert.deepEqual(usageOf(t, 'sv-a'), { up: 1, down: 2, lastUsed: 3 });
  assert.deepEqual(usageOf(t, 'sv-b'), { up: 0, down: 0, lastUsed: 0 });
  assert.deepEqual(usageOf(null, 'sv-a'), { up: 0, down: 0, lastUsed: 0 });
});

test('the grand total leaves out what never went through a proxy', () => {
  const t = { 'sv-a': { up: 10, down: 20 }, 'chain:c1': { up: 1, down: 2 }, direct: { up: 900, down: 900 } };
  assert.deepEqual(grandTotal(t), { up: 11, down: 22 });
  assert.deepEqual(grandTotal(t, { includeDirect: true }), { up: 911, down: 922 });
  assert.deepEqual(grandTotal(null), { up: 0, down: 0 });
});

test('pruning forgets deleted configs and keeps the file from growing for ever', () => {
  const t = { 'sv-a': { up: 1, down: 1 }, 'sv-gone': { up: 2, down: 2 }, 'chain:c1': { up: 3, down: 3 }, direct: { up: 4, down: 4 } };
  assert.deepEqual(pruneTotals(t, ['sv-a', 'chain:c1']), {
    'sv-a': { up: 1, down: 1 }, 'chain:c1': { up: 3, down: 3 }, direct: { up: 4, down: 4 }
  }, 'direct survives: it belongs to no config, so no config list can vouch for it');
  assert.equal(pruneTotals(t, ['sv-a', 'sv-gone', 'chain:c1']), t, 'nothing to drop, nothing to save');
  assert.equal(pruneTotals(t, null), t, 'no list means no opinion — never a reason to delete everything');
});

/* --------------------------- the meter across sessions --------------------------- */

const single = (id) => ({ mode: 'single', server: srv(id) });

test('a whole life: connect, traffic, disconnect, reconnect — the total just keeps going', () => {
  const m = new UsageMeter({ totals: { 'sv-a': { up: 1000, down: 1000, lastUsed: 1 } }, now: 0 });
  m.setPlan(single('sv-a'), 'sv-a');
  m.tick({ proxy: { up: 100, down: 200 } }, 10);
  m.tick({ proxy: { up: 300, down: 500 } }, 20);
  assert.deepEqual(m.totals['sv-a'], { up: 1300, down: 1500, lastUsed: 20 });

  m.reset();                                       // disconnect: the core and its counters are gone
  m.setPlan(single('sv-a'), 'sv-a');
  m.tick({ proxy: { up: 50, down: 60 } }, 30);      // a brand-new core, counting from zero again
  assert.deepEqual(m.totals['sv-a'], { up: 1350, down: 1560, lastUsed: 30 });
});

test('reset() is what makes a reconnect lossless — the restart is not always visible in the numbers', () => {
  // A restart normally shows up as a counter that fell, and accumulate handles
  // that on its own. But if the new core has already carried MORE than the old
  // one had by the time of the first poll, the reading looks like ordinary
  // growth and the difference is silently swallowed. Only the caller knows the
  // core restarted, which is why reset() has to be wired to every stats.stop().
  const run = (withReset) => {
    const m = new UsageMeter({ now: 0 });
    m.setPlan(single('sv-a'), 'sv-a');
    m.tick({ proxy: { up: 1000, down: 0 } }, 10);
    if (withReset) m.reset();
    m.tick({ proxy: { up: 1500, down: 0 } }, 20);   // a fresh core, already past the old figure
    return m.totals['sv-a'].up;
  };
  assert.equal(run(true), 2500);
  assert.equal(run(false), 1500, 'this is the bug reset() exists to prevent');
});

test('the meter says when there is something worth writing, and how often', () => {
  const m = new UsageMeter({ now: 0 });
  m.setPlan(single('sv-a'), 'sv-a');
  assert.equal(m.dirty, false);
  assert.equal(m.tick({ proxy: { up: 0, down: 0 } }, 1000), false, 'an idle poll is not a reason to touch the disk');
  assert.equal(m.dirty, false);

  assert.equal(m.tick({ proxy: { up: 10, down: 10 } }, 2000), true);
  assert.equal(m.dirty, true);
  assert.equal(m.dueForSave(2000, 30000), false, 'dirty, but the file was written 2 s ago');
  assert.equal(m.dueForSave(31000, 30000), true);

  m.markSaved(31000);
  assert.equal(m.dirty, false);
  assert.equal(m.dueForSave(99000, 30000), false, 'nothing has changed since it was written');
});

test('a poll that failed or returned nothing changes nothing', () => {
  const m = new UsageMeter({ now: 0 });
  m.setPlan(single('sv-a'), 'sv-a');
  m.tick({ proxy: { up: 10, down: 10 } }, 10);
  for (const bad of [null, undefined, 'nope', 42]) assert.equal(m.tick(bad, 20), false, String(bad));
  assert.deepEqual(m.totals['sv-a'], { up: 10, down: 10, lastUsed: 10 });
  // and the sample it kept is still the good one — the next real poll must not
  // read as a fresh core
  m.tick({ proxy: { up: 30, down: 30 } }, 30);
  assert.deepEqual(m.totals['sv-a'], { up: 30, down: 30, lastUsed: 30 });
});

test('switching config mid-session moves the counting, not the history', () => {
  const m = new UsageMeter({ now: 0 });
  m.setPlan(single('sv-a'), 'sv-a');
  m.tick({ proxy: { up: 500, down: 500 } }, 10);
  m.reset();                                       // the settings apply stopped the core
  m.setPlan(single('sv-b'), 'sv-b');
  m.tick({ proxy: { up: 70, down: 70 } }, 20);
  assert.deepEqual(m.totals, {
    'sv-a': { up: 500, down: 500, lastUsed: 10 },
    'sv-b': { up: 70, down: 70, lastUsed: 20 }
  });
});

test('the meter starts from a store that is empty, missing or damaged', () => {
  for (const t of [undefined, null, 'nonsense', { 'sv-a': { up: 'x', down: 'y' } }]) {
    const m = new UsageMeter({ totals: t, now: 0 });
    m.setPlan(single('sv-a'), 'sv-a');
    m.tick({ proxy: { up: 5, down: 5 } }, 10);
    assert.deepEqual(m.totals, { 'sv-a': { up: 5, down: 5, lastUsed: 10 } }, JSON.stringify(t));
  }
});

test('the meter counts nothing until it has been told the plan', () => {
  // A tick that arrives before setPlan (a poller left running, a status event
  // out of order) must not file bytes under a config nobody named.
  const m = new UsageMeter({ now: 0 });
  assert.equal(m.tick({ proxy: { up: 9, down: 9 } }, 10), false);
  assert.deepEqual(m.totals, {});
});

test('forgetting a deleted config is the meter\'s job too', () => {
  const m = new UsageMeter({ totals: { 'sv-a': { up: 1, down: 1 }, 'sv-gone': { up: 2, down: 2 } }, now: 0 });
  assert.equal(m.prune(['sv-a']), true);
  assert.deepEqual(Object.keys(m.totals), ['sv-a']);
  assert.equal(m.dirty, true, 'the file has to be written or the record comes back at the next launch');
  m.markSaved(0);
  assert.equal(m.prune(['sv-a']), false);
  assert.equal(m.dirty, false);
});

/* ----------------------------- forgetting a total ----------------------------- */

test('UsageMeter.clear(id) forgets one config; clear() forgets everything; both mark dirty', () => {
  // A total that is only gone in memory comes back at the next launch, so
  // clearing has to reach the disk the same way counting does.
  const m = new UsageMeter({ totals: { 'sv-a': { down: 10, up: 1 }, 'sv-b': { down: 20, up: 2 } } });
  m.markSaved();
  assert.equal(m.clear('sv-zzz'), false, 'unknown id: nothing to forget');
  assert.equal(m.dirty, false, 'and nothing to write');
  assert.equal(m.clear('sv-a'), true);
  assert.deepEqual(Object.keys(m.totals), ['sv-b']);
  assert.equal(m.dirty, true);
  m.markSaved();
  assert.equal(m.clear(), true);
  assert.deepEqual(m.totals, {});
  assert.equal(m.dirty, true);
  assert.equal(m.clear(), false, 'already empty');
});

test('clearing a config does not disturb the live sample: the next tick counts from the current reading', () => {
  // The core keeps counting through a clear. Whatever it has carried since the
  // last poll belongs to the config; only what was there BEFORE is forgotten.
  const m = new UsageMeter({ totals: {} });
  m.setPlan({ mode: 'single', server: { id: 'sv-a', outbound: {} } }, 'sv-a');
  m.tick({ proxy: { up: 0, down: 0 } });
  m.tick({ proxy: { up: 100, down: 900 } });
  const seen = (id) => ({ up: m.totals[id].up, down: m.totals[id].down });
  assert.deepEqual(seen('sv-a'), { up: 100, down: 900 });
  m.clear('sv-a');
  m.tick({ proxy: { up: 150, down: 1000 } });
  assert.deepEqual(seen('sv-a'), { up: 50, down: 100 }, 'only the new bytes');
});
