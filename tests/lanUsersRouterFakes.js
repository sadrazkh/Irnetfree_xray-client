'use strict';
/**
 * Fakes for the users module's router half (src/modules/lanUsers/router): a
 * file system in memory, a LAN (ubus, `ip neigh`, the lease file, the nft
 * table's counters) that answers from the test's own data, a gateway that
 * records every table load, and a users meter. Nothing here runs `ip` or
 * `nft`, binds a port or writes a file on the machine running the tests.
 *
 * Not a test file itself (no `.test.js`): required by the lanUsersRouter* tests.
 */
const ENOENT = () => Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
const norm = (p) => String(p).replace(/\\/g, '/');

function memFs() {
  const files = new Map();
  const dirOf = (p) => p.slice(0, p.lastIndexOf('/'));
  return {
    files,
    get: (p) => files.get(norm(p)),
    writeFileSync: (p, text) => { files.set(norm(p), String(text)); },
    readFileSync: (p) => { if (!files.has(norm(p))) throw ENOENT(); return files.get(norm(p)); },
    renameSync: (a, b) => { if (!files.has(norm(a))) throw ENOENT(); files.set(norm(b), files.get(norm(a))); files.delete(norm(a)); },
    mkdirSync: () => {},
    readdirSync: (dir) => [...files.keys()].filter(k => dirOf(k) === norm(dir)).map(k => k.slice(k.lastIndexOf('/') + 1)),
    unlinkSync: (p) => { if (!files.delete(norm(p))) throw ENOENT(); }
  };
}

/** `nft -j list table inet irnetfree` with these named counters ({ mac: { up, down } }) — and the clutter a real listing has around them. */
function nftJson(counters) {
  const items = [{ metainfo: { version: '1.0.9', release_name: 'Old Doc Yak #3', json_schema_version: 1 } }, { table: { family: 'inet', name: 'irnetfree', handle: 7 } }];
  let h = 10;
  for (const [mac, c] of Object.entries(counters || {})) {
    const hex = mac.replace(/:/g, '');
    items.push({ counter: { family: 'inet', name: 'cu_' + hex, table: 'irnetfree', handle: h++, packets: 3, bytes: c.up || 0 } });
    items.push({ counter: { family: 'inet', name: 'cd_' + hex, table: 'irnetfree', handle: h++, packets: 3, bytes: c.down || 0 } });
  }
  // a rule's own anonymous counter is nested in the rule — never one of ours
  items.push({ rule: { family: 'inet', table: 'irnetfree', chain: 'lu_fwd', handle: h++, expr: [{ counter: { packets: 9, bytes: 999999 } }, { drop: null }] } });
  return { nftables: items };
}

/**
 * The LAN as the router's commands see it. `lan.neigh` / `lan.leases` are
 * the text `ip neigh show dev br-lan` and /tmp/dhcp.leases hold, `lan.counters`
 * the table's counters now; change them between ticks. `lan.calls`: every
 * command line run.
 */
function fakeLan(init = {}) {
  const lan = Object.assign({ neigh: '', leases: '', counters: {}, address: '192.168.1.1', calls: [] }, init);
  lan.run = async (cmd, args) => {
    const line = [cmd, ...args].join(' ');
    lan.calls.push(line);
    if (line === 'ubus call network.interface.lan status') return JSON.stringify({ up: true, l3_device: 'br-lan', 'ipv4-address': lan.address ? [{ address: lan.address, mask: 24 }] : [] });
    if (line === 'ip neigh show dev br-lan') return lan.neigh;
    if (line === 'nft -j list table inet irnetfree') return JSON.stringify(nftJson(lan.counters));
    throw new Error('not faked: ' + line);
  };
  lan.readFile = async (p) => { if (norm(p) === '/tmp/dhcp.leases') return lan.leases; throw ENOENT(); };
  return lan;
}

/** The gateway as the controller uses it: up, its table loads recorded, each one counting from zero. */
function fakeGateway() {
  return { active: true, tableGen: 0, loads: [], async setLanUsers(desc) { this.loads.push(JSON.parse(JSON.stringify(desc))); this.tableGen++; } };
}

/** A users meter with the two calls the router makes: bytes per user in, `usage()` out — a cap in bytes per user. */
function fakeMeter(caps = {}) {
  const used = {};
  return {
    fed: [],
    feedDevices(byUser) { this.fed.push(JSON.parse(JSON.stringify(byUser))); for (const [id, v] of Object.entries(byUser)) used[id] = (used[id] || 0) + v.bytes; },
    usage() {
      const out = {};
      for (const [id, quotaBytes] of Object.entries(caps)) {
        const bytes = used[id] || 0;
        out[id] = { bytes, quotaBytes, over: quotaBytes > 0 && bytes >= quotaBytes, period: '2026-10', until: 0 };
      }
      return out;
    },
    newPeriod() { for (const k of Object.keys(used)) delete used[k]; }
  };
}

module.exports = { memFs, nftJson, fakeLan, fakeGateway, fakeMeter };
