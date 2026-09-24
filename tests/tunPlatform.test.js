'use strict';
/**
 * The helpers both TUN backends share. They were moved out of tunManager.js
 * unchanged; these tests pin what they parse from canned command output so a
 * refactor on either side cannot silently change a route or DNS decision.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

// The module destructures `execFile` at require time, so the stub has to be
// installed BEFORE it is loaded. `answer(cmd, args)` returns the canned stdout
// (or throws to fail the command); every call is recorded for argv assertions.
const cp = require('node:child_process');
const realExecFile = cp.execFile;
const calls = [];
let answer = null;
cp.execFile = (cmd, args, opts, cb) => {
  if (typeof opts === 'function') { cb = opts; opts = undefined; }
  if (!answer) return realExecFile(cmd, args, opts, cb);
  calls.push([cmd, args]);
  let out;
  try { out = answer(cmd, args); } catch (e) { return process.nextTick(() => cb(e, '', e.message)); }
  process.nextTick(() => cb(null, out, ''));
};

const P = require('../src/main/tunPlatform');

/** Route each command to a canned answer by a regex over `cmd + argv`. */
function canned(table) {
  calls.length = 0;
  answer = (cmd, args) => {
    const line = [cmd, ...args].join(' ');
    for (const [re, out] of table) if (re.test(line)) return typeof out === 'function' ? out() : out;
    throw new Error('unexpected command: ' + line);
  };
}
const joined = (i) => [calls[i][0], ...calls[i][1]].join(' ');

test('sh() single-quotes for bash, escaping embedded quotes', () => {
  assert.equal(P.sh('Wi-Fi'), "'Wi-Fi'");
  assert.equal(P.sh("it's"), "'it'\\''s'");
  assert.equal(P.sh(12), "'12'");
});

test('isOwnTunInterface knows both backends\' adapters', () => {
  assert.equal(P.isOwnTunInterface('XrayTun'), true, 'tun2socks / wintun');
  assert.equal(P.isOwnTunInterface('IRNetFree'), true, 'sing-box interface_name');
  assert.equal(P.isOwnTunInterface('utun7'), true);
  assert.equal(P.isOwnTunInterface('tun0'), true);
  assert.equal(P.isOwnTunInterface('Wi-Fi'), false);
  assert.equal(P.isOwnTunInterface('irnetfree'), false, 'exact name, like XrayTun');
  assert.equal(P.isOwnTunInterface(null), false);
});

test('resolveServerIps: literals pass, duplicates collapse, AAAA lookups only on request', async () => {
  // Unchanged from tunManager: v4 literals are kept as-is, and a v6 literal
  // comes back from dns.lookup untouched whatever `family` says (measured:
  // Node returns any IP literal with its own family), so it is kept too.
  assert.deepEqual(await P.resolveServerIps(['1.2.3.4', '1.2.3.4', '', null, '2001:db8::1']), ['1.2.3.4', '2001:db8::1']);
  assert.deepEqual(await P.resolveServerIps('5.6.7.8'), ['5.6.7.8'], 'a single string is accepted');
  assert.deepEqual(await P.resolveServerIps(['1.2.3.4', '2001:db8::1', '2001:db8::1'], { ipv6: true }),
    ['1.2.3.4', '2001:db8::1'], 'sing-box routes v6 too, so its bypass list wants the v6 literals explicitly');
  const local4 = await P.resolveServerIps(['localhost']);
  assert.ok(local4.includes('127.0.0.1'), 'hostnames resolve (A records)');
  assert.ok(!local4.includes('::1'), 'without the flag a hostname yields A records only');
  const localAll = await P.resolveServerIps(['localhost'], { ipv6: true });
  assert.ok(localAll.includes('127.0.0.1'), 'with the flag the A records are still there');
});

/** One row of the default-route query, as getDefaultGatewayWin's PowerShell prints it. */
const row = (nextHop, ifIndex, alias, routeMetric, ifMetric, state = 'Connected') => ({ nextHop, ifIndex, alias, routeMetric, ifMetric, state });

test('pickDefaultRouteWin: the default route Windows itself routes by', () => {
  const pick = P.pickDefaultRouteWin;
  // lowest route metric + interface metric — RouteMetric alone ties at 0 for every DHCP gateway
  assert.deepEqual(pick([row('192.168.10.1', 23, 'Wi-Fi', 0, 55), row('192.168.1.1', 5, 'Ethernet', 0, 25)]),
    { nextHop: '192.168.1.1', ifIndex: '5' });
  assert.deepEqual(pick([row('192.168.10.1', 23, 'Wi-Fi', 0, 35), row('192.168.1.1', 5, 'Ethernet', 50, 25)]),
    { nextHop: '192.168.10.1', ifIndex: '23' }, 'the sum decides, not either half');
  // a gateway left in the table on an interface that is not connected is not a way out
  assert.deepEqual(pick([row('192.168.1.1', 5, 'Ethernet', 0, 25, 'Disconnected'), row('192.168.10.1', 23, 'Wi-Fi', 0, 55)]),
    { nextHop: '192.168.10.1', ifIndex: '23' });
  assert.deepEqual(pick([row('192.168.1.1', 5, 'Ethernet', 0, 25, 'Disconnected')]), { nextHop: '', ifIndex: '' },
    'nothing connected: nothing, rather than a dead NIC');
  // our own adapters, and on-link defaults (no next hop to pin a /32 to), are never the answer
  assert.deepEqual(pick([row('10.255.0.1', 44, 'XrayTun', 0, 1), row('172.19.0.2', 45, 'IRNetFree', 0, 0),
    row('0.0.0.0', 9, 'PPP', 0, 1), row('192.168.10.1', 23, 'Wi-Fi', 0, 55)]), { nextHop: '192.168.10.1', ifIndex: '23' });
  // equal cost: the lower interface metric, then the lower index — never the listing order
  assert.deepEqual(pick([row('10.0.0.1', 12, 'B', 10, 20), row('10.0.1.1', 7, 'A', 20, 10)]), { nextHop: '10.0.1.1', ifIndex: '7' });
  assert.deepEqual(pick([row('10.0.0.1', 12, 'B', 0, 10), row('10.0.1.1', 7, 'A', 0, 10)]), { nextHop: '10.0.1.1', ifIndex: '7' });
  // no interface facts at all (Get-NetIPInterface failed): every row still counts, by route metric
  assert.deepEqual(pick([
    { nextHop: '192.168.10.1', ifIndex: 23, alias: 'Wi-Fi', routeMetric: 5, ifMetric: null, state: '' },
    { nextHop: '192.168.1.1', ifIndex: 5, alias: 'Ethernet', routeMetric: 0, ifMetric: null, state: '' }
  ]), { nextHop: '192.168.1.1', ifIndex: '5' });
  // the state as the enum's value rather than its name still reads
  assert.deepEqual(pick([row('192.168.1.1', 5, 'Ethernet', 0, 25, '0'), row('192.168.10.1', 23, 'Wi-Fi', 0, 55, '1')]),
    { nextHop: '192.168.10.1', ifIndex: '23' });
  // PowerShell 5.1 unwraps a one-element array into the object; junk is no route
  assert.deepEqual(pick(row('192.168.8.1', 12, 'Wi-Fi', 0, 35)), { nextHop: '192.168.8.1', ifIndex: '12' });
  for (const junk of [null, undefined, [], 'text', [null, 7, { nextHop: 'fe80::1', ifIndex: 3 }], [{ nextHop: '1.2.3.4' }]]) {
    assert.deepEqual(pick(junk), { nextHop: '', ifIndex: '' }, JSON.stringify(junk));
  }
});

test('getDefaultGatewayWin: one PowerShell for the active default routes and their interfaces, then the pick', async () => {
  canned([[/Get-NetRoute -DestinationPrefix '0\.0\.0\.0\/0'/, JSON.stringify([
    row('192.168.1.1', 5, 'Ethernet', 0, 25, 'Disconnected'), row('192.168.8.1', 12, 'Wi-Fi', 0, 35)]) + '\r\n']]);
  assert.deepEqual(await P.getDefaultGatewayWin(), { nextHop: '192.168.8.1', ifIndex: '12' });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], 'powershell');
  assert.deepEqual(calls[0][1].slice(0, 3), ['-NoProfile', '-NonInteractive', '-Command']);
  const script = calls[0][1].at(-1);   // psArgs puts the UTF-8 line before the script
  assert.match(script, /-PolicyStore ActiveStore/, 'a static gateway of an unplugged NIC lives on in the persistent store');
  assert.match(script, /Get-NetIPInterface -AddressFamily IPv4/);
  assert.match(script, /ConnectionState/);
  assert.match(script, /InterfaceMetric/);
  canned([[/Get-NetRoute/, '[]\r\n']]);
  assert.deepEqual(await P.getDefaultGatewayWin(), { nextHop: '', ifIndex: '' }, 'no route: empty, not undefined');
  canned([[/Get-NetRoute/, 'Get-NetRoute : something went wrong\r\n']]);
  assert.deepEqual(await P.getDefaultGatewayWin(), { nextHop: '', ifIndex: '' }, 'not JSON: no route, no throw');
});

// The one test that runs the real query — on the GitHub Windows runner ONLY,
// never on a developer's or the owner's machine (fakes only there). Nobody can
// run this PowerShell by hand in the repo's sandbox, and a syntax slip in it
// would take the gateway, and TUN mode with it, from every Windows user. It
// only reads: Get-NetIPInterface and Get-NetRoute. It runs in a child Node of
// its own: this process carries the suite's no-network guard, which refuses
// every PowerShell — this read-only one included, on the runner too.
test('the default-route query on a real Windows (CI runner only): it runs, and its rows are what the pick expects',
  { skip: !(process.platform === 'win32' && process.env.GITHUB_ACTIONS === 'true') }, async () => {
    const script = `
      const P = require(${JSON.stringify(require.resolve('../src/main/tunPlatform'))});
      (async () => {
        const out = await P.run('powershell', P.psArgs(P.DEFAULT_ROUTES_PS));   // exactly the production argv
        const gw = await P.getDefaultGatewayWin();
        console.log('RESULT ' + JSON.stringify({ out, gw }));
      })().catch((e) => { console.error((e && e.stack) || e); process.exit(2); });
    `;
    const r = require('node:child_process').spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', timeout: 60000, windowsHide: true });
    const line = (r.stdout.match(/^RESULT (.*)$/m) || [])[1];
    assert.ok(line, r.stdout + r.stderr);
    const { out, gw } = JSON.parse(line);
    const rows = [].concat(JSON.parse(out.trim()));
    assert.ok(rows.length >= 1, 'the runner has a default route: ' + out);
    const live = rows.filter(r => r.state === 'Connected');
    assert.ok(live.length >= 1, 'ConnectionState arrives as its name: ' + out);
    for (const r of live) {
      assert.equal(typeof r.ifIndex, 'number');
      assert.equal(typeof r.routeMetric, 'number');
      assert.equal(typeof r.ifMetric, 'number');
      assert.equal(typeof r.alias, 'string');
    }
    assert.match(gw.nextHop, /^\d+\.\d+\.\d+\.\d+$/, out);
    assert.match(gw.ifIndex, /^\d+$/);
  });

test('getTunIfIndex asks for the adapter it is given', async () => {
  canned([[/Get-NetAdapter -Name 'IRNetFree'/, '23\r\n']]);
  assert.equal(await P.getTunIfIndex('IRNetFree'), '23');
  canned([[/Get-NetAdapter -Name 'XrayTun'/, '\r\n']]);
  assert.equal(await P.getTunIfIndex('XrayTun'), null);
});

test('waitForAdapter polls Get-NetAdapter Status until Up', async () => {
  canned([[/Get-NetAdapter -Name 'IRNetFree'.*Status/, 'Up\r\n']]);
  assert.equal(await P.waitForAdapter('IRNetFree', 2000), true);
  assert.equal(calls.length, 1);
  canned([[/Get-NetAdapter -Name 'IRNetFree'.*Status/, 'Disconnected\r\n']]);
  assert.equal(await P.waitForAdapter('IRNetFree', 300), false, 'never Up → false after the deadline');
});

const ROUTE_GET_DEFAULT = [
  '   route to: default',
  'destination: default',
  '       mask: default',
  '    gateway: 192.168.1.1',
  '  interface: en0',
  '      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>',
  ''
].join('\n');
const SERVICE_ORDER = [
  'An asterisk (*) denotes that a network service is disabled.',
  '(1) Wi-Fi',
  '(Hardware Port: Wi-Fi, Device: en0)',
  '',
  '(2) Thunderbolt Bridge',
  '(Hardware Port: Thunderbolt Bridge, Device: bridge0)',
  ''
].join('\n');

test('getDefaultRouteMac parses `route -n get default`', async () => {
  canned([[/^route -n get default$/, ROUTE_GET_DEFAULT]]);
  assert.deepEqual(await P.getDefaultRouteMac(), { gateway: '192.168.1.1', device: 'en0' });
  canned([[/^route/, () => { throw new Error('route: writing to routing socket: not in table'); }]]);
  assert.deepEqual(await P.getDefaultRouteMac(), { gateway: '', device: '' }, 'no default route: empty fields');
});

test('serviceForDeviceMac maps a BSD device to its networksetup service', async () => {
  canned([[/networksetup -listnetworkserviceorder/, SERVICE_ORDER]]);
  assert.equal(await P.serviceForDeviceMac('en0'), 'Wi-Fi');
  assert.equal(await P.serviceForDeviceMac('bridge0'), 'Thunderbolt Bridge');
  assert.equal(await P.serviceForDeviceMac('en9'), null);
  assert.equal(await P.serviceForDeviceMac(''), null, 'no device: no lookup');
});

test('getServiceDnsMac: "aren\'t any" means DHCP, otherwise the list (v4 and v6)', async () => {
  canned([[/networksetup -getdnsservers Wi-Fi/, "There aren't any DNS Servers set on Wi-Fi.\n"]]);
  assert.deepEqual(await P.getServiceDnsMac('Wi-Fi'), []);
  canned([[/networksetup -getdnsservers Wi-Fi/, '1.1.1.1\n2606:4700::1111\n']]);
  assert.deepEqual(await P.getServiceDnsMac('Wi-Fi'), ['1.1.1.1', '2606:4700::1111']);
  assert.deepEqual(await P.getServiceDnsMac(null), []);
});

test('runScriptPrivileged (not root) goes through one osascript admin prompt, path escaped', async () => {
  canned([[/^osascript -e/, '']]);
  await P.runScriptPrivileged('/Users/a b/Library/Application Support/IRNetFree/tun/setup.sh');
  assert.equal(calls[0][0], 'osascript');
  assert.deepEqual(calls[0][1], ['-e',
    'do shell script "/bin/bash \\"/Users/a b/Library/Application Support/IRNetFree/tun/setup.sh\\"" with administrator privileges']);
});

test('physicalInterface (win32): default route → adapter friendly name, ifIndex, gateway', async () => {
  canned([
    [/Get-NetRoute -DestinationPrefix/, JSON.stringify([row('192.168.8.1', 12, 'Wi-Fi', 0, 35)]) + '\r\n'],
    [/Get-NetAdapter -InterfaceIndex 12/, 'Wi-Fi\r\n']
  ]);
  assert.deepEqual(await P.physicalInterface('win32'), { name: 'Wi-Fi', ifIndex: '12', gateway: '192.168.8.1' });
  assert.match(joined(1), /\(Get-NetAdapter -InterfaceIndex 12 -ErrorAction SilentlyContinue\)\.Name/);
  canned([[/Get-NetRoute -DestinationPrefix/, '[]\r\n']]);
  assert.deepEqual(await P.physicalInterface('win32'), { name: null, ifIndex: null, gateway: null }, 'nothing found: nulls, no throw');
  canned([[/Get-NetRoute/, () => { throw new Error('powershell is not recognized'); }]]);
  assert.deepEqual(await P.physicalInterface('win32'), { name: null, ifIndex: null, gateway: null }, 'a failing command: nulls, no throw');
});

test('physicalInterface (darwin): `route -n get default` device + gateway', async () => {
  canned([[/^route -n get default$/, ROUTE_GET_DEFAULT]]);
  assert.deepEqual(await P.physicalInterface('darwin'), { name: 'en0', ifIndex: null, gateway: '192.168.1.1' });
  canned([[/^route/, '']]);
  assert.deepEqual(await P.physicalInterface('darwin'), { name: null, ifIndex: null, gateway: null });
});

test('physicalInterface (linux): `ip route show default`', async () => {
  canned([[/^ip route show default$/, 'default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.5 metric 100\n']]);
  assert.deepEqual(await P.physicalInterface('linux'), { name: 'eth0', ifIndex: null, gateway: '10.0.0.1' });
  canned([[/^ip route show default$/, '']]);
  assert.deepEqual(await P.physicalInterface('linux'), { name: null, ifIndex: null, gateway: null });
});

test('isElevated: darwin can always prompt; linux needs root', () => {
  assert.equal(P.isElevated('darwin'), true);
  const root = !!(process.getuid && process.getuid() === 0);
  assert.equal(P.isElevated('linux'), root);
});
