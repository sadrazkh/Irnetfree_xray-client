'use strict';
/**
 * v1.16.2 — the router's open files. The owner's AC-1304 (OpenWrt 23.05.4,
 * v1.16.1): 49-90 s after "TUN mode active", hundreds of sing-box lines
 * "socket: too many open files", and no device behind the router could
 * browse. sing-box and Xray had the kernel's 4096 descriptors (procd sets
 * none; irnetfree.init now gives 65536) and nothing in the service said so.
 *
 * At every connect the service now reads each process's descriptors in use
 * (/proc/<pid>/fd) against its "Max open files" (/proc/<pid>/limits) and says
 * it — at warn, into syslog, when a core got less than the init sets; the
 * diagnostics bundle carries the same; and a "too many open files" from
 * sing-box or the core becomes one error line with the numbers (at most one a
 * minute). The real service over the gateway fakes: /proc is handed in.
 */
process.env.IRNETFREE_PLATFORM = 'openwrt';
const test = require('node:test');
const assert = require('node:assert/strict');
const H = require('./serviceHarness');

process.setMaxListeners(60);
test.after(() => H.cleanupDirs());

const { SERVER } = H;
const lines = (s) => s.logs.map((l) => `[${l.level}] ${l.line}`);

/** /proc as a router shows it: node, the core (4242) and sing-box (5151, gatewayFakes) — `soft`/`hard` per pid, `open` descriptors. */
function fakeProc({ limits = {}, open = {} } = {}) {
  const pids = { [process.pid]: 'node', 4242: 'xray', 5151: 'sing-box' };
  const lim = (name) => limits[name] || [65536, 65536];
  return {
    readProc: (p) => {
      const m = /^\/proc\/(\d+)\/limits$/.exec(p);
      if (m && pids[m[1]]) {
        const [soft, hard] = lim(pids[m[1]]);
        return 'Limit                     Soft Limit           Hard Limit           Units     \n' +
          'Max cpu time              unlimited            unlimited            seconds   \n' +
          `Max open files            ${soft}                ${hard}                files     \n` +
          'Max locked memory         8388608              8388608              bytes     \n';
      }
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    },
    listProc: (p) => {
      const m = /^\/proc\/(\d+)\/fd$/.exec(p);
      if (m && pids[m[1]]) return Array.from({ length: open[pids[m[1]]] || 7 }, (_, i) => String(i));
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    }
  };
}

test('at connect the router says each process\'s open files against its limit — info when the init\'s 65536 is there', async (t) => {
  const s = H.start({}, fakeProc({ open: { node: 12, xray: 40, 'sing-box': 31 } }));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const said = s.logs.filter(l => /^Open files/.test(l.line));
  assert.deepEqual(said.map(l => [l.level, l.line]), [['info', 'Open files at connect: node 12 of 65536, xray 40 of 65536, sing-box 31 of 65536']], lines(s).join('\n'));
  assert.ok(!s.syslog.some(([, l]) => /Open files/.test(l)), 'a healthy budget stays out of syslog (info)');
});

test('a core with less than the init sets is said at warn — into syslog — with what to do', async (t) => {
  const s = H.start({}, fakeProc({ limits: { xray: [4096, 4096], 'sing-box': [4096, 4096] }, open: { node: 12, xray: 40, 'sing-box': 31 } }));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const warn = s.logs.filter(l => l.level === 'warn' && /^Open files/.test(l.line));
  assert.equal(warn.length, 1, lines(s).join('\n'));
  assert.equal(warn[0].line, 'Open files: xray and sing-box may hold only 4096 (their "Max open files") — a busy LAN runs that out ("too many open files": no device behind the router can browse). The service\'s init gives every process 65536: restart it (/etc/init.d/irnetfree restart), or reinstall the package if this stays. Now: node 12 of 65536, xray 40 of 4096, sing-box 31 of 4096');
  assert.ok(s.syslog.some(([, l]) => /\[warn\] Open files: xray and sing-box may hold only 4096/.test(l)), 'the warn reaches syslog');
});

test('the diagnostics bundle carries the open files of node, xray and sing-box', async (t) => {
  const s = H.start({}, fakeProc({ open: { node: 12, xray: 40, 'sing-box': 31 } }));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const { text } = await s.service.diagnostics();
  assert.match(text, /^open files \(in use\/Max open files\): node=12\/65536 xray=40\/65536 sing-box=31\/65536$/m, text);
});

test('"too many open files" from sing-box or the core becomes one error line with the numbers — at most one a minute', async (t) => {
  const s = H.start({}, fakeProc({ limits: { 'sing-box': [4096, 4096] }, open: { node: 12, xray: 900, 'sing-box': 4090 } }));
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  const gw = s.state.gateways[s.state.gateways.length - 1];
  for (let i = 0; i < 5; i++) gw.onLog(`[tun] ERROR [${1000 + i} 3ms] connection: open outbound connection: dial tcp 127.0.0.1:47808: socket: too many open files`, 'warn');
  s.state.xray.log('2026/10/03 12:00:00 [Error] transport/internet/udp: failed to listen UDP: listen udp 127.0.0.1:0: socket: too many open files', 'error');
  const out = s.logs.filter(l => /^Out of open files/.test(l.line));
  assert.deepEqual(out.map(l => [l.level, l.line]), [['error', 'Out of open files ("too many open files"): node=12/65536 xray=900/65536 sing-box=4090/4096 — new connections from the LAN fail until some close']], lines(s).join('\n'));
  assert.ok(s.syslog.some(([, l]) => /\[error\] Out of open files/.test(l)), 'into syslog');
});

test('without /proc (not Linux, a container) nothing is said and nothing breaks', async (t) => {
  const none = () => { throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); };
  const s = H.start({}, { readProc: none, listProc: none });
  t.after(() => s.service.shutdown());
  await s.service.invoke('connect', SERVER.id);
  assert.equal(H.connectedCount(s), 1);
  assert.ok(!s.logs.some(l => /Open files|Out of open files/.test(l.line)), lines(s).join('\n'));
  const { text } = await s.service.diagnostics();
  assert.doesNotMatch(text, /^open files/m);
});
