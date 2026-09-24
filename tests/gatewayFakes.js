'use strict';
/**
 * Fakes for running the headless service's connect path on a "router" in a
 * test: a core manager that spawns nothing, and the REAL gateway backend
 * (TunOpenwrt) over a fake sing-box and a fake command runner. Nothing binds
 * a port, starts a process or touches the machine's network, on any OS.
 *
 * Not a test file itself (no `.test.js`): required by serviceGateway.test.js
 * and by the child process that test starts for the exit hook.
 */
const { TunOpenwrt } = require('../src/main/tunOpenwrt');

const RULES_OK = '0:\tfrom all lookup local\n8998:\tnot from all dport 53 lookup main suppress_prefixlength 0\n9002:\tnot from all iif lo lookup 2022\n32766:\tfrom all lookup main\n';

/**
 * `state` is shared with the test: flip `gatewayFails`, `singboxMissing`,
 * `xrayFails` to make the next attempt fail; read `events`, `xray`, `gateways`.
 */
function makeState() {
  return { events: [], gateways: [], inners: [], gatewayFails: false, singboxMissing: false, xrayFails: false, xray: null };
}

function fakeInner(state) {
  const inner = {
    starts: 0,
    active: false,
    proc: null,
    exited: Promise.resolve(),
    excludeIps: [],
    interfaceName: 'IRNetFree',
    dnsPeer: '172.19.0.2',
    dnsPeer6: 'fdfe:dcba:9876::2',
    lang: 'fa',
    isAvailable: () => !state.singboxMissing,
    isElevated: () => true,
    prepare: async () => {},
    physicalInterface: async () => ({ name: 'eth0', ifIndex: null, gateway: '192.168.1.2' }),
    async start() {
      inner.starts++;
      state.events.push('gateway:start');
      if (state.gatewayFails) throw new Error('sing-box exited immediately');
      inner.exited = new Promise((resolve) => { inner.gone = resolve; });
      inner.proc = { kill: () => {} };
      inner.active = true;
      inner.excludeIps = ['192.0.2.10/32'];
    },
    /** sing-box dying on its own */
    crash() { inner.active = false; inner.proc = null; inner.gone({ code: null, signal: 'SIGKILL' }); },
    async stop() {
      const was = inner.active;
      inner.active = false; inner.proc = null; inner.excludeIps = [];
      if (was && inner.gone) inner.gone({ code: 0, signal: 'SIGTERM' });
    },
    cleanupSync() { inner.active = false; }
  };
  state.inners.push(inner);
  return inner;
}

/** deps.gateway: the real TunOpenwrt over the fakes. */
function gatewayFactory(state) {
  return (opts) => {
    const inner = fakeInner(state);
    const run = async (cmd, args) => {
      const line = [cmd, ...args].join(' ');
      if (/^nft delete table/.test(line)) state.events.push('gateway:clear-table');
      if (/^ip link show IRNetFree/.test(line)) { if (!inner.active) throw new Error('Device "IRNetFree" does not exist.'); return ''; }
      if (/^ip rule show/.test(line)) return RULES_OK;
      if (/^ip -[46] rule del/.test(line)) throw new Error('RTNETLINK answers: No such file or directory');
      return '';
    };
    const runSync = (cmd, args) => {
      const line = [cmd, ...args].join(' ');
      if (/^ip link show IRNetFree/.test(line) && !inner.active) throw new Error('no device');
      if (/ rule del /.test(line)) throw new Error('no rule');
    };
    const gw = new TunOpenwrt(Object.assign({}, opts, {
      inner, run, runSync,
      writeFile: () => {},
      lanStatus: async () => ({ device: 'br-lan', address: '192.168.1.1', mask: 24 }),
      which: () => true,
      verifyWaitMs: 200,
      linkWaitMs: 50
    }));
    state.gateways.push(gw);
    return gw;
  };
}

/** deps.xray: an XrayManager that runs nothing. `crash()` is the core dying on its own. */
function xrayFactory(state) {
  return (o) => {
    const x = {
      running: false,
      proc: null,
      binPath: null,
      starts: [],
      stops: 0,
      validated: [],
      resolveEngine: (id) => ({ id: id === 'sing-box' || id === 'xray-pattn' ? id : 'xray', bin: '/fake/' + (id || 'xray') }),
      resolveBin: (id) => '/fake/' + (id || 'xray'),
      binExists: () => true,
      anyBin: () => '/fake/xray',
      version: async () => '26.1.1',
      forgetVersions() {},
      validate: async () => ({ ok: true }),
      async validateWithFallback(config, engine) { x.validated.push({ config, engine }); return { ok: true, engine }; },
      async start(config, engine) {
        if (x.running) await x.stop();
        x.starts.push({ config, engine });
        state.events.push('xray:start');
        if (state.xrayFails) throw new Error('xray exited on startup (code 23)');
        x.running = true;
        x.proc = { pid: 4242, kill: (sig) => { state.events.push('xray:kill ' + (sig || 'SIGTERM')); } };
        o.onStatus('running', { pid: 4242 });
        return true;
      },
      async stop() {
        x.stops++;
        if (!x.running) return;
        x.running = false; x.proc = null;
        state.events.push('xray:stop');
        o.onStatus('stopped', { code: 0, signal: 'SIGTERM' });
      },
      crash() { x.running = false; x.proc = null; o.onStatus('stopped', { code: null, signal: 'SIGKILL' }); },
      startTest: async () => { throw new Error('no test cores here'); }
    };
    state.xray = x;
    return x;
  };
}

/** Every seam the service has, faked; `timing` short enough for a test. */
function deps(state, extra = {}) {
  return Object.assign({
    xray: xrayFactory(state),
    gateway: gatewayFactory(state),
    setSystemProxy: async () => {},
    waitForLocalPort: async () => true,
    orphans: () => [],
    kill: () => { throw Object.assign(new Error('ESRCH'), { code: 'ESRCH' }); },
    syslog: () => {},
    timing: { bootDelayMs: 5, bootEveryMs: 20, bootSlowAfter: 1000, bootSlowMs: 20, routerBackoffMs: [5, 5, 10] }
  }, extra);
}

module.exports = { makeState, deps, RULES_OK };
