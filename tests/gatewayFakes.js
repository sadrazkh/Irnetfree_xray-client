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
const { createKillSwitch } = require('../src/main/killSwitchOpenwrt');

const RULES_OK = '0:\tfrom all lookup local\n8998:\tnot from all dport 53 lookup main suppress_prefixlength 0\n9002:\tnot from all iif lo lookup 2022\n32766:\tfrom all lookup main\n';

/**
 * `state` is shared with the test: flip `gatewayFails`, `singboxMissing`,
 * `xrayFails` to make the next attempt fail, set `gatewayGate` (a promise) to
 * hold the next gateway start until it resolves; read `events`, `xray`, `gateways`.
 */
function makeState() {
  // `commands`: every `ip` / `nft` line the gateway ran, in order
  return { events: [], commands: [], gateways: [], inners: [], gatewayFails: false, singboxMissing: false, xrayFails: false, xray: null };
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
    bypass: null,   // the addresses the last start was told to keep off the tunnel
    async start(socksPort, bypassAddrs) {
      inner.starts++;
      inner.bypass = (bypassAddrs || []).slice();
      state.events.push('gateway:start');
      if (state.gatewayGate) await state.gatewayGate;   // a gateway slow to come up: the test opens it
      if (state.gatewayFails) throw new Error('sing-box exited immediately');
      inner.exited = new Promise((resolve) => { inner.gone = resolve; });
      inner.proc = { pid: 5151, kill: () => {} };   // a pid: the service reads its RSS from /proc (memInfo)
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
      state.commands.push(line);
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
      linkWaitMs: 50,
      // the service as root, dnsmasq as its own user (OpenWrt's) — `state.procUids` overrides; never this machine's /proc
      uid: 0,
      uidsOf: (name) => ((state.procUids && state.procUids[name]) || (name === 'dnsmasq' ? [453] : []))
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
      resolveBin: (id) => (state.missingBins && state.missingBins.includes(id || 'xray') ? null : '/fake/' + (id || 'xray')),
      binExists: () => true,
      anyBin: () => '/fake/xray',
      // `state.coreVersions`: { xray: '24.12.31' } — what `xray version` answers per engine (a current core by default)
      versionsAsked: [],
      version: async (id = 'xray') => { x.versionsAsked.push(id); return ((state.coreVersions || {})[id]) || (id === 'xray-pattn' ? '26.9.1' : '26.3.27'); },
      forgetVersions() {},
      validate: async () => ({ ok: true }),
      // `state.check`: what the next validation answers instead of a pass (a refusal, a fallback)
      async validateWithFallback(config, engine) { x.validated.push({ config, engine }); return state.check ? Object.assign({ engine }, state.check) : { ok: true, engine }; },
      recent: [],
      /** The running core's last output lines (XrayManager.recentLines). */
      recentLines: (n = 5) => x.recent.slice(-n),
      async start(config, engine) {
        if (x.running) await x.stop();
        x.starts.push({ config, engine });
        x.recent = [];
        state.events.push('xray:start');
        if (state.xrayFails) throw new Error('xray exited on startup (code 23)');
        x.running = true;
        x.proc = { pid: 4242, kill: (sig) => { state.events.push('xray:kill ' + (sig || 'SIGTERM')); } };
        o.onStatus('running', { pid: 4242 });
        return true;
      },
      async stop() {
        x.stops++;
        if (state.stopDelayMs) await new Promise((r) => setTimeout(r, state.stopDelayMs));   // a core slow to exit
        if (!x.running) return;
        x.running = false; x.proc = null;
        state.events.push('xray:stop');
        o.onStatus('stopped', { code: 0, signal: 'SIGTERM' });
      },
      /** The core dying on its own; `lines`: what it printed last. */
      crash(lines) { if (Array.isArray(lines)) x.recent = lines.slice(); x.running = false; x.proc = null; o.onStatus('stopped', { code: null, signal: 'SIGKILL' }); },
      startTest: async () => { throw new Error('no test cores here'); }
    };
    state.xray = x;
    return x;
  };
}

/** deps.killSwitch: the real module over a run that records into `state.commands` and an in-memory fs — never the machine's nft. */
function killSwitchFactory(state) {
  return ({ dataDir }) => {
    const files = new Map();
    const fs = {
      writeFileSync: (p, text) => { files.set(p, String(text)); },
      readFileSync: (p) => { if (!files.has(p)) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); return files.get(p); },
      unlinkSync: (p) => { if (!files.delete(p)) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); },
      existsSync: (p) => files.has(p),
      mkdirSync: () => {}
    };
    const run = async (cmd, args) => { state.commands.push([cmd, ...args].join(' ')); return ''; };
    return createKillSwitch({ run, dataDir, fs, tmpDir: '/tmp' });
  };
}

/** Every seam the service has, faked; `timing` short enough for a test. */
function deps(state, extra = {}) {
  return Object.assign({
    xray: xrayFactory(state),
    gateway: gatewayFactory(state),
    killSwitch: killSwitchFactory(state),
    setSystemProxy: async () => {},
    waitForLocalPort: async () => true,
    // the device list's ubus / ip neigh: no LAN here (a test that wants one passes its own)
    lanRun: async (cmd, args) => { throw new Error(`no ${cmd} here: ${[cmd, ...args].join(' ')}`); },
    orphans: () => [],
    kill: () => { throw Object.assign(new Error('ESRCH'), { code: 'ESRCH' }); },
    syslog: () => {},
    timing: { bootDelayMs: 5, bootEveryMs: 20, bootSlowAfter: 1000, bootSlowMs: 20, routerBackoffMs: [5, 5, 10], crashWindowMs: 0 }
  }, extra);
}

module.exports = { makeState, deps, RULES_OK };
