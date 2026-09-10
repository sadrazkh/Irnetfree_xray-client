'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { isIP } = require('net');
const { spawn, execFileSync } = require('child_process');
const platform = require('./tunPlatform');

// The bridge accepts commands, never shell text, binary paths or core configs.
function runNative(executable, command, request = {}, { timeout = 95000, spawnImpl = spawn } = {}) {
  return new Promise((resolve, reject) => {
    let child, timer, finished = false, output = '', bytes = 0;
    const finish = (error, value) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      error ? reject(error) : resolve(value);
    };
    const abort = message => {
      try { child.kill('SIGKILL'); } catch {}
      finish(new Error(message));
    };
    try {
      child = spawnImpl(executable, [command], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
      timer = setTimeout(() => abort('Native macOS service request timed out; recovery may be required.'), timeout);
      child.on('error', () => finish(new Error('Could not launch the native macOS service bridge.')));
      child.stdout.on('data', data => {
        bytes += data.length;
        if (bytes > 65536) return abort('Native macOS service response exceeded its size limit.');
        output += data.toString('utf8');
      });
      // Drain stderr, but never propagate possibly sensitive native diagnostics.
      child.stderr.on('data', data => {
        bytes += data.length;
        if (bytes > 65536) abort('Native macOS service response exceeded its size limit.');
      });
      child.stdin.on('error', () => {});
      child.on('close', code => {
        try {
          const reply = JSON.parse(output);
          if (!reply || typeof reply !== 'object' || Array.isArray(reply) || typeof reply.ok !== 'boolean') throw new Error();
          if (code !== 0 && reply.ok) throw new Error();
          finish(null, reply);
        } catch { finish(new Error('Native macOS service returned an invalid response.')); }
      });
      child.stdin.end(JSON.stringify(request));
    } catch { finish(new Error('Could not launch the native macOS service bridge.')); }
  });
}

class NativeMacTun {
  constructor(opts = {}) {
    this.platform = opts.platform || os.platform();
    this.nativePath = opts.nativePath || path.resolve(process.resourcesPath || '', '..', 'MacOS', 'IRNetFreeNative');
    this.run = opts.run || ((command, request) => runNative(this.nativePath, command, request));
    this.exists = opts.exists || fs.existsSync;
    this.resolveServerIps = opts.resolveServerIps || platform.resolveServerIps;
    this.lookupInterface = opts.physicalInterface || (() => platform.physicalInterface(this.platform));
    this.execSync = opts.execSync || execFileSync;
    this.onLog = opts.onLog || (() => {});
    this.onUnexpectedExit = opts.onUnexpectedExit || (() => {});
    this.backendId = 'sing-box';
    this.native = true;
    this.managesDns = true;
    this.interfaceName = null;
    this.dnsPeer = '172.19.0.2';
    this.dnsPeer6 = 'fdfe:dcba:9876::2';
    this.active = false;
    this.excludeIps = [];
    this.macState = null;
    this.sessionId = null;
    this.pendingRecovery = false;
    this.queue = Promise.resolve();
    this.healthTimer = null;
    this.healthInFlight = false;
    this.stopping = false;
    this.exitNotified = false;
  }

  isAvailable() { return this.platform === 'darwin' && this.exists(this.nativePath); }
  isElevated() { return true; }
  physicalInterface() { return this.lookupInterface(); }
  hasPendingMacRecovery() { return this.pendingRecovery; }
  service(command) {
    if (!['status', 'register', 'unregister', 'settings'].includes(command)) return Promise.reject(new Error('Unsupported native service command.'));
    if (!this.isAvailable()) return Promise.reject(new Error('Native VPN requires macOS 13 or later and the packaged IRNetFree application.'));
    return this.run(command, {});
  }
  async prepare(opts = {}) {
    if (opts.strict) throw new Error('Native macOS VPN does not support strict leak protection. Select the compatibility backend to use strict mode.');
    if (!this.isAvailable()) throw new Error('Native VPN requires macOS 13 or later and the packaged IRNetFree application.');
    return this.ensureRegistered();
  }
  serialize(action) {
    const result = this.queue.then(action);
    this.queue = result.catch(() => {});
    return result;
  }
  async ensureRegistered() {
    // Registering installs a root LaunchDaemon: the user's decision, made once
    // in Settings, never a side effect of pressing Connect. So this only reads
    // the status — `nativeService('register')` is the single way in.
    const reply = await this.run('status', {});
    if (reply.status === 'notRegistered') {
      throw new Error('Enable the macOS tunnel service first: Settings → TUN → macOS tunnel service → Enable service.');
    }
    if (reply.status === 'requiresApproval') {
      throw new Error('Enable IRNetFree in System Settings → General → Login Items & Extensions (Allow in the Background), then reconnect.');
    }
    if (!reply.ok || reply.status !== 'enabled') {
      throw new Error('Native macOS service is unavailable. Install the signed IRNetFree application in Applications and try again.');
    }
    return reply;
  }
  start(socksPort, bypassAddrs, dnsServers, opts = {}) {
    return this.serialize(async () => {
      if (this.active) return;
      if (!this.isAvailable()) throw new Error('The native macOS service is missing from this application.');
      if (!Number.isInteger(socksPort) || socksPort < 1 || socksPort > 65535) throw new Error('Invalid SOCKS port.');
      if (!Array.isArray(dnsServers) || !dnsServers.length || dnsServers.some(ip => typeof ip !== 'string' || !isIP(ip))) throw new Error('Native macOS VPN requires DNS server IP addresses.');
      await this.prepare(opts);
      if (this.pendingRecovery) await this.stopInternal();
      const excludeIps = await this.resolveServerIps(bypassAddrs, { ipv6: true });
      this.pendingRecovery = true;
      this.exitNotified = false;
      const reply = await this.run('start', { socksPort, excludeIps, dnsServers, strict: false, ipv6: !!opts.ipv6 });
      if (!reply.ok || reply.active !== true || !/^utun\d+$/.test(reply.device || '') || typeof reply.sessionId !== 'string' || !reply.sessionId) {
        throw new Error('Native macOS tunnel did not become ready. Use network recovery before reconnecting.');
      }
      this.sessionId = reply.sessionId;
      this.active = true;
      this.interfaceName = reply.device;
      this.excludeIps = excludeIps;
      this.macState = { device: reply.device, native: true };
      this.healthTimer = setInterval(() => { void this.checkHealth(); }, 5000);
      this.healthTimer.unref?.();
      this.onLog('Native macOS tunnel connected.', 'info');
    });
  }
  async checkHealth() {
    if (!this.active || this.stopping || this.healthInFlight) return;
    this.healthInFlight = true;
    const sessionId = this.sessionId;
    try {
      const reply = await this.run('heartbeat', { sessionId });
      if (!reply.ok || reply.active !== true || reply.sessionId !== sessionId) throw new Error();
    } catch {
      if (this.active && !this.stopping && this.sessionId === sessionId && !this.exitNotified) {
        this.exitNotified = true;
        clearInterval(this.healthTimer);
        this.healthTimer = null;
        // Preserve state: a lost bridge response does not prove cleanup succeeded.
        Promise.resolve().then(() => this.onUnexpectedExit(new Error('Native macOS tunnel health check failed; disconnect and recover the network.'))).catch(() => {});
      }
    } finally { this.healthInFlight = false; }
  }
  stop() { return this.serialize(() => this.stopInternal()); }
  async stopInternal() {
    if (!this.active && !this.pendingRecovery) return;
    this.stopping = true;
    try {
      const reply = await this.run('stop', this.sessionId ? { sessionId: this.sessionId } : {});
      if (!reply.ok || reply.active !== false) throw new Error('Native macOS tunnel cleanup failed. Recovery information has been retained; retry disconnect.');
      clearInterval(this.healthTimer);
      this.healthTimer = null;
      this.active = false;
      this.pendingRecovery = false;
      this.sessionId = null;
      this.macState = null;
      this.interfaceName = null;
      this.excludeIps = [];
      this.onLog('Native macOS tunnel stopped.', 'info');
    } finally { this.stopping = false; }
  }
  recoverMacSessions() {
    return this.serialize(async () => {
      if (!this.isAvailable()) return;
      const reply = await this.run('status', {});
      if (reply.status !== 'enabled') return;
      if (!reply.ok) throw new Error('Native macOS service recovery status is unavailable.');
      if (reply.active || reply.recoveryPending || this.pendingRecovery) {
        this.pendingRecovery = true;
        await this.stopInternal();
      }
    });
  }
  cleanupSync() {
    clearInterval(this.healthTimer);
    this.healthTimer = null;
    if (!this.active && !this.pendingRecovery) return;
    try {
      this.execSync(this.nativePath, ['stop'], {
        input: JSON.stringify(this.sessionId ? { sessionId: this.sessionId } : {}),
        stdio: ['pipe', 'ignore', 'ignore'], timeout: 5000, windowsHide: true
      });
    } catch {} // The daemon's heartbeat lease also expires after app termination.
  }
}

module.exports = { NativeMacTun, runNative };
