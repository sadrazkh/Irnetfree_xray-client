'use strict';
/**
 * Selectable proxy cores ("engines"). Each server config can run on its OWN
 * engine (chosen per-config in the edit screen) — switching one config to an
 * alternate core does NOT affect any other config or the app globally.
 *
 * Engines whose `format` is 'xray' reuse the EXACT Xray JSON config, so a
 * config-compatible patched core (e.g. one that injects a fake ClientHello /
 * spoofed SNI) only needs its own binary dropped into `bin/` — no separate
 * config builder. Engines with a different config format would register their
 * own builder here later (that's why this is a registry, not a boolean).
 *
 * To add a core: drop its binary in `bin/` and add an entry below.
 */
const ENGINES = {
  xray: {
    id: 'xray',
    label: 'Xray (official)',
    format: 'xray',
    repo: 'XTLS/Xray-core',                            // GitHub releases the binary comes from
    exe: { win32: 'xray.exe', default: 'xray' },
    // CLI shape (argv builders) for this core.
    runArgs: (cfg) => ['run', '-c', cfg],
    testArgs: (cfg) => ['run', '-test', '-c', cfg]
  },
  // patterniha's fork: upstream + one change — it does not refuse plaintext
  // VLESS/Trojan to public addresses (upstream's validateOutboundTransportSecurity).
  // Same config format, same argv, same release asset names; only the exe name
  // differs so both can live in bin/ side by side.
  'xray-pattn': {
    id: 'xray-pattn',
    label: 'Xray-PattN (patterniha)',
    format: 'xray',
    repo: 'patterniha/Xray-core',
    exe: { win32: 'xray-pattn.exe', default: 'xray-pattn' },
    runArgs: (cfg) => ['run', '-c', cfg],
    testArgs: (cfg) => ['run', '-test', '-c', cfg]
  },
  'sing-box': {
    id: 'sing-box',
    label: 'sing-box (fake ClientHello / uTLS / fragment)',
    format: 'sing-box',                               // needs the sing-box translator
    exe: { win32: 'sing-box.exe', default: 'sing-box' },
    runArgs: (cfg) => ['run', '-c', cfg],
    testArgs: (cfg) => ['check', '-c', cfg]
  }
};

const DEFAULT_ENGINE = 'xray';

function engine(id) {
  return ENGINES[id] || ENGINES[DEFAULT_ENGINE];
}

/** Executable file name for an engine on the given (default: current) platform. */
function engineExe(id, platform = process.platform) {
  const e = engine(id);
  return e.exe[platform] || e.exe.default;
}

/** Config format an engine consumes ('xray' | 'sing-box'). */
function engineFormat(id) {
  return engine(id).format;
}

/** argv for running / validating a config file with an engine. */
function engineRunArgs(id, cfgPath) {
  return engine(id).runArgs(cfgPath);
}
function engineTestArgs(id, cfgPath) {
  return engine(id).testArgs(cfgPath);
}

/** [{ id, label }] for populating the UI selector. */
function engineList() {
  return Object.values(ENGINES).map(e => ({ id: e.id, label: e.label }));
}

/** Ids of the engines that consume the Xray JSON format, default first. */
function xrayEngines() {
  return Object.values(ENGINES).filter(e => e.format === 'xray').map(e => e.id);
}

/** Human label for status lines and logs. */
function engineLabel(id) {
  return engine(id).label;
}

module.exports = {
  ENGINES, DEFAULT_ENGINE,
  engine, engineExe, engineFormat, engineRunArgs, engineTestArgs, engineList, xrayEngines, engineLabel
};
