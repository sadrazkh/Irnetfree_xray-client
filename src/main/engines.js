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
    label: 'Xray (default)',
    format: 'xray',
    exe: { win32: 'xray.exe', default: 'xray' },
    // CLI shape (argv builders) for this core.
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

/** Executable file name for an engine on the current platform. */
function engineExe(id) {
  const e = engine(id);
  return e.exe[process.platform] || e.exe.default;
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

module.exports = {
  ENGINES, DEFAULT_ENGINE,
  engine, engineExe, engineFormat, engineRunArgs, engineTestArgs, engineList
};
