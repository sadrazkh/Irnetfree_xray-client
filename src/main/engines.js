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
    exe: { win32: 'xray.exe', default: 'xray' }
  },
  'xray-spoof': {
    id: 'xray-spoof',
    label: 'Spoof core (fake ClientHello / SNI)',
    format: 'xray',                                   // Xray-config-compatible
    exe: { win32: 'xray-spoof.exe', default: 'xray-spoof' }
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

/** [{ id, label }] for populating the UI selector. */
function engineList() {
  return Object.values(ENGINES).map(e => ({ id: e.id, label: e.label }));
}

module.exports = { ENGINES, DEFAULT_ENGINE, engine, engineExe, engineList };
