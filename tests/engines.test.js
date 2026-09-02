'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { ENGINES, DEFAULT_ENGINE, engine, engineExe, engineFormat, engineRunArgs, engineTestArgs, engineList, xrayEngines, engineLabel } = require('../src/main/engines');

test('the patterniha fork is an Xray-format engine with its own exe and repo', () => {
  const p = ENGINES['xray-pattn'];
  assert.equal(p.format, 'xray');
  assert.equal(p.repo, 'patterniha/Xray-core');
  assert.equal(engineExe('xray-pattn', 'win32'), 'xray-pattn.exe');
  assert.equal(engineExe('xray-pattn', 'darwin'), 'xray-pattn');
  assert.equal(ENGINES.xray.repo, 'XTLS/Xray-core');
});

test('both Xray engines run and test a config with the same argv', () => {
  assert.deepEqual(engineRunArgs('xray-pattn', 'c.json'), engineRunArgs('xray', 'c.json'));
  assert.deepEqual(engineTestArgs('xray-pattn', 'c.json'), ['run', '-test', '-c', 'c.json']);
  assert.equal(engineFormat('xray-pattn'), 'xray');
});

test('xrayEngines lists the Xray-format cores, default first; sing-box is not one', () => {
  assert.deepEqual(xrayEngines(), ['xray', 'xray-pattn']);
  assert.equal(DEFAULT_ENGINE, 'xray');
  assert.equal(engineFormat('sing-box'), 'sing-box');
});

test('unknown ids fall back to the default engine; labels are human', () => {
  assert.equal(engine('nope').id, 'xray');
  assert.equal(engineLabel('xray-pattn'), 'Xray-PattN (patterniha)');
  assert.deepEqual(engineList().map(e => e.id), ['xray', 'xray-pattn', 'sing-box']);
});
