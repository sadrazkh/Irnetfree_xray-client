'use strict';
/**
 * The release workflow's Checksums step, run the way GitHub runs a `bash`
 * step (bash --noprofile --norc -eo pipefail, a script file).
 *
 * v1.5.0 shipped without any Windows installer: the step called the perl
 * `shasum`, which the Windows runner's profile-less bash does not have on its
 * PATH, so the step failed and the upload and publish steps were skipped.
 * These tests pin three things: the step succeeds with `shasum` absent (and,
 * for macOS, with `sha256sum` absent), its output is what
 * src/main/appUpdate.js parses, and it can never block publishing again.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { parseSha256Sums, sha256File } = require('../src/main/appUpdate');

const YML = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'release.yml'), 'utf8');

/** The `- name: Checksums` step of the build job: its keys and its `run: |` script. */
function checksumStep() {
  const lines = YML.split(/\r?\n/);
  const start = lines.findIndex(l => /^ {6}- name: Checksums\s*$/.test(l));
  assert.ok(start >= 0, 'release.yml has a "Checksums" step');
  const keys = {};
  const run = [];
  let inRun = false;
  for (let i = start + 1; i < lines.length; i++) {
    const l = lines[i];
    if (/^ {6}- /.test(l) || /^ {0,5}\S/.test(l)) break;       // next step / next job
    if (inRun) {
      if (l.trim() === '' || /^ {10}/.test(l)) { run.push(l.slice(10)); continue; }
      inRun = false;
    }
    const m = /^ {8}([\w-]+):\s*(.*)$/.exec(l);
    if (!m) continue;
    keys[m[1]] = m[2];
    if (m[1] === 'run') assert.equal(m[2], '|', 'run is a literal block');
    inRun = m[1] === 'run';
  }
  return { keys, script: run.join('\n').trim() + '\n' };
}

/** Git's bash on Windows (the one GitHub's windows runner uses), plain bash elsewhere. */
function findBash() {
  const candidates = process.platform === 'win32'
    ? [
      path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Git', 'bin', 'bash.exe'),
      path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Git', 'usr', 'bin', 'bash.exe'),
      'bash'
    ]
    : ['bash'];
  for (const b of candidates) {
    const r = spawnSync(b, ['--noprofile', '--norc', '-c', 'echo "$BASH_VERSION"'], { encoding: 'utf8' });
    if (r.status === 0 && /^\d/.test(String(r.stdout).trim())) return b;
  }
  return null;
}

/**
 * Runs the step in a scratch checkout whose dist/ holds `files`, with the
 * named commands made to fail like "command not found" (exit 127) — a shell
 * function shadows a PATH lookup, so this works on every platform.
 */
function runStep(bash, matrixOs, files, missing) {
  const { keys, script } = checksumStep();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-rel-'));
  const cleanup = () => { try { fs.rmSync(root, { recursive: true, force: true }); } catch {} };
  fs.mkdirSync(path.join(root, 'dist'));
  for (const [name, body] of Object.entries(files)) fs.writeFileSync(path.join(root, 'dist', name), body);
  const prelude = missing.map(c => `${c}() { echo "${c}: command not found" >&2; return 127; }`).join('\n');
  const body = script.split('${{ matrix.os }}').join(matrixOs);
  const file = path.join(root, 'step.sh');
  fs.writeFileSync(file, `${prelude}\n${body}`);
  const r = spawnSync(bash, ['--noprofile', '--norc', '-eo', 'pipefail', file], { cwd: root, encoding: 'utf8' });
  const sumsFile = path.join(root, 'dist', `SHA256SUMS-${matrixOs}.txt`);
  const sums = fs.existsSync(sumsFile) ? parseSha256Sums(fs.readFileSync(sumsFile, 'utf8')) : null;
  return { keys, status: r.status, stdout: r.stdout, stderr: r.stderr, sums, dir: path.join(root, 'dist'), cleanup };
}

test('Checksums step: bash, and it never blocks the installers from being published', () => {
  const { keys } = checksumStep();
  assert.equal(keys.shell, 'bash');
  assert.equal(keys['continue-on-error'], 'true', 'a checksum hiccup must not skip the upload/publish steps');
});

test('Checksums step: Windows — no perl shasum on the runner; every installer is listed and verifiable', async (t) => {
  const bash = findBash();
  if (!bash) return t.skip('no bash on this machine');
  const files = {
    'IRNetFree-Setup-9.9.9.exe': 'setup bytes\n',
    'IRNetFree-Portable-9.9.9.exe': 'portable bytes\n',
    'builder-debug.yml': 'not an installer'
  };
  const r = runStep(bash, 'windows-latest', files, ['shasum']);
  try {
    assert.equal(r.status, 0, `step failed:\n${r.stdout}\n${r.stderr}`);
    assert.ok(r.sums, 'SHA256SUMS-windows-latest.txt was written');
    assert.deepEqual(Object.keys(r.sums).sort(), ['IRNetFree-Portable-9.9.9.exe', 'IRNetFree-Setup-9.9.9.exe']);
    for (const name of Object.keys(r.sums)) {
      assert.equal(r.sums[name], await sha256File(path.join(r.dir, name)), `${name} hashes to what the app computes`);
    }
  } finally {
    r.cleanup();
  }
});

test('Checksums step: macOS — no coreutils sha256sum; shasum is the fallback', async (t) => {
  const bash = findBash();
  if (!bash) return t.skip('no bash on this machine');
  const has = spawnSync(bash, ['--noprofile', '--norc', '-c', 'command -v shasum'], { encoding: 'utf8' });
  if (has.status !== 0) return t.skip('no shasum on this machine to fall back to');
  const files = { 'IRNetFree-9.9.9-arm64.dmg': 'dmg\n', 'IRNetFree-9.9.9-mac.zip': 'zip\n' };
  const r = runStep(bash, 'macos-latest', files, ['sha256sum']);
  try {
    assert.equal(r.status, 0, `step failed:\n${r.stdout}\n${r.stderr}`);
    assert.deepEqual(Object.keys(r.sums).sort(), ['IRNetFree-9.9.9-arm64.dmg', 'IRNetFree-9.9.9-mac.zip']);
    assert.equal(r.sums['IRNetFree-9.9.9-mac.zip'], await sha256File(path.join(r.dir, 'IRNetFree-9.9.9-mac.zip')));
  } finally {
    r.cleanup();
  }
});

test('Checksums step: with nothing to hash the file is still written, empty', (t) => {
  const bash = findBash();
  if (!bash) return t.skip('no bash on this machine');
  const r = runStep(bash, 'ubuntu-latest', { 'builder-debug.yml': 'x' }, []);
  try {
    assert.equal(r.status, 0, `step failed:\n${r.stdout}\n${r.stderr}`);
    assert.deepEqual(r.sums, {});
  } finally {
    r.cleanup();
  }
});
