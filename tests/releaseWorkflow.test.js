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

/* --------------------------- the Android SDK step --------------------------- */

/**
 * Both workflows must name the SDK packages they want.
 *
 * `android-actions/setup-android`'s default is `tools platform-tools`, and on
 * 2026-09-16 Google removed the deprecated `tools` package from the SDK
 * repository (the action's issues #537 and #538). Every Android job failed at
 * SDK setup, before a line of this repo was read, and v1.7.5 shipped without
 * an APK. An explicit list is the fix; the Gradle build fetches the platform
 * and build-tools it needs by itself.
 */
test('the Android SDK step asks for an explicit package list, and never for `tools`', () => {
  for (const name of ['release.yml', 'test.yml']) {
    const yml = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', name), 'utf8');
    const lines = yml.split(/\r?\n/);
    const at = lines.findIndex(l => /uses: android-actions\/setup-android@/.test(l));
    assert.ok(at >= 0, `${name} has no setup-android step`);
    // its `with:` block: the indented lines that follow, comments aside
    const body = [];
    for (let i = at + 1; i < lines.length; i++) {
      if (/^\s*-\s/.test(lines[i]) || /^\S/.test(lines[i])) break;
      body.push(lines[i]);
    }
    const packages = body.find(l => /^\s+packages:/.test(l));
    assert.ok(packages, `${name}: the setup-android step must pass an explicit \`packages:\` — the default installs the removed \`tools\` package`);
    const value = packages.split(':').slice(1).join(':').trim().replace(/^['"]|['"]$/g, '');
    assert.ok(value.length, `${name}: \`packages:\` is empty`);
    assert.equal(value.split(/\s+/).includes('tools'), false, `${name}: \`tools\` no longer exists in the SDK repository`);
    assert.ok(value.split(/\s+/).includes('platform-tools'), `${name}: platform-tools is what the build needs installed`);
  }
});

/*
 * The APK a tag actually ships.
 *
 * v1.9.1's Android job reported success and attached a DEBUG APK: 2 GB of
 * Gradle heap was not enough for `collectReleaseDependencies`, assembleRelease
 * died of OutOfMemoryError, and `assembleDebug assembleRelease … || true`
 * swallowed it. The Collect step then found no release APK, silently fell back
 * to the debug one it had built first, and said so in a single line of a very
 * long log. The owner would have installed a debuggable build without knowing.
 *
 * The fallback itself is right — a tag with no APK at all is worse — so what is
 * pinned here is that it cannot be silent, and that the build is given enough
 * memory to not need it.
 */
test('a tag that ships the debug APK says so loudly', () => {
  const lines = YML.split(/\r?\n/);
  const at = lines.findIndex(l => /- name: Collect APK/.test(l));
  assert.ok(at >= 0, 'release.yml has no Collect APK step');
  const body = [];
  for (let i = at + 1; i < lines.length; i++) {
    if (/^\s{6}-\s/.test(lines[i])) break;
    body.push(lines[i]);
  }
  const script = body.join('\n');
  assert.match(script, /apk\/release/, 'the release variant must be preferred');
  assert.match(script, /apk\/debug/, 'and debug kept as a fallback, so a tag always has an installable APK');
  assert.match(script, /::error::/,
    'falling back to the debug APK must raise a workflow error annotation — it shipped once without one');
  assert.match(script, /GITHUB_STEP_SUMMARY/,
    'and say which variant shipped in the run summary, where it is read without opening the log');
});

test('Gradle gets more heap than the build that ran out of it', () => {
  const props = fs.readFileSync(path.join(__dirname, '..', 'android', 'gradle.properties'), 'utf8');
  const m = props.match(/^org\.gradle\.jvmargs=.*?-Xmx(\d+)([mg])/mi);
  assert.ok(m, 'android/gradle.properties sets no -Xmx');
  const mb = m[2].toLowerCase() === 'g' ? Number(m[1]) * 1024 : Number(m[1]);
  // 2048 MB is the value that failed collectReleaseDependencies on the v1.9.1 tag.
  assert.ok(mb >= 3072, `-Xmx${m[1]}${m[2]} is not more than the 2048m that ran out of heap`);
});

/**
 * The OpenWrt package rides the release (v1.13.0): its own job, the version
 * synced to the tag like the desktop build, the ipk and its checksum published
 * — and, unlike the desktop artefacts, a MISSING ipk fails the job: there is
 * nothing to fall back to.
 */
test('the release workflow builds and publishes the OpenWrt package', () => {
  const yml = YML.replace(/\r\n/g, '\n');   // the checkout may be CRLF on Windows
  const at = yml.indexOf('\n  openwrt:\n');
  assert.ok(at >= 0, 'release.yml has an openwrt job');
  const job = yml.slice(at);
  assert.match(job, /name: Build OpenWrt package/);
  assert.match(job, /npm version --no-git-tag-version --allow-same-version "\$\{GITHUB_REF_NAME#v\}"/, 'the ipk carries the tag version');
  assert.match(job, /node openwrt\/build-ipk\.js dist/);
  assert.match(job, /sha256sum irnetfree_\*_all\.ipk > SHA256SUMS-openwrt\.txt/);
  assert.match(job, /uses: softprops\/action-gh-release@v2/);
  assert.match(job, /dist\/irnetfree_\*_all\.ipk/);
  assert.match(job, /fail_on_unmatched_files: true/, 'no ipk, no green release');
});

/** The openwrt job's `- name: Build ipk` step: its keys and its `run: |` script. */
function buildIpkStep() {
  const lines = YML.replace(/\r\n/g, '\n').split('\n');
  const job = lines.findIndex(l => l === '  openwrt:');
  assert.ok(job >= 0, 'release.yml has an openwrt job');
  const start = lines.findIndex((l, i) => i > job && /^ {6}- name: Build ipk\s*$/.test(l));
  assert.ok(start >= 0, 'the openwrt job has a "Build ipk" step');
  const keys = {};
  const run = [];
  let inRun = false;
  for (let i = start + 1; i < lines.length; i++) {
    const l = lines[i];
    if (/^ {6}- /.test(l) || /^ {0,5}\S/.test(l)) break;
    if (inRun) {
      if (l.trim() === '' || /^ {10}/.test(l)) { run.push(l.slice(10)); continue; }
      inRun = false;
    }
    const m = /^ {8}([\w-]+):\s*(.*)$/.exec(l);
    if (!m) continue;
    keys[m[1]] = m[2];
    inRun = m[1] === 'run';
  }
  return { keys, script: run.join('\n').trim() + '\n' };
}

/*
 * The ipk's files carry the tagged commit's time. uhttpd serves a LuCI view
 * with its mtime as Last-Modified and no Cache-Control, and a browser keeps a
 * response fresh for a tenth of its age — stamped 1970 (build-ipk's old
 * default) that was years, so after an upgrade the owner kept the old views.
 * Run for real: the step's lines up to the build, in a scratch git repo whose
 * one commit has a known time, with `node` replaced by a function that records
 * the SOURCE_DATE_EPOCH it was handed.
 */
test('the OpenWrt release package is stamped with the tagged commit\'s time (SOURCE_DATE_EPOCH), not 1970', (t) => {
  const bash = findBash();
  if (!bash) return t.skip('no bash on this machine');
  const { keys, script } = buildIpkStep();
  assert.equal(keys.shell, 'bash');
  const lines = script.split('\n');
  const build = lines.findIndex(l => /^node openwrt\/build-ipk\.js dist$/.test(l.trim()));
  assert.ok(build >= 0, 'the step builds with node openwrt/build-ipk.js dist');
  assert.ok(lines.slice(0, build).some(l => /SOURCE_DATE_EPOCH/.test(l)), 'SOURCE_DATE_EPOCH is set before the build');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-rel-'));
  try {
    const git = (...a) => spawnSync('git', a, {
      cwd: root, encoding: 'utf8',
      env: Object.assign({}, process.env, { GIT_AUTHOR_DATE: '1790000000 +0000', GIT_COMMITTER_DATE: '1790000000 +0000' })
    });
    if (git('init', '-q').status !== 0) return t.skip('no git on this machine');
    const c = git('-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-q', '--no-verify', '--allow-empty', '-m', 'tag');
    assert.equal(c.status, 0, c.stderr);
    const file = path.join(root, 'step.sh');
    fs.writeFileSync(file, [
      'node() { printf "%s" "${SOURCE_DATE_EPOCH-unset}" > seen.txt; }',
      ...lines.slice(0, build + 1)
    ].join('\n') + '\n');
    const r = spawnSync(bash, ['--noprofile', '--norc', '-eo', 'pipefail', file], { cwd: root, encoding: 'utf8' });
    assert.equal(r.status, 0, `step failed:\n${r.stdout}\n${r.stderr}`);
    assert.equal(fs.readFileSync(path.join(root, 'seen.txt'), 'utf8'), '1790000000', 'build-ipk is handed the commit\'s time, exported');
    // a step that cannot read the commit time must fail, not build a package stamped 1970 (or "now")
    fs.rmSync(path.join(root, '.git'), { recursive: true, force: true });
    fs.rmSync(path.join(root, 'seen.txt'), { force: true });
    const r2 = spawnSync(bash, ['--noprofile', '--norc', '-eo', 'pipefail', file], { cwd: root, encoding: 'utf8', env: Object.assign({}, process.env, { GIT_CEILING_DIRECTORIES: path.dirname(root) }) });
    assert.notEqual(r2.status, 0, 'no commit time, no build');
    assert.equal(fs.existsSync(path.join(root, 'seen.txt')), false, 'build-ipk never ran');
  } finally {
    try { fs.rmSync(root, { recursive: true, force: true }); } catch {}
  }
});

test('the test workflow boots OpenWrt in QEMU and runs the smoke', () => {
  const tests = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'test.yml'), 'utf8').replace(/\r\n/g, '\n');
  const at = tests.indexOf('\n  openwrt:\n');
  assert.ok(at >= 0, 'test.yml has an openwrt job');
  const job = tests.slice(at);
  assert.match(job, /qemu-system-arm/);
  // both feeds' nodes: 24.10 (node 20) and 23.05 (node 18, the owner's router)
  assert.match(job, /release: \['24\.10\.2', '23\.05\.5'\]/);
  assert.match(job, /openwrt-\$\{\{ matrix\.release \}\}-armsr-armv7-generic-initramfs-kernel\.bin/);
  assert.match(job, /fail-fast: false/, 'one release failing must not hide the other');
  assert.match(job, /if: matrix\.release == '24\.10\.2'\s*\n\s*uses: actions\/upload-artifact@v4/, 'one artifact, not one per release');
  assert.match(job, /node openwrt\/build-ipk\.js dist/);
  assert.match(job, /node openwrt\/ci\/qemu-smoke\.js --kernel \/tmp\/openwrt-kernel\.bin --ipk/);
  assert.match(job, /timeout-minutes: \d+/, 'TCG is slow; a hang must not run for six hours');
  // a testable package from every push, not only from a tag
  assert.match(job, /uses: actions\/upload-artifact@v4[\s\S]*name: IRNetFree-OpenWrt-dev[\s\S]*path: dist\/irnetfree_\*_all\.ipk/);
});

/** The `run: |` script and the env keys of the android job's step named `name`. */
function androidStep(name) {
  const lines = YML.split(/\r?\n/);
  const at = lines.findIndex(l => l.trim() === '- name: ' + name);
  assert.ok(at >= 0, 'release.yml has a "' + name + '" step');
  const body = [];
  for (let i = at + 1; i < lines.length; i++) {
    if (/^\s{6}-\s/.test(lines[i]) || /^\s{2}\S/.test(lines[i])) break;
    body.push(lines[i]);
  }
  const text = body.join('\n');
  const runAt = body.findIndex(l => /^\s+run: \|\s*$/.test(l));
  const run = runAt < 0 ? '' : body.slice(runAt + 1).map(l => l.replace(/^ {10}/, '')).join('\n');
  return { text, run };
}

/*
 * Every release before v1.16.3 was signed with the runner's throwaway debug key
 * (no keystore secret), so each version carried a different certificate and a
 * phone with an older copy refused the update: "App not installed as package
 * appears to be invalid". The real key is four secrets; with one missing Gradle
 * falls back to that debug key without a word.
 */
test('a release key is all four secrets or none — a partial set fails the build', (t) => {
  const bash = findBash();
  if (!bash) return t.skip('no bash here');
  const { run } = androidStep('Decode release keystore (if configured)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-ks-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'step.sh');
  fs.writeFileSync(file, run);
  const go = (env) => {
    const out = path.join(dir, 'out-' + Object.keys(env).join('-'));
    fs.writeFileSync(out, '');
    const r = spawnSync(bash, ['--noprofile', '--norc', '-eo', 'pipefail', file], {
      encoding: 'utf8',
      env: Object.assign({}, process.env, { RUNNER_TEMP: dir, GITHUB_OUTPUT: out, KS_B64: '', KS_PASS: '', KS_ALIAS: '', KS_KEY_PASS: '' }, env)
    });
    return { status: r.status, text: r.stdout + r.stderr, output: fs.readFileSync(out, 'utf8') };
  };
  const b64 = Buffer.from('not really a keystore').toString('base64');
  const none = go({});
  assert.equal(none.status, 0, 'no key at all: a fork still builds (debug-signed)');
  assert.match(none.text, /No keystore secret/);
  for (const missing of ['KS_PASS', 'KS_ALIAS', 'KS_KEY_PASS']) {
    const env = { KS_B64: b64, KS_PASS: 'p', KS_ALIAS: 'irnetfree', KS_KEY_PASS: 'p' };
    env[missing] = '';
    const r = go(env);
    assert.notEqual(r.status, 0, 'the keystore with ' + missing + ' empty must fail the step');
    assert.match(r.text, /::error::/);
    assert.doesNotMatch(r.output, /path=/, 'and hand Gradle no keystore');
  }
  const all = go({ KS_B64: b64, KS_PASS: 'p', KS_ALIAS: 'irnetfree', KS_KEY_PASS: 'p' });
  assert.equal(all.status, 0, all.text);
  assert.match(all.output, /^path=.*release\.keystore$/m);
});

test('with the release key configured, a tag never ships the debug APK', () => {
  const { text, run } = androidStep('Collect APK');
  assert.match(text, /KEYSTORE_PATH: \$\{\{ steps\.keystore\.outputs\.path \}\}/, 'the step knows whether a real key was configured');
  const refuse = run.indexOf('refusing to publish the debug build');
  const warn = run.indexOf('this release carries the DEBUG build');
  assert.ok(refuse > 0 && warn > refuse, 'the refusal comes before the old warn-and-ship path');
  assert.match(run.slice(0, warn), /KEYSTORE_PATH[\s\S]*GITHUB_REF_TYPE[\s\S]*exit 1/);
});

test("the APK's certificate is pinned to IRNetFree's release key", () => {
  const { text, run } = androidStep("Verify the APK's certificate (release key)");
  assert.match(text, /if: steps\.keystore\.outputs\.path != ''/, 'only where the real key was used (a fork without it still builds)');
  assert.match(text, /EXPECTED_CERT_SHA256: aabda682057fde3ea565c0d972ea103eed0d6c9ee20232bee98f0b6fc8ce3fc6/);
  assert.match(run, /apksigner" verify --print-certs "\$GITHUB_WORKSPACE\/\$\{\{ steps\.apk\.outputs\.file \}\}"/);
  assert.match(run, /Signer #1 certificate SHA-256 digest/);
  assert.match(run, /exit 1/);
  const lines = YML.split(/\r?\n/);
  const verify = lines.findIndex(l => l.includes("- name: Verify the APK's certificate"));
  const upload = lines.findIndex(l => l.includes('- name: Upload APK artifact'));
  const publish = lines.findIndex(l => l.includes('- name: Publish APK to GitHub Release'));
  assert.ok(verify > 0 && verify < upload && verify < publish, 'checked before anything is uploaded or published');
});
