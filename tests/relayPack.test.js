'use strict';
/**
 * What `harbora deploy` would upload for the relay — judged with Harbora's own
 * packer rules (Harbora/src/Harbora.Cli/SourcePacker.cs, re-implemented here
 * line for line), applied to this repo's files and the root .dockerignore:
 *
 *   - .dockerignore is read instead of .gitignore when present; lines are
 *     trimmed, blank/`#`/`!` lines DROPPED (no negation!), slashes trimmed;
 *   - built-in names (.git, node_modules, bin, .env, …) match any segment;
 *     build/dist/target/vendor/.output match the first segment only;
 *   - a pattern with `*` matches when any segment, or the whole path, matches
 *     it as a simple wildcard; any other pattern matches the whole path, a
 *     prefix of it (`pattern/`), or ANY segment equal to it (case-insensitive).
 *
 * The first .dockerignore used `*` + `!relay/` negations: Docker keeps the
 * negated files, Harbora's packer drops the `!` lines, so `*` excluded every
 * file and the deploy had nothing to build from (review I4). This pins the
 * upload set: every COPY source of relay/Dockerfile is in it, the big trees
 * and the router-only modules are not, and it stays small.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

const ALWAYS = ['.git', '.hg', '.svn', 'node_modules', 'bower_components', 'bin', 'obj', '.next', '.nuxt', '.venv', 'venv', '__pycache__', '.pytest_cache', '.idea', '.vs', '.vscode', '.DS_Store', 'Thumbs.db', '.env', '.env.local', '.terraform', '.gradle'].map((s) => s.toLowerCase());
const ROOT_ONLY = ['build', 'dist', 'target', 'vendor', '.output'];

/** SourcePacker.LoadIgnorePatterns */
function loadIgnorePatterns(root) {
  for (const name of ['.dockerignore', '.gitignore']) {
    const p = path.join(root, name);
    if (!fs.existsSync(p)) continue;
    return fs.readFileSync(p, 'utf8').split(/\r?\n/).map((l) => l.trim())
      .filter((l) => l.length && !l.startsWith('#') && !l.startsWith('!'))
      .map((l) => l.replace(/\\/g, '/').replace(/^\/+|\/+$/g, ''))
      .filter((l) => l.length);
  }
  return [];
}

/** FileSystemName.MatchesSimpleExpression: `*` any run, `?` one char, case-insensitive, whole string. */
function simpleMatch(pattern, s) {
  const re = new RegExp('^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i');
  return re.test(s);
}

/** SourcePacker.DescribeExclusion — the reason a relative path is left out, or null. */
function describeExclusion(rel, patterns) {
  const segments = rel.split('/');
  const builtin = segments.find((s) => ALWAYS.includes(s.toLowerCase()));
  if (builtin) return `built-in rule '${builtin}'`;
  if (ROOT_ONLY.includes(segments[0].toLowerCase())) return `built-in rule '${segments[0]}' (project root)`;
  for (const pattern of patterns) {
    if (pattern.includes('*')) {
      if (segments.some((s) => simpleMatch(pattern, s)) || simpleMatch(pattern, rel)) return `ignore pattern '${pattern}'`;
    } else if (rel.toLowerCase() === pattern.toLowerCase() || rel.toLowerCase().startsWith(pattern.toLowerCase() + '/') || segments.some((s) => s.toLowerCase() === pattern.toLowerCase())) {
      return `ignore pattern '${pattern}'`;
    }
  }
  return null;
}

/** Every file under root as a relative POSIX path; .git and node_modules skipped early (built-in excluded anyway, and huge). */
function walk(dir, rel = '', out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === '.git' || e.name === 'node_modules') continue;
    const r = rel ? rel + '/' + e.name : e.name;
    if (e.isDirectory()) walk(path.join(dir, e.name), r, out);
    else if (e.isFile()) out.push(r);
  }
  return out;
}

const patterns = loadIgnorePatterns(ROOT);
const all = walk(ROOT);
const upload = all.filter((rel) => describeExclusion(rel, patterns) === null);
const dockerfile = fs.readFileSync(path.join(ROOT, 'relay', 'Dockerfile'), 'utf8');

test('the root .dockerignore holds only patterns Harbora keeps: no negations, no bare `*`', () => {
  const raw = fs.readFileSync(path.join(ROOT, '.dockerignore'), 'utf8').split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  assert.ok(raw.length > 5);
  assert.ok(!raw.some((l) => l.startsWith('!')), 'a `!` line is dropped by Harbora, so nothing may depend on one');
  assert.ok(!raw.some((l) => l === '*' || l === '**' || l === '*/' || l === '/*'), 'a bare wildcard excludes everything');
});

test('every COPY source of relay/Dockerfile is in the upload Harbora would pack', () => {
  const sources = [];
  for (const m of dockerfile.matchAll(/^COPY\s+(.+)$/gm)) {
    const parts = m[1].trim().split(/\s+/).filter((p) => !p.startsWith('--'));
    sources.push(...parts.slice(0, -1));
  }
  assert.ok(sources.length >= 4, 'COPY lines found: ' + sources.join(' '));
  for (const src of sources) {
    if (src.endsWith('/')) {
      const inside = upload.filter((f) => f.startsWith(src));
      assert.ok(inside.length > 0, `${src} has files in the upload`);
    } else {
      assert.ok(upload.includes(src), `${src} is in the upload (reason it is not: ${describeExclusion(src, patterns)})`);
    }
  }
  for (const must of ['relay/server.js', 'relay/lib/auth.js', 'relay/lib/store.js', 'relay/lib/proxy.js', 'relay/lib/pages.js', 'relay/Dockerfile', 'relay/harbora.yml',
    'src/server/remote/ws.js', 'src/server/remote/frames.js', 'src/server/remote/token.js']) {
    assert.ok(upload.includes(must), `${must} is in the upload (${describeExclusion(must, patterns)})`);
  }
});

test('the upload carries nothing the relay does not need: no router modules, no app, no tests, no docs, no worktrees — and it is small', () => {
  const never = [/^src\/main\//, /^src\/renderer\//, /^src\/server\/(server|service|guard|web-api|luciApi)\.js$/, /^src\/server\/remote\/(agent|api|cloudflared)\.js$/,
    /^android\//, /^openwrt\//, /^tests\//, /^docs\//, /^assets\//, /^scripts\//, /^native\//, /^\.claude\//, /^\.superpowers\//, /^\.github\//, /^package(-lock)?\.json$/, /^install\.sh$/];
  for (const f of upload) assert.ok(!never.some((re) => re.test(f)), `${f} should not be uploaded`);
  const bytes = upload.reduce((n, f) => n + fs.statSync(path.join(ROOT, f)).size, 0);
  assert.ok(upload.length <= 40, `${upload.length} files: ${upload.join(', ')}`);
  assert.ok(bytes < 512 * 1024, `${bytes} bytes`);
  // the patterns themselves do what they say with Harbora's "bare name = any segment" rule, and do not
  // eat anything under relay/ or the three shared modules by accident
  for (const kept of upload.filter((f) => f.startsWith('relay/') || f.startsWith('src/server/remote/'))) assert.equal(describeExclusion(kept, patterns), null, kept);
});
