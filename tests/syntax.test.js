'use strict';
/**
 * Every JavaScript file the app ships has to at least PARSE.
 *
 * v1.7.3 shipped with an apostrophe inside a single-quoted string in
 * src/renderer/i18n.js. Nothing required that file: the main process never
 * loads renderer code, the renderer test reads it as text, and `npm test` was
 * green. The window loaded i18n.js, hit the SyntaxError, and every script after
 * it never ran — a dead UI on every platform, on the release the owner had
 * asked for to test a crash fix. This compiles each file (no execution) so a
 * broken string, a stray brace or a half-finished edit fails here first.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');
const DIRS = ['src/main', 'src/renderer', 'src/server', 'scripts'];

function jsFiles(dir) {
  const abs = path.join(ROOT, dir);
  if (!fs.existsSync(abs)) return [];
  const out = [];
  for (const entry of fs.readdirSync(abs, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) { if (entry.name !== 'vendor' && entry.name !== 'node_modules') out.push(...jsFiles(p)); continue; }
    if (entry.isFile() && /\.js$/.test(entry.name)) out.push(p);
  }
  return out;
}

const files = DIRS.flatMap(jsFiles);

test('the shipped JavaScript files are found', () => {
  assert.ok(files.length >= 40, `only ${files.length} files found under ${DIRS.join(', ')}`);
  for (const must of ['src/renderer/i18n.js', 'src/renderer/app.js', 'src/main/main.js', 'src/server/service.js']) {
    assert.ok(files.includes(must.split('/').join(path.sep)) || files.includes(must), `${must} is not in the list`);
  }
});

for (const rel of files) {
  test(`parses: ${rel.split(path.sep).join('/')}`, () => {
    // A CLI entry point starts with a shebang, which only the very first line
    // of a file may carry — Node strips it before compiling, and so does this.
    const source = fs.readFileSync(path.join(ROOT, rel), 'utf8').replace(/^#![^\n]*/, '');
    // Renderer files are classic scripts in a window; main/server files are
    // CommonJS modules. Both parse as a function body, which is what the
    // module wrapper and a <script> tag both accept — `return` aside, which
    // none of them uses at top level.
    assert.doesNotThrow(() => new vm.Script(`(function () {\n${source}\n})`, { filename: rel }),
      `${rel} does not parse — the UI would not load, or the process would not start`);
  });
}
