'use strict';
/**
 * The OpenWrt package, built into a temp dir and read back with our own tar
 * reader: the three members opkg expects, the control fields, every file the
 * router side needs with the right mode, and — because ash is not bash — a
 * scan of every script that runs on the router for bashisms.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const { spawnSync } = require('node:child_process');
const { tar, untar, tgz, untgz } = require('../openwrt/tar');
const { buildIpk, sourceDateEpoch, PKG, DEPENDS, PREFIX } = require('../openwrt/build-ipk');

const ROOT = path.join(__dirname, '..');
const VERSION = require('../package.json').version;

test('tar: ustar headers a real tar reads, round-trips through our reader, deterministic', () => {
  const a = tar([{ name: 'd', dir: true }, { name: 'd/x.txt', data: 'hi\n', mode: 0o644 }, { name: 'd/run', data: '#!/bin/sh\n', mode: 0o755 }], { mtime: 0 });
  const b = tar([{ name: 'd', dir: true }, { name: 'd/x.txt', data: 'hi\n', mode: 0o644 }, { name: 'd/run', data: '#!/bin/sh\n', mode: 0o755 }], { mtime: 0 });
  assert.ok(a.equals(b), 'same input, same bytes');
  assert.equal(a.length % 512, 0);
  const back = untar(a);
  assert.deepEqual(back.map(e => [e.name, e.type, e.mode]), [['./d/', '5', 0o755], ['./d/x.txt', '0', 0o644], ['./d/run', '0', 0o755]]);
  assert.equal(back[1].data.toString(), 'hi\n');
  // ustar magic + a checksum the C tools accept
  assert.equal(a.subarray(257, 263).toString(), 'ustar\0');
  const sum = [...a.subarray(0, 512)].reduce((n, b, i) => n + (i >= 148 && i < 156 ? 32 : b), 0);
  assert.equal(parseInt(a.subarray(148, 154).toString(), 8), sum);
  assert.deepEqual(untgz(tgz([{ name: 'f', data: 'x' }])).map(e => e.name), ['./f']);
  assert.throws(() => tar([{ name: 'x'.repeat(100), data: '' }]), /too long/);
  // the system tar, where there is one, agrees
  const sys = spawnSync('tar', ['-tf', '-'], { input: a, encoding: 'utf8' });
  if (sys.status === 0) assert.deepEqual(sys.stdout.trim().split(/\r?\n/), ['./d/', './d/x.txt', './d/run']);
});

/** The LuCI pages where LuCI looks for them: views by their menu path, the shared module by its require name. */
const LUCI_PAGES = ['overview', 'settings', 'remote', 'log'].map((v) => `./www/luci-static/resources/view/irnetfree/${v}.js`)
  .concat('./www/luci-static/resources/irnetfree/common.js');

const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-ipk-'));
test.after(() => { try { fs.rmSync(outDir, { recursive: true, force: true }); } catch {} });
const built = buildIpk({ root: ROOT, outDir, mtime: 0 });
const outer = untgz(fs.readFileSync(built.out));
const byName = (list) => Object.fromEntries(list.map(e => [e.name, e]));
const outerMap = byName(outer);
const control = byName(untgz(outerMap['./control.tar.gz'].data));
const data = byName(untgz(outerMap['./data.tar.gz'].data));

test('the ipk is what opkg expects: debian-binary, control, data — and is named after the version', () => {
  assert.equal(path.basename(built.out), `${PKG}_${VERSION}_all.ipk`);
  assert.deepEqual(outer.map(e => e.name), ['./debian-binary', './control.tar.gz', './data.tar.gz']);
  assert.equal(outerMap['./debian-binary'].data.toString(), '2.0\n');
});

/**
 * Every tar header's mtime in a gzipped tar, in order — the ustar field at
 * offset 136, octal. Our reader leaves it out; this is all the tests need.
 */
function mtimesOf(gz) {
  const buf = zlib.gunzipSync(gz);
  const out = [];
  for (let off = 0; off + 512 <= buf.length;) {
    const h = buf.subarray(off, off + 512);
    if (h.every(b => b === 0)) break;
    out.push(parseInt(h.subarray(136, 148).toString('utf8').replace(/\0[\s\S]*$/, '').trim(), 8));
    off += 512 + Math.ceil((parseInt(h.subarray(124, 136).toString('utf8').replace(/\0[\s\S]*$/, '').trim(), 8) || 0) / 512) * 512;
  }
  return out;
}

/** The mtimes of all three tars an ipk is made of: the outer one, control.tar.gz and data.tar.gz. */
function ipkMtimes(file) {
  const raw = fs.readFileSync(file);
  const members = byName(untgz(raw));
  return [...mtimesOf(raw), ...mtimesOf(members['./control.tar.gz'].data), ...mtimesOf(members['./data.tar.gz'].data)];
}

/** Runs `fn` with SOURCE_DATE_EPOCH set to `value` (undefined: unset), then puts the environment back. */
function withEpoch(value, fn) {
  const had = Object.prototype.hasOwnProperty.call(process.env, 'SOURCE_DATE_EPOCH');
  const old = process.env.SOURCE_DATE_EPOCH;
  if (value === undefined) delete process.env.SOURCE_DATE_EPOCH; else process.env.SOURCE_DATE_EPOCH = value;
  try { return fn(); } finally { if (had) process.env.SOURCE_DATE_EPOCH = old; else delete process.env.SOURCE_DATE_EPOCH; }
}

/*
 * The files' mtimes. uhttpd hands a file's mtime to the browser as
 * Last-Modified and sends no Cache-Control, so the browser keeps a LuCI view
 * fresh for a tenth of its age: stamped 1970 that is years, and after an
 * upgrade the owner kept seeing the old pages. The release stamps the tagged
 * commit's time (SOURCE_DATE_EPOCH, release.yml); a build without it takes the
 * checkout's commit time — the same commit, the same bytes, and never 1970.
 */
test('mtimes: SOURCE_DATE_EPOCH stamps every member of all three tars, and the same epoch builds the same bytes', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-ipk-sde-'));
  try {
    const epoch = 1790000000;
    const a = withEpoch(String(epoch), () => fs.readFileSync(buildIpk({ root: ROOT, outDir: path.join(dir, 'a') }).out));
    const b = withEpoch(String(epoch), () => fs.readFileSync(buildIpk({ root: ROOT, outDir: path.join(dir, 'b') }).out));
    assert.ok(a.equals(b), 'reproducible: one epoch, one package');
    const all = ipkMtimes(path.join(dir, 'a', `${PKG}_${VERSION}_all.ipk`));
    assert.ok(all.length > 50, 'every header was read');
    assert.deepEqual([...new Set(all)], [epoch]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('mtimes: without SOURCE_DATE_EPOCH the checkout\'s commit time — never 1970', (t) => {
  const git = spawnSync('git', ['-C', ROOT, 'log', '-1', '--format=%ct'], { encoding: 'utf8' });
  if (git.status !== 0 || !/^\d+$/.test(String(git.stdout).trim())) return t.skip('not a git checkout');
  const commit = Number(String(git.stdout).trim());
  assert.equal(sourceDateEpoch({ env: {}, root: ROOT }), commit);
  assert.equal(sourceDateEpoch({ env: { SOURCE_DATE_EPOCH: '' }, root: ROOT }), commit, 'an empty value is no value');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-ipk-git-'));
  try {
    const out = withEpoch(undefined, () => buildIpk({ root: ROOT, outDir: dir }).out);
    assert.deepEqual([...new Set(ipkMtimes(out))], [commit]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('mtimes: no SOURCE_DATE_EPOCH and no git — the build time, still never 1970', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-ipk-nogit-'));
  try {
    if (spawnSync('git', ['-C', dir, 'rev-parse', '--git-dir'], { encoding: 'utf8' }).status === 0) return t.skip('the temp dir is inside a git checkout');
    assert.equal(sourceDateEpoch({ env: {}, root: dir, now: () => 1790000000999 }), 1790000000);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('mtimes: a SOURCE_DATE_EPOCH that is not whole seconds refuses to build', () => {
  for (const bad of ['yesterday', '-5', '1.5', '17e8', '0x10']) {
    assert.throws(() => sourceDateEpoch({ env: { SOURCE_DATE_EPOCH: bad }, root: ROOT }), /SOURCE_DATE_EPOCH/, bad);
  }
  assert.equal(sourceDateEpoch({ env: { SOURCE_DATE_EPOCH: ' 1790000000\n' }, root: ROOT }), 1790000000, 'surrounding whitespace is fine');
  assert.equal(sourceDateEpoch({ env: { SOURCE_DATE_EPOCH: '0' }, root: ROOT }), 0, 'an explicit 0 is what was asked for');
});

test('control: the fields, the dependencies the router needs, conffiles, and the standard OpenWrt scripts', () => {
  const c = control['./control'].data.toString();
  assert.match(c, /^Package: irnetfree$/m);
  assert.match(c, new RegExp(`^Version: ${VERSION.replace(/\./g, '\\.')}$`, 'm'));
  assert.match(c, /^Architecture: all$/m);
  assert.match(c, /^Section: net$/m);
  assert.match(c, /^Depends: node, kmod-tun, nftables, ip-full, unzip, ca-bundle$/m);
  assert.deepEqual(DEPENDS, ['node', 'kmod-tun', 'nftables', 'ip-full', 'unzip', 'ca-bundle']);
  const installed = Object.values(data).filter(e => e.type === '0').reduce((n, e) => n + e.data.length, 0);
  assert.match(c, new RegExp(`^Installed-Size: ${installed}$`, 'm'));
  assert.equal(control['./conffiles'].data.toString(), '/etc/config/irnetfree\n');
  for (const s of ['./postinst', './prerm']) {
    assert.equal(control[s].mode, 0o755, s);
    assert.match(control[s].data.toString(), /^#!\/bin\/sh\n/);
    assert.match(control[s].data.toString(), /\/lib\/functions\.sh/, `${s} defers to OpenWrt's default_* helper`);
  }
});

test('data: the app under /usr/lib/irnetfree, the service files, the LuCI files — right modes, no junk', () => {
  const files = Object.keys(data).filter(n => data[n].type === '0');
  for (const must of [
    `./${PREFIX}/src/server/server.js`, `./${PREFIX}/src/server/service.js`, `./${PREFIX}/src/main/tunOpenwrt.js`,
    `./${PREFIX}/src/renderer/index.html`, `./${PREFIX}/assets/logo.svg`, `./${PREFIX}/package.json`,
    './etc/init.d/irnetfree', './etc/init.d/irnetfree-ks', './etc/config/irnetfree', './etc/uci-defaults/99-irnetfree',
    './usr/share/luci/menu.d/luci-app-irnetfree.json', './usr/share/rpcd/acl.d/luci-app-irnetfree.json',
    ...LUCI_PAGES
  ]) assert.ok(files.includes(must), `${must} is not in the package`);
  assert.ok(!files.includes('./www/luci-static/resources/view/irnetfree.js'), 'the old link page is gone (opkg removes it on upgrade)');
  assert.equal(data['./etc/init.d/irnetfree'].mode, 0o755);
  assert.equal(data['./etc/uci-defaults/99-irnetfree'].mode, 0o755);
  assert.equal(data['./etc/config/irnetfree'].mode, 0o644);
  assert.equal(data[`./${PREFIX}/src/server/server.js`].mode, 0o644);
  // rpcd execs its plugins directly: executable, LF, byte for byte the checked-in script
  const plug = data['./usr/libexec/rpcd/luci.irnetfree'];
  assert.ok(plug, 'the rpcd plugin LuCI talks to is in the package');
  assert.equal(plug.mode, 0o755);
  assert.ok(!plug.data.includes('\r'), 'the rpcd plugin carries a carriage return');
  assert.equal(plug.data.toString(), fs.readFileSync(path.join(ROOT, 'openwrt/files/rpcd/luci.irnetfree'), 'utf8').replace(/\r\n/g, '\n'));
  assert.ok(!files.some(n => /node_modules|\.map$|\.test\.js$/.test(n)), 'no dev files ship');
  // remote control: the router's side ships (the agent and what it needs), the relay app does not (it runs on a server)
  for (const f of ['ws.js', 'frames.js', 'token.js', 'agent.js', 'api.js', 'cloudflared.js']) assert.ok(files.includes(`./${PREFIX}/src/server/remote/${f}`), `src/server/remote/${f} is in the package`);
  assert.ok(!files.some(n => n.includes('/relay/')), 'the relay app does not ship in the ipk');
  // every file's directory exists as an entry, in order, so opkg never has to invent one
  for (const n of files) {
    const dir = n.slice(0, n.lastIndexOf('/') + 1);
    if (dir !== './') assert.ok(data[dir] && data[dir].type === '5', `no directory entry for ${dir}`);
  }
  assert.equal(data[`./${PREFIX}/src/server/server.js`].data.toString(), fs.readFileSync(path.join(ROOT, 'src/server/server.js')).toString(), 'shipped verbatim');
  // the router-side text files are LF whatever the checkout did (a CRLF shebang is "/bin/sh^M: not found")
  for (const n of ['./etc/init.d/irnetfree', './etc/uci-defaults/99-irnetfree', './etc/config/irnetfree', ...LUCI_PAGES]) {
    assert.ok(!data[n].data.includes('\r'), `${n} carries a carriage return`);
  }
  for (const s of ['./postinst', './prerm']) assert.ok(!control[s].data.includes('\r'), `${s} carries a carriage return`);
});

test('postinst: rpcd reloads (the plugin and the ACL) and LuCI forgets its caches — on a live router, after the default steps', () => {
  const s = control['./postinst'].data.toString();
  const dflt = s.indexOf('default_postinst "$0" "$@"');
  assert.ok(dflt > 0, 'the default steps (uci-defaults, enable, start) still run');
  const tail = s.slice(dflt);
  // rpcd reads plugins and ACLs only when it starts; a reload re-execs it and keeps the sessions
  assert.match(tail, /\[ -n "\$IPKG_INSTROOT" \] \|\| \{[\s\S]*\/etc\/init\.d\/rpcd reload[\s\S]*\}/, 'not while an image is being built');
  assert.match(tail, /\[ -x \/etc\/init\.d\/rpcd \] && \/etc\/init\.d\/rpcd reload/, 'a router without rpcd (no LuCI) is fine');
  assert.match(tail, /rm -rf \/tmp\/luci-indexcache\* \/tmp\/luci-modulecache\//, 'the menu and module caches');
  assert.match(tail, /^rc=\$\?$/m);
  assert.match(s, /exit \$rc\n$/, 'the default steps\' result is the script\'s');
});

/** ash is not bash: the constructs that silently do the wrong thing there. */
const BASHISMS = [
  [/\[\[/, '[[ ]]'],
  [/^\s*function\s+\w+\s*\(?/m, 'function keyword'],
  [/\$\{\w+\[[@*0-9]/, 'arrays'],
  [/\$'/, "$'…' quoting"],
  [/\[ [^\]\n]*[^=!]==[^=]/, '== inside [ ]'],
  [/\bdeclare\b|\btypeset\b/, 'declare'],
  [/^\s*source\s/m, 'source (use .)'],
  [/&>/, '&> redirection'],
  [/\bpushd\b|\bpopd\b/, 'pushd/popd'],
  [/<<<\s/, 'here-string']
];
for (const [rel, name] of [
  ['./etc/init.d/irnetfree', 'the init script'], ['./etc/uci-defaults/99-irnetfree', 'the uci-defaults script'],
  ['CONTROL:./postinst', 'postinst'], ['CONTROL:./prerm', 'prerm'],
  ['./usr/libexec/rpcd/luci.irnetfree', 'the rpcd plugin']
]) {
  test(`${name} is POSIX sh: no bashisms`, () => {
    const src = (rel.startsWith('CONTROL:') ? control[rel.slice(8)] : data[rel]).data.toString();
    assert.match(src, /^#!\/bin\/sh( \/etc\/rc\.common)?\n/, 'a /bin/sh shebang');
    for (const [re, what] of BASHISMS) assert.doesNotMatch(src, re, what);
  });
}

test('the init script: procd, the token FILE (never the token itself), the exact command line, POSIX', () => {
  const s = data['./etc/init.d/irnetfree'].data.toString();
  assert.match(s, /^#!\/bin\/sh \/etc\/rc\.common\n/);
  assert.match(s, /^USE_PROCD=1$/m);
  assert.match(s, /^START=95$/m);
  assert.match(s, /config_load irnetfree/);
  assert.match(s, /head -c 16 \/dev\/urandom \| hexdump -ve '1\/1 "%02x"' > "\$data_dir\/token"/);
  // the token on the command line was in `ps`, and in the banner — which procd hands to syslog
  assert.match(s, /procd_set_param command \/usr\/bin\/node --max-old-space-size=160 "\$APP" --host "\$bind" --port "\$port" --data-dir "\$data_dir" --token-file "\$data_dir\/token"$/m);
  assert.doesNotMatch(s, /--token "/);
  assert.match(s, /procd_set_param env IRNETFREE_PLATFORM=openwrt/);
  // never give up: procd's default (5 crashes in an hour) left a router with no gateway until someone restarted it by hand
  assert.match(s, /^\tprocd_set_param respawn 3600 5 0$/m);
  // time for a clean teardown of the gateway on stop (procd's default is 5s, then SIGKILL)
  assert.match(s, /procd_set_param term_timeout 15/);
  // v1.16.2: the descriptor limit for node and the cores it starts (procd applies it before exec; children
  // inherit it). Without it they had the kernel's 4096 — the owner's AC-1304 ran out ("too many open files")
  const inst = s.slice(s.indexOf('procd_open_instance'), s.indexOf('procd_close_instance'));
  assert.match(inst, /^\tprocd_set_param limits nofile="65536 65536"$/m, 'one limits call, soft and hard, inside the instance');
  assert.equal((s.match(/procd_set_param limits/g) || []).length, 1, 'a second limits call would replace the first');
  assert.match(s, /procd_add_reload_trigger irnetfree/);
  // a zone added after the install (a guest Wi-Fi) is picked up at the next start
  assert.match(s, /sh \/usr\/lib\/irnetfree\/fw-forwardings\.sh >\/dev\/null 2>&1 \|\| true/);
});

test('the kill switch ships: /etc/init.d/irnetfree-ks (START=19, before network at 20) replays the snippet; prerm removes the table and the snippet', () => {
  const ks = data['./etc/init.d/irnetfree-ks'];
  assert.ok(ks, 'the boot script is in the package');
  assert.equal(ks.mode, 0o755);
  const src = ks.data.toString();
  assert.ok(!src.includes('\r'), 'LF only');
  assert.match(src, /^#!\/bin\/sh \/etc\/rc\.common\n/);
  for (const [re, what] of BASHISMS) assert.doesNotMatch(src, re, what);
  assert.match(src, /^START=19$/m, 'after firewall (19, sorts first), before network (20): the block is in place before any interface is up');
  assert.match(src, /^STOP=90$/m);
  assert.doesNotMatch(src, /USE_PROCD/, 'not a daemon: start() loads a file and returns');
  assert.match(src, /config_load irnetfree/);
  assert.match(src, /config_get data_dir main data_dir \/etc\/irnetfree/);
  assert.match(src, /\[ -s "\$f" \] \|\| return 0/, 'no snippet (disarmed): nothing to do');
  // "Connect when the router starts" off in the store: the VPN stays off after this boot — the snippet is not loaded,
  // so the LAN is not blocked for the minute before the service starts and disarms (review I1)
  assert.match(src, /jsonfilter -i "\$store" -e '@\.settings\.autoConnect'/, 'the switch is read from store.json');
  assert.match(src, /= "false" \]/, 'only an explicit off skips it (a store without the key is a router that connects at start)');
  assert.ok(src.indexOf('jsonfilter') < src.indexOf('nft -c -f'), 'checked before the load');
  assert.match(src, /nft -c -f "\$f" 2>\/dev\/null && nft -f "\$f"/, 'validated first: a broken snippet loads nothing');
  assert.match(src, /^stop\(\) \{\n\tnft delete table inet irnetfree_ks 2>\/dev\/null\n\treturn 0\n\}/m, 'the escape hatch from SSH: lifts the block by hand');
  const prerm = control['./prerm'].data.toString();
  assert.match(prerm, /nft delete table inet irnetfree_ks 2>\/dev\/null/);
  assert.match(prerm, /rm -f "\$data_dir\/killswitch\.nft"/);
  assert.match(prerm, /\[ -z "\$IPKG_INSTROOT" \]|\[ -n "\$IPKG_INSTROOT" \] \|\|/, 'only on the live system');
  assert.match(prerm, /default_prerm "\$0" "\$@"/);
  assert.match(prerm, /^exit \$ret$/m, 'default_prerm’s own status is what opkg sees');
});

test('fw-forwardings.sh ships executable, LF, POSIX, and both the install and every start run it', () => {
  const f = data[`./${PREFIX}/fw-forwardings.sh`];
  assert.ok(f, 'the forwarding script is in the package');
  assert.equal(f.mode, 0o755);
  const src = f.data.toString();
  assert.ok(!src.includes('\r'), 'LF only');
  assert.match(src, /^#!\/bin\/sh\n/);
  for (const [re, what] of BASHISMS) assert.doesNotMatch(src, re, what);
  assert.match(src, /^set -f\b/m, 'no globbing: an anonymous section is @forwarding[0]');
  assert.match(data['./etc/uci-defaults/99-irnetfree'].data.toString(), /^sh \/usr\/lib\/irnetfree\/fw-forwardings\.sh$/m);
});

/**
 * The forwarding script run for real — by this machine's POSIX sh, against a
 * fake `uci` (a node script on PATH) that keeps the firewall config in a file.
 * busybox ash on the router is what the QEMU job runs it with.
 */
function findSh() {
  if (process.platform !== 'win32') return '/bin/sh';
  for (const p of ['C:/Program Files/Git/usr/bin/sh.exe', 'C:/Program Files/Git/bin/sh.exe']) if (fs.existsSync(p)) return p;
  return null;
}
const FAKE_UCI = `#!/usr/bin/env node
// uci over a JSON file: [[key, value], …] in order; "firewall.x" → type, "firewall.x.opt" → value
const fs = require('fs');
const db = process.env.FAKE_UCI_DB;
const rows = JSON.parse(fs.readFileSync(db, 'utf8'));
const save = () => fs.writeFileSync(db, JSON.stringify(rows));
const unq = (v) => v.replace(/^'(.*)'$/, '$1');
const set = (kv) => { const i = kv.indexOf('='); const k = kv.slice(0, i), v = unq(kv.slice(i + 1)); const r = rows.find(x => x[0] === k); if (r) r[1] = v; else rows.push([k, v]); };
let a = process.argv.slice(2);
if (a[0] === '-q') a = a.slice(1);
const cmd = a[0];
if (cmd === 'show') { for (const [k, v] of rows) if (k.startsWith(a[1] + '.')) console.log(k.split('.').length === 2 ? k + '=' + v : k + "='" + v + "'"); process.exit(0); }
if (cmd === 'get') { const r = rows.find(x => x[0] === a[1]); if (!r) process.exit(1); console.log(r[1]); process.exit(0); }
if (cmd === 'set') { set(a[1]); save(); process.exit(0); }
if (cmd === 'commit') { rows.push(['#commit', a[1]]); save(); process.exit(0); }
if (cmd === 'batch') {
  for (const line of fs.readFileSync(0, 'utf8').split(/\\r?\\n/)) {
    const t = line.trim(); if (!t) continue;
    const [verb, rest] = [t.slice(0, t.indexOf(' ')), t.slice(t.indexOf(' ') + 1)];
    if (verb === 'set') set(rest); else if (verb === 'commit') rows.push(['#commit', rest]);
  }
  save(); process.exit(0);
}
process.exit(2);
`;

test('fw-forwardings.sh: every zone that forwards to wan gets a forwarding to irnetfree — once', (t) => {
  const sh = findSh();
  if (!sh) return t.skip('no POSIX sh here');
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-fw-'));
  t.after(() => { try { fs.rmSync(work, { recursive: true, force: true }); } catch {} });
  fs.writeFileSync(path.join(work, 'uci'), FAKE_UCI, { mode: 0o755 });
  const script = path.join(work, 'fw-forwardings.sh');
  fs.writeFileSync(script, data[`./${PREFIX}/fw-forwardings.sh`].data);
  const dbFile = path.join(work, 'db.json');
  const rows = [
    ['firewall.lan', 'zone'], ['firewall.lan.name', 'lan'],
    ['firewall.wan', 'zone'], ['firewall.wan.name', 'wan'],
    ['firewall.guest_zone', 'zone'], ['firewall.guest_zone.name', 'guest'],
    ['firewall.@forwarding[0]', 'forwarding'], ['firewall.@forwarding[0].src', 'lan'], ['firewall.@forwarding[0].dest', 'wan'],
    ['firewall.guest_wan', 'forwarding'], ['firewall.guest_wan.src', 'guest'], ['firewall.guest_wan.dest', 'wan'],
    ['firewall.iot', 'zone'], ['firewall.iot.name', 'iot'],                       // an isolated zone: no wan, so no tunnel either
    ['firewall.irnetfree', 'zone'], ['firewall.irnetfree.name', 'irnetfree'],
    ['firewall.irnetfree_lan', 'forwarding'], ['firewall.irnetfree_lan.src', 'lan'], ['firewall.irnetfree_lan.dest', 'irnetfree']
  ];
  fs.writeFileSync(dbFile, JSON.stringify(rows));
  const env = Object.assign({}, process.env, { FAKE_UCI_DB: dbFile, PATH: work + path.delimiter + process.env.PATH });
  const run = () => spawnSync(sh, [script], { env, encoding: 'utf8', cwd: work });
  const r1 = run();
  assert.equal(r1.status, 0, r1.stderr);
  const after = JSON.parse(fs.readFileSync(dbFile, 'utf8'));
  const has = (k, v) => after.some(x => x[0] === k && x[1] === v);
  assert.ok(has('firewall.irnetfree_guest', 'forwarding') && has('firewall.irnetfree_guest.src', 'guest') && has('firewall.irnetfree_guest.dest', 'irnetfree'), JSON.stringify(after));
  assert.ok(!after.some(x => /irnetfree_iot/.test(x[0])), 'a zone that may not reach wan does not get the tunnel');
  assert.equal(after.filter(x => x[0].endsWith('.src') && x[1] === 'lan').length, 2, 'lan already had one: not doubled');
  assert.equal(after.filter(x => x[0] === '#commit').length, 1, 'committed once');
  // idempotent: a second run changes nothing and commits nothing
  const r2 = run();
  assert.equal(r2.status, 0, r2.stderr);
  assert.deepEqual(JSON.parse(fs.readFileSync(dbFile, 'utf8')), after);
  // no irnetfree zone (removed by hand): the script leaves the firewall alone
  fs.writeFileSync(dbFile, JSON.stringify(rows.filter(x => !/^firewall\.irnetfree/.test(x[0]))));
  assert.equal(run().status, 0);
  assert.ok(!JSON.parse(fs.readFileSync(dbFile, 'utf8')).some(x => /irnetfree/.test(x[0])));
});

test('uci config and uci-defaults: the four options, the firewall zone, idempotent', () => {
  const cfg = data['./etc/config/irnetfree'].data.toString();
  for (const opt of ["option enabled '1'", "option port '6969'", "option bind '0.0.0.0'", "option data_dir '/etc/irnetfree'"]) assert.ok(cfg.includes(opt), opt);
  const d = data['./etc/uci-defaults/99-irnetfree'].data.toString();
  assert.match(d, /^if uci -q get firewall\.irnetfree >\/dev\/null; then$/m, 'an upgrade finds the zone and repairs it; a fresh install creates it');
  for (const line of ["set firewall.irnetfree=zone", "set firewall.irnetfree.name='irnetfree'", "add_list firewall.irnetfree.device='IRNetFree'",
    "set firewall.irnetfree.input='ACCEPT'", "set firewall.irnetfree.output='ACCEPT'", "set firewall.irnetfree.forward='REJECT'", "set firewall.irnetfree.masq='0'",
    "set firewall.irnetfree_lan=forwarding", "set firewall.irnetfree_lan.src='lan'", "set firewall.irnetfree_lan.dest='irnetfree'", 'commit firewall']) {
    assert.ok(d.includes(line), line);
  }
  // sing-box's system stack delivers LAN TCP as INPUT on the tun: REJECT here was "UDP passes, no TCP at all" (v1.13.3)
  assert.doesNotMatch(d, /input='REJECT'/, 'input must never be REJECT again');
  assert.match(d, /"\$\(uci -q get firewall\.irnetfree\.input\)" != "ACCEPT"[\s\S]*uci set firewall\.irnetfree\.input='ACCEPT'/, 'and an old zone is repaired on upgrade');
  // <<-EOF strips leading TABS only; a space-indented heredoc body would be fed to uci verbatim
  for (const m of d.matchAll(/^([ \t]+)(set|add_list|commit) /gm)) assert.match(m[1], /^\t+$/, 'heredoc body indented with tabs');
  assert.match(d, /^exit 0\s*$/m, 'uci-defaults must exit 0 or it is kept and re-run forever');
});

test('the QEMU guest script is POSIX sh and ends with the marker the driver looks for', () => {
  const src = fs.readFileSync(path.join(ROOT, 'openwrt', 'ci', 'guest-smoke.sh'), 'utf8');
  assert.match(src, /^#!\/bin\/sh\n/);
  for (const [re, what] of BASHISMS) assert.doesNotMatch(src, re, what);
  assert.match(src, /^set -eu$/m);
  assert.match(src, /say "SMOKE OK"\s*$/, 'the last line is the success marker');
  assert.ok(!src.includes('\r'), 'LF only');
  assert.match(src, /^sh \/tmp\/install\.sh \/tmp\/irnetfree\.ipk$/m, 'the smoke installs with the same installer a user runs');
  // remote control (feat/remote): the modules on the real node, cloudflared from the feed, the dnsmasq drop-in dir
  assert.match(src, /REMOTE SELFTEST OK/, 'the remote modules are exercised on the router\'s node');
  assert.match(src, /^if opkg install cloudflared /m, 'cloudflared is installed from the feed');
  assert.match(src, /grep -h '\^conf-dir=' \/var\/etc\/dnsmasq\.conf\.\*/, 'the drop-in dir is read off dnsmasq\'s generated config, not assumed');
  // the driver's own contract with it
  const drv = fs.readFileSync(path.join(ROOT, 'openwrt', 'ci', 'qemu-smoke.js'), 'utf8');
  assert.match(drv, /SMOKE OK/);
  assert.match(drv, /Please press Enter to activate this console/);
  assert.match(drv, /'\/install\.sh': path\.join\(__dirname, '\.\.', 'install\.sh'\)/, 'and the driver hands the installer to the guest');
});

test('the QEMU smoke proves v1.16.2: 65536 open files for node and both cores, udp_timeout 120, the router\'s DNS block, both cores held past v1.16.1\'s 4096 open files from the LAN with no "too many open files", the drain, the DoH outage and names after it', () => {
  const src = fs.readFileSync(path.join(ROOT, 'openwrt', 'ci', 'guest-smoke.sh'), 'utf8');
  const at = src.indexOf('say "v1.16.2: connect;');
  assert.notEqual(at, -1, 'the v1.16.2 section is gone');
  const v = src.slice(at, src.indexOf('say "SMOKE OK"'));
  assert.match(v, /for p in \$\(pidof node\) \$FD_SB \$FD_X; do/, 'node, the gateway\'s sing-box and the core');
  assert.match(v, /\[ "\$l" = "65536 65536" \]/, 'soft and hard, from /proc/<pid>/limits');
  assert.match(v, /jq -e '\.inbounds\[0\]\.udp_timeout == 120' "\$SB_CFG"/);
  assert.match(v, /\.dns\.enableParallelQuery == true and \.dns\.serveStale == true and \.dns\.serveExpiredTTL == 86400/);
  assert.match(v, /all\(\.timeoutMs == 8000\)/);
  assert.match(v, /judged 'Open files at connect: node \[0-9\]\* of 65536, xray \[0-9\]\* of 65536, sing-box \[0-9\]\* of 65536'/, 'the service says it at connect');
  // the flood: from lan0 through dnsmasq, then TCP connections held, then UDP flows; open files sampled; no EMFILE in a live capture of the log
  assert.match(v, /ip netns exec lan0 "\$@"/);
  assert.match(v, /inlan node \/tmp\/irnf-flood\.js dns 192\.168\.1\.1 1500 "a\$\$" 1 3000 100/);
  assert.match(v, /inlan node \/tmp\/irnf-flood\.js udp 198\.51\.100\.1 30000 300/);
  assert.match(v, /logread -f > \/tmp\/irnf-flood-a\.log/);
  // past the old budget, or the "no EMFILE" below proves nothing: sing-box's TUN keeps at most 1024 UDP sessions
  // (about 2048 open files), so the load that crosses 4096 is TCP — 2400 connections from the LAN, each answered
  // end to end by a sink behind the test's upstream, all held open at once (two open files each in sing-box and xray)
  const tcp = v.search(/inlan node \/tmp\/irnf-flood\.js tcp 198\.51\.100\.10 18090 2400 50 /);
  assert.notEqual(tcp, -1, 'the TCP hold from the LAN');
  assert.match(v, /\( ulimit -H -n 65536 && ulimit -S -n 65536 && exec node \/tmp\/irnf-flood\.js sink 18090 \)/, 'the sink holds 2400 sockets itself');
  // the upstream hands 198.51.100.10 to the sink on loopback (everything else still leaves bound to br-lan) and may open as many files
  assert.match(src, /"route":\{"rules":\[\{"ip_cidr":\["198\.51\.100\.10\/32"\],"action":"route","outbound":"sink","override_address":"127\.0\.0\.1","override_port":18090\}\],"final":"out"\}/);
  assert.match(src, /^\( ulimit -H -n 65536 && ulimit -S -n 65536 && exec sing-box run -c \/tmp\/upstream\.json \) > \/tmp\/upstream\.log 2>&1 &$/m);
  assert.match(v, /\[ "\$\(nofile "\$UP_PID"\)" = "65536 65536" \]/, 'the test\'s own upstream must not run out before the gateway does');
  assert.match(v, /HELD_SB="\$\(fdn "\$FD_SB"\)"; HELD_X="\$\(fdn "\$FD_X"\)"/, 'read while every connection is held');
  assert.match(v, /jq -e '\.echoed == 2400 and \.failed == 0 and \.closedEarly == 0'/, 'every connection answered and none dropped while held');
  const pastSb = v.indexOf('[ "$HELD_SB" -gt 4096 ]');
  const pastX = v.indexOf('[ "$HELD_X" -gt 4096 ]');
  const emfileA = v.indexOf("grep -ci 'too many open files' /tmp/irnf-flood-a.log");
  assert.ok(pastSb > tcp && pastX > tcp, 'sing-box and xray each held more than v1.16.1\'s 4096 at once');
  assert.ok(emfileA > pastSb && emfileA > pastX, 'the "no too many open files" check comes after the proof that the load crossed 4096');
  assert.ok(tcp < v.indexOf('inlan node /tmp/irnf-flood.js udp 198.51.100.1 30000 300'), 'the TCP hold is let go before the UDP flows, whose clock the drain reads');
  assert.match(v, /\[ "\$\(fdn "\$FD_SB"\)" -le \$\(\(PRE_TCP_SB \+ 60\)\) \]/, 'the held connections let go of their files');
  assert.match(v, /\[ "\$PEAK_SB" -lt 32768 \]/, 'well under the limit');
  assert.match(v, /resolves example\.net/);
  // the drain: past 120 s, a fresh session each look, back near the baseline before 200 s (300 s would still hold them)
  assert.match(v, /-lt 125 \]; do sleep 5; done/);
  assert.match(v, /if \[ "\$NOW_SB" -le \$\(\(BASE_SB \+ 60\)\) \]; then DRAINED=1; break; fi/);
  // the owner's failure: DoH black-holed, three tries each, nothing answered, no EMFILE, names back after it
  assert.match(v, /"dnsRemote":\["https:\/\/192\.0\.2\.1\/dns-query"\]/);
  assert.match(v, /inlan node \/tmp\/irnf-flood\.js dns 192\.168\.1\.1 400 "b\$\$" 3 2000 100/);
  assert.match(v, /grep -ci 'too many open files' \/tmp\/irnf-flood-b\.log/);
  // that load stays far under 4096 (dnsmasq's 150 in flight bound it): its open-files checks are said to be a sanity run, not the proof
  const b = v.slice(v.indexOf('irnf-flood-b.log'), v.indexOf('say "v1.16.2: the DoH back'));
  assert.match(b, /a sanity check, not the proof: this load stays far under 4096/);
  assert.doesNotMatch(b, /-gt 4096/, 'no claim of crossing the old budget where nothing crosses it');
  // the outage proven by a name that exists getting no address — not by the flood's answers, which the feed cores never give
  assert.match(v, /out="\$\(inlan nslookup www\.example\.com 192\.168\.1\.1 2>&1 \|\| true\)"/);
  assert.match(v, /a name resolved with the DoH black-holed — the outage was not simulated/);
  assert.doesNotMatch(v, /\.answered \* 4 >= \.sent \* 3/, 'REFUSED from an overflowing dnsmasq is no answer');
  assert.match(v, /resolves example\.org/);
  // the one-time repair on the real store: the owner's shape seeded with the service stopped, repaired and said once
  assert.match(v, /jq 'del\(\.routerRepair\) \| \.settings\.lanBlockQuic = false \| \.settings\.autoConnect = false \| \.settings\.dnsDirect = \["1\.1\.1\.1", "8\.8\.8\.8"\]'/);
  assert.match(v, /since_mark \| grep 'Router settings repaired once' \|\|/);
  assert.match(v, /\.result\.dnsDirect == \["178\.22\.122\.100", "185\.51\.200\.2"\]/);
  assert.match(v, /if since_mark \| grep -q 'Router settings repaired once'; then echo "the repair ran a second time"; exit 1; fi/);
  assert.match(v, /cp \/tmp\/irnf-store\.saved "\$STORE"/, 'the store is put back as it was');
  // the flood script inside: arrow functions only (the bashism check reads heredocs too)
  assert.doesNotMatch(v, /^\s*function\s/m);
});

test('the QEMU smoke proves D3: the in-country resolvers stay in the whole-LAN tunnel, the core’s own query leaves by the WAN (fix/v1161-core)', () => {
  const src = fs.readFileSync(path.join(ROOT, 'openwrt', 'ci', 'guest-smoke.sh'), 'utf8');
  const at = src.indexOf('say "D3: bypass-ir');
  assert.notEqual(at, -1, 'the D3 section is gone');
  const d3 = src.slice(at, src.indexOf('say "SMOKE OK"'));
  // from a LAN client, DNS and HTTPS to them; as dnsmasq's own user, DNS (its upstream) — all dev IRNetFree
  assert.match(d3, /ip route get "\$ip" from 192\.168\.1\.50 iif br-lan ipproto udp dport 53\)/);
  assert.match(d3, /ip route get "\$ip" from 192\.168\.1\.50 iif br-lan ipproto tcp dport 443\)/);
  assert.match(d3, /ip route get "\$ip" ipproto udp dport 53 uid "\$DNSMASQ_UID"\)/);
  assert.match(d3, /\[ "\$DNSMASQ_UID" != 0 \]/, 'dnsmasq runs as a user of its own, or the own-lookup rule would take it out too');
  // …and the service's own DNS to them (the relay link's lookup) leaves by the WAN — UDP 53 of its own user only (review of v1.16.1)
  assert.match(d3, /grep -F 'iif lo' \| grep -F 'uidrange 0-0' \| grep -qE 'ipproto \(udp\|17\) dport 53'/);
  assert.match(d3, /ip route get "\$ip" ipproto udp dport 53 uid 0\)/);
  assert.match(d3, /grep -q "dev \$WANDEV"/);
  assert.match(d3, /ip route get "\$ip" ipproto tcp dport 443 uid 0\)/);
  assert.match(d3, /ip route get "\$ip" ipproto udp dport 53 uid 65534\)/);
  // real packets: root's query from the WAN address, nobody's (setuid before the socket) not
  assert.match(d3, /if \(uid\) process\.setuid\(Number\(uid\)\);\nconst s = require\('dgram'\)\.createSocket\('udp4'\);/);
  assert.match(d3, /node \/tmp\/irnf-own-dns\.js 9\.9\.9\.9 "\$1" \$\{2:-\}/);
  assert.match(d3, /ct2="\$\(own_ct "\$port" 65534\)"/);
  // cloudflared's edge discovery: the unbound lines refused (the control), then an SRV answer through the
  // drop-in the service's own remote api writes, its lines bound to the WAN device
  assert.match(d3, /cf\.dnsmasqDropIn\(\['9\.9\.9\.9', '149\.112\.112\.112'\]\);/);
  assert.match(d3, /the UNBOUND lines answered SRV/);
  assert.match(d3, /luci remote_set '\{"cloudflared":\{"enabled":true,/);
  assert.match(d3, /grep -q "\^server=\/argotunnel\.com\/9\.9\.9\.9@\$WANDEV\\\$"/);
  assert.match(d3, /cf\.dnsmasqDropIn\(\['9\.9\.9\.9', '149\.112\.112\.112'\], process\.argv\[1\]\)/);
  assert.match(d3, /d\.setServers\(\['127\.0\.0\.1'\]\); d\.resolveSrv\('_v2-origintunneld\._tcp\.argotunnel\.com'/);
  assert.match(d3, /until echo "\$out" \| grep -q '"port":7844'; do/);
  assert.match(d3, /luci remote_set '\{"cloudflared":\{"enabled":false\}\}'/);
  // the own-lookup rules go with the gateway
  assert.match(d3, /the own-lookup rules stayed after the D3 disconnect/);
  // Quad9 as the in-country pair is said at warn (field report D3: a desktop's 8.8.8.8 restored on the router)
  assert.match(d3, /since_mark \| grep -E '\(holds public resolvers\|رزولورهای عمومی دارد\) \\\(9\\\.9\\\.9\\\.9, 149\\\.112\\\.112\\\.112\\\)'/);
  // sing-box's own exclusion list: the entry server stays, the resolvers do not
  assert.match(d3, /route_exclude_address \| index\("192\.168\.1\.1\/32"\)/);
  // the config: dns-internal → direct on :53, the direct dial bound to the WAN device; an Iranian name resolves; conntrack shows the WAN source
  assert.match(d3, /\.outboundTag == "direct" and \.port == "53"/);
  assert.match(d3, /\.streamSettings\.sockopt\.interface == \$dev/);
  assert.match(d3, /nslookup www\.digikala\.com 1\.1\.1\.1/);
  assert.match(d3, /\/proc\/net\/nf_conntrack/);
  // and it leaves the router as it found it
  assert.match(d3, /\\"routingMode\\":\\"global\\",\\"dnsDirect\\":\$D3_DIRECT_WAS/);
});

test('the one-line installer is POSIX sh, refuses anything but OpenWrt 24, and takes a local ipk', () => {
  const src = fs.readFileSync(path.join(ROOT, 'openwrt', 'install.sh'), 'utf8');
  assert.match(src, /^#!\/bin\/sh\n/);
  for (const [re, what] of BASHISMS) assert.doesNotMatch(src, re, what);
  assert.ok(!src.includes('\r'), 'LF only');
  assert.match(src, /^set -eu$/m);
  assert.match(src, /\. \/etc\/openwrt_release/);
  assert.match(src, /\t24\.\*\|23\.05\*\) ;;/, '24.x (node 20) and 23.05 (node 18); 25/SNAPSHOT use apk');
  assert.match(src, /opkg install node kmod-tun nftables ip-full unzip ca-bundle$/m, 'the same dependency list as the package');
  assert.match(src, /\[ "\$\{NODE_MAJOR:-0\}" -ge 18 \]/, 'and the node that arrived is checked, not assumed');
  assert.match(src, /IPK="\$\{1:-\}"/, 'a local package as the first argument');
  assert.match(src, /releases\/latest.*grep -o 'https:\/\/\[\^"\]\*_all\\\.ipk'/, 'else the newest release, found without jq');
  assert.match(src, /wget -q -O /, 'uclient-fetch syntax (the busybox wget applet is not on every image)');
  assert.doesNotMatch(src, /wget -qO-/, 'combined short options are not safe on uclient-fetch');
  assert.match(src, /raw\.githubusercontent\.com\/sadrazkh\/Irnetfree_xray-client\/main\/openwrt\/install\.sh/, 'its own one-line URL is in the header');
  // the cores it points to: the app's own download first, the feed's xray-core only as a fallback — the LAN's DNS
  // (REFUSED for HTTPS/SVCB queries, expectedIPs) is verified on xray 26.3.27+, and both feeds carry older builds
  const out = src.split('\n').filter(l => /^echo /.test(l));
  const from = out.findIndex(l => /Cores:/.test(l));
  assert.ok(from >= 0, 'the installer says where the cores come from');
  const cores = out.slice(from, out.findIndex((l, i) => i > from && /Log:/.test(l))).join('\n');
  assert.match(cores, /Settings -> Required files/);
  assert.match(cores, /opkg install xray-core sing-box/);
  assert.ok(cores.indexOf('Required files') < cores.indexOf('opkg install xray-core'), 'Required files is named first');
  assert.match(cores, /26\.3\.27/, 'and why: the version the LAN\'s DNS is verified on');
  assert.match(cores, /fallback/i, 'the feed is the fallback, not an equal choice');
  // Required files is in the :6969 web UI only — LuCI has a Settings tab of its own, without any core download
  assert.match(cores, /web UI[^\n]*Settings -> Required files/, 'the place is named: the web UI the link above opens');
  assert.match(cores, /not LuCI's Settings tab/, 'and it is not LuCI\'s Settings tab');
  // After an upgrade the browser keeps the old LuCI pages: v1.16.0 and older dated every file 1970, the view URLs do
  // not change between versions, so a cached copy stays "fresh" for years and is never asked for again — Ctrl+F5
  // refreshes one page load, not the views LuCI fetches after it. Said every time, not "if the pages look old".
  const upgrade = out.slice(out.findIndex(l => /After an upgrade/.test(l))).join('\n');
  assert.ok(out.some(l => /After an upgrade/.test(l)), 'the installer says what to do in the browser after an upgrade');
  assert.match(upgrade, /log out of LuCI/);
  assert.match(upgrade, /cached (images and )?files/, 'clear the browser\'s cached files — the step that reliably works');
  assert.match(upgrade, /Ctrl\+Shift\+Del/);
  assert.match(upgrade, /phone/, 'and on a phone');
  assert.match(upgrade, /private/, 'a private window: no cache, the quick check');
  assert.match(upgrade, /v1\.16\.0 or older/, 'unconditional coming from a 1970-dated package');
  assert.doesNotMatch(upgrade, /\bif (the )?(LuCI )?pages? (look|show)/i, 'not conditional on noticing old pages — nothing tells the owner they are old');
});

test('LuCI: Services → IRNetFree with four tabs, behind its own ACL', () => {
  const menu = JSON.parse(data['./usr/share/luci/menu.d/luci-app-irnetfree.json'].data.toString());
  const top = menu['admin/services/irnetfree'];
  assert.equal(top.title, 'IRNetFree');
  assert.equal(top.order, 90);
  assert.deepEqual(top.action, { type: 'firstchild' }, 'the entry opens its first tab');
  assert.deepEqual(top.depends, { acl: ['luci-app-irnetfree'] });
  const tabs = Object.keys(menu).filter((k) => k !== 'admin/services/irnetfree');
  assert.deepEqual(tabs.map((k) => [k, menu[k].title, menu[k].order, menu[k].action]), [
    ['admin/services/irnetfree/overview', 'Overview', 10, { type: 'view', path: 'irnetfree/overview' }],
    ['admin/services/irnetfree/settings', 'Settings', 20, { type: 'view', path: 'irnetfree/settings' }],
    ['admin/services/irnetfree/remote', 'Remote access', 30, { type: 'view', path: 'irnetfree/remote' }],
    ['admin/services/irnetfree/log', 'Log', 40, { type: 'view', path: 'irnetfree/log' }]
  ]);
});

test('LuCI ACL: reading and changing are split method by method, one file (the token) is readable, nothing else', () => {
  const acl = JSON.parse(data['./usr/share/rpcd/acl.d/luci-app-irnetfree.json'].data.toString());
  assert.deepEqual(Object.keys(acl), ['luci-app-irnetfree']);
  const a = acl['luci-app-irnetfree'];
  assert.equal(a.description, 'IRNetFree: status, settings and remote access');
  const READ = ['status', 'configs', 'settings_get', 'devices', 'log', 'diagnostics', 'remote_get', 'remote_status'];
  const WRITE = ['connect', 'select', 'disconnect', 'reconnect', 'test', 'subs_update', 'settings_set', 'remote_set',
    'cloudflared_install', 'service'];
  assert.deepEqual(a.read.ubus, { 'luci.irnetfree': READ });
  assert.deepEqual(a.write.ubus, { 'luci.irnetfree': WRITE });
  assert.deepEqual(a.read.file, { '/etc/irnetfree/token': ['read'] }, 'the token file (the web UI link) and no other file');
  assert.equal(a.write.file, undefined, 'no file is writable');
  assert.deepEqual(a.read.uci, ['irnetfree']);
  assert.deepEqual(a.write.uci, ['irnetfree'], 'the web UI port and listen address');
  // every method the rpcd plugin declares is granted exactly once — as reading or as changing
  const plugin = data['./usr/libexec/rpcd/luci.irnetfree'].data.toString();
  const list = JSON.parse(/cat <<'EOF'\n([\s\S]*?)\nEOF/.exec(plugin)[1]);
  assert.deepEqual([...READ, ...WRITE].sort(), Object.keys(list).sort());
  assert.equal(new Set([...READ, ...WRITE]).size, READ.length + WRITE.length, 'no method is both');
});

test('LuCI: every tab\'s view and the shared module ship verbatim, where the menu and the require name point', () => {
  const menu = JSON.parse(data['./usr/share/luci/menu.d/luci-app-irnetfree.json'].data.toString());
  for (const [key, node] of Object.entries(menu)) {
    if (!node.action || node.action.type !== 'view') continue;
    const f = `./www/luci-static/resources/view/${node.action.path}.js`;
    assert.ok(data[f], `${key} opens ${node.action.path}, which is not in the package`);
    assert.equal(data[f].mode, 0o644);
    assert.equal(data[f].data.toString(), fs.readFileSync(path.join(ROOT, 'openwrt/files/luci/view', path.basename(f)), 'utf8').replace(/\r\n/g, '\n'));
    // 'require irnetfree.common' is /luci-static/resources/irnetfree/common.js
    assert.match(data[f].data.toString(), /^'require irnetfree\.common as common';$/m);
  }
  const common = data['./www/luci-static/resources/irnetfree/common.js'];
  assert.equal(common.data.toString(), fs.readFileSync(path.join(ROOT, 'openwrt/files/luci/irnetfree-common.js'), 'utf8').replace(/\r\n/g, '\n'));
  assert.match(common.data.toString(), /rpc\.declare\(\{ object: 'luci\.irnetfree'/);
  // the web UI link the old page had lives on in the Overview
  const overview = data['./www/luci-static/resources/view/irnetfree/overview.js'].data.toString();
  assert.match(overview, /fs\.read\('\/etc\/irnetfree\/token'\)/);
  assert.match(common.data.toString(), /'\?token=' \+ encodeURIComponent\(token\)/);
});
