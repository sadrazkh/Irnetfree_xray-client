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
