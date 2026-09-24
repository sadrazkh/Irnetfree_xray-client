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
const { spawnSync } = require('node:child_process');
const { tar, untar, tgz, untgz } = require('../openwrt/tar');
const { buildIpk, PKG, DEPENDS, PREFIX } = require('../openwrt/build-ipk');

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
    './etc/init.d/irnetfree', './etc/config/irnetfree', './etc/uci-defaults/99-irnetfree',
    './usr/share/luci/menu.d/luci-app-irnetfree.json', './usr/share/rpcd/acl.d/luci-app-irnetfree.json',
    './www/luci-static/resources/view/irnetfree.js'
  ]) assert.ok(files.includes(must), `${must} is not in the package`);
  assert.equal(data['./etc/init.d/irnetfree'].mode, 0o755);
  assert.equal(data['./etc/uci-defaults/99-irnetfree'].mode, 0o755);
  assert.equal(data['./etc/config/irnetfree'].mode, 0o644);
  assert.equal(data[`./${PREFIX}/src/server/server.js`].mode, 0o644);
  assert.ok(!files.some(n => /node_modules|\.map$|\.test\.js$/.test(n)), 'no dev files ship');
  // every file's directory exists as an entry, in order, so opkg never has to invent one
  for (const n of files) {
    const dir = n.slice(0, n.lastIndexOf('/') + 1);
    if (dir !== './') assert.ok(data[dir] && data[dir].type === '5', `no directory entry for ${dir}`);
  }
  assert.equal(data[`./${PREFIX}/src/server/server.js`].data.toString(), fs.readFileSync(path.join(ROOT, 'src/server/server.js')).toString(), 'shipped verbatim');
  // the router-side text files are LF whatever the checkout did (a CRLF shebang is "/bin/sh^M: not found")
  for (const n of ['./etc/init.d/irnetfree', './etc/uci-defaults/99-irnetfree', './etc/config/irnetfree', './www/luci-static/resources/view/irnetfree.js']) {
    assert.ok(!data[n].data.includes('\r'), `${n} carries a carriage return`);
  }
  for (const s of ['./postinst', './prerm']) assert.ok(!control[s].data.includes('\r'), `${s} carries a carriage return`);
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
  ['CONTROL:./postinst', 'postinst'], ['CONTROL:./prerm', 'prerm']
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
  assert.match(s, /procd_set_param respawn/);
  // time for a clean teardown of the gateway on stop (procd's default is 5s, then SIGKILL)
  assert.match(s, /procd_set_param term_timeout 15/);
  assert.match(s, /procd_add_reload_trigger irnetfree/);
  // a zone added after the install (a guest Wi-Fi) is picked up at the next start
  assert.match(s, /sh \/usr\/lib\/irnetfree\/fw-forwardings\.sh >\/dev\/null 2>&1 \|\| true/);
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

test('LuCI: the menu points at the view, the ACL grants the token and nothing else, the view is a LuCI module', () => {
  const menu = JSON.parse(data['./usr/share/luci/menu.d/luci-app-irnetfree.json'].data.toString());
  assert.deepEqual(menu['admin/services/irnetfree'].action, { type: 'view', path: 'irnetfree' });
  assert.deepEqual(menu['admin/services/irnetfree'].depends, { acl: ['luci-app-irnetfree'] });
  const acl = JSON.parse(data['./usr/share/rpcd/acl.d/luci-app-irnetfree.json'].data.toString());
  assert.deepEqual(Object.keys(acl['luci-app-irnetfree'].read.file), ['/etc/irnetfree/token']);
  assert.deepEqual(acl['luci-app-irnetfree'].read.uci, ['irnetfree']);
  assert.equal(acl['luci-app-irnetfree'].write, undefined, 'the page changes nothing');
  const view = data['./www/luci-static/resources/view/irnetfree.js'].data.toString();
  assert.match(view, /^'use strict';\n'require view';\n'require fs';\n'require uci';/);
  assert.match(view, /fs\.read\('\/etc\/irnetfree\/token'\)/);
  assert.match(view, /'\?token=' \+ encodeURIComponent\(token\)/);
});
