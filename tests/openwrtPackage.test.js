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
  assert.match(c, /^Depends: node, kmod-tun, nftables, unzip, ca-bundle$/m);
  assert.deepEqual(DEPENDS, ['node', 'kmod-tun', 'nftables', 'unzip', 'ca-bundle']);
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

test('the init script: procd, the token, the exact command line, POSIX', () => {
  const s = data['./etc/init.d/irnetfree'].data.toString();
  assert.match(s, /^#!\/bin\/sh \/etc\/rc\.common\n/);
  assert.match(s, /^USE_PROCD=1$/m);
  assert.match(s, /^START=95$/m);
  assert.match(s, /config_load irnetfree/);
  assert.match(s, /head -c 16 \/dev\/urandom \| hexdump -ve '1\/1 "%02x"' > "\$data_dir\/token"/);
  assert.match(s, /procd_set_param command \/usr\/bin\/node --max-old-space-size=160 "\$APP" --host "\$bind" --port "\$port" --data-dir "\$data_dir" --token "\$\(cat "\$data_dir\/token"\)"/);
  assert.match(s, /procd_set_param env IRNETFREE_PLATFORM=openwrt/);
  assert.match(s, /procd_set_param respawn/);
  assert.match(s, /procd_add_reload_trigger irnetfree/);
});

test('uci config and uci-defaults: the four options, the firewall zone, idempotent', () => {
  const cfg = data['./etc/config/irnetfree'].data.toString();
  for (const opt of ["option enabled '1'", "option port '6969'", "option bind '0.0.0.0'", "option data_dir '/etc/irnetfree'"]) assert.ok(cfg.includes(opt), opt);
  const d = data['./etc/uci-defaults/99-irnetfree'].data.toString();
  assert.match(d, /uci -q get firewall\.irnetfree >\/dev\/null \|\| \{/, 'runs once: a second install finds the zone');
  for (const line of ["set firewall.irnetfree=zone", "set firewall.irnetfree.name='irnetfree'", "add_list firewall.irnetfree.device='IRNetFree'",
    "set firewall.irnetfree.input='REJECT'", "set firewall.irnetfree.output='ACCEPT'", "set firewall.irnetfree.forward='REJECT'", "set firewall.irnetfree.masq='0'",
    "set firewall.irnetfree_lan=forwarding", "set firewall.irnetfree_lan.src='lan'", "set firewall.irnetfree_lan.dest='irnetfree'", 'commit firewall']) {
    assert.ok(d.includes(line), line);
  }
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
  // the driver's own contract with it
  const drv = fs.readFileSync(path.join(ROOT, 'openwrt', 'ci', 'qemu-smoke.js'), 'utf8');
  assert.match(drv, /SMOKE OK/);
  assert.match(drv, /Please press Enter to activate this console/);
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
