#!/usr/bin/env node
'use strict';
/**
 * Build `irnetfree_<version>_all.ipk` — the OpenWrt package.
 *
 *   node openwrt/build-ipk.js [outDir]        (default: dist/)
 *
 * What goes in: the app exactly as checked out (src/, assets/, package.json —
 * the service reads its version from it) under /usr/lib/irnetfree, the procd
 * init script, the uci config, a uci-defaults script that adds the firewall
 * zone once, and three static LuCI files. What stays out: node itself (a feed
 * package, `Depends:`), every core binary (downloaded on the router, or the
 * feed's xray-core/sing-box in /usr/bin), node_modules (the runtime needs
 * none), tests, source maps.
 *
 * Architecture `all`: nothing in here is compiled. `Installed-Size` is the
 * byte total of the files, which is what opkg's free-space check reads.
 */
const fs = require('fs');
const path = require('path');
const { tgz } = require('./tar');

const ROOT = path.join(__dirname, '..');
const PKG = 'irnetfree';
const PREFIX = 'usr/lib/irnetfree';
/**
 * kmod-tun: the TUN device; nftables: `nft`; ip-full: iproute2's `ip` (the
 * gateway's `ip rule … suppress_prefixlength` and `ip route get … mark` checks;
 * busybox's applet has the former but not a reliable latter); unzip: the
 * Downloader's zip step; ca-bundle: TLS to GitHub.
 */
const DEPENDS = ['node', 'kmod-tun', 'nftables', 'ip-full', 'unzip', 'ca-bundle'];

/** Files under `dir`, relative POSIX paths, sorted; dev files skipped. */
function walk(dir, rel = '') {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
    const r = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) { out.push(...walk(path.join(dir, entry.name), r)); continue; }
    if (!entry.isFile() || /\.map$|\.test\.js$/.test(entry.name)) continue;
    out.push({ rel: r, abs: path.join(dir, entry.name) });
  }
  return out;
}

function buildIpk({ root = ROOT, outDir = path.join(ROOT, 'dist'), version, mtime = Number(process.env.SOURCE_DATE_EPOCH) || 0 } = {}) {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const ver = version || pkg.version;
  const data = [];
  const dirs = new Set();
  const ensureDir = (d) => {
    if (!d || d === '.' || dirs.has(d)) return;
    ensureDir(path.posix.dirname(d));
    dirs.add(d);
    data.push({ name: d, dir: true, mode: 0o755 });
  };
  // `lf`: the router-side text files are shipped with LF line endings whatever
  // the checkout did to them — a CRLF shebang is "/bin/sh^M: not found" on ash.
  const lfBytes = (abs) => Buffer.from(fs.readFileSync(abs, 'utf8').replace(/\r\n/g, '\n'), 'utf8');
  const file = (name, abs, mode, { lf = false } = {}) => {
    if (!fs.existsSync(abs)) throw new Error(`build-ipk: missing ${abs}`);
    ensureDir(path.posix.dirname(name));
    data.push({ name, data: lf ? lfBytes(abs) : fs.readFileSync(abs), mode });
  };

  for (const top of ['src', 'assets']) for (const f of walk(path.join(root, top))) file(`${PREFIX}/${top}/${f.rel}`, f.abs, 0o644);
  file(`${PREFIX}/package.json`, path.join(root, 'package.json'), 0o644);

  const F = (n) => path.join(root, 'openwrt', 'files', n);
  const LF = { lf: true };
  file('etc/init.d/irnetfree', F('irnetfree.init'), 0o755, LF);
  file('etc/config/irnetfree', F('irnetfree.config'), 0o644, LF);
  file('etc/uci-defaults/99-irnetfree', F('99-irnetfree.defaults'), 0o755, LF);
  // run by the uci-defaults script and by the init script (see the file)
  file(`${PREFIX}/fw-forwardings.sh`, F('fw-forwardings.sh'), 0o755, LF);
  file('usr/share/luci/menu.d/luci-app-irnetfree.json', F('luci/menu.json'), 0o644, LF);
  file('usr/share/rpcd/acl.d/luci-app-irnetfree.json', F('luci/acl.json'), 0o644, LF);
  file('www/luci-static/resources/view/irnetfree.js', F('luci/irnetfree.js'), 0o644, LF);

  const installed = data.reduce((n, e) => n + (e.data ? e.data.length : 0), 0);
  const control = [
    `Package: ${PKG}`,
    `Version: ${ver}`,
    'Architecture: all',
    'Section: net',
    'Priority: optional',
    'Maintainer: IRNetFree <irnetfree@users.noreply.github.com>',
    `Depends: ${DEPENDS.join(', ')}`,
    `Installed-Size: ${installed}`,
    'Description: IRNetFree as the router: every device behind it goes through the tunnel (Xray, Xray-PattN, sing-box). Web UI on port 6969; LuCI: Services > IRNetFree.',
    ''
  ].join('\n');
  const ctl = [
    { name: 'control', data: control, mode: 0o644 },
    { name: 'conffiles', data: '/etc/config/irnetfree\n', mode: 0o644 },
    { name: 'postinst', data: lfBytes(F('control/postinst')), mode: 0o755 },
    { name: 'prerm', data: lfBytes(F('control/prerm')), mode: 0o755 }
  ];
  const outer = tgz([
    { name: 'debian-binary', data: '2.0\n', mode: 0o644 },
    { name: 'control.tar.gz', data: tgz(ctl, { mtime }), mode: 0o644 },
    { name: 'data.tar.gz', data: tgz(data, { mtime }), mode: 0o644 }
  ], { mtime });

  fs.mkdirSync(outDir, { recursive: true });
  const out = path.join(outDir, `${PKG}_${ver}_all.ipk`);
  fs.writeFileSync(out, outer);
  return { out, files: data.filter(e => !e.dir).map(e => e.name), control, installed };
}

if (require.main === module) {
  const r = buildIpk({ outDir: process.argv[2] ? path.resolve(process.argv[2]) : undefined });
  console.log(`${r.out}  (${r.files.length} files, ${(r.installed / 1048576).toFixed(1)} MB installed)`);
}

module.exports = { buildIpk, PKG, DEPENDS, PREFIX };
