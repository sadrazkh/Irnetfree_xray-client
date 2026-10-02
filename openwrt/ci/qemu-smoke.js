#!/usr/bin/env node
'use strict';
/**
 * Boot OpenWrt (armsr/armv7) in QEMU and run openwrt/ci/guest-smoke.sh inside
 * it over the serial console.
 *
 *   node openwrt/ci/qemu-smoke.js --kernel <initramfs-kernel.bin> --ipk <irnetfree_x_all.ipk>
 *
 * The console is driven by markers: every command is followed by
 * `echo <marker>rc=$?`, and the driver waits for the marker to read the exit
 * code. The guest fetches the package and the script from a one-file HTTP
 * server here (slirp shows the host as 192.168.1.2). Exit 0 only when the
 * guest script exited 0 and printed SMOKE OK. Everything the guest prints is
 * streamed to stdout, so a red job has the whole story in its log.
 */
const { spawn, spawnSync } = require('child_process');
const http = require('http');
const net = require('net');
const os = require('os');
const fs = require('fs');
const path = require('path');

function arg(name, def) { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : def; }
const KERNEL = arg('--kernel');
const IPK = arg('--ipk');
const QEMU = arg('--qemu', 'qemu-system-arm');
const HOST_IP = '192.168.1.2';
const DNS_IP = '192.168.1.3';
if (!KERNEL || !IPK) { console.error('usage: qemu-smoke.js --kernel <bin> --ipk <ipk>'); process.exit(2); }

/* ----------------------------- the files the guest fetches ----------------------------- */
const FILES = {
  '/irnetfree.ipk': IPK,
  '/guest-smoke.sh': path.join(__dirname, 'guest-smoke.sh'),
  '/install.sh': path.join(__dirname, '..', 'install.sh')     // the user's installer is what the smoke installs with
};
for (const [u, f] of Object.entries(FILES)) {
  if (!fs.existsSync(f)) { console.error(`missing file for ${u}: ${f}`); process.exit(2); }
}
const srv = http.createServer((req, res) => {
  const f = FILES[req.url.split('?')[0]];
  // every request is logged: the guest's wget says only "exit 4" when it fails
  console.log(`[http] ${req.method} ${req.url} -> ${f ? 200 : 404}`);
  if (!f) { res.writeHead(404); return res.end(); }
  res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': fs.statSync(f).size });
  fs.createReadStream(f).pipe(res);
});

/* ----------------------------- the serial console ----------------------------- */
class Console {
  constructor(proc) {
    this.proc = proc; this.buf = ''; this.waiters = [];
    proc.stdout.on('data', d => this.feed(d));
    proc.stderr.on('data', d => this.feed(d));
  }
  feed(d) {
    const s = d.toString('utf8');
    process.stdout.write(s);
    this.buf += s;
    if (this.buf.length > 4e6) this.buf = this.buf.slice(-2e6);
    for (const w of [...this.waiters]) {
      const m = w.re.exec(this.buf);
      if (m) { this.waiters.splice(this.waiters.indexOf(w), 1); clearTimeout(w.timer); w.resolve(m); }
    }
  }
  waitFor(re, ms) {
    return new Promise((resolve, reject) => {
      const m = re.exec(this.buf);
      if (m) return resolve(m);
      const w = { re, resolve };
      w.timer = setTimeout(() => { this.waiters.splice(this.waiters.indexOf(w), 1); reject(new Error(`timed out after ${ms} ms waiting for ${re}`)); }, ms);
      this.waiters.push(w);
    });
  }
  send(s) { this.proc.stdin.write(s); }
}

/* ----------------------------- the LuCI pages in a real browser ----------------------------- */
// The guest script proves the plugin, the menu and the ubus calls; that the
// pages RUN only a browser can show. After it passed, each IRNetFree tab is
// opened by this runner's Chrome through QEMU's forward to the guest's uhttpd
// (:80), logged in the way LuCI's login form does (a fresh image has no root
// password), and the DOM is read after the scripts ran: a page that threw shows
// LuCI's error box or never leaves "Loading view…". Then LuCI is switched to
// Persian in the guest and the Overview is read again. No Chrome here (a local
// run): skipped, and said so.
// what each tab shows once the service's /luci API answers (the facade, or the
// guest script's stub of it on a branch without the facade)
const LUCI_TABS = {
  overview: /class="irnf-badge"/,                                        // the status, as a badge
  settings: /id="cbi-json"[\s\S]*id="cbi-irnetfree"/,                     // the router settings, then the UCI form
  remote: /<h2[^>]*>(Remote access|دسترسی از راه دور)<\/h2>/,
  log: /id="irnf-log"[^>]*>[^<]{10,}/                                     // lines in the log
};
const LUCI_ERROR = /<h4>(TypeError|ReferenceError|SyntaxError|RangeError|NetworkError|RPCError|DependencyError|InternalError|Runtime error)[^<]*<\/h4>[\s\S]{0,400}/;
// one tab (a page normally takes 10-30 s here): six tabs stay well inside what the 40-min job
// leaves after the guest script, and a Chrome that gives no DOM at all ends the check at once
const TAB_LIMIT_MS = 90000;

/** A loopback port nobody listens on, for the forward to the guest's LuCI. */
function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

function findChrome() {
  for (const c of ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser']) {
    const r = spawnSync('sh', ['-c', `command -v ${c}`], { encoding: 'utf8' });
    if (r.status === 0 && r.stdout.trim()) return r.stdout.trim();
  }
  return null;
}

/** Chrome's DOM of `url` after its scripts ran (virtual time: network waits do not count), and its console. */
function dumpDom(chrome, url) {
  return new Promise((resolve) => {
    const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-chrome-'));
    const p = spawn(chrome, ['--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-first-run',
      '--no-default-browser-check', `--user-data-dir=${profile}`, '--enable-logging=stderr', '--log-level=0',
      '--virtual-time-budget=30000', '--dump-dom', url], { stdio: ['ignore', 'pipe', 'pipe'] });
    let dom = '', log = '', killed = false;
    p.stdout.on('data', (d) => { dom += d; });
    p.stderr.on('data', (d) => { log += d; });
    const timer = setTimeout(() => { killed = true; p.kill('SIGKILL'); }, TAB_LIMIT_MS);
    p.on('error', (e) => { log += e.message; });
    p.on('close', (code) => {
      clearTimeout(timer);
      try { fs.rmSync(profile, { recursive: true, force: true }); } catch { /* best effort */ }
      resolve({ code, dom, log, killed });
    });
  });
}

const textOf = (html) => html.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/g, ' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();

/** One tab: rendered, not stuck, no LuCI error box, no uncaught exception. → a problem, or null. */
async function checkTab(chrome, port, tab, mark) {
  const url = `http://127.0.0.1:${port}/cgi-bin/luci/admin/services/irnetfree/${tab}?luci_username=root&luci_password=`;
  const started = Date.now();
  const r = await dumpDom(chrome, url);
  const secs = Math.round((Date.now() - started) / 1000);
  const view = /<div[^>]*id="view"[^>]*>([\s\S]*)/.exec(r.dom);
  const uncaught = r.log.split('\n').filter((l) => /CONSOLE/.test(l) && /Uncaught|is not defined|is not a function|Cannot read/.test(l));
  for (const l of r.log.split('\n').filter((x) => /CONSOLE/.test(x))) console.log(`  [console] ${l.replace(/^.*?CONSOLE/, 'CONSOLE').slice(0, 300)}`);
  let problem = null;
  if (!r.dom) problem = r.killed ? `Chrome gave no DOM within ${TAB_LIMIT_MS / 1000}s` : `Chrome gave no DOM (exit ${r.code})`;
  else if (LUCI_ERROR.test(r.dom)) problem = `LuCI's error box: ${textOf(LUCI_ERROR.exec(r.dom)[0]).slice(0, 400)}`;
  else if (uncaught.length) problem = `uncaught: ${uncaught[0].slice(0, 300)}`;
  else if (!view) problem = 'no #view in the page (not logged in?)';
  else if (/Loading view/.test(view[1].slice(0, 400))) problem = 'stuck on "Loading view…"';
  else if (/<img[^>]*src="x"/.test(r.dom)) problem = 'a config name went into the page as HTML';
  else if (!mark.test(r.dom)) problem = `the page did not render (no ${mark})`;
  console.log(`LUCI-RENDER ${tab}: ${problem ? 'FAILED — ' + problem : 'ok'} (${secs}s)`);
  console.log(`  ${textOf(view ? view[1] : r.dom).slice(0, 700)}`);
  return { problem, dom: r.dom, noDom: !r.dom };
}

async function luciInBrowser(con, port) {
  const chrome = findChrome();
  if (!chrome) { console.log('\nLUCI-RENDER skipped: no Chrome on this machine'); return 0; }
  console.log(`\n== the LuCI pages in a real browser (${chrome}, forward 127.0.0.1:${port} -> 192.168.1.1:80)`);
  let bad = 0;
  for (const [tab, mark] of Object.entries(LUCI_TABS)) {
    const res = await checkTab(chrome, port, tab, mark);
    // a browser or forward that hangs would hang the same way for every tab: stop, say why
    if (res.noDom) { console.log(`SMOKE FAILED: the LuCI render check — ${res.problem} for the ${tab} tab; stopping here`); return 1; }
    if (res.problem) bad++;
  }
  // Persian: LuCI in fa loads irnetfree.fa.lmo (the tab names) and the pages read <html lang="fa">
  if (await sh(con, "uci set luci.main.lang='fa' && uci commit luci && rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache/", 30000) === 0) {
    const fa = await checkTab(chrome, port, 'overview', /class="irnf-badge"/);
    const missing = ['وضعیت', 'نمای کلی', 'دسترسی از راه دور'].filter((s) => !fa.dom.includes(s));
    if (fa.problem || missing.length) { bad++; console.log(`LUCI-RENDER overview (fa): FAILED — ${fa.problem || 'no ' + missing.join(', ')}`); }
    else console.log('LUCI-RENDER overview (fa): ok — Persian page text and tab names');
    await sh(con, "uci set luci.main.lang='auto' && uci commit luci", 30000);
  }
  else { bad++; console.log('LUCI-RENDER: could not switch LuCI to Persian in the guest'); }
  if (bad) console.log(`SMOKE FAILED: the LuCI render check — ${bad} page(s) failed (the LUCI-RENDER lines above)`);
  else console.log('LUCI-RENDER OK');
  return bad ? 1 : 0;
}

let n = 0;
/** Run one shell line in the guest; resolve with its exit code. */
async function sh(con, cmd, ms) {
  const mark = `IRNF_${++n}_`;
  con.send(`${cmd}; echo ${mark}rc=$?\n`);
  const m = await con.waitFor(new RegExp(`${mark}rc=(\\d+)`), ms);
  return Number(m[1]);
}
function step(name, rc) { if (rc !== 0) throw new Error(`${name} failed with exit code ${rc}`); }

(async () => {
  await new Promise(r => srv.listen(0, '0.0.0.0', r));
  const port = srv.address().port;
  const luciPort = await freePort();
  const qemu = spawn(QEMU, [
    '-M', 'virt', '-cpu', 'cortex-a15', '-smp', '2', '-m', '768', '-nographic', '-no-reboot',
    '-kernel', KERNEL,
    // the forward: this runner's browser reaches the guest's LuCI (uhttpd on the LAN address)
    '-netdev', `user,id=n0,net=192.168.1.0/24,host=${HOST_IP},dns=${DNS_IP},hostfwd=tcp:127.0.0.1:${luciPort}-192.168.1.1:80`,
    '-device', 'virtio-net-pci,netdev=n0'
  ], { stdio: ['pipe', 'pipe', 'pipe'] });
  qemu.on('error', (e) => { console.error(`\ncould not start ${QEMU}: ${e.message}`); process.exit(1); });
  const con = new Console(qemu);
  let rc = 1;
  try {
    await con.waitFor(/Please press Enter to activate this console/, 300000);
    // The "press Enter" line is printed before the console reader is attached,
    // so a single newline can vanish (the second run's did: the prompt only
    // appeared when the final `poweroff` newline reached it). Keep pressing
    // Enter until the prompt answers. The shell also resets the tty when it
    // starts, so nothing else is typed before that prompt.
    let prompt = null;
    for (let i = 0; i < 36 && !prompt; i++) {
      con.send('\n');
      try { prompt = await con.waitFor(/root@OpenWrt:\S*#/, 5000); } catch { /* not yet */ }
    }
    if (!prompt) throw new Error('no shell prompt after activating the console');
    let synced = 1;
    for (let attempt = 0; attempt < 3 && synced !== 0; attempt++) {
      try { synced = await sh(con, 'true', 30000); } catch { con.send('\n'); }
    }
    step('shell', synced);
    // The LAN is static 192.168.1.1 with no gateway; give it slirp's host as
    // the gateway THROUGH netifd (uci), not `ip route add`, which raced the
    // bridge coming up on the third run and is undone by any network reload.
    step('route to the host', await sh(con,
      `uci set network.lan.gateway='${HOST_IP}' && uci set network.lan.dns='${DNS_IP}' && uci commit network && /etc/init.d/network reload; ` +
      `i=0; until ip route show default | grep -q 'via ${HOST_IP}'; do i=$((i+1)); [ $i -lt 60 ] || { ip addr; ip route; false; break; }; sleep 1; done && ` +
      `echo nameserver ${DNS_IP} > /etc/resolv.conf`, 120000));
    // one step per file, not quiet, and three tries: a failing download names
    // itself, and slirp's first connections have dropped for no reason twice
    for (const name of ['irnetfree.ipk', 'guest-smoke.sh', 'install.sh']) {
      let rc = 1;
      for (let attempt = 1; attempt <= 3 && rc !== 0; attempt++) {
        rc = await sh(con, `wget -O /tmp/${name} http://${HOST_IP}:${port}/${name}`, 120000);
        if (rc !== 0) await sh(con, 'sleep 3', 15000);
      }
      step(`fetch ${name}`, rc);
    }
    // the recovery steps (four rebuilds of the gateway on an emulated CPU) are
    // the slow part; the job's own limit is 40 minutes
    rc = await sh(con, 'sh /tmp/guest-smoke.sh 2>&1', 32 * 60000);
    if (rc !== 0) console.error(`\nguest-smoke.sh exited ${rc}`);
    else if (!/SMOKE OK/.test(con.buf)) { console.error('\nthe guest script exited 0 but never printed SMOKE OK'); rc = 1; }
    else rc = await luciInBrowser(con, luciPort);
  } catch (e) {
    console.error('\n' + e.message);
    rc = 1;
  } finally {
    try { con.send('poweroff\n'); } catch { /* gone already */ }
    setTimeout(() => { try { qemu.kill('SIGKILL'); } catch { /* gone */ } }, 8000).unref();
    srv.close();
  }
  process.exitCode = rc;
})();
