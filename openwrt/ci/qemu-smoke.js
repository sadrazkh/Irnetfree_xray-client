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
const { spawn } = require('child_process');
const http = require('http');
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
  const qemu = spawn(QEMU, [
    '-M', 'virt', '-cpu', 'cortex-a15', '-smp', '2', '-m', '768', '-nographic', '-no-reboot',
    '-kernel', KERNEL,
    '-netdev', `user,id=n0,net=192.168.1.0/24,host=${HOST_IP},dns=${DNS_IP}`,
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
    // one step per file, and not quiet: a failing download then names itself
    for (const name of ['irnetfree.ipk', 'guest-smoke.sh', 'install.sh']) {
      step(`fetch ${name}`, await sh(con, `wget -O /tmp/${name} http://${HOST_IP}:${port}/${name}`, 120000));
    }
    rc = await sh(con, 'sh /tmp/guest-smoke.sh 2>&1', 25 * 60000);
    if (rc !== 0) console.error(`\nguest-smoke.sh exited ${rc}`);
    else if (!/SMOKE OK/.test(con.buf)) { console.error('\nthe guest script exited 0 but never printed SMOKE OK'); rc = 1; }
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
