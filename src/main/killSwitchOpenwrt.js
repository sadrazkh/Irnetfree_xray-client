'use strict';
/**
 * The router's kill switch (v1.16, spec K1–K6): while the VPN is meant to be
 * on and the tunnel is not up, LAN devices' forwarded traffic towards the
 * internet is rejected — so a sing-box that died, a rebuild, a recovery, a
 * reboot never leave the house on the ISP without anyone noticing.
 *
 * Its own nft table, `inet irnetfree_ks`, because the gateway's table (`inet
 * irnetfree`, with its 0x1f1e mark for excluded devices) is deleted on every
 * stop, rebuild and orphan sweep — exactly the moments a kill switch is for.
 * Two chains:
 *
 *   pre  (prerouting, mangle + 5): marks packets from the excluded devices
 *        (`lanBypassMacs`) 0x1f1e, so they pass below whatever the gateway's
 *        own table is doing right now;
 *   fwd  (forward, filter - 5, ahead of fw4): accepts reply-direction packets
 *        (an inbound port-forward's answers), anything through the tunnel
 *        device either way, the marked devices, private / link-local /
 *        multicast / CGNAT destinations (LAN↔LAN, guest↔LAN, the ISP modem's
 *        page) — and rejects the rest with admin-prohibited (a browser fails
 *        at once instead of hanging). The router's own traffic is OUTPUT, not
 *        forward: it is never touched (it must reach NTP, opkg, the servers,
 *        the remote relay).
 *
 * Applied atomically: the whole snippet is validated (`nft -c -f`) before it
 * is loaded, and the `table / delete table / table {…}` header makes the load
 * one replace with no moment without a table. The same text is written to
 * <dataDir>/killswitch.nft when arming and removed when disarming;
 * /etc/init.d/irnetfree-ks (START=19 — with the firewall, before network at
 * 20) replays it at boot, so the block is in place before any interface is
 * up. Not a fw4 include: a broken include would stop fw4 loading the whole
 * firewall. `/etc/init.d/irnetfree-ks stop` lifts it from SSH.
 *
 * Pure enough to test: `run`, the fs and the temp dir are injected.
 */
const os = require('os');
const path = require('path');
const { validMacs } = require('./openwrtNet');

const KS_TABLE = 'inet irnetfree_ks';
const MARK = '0x1f1e';   // the same mark the gateway uses for excluded devices (openwrtNet.BYPASS_MARK)
const PRIVATE4 = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '255.255.255.255'];
const PRIVATE6 = ['::1', 'fc00::/7', 'fe80::/10', 'ff00::/8'];

/** The complete `nft -f` text, idempotent. Only validated MACs ever reach it; `wanDevs` are recorded (sanitised) for the record. */
function ksSnippet({ bypassMacs = [], wanDevs = [] } = {}) {
  const macs = validMacs(bypassMacs);
  const devs = (Array.isArray(wanDevs) ? wanDevs : []).map(d => String(d == null ? '' : d).replace(/[^A-Za-z0-9_.-]/g, '')).filter(Boolean);
  const lines = [
    '# IRNetFree kill switch — written by the service when it arms, replayed by /etc/init.d/irnetfree-ks at boot.',
    '# Lift by hand: /etc/init.d/irnetfree-ks stop   (or turn the VPN off in the UI, which removes this file).'
  ];
  if (devs.length) lines.push(`# wan devices: ${devs.join(' ')}`);
  lines.push(
    `table ${KS_TABLE}`,
    `delete table ${KS_TABLE}`,
    `table ${KS_TABLE} {`,
    `\tset bypass { type ether_addr;${macs.length ? ` elements = { ${macs.join(', ')} };` : ''} }`,
    '\tchain pre {',
    '\t\ttype filter hook prerouting priority mangle + 5; policy accept;',
    `\t\tether saddr @bypass meta mark set ${MARK}`,
    '\t}',
    '\tchain fwd {',
    '\t\ttype filter hook forward priority filter - 5; policy accept;',
    '\t\tct direction reply accept',
    '\t\tiifname "IRNetFree" accept',
    '\t\toifname "IRNetFree" accept',
    `\t\tmeta mark ${MARK} accept`,
    `\t\tip daddr { ${PRIVATE4.join(', ')} } accept`,
    `\t\tip6 daddr { ${PRIVATE6.join(', ')} } accept`,
    '\t\tcounter reject with icmpx type admin-prohibited',
    '\t}',
    '}',
    ''
  );
  return lines.join('\n');
}

/**
 * @param run     (cmd, args) => Promise<string> — tunPlatform.run's shape
 * @param dataDir where the boot snippet lives (<dataDir>/killswitch.nft)
 * @param fs      the fs to use (a test hands in an in-memory one)
 * @param tmpDir  where the text goes for `nft -c -f` / `nft -f`
 */
function createKillSwitch({ run, dataDir, fs: fsImpl, tmpDir } = {}) {
  if (typeof run !== 'function') throw new Error('createKillSwitch: run is required');
  const f = fsImpl || require('fs');
  // router paths are POSIX paths whatever the tests run on; a data dir that is a
  // host path (a test's temp dir) is joined the host's way
  const dir = String(dataDir || '/etc/irnetfree');
  const snippetPath = (dir.startsWith('/') ? path.posix : path).join(dir, 'killswitch.nft');
  const tmpPath = path.posix.join(String(tmpDir || os.tmpdir()).replace(/\\/g, '/'), 'irnetfree-ks.nft');
  let armed = false;
  let current = { bypassMacs: [], wanDevs: [] };

  /** Validate, then load: a snippet nft refuses changes nothing in the kernel. */
  async function load(text) {
    f.writeFileSync(tmpPath, text, { mode: 0o600 });
    await run('nft', ['-c', '-f', tmpPath]);
    await run('nft', ['-f', tmpPath]);
  }

  return {
    snippetPath,
    isArmed: () => armed,
    bypassMacs: () => current.bypassMacs.slice(),
    /** Load the table (validated first) and write the boot snippet. Rejects, with nothing applied or written, when nft refuses it. */
    async arm({ bypassMacs = [], wanDevs = [] } = {}) {
      const text = ksSnippet({ bypassMacs, wanDevs });
      await load(text);
      try { f.mkdirSync(path.dirname(snippetPath), { recursive: true }); } catch { /* exists */ }
      f.writeFileSync(snippetPath, text, { mode: 0o600 });
      armed = true;
      current = { bypassMacs: validMacs(bypassMacs), wanDevs: Array.isArray(wanDevs) ? wanDevs.slice() : [] };
    },
    /** Remove the boot snippet, then the table; a table that is not there is fine. */
    async disarm() {
      try { f.unlinkSync(snippetPath); } catch { /* not there */ }
      try { await run('nft', ['delete', 'table', ...KS_TABLE.split(' ')]); }
      catch (e) {
        if (!/No such file or directory|does not exist/i.test(String((e && e.message) || e))) throw e;
      }
      armed = false;
      current = { bypassMacs: [], wanDevs: [] };
    },
    /** The excluded devices changed under an armed switch: the set and the snippet, atomically. Disarmed: nothing. */
    async setBypassMacs(macs) {
      if (!armed) return;
      await this.arm({ bypassMacs: macs, wanDevs: current.wanDevs });
    }
  };
}

module.exports = { ksSnippet, createKillSwitch, KS_TABLE, MARK, PRIVATE4, PRIVATE6 };
