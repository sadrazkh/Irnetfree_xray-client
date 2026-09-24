'use strict';
/**
 * "Relaunch as administrator" (Windows), in an order that cannot leave the
 * user with no app.
 *
 * The UAC prompt comes FIRST and nothing is torn down until it was accepted.
 * One PowerShell run, which the caller awaits, starts an ELEVATED helper
 * PowerShell: that start is the prompt, so a cancelled prompt fails this run
 * and the app simply keeps running as it was. The helper waits for THIS
 * process to exit — the caller tears down and quits once the run succeeded —
 * and only then starts the elevated copy, which finds the single-instance lock
 * free. The helper's script travels base64-encoded (-EncodedCommand), so no
 * path or argument has to survive a second round of quoting.
 */
const { execFile } = require('child_process');
const { psArgs } = require('./tunPlatform');

/** Single-quote for PowerShell. */
const psq = (s) => `'${String(s).replace(/'/g, "''")}'`;

/**
 * `cwd`: the copy starts where this one runs — an elevated PowerShell starts in
 * System32, and the dev relaunch (`electron .`) resolves '.' against the cwd.
 * An empty argument goes as a literal "" — Start-Process refuses an empty
 * element, and the other side's command-line parser reads "" as one.
 */
function elevatedRelaunchScript({ exe, args = [], pid, cwd = null, waitSeconds = 60 }) {
  const id = Number(pid);
  if (!Number.isInteger(id) || id <= 0) throw new Error('elevated relaunch: no pid to wait for');
  const argv = args.map(a => (String(a) === '' ? '""' : String(a)));
  const start = `Start-Process -FilePath ${psq(exe)}`
    + (cwd ? ` -WorkingDirectory ${psq(cwd)}` : '')
    + (argv.length ? ` -ArgumentList ${argv.map(psq).join(',')}` : '');
  const inner = `Wait-Process -Id ${id} -Timeout ${Number(waitSeconds) || 60} -ErrorAction SilentlyContinue; ${start}`;
  const encoded = Buffer.from(inner, 'utf16le').toString('base64');
  return `Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Hidden -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','${encoded}' -ErrorAction Stop`;
}

function defaultExec(cmd, args) {
  return new Promise((resolve, reject) => {
    // the prompt waits on the user: generous, but not for ever
    execFile(cmd, args, { windowsHide: true, timeout: 120000 }, (err, stdout, stderr) => {
      if (err) return reject(new Error((stderr || err.message || '').toString().trim() || 'elevation failed'));
      resolve((stdout || '').toString());
    });
  });
}

/** Resolves once the elevated helper is running (the prompt was accepted); rejects when it was not. */
async function runElevatedRelaunch(opts, exec = defaultExec) {
  await exec('powershell', psArgs(elevatedRelaunchScript(opts)));
}

module.exports = { elevatedRelaunchScript, runElevatedRelaunch };
