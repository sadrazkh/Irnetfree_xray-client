'use strict';
/**
 * "Relaunch as administrator" asks UAC FIRST and tears nothing down until the
 * answer is yes. It used to hand the lock over, start `Start-Process -Verb
 * RunAs` fire-and-forget and quit 300 ms later — a cancelled prompt left no app
 * at all, and a connection torn down for nothing. Now one PowerShell run we
 * wait on starts an ELEVATED helper (that is the prompt: cancelled, the run
 * fails), and the helper waits for this process to exit before it starts the
 * copy — which then finds the single-instance lock free. The exec is injected:
 * nothing here runs PowerShell.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { elevatedRelaunchScript, runElevatedRelaunch } = require('../src/main/relaunch');

const decode = (script) => {
  const b64 = /'-EncodedCommand','([A-Za-z0-9+/=]+)'/.exec(script);
  assert.ok(b64, script);
  return Buffer.from(b64[1], 'base64').toString('utf16le');
};

test('the prompt is for an elevated helper that waits for this process, then starts the copy', () => {
  const s = elevatedRelaunchScript({ exe: 'C:\\Program Files\\IRNetFree\\IRNetFree.exe', args: [], pid: 4321 });
  assert.match(s, /^Start-Process -FilePath 'powershell\.exe' -Verb RunAs -WindowStyle Hidden -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','[A-Za-z0-9+/=]+' -ErrorAction Stop$/);
  const inner = decode(s);
  assert.equal(inner, "Wait-Process -Id 4321 -Timeout 60 -ErrorAction SilentlyContinue; Start-Process -FilePath 'C:\\Program Files\\IRNetFree\\IRNetFree.exe'");
});

test('arguments and quotes survive; the pid is a number, never text', () => {
  const inner = decode(elevatedRelaunchScript({ exe: "C:\\Bob's\\app.exe", args: ['.', "--x=it's"], pid: 99 }));
  assert.match(inner, /^Wait-Process -Id 99 /);
  assert.match(inner, /Start-Process -FilePath 'C:\\Bob''s\\app\.exe' -ArgumentList '\.','--x=it''s'$/);
  for (const pid of ['x', '99; Remove-Item', 0, -1, 1.5, undefined]) {
    assert.throws(() => elevatedRelaunchScript({ exe: 'a.exe', args: [], pid }), /pid/, String(pid));
  }
});

test('an accepted prompt resolves; a cancelled one rejects — and the caller tears nothing down', async () => {
  const calls = [];
  await runElevatedRelaunch({ exe: 'a.exe', args: [], pid: 1 }, async (cmd, args) => { calls.push([cmd, args]); return ''; });
  assert.equal(calls[0][0], 'powershell');
  assert.match(calls[0][1][calls[0][1].length - 1], /-Verb RunAs/);
  await assert.rejects(runElevatedRelaunch({ exe: 'a.exe', args: [], pid: 1 }, async () => {
    throw new Error('This command cannot be run due to the error: The operation was canceled by the user.');
  }), /canceled by the user/);
});
