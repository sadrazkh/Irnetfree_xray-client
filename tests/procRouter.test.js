'use strict';
/**
 * The two names of a process, and the parsers that read them off the OS.
 *
 * A connection carries TWO names and they are not the same string:
 *
 *   `name` — what the OS calls the process (Windows `ProcessName` = 'chrome',
 *            lsof's COMMAND, the kernel's `comm`). This is what the advanced
 *            routing rules and the per-process IP cache key on, and it must not
 *            change: a stored rule holds this value.
 *   `exe`  — the image file's leaf name ('chrome.exe'), which is the ONLY thing
 *            sing-box's `process_name` rule matches (it compares
 *            `filepath.Base(ProcessPath)`, exactly, case and all).
 *
 * Handing the per-app picker `name` on Windows produced a rule that could never
 * fire — and in «only» mode that walks the chosen app around the tunnel. So the
 * mapping gets its own pure helper and the OS output gets pure parsers, pinned
 * here per platform.
 *
 * Everything below passes `platform` explicitly: the suite runs on all three
 * OSes and none of these answers may depend on the host it runs on.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  exeNameOf, parseWinConnections, parseLsof, parseSs, aggregateProcesses
} = require('../src/main/procRouter');

/* ------------------------------- exeNameOf ------------------------------- */

test('exeNameOf on win32: the image leaf wins, exactly as the OS spelled it', () => {
  // Get-Process gives the image leaf whenever the process can be opened; its
  // case is the file's own ('Explorer.EXE'), and sing-box compares case-sensitively.
  const table = [
    [{ name: 'chrome', exe: 'chrome.exe' }, 'chrome.exe'],
    [{ name: 'explorer', exe: 'Explorer.EXE' }, 'Explorer.EXE'],
    [{ name: 'OneDrive.Sync.Service', exe: 'OneDrive.Sync.Service.exe' }, 'OneDrive.Sync.Service.exe'],
    [{ name: 'chrome', exe: '  chrome.exe  ' }, 'chrome.exe']
  ];
  for (const [entry, want] of table) {
    assert.equal(exeNameOf(entry, 'win32'), want, JSON.stringify(entry));
  }
});

test('exeNameOf on win32 without an image leaf: .exe unless the name already ends in one', () => {
  // Elevated / other-session processes (svchost, an elevated xray) have no
  // readable Path, so the ProcessName is all there is.
  const table = [
    [{ name: 'xray', exe: '' }, 'xray.exe'],
    [{ name: 'svchost' }, 'svchost.exe'],
    [{ name: 'IRNetFree', exe: '' }, 'IRNetFree.exe'],
    [{ name: 'chrome.exe', exe: '' }, 'chrome.exe'],
    [{ name: 'foo.scr', exe: '' }, 'foo.scr'],
    // dots that are not an extension: the real image is OneDrive.Sync.Service.exe
    [{ name: 'OneDrive.Sync.Service', exe: '' }, 'OneDrive.Sync.Service.exe'],
    [{ name: '', exe: '' }, ''],
    [{}, '']
  ];
  for (const [entry, want] of table) {
    assert.equal(exeNameOf(entry, 'win32'), want, JSON.stringify(entry));
  }
});

test('exeNameOf on darwin decodes lsof’s \\xNN escapes — that is where the spaces went', () => {
  const table = [
    [{ name: 'Google\\x20Chrome' }, 'Google Chrome'],
    [{ name: 'Microsoft\\x20Teams\\x20(work)' }, 'Microsoft Teams (work)'],
    [{ name: 'node' }, 'node'],
    // nothing is appended off Windows: the bundle's binary has no extension
    [{ name: 'Telegram' }, 'Telegram']
  ];
  for (const [entry, want] of table) {
    assert.equal(exeNameOf(entry, 'darwin'), want, JSON.stringify(entry));
  }
});

test('exeNameOf on linux prefers the resolved image, and falls back to the (truncated) comm', () => {
  // /proc/<pid>/comm is capped at 15 characters, which is exactly the name ss
  // reports — 'telegram-deskto' would never match the real binary.
  assert.equal(exeNameOf({ name: 'telegram-deskto', exe: 'telegram-desktop' }, 'linux'), 'telegram-desktop');
  assert.equal(exeNameOf({ name: 'telegram-deskto', exe: '' }, 'linux'), 'telegram-deskto');
  assert.equal(exeNameOf({ name: 'firefox' }, 'linux'), 'firefox');
});

test('exeNameOf never appends .exe off Windows, whatever the host is', () => {
  for (const plat of ['darwin', 'linux', 'freebsd', undefined]) {
    assert.equal(exeNameOf({ name: 'chrome' }, plat), 'chrome', String(plat));
  }
});

/* -------------------------- parseWinConnections -------------------------- */

const WIN_OUT = [
  'claude|25272|140.82.114.22|Claude.exe',
  'chrome|11724|142.250.185.78|chrome.exe',
  'svchost|5004|20.190.160.14|',            // elevated: no readable Path
  'explorer|10908|23.62.61.10|Explorer.EXE',
  '',                                        // blank lines are normal
  '|1234|1.2.3.4|',                          // no name: nothing to route on
  'garbage',                                 // not our format
  'legacy|999|8.8.8.8'                       // a 3-field line still parses
].join('\r\n');

test('parseWinConnections reads the four fields and answers both names for each', () => {
  assert.deepEqual(parseWinConnections(WIN_OUT), [
    { name: 'claude', pid: 25272, remote: '140.82.114.22', exe: 'Claude.exe' },
    { name: 'chrome', pid: 11724, remote: '142.250.185.78', exe: 'chrome.exe' },
    { name: 'svchost', pid: 5004, remote: '20.190.160.14', exe: 'svchost.exe' },
    { name: 'explorer', pid: 10908, remote: '23.62.61.10', exe: 'Explorer.EXE' },
    { name: 'legacy', pid: 999, remote: '8.8.8.8', exe: 'legacy.exe' }
  ]);
});

test('parseWinConnections: an unreadable pid is 0, and empty output is no connections', () => {
  assert.deepEqual(parseWinConnections('name|nope|1.2.3.4|name.exe'), [
    { name: 'name', pid: 0, remote: '1.2.3.4', exe: 'name.exe' }
  ]);
  assert.deepEqual(parseWinConnections(''), []);
  assert.deepEqual(parseWinConnections(undefined), []);
});

/* ------------------------------- parseLsof ------------------------------- */

const LSOF_OUT = [
  'COMMAND     PID  USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME',
  'Google\\x20Chrome 5551 sadra   40u  IPv4 0x9f2a1b3c4d5e6f70      0t0  TCP 192.168.1.5:52344->142.250.185.78:443 (ESTABLISHED)',
  'node             6001 sadra   22u  IPv6 0x9f2a1b3c4d5e6f71      0t0  TCP [2001:db8::5]:52345->[2606:4700::1111]:443 (ESTABLISHED)',
  'ssh              6100 sadra    3u  IPv4 0x9f2a1b3c4d5e6f72      0t0  TCP 127.0.0.1:22 (LISTEN)',   // no ->: not a connection
  'short 1 2 3'
].join('\n');

test('parseLsof reads COMMAND/PID/peer, and on darwin the escaped name is the real one', () => {
  assert.deepEqual(parseLsof(LSOF_OUT, 'darwin'), [
    { name: 'Google\\x20Chrome', pid: 5551, remote: '142.250.185.78', exe: 'Google Chrome' },
    { name: 'node', pid: 6001, remote: '2606:4700::1111', exe: 'node' }
  ]);
});

test('parseLsof on linux upgrades the name through /proc/<pid>/exe when it can', () => {
  const resolved = { 5551: 'chrome', 6001: 'node' };
  assert.deepEqual(parseLsof(LSOF_OUT, 'linux', (pid) => resolved[pid] || ''), [
    { name: 'Google\\x20Chrome', pid: 5551, remote: '142.250.185.78', exe: 'chrome' },
    { name: 'node', pid: 6001, remote: '2606:4700::1111', exe: 'node' }
  ]);
});

test('parseLsof: nothing in, nothing out', () => {
  assert.deepEqual(parseLsof('', 'darwin'), []);
  assert.deepEqual(parseLsof(undefined, 'darwin'), []);
});

/* -------------------------------- parseSs -------------------------------- */

const SS_OUT = [
  'Recv-Q Send-Q Local Address:Port  Peer Address:Port Process',
  '0      0      192.168.1.5:44096   142.250.185.78:443 users:(("telegram-deskto",pid=2431,fd=27))',
  '0      0      [2001:db8::5]:44097 [2606:4700::1111]:443 users:(("firefox",pid=2500,fd=91))',
  '0      0      192.168.1.5:44098   1.1.1.1:443'      // no process column (another user, no root)
].join('\n');

test('parseSs reads the peer and the process column, and asks /proc for the untruncated name', () => {
  const resolved = { 2431: 'telegram-desktop' };
  assert.deepEqual(parseSs(SS_OUT, (pid) => resolved[pid] || ''), [
    { name: 'telegram-deskto', pid: 2431, remote: '142.250.185.78', exe: 'telegram-desktop' },
    { name: 'firefox', pid: 2500, remote: '2606:4700::1111', exe: 'firefox' }
  ]);
});

test('parseSs: nothing in, nothing out', () => {
  assert.deepEqual(parseSs('', () => ''), []);
  assert.deepEqual(parseSs(undefined, () => ''), []);
});

/* --------------------------- aggregateProcesses --------------------------- */

test('aggregateProcesses counts by name, keeps the first exe seen and sorts case-insensitively', () => {
  assert.deepEqual(aggregateProcesses([
    { name: 'chrome', pid: 11724, remote: '1.1.1.1', exe: 'chrome.exe' },
    { name: 'chrome', pid: 11725, remote: '1.0.0.1', exe: 'chrome.exe' },
    { name: 'Claude', pid: 25272, remote: '140.82.114.22', exe: 'Claude.exe' },
    { name: '', pid: 1, remote: '8.8.8.8', exe: '' }
  ]), [
    { name: 'chrome', exe: 'chrome.exe', pid: 11724, count: 2 },
    { name: 'Claude', exe: 'Claude.exe', pid: 25272, count: 1 }
  ]);
});

test('aggregateProcesses: an entry with no exe answers its own name, so a caller always has a value', () => {
  assert.deepEqual(aggregateProcesses([{ name: 'firefox', pid: 7, remote: '1.1.1.1' }]), [
    { name: 'firefox', exe: 'firefox', pid: 7, count: 1 }
  ]);
});
