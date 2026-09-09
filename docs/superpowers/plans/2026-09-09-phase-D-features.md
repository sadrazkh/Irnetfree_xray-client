# Phase D — features — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Run on Opus; D10 in its own Fable session.

**Goal:** The ten additions the owner asked to have planned: start with the OS and auto-connect (D1), an "Auto" target that picks the fastest tested server (D2), system notifications (D3), server switching from the tray (D4), an in-app update download that verifies a checksum (D5), weekly geo/core updates (D6), backup and restore (D7), a speed sparkline (D8), usage figures on chain and pool cards (D9), and per-app split tunnelling under the sing-box TUN (D10).

**Architecture:** Each feature is a small pure module (`autostart.js`, `trayMenu.js`, `appUpdate.js`, `assetUpdater.js`, `backup.js`) plus wiring in both mirrors, or renderer-only (D2, D8, D9). D10 extends `buildTunConfig` with sing-box `process_name` route rules — the only honest per-app routing available to this app (Xray cannot match by process; see `procRouter.js`).

**Tech Stack:** Node 18+ core, Electron 31 (`Notification`, `Tray`, `Menu`, `app.setLoginItemSettings`), `node --test`, sing-box 1.13.14 for `sing-box check`. Branch `feature/phase-D` from `main`. Shipped as v1.5.0 (D10 deferred — see the tag message).

## Global Constraints

- Runtime code uses only Node core modules; `package.json` `dependencies` stays empty (no `electron-updater`).
- `npm test` green and pristine; `npm run validate` green (with `IRNF_SINGBOX_EXE`, D10's TUN shapes pass `sing-box check`).
- `src/server/service.js` mirrors `src/main/main.js`: every handler exists in both (desktop-only ones return `{ ok: false, error: 'desktop-only' }` on the server, as `app:relaunchAdmin` does today).
- New settings: default in BOTH `DEFAULT_SETTINGS`; connection-baked ones (`tunAppMode`, `tunApps`) in `RECONNECT_KEYS` + `set.<key>` in both i18n blocks; renderer reads/writes in `applySettingsToUI()` (app.js 313), `readSettingsForm()` (476), the row's `onchange`.
- Renderer rules: `t()` everywhere, keys once per language, logical CSS, tokens, no inline styles, `[hidden]`. Browser checks: `node src/server/server.js --port 3996 --data-dir %TEMP%\irnf-phaseD`. Never 10808/10809/10085; never kill `IRNetFree.exe`.
- Nothing may change this machine: D1's `schtasks` and D5's installer launch are exercised as ARGUMENT ARRAYS in tests only; D10 never starts a TUN.
- Commits in the owner's name only, no `Co-Authored-By`. Do not bump the version.

Order: D3 first (D1 and the phase-C health watch call `notify()`), then {D1, D2, D4, D8, D9} in parallel, then {D5, D6, D7}, then D10 (Fable).

---

## File map

| File | Responsibility | Tasks |
|---|---|---|
| `src/main/main.js`, `src/server/service.js` | `notify()`, `setAutostart`, auto-connect, tray rebuild, update download, asset updater, backup IPC, per-app TUN opts | D1–D7, D10 |
| `src/main/autostart.js` (new), `tests/autostart.test.js` | `schtasks` argument builders | D1 |
| `src/main/trayMenu.js` (new), `tests/trayMenu.test.js` | grouping for the tray submenu | D4 |
| `src/main/appUpdate.js` (new), `tests/appUpdate.test.js` | `pickUpdateAsset`, `parseSha256Sums`, `sha256File` | D5 |
| `.github/workflows/release.yml` | `SHA256SUMS-<os>.txt` assets | D5 |
| `src/main/assetUpdater.js` (new), `tests/assetUpdater.test.js` | weekly tick; `cmpVersion` moves here | D6 |
| `src/main/downloader.js` | `latestVersion(engineId)` | D6 |
| `src/main/backup.js` (new), `tests/backup.test.js` | export/import bundle | D7 |
| `src/main/tunSingbox.js`, `tests/tunSingbox.test.js` | `apps` in `buildTunConfig`/`writeConfig` | D10 |
| `src/preload/preload.js`, `src/server/web-api.js` | `downloadUpdate`, `exportBackup`, `importBackup` | D5, D7 |
| `src/renderer/*` | switches, Auto row, sparkline, usage spans, per-app section | D1, D2, D3, D5–D10 |

---

### Task D3: system notifications

**Files:**
- Modify: `src/main/main.js` (require line 2; a `notify()` helper after `send()` ≈ 196; calls in `runRecovery` 1248/1300/1339 and the kill-switch branch ≈ 2048), `src/server/service.js` (a no-op `notify`), `index.html`, `app.js`, `i18n.js`

**Interfaces:**
- `notify(title, body)` (main): shown only when `settings.notifications` and `Notification.isSupported()`; silent. Setting `notifications: true`.

- [ ] **Step 1: Helper**

main.js line 2: add `Notification` to the electron destructuring. After `send()`:
```js
/** A desktop notification, when the user wants them. Silent; never throws. */
function notify(title, body) {
  try {
    if (!getSettings().notifications || !Notification.isSupported()) return;
    new Notification({ title, body, silent: true }).show();
  } catch { /* no notification centre */ }
}
```
service.js: `function notify() {}` next to its `send` (the API surface stays identical for the shared call sites).

Both `DEFAULT_SETTINGS`: `notifications: true,` after `autoReconnectOnNetworkChange`.

- [ ] **Step 2: Call sites (main.js and service.js alike; the service's `notify` is a no-op)**

- `runRecovery` right after `send('status', { state: 'reconnecting', … })` when `attempt === 0`:
  `if (attempt === 0) notify('IRNetFree', getSettings().lang === 'en' ? 'Network changed — reconnecting' : 'شبکه عوض شد — در حال اتصال مجدد');`
- `runRecovery` "restored": `notify('IRNetFree', getSettings().lang === 'en' ? 'Connection restored' : 'اتصال برقرار شد');`
- `runRecovery` give-up (before `send('status', { state: 'reconnect-failed' …`): `notify('IRNetFree', getSettings().lang === 'en' ? 'Could not reconnect — open the app' : 'اتصال مجدد ناموفق — برنامه را باز کنید');`
- kill switch engaged (main.js ≈ 2048, inside `if (r && r.ok)`): `notify('IRNetFree', getSettings().lang === 'en' ? 'VPN dropped — internet blocked by the kill switch' : 'اتصال افتاد — اینترنت با کیل‌سوییچ بسته شد');`

- [ ] **Step 3: Setting UI**

`index.html` after the `optNetAuto` switch-row: a switch-row `id="optNotify"` with `data-i18n="notify.title"` / `notify.sub`. i18n fa: `'notify.title': 'اعلان سیستمی', 'notify.sub': 'هنگام قطع، اتصال مجدد یا فعال‌شدن کیل‌سوییچ یک اعلان کوتاه نشان داده می‌شود'`; en: `'notify.title': 'System notifications', 'notify.sub': 'A short notification when the tunnel drops, reconnects, or the kill switch engages'`. `app.js`: `$('#optNotify').checked = s.notifications !== false;` / `notifications: $('#optNotify').checked,` / `$('#optNotify').onchange = () => saveSettings({ notifications: $('#optNotify').checked });`.

- [ ] **Step 4: Tests + commit**

`npm test` — PASS.
```bash
git add src/main/main.js src/server/service.js src/renderer/index.html src/renderer/app.js src/renderer/i18n.js
git commit -m "A desktop notification when the tunnel drops, comes back, gives up, or the kill switch engages"
```

---

### Task D1: start with the OS, hidden, and connect to the last server

**Files:**
- Create: `src/main/autostart.js`, `tests/autostart.test.js`
- Modify: `src/main/main.js` (`createWindow` 292; `store.set('activeServerId', serverId)` 794; `settings:set` 1741; `whenReady` 2004–2140), `src/server/service.js` (auto-connect only), `index.html`, `app.js`, `i18n.js`

**Why the scheduled task:** the Windows build is `requestedExecutionLevel: requireAdministrator` (package.json `build.win`). UAC silently skips Run-key and Startup-folder entries for programs that require elevation, so `app.setLoginItemSettings` can never work on Windows for this app. A scheduled task at logon with "run with highest privileges" is the supported mechanism and what every elevated tray app uses. macOS/Linux use the Electron login item.

**Interfaces:**
- `schtasksCreateArgs(exePath, taskName?)`, `schtasksDeleteArgs(taskName?)`, `schtasksQueryArgs(taskName?)`, `TASK = 'IRNetFree'` (autostart.js).
- Settings `launchAtLogin: false`, `autoConnect: false`; store key `lastServerId`.

- [ ] **Step 1: Failing test**

`tests/autostart.test.js`:
```js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { schtasksCreateArgs, schtasksDeleteArgs, schtasksQueryArgs, TASK } = require('../src/main/autostart');

test('the logon task runs the exe hidden with highest privileges, replacing any old task', () => {
  assert.deepEqual(schtasksCreateArgs('C:\\Apps\\IRNetFree\\IRNetFree.exe'), [
    '/Create', '/TN', TASK, '/SC', 'ONLOGON', '/RL', 'HIGHEST', '/IT', '/F',
    '/TR', '"C:\\Apps\\IRNetFree\\IRNetFree.exe" --hidden'
  ]);
  assert.deepEqual(schtasksDeleteArgs(), ['/Delete', '/TN', TASK, '/F']);
  assert.deepEqual(schtasksQueryArgs(), ['/Query', '/TN', TASK]);
  assert.equal(TASK, 'IRNetFree');
});
```
Run — FAIL.

- [ ] **Step 2: Module**

```js
'use strict';
/**
 * Start with the OS, hidden in the tray.
 *
 * Windows: the app is built with requestedExecutionLevel=requireAdministrator,
 * and a Run-key or Startup-folder entry for an elevated program is SILENTLY
 * skipped by UAC — `app.setLoginItemSettings` can never work here. A scheduled
 * task at logon with "highest privileges" is the supported way. The builders
 * are pure so the arguments are pinned by a test; main.js runs schtasks.
 */
const TASK = 'IRNetFree';

function schtasksCreateArgs(exePath, taskName = TASK) {
  return ['/Create', '/TN', taskName, '/SC', 'ONLOGON', '/RL', 'HIGHEST', '/IT', '/F', '/TR', `"${exePath}" --hidden`];
}
function schtasksDeleteArgs(taskName = TASK) { return ['/Delete', '/TN', taskName, '/F']; }
function schtasksQueryArgs(taskName = TASK) { return ['/Query', '/TN', taskName]; }

module.exports = { TASK, schtasksCreateArgs, schtasksDeleteArgs, schtasksQueryArgs };
```
Run — PASS.

- [ ] **Step 3: main.js**

Requires: `const { schtasksCreateArgs, schtasksDeleteArgs } = require('./autostart');`. Both `DEFAULT_SETTINGS`: `launchAtLogin: false, autoConnect: false,`.

Helper (after `notify`):
```js
/** Register / unregister the OS autostart. Windows: a logon task (see autostart.js). */
function setAutostart(enabled) {
  if (process.platform === 'win32') {
    // The portable build runs from a temp extraction; its real file is in this env var.
    const exe = process.env.PORTABLE_EXECUTABLE_FILE || process.execPath;
    const args = enabled ? schtasksCreateArgs(exe) : schtasksDeleteArgs();
    return new Promise((resolve) => execFile('schtasks', args, { windowsHide: true }, (err, so, se) =>
      resolve({ ok: !err, error: err ? String(se || err.message).trim() : null })));
  }
  try { app.setLoginItemSettings({ openAtLogin: !!enabled, args: ['--hidden'] }); return Promise.resolve({ ok: true }); }
  catch (e) { return Promise.resolve({ ok: false, error: e.message }); }
}
```
`settings:set` (after the kill-switch reaction):
```js
    if ('launchAtLogin' in partial) {
      setAutostart(!!next.launchAtLogin).then((r) => {
        if (!r.ok) send('log', { line: 'Could not change "start with Windows": ' + r.error, level: 'error' });
        else send('log', { line: next.launchAtLogin ? 'IRNetFree will start with the OS' : 'IRNetFree will no longer start with the OS', level: 'info' });
      });
    }
```
`createWindow()`: `const startHidden = process.argv.includes('--hidden');` and `show: !startHidden,` in the `BrowserWindow` options. (Electron shows the window by default; with `show:false` the tray's "Show" and `app.on('activate')` already bring it up.)

`doConnect` line 794: after `store.set('activeServerId', serverId);` add `store.set('lastServerId', serverId);`.

`whenReady`, after `createTray();`:
```js
  // Auto-connect to the last server. Deferred so the window (or the tray) is up
  // first and a failure has somewhere to be shown.
  const boot = getSettings();
  const lastId = store.get('lastServerId', null);
  if (boot.autoConnect && lastId && store.get('servers', []).some(s => s.id === lastId)) {
    setTimeout(() => doConnect(lastId).catch((e) => send('log', { line: 'Auto-connect failed: ' + e.message, level: 'error' })), 1500);
  }
```
service.js: same `lastServerId` write and the same auto-connect block at the end of `createService`'s start-up (the headless server benefits most from it); `launchAtLogin` there is a no-op with a log line.

- [ ] **Step 4: Settings UI**

Two switch-rows after `optNetAuto`: `optLaunchAtLogin` (`login.title` / `login.sub`) and `optAutoConnect` (`autoconn.title` / `autoconn.sub`). i18n fa: `'login.title': 'اجرا با ویندوز', 'login.sub': 'برنامه هنگام ورود به سیستم، پنهان در سینی، اجرا می‌شود (روی ویندوز یک task زمان‌بندی‌شده با دسترسی ادمین ساخته می‌شود)', 'autoconn.title': 'اتصال خودکار', 'autoconn.sub': 'هنگام اجرا به آخرین سروری که وصل بودید وصل می‌شود'`; en: `'login.title': 'Start with the OS', 'login.sub': 'Starts hidden in the tray at logon (on Windows via a scheduled task with administrator rights)', 'autoconn.title': 'Connect automatically', 'autoconn.sub': 'Connects to the last server you used when the app starts'`. app.js: read/write/onchange for both keys.

- [ ] **Step 5: Tests + commit**

`npm test` — PASS.
```bash
git add src/main/autostart.js tests/autostart.test.js src/main/main.js src/server/service.js src/renderer/index.html src/renderer/app.js src/renderer/i18n.js
git commit -m "IRNetFree can start with the OS, hidden, and reconnect to the last server on its own"
```
Fable review: the task name is fixed so a reinstall replaces rather than duplicates; turning the switch off deletes it; the portable exe path.
**Device-verified:** toggle on → `schtasks /Query /TN IRNetFree` lists it; log off/on → tray icon appears without a UAC prompt; toggle off → the task is gone.

---

### Task D2: an "Auto" target that connects to the fastest tested server

**Files:**
- Modify: `src/renderer/app.js` (`renderPicker` 901–995, `connect` 1254, `isPseudo` ≈ 872), `i18n.js`

**Interfaces (renderer):** `AUTO_ID = '__auto__'`; `bestServerId() → id|null` (lowest real-delay `ms` among `ok` results, TCP as fallback); `connectAuto()`.

- [ ] **Step 1: Helpers**

After the `POOL_ID` constant:
```js
const AUTO_ID = '__auto__';
/** The fastest tested server: real delay first, TCP ping as the fallback; null when nothing has been tested. */
function bestServerId() {
  const scored = state.servers.map((s) => {
    const p = state.pings[s.id] || {};
    const real = p.real && p.real.ok ? p.real.ms : null;
    const tcp = p.tcp && p.tcp.ok ? p.tcp.ms : null;
    return { id: s.id, key: real != null ? real : (tcp != null ? 100000 + tcp : null) };
  }).filter(x => x.key != null).sort((a, b) => a.key - b.key);
  return scored.length ? scored[0].id : null;
}
async function connectAuto() {
  let best = bestServerId();
  if (!best) { await pingMany(state.servers.map(s => s.id)); best = bestServerId(); }
  if (!best) return toast(t('t.autoNone'), 'err');
  const s = srvById(best);
  toast(`${t('picker.auto')} → ${s ? s.name : best}`, 'ok');
  return connect(best);
}
```

- [ ] **Step 2: The picker row**

In `renderPicker()` before `if (poolReady()) addRow(POOL_ID, …)`:
```js
  if (state.servers.length >= 2) {
    const row = document.createElement('div');
    row.className = 'picker-item picker-special';
    row.innerHTML = `<span class="q-dot"></span><span class="proto-badge proto-auto">⚡</span><span class="pi-name">${escapeHtml(t('picker.auto'))}</span>`;
    row.onclick = () => { closePicker(); connectAuto(); };
    menu.appendChild(row);
  }
```
`lists.css` (where `.proto-badge.proto-chain` is styled — `grep -n "proto-chain" src/renderer/*.css`): add `.proto-badge.proto-auto { background: var(--okSoft); color: var(--ok); }`.

i18n fa: `'picker.auto': 'خودکار (سریع‌ترین)', 't.autoNone': 'هیچ سروری جواب نداد'`; en: `'picker.auto': 'Auto (fastest)', 't.autoNone': 'No server answered'`.

- [ ] **Step 3: Tests + browser**

`npm test` — PASS (`proto-auto` becomes a styled class in the baseline). Browser 3996 with 3 servers: the picker shows the Auto row first; clicking it runs "test all" then toasts the chosen name and starts a connect (the headless data dir has no core → the connect fails with the usual message; that is fine here).

- [ ] **Step 4: Commit**

```bash
git add src/renderer/app.js src/renderer/lists.css src/renderer/i18n.js
git commit -m "The picker offers Auto: test every server and connect to the fastest"
```

---

### Task D4: switch servers from the tray

**Files:**
- Create: `src/main/trayMenu.js`, `tests/trayMenu.test.js`
- Modify: `src/main/main.js` (`createTray` 322–341; `send()`; the servers handlers 1574–1700)

**Interfaces:**
- `trayGroups(servers, subs, max = 25) → [{ label, items: [{ id, name }] }]` — manual servers first under `''`, then one group per subscription that has servers.
- main: `trayMenuTemplate()`, `refreshTray()`, `setServers(list)`.

- [ ] **Step 1: Failing test**

```js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { trayGroups } = require('../src/main/trayMenu');

test('trayGroups: hand-added first, then each subscription that has servers, capped', () => {
  const servers = [{ id: 'a1', name: 'A1', subId: 'A' }, { id: 'm1', name: 'M1' }, { id: 'b1', name: 'B1', subId: 'B' }, { id: 'a2', name: 'A2', subId: 'A' }, { id: 'x', name: 'X', subId: 'gone' }];
  const subs = [{ id: 'A', name: 'Sub A' }, { id: 'B', name: 'Sub B' }, { id: 'C', name: 'Empty' }];
  assert.deepEqual(trayGroups(servers, subs, 1), [
    { label: '', items: [{ id: 'm1', name: 'M1' }] },
    { label: 'Sub A', items: [{ id: 'a1', name: 'A1' }] },
    { label: 'Sub B', items: [{ id: 'b1', name: 'B1' }] },
    { label: '?', items: [{ id: 'x', name: 'X' }] }
  ]);
  assert.deepEqual(trayGroups([], subs), []);
});
```
Run — FAIL.

- [ ] **Step 2: Module**

```js
'use strict';
/** The servers as tray submenus: hand-added first, then per subscription; `max` per group. */
function trayGroups(servers, subs, max = 25) {
  const list = (servers || []).filter(s => s && s.id);
  const out = [];
  const manual = list.filter(s => !s.subId).slice(0, max).map(s => ({ id: s.id, name: s.name || s.address || s.id }));
  if (manual.length) out.push({ label: '', items: manual });
  const seen = new Set();
  for (const sub of subs || []) {
    const items = list.filter(s => s.subId === sub.id).slice(0, max).map(s => ({ id: s.id, name: s.name || s.address || s.id }));
    seen.add(sub.id);
    if (items.length) out.push({ label: sub.name || sub.url || '?', items });
  }
  const orphan = list.filter(s => s.subId && !seen.has(s.subId)).slice(0, max).map(s => ({ id: s.id, name: s.name || s.id }));
  if (orphan.length) out.push({ label: '?', items: orphan });
  return out;
}
module.exports = { trayGroups };
```
Run — PASS.

- [ ] **Step 3: main.js**

Require `trayGroups`. Replace the menu construction in `createTray()` with `refreshTray()` and add:
```js
function trayMenuTemplate() {
  const en = getSettings().lang === 'en';
  const active = store.get('activeServerId', null);
  const item = (it) => ({ label: (it.id === active ? '● ' : '') + it.name, click: () => doConnect(it.id).catch((e) => send('log', { line: 'Connect failed: ' + e.message, level: 'error' })) });
  const groups = trayGroups(store.get('servers', []), store.get('subscriptions', [])).map((g) => ({
    label: g.label || (en ? 'Servers' : 'سرورها'), submenu: g.items.map(item)
  }));
  return [
    { label: en ? 'Show' : 'نمایش', click: () => { if (mainWindow) mainWindow.show(); } },
    { type: 'separator' },
    ...groups,
    ...(groups.length ? [{ type: 'separator' }] : []),
    { label: en ? 'Disconnect' : 'قطع اتصال', enabled: !!active, click: () => doDisconnect() },
    { type: 'separator' },
    { label: en ? 'Quit' : 'خروج', click: () => { isQuitting = true; app.quit(); } }
  ];
}
function refreshTray() { if (tray) tray.setContextMenu(Menu.buildFromTemplate(trayMenuTemplate())); }
/** Every write of the servers list goes through here so the tray follows it. */
function setServers(list) { store.set('servers', list); refreshTray(); }
```
In `send()`: `if (channel === 'status' || channel === 'subs-updated') refreshTray();` (after the window send). In `registerIpc()` replace each `store.set('servers', …)` inside the `servers:*` handlers (import, add, addWireguard, addProxy, update, delete, clear — `grep -n "store.set('servers'" src/main/main.js` and take only the ones inside those handlers) with `setServers(…)`. `settings:set` with `'lang' in partial` → `refreshTray()`.

- [ ] **Step 4: Tests + commit**

`npm test` — PASS. (The tray cannot be exercised headless; `node --check src/main/main.js`.)
```bash
git add src/main/trayMenu.js tests/trayMenu.test.js src/main/main.js
git commit -m "The tray menu lists the servers by subscription; one click connects"
```

---

### Task D5: download the update and verify it

**Files:**
- Create: `src/main/appUpdate.js`, `tests/appUpdate.test.js`
- Modify: `.github/workflows/release.yml` (checksum step + globs)
- Modify: `src/main/main.js` (`app:checkUpdate` 1893; new `app:downloadUpdate`), `src/server/service.js` (desktop-only stubs), `preload.js`, `web-api.js`, `app.js` (2000–2035), `i18n.js`

**Interfaces:**
- `pickUpdateAsset(assets, platform, arch) → asset|null`; `parseSha256Sums(text) → { [fileName]: hex }`; `sha256File(path) → Promise<hex>`.
- `app:checkUpdate` result gains `asset: { name, url, size } | null` and `sums: [url…]`.
- `app:downloadUpdate` → `{ ok, file }` (progress on `asset-progress` with `component: 'app'`); opens the installer with `shell.openPath`.

- [ ] **Step 1: Failing tests**

```js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'); const os = require('node:os'); const path = require('node:path');
const { pickUpdateAsset, parseSha256Sums, sha256File } = require('../src/main/appUpdate');

const assets = [
  { name: 'IRNetFree-Setup-1.6.0.exe', browser_download_url: 'u1', size: 1 },
  { name: 'IRNetFree-Portable-1.6.0.exe', browser_download_url: 'u2', size: 2 },
  { name: 'IRNetFree-1.6.0-arm64.dmg', browser_download_url: 'u3', size: 3 },
  { name: 'IRNetFree-1.6.0-x64.dmg', browser_download_url: 'u4', size: 4 },
  { name: 'IRNetFree-1.6.0.AppImage', browser_download_url: 'u5', size: 5 },
  { name: 'SHA256SUMS-windows-latest.txt', browser_download_url: 'u6', size: 6 }
];
test('pickUpdateAsset: the installer for this platform and arch', () => {
  assert.equal(pickUpdateAsset(assets, 'win32', 'x64').name, 'IRNetFree-Setup-1.6.0.exe');
  assert.equal(pickUpdateAsset(assets, 'darwin', 'arm64').name, 'IRNetFree-1.6.0-arm64.dmg');
  assert.equal(pickUpdateAsset(assets, 'darwin', 'x64').name, 'IRNetFree-1.6.0-x64.dmg');
  assert.equal(pickUpdateAsset(assets, 'linux', 'x64').name, 'IRNetFree-1.6.0.AppImage');
  assert.equal(pickUpdateAsset([], 'win32', 'x64'), null);
});
test('parseSha256Sums + sha256File agree', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irnf-upd-'));
  const f = path.join(dir, 'a.bin'); fs.writeFileSync(f, 'hello');
  const sums = parseSha256Sums('2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824 *a.bin\nabc  b.bin\n');
  assert.equal(await sha256File(f), sums['a.bin']);
  assert.equal(sums['b.bin'], undefined, 'a malformed line is ignored');
  fs.rmSync(dir, { recursive: true, force: true });
});
```
Run — FAIL.

- [ ] **Step 2: Module**

```js
'use strict';
const fs = require('fs');
const crypto = require('crypto');

/** The release asset that installs on this platform/arch (electron-builder's artifact names, package.json `build`). */
function pickUpdateAsset(assets, platform = process.platform, arch = process.arch) {
  const list = Array.isArray(assets) ? assets : [];
  const find = (re) => list.find(a => a && re.test(String(a.name || ''))) || null;
  if (platform === 'win32') return find(/^IRNetFree-Setup-.*\.exe$/i);
  if (platform === 'darwin') return find(new RegExp(`^IRNetFree-.*-${arch === 'arm64' ? 'arm64' : 'x64'}\\.dmg$`, 'i'));
  return find(/^IRNetFree-.*\.AppImage$/i);
}

/** `sha256sum` output → { name: hex } (64 hex chars, then whitespace, optional '*', the name). */
function parseSha256Sums(text) {
  const out = {};
  for (const m of String(text || '').matchAll(/^([0-9a-f]{64})\s+\*?(\S.*?)\s*$/gim)) out[m[2]] = m[1].toLowerCase();
  return out;
}

function sha256File(file) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    fs.createReadStream(file).on('data', (c) => h.update(c)).on('end', () => resolve(h.digest('hex'))).on('error', reject);
  });
}

module.exports = { pickUpdateAsset, parseSha256Sums, sha256File };
```
Run — PASS.

- [ ] **Step 3: CI produces the sums**

`.github/workflows/release.yml`, in the `build` job after the `Build` step:
```yaml
      - name: Checksums
        shell: bash
        run: |
          cd dist
          ls *.exe *.dmg *.zip *.AppImage *.deb 2>/dev/null | xargs -r sha256sum > "SHA256SUMS-${{ matrix.os }}.txt"
          cat "SHA256SUMS-${{ matrix.os }}.txt"
```
Add `dist/SHA256SUMS-*.txt` to both the `Upload build artifacts` and `Publish to GitHub Release` `files:` lists.

- [ ] **Step 4: main.js**

Requires: `const { pickUpdateAsset, parseSha256Sums, sha256File } = require('./appUpdate');`, `const { downloadFile } = require('./downloader');` (add to the existing downloader require). A `getText(url)` next to `getJSON` (same redirect-following GET, resolving the body as a string).

`app:checkUpdate`: in the `ok: true` object add
```js
        asset: (() => { const a = pickUpdateAsset(rel.assets); return a ? { name: a.name, url: a.browser_download_url, size: a.size } : null; })(),
        sums: (rel.assets || []).filter(a => /^SHA256SUMS.*\.txt$/i.test(a.name)).map(a => a.browser_download_url)
```
New handler:
```js
  // Download the installer for this platform into the temp dir, verify it
  // against the release's SHA256SUMS when they exist, and hand it to the OS.
  // The app keeps running: the user quits when the installer asks.
  ipcMain.handle('app:downloadUpdate', async (e, info) => {
    if (!info || !info.asset || !info.asset.url) return { ok: false, error: 'no installer for this platform' };
    const dir = path.join(app.getPath('temp'), 'IRNetFree-update');
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, info.asset.name);
    try {
      await downloadFile(info.asset.url, file, (p) => send('asset-progress', { component: 'app', pct: p }));
      let verified = false;
      for (const url of info.sums || []) {
        const sums = parseSha256Sums(await getText(url).catch(() => ''));
        if (!sums[info.asset.name]) continue;
        const have = await sha256File(file);
        if (have !== sums[info.asset.name]) { fs.rmSync(file, { force: true }); return { ok: false, error: 'checksum mismatch — the download was discarded' }; }
        verified = true; break;
      }
      send('log', { line: `Update downloaded: ${info.asset.name}` + (verified ? ' (checksum verified)' : ' (no checksum published for it)'), level: 'info' });
      if (process.platform !== 'win32') { try { fs.chmodSync(file, 0o755); } catch { /* dmg */ } }
      await shell.openPath(file);
      return { ok: true, file, verified };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  });
```
service.js: `'app:downloadUpdate': () => ({ ok: false, error: 'update download is desktop-only' }),`. preload/web-api: `downloadUpdate: (info) => …invoke('app:downloadUpdate', info)`.

- [ ] **Step 5: Renderer**

`app.js` `$('#btnDownloadUpdate').onclick` becomes:
```js
$('#btnDownloadUpdate').onclick = async () => {
  const url = (updateInfo && updateInfo.url) || 'https://github.com/sadrazkh/Irnetfree_xray-client/releases/latest';
  if (!updateInfo || !updateInfo.asset || !window.api.downloadUpdate) return window.api.openExternal(url);
  const btn = $('#btnDownloadUpdate'), st = $('#updateStatus');
  btn.disabled = true;
  st.textContent = t('about.downloading') + ' 0%';
  const res = await window.api.downloadUpdate({ asset: updateInfo.asset, sums: updateInfo.sums });
  btn.disabled = false;
  if (!res || !res.ok) { st.textContent = t('about.downloadFailed') + (res && res.error ? ': ' + res.error : ''); st.className = 'update-status warn'; return; }
  st.textContent = res.verified ? t('about.installerOpened') : t('about.installerOpenedUnverified');
  st.className = 'update-status ok';
};
```
In the existing `onAssetProgress` handler (`grep -n onAssetProgress src/renderer/app.js`) add: `if (d.component === 'app') { const st = $('#updateStatus'); if (st) st.textContent = t('about.downloading') + ' ' + Math.round(d.pct) + '%'; }`.
i18n fa: `'about.downloading': 'در حال دانلود نصب‌کننده', 'about.downloadFailed': 'دانلود ناموفق', 'about.installerOpened': 'نصب‌کننده باز شد (checksum تأیید شد) — برنامه را ببندید و نصب را ادامه دهید', 'about.installerOpenedUnverified': 'نصب‌کننده باز شد (checksum منتشر نشده بود)'`; en: `'about.downloading': 'Downloading the installer', 'about.downloadFailed': 'Download failed', 'about.installerOpened': 'Installer opened (checksum verified) — quit the app to continue', 'about.installerOpenedUnverified': 'Installer opened (no checksum was published)'`.

- [ ] **Step 6: Tests + commit**

`npm test` — PASS.
```bash
git add src/main/appUpdate.js tests/appUpdate.test.js .github/workflows/release.yml src/main/main.js src/server/service.js src/preload/preload.js src/server/web-api.js src/renderer/app.js src/renderer/i18n.js
git commit -m "Update from inside the app: the installer is downloaded, checked against the release checksums and opened"
```
Fable review: a checksum mismatch must delete the file and never open it; without published sums the UI must say so.

---

### Task D6: weekly geo and core updates

**Files:**
- Create: `src/main/assetUpdater.js`, `tests/assetUpdater.test.js`
- Modify: `src/main/downloader.js` (add `latestVersion(engineId)`), `src/main/main.js` (move `cmpVersion` out; wire), `src/server/service.js`, `index.html`, `app.js`, `i18n.js`

**Interfaces:**
- `cmpVersion(a, b)` exported from `assetUpdater.js` (moved from main.js ≈ line 1985; main imports it).
- `class AssetUpdater({ getSettings, getCheckedAt, setCheckedAt, download(component), installed(id), currentVersion(id), latestVersion(id), busy(), onLog, now })` with `due(nowMs)`, `tick() → { ran, deferred?, done: string[] }`, `start(everyMs = 6h)`, `stop()`.
- Setting `autoUpdateAssets: 'off' | 'weekly'` (default `'weekly'`); store key `assetsCheckedAt`.

- [ ] **Step 1: Failing tests**

```js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { AssetUpdater, cmpVersion, WEEK_MS } = require('../src/main/assetUpdater');

function make(over) {
  const log = [], dl = [];
  let checkedAt = 0, now = 10 * WEEK_MS;
  const u = new AssetUpdater(Object.assign({
    getSettings: () => ({ autoUpdateAssets: 'weekly' }),
    getCheckedAt: () => checkedAt, setCheckedAt: (t) => { checkedAt = t; },
    download: async (c) => { dl.push(c); }, installed: (id) => id !== 'sing-box',
    currentVersion: async (id) => (id === 'xray' ? '26.3.27' : '26.9.1'),
    latestVersion: async (id) => (id === 'xray' ? '26.4.1' : '26.9.1'),
    busy: () => false, onLog: (l) => log.push(l), now: () => now
  }, over || {}));
  return { u, dl, log, set: (t) => { now = t; }, checked: () => checkedAt };
}
test('cmpVersion', () => { assert.ok(cmpVersion('26.4.1', '26.3.27') > 0); assert.equal(cmpVersion('1.6.0', '1.6.0'), 0); assert.ok(cmpVersion('v1.6', '1.10') < 0); });
test('due once a week; geo always, a core only when newer; installed cores only', async () => {
  const h = make();
  assert.deepEqual(await h.u.tick(), { ran: true, done: ['geo', 'xray'] });
  assert.deepEqual(h.dl, ['geo', 'xray']);
  assert.equal(h.checked(), 10 * WEEK_MS);
  assert.deepEqual(await h.u.tick(), { ran: false });
  h.set(11 * WEEK_MS + 1);
  assert.equal((await h.u.tick()).ran, true);
});
test('off: never; busy (connected): deferred without moving the stamp; a failing download is logged, not fatal', async () => {
  assert.deepEqual(await make({ getSettings: () => ({ autoUpdateAssets: 'off' }) }).u.tick(), { ran: false });
  const b = make({ busy: () => true });
  assert.deepEqual(await b.u.tick(), { ran: false, deferred: true });
  assert.equal(b.checked(), 0);
  const f = make({ download: async (c) => { if (c === 'geo') throw new Error('net'); } });
  assert.deepEqual(await f.u.tick(), { ran: true, done: ['xray'] });
  assert.ok(f.log.some(l => /Geo update failed: net/.test(l)));
});
```
Run — FAIL.

- [ ] **Step 2: Module**

```js
'use strict';
const WEEK_MS = 7 * 24 * 3600 * 1000;

/** Numeric dotted compare; a leading v is ignored; missing parts are 0. */
function cmpVersion(a, b) {
  const pa = String(a || '').replace(/^v/i, '').split('.').map(x => parseInt(x, 10) || 0);
  const pb = String(b || '').replace(/^v/i, '').split('.').map(x => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d; }
  return 0;
}

/**
 * Keep the geo files and the installed cores fresh without anyone asking.
 * Once a week, never while a tunnel is up (a core is never swapped under a
 * running connection — the attempt is deferred to the next tick), and a
 * failure is a log line, not a stuck timer.
 */
class AssetUpdater {
  constructor(o) {
    this.o = o;
    this.timer = null;
    this.now = o.now || (() => Date.now());
  }
  due(nowMs) {
    if (this.o.getSettings().autoUpdateAssets !== 'weekly') return false;
    return nowMs - (Number(this.o.getCheckedAt()) || 0) >= WEEK_MS;
  }
  async tick() {
    const nowMs = this.now();
    if (!this.due(nowMs)) return { ran: false };
    if (this.o.busy()) return { ran: false, deferred: true };
    const done = [];
    try { await this.o.download('geo'); done.push('geo'); } catch (e) { this.o.onLog('Geo update failed: ' + e.message, 'warn'); }
    for (const id of ['xray', 'xray-pattn', 'sing-box']) {
      if (!this.o.installed(id)) continue;
      try {
        const cur = await this.o.currentVersion(id), latest = await this.o.latestVersion(id);
        if (cur && latest && cmpVersion(latest, cur) > 0) { await this.o.download(id); done.push(id); }
      } catch (e) { this.o.onLog(`Update check failed for ${id}: ` + e.message, 'warn'); }
    }
    this.o.setCheckedAt(nowMs);
    return { ran: true, done };
  }
  start(everyMs = 6 * 3600 * 1000) {
    this.stop();
    this.timer = setInterval(() => this.tick().catch(() => {}), everyMs);
    if (this.timer.unref) this.timer.unref();
    setTimeout(() => this.tick().catch(() => {}), 30000).unref();   // half a minute after launch
  }
  stop() { if (this.timer) { clearInterval(this.timer); this.timer = null; } }
}
module.exports = { AssetUpdater, cmpVersion, WEEK_MS };
```
Run — PASS.

- [ ] **Step 3: `downloader.latestVersion`**

In `Downloader` (downloader.js) add:
```js
  /** The latest release tag of an engine, without a leading v. */
  async latestVersion(engineId) {
    const url = engineId === 'sing-box'
      ? 'https://api.github.com/repos/SagerNet/sing-box/releases/latest'
      : Downloader.releaseApiUrl(engineId);
    const rel = await getJSON(url);
    return String(rel.tag_name || '').replace(/^v/i, '').trim();
  }
```

- [ ] **Step 4: Wire (main.js)**

Remove main.js's own `cmpVersion` and import it: `const { AssetUpdater, cmpVersion } = require('./assetUpdater');`. Both `DEFAULT_SETTINGS`: `autoUpdateAssets: 'weekly',`. In `whenReady` after `downloader = new Downloader(...)`:
```js
  assetUpdater = new AssetUpdater({
    getSettings, getCheckedAt: () => store.get('assetsCheckedAt', 0), setCheckedAt: (t) => store.set('assetsCheckedAt', t),
    download: (c) => downloader.download(c).then(() => { if (c !== 'geo') { xray.forgetVersions(); stats.setBin(xray.anyBin()); } }),
    installed: (id) => !!assetStatus()[id],
    currentVersion: (id) => xray.version(id),          // sing-box: see step 5
    latestVersion: (id) => downloader.latestVersion(id),
    busy: () => !!(xray.running || (tun && tun.active)),
    onLog: (line, level) => send('log', { line, level })
  });
  assetUpdater.start();
```
(`let assetUpdater = null;` at module level; `xray.version('sing-box')` — check `XrayManager.version` handles the sing-box binary's `version` output; if it throws, wrap `currentVersion` to return `''` for sing-box so it is skipped.) `settings:set` with `'autoUpdateAssets' in partial`: nothing to re-arm (the tick checks the setting). service.js: identical block after its downloader.

- [ ] **Step 5: UI**

A select row in the "فایل‌های موردنیاز" card: `optAutoUpdateAssets` with options `off`/`weekly` (`assets.auto.off` / `assets.auto.weekly`, label `assets.auto`). i18n fa: `'assets.auto': 'به‌روزرسانی خودکار فایل‌ها', 'assets.auto.off': 'خاموش', 'assets.auto.weekly': 'هفتگی (فقط وقتی وصل نیستید)'`; en: `'assets.auto': 'Update files automatically', 'assets.auto.off': 'Off', 'assets.auto.weekly': 'Weekly (only while disconnected)'`. app.js read/write/onchange.

- [ ] **Step 6: Tests + commit**

`npm test` — PASS.
```bash
git add src/main/assetUpdater.js tests/assetUpdater.test.js src/main/downloader.js src/main/main.js src/server/service.js src/renderer/index.html src/renderer/app.js src/renderer/i18n.js
git commit -m "Geo files and installed cores update themselves once a week, never under a live tunnel"
```

---

### Task D7: backup and restore

**Files:**
- Create: `src/main/backup.js`, `tests/backup.test.js`
- Modify: `src/main/main.js` + `src/server/service.js` (IPC `backup:export`, `backup:import`), `preload.js`, `web-api.js`, `index.html` (About card), `app.js`, `i18n.js`

**Interfaces:**
- `exportBundle({ version, store: { servers, subscriptions, chains, pool, settings }, usage }) → object`
- `importBundle(bundle, current) → { next: { servers, subscriptions, chains, pool, settings, usage }, added: { servers, subscriptions, chains, pool } }` — merges by id, never drops what is there; throws on a foreign file.
- IPC `backup:export → string` (pretty JSON), `backup:import(text) → { ok, added }`; renderer `exportBackup()`, `importBackup(text)`.

- [ ] **Step 1: Failing tests**

```js
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { exportBundle, importBundle } = require('../src/main/backup');

const cur = { servers: [{ id: 's1', outbound: {} }], subscriptions: [{ id: 'A', url: 'https://a' }], chains: [], pool: [], settings: { lang: 'fa', socksPort: 10808 }, usage: { s1: { down: 1, up: 1 } } };

test('export carries everything and says what it is', () => {
  const b = exportBundle({ version: '1.6.0', store: cur, usage: cur.usage });
  assert.equal(b.app, 'IRNetFree'); assert.equal(b.format, 1); assert.equal(b.version, '1.6.0');
  assert.deepEqual(b.servers, cur.servers); assert.deepEqual(b.usage, cur.usage);
  assert.match(b.exportedAt, /^\d{4}-\d{2}-\d{2}T/);
});
test('import merges by id, keeps what is there, overlays settings, refuses foreign files', () => {
  const b = exportBundle({ version: '1.6.0', store: {
    servers: [{ id: 's1', outbound: {} }, { id: 's2', outbound: {} }, { id: 'bad' }],
    subscriptions: [{ id: 'B', url: 'https://b' }], chains: [{ id: 'c1' }], pool: [{ id: 'p1' }],
    settings: { socksPort: 20808, theme: 'light' }
  }, usage: { s2: { down: 5, up: 5 } } });
  const r = importBundle(b, cur);
  assert.deepEqual(r.added, { servers: 1, subscriptions: 1, chains: 1, pool: 1 });
  assert.deepEqual(r.next.servers.map(s => s.id), ['s1', 's2']);
  assert.deepEqual(r.next.settings, { lang: 'fa', socksPort: 20808, theme: 'light' });
  assert.deepEqual(r.next.usage, { s1: { down: 1, up: 1 }, s2: { down: 5, up: 5 } });
  assert.throws(() => importBundle({ app: 'other' }, cur), /not an IRNetFree backup/);
});
```
Run — FAIL.

- [ ] **Step 2: Module**

```js
'use strict';
const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);

function exportBundle({ version, store, usage }) {
  const s = store || {};
  return {
    app: 'IRNetFree', format: 1, version: version || '', exportedAt: new Date().toISOString(),
    servers: s.servers || [], subscriptions: s.subscriptions || [], chains: s.chains || [], pool: s.pool || [],
    settings: isObj(s.settings) ? s.settings : {}, usage: isObj(usage) ? usage : {}
  };
}

/** Merge a bundle into the current data: new ids are added, existing ones kept, settings overlaid. */
function importBundle(bundle, current) {
  if (!isObj(bundle) || bundle.app !== 'IRNetFree' || bundle.format !== 1) throw new Error('not an IRNetFree backup');
  const c = current || {};
  const merge = (have, incoming, keep) => {
    const ids = new Set((have || []).map(x => x && x.id));
    const add = (incoming || []).filter(x => x && x.id && !ids.has(x.id) && keep(x));
    return { list: [...(have || []), ...add], n: add.length };
  };
  const servers = merge(c.servers, bundle.servers, (s) => isObj(s.outbound));
  const subscriptions = merge(c.subscriptions, bundle.subscriptions, (s) => typeof s.url === 'string');
  const chains = merge(c.chains, bundle.chains, () => true);
  const pool = merge(c.pool, bundle.pool, () => true);
  return {
    next: {
      servers: servers.list, subscriptions: subscriptions.list, chains: chains.list, pool: pool.list,
      settings: Object.assign({}, isObj(c.settings) ? c.settings : {}, isObj(bundle.settings) ? bundle.settings : {}),
      usage: Object.assign({}, isObj(c.usage) ? c.usage : {}, isObj(bundle.usage) ? bundle.usage : {})
    },
    added: { servers: servers.n, subscriptions: subscriptions.n, chains: chains.n, pool: pool.n }
  };
}
module.exports = { exportBundle, importBundle };
```
Run — PASS.

- [ ] **Step 3: IPC (main.js; service.js identical)**

```js
  ipcMain.handle('backup:export', () => JSON.stringify(exportBundle({
    version: app.getVersion(),
    store: { servers: store.get('servers', []), subscriptions: store.get('subscriptions', []), chains: getChains(), pool: getPool(), settings: getSettings() },
    usage: usage ? usage.totals : {}
  }), null, 2));
  ipcMain.handle('backup:import', (e, text) => {
    let bundle;
    try { bundle = JSON.parse(String(text || '')); } catch { return { ok: false, error: 'not JSON' }; }
    let r;
    try {
      r = importBundle(bundle, { servers: store.get('servers', []), subscriptions: store.get('subscriptions', []), chains: getChains(), pool: getPool(), settings: getSettings(), usage: usage ? usage.totals : {} });
    } catch (err) { return { ok: false, error: err.message }; }
    store.assign({ servers: r.next.servers.map(migrateStoredServer), subscriptions: r.next.subscriptions, chains: r.next.chains, pool: r.next.pool, settings: r.next.settings });
    if (usage) { usage.totals = r.next.usage; usage.dirty = true; usageStore.set('totals', usage.totals); usage.markSaved(); }
    return { ok: true, added: r.added };
  });
```
(service.js uses its `appVersion` instead of `app.getVersion()`; `migrateStoredServer` is already imported in both.) preload/web-api: `exportBackup: () => …invoke('backup:export')`, `importBackup: (text) => …invoke('backup:import', text)`.

- [ ] **Step 4: Renderer**

About card (`index.html` ≈ 651): a `row-gap` with `<button class="btn ghost" id="btnBackupExport" data-i18n="backup.export">` and `<button class="btn ghost" id="btnBackupImport" data-i18n="backup.import">` plus `<input type="file" id="backupFile" accept=".json,application/json" class="vis-hidden" />`.
app.js:
```js
$('#btnBackupExport').onclick = async () => {
  const text = await window.api.exportBackup();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  a.download = 'irnetfree-backup-' + new Date().toISOString().slice(0, 10) + '.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
};
$('#btnBackupImport').onclick = () => $('#backupFile').click();
$('#backupFile').onchange = async () => {
  const f = $('#backupFile').files[0];
  if (!f) return;
  const res = await window.api.importBackup(await f.text());
  $('#backupFile').value = '';
  if (!res || !res.ok) return toast(t('backup.failed') + (res && res.error ? ': ' + res.error : ''), 'err');
  const data = await window.api.init();
  state.servers = data.servers || []; state.subscriptions = data.subscriptions || []; state.settings = data.settings || {};
  state.chains = data.chains || []; state.pool = data.pool || []; state.usage = data.usage || {};
  applySettingsToUI(); renderServers(); renderPicker(); renderSubs(); renderChains(); renderPool(); renderAdvanced();
  toast(`${t('backup.done')}: ${res.added.servers} / ${res.added.subscriptions} / ${res.added.chains} / ${res.added.pool}`, 'ok');
};
```
i18n fa: `'backup.export': 'پشتیبان‌گیری (JSON)', 'backup.import': 'بازیابی از فایل', 'backup.done': 'بازیابی شد (سرور / ساب / زنجیره / استخر)', 'backup.failed': 'بازیابی ناموفق'`; en: `'backup.export': 'Back up (JSON)', 'backup.import': 'Restore from file', 'backup.done': 'Restored (servers / subs / chains / pool)', 'backup.failed': 'Restore failed'`.

- [ ] **Step 5: Tests + browser + commit**

`npm test` — PASS. Browser 3996: export downloads a JSON; importing it back reports `0 / 0 / 0 / 0` (nothing new) and keeps the list.
```bash
git add src/main/backup.js tests/backup.test.js src/main/main.js src/server/service.js src/preload/preload.js src/server/web-api.js src/renderer/index.html src/renderer/app.js src/renderer/i18n.js
git commit -m "Settings, servers, subscriptions, chains, pool and usage can be exported to one JSON and restored from it"
```

---

### Task D8: a speed sparkline on the home page

**Files:**
- Modify: `src/renderer/index.html` (readouts, after `.stat-row` ≈ 142), `app.js` (`onStats` 3412, `resetTraffic` 3430), `home.css`

- [ ] **Step 1: Markup + CSS**

After the closing `</div>` of `.stat-row` (before `<div class="traffic-row" …>`): `<canvas id="speedSpark" class="spark" width="360" height="40"></canvas>`.
`home.css`: `.spark { inline-size: 100%; block-size: 40px; display: block; margin-block: 4px 8px; }`

- [ ] **Step 2: Renderer**

Near `resetTraffic`:
```js
const SPARK_N = 60;
const hist = { down: [], up: [] };
function pushHist(down, up) {
  hist.down.push(Number(down) || 0); hist.up.push(Number(up) || 0);
  if (hist.down.length > SPARK_N) { hist.down.shift(); hist.up.shift(); }
}
/** Sixty seconds of speed, two lines, drawn once a second — one canvas, no DOM. */
function drawSpark() {
  const c = $('#speedSpark');
  if (!c) return;
  const ctx = c.getContext('2d'), W = c.width, H = c.height;
  ctx.clearRect(0, 0, W, H);
  const css = getComputedStyle(document.documentElement);
  const max = Math.max(1, ...hist.down, ...hist.up);
  for (const [arr, tok] of [[hist.down, '--accent'], [hist.up, '--ok']]) {
    if (arr.length < 2) continue;
    ctx.beginPath();
    ctx.strokeStyle = css.getPropertyValue(tok).trim();
    ctx.lineWidth = 1.5;
    arr.forEach((v, i) => { const x = (i / (SPARK_N - 1)) * W, y = H - 1 - (v / max) * (H - 2); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
    ctx.stroke();
  }
}
```
In `onStats` after the `#upSpeed` write: `pushHist(s.downSpeed, s.upSpeed); drawSpark();`. In `resetTraffic()`: `hist.down.length = 0; hist.up.length = 0; drawSpark();`. In `applySkin()` and the theme apply (`grep -n "^function applyTheme" src/renderer/app.js`): call `drawSpark()` at the end so the colours follow the tokens.

- [ ] **Step 3: Tests + browser + commit**

`npm test` — PASS (`speedSpark` is in the markup). Browser 3996: the canvas is present and empty when disconnected.
```bash
git add src/renderer/index.html src/renderer/app.js src/renderer/home.css
git commit -m "A sixty-second speed sparkline under the readouts"
```

---

### Task D9: usage figures on chain and pool cards

**Files:**
- Modify: `src/renderer/app.js` (`renderChains` 2783, `renderPool` 2967), `lists.css`

Requires B1's `applyUsageDisplays()` and `data-usage`.

- [ ] **Step 1: Chain cards**

In `renderChains()` card markup, inside `.chain-card-head` after `.chain-pings`: `<span class="srv-usage" data-usage="chain:${chain.id}" title="${escapeHtml(t('srv.usage'))}">${usageLabel('chain:' + chain.id)}</span>`.

- [ ] **Step 2: Pool rows**

In `renderPool()`, find where each entry row is built (`grep -n "pool-row\|poolRow" src/renderer/app.js`); add next to the target label: `<span class="srv-usage" data-usage="${escapeHtml(e.target)}" title="${escapeHtml(t('srv.usage'))}">${usageLabel(e.target)}</span>` (pool totals are keyed by the target id — a server id or `chain:<id>` — see `tagMapFor` in usage.js).

- [ ] **Step 3: Tests + browser + commit**

`npm test` — PASS. Browser 3996 with `usage.json` holding `{"totals":{"chain:<id>":{"down":2048,"up":100}}}`: the chain card shows `↓2 KB·↑100 B`.
```bash
git add src/renderer/app.js src/renderer/lists.css
git commit -m "Chain and pool cards show how much has gone through them"
```

---

### Task D10: per-app split under the sing-box TUN — Fable

**Files:**
- Modify: `src/main/tunSingbox.js` (`buildTunConfig` 66–82, `writeConfig` 270), `tests/tunSingbox.test.js`
- Modify: `src/main/settingsMeta.js`, both `DEFAULT_SETTINGS`, `main.js` + `service.js` (`myTun.start` opts ≈ 862), `scripts/validate-configs.js`
- Modify: `index.html`, `app.js`, `i18n.js`, `settings.css`

**Why:** Xray cannot match by process (procRouter.js explains the IP approximation). sing-box's TUN CAN — `process_name` rules are evaluated on the packet's owning process on Windows, macOS and Linux — so "these apps go around the VPN" / "only these apps use it" is finally honest, for the sing-box backend.

**Interfaces:**
- `buildTunConfig({ …, apps: { mode: 'exclude'|'only', names: string[] } | null })`: `exclude` → `route.rules = [{ process_name, outbound: 'direct' }]`; `only` → `[{ process_name, outbound: 'socks-out' }]` and `route.final = 'direct'`; both add `{ type: 'direct', tag: 'direct' }`. Byte-stable when `apps` is null.
- Settings `tunAppMode: 'off'|'exclude'|'only'`, `tunApps: []` (reconnect keys).
- Rule: `exclude` is IGNORED (logged) under `leakGuard: 'strict'` — the strict firewall blocks exactly what the excluded apps would send.

- [ ] **Step 1: Failing tests**

```js
test('buildTunConfig: apps null keeps the shape; exclude routes the names direct; only inverts', () => {
  const base = buildTunConfig({ socksPort: 10808 });
  assert.deepEqual(buildTunConfig({ socksPort: 10808, apps: null }), base);
  assert.deepEqual(buildTunConfig({ socksPort: 10808, apps: { mode: 'exclude', names: [] } }), base, 'no names: nothing to route');
  const ex = buildTunConfig({ socksPort: 10808, apps: { mode: 'exclude', names: ['Telegram.exe', ' steam.exe '] } });
  assert.deepEqual(ex.route.rules, [{ process_name: ['Telegram.exe', 'steam.exe'], outbound: 'direct' }]);
  assert.equal(ex.route.final, 'socks-out');
  assert.deepEqual(ex.outbounds.map(o => o.tag), ['socks-out', 'direct']);
  const only = buildTunConfig({ socksPort: 10808, apps: { mode: 'only', names: ['chrome.exe'] } });
  assert.deepEqual(only.route.rules, [{ process_name: ['chrome.exe'], outbound: 'socks-out' }]);
  assert.equal(only.route.final, 'direct');
});
```
Run — FAIL.

- [ ] **Step 2: Builder**

```js
function buildTunConfig({ socksPort, excludeIps = [], ipv6 = false, strict = false, stack = 'system', mtu = 1500, interfaceName = TUN_IF, apps = null } = {}) {
  void ipv6;
  const inbound = { type: 'tun', tag: 'tun-in' };
  …unchanged…
  const outbounds = [{ type: 'socks', tag: 'socks-out', server: '127.0.0.1', server_port: socksPort, version: '5' }];
  const route = { final: 'socks-out', auto_detect_interface: true };
  // Per-app split: sing-box matches the packet's owning process, which Xray
  // cannot. `direct` leaves by the physical interface (auto_detect_interface);
  // its DNS still goes to the TUN resolver, so an excluded app resolves
  // through the tunnel and only its traffic goes around it.
  const names = apps && Array.isArray(apps.names) ? apps.names.map(n => String(n || '').trim()).filter(Boolean) : [];
  if (names.length && (apps.mode === 'exclude' || apps.mode === 'only')) {
    outbounds.push({ type: 'direct', tag: 'direct' });
    if (apps.mode === 'exclude') route.rules = [{ process_name: names, outbound: 'direct' }];
    else { route.rules = [{ process_name: names, outbound: 'socks-out' }]; route.final = 'direct'; }
  }
  return { log: { level: 'warn', timestamp: false }, inbounds: [inbound], outbounds, route };
}
```
(Key order: keep `final` before `auto_detect_interface` and add `rules` after — the byte-stable test compares the null case only.) `writeConfig(socksPort, excludeIps, opts, interfaceName)`: pass `apps: opts.apps || null`.
Run — PASS.

- [ ] **Step 3: Settings + wiring**

`settingsMeta.js` `RECONNECT_KEYS`: after `'blockUdpInProxyMode',` add `'tunAppMode', 'tunApps',`. Both `DEFAULT_SETTINGS`: `tunAppMode: 'off', tunApps: [],`. i18n `set.tunAppMode` / `set.tunApps` in both languages (`'روتینگ برنامه‌ها زیر TUN'` / `'برنامه‌های انتخاب‌شده'`; `'Per-app routing under TUN'` / `'Selected apps'`).
main.js at the `myTun.start(...)` call: the 4th argument gains
```js
            apps: appsForTun(settings, myTun)
```
with the helper next to `makeTun`:
```js
/** The per-app rule for this tunnel, or null: sing-box only; `exclude` is refused under the strict guard. */
function appsForTun(settings, tunInstance) {
  const mode = settings.tunAppMode;
  const names = Array.isArray(settings.tunApps) ? settings.tunApps : [];
  if (mode !== 'exclude' && mode !== 'only') return null;
  if (!names.length) return null;
  if (tunInstance.backendId !== 'sing-box') { send('log', { line: 'Per-app routing needs the sing-box TUN backend — ignored', level: 'warn' }); return null; }
  if (mode === 'exclude' && settings.leakGuard === 'strict') { send('log', { line: 'Per-app exclude is not possible under the strict guard (it blocks exactly that traffic) — ignored', level: 'warn' }); return null; }
  return { mode, names };
}
```
Same in service.js. `scripts/validate-configs.js`: add the `exclude` and `only` TUN shapes to the `IRNF_SINGBOX_EXE` block.

- [ ] **Step 4: UI**

In the TUN card (near `#tunBackendCards`): three option cards for `tunAppMode` (reuse `renderOptionCards('tunAppMode', 'tunAppModeCards', …)` — a `vis-hidden` `<select id="tunAppMode">` with `off/exclude/only` options carrying `data-i18n="tunapp.off|exclude|only"` labels of the form `title — description`), a `<textarea id="tunApps" class="input" rows="3" data-i18n-ph="tunapp.ph">` (one name per line), and a `<button class="btn ghost" id="btnTunAppsPick" data-i18n="tunapp.pick">` that loads `listProcesses()` and appends a chosen name (reuse `processOptions()` inside a small `<select>` shown under the textarea). A hint `tunapp.strictNote` shown when `leakGuard === 'strict'` and mode is `exclude`. i18n both languages: `tunapp.title`, `tunapp.off`, `tunapp.exclude`, `tunapp.only`, `tunapp.ph`, `tunapp.pick`, `tunapp.strictNote`, `tunapp.needsSingbox`.
app.js: `applySettingsToUI` → select value + textarea (`(s.tunApps || []).join('\n')`), `renderSettingCards()` includes the new card set; `readSettingsForm` → `tunAppMode`, `tunApps: $('#tunApps').value.split(/\r?\n/).map(x => x.trim()).filter(Boolean)`; onchange → `saveSettings({...})` (this is a reconnect key: the existing pending-reconnect dialog handles it).

- [ ] **Step 5: Tests + validate + commit**

`npm test` — PASS; `set IRNF_SINGBOX_EXE=… && npm run validate` — the two new TUN shapes pass `sing-box check`.
```bash
git add src/main/tunSingbox.js tests/tunSingbox.test.js src/main/settingsMeta.js src/main/main.js src/server/service.js scripts/validate-configs.js src/renderer/index.html src/renderer/app.js src/renderer/i18n.js src/renderer/settings.css
git commit -m "Under the sing-box TUN, chosen apps can go around the tunnel or be the only ones inside it"
```
**Device-verified:** exclude `chrome.exe` → C1's self-test in Chrome's context is not possible; instead: `curl` (not excluded) shows the VPN IP at ipinfo, Chrome shows the ISP IP; DNS for both = tunnel peer (adapter DNS unchanged). Then `only chrome.exe`: the reverse.

---

## Phase gate

- `npm test` green, pristine; `npm run validate` green (and with `IRNF_SINGBOX_EXE`).
- Fable reviews: D1, D5; D10 Fable-implemented.
- Device checklists: D1 (task exists / gone), D4 (tray submenus), D5 (a real update on a test box), D10.
- Merge `feature/phase-D`, tag v1.6.0. README: add a row per feature to the features table and a paragraph under the relevant section (autostart under "نصب و اجرا", Auto under "شروع سریع", backup under "نسخه و به‌روزرسانی", per-app under "حالت اتصال").
