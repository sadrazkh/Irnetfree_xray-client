# Phase A — close the gaps v1.3.0 left open — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the seven small items the v1.3.0 ledger left open: the README for that batch, two code-hygiene fixes, a network change that lands during the first connect, a usage bar that tells 95% from 10%, a way to clear usage history, and a file list that includes sing-box.

**Architecture:** Every change is local. The only one on the connect path (A3) reuses the existing recovery entry point (`recoverFromNetworkChange`) and the watcher's own pure `fingerprint()`; it adds no new state machine. A5 adds one method to `UsageMeter`, one IPC channel in both mirrors, one button. A7 moves a hard-coded file list into `assets.js` so a test can assert it covers every engine.

**Tech Stack:** Node 18+ core only, Electron 31 for the desktop, `node --test`. Branch `feature/phase-A` from `main` at v1.3.0. Tag at the end: v1.3.1 (the owner tags).

## Global Constraints

- Runtime code uses only Node core modules; `package.json` `dependencies` stays empty.
- `node --test "tests/*.test.js"` (559 tests at v1.3.0) stays green **and its output stays pristine** — no warnings, no experimental Node APIs.
- `src/server/service.js` mirrors `src/main/main.js`: a change to the connect path or a handler in one belongs in the other, in the same commit.
- A new setting needs a default in BOTH `DEFAULT_SETTINGS` objects (`src/main/main.js` ≈ line 89, `src/server/service.js` line 43). If it is baked into the running connection it goes into `RECONNECT_KEYS` (`src/main/settingsMeta.js`) AND gets `set.<key>` in both the `fa` and `en` blocks of `src/renderer/i18n.js` (`tests/settingsMeta.test.js` enforces it). No task in this phase adds a setting.
- Every string on screen goes through `data-i18n` / `t()`; every key is defined exactly once per language (`tests/renderer.test.js` enforces it). Persian is RTL: CSS uses logical properties only; colours only via tokens (`--accent`, `--ok`, `--warn`, `--danger`, `--ink3`, `--line`); no inline `style=` in `index.html`; `[hidden]` hides.
- Renderer changes are verified in the browser through the headless server, which serves the identical UI: `node src/server/server.js --port 3999 --data-dir %TEMP%\irnf-phaseA`. **Never** use ports 10808/10809/10085 and **never** kill `IRNetFree.exe` — the owner's own instance runs on this machine.
- Nothing here may touch the machine's real network (no TUN, no `netsh`, no firewall rule, no adapter DNS, no admin relaunch).
- Commits in the repository owner's name only — **no `Co-Authored-By` trailer**. Subject: one plain sentence about the user-visible change; body: why.
- Do not bump the version.

Parallel batches: {A1, A2, A4, A6} · {A5, A7} · A3 last (it touches the connect path; a Fable review of its diff follows).

---

## File map

| File | Responsibility | Tasks |
|---|---|---|
| `README.md` | features table, usage section, settings reference | A1 |
| `src/main/parser.js` | drop the second copy of two helpers | A2 |
| `tests/parser.test.js` | guard against duplicate top-level declarations | A2 |
| `src/main/main.js`, `src/server/service.js` | A3 snapshot/compare around `doConnect`; A5 `usage:clear`; A7 file list | A3, A5, A7 |
| `src/main/netWatcher.js` | already exports `fingerprint` — used by A3 | A3 |
| `src/renderer/lists.css` | usage bar colours; clickable usage span | A4, A5 |
| `src/main/usage.js`, `tests/usage.test.js` | `UsageMeter.clear(id)` | A5 |
| `src/preload/preload.js`, `src/server/web-api.js` | `clearUsage` | A5 |
| `src/renderer/index.html`, `src/renderer/app.js`, `src/renderer/i18n.js` | clear-usage button; utility classes | A5, A6 |
| `src/renderer/styles.css` | utility classes replacing inline styles | A6 |
| `tests/renderer.test.js` | "no inline style" guard | A6 |
| `src/main/assets.js`, `tests/assets.test.js` | `downloadedFileNames(platform)` | A7 |

---

### Task A1: README for the v1.3.0 batch

**Files:**
- Modify: `README.md` (features table lines 57–88; "📊 آمار و تست" section at line 742; settings reference table after line 860)

**Why:** v1.3.0 shipped subscription grouping, bold selected config synced both ways, lifetime per-config usage in `usage.json`, option cards in Settings, TUN as the default mode and the mode picker fix — and only the skin table was updated.

- [ ] **Step 1: Add three rows to the features table**

Insert after the row that starts with `| **ساب‌اسکریپشن** |` (line ≈ 65):

```markdown
| **گروه‌بندی سرورها** | لیست سرورها به تفکیک منبع نشان داده می‌شود: «افزوده‌شده به‌دست خودتان» اول، بعد هر ساب‌اسکریپشن با نام و تعداد خودش؛ کانفیگ انتخاب‌شده در لیست و در انتخابگر صفحهٔ خانه هم‌زمان پررنگ می‌شود و انتخاب در هر کدام در دیگری هم اعمال می‌شود |
| **مصرف دائمی هر کانفیگ** | حجم دانلود/آپلودی که تا امروز از هر سرور، زنجیره یا عضو استخر رفته — در برابر قطع‌ووصل و بستن برنامه می‌ماند (فایل جداگانهٔ `usage.json`، هر ۳۰ ثانیه ذخیره) و روی کارت هر سرور نشان داده می‌شود |
| **کارت‌های تنظیمات** | گزینه‌هایی که پیامد دارند (بک‌اند TUN، سطح گارد نشتی، حالت اتصال) به‌جای دراپ‌داون خالی، کارت با آیکون، عنوان و توضیح‌اند؛ اگر بک‌اند نصب نباشد همان‌جا می‌گوید چه چیزی را از «فایل‌های موردنیاز» نصب کنید |
```

- [ ] **Step 2: Change the TUN row to say it is the default**

In the row `| **حالت TUN** |`, replace `تونل کردن **کل ترافیک سیستم**` with `**پیش‌فرض.** تونل کردن **کل ترافیک سیستم**`.

- [ ] **Step 3: Add a "مصرف هر کانفیگ" subsection**

Insert immediately before the line `### تست‌های توسعه‌دهنده` (line ≈ 751):

```markdown
### مصرف هر کانفیگ (Lifetime usage)

شمارنده‌های هسته با هر اتصال از صفر شروع می‌شوند، پس «این نشست چقدر رفت» تنها چیزی بود که برنامه می‌توانست بگوید. حالا هر ۵ ثانیه اختلاف شمارنده‌ها به مجموع دائمیِ همان کانفیگ اضافه می‌شود — با این قاعده که شمارنده‌ای که **کم** شده یعنی هسته دوباره بالا آمده و خودِ عدد جدید همان اختلاف است، پس نه بایتی در ری‌استارت گم می‌شود و نه دوبار شمرده می‌شود. مجموع‌ها در `usage.json` (کنار `store.json`) هر ۳۰ ثانیه و در هر قطع/خروج ذخیره می‌شوند و با حذف کانفیگ پاک می‌شوند. زنجیره زیر شناسهٔ خودش شمرده می‌شود، نه زیر آخرین هاپش.
```

- [ ] **Step 4: Fix the settings-reference default for TUN**

In the settings reference table (after line ≈ 860) find the row for `حالت TUN` / `tunMode`. If its default column says `false` or `خاموش`, change it to `true` (`روشن`). If no such row exists, add after the `پورت آمار (API)` row:

```markdown
| حالت TUN | `روشن` | کل سیستم از تونل می‌رود؛ بدون بک‌اند نصب‌شده یا بدون دسترسی ادمین، اتصال با پیام «چه چیزی را نصب کن» رد می‌شود |
| اعمال حالت ساده زیر روتینگ پیشرفته | `خاموش` | `advancedUseMode` — دور زدن ایران/چین زیرِ قانون‌های خودتان هم اعمال شود |
```

- [ ] **Step 5: Check the anchors still resolve**

Run: `grep -c "مصرف هر کانفیگ\|گروه‌بندی سرورها\|کارت‌های تنظیمات" README.md`
Expected: `3` or more.

- [ ] **Step 6: Commit**

```bash
git add README.md
git commit -m "README catches up with v1.3.0: grouped servers, lifetime usage, setting cards, TUN by default"
```

---

### Task A2: parser.js declares two helpers twice

**Files:**
- Modify: `src/main/parser.js:971-991`
- Test: `tests/parser.test.js`

**Why:** `asList` and `repairWgDnsFields` are declared twice (lines 950/957 and 972/979). JavaScript takes the last declaration silently, so nothing breaks today — and nothing would say so if the two copies drifted apart.

- [ ] **Step 1: Write the failing guard test**

`tests/parser.test.js` imports only parser functions. Add at the top, after `const assert = require('node:assert/strict');`:

```js
const fs = require('node:fs');
const path = require('node:path');
```

and at the end of the file:

```js
test('parser.js declares each top-level function exactly once', () => {
  // JavaScript keeps the LAST declaration and says nothing; two copies drift.
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'parser.js'), 'utf8');
  const names = [...src.matchAll(/^function ([A-Za-z0-9_$]+)\s*\(/gm)].map(m => m[1]);
  const dup = names.filter((n, i) => names.indexOf(n) !== i);
  assert.deepEqual(dup, [], 'declared more than once');
});
```

- [ ] **Step 2: Run it to see it fail**

Run: `node --test tests/parser.test.js`
Expected: FAIL — `dup` is `['asList', 'repairWgDnsFields']`.

- [ ] **Step 3: Delete the second copy**

Delete lines 971–991 of `src/main/parser.js`: the block that starts with the comment
`/** A list field from a hand-editable store: anything that is not an array is empty. */` followed by
`function asList(v) { return Array.isArray(v) ? v : []; }` and the second `repairWgDnsFields` up to and including its closing `}` — i.e. the SECOND occurrence of each. Keep the first (lines 949–969). After the edit, `grep -n "^function asList\|^function repairWgDnsFields" src/main/parser.js` prints exactly two lines.

- [ ] **Step 4: Run the tests**

Run: `npm test`
Expected: all pass (560 now).

- [ ] **Step 5: Commit**

```bash
git add src/main/parser.js tests/parser.test.js
git commit -m "parser.js declared two helpers twice; a test now keeps every declaration single"
```

---

### Task A3: a network that moves during the first connect is invisible

**Files:**
- Modify: `src/main/main.js` (`doConnect` line ≈ 671, the watcher start at line ≈ 985; requires at line 32)
- Modify: `src/server/service.js` (`doConnect` line 626, watcher start line 894, requires line 41)
- No unit test possible (main/service are not importable); verification below.

**Why:** `startNetWatcher()` runs at the END of `doConnect()`, so the watcher's baseline is whatever the network is when the connect finishes. A Wi-Fi that re-associates or a lease that renews while the tunnel is being built leaves the tunnel built for the old gateway, the watcher happy with the new one, and nobody to notice. The fix reuses the watcher's pure `fingerprint()` (exported from `netWatcher.js`) and the existing recovery entry point.

**Interfaces:**
- Consumes: `fingerprint(interfaces, ignoreInterface)` from `src/main/netWatcher.js`; `isOwnTunInterface` (already imported in both files); `recoverFromNetworkChange(reason)`.

- [ ] **Step 1: Import `fingerprint` in main.js**

Line 32 currently reads `const { NetWatcher } = require('./netWatcher');`. Change to:

```js
const { NetWatcher, fingerprint } = require('./netWatcher');
```

- [ ] **Step 2: Add the helper next to `startNetWatcher`**

Insert immediately before `function startNetWatcher() {` (line ≈ 1346):

```js
/** The machine's network as the watcher would see it right now. */
function currentNetFingerprint() {
  return fingerprint(os.networkInterfaces(), isOwnTunInterface);
}
```

- [ ] **Step 3: Snapshot at the top of `doConnect`**

Right after `const abandoned = { ok: false, stale: true };` (line ≈ 680) add:

```js
  // The watcher only starts once this connect has finished (see the end of
  // this function), so a network that moves DURING the first connect is
  // invisible to it: the tunnel comes up built for the old gateway, the
  // watcher adopts the new one as normal, and nothing is left to notice. A
  // watcher that is already running (a reconnect) covers the window itself.
  const netBefore = netWatcher ? null : currentNetFingerprint();
```

- [ ] **Step 4: Compare after the watcher is up**

Right after `if (!netWatcher) startNetWatcher();` (line ≈ 985) add:

```js
  if (netBefore != null && currentNetFingerprint() !== netBefore) {
    send('log', { line: 'The network changed while connecting — rebuilding for the new one', level: 'warn' });
    // Deferred, so the 'connected' status below goes out first and the
    // recovery's own 'reconnecting' follows it in order.
    setTimeout(() => recoverFromNetworkChange('changed-during-connect').catch((e) => {
      send('log', { line: 'Network recovery failed: ' + ((e && e.message) || e), level: 'error' });
    }), 0);
  }
```

- [ ] **Step 5: Mirror in service.js**

Same three edits: the require at line 41 (`require('../main/netWatcher')`), the helper before `function startNetWatcher()`, the snapshot after `const abandoned = { ok: false, stale: true };` (line ≈ 636), the compare after `if (!netWatcher) startNetWatcher();` (line 894).

- [ ] **Step 6: Syntax + suite**

Run: `node --check src/main/main.js && node --check src/server/service.js && npm test`
Expected: no output from `--check`; tests pass.

- [ ] **Step 7: Headless smoke**

Run: `node src/server/server.js --port 3999 --data-dir %TEMP%\irnf-phaseA` and open `http://127.0.0.1:3999` in the browser tool. Confirm the page loads and the server log shows no exception. Stop the server.

- [ ] **Step 8: Commit**

```bash
git add src/main/main.js src/server/service.js
git commit -m "A network that changes while the first connect is running now triggers the same rebuild a later change would"
```

Fable review after this commit: confirm the `setTimeout` cannot fire for a connect that was overtaken (the `stale()` gate above the watcher start already returned `abandoned` in that case, so the compare is never reached), and that `recoverFromNetworkChange` refuses when `activeServerId` was cleared meanwhile.

---

### Task A4: the subscription usage bar is one colour at 10% and at 95%

**Files:**
- Modify: `src/renderer/lists.css:172`

**Why:** `subUsageHtml()` in `app.js` already emits `usage-fill good|mid|bad` (≥90% bad, ≥70% mid); the stylesheet paints all three with `--accent`.

- [ ] **Step 1: Add the three rules**

After line 172 (`.usage-fill { height: 100%; background: var(--accent); border-radius: var(--r1); }`) add:

```css
.usage-fill.good { background: var(--ok); }
.usage-fill.mid { background: var(--warn); }
.usage-fill.bad { background: var(--danger); }
```

- [ ] **Step 2: Verify in the browser**

With the headless server on port 3999 and a data dir that has a subscription with `usage: { upload: 0, download: 95, total: 100 }` (edit `%TEMP%\irnf-phaseA\store.json` → `subscriptions[0].usage` and restart the server), open the Subs page and run in the browser tool:

```js
getComputedStyle(document.querySelector('.usage-fill.bad')).backgroundColor
```
Expected: the value of `--danger` in the current theme (`rgb(255, 107, 107)` dark / `rgb(192, 57, 43)` light), not the accent.

- [ ] **Step 3: Commit**

```bash
git add src/renderer/lists.css
git commit -m "The subscription quota bar turns amber at 70% and red at 90% instead of staying accent-coloured"
```

---

### Task A5: clear the usage history — all of it, or one config's

**Files:**
- Modify: `src/main/usage.js` (`UsageMeter`, line ≈ 305–376)
- Test: `tests/usage.test.js`
- Modify: `src/main/main.js` (IPC block near `usage:get`, line 1937), `src/server/service.js` (handlers near `'usage:get'`, line 1453)
- Modify: `src/preload/preload.js:103`, `src/server/web-api.js:133`
- Modify: `src/renderer/index.html` (servers head, line ≈ 185), `src/renderer/app.js` (`renderServers` line 787; usage handler line 3405), `src/renderer/i18n.js`, `src/renderer/lists.css:390`

**Interfaces:**
- Produces: `UsageMeter.clear(id?: string) → boolean` (true when anything changed); IPC `usage:clear` (arg: id or null) → `{ ok: true, totals }`; renderer API `clearUsage(id)`.

- [ ] **Step 1: Failing tests**

Append to `tests/usage.test.js`:

```js
test('UsageMeter.clear(id) forgets one config; clear() forgets everything; both mark dirty', () => {
  const m = new UsageMeter({ totals: { 'sv-a': { down: 10, up: 1 }, 'sv-b': { down: 20, up: 2 } } });
  m.markSaved();
  assert.equal(m.clear('sv-zzz'), false, 'unknown id: nothing to forget');
  assert.equal(m.dirty, false);
  assert.equal(m.clear('sv-a'), true);
  assert.deepEqual(Object.keys(m.totals), ['sv-b']);
  assert.equal(m.dirty, true);
  m.markSaved();
  assert.equal(m.clear(), true);
  assert.deepEqual(m.totals, {});
  assert.equal(m.dirty, true);
  assert.equal(m.clear(), false, 'already empty');
});
```

- [ ] **Step 2: Run to see it fail**

Run: `node --test tests/usage.test.js`
Expected: FAIL with `m.clear is not a function`.

- [ ] **Step 3: Implement**

In `class UsageMeter`, after `prune(keepIds) {...}` add:

```js
  /**
   * Forget the running total of one config, or of every config. The user's
   * own "start over" — a subscription that changed hands, a test server that
   * moved on. `dirty` so the next flush writes the absence too.
   * @returns {boolean} whether anything was forgotten
   */
  clear(id) {
    if (id == null) {
      if (!Object.keys(this.totals).length) return false;
      this.totals = {};
    } else {
      if (!Object.prototype.hasOwnProperty.call(this.totals, id)) return false;
      const next = Object.assign({}, this.totals);
      delete next[id];
      this.totals = next;
    }
    this.dirty = true;
    return true;
  }
```

- [ ] **Step 4: Run the tests**

Run: `node --test tests/usage.test.js`
Expected: PASS.

- [ ] **Step 5: IPC in main.js**

After the `ipcMain.handle('usage:get', …)` line (1937) add:

```js
  // Forget a total on request (one config, or all). Written through at once:
  // an absence the next flush might not reach is a number that comes back.
  ipcMain.handle('usage:clear', (e, id) => {
    if (usage && usage.clear(id == null ? null : String(id))) {
      usageStore.set('totals', usage.totals);
      usage.markSaved();
      send('usage', { totals: usage.totals });
    }
    return { ok: true, totals: usage ? usage.totals : {} };
  });
```

- [ ] **Step 6: Mirror in service.js**

After the `'usage:get': …` handler (line 1453) add:

```js
    'usage:clear': (id) => {
      if (usage && usage.clear(id == null ? null : String(id))) {
        usageStore.set('totals', usage.totals);
        usage.markSaved();
        send('usage', { totals: usage.totals });
      }
      return { ok: true, totals: usage ? usage.totals : {} };
    },
```

- [ ] **Step 7: Expose it**

`src/preload/preload.js` after line 103 (`getUsage: …`):
```js
  clearUsage: (id) => ipcRenderer.invoke('usage:clear', id == null ? null : id),
```
`src/server/web-api.js` after line 133 (`getUsage: …`):
```js
    clearUsage: (id) => invoke('usage:clear', id == null ? null : id),
```

- [ ] **Step 8: i18n keys**

In `src/renderer/i18n.js`, after the line containing `'srv.usage': 'مصرف کل',` (fa, line 15) add:
```js
    'btn.clearUsage': 'پاک‌کردن مصرف', 'confirm.clearUsageAll': 'مصرف دائمیِ همهٔ کانفیگ‌ها پاک شود؟',
    'confirm.clearUsageOne': 'مصرف دائمی این کانفیگ پاک شود؟', 't.usageCleared': 'مصرف پاک شد',
    'srv.usageClick': 'برای پاک‌کردن کلیک کنید',
```
After the line containing `'srv.usage': 'Total used',` (en, line 389) add:
```js
    'btn.clearUsage': 'Clear usage', 'confirm.clearUsageAll': 'Forget the lifetime usage of every config?',
    'confirm.clearUsageOne': 'Forget the lifetime usage of this config?', 't.usageCleared': 'Usage cleared',
    'srv.usageClick': 'Click to clear',
```

- [ ] **Step 9: The button and the click**

`src/renderer/index.html`, in the servers view head, before `<button class="btn ghost" id="btnClearServers" …>` (line ≈ 186) add:
```html
            <button class="btn ghost" id="btnClearUsage" data-i18n="btn.clearUsage">پاک‌کردن مصرف</button>
```

`src/renderer/app.js`, in `renderServers()` change the usage span (line ≈ 823) to carry the id and a hint:
```js
      <span class="srv-usage" data-usage-id="${s.id}" title="${escapeHtml(t('srv.usage'))} — ${escapeHtml(t('srv.usageClick'))}">${usageLabel(s.id)}</span>
```
and after `card.querySelector('.del-srv').onclick = …` add:
```js
    card.querySelector('.srv-usage').onclick = async (e) => {
      e.stopPropagation();
      if (!usageLabel(s.id)) return;                      // nothing to clear
      if (!window.confirm(t('confirm.clearUsageOne'))) return;
      const res = await window.api.clearUsage(s.id);
      state.usage = (res && res.totals) || {};
      renderServers();
      toast(t('t.usageCleared'), 'ok');
    };
```
Next to `$('#btnPingAll').onclick = …` (line ≈ 1198) add:
```js
$('#btnClearUsage').onclick = async () => {
  if (!window.confirm(t('confirm.clearUsageAll'))) return;
  const res = await window.api.clearUsage(null);
  state.usage = (res && res.totals) || {};
  renderServers();
  toast(t('t.usageCleared'), 'ok');
};
```

`src/renderer/lists.css`, in the `.srv-usage {` block (line 390) add `cursor: pointer;`.

- [ ] **Step 10: Contract + suite**

Run: `npm test`
Expected: PASS (renderer.test.js sees `btnClearUsage` in the markup and the five new keys in both languages).

- [ ] **Step 11: Browser check**

Headless server on 3999 with a store whose `usage.json` is `{"totals":{"<a server id>":{"down":1000,"up":10}}}`: the card shows `↓1 KB·↑10 B`; clicking it and confirming empties the span; `usage.json` on disk is `{"totals":{}}`.

- [ ] **Step 12: Commit**

```bash
git add src/main/usage.js tests/usage.test.js src/main/main.js src/server/service.js src/preload/preload.js src/server/web-api.js src/renderer/index.html src/renderer/app.js src/renderer/i18n.js src/renderer/lists.css
git commit -m "Lifetime usage can be cleared — for one config from its card, or for all of them from the servers page"
```

---

### Task A6: the six inline `style=` attributes in index.html

**Files:**
- Modify: `src/renderer/index.html:205,296,470,496,785,853`
- Modify: `src/renderer/styles.css` (append)
- Test: `tests/renderer.test.js`

- [ ] **Step 1: Failing guard test**

Append to `tests/renderer.test.js`:

```js
test('the markup carries no inline style attributes', () => {
  // Inline styles bypass the tokens, the skins and the RTL logical properties.
  const inline = [...HTML.matchAll(/ style="([^"]*)"/g)].map((m) => m[1]);
  assert.deepEqual(inline, []);
});
```

Run: `node --test tests/renderer.test.js` — Expected: FAIL listing six values.

- [ ] **Step 2: Utility classes**

Append to `src/renderer/styles.css`:

```css
/* Spacing utilities — the only replacement for inline style= in the markup. */
.u-mbe-8 { margin-block-end: 8px; }
.u-mbe-12 { margin-block-end: 12px; }
.u-mbs-8 { margin-block-start: 8px; }
.u-mbs-10 { margin-block-start: 10px; }
.u-block { display: block; }
.btn.tiny { padding: 3px 10px; font-size: 12px; margin-inline-start: 8px; }
```

- [ ] **Step 3: Replace each attribute**

| Line | Was | Becomes |
|---|---|---|
| 205 | `class="row-gap" style="margin-bottom:12px"` | `class="row-gap u-mbe-12"` |
| 296 | `class="input" … style="margin-top:10px"` | `class="input u-mbs-10"` (drop the style attr) |
| 470 | `class="select" style="margin-bottom:8px"` | `class="select u-mbe-8"` |
| 496 | `class="select" style="margin-bottom:8px"` | `class="select u-mbe-8"` |
| 785 | `class="btn ghost" … style="padding:3px 10px;font-size:12px;margin-inline-start:8px"` | `class="btn ghost tiny"` (drop the style attr) |
| 853 | `class="field-label" … style="margin-top:8px;display:block"` | `class="field-label u-mbs-8 u-block"` (drop the style attr) |

- [ ] **Step 4: Tests + a glance**

Run: `npm test` — Expected: PASS. In the browser (port 3999) open Settings → DNS and the edit modal (any server → ✎): spacing unchanged, the "Clear pin" button still small.

- [ ] **Step 5: Commit**

```bash
git add src/renderer/index.html src/renderer/styles.css tests/renderer.test.js
git commit -m "The markup's last six inline styles become utility classes, and a test keeps it that way"
```

---

### Task A7: "remove downloaded files" does not know about sing-box

**Files:**
- Modify: `src/main/assets.js` (add `downloadedFileNames`)
- Test: `tests/assets.test.js`
- Modify: `src/main/main.js:1958` and `src/server/service.js:1411` (use it)

**Interfaces:**
- Produces: `downloadedFileNames(platform) → string[]` from `src/main/assets.js`.

- [ ] **Step 1: Failing test**

Append to `tests/assets.test.js` (it already imports `assetStatus`; extend the require to `{ assetStatus, downloadedFileNames }`):

```js
test('downloadedFileNames covers every engine, both TUN backends and the geo files', () => {
  const { ENGINES, engineExe } = require('../src/main/engines');
  for (const platform of ['win32', 'darwin', 'linux']) {
    const names = downloadedFileNames(platform);
    for (const id of Object.keys(ENGINES)) assert.ok(names.includes(engineExe(id, platform)), `${platform}: ${id}`);
    assert.ok(names.includes(platform === 'win32' ? 'tun2socks.exe' : 'tun2socks'));
    assert.ok(names.includes('geoip.dat') && names.includes('geosite.dat'));
    assert.equal(names.includes('wintun.dll'), platform === 'win32');
  }
});
```

Run: `node --test tests/assets.test.js` — Expected: FAIL (`downloadedFileNames is not a function`).

- [ ] **Step 2: Implement**

In `src/main/assets.js`, before `module.exports`:

```js
/**
 * Every file the downloader can put into userData/bin — what "remove
 * downloaded files" deletes. Derived from the engine registry so a new core
 * cannot be forgotten here (sing-box was, for two releases).
 */
function downloadedFileNames(platform = process.platform) {
  const win = platform === 'win32';
  const names = Object.keys(ENGINES).map(id => engineExe(id, platform));
  names.push(win ? 'tun2socks.exe' : 'tun2socks');
  if (win) names.push('wintun.dll');
  names.push('geoip.dat', 'geosite.dat');
  return names;
}
```
and export it: `module.exports = { assetStatus, downloadedFileNames };`. (`ENGINES`/`engineExe` are already imported at the top of assets.js — check with `grep -n "require('./engines')" src/main/assets.js`; if only one of them is imported, extend the destructuring.)

- [ ] **Step 3: Use it in both mirrors**

`src/main/main.js:16`: `const { assetStatus: scanAssets, downloadedFileNames } = require('./assets');`
`src/main/main.js:1958`: replace the literal `const names = ['xray', 'xray.exe', …];` with `const names = downloadedFileNames();`.
`src/server/service.js:24`: `const { assetStatus: scanAssets, downloadedFileNames } = require('../main/assets');`
`src/server/service.js:1411`: same replacement.

- [ ] **Step 4: Tests**

Run: `npm test` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main/assets.js tests/assets.test.js src/main/main.js src/server/service.js
git commit -m "Removing downloaded files now removes sing-box too; the list comes from the engine registry"
```

---

## Phase gate

- `npm test` green, output pristine.
- `npm run validate` unchanged (no config shape changed in this phase).
- Headless smoke on port 3999: home, servers, subs, settings render; no console errors.
- Fable review of A3's diff (both mirrors).
- The owner merges `feature/phase-A` and tags v1.3.1.
