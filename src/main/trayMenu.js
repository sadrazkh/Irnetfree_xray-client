'use strict';
/**
 * The servers as tray submenus. Pure — main.js turns these groups into Electron
 * menu items — so the grouping (hand-added first, then one group per
 * subscription, the orphans of a deleted subscription last) is tested without
 * a tray. `max` keeps a 300-server subscription from becoming a 300-line menu.
 */
function trayGroups(servers, subs, max = 25) {
  const list = (servers || []).filter(s => s && s.id);
  const item = (s) => ({ id: s.id, name: s.name || s.address || s.id });
  const out = [];
  const manual = list.filter(s => !s.subId).slice(0, max).map(item);
  if (manual.length) out.push({ label: '', items: manual });
  const seen = new Set();
  for (const sub of subs || []) {
    if (!sub || !sub.id) continue;
    seen.add(sub.id);
    const items = list.filter(s => s.subId === sub.id).slice(0, max).map(item);
    if (items.length) out.push({ label: sub.name || sub.url || '?', items });
  }
  const orphans = list.filter(s => s.subId && !seen.has(s.subId)).slice(0, max).map(item);
  if (orphans.length) out.push({ label: '?', items: orphans });
  return out;
}

/**
 * The tray's Disconnect item. While a connect is in flight — a first connect,
 * a switch, a rebuild after a drop — it is that connect's Cancel: a connect that
 * hangs (a dead server, no network) could otherwise only be waited out from the
 * tray, whose Disconnect was greyed out until something was active. `state` is
 * the last connection status told to the window.
 */
function trayStopItem({ active, state, en }) {
  if (state === 'connecting' || state === 'reconnecting') {
    return { label: en ? 'Cancel connecting' : 'لغو اتصال', enabled: true };
  }
  return { label: en ? 'Disconnect' : 'قطع اتصال', enabled: !!active };
}

module.exports = { trayGroups, trayStopItem };
