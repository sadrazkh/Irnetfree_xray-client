'use strict';

// Standalone panel: only the explicit Test button initiates destination traffic.
(() => {
  let panel;
  const el = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text != null) node.textContent = text;
    if (className) node.className = className;
    return node;
  };
  function open() {
    if (panel) { panel.focus(); return; }
    const previousFocus = document.activeElement;
    const dialog = el('dialog', null, 'diagnostics-panel');
    dialog.dir = 'ltr';
    dialog.lang = 'en';
    panel = dialog;
    let report;
    let busy = false;
    dialog.setAttribute('aria-labelledby', 'diagnostics-title');
    const title = el('h2', 'Connection diagnostics');
    title.id = 'diagnostics-title';
    const close = el('button', 'Close');
    close.type = 'button';
    close.onclick = () => dialog.close();
    dialog.addEventListener('close', () => { dialog.remove(); panel = null; previousFocus?.focus(); });
    const header = el('header'); header.append(title, close);
    const message = el('p', 'Reading connection state…');
    message.setAttribute('role', 'status');
    const content = el('div');
    const actions = el('div', null, 'diagnostics-actions');
    const refresh = el('button', 'Refresh state');
    const copy = el('button', 'Copy sanitized report');
    const download = el('button', 'Download sanitized report');
    const repair = el('button', 'Recover network');
    actions.append(refresh, copy, download, repair);
    const form = el('form', null, 'diagnostics-probe');
    const hostLabel = el('label', 'Destination hostname or IP');
    const host = el('input'); host.required = true; host.maxLength = 253; host.autocomplete = 'off'; host.spellcheck = false;
    hostLabel.append(host);
    const portLabel = el('label', 'TCP port');
    const port = el('input'); port.type = 'number'; port.min = '1'; port.max = '65535'; port.required = true;
    portLabel.append(port);
    const test = el('button', 'Test through current proxy'); test.type = 'submit';
    form.append(hostLabel, portLabel, test);
    function render(value) {
      report = value;
      content.replaceChildren();
      for (const [key, label] of [['core', 'Core process'], ['tun', 'System tunnel'], ['dns', 'DNS'], ['connectivity', 'Destination test']]) {
        const item = value[key] || {};
        content.append(el('h3', label), el('p', String(item.status || 'unknown').replaceAll('-', ' ') + (Number.isFinite(item.ms) ? ` (${item.ms} ms)` : '')));
        if (item.scope) content.append(el('p', item.scope, 'diagnostics-note'));
        if (item.reason || item.error) content.append(el('p', item.reason || item.error));
      }
      const routes = value.routes || {};
      content.append(el('h3', 'Routing and chain order'));
      if (routes.status !== 'available') content.append(el('p', 'No running routing configuration is available.'));
      else {
        content.append(el('p', routes.semantics, 'diagnostics-note'));
        const list = el('ol');
        for (const rule of routes.rules || []) {
          const criteria = (rule.criteria || []).map(c => `${c.field}: ${c.count}`).join(', ') || 'no listed criteria';
          list.append(el('li', `Priority ${rule.priority}: ${criteria} → ${rule.target}${rule.catchAll ? ' (all ports)' : ''}`));
        }
        content.append(list, el('p', `Default: ${routes.fallback || 'unknown'}`));
        for (const path of routes.paths || []) content.append(el('p', `${path.id}: client → ${(path.hops || []).join(' → ')}${path.complete ? '' : ' (incomplete path)'}`));
      }
    }
    async function load(probe) {
      if (busy) return;
      busy = true; refresh.disabled = test.disabled = repair.disabled = true;
      message.textContent = probe ? 'Testing the selected service through local SOCKS…' : 'Reading connection state…';
      try {
        const value = await window.api.connectionDiagnostics(probe);
        if (!value || !value.core) throw new Error('unavailable');
        render(value); message.textContent = 'State captured. Network traffic is tested only when you press Test.';
      } catch { message.textContent = 'Diagnostics could not be read. Retry after checking the connection.'; }
      finally { busy = false; refresh.disabled = test.disabled = repair.disabled = false; }
    }
    refresh.onclick = () => load();
    form.onsubmit = event => { event.preventDefault(); if (form.reportValidity()) load({ host: host.value.trim(), port: Number(port.value) }); };
    copy.onclick = async () => {
      if (!report) return;
      try { await navigator.clipboard.writeText(JSON.stringify(report, null, 2)); message.textContent = 'Sanitized report copied.'; }
      catch { message.textContent = 'Clipboard unavailable. Use Download instead.'; }
    };
    download.onclick = () => {
      if (!report) return;
      const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
      const link = el('a'); link.href = url; link.download = 'irnetfree-diagnostics.json'; link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    };
    repair.onclick = async () => {
      if (busy) return;
      busy = true; refresh.disabled = test.disabled = repair.disabled = true;
      message.textContent = 'Recovering changes owned by this application…';
      try {
        const result = await window.api.repairNetwork();
        message.textContent = result && result.ok === true ? 'Recovery completed. Refresh state to inspect the result.' : 'Recovery was not completed. Disconnect first, then retry; an administrator prompt may be required.';
      } catch { message.textContent = 'Recovery was not completed. Disconnect first, then retry.'; }
      finally { busy = false; refresh.disabled = test.disabled = repair.disabled = false; }
    };
    dialog.append(header, message, content, el('p', 'Private WireGuard service check: choose a service and port you expect to reach. This verifies a TCP connection through the current proxy; it does not prove which route matched.', 'diagnostics-note'), form, actions, el('p', 'Reports omit server names, addresses, credentials, rule values, test destination and raw errors.', 'diagnostics-note'));
    document.body.append(dialog); dialog.showModal(); load();
  }
  window.IRNFDiagnostics = { open };
})();
