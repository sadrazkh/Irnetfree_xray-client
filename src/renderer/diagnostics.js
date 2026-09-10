'use strict';

/**
 * Standalone panel: only the explicit Test button initiates destination traffic.
 *
 * Every string this file writes goes through t(), and the panel follows the
 * page's own direction and language like any other surface. Report VALUES do
 * not: statuses, scopes, reasons, rule targets and hop names are the export's
 * vocabulary, and the JSON is a machine-readable artefact meant to be pasted
 * into an issue, so it stays exactly as collectDiagnostics wrote it.
 */
(() => {
  let panel;
  const t = (key) => window.i18n.t(key);
  const el = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text != null) node.textContent = text;
    if (className) node.className = className;
    return node;
  };
  /**
   * A node whose whole text is ours, tagged so applyI18n() retranslates it when
   * the language is switched with the panel open. Never on a <label> that also
   * holds a control: applyI18n replaces textContent, which would take the input
   * with it.
   */
  const tel = (tag, key, className) => {
    const node = el(tag, t(key), className);
    node.dataset.i18n = key;
    return node;
  };
  function open() {
    if (panel) { panel.focus(); return; }
    const previousFocus = document.activeElement;
    const dialog = el('dialog', null, 'diagnostics-panel');
    panel = dialog;
    let report;
    let busy = false;
    dialog.setAttribute('aria-labelledby', 'diagnostics-title');
    const title = tel('h2', 'diag.title');
    title.id = 'diagnostics-title';
    const close = tel('button', 'diag.close', 'btn ghost');
    close.type = 'button';
    /**
     * One teardown, run by the Close button AND by the `close` event, and safe
     * to run twice. It used to hang off the event alone — which did not arrive
     * in every Chromium, leaving the dialog in the DOM with `panel` still set,
     * so open() returned early for ever after and the panel could never be
     * reopened.
     */
    function teardown() {
      if (!panel) return;
      const node = panel;
      panel = null;
      busy = false;
      try { node.close(); } catch {}
      node.remove();
      previousFocus?.focus?.();
    }
    close.onclick = () => teardown();
    dialog.addEventListener('close', () => teardown());
    const header = el('header'); header.append(title, close);
    const message = el('p');
    message.setAttribute('role', 'status');
    const say = (key) => { message.dataset.i18n = key; message.textContent = t(key); };
    say('diag.reading');
    const content = el('div');
    const actions = el('div', null, 'diagnostics-actions');
    const refresh = tel('button', 'diag.refresh', 'btn ghost');
    const copy = tel('button', 'diag.copy', 'btn ghost');
    const download = tel('button', 'diag.download', 'btn ghost');
    const repair = tel('button', 'diag.repair', 'btn ghost');
    // The only control here that changes anything. Hidden until a report says
    // the core is stopped: recovery undoes what a CRASHED session left behind,
    // and offering it beside three read-only buttons invited a silent teardown
    // of a live VPN.
    repair.hidden = true;
    for (const button of [refresh, copy, download, repair]) button.type = 'button';
    actions.append(refresh, copy, download, repair);
    const repairNote = tel('p', 'diag.repairScope', 'diagnostics-note');
    const form = el('form', null, 'diagnostics-probe');
    const hostLabel = el('label');
    const host = el('input', null, 'input'); host.required = true; host.maxLength = 253; host.autocomplete = 'off'; host.spellcheck = false;
    hostLabel.append(tel('span', 'diag.host'), host);
    const portLabel = el('label');
    const port = el('input', null, 'input'); port.type = 'number'; port.min = '1'; port.max = '65535'; port.required = true;
    portLabel.append(tel('span', 'diag.port'), port);
    const test = tel('button', 'diag.test', 'btn primary'); test.type = 'submit';
    form.append(hostLabel, portLabel, test);
    function render(value) {
      report = value;
      content.replaceChildren();
      for (const [key, labelKey] of [['core', 'diag.core'], ['tun', 'diag.tun'], ['dns', 'diag.dns'], ['connectivity', 'diag.connectivity']]) {
        const item = value[key] || {};
        content.append(tel('h3', labelKey), el('p', String(item.status || t('diag.unknown')).replaceAll('-', ' ') + (Number.isFinite(item.ms) ? ` (${item.ms} ms)` : '')));
        if (item.scope) content.append(el('p', item.scope, 'diagnostics-note'));
        if (item.reason || item.error) content.append(el('p', item.reason || item.error));
      }
      const routes = value.routes || {};
      content.append(tel('h3', 'diag.routes'));
      if (routes.status !== 'available') content.append(tel('p', 'diag.noRoutes'));
      else {
        content.append(el('p', routes.semantics, 'diagnostics-note'));
        const list = el('ol');
        for (const rule of routes.rules || []) {
          const criteria = (rule.criteria || []).map(c => `${c.field}: ${c.count}`).join(', ') || t('diag.noCriteria');
          list.append(el('li', `${t('diag.priority')} ${rule.priority}: ${criteria} → ${rule.target}${rule.catchAll ? ' ' + t('diag.allPorts') : ''}`));
        }
        content.append(list, el('p', `${t('diag.default')}: ${routes.fallback || t('diag.unknown')}`));
        for (const path of routes.paths || []) content.append(el('p', `${path.id}: ${t('diag.client')} → ${(path.hops || []).join(' → ')}${path.complete ? '' : ' ' + t('diag.incomplete')}`));
      }
      const running = (value.core || {}).status === 'running';
      repair.hidden = running;
      repairNote.dataset.i18n = running ? 'diag.repairConnected' : 'diag.repairScope';
      repairNote.textContent = t(repairNote.dataset.i18n);
    }
    /** Disable the controls for the length of one request, and put back exactly
     *  what each of them was — not "all enabled", which would hand the user a
     *  button the report had deliberately disabled. */
    function freeze() {
      const previous = [refresh, test, repair].map(button => [button, button.disabled]);
      for (const [button] of previous) button.disabled = true;
      return () => { for (const [button, was] of previous) button.disabled = was; };
    }
    async function load(probe) {
      if (busy) return;
      busy = true;
      const thaw = freeze();
      say(probe ? 'diag.testing' : 'diag.reading');
      try {
        const value = await window.api.connectionDiagnostics(probe);
        if (!value || !value.core) throw new Error('unavailable');
        render(value); say('diag.captured');
      } catch { say('diag.unavailable'); }
      finally { busy = false; thaw(); }
    }
    refresh.onclick = () => load();
    form.onsubmit = event => { event.preventDefault(); if (form.reportValidity()) load({ host: host.value.trim(), port: Number(port.value) }); };
    copy.onclick = async () => {
      if (!report) return;
      try { await navigator.clipboard.writeText(JSON.stringify(report, null, 2)); say('diag.copied'); }
      catch { say('diag.clipboard'); }
    };
    download.onclick = () => {
      if (!report) return;
      const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
      const link = el('a'); link.href = url; link.download = 'irnetfree-diagnostics.json'; link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    };
    repair.onclick = async () => {
      if (busy) return;
      busy = true;
      const thaw = freeze();
      say('diag.repairing');
      try {
        const result = await window.api.repairNetwork();
        if (result && result.ok === true) say('diag.repaired');
        else say(result && result.error === 'connected' ? 'diag.repairConnected' : 'diag.repairFailed');
      } catch { say('diag.repairFailed'); }
      finally { busy = false; thaw(); }
    };
    dialog.append(header, message, content, tel('p', 'diag.probeNote', 'diagnostics-note'), form, actions, repairNote, tel('p', 'diag.privacyNote', 'diagnostics-note'));
    document.body.append(dialog); dialog.showModal(); load();
  }
  window.IRNFDiagnostics = { open };
})();
