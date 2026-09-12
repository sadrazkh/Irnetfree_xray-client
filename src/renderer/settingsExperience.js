'use strict';
/* Organize existing controls before app.js binds them. No values or persistence
 * live here: section changes and search only affect presentation. */
(() => {
  const page = document.getElementById('view-settings');
  const original = Array.from(page.querySelectorAll(':scope > .card'));
  const [network, components, protection, core, save, about] = original;
  const tr = key => window.i18n.t(key);
  function translated(tag, key, className) {
    const node = document.createElement(tag); node.dataset.i18n = key;
    node.textContent = tr(key); if (className) node.className = className; return node;
  }
  const appearance = document.createElement('div'); appearance.className = 'card';
  for (const id of ['langSelect', 'themeSelect']) appearance.append(document.getElementById(id).closest('.grid2'));
  const automation = document.createElement('div'); automation.className = 'card';
  for (const id of ['optNetAuto','optNotify','optLaunchAtLogin','optAutoConnect']) automation.append(document.getElementById(id).closest('.switch-row'));
  const sections = [
    [network,'network'],[protection,'protection'],[appearance,'appearance'],
    [automation,'automation'],[components,'components'],[core,'components'],[about,'about']
  ];
  for (const [card, category] of sections) {
    card.dataset.settingsCategory = category;
    // Existing component/core/about labels already provide descriptive headings.
    if (![components,core,about].includes(card)) card.prepend(translated('h3','settings.'+category,'settings-section-title'));
    page.append(card);
  }
  page.append(save); save.classList.add('settings-save');
  const intro = translated('p','settings.intro','settings-intro');
  const tools = document.createElement('div'); tools.className = 'settings-tools';
  const searchBox = document.createElement('div'); searchBox.className = 'settings-search';
  const search = document.createElement('input'); search.type = 'search'; search.className = 'input';
  search.id = 'settingsSearch'; search.dataset.i18nPh = 'settings.search';
  search.placeholder = tr('settings.search'); search.setAttribute('aria-label', tr('settings.search'));
  const clear = translated('button','settings.clear','btn ghost'); clear.type = 'button';
  clear.hidden = true; clear.onclick = () => { search.value = ''; filter(); search.focus(); };
  searchBox.append(search, clear);
  const nav = document.createElement('nav'); nav.className = 'settings-nav';
  nav.setAttribute('aria-label',tr('nav.settings'));
  let selected = 'all';
  for (const category of ['all','network','protection','appearance','automation','components','about']) {
    const button = translated('button','settings.'+category,'settings-chip'); button.type='button';
    button.dataset.category=category; button.setAttribute('aria-pressed', String(category===selected));
    button.onclick = () => { selected=category; search.value=''; filter(); }; nav.append(button);
  }
  const empty = translated('p','settings.empty','settings-empty'); empty.hidden=true;
  empty.setAttribute('role','status');
  tools.append(searchBox,nav); page.querySelector('.view-head').after(intro,tools,empty);
  const normalize = value => value.normalize('NFKC').replace(/ي/g,'ی').replace(/ك/g,'ک').toLocaleLowerCase().trim();
  function filter() {
    const query = normalize(search.value); let visible=0;
    clear.hidden = !query;
    for (const button of nav.children) button.setAttribute('aria-pressed',String(button.dataset.category===(query ? 'all' : selected)));
    for (const [card, category] of sections) {
      // Search spans all topics, so a selected category cannot hide a matching setting.
      const matches = query ? normalize(card.textContent + ' ' + Array.from(card.querySelectorAll('input,select')).map(el=>el.id).join(' ')).includes(query) : selected==='all'||selected===category;
      card.hidden = !matches; if (matches) visible++;
    }
    empty.hidden=visible>0;
  }
  search.addEventListener('input',filter);
  search.addEventListener('keydown',event=>{ if(event.key==='Escape'){ search.value='';filter(); } });
  // Labels remain current when the language switches while this page is open.
  new MutationObserver(() => { search.setAttribute('aria-label',tr('settings.search')); nav.setAttribute('aria-label',tr('nav.settings')); filter(); }).observe(document.documentElement,{attributes:true,attributeFilter:['lang']});
  // Supply accessible names to the original unlabelled switch inputs and fields.
  for (const input of page.querySelectorAll('input,select')) {
    if (input.hasAttribute('aria-label') || input.hasAttribute('aria-labelledby')) continue;
    const title = input.closest('.switch-row')?.querySelector('.switch-title') || input.parentElement.querySelector('.field-label');
    if (title) { if (!title.id) title.id=input.id+'Label'; input.setAttribute('aria-labelledby',title.id); }
  }
})();
