/* IRNetFree site: theme, menu, the latest release's download links, the screenshot tour, copy buttons.
   Node loads the pure helpers at the top for tests/site.test.js; a browser runs the rest. */
(function () {
  'use strict';

  var REPO = 'sadrazkh/Irnetfree_xray-client';
  var RELEASES = 'https://github.com/' + REPO + '/releases/latest';

  // A release asset's name → the button it fills. First match wins, so the narrower patterns come first.
  var SLOTS = [
    ['win-setup', /^IRNetFree-Setup-.+\.exe$/i],
    ['win-portable', /^IRNetFree-Portable-.+\.exe$/i],
    ['mac-arm64', /^IRNetFree-.+-arm64\.dmg$/i],
    ['mac-x64', /^IRNetFree-.+-x64\.dmg$/i],
    ['mac-arm64-zip', /^IRNetFree-.+-arm64-mac\.zip$/i],
    ['mac-x64-zip', /^IRNetFree-[\d.]+-mac\.zip$/i],
    ['deb', /^IRNetFree-.+-amd64\.deb$/i],
    ['appimage', /^IRNetFree-.+\.AppImage$/i],
    ['apk', /^IRNetFree-.+\.apk$/i],
    ['ipk', /^irnetfree_.+\.ipk$/i]
  ];

  function slotsOf(assets) {
    var out = {};
    (assets || []).forEach(function (a) {
      if (!a || typeof a.name !== 'string') return;
      for (var i = 0; i < SLOTS.length; i++) {
        if (SLOTS[i][1].test(a.name)) { if (!out[SLOTS[i][0]]) out[SLOTS[i][0]] = a; return; }
      }
    });
    return out;
  }

  // Which button the hero offers. iPadOS asks for the desktop site and says "Macintosh", so touch decides.
  function detectOS(ua, platform, touchPoints) {
    ua = String(ua || ''); platform = String(platform || '');
    if (/iPhone|iPad|iPod/i.test(ua) || (/Mac/i.test(platform + ua) && touchPoints > 1)) return 'ios';
    if (/Android/i.test(ua)) return 'android';
    if (/Windows|Win32|Win64/i.test(ua + platform)) return 'windows';
    if (/Mac/i.test(platform + ua)) return 'mac';
    if (/Linux|X11|CrOS/i.test(ua + platform)) return 'linux';
    return '';
  }

  // Which slot the hero's button takes on each system.
  var HERO_SLOT = { windows: 'win-setup', mac: 'mac-arm64', linux: 'appimage', android: 'apk' };

  function formatSize(bytes, lang) {
    if (!(bytes > 0)) return '';
    var mb = bytes / 1048576;
    var n = mb >= 10 ? Math.round(mb) : Math.round(mb * 10) / 10;
    if (lang === 'fa') return n.toLocaleString('fa-IR') + ' مگابایت';
    return n + ' MB';
  }

  function formatDate(iso, lang) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return '';
    try {
      return new Intl.DateTimeFormat(lang === 'fa' ? 'fa-IR' : 'en-US', { year: 'numeric', month: 'long', day: 'numeric' }).format(d);
    } catch (e) { return d.toISOString().slice(0, 10); }
  }

  // The API's release → what the page needs. The build script writes the same shape into release.json.
  function slimRelease(body) {
    if (!body || typeof body.tag_name !== 'string') return null;
    return {
      tag: body.tag_name,
      version: body.tag_name.replace(/^v/, ''),
      published: body.published_at || null,
      url: body.html_url || RELEASES,
      assets: (body.assets || []).map(function (a) { return { name: a.name, size: a.size, url: a.browser_download_url }; })
    };
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { REPO: REPO, SLOTS: SLOTS, HERO_SLOT: HERO_SLOT, slotsOf: slotsOf, detectOS: detectOS, formatSize: formatSize, formatDate: formatDate, slimRelease: slimRelease };
    return;
  }

  // ---------------------------------------------------------------- browser
  var doc = document;
  var root = doc.documentElement;
  var lang = root.lang === 'fa' ? 'fa' : 'en';
  var base = root.getAttribute('data-root') || '.';
  var T = {
    fa: {
      windows: 'دانلود برای ویندوز', mac: 'دانلود برای مک', linux: 'دانلود برای لینوکس', android: 'دانلود برای اندروید',
      ios: 'آیفون داری؟ این را بخوان', any: 'دانلود', you: 'دستگاه تو', copied: 'کپی شد', copy: 'کپی',
      themeDark: 'تم تاریک', themeLight: 'تم روشن'
    },
    en: {
      windows: 'Download for Windows', mac: 'Download for macOS', linux: 'Download for Linux', android: 'Download for Android',
      ios: 'On an iPhone? Read this', any: 'Download', you: 'Your device', copied: 'Copied', copy: 'Copy',
      themeDark: 'Dark theme', themeLight: 'Light theme'
    }
  }[lang];

  function $(sel, el) { return (el || doc).querySelector(sel); }
  function $all(sel, el) { return Array.prototype.slice.call((el || doc).querySelectorAll(sel)); }

  // Theme: the head script already set data-theme before the first paint.
  var themeBtn = $('#themeBtn');
  function syncThemeLabel() {
    if (!themeBtn) return;
    var dark = root.getAttribute('data-theme') !== 'light';
    themeBtn.setAttribute('aria-label', dark ? T.themeLight : T.themeDark);
    themeBtn.setAttribute('title', dark ? T.themeLight : T.themeDark);
    var meta = $('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', dark ? '#0a0f15' : '#f6f8fb');
  }
  if (themeBtn) {
    themeBtn.addEventListener('click', function () {
      var next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('irnf-theme', next); } catch (e) { /* private window */ }
      syncThemeLabel();
    });
    syncThemeLabel();
  }

  // Mobile menu.
  var menuBtn = $('#menuBtn');
  var links = $('#navLinks');
  function closeMenu() { if (links) links.classList.remove('open'); if (menuBtn) menuBtn.setAttribute('aria-expanded', 'false'); }
  if (menuBtn && links) {
    menuBtn.addEventListener('click', function () {
      var open = !links.classList.contains('open');
      links.classList.toggle('open', open);
      menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    $all('a', links).forEach(function (a) { a.addEventListener('click', closeMenu); });
    doc.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeMenu(); });
  }

  // Header border once the page scrolls, and the nav link of the section in view.
  var nav = $('.nav');
  function onScroll() { if (nav) nav.classList.toggle('scrolled', window.scrollY > 8); }
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
  if ('IntersectionObserver' in window) {
    var navMap = {};
    $all('.nav-links a[href^="#"]').forEach(function (a) { navMap[a.getAttribute('href').slice(1)] = a; });
    var spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        var a = navMap[en.target.id];
        if (a && en.isIntersecting) {
          Object.keys(navMap).forEach(function (k) { navMap[k].classList.remove('on'); });
          a.classList.add('on');
        }
      });
    }, { rootMargin: '-45% 0px -50% 0px' });
    Object.keys(navMap).forEach(function (id) { var s = doc.getElementById(id); if (s) spy.observe(s); });

    var rev = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { en.target.classList.add('in'); rev.unobserve(en.target); } });
    }, { rootMargin: '0px 0px -8% 0px' });
    $all('.reveal').forEach(function (el) { rev.observe(el); });
  } else {
    $all('.reveal').forEach(function (el) { el.classList.add('in'); });
  }

  // Downloads. release.json comes from this site (written at build time); the API is the fallback.
  var os = detectOS(navigator.userAgent, (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform, navigator.maxTouchPoints || 0);
  var card = os && $('.platform[data-os="' + os + '"]');
  if (card) {
    card.classList.add('you');
    var badge = $('.you-badge', card);
    if (badge) badge.textContent = T.you;
  }
  var heroBtn = $('#heroDl');
  var heroLabel = $('#heroDlLabel');
  if (heroLabel) heroLabel.textContent = T[os] || T.any;
  if (heroBtn && os === 'ios') heroBtn.setAttribute('href', '#faq-ios');
  if (heroBtn && os === 'ios') heroBtn.addEventListener('click', function () { var d = $('#faq-ios'); if (d) d.open = true; });

  function apply(rel) {
    if (!rel || !rel.tag) return;
    $all('[data-ver]').forEach(function (el) { el.textContent = rel.version; });
    var when = formatDate(rel.published, lang);
    $all('[data-date]').forEach(function (el) { el.textContent = when; el.hidden = !when; });
    $all('[data-notes]').forEach(function (el) { el.setAttribute('href', rel.url || RELEASES); });
    var slots = slotsOf(rel.assets);
    $all('[data-asset]').forEach(function (el) {
      var a = slots[el.getAttribute('data-asset')];
      if (!a) return;
      el.setAttribute('href', a.url);
      el.setAttribute('download', '');
      var name = $('[data-name]', el);
      if (name) name.textContent = a.name;
      var size = $('[data-size]', el);
      if (size) size.textContent = formatSize(a.size, lang);
    });
    var slot = HERO_SLOT[os];
    var a = slot && slots[slot];
    if (heroBtn && a) {
      heroBtn.setAttribute('href', a.url);
      var meta = $('#heroDlMeta');
      if (meta) meta.textContent = rel.version + ' · ' + formatSize(a.size, lang);
    }
  }

  function getJSON(url) {
    return fetch(url, { cache: 'no-cache' }).then(function (r) { if (!r.ok) throw new Error(String(r.status)); return r.json(); });
  }
  if (window.fetch) {
    getJSON(base + '/release.json')
      .then(function (rel) { if (!rel || !rel.tag || !(rel.assets || []).length) throw new Error('empty'); return rel; })
      .catch(function () { return getJSON('https://api.github.com/repos/' + REPO + '/releases/latest').then(slimRelease); })
      .then(apply)
      .catch(function () { /* the links already point at the releases page */ });
  }

  // Screenshot tour.
  var tabs = $all('.tab');
  function select(tab, focus) {
    tabs.forEach(function (t) {
      var on = t === tab;
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
      var panel = doc.getElementById(t.getAttribute('aria-controls'));
      if (panel) { panel.classList.toggle('on', on); panel.hidden = !on; }
    });
    if (focus) tab.focus();
  }
  tabs.forEach(function (t, i) {
    t.addEventListener('click', function () { select(t, false); });
    t.addEventListener('keydown', function (e) {
      var fwd = lang === 'fa' ? 'ArrowLeft' : 'ArrowRight';
      var back = lang === 'fa' ? 'ArrowRight' : 'ArrowLeft';
      var n = null;
      if (e.key === fwd || e.key === 'ArrowDown') n = tabs[(i + 1) % tabs.length];
      else if (e.key === back || e.key === 'ArrowUp') n = tabs[(i - 1 + tabs.length) % tabs.length];
      else if (e.key === 'Home') n = tabs[0];
      else if (e.key === 'End') n = tabs[tabs.length - 1];
      if (n) { e.preventDefault(); select(n, true); }
    });
  });
  if (tabs.length) select(tabs[0], false);

  // Lightbox for the screenshots.
  var box = $('#lightbox');
  if (box && typeof box.showModal === 'function') {
    var boxImg = $('img', box);
    var boxCap = $('p', box);
    $all('[data-zoom]').forEach(function (el) {
      el.addEventListener('click', function () {
        var img = $('img', el);
        if (!img) return;
        boxImg.src = img.currentSrc || img.src;
        boxImg.alt = img.alt;
        boxCap.textContent = img.alt;
        if (!box.open) box.showModal();
      });
    });
    var shut = function () { if (box.open) box.close(); };
    box.addEventListener('click', function (e) { if (e.target === box || e.target.closest('[data-close]')) shut(); });
  }

  // Copy buttons next to the one-line installs.
  $all('.copy').forEach(function (btn) {
    btn.setAttribute('aria-label', T.copy);
    btn.addEventListener('click', function () {
      var pre = btn.parentNode && $('pre', btn.parentNode);
      if (!pre) return;
      var text = pre.textContent.trim();
      var done = function () {
        btn.classList.add('done');
        btn.setAttribute('aria-label', T.copied);
        setTimeout(function () { btn.classList.remove('done'); btn.setAttribute('aria-label', T.copy); }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, function () {});
    });
  });

  // A link to #faq-… opens that answer.
  function openHash() {
    var id = decodeURIComponent(location.hash.slice(1));
    var el = id && doc.getElementById(id);
    if (el && el.tagName === 'DETAILS') el.open = true;
  }
  window.addEventListener('hashchange', openHash);
  openHash();
})();
