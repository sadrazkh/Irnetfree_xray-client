'use strict';
/*
 * Paint the remembered theme before anything else does.
 *
 * app.js can only set data-theme once app:init has answered (the preference lives
 * in the backend store), and until then the CSS defaults to dark — so a user on
 * the light theme saw a dark flash on every launch. This runs from <head>, before
 * the body is parsed, and re-applies whatever applyTheme() last resolved to.
 *
 * It is a hint, not the source of truth: app:init still calls applyTheme() and
 * corrects the attribute (which matters for 'system', where the OS may have
 * flipped since). With nothing remembered — a first run — it does nothing at all,
 * leaving the dark default exactly as it was.
 *
 * Loaded as its own file rather than inline because the page's CSP is
 * script-src 'self' (no 'unsafe-inline').
 */
(function () {
  try {
    var last = localStorage.getItem('irnetfree.theme');
    if (last === 'dark' || last === 'light') {
      document.documentElement.setAttribute('data-theme', last);
    }
    // same for the chosen look — a console/legacy user should not see the
    // cockpit's orange flash on every launch
    var skin = localStorage.getItem('irnetfree.skin');
    if (skin === 'console' || skin === 'legacy') {
      document.documentElement.setAttribute('data-skin', skin);
    }
  } catch {}
})();
