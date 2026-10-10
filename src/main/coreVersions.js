'use strict';
/**
 * The cores' version picker — Settings → Required files → «انتخاب نسخه» /
 * "Choose version" (docs/superpowers/specs/2026-10-03-core-version-picker-design.md).
 *
 * Which releases of a core to offer, how each one is labelled, and the one
 * table of versions this release of the app is verified with. The releases
 * come from the Downloader (GitHub's API, listReleases), the installed version
 * from the core itself (`<bin> version`); nothing here fetches, spawns or
 * writes. createCoreVersionsApi() is the pair of IPC handlers main.js and the
 * router's service.js share — every effect it has goes through what they hand in.
 *
 * «به‌روزرسانی» / Update is not this: it installs the default target — GitHub's
 * latest stable release, or SUGGESTED below when that is newer
 * (Downloader.defaultRelease) — and the weekly updater still does what the
 * user chose there.
 */
const { cmpVersion } = require('./assetUpdater');

/** The cores with a picker. Geo files, tun2socks and wintun keep their single button. */
const CORE_IDS = ['xray', 'xray-pattn', 'sing-box'];

/** Short names for the log. */
const CORE_NAMES = { xray: 'Xray', 'xray-pattn': 'Xray-PattN', 'sing-box': 'sing-box' };

/**
 * ⭐ Suggested — the version of each core this release of the app is verified
 * with. One value per core; each comment says where it was verified.
 */
const SUGGESTED = Object.freeze({
  // XTLS/Xray-core 26.9.30, verified in CI: the `cores` job (.github/workflows/
  // test.yml) hands it every config shape this app writes — the plans, the DNS
  // modes, TUN, the v1.18 link forms (scripts/validate-configs.js) — through
  // `xray run -test`, the version read from this table. XTLS has marked every
  // release after 26.3.27 a pre-release, so 26.3.27 is still the newest one it
  // calls stable; v2rayN 7.25.4 (a stable release) and v2rayNG 2.3.10 ship
  // 26.9.30. A plain download installs the newer of the two
  // (Downloader.defaultRelease). The oldest official core each part was checked
  // on stays 26.3.27: the DNS block's server objects and the REFUSED hijack
  // rules (dnsBuilder.js), the certificate pins (certPin.js), the finalmask line
  // (xrayManager.js FINALMASK_SINCE), the router's LAN DNS (service.js
  // CORE_DNS_VERIFIED, openwrt/install.sh).
  xray: '26.9.30',

  // patterniha/Xray-core 26.9.22, verified on the owner's router: the AC-1304 has
  // run this release line on it since the v1.16.2 field round, whose log
  // (xray-pattn 26.9.22) the router's DNS and open-files fixes were made from and
  // confirmed on. 26.9.1 is where the desktop's DNS hijack rules, certificate
  // pins and chained WireGuard were first verified (dnsBuilder.js, certPin.js,
  // docs/releases/v1.7.2.md); 26.9.22 runs those same config builders (the
  // desktop's are pinned byte for byte, tests/desktopPin.test.js) and is the
  // newest build known to work with them end to end.
  'xray-pattn': '26.9.22',

  // SagerNet/sing-box 1.14.3, verified on a REAL TUN in CI (test.yml `tun-dns`,
  // scripts/tun-dns-probe.js): with the dns_mode "disabled" tunSingbox writes
  // from 1.14 on (by the installed binary's version), a WireGuard's private
  // names reach Xray and no query leaves past the tunnel; the control run
  // without it shows 1.14's hijack. Every TUN config passes `sing-box check` on
  // it in the `cores` job, and it is the WireGuard peer there
  // (scripts/probe-wg-base.js). 1.13.14 stays verified the same way (tun-dns
  // runs both lines) and is still what the macOS app bundles
  // (scripts/build-mac-native.js VERSION — its own TUN config, not tunSingbox's).
  'sing-box': '1.14.3'
});

/** Stable: the 6 newest with this platform's build. With pre-releases: also the 4 newest pre-releases. */
const STABLE_COUNT = 6;
const PRERELEASE_COUNT = 4;

/** A release tag the picker may ask for: `v26.9.22`, `1.13.14`, `v1.15.0-alpha.10`. */
const TAG_RE = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?$/;

/**
 * The first version in a tag or in a core's own output, its pre-release part
 * kept: 'v1.15.0-alpha.10' → '1.15.0-alpha.10'; 'Xray 26.3.27 (Xray, …)' →
 * '26.3.27'; 'sing-box version 1.13.14' → '1.13.14'; '' when there is none.
 */
function fullVersion(s) {
  const m = /(\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?)/.exec(String(s == null ? '' : s));
  return m ? m[1] : '';
}

const sameVersion = (a, b) => !!a && !!b && cmpVersion(a, b) === 0;

/** GitHub's pre-release flag — or a semver pre-release tag (`-alpha.3`) a release was published without it. */
function isPrerelease(r) {
  return !!(r && (r.prerelease || /-/.test(fullVersion(r.tag_name))));
}

const usable = (r) => !!(r && typeof r === 'object' && !r.draft && fullVersion(r.tag_name));
const newestFirst = (a, b) => cmpVersion(b.version, a.version);

/**
 * GitHub's latest stable release: the tag `/releases/latest` named, or else the
 * newest stable release in the list that is not a draft (what that endpoint
 * would have answered). '' for an empty list.
 */
function latestOf(releases, latestTag) {
  const given = fullVersion(latestTag);
  if (given) return given;
  let best = '';
  for (const r of Array.isArray(releases) ? releases : []) {
    if (!usable(r) || isPrerelease(r)) continue;
    const v = fullVersion(r.tag_name);
    if (!best || cmpVersion(v, best) > 0) best = v;
  }
  return best;
}

/**
 * The picker's cards for one core, newest version first.
 *
 *   releases    GitHub's release objects (tag_name, prerelease, draft,
 *               published_at, assets [{ name, size }]) — raw or trimmed
 *   matchAsset  (assetName) → this platform's archive of the core?
 *   installed   the installed core's version ('' if none, or unreadable)
 *   latestTag   GitHub's latest stable tag ('' if unknown: see latestOf)
 *   suggested   SUGGESTED[core]
 *   prerelease  offer the pre-releases too
 *
 * Offered: the STABLE_COUNT newest stable releases that carry this platform's
 * archive; with `prerelease` also the PRERELEASE_COUNT newest pre-releases; and
 * always the suggested and the installed release when they are in the list —
 * the ⭐ card is the one to go back to, and the installed one says where you
 * are. Never a draft, a release without this platform's build, or a tag
 * without a version; one card per version.
 *
 * Each card: { version, tag, date, size, asset, prerelease, isInstalled,
 * isSuggested, isLatest, action, olderThanSuggested } — `action` is what
 * installing it does to what is there: 'upgrade' | 'downgrade' | 'reinstall',
 * or 'install' when nothing (readable) is installed.
 */
function buildCards({ releases, matchAsset, installed, latestTag, suggested, prerelease } = {}) {
  const match = typeof matchAsset === 'function' ? matchAsset : () => false;
  const inst = fullVersion(installed);
  const latest = latestOf(releases, latestTag);
  const seen = new Set();
  const all = [];
  for (const r of Array.isArray(releases) ? releases : []) {
    if (!usable(r)) continue;
    const asset = (Array.isArray(r.assets) ? r.assets : []).find((a) => a && match(String(a.name || '')));
    if (!asset) continue;
    const version = fullVersion(r.tag_name);
    const key = version.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    all.push({ r, asset, version });
  }
  all.sort(newestFirst);
  const pick = new Set([
    ...all.filter((x) => !isPrerelease(x.r)).slice(0, STABLE_COUNT),
    ...(prerelease ? all.filter((x) => isPrerelease(x.r)).slice(0, PRERELEASE_COUNT) : []),
    ...all.filter((x) => sameVersion(x.version, suggested) || sameVersion(x.version, inst))
  ]);
  return all.filter((x) => pick.has(x)).map(({ r, asset, version }) => {
    const cmp = inst ? cmpVersion(version, inst) : null;
    return {
      version,
      tag: String(r.tag_name),
      date: r.published_at || r.created_at || null,
      size: Number(asset.size) || 0,
      asset: String(asset.name),
      prerelease: isPrerelease(r),
      isInstalled: cmp === 0,
      isSuggested: sameVersion(version, suggested),
      isLatest: sameVersion(version, latest),
      action: cmp === null ? 'install' : cmp > 0 ? 'upgrade' : cmp < 0 ? 'downgrade' : 'reinstall',
      olderThanSuggested: !!fullVersion(suggested) && cmpVersion(version, suggested) < 0
    };
  });
}

/** Thrown out of installVersion's last step when a connection started while it downloaded. */
function refusedConnected() {
  return Object.assign(new Error('a connection started — the core is not replaced under it'), { refused: 'connected' });
}

/**
 * The two IPC handlers — 'cores:versions' and 'cores:install' — for main.js and
 * the router's service.js, which differ only in what they hand in:
 *
 *   downloader        the Downloader (listReleases, assetMatcher, target, installVersion)
 *   installedVersion  (core) → Promise<string>: the core's own `version` output
 *   busy              () → connected, connecting or rebuilding a connection
 *   afterInstall      (core) → the refresh a download does (versions, stats, binPath)
 *   result            () → { assets, tunAvailable, xrayReady } as after a download
 *   onLog             (line, level)
 *
 * A core is never replaced under a connection: refused while busy() before
 * anything is fetched, and asked again right before the binary is put in place
 * (a connect may start during the download). One install at a time.
 */
function createCoreVersionsApi({ downloader, installedVersion, busy, afterInstall, result, onLog = () => {} }) {
  let installing = null;
  const isBusy = () => { try { return !!busy(); } catch { return false; } };
  const readInstalled = async (id) => { try { return fullVersion(await installedVersion(id)); } catch { return ''; } };
  const where = () => (installing ? { component: installing.component, tag: installing.tag } : null);

  async function versions(arg) {
    const { component } = arg || {};
    if (!CORE_IDS.includes(component)) return { ok: false, error: 'unknown core: ' + component };
    const prerelease = !!(arg && arg.prerelease);
    const installed = await readInstalled(component);
    const out = {
      component, installed, suggested: SUGGESTED[component], latest: '', platform: downloader.target(component),
      prerelease, busy: isBusy(), installing: where(), cards: []
    };
    try {
      const { releases, latestTag } = await downloader.listReleases(component, { force: !!(arg && arg.force) });
      out.latest = latestOf(releases, latestTag);
      out.cards = buildCards({ releases, matchAsset: downloader.assetMatcher(component), installed, latestTag, suggested: SUGGESTED[component], prerelease });
      return Object.assign({ ok: true }, out);
    } catch (e) {
      return Object.assign({ ok: false, error: (e && e.message) || String(e), reason: e && e.rateLimited ? 'rate-limit' : 'network' }, out);
    }
  }

  async function install(arg) {
    const { component } = arg || {};
    const tag = arg && typeof arg.tag === 'string' ? arg.tag.trim() : '';
    if (!CORE_IDS.includes(component)) return { ok: false, error: 'unknown core: ' + component };
    if (!TAG_RE.test(tag)) return { ok: false, error: 'not a release tag: ' + tag };
    if (isBusy()) return { ok: false, refused: 'connected', component, tag };
    if (installing) return { ok: false, refused: 'installing', component, tag, installing: where() };
    installing = { component, tag };
    const name = `${CORE_NAMES[component]} ${tag}`;
    try {
      const res = await downloader.installVersion(component, tag, { beforePlace: () => { if (isBusy()) throw refusedConnected(); } });
      afterInstall(component);
      onLog(`${name} installed (chosen under Required files)`, 'info');
      return Object.assign({ ok: true, component, tag, version: (res && res.version) || fullVersion(tag) }, result());
    } catch (e) {
      if (e && e.refused) return { ok: false, refused: e.refused, component, tag };
      // an Update (or the weekly updater) is writing this core right now: the page says so in its language
      if (e && e.code === 'ECOREBUSY') return { ok: false, refused: 'core-busy', component, tag };
      const error = (e && e.message) || String(e);
      // Windows: the core file held by a latency test or a config check — nothing broke, nothing was replaced
      if (e && e.code === 'ECOREINUSE') {
        onLog(`Installing ${name}: ${error}`, 'warn');
        return { ok: false, component, tag, error, reason: 'in-use', assets: result().assets };
      }
      onLog(`Installing ${name} failed: ${error}`, 'error');
      return { ok: false, component, tag, error, assets: result().assets };
    } finally {
      installing = null;
    }
  }

  return { versions, install, installing: where };
}

module.exports = {
  CORE_IDS, CORE_NAMES, SUGGESTED, STABLE_COUNT, PRERELEASE_COUNT, TAG_RE,
  fullVersion, isPrerelease, latestOf, buildCards, createCoreVersionsApi
};
