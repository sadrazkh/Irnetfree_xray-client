'use strict';
/**
 * GitHub release lists for the three cores, shaped like
 * `GET /repos/<repo>/releases?per_page=30` answers — tags, order, the
 * pre-release flags and the asset names as the three release pages had them on
 * 2026-10-03 (XTLS/Xray-core: every 2026 build after 26.3.27 is a pre-release;
 * patterniha/Xray-core: all stable; SagerNet/sing-box: alphas, betas and rcs
 * between the stables). Not a test file itself (no `.test.js`).
 */

const XRAY_TARGETS = ['windows-64', 'windows-arm64-v8a', 'win7-64', 'linux-64', 'linux-arm32-v7a', 'linux-arm64-v8a',
  'linux-mips32le', 'macos-64', 'macos-arm64-v8a', 'android-arm64-v8a'];
const SINGBOX_TARGETS = ['windows-amd64.zip', 'windows-amd64-legacy.zip', 'windows-arm64.zip', 'linux-amd64.tar.gz',
  'linux-amd64v3.tar.gz', 'linux-armv7.tar.gz', 'linux-arm64.tar.gz', 'darwin-amd64.tar.gz', 'darwin-arm64.tar.gz',
  'android-arm64.tar.gz'];

const day = (iso) => `${iso}T09:30:00Z`;

function xrayAssets(repo, tag) {
  const out = [];
  for (const t of XRAY_TARGETS) {
    const name = `Xray-${t}.zip`;
    out.push({ name, size: 20594290, browser_download_url: `https://github.com/${repo}/releases/download/${tag}/${name}`, uploader: { login: 'github-actions[bot]' } });
    out.push({ name: name + '.dgst', size: 299, browser_download_url: `https://github.com/${repo}/releases/download/${tag}/${name}.dgst` });
  }
  return out;
}

function singboxAssets(tag) {
  const ver = tag.replace(/^v/, '');
  const out = [];
  for (const t of SINGBOX_TARGETS) {
    const name = `sing-box-${ver}-${t}`;
    out.push({ name, size: 15728640, browser_download_url: `https://github.com/SagerNet/sing-box/releases/download/${tag}/${name}` });
    if (/\.tar\.gz$/.test(t)) out.push({ name: name + '.sha256', size: 90, browser_download_url: `https://github.com/SagerNet/sing-box/releases/download/${tag}/${name}.sha256` });
  }
  return out;
}

/** [tag, date, prerelease] rows → GitHub release objects. */
function releases(repo, rows, assetsOf) {
  return rows.map(([tag, date, prerelease]) => ({
    url: `https://api.github.com/repos/${repo}/releases/1`,
    tag_name: tag,
    name: repo.startsWith('XTLS') ? `Xray-core ${tag}` : tag,
    draft: false,
    prerelease: !!prerelease,
    created_at: day(date),
    published_at: day(date),
    body: 'What’s changed …',
    assets: assetsOf(tag)
  }));
}

const XTLS_ROWS = [
  ['v26.9.30', '2026-09-30', true], ['v26.9.9', '2026-09-08', true], ['v26.9.8', '2026-09-08', true],
  ['v26.7.28', '2026-07-28', true], ['v26.7.11', '2026-07-11', true], ['v26.6.27', '2026-06-27', true],
  ['v26.6.22', '2026-06-22', true], ['v26.6.1', '2026-06-01', true], ['v26.5.9', '2026-05-09', true],
  ['v26.5.3', '2026-05-03', true], ['v26.4.25', '2026-04-25', true], ['v26.4.17', '2026-04-17', true],
  ['v26.4.15', '2026-04-15', true], ['v26.4.13', '2026-04-13', true], ['v26.3.27', '2026-03-27', false],
  ['v26.3.23', '2026-03-23', true], ['v26.2.6', '2026-02-06', false], ['v26.2.4', '2026-02-04', true],
  ['v26.2.2', '2026-02-02', true], ['v26.1.31', '2026-01-31', true], ['v26.1.23', '2026-01-23', false],
  ['v26.1.18', '2026-01-18', true], ['v26.1.13', '2026-01-13', true], ['v25.12.8', '2025-12-08', false],
  ['v25.12.2', '2025-12-02', true], ['v25.12.1', '2025-12-01', true], ['v25.10.15', '2025-10-15', false],
  ['v25.9.11', '2025-09-10', false], ['v25.9.10', '2025-09-10', true], ['v25.9.5', '2025-09-05', false]
];

const PATTN_ROWS = [
  ['v26.10.3', '2026-10-03'], ['v26.9.27', '2026-09-27'], ['v26.9.26', '2026-09-26'], ['v26.9.24', '2026-09-24'],
  ['v26.9.22', '2026-09-22'], ['v26.9.13', '2026-09-13'], ['v26.9.9', '2026-09-09'], ['v26.9.8', '2026-09-08'],
  ['v26.9.7', '2026-09-06'], ['v26.9.1', '2026-09-01'], ['v26.8.28', '2026-08-28']
];

const SINGBOX_ROWS = [
  ['v1.14.3', '2026-10-06', false], ['v1.15.0-alpha.10', '2026-10-03', true], ['v1.15.0-alpha.9', '2026-09-26', true],
  ['v1.15.0-alpha.8', '2026-09-24', true], ['v1.14.2', '2026-09-24', false], ['v1.15.0-alpha.7', '2026-09-22', true],
  ['v1.15.0-alpha.6', '2026-09-18', true], ['v1.15.0-alpha.5', '2026-09-16', true], ['v1.15.0-alpha.4', '2026-09-15', true],
  ['v1.14.1', '2026-09-15', false], ['v1.15.0-alpha.3', '2026-09-13', true], ['v1.15.0-alpha.2', '2026-09-05', true],
  ['v1.15.0-alpha.1', '2026-09-04', true], ['v1.14.0', '2026-08-31', false], ['v1.14.0-rc.5', '2026-08-30', true],
  ['v1.13.21', '2026-08-30', false], ['v1.14.0-rc.4', '2026-08-29', true], ['v1.13.20', '2026-08-29', false],
  ['v1.14.0-rc.2', '2026-08-28', true], ['v1.14.0-rc.1', '2026-08-24', true], ['v1.14.0-beta.17', '2026-08-17', true],
  ['v1.13.19', '2026-08-17', false], ['v1.14.0-beta.15', '2026-08-15', true], ['v1.14.0-beta.14', '2026-08-11', true],
  ['v1.14.0-beta.13', '2026-08-10', true], ['v1.14.0-beta.12', '2026-08-09', true], ['v1.13.18', '2026-08-09', false],
  ['v1.14.0-beta.10', '2026-08-08', true], ['v1.14.0-beta.9', '2026-08-07', true], ['v1.14.0-beta.8', '2026-08-06', true]
];

/** Fresh copies every call: a test may change what it got. */
const xtls = () => releases('XTLS/Xray-core', XTLS_ROWS, (tag) => xrayAssets('XTLS/Xray-core', tag));
const pattn = () => releases('patterniha/Xray-core', PATTN_ROWS, (tag) => xrayAssets('patterniha/Xray-core', tag));
const singbox = () => releases('SagerNet/sing-box', SINGBOX_ROWS, singboxAssets);
/** `GET /releases/tags/<tag>` — one sing-box release by its tag (a suggested one the 30 newest do not hold). */
const singboxTag = (tag) => releases('SagerNet/sing-box', [[tag, '2026-07-02', /-/.test(tag)]], singboxAssets)[0];

module.exports = { xtls, pattn, singbox, singboxTag, xrayAssets, singboxAssets, releases };
