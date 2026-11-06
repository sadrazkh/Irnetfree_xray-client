'use strict';
/**
 * SNI spoof, per config (the «جعل SNI» extension, src/renderer/modules.js
 * `sniSpoof`): a forged TLS ClientHello carrying a whitelisted name goes out
 * before the real one, in a TCP segment the server must drop — its sequence
 * number is left of the receive window (`wrong-sequence`, the default), its
 * checksum is wrong, its ACK is old, it carries a TCP-MD5 option or a backdated
 * timestamp — while a passive DPI box, which keeps no TCP state, reads the fake
 * name and lets the connection through. patterniha/SNI-Spoofing's technique,
 * built into sing-box 1.14 as the outbound TLS fields `spoof` and `spoof_method`
 * (common/tlsspoof: client_hello.go builds the hello, packet.go the segment,
 * raw_linux.go / raw_darwin.go / raw_windows.go send it on a raw socket — on
 * Windows through the WinDivert driver sing-box embeds, common/windivert). So:
 *
 *  - sing-box 1.14.0 or newer runs the config, whatever core its record names
 *    (engineChoice.chooseEngine) — never an Xray core, which has no such thing;
 *  - the process needs raw packets: Administrator on Windows (the app's elevated
 *    relaunch, as for TUN), root on Linux (capabilities on the binary are not read
 *    here) and on macOS; Windows on ARM64 is not supported by sing-box;
 *  - TLS over TCP only: tcp, ws, grpc, httpupgrade (and AnyTLS). XHTTP and mKCP
 *    are not sing-box's; QUIC (Hysteria2, TUIC) has no TCP segment to forge.
 *
 * The record keeps three keys of its own (serverFields.js `@sniSpoof`,
 * `@sniSpoofNames`, `@sniSpoofMethod`), this device's: no share link carries
 * them (there is no agreed link key), a backup does. Several names: one is
 * picked at random on every connect (pickSpoofName), so a name the ISP stops
 * whitelisting is not every connect's. Off — the extension not installed, the
 * switch off or no name — writes nothing: every config is byte for byte what
 * it was.
 *
 * Shared by main.js, service.js, engineChoice.js and singboxBuilder.js; it
 * requires nothing of the app.
 */

const { isOn } = require('../renderer/modules');

/** sing-box's spoof_method values (common/tlsspoof/spoof.go); the first is its default. wrong-timestamp: Linux and Windows only. */
const SPOOF_METHODS = ['wrong-sequence', 'wrong-checksum', 'wrong-ack', 'wrong-md5', 'wrong-timestamp'];
const DEFAULT_METHOD = SPOOF_METHODS[0];
/** The first sing-box with `tls.spoof` (changelog 1.14.0 "Add TLS spoof"); an older one refuses the config as an unknown field. */
const SINGBOX_SPOOF_SINCE = [1, 14];

/** The record's names, cleaned: trimmed, lower-cased, no empties and no duplicates. */
function spoofNamesOf(server) {
  const raw = server && server.sniSpoofNames;
  const list = Array.isArray(raw) ? raw : (typeof raw === 'string' ? raw.split(/[,\s]+/) : []);
  const out = [];
  for (const n of list) {
    const s = String(n == null ? '' : n).trim().toLowerCase();
    if (s && !out.includes(s)) out.push(s);
  }
  return out;
}

/** Is this a name sing-box takes as a spoof? A hostname, never an IP literal (the core rejects those) and never a URL. */
function validSpoofName(name) {
  const s = String(name == null ? '' : name).trim();
  if (!s || s.length > 253 || /[\s/:\\@]/.test(s)) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return false;
  return /^[a-z0-9-]+(\.[a-z0-9-]+)*\.?$/i.test(s);
}

/** The record's method, or sing-box's default for anything it does not know. */
function spoofMethodOf(server) {
  const m = String((server && server.sniSpoofMethod) || '').trim().toLowerCase();
  return SPOOF_METHODS.includes(m) ? m : DEFAULT_METHOD;
}

/** Does the record itself ask for a spoof (the switch on and at least one name) — the extension aside? */
function wantsSniSpoof(server) {
  return !!(server && server.sniSpoof === true && spoofNamesOf(server).length);
}

/** Does this connect spoof: the extension installed in these settings (`modules.sniSpoof`) and the record asking for it? */
function spoofsSni(server, settings) {
  return wantsSniSpoof(server) && isOn(settings, 'sniSpoof');
}

/** One of the names, at random (`rnd` in [0, 1] for a test — 1 is the last; Math.random otherwise). */
function pickSpoofName(names, rnd) {
  const list = Array.isArray(names) ? names.filter(Boolean) : [];
  if (!list.length) return '';
  const r = typeof rnd === 'number' && rnd >= 0 && rnd <= 1 ? rnd : Math.random();
  return list[Math.min(list.length - 1, Math.floor(r * list.length))];
}

/**
 * The TLS fields sing-box takes for this record — `{ spoof, spoof_method? }`,
 * the method only when the record names one other than sing-box's default —
 * or null when the connect does not spoof (spoofsSni).
 */
function spoofTlsFields(server, settings, rnd) {
  if (!spoofsSni(server, settings)) return null;
  const out = { spoof: pickSpoofName(spoofNamesOf(server), rnd) };
  const method = spoofMethodOf(server);
  if (method !== DEFAULT_METHOD) out.spoof_method = method;
  return out;
}

/** Does this sing-box (its `version` line, tunSingbox.singboxVersionOf) take `tls.spoof`? Unknown version: no. */
function singboxSpoofs(version) {
  const m = /(\d+)\.(\d+)\.\d+/.exec(String(version == null ? '' : version));
  if (!m) return false;
  const major = Number(m[1]), minor = Number(m[2]);
  return major > SINGBOX_SPOOF_SINCE[0] || (major === SINGBOX_SPOOF_SINCE[0] && minor >= SINGBOX_SPOOF_SINCE[1]);
}

/**
 * Does the process hold what the forged segment needs? Windows: Administrator
 * (tunPlatform.isElevated's `net session`). Linux and macOS: root — a capability
 * set on the binary is not read here, so a service with CAP_NET_RAW only would
 * be refused; the router's service runs as root.
 */
function spoofElevated(platform, isElevatedWin, getuid) {
  const plat = platform || process.platform;
  if (plat === 'win32') return !!isElevatedWin();
  try { return typeof getuid === 'function' ? getuid() === 0 : (process.getuid && process.getuid() === 0); } catch { return false; }
}

/**
 * Why a spoofing config cannot connect, in the app's language — the connect
 * (and the window's toast) say it instead of running without the spoof:
 *  - 'missing':  sing-box is not installed;
 *  - 'old':      the installed sing-box is older than 1.14 (`detail`: its version);
 *  - 'admin':    the process is not elevated (Windows) / not root (Linux, macOS);
 *  - 'router':   the OpenWrt service runs every config on Xray (the LAN's DNS is Xray's);
 *  - 'carry':    sing-box cannot carry this config (`detail`: the builder's reason);
 *  - 'arm64':    Windows on ARM64, which sing-box's spoof does not support.
 */
function sniSpoofError(server, why, lang, detail) {
  const name = String((server && server.name) || 'config');
  const en = lang === 'en';
  const d = detail ? ` (${detail})` : '';
  switch (why) {
    case 'missing':
      return en
        ? `"${name}" has SNI spoof on: it needs the sing-box core (1.14 or newer), which is not installed — Settings → Required files → sing-box.`
        : `«${name}» جعل SNI روشن دارد و به هستهٔ sing-box (نسخهٔ 1.14 یا جدیدتر) نیاز دارد، که نصب نیست — تنظیمات → فایل‌های موردنیاز → sing-box.`;
    case 'old':
      return en
        ? `"${name}" has SNI spoof on: the installed sing-box${d} is older than 1.14 and has no spoof — update it under Settings → Required files.`
        : `«${name}» جعل SNI روشن دارد، ولی sing-box نصب‌شده${d} از 1.14 قدیمی‌تر است و جعل SNI ندارد — از تنظیمات → فایل‌های موردنیاز به‌روزش کن.`;
    case 'admin':   // `detail`: the platform (process.platform when not given)
      return (detail || process.platform) === 'win32'
        ? (en
          ? `"${name}" has SNI spoof on: the forged packet needs Administrator rights — relaunch the app as administrator (as for TUN), or turn SNI spoof off in its editor.`
          : `«${name}» جعل SNI روشن دارد و بستهٔ جعلی به دسترسی Administrator نیاز دارد — برنامه را با دسترسی ادمین اجرا کن (مثل حالت TUN)، یا جعل SNI را در ویرایشگرش خاموش کن.`)
        : (en
          ? `"${name}" has SNI spoof on: the forged packet needs root (CAP_NET_RAW and CAP_NET_ADMIN) — run the app as root, or turn SNI spoof off in its editor.`
          : `«${name}» جعل SNI روشن دارد و بستهٔ جعلی به root (CAP_NET_RAW و CAP_NET_ADMIN) نیاز دارد — برنامه را با root اجرا کن، یا جعل SNI را در ویرایشگرش خاموش کن.`);
    case 'router':
      return en
        ? `"${name}" has SNI spoof on: it runs only on sing-box, and the router runs every config on Xray (the LAN's DNS is Xray's) — turn SNI spoof off for it on the router.`
        : `«${name}» جعل SNI روشن دارد و فقط با sing-box اجرا می‌شود، ولی روتر همهٔ کانفیگ‌ها را با Xray اجرا می‌کند (DNS شبکهٔ پشت روتر با Xray است) — روی روتر جعل SNI را برایش خاموش کن.`;
    case 'carry':
      return en
        ? `"${name}" has SNI spoof on, which only sing-box does — and sing-box cannot carry this config${d}. Turn SNI spoof off in its editor, or change what sing-box refuses.`
        : `«${name}» جعل SNI روشن دارد که فقط sing-box انجامش می‌دهد — ولی sing-box این کانفیگ را نمی‌تواند اجرا کند${d}. جعل SNI را در ویرایشگرش خاموش کن، یا چیزی را که sing-box رد می‌کند تغییر بده.`;
    case 'plan':
      return en
        ? `"${name}" has SNI spoof on, which runs only when it is connected on its own: here it is in a chain, a group, a routing or the pool, where the spoof would be lost. Connect it alone, or turn its SNI spoof off.`
        : `«${name}» جعل SNI روشن دارد، که فقط وقتی تنها وصل شود کار می‌کند: اینجا داخل چین، گروه، روتینگ یا پول است و جعل آنجا از دست می‌رود. تنها وصلش کن، یا جعل SNI آن را خاموش کن.`;
    case 'version':
      return en
        ? `"${name}" has SNI spoof on, but the installed sing-box did not say its version, so it cannot be known to have it (1.14 or newer) — reinstall it in Settings → Required files → sing-box.`
        : `«${name}» جعل SNI روشن دارد، ولی sing-box نصب‌شده نسخه‌اش را نگفت و معلوم نیست آن را دارد (1.14 یا جدیدتر) — از تنظیمات ← فایل‌های لازم ← sing-box دوباره نصبش کن.`;
    case 'arm64':
      return en
        ? `"${name}" has SNI spoof on: sing-box does not support it on Windows on ARM64 — turn it off in its editor.`
        : `«${name}» جعل SNI روشن دارد، ولی sing-box روی ویندوزِ ARM64 آن را ندارد — در ویرایشگرش خاموشش کن.`;
    default:
      return en ? `"${name}": SNI spoof cannot run${d}.` : `«${name}»: جعل SNI اجرا نمی‌شود${d}.`;
  }
}

module.exports = {
  SPOOF_METHODS, DEFAULT_METHOD, SINGBOX_SPOOF_SINCE,
  spoofNamesOf, validSpoofName, spoofMethodOf, wantsSniSpoof, spoofsSni, pickSpoofName, spoofTlsFields,
  singboxSpoofs, spoofElevated, sniSpoofError
};
