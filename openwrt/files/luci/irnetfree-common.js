'use strict';
'require baseclass';
'require rpc';
'require ui';

/*
 * Shared by the four IRNetFree pages (Services → IRNetFree): the ubus calls,
 * the Persian dictionary, and the small helpers the pages and their tests use.
 * Shipped as /www/luci-static/resources/irnetfree/common.js and loaded with
 * 'require irnetfree.common as common'.
 *
 * Every call goes to the rpcd plugin luci.irnetfree, which forwards it to the
 * service's local API (POST 127.0.0.1:<port>/luci/<method>) and answers with a
 * JSON object: the service's reply, {"result":[…]} for a list, or
 * {"error":"…"} (not-running, timeout, unauthorized, http <code>, or the
 * service's own message). ES5 on purpose — no arrow functions, no classes:
 * LuCI runs this file as it is, in whatever browser opens the router.
 */

var call = function (method, params) {
	return rpc.declare({ object: 'luci.irnetfree', method: method, params: params || [], expect: { '': {} } });
};

/* English → Persian, for LuCI running in fa (its theme does the right-to-left
 * layout). Every string the pages show goes through t(); %s are filled in order. */
var FA = {
	// the connection state
	'Connected': 'متصل',
	'Connecting…': 'در حال اتصال…',
	'Reconnecting…': 'اتصال مجدد…',
	'Reconnecting… (attempt %s)': 'اتصال مجدد… (تلاش %s)',
	'Waiting for internet…': 'منتظر اینترنت…',
	'Waiting for internet… (attempt %s)': 'منتظر اینترنت… (تلاش %s)',
	'Disconnected': 'قطع شده',
	'Error': 'خطا',
	'Error: %s': 'خطا: %s',
	'Unknown': 'نامشخص',
	// errors from the plugin or the service
	'The IRNetFree service is not running.': 'سرویس IRNetFree اجرا نمی‌شود.',
	'The service did not answer in time.': 'سرویس به‌موقع جواب نداد.',
	'The service refused the request: its token changed. Restart the service.': 'سرویس درخواست را رد کرد: توکنش عوض شده است. سرویس را دوباره اجرا کن.',
	'This IRNetFree service does not know this request yet — update IRNetFree.': 'این نسخهٔ سرویس IRNetFree این درخواست را نمی‌شناسد — IRNetFree را به‌روز کن.',
	'Remote access is not part of this IRNetFree version.': 'دسترسی از راه دور در این نسخهٔ IRNetFree نیست.',
	'The service answered with an error (HTTP %s).': 'سرویس با خطا جواب داد (HTTP %s).',
	'No answer from the service.': 'جوابی از سرویس نیامد.',
	'Start the service': 'اجرای سرویس',
	'Starting the service…': 'در حال اجرای سرویس…',
	'The service has not answered yet — it may still be starting. Reload this page in a moment.': 'سرویس هنوز جواب نداده — شاید هنوز در حال بالا آمدن است. کمی بعد این صفحه را دوباره باز کن.',
	'Your LuCI login may not change IRNetFree (it needs write access to luci-app-irnetfree).': 'کاربر LuCI شما اجازهٔ تغییر IRNetFree را ندارد (دسترسی نوشتن luci-app-irnetfree لازم است).',
	'The router did not answer in time.': 'روتر به‌موقع جواب نداد.',
	// remote-access states
	'Relay: %s': 'رله: %s',
	'Cloudflare Tunnel: %s': 'تونل کلودفلر: %s',
	'online (direct)': 'آنلاین (مستقیم)',
	'online through the VPN': 'آنلاین (از داخل VPN)',
	'connecting…': 'در حال اتصال…',
	'offline': 'آفلاین',
	'offline — %s': 'آفلاین — %s',
	'connecting… (attempt %s)': 'در حال اتصال… (تلاش %s)',
	'connecting… (attempt %s) — %s': 'در حال اتصال… (تلاش %s) — %s',
	'Enabled but not running: %s': 'فعال ولی اجرا نمی‌شود: %s',
	'cloudflared is not installed': 'cloudflared نصب نشده است',
	'no tunnel token': 'توکن تونل تنظیم نشده',
	'see the Log tab': 'زبانهٔ «لاگ» را ببین',
	'applying…': 'در حال اعمال…',
	'installing…': 'در حال نصب…',
	'off': 'خاموش',
	'not installed': 'نصب نشده',
	'running': 'در حال اجرا',
	'stopped': 'متوقف',
	'since %s': 'از %s',
	// sizes and times
	'%sd %s': '%s روز %s',
	'Download %s (%s) · Upload %s (%s)': 'دانلود %s (%s) · آپلود %s (%s)',
	// config groups
	'Manual servers': 'کانفیگ‌های دستی',
	'Chains': 'زنجیره‌ها',
	'Pools': 'استخر پروکسی',
	'Advanced routing': 'روتینگ ویژه',
	'Subscription': 'ساب',
	'Unknown device': 'دستگاه ناشناس',
	// shared by the pages
	'Saved — applied.': 'ذخیره شد — اعمال شد.',
	'Nothing changed.': 'چیزی تغییر نکرد.',
	'Not saved': 'ذخیره نشد',
	'Close': 'بستن',
	'The browser did not allow copying. Select all the text below and copy it.': 'مرورگر اجازهٔ کپی نداد. همهٔ متن زیر را انتخاب و کپی کن.',

	// Overview
	'The tunnel for every device behind this router. Changes on this page take effect at once.': 'تونل برای همهٔ دستگاه‌های پشت این روتر. تغییرهای این صفحه بلافاصله اعمال می‌شوند.',
	'Version %s': 'نسخهٔ %s',
	'Status': 'وضعیت',
	'Connection': 'اتصال',
	'VPN': 'VPN',
	'On': 'روشن',
	'Off': 'خاموش',
	'Config': 'کانفیگ',
	'Connected for': 'مدت اتصال',
	'Traffic': 'ترافیک',
	'Kill switch': 'کیل سوییچ',
	'Whole-network tunnel': 'تونل کل شبکه',
	'On — every device behind the router goes through the VPN': 'روشن — همهٔ دستگاه‌های پشت روتر از VPN می‌روند',
	'This config is already connected — press Reconnect to apply changes.': 'همین کانفیگ الان وصل است — برای اعمال تغییرها «اتصال مجدد» را بزن.',
	'On — ready: it blocks only while the VPN is on and the tunnel is down': 'روشن — آماده: فقط وقتی VPN روشن است و تونل قطع است می‌بندد',
	'On — waits until the VPN is switched on': 'روشن — تا VPN روشن نشود کاری نمی‌کند',
	'On — blocking': 'روشن — در حال بستن',
	'LAN internet is blocked until the VPN is back.': 'اینترنت دستگاه‌های شبکه تا برگشتن VPN بسته است.',
	'Turn the VPN off': 'خاموش کردن VPN',
	'Remote access': 'دسترسی از راه دور',
	'Configs': 'کانفیگ‌ها',
	'Pick a config, then Connect. Choosing one here also selects it in the web UI.': 'یک کانفیگ انتخاب کن و «اتصال» را بزن. انتخاب این‌جا در رابط وب هم اعمال می‌شود.',
	'No configs yet — add servers or a subscription in the web UI.': 'هنوز کانفیگی نیست — در رابط وب سرور یا ساب اضافه کن.',
	'Connect': 'اتصال',
	'Reconnect': 'اتصال مجدد',
	'Test connection': 'تست اتصال',
	'Update subscriptions': 'به‌روزرسانی ساب‌ها',
	'Choose a config first.': 'اول یک کانفیگ انتخاب کن.',
	'Testing…': 'در حال تست…',
	'Test: %s ms': 'تست: %s میلی‌ثانیه',
	'Test failed: %s': 'تست ناموفق: %s',
	'Updating subscriptions — the list refreshes when they are done.': 'ساب‌ها در حال به‌روزرسانی‌اند — فهرست بعد از پایان تازه می‌شود.',
	'Web UI': 'رابط وب',
	'The full IRNetFree web UI has everything else: servers, subscriptions, routing, chains and logs.': 'رابط وب کامل IRNetFree بقیهٔ امکانات را دارد: سرورها، ساب‌ها، روتینگ، زنجیره‌ها و لاگ‌ها.',
	'Open full web UI': 'باز کردن رابط وب کامل',
	'No token yet: start the service and reload this page.': 'هنوز توکنی ساخته نشده: سرویس را اجرا کن و این صفحه را دوباره باز کن.',

	// Settings
	'IRNetFree settings': 'تنظیمات IRNetFree',
	'Saved changes take effect at once — no restart, no reconnect.': 'تغییرها بعد از ذخیره بلافاصله اعمال می‌شوند — بدون ری‌استارت و بدون اتصال مجدد.',
	'Connect when the router starts': 'با روشن شدن روتر وصل شو',
	'After a reboot or power cut the VPN comes back as it was': 'بعد از ریبوت یا قطع برق، VPN همان‌طور که بود برمی‌گردد',
	'While the VPN is switched on and the tunnel is not up — a drop, a reconnect, the router starting — devices on the LAN get no internet instead of going out unprotected. Devices that bypass the VPN, traffic inside the LAN and the router’s own traffic are never blocked. Turning the VPN off gives the LAN normal internet.': 'وقتی VPN روشن است ولی تونل برقرار نیست — قطعی، اتصال مجدد، بالا آمدن روتر — دستگاه‌های شبکه به‌جای رفتن بدون محافظت، اینترنت ندارند. دستگاه‌هایی که از VPN رد نمی‌شوند، ترافیک داخل شبکه و ترافیک خود روتر هیچ‌وقت بسته نمی‌شوند. با خاموش کردن VPN، شبکه اینترنت عادی دارد.',
	'Block QUIC from the LAN': 'QUIC (UDP 443) از شبکه رد نشود',
	'Browsers fall back to TCP at once, which every proxy carries; devices that bypass the VPN are not affected.': 'مرورگرها بلافاصله سراغ TCP می‌روند که هر پروکسی‌ای حمل می‌کند؛ دستگاه‌هایی که از VPN رد نمی‌شوند دست نمی‌خورند.',
	'Devices that bypass the VPN': 'دستگاه‌هایی که از VPN رد نمی‌شوند',
	'These devices reach the internet directly, not through the tunnel. Pick one the router has given an address to, or type a MAC address.': 'این دستگاه‌ها مستقیم به اینترنت می‌روند، نه از تونل. یکی از دستگاه‌هایی را که از روتر IP گرفته‌اند انتخاب کن یا آدرس MAC را بنویس.',
	'The port and address the IRNetFree web UI listens on. Save & Apply restarts the service: a few seconds, then the tunnel comes back by itself.': 'پورت و آدرسی که رابط وب IRNetFree روی آن گوش می‌دهد. «ذخیره و اعمال» سرویس را ری‌استارت می‌کند: چند ثانیه، بعد تونل خودش برمی‌گردد.',
	'Port': 'پورت',
	'Listen address': 'آدرس',
	'The LAN and this router (0.0.0.0)': 'شبکهٔ محلی و خود روتر (0.0.0.0)',
	'This router only (127.0.0.1)': 'فقط خود روتر (127.0.0.1)',
	'With “This router only” no device on the LAN can open the web UI; these LuCI pages keep working either way.': 'با «فقط خود روتر» هیچ دستگاهی در شبکه رابط وب را باز نمی‌کند؛ این صفحه‌های LuCI در هر دو حالت کار می‌کنند.',

	// Remote access
	'Control this router from outside the home — turn the VPN on or off, change the config — without a static IP, even behind CGNAT. The control link never goes through the VPN. Both ways can be on at once.': 'این روتر را از بیرون خانه کنترل کن — VPN را روشن یا خاموش کن، کانفیگ را عوض کن — بدون IP ثابت و حتی پشت CGNAT. لینک کنترل هیچ‌وقت از داخل VPN نمی‌رود. هر دو راه می‌توانند هم‌زمان روشن باشند.',
	'Changes take effect only when you press Save at the bottom of the page.': 'تغییرها فقط با دکمهٔ «ذخیره» پایین صفحه اعمال می‌شوند.',
	'Your own relay': 'رلهٔ خودت',
	'The relay is a server you run yourself; IRNetFree does not provide one. Deploy relay/ on Harbora or any Docker host, press Add router on the relay’s page, then paste the relay URL and the 43-character device token here.': 'رله سرور خودِ توست؛ IRNetFree رله‌ای نمی‌دهد. اول relay/ را روی هاربورا یا هر سرور داکر بالا بیاور، در صفحهٔ رله «Add router» را بزن، بعد آدرس رله و توکن ۴۳ کاراکتری را این‌جا بچسبان.',
	'Step-by-step guide: docs/remote.md': 'راهنمای قدم‌به‌قدم: docs/remote.md',
	'To enable, first enter the relay URL and the device token': 'برای فعال‌کردن، اول آدرس رله و توکن دستگاه را وارد کن',
	'Install cloudflared first (the Install button above)': 'اول cloudflared را نصب کن (دکمهٔ «نصب» بالا)',
	'Paste the Cloudflare tunnel token first': 'اول توکن تونل کلودفلر را بچسبان',
	'The token must be the 43-character device token the relay showed.': 'توکن باید همان توکن ۴۳ کاراکتری‌ای باشد که رله نشان داد.',
	'The Cloudflare tunnel token does not look right.': 'توکن تونل کلودفلر درست به نظر نمی‌رسد.',
	'Enabled': 'فعال',
	'Relay URL': 'آدرس رله',
	'Use https:// and a host name, with no path.': 'با https:// و نام میزبان بنویس، بدون مسیر.',
	'Router name': 'نام روتر',
	'Up to 40 characters.': 'حداکثر 40 کاراکتر.',
	'home': 'خانه',
	'Device token': 'توکن دستگاه',
	'A token is set. Type a new one only to replace it.': 'توکن تنظیم شده است. فقط برای عوض کردنش توکن جدید بنویس.',
	'Not set yet: paste the token the relay showed when you added this router.': 'هنوز تنظیم نشده: توکنی را که رله هنگام افزودن این روتر نشان داد بچسبان.',
	'State': 'وضعیت',
	'Open the relay': 'باز کردن رله',
	'Cloudflare Tunnel': 'تونل کلودفلر',
	'A second way in, through Cloudflare: create a tunnel in the Cloudflare dashboard, point its public hostname at http://127.0.0.1:%s and protect it with Cloudflare Access, then paste the tunnel token here.': 'راه دوم، از طریق کلودفلر: در داشبورد کلودفلر یک تونل بساز، نام عمومی‌اش را به http://127.0.0.1:%s بفرست و با Cloudflare Access از آن محافظت کن، بعد توکن تونل را این‌جا بچسبان.',
	'cloudflared program': 'برنامهٔ cloudflared',
	'Installed': 'نصب شده',
	'Not installed': 'نصب نشده',
	'Install': 'نصب',
	'Installing… (opkg update, then opkg install cloudflared — this can take a few minutes)': 'در حال نصب… (opkg update و بعد opkg install cloudflared — ممکن است چند دقیقه طول بکشد)',
	'cloudflared is installed.': 'cloudflared نصب شد.',
	'Install failed: %s': 'نصب ناموفق بود: %s',
	'Tunnel token': 'توکن تونل',
	'Not set yet: paste the token of the tunnel you created in the Cloudflare dashboard.': 'هنوز تنظیم نشده: توکن تونلی را که در داشبورد کلودفلر ساختی بچسبان.',

	// Log
	'IRNetFree log': 'لاگ IRNetFree',
	'The service’s last 300 lines, newest at the bottom.': '300 خط آخر لاگ سرویس، جدیدترین پایین.',
	'Refresh': 'تازه‌سازی',
	'Copy diagnostics': 'کپی اطلاعات عیب‌یابی',
	'Copy diagnostics puts the status, versions, memory, routing rules and these lines on the clipboard for a bug report — tokens and passwords are left out.': '«کپی اطلاعات عیب‌یابی» وضعیت، نسخه‌ها، حافظه، قانون‌های مسیریابی و همین خط‌ها را برای گزارش مشکل در کلیپ‌بورد می‌گذارد — توکن‌ها و رمزها حذف می‌شوند.',
	'The log is empty.': 'لاگ خالی است.',
	'Diagnostics copied to the clipboard.': 'اطلاعات عیب‌یابی در کلیپ‌بورد کپی شد.'
};

/* LuCI's language: the theme writes it on <html lang>; fa → Persian. */
function isFa() {
	var lang = (L.env && L.env.lang) || (document.documentElement && document.documentElement.getAttribute('lang')) || '';
	return /^fa(\b|[-_])/i.test(String(lang));
}

function fill(s, args) {
	var i = 0;
	return String(s).replace(/%s/g, function () { return i < args.length ? String(args[i++]) : ''; });
}

/* t('Reconnecting… (attempt %s)', 2): the Persian text when LuCI runs in fa, else the English. */
function t(en) {
	var s = (isFa() && Object.prototype.hasOwnProperty.call(FA, en)) ? FA[en] : en;
	return fill(s, Array.prototype.slice.call(arguments, 1));
}

/* The state badge: the text and a tone for each state the service reports
 * (connSnapshot, spec S1/S4/B3). attempt counts recoveries and boot retries. */
function badge(state, attempt, reason) {
	var n = (+attempt > 0) ? Math.floor(+attempt) : 0;
	switch (state) {
	case 'connected': return { text: t('Connected'), tone: 'ok' };
	case 'connecting': return { text: t('Connecting…'), tone: 'busy' };
	case 'reconnecting': return { text: n ? t('Reconnecting… (attempt %s)', n) : t('Reconnecting…'), tone: 'busy' };
	case 'waiting': return { text: n ? t('Waiting for internet… (attempt %s)', n) : t('Waiting for internet…'), tone: 'busy' };
	case 'disconnected': return { text: t('Disconnected'), tone: 'off' };
	case 'error': return { text: reason ? t('Error: %s', reason) : t('Error'), tone: 'bad' };
	default: return { text: t('Unknown'), tone: 'off' };
	}
}

var TONES = { ok: '#2e7d32', busy: '#e08a00', off: '#6c757d', bad: '#c62828' };

function renderBadge(b) {
	return E('span', {
		'class': 'irnf-badge',
		'data-tone': b.tone,
		'style': 'display:inline-block;padding:.15em .7em;border-radius:1em;color:#fff;font-weight:bold;background:' + (TONES[b.tone] || TONES.off)
	}, [ b.text ]);
}

/* The VPN is "on" (the switch) in every state where the service means to be connected. */
function vpnOn(state) {
	return state === 'connected' || state === 'connecting' || state === 'reconnecting' || state === 'waiting';
}

/* What a reply says went wrong, as a sentence for the page — or null when it is a reply.
 * {} is what LuCI gives when the ubus call itself failed (no plugin, no permission). */
function errorOf(res) {
	if (res == null || typeof res !== 'object') return t('No answer from the service.');
	if (res.error == null) return Object.keys(res).length ? null : t('No answer from the service.');
	var e = String(res.error), m;
	if (e === 'not-running') return t('The IRNetFree service is not running.');
	if (e === 'timeout') return t('The service did not answer in time.');
	if (e === 'unauthorized') return t('The service refused the request: its token changed. Restart the service.');
	if (e === 'unknown method' || e === 'http 404' || e === 'http 405') return t('This IRNetFree service does not know this request yet — update IRNetFree.');
	if (e === 'remote not available') return t('Remote access is not part of this IRNetFree version.');
	if ((m = /^http (\d+)$/.exec(e)) != null) return t('The service answered with an error (HTTP %s).', m[1]);
	if (e === 'empty reply' || e === 'bad reply') return t('No answer from the service.');
	return serviceRefusal(e) || t('Error: %s', e);
}

/* The remote api's refusals (src/server/remote/api.js, remote_set) as the
 * page's own sentences — a refusal in English was missed (field report L1). */
function serviceRefusal(e) {
	switch (e) {
	case 'enabling needs the relay URL and the device token': return t('To enable, first enter the relay URL and the device token');
	case 'enabling needs cloudflared — install it first': return t('Install cloudflared first (the Install button above)');
	case 'enabling needs the Cloudflare tunnel token': return t('Paste the Cloudflare tunnel token first');
	case 'token must be the 43-character device token the relay showed': return t('The token must be the 43-character device token the relay showed.');
	case 'relayUrl must be https://<host>[:port]/ with no path': return t('Use https:// and a host name, with no path.');
	case 'name must be at most 40 printable characters': return t('Up to 40 characters.');
	case 'the Cloudflare tunnel token does not look right': return t('The Cloudflare tunnel token does not look right.');
	default: return null;
	}
}

/* Why ticking «Enabled» cannot be saved as the form stands — the checks
 * remote_set makes, so nothing is sent that it would refuse — or null. */
function relayEnableProblem(on, relayUrl, hasToken) {
	return (on && !(relayUrl && hasToken)) ? t('To enable, first enter the relay URL and the device token') : null;
}

function cloudflaredEnableProblem(on, installed, hasToken) {
	if (!on) return null;
	if (!installed) return t('Install cloudflared first (the Install button above)');
	return hasToken ? null : t('Paste the Cloudflare tunnel token first');
}

/* A refused Save: a dialog with the reason and Close — a notice at the top of
 * the page was easy to miss below the fold (field report L1). */
function showRefusal(msg) {
	ui.showModal(t('Not saved'), [
		E('p', {}, [ String(msg) ]),
		E('div', { 'class': 'right' }, [ E('button', { 'class': 'btn', 'click': ui.hideModal }, [ t('Close') ]) ])
	]);
}

function isDown(res) {
	return !!(res && res.error === 'not-running');
}

/* A call that did not resolve at all — LuCI's rpc rejects when the HTTP request
 * fails or times out (20 s) and when ubus refuses it (a LuCI user with only the
 * read half of luci-app-irnetfree gets "Access denied" for every action). */
function rpcError(e) {
	var m = String((e && e.message) || e || '');
	if (/Access denied|-32002/.test(m)) return t('Your LuCI login may not change IRNetFree (it needs write access to luci-app-irnetfree).');
	if (/timed out|timeout/i.test(m)) return t('The router did not answer in time.');
	return t('Error: %s', m.split('\n')[0]);
}

function failed(e) {
	return notify(rpcError(e), 'danger');
}

/* A list reply: the plugin wraps the service's arrays as {result: […]}. */
function list(res) {
	if (Array.isArray(res)) return res;
	return (res && Array.isArray(res.result)) ? res.result : [];
}

function pad2(n) { return (n < 10 ? '0' : '') + n; }

/* 3725 → "01:02:05", 90061 → "1d 01:01:01" */
function duration(sec) {
	sec = Math.max(0, Math.floor(+sec || 0));
	var d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
	var hms = pad2(h) + ':' + pad2(m) + ':' + pad2(s);
	return d ? t('%sd %s', d, hms) : hms;
}

/* bytes → "0 B", "1.5 KB", "12.3 MB", "1.02 GB" */
function size(n) {
	n = +n || 0;
	if (n < 1024) return Math.max(0, Math.round(n)) + ' B';
	var units = [ 'KB', 'MB', 'GB', 'TB' ], i = -1;
	do { n /= 1024; i++; } while (n >= 1024 && i < units.length - 1);
	return (n >= 100 ? n.toFixed(0) : n >= 10 ? n.toFixed(1) : n.toFixed(2)) + ' ' + units[i];
}

function rate(n) { return size(n) + '/s'; }

function traffic(tr) {
	if (!tr || typeof tr !== 'object') return '—';
	return t('Download %s (%s) · Upload %s (%s)', size(tr.down), rate(tr.downRate), size(tr.up), rate(tr.upRate));
}

function clock(ms) {
	var d = new Date(+ms);
	return isNaN(d.getTime()) ? '' : d.toLocaleString();
}

/* The relay agent's status ({state, path, since, lastError, attempt}) as a
 * phrase; while it redials, the attempt and why the last one failed. */
function relayText(r) {
	if (!r || typeof r !== 'object') return t('off');
	var s, n;
	switch (r.state) {
	case 'online': s = (r.path === 'vpn') ? t('online through the VPN') : t('online (direct)'); break;
	case 'connecting':
		n = (+r.attempt > 0) ? Math.floor(+r.attempt) : 0;
		s = !n ? t('connecting…') : r.lastError ? t('connecting… (attempt %s) — %s', n, r.lastError) : t('connecting… (attempt %s)', n);
		break;
	case 'error': s = r.lastError ? t('offline — %s', r.lastError) : t('offline'); break;
	case 'off': return t('off');
	default: s = r.state ? String(r.state) : t('off');
	}
	return (r.since && r.state === 'online') ? s + ' · ' + t('since %s', clock(r.since)) : s;
}

/* cloudflared's status as a phrase: {installed, running, lastLine} and, from
 * v1.16.1, {enabled, tokenSet, applying, apply: {ok, error}, installing} —
 * meant to run and not running says why (it used to say nothing, L2). */
function cloudflaredText(c) {
	if (!c || typeof c !== 'object') return t('not installed');
	if (c.installing) return t('installing…');
	if (c.applying) return t('applying…');
	if (c.installed && c.running) return t('running');
	if (c.enabled) return t('Enabled but not running: %s', cloudflaredWhy(c));
	return c.installed ? t('stopped') : t('not installed');
}

function cloudflaredWhy(c) {
	if (!c.installed) return t('cloudflared is not installed');
	if (c.tokenSet === false) return t('no tunnel token');
	if (c.apply && c.apply.ok === false && c.apply.error) return String(c.apply.error);
	if (c.lastLine) return String(c.lastLine);
	return t('see the Log tab');
}

function remoteLine(rm) {
	if (!rm || typeof rm !== 'object' || (!rm.relay && !rm.cloudflared)) return null;
	return t('Relay: %s', relayText(rm.relay)) + ' · ' + t('Cloudflare Tunnel: %s', cloudflaredText(rm.cloudflared));
}

/* The <optgroup> label of a config group from the configs reply. */
function groupLabel(g) {
	switch (g && g.kind) {
	case 'manual': return t('Manual servers');
	case 'chains': return t('Chains');
	case 'pools': return t('Pools');
	case 'routing': return t('Advanced routing');
	default: return (g && g.name) ? String(g.name) : t('Subscription');
	}
}

function itemLabel(it, active) {
	var s = String(it.name || it.id || '?');
	if (it.proto) s += ' · ' + it.proto;
	return active ? '● ' + s : s;
}

var MAC = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;

function normMac(s) {
	return String(s == null ? '' : s).trim().toLowerCase().replace(/-/g, ':');
}

function isMac(s) {
	return MAC.test(normMac(s));
}

function deviceLabel(d) {
	return (d.name ? String(d.name) : t('Unknown device')) + ' (' + (d.ip || '-') + ', ' + normMac(d.mac) + ')';
}

/* The four router settings, normalised: booleans and a lower-case MAC list. */
function routerSettings(s) {
	s = s || {};
	return {
		autoConnect: !!s.autoConnect,
		killSwitch: !!s.killSwitch,
		lanBlockQuic: !!s.lanBlockQuic,
		lanBypassMacs: (Array.isArray(s.lanBypassMacs) ? s.lanBypassMacs : []).map(normMac).filter(isMac)
	};
}

/* The keys of `next` that differ from `prev` (lists compared as sets), or null. */
function changed(prev, next) {
	var out = {}, any = false;
	for (var k in next) {
		if (!Object.prototype.hasOwnProperty.call(next, k)) continue;
		var a = prev ? prev[k] : undefined, b = next[k];
		var same = (Array.isArray(a) || Array.isArray(b))
			? (a || []).slice().sort().join(' ') === (b || []).slice().sort().join(' ')
			: a === b;
		if (!same) { out[k] = b; any = true; }
	}
	return any ? out : null;
}

function validRelayUrl(v) {
	return /^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?\/?$/.test(String(v || ''));
}

function validRouterName(v) {
	v = String(v == null ? '' : v);
	return v.length <= 40 && !/[\u0000-\u001f\u007f]/.test(v);
}

function webUiUrl(host, port, token) {
	return 'http://' + host + ':' + port + '/' + (token ? '?token=' + encodeURIComponent(token) : '');
}

/* A notice at the top of the page that goes away by itself. */
function notify(msg, kind) {
	var n = ui.addNotification(null, E('p', {}, [ msg ]), kind || 'info');
	if (kind !== 'danger')
		window.setTimeout(function () { if (n && n.parentNode) n.parentNode.removeChild(n); }, 6000);
	return n;
}

/* The box a page shows instead of its content when the service does not answer:
 * the reason, and Start when it is not running. onStarted runs after a start. */
function problemBox(res, onStarted) {
	var children = [ E('p', {}, [ errorOf(res) || '' ]) ];
	if (isDown(res)) {
		children.push(E('button', {
			'class': 'btn cbi-button cbi-button-apply',
			'click': ui.createHandlerFn(null, function () {
				return serviceAction('start').then(function (r) {
					var e = errorOf(r);
					if (e) return notify(e, 'danger');
					notify(t('Starting the service…'));
					if (typeof onStarted === 'function') return onStarted();
				}, failed);
			})
		}, [ t('Start the service') ]));
	}
	return E('div', { 'class': 'alert-message warning irnf-problem' }, children);
}

/* After a start: ask every 2 s until the service answers (any reply but
 * not-running), at most `tries` times. → Promise<boolean> */
function waitUntilUp(tries) {
	tries = (tries == null) ? 20 : tries;
	return statusCall().then(function (r) { return !isDown(r); }, function () { return false; }).then(function (up) {
		if (up || tries <= 1) return up;
		return new Promise(function (resolve) { window.setTimeout(resolve, 2000); }).then(function () { return waitUntilUp(tries - 1); });
	});
}

/* What a page that cannot render without the service does after Start:
 * reload once the service answers — node takes a while to listen on a slow router. */
function reloadWhenUp() {
	return waitUntilUp().then(function (up) {
		if (up) window.location.reload();
		else notify(t('The service has not answered yet — it may still be starting. Reload this page in a moment.'), 'warning');
	});
}

/* Copy text: the async clipboard where the page is a secure context, the old
 * execCommand way elsewhere (a router is usually plain http). → Promise<boolean> */
function copyText(text) {
	var nav = window.navigator;
	if (nav && nav.clipboard && window.isSecureContext)
		return nav.clipboard.writeText(text).then(function () { return true; }, function () { return legacyCopy(text); });
	return Promise.resolve(legacyCopy(text));
}

function legacyCopy(text) {
	var ta = E('textarea', { 'style': 'position:fixed;top:0;left:0;width:2em;height:2em;opacity:0', 'readonly': 'readonly' });
	ta.value = text;
	document.body.appendChild(ta);
	var ok = false;
	try {
		ta.select();
		ok = !!document.execCommand('copy');
	}
	catch (e) { ok = false; }
	document.body.removeChild(ta);
	return ok;
}

/* When copying is not allowed: the text in a dialog, ready to select. */
function showText(title, text) {
	var ta = E('textarea', { 'class': 'cbi-input-textarea', 'dir': 'ltr', 'readonly': 'readonly', 'style': 'width:100%;height:22em;font-family:monospace;font-size:12px' });
	ta.value = text;
	ui.showModal(title, [
		E('p', {}, [ t('The browser did not allow copying. Select all the text below and copy it.') ]),
		ta,
		E('div', { 'class': 'right' }, [ E('button', { 'class': 'btn', 'click': ui.hideModal }, [ t('Close') ]) ])
	]);
	try { ta.focus(); ta.select(); } catch (e) { /* not on this browser */ }
	return ta;
}

/* docs/remote.md: running the relay, pairing a router, Cloudflare Tunnel (English, then Persian) */
var REMOTE_GUIDE = 'https://github.com/sadrazkh/Irnetfree_xray-client/blob/main/docs/remote.md';

var serviceAction = call('service', [ 'action' ]);
var statusCall = call('status');

return baseclass.extend({
	/* the service's local API, through the rpcd plugin (spec §3.4) */
	status: statusCall,
	configs: call('configs'),
	connect: call('connect', [ 'id' ]),
	select: call('select', [ 'id' ]),
	disconnect: call('disconnect'),
	reconnect: call('reconnect'),
	test: call('test'),
	subsUpdate: call('subs_update'),
	settingsGet: call('settings_get'),
	settingsSet: rpc.declare({ object: 'luci.irnetfree', method: 'settings_set', params: [ 'autoConnect', 'killSwitch', 'lanBlockQuic', 'lanBypassMacs' ], expect: { '': {} } }),
	devices: call('devices'),
	log: call('log', [ 'lines' ]),
	diagnostics: call('diagnostics'),
	remoteGet: call('remote_get'),
	remoteSet: call('remote_set', [ 'relay', 'cloudflared' ]),
	remoteStatus: call('remote_status'),
	cloudflaredInstall: call('cloudflared_install'),
	/* answered by the plugin itself: start or restart the service */
	service: serviceAction,

	dict: FA,
	t: t,
	badge: badge,
	renderBadge: renderBadge,
	vpnOn: vpnOn,
	errorOf: errorOf,
	isDown: isDown,
	list: list,
	duration: duration,
	size: size,
	rate: rate,
	traffic: traffic,
	relayText: relayText,
	cloudflaredText: cloudflaredText,
	remoteLine: remoteLine,
	groupLabel: groupLabel,
	itemLabel: itemLabel,
	normMac: normMac,
	isMac: isMac,
	deviceLabel: deviceLabel,
	routerSettings: routerSettings,
	changed: changed,
	validRelayUrl: validRelayUrl,
	validRouterName: validRouterName,
	webUiUrl: webUiUrl,
	remoteGuide: REMOTE_GUIDE,
	relayEnableProblem: relayEnableProblem,
	cloudflaredEnableProblem: cloudflaredEnableProblem,
	showRefusal: showRefusal,
	notify: notify,
	rpcError: rpcError,
	failed: failed,
	problemBox: problemBox,
	waitUntilUp: waitUntilUp,
	reloadWhenUp: reloadWhenUp,
	copyText: copyText,
	showText: showText
});
