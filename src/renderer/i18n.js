'use strict';
/* Lightweight i18n: fa (RTL) + en (LTR). Applies to [data-i18n],
   [data-i18n-ph] (placeholder) and [data-i18n-title] (title attr). */

(function () {
const I18N = {
  fa: {
    'app.name': 'IRNetFree',
    'nav.home': 'اتصال', 'nav.servers': 'سرورها', 'nav.subs': 'ساب‌ها',
    'nav.chain': 'زنجیره', 'nav.routing': 'روتینگ', 'nav.settings': 'تنظیمات', 'nav.logs': 'لاگ‌ها',
    'tb.min': 'کوچک', 'tb.hide': 'مخفی', 'tb.close': 'بستن',

    'pill.connected': 'متصل', 'pill.disconnected': 'قطع', 'pill.connecting': 'اتصال…', 'pill.error': 'خطا',
    'state.connected': 'متصل', 'state.disconnected': 'قطع شده',
    'state.connecting': 'در حال اتصال…', 'state.error': 'خطا',
    'conn.noServer': 'سروری انتخاب نشده',

    'stat.tcp': 'پینگ TCP', 'stat.real': 'تأخیر واقعی', 'stat.ip': 'IP خروجی',
    'geo.unknown': 'موقعیت نامشخص',

    'traffic.down': 'دانلود', 'traffic.up': 'آپلود',
    'mode.proxy': 'پروکسی', 'mode.tun': 'TUN',
    'mode.proxySub': 'SOCKS/HTTP', 'mode.tunSub': 'کل سیستم',

    'session.title': 'مصرف این نشست',
    'session.down': 'دانلود کل', 'session.up': 'آپلود کل', 'session.sum': 'مجموع',

    'btn.quickPing': 'تست پینگ', 'btn.checkIp': 'بررسی IP',
    'picker.choose': 'سرور را انتخاب کن', 'picker.none': 'سروری موجود نیست',
    'picker.listLabel': 'سرورها و زنجیره‌ها',

    'servers.title': 'سرورها',
    'btn.pingAll': 'تست همه', 'btn.clearAll': 'حذف همه', 'btn.add': '+ افزودن',
    'import.ph': 'کانفیگ یا آدرس ساب را اینجا بذار (یا هر جای برنامه Ctrl+V کن):\nvless://...  vmess://...  trojan://...  ss://...\nhttps://...  ← آدرس ساب‌اسکریپشن (خودکار تشخیص داده می‌شود)\nیا متن base64 ساب',
    'btn.import': 'وارد کردن', 'btn.cancel': 'انصراف',
    'servers.empty': 'هنوز سروری اضافه نشده. روی «افزودن» بزن.',
    'srv.selected': 'انتخاب‌شده',
    'btn.edit': 'ویرایش', 'btn.addWg': '+ وایرگارد', 'btn.addWgGo': 'افزودن',

    'wg.title': 'افزودن WireGuard', 'wg.name': 'نام', 'wg.namePh': 'نام دلخواه',
    'wg.endpoint': 'Endpoint (host:port)', 'wg.privateKey': 'کلید خصوصی',
    'wg.publicKey': 'کلید عمومی Peer', 'wg.address': 'Address (محلی، /32)',
    'wg.psk': 'کلید پیش‌اشتراکی (اختیاری)', 'wg.mtu': 'MTU', 'wg.reserved': 'Reserved (اختیاری)',
    'wg.allowed': 'Allowed IPs (رنج‌های مجاز)',
    'wg.endpointHost': 'آدرس سرور (Endpoint host)',
    'wg.endpointPort': 'پورت سرور (Endpoint port)',
    'wg.addrHint': '«Address» باید آدرس محلی خودت در کانفیگ WireGuard باشد و حتماً /32 (مثل 10.8.0.2/32). برای دسترسی به رنج دیتابیس، رنج را در «Allowed IPs» بگذار (مثل 192.168.60.0/24) یا 0.0.0.0/0 را نگه دار.',

    'edit.title': 'ویرایش سرور', 'edit.name': 'نام', 'edit.address': 'آدرس', 'edit.port': 'پورت',
    'edit.uuid': 'شناسه (UUID)', 'edit.password': 'رمز عبور',
    'edit.network': 'ترنسپورت', 'edit.security': 'امنیت', 'edit.sni': 'SNI', 'edit.host': 'Host',
    'edit.path': 'Path / ServiceName', 'edit.fp': 'Fingerprint',
    'edit.pbk': 'Public Key (pbk)', 'edit.sid': 'Short ID (sid)', 'edit.allowInsecure': 'Allow Insecure',

    'chain.title': 'زنجیره پروکسی', 'chain.enable': 'فعال‌سازی زنجیره',
    'chain.hint': 'ترافیک به‌ترتیب از این سرورها عبور می‌کند. با کشیدن و رها کردن، ترتیب را تغییر بده.',
    'chain.client': '💻 شما', 'chain.internet': '🌐 اینترنت',
    'chain.empty': 'هنوز سروری به زنجیره اضافه نشده. از پایین اضافه کن (حداقل ۲ سرور لازم است).',
    'chain.available': 'سرورهای موجود', 'chain.poolEmpty': 'همه سرورها در زنجیره هستند.',
    'chain.add': 'افزودن به زنجیره',
    'chain.new': '+ زنجیره جدید',
    'chain.intro': 'هر زنجیره مثل یک کانفیگ ساخته می‌شود: یک نام بده، چند سرور را به‌ترتیب بچین، سپس از صفحهٔ «اتصال» یا در «روتینگ ویژه» مثل یک کانفیگ ازش استفاده کن. می‌توانی چند زنجیره داشته باشی و هرکدام را پینگ بگیری.',
    'chain.wgHint': 'برای رسیدن به دیتابیس وقتی WireGuard مستقیم کار نمی‌کند: یک کانفیگ را اولِ زنجیره و WireGuard را آخرِ زنجیره بگذار؛ بعد در «روتینگ ویژه» رنج IP دیتابیس را به این زنجیره بفرست (اول از کانفیگ رد می‌شود، بعد روی آن رنج از WireGuard).',
    'chain.noneYet': 'هنوز زنجیره‌ای ساخته نشده. روی «زنجیره جدید» بزن.',
    'chain.addFromBelow': 'از پایین سرور اضافه کن…',

    'mode.pick': 'حالت اتصال', 'mode.proxyDesc': 'سبک و سریع؛ فقط برنامه‌هایی که از پروکسی سیستمی/SOCKS استفاده می‌کنند تونل می‌شوند.',
    'mode.tunDesc': 'تمام ترافیک کل سیستم از تونل عبور می‌کند (نیازمند tun2socks و دسترسی ادمین).',

    'subs.title': 'ساب‌اسکریپشن‌ها',
    'btn.refreshAll': 'به‌روزرسانی همه', 'btn.addSub': '+ افزودن ساب',
    'sub.urlPh': 'آدرس ساب‌اسکریپشن (https://…)', 'sub.namePh': 'نام دلخواه (اختیاری)',
    'btn.addFetch': 'افزودن و دریافت',
    'autoupdate.title': 'به‌روزرسانی خودکار', 'autoupdate.sub': 'ساب‌ها در فاصله‌ی مشخص خودکار تازه می‌شن',
    'interval.label': 'فاصله (دقیقه)', 'subs.empty': 'هنوز ساب‌اسکریپشنی اضافه نشده.',
    'sub.servers': 'سرور', 'sub.lastUpdate': 'آخرین به‌روزرسانی',

    'routing.title': 'روتینگ', 'routing.modeLabel': 'حالت روتینگ',
    'routing.global': 'گلوبال (همه از پروکسی)', 'routing.bypassIr': 'دور زدن ایران',
    'routing.bypassCn': 'دور زدن چین', 'routing.direct': 'مستقیم',
    'routing.hint': 'در حالت «دور زدن ایران»، ترافیک داخلی مستقیم می‌ره و بقیه از پروکسی.',
    'ads.title': 'مسدودسازی تبلیغات', 'ads.sub': 'دامنه‌های تبلیغاتی بلاک می‌شن',
    'sniff.title': 'Sniffing', 'sniff.sub': 'تشخیص دامنه برای روتینگ دقیق‌تر',
    'rules.label': 'قوانین سفارشی',
    'rules.hint': 'هر خط: domain|ip|port , مقدار , خروجی(proxy/direct/block)',
    'btn.saveRules': 'ذخیره قوانین',
    'routing.geoNote': 'روتینگ به فایل‌های geoip.dat و geosite.dat نیاز دارد. اگر کار نمی‌کند، از تنظیمات → فایل‌های موردنیاز آن‌ها را دانلود کن.',

    'settings.title': 'تنظیمات',
    'set.socks': 'پورت SOCKS', 'set.http': 'پورت HTTP',
    'set.dns': 'DNS (با کاما)', 'set.logLevel': 'سطح لاگ',
    'set.lang': 'زبان / Language',
    'sysproxy.title': 'پروکسی سیستمی', 'sysproxy.sub': 'هنگام اتصال، پروکسی ویندوز تنظیم بشه',
    'tun.title': 'حالت TUN (تانل کل سیستم)', 'tun.sub': 'همه‌ی ترافیک سیستم از تانل رد می‌شه (نیازمند tun2socks و دسترسی ادمین)',
    'lan.title': 'اجازه به شبکه محلی (LAN)', 'lan.sub': 'دستگاه‌های دیگه هم بتونن وصل بشن',

    'comp.title': 'فایل‌های موردنیاز', 'comp.hint': 'اگر فایلی نبود با یک کلیک دانلود و یکپارچه می‌شود — بدون نیاز به ساخت دوباره برنامه.',
    'comp.xray': 'هسته Xray', 'comp.tun2socks': 'tun2socks (حالت TUN)',
    'comp.wintun': 'wintun.dll (حالت TUN)', 'comp.geo': 'فایل‌های روتینگ (geoip + geosite)',
    'comp.installed': 'نصب‌شده', 'comp.missing': 'موجود نیست',
    'btn.download': 'دانلود', 'btn.update': 'به‌روزرسانی', 'btn.downloading': 'در حال دانلود…',

    'xray.label': 'مسیر هسته Xray', 'xray.checking': 'در حال بررسی…',
    'xray.ok': '✓ هسته Xray پیدا شد و آماده است',
    'xray.missing': '✗ هسته Xray پیدا نشد. از «فایل‌های موردنیاز» دانلودش کن یا فایل را انتخاب کن.',
    'btn.locate': 'انتخاب فایل xray', 'btn.openData': 'پوشه داده‌ها', 'btn.help': 'راهنمای دانلود',
    'btn.save': 'ذخیره تنظیمات', 'saved': 'ذخیره شد ✓',

    'logs.title': 'لاگ‌ها', 'btn.clearLogs': 'پاک کردن',

    'tun.unavailable': '⚠ tun2socks یا wintun.dll پیدا نشد — حالت TUN غیرفعال است. از «فایل‌های موردنیاز» دانلودشان کن.',
    'tun.ready': '✓ حالت TUN آماده است (هنگام اتصال، کل سیستم تانل می‌شود — اجرا با دسترسی ادمین).',
    'tun.off': 'حالت TUN در دسترس است ولی خاموش.',

    't.settingsSaved': 'تنظیمات ذخیره شد', 't.rulesSaved': 'قوانین ذخیره شد',
    't.routingMode': 'حالت روتینگ', 't.noServerSel': 'سروری انتخاب نشده',
    't.addServerFirst': 'اول یک سرور اضافه کن', 't.pingingAll': 'در حال تست همه سرورها…',
    't.testDone': 'تست تمام شد', 't.allServersDeleted': 'همه سرورها حذف شدند',
    't.connectFailed': 'اتصال ناموفق', 't.disconnected': 'اتصال قطع شد',
    't.ipFailed': 'بررسی IP ناموفق', 't.subAdded': 'ساب اضافه شد',
    't.subAddedShort': 'ساب', 't.nothingFound': 'چیزی برای افزودن پیدا نشد',
    't.pasteDetected': 'در حال افزودن از کلیپ‌بورد…',
    't.subUrl': 'آدرس ساب را وارد کن', 't.fetching': 'در حال دریافت…',
    't.updating': 'در حال به‌روزرسانی…', 't.updated': 'به‌روز شد', 't.failed': 'ناموفق',
    't.subRemoved': 'ساب حذف شد', 't.noSubs': 'ساب‌اسکریپشنی موجود نیست',
    't.serversAdded': 'سرور اضافه شد', 't.errors': 'خطا',
    't.tunNeedFiles': 'برای حالت TUN باید tun2socks و wintun.dll دانلود شوند',
    't.tunReconnect': 'برای اعمال حالت TUN، دوباره وصل شو',
    't.downloading': 'در حال دانلود', 't.downloaded': 'دانلود و یکپارچه شد', 't.downloadFailed': 'دانلود ناموفق',
    't.xraySet': 'هسته Xray تنظیم شد', 't.xrayDownPage': 'صفحه دانلود Xray-core باز شد',
    't.never': 'هرگز', 't.secAgo': 'ثانیه پیش', 't.minAgo': 'دقیقه پیش', 't.hrAgo': 'ساعت پیش', 't.dayAgo': 'روز پیش',
    't.error': 'خطا',
    't.serverUpdated': 'سرور به‌روزرسانی شد', 't.wgAdded': 'WireGuard اضافه شد',
    't.wgMissing': 'Endpoint و کلید خصوصی و عمومی لازم است',
    't.wgBadEndpoint': 'Endpoint باید آدرس سرور عمومی به شکل host:port باشد (مثل cobra.tes.ca:42421)، نه آدرس محلی تونل',
    't.chainOn': 'زنجیره فعال شد', 't.chainOff': 'زنجیره غیرفعال شد',

    'picker.chain': 'زنجیره', 'picker.advanced': 'روتینگ ویژه',
    'chain.pickHint': 'پس از ساخت زنجیره، از صفحه «اتصال» گزینه ⛓ زنجیره را انتخاب و وصل شو.',

    'adv.title': 'روتینگ ویژه (پیشرفته)',
    'adv.sub': 'هر IP/دامنه/پورت را به یک کانفیگ، زنجیره، مستقیم یا بلاک بفرست',
    'adv.hint': 'قانون‌ها از بالا به پایین بررسی می‌شوند؛ اولین تطابق اعمال می‌شود. بقیه ترافیک از «پیش‌فرض» می‌رود. در صفحه «اتصال» گزینه 🧭 را انتخاب کن.',
    'adv.addRule': '+ افزودن قانون', 'adv.default': 'بقیه ترافیک (پیش‌فرض)',
    'adv.save': 'ذخیره روتینگ', 'adv.direct': 'مستقیم', 'adv.block': 'بلاک',
    'adv.empty': 'هنوز قانونی نیست. «افزودن قانون» را بزن.',
    'adv.valuePh': 'مثلا 1.2.3.0/24 یا example.com یا 443',
    'adv.type.ip': 'IP', 'adv.type.domain': 'دامنه', 'adv.type.port': 'پورت',

    'tun.needAdmin': '⚠ حالت TUN نیازمند دسترسی ادمین است. برای فعال شدن تانل، برنامه را با دسترسی ادمین اجرا کن.',
    'tun.runAdmin': 'اجرا با دسترسی ادمین',

    't.advOn': 'روتینگ ویژه فعال شد', 't.advOff': 'روتینگ ویژه غیرفعال شد',
    't.advSaved': 'روتینگ ویژه ذخیره شد', 't.adminFailed': 'اجرا با دسترسی ادمین ناموفق بود'
  },

  en: {
    'app.name': 'IRNetFree',
    'nav.home': 'Connect', 'nav.servers': 'Servers', 'nav.subs': 'Subs',
    'nav.chain': 'Chain', 'nav.routing': 'Routing', 'nav.settings': 'Settings', 'nav.logs': 'Logs',
    'tb.min': 'Minimize', 'tb.hide': 'Hide', 'tb.close': 'Close',

    'pill.connected': 'Connected', 'pill.disconnected': 'Off', 'pill.connecting': 'Connecting…', 'pill.error': 'Error',
    'state.connected': 'Connected', 'state.disconnected': 'Disconnected',
    'state.connecting': 'Connecting…', 'state.error': 'Error',
    'conn.noServer': 'No server selected',

    'stat.tcp': 'TCP ping', 'stat.real': 'Real delay', 'stat.ip': 'Egress IP',
    'geo.unknown': 'Unknown location',

    'traffic.down': 'Download', 'traffic.up': 'Upload',
    'mode.proxy': 'Proxy', 'mode.tun': 'TUN',
    'mode.proxySub': 'SOCKS/HTTP', 'mode.tunSub': 'Whole system',

    'session.title': 'This session',
    'session.down': 'Total down', 'session.up': 'Total up', 'session.sum': 'Total',

    'btn.quickPing': 'Ping test', 'btn.checkIp': 'Check IP',
    'picker.choose': 'Choose a server', 'picker.none': 'No servers',
    'picker.listLabel': 'Servers & chains',

    'servers.title': 'Servers',
    'btn.pingAll': 'Ping all', 'btn.clearAll': 'Clear all', 'btn.add': '+ Add',
    'import.ph': 'Paste a config or a subscription URL here (or press Ctrl+V anywhere):\nvless://...  vmess://...  trojan://...  ss://...\nhttps://...  ← subscription URL (auto-detected)\nor a base64 subscription blob',
    'btn.import': 'Import', 'btn.cancel': 'Cancel',
    'servers.empty': 'No servers yet. Click “Add”.',
    'srv.selected': 'Selected',
    'btn.edit': 'Edit', 'btn.addWg': '+ WireGuard', 'btn.addWgGo': 'Add',

    'wg.title': 'Add WireGuard', 'wg.name': 'Name', 'wg.namePh': 'Custom name',
    'wg.endpoint': 'Endpoint (host:port)', 'wg.privateKey': 'Private Key',
    'wg.publicKey': 'Peer Public Key', 'wg.address': 'Address (local, /32)',
    'wg.psk': 'Pre-shared Key (optional)', 'wg.mtu': 'MTU', 'wg.reserved': 'Reserved (optional)',
    'wg.allowed': 'Allowed IPs',
    'wg.endpointHost': 'Server address (Endpoint host)',
    'wg.endpointPort': 'Server port (Endpoint port)',
    'wg.addrHint': '“Address” is your own local IP from the WireGuard config and must be /32 (e.g. 10.8.0.2/32). To reach a database range, put the range in “Allowed IPs” (e.g. 192.168.60.0/24) or keep 0.0.0.0/0.',

    'edit.title': 'Edit server', 'edit.name': 'Name', 'edit.address': 'Address', 'edit.port': 'Port',
    'edit.uuid': 'UUID', 'edit.password': 'Password',
    'edit.network': 'Transport', 'edit.security': 'Security', 'edit.sni': 'SNI', 'edit.host': 'Host',
    'edit.path': 'Path / ServiceName', 'edit.fp': 'Fingerprint',
    'edit.pbk': 'Public Key (pbk)', 'edit.sid': 'Short ID (sid)', 'edit.allowInsecure': 'Allow Insecure',

    'chain.title': 'Proxy chain', 'chain.enable': 'Enable chain',
    'chain.hint': 'Traffic passes through these servers in order. Drag and drop to reorder.',
    'chain.client': '💻 You', 'chain.internet': '🌐 Internet',
    'chain.empty': 'No servers in the chain yet. Add from below (at least 2 needed).',
    'chain.available': 'Available servers', 'chain.poolEmpty': 'All servers are in the chain.',
    'chain.add': 'Add to chain',
    'chain.new': '+ New chain',
    'chain.intro': 'Each chain works like a config: give it a name, order a few servers, then use it like a config from the Connect page or in Advanced routing. You can keep several chains and ping each one.',
    'chain.wgHint': 'To reach a database when WireGuard does not work directly: put a config first and WireGuard last in the chain; then in Advanced routing send the database IP range to this chain (it goes through the config first, then over WireGuard for that range).',
    'chain.noneYet': 'No chains yet. Click “New chain”.',
    'chain.addFromBelow': 'Add a server from below…',

    'mode.pick': 'Connection mode', 'mode.proxyDesc': 'Light and fast; only apps that use the system/SOCKS proxy are tunneled.',
    'mode.tunDesc': 'All system traffic goes through the tunnel (needs tun2socks + admin).',

    'subs.title': 'Subscriptions',
    'btn.refreshAll': 'Refresh all', 'btn.addSub': '+ Add sub',
    'sub.urlPh': 'Subscription URL (https://…)', 'sub.namePh': 'Custom name (optional)',
    'btn.addFetch': 'Add & fetch',
    'autoupdate.title': 'Auto update', 'autoupdate.sub': 'Subscriptions refresh automatically on an interval',
    'interval.label': 'Interval (min)', 'subs.empty': 'No subscriptions yet.',
    'sub.servers': 'servers', 'sub.lastUpdate': 'Last update',

    'routing.title': 'Routing', 'routing.modeLabel': 'Routing mode',
    'routing.global': 'Global (all via proxy)', 'routing.bypassIr': 'Bypass Iran',
    'routing.bypassCn': 'Bypass China', 'routing.direct': 'Direct',
    'routing.hint': 'In “Bypass Iran”, domestic traffic goes direct and the rest via the proxy.',
    'ads.title': 'Block ads', 'ads.sub': 'Ad domains are blocked',
    'sniff.title': 'Sniffing', 'sniff.sub': 'Domain detection for more accurate routing',
    'rules.label': 'Custom rules',
    'rules.hint': 'Each line: domain|ip|port , value , outbound(proxy/direct/block)',
    'btn.saveRules': 'Save rules',
    'routing.geoNote': 'Routing needs geoip.dat and geosite.dat. If it doesn’t work, download them in Settings → Required files.',

    'settings.title': 'Settings',
    'set.socks': 'SOCKS port', 'set.http': 'HTTP port',
    'set.dns': 'DNS (comma-separated)', 'set.logLevel': 'Log level',
    'set.lang': 'زبان / Language',
    'sysproxy.title': 'System proxy', 'sysproxy.sub': 'Set the Windows proxy when connecting',
    'tun.title': 'TUN mode (system-wide tunnel)', 'tun.sub': 'All system traffic goes through the tunnel (needs tun2socks + admin)',
    'lan.title': 'Allow LAN', 'lan.sub': 'Let other devices connect too',

    'comp.title': 'Required files', 'comp.hint': 'Missing files are downloaded and integrated with one click — no rebuild needed.',
    'comp.xray': 'Xray core', 'comp.tun2socks': 'tun2socks (TUN mode)',
    'comp.wintun': 'wintun.dll (TUN mode)', 'comp.geo': 'Routing files (geoip + geosite)',
    'comp.installed': 'Installed', 'comp.missing': 'Missing',
    'btn.download': 'Download', 'btn.update': 'Update', 'btn.downloading': 'Downloading…',

    'xray.label': 'Xray core path', 'xray.checking': 'Checking…',
    'xray.ok': '✓ Xray core found and ready',
    'xray.missing': '✗ Xray core not found. Download it under “Required files” or pick the file.',
    'btn.locate': 'Pick xray file', 'btn.openData': 'Data folder', 'btn.help': 'Download help',
    'btn.save': 'Save settings', 'saved': 'Saved ✓',

    'logs.title': 'Logs', 'btn.clearLogs': 'Clear',

    'tun.unavailable': '⚠ tun2socks or wintun.dll not found — TUN mode disabled. Download them under “Required files”.',
    'tun.ready': '✓ TUN mode ready (on connect the whole system is tunneled — run as admin).',
    'tun.off': 'TUN mode is available but off.',

    't.settingsSaved': 'Settings saved', 't.rulesSaved': 'Rules saved',
    't.routingMode': 'Routing mode', 't.noServerSel': 'No server selected',
    't.addServerFirst': 'Add a server first', 't.pingingAll': 'Testing all servers…',
    't.testDone': 'Test finished', 't.allServersDeleted': 'All servers removed',
    't.connectFailed': 'Connection failed', 't.disconnected': 'Disconnected',
    't.ipFailed': 'IP check failed', 't.subAdded': 'Subscription added',
    't.subAddedShort': 'sub(s)', 't.nothingFound': 'Nothing to add found',
    't.pasteDetected': 'Adding from clipboard…',
    't.subUrl': 'Enter the subscription URL', 't.fetching': 'Fetching…',
    't.updating': 'Updating…', 't.updated': 'Updated', 't.failed': 'Failed',
    't.subRemoved': 'Subscription removed', 't.noSubs': 'No subscriptions',
    't.serversAdded': 'servers added', 't.errors': 'errors',
    't.tunNeedFiles': 'TUN mode needs tun2socks and wintun.dll downloaded',
    't.tunReconnect': 'Reconnect to apply TUN mode',
    't.downloading': 'Downloading', 't.downloaded': 'Downloaded & integrated', 't.downloadFailed': 'Download failed',
    't.xraySet': 'Xray core set', 't.xrayDownPage': 'Xray-core download page opened',
    't.never': 'never', 't.secAgo': 's ago', 't.minAgo': 'm ago', 't.hrAgo': 'h ago', 't.dayAgo': 'd ago',
    't.error': 'Error',
    't.serverUpdated': 'Server updated', 't.wgAdded': 'WireGuard added',
    't.wgMissing': 'Endpoint, private key and public key are required',
    't.wgBadEndpoint': 'Endpoint must be the public server as host:port (e.g. cobra.tes.ca:42421), not the local tunnel address',
    't.chainOn': 'Chain enabled', 't.chainOff': 'Chain disabled',

    'picker.chain': 'Chain', 'picker.advanced': 'Advanced routing',
    'chain.pickHint': 'After building a chain, pick ⛓ Chain on the Connect page and connect.',

    'adv.title': 'Advanced routing',
    'adv.sub': 'Send each IP/domain/port to a config, chain, direct or block',
    'adv.hint': 'Rules are matched top to bottom; the first match wins. The rest goes through “Default”. Pick 🧭 on the Connect page.',
    'adv.addRule': '+ Add rule', 'adv.default': 'Rest of traffic (default)',
    'adv.save': 'Save routing', 'adv.direct': 'Direct', 'adv.block': 'Block',
    'adv.empty': 'No rules yet. Click “Add rule”.',
    'adv.valuePh': 'e.g. 1.2.3.0/24 or example.com or 443',
    'adv.type.ip': 'IP', 'adv.type.domain': 'Domain', 'adv.type.port': 'Port',

    'tun.needAdmin': '⚠ TUN mode needs administrator rights. Relaunch the app as admin to enable the tunnel.',
    'tun.runAdmin': 'Relaunch as admin',

    't.advOn': 'Advanced routing enabled', 't.advOff': 'Advanced routing disabled',
    't.advSaved': 'Advanced routing saved', 't.adminFailed': 'Relaunch as admin failed'
  }
};

let currentLang = 'fa';

function t(key) {
  const dict = I18N[currentLang] || I18N.fa;
  return (key in dict) ? dict[key] : (I18N.fa[key] ?? key);
}

function applyI18n(lang) {
  currentLang = I18N[lang] ? lang : 'fa';
  const rtl = currentLang === 'fa';
  document.documentElement.lang = currentLang;
  document.documentElement.dir = rtl ? 'rtl' : 'ltr';

  document.querySelectorAll('[data-i18n]').forEach(el => {
    el.textContent = t(el.getAttribute('data-i18n'));
  });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => {
    el.setAttribute('placeholder', t(el.getAttribute('data-i18n-ph')));
  });
  document.querySelectorAll('[data-i18n-title]').forEach(el => {
    el.setAttribute('title', t(el.getAttribute('data-i18n-title')));
  });
}

window.i18n = { t, applyI18n, get lang() { return currentLang; } };
})();
