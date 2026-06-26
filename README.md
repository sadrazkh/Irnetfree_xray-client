# IRNetFree

یک کلاینت دسکتاپ تمیز و مدرن برای اجرای کانفیگ‌های Xray — با پشتیبانی از پروکسی، تانل، روتینگ، تست پینگ و بررسی IP. (ساخته‌ی گروه **IRNetFree**)

A clean, modern desktop VPN client built on **Electron** that drives **xray-core**.

## امکانات / Features

- **پروتکل‌ها:** VLESS (+ Reality / XTLS-Vision)، VMess، Trojan، Shadowsocks
- **افزودن کانفیگ:** چسباندن لینک تکی، چند لینک، یا لینک ساب‌اسکریپشن (base64)
- **ساب‌اسکریپشن:** افزودن آدرس ساب، به‌روزرسانی دستی، و **به‌روزرسانی خودکار** با فاصله‌ی دلخواه
- **پروکسی محلی:** SOCKS5 + HTTP inbound (پورت‌ها قابل تنظیم)
- **پروکسی سیستمی:** تنظیم خودکار پروکسی ویندوز (رجیستری WinINet) هنگام اتصال
- **حالت TUN:** تانل کل سیستم با tun2socks + wintun (نیازمند دسترسی ادمین)
- **روتینگ:** گلوبال / دور زدن ایران / دور زدن چین / مستقیم + قوانین سفارشی + بلاک تبلیغات
- **تست پینگ:** پینگ TCP (handshake) و **تأخیر واقعی** از داخل تانل
- **آمار زنده ترافیک:** سرعت دانلود/آپلود و حجم کل از طریق Stats API هسته
- **بررسی IP:** نمایش IP و کشور خروجی (مستقیم یا از طریق پروکسی)
- **لاگ زنده، سینی سیستم (tray)، تم دارک، رابط فارسی/RTL**

## پیش‌نیاز / Prerequisites

- Node.js 18+
- هسته **xray-core** (فایل `xray.exe`)
- برای حالت TUN: **tun2socks** و **wintun.dll** در پوشه‌ی `bin/`

## نصب و اجرا / Setup

```bash
cd xray-client
npm install

# دانلود خودکار آخرین نسخه xray-core در پوشه bin/
npm run get-xray
# یا فایل xray.exe را دستی در پوشه bin/ بگذارید
# یا از داخل برنامه: تنظیمات → انتخاب فایل xray

npm start
```

## ساخت نسخه نصبی / Build installer (Windows)

```bash
npm run dist
```

خروجی در پوشه `dist/` ساخته می‌شود (NSIS installer + portable).

## ساخت نسخه مک / Build for macOS (Intel + Apple Silicon)

> ⚠️ خروجی مک فقط روی **خودِ macOS** ساخته می‌شود؛ ویندوز نمی‌تواند `.dmg/.app` مک بسازد (به ابزارهای `hdiutil`/`codesign` و symlinkهای داخل bundle نیاز است).

روی یک Mac:

```bash
cd xray-client
npm install
npm run gen-icons        # ساخت icon.icns (یک‌بار، اگر assets/icon.icns نباشد)

# هر دو معماری (Intel x64 + Apple Silicon arm64) با هم:
npm run dist:mac

# یا جداگانه:
npm run dist:mac:x64     # مک‌های Intel
npm run dist:mac:arm64   # مک‌های M1/M2/M3/M4
```

خروجی‌ها در `dist/` ساخته می‌شوند:
`IRNetFree-<version>-x64.dmg`، `IRNetFree-<version>-arm64.dmg` (و فایل‌های `.zip` متناظر).

### اجرای اولیه روی مک / First run on macOS

- چون بیلد بدون گواهی Apple Developer امضا شده، در مک مقصد یک‌بار:
  - یا روی برنامه **راست‌کلیک → Open** بزنید،
  - یا در ترمینال: `xattr -cr /Applications/IRNetFree.app`
- هسته **xray** و **tun2socks** را از داخل برنامه (تنظیمات → فایل‌های موردنیاز) دانلود کنید؛ برنامه به‌طور خودکار معماری درست (Intel/ARM) را می‌گیرد و باینری‌ها را برای اجرا روی Apple Silicon امضای ad-hoc می‌کند.

### حالت TUN روی مک / TUN mode on macOS

- نیازی به اجرای دستی با `sudo` نیست؛ هنگام اتصال، یک‌بار پنجره‌ی **رمز عبور (administrator)** نمایش داده می‌شود و سپس tun2socks + روت‌ها + DNS به‌صورت کامل تنظیم می‌شوند.
- پیش از **خروج** از برنامه بهتر است ابتدا **قطع اتصال** بزنید تا روت‌ها و DNS تمیز بازگردانده شوند.

## ساختار / Structure

```
src/
  main/
    main.js          # فرآیند اصلی Electron، IPC، چرخه عمر
    parser.js        # تبدیل لینک‌های اشتراک به outbound اکس‌ری
    configBuilder.js # ساخت config.json کامل (inbounds + routing)
    xrayManager.js   # مدیریت پروسه xray-core (start/stop/test)
    subscription.js  # مدیریت ساب‌اسکریپشن (دریافت/به‌روزرسانی خودکار)
    tunManager.js    # حالت TUN با tun2socks + wintun
    stats.js         # آمار زنده ترافیک از Stats API
    sysproxy.js      # تنظیم پروکسی سیستمی (Win/macOS/Linux)
    netutils.js      # پینگ TCP، تأخیر واقعی، بررسی IP/geo
    store.js         # ذخیره‌ساز JSON ساده
  preload/preload.js # پل امن IPC
  renderer/          # رابط کاربری (HTML/CSS/JS)
scripts/
  download-xray.js   # دانلودر خودکار هسته
```

## نکته امنیتی / Security

- `contextIsolation` فعال و `nodeIntegration` غیرفعال است؛ رندرر فقط از طریق preload با main حرف می‌زند.
- هنگام خروج یا قطع اتصال، پروکسی سیستمی به‌صورت خودکار غیرفعال می‌شود.
- کلیدها/کانفیگ‌ها فقط به‌صورت محلی در `userData/store.json` ذخیره می‌شوند.

## عیب‌یابی / Troubleshooting

- **«هسته Xray پیدا نشد»** → `npm run get-xray` را اجرا کنید یا از تنظیمات فایل را انتخاب کنید.
- **اتصال برقرار شد ولی اینترنت ندارید** → حالت روتینگ را روی «گلوبال» بگذارید و پورت‌ها را چک کنید.
- **پروکسی سیستمی پاک نشد** → برنامه را دوباره باز کنید؛ هنگام شروع، پروکسی پاک‌سازی می‌شود.
- **حالت TUN کار نمی‌کند** → برنامه را با دسترسی Administrator اجرا کنید و مطمئن شوید `tun2socks.exe` و `wintun.dll` در پوشه‌ی `bin/` هستند.
- **ساب‌اسکریپشن دریافت نمی‌شود** → آدرس باید با `http://` یا `https://` شروع شود و در دسترس باشد.
