# Core version picker (Required files) — design

Date: 2026-10-03. Platforms: the desktop app (Windows, macOS, Linux) and the router's web UI (same renderer, served by
src/server/service.js). Android bundles its cores in the APK and has no download option — untouched.

## Owner's request (verbatim)
> اون بخش که میتونی هسته هارو اپدیت یا دانلود کنی هرکدوم که هست یه گزیه اپدیت باشه یه گزینه انتخاب دستی که اونو زد خیلی
> شیک و قشنگ نسخه های مختلف نه زیاد نسخه های پایدار و یه گزینه ها نسخه های پریلیز رو ببینه ساجست و لیتست رو ببینه بتونه
> انتخاب کنه برای نصب و دانلود بتونه اپدیت یا دانگرید کنه راحت تمیز باشه ... ui/ux خیلی خوب باشه مدال شبیه قشنگ و کال باز بشه
> چیزی خراب نشه

Decisions with the owner: «به‌روزرسانی» keeps installing the latest stable release (unchanged); while connected (or
connecting) a version change is refused with "disconnect first".

## Behaviour
- Cores with the picker: `xray` (official), `xray-pattn` (patterniha fork), `sing-box`. Geo files, tun2socks and wintun keep
  their single button. Each core row shows the installed version, «به‌روزرسانی» (unchanged) and «انتخاب نسخه».
- The modal: core name, installed version, the platform/arch it downloads for. A segmented control: Stable (the 6 newest
  stable releases that have this platform's asset) | With pre-releases (adds the 4 newest pre-releases). One card per
  version: version, age ("3 days ago"), size; badges ⭐ Suggested (the version this app release is verified with — one table
  in code, with a comment saying where each value was verified), Latest (GitHub's latest stable), Installed ✓, Pre-release.
  The action reads Upgrade / Downgrade (amber) / Reinstall. Choosing a version older than Suggested shows a short inline
  warning first. Progress inside the card; success or an inline error with Retry. Light/dark themes, RTL Persian, smooth
  open, cards stack on narrow screens (the router UI on a phone).
- Install of a chosen tag: fetch that release's asset → extract to a temp dir → (macOS: the existing quarantine strip +
  ad-hoc sign) → run `<bin> version` and require the expected version → only then the existing atomic `place()`. Any
  failure leaves the installed binary untouched. The bundled geo files are NOT replaced by a version install.
- Refused while connected/connecting (main and service): `{ ok:false, refused:'connected' }`; the modal disables the actions
  and says to disconnect first.
- Releases list: GitHub API `GET /repos/<repo>/releases?per_page=30` through the existing downloader's HTTP helper, cached
  10 minutes per core; a network error is a friendly message with Retry inside the modal.

## Out of scope
Android; changing what «به‌روزرسانی» or the weekly asset updater install; signature checks beyond running the binary.
