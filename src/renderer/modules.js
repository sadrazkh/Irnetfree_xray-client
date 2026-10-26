'use strict';
/**
 * Extensions («افزونه‌ها») — the app's advanced features as parts the user
 * installs or removes. Every one of them is built in (nothing is downloaded):
 * "installed" is one flag in the settings, `settings.modules[id] === true`, and
 * a new install starts with all of them off. What is left with none installed
 * is the core the app was made for — connect, servers, subscriptions, the
 * simple routing modes, TUN / system proxy, the kill switch, pings, DNS, the
 * cores, the log, the settings — and that is never a module.
 *
 * What "off" means (the contract, docs of the 2026-10-26 round):
 *  - hidden: every nav item, view, settings card, editor field and picker entry
 *    of the extension. The markup names its own with `data-module="<id>"`
 *    (index.html), the body says which are off (`attrOf(id)` = "off", set by
 *    app.js applyModules) and one rule in styles.css hides them; the lists and
 *    pickers app.js draws ask too. A picker still shows the item already
 *    SELECTED, so a connection never changes by itself.
 *  - inert only where it is purely a setting: multiWan (configBuilder treats it
 *    as disabled) and lanUsers (no inbound, no rule). The rest carry data —
 *    groups, chains, pool entries, routing profiles, WARP / MASQUE servers, an
 *    ECH outbound, anti-DPI values — and keep working for what exists: off
 *    hides the way to make or edit more, never the records or the links.
 *
 * A store from before this version (no `modulesMigrated`) gets, once, every
 * extension it USES switched on — an update must not hide what someone set up
 * — and the rest off (migrateModules); a fresh store is migrated already (the
 * defaults carry `modulesMigrated: true`).
 *
 * One file for the window and the router's page (window.IRNF_MODULES) and for
 * Node (main.js, service.js, configBuilder.js require it). Android mirrors the
 * ids and the rules. It touches neither the DOM nor the file system.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.IRNF_MODULES = api;
}(typeof self !== 'undefined' ? self : this, function () {

  const PLATFORMS = ['desktop', 'router', 'android'];
  /** The Extensions page's sections, in this order. */
  const CATEGORIES = ['connection', 'routing', 'network', 'security'];
  const ALL = PLATFORMS;

  /**
   * id, icon (one emoji), category, where it exists, what it needs installed
   * with it, its name and one line in both languages, and — for the question
   * a removal asks — what removing it hides.
   *
   * `requires`: only what truly depends. WARP needs chains: a WARP account on
   * WireGuard is made as a chain's exit (the + WARP dialog's default, and the
   * way it reaches Cloudflare where WireGuard to it is blocked), so a WARP
   * without the chains would make chains nobody can see. Nothing else needs
   * another: a chain's hop may be a group, a pool entry or a rule may point at
   * a chain — but each works with servers alone; LAN users listen on their own
   * ports with a password, never through the open LAN sharing.
   */
  const MODULES = [
    {
      id: 'chains', icon: '⛓', category: 'connection', platforms: ALL, requires: [],
      fa: { name: 'زنجیره', desc: 'چند سرور پشت سر هم: ترافیک از اولی به بعدی می‌رود و از آخری بیرون می‌آید — مثلاً یک کانفیگ و بعد WireGuard', hides: 'زبانهٔ زنجیره‌ها، «زنجیرهٔ جدید» و زنجیره‌ها در انتخاب‌گرها' },
      en: { name: 'Chains', desc: 'Several servers one after another: traffic goes through the first to the next and leaves from the last — a config, then WireGuard, say', hides: 'the Chains tab, + New chain and chains in the pickers' }
    },
    {
      id: 'groups', icon: '⧉', category: 'connection', platforms: ALL, requires: [],
      fa: { name: 'گروه', desc: 'چند کانفیگ با هم مثل یک کانفیگ: اتصال‌ها بینشان پخش می‌شوند، سریع‌ترین انتخاب می‌شود یا یکی پشتیبان است', hides: 'زبانهٔ گروه‌ها، «گروه تازه» و گروه‌ها در انتخاب‌گرها' },
      en: { name: 'Groups', desc: 'Several configs used together as one: connections spread over them, the fastest is picked, or one is the backup', hides: 'the Groups tab, + New group and groups in the pickers' }
    },
    {
      id: 'warp', icon: '☁', category: 'connection', platforms: ALL, requires: ['chains'],
      fa: { name: 'WARP و MASQUE', desc: 'حساب WARP کلادفلر — ثبت‌نام در خود برنامه یا وارد کردن — روی WireGuard پشت یک سرور در زنجیره، یا روی MASQUE', hides: 'دکمهٔ «+ WARP»، ثبت‌نام WARP و MASQUE برای سرور تازه' },
      en: { name: 'WARP & MASQUE', desc: 'Cloudflare WARP accounts — signed up in the app or imported — on WireGuard behind a server in a chain, or on MASQUE', hides: 'the + WARP button, the WARP sign-up and MASQUE for a new server' }
    },
    {
      id: 'pool', icon: '🧩', category: 'routing', platforms: ALL, requires: [],
      fa: { name: 'استخر پروکسی', desc: 'چند کانفیگ هم‌زمان، هرکدام روی پورت محلی خودش؛ هر برنامه را به پورتی که می‌خواهی وصل کن', hides: 'صفحهٔ استخر پروکسی و ردیف استخر در انتخاب‌گر' },
      en: { name: 'Proxy pool', desc: 'Several configs at once, each on a local port of its own; point each app at the port you want', hides: 'the Proxy pool page and its row in the picker' }
    },
    {
      id: 'advancedRouting', icon: '🧭', category: 'routing', platforms: ALL, requires: [],
      fa: { name: 'روتینگ پیشرفته', desc: 'هر دسته از ترافیک به کانفیگ دلخواه: چند روتینگ، پایه، و درخت مسیر ترافیک', hides: 'کارت روتینگ پیشرفته، روتینگ‌ها، درخت مسیر و ردیف‌های 🧭 در انتخاب‌گر' },
      en: { name: 'Advanced routing', desc: 'Each kind of traffic to the config you choose: several routings, a base, and the traffic flow tree', hides: 'the advanced routing card, the routings, the flow tree and the 🧭 rows in the picker' }
    },
    {
      id: 'echOutbound', icon: '🔐', category: 'security', platforms: ALL, requires: [],
      fa: { name: 'خروجیِ ECH', desc: 'فیلد «ECH outbound» در ویرایشگر سرور: پرس‌وجوی ECH از مسیری که خودت می‌گویی (هستهٔ PattN). لینک‌هایی که آن را دارند بدون این هم کار می‌کنند', hides: 'فیلد ECH outbound در ویرایشگر سرور' },
      en: { name: 'ECH outbound', desc: 'The ECH outbound field of the server editor: the ECH query over a path you name (the PattN core). Links that carry one work without it', hides: 'the ECH outbound field of the server editor' }
    },
    {
      id: 'antiDpi', icon: '🛡', category: 'security', platforms: ALL, requires: [],
      fa: { name: 'ضد DPI', desc: 'fragment، noise، cipherSuites و finalmask در ویرایشگر سرور و کلید «پنهان کردن SNI»', hides: 'فیلدهای fragment، noise، cipherSuites و finalmask و کلید پنهان کردن SNI' },
      en: { name: 'Anti-DPI', desc: 'Fragment, noise, cipherSuites and finalmask in the server editor, and the Hide SNI switch', hides: 'the fragment, noise, cipherSuites and finalmask fields and the Hide SNI switch' }
    },
    {
      id: 'lanShare', icon: '📡', category: 'network', platforms: ['desktop', 'android'], requires: [],
      fa: { name: 'اشتراک در شبکهٔ محلی', desc: 'دستگاه‌های دیگرِ همین شبکه از پورت‌های SOCKS و HTTP این دستگاه وصل شوند', hides: 'کلید «اجازه به شبکه محلی» و نشانی‌اش' },
      en: { name: 'LAN sharing', desc: 'Other devices on this network use the SOCKS and HTTP ports of this device', hides: 'the Allow LAN switch and its address' }
    },
    {
      id: 'multiWan', icon: '🔀', category: 'network', platforms: ['desktop', 'router'], requires: [],
      fa: { name: 'ترکیب اینترنت‌ها', desc: 'دو اینترنتِ وصل با هم: ترکیب، پشتیبان، یا آپلود و دانلود جدا — با سقف مصرف برای هرکدام', hides: 'کارت ترکیب اینترنت‌ها؛ تا دوباره نصب نشود اتصال فقط از یک اینترنت می‌رود' },
      en: { name: 'Combine internets', desc: 'Two connected internets together: combined, one as a backup, or upload and download apart — with a data cap for each', hides: 'the Combine internets card; until it is installed again a connection uses one internet' }
    },
    {
      id: 'remoteRelay', icon: '🛰', category: 'network', platforms: ['router'], requires: [],
      fa: { name: 'کنترل از راه دور', desc: 'رسیدن به صفحهٔ روتر از بیرونِ خانه، با رله یا Cloudflare Tunnel — راه‌اندازی‌اش در LuCI است', hides: 'راهنمای دسترسی از راه دور در تنظیمات' },
      en: { name: 'Remote control', desc: 'Reach the page of the router from outside the home, over the relay or a Cloudflare Tunnel — set up in LuCI', hides: 'the remote access pointer in Settings' }
    },
    {
      id: 'lanUsers', icon: '👥', category: 'network', platforms: ['desktop', 'router'], requires: [],
      fa: { name: 'کاربران', desc: 'افراد شبکه‌ات با نام کاربری و رمز وصل می‌شوند، هرکدام با سقف مصرف و کانفیگ خودش', hides: 'صفحهٔ کاربران؛ تا دوباره نصب نشود هیچ کاربری وصل نمی‌شود' },
      en: { name: 'Users', desc: 'People on your network connect with a username and password, each with their own data cap and config', hides: 'the Users page; until it is installed again no user can connect' }
    }
  ];

  const BY_ID = new Map(MODULES.map((m) => [m.id, m]));
  const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
  const arr = (v) => (Array.isArray(v) ? v : []);
  /** A value that holds something: a non-blank string, a non-empty object or list, true, a number. */
  function filled(v) {
    if (v == null || v === false) return false;
    if (typeof v === 'string') return v.trim() !== '';
    if (Array.isArray(v)) return v.length > 0;
    if (typeof v === 'object') return Object.keys(v).length > 0;
    return true;
  }

  function moduleOf(id) { return BY_ID.get(String(id)) || null; }

  /** The stored flags as they mean something: a known id → true, nothing else (an unknown id, a "false", junk) kept. */
  function normalizeModules(raw) {
    const out = {};
    if (!isObj(raw)) return out;
    for (const m of MODULES) if (raw[m.id] === true) out[m.id] = true;
    return out;
  }

  /** Is extension `id` installed in these settings? */
  function isOn(settings, id) {
    return !!(isObj(settings) && isObj(settings.modules) && settings.modules[id] === true && BY_ID.has(id));
  }

  /** Does extension `id` exist on this platform ('desktop' | 'router' | 'android')? */
  function available(id, platform) {
    const m = moduleOf(id);
    return !!m && m.platforms.includes(platform);
  }

  /** What `id` needs installed with it, every level down, in the registry's order. */
  function requiresOf(id) {
    const seen = new Set();
    const walk = (x) => {
      const m = moduleOf(x);
      if (!m) return;
      for (const r of m.requires) if (!seen.has(r)) { seen.add(r); walk(r); }
    };
    walk(id);
    seen.delete(id);
    return MODULES.map((m) => m.id).filter((x) => seen.has(x));
  }

  /** The extensions that need `id` (any level up), in the registry's order. */
  function dependentsOf(id) {
    return MODULES.map((m) => m.id).filter((x) => x !== id && requiresOf(x).includes(id));
  }

  /**
   * How much of each extension a store uses — { [id]: count }, every id there,
   * 0 for none. `data` = { servers, groups, chains, pool, routingProfiles,
   * settings, lanUsers, remote } as stored (remote: the router's remote.json,
   * where the relay keeps its settings). What counts:
   *   chains / groups / pool   how many there are
   *   advancedRouting          on: the profiles with rules or a default (at
   *                            least 1); off: those besides rp-default
   *   warp                     MASQUE servers and servers made from a WARP account
   *   echOutbound              servers whose TLS names an ECH outbound
   *   antiDpi                  servers with a fragment, noise, cipherSuites or a
   *                            finalmask of their own (Hysteria2's obfuscation is
   *                            stored as finalmask too, and is no anti-DPI field),
   *                            and a global fragment setting (Android's)
   *   lanShare                 allowLan
   *   multiWan                 multiWan.enabled
   *   remoteRelay              the relay and the Cloudflare Tunnel, each set up
   *   lanUsers                 the users
   */
  function inUseOf(data) {
    const d = isObj(data) ? data : {};
    const s = isObj(d.settings) ? d.settings : {};
    const out = {};
    for (const m of MODULES) out[m.id] = 0;
    out.chains = arr(d.chains).filter(isObj).length;
    out.groups = arr(d.groups).filter(isObj).length;
    out.pool = arr(d.pool).filter(isObj).length;
    const profiles = arr(d.routingProfiles).filter((p) => isObj(p) && (arr(p.rules).length > 0 || filled(p.def)));
    out.advancedRouting = s.advancedRouting ? Math.max(1, profiles.length) : profiles.filter((p) => p.id !== 'rp-default').length;
    for (const sv of arr(d.servers)) {
      if (!isObj(sv)) continue;
      const ob = isObj(sv.outbound) ? sv.outbound : {};
      const st = isObj(ob.streamSettings) ? ob.streamSettings : {};
      const tls = isObj(st.tlsSettings) ? st.tlsSettings : {};
      const protocol = String(sv.protocol || ob.protocol || '');
      if (protocol === 'masque' || isObj(sv.warp)) out.warp++;
      if (filled(tls.echOutbound)) out.echOutbound++;
      const ownMask = protocol !== 'hysteria2' && protocol !== 'hysteria' && filled(st.finalmask);
      if (filled(ob._fragment) || filled(ob._noise) || filled(tls.cipherSuites) || ownMask) out.antiDpi++;
    }
    const gf = s.fragment;
    if (filled(gf) && gf !== 'off' && !(isObj(gf) && gf.enabled === false)) out.antiDpi++;
    out.lanShare = s.allowLan ? 1 : 0;
    out.multiWan = isObj(s.multiWan) && s.multiWan.enabled ? 1 : 0;
    const r = isObj(d.remote) ? d.remote : {};
    const relay = isObj(r.relay) ? r.relay : {};
    const cf = isObj(r.cloudflared) ? r.cloudflared : {};
    out.remoteRelay = (relay.enabled || filled(relay.relayUrl) ? 1 : 0) + (cf.enabled ? 1 : 0);
    out.lanUsers = isObj(d.lanUsers) ? arr(d.lanUsers.users).filter(isObj).length : 0;
    return out;
  }

  /** `modules` with every extension `inUse` counts switched on, with what each needs. A new object. */
  function installInUse(modules, inUse) {
    const out = normalizeModules(modules);
    const used = isObj(inUse) ? inUse : {};
    for (const m of MODULES) {
      if (!(Number(used[m.id]) > 0)) continue;
      out[m.id] = true;
      for (const r of requiresOf(m.id)) out[r] = true;
    }
    return out;
  }

  /**
   * The extensions a store starts this version with. Already migrated
   * (`settings.modulesMigrated`): what it has. From before: what it uses on,
   * the rest off — so a fresh store (nothing in use) has none. Pure, and the
   * same answer however often it is asked; the caller writes it with
   * `modulesMigrated: true`.
   */
  function migrateModules(settings, data) {
    const s = isObj(settings) ? settings : {};
    if (s.modulesMigrated === true) return normalizeModules(s.modules);
    const d = Object.assign({}, isObj(data) ? data : {});
    if (!isObj(d.settings)) d.settings = s;
    return installInUse(s.modules, inUseOf(d));
  }

  /**
   * Install (`on`) or remove extension `id` on `platform` — modules:set.
   * Installing one installs what it needs too. Removing one that another
   * installed extension needs is refused: `blockedBy` names those, `modules`
   * stays as it was. Removing one in use is allowed (the page asked first):
   * its data stays, only hidden. → { modules, blockedBy?, error? } (error:
   * 'unknown' | 'unavailable' — nothing changed).
   */
  function setModule(modules, id, on, platform) {
    const cur = normalizeModules(modules);
    const m = moduleOf(id);
    if (!m) return { modules: cur, error: 'unknown' };
    if (platform && !m.platforms.includes(platform)) return { modules: cur, error: 'unavailable' };
    const next = Object.assign({}, cur);
    if (on) {
      next[m.id] = true;
      for (const r of requiresOf(m.id)) next[r] = true;
      return { modules: next };
    }
    const blockedBy = dependentsOf(m.id).filter((x) => cur[x] && (!platform || available(x, platform)));
    if (blockedBy.length) return { modules: cur, blockedBy };
    delete next[m.id];
    return { modules: next };
  }

  /** The body attribute that says whether `id` is off here: 'advancedRouting' → 'data-mod-advanced-routing'. */
  function attrOf(id) {
    return 'data-mod-' + String(id).replace(/[A-Z]/g, (c) => '-' + c.toLowerCase());
  }

  /**
   * Is an element whose data-module is `list` hidden, with `off` ({ [id]: true })
   * the extensions off here? A list names one extension, or several separated by
   * spaces when the element belongs to each ("chains groups": the page that holds
   * both) — hidden only when every one of them is off. No list: never.
   */
  function hiddenBy(list, off) {
    const ids = String(list || '').split(/\s+/).filter(Boolean);
    const o = isObj(off) ? off : {};
    return ids.length > 0 && ids.every((x) => o[x] === true);
  }

  return {
    MODULES, CATEGORIES, PLATFORMS,
    moduleOf, normalizeModules, isOn, available, requiresOf, dependentsOf,
    inUseOf, installInUse, migrateModules, setModule, attrOf, hiddenBy
  };
}));
