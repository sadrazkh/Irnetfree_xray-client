# Remote control — reach the home router from anywhere

From **v1.16.0**. The router has no static IP and may sit behind CGNAT; nothing has to be opened on it.
Two ways in, both set up on the router under **LuCI → Services → IRNetFree → Remote access**; both can be on
at once:

| | Relay (main path) | Cloudflare Tunnel (second path) |
|---|---|---|
| Who runs it | You — `relay/` in this repo, on Harbora or any Docker host | Cloudflare |
| What the router does | keeps an outbound WebSocket link to your relay | runs the feed's `cloudflared`, which keeps connections to Cloudflare's edge |
| What you open | `https://<your relay>/` — your password, then the router's own IRNetFree UI | `https://<your hostname>/?token=<UI token>` behind Cloudflare Access |
| When the VPN on the router is broken | works: the link's dial bypasses the tunnel, and so does its DNS in a bypass routing mode (in global mode the relay's name is looked up through the tunnel — the last good address carries the link then); falls back **through** the tunnel if the direct way is blocked | works: its edge addresses bypass the tunnel and its edge discovery asks the direct resolvers out the WAN (no fallback through the tunnel — cloudflared cannot use a proxy) |
| During an internet shutdown in Iran | works if the relay runs on a server **inside** Iran (same image) | expected to fail (Cloudflare's addresses were reopened only for allow-listed names in 2026) |

Either way you end up in the same IRNetFree web UI the LAN uses: turn the VPN on and off, switch configs,
change settings, read the log.

## 1. The relay

One Node process, no npm dependencies, ~1 MB. It does three things: logs you in (one password), pairs
routers (a device token each), and carries every request you make to the selected router over the link the
router keeps open to it. What it sees is plaintext — it is *your* server (see Security below).

### On Harbora

1. In the panel: **Create app** — name `irnetfree-relay`, size **Small**, **container port 8080**, a
   **volume mounted at `/app/data`**, and an environment **secret `RELAY_PASSWORD`** (12 characters or
   more; the relay refuses to start with less). No database, no other variables. `PORT` is not injected by
   Harbora; the Dockerfile sets it.
2. From this repo's root (the build context is the root; `relay/harbora.yml` names the Dockerfile):

   ```sh
   harbora login --server https://<your panel> --token hbr_cli_…
   cp relay/harbora.yml ./harbora.yml      # or pass --path; the file only names the app and the Dockerfile
   harbora deploy irnetfree-relay -y
   ```

   The upload is small: the root `.dockerignore` names everything but `relay/` and three files under
   `src/server/remote/` (Harbora's packer reads it with its own rules — no `!` negations, a bare name
   matches at any depth — and `tests/relayPack.test.js` pins the resulting upload set). `harbora deploy`
   runs `harbora doctor` first; its "would exclude" list must keep `relay/` and `src/server/remote/ws.js`,
   `frames.js`, `token.js` — if it does not, do not deploy with `--skip-doctor`, fix the ignore file.
   Health: Harbora GETs `/` and passes on anything under 500 — the relay answers 302 (to the login page)
   there and `200 ok` on `/_relay/health`.
3. Open `https://<the app's domain>/_relay/login`, sign in with `RELAY_PASSWORD`.

Redeploys are start-first: for a while the old and the new container share the volume. The relay keeps its
data in atomic JSON writes with no lock, so that is fine. Bump `LABEL org.opencontainers.image.revision` in
`relay/Dockerfile` per deploy if you want the image to say which one it is.

### On any Docker host

```sh
docker build -f relay/Dockerfile -t irnetfree-relay .
docker run -d --name irnetfree-relay --restart unless-stopped \
  -e RELAY_PASSWORD='a password of twelve characters or more' \
  -v irnetfree-relay:/app/data -p 127.0.0.1:8080:8080 irnetfree-relay
```

Put TLS in front of it (Caddy: `relay.example.com { reverse_proxy 127.0.0.1:8080 }`; nginx or Traefik
likewise). The session cookie is `Secure`, so the relay must be reached over `https://`
(`http://localhost:8080` works for a local try — browsers treat localhost as secure). Forwarded headers
(`X-Forwarded-Proto/Host/For`) are trusted only when the proxy's address is private (10/8, 172.16/12,
192.168/16, 127/8), which Docker networks are.

### Pair a router

1. Relay → **Routers** → **Add router** (give it a name). The page shows a **device token once** — copy it.
   The relay keeps only its SHA-256; lose it and you revoke + add again.
2. Router → LuCI → **Services → IRNetFree → Remote access → Relay**: enable, relay URL
   (`https://relay.example.com`, no path), router name, paste the device token, Save. The state line goes
   **connecting → online (direct)** within seconds.
3. Relay → the router's **Open** button → you are in the router's IRNetFree UI. Bookmark the relay, not the
   router.

What the router does with that token: it dials `wss://<relay>/_relay/agent` with the token as a Bearer,
says hello (name, app version, path), and from then on executes what the relay forwards — only against its
own IRNetFree UI on `127.0.0.1:<port>`, injecting the router's UI token itself (the UI token never leaves
the router), refusing anything aimed at LuCI or `/_relay/`.

The link does not ride the VPN: while the tunnel is up the relay's address is resolved through the config's
direct (in-country) resolvers and routed past the tunnel (`service.setRemoteBypass`). From v1.16.1 those
resolvers are inside the whole-LAN tunnel for every LAN device and for dnsmasq (cut out of it, their DNS left
by the ISP in plain text); only the IRNetFree service's own UDP 53 to them leaves by the WAN — an `ip rule`
at pref 8997 for the service's user, from the router itself (`iif lo`), laid and removed with the gateway. In
**global** mode the config has no direct resolvers: the lookup goes to the `dnsDirect` setting through the
tunnel, as in v1.16.0, and fails while the VPN's exit is dead. The last good addresses are remembered for that
and for any DNS outage, and after three failed direct dials in a row it dials **through** the tunnel
(the local SOCKS inbound) and shows **online (via VPN)**, trying direct again every 10 minutes. Reconnects
back off 2/5/10/30/60 s.

### The relay's pages

| Page | What |
|---|---|
| `/_relay/login` | password; 5 wrong tries per 15 minutes per IP, then a wait |
| `/_relay/` | routers: online/offline, path (direct / via VPN), app version, last seen; Add, Open, Revoke; Log out |
| `/` (and everything else) | the selected router's IRNetFree UI, or "Router offline (last seen …)" |
| `?lang=fa` / `?lang=en` | Persian / English (a cookie remembers it) |

Static files of the UI (~0.65 MB per page load) are cached on the relay per router and app version, so a
phone reload does not pull them through the home uplink again.

## 2. Cloudflare Tunnel

The feed's `cloudflared` package, installed and configured from the Remote access page; the tunnel and the
public hostname are made in Cloudflare's dashboard.

1. Cloudflare dashboard → **Zero Trust → Networks → Tunnels → Create a tunnel** (Cloudflared) → name it →
   on the install page copy the **token** (the long string after `--token` in the command shown).
2. **Public hostname**: `router.<your domain>` → service **HTTP** `127.0.0.1:6969` (the IRNetFree UI's
   port on the router; 6969 unless changed in `/etc/config/irnetfree`).
3. **Zero Trust → Access → Applications → Add** → self-hosted, that hostname, a policy that allows only you
   (your email with a one-time PIN, or your identity provider). Without this the UI is reachable by anyone
   who guesses the token in the URL.
4. Router → LuCI → Remote access → **Cloudflare Tunnel**: **Install** (runs `opkg update && opkg install
   cloudflared`; the page follows the progress), paste the token, enable, Save. The service writes the token
   into `/etc/config/cloudflared` (the package's own config), pins `protocol http2`, enables and starts the
   package's service, and routes Cloudflare's tunnel edge past the VPN.
5. Open `https://router.<your domain>/?token=<the UI token>` — the token is in `/etc/irnetfree/token` on the
   router (`cat` it over SSH, or LuCI's "Open full web UI" link carries it). Bookmark it.

Notes:

- **http2 only.** QUIC has been throttled or blocked on Iranian ISPs since mid-2025, so the tunnel is pinned
  to `--protocol http2` (TCP 7844). The edge addresses it dials (Cloudflare's published list,
  198.41.192.0/24, 198.41.200.0/24 and the two IPv6 ranges) bypass the VPN, and the edge-discovery names
  (`argotunnel.com`, `cftunnel.com`) are resolved through the config's direct resolvers (a dnsmasq drop-in
  `irnetfree-cloudflared.conf` in the dir dnsmasq reads — `/tmp/dnsmasq.d` on 23.05, `/tmp/dnsmasq.<instance>.d`
  on 24.10 — there only while the tunnel is enabled). Each line is bound to the WAN device,
  `server=/argotunnel.com/<resolver>@<WAN device>`: from v1.16.1 those resolvers are inside the whole-LAN
  tunnel, whose DNS does not answer the SRV lookup edge discovery is (the hijack refuses it, or the feed's older
  cores leave it unanswered), and the binding (SO_BINDTODEVICE) takes dnsmasq's
  query for these two names out by the WAN in every routing mode. A drop-in written before the WAN had a device
  (at boot) is rewritten within a minute of one appearing. dnsmasq is restarted for every change of it: its
  reload re-reads no config.
- **No fallback through the VPN**: cloudflared cannot use a SOCKS/HTTP proxy for its own connections. If the
  direct way to Cloudflare is blocked, this path is down; the relay is the one to rely on.
- **Package version.** OpenWrt 23.05's feed ships `cloudflared 2024.4.1` (8 MB), 24.10's `2025.5.0` (both
  verified on the CI images). Cloudflare supports cloudflared releases within a year of the latest, so both
  are outside the window — they still connect today, but may stop working at some point, and no newer package
  exists for those releases. The Remote access page shows the installed version. Upstream binaries (36 MB,
  armhf) are not fetched by IRNetFree in this round.
- RAM: cloudflared takes roughly 30 MB on the router.

## 3. Security

- The relay sees the traffic in clear between the browser and the router's UI (it terminates one leg of the
  link and opens the other). It is your server, with your password; nobody else's. If that is not acceptable,
  use the Cloudflare path (Cloudflare sees it instead) or neither.
- The router's UI token never leaves the router: the agent adds it to each request on the router, and a token
  the browser might send is dropped. Relay cookies are never forwarded to the router.
- The device token is shown once by the relay and kept as a hash there; on the router it is write-only
  (LuCI shows "set", never the token) and lives in `/etc/irnetfree/remote.json`, outside backups and
  `app:init`. No token appears in any log line.
- The agent can only reach the IRNetFree UI on the router — never LuCI, SSH or another host; `/luci/*` and
  `/_relay/*` are refused on the router side as well.
- TLS to the relay is verified against the system CA bundle (`ca-bundle` is a dependency of the package);
  when DNS fails the remembered address is dialed with the relay's hostname as SNI, still verified.
- Relay: HttpOnly/Secure/SameSite=Strict session cookie signed with a key kept on the volume; every POST
  checks `Origin`; login attempts are rate-limited per IP and globally; forwarded headers are trusted from
  private peers only.

## 4. The Iran-shutdown note

When international links are cut, a relay on a server abroad is unreachable, as is Cloudflare. The same relay
image runs anywhere Docker runs: a small VPS or a Harbora node **inside Iran** keeps the home router reachable
from inside the country during a shutdown (the home side needs no change — it dials whatever relay URL is
set, and you can set two routers' worth of pairing on two relays). Keep the relay's password strong; it is the
only thing between the internet and the router's UI.

## 5. Troubleshooting

| Symptom | Where to look |
|---|---|
| LuCI says **connecting** forever, error "could not resolve" | the router has no DNS for the relay host; wait, or check the WAN. Once it has connected once, the address is remembered |
| "the relay refused the device token (401)" | the token was revoked or belongs to another relay — Add router again, paste the new token |
| Relay shows the router **Offline** | the link is down: `logread -e irnetfree \| grep remote:` on the router |
| **online (via VPN)** | the direct way to the relay is blocked from the home line; it works through the tunnel and retries direct every 10 min |
| "Router offline (last seen …)" page in the browser | the router has no link right now; the page reloads by itself |
| Cloudflare: installed but **not running** | `logread -e cloudflared`; check the token and that port 7844/TCP is reachable |

---

# کنترل از راه دور — رسیدن به روتر خانه از هر جا

از **v1.16.0**. روتر IP ثابت ندارد و ممکن است پشت CGNAT باشد؛ هیچ پورتی رویش باز نمی‌شود. دو راه، هر دو از
**LuCI ← Services ← IRNetFree ← Remote access** تنظیم می‌شوند و می‌توانند هم‌زمان روشن باشند:

| | رله (راه اصلی) | Cloudflare Tunnel (راه دوم) |
|---|---|---|
| چه کسی اجرایش می‌کند | خودت — `relay/` در همین مخزن، روی هاربورا یا هر سرور داکر | کلادفلر |
| روتر چه می‌کند | یک اتصال WebSocket خروجی به رله‌ات نگه می‌دارد | `cloudflared` فید را اجرا می‌کند که به لبهٔ کلادفلر وصل می‌ماند |
| چه چیزی باز می‌کنی | `https://<رله>/` — رمز، بعد همان UI خود IRNetFree روتر | `https://<دامنه>/?token=<توکن UI>` پشت Cloudflare Access |
| وقتی VPN روتر خراب است | کار می‌کند: اتصالش تونل را دور می‌زند و در حالت‌های bypass، DNSاش هم (در حالت global نام رله از داخل تونل پرسیده می‌شود — آن وقت آخرین آدرس خوب اتصال را نگه می‌دارد)؛ اگر راه مستقیم بسته باشد **از داخل تونل** می‌رود | کار می‌کند: آدرس‌های لبه‌اش تونل را دور می‌زنند و کشف لبه‌اش از راه WAN از رزولورهای مستقیم می‌پرسد (ولی راه جایگزین از داخل تونل ندارد — cloudflared پراکسی نمی‌پذیرد) |
| در قطعی اینترنت ایران | اگر رله روی سروری **داخل ایران** باشد کار می‌کند (همین image) | انتظار می‌رود کار نکند (در ۲۰۲۶ آدرس‌های کلادفلر فقط برای نام‌های سفید باز شدند) |

در هر دو، به همان UI وب IRNetFree می‌رسی که در خانه می‌بینی: VPN را روشن/خاموش کن، کانفیگ عوض کن، تنظیمات را
تغییر بده، لاگ را بخوان.

## ۱. رله

یک پروسهٔ Node، بدون هیچ وابستگی npm، حدود ۱ مگابایت. سه کار می‌کند: ورود با یک رمز، جفت کردن روترها (هر کدام
یک توکن دستگاه)، و رساندن هر درخواستت به روتر انتخاب‌شده از روی اتصالی که روتر خودش به رله باز نگه داشته.
آنچه می‌بیند رمزنگاری‌نشده است — سرور خودت است (بخش امنیت را ببین).

### روی هاربورا

۱. در پنل: **Create app** — نام `irnetfree-relay`، اندازهٔ **Small**، **پورت کانتینر 8080**، یک **والیوم روی
   `/app/data`**، و یک **سکرت محیطی `RELAY_PASSWORD`** (دست‌کم ۱۲ کاراکتر؛ با کمتر، رله بالا نمی‌آید). دیتابیس
   و متغیر دیگری لازم نیست. هاربورا `PORT` را تزریق نمی‌کند؛ Dockerfile خودش آن را می‌گذارد.
۲. از ریشهٔ همین مخزن (context ساخت ریشه است؛ `relay/harbora.yml` فقط Dockerfile را نام می‌برد):

   ```sh
   harbora login --server https://<پنل> --token hbr_cli_…
   cp relay/harbora.yml ./harbora.yml
   harbora deploy irnetfree-relay -y
   ```

   آپلود کوچک است: `.dockerignore` ریشه همه‌چیز جز `relay/` و سه فایل زیر `src/server/remote/` را نام می‌برد
   (پکر هاربورا آن را با قواعد خودش می‌خواند — بدون خط‌های `!`، و یک نام ساده در هر عمقی می‌گیرد؛
   `tests/relayPack.test.js` مجموعهٔ آپلود را ثابت نگه می‌دارد). `harbora deploy` اول `harbora doctor` را اجرا
   می‌کند؛ فهرست «would exclude» آن باید `relay/` و `src/server/remote/ws.js`، `frames.js`، `token.js` را نگه
   داشته باشد — اگر نه، با `--skip-doctor` استقرار نده، فایل ignore را درست کن. سلامت: هاربورا `/` را می‌گیرد
   و زیر ۵۰۰ قبول می‌کند — رله آنجا 302 (به صفحهٔ ورود) می‌دهد و روی `/_relay/health` هم `200 ok`.
۳. `https://<دامنهٔ اپ>/_relay/login` را باز کن و با `RELAY_PASSWORD` وارد شو.

استقرار دوباره start-first است: مدتی کانتینر قدیم و جدید یک والیوم را شریک‌اند. رله داده‌اش را با نوشتن اتمیک
JSON و بدون قفل نگه می‌دارد، پس مشکلی نیست.

### روی هر سرور داکر

```sh
docker build -f relay/Dockerfile -t irnetfree-relay .
docker run -d --name irnetfree-relay --restart unless-stopped \
  -e RELAY_PASSWORD='یک رمز دست‌کم دوازده کاراکتری' \
  -v irnetfree-relay:/app/data -p 127.0.0.1:8080:8080 irnetfree-relay
```

جلویش TLS بگذار (Caddy: `relay.example.com { reverse_proxy 127.0.0.1:8080 }`؛ nginx یا Traefik همین‌طور).
کوکی نشست `Secure` است، پس رله باید از `https://` باز شود (`http://localhost:8080` برای امتحان محلی کار
می‌کند). هدرهای `X-Forwarded-*` فقط وقتی اعتماد می‌شوند که آدرس پراکسی خصوصی باشد (10/8، 172.16/12،
192.168/16، 127/8) — شبکه‌های داکر همین‌اند.

### جفت کردن یک روتر

۱. رله ← **Routers** ← **Add router** (یک نام بده). صفحه **توکن دستگاه را فقط یک بار** نشان می‌دهد — کپی‌اش کن.
   رله فقط SHA-256 آن را نگه می‌دارد؛ گمش کنی باید Revoke و دوباره Add کنی.
۲. روتر ← LuCI ← **Services ← IRNetFree ← Remote access ← Relay**: فعال، آدرس رله (`https://relay.example.com`،
   بدون مسیر)، نام روتر، توکن دستگاه را بچسبان، Save. خط وضعیت در چند ثانیه **connecting ← online (direct)**
   می‌شود.
۳. رله ← دکمهٔ **Open** روتر ← داخل UI خود IRNetFree روتر هستی. رله را بوکمارک کن، نه روتر را.

روتر با آن توکن چه می‌کند: به `wss://<رله>/_relay/agent` با توکن به‌صورت Bearer وصل می‌شود، سلام می‌کند (نام،
نسخهٔ برنامه، مسیر)، و از آن به بعد آنچه رله می‌فرستد را اجرا می‌کند — فقط روی UI خودش روی
`127.0.0.1:<پورت>`، توکن UI روتر را خودش می‌گذارد (توکن UI هیچ‌وقت از روتر بیرون نمی‌رود)، و هر چیزی به سمت
LuCI یا `/_relay/` را رد می‌کند.

این اتصال از VPN نمی‌رود: وقتی تونل بالاست آدرس رله از رزولورهای مستقیم (داخل کشور) کانفیگ حل می‌شود و از
کنار تونل مسیریابی می‌شود (`service.setRemoteBypass`). از v1.16.1 این رزولورها برای همهٔ دستگاه‌های LAN و
برای dnsmasq داخل تونل کل شبکه‌اند (بیرون از آن، DNSشان بی‌رمز از راه ISP می‌رفت)؛ فقط UDP 53 خود سرویس
IRNetFree به آن‌ها از راه WAN می‌رود — یک `ip rule` در pref 8997 برای کاربر سرویس، فقط از خود روتر (`iif lo`)،
که با گیت‌وی گذاشته و برداشته می‌شود. در حالت **global** کانفیگ رزولور مستقیم ندارد: پرسش به تنظیم `dnsDirect`
از داخل تونل می‌رود، مثل v1.16.0، و تا خروجی VPN مرده است جواب نمی‌گیرد. آخرین آدرس‌های خوب برای همین و برای
هر قطعی DNS به خاطر سپرده می‌شوند، و بعد از سه شکست پشت‌سرهم در راه مستقیم، **از داخل تونل** (SOCKS محلی) وصل می‌شود و
**online (via VPN)** نشان می‌دهد؛ هر ۱۰ دقیقه راه مستقیم را دوباره امتحان می‌کند. اتصال مجدد با فاصله‌های
۲/۵/۱۰/۳۰/۶۰ ثانیه.

### صفحه‌های رله

| صفحه | چه |
|---|---|
| `/_relay/login` | رمز؛ ۵ تلاش اشتباه در ۱۵ دقیقه برای هر IP، بعد انتظار |
| `/_relay/` | روترها: آنلاین/آفلاین، مسیر (direct / via VPN)، نسخهٔ برنامه، آخرین اتصال؛ Add، Open، Revoke؛ خروج |
| `/` (و هر چیز دیگر) | UI روتر انتخاب‌شده، یا «روتر آفلاین است (آخرین اتصال …)» |
| `?lang=fa` / `?lang=en` | فارسی / انگلیسی (کوکی به خاطر می‌سپارد) |

فایل‌های ثابت UI (حدود ۰٫۶۵ مگابایت در هر بار باز شدن صفحه) روی رله به ازای هر روتر و نسخهٔ برنامه کش می‌شوند تا
رفرش گوشی دوباره از آپلود خانه نگذرد.

## ۲. Cloudflare Tunnel

بستهٔ `cloudflared` فید، از صفحهٔ Remote access نصب و تنظیم می‌شود؛ خود تونل و نام عمومی در داشبورد کلادفلر
ساخته می‌شوند.

۱. داشبورد کلادفلر ← **Zero Trust ← Networks ← Tunnels ← Create a tunnel** (Cloudflared) ← نام ← در صفحهٔ
   نصب **توکن** را کپی کن (رشتهٔ بلند بعد از `--token` در دستوری که نشان می‌دهد).
۲. **Public hostname**: `router.<دامنه>` ← سرویس **HTTP** `127.0.0.1:6969` (پورت UI روی روتر؛ 6969 مگر این که
   در `/etc/config/irnetfree` عوضش کرده باشی).
۳. **Zero Trust ← Access ← Applications ← Add** ← self-hosted، همان نام، سیاستی که فقط تو را راه بدهد (ایمیلت با
   PIN یک‌بارمصرف، یا هویت‌سنج خودت). بدون این، هر کسی که توکن داخل URL را حدس بزند به UI می‌رسد.
۴. روتر ← LuCI ← Remote access ← **Cloudflare Tunnel**: **Install** (`opkg update && opkg install cloudflared`؛
   صفحه پیشرفت را دنبال می‌کند)، توکن را بچسبان، فعال کن، Save. سرویس توکن را در `/etc/config/cloudflared`
   (کانفیگ خود بسته) می‌نویسد، `protocol http2` را ثابت می‌کند، سرویس بسته را فعال و اجرا می‌کند و لبهٔ تونل
   کلادفلر را از کنار VPN رد می‌کند.
۵. `https://router.<دامنه>/?token=<توکن UI>` را باز کن — توکن در `/etc/irnetfree/token` روی روتر است (با SSH
   `cat` کن، یا لینک «Open full web UI» در LuCI آن را دارد). بوکمارکش کن.

نکته‌ها:

- **فقط http2.** QUIC از نیمهٔ ۲۰۲۵ روی ISPهای ایران محدود یا بسته است، پس تونل روی `--protocol http2`
  (TCP 7844) ثابت شده. آدرس‌های لبه‌ای که می‌گیرد (فهرست منتشرشدهٔ کلادفلر: 198.41.192.0/24، 198.41.200.0/24 و
  دو بازهٔ IPv6) VPN را دور می‌زنند و نام‌های کشف لبه (`argotunnel.com`، `cftunnel.com`) از رزولورهای مستقیم
  کانفیگ حل می‌شوند (یک drop-in به نام `irnetfree-cloudflared.conf` در پوشه‌ای که dnsmasq می‌خواند — در 23.05
  `/tmp/dnsmasq.d`، در 24.10 `/tmp/dnsmasq.<instance>.d` — فقط تا وقتی تونل فعال است). هر خط به دستگاه WAN
  بسته شده، `server=/argotunnel.com/<رزولور>@<دستگاه WAN>`: از v1.16.1 این رزولورها داخل تونل کل شبکه‌اند که
  DNSاش به پرسش SRV کشف لبه جواب نمی‌دهد (hijack آن را رد می‌کند، یا هسته‌های قدیمی‌تر فید بی‌جواب می‌گذارندش)، و
  این بستن (SO_BINDTODEVICE) پرسش dnsmasq برای این دو نام را در هر
  حالت مسیریابی از راه WAN بیرون می‌برد. drop-in‌ای که پیش از داشتن دستگاه WAN نوشته شده (هنگام بوت) حداکثر یک
  دقیقه بعد از پیدا شدن آن دوباره نوشته می‌شود. با هر تغییرش dnsmasq ری‌استارت می‌شود: reload آن هیچ کانفیگی را
  دوباره نمی‌خواند.
- **راه جایگزین از داخل VPN ندارد**: cloudflared برای اتصال‌های خودش پراکسی SOCKS/HTTP نمی‌پذیرد. اگر راه مستقیم
  به کلادفلر بسته باشد این مسیر پایین است؛ رله همانی است که باید رویش حساب کرد.
- **نسخهٔ بسته.** فید OpenWrt 23.05 نسخهٔ `cloudflared 2024.4.1` (۸ مگابایت) و فید 24.10 نسخهٔ `2025.5.0` را دارد
  (هر دو روی image‌های CI دیده شده). کلادفلر نسخه‌های تا یک سال پس از آخرین انتشار را پشتیبانی می‌کند، پس هر دو
  بیرون از آن بازه‌اند — امروز وصل می‌شوند ولی ممکن است روزی از کار بیفتند و بستهٔ تازه‌تری برای این نسخه‌ها
  نیست. صفحهٔ Remote access نسخهٔ نصب‌شده را نشان می‌دهد. باینری‌های upstream (۳۶ مگابایت) در این دور توسط
  IRNetFree دانلود نمی‌شوند.
- RAM: cloudflared حدود ۳۰ مگابایت روی روتر می‌گیرد.

## ۳. امنیت

- رله ترافیک بین مرورگر و UI روتر را رمزنگاری‌نشده می‌بیند (یک سر اتصال را می‌بندد و سر دیگر را باز می‌کند).
  سرور خودت است، با رمز خودت؛ مال هیچ‌کس دیگر نیست. اگر این قابل قبول نیست، مسیر کلادفلر (آن‌وقت کلادفلر
  می‌بیند) یا هیچ‌کدام.
- توکن UI روتر هیچ‌وقت از روتر بیرون نمی‌رود: agent آن را روی خود روتر به هر درخواست اضافه می‌کند و توکنی که
  مرورگر بفرستد دور ریخته می‌شود. کوکی‌های رله هیچ‌وقت به روتر فرستاده نمی‌شوند.
- توکن دستگاه را رله یک بار نشان می‌دهد و فقط هش آن را نگه می‌دارد؛ روی روتر فقط‌نوشتنی است (LuCI «set» نشان
  می‌دهد، نه توکن را) و در `/etc/irnetfree/remote.json` می‌ماند، بیرون از بکاپ و `app:init`. هیچ توکنی در هیچ
  خط لاگی نمی‌آید.
- agent فقط به UI IRNetFree روی روتر می‌رسد — نه LuCI، نه SSH، نه میزبان دیگری؛ `/luci/*` و `/_relay/*` در
  سمت روتر هم رد می‌شوند.
- TLS به رله با بستهٔ CA سیستم بررسی می‌شود (`ca-bundle` وابستگی بسته است)؛ وقتی DNS قطع است آدرس
  به‌خاطرسپرده با نام رله به‌عنوان SNI گرفته می‌شود، باز هم با بررسی.
- رله: کوکی نشست HttpOnly/Secure/SameSite=Strict با کلیدی روی والیوم امضا می‌شود؛ هر POST `Origin` را چک
  می‌کند؛ تلاش‌های ورود به ازای IP و سراسری محدودند؛ هدرهای forwarded فقط از همسایه‌های خصوصی پذیرفته می‌شوند.

## ۴. نکتهٔ قطعی ایران

وقتی لینک‌های بین‌المللی قطع‌اند، رله‌ای روی سرور خارج در دسترس نیست و کلادفلر هم همین‌طور. همین image رله هر
جا داکر باشد اجرا می‌شود: یک VPS کوچک یا یک نود هاربورا **داخل ایران** روتر خانه را در قطعی از داخل کشور در
دسترس نگه می‌دارد (سمت خانه تغییری لازم ندارد — به هر آدرس رله‌ای که تنظیم شده وصل می‌شود). رمز رله را قوی
نگه دار؛ تنها چیزی است که بین اینترنت و UI روتر می‌ایستد.

## ۵. رفع اشکال

| نشانه | کجا نگاه کنی |
|---|---|
| LuCI همیشه **connecting** می‌گوید، خطای "could not resolve" | روتر DNS برای میزبان رله ندارد؛ صبر کن یا WAN را ببین. بعد از اولین اتصال، آدرس به خاطر سپرده می‌شود |
| "the relay refused the device token (401)" | توکن لغو شده یا مال رلهٔ دیگری است — دوباره Add router و توکن تازه |
| رله روتر را **Offline** نشان می‌دهد | اتصال پایین است: روی روتر `logread -e irnetfree \| grep remote:` |
| **online (via VPN)** | راه مستقیم به رله از خط خانه بسته است؛ از داخل تونل کار می‌کند و هر ۱۰ دقیقه مستقیم را امتحان می‌کند |
| صفحهٔ «روتر آفلاین است (آخرین اتصال …)» در مرورگر | روتر الان اتصال ندارد؛ صفحه خودش تازه می‌شود |
| کلادفلر: نصب شده ولی **running** نیست | `logread -e cloudflared`؛ توکن و دسترسی به پورت 7844/TCP را ببین |
