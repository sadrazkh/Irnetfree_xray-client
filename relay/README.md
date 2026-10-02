# IRNetFree relay

The owner's own door to a home router that has no static IP and sits behind any NAT. The router
keeps an outbound WebSocket link to this relay; the logged-in owner opens the relay in a browser and
sees the router's IRNetFree web UI, carried over that link. One Node process, **no npm dependencies**,
Node ≥ 20. The full guide (deploying on Harbora or any Docker host, pairing a router, the Cloudflare
Tunnel alternative, security notes — English and Persian) is in [`docs/remote.md`](../docs/remote.md).

## Run it

```sh
# from the repo root — the Dockerfile copies relay/ and three files from src/server/remote/
docker build -f relay/Dockerfile -t irnetfree-relay .
docker run -d --name irnetfree-relay --restart unless-stopped \
  -e RELAY_PASSWORD='a password of twelve characters or more' \
  -v irnetfree-relay:/app/data -p 127.0.0.1:8080:8080 irnetfree-relay
```

Put TLS in front of it (Caddy, nginx, Traefik — the session cookie is `Secure`, so the relay must be
reached over `https://`; `http://localhost` works for a local try). On Harbora: create the app in the
panel (Small, container port **8080**, volume **/app/data**, secret **RELAY_PASSWORD**), then
`harbora deploy irnetfree-relay -y` with `relay/harbora.yml`.

| Env | Meaning |
|---|---|
| `RELAY_PASSWORD` | the owner's password; the relay refuses to start when it is shorter than 12 characters |
| `RELAY_DATA` | data dir (default `/app/data`): routers, sessions, the cookie-signing secret — atomic JSON, no lock |
| `PORT` | listen port (default 8080; Harbora does not inject it, the Dockerfile sets it) |

## Endpoints

| Path | What |
|---|---|
| `GET /_relay/health` | `200 ok`, no auth (Harbora's health gate reads `/`, which answers 302 — also fine) |
| `/_relay/login`, `/_relay/logout` | the owner's session (HttpOnly, Secure, SameSite=Strict, 30 days); failed logins limited per IP (5 / 15 min) |
| `/_relay/` | routers: add (mints a device token, shown once, stored as SHA-256), open, revoke |
| `GET /_relay/agent` (WebSocket) | the router's link, `Authorization: Bearer <device token>` |
| everything else | carried to the selected router (`relay_router` cookie) and answered by its IRNetFree UI |

Pages are English or Persian (`?lang=fa` / `?lang=en` on any relay page sets a cookie).

## Tests

`tests/relay.test.js` runs the whole thing on loopback: login, rate limit, cookies, pairing, a fake
agent answering frames, SSE streaming, the offline page, revoke, link replacement, the static cache.

```sh
node --require ./tests/noNetwork.preload.js --test tests/relay.test.js
```
