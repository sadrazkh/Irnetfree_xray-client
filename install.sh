#!/usr/bin/env bash
# IRNetFree headless (Linux/CLI) one-line installer.
#
#   curl -fsSL https://raw.githubusercontent.com/sadrazkh/Irnetfree_xray-client/main/install.sh | bash
#
# Installs the SAME app the desktop uses, but serves its web UI on a local port
# so you can drive it from a GUI-less server (forward the port with `ssh -L`).
# The app has NO npm dependencies (pure Node core) — this just needs Node.js and
# the xray-core binary, both of which are fetched here if missing.
#
# Flags (pass with:  ... | bash -s -- --start --port 6969):
#   --start           start the server right after installing (foreground)
#   --service         install & enable a systemd service (needs sudo/root)
#   --port <n>        web UI port (default 6969)
#   --host <addr>     bind address (default 127.0.0.1; use 0.0.0.0 to expose)
#   --dir <path>      install dir (default ~/.irnetfree)
set -euo pipefail

REPO="sadrazkh/Irnetfree_xray-client"
BRANCH="main"
DIR="${HOME}/.irnetfree"
PORT="6969"
HOST="127.0.0.1"
DO_START=0
DO_SERVICE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --start) DO_START=1 ;;
    --service) DO_SERVICE=1 ;;
    --port) PORT="$2"; shift ;;
    --host) HOST="$2"; shift ;;
    --dir) DIR="$2"; shift ;;
    *) echo "unknown flag: $1" >&2 ;;
  esac
  shift
done

APP="$DIR/app"
say() { printf '\033[36m==>\033[0m %s\n' "$*"; }
err() { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

case "$(uname -m)" in
  x86_64|amd64) ARCH=x64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv7*) ARCH=armv7l ;;
  *) err "unsupported CPU arch: $(uname -m)" ;;
esac

mkdir -p "$DIR"

# ----------------------------- Node.js -----------------------------
NODE=""
if have node; then
  MAJ="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  [ "${MAJ:-0}" -ge 18 ] && NODE="$(command -v node)"
fi
if [ -z "$NODE" ] && [ -x "$DIR/node/bin/node" ]; then NODE="$DIR/node/bin/node"; fi
if [ -z "$NODE" ]; then
  NVER="v20.17.0"
  say "Node.js 18+ not found — downloading a portable Node ${NVER} (${ARCH})…"
  URL="https://nodejs.org/dist/${NVER}/node-${NVER}-linux-${ARCH}.tar.xz"
  tmp="$(mktemp -d)"
  if have curl; then curl -fsSL "$URL" -o "$tmp/node.tar.xz"; else wget -qO "$tmp/node.tar.xz" "$URL"; fi
  tar -xJf "$tmp/node.tar.xz" -C "$tmp"
  rm -rf "$DIR/node"; mv "$tmp/node-${NVER}-linux-${ARCH}" "$DIR/node"
  rm -rf "$tmp"
  NODE="$DIR/node/bin/node"
fi
say "Using Node: $($NODE -v)  ($NODE)"

# ----------------------------- app source -----------------------------
say "Fetching IRNetFree source (${BRANCH})…"
tmp="$(mktemp -d)"
TARURL="https://codeload.github.com/${REPO}/tar.gz/refs/heads/${BRANCH}"
if have curl; then curl -fsSL "$TARURL" -o "$tmp/src.tgz"; else wget -qO "$tmp/src.tgz" "$TARURL"; fi
tar -xzf "$tmp/src.tgz" -C "$tmp"
SRCDIR="$(find "$tmp" -maxdepth 1 -type d -name 'Irnetfree_xray-client-*' | head -n1)"
[ -n "$SRCDIR" ] || err "could not extract source"
rm -rf "$APP"; mkdir -p "$APP"
cp -a "$SRCDIR/." "$APP/"
rm -rf "$tmp"

# ----------------------------- xray-core -----------------------------
if [ ! -x "$APP/bin/xray" ]; then
  say "Downloading xray-core…"
  ( cd "$APP" && "$NODE" scripts/download-xray.js ) || say "xray download failed — you can retry later from the UI (Settings → Required files)."
fi

# ----------------------------- launcher -----------------------------
cat > "$DIR/run.sh" <<EOF
#!/usr/bin/env bash
exec "$NODE" "$APP/src/server/server.js" --port "$PORT" --host "$HOST" "\$@"
EOF
chmod +x "$DIR/run.sh"

# convenience symlink if ~/.local/bin is on PATH
if [ -d "$HOME/.local/bin" ]; then ln -sf "$DIR/run.sh" "$HOME/.local/bin/irnetfree" 2>/dev/null || true; fi

echo ""
say "Installed to: $DIR"
echo "  Start it:      $DIR/run.sh"
echo "  Web UI:        http://$HOST:$PORT/"
echo ""
echo "  From your laptop, forward the port over SSH, then open it locally:"
echo "    ssh -N -L $PORT:127.0.0.1:$PORT user@THIS_SERVER"
echo "    # then browse to  http://127.0.0.1:$PORT/"
echo ""
echo "  Tip: proxy/pool modes need no root. TUN (whole-server tunnel) needs sudo."
echo ""

# ----------------------------- systemd (optional) -----------------------------
if [ "$DO_SERVICE" = "1" ]; then
  if [ "$(id -u)" != "0" ] && ! have sudo; then err "--service needs root (or sudo)"; fi
  SUDO=""; [ "$(id -u)" != "0" ] && SUDO="sudo"
  say "Installing systemd service irnetfree.service…"
  $SUDO tee /etc/systemd/system/irnetfree.service >/dev/null <<EOF
[Unit]
Description=IRNetFree headless server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$NODE $APP/src/server/server.js --port $PORT --host $HOST
Restart=on-failure
RestartSec=3
User=$(id -un)

[Install]
WantedBy=multi-user.target
EOF
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now irnetfree.service
  say "Service enabled. Status:  systemctl status irnetfree"
elif [ "$DO_START" = "1" ]; then
  say "Starting server (Ctrl+C to stop)…"
  exec "$DIR/run.sh"
fi
