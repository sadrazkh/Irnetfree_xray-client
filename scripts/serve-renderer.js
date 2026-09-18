'use strict';
/**
 * Dev only: serve src/renderer over http so a browser can render the UI.
 *
 * The renderer is plain HTML/CSS/JS, so most visual work (a modal's layout, a
 * font, the QR plate) can be checked without building or launching Electron —
 * but only over http: opening index.html as a file:// URL leaves the relative
 * <script>/<link> tags unresolved. Nothing here talks to the app: window.api
 * does not exist, so anything that needs the main process stays blank.
 *
 *   node scripts/serve-renderer.js   → http://localhost:8765
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..', 'src', 'renderer');
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2', '.svg': 'image/svg+xml', '.jsx': 'text/javascript', '.png': 'image/png' };
http.createServer((req, res) => {
  const rel = decodeURIComponent(req.url.split('?')[0]).replace(/^\/+/, '') || 'index.html';
  const file = path.join(root, rel);
  if (!file.startsWith(root)) { res.writeHead(403); return res.end('no'); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' });
    res.end(buf);
  });
}).listen(8765, () => console.log('renderer on http://localhost:8765'));
