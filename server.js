// Minimal zero-dependency static server + date-confirmation API.
// Serves the current folder (defaults to index.html) and exposes:
//   GET  /api/status   -> { confirmed, date, time }
//   POST /api/confirm   -> records the date, emails the notify address, locks the page
//
// Email is sent straight over Gmail SMTP (SSL :465) with no external deps.
// Provide credentials via env vars SMTP_USER / SMTP_PASS, or a mail.config.json
// file: { "user": "you@gmail.com", "pass": "16-char app password" }.
//
// Usage: node server.js   (optionally: PORT=8080 node server.js)

import http from 'http';
import fs from 'fs';
import path from 'path';
import net from 'net';
import tls from 'tls';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const STATE_FILE = path.join(ROOT, 'date-state.json'); // its existence = "locked"
const OPENED_FILE = path.join(ROOT, 'opened-state.json'); // its existence = "open email already sent"
const NOTIFY_TO = 'a.roets12@gmail.com';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.mp3': 'audio/mpeg',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
};

// --- Mail credentials: env vars take priority, else mail.config.json ---
function loadMailConfig() {
  const cfg = { user: process.env.SMTP_USER || '', pass: process.env.SMTP_PASS || '' };
  try {
    const file = JSON.parse(fs.readFileSync(path.join(ROOT, 'mail.config.json'), 'utf8'));
    cfg.user = cfg.user || file.user || '';
    cfg.pass = cfg.pass || file.pass || '';
  } catch { /* no config file — fine */ }
  return cfg;
}

// --- Zero-dependency Gmail SMTP sender (submission on :587, STARTTLS, AUTH LOGIN) ---
// Port 587 + STARTTLS is used because many hosts (e.g. Hetzner) block the implicit-TLS
// port 465 outbound. Override the port with SMTP_PORT if needed.
function sendMail({ user, pass, to, subject, text }) {
  return new Promise((resolve, reject) => {
    const host = 'smtp.gmail.com';
    const port = Number(process.env.SMTP_PORT) || 587;
    const message = [
      `From: Date Page <${user}>`,
      `To: ${to}`,
      `Subject: ${subject}`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
      '',
      text,
    ].join('\r\n');

    // Each step waits for `expect` (the final SMTP reply code) then sends `cmd`.
    // The step flagged `starttls` upgrades the plaintext socket to TLS before its cmd.
    const steps = [
      { expect: 220, cmd: 'EHLO localhost\r\n' },                                  // server greeting
      { expect: 250, cmd: 'STARTTLS\r\n' },                                        // ask to go secure
      { expect: 220, cmd: 'EHLO localhost\r\n', starttls: true },                  // upgrade, re-greet
      { expect: 250, cmd: 'AUTH LOGIN\r\n' },
      { expect: 334, cmd: Buffer.from(user).toString('base64') + '\r\n' },
      { expect: 334, cmd: Buffer.from(pass).toString('base64') + '\r\n' },
      { expect: 235, cmd: `MAIL FROM:<${user}>\r\n` },
      { expect: 250, cmd: `RCPT TO:<${to}>\r\n` },
      { expect: 250, cmd: 'DATA\r\n' },
      { expect: 354, cmd: message + '\r\n.\r\n' },
      { expect: 250, cmd: 'QUIT\r\n' },
    ];

    let socket = net.connect(port, host);
    socket.setEncoding('utf8');
    socket.setTimeout(20000);
    let i = 0;
    let buf = '';
    let done = false;

    // Unwrap AggregateError (Node ≥17 returns one when all addresses fail) so the
    // rejection carries a real message instead of an empty string.
    const fail = (err) => {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch { /* already gone */ }
      if (err && Array.isArray(err.errors) && err.errors.length) {
        const inner = err.errors.map((e) => e.message || e.code || String(e)).join('; ');
        return reject(new Error(err.message || inner || 'connection failed'));
      }
      reject(err instanceof Error ? err : new Error(String(err)));
    };

    const attach = (s) => {
      s.setEncoding('utf8');
      s.setTimeout(20000);
      s.on('data', onData);
      s.on('error', fail);
      s.on('timeout', () => fail(new Error('SMTP timeout')));
    };

    function onData(chunk) {
      if (done || i >= steps.length) return;
      buf += chunk;
      let idx;
      while ((idx = buf.indexOf('\r\n')) !== -1) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const m = line.match(/^(\d{3})([ -])/);
        if (!m) continue;
        if (m[2] === '-') continue; // continuation line — keep reading
        const code = parseInt(m[1], 10);
        const step = steps[i];
        if (code !== step.expect) {
          return fail(new Error(`SMTP step ${i}: expected ${step.expect}, got "${line}"`));
        }
        i++;
        if (step.starttls) {
          // Upgrade the plaintext socket to TLS, then send this step's cmd over it.
          socket.removeListener('data', onData);
          buf = '';
          const secure = tls.connect({ socket, servername: host }, () => {
            socket = secure;
            attach(secure);
            secure.write(step.cmd);
          });
          secure.on('error', fail);
          return; // wait for the secure channel and its replies
        }
        socket.write(step.cmd);
        if (i >= steps.length) { socket.end(); done = true; return resolve(); }
        break; // wait for the next reply
      }
    }

    socket.on('data', onData);
    socket.on('error', fail);
    socket.on('timeout', () => fail(new Error('SMTP timeout')));
  });
}

function sendJson(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}

function readState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); }
  catch { return null; }
}

// Fire a "the link was opened" email the FIRST time the page is loaded.
// Writes a marker file before sending so concurrent loads only email once.
function notifyOpenedOnce() {
  // wx = create-only: throws if the marker already exists, so this body runs just once.
  try { fs.writeFileSync(OPENED_FILE, JSON.stringify({ at: new Date().toISOString() }, null, 2), { flag: 'wx' }); }
  catch { return; } // already sent (marker exists) — nothing to do

  const { user, pass } = loadMailConfig();
  const at = new Date().toISOString();
  const subject = '👀 Your date link was just opened!';
  const text = [
    'Someone just opened the date page for the first time. 🌸',
    '',
    `Opened at ${at}`,
  ].join('\n');

  if (user && pass) {
    sendMail({ user, pass, to: NOTIFY_TO, subject, text })
      .then(() => console.log('✉️  Link-opened email sent.'))
      .catch((e) => console.error('✉️  Link-opened email failed:', e.message));
  } else {
    console.log('✉️  No SMTP credentials set — link opened, logging instead:\n' + text + '\n');
  }
}

const server = http.createServer((req, res) => {
  const urlPath = decodeURIComponent(req.url.split('?')[0]);

  // --- Status: is the page already locked to a confirmed date? ---
  if (req.method === 'GET' && urlPath === '/api/status') {
    notifyOpenedOnce(); // first time the link is opened, email the notify address
    const state = readState();
    if (state) return sendJson(res, 200, { confirmed: true, date: state.date, time: state.time });
    return sendJson(res, 200, { confirmed: false });
  }

  // --- Confirm a date: lock it, then email the notify address ---
  if (req.method === 'POST' && urlPath === '/api/confirm') {
    const existing = readState();
    if (existing) {
      // Already confirmed — locked. Don't allow a restart/overwrite.
      return sendJson(res, 200, { ok: true, alreadyConfirmed: true, date: existing.date, time: existing.time });
    }

    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 1e5) req.destroy(); });
    req.on('end', async () => {
      let data;
      try { data = JSON.parse(body || '{}'); }
      catch { return sendJson(res, 400, { ok: false, error: 'bad json' }); }

      const date = String(data.date || '').slice(0, 40);
      const time = String(data.time || '').slice(0, 20);
      const note = String(data.note || '').slice(0, 1000);
      if (!date) return sendJson(res, 400, { ok: false, error: 'date required' });

      // Persist first — this file's existence locks the page.
      const record = { confirmed: true, date, time, note, at: new Date().toISOString() };
      try { fs.writeFileSync(STATE_FILE, JSON.stringify(record, null, 2)); }
      catch (e) { return sendJson(res, 500, { ok: false, error: 'could not save state' }); }

      // Email best-effort: a save already succeeded, so never fail the request on email.
      const { user, pass } = loadMailConfig();
      const subject = '💚 She said YES — date confirmed!';
      const text = [
        'Great news — the date is on! 🌸',
        '',
        `Date: ${date}`,
        time ? `Time: ${time}` : null,
        note ? `Note: ${note}` : null,
        '',
        `Confirmed at ${record.at}`,
      ].filter(Boolean).join('\n');

      let emailed = false;
      let emailError = null;
      if (user && pass) {
        try { await sendMail({ user, pass, to: NOTIFY_TO, subject, text }); emailed = true; }
        catch (e) { emailError = e.message; console.error('✉️  Email failed:', e.message); }
      } else {
        console.log('✉️  No SMTP credentials set — logging confirmation instead:\n' + text + '\n');
      }
      return sendJson(res, 200, { ok: true, emailed, emailError });
    });
    return;
  }

  // --- Static file serving (GET only) ---
  if (req.method !== 'GET') {
    res.writeHead(405);
    return res.end('Method Not Allowed');
  }

  let filePath = urlPath === '/' ? '/index.html' : urlPath;
  filePath = path.join(ROOT, path.normalize(filePath));
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end('<h1>404 - Not Found</h1>');
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': 'no-store', // always serve the latest file (no stale cache)
    });
    res.end(data);
  });
});

server.listen(PORT, () => {
  console.log(`💚 Serving on http://localhost:${PORT}`);
  const { user, pass } = loadMailConfig();
  console.log(user && pass
    ? `✉️  Email enabled — confirmations go to ${NOTIFY_TO} (from ${user})`
    : `✉️  Email NOT configured — confirmations will be logged here. Add SMTP_USER/SMTP_PASS or mail.config.json.`);
});
