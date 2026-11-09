'use strict';
/**
 * Local preview that behaves like the Vercel deployment: serves the static site, runs
 * /api/feedback, and applies the headers from vercel.json (including the Content-Security-Policy).
 * It needs no Vercel login:   npm run dev   ->   http://127.0.0.1:4173
 *
 * Put SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in the environment to send real submissions.
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const feedback = require('../api/feedback');

const root = path.join(__dirname, '..');
const port = Number(process.env.PORT || 4173);
const config = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json'), 'utf8'));
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml', '.jpg': 'image/jpeg', '.png': 'image/png', '.woff2': 'font/woff2', '.json': 'application/json',
};
const PRIVATE = new Set(['api', 'tests', 'scripts', 'node_modules']); // served by Vercel as functions or not at all

function applyHeaders(pathname, res) {
  for (const rule of config.headers || []) {
    const pattern = new RegExp(`^${rule.source.replace(/\(\.\*\)/g, '.*')}$`);
    if (pattern.test(pathname)) for (const h of rule.headers) res.setHeader(h.key, h.value);
  }
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const type = String(req.headers['content-type'] || '');
      try {
        if (type.includes('application/json')) return resolve(JSON.parse(raw));
        if (type.includes('application/x-www-form-urlencoded')) return resolve(Object.fromEntries(new URLSearchParams(raw)));
      } catch { /* fall through */ }
      resolve(undefined);
    });
  });
}

http
  .createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    applyHeaders(url.pathname, res);
    if (url.pathname === '/api/feedback') {
      req.body = await readBody(req);
      return feedback(req, res);
    }
    const rel = decodeURIComponent(url.pathname === '/' ? 'index.html' : url.pathname.slice(1));
    const file = path.resolve(root, rel);
    const top = rel.split('/')[0];
    if (!file.startsWith(root + path.sep) || PRIVATE.has(top) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
      res.statusCode = 404;
      return res.end('Not found');
    }
    res.setHeader('Content-Type', TYPES[path.extname(file)] || 'application/octet-stream');
    fs.createReadStream(file).pipe(res);
  })
  .listen(port, '127.0.0.1', () => console.log(`NEXUS site preview on http://127.0.0.1:${port}`));
