'use strict';
/**
 * POST /api/feedback - stores a message from the website form in Supabase.
 *
 * Environment (provided by the Vercel Supabase integration, or set by hand):
 *   SUPABASE_URL or NEXT_PUBLIC_SUPABASE_URL
 *   SUPABASE_SERVICE_ROLE_KEY  (preferred: server-only, bypasses RLS)
 *   NEXT_PUBLIC_SUPABASE_ANON_KEY  (fallback; needs supabase/optional/anon-insert-policy.sql)
 *
 * The browser never sees a Supabase key and never talks to Supabase directly. Plain HTML form posts
 * (no JavaScript) are answered with a redirect; fetch() callers get JSON.
 */

const KINDS = new Set(['bug', 'idea', 'question']);
const MAX_MESSAGE = 2000;
const MAX_EMAIL = 254;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const REQUEST_TIMEOUT_MS = 8000;

function text(value) {
  return typeof value === 'string' ? value.trim() : '';
}

/** Returns { row } for a valid submission, { ignore: true } for bots, or { error } with a message. */
function validate(body) {
  const b = body && typeof body === 'object' ? body : {};
  // Honeypot: real people never see this field. Pretend success so bots learn nothing.
  if (text(b.website) !== '') return { ignore: true };

  const kind = text(b.kind);
  const message = text(b.message);
  const email = text(b.email);

  if (!KINDS.has(kind)) return { error: 'Choose what kind of message this is.' };
  if (message.length === 0) return { error: 'Please write a message.' };
  if (message.length > MAX_MESSAGE) return { error: `Please keep the message under ${MAX_MESSAGE} characters.` };
  if (email && (email.length > MAX_EMAIL || !EMAIL_RE.test(email))) return { error: 'That email address does not look right. It is optional, so you can leave it empty.' };

  return { row: { kind, message, email: email || null, source: 'website' } };
}

function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true; // non-browser callers and same-origin form posts without the header
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}

function wantsRedirect(req) {
  const type = String(req.headers['content-type'] || '');
  return type.includes('application/x-www-form-urlencoded') && !String(req.headers.accept || '').includes('application/json');
}

function reply(req, res, status, payload) {
  if (wantsRedirect(req)) {
    res.statusCode = 303;
    res.setHeader('Location', payload.ok ? '/?feedback=sent#feedback' : '/?feedback=error#feedback');
    return res.end();
  }
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  return res.end(JSON.stringify(payload));
}

async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return reply(req, res, 405, { ok: false, error: 'Use POST.' });
  }
  if (!sameOrigin(req)) return reply(req, res, 403, { ok: false, error: 'Cross-site submissions are not accepted.' });

  const checked = validate(req.body);
  if (checked.ignore) return reply(req, res, 201, { ok: true });
  if (checked.error) return reply(req, res, 400, { ok: false, error: checked.error });

  const url = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !key) {
    console.error('feedback: Supabase environment variables are missing');
    return reply(req, res, 503, { ok: false, error: 'Feedback is not set up yet. Please open an issue on GitHub instead.' });
  }

  try {
    const response = await fetch(`${url.replace(/\/+$/, '')}/rest/v1/feedback`, {
      method: 'POST',
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify(checked.row),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!response.ok) {
      // The body can echo schema details; keep it in the server log only.
      console.error(`feedback: Supabase answered ${response.status}`);
      return reply(req, res, 502, { ok: false, error: 'Your message could not be saved. Please try again later.' });
    }
  } catch (err) {
    console.error('feedback: request to Supabase failed', err && err.name);
    return reply(req, res, 502, { ok: false, error: 'Your message could not be saved. Please try again later.' });
  }

  return reply(req, res, 201, { ok: true });
}

module.exports = handler;
module.exports.validate = validate;
