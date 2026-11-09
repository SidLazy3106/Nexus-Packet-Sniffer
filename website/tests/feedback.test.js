'use strict';
// Run with: npm test
const test = require('node:test');
const assert = require('node:assert/strict');
const handler = require('../api/feedback');

const ENV_KEYS = ['SUPABASE_URL', 'NEXT_PUBLIC_SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'NEXT_PUBLIC_SUPABASE_ANON_KEY'];
const realFetch = global.fetch;
let saved;

test.beforeEach(() => {
  saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  ENV_KEYS.forEach((k) => delete process.env[k]);
  console.error = () => {}; // the function logs server-side failures on purpose
});
test.afterEach(() => {
  global.fetch = realFetch;
  ENV_KEYS.forEach((k) => (saved[k] === undefined ? delete process.env[k] : (process.env[k] = saved[k])));
});

function request({ method = 'POST', body, headers = {} } = {}) {
  return { method, body, headers: { host: 'nexus.example', ...headers } };
}
function response() {
  const res = { statusCode: 200, headers: {}, body: '' };
  res.setHeader = (k, v) => { res.headers[k.toLowerCase()] = v; };
  res.end = (b = '') => { res.body = b; res.ended = true; return res; };
  return res;
}
const good = { kind: 'bug', message: 'The export button did nothing.', email: 'a@b.co' };
function configure() {
  process.env.SUPABASE_URL = 'https://proj.supabase.co/';
  process.env.SUPABASE_SERVICE_ROLE_KEY = 'service-key';
}
function fakeFetch(status = 201) {
  const calls = [];
  global.fetch = async (url, init) => { calls.push({ url, init }); return { ok: status < 300, status }; };
  return calls;
}
const json = (res) => JSON.parse(res.body);

test('stores a valid submission in Supabase with the service-role key', async () => {
  configure();
  const calls = fakeFetch();
  const res = response();
  await handler(request({ body: good }), res);
  assert.equal(res.statusCode, 201);
  assert.deepEqual(json(res), { ok: true });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://proj.supabase.co/rest/v1/feedback');
  assert.equal(calls[0].init.headers.apikey, 'service-key');
  assert.equal(calls[0].init.headers.Authorization, 'Bearer service-key');
  assert.deepEqual(JSON.parse(calls[0].init.body), { kind: 'bug', message: good.message, email: 'a@b.co', source: 'website' });
});

test('email is optional and stored as null', async () => {
  configure();
  const calls = fakeFetch();
  await handler(request({ body: { kind: 'idea', message: 'Dark mode please', email: '  ' } }), response());
  assert.equal(JSON.parse(calls[0].init.body).email, null);
});

test('falls back to the public URL and anon key names the integration documents', async () => {
  process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://p.supabase.co';
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = 'anon';
  const calls = fakeFetch();
  const res = response();
  await handler(request({ body: good }), res);
  assert.equal(res.statusCode, 201);
  assert.equal(calls[0].init.headers.apikey, 'anon');
});

test('rejects invalid input with a 400 and never calls Supabase', async () => {
  configure();
  const calls = fakeFetch();
  for (const body of [
    {},
    { kind: 'spam', message: 'x' },
    { kind: 'bug', message: '   ' },
    { kind: 'bug', message: 'x'.repeat(2001) },
    { kind: 'bug', message: 'ok', email: 'not-an-email' },
    { kind: 'bug', message: 'ok', email: `${'a'.repeat(250)}@b.co` },
    null,
    'a string',
  ]) {
    const res = response();
    await handler(request({ body }), res);
    assert.equal(res.statusCode, 400, JSON.stringify(body)?.slice(0, 40));
    assert.equal(json(res).ok, false);
  }
  assert.equal(calls.length, 0);
});

test('a filled honeypot looks like success but stores nothing', async () => {
  configure();
  const calls = fakeFetch();
  const res = response();
  await handler(request({ body: { ...good, website: 'http://spam.example' } }), res);
  assert.equal(res.statusCode, 201);
  assert.equal(calls.length, 0);
});

test('only POST is accepted', async () => {
  const res = response();
  await handler(request({ method: 'GET' }), res);
  assert.equal(res.statusCode, 405);
  assert.equal(res.headers.allow, 'POST');
});

test('cross-site submissions are refused', async () => {
  configure();
  const calls = fakeFetch();
  const res = response();
  await handler(request({ body: good, headers: { origin: 'https://evil.example' } }), res);
  assert.equal(res.statusCode, 403);
  assert.equal(calls.length, 0);
  const same = response();
  await handler(request({ body: good, headers: { origin: 'https://nexus.example' } }), same);
  assert.equal(same.statusCode, 201);
});

test('reports a clear 503 when Supabase is not configured', async () => {
  const calls = fakeFetch();
  const res = response();
  await handler(request({ body: good }), res);
  assert.equal(res.statusCode, 503);
  assert.match(json(res).error, /not set up yet/);
  assert.equal(calls.length, 0);
});

test('Supabase failures become a generic 502 without leaking details', async () => {
  configure();
  fakeFetch(500);
  const res = response();
  await handler(request({ body: good }), res);
  assert.equal(res.statusCode, 502);
  assert.doesNotMatch(res.body, /500|supabase|service-key/i);
});

test('a network error or timeout also becomes a 502', async () => {
  configure();
  global.fetch = async () => { throw Object.assign(new Error('boom'), { name: 'TimeoutError' }); };
  const res = response();
  await handler(request({ body: good }), res);
  assert.equal(res.statusCode, 502);
});

test('plain HTML form posts are redirected back to the page', async () => {
  configure();
  fakeFetch();
  const ok = response();
  await handler(request({ body: good, headers: { 'content-type': 'application/x-www-form-urlencoded' } }), ok);
  assert.equal(ok.statusCode, 303);
  assert.equal(ok.headers.location, '/?feedback=sent#feedback');
  const bad = response();
  await handler(request({ body: { kind: 'bug', message: '' }, headers: { 'content-type': 'application/x-www-form-urlencoded' } }), bad);
  assert.equal(bad.headers.location, '/?feedback=error#feedback');
});

test('responses are never cached', async () => {
  const res = response();
  await handler(request({ method: 'GET' }), res);
  assert.equal(res.headers['cache-control'], 'no-store');
});
