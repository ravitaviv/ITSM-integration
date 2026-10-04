'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const nodeCrypto = require('node:crypto');
const esbuild = require('esbuild');
const { bundleOptions } = require('../scripts/build-pages');
const shim = require('../web/shims/crypto');

// ---- the SHA-256 stand-in must agree with Node's -------------------------------------------------------------------

test('browser sha256 matches node:crypto, including at the padding boundaries', () => {
  const inputs = ['', 'abc', 'demo-secret-it-ops', 'é€😀 unicode', 'x'.repeat(55), 'x'.repeat(56), 'x'.repeat(63), 'x'.repeat(64), 'x'.repeat(65), 'y'.repeat(1000)];
  for (const input of inputs) {
    const expected = nodeCrypto.createHash('sha256').update(input).digest('hex');
    const actual = Buffer.from(shim.createHash('sha256').update(input).digest()).toString('hex');
    assert.equal(actual, expected, `sha256 of ${input.length} characters`);
  }
});

test('browser timingSafeEqual and randomBytes behave like the Node ones', () => {
  assert.equal(shim.timingSafeEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 3)), true);
  assert.equal(shim.timingSafeEqual(Uint8Array.of(1, 2, 3), Uint8Array.of(1, 2, 4)), false);
  assert.throws(() => shim.timingSafeEqual(Uint8Array.of(1), Uint8Array.of(1, 2)), RangeError);
  assert.match(shim.randomBytes(8).toString('hex'), /^[0-9a-f]{16}$/);
  assert.match(shim.randomUUID(), /^[0-9a-f-]{36}$/);
});

// ---- the whole app, running the way it does in the page: no server, no network ------------------------------------

// Builds the browser bundle and runs it in an isolated context that has only what a page has. Its fetch is the
// one the bundle installs; anything not meant for the app would reach the (here failing) native fetch.
async function loadBrowserApp() {
  const { outputFiles } = await esbuild.build({ ...bundleOptions, write: false, outfile: 'bundle.js' });
  const sandbox = {
    console, URL, Headers, Response, TextEncoder, structuredClone, AbortSignal,
    crypto: nodeCrypto.webcrypto,
    location: { href: 'https://example.github.io/ITSM-integration/' },
    fetch: async (input) => { throw new Error(`the network was used for ${input}`); },
  };
  vm.createContext(sandbox);
  vm.runInContext(outputFiles[0].text, sandbox);
  return sandbox.fetch;
}

async function client() {
  const fetch = await loadBrowserApp();
  const call = async (method, path, body, headers = {}) => {
    const res = await fetch(path, { method, headers: { 'content-type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await res.text();
    return { status: res.status, headers: res.headers, body: text ? JSON.parse(text) : null };
  };
  const token = (await call('POST', '/idp/token', { grant_type: 'client_credentials', client_id: 'it-ops-agent', client_secret: 'demo-secret-it-ops' })).body.access_token;
  const init = await call('POST', '/mcp/postgres', { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }, { authorization: `Bearer ${token}` });
  const headers = { authorization: `Bearer ${token}`, 'mcp-session-id': init.headers.get('mcp-session-id') };
  let id = 2;
  const run = (sql, incident = 'INC0012349') => call('POST', '/mcp/postgres', { jsonrpc: '2.0', id: id++, method: 'tools/call', params: { name: 'run_query', arguments: { database: 'orders-prod', sql, incident } } }, headers);
  return { fetch, call, token, headers, run, init };
}

test('browser build: a write case runs end to end inside the page, with no network', async () => {
  const { call, headers, run, init } = await client();
  assert.equal(init.status, 200);
  assert.ok(headers['mcp-session-id'], 'the session id header reaches the page');

  const read = (await run("SELECT * FROM orders WHERE status = 'stuck'")).body.result;
  assert.equal(read.isError, false);
  assert.equal(read.structuredContent.row_count, 3);

  const write = (await run("UPDATE orders SET status='processing' WHERE status='stuck'")).body.result;
  assert.equal(write.structuredContent.rows_affected, 3);
  assert.equal((await call('GET', '/demo/db/orders-prod/orders')).body.rows.filter((r) => r.status === 'stuck').length, 0);

  const refused = (await run('DELETE FROM orders')).body.result;
  assert.equal(refused.isError, true);
  assert.equal(refused.structuredContent.code, 'MISSING_WHERE_CLAUSE');

  assert.equal((await call('DELETE', '/mcp/postgres', undefined, headers)).status, 204);
  const incident = (await call('GET', '/itsm/incidents/INC0012349')).body.result;
  assert.equal(incident.work_notes.length, 3, 'two write notes and the session summary');
  assert.match(incident.work_notes[2].text, /Writes: 1\nRefused writes: 1/);

  const events = (await call('GET', '/warden/audit')).body.events.map((e) => `${e.event}:${e.kind || ''}`);
  assert.ok(events.includes('query:WRITE') && events.includes('query_blocked:WRITE'));
  const calls = (await call('GET', '/demo/itsm-calls')).body.calls.filter((c) => c.caller === 'warden-broker');
  assert.ok(calls.some((c) => c.method === 'POST' && c.route.endsWith('/work_notes')), 'the gateway reached the mock ITSM through fetch');
});

test('browser build: protocol errors, authentication and unknown routes behave as on the server', async () => {
  const { fetch, call, token } = await client();
  assert.equal((await call('POST', '/mcp/postgres', { jsonrpc: '2.0', id: 1, method: 'tools/list' })).status, 401);
  const bad = await fetch('/mcp/postgres', { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: '{nope' });
  assert.equal(bad.status, 400);
  assert.equal((await bad.json()).error.code, -32700);
  assert.equal((await call('GET', '/mcp/postgres', undefined, { authorization: `Bearer ${token}` })).status, 405);
  assert.equal((await fetch('/demo/nope', { method: 'POST' })).status, 404);
  assert.equal((await call('POST', '/idp/token', { grant_type: 'client_credentials', client_id: 'it-ops-agent', client_secret: 'wrong' })).status, 401);
  await assert.rejects(() => fetch('https://fonts.googleapis.com/css2'), /the network was used/);
});

test('browser build: an ITSM outage is still a fail-closed refusal', async () => {
  const { call, run } = await client();
  await call('POST', '/demo/itsm-outage', { down: true });
  const res = (await run("SELECT * FROM orders WHERE status = 'stuck'")).body.result;
  assert.equal(res.isError, true);
  assert.equal(res.structuredContent.code, 'CHECK_UNAVAILABLE');
});
