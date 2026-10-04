'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { IT_OPS, MCP, SQL, setup, connect, rpc, struct, workNotes } = require('./helpers');

test('handshake: token from the IdP, initialize returns a session id, initialized is accepted', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);

  const token = await ctx.post('/idp/token', { grant_type: 'client_credentials', ...IT_OPS });
  assert.equal(token.status, 200);
  assert.equal(token.body.token_type, 'Bearer');
  const headers = { authorization: `Bearer ${token.body.access_token}` };

  const init = await ctx.call('POST', MCP, rpc(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'a', version: '1' } }), headers);
  assert.equal(init.status, 200);
  assert.equal(init.body.jsonrpc, '2.0');
  assert.equal(init.body.id, 1);
  assert.equal(init.body.result.protocolVersion, '2025-06-18');
  assert.deepEqual(init.body.result.capabilities, { tools: { listChanged: false } });
  const sessionId = init.headers.get('mcp-session-id');
  assert.ok(sessionId);

  const initialized = await ctx.call('POST', MCP, { jsonrpc: '2.0', method: 'notifications/initialized' }, { ...headers, 'mcp-session-id': sessionId });
  assert.equal(initialized.status, 202);
  assert.equal(initialized.text, '');
});

test('tools/list offers run_query and list_databases; run_query needs an incident', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);

  const { tools } = (await agent.rpc('tools/list')).body.result;
  assert.deepEqual(tools.map((tool) => tool.name), ['list_databases', 'run_query']);
  assert.deepEqual(tools[1].inputSchema.required, ['database', 'sql', 'incident']);
});

test('list_databases returns what the policy allows', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);
  const res = await agent.rpc('tools/call', { name: 'list_databases', arguments: {} });
  assert.equal(res.body.result.isError, false);
  assert.deepEqual(struct(res).databases, [{ database: 'orders-prod', access: 'read' }]);
});

test('authentication: no token, a bad token and a wrong client secret are all rejected', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);

  const bad = await ctx.post('/idp/token', { grant_type: 'client_credentials', client_id: 'it-ops-agent', client_secret: 'wrong' });
  assert.equal(bad.status, 401);
  assert.equal(bad.body.error, 'invalid_client');
  assert.equal((await ctx.post('/idp/token', { grant_type: 'password', ...IT_OPS })).status, 400);

  const body = rpc(1, 'initialize', {});
  const none = await ctx.call('POST', MCP, body);
  assert.equal(none.status, 401);
  assert.match(none.headers.get('www-authenticate'), /^Bearer/);
  assert.equal((await ctx.call('POST', MCP, body, { authorization: 'Bearer nope' })).status, 401);
});

test('sessions: the header is required, unknown ids are 404, and a closed session is gone', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);
  const auth = { authorization: `Bearer ${agent.token}` };

  const missing = await ctx.call('POST', MCP, rpc(9, 'tools/list'), auth);
  assert.equal(missing.status, 400);
  assert.equal(missing.body.error.code, -32600);
  assert.equal((await ctx.call('POST', MCP, rpc(9, 'tools/list'), { ...auth, 'mcp-session-id': 'nope' })).status, 404);

  assert.equal((await agent.end()).status, 204);
  assert.equal((await agent.rpc('tools/list')).status, 404);
});

test('a session id only works for the client that opened it', async (t) => {
  const ctx = await setup({ idpClients: { 'it-ops-agent': 'demo-secret-it-ops', 'rogue-agent': 'demo-secret-rogue' } });
  t.after(ctx.close);
  const agent = await connect(ctx);
  const other = (await ctx.post('/idp/token', { grant_type: 'client_credentials', client_id: 'rogue-agent', client_secret: 'demo-secret-rogue' })).body.access_token;
  const res = await ctx.call('POST', MCP, rpc(5, 'tools/list'), { authorization: `Bearer ${other}`, 'mcp-session-id': agent.sessionId });
  assert.equal(res.status, 404);
});

test('JSON-RPC errors: parse error, invalid request, unknown method, unknown tool, bad arguments', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);
  const headers = { authorization: `Bearer ${agent.token}`, 'mcp-session-id': agent.sessionId };

  const parse = await fetch(`${ctx.base}${MCP}`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: '{nope' });
  assert.equal(parse.status, 400);
  assert.equal((await parse.json()).error.code, -32700);

  assert.equal((await ctx.call('POST', MCP, { hello: 'world' }, headers)).body.error.code, -32600);
  assert.equal((await agent.rpc('resources/list')).body.error.code, -32601);
  assert.equal((await agent.rpc('tools/call', { name: 'drop_everything', arguments: {} })).body.error.code, -32602);
  assert.equal((await agent.rpc('tools/call', { name: 'run_query', arguments: { database: 'orders-prod', sql: SQL } })).body.error.code, -32602, 'incident is required');
  assert.equal((await agent.rpc('ping')).body.error, undefined);
});

test('other verbs and servers: GET is 405, an unknown MCP server is 404', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);
  const headers = { authorization: `Bearer ${agent.token}`, 'mcp-session-id': agent.sessionId };
  assert.equal((await ctx.call('GET', MCP, undefined, headers)).status, 405);
  assert.equal((await ctx.call('POST', '/mcp/other-server', rpc(1, 'tools/list'), headers)).status, 404);
});

test('closing the MCP session ends every access session opened through it, each with its own note', async (t) => {
  const incident = (number) => ({ number, short_description: 'x', state: 'In progress', priority: 'P1', assignment_group: 'DB Ops', assigned_to: '', cmdb_ci: 'orders-prod' });
  const ctx = await setup({ incidents: [incident('INC0000001'), incident('INC0000002')] });
  t.after(ctx.close);
  const agent = await connect(ctx);

  // Two incidents through one connection: two access sessions. A repeat for the same incident reuses its session.
  const a = struct(await agent.runQuery('INC0000001'));
  const b = struct(await agent.runQuery('INC0000002'));
  const again = struct(await agent.runQuery('INC0000001', 'SELECT 1;'));
  assert.notEqual(a.session_id, b.session_id);
  assert.equal(again.session_id, a.session_id);

  await agent.end();
  const [noteA] = await workNotes(ctx, 'INC0000001');
  const [noteB] = await workNotes(ctx, 'INC0000002');
  assert.match(noteA.text, new RegExp(`Session: ${a.session_id}`));
  assert.match(noteA.text, /Queries: 2/);
  assert.match(noteB.text, new RegExp(`Session: ${b.session_id}`));
  assert.match(noteB.text, /Queries: 1/);
});
