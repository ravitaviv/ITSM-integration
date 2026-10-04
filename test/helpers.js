'use strict';
const net = require('node:net');
const { start } = require('../src/app');

const AGENT = 'IT Ops Agent';
const IT_OPS = { client_id: 'it-ops-agent', client_secret: 'demo-secret-it-ops' };
const ROGUE = { client_id: 'rogue-agent', client_secret: 'demo-secret-rogue' };
const MCP = '/mcp/postgres';
const SQL = "SELECT count(*) FROM orders WHERE status = 'pending';";

// Starts a fresh mock on a random port. Register `t.after(ctx.close)` in the test.
async function setup(options = {}) {
  const { app, server, base } = await start(options, 0);
  async function call(method, path, body, headers = {}) {
    const res = await fetch(base + path, {
      method,
      headers: { 'content-type': 'application/json', ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    return { status: res.status, headers: res.headers, text, body: text ? JSON.parse(text) : null };
  }
  return {
    app,
    base,
    get: (path) => call('GET', path),
    post: (path, body = {}, headers) => call('POST', path, body, headers),
    call,
    close: () => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }),
  };
}

// An agent talking MCP to the gateway: gets a token from the IdP, opens an MCP session, then calls tools.
// Every helper returns the raw response; `struct` digs out the tool's structuredContent.
async function connect(ctx, client = IT_OPS) {
  const token = (await ctx.post('/idp/token', { grant_type: 'client_credentials', ...client })).body.access_token;
  const headers = { authorization: `Bearer ${token}` };
  const init = await ctx.call('POST', MCP, rpc(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test agent', version: '1' } }), headers);
  const sessionId = init.headers.get('mcp-session-id');
  const withSession = { ...headers, 'mcp-session-id': sessionId };
  await ctx.call('POST', MCP, { jsonrpc: '2.0', method: 'notifications/initialized' }, withSession);

  let nextId = 2;
  const agent = {
    token,
    sessionId,
    rpc: (method, params) => ctx.call('POST', MCP, rpc(nextId++, method, params), withSession),
    runQuery: (incident, sql = SQL, database = 'orders-prod') =>
      agent.rpc('tools/call', { name: 'run_query', arguments: { database, sql, incident } }),
    end: () => ctx.call('DELETE', MCP, undefined, withSession),
  };
  return agent;
}

const rpc = (id, method, params) => ({ jsonrpc: '2.0', id, method, params });
const struct = (res) => res.body.result.structuredContent;

// A port that nothing is listening on, to stand in for an unreachable ITSM.
function closedPort() {
  return new Promise((resolve) => {
    const s = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

const workNotes = async (ctx, number) => (await ctx.get(`/itsm/incidents/${number}`)).body.result.work_notes;

const policyFor = (agent, clientId, over = {}) => ({
  agent, client_id: clientId, owner: 'DB Ops', assignment_group: 'DB Ops', allowed_databases: ['orders-prod'],
  access: 'read', max_duration_minutes: 30, allowed_priorities: ['P1', 'P2'], required_ticket_type: 'INC', ...over,
});

module.exports = { AGENT, IT_OPS, ROGUE, MCP, SQL, setup, connect, rpc, struct, closedPort, workNotes, policyFor };
