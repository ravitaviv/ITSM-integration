'use strict';
const express = require('express');

const SERVER_NAME = 'postgres';
const PROTOCOL_VERSION = '2025-06-18';

// The database MCP server offers two tools: run_query and list_databases. `incident` on run_query is this
// prototype's own addition: the way the agent tells the gateway which ITSM incident justifies the access.
const TOOLS = [
  {
    name: 'list_databases',
    description: 'List the databases this agent may query.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'run_query',
    description: 'Run a SQL statement on a database. Access is granted just in time and only while an ITSM incident justifies it. Reads are allowed; a write needs the incident to have a write policy covering that table and statement.',
    inputSchema: {
      type: 'object',
      properties: {
        database: { type: 'string', description: 'Database name, for example orders-prod' },
        sql: { type: 'string', description: 'The SQL statement to run' },
        incident: { type: 'string', description: 'ITSM incident number that justifies the access, for example INC0012345 (proposed extension)' },
      },
      required: ['database', 'sql', 'incident'],
      additionalProperties: false,
    },
  },
];

const rpcResult = (id, result) => ({ jsonrpc: '2.0', id, result });
const rpcError = (id, code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });
const isText = (v) => typeof v === 'string' && v.trim() !== '';

// A tool's outcome as an MCP tool result. A refusal by policy is a tool error (isError), not a protocol error.
function toolResult(outcome) {
  const { ok, ...data } = outcome;
  const done = data.kind === 'write' ? `${data.rows_affected} row(s) changed` : JSON.stringify(data.rows ?? data.databases);
  const text = ok ? done : `${data.code}: ${data.reason}`;
  return { content: [{ type: 'text', text }], structuredContent: data, isError: !ok };
}

// MCP over HTTP ("Streamable HTTP" transport), simplified: one endpoint per MCP server, JSON-RPC 2.0 requests
// in POST bodies, plain JSON responses (no SSE stream). The gateway authenticates every call with the bearer
// token the agent got from its identity provider.
function createMcp({ broker, idp }) {
  const router = express.Router();

  function authenticate(req, res) {
    const match = /^Bearer (.+)$/.exec(req.get('authorization') || '');
    const identity = match && idp.validate(match[1]);
    if (!identity) {
      res.set('WWW-Authenticate', 'Bearer error="invalid_token"').status(401).json({ error: 'invalid_token', error_description: 'Missing, invalid or expired access token' });
      return null;
    }
    return identity;
  }

  // Returns the caller's MCP session, or answers 400/404 and returns null.
  function sessionOf(req, res, identity, id = null) {
    const sessionId = req.get('mcp-session-id');
    if (!sessionId) {
      res.status(400).json(rpcError(id, -32600, 'Missing Mcp-Session-Id header. Send initialize first'));
      return null;
    }
    const session = broker.getMcpSession(sessionId, identity.client_id);
    if (!session) {
      res.status(404).json(rpcError(id, -32600, 'Unknown or closed MCP session. Send initialize to start a new one'));
      return null;
    }
    return session;
  }

  // Every route starts with the same two steps: the right server name, then a valid bearer token.
  const guarded = (handler) => (req, res) => {
    if (req.params.server !== SERVER_NAME) return res.status(404).json({ error: 'unknown_mcp_server' });
    const identity = authenticate(req, res);
    if (identity) return handler(req, res, identity);
  };

  router.post('/:server', guarded(async (req, res, identity) => {
    const msg = req.body;
    if (Array.isArray(msg) || typeof msg.method !== 'string' || msg.jsonrpc !== '2.0') {
      return res.status(400).json(rpcError(msg && msg.id !== undefined ? msg.id : null, -32600, 'Invalid Request: expected one JSON-RPC 2.0 request object'));
    }
    const { id, method } = msg;

    if (method === 'initialize') {
      const session = broker.openMcpSession(identity.client_id);
      res.set('Mcp-Session-Id', session.id);
      return res.json(rpcResult(id, {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'warden-mcp', title: 'Warden access gateway (mock)', version: '0.1.0' },
      }));
    }

    const session = sessionOf(req, res, identity, id ?? null);
    if (!session) return;
    if (id === undefined) return res.status(202).end(); // a notification, such as notifications/initialized

    switch (method) {
      case 'ping':
        return res.json(rpcResult(id, {}));
      case 'tools/list':
        return res.json(rpcResult(id, { tools: TOOLS }));
      case 'tools/call': {
        const { name, arguments: args = {} } = msg.params || {};
        if (!TOOLS.some((t) => t.name === name)) return res.json(rpcError(id, -32602, `Unknown tool: ${name}`));
        if (name === 'list_databases') return res.json(rpcResult(id, toolResult(broker.listDatabases(session))));
        if (![args.database, args.sql, args.incident].every(isText)) {
          return res.json(rpcError(id, -32602, 'Invalid arguments: database, sql and incident are required strings'));
        }
        return res.json(rpcResult(id, toolResult(await broker.runQuery(session, args))));
      }
      default:
        return res.json(rpcError(id, -32601, `Method not found: ${method}`));
    }
  }));

  // The agent closes its connection (session termination in the Streamable HTTP transport).
  router.delete('/:server', guarded(async (req, res, identity) => {
    const session = sessionOf(req, res, identity);
    if (!session) return;
    await broker.closeMcpSession(session);
    res.status(204).end();
  }));

  // No server-to-client SSE stream in this mock.
  router.get('/:server', (req, res) => res.set('Allow', 'POST, DELETE').status(405).json({ error: 'method_not_allowed' }));

  return { router };
}

module.exports = { createMcp, rpcError, SERVER_NAME, TOOLS };
