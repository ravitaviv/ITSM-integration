'use strict';
const path = require('node:path');
const express = require('express');
const { loadPolicy } = require('./policy');
const { createItsm } = require('./itsm');
const { createItsmClient } = require('./itsm-client');
const { createBroker } = require('./broker');
const { createIdp } = require('./idp');
const { createMockDb } = require('./mockdb');
const { createMcp, rpcError } = require('./mcp');

// Builds the whole mock: ITSM at /itsm, the identity provider at /idp, the Warden MCP gateway at /mcp,
// Warden's admin API at /warden, demo controls at /demo, the page at /.
// itsmBaseUrl is where the broker reaches ITSM (a string or a function returning one).
function createApp({ policy = path.join(__dirname, '..', 'policy.json'), incidents, idpClients, itsmBaseUrl, itsmTimeoutMs, now } = {}) {
  const app = express();
  app.use(express.json());
  app.use((req, res, next) => { req.body ??= {}; next(); });

  const itsm = createItsm({ seed: incidents, now });
  const db = createMockDb();
  const broker = createBroker({
    policies: loadPolicy(policy),
    db,
    itsmClient: createItsmClient(itsmBaseUrl, { timeoutMs: itsmTimeoutMs }),
    now,
  });

  const idp = createIdp({ clients: idpClients, now });

  app.use('/itsm', itsm.router);
  app.use('/idp', idp.router);
  app.use('/mcp', createMcp({ broker, idp }).router);
  app.use('/warden', broker.adminRouter);

  // Mock-only controls. Not part of either real product.
  app.post('/demo/reset', (req, res) => {
    itsm.reset();
    broker.reset();
    db.reset();
    res.json({ ok: true });
  });
  // A look at the mock database for the page's before/after view. The agent never gets this; it only has run_query.
  app.get('/demo/db/:database/:table', (req, res) => {
    const rows = db.snapshot(req.params.database, req.params.table);
    if (!rows) return res.status(404).json({ error: 'No such table' });
    res.json({ database: req.params.database, table: req.params.table, rows });
  });
  app.get('/demo/itsm-calls', (req, res) => res.json({ calls: itsm.getCalls() }));
  app.post('/demo/itsm-outage', (req, res) => {
    itsm.setDown(req.body.down);
    res.json({ down: Boolean(req.body.down) });
  });

  app.use(express.static(path.join(__dirname, '..', 'public')));

  app.use((err, req, res, next) => {
    if (err.type === 'entity.parse.failed') {
      if (req.originalUrl.startsWith('/mcp')) return res.status(400).json(rpcError(null, -32700, 'Parse error'));
      return res.status(400).json({ code: 'BAD_REQUEST', reason: 'Body is not valid JSON' });
    }
    console.error(err);
    res.status(500).json({ code: 'INTERNAL_ERROR', reason: 'Unexpected error in the mock' });
  });

  app.locals.itsm = itsm;
  app.locals.broker = broker;
  app.locals.db = db;
  return app;
}

// Creates the app and listens on localhost only. The broker's ITSM client points back at this server.
async function start(options = {}, port = 3000) {
  let base;
  const app = createApp({ itsmBaseUrl: () => base, ...options });
  const server = await new Promise((resolve, reject) => {
    const s = app.listen(port, '127.0.0.1', () => resolve(s));
    s.on('error', reject);
  });
  base = `http://127.0.0.1:${server.address().port}`;
  return { app, server, base };
}

module.exports = { createApp, start };
