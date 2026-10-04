'use strict';
const express = require('express');

const STATES = ['New', 'In progress', 'On hold', 'Resolved', 'Closed', 'Canceled'];

const SEED = [
  // Open P1, assigned to the agent's group.
  { number: 'INC0012345', short_description: 'Orders API timing out', state: 'In progress', priority: 'P1', assignment_group: 'DB Ops', assigned_to: '', cmdb_ci: 'orders-prod' },
  // Open P1, but owned by a human in another group.
  { number: 'INC0012346', short_description: 'Orders connection pool exhausted', state: 'In progress', priority: 'P1', assignment_group: 'Network Ops', assigned_to: 'M. Cohen', cmdb_ci: 'orders-prod' },
  // Open P1 in the right group, but about a different database.
  { number: 'INC0012347', short_description: 'Payments settlement delayed', state: 'In progress', priority: 'P1', assignment_group: 'DB Ops', assigned_to: '', cmdb_ci: 'payments-prod' },
  // Already resolved.
  { number: 'INC0012348', short_description: 'Orders replica lag', state: 'Resolved', priority: 'P1', assignment_group: 'DB Ops', assigned_to: '', cmdb_ci: 'orders-prod' },
  // Open P1 in the agent's group about orders stuck in the database: the one incident with a narrow write scope (see policy.json).
  { number: 'INC0012349', short_description: 'Orders stuck after payment callback', state: 'In progress', priority: 'P1', assignment_group: 'DB Ops', assigned_to: '', cmdb_ci: 'orders-prod' },
];

// Mock of the ITSM Table API for incidents. State lives in memory.
function createItsm({ seed = SEED, now = () => new Date() } = {}) {
  let incidents;
  let calls;
  let down = false;

  function reset() {
    incidents = new Map(seed.map((i) => [i.number, { ...i, work_notes: [] }]));
    calls = [];
    down = false;
  }
  reset();

  const router = express.Router();

  // Every call is recorded (route template, real path, request and response bodies, status, and who sent it
  // via x-caller) so the demo page can show which ITSM APIs the broker used behind the scenes.
  router.use((req, res, next) => {
    let response;
    const send = res.json.bind(res);
    res.json = (body) => { response = structuredClone(body); return send(body); };
    res.on('finish', () => {
      const route = req.route ? req.route.path : req.path.replace(/^\/incidents\/[^/]+/, '/incidents/:number');
      calls.push({
        method: req.method,
        route: req.baseUrl + route,
        path: req.originalUrl.split('?')[0],
        caller: req.get('x-caller') || 'client',
        status: res.statusCode,
        request: Object.keys(req.body).length ? structuredClone(req.body) : undefined,
        response,
      });
    });
    next();
  });

  // Simulated outage: every /itsm route answers 503 while `down` is set.
  router.use((req, res, next) => {
    if (down) return res.status(503).json({ error: { message: 'ITSM unavailable (simulated outage)' } });
    next();
  });

  function find(req, res) {
    const inc = incidents.get(req.params.number);
    if (!inc) res.status(404).json({ error: { message: 'No Record found', detail: `Record doesn't exist: ${req.params.number}` } });
    return inc;
  }
  const view = (inc) => ({ result: { ...inc, work_notes: inc.work_notes.map((n) => ({ ...n })) } });

  router.get('/incidents/:number', (req, res) => {
    const inc = find(req, res);
    if (inc) res.json(view(inc));
  });

  router.post('/incidents/:number/state', (req, res) => {
    const inc = find(req, res);
    if (!inc) return;
    const { state } = req.body;
    if (!STATES.includes(state)) return res.status(400).json({ error: { message: `state must be one of: ${STATES.join(', ')}` } });
    inc.state = state;
    res.json(view(inc));
  });

  router.post('/incidents/:number/work_notes', (req, res) => {
    const inc = find(req, res);
    if (!inc) return;
    const { work_notes: text, author = 'system' } = req.body;
    if (typeof text !== 'string' || !text.trim()) return res.status(400).json({ error: { message: 'work_notes must be a non-empty string' } });
    inc.work_notes.push({ created_on: now().toISOString(), author, text });
    res.json(view(inc));
  });

  return {
    router,
    reset,
    setDown: (value) => { down = Boolean(value); },
    getCalls: () => structuredClone(calls),
  };
}

module.exports = { createItsm, SEED, STATES };
