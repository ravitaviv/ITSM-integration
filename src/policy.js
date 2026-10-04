'use strict';
const fs = require('node:fs');

const REQUIRED = ['agent', 'client_id', 'owner', 'assignment_group', 'allowed_databases', 'access', 'max_duration_minutes', 'allowed_priorities', 'required_ticket_type'];
const WRITABLE = ['INSERT', 'UPDATE', 'DELETE'];

// Accepts a path to a JSON file or an already-parsed object. Returns Map(agent name -> policy).
//
// `write_scopes` is optional mock data: for a given incident number, the one database, the tables and the statement
// types an agent may WRITE with while that incident justifies the access. An incident without a scope is read only.
function loadPolicy(source) {
  const raw = typeof source === 'string' ? JSON.parse(fs.readFileSync(source, 'utf8')) : source;
  if (!raw || !Array.isArray(raw.agents) || raw.agents.length === 0) throw new Error('policy: "agents" must be a non-empty array');
  const policies = new Map();
  for (const entry of raw.agents) {
    for (const key of REQUIRED) {
      if (entry[key] === undefined || entry[key] === '') throw new Error(`policy: agent "${entry.agent}" is missing "${key}"`);
    }
    if (!/^[A-Z]{2,5}$/.test(entry.required_ticket_type)) throw new Error(`policy: bad required_ticket_type "${entry.required_ticket_type}"`);
    const writeScopes = entry.write_scopes || {};
    for (const [incident, scope] of Object.entries(writeScopes)) {
      const where = `policy: write scope for ${incident}`;
      if (!entry.allowed_databases.includes(scope.database)) throw new Error(`${where} names a database the agent may not use`);
      if (!Array.isArray(scope.tables) || scope.tables.length === 0) throw new Error(`${where} needs a non-empty "tables" list`);
      if (!Array.isArray(scope.statements) || scope.statements.length === 0 || !scope.statements.every((s) => WRITABLE.includes(s))) {
        throw new Error(`${where} "statements" must be a non-empty list of ${WRITABLE.join(', ')}`);
      }
    }
    policies.set(entry.agent, { ...entry, write_scopes: writeScopes, ticket_pattern: new RegExp(`^${entry.required_ticket_type}[0-9]{7}$`) });
  }
  return policies;
}

module.exports = { loadPolicy };
