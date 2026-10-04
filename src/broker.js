'use strict';
const crypto = require('node:crypto');
const express = require('express');
const { ItsmUnavailableError } = require('./itsm-client');
const { analyze } = require('./sql');
const { MockDbError } = require('./mockdb');

// "Open" means someone is actively working the incident. On hold, Resolved, Closed and Canceled are not.
const OPEN_STATES = new Set(['New', 'In progress']);

const CANNED_ROWS = [
  [/count\s*\(\s*\*\s*\)/i, () => [{ count: 42 }]],
  [/pg_stat_activity/i, () => [
    { pid: 4121, state: 'active', wait_event: 'Lock' },
    { pid: 4130, state: 'idle in transaction', wait_event: null },
  ]],
];
const cannedRows = (sql) => { const hit = CANNED_ROWS.find(([re]) => re.test(sql)); return hit ? hit[1]() : null; };

// The tool call carries no "mode", so the gateway reads it from the statements (see sql.js). Reads are always
// allowed. A write needs the incident's write scope: one database, the tables and the statement types it may use.
// The order of the tests decides which refusal the agent sees: a forbidden statement is refused whatever the scope
// says, and a missing WHERE is reported before an unlisted statement type, because it is the more dangerous mistake.
function judge({ analysis, incident, database }, policy) {
  const scope = policy.write_scopes[incident];
  const scoped = scope && scope.database === database ? scope : null;
  const forbidden = analysis.statements.find((st) => st.kind === 'forbidden');
  if (forbidden) return fail('FORBIDDEN_STATEMENT', forbidden.reason);

  const writes = analysis.statements.filter((st) => st.kind === 'write');
  for (const st of writes) {
    if (!scoped) return fail('WRITE_NOT_ALLOWED', `${incident} has no write policy for ${database}; access is read only`);
    if (!scoped.tables.includes(st.table)) return fail('TABLE_NOT_IN_SCOPE', `Table "${st.table}" is not writable under ${incident} (writable: ${scoped.tables.join(', ')})`);
    if (st.verb !== 'INSERT' && !st.hasWhere) return fail('MISSING_WHERE_CLAUSE', `${st.verb} on ${st.table} needs a WHERE clause`);
    if (!scoped.statements.includes(st.verb)) return fail('WRITE_NOT_ALLOWED', `${st.verb} is not allowed under ${incident} (allowed: ${scoped.statements.join(', ')})`);
  }
  const upTo = `up to ${policy.max_duration_minutes} min`;
  if (writes.length > 0) return pass(`${database}, WRITE ${[...new Set(writes.map((st) => st.verb))].join('/')} on ${[...new Set(writes.map((st) => st.table))].join(', ')}, allowed by ${incident}, ${upTo}`);
  if (scoped) return pass(`${database}, read; writes limited to ${scoped.tables.join(', ')} (${scoped.statements.join('/')}), ${upTo}`);
  return pass(`${database}, read only, ${upTo}`);
}

const accessOf = (policy, incident, database) => {
  const scope = policy.write_scopes[incident];
  return scope && scope.database === database ? `read; writes: ${scope.statements.join('/')} on ${scope.tables.join(', ')}` : 'read';
};

// The seven checks, in the order they run. Each returns { ok, code, reason, detail }:
// detail says what was verified (pass) or why it failed; code/reason are used on failure.
// Checks 3-7 read ctx.incident, which check 3 fetches from ITSM.
const CHECKS = [
  {
    id: 'agent_recognized',
    label: () => 'Agent is recognized',
    run: ({ req, policy, broker }) => {
      if (!policy) return fail('AGENT_NOT_RECOGNIZED', `Agent "${req.agent}" is not registered in Warden`);
      if (broker.suspended.has(req.agent)) return fail('AGENT_SUSPENDED', `Agent "${req.agent}" is suspended by a security admin`);
      return pass(`${req.agent} is registered, owner ${policy.owner}`);
    },
  },
  {
    id: 'policy_allows',
    label: () => 'Policy allows this database and mode',
    run: ({ req, policy }) => {
      if (!policy.allowed_databases.includes(req.database)) return fail('MODE_NOT_ALLOWED', `Policy does not allow ${req.agent} on database "${req.database}"`);
      return judge(req, policy);
    },
  },
  {
    id: 'incident_exists',
    label: (p) => `Incident exists, valid ${p ? p.required_ticket_type : 'INC'} number`,
    run: async (ctx) => {
      const { req, policy, broker } = ctx;
      if (!policy.ticket_pattern.test(req.incident)) return fail('INCIDENT_NOT_FOUND', `"${req.incident}" is not a valid ${policy.required_ticket_type} ticket number`);
      ctx.incident = await broker.itsm.getIncident(req.incident);
      if (!ctx.incident) return fail('INCIDENT_NOT_FOUND', `${req.incident} does not exist in ITSM`);
      return pass(`${req.incident} found`);
    },
  },
  {
    id: 'incident_open',
    label: () => 'Incident is open',
    run: ({ incident }) => (OPEN_STATES.has(incident.state)
      ? pass(`State: ${incident.state}`)
      : fail('INCIDENT_NOT_OPEN', `${incident.number} is ${incident.state}, not open`)),
  },
  {
    id: 'priority_allowed',
    label: (p) => `Priority is allowed${p ? ` (${p.allowed_priorities.join(' or ')})` : ''}`,
    run: ({ incident, policy }) => (policy.allowed_priorities.includes(incident.priority)
      ? pass(`Priority: ${incident.priority}`)
      : fail('PRIORITY_NOT_ALLOWED', `Priority ${incident.priority} is not allowed (${policy.allowed_priorities.join(' or ')})`)),
  },
  {
    id: 'assigned',
    label: () => 'Assigned to the agent or its group',
    run: ({ req, incident, policy }) => {
      if (incident.assigned_to === req.agent) return pass(`Assigned to ${req.agent}`);
      if (incident.assignment_group === policy.assignment_group) return pass(`Assignment group: ${incident.assignment_group}`);
      const who = incident.assigned_to ? `${incident.assigned_to}, ${incident.assignment_group}` : incident.assignment_group;
      return fail('INCIDENT_NOT_ASSIGNED', `${incident.number} is assigned to ${who}, not to ${req.agent} or ${policy.assignment_group}`, `Assigned to ${who}`);
    },
  },
  {
    id: 'target_matches',
    label: () => 'Incident CI matches the database',
    run: ({ req, incident }) => (incident.cmdb_ci === req.database
      ? pass(incident.cmdb_ci)
      : fail('TARGET_MISMATCH', `Incident CI is ${incident.cmdb_ci}, request targets ${req.database}`)),
  },
];
const INCIDENT_CHECKS_START = 2; // checks 3-7 depend on the incident; these are rechecked on every query

const pass = (detail) => ({ ok: true, detail });
const fail = (code, reason, detail = reason) => ({ ok: false, code, reason, detail });

// Runs checks from `start`, stopping at the first failure (later ones are reported as skipped).
// Fail closed: if ITSM cannot be reached the failing check reports CHECK_UNAVAILABLE.
async function runChecks(ctx, start = 0) {
  const checks = [];
  let failure = null;
  for (const check of CHECKS.slice(start)) {
    const label = check.label(ctx.policy);
    if (failure) {
      checks.push({ id: check.id, label, status: 'skip', detail: 'Not checked' });
      continue;
    }
    let result;
    try {
      result = await check.run(ctx);
    } catch (err) {
      if (!(err instanceof ItsmUnavailableError)) throw err;
      result = fail('CHECK_UNAVAILABLE', `${err.message}. Access is denied while the incident cannot be verified`);
    }
    checks.push({ id: check.id, label, status: result.ok ? 'pass' : 'fail', detail: result.detail });
    if (!result.ok) failure = { code: result.code, reason: result.reason };
  }
  return { checks, failure };
}

const humanize = (endReason) => endReason.replace(/_/g, ' ');
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
const queries = (n) => plural(n, 'query').replace('querys', 'queries');

// The Warden side of the agent's connection. The MCP transport (JSON-RPC, sessions, tool schemas) lives in
// mcp.js; this is the policy engine behind its two tools.
//
// Two kinds of session, kept apart on purpose:
//   MCP session    - the agent's connection to the gateway (Mcp-Session-Id). Created at `initialize`.
//   access session - the just-in-time grant to one database for one incident ("sess_..."). It holds the
//                    simulated database credential and is opened by the first run_query for that
//                    (database, incident) pair. Every access session belongs to one MCP session.
function createBroker({ policies, itsmClient, db, now = () => new Date() }) {
  const policyByClient = new Map([...policies.values()].map((p) => [p.client_id, p]));
  const sessions = new Map(); // access sessions by id; they hold the simulated credential, never sent to callers
  const mcpSessions = new Map();
  const suspended = new Set();
  const auditLog = [];
  const broker = { itsm: itsmClient, suspended };

  function audit(event, fields) {
    auditLog.push({ id: auditLog.length + 1, ts: now().toISOString(), event, ...fields });
  }

  function reset() {
    sessions.clear();
    mcpSessions.clear();
    suspended.clear();
    auditLog.length = 0;
  }

  // Ends an access session and writes the summary to the incident work notes. State changes first
  // (synchronously), so the session is dead even if ITSM is down when the note is written.
  async function endSession(s, endReason) {
    if (s.status !== 'active') return;
    s.status = 'ended';
    s.end_reason = endReason;
    s.ended_at = now().toISOString();
    s.credential = null; // the simulated credential expires with the session
    const writes = s.writes > 0 ? `, ${plural(s.writes, 'write')}` : '';
    audit('session_ended', { agent: s.agent, session_id: s.id, incident: s.incident, database: s.database, end_reason: endReason, queries: s.queries, detail: `${humanize(endReason)}, ${queries(s.queries)}${writes}` });

    const note = [
      'Warden session summary',
      `Session: ${s.id}`,
      `Agent: ${s.agent}`,
      `Owner: ${s.owner}`,
      `Database: ${s.database} (${s.access})`,
      `Queries: ${s.queries}`,
      ...(s.writes > 0 ? [`Writes: ${s.writes}`] : []),
      ...(s.refused_writes > 0 ? [`Refused writes: ${s.refused_writes}`] : []),
      `Ended: ${humanize(endReason)}`,
    ].join('\n');
    try {
      await itsmClient.addWorkNote(s.incident, note, 'Warden');
      audit('work_note_written', { agent: s.agent, session_id: s.id, incident: s.incident, detail: 'Summary added to the incident' });
    } catch (err) {
      audit('work_note_failed', { agent: s.agent, session_id: s.id, incident: s.incident, detail: err.message });
    }
  }

  // Every write attempt, allowed or refused, goes on the incident as it happens: time, agent, statement, result.
  async function writeNote(s, sql, result) {
    const note = ['Warden write attempt', `Time: ${now().toISOString()}`, `Agent: ${s.agent}`, `Session: ${s.id}`, `Statement: ${sql.trim()}`, `Result: ${result}`].join('\n');
    try {
      await itsmClient.addWorkNote(s.incident, note, 'Warden');
      audit('work_note_written', { agent: s.agent, session_id: s.id, incident: s.incident, kind: 'WRITE', detail: 'Write attempt recorded on the incident' });
    } catch (err) {
      audit('work_note_failed', { agent: s.agent, session_id: s.id, incident: s.incident, kind: 'WRITE', detail: err.message });
    }
  }

  // ---- MCP sessions -------------------------------------------------------

  function openMcpSession(clientId) {
    const policy = policyByClient.get(clientId);
    const session = { id: crypto.randomUUID(), clientId, agent: policy ? policy.agent : clientId, grants: new Map() };
    mcpSessions.set(session.id, session);
    return session;
  }

  const getMcpSession = (id, clientId) => {
    const session = mcpSessions.get(id);
    return session && session.clientId === clientId ? session : undefined;
  };

  // The agent closes its connection: every access session opened through it ends as "task complete".
  async function closeMcpSession(session) {
    mcpSessions.delete(session.id);
    await Promise.all([...session.grants.values()].map((s) => endSession(s, 'task_complete')));
  }

  // ---- Tools --------------------------------------------------------------

  function listDatabases(mcp) {
    const policy = policyByClient.get(mcp.clientId);
    const identity = CHECKS[0].run({ req: { agent: mcp.agent }, policy, broker });
    if (!identity.ok) return { ok: false, code: identity.code, reason: identity.reason };
    return { ok: true, databases: policy.allowed_databases.map((database) => ({ database, access: policy.access })) };
  }

  // run_query. The first call for a (database, incident) pair is the access request: all seven checks run and,
  // if they pass, an access session opens. Later calls for the same pair reuse it and recheck the incident.
  async function runQuery(mcp, { database, sql, incident }) {
    const policy = policyByClient.get(mcp.clientId);
    const grant = mcp.grants.get(`${database}|${incident}`);
    if (grant) return queryOnSession(grant, policy, sql);
    const analysis = analyze(sql, { database, databases: db.names() });
    return openSession(mcp, policy, { agent: mcp.agent, database, incident, analysis }, sql);
  }

  async function openSession(mcp, policy, request, sql) {
    const { analysis } = request;
    const ctx = { req: request, policy, broker };
    const { checks, failure } = await runChecks(ctx);

    // The agent could have been suspended, or have closed its connection, while we waited on ITSM.
    let denial = failure;
    if (!denial && suspended.has(request.agent)) denial = { code: 'AGENT_SUSPENDED', reason: `Agent "${request.agent}" is suspended by a security admin` };
    if (!denial && !mcpSessions.has(mcp.id)) denial = { code: 'SESSION_REVOKED', reason: 'The MCP session was closed' };
    if (denial) {
      // No work note here: the incident is only verified by check 3, and a refusal at check 2 comes before it.
      audit('access_denied', { agent: request.agent, incident: request.incident, database: request.database, kind: analysis.intent, code: denial.code, detail: denial.reason });
      return { ok: false, ...denial, kind: analysis.intent.toLowerCase(), checks };
    }

    const opened = now();
    const s = {
      id: `sess_${crypto.randomBytes(8).toString('hex')}`,
      agent: request.agent,
      owner: policy.owner,
      database: request.database,
      access: accessOf(policy, request.incident, request.database),
      incident: request.incident,
      status: 'active',
      queries: 0,
      writes: 0,
      refused_writes: 0,
      end_reason: null,
      opened_at: opened.toISOString(),
      expires_at: new Date(opened.getTime() + policy.max_duration_minutes * 60_000).toISOString(),
      credential: `sim-cred-${crypto.randomUUID()}`, // simulated; the agent only ever gets query results
    };
    sessions.set(s.id, s);
    mcp.grants.set(`${s.database}|${s.incident}`, s);
    audit('session_opened', { agent: s.agent, session_id: s.id, incident: s.incident, database: s.database, detail: `${s.access} access until ${s.expires_at}` });
    return { ...(await run(s, sql, analysis)), checks };
  }

  const rowsFor = (database, st) => cannedRows(st.text) || db.select(database, st) || [];

  // Runs the statements on the mock database. Every write is prepared before any is applied, so a statement the
  // database rejects leaves the data untouched.
  function execute(s, sql, analysis) {
    const plans = analysis.statements.map((st) => (st.kind === 'write' ? db.prepare(s.database, st) : null));
    let rows = [];
    let changed = 0;
    analysis.statements.forEach((st, i) => {
      if (plans[i]) changed += plans[i].run();
      else rows = rowsFor(s.database, st);
    });
    const write = analysis.intent === 'WRITE';
    s.queries += 1;
    if (write) s.writes += 1;
    audit('query', {
      agent: s.agent, session_id: s.id, incident: s.incident, database: s.database, sql,
      kind: analysis.intent, ...(write && { rows_affected: changed }),
      detail: write ? `${sql.trim()} (${plural(changed, 'row')} changed)` : sql,
    });
    return { ok: true, session_id: s.id, expires_at: s.expires_at, kind: analysis.intent.toLowerCase(), rows, row_count: rows.length, ...(write && { rows_affected: changed }) };
  }

  // Execute, then record a write on the incident whatever its result.
  async function run(s, sql, analysis) {
    let out;
    try {
      out = execute(s, sql, analysis);
    } catch (err) {
      if (!(err instanceof MockDbError)) throw err;
      audit('query_blocked', { agent: s.agent, session_id: s.id, incident: s.incident, database: s.database, sql, kind: analysis.intent, code: 'STATEMENT_ERROR', detail: err.message });
      out = { ok: false, code: 'STATEMENT_ERROR', reason: `The database rejected the statement: ${err.message}`, session_id: s.id, kind: analysis.intent.toLowerCase() };
    }
    if (analysis.intent === 'WRITE') {
      await writeNote(s, sql, out.ok ? `ALLOWED, ${plural(out.rows_affected, 'row')} changed` : `FAILED (${out.code}): ${out.reason}`);
    }
    return out;
  }

  async function queryOnSession(s, policy, sql) {
    const analysis = analyze(sql, { database: s.database, databases: db.names() });
    // Audit the refused query first, then end the session it caused (if it was still live), then answer.
    const refuse = async (code, reason, endReason) => {
      audit('query_blocked', { agent: s.agent, session_id: s.id, incident: s.incident, database: s.database, sql, kind: analysis.intent, code, detail: reason });
      if (endReason) await endSession(s, endReason);
      return { ok: false, code, reason, session_id: s.id, kind: analysis.intent.toLowerCase(), ...(s.end_reason && { end_reason: s.end_reason }) };
    };
    const alreadyEnded = () => refuse('SESSION_REVOKED', `Session already ended (${humanize(s.end_reason)})`);

    if (s.status !== 'active') return alreadyEnded();
    // A statement the policy does not allow is refused on its own; it does not end the session.
    const verdict = CHECKS[1].run({ req: { agent: s.agent, database: s.database, incident: s.incident, analysis }, policy });
    if (!verdict.ok) {
      const out = await refuse(verdict.code, verdict.reason);
      if (analysis.intent === 'WRITE') {
        s.refused_writes += 1;
        await writeNote(s, sql, `REFUSED (${verdict.code}): ${verdict.reason}`);
      }
      return out;
    }
    if (now().getTime() >= new Date(s.expires_at).getTime()) return refuse('SESSION_REVOKED', 'Session expired', 'expired');

    // Recheck the incident on every query, not only when access was granted.
    const { failure } = await runChecks({ req: s, policy, broker }, INCIDENT_CHECKS_START);
    if (s.status !== 'active') return alreadyEnded(); // e.g. kill switch fired during the recheck
    if (failure) {
      const unavailable = failure.code === 'CHECK_UNAVAILABLE';
      return refuse(
        unavailable ? 'CHECK_UNAVAILABLE' : 'SESSION_REVOKED',
        `Incident recheck failed: ${failure.reason}. Session revoked`,
        unavailable ? 'check_unavailable' : failure.code.toLowerCase(),
      );
    }
    return run(s, sql, analysis);
  }

  // ---- Admin API (not part of the agent protocol) ---------------------------

  const adminRouter = express.Router();

  // Kill switch: suspend the agent and close every access session it has open.
  adminRouter.post('/agents/:agent/suspend', async (req, res) => {
    const agent = req.params.agent;
    if (!policies.has(agent)) return res.status(404).json({ code: 'AGENT_NOT_RECOGNIZED', reason: `Agent "${agent}" is not registered in Warden` });
    suspended.add(agent);
    const open = [...sessions.values()].filter((s) => s.agent === agent && s.status === 'active');
    audit('agent_suspended', { agent, detail: `${open.length} session(s) closed` });
    await Promise.all(open.map((s) => endSession(s, 'kill_switch')));
    res.json({ agent, suspended: true, closed_sessions: open.map((s) => s.id) });
  });

  adminRouter.get('/audit', (req, res) => res.json({ events: auditLog }));

  return { adminRouter, reset, sessions, mcpSessions, suspended, auditLog, openMcpSession, getMcpSession, closeMcpSession, listDatabases, runQuery };
}

module.exports = { createBroker, CHECKS };
