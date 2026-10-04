'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { AGENT, setup, connect, struct, closedPort, workNotes, policyFor } = require('./helpers');

const ACTIVITY = 'SELECT pid, state, wait_event FROM pg_stat_activity;';

test('valid incident: access opens on the first run_query, queries are logged, summary written on end', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);

  const first = await agent.runQuery('INC0012345');
  assert.equal(first.status, 200);
  assert.equal(first.body.result.isError, false);
  const opened = struct(first);
  assert.match(opened.session_id, /^sess_[0-9a-f]{16}$/);
  const minutes = (new Date(opened.expires_at) - Date.now()) / 60_000;
  assert.ok(minutes > 29 && minutes <= 30, `expires in ~30 min, got ${minutes}`);
  assert.equal(opened.checks.length, 7);
  assert.ok(opened.checks.every((c) => c.status === 'pass'));
  assert.deepEqual(opened.rows, [{ count: 42 }]);

  // The second call reuses the access session: no new checks payload, same session id.
  const second = struct(await agent.runQuery('INC0012345', ACTIVITY));
  assert.equal(second.session_id, opened.session_id);
  assert.equal(second.checks, undefined);
  assert.equal(second.row_count, 2);

  const ended = await agent.end();
  assert.equal(ended.status, 204);

  const [note] = await workNotes(ctx, 'INC0012345');
  for (const expected of [AGENT, 'Owner: DB Ops', 'Database: orders-prod', 'Queries: 2', 'Ended: task complete']) {
    assert.ok(note.text.includes(expected), `work note should include "${expected}":\n${note.text}`);
  }

  const events = (await ctx.get('/warden/audit')).body.events.map((e) => e.event);
  assert.deepEqual(events, ['session_opened', 'query', 'query', 'session_ended', 'work_note_written']);
});

test('wrong assignee: refused with INCIDENT_NOT_ASSIGNED and no access session', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);

  const res = await agent.runQuery('INC0012346');
  assert.equal(res.status, 200, 'a policy refusal is a tool error, not an HTTP error');
  assert.equal(res.body.result.isError, true);
  const denied = struct(res);
  assert.equal(denied.code, 'INCIDENT_NOT_ASSIGNED');
  assert.deepEqual(denied.checks.map((c) => c.status), ['pass', 'pass', 'pass', 'pass', 'pass', 'fail', 'skip']);
  assert.match(denied.checks[5].detail, /M\. Cohen, Network Ops/);
  assert.equal(denied.session_id, undefined);
  assert.equal(denied.rows, undefined);
  assert.equal(ctx.app.locals.broker.sessions.size, 0);
  assert.equal((await ctx.get('/warden/audit')).body.events[0].code, 'INCIDENT_NOT_ASSIGNED');
});

test('wrong database: refused with TARGET_MISMATCH', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);

  const res = await agent.runQuery('INC0012347');
  assert.equal(res.body.result.isError, true);
  const denied = struct(res);
  assert.equal(denied.code, 'TARGET_MISMATCH');
  assert.match(denied.reason, /payments-prod.*orders-prod/);
  assert.equal(denied.checks[6].status, 'fail');
  assert.equal(ctx.app.locals.broker.sessions.size, 0);
});

test('resolved mid-session: the next run_query is refused with SESSION_REVOKED and the session stays dead', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);

  assert.equal((await agent.runQuery('INC0012345')).body.result.isError, false);
  await ctx.post('/itsm/incidents/INC0012345/state', { state: 'Resolved' });

  const revoked = await agent.runQuery('INC0012345', ACTIVITY);
  assert.equal(revoked.body.result.isError, true);
  assert.equal(struct(revoked).code, 'SESSION_REVOKED');
  assert.equal(struct(revoked).end_reason, 'incident_not_open');
  assert.equal(struct(revoked).rows, undefined);

  // Re-opening the incident does not bring the session back...
  await ctx.post('/itsm/incidents/INC0012345/state', { state: 'In progress' });
  assert.equal(struct(await agent.runQuery('INC0012345', ACTIVITY)).code, 'SESSION_REVOKED');
  // ...but a new MCP session gets a fresh decision.
  const fresh = await connect(ctx);
  assert.equal((await fresh.runQuery('INC0012345')).body.result.isError, false);

  const [note] = await workNotes(ctx, 'INC0012345');
  assert.match(note.text, /Queries: 1/);
  assert.match(note.text, /Ended: incident not open/);

  // The audit reads in the order things happened: refused query, session end, note, then the later refusal.
  const events = (await ctx.get('/warden/audit')).body.events.map((e) => e.event);
  assert.deepEqual(events.slice(0, 6), ['session_opened', 'query', 'query_blocked', 'session_ended', 'work_note_written', 'query_blocked']);
});

test("kill switch: closes only that agent's sessions and blocks new access", async (t) => {
  const ctx = await setup({
    policy: { agents: [policyFor(AGENT, 'it-ops-agent'), policyFor('Other Agent', 'other-agent', { allowed_priorities: ['P1'] })] },
    idpClients: { 'it-ops-agent': 'demo-secret-it-ops', 'other-agent': 'other-secret' },
  });
  t.after(ctx.close);

  const a1 = await connect(ctx);
  const a2 = await connect(ctx);
  const b1 = await connect(ctx, { client_id: 'other-agent', client_secret: 'other-secret' });
  const ids = [];
  for (const a of [a1, a2, b1]) ids.push(struct(await a.runQuery('INC0012345')).session_id);

  const suspend = await ctx.post(`/warden/agents/${encodeURIComponent(AGENT)}/suspend`);
  assert.equal(suspend.status, 200);
  assert.deepEqual(suspend.body.closed_sessions.sort(), [ids[0], ids[1]].sort());

  for (const a of [a1, a2]) {
    const res = await a.runQuery('INC0012345', ACTIVITY);
    assert.equal(res.body.result.isError, true);
    assert.equal(struct(res).code, 'SESSION_REVOKED');
    assert.equal(struct(res).end_reason, 'kill_switch');
  }
  assert.equal((await b1.runQuery('INC0012345', ACTIVITY)).body.result.isError, false, 'other agent is unaffected');

  // A suspended agent cannot open a new connection's worth of access either.
  const again = await (await connect(ctx)).runQuery('INC0012345');
  assert.equal(struct(again).code, 'AGENT_SUSPENDED');

  const notes = await workNotes(ctx, 'INC0012345');
  assert.equal(notes.filter((n) => n.text.includes('Ended: kill switch')).length, 2);
});

test('fail closed: ITSM unreachable at request time refuses with CHECK_UNAVAILABLE', async (t) => {
  const ctx = await setup({ itsmBaseUrl: `http://127.0.0.1:${await closedPort()}` });
  t.after(ctx.close);
  const agent = await connect(ctx);

  const res = await agent.runQuery('INC0012345');
  assert.equal(res.body.result.isError, true);
  assert.equal(struct(res).code, 'CHECK_UNAVAILABLE');
  assert.deepEqual(struct(res).checks.map((c) => c.status), ['pass', 'pass', 'fail', 'skip', 'skip', 'skip', 'skip']);
  assert.equal(ctx.app.locals.broker.sessions.size, 0);
});

test('fail closed: ITSM outage during a session revokes it and it stays revoked', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);

  assert.equal((await agent.runQuery('INC0012345')).body.result.isError, false);
  await ctx.post('/demo/itsm-outage', { down: true });

  const res = await agent.runQuery('INC0012345', ACTIVITY);
  assert.equal(res.body.result.isError, true);
  assert.equal(struct(res).code, 'CHECK_UNAVAILABLE');
  assert.equal(struct(res).rows, undefined);

  await ctx.post('/demo/itsm-outage', { down: false });
  assert.equal(struct(await agent.runQuery('INC0012345', ACTIVITY)).code, 'SESSION_REVOKED');

  // The note could not be written during the outage; the audit log says so.
  const events = (await ctx.get('/warden/audit')).body.events.map((e) => e.event);
  assert.ok(events.includes('work_note_failed'));
});

test('no database credential in any response: the agent only ever gets query results', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);

  const responses = [];
  const track = async (promise) => { const r = await promise; responses.push(r); return r; };

  const granted = await track(agent.runQuery('INC0012345'));
  const session = ctx.app.locals.broker.sessions.get(struct(granted).session_id);
  assert.match(session.credential, /^sim-cred-/, 'the broker does hold a credential internally');

  await track(agent.rpc('tools/list'));
  await track(agent.rpc('tools/call', { name: 'list_databases', arguments: {} }));
  await track(agent.runQuery('INC0012345', ACTIVITY));
  await track(agent.runQuery('INC0012346'));
  await track(ctx.post(`/warden/agents/${encodeURIComponent(AGENT)}/suspend`));
  await track(agent.runQuery('INC0012345', ACTIVITY));
  await track(agent.end());
  await track(ctx.get('/warden/audit'));
  await track(ctx.get('/itsm/incidents/INC0012345'));

  assert.equal(session.credential, null, 'the credential is dropped when the session ends');
  for (const r of responses) {
    assert.ok(!/sim-cred|password|passwd|credential/i.test(r.text), `response leaks a credential-like value: ${r.text}`);
  }
  assert.deepEqual(Object.keys(struct(granted)).sort(), ['checks', 'expires_at', 'kind', 'row_count', 'rows', 'session_id']);
});

test('the ITSM call log shows which APIs the broker used, and when', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);

  await agent.runQuery('INC0012345');
  await agent.runQuery('INC0012345', ACTIVITY);
  await agent.end();

  const { calls } = (await ctx.get('/demo/itsm-calls')).body;
  const brokerCalls = calls.filter((c) => c.caller === 'warden-broker').map((c) => `${c.method} ${c.route} ${c.status}`);
  assert.deepEqual(brokerCalls, [
    'GET /itsm/incidents/:number 200', // first run_query: checks 3-7
    'GET /itsm/incidents/:number 200', // second run_query: recheck
    'POST /itsm/incidents/:number/work_notes 200', // MCP session closed: summary
  ]);

  // The log also keeps the real path and payloads, so the page can show them.
  const read = calls[0];
  assert.equal(read.path, '/itsm/incidents/INC0012345');
  assert.equal(read.request, undefined);
  assert.equal(read.response.result.number, 'INC0012345');
  const write = calls.at(-1);
  assert.equal(write.request.author, 'Warden');
  assert.match(write.request.work_notes, /Ended: task complete/);
  assert.equal(write.response.result.work_notes.length, 1);

  // Calls from anyone else are tagged differently.
  await ctx.get('/itsm/incidents/INC0012345');
  assert.equal((await ctx.get('/demo/itsm-calls')).body.calls.at(-1).caller, 'client');
});
