'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { AGENT, IT_OPS, ROGUE, SQL, setup, connect, struct } = require('./helpers');

const inc = (over) => ({ number: 'INC0000001', short_description: 'x', state: 'In progress', priority: 'P1', assignment_group: 'DB Ops', assigned_to: '', cmdb_ci: 'orders-prod', ...over });
const INCIDENTS = [
  inc({ number: 'INC0000001' }),
  inc({ number: 'INC0000002', state: 'Resolved' }),
  inc({ number: 'INC0000003', priority: 'P3' }),
  inc({ number: 'INC0000004', assignment_group: 'Network Ops', assigned_to: AGENT }),
  inc({ number: 'INC0000005', state: 'On hold' }),
];

// [expected code, the client to connect as, run_query arguments]
const cases = [
  ['AGENT_NOT_RECOGNIZED', ROGUE, ['INC0000001']],
  ['WRITE_NOT_ALLOWED', IT_OPS, ['INC0000001', 'DELETE FROM orders WHERE id = 1;']], // INC0000001 has no write scope
  ['FORBIDDEN_STATEMENT', IT_OPS, ['INC0000001', `${SQL} DROP TABLE orders;`]],
  ['MODE_NOT_ALLOWED', IT_OPS, ['INC0000001', SQL, 'payments-prod']],
  ['INCIDENT_NOT_FOUND', IT_OPS, ['INC9999999']],
  ['INCIDENT_NOT_FOUND', IT_OPS, ['CHG0000001']],
  ['INCIDENT_NOT_FOUND', IT_OPS, ['not-a-ticket']],
  ['INCIDENT_NOT_OPEN', IT_OPS, ['INC0000002']],
  ['INCIDENT_NOT_OPEN', IT_OPS, ['INC0000005']],
  ['PRIORITY_NOT_ALLOWED', IT_OPS, ['INC0000003']],
];

for (const [code, client, args] of cases) {
  test(`refuses with ${code}: ${client.client_id} ${JSON.stringify(args)}`, async (t) => {
    const ctx = await setup({ incidents: INCIDENTS });
    t.after(ctx.close);
    const agent = await connect(ctx, client);
    const res = await agent.runQuery(...args);
    assert.equal(res.body.result.isError, true);
    assert.equal(struct(res).code, code);
    assert.equal(struct(res).checks.length, 7);
    assert.equal(struct(res).checks.filter((c) => c.status === 'fail').length, 1);
    assert.equal(ctx.app.locals.broker.sessions.size, 0);
  });
}

test('assignment to the agent itself is enough, even in another group', async (t) => {
  const ctx = await setup({ incidents: INCIDENTS });
  t.after(ctx.close);
  const res = await (await connect(ctx)).runQuery('INC0000004');
  assert.equal(res.body.result.isError, false);
  assert.equal(struct(res).checks[5].detail, `Assigned to ${AGENT}`);
});

test('checks run in order: the first failure wins and later checks are skipped', async (t) => {
  const ctx = await setup({ incidents: INCIDENTS });
  t.after(ctx.close);
  // Unknown agent AND a bogus incident: the agent check comes first.
  const res = await (await connect(ctx, ROGUE)).runQuery('INC9999999');
  assert.equal(struct(res).code, 'AGENT_NOT_RECOGNIZED');
  assert.deepEqual(struct(res).checks.map((c) => c.status), ['fail', 'skip', 'skip', 'skip', 'skip', 'skip', 'skip']);
});

test('a statement the policy does not allow is refused on its own and does not end the session', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);
  assert.equal((await agent.runQuery('INC0012345')).body.result.isError, false);

  const write = await agent.runQuery('INC0012345', 'UPDATE orders SET status = 1;');
  assert.equal(write.body.result.isError, true);
  assert.equal(struct(write).code, 'WRITE_NOT_ALLOWED');
  assert.equal(struct(write).end_reason, undefined);

  assert.equal((await agent.runQuery('INC0012345')).body.result.isError, false, 'the session is still alive');
});

test('a session stops working after max_duration_minutes', async (t) => {
  let clock = Date.now();
  const ctx = await setup({ now: () => new Date(clock) });
  t.after(ctx.close);
  const agent = await connect(ctx);
  assert.equal((await agent.runQuery('INC0012345')).body.result.isError, false);
  clock += 31 * 60_000;
  const res = await agent.runQuery('INC0012345');
  assert.equal(res.body.result.isError, true);
  assert.equal(struct(res).code, 'SESSION_REVOKED');
  assert.equal(struct(res).end_reason, 'expired');
});

test('the admin kill switch rejects unknown agents', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  assert.equal((await ctx.post('/warden/agents/Nobody/suspend')).status, 404);
});
