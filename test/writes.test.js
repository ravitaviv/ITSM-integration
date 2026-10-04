'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { analyze } = require('../src/sql');
const { createMockDb } = require('../src/mockdb');
const { loadPolicy } = require('../src/policy');
const { AGENT, setup, connect, struct, workNotes, policyFor } = require('./helpers');

const STUCK = 'INC0012349'; // the incident with a narrow write scope: orders, UPDATE only
const FIX = "UPDATE orders SET status='processing' WHERE status='stuck'";
const READ_STUCK = "SELECT * FROM orders WHERE status = 'stuck';";

const ordersOf = async (ctx) => (await ctx.get('/demo/db/orders-prod/orders')).body.rows;
const countStatus = (rows, status) => rows.filter((r) => r.status === status).length;
const events = async (ctx) => (await ctx.get('/warden/audit')).body.events;

// ---- classification (sql.js) --------------------------------------------------------------------------------------

const opts = { database: 'orders-prod', databases: ['orders-prod', 'payments-prod'] };
const classes = [
  ["SELECT * FROM orders", 'READ', 'read', 'SELECT', 'orders'],
  [FIX, 'WRITE', 'write', 'UPDATE', 'orders'],
  ['UPDATE payments SET status = \'x\' WHERE id = 1', 'WRITE', 'write', 'UPDATE', 'payments'],
  ['INSERT INTO orders (customer) VALUES (\'A\')', 'WRITE', 'write', 'INSERT', 'orders'],
  ['DELETE FROM public.orders WHERE id = 1', 'WRITE', 'write', 'DELETE', 'orders'],
  ['DROP TABLE orders', 'WRITE', 'forbidden', 'DROP'],
  ['ALTER TABLE orders ADD COLUMN x int', 'WRITE', 'forbidden', 'ALTER'],
  ['TRUNCATE orders', 'WRITE', 'forbidden', 'TRUNCATE'],
  ['GRANT ALL ON orders TO public', 'WRITE', 'forbidden', 'GRANT'],
  ['REVOKE ALL ON orders FROM public', 'WRITE', 'forbidden', 'REVOKE'],
  ['CREATE TABLE t (id int)', 'WRITE', 'forbidden', 'CREATE'],
  ['VACUUM orders', 'WRITE', 'forbidden', 'VACUUM'],
  ['SELECT * FROM "payments-prod".public.ledger', 'READ', 'forbidden', 'SELECT'],
  ['UPDATE payments-prod.ledger SET amount = 1 WHERE id = 1', 'WRITE', 'forbidden', 'UPDATE'],
  ['SELECT * FROM otherdb.public.orders', 'READ', 'forbidden', 'SELECT'],
  ['WITH x AS (DELETE FROM orders RETURNING *) SELECT * FROM x', 'READ', 'forbidden', 'WITH'],
];
for (const [sql, intent, kind, verb, table] of classes) {
  test(`classifies: ${sql}`, () => {
    const a = analyze(sql, opts);
    assert.equal(a.intent, intent);
    assert.equal(a.statements[0].kind, kind);
    assert.equal(a.statements[0].verb, verb);
    if (table) assert.equal(a.statements[0].table, table);
  });
}

test('classifies: a WHERE clause is found, and a match-everything WHERE does not count', () => {
  const has = (sql) => analyze(sql, opts).statements[0].hasWhere;
  assert.equal(has("UPDATE orders SET status = 'a' WHERE id = 1"), true);
  assert.equal(has("UPDATE orders SET status = 'a'"), false);
  assert.equal(has('DELETE FROM orders'), false);
  assert.equal(has('DELETE FROM orders WHERE 1=1'), false);
  assert.equal(has('DELETE FROM orders WHERE true'), false);
  assert.equal(has("DELETE FROM orders WHERE note = 'where'"), true);
});

test('classifies: keywords inside strings and comments are ignored; scripts are split', () => {
  const a = analyze("SELECT 'DROP TABLE x; DELETE FROM orders' AS note; -- DROP TABLE y\nUPDATE orders SET status = 'a' /* DROP */ WHERE id = 1", opts);
  assert.deepEqual(a.statements.map((s) => s.kind), ['read', 'write']);
  assert.equal(a.intent, 'WRITE');
  assert.equal(analyze('SELECT 1; DROP TABLE orders', opts).statements[1].kind, 'forbidden');
  assert.equal(analyze('', opts).statements[0].kind, 'forbidden');
});

// ---- mock database (mockdb.js) ------------------------------------------------------------------------------------

test('mock database: update, delete and insert change the rows; select reads them; errors change nothing', () => {
  const db = createMockDb();
  const st = (sql) => analyze(sql, opts).statements[0];
  const apply = (sql) => db.prepare('orders-prod', st(sql)).run();
  assert.equal(db.select('orders-prod', st("SELECT * FROM orders WHERE status = 'stuck'")).length, 3);
  assert.equal(apply(FIX), 3);
  assert.equal(db.select('orders-prod', st("SELECT * FROM orders WHERE status = 'stuck'")).length, 0);
  assert.equal(apply("INSERT INTO orders (customer, status) VALUES ('Wayne', 'pending')"), 1);
  assert.equal(db.snapshot('orders-prod', 'orders').at(-1).id, 1007);
  assert.equal(apply("DELETE FROM orders WHERE customer = 'Wayne' AND status = 'pending'"), 1);
  assert.throws(() => apply('UPDATE orders SET nope = 1 WHERE id = 1'), /column "nope"/);
  assert.throws(() => apply("UPDATE nothing SET a = 1 WHERE id = 1"), /relation "nothing"/);
  assert.throws(() => apply("UPDATE orders SET status = 'x' WHERE id = 1 OR id = 2"), /unsupported/);
  db.reset();
  assert.equal(db.snapshot('orders-prod', 'orders').filter((r) => r.status === 'stuck').length, 3);
});

// ---- enforcement through the gateway ------------------------------------------------------------------------------

test('fix stuck orders: the allowed write changes the data, is marked WRITE, and is noted on the incident', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);

  const read = await agent.runQuery(STUCK, READ_STUCK);
  assert.equal(struct(read).kind, 'read');
  assert.equal(struct(read).row_count, 3);
  assert.match(struct(read).checks[1].detail, /writes limited to orders \(UPDATE\)/);
  assert.equal(countStatus(await ordersOf(ctx), 'stuck'), 3);

  const write = await agent.runQuery(STUCK, FIX);
  assert.equal(write.body.result.isError, false);
  assert.equal(struct(write).kind, 'write');
  assert.equal(struct(write).rows_affected, 3);
  assert.equal(write.body.result.content[0].text, '3 row(s) changed');

  const after = await ordersOf(ctx);
  assert.equal(countStatus(after, 'stuck'), 0);
  assert.equal(countStatus(after, 'processing'), 3);
  assert.equal(struct(await agent.runQuery(STUCK, READ_STUCK)).row_count, 0, 'the agent sees the change');

  const query = (await events(ctx)).filter((e) => e.event === 'query');
  assert.deepEqual(query.map((e) => e.kind), ['READ', 'WRITE', 'READ']);
  assert.equal(query[1].rows_affected, 3);
  assert.equal(query[1].sql, FIX);

  const [note] = await workNotes(ctx, STUCK);
  for (const expected of ['Warden write attempt', 'Time: ', `Agent: ${AGENT}`, `Statement: ${FIX}`, 'Result: ALLOWED, 3 rows changed']) {
    assert.ok(note.text.includes(expected), `write note should include "${expected}":\n${note.text}`);
  }

  await agent.end();
  const notes = await workNotes(ctx, STUCK);
  assert.equal(notes.length, 2);
  assert.match(notes[1].text, /Queries: 3\nWrites: 1\nEnded: task complete/);
  assert.match(notes[1].text, /Database: orders-prod \(read; writes: UPDATE on orders\)/);
});

// [name, statement, expected code, the table that must stay untouched]
const refusals = [
  ['out of scope table', "UPDATE payments SET status = 'captured' WHERE status = 'pending'", 'TABLE_NOT_IN_SCOPE', 'payments'],
  ['no WHERE', 'DELETE FROM orders', 'MISSING_WHERE_CLAUSE', 'orders'],
  ['UPDATE without WHERE', "UPDATE orders SET status = 'processing'", 'MISSING_WHERE_CLAUSE', 'orders'],
  ['match-everything WHERE', "UPDATE orders SET status = 'processing' WHERE 1=1", 'MISSING_WHERE_CLAUSE', 'orders'],
  ['statement type not in scope (DELETE)', 'DELETE FROM orders WHERE id = 1001', 'WRITE_NOT_ALLOWED', 'orders'],
  ['statement type not in scope (INSERT)', "INSERT INTO orders (customer, status) VALUES ('Wayne', 'pending')", 'WRITE_NOT_ALLOWED', 'orders'],
  ['DROP TABLE', 'DROP TABLE orders', 'FORBIDDEN_STATEMENT', 'orders'],
  ['TRUNCATE', 'TRUNCATE orders', 'FORBIDDEN_STATEMENT', 'orders'],
  ['a forbidden statement after an allowed one', `${FIX}; DROP TABLE orders`, 'FORBIDDEN_STATEMENT', 'orders'],
  ['another database', 'UPDATE "payments-prod".public.ledger SET amount = 0 WHERE id = 1', 'FORBIDDEN_STATEMENT', 'orders'],
];
for (const [name, statement, code, table] of refusals) {
  test(`refused write (${name}): ${code}, no change, logged, noted, session stays open`, async (t) => {
    const ctx = await setup();
    t.after(ctx.close);
    const agent = await connect(ctx);
    await agent.runQuery(STUCK, READ_STUCK);
    const before = (await ctx.get(`/demo/db/orders-prod/${table}`)).body.rows;

    const res = await agent.runQuery(STUCK, statement);
    assert.equal(res.body.result.isError, true);
    assert.equal(struct(res).code, code);
    assert.equal(struct(res).kind, 'write');
    assert.equal(struct(res).end_reason, undefined, 'a refused statement does not end the session');

    assert.deepEqual((await ctx.get(`/demo/db/orders-prod/${table}`)).body.rows, before, 'the data is unchanged');
    assert.equal(countStatus(await ordersOf(ctx), 'processing'), 0, 'not even the allowed first statement ran');

    const blocked = (await events(ctx)).find((e) => e.event === 'query_blocked');
    assert.equal(blocked.kind, 'WRITE');
    assert.equal(blocked.code, code);
    assert.equal(blocked.sql, statement);

    const [note] = await workNotes(ctx, STUCK);
    assert.match(note.text, new RegExp(`Result: REFUSED \\(${code}\\)`));
    assert.ok(note.text.includes(`Statement: ${statement}`));

    assert.equal((await agent.runQuery(STUCK, READ_STUCK)).body.result.isError, false, 'the session still works');
    await agent.end();
    assert.match((await workNotes(ctx, STUCK)).at(-1).text, /Refused writes: 1/);
  });
}

test('an incident with no write policy is read only: a write is refused with WRITE_NOT_ALLOWED', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);
  await agent.runQuery('INC0012345', READ_STUCK);
  const res = await agent.runQuery('INC0012345', FIX);
  assert.equal(struct(res).code, 'WRITE_NOT_ALLOWED');
  assert.match(struct(res).reason, /read only/);
  assert.equal(countStatus(await ordersOf(ctx), 'stuck'), 3);
});

test('a read that touches another database is refused as FORBIDDEN_STATEMENT, and is not noted as a write', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);
  await agent.runQuery(STUCK, READ_STUCK);
  const res = await agent.runQuery(STUCK, 'SELECT * FROM "payments-prod".public.ledger');
  assert.equal(struct(res).code, 'FORBIDDEN_STATEMENT');
  assert.equal(struct(res).kind, 'read');
  assert.equal((await workNotes(ctx, STUCK)).length, 0);
});

test('a refused write as the very first call is denied at check 2, opens no session and is audited but not noted', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);
  const res = await agent.runQuery(STUCK, 'DELETE FROM orders');
  assert.equal(struct(res).code, 'MISSING_WHERE_CLAUSE');
  assert.deepEqual(struct(res).checks.map((c) => c.status), ['pass', 'fail', 'skip', 'skip', 'skip', 'skip', 'skip']);
  assert.equal(ctx.app.locals.broker.sessions.size, 0);
  const [denied] = await events(ctx);
  assert.deepEqual([denied.event, denied.kind, denied.code], ['access_denied', 'WRITE', 'MISSING_WHERE_CLAUSE']);
  assert.equal((await workNotes(ctx, STUCK)).length, 0, 'the incident is not verified until check 3');
  assert.equal((await ordersOf(ctx)).length, 6);
});

test('an allowed write as the first call opens the session, runs, and is noted', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);
  const res = await agent.runQuery(STUCK, FIX);
  assert.equal(res.body.result.isError, false);
  assert.equal(struct(res).rows_affected, 3);
  assert.match(struct(res).checks[1].detail, /WRITE UPDATE on orders, allowed by INC0012349/);
  assert.match((await workNotes(ctx, STUCK))[0].text, /Result: ALLOWED, 3 rows changed/);
});

test('a statement the policy allows but the database rejects changes nothing, is noted as FAILED, and keeps the session', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);
  await agent.runQuery(STUCK, READ_STUCK);
  // The second statement is bad, so the first must not be applied either.
  const res = await agent.runQuery(STUCK, `${FIX}; UPDATE orders SET nope = 1 WHERE id = 1002`);
  assert.equal(struct(res).code, 'STATEMENT_ERROR');
  assert.equal(countStatus(await ordersOf(ctx), 'processing'), 0);
  assert.match((await workNotes(ctx, STUCK))[0].text, /Result: FAILED \(STATEMENT_ERROR\)/);
  assert.equal((await agent.runQuery(STUCK, READ_STUCK)).body.result.isError, false);
});

test('a write after the incident is resolved is refused with SESSION_REVOKED and changes nothing', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);
  await agent.runQuery(STUCK, READ_STUCK);
  await ctx.post(`/itsm/incidents/${STUCK}/state`, { state: 'Resolved' });
  const res = await agent.runQuery(STUCK, FIX);
  assert.equal(struct(res).code, 'SESSION_REVOKED');
  assert.equal(countStatus(await ordersOf(ctx), 'stuck'), 3);
});

test('the kill switch stops writes too', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  const agent = await connect(ctx);
  await agent.runQuery(STUCK, READ_STUCK);
  await ctx.post(`/warden/agents/${encodeURIComponent(AGENT)}/suspend`);
  const res = await agent.runQuery(STUCK, FIX);
  assert.equal(struct(res).end_reason, 'kill_switch');
  assert.equal(countStatus(await ordersOf(ctx), 'stuck'), 3);
});

test('demo reset restores the mock data, and the inspector rejects unknown tables', async (t) => {
  const ctx = await setup();
  t.after(ctx.close);
  await (await connect(ctx)).runQuery(STUCK, FIX);
  assert.equal(countStatus(await ordersOf(ctx), 'stuck'), 0);
  await ctx.post('/demo/reset');
  assert.equal(countStatus(await ordersOf(ctx), 'stuck'), 3);
  assert.equal((await ctx.get('/demo/db/orders-prod/nope')).status, 404);
});

test('the write scope is mock data in the policy: it is validated when loaded', () => {
  const bad = (scope) => () => loadPolicy({ agents: [policyFor(AGENT, 'it-ops-agent', { write_scopes: { INC0012349: scope } })] });
  assert.throws(bad({ database: 'other-db', tables: ['orders'], statements: ['UPDATE'] }), /may not use/);
  assert.throws(bad({ database: 'orders-prod', tables: [], statements: ['UPDATE'] }), /tables/);
  assert.throws(bad({ database: 'orders-prod', tables: ['orders'], statements: ['DROP'] }), /statements/);
  assert.doesNotThrow(bad({ database: 'orders-prod', tables: ['orders'], statements: ['UPDATE'] }));
});
