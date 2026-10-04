'use strict';

// The mock database behind the gateway. It holds a few rows per table so a write visibly changes something.
// It understands only what the demo needs: UPDATE and DELETE with `col = value` conditions joined by AND,
// single-row INSERT, and SELECT * with the same conditions. Anything else is a "database error".
class MockDbError extends Error {}

const SEED = {
  'orders-prod': {
    orders: [
      { id: 1001, customer: 'Acme Corp', status: 'shipped' },
      { id: 1002, customer: 'Globex', status: 'stuck' },
      { id: 1003, customer: 'Initech', status: 'stuck' },
      { id: 1004, customer: 'Umbrella', status: 'pending' },
      { id: 1005, customer: 'Hooli', status: 'stuck' },
      { id: 1006, customer: 'Stark Industries', status: 'delivered' },
    ],
    payments: [
      { id: 1, order_id: 1001, status: 'captured' },
      { id: 2, order_id: 1002, status: 'pending' },
      { id: 3, order_id: 1003, status: 'pending' },
      { id: 4, order_id: 1006, status: 'captured' },
    ],
  },
  // Exists so a statement that names it is recognized as touching another database.
  'payments-prod': { ledger: [{ id: 1, amount: 100 }] },
};

const OPS = {
  '=': (a, b) => a === b,
  '<>': (a, b) => a !== b,
  '!=': (a, b) => a !== b,
  '<': (a, b) => a < b,
  '>': (a, b) => a > b,
  '<=': (a, b) => a <= b,
  '>=': (a, b) => a >= b,
};

const unquote = (id) => id.trim().replace(/"/g, '').toLowerCase();

function createMockDb({ seed = SEED } = {}) {
  const columns = {};
  for (const [database, tables] of Object.entries(seed)) {
    columns[database] = Object.fromEntries(Object.entries(tables).map(([name, rows]) => [name, Object.keys(rows[0])]));
  }
  let data;
  const reset = () => { data = structuredClone(seed); };
  reset();

  function table(database, name) {
    const rows = data[database] && data[database][name];
    if (!rows) throw new MockDbError(`relation "${name}" does not exist`);
    return rows;
  }

  function column(database, tableName, id) {
    const name = unquote(id);
    if (!columns[database][tableName].includes(name)) throw new MockDbError(`column "${name}" of relation "${tableName}" does not exist`);
    return name;
  }

  // A literal: a masked 'string' (see sql.js), a number or NULL.
  function value(token, values) {
    const t = token.trim();
    const masked = /^\x01(\d+)\x01$/.exec(t);
    if (masked) return values[Number(masked[1])];
    if (/^null$/i.test(t)) return null;
    if (/^-?\d+(\.\d+)?$/.test(t)) return Number(t);
    throw new MockDbError(`unsupported value: ${t}`);
  }

  function condition(where, values, database, tableName) {
    if (!where) return () => true;
    const parts = where.split(/\s+and\s+/i).map((part) => {
      const m = /^\(?\s*("[^"]+"|\w+)\s*(<=|>=|<>|!=|=|<|>)\s*(.+?)\s*\)?$/.exec(part.trim());
      if (!m) throw new MockDbError(`unsupported condition: ${part.trim()}`);
      return { col: column(database, tableName, m[1]), test: OPS[m[2]], val: value(m[3], values) };
    });
    return (row) => parts.every(({ col, test, val }) => test(row[col], val));
  }

  // Checks a write statement and returns something that can apply it. Nothing changes until run() is called, so a
  // caller can prepare every statement of a script first and apply none if one of them is rejected.
  function prepare(database, st) {
    const rows = table(database, st.table);
    if (st.verb === 'UPDATE') {
      const sets = st.set.split(',').map((part) => {
        const m = /^\s*("[^"]+"|\w+)\s*=\s*(.+?)\s*$/.exec(part);
        if (!m) throw new MockDbError(`unsupported SET clause: ${part.trim()}`);
        return [column(database, st.table, m[1]), value(m[2], st.values)];
      });
      const matches = condition(st.where, st.values, database, st.table);
      return { run: () => { const hit = rows.filter(matches); hit.forEach((row) => sets.forEach(([col, val]) => { row[col] = val; })); return hit.length; } };
    }
    if (st.verb === 'DELETE') {
      const matches = condition(st.where, st.values, database, st.table);
      return { run: () => { let n = 0; for (let i = rows.length - 1; i >= 0; i--) if (matches(rows[i])) { rows.splice(i, 1); n++; } return n; } };
    }
    const m = /^insert\s+into\s+[^(]+\(([^)]*)\)\s*values\s*\(([^)]*)\)\s*$/i.exec(st.masked);
    if (!m) throw new MockDbError('only INSERT INTO t (columns) VALUES (values) is supported');
    const names = m[1].split(',').map((c) => column(database, st.table, c));
    const vals = m[2].split(',').map((v) => value(v, st.values));
    if (names.length !== vals.length) throw new MockDbError('INSERT has a different number of columns and values');
    return {
      run: () => {
        const row = Object.fromEntries(columns[database][st.table].map((c) => [c, null]));
        names.forEach((c, i) => { row[c] = vals[i]; });
        if (row.id === null && 'id' in row) row.id = rows.reduce((max, r) => Math.max(max, r.id), 0) + 1;
        rows.push(row);
        return 1;
      },
    };
  }

  // SELECT * FROM t [WHERE ...] [LIMIT n]. Returns null for anything else so the caller can fall back.
  function select(database, st) {
    const m = /^select\s+\*\s+from\s+(?:"?public"?\.)?("[^"]+"|\w+)(?:\s+where\s+([\s\S]+?))?(?:\s+limit\s+(\d+))?$/i.exec(st.masked);
    if (!m) return null;
    try {
      const name = unquote(m[1]);
      const matches = condition(m[2], st.values, database, name);
      const out = table(database, name).filter(matches).map((row) => ({ ...row }));
      return m[3] ? out.slice(0, Number(m[3])) : out;
    } catch (err) {
      if (err instanceof MockDbError) return null;
      throw err;
    }
  }

  // A copy of a table's rows, for the demo page's before/after view. Not part of the agent's path.
  function snapshot(database, name) {
    const rows = data[database] && data[database][name];
    return rows ? structuredClone(rows) : null;
  }

  return { reset, prepare, select, snapshot, names: () => Object.keys(seed) };
}

module.exports = { createMockDb, MockDbError, SEED };
