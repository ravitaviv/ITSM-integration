'use strict';

// Deliberately simple SQL handling for the mock: keyword plus target table. This is not a SQL parser. It is enough
// to decide read or write, find the table a write targets, and see whether an UPDATE or DELETE has a WHERE clause.
// It does not look inside subqueries, so only the table a write names is checked.
const READ_VERBS = new Set(['select', 'with', 'explain', 'show', 'values', 'table']);
const WRITE_VERBS = new Set(['insert', 'update', 'delete']);
const FORBIDDEN_VERBS = new Set(['drop', 'alter', 'truncate', 'grant', 'revoke', 'create']);

// Splits a script into statements and masks 'string literals' as \x01N\x01 (their values are kept), so keywords
// and names inside strings cannot fool the checks. Comments are dropped. "Quoted identifiers" are left as they are.
function scan(sql) {
  const statements = [];
  let text = '';
  let masked = '';
  let values = [];
  const push = () => {
    if (masked.trim()) statements.push({ text: text.trim(), masked: masked.trim().replace(/\s+/g, ' '), values });
    text = '';
    masked = '';
    values = [];
  };
  let i = 0;
  while (i < sql.length) {
    const c = sql[i];
    if (c === '-' && sql[i + 1] === '-') {
      while (i < sql.length && sql[i] !== '\n') i++;
    } else if (c === '/' && sql[i + 1] === '*') {
      const end = sql.indexOf('*/', i + 2);
      i = end < 0 ? sql.length : end + 2;
      text += ' ';
      masked += ' ';
    } else if (c === "'") {
      let j = i + 1;
      while (j < sql.length && !(sql[j] === "'" && sql[j + 1] !== "'")) j += sql[j] === "'" ? 2 : 1;
      const literal = sql.slice(i, j + 1);
      values.push(literal.slice(1, -1).replace(/''/g, "'"));
      text += literal;
      masked += `\x01${values.length - 1}\x01`;
      i = j + 1;
    } else if (c === '"') {
      const end = sql.indexOf('"', i + 1);
      const quoted = sql.slice(i, end < 0 ? sql.length : end + 1);
      text += quoted;
      masked += quoted;
      i += quoted.length;
    } else if (c === ';') {
      push();
      i++;
    } else {
      text += c;
      masked += c;
      i++;
    }
  }
  push();
  return statements;
}

const NAME = '((?:"[^"]+"|[A-Za-z_]\\w*)(?:\\.(?:"[^"]+"|[A-Za-z_]\\w*)){0,2})';
const FORMS = {
  update: new RegExp(`^update\\s+(?:only\\s+)?${NAME}\\s+set\\s+([\\s\\S]+?)(?:\\s+where\\s+([\\s\\S]+))?$`, 'i'),
  delete: new RegExp(`^delete\\s+from\\s+(?:only\\s+)?${NAME}(?:\\s+where\\s+([\\s\\S]+))?$`, 'i'),
  insert: new RegExp(`^insert\\s+into\\s+${NAME}`, 'i'),
};

// "public"."Orders" -> orders
const lastName = (name) => name.split('.').pop().replace(/"/g, '').toLowerCase();

// A WHERE that matches everything (1=1, true) is no better than none.
const realCondition = (cond) => cond.trim() !== '' && !/^\(?\s*(1\s*=\s*1|true)\s*\)?$/i.test(cond.trim());

function parseWrite(verb, masked) {
  const m = FORMS[verb].exec(masked);
  if (!m) return null;
  const table = lastName(m[1]);
  if (verb === 'insert') return { table };
  const set = verb === 'update' ? m[2] : undefined;
  const where = ((verb === 'update' ? m[3] : m[2]) || '').trim();
  return { table, set, where, hasWhere: realCondition(where) };
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Names another database: one of the known database names, dblink, or a database.schema.table name.
function otherDatabase(masked, database, databases) {
  for (const name of databases) {
    if (name !== database && new RegExp(`(?<![\\w-])"?${escapeRe(name)}"?(?![\\w-])`, 'i').test(masked)) return name;
  }
  if (/\b(dblink\w*|postgres_fdw)\b/i.test(masked)) return 'dblink';
  const qualified = /(?:"([^"]+)"|\b([A-Za-z_]\w*))\s*\.\s*(?:"[^"]+"|[A-Za-z_]\w*)\s*\.\s*(?:"[^"]+"|[A-Za-z_]\w*)/g;
  for (let m = qualified.exec(masked); m; m = qualified.exec(masked)) {
    const first = m[1] || m[2];
    if (first.toLowerCase() !== database.toLowerCase()) return first;
  }
  return null;
}

function classify(st, database, databases) {
  const verb = ((/^([a-z]+)/i.exec(st.masked) || [])[1] || '').toLowerCase();
  const base = { ...st, verb: verb.toUpperCase(), intent: READ_VERBS.has(verb) ? 'read' : 'write' };
  const forbidden = (reason) => ({ ...base, kind: 'forbidden', reason });

  if (FORBIDDEN_VERBS.has(verb)) return forbidden(`${base.verb} statements are never allowed`);
  const other = otherDatabase(st.masked, database, databases);
  if (other) return forbidden(`The statement touches another database (${other})`);

  if (READ_VERBS.has(verb)) {
    if ((verb === 'with' || verb === 'explain') && /\b(insert|update|delete)\b/i.test(st.masked)) {
      return forbidden(`${base.verb} with a data change inside is not supported`);
    }
    const from = new RegExp(`\\bfrom\\s+${NAME}`, 'i').exec(st.masked);
    return { ...base, kind: 'read', table: from ? lastName(from[1]) : null };
  }
  if (!WRITE_VERBS.has(verb)) return forbidden(verb ? `${base.verb} statements are not supported` : 'Unrecognized statement');

  const target = parseWrite(verb, st.masked);
  if (!target) return forbidden(`Could not find the target table of this ${base.verb}`);
  return { ...base, kind: 'write', ...target };
}

// What a script is made of. `intent` is READ unless some statement is not a read (a refused DROP is still a write attempt).
function analyze(sql, { database, databases = [] }) {
  const statements = scan(sql).map((st) => classify(st, database, databases));
  if (statements.length === 0) {
    statements.push({ text: '', masked: '', values: [], verb: '', intent: 'write', kind: 'forbidden', reason: 'Empty statement' });
  }
  return { statements, intent: statements.some((st) => st.intent === 'write') ? 'WRITE' : 'READ' };
}

module.exports = { analyze, scan };
