"use strict";
(() => {
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __commonJS = (cb, mod) => function __require() {
    try {
      return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
    } catch (e) {
      throw mod = 0, e;
    }
  };

  // web/shims/stub.js
  var require_stub = __commonJS({
    "web/shims/stub.js"(exports, module) {
      "use strict";
      module.exports = {
        readFileSync() {
          throw new Error("Reading files is not available in the browser build");
        },
        join: (...parts) => parts.filter(Boolean).join("/")
      };
    }
  });

  // web/shims/express.js
  var require_express = __commonJS({
    "web/shims/express.js"(exports, module) {
      "use strict";
      var Req = class {
        constructor(method, url, headers, rawBody) {
          this.method = method.toUpperCase();
          this.url = url;
          this.originalUrl = url;
          this.baseUrl = "";
          this.headers = headers;
          this.rawBody = rawBody;
          this.params = {};
          this.body = void 0;
          this.route = void 0;
        }
        get path() {
          return this.url.split("?")[0];
        }
        get(name) {
          return this.headers[String(name).toLowerCase()];
        }
      };
      var Res = class {
        constructor() {
          this.statusCode = 200;
          this.headers = {};
          this.body = null;
          this.finished = false;
          this.finishListeners = [];
          this.done = new Promise((resolve) => {
            this.resolve = resolve;
          });
        }
        status(code) {
          this.statusCode = code;
          return this;
        }
        set(name, value) {
          this.headers[String(name).toLowerCase()] = String(value);
          return this;
        }
        get(name) {
          return this.headers[String(name).toLowerCase()];
        }
        json(body) {
          this.set("content-type", "application/json; charset=utf-8");
          return this.end(JSON.stringify(body));
        }
        end(body) {
          if (this.finished) return this;
          this.finished = true;
          this.body = body === void 0 ? null : body;
          for (const fn of this.finishListeners) fn();
          this.resolve({ status: this.statusCode, headers: this.headers, body: this.body });
          return this;
        }
        on(event, fn) {
          if (event === "finish") this.finishListeners.push(fn);
          return this;
        }
      };
      function compile(pattern) {
        const names = [];
        const source = pattern.replace(/\/+$/, "").split("/").map((segment) => {
          if (segment.startsWith(":")) {
            names.push(segment.slice(1));
            return "([^/]+)";
          }
          return segment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        }).join("/");
        return { names, regex: new RegExp(`^${source}/?$`, "i") };
      }
      function Router() {
        const stack = [];
        function handle(req, res, done) {
          const baseUrl = req.baseUrl;
          const url = req.url;
          const query = url.includes("?") ? url.slice(url.indexOf("?")) : "";
          const pathname = url.split("?")[0];
          let index = 0;
          function runChain(handlers, i, err) {
            if (i >= handlers.length) return next(err);
            const fn = handlers[i];
            if (err ? fn.length !== 4 : fn.length === 4) return runChain(handlers, i + 1, err);
            const after = (nextErr) => runChain(handlers, i + 1, nextErr);
            try {
              const out = err ? fn(err, req, res, after) : fn(req, res, after);
              if (out && typeof out.then === "function") out.catch(after);
            } catch (thrown) {
              after(thrown);
            }
          }
          function next(err) {
            req.baseUrl = baseUrl;
            req.url = url;
            while (index < stack.length) {
              const layer = stack[index++];
              if (layer.type === "use") {
                const prefix = layer.prefix === "/" ? "" : layer.prefix.replace(/\/$/, "");
                if (prefix && pathname !== prefix && !pathname.startsWith(`${prefix}/`)) continue;
                req.baseUrl = baseUrl + prefix;
                req.url = (pathname.slice(prefix.length) || "/") + query;
                return runChain(layer.handlers, 0, err);
              }
              const match = layer.regex.exec(pathname);
              if (layer.method !== req.method || !match) continue;
              req.params = {};
              layer.names.forEach((name, i) => {
                req.params[name] = decodeURIComponent(match[i + 1]);
              });
              req.route = { path: layer.pattern };
              return runChain(layer.handlers, 0, err);
            }
            return done(err);
          }
          next();
        }
        const router = (req, res, done) => handle(req, res, done);
        router.use = (...args) => {
          const prefix = typeof args[0] === "string" ? args.shift() : "/";
          stack.push({ type: "use", prefix, handlers: args });
          return router;
        };
        for (const method of ["get", "post", "delete"]) {
          router[method] = (pattern, ...handlers) => {
            stack.push({ type: "route", method: method.toUpperCase(), pattern, ...compile(pattern), handlers });
            return router;
          };
        }
        return router;
      }
      function express() {
        const app2 = Router();
        app2.locals = {};
        app2.dispatch = ({ method, url, headers, body }) => {
          const req = new Req(method, url, headers, body);
          const res = new Res();
          app2(req, res, (err) => {
            if (err) {
              console.error(err);
              res.status(err.status || 500).end("Internal Server Error");
            } else {
              res.status(404).end(`Cannot ${req.method} ${req.originalUrl}`);
            }
          });
          return res.done;
        };
        return app2;
      }
      express.Router = Router;
      express.json = () => (req, res, next) => {
        if (!req.rawBody) return next();
        try {
          const parsed = JSON.parse(req.rawBody);
          if (parsed === null || typeof parsed !== "object") throw new Error("not an object or array");
          req.body = parsed;
          return next();
        } catch {
          const err = new Error("Invalid JSON");
          err.type = "entity.parse.failed";
          err.status = 400;
          return next(err);
        }
      };
      express.static = () => (req, res, next) => next();
      module.exports = express;
    }
  });

  // src/policy.js
  var require_policy = __commonJS({
    "src/policy.js"(exports, module) {
      "use strict";
      var fs = require_stub();
      var REQUIRED = ["agent", "client_id", "owner", "assignment_group", "allowed_databases", "access", "max_duration_minutes", "allowed_priorities", "required_ticket_type"];
      var WRITABLE = ["INSERT", "UPDATE", "DELETE"];
      function loadPolicy(source) {
        const raw = typeof source === "string" ? JSON.parse(fs.readFileSync(source, "utf8")) : source;
        if (!raw || !Array.isArray(raw.agents) || raw.agents.length === 0) throw new Error('policy: "agents" must be a non-empty array');
        const policies = /* @__PURE__ */ new Map();
        for (const entry of raw.agents) {
          for (const key of REQUIRED) {
            if (entry[key] === void 0 || entry[key] === "") throw new Error(`policy: agent "${entry.agent}" is missing "${key}"`);
          }
          if (!/^[A-Z]{2,5}$/.test(entry.required_ticket_type)) throw new Error(`policy: bad required_ticket_type "${entry.required_ticket_type}"`);
          const writeScopes = entry.write_scopes || {};
          for (const [incident, scope] of Object.entries(writeScopes)) {
            const where = `policy: write scope for ${incident}`;
            if (!entry.allowed_databases.includes(scope.database)) throw new Error(`${where} names a database the agent may not use`);
            if (!Array.isArray(scope.tables) || scope.tables.length === 0) throw new Error(`${where} needs a non-empty "tables" list`);
            if (!Array.isArray(scope.statements) || scope.statements.length === 0 || !scope.statements.every((s) => WRITABLE.includes(s))) {
              throw new Error(`${where} "statements" must be a non-empty list of ${WRITABLE.join(", ")}`);
            }
          }
          policies.set(entry.agent, { ...entry, write_scopes: writeScopes, ticket_pattern: new RegExp(`^${entry.required_ticket_type}[0-9]{7}$`) });
        }
        return policies;
      }
      module.exports = { loadPolicy };
    }
  });

  // src/itsm.js
  var require_itsm = __commonJS({
    "src/itsm.js"(exports, module) {
      "use strict";
      var express = require_express();
      var STATES = ["New", "In progress", "On hold", "Resolved", "Closed", "Canceled"];
      var SEED = [
        // Open P1, assigned to the agent's group.
        { number: "INC0012345", short_description: "Orders API timing out", state: "In progress", priority: "P1", assignment_group: "DB Ops", assigned_to: "", cmdb_ci: "orders-prod" },
        // Open P1, but owned by a human in another group.
        { number: "INC0012346", short_description: "Orders connection pool exhausted", state: "In progress", priority: "P1", assignment_group: "Network Ops", assigned_to: "M. Cohen", cmdb_ci: "orders-prod" },
        // Open P1 in the right group, but about a different database.
        { number: "INC0012347", short_description: "Payments settlement delayed", state: "In progress", priority: "P1", assignment_group: "DB Ops", assigned_to: "", cmdb_ci: "payments-prod" },
        // Already resolved.
        { number: "INC0012348", short_description: "Orders replica lag", state: "Resolved", priority: "P1", assignment_group: "DB Ops", assigned_to: "", cmdb_ci: "orders-prod" },
        // Open P1 in the agent's group about orders stuck in the database: the one incident with a narrow write scope (see policy.json).
        { number: "INC0012349", short_description: "Orders stuck after payment callback", state: "In progress", priority: "P1", assignment_group: "DB Ops", assigned_to: "", cmdb_ci: "orders-prod" }
      ];
      function createItsm({ seed = SEED, now = () => /* @__PURE__ */ new Date() } = {}) {
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
        router.use((req, res, next) => {
          let response;
          const send = res.json.bind(res);
          res.json = (body) => {
            response = structuredClone(body);
            return send(body);
          };
          res.on("finish", () => {
            const route = req.route ? req.route.path : req.path.replace(/^\/incidents\/[^/]+/, "/incidents/:number");
            calls.push({
              method: req.method,
              route: req.baseUrl + route,
              path: req.originalUrl.split("?")[0],
              caller: req.get("x-caller") || "client",
              status: res.statusCode,
              request: Object.keys(req.body).length ? structuredClone(req.body) : void 0,
              response
            });
          });
          next();
        });
        router.use((req, res, next) => {
          if (down) return res.status(503).json({ error: { message: "ITSM unavailable (simulated outage)" } });
          next();
        });
        function find(req, res) {
          const inc = incidents.get(req.params.number);
          if (!inc) res.status(404).json({ error: { message: "No Record found", detail: `Record doesn't exist: ${req.params.number}` } });
          return inc;
        }
        const view = (inc) => ({ result: { ...inc, work_notes: inc.work_notes.map((n) => ({ ...n })) } });
        router.get("/incidents/:number", (req, res) => {
          const inc = find(req, res);
          if (inc) res.json(view(inc));
        });
        router.post("/incidents/:number/state", (req, res) => {
          const inc = find(req, res);
          if (!inc) return;
          const { state } = req.body;
          if (!STATES.includes(state)) return res.status(400).json({ error: { message: `state must be one of: ${STATES.join(", ")}` } });
          inc.state = state;
          res.json(view(inc));
        });
        router.post("/incidents/:number/work_notes", (req, res) => {
          const inc = find(req, res);
          if (!inc) return;
          const { work_notes: text, author = "system" } = req.body;
          if (typeof text !== "string" || !text.trim()) return res.status(400).json({ error: { message: "work_notes must be a non-empty string" } });
          inc.work_notes.push({ created_on: now().toISOString(), author, text });
          res.json(view(inc));
        });
        return {
          router,
          reset,
          setDown: (value) => {
            down = Boolean(value);
          },
          getCalls: () => structuredClone(calls)
        };
      }
      module.exports = { createItsm, SEED, STATES };
    }
  });

  // src/itsm-client.js
  var require_itsm_client = __commonJS({
    "src/itsm-client.js"(exports, module) {
      "use strict";
      var ItsmUnavailableError = class extends Error {
      };
      function createItsmClient(baseUrl, { timeoutMs = 2e3 } = {}) {
        const base = () => typeof baseUrl === "function" ? baseUrl() : baseUrl;
        async function call(path, init = {}) {
          try {
            return await fetch(`${base()}/itsm${path}`, {
              ...init,
              headers: { "content-type": "application/json", "x-caller": "warden-broker" },
              signal: AbortSignal.timeout(timeoutMs)
            });
          } catch (err) {
            throw new ItsmUnavailableError(`ITSM unreachable (${err.cause?.code || err.name})`);
          }
        }
        return {
          // Returns the incident, or null when ITSM says it does not exist.
          async getIncident(number) {
            const res = await call(`/incidents/${encodeURIComponent(number)}`);
            if (res.status === 404) return null;
            if (!res.ok) throw new ItsmUnavailableError(`ITSM returned ${res.status}`);
            try {
              return (await res.json()).result;
            } catch {
              throw new ItsmUnavailableError("ITSM returned an unreadable response");
            }
          },
          async addWorkNote(number, text, author) {
            const res = await call(`/incidents/${encodeURIComponent(number)}/work_notes`, {
              method: "POST",
              body: JSON.stringify({ work_notes: text, author })
            });
            if (!res.ok) throw new ItsmUnavailableError(`ITSM returned ${res.status}`);
          }
        };
      }
      module.exports = { createItsmClient, ItsmUnavailableError };
    }
  });

  // web/shims/crypto.js
  var require_crypto = __commonJS({
    "web/shims/crypto.js"(exports, module) {
      "use strict";
      var webCrypto = globalThis.crypto;
      var toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
      function randomBytes(n) {
        const bytes = webCrypto.getRandomValues(new Uint8Array(n));
        Object.defineProperty(bytes, "toString", {
          value: (encoding) => encoding === "hex" ? toHex(bytes) : Uint8Array.prototype.toString.call(bytes)
        });
        return bytes;
      }
      var randomUUID = () => webCrypto.randomUUID();
      function timingSafeEqual(a, b) {
        if (a.length !== b.length) throw new RangeError("Input buffers must have the same byte length");
        let diff = 0;
        for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff === 0;
      }
      var K = new Uint32Array([
        1116352408,
        1899447441,
        3049323471,
        3921009573,
        961987163,
        1508970993,
        2453635748,
        2870763221,
        3624381080,
        310598401,
        607225278,
        1426881987,
        1925078388,
        2162078206,
        2614888103,
        3248222580,
        3835390401,
        4022224774,
        264347078,
        604807628,
        770255983,
        1249150122,
        1555081692,
        1996064986,
        2554220882,
        2821834349,
        2952996808,
        3210313671,
        3336571891,
        3584528711,
        113926993,
        338241895,
        666307205,
        773529912,
        1294757372,
        1396182291,
        1695183700,
        1986661051,
        2177026350,
        2456956037,
        2730485921,
        2820302411,
        3259730800,
        3345764771,
        3516065817,
        3600352804,
        4094571909,
        275423344,
        430227734,
        506948616,
        659060556,
        883997877,
        958139571,
        1322822218,
        1537002063,
        1747873779,
        1955562222,
        2024104815,
        2227730452,
        2361852424,
        2428436474,
        2756734187,
        3204031479,
        3329325298
      ]);
      function sha256(bytes) {
        const h = new Uint32Array([1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225]);
        const bits = bytes.length * 8;
        const padded = new Uint8Array(bytes.length + 9 + 63 >> 6 << 6);
        padded.set(bytes);
        padded[bytes.length] = 128;
        const view = new DataView(padded.buffer);
        view.setUint32(padded.length - 8, Math.floor(bits / 4294967296));
        view.setUint32(padded.length - 4, bits >>> 0);
        const w = new Uint32Array(64);
        for (let offset = 0; offset < padded.length; offset += 64) {
          for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4);
          for (let i = 16; i < 64; i++) {
            const x = w[i - 15];
            const y = w[i - 2];
            const s0 = (x >>> 7 | x << 25) ^ (x >>> 18 | x << 14) ^ x >>> 3;
            const s1 = (y >>> 17 | y << 15) ^ (y >>> 19 | y << 13) ^ y >>> 10;
            w[i] = w[i - 16] + s0 + w[i - 7] + s1 >>> 0;
          }
          let [a, b, c, d, e, f, g, hh] = h;
          for (let i = 0; i < 64; i++) {
            const big1 = (e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7);
            const choose = e & f ^ ~e & g;
            const t1 = hh + big1 + choose + K[i] + w[i] >>> 0;
            const big0 = (a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10);
            const majority = a & b ^ a & c ^ b & c;
            const t2 = big0 + majority >>> 0;
            hh = g;
            g = f;
            f = e;
            e = d + t1 >>> 0;
            d = c;
            c = b;
            b = a;
            a = t1 + t2 >>> 0;
          }
          h[0] += a;
          h[1] += b;
          h[2] += c;
          h[3] += d;
          h[4] += e;
          h[5] += f;
          h[6] += g;
          h[7] += hh;
        }
        const out = new Uint8Array(32);
        const outView = new DataView(out.buffer);
        h.forEach((word, i) => outView.setUint32(i * 4, word));
        return out;
      }
      function createHash(algorithm) {
        if (algorithm !== "sha256") throw new Error(`Only sha256 is available in the browser build, not ${algorithm}`);
        const parts = [];
        return {
          update(data) {
            parts.push(String(data));
            return this;
          },
          digest() {
            return sha256(new TextEncoder().encode(parts.join("")));
          }
        };
      }
      module.exports = { randomBytes, randomUUID, timingSafeEqual, createHash, sha256 };
    }
  });

  // src/sql.js
  var require_sql = __commonJS({
    "src/sql.js"(exports, module) {
      "use strict";
      var READ_VERBS = /* @__PURE__ */ new Set(["select", "with", "explain", "show", "values", "table"]);
      var WRITE_VERBS = /* @__PURE__ */ new Set(["insert", "update", "delete"]);
      var FORBIDDEN_VERBS = /* @__PURE__ */ new Set(["drop", "alter", "truncate", "grant", "revoke", "create"]);
      function scan(sql) {
        const statements = [];
        let text = "";
        let masked = "";
        let values = [];
        const push = () => {
          if (masked.trim()) statements.push({ text: text.trim(), masked: masked.trim().replace(/\s+/g, " "), values });
          text = "";
          masked = "";
          values = [];
        };
        let i = 0;
        while (i < sql.length) {
          const c = sql[i];
          if (c === "-" && sql[i + 1] === "-") {
            while (i < sql.length && sql[i] !== "\n") i++;
          } else if (c === "/" && sql[i + 1] === "*") {
            const end = sql.indexOf("*/", i + 2);
            i = end < 0 ? sql.length : end + 2;
            text += " ";
            masked += " ";
          } else if (c === "'") {
            let j = i + 1;
            while (j < sql.length && !(sql[j] === "'" && sql[j + 1] !== "'")) j += sql[j] === "'" ? 2 : 1;
            const literal = sql.slice(i, j + 1);
            values.push(literal.slice(1, -1).replace(/''/g, "'"));
            text += literal;
            masked += `${values.length - 1}`;
            i = j + 1;
          } else if (c === '"') {
            const end = sql.indexOf('"', i + 1);
            const quoted = sql.slice(i, end < 0 ? sql.length : end + 1);
            text += quoted;
            masked += quoted;
            i += quoted.length;
          } else if (c === ";") {
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
      var NAME = '((?:"[^"]+"|[A-Za-z_]\\w*)(?:\\.(?:"[^"]+"|[A-Za-z_]\\w*)){0,2})';
      var FORMS = {
        update: new RegExp(`^update\\s+(?:only\\s+)?${NAME}\\s+set\\s+([\\s\\S]+?)(?:\\s+where\\s+([\\s\\S]+))?$`, "i"),
        delete: new RegExp(`^delete\\s+from\\s+(?:only\\s+)?${NAME}(?:\\s+where\\s+([\\s\\S]+))?$`, "i"),
        insert: new RegExp(`^insert\\s+into\\s+${NAME}`, "i")
      };
      var lastName = (name) => name.split(".").pop().replace(/"/g, "").toLowerCase();
      var realCondition = (cond) => cond.trim() !== "" && !/^\(?\s*(1\s*=\s*1|true)\s*\)?$/i.test(cond.trim());
      function parseWrite(verb, masked) {
        const m = FORMS[verb].exec(masked);
        if (!m) return null;
        const table = lastName(m[1]);
        if (verb === "insert") return { table };
        const set = verb === "update" ? m[2] : void 0;
        const where = ((verb === "update" ? m[3] : m[2]) || "").trim();
        return { table, set, where, hasWhere: realCondition(where) };
      }
      var escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      function otherDatabase(masked, database, databases) {
        for (const name of databases) {
          if (name !== database && new RegExp(`(?<![\\w-])"?${escapeRe(name)}"?(?![\\w-])`, "i").test(masked)) return name;
        }
        if (/\b(dblink\w*|postgres_fdw)\b/i.test(masked)) return "dblink";
        const qualified = /(?:"([^"]+)"|\b([A-Za-z_]\w*))\s*\.\s*(?:"[^"]+"|[A-Za-z_]\w*)\s*\.\s*(?:"[^"]+"|[A-Za-z_]\w*)/g;
        for (let m = qualified.exec(masked); m; m = qualified.exec(masked)) {
          const first = m[1] || m[2];
          if (first.toLowerCase() !== database.toLowerCase()) return first;
        }
        return null;
      }
      function classify(st, database, databases) {
        const verb = ((/^([a-z]+)/i.exec(st.masked) || [])[1] || "").toLowerCase();
        const base = { ...st, verb: verb.toUpperCase(), intent: READ_VERBS.has(verb) ? "read" : "write" };
        const forbidden = (reason) => ({ ...base, kind: "forbidden", reason });
        if (FORBIDDEN_VERBS.has(verb)) return forbidden(`${base.verb} statements are never allowed`);
        const other = otherDatabase(st.masked, database, databases);
        if (other) return forbidden(`The statement touches another database (${other})`);
        if (READ_VERBS.has(verb)) {
          if ((verb === "with" || verb === "explain") && /\b(insert|update|delete)\b/i.test(st.masked)) {
            return forbidden(`${base.verb} with a data change inside is not supported`);
          }
          const from = new RegExp(`\\bfrom\\s+${NAME}`, "i").exec(st.masked);
          return { ...base, kind: "read", table: from ? lastName(from[1]) : null };
        }
        if (!WRITE_VERBS.has(verb)) return forbidden(verb ? `${base.verb} statements are not supported` : "Unrecognized statement");
        const target = parseWrite(verb, st.masked);
        if (!target) return forbidden(`Could not find the target table of this ${base.verb}`);
        return { ...base, kind: "write", ...target };
      }
      function analyze(sql, { database, databases = [] }) {
        const statements = scan(sql).map((st) => classify(st, database, databases));
        if (statements.length === 0) {
          statements.push({ text: "", masked: "", values: [], verb: "", intent: "write", kind: "forbidden", reason: "Empty statement" });
        }
        return { statements, intent: statements.some((st) => st.intent === "write") ? "WRITE" : "READ" };
      }
      module.exports = { analyze, scan };
    }
  });

  // src/mockdb.js
  var require_mockdb = __commonJS({
    "src/mockdb.js"(exports, module) {
      "use strict";
      var MockDbError = class extends Error {
      };
      var SEED = {
        "orders-prod": {
          orders: [
            { id: 1001, customer: "Acme Corp", status: "shipped" },
            { id: 1002, customer: "Globex", status: "stuck" },
            { id: 1003, customer: "Initech", status: "stuck" },
            { id: 1004, customer: "Umbrella", status: "pending" },
            { id: 1005, customer: "Hooli", status: "stuck" },
            { id: 1006, customer: "Stark Industries", status: "delivered" }
          ],
          payments: [
            { id: 1, order_id: 1001, status: "captured" },
            { id: 2, order_id: 1002, status: "pending" },
            { id: 3, order_id: 1003, status: "pending" },
            { id: 4, order_id: 1006, status: "captured" }
          ]
        },
        // Exists so a statement that names it is recognized as touching another database.
        "payments-prod": { ledger: [{ id: 1, amount: 100 }] }
      };
      var OPS = {
        "=": (a, b) => a === b,
        "<>": (a, b) => a !== b,
        "!=": (a, b) => a !== b,
        "<": (a, b) => a < b,
        ">": (a, b) => a > b,
        "<=": (a, b) => a <= b,
        ">=": (a, b) => a >= b
      };
      var unquote = (id) => id.trim().replace(/"/g, "").toLowerCase();
      function createMockDb({ seed = SEED } = {}) {
        const columns = {};
        for (const [database, tables] of Object.entries(seed)) {
          columns[database] = Object.fromEntries(Object.entries(tables).map(([name, rows]) => [name, Object.keys(rows[0])]));
        }
        let data;
        const reset = () => {
          data = structuredClone(seed);
        };
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
        function prepare(database, st) {
          const rows = table(database, st.table);
          if (st.verb === "UPDATE") {
            const sets = st.set.split(",").map((part) => {
              const m2 = /^\s*("[^"]+"|\w+)\s*=\s*(.+?)\s*$/.exec(part);
              if (!m2) throw new MockDbError(`unsupported SET clause: ${part.trim()}`);
              return [column(database, st.table, m2[1]), value(m2[2], st.values)];
            });
            const matches = condition(st.where, st.values, database, st.table);
            return { run: () => {
              const hit = rows.filter(matches);
              hit.forEach((row) => sets.forEach(([col, val]) => {
                row[col] = val;
              }));
              return hit.length;
            } };
          }
          if (st.verb === "DELETE") {
            const matches = condition(st.where, st.values, database, st.table);
            return { run: () => {
              let n = 0;
              for (let i = rows.length - 1; i >= 0; i--) if (matches(rows[i])) {
                rows.splice(i, 1);
                n++;
              }
              return n;
            } };
          }
          const m = /^insert\s+into\s+[^(]+\(([^)]*)\)\s*values\s*\(([^)]*)\)\s*$/i.exec(st.masked);
          if (!m) throw new MockDbError("only INSERT INTO t (columns) VALUES (values) is supported");
          const names = m[1].split(",").map((c) => column(database, st.table, c));
          const vals = m[2].split(",").map((v) => value(v, st.values));
          if (names.length !== vals.length) throw new MockDbError("INSERT has a different number of columns and values");
          return {
            run: () => {
              const row = Object.fromEntries(columns[database][st.table].map((c) => [c, null]));
              names.forEach((c, i) => {
                row[c] = vals[i];
              });
              if (row.id === null && "id" in row) row.id = rows.reduce((max, r) => Math.max(max, r.id), 0) + 1;
              rows.push(row);
              return 1;
            }
          };
        }
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
        function snapshot(database, name) {
          const rows = data[database] && data[database][name];
          return rows ? structuredClone(rows) : null;
        }
        return { reset, prepare, select, snapshot, names: () => Object.keys(seed) };
      }
      module.exports = { createMockDb, MockDbError, SEED };
    }
  });

  // src/broker.js
  var require_broker = __commonJS({
    "src/broker.js"(exports, module) {
      "use strict";
      var crypto = require_crypto();
      var express = require_express();
      var { ItsmUnavailableError } = require_itsm_client();
      var { analyze } = require_sql();
      var { MockDbError } = require_mockdb();
      var OPEN_STATES = /* @__PURE__ */ new Set(["New", "In progress"]);
      var CANNED_ROWS = [
        [/count\s*\(\s*\*\s*\)/i, () => [{ count: 42 }]],
        [/pg_stat_activity/i, () => [
          { pid: 4121, state: "active", wait_event: "Lock" },
          { pid: 4130, state: "idle in transaction", wait_event: null }
        ]]
      ];
      var cannedRows = (sql) => {
        const hit = CANNED_ROWS.find(([re]) => re.test(sql));
        return hit ? hit[1]() : null;
      };
      function judge({ analysis, incident, database }, policy2) {
        const scope = policy2.write_scopes[incident];
        const scoped = scope && scope.database === database ? scope : null;
        const forbidden = analysis.statements.find((st) => st.kind === "forbidden");
        if (forbidden) return fail("FORBIDDEN_STATEMENT", forbidden.reason);
        const writes = analysis.statements.filter((st) => st.kind === "write");
        for (const st of writes) {
          if (!scoped) return fail("WRITE_NOT_ALLOWED", `${incident} has no write policy for ${database}; access is read only`);
          if (!scoped.tables.includes(st.table)) return fail("TABLE_NOT_IN_SCOPE", `Table "${st.table}" is not writable under ${incident} (writable: ${scoped.tables.join(", ")})`);
          if (st.verb !== "INSERT" && !st.hasWhere) return fail("MISSING_WHERE_CLAUSE", `${st.verb} on ${st.table} needs a WHERE clause`);
          if (!scoped.statements.includes(st.verb)) return fail("WRITE_NOT_ALLOWED", `${st.verb} is not allowed under ${incident} (allowed: ${scoped.statements.join(", ")})`);
        }
        const upTo = `up to ${policy2.max_duration_minutes} min`;
        if (writes.length > 0) return pass(`${database}, WRITE ${[...new Set(writes.map((st) => st.verb))].join("/")} on ${[...new Set(writes.map((st) => st.table))].join(", ")}, allowed by ${incident}, ${upTo}`);
        if (scoped) return pass(`${database}, read; writes limited to ${scoped.tables.join(", ")} (${scoped.statements.join("/")}), ${upTo}`);
        return pass(`${database}, read only, ${upTo}`);
      }
      var accessOf = (policy2, incident, database) => {
        const scope = policy2.write_scopes[incident];
        return scope && scope.database === database ? `read; writes: ${scope.statements.join("/")} on ${scope.tables.join(", ")}` : "read";
      };
      var CHECKS = [
        {
          id: "agent_recognized",
          label: () => "Agent is recognized",
          run: ({ req, policy: policy2, broker }) => {
            if (!policy2) return fail("AGENT_NOT_RECOGNIZED", `Agent "${req.agent}" is not registered in Warden`);
            if (broker.suspended.has(req.agent)) return fail("AGENT_SUSPENDED", `Agent "${req.agent}" is suspended by a security admin`);
            return pass(`${req.agent} is registered, owner ${policy2.owner}`);
          }
        },
        {
          id: "policy_allows",
          label: () => "Policy allows this database and mode",
          run: ({ req, policy: policy2 }) => {
            if (!policy2.allowed_databases.includes(req.database)) return fail("MODE_NOT_ALLOWED", `Policy does not allow ${req.agent} on database "${req.database}"`);
            return judge(req, policy2);
          }
        },
        {
          id: "incident_exists",
          label: (p) => `Incident exists, valid ${p ? p.required_ticket_type : "INC"} number`,
          run: async (ctx) => {
            const { req, policy: policy2, broker } = ctx;
            if (!policy2.ticket_pattern.test(req.incident)) return fail("INCIDENT_NOT_FOUND", `"${req.incident}" is not a valid ${policy2.required_ticket_type} ticket number`);
            ctx.incident = await broker.itsm.getIncident(req.incident);
            if (!ctx.incident) return fail("INCIDENT_NOT_FOUND", `${req.incident} does not exist in ITSM`);
            return pass(`${req.incident} found`);
          }
        },
        {
          id: "incident_open",
          label: () => "Incident is open",
          run: ({ incident }) => OPEN_STATES.has(incident.state) ? pass(`State: ${incident.state}`) : fail("INCIDENT_NOT_OPEN", `${incident.number} is ${incident.state}, not open`)
        },
        {
          id: "priority_allowed",
          label: (p) => `Priority is allowed${p ? ` (${p.allowed_priorities.join(" or ")})` : ""}`,
          run: ({ incident, policy: policy2 }) => policy2.allowed_priorities.includes(incident.priority) ? pass(`Priority: ${incident.priority}`) : fail("PRIORITY_NOT_ALLOWED", `Priority ${incident.priority} is not allowed (${policy2.allowed_priorities.join(" or ")})`)
        },
        {
          id: "assigned",
          label: () => "Assigned to the agent or its group",
          run: ({ req, incident, policy: policy2 }) => {
            if (incident.assigned_to === req.agent) return pass(`Assigned to ${req.agent}`);
            if (incident.assignment_group === policy2.assignment_group) return pass(`Assignment group: ${incident.assignment_group}`);
            const who = incident.assigned_to ? `${incident.assigned_to}, ${incident.assignment_group}` : incident.assignment_group;
            return fail("INCIDENT_NOT_ASSIGNED", `${incident.number} is assigned to ${who}, not to ${req.agent} or ${policy2.assignment_group}`, `Assigned to ${who}`);
          }
        },
        {
          id: "target_matches",
          label: () => "Incident CI matches the database",
          run: ({ req, incident }) => incident.cmdb_ci === req.database ? pass(incident.cmdb_ci) : fail("TARGET_MISMATCH", `Incident CI is ${incident.cmdb_ci}, request targets ${req.database}`)
        }
      ];
      var INCIDENT_CHECKS_START = 2;
      var pass = (detail) => ({ ok: true, detail });
      var fail = (code, reason, detail = reason) => ({ ok: false, code, reason, detail });
      async function runChecks(ctx, start = 0) {
        const checks = [];
        let failure = null;
        for (const check of CHECKS.slice(start)) {
          const label = check.label(ctx.policy);
          if (failure) {
            checks.push({ id: check.id, label, status: "skip", detail: "Not checked" });
            continue;
          }
          let result;
          try {
            result = await check.run(ctx);
          } catch (err) {
            if (!(err instanceof ItsmUnavailableError)) throw err;
            result = fail("CHECK_UNAVAILABLE", `${err.message}. Access is denied while the incident cannot be verified`);
          }
          checks.push({ id: check.id, label, status: result.ok ? "pass" : "fail", detail: result.detail });
          if (!result.ok) failure = { code: result.code, reason: result.reason };
        }
        return { checks, failure };
      }
      var humanize = (endReason) => endReason.replace(/_/g, " ");
      var plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
      var queries = (n) => plural(n, "query").replace("querys", "queries");
      function createBroker({ policies, itsmClient, db, now = () => /* @__PURE__ */ new Date() }) {
        const policyByClient = new Map([...policies.values()].map((p) => [p.client_id, p]));
        const sessions = /* @__PURE__ */ new Map();
        const mcpSessions = /* @__PURE__ */ new Map();
        const suspended = /* @__PURE__ */ new Set();
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
        async function endSession(s, endReason) {
          if (s.status !== "active") return;
          s.status = "ended";
          s.end_reason = endReason;
          s.ended_at = now().toISOString();
          s.credential = null;
          const writes = s.writes > 0 ? `, ${plural(s.writes, "write")}` : "";
          audit("session_ended", { agent: s.agent, session_id: s.id, incident: s.incident, database: s.database, end_reason: endReason, queries: s.queries, detail: `${humanize(endReason)}, ${queries(s.queries)}${writes}` });
          const note = [
            "Warden session summary",
            `Session: ${s.id}`,
            `Agent: ${s.agent}`,
            `Owner: ${s.owner}`,
            `Database: ${s.database} (${s.access})`,
            `Queries: ${s.queries}`,
            ...s.writes > 0 ? [`Writes: ${s.writes}`] : [],
            ...s.refused_writes > 0 ? [`Refused writes: ${s.refused_writes}`] : [],
            `Ended: ${humanize(endReason)}`
          ].join("\n");
          try {
            await itsmClient.addWorkNote(s.incident, note, "Warden");
            audit("work_note_written", { agent: s.agent, session_id: s.id, incident: s.incident, detail: "Summary added to the incident" });
          } catch (err) {
            audit("work_note_failed", { agent: s.agent, session_id: s.id, incident: s.incident, detail: err.message });
          }
        }
        async function writeNote(s, sql, result) {
          const note = ["Warden write attempt", `Time: ${now().toISOString()}`, `Agent: ${s.agent}`, `Session: ${s.id}`, `Statement: ${sql.trim()}`, `Result: ${result}`].join("\n");
          try {
            await itsmClient.addWorkNote(s.incident, note, "Warden");
            audit("work_note_written", { agent: s.agent, session_id: s.id, incident: s.incident, kind: "WRITE", detail: "Write attempt recorded on the incident" });
          } catch (err) {
            audit("work_note_failed", { agent: s.agent, session_id: s.id, incident: s.incident, kind: "WRITE", detail: err.message });
          }
        }
        function openMcpSession(clientId) {
          const policy2 = policyByClient.get(clientId);
          const session = { id: crypto.randomUUID(), clientId, agent: policy2 ? policy2.agent : clientId, grants: /* @__PURE__ */ new Map() };
          mcpSessions.set(session.id, session);
          return session;
        }
        const getMcpSession = (id, clientId) => {
          const session = mcpSessions.get(id);
          return session && session.clientId === clientId ? session : void 0;
        };
        async function closeMcpSession(session) {
          mcpSessions.delete(session.id);
          await Promise.all([...session.grants.values()].map((s) => endSession(s, "task_complete")));
        }
        function listDatabases(mcp) {
          const policy2 = policyByClient.get(mcp.clientId);
          const identity = CHECKS[0].run({ req: { agent: mcp.agent }, policy: policy2, broker });
          if (!identity.ok) return { ok: false, code: identity.code, reason: identity.reason };
          return { ok: true, databases: policy2.allowed_databases.map((database) => ({ database, access: policy2.access })) };
        }
        async function runQuery(mcp, { database, sql, incident }) {
          const policy2 = policyByClient.get(mcp.clientId);
          const grant = mcp.grants.get(`${database}|${incident}`);
          if (grant) return queryOnSession(grant, policy2, sql);
          const analysis = analyze(sql, { database, databases: db.names() });
          return openSession(mcp, policy2, { agent: mcp.agent, database, incident, analysis }, sql);
        }
        async function openSession(mcp, policy2, request, sql) {
          const { analysis } = request;
          const ctx = { req: request, policy: policy2, broker };
          const { checks, failure } = await runChecks(ctx);
          let denial = failure;
          if (!denial && suspended.has(request.agent)) denial = { code: "AGENT_SUSPENDED", reason: `Agent "${request.agent}" is suspended by a security admin` };
          if (!denial && !mcpSessions.has(mcp.id)) denial = { code: "SESSION_REVOKED", reason: "The MCP session was closed" };
          if (denial) {
            audit("access_denied", { agent: request.agent, incident: request.incident, database: request.database, kind: analysis.intent, code: denial.code, detail: denial.reason });
            return { ok: false, ...denial, kind: analysis.intent.toLowerCase(), checks };
          }
          const opened = now();
          const s = {
            id: `sess_${crypto.randomBytes(8).toString("hex")}`,
            agent: request.agent,
            owner: policy2.owner,
            database: request.database,
            access: accessOf(policy2, request.incident, request.database),
            incident: request.incident,
            status: "active",
            queries: 0,
            writes: 0,
            refused_writes: 0,
            end_reason: null,
            opened_at: opened.toISOString(),
            expires_at: new Date(opened.getTime() + policy2.max_duration_minutes * 6e4).toISOString(),
            credential: `sim-cred-${crypto.randomUUID()}`
            // simulated; the agent only ever gets query results
          };
          sessions.set(s.id, s);
          mcp.grants.set(`${s.database}|${s.incident}`, s);
          audit("session_opened", { agent: s.agent, session_id: s.id, incident: s.incident, database: s.database, detail: `${s.access} access until ${s.expires_at}` });
          return { ...await run(s, sql, analysis), checks };
        }
        const rowsFor = (database, st) => cannedRows(st.text) || db.select(database, st) || [];
        function execute(s, sql, analysis) {
          const plans = analysis.statements.map((st) => st.kind === "write" ? db.prepare(s.database, st) : null);
          let rows = [];
          let changed = 0;
          analysis.statements.forEach((st, i) => {
            if (plans[i]) changed += plans[i].run();
            else rows = rowsFor(s.database, st);
          });
          const write = analysis.intent === "WRITE";
          s.queries += 1;
          if (write) s.writes += 1;
          audit("query", {
            agent: s.agent,
            session_id: s.id,
            incident: s.incident,
            database: s.database,
            sql,
            kind: analysis.intent,
            ...write && { rows_affected: changed },
            detail: write ? `${sql.trim()} (${plural(changed, "row")} changed)` : sql
          });
          return { ok: true, session_id: s.id, expires_at: s.expires_at, kind: analysis.intent.toLowerCase(), rows, row_count: rows.length, ...write && { rows_affected: changed } };
        }
        async function run(s, sql, analysis) {
          let out;
          try {
            out = execute(s, sql, analysis);
          } catch (err) {
            if (!(err instanceof MockDbError)) throw err;
            audit("query_blocked", { agent: s.agent, session_id: s.id, incident: s.incident, database: s.database, sql, kind: analysis.intent, code: "STATEMENT_ERROR", detail: err.message });
            out = { ok: false, code: "STATEMENT_ERROR", reason: `The database rejected the statement: ${err.message}`, session_id: s.id, kind: analysis.intent.toLowerCase() };
          }
          if (analysis.intent === "WRITE") {
            await writeNote(s, sql, out.ok ? `ALLOWED, ${plural(out.rows_affected, "row")} changed` : `FAILED (${out.code}): ${out.reason}`);
          }
          return out;
        }
        async function queryOnSession(s, policy2, sql) {
          const analysis = analyze(sql, { database: s.database, databases: db.names() });
          const refuse = async (code, reason, endReason) => {
            audit("query_blocked", { agent: s.agent, session_id: s.id, incident: s.incident, database: s.database, sql, kind: analysis.intent, code, detail: reason });
            if (endReason) await endSession(s, endReason);
            return { ok: false, code, reason, session_id: s.id, kind: analysis.intent.toLowerCase(), ...s.end_reason && { end_reason: s.end_reason } };
          };
          const alreadyEnded = () => refuse("SESSION_REVOKED", `Session already ended (${humanize(s.end_reason)})`);
          if (s.status !== "active") return alreadyEnded();
          const verdict = CHECKS[1].run({ req: { agent: s.agent, database: s.database, incident: s.incident, analysis }, policy: policy2 });
          if (!verdict.ok) {
            const out = await refuse(verdict.code, verdict.reason);
            if (analysis.intent === "WRITE") {
              s.refused_writes += 1;
              await writeNote(s, sql, `REFUSED (${verdict.code}): ${verdict.reason}`);
            }
            return out;
          }
          if (now().getTime() >= new Date(s.expires_at).getTime()) return refuse("SESSION_REVOKED", "Session expired", "expired");
          const { failure } = await runChecks({ req: s, policy: policy2, broker }, INCIDENT_CHECKS_START);
          if (s.status !== "active") return alreadyEnded();
          if (failure) {
            const unavailable = failure.code === "CHECK_UNAVAILABLE";
            return refuse(
              unavailable ? "CHECK_UNAVAILABLE" : "SESSION_REVOKED",
              `Incident recheck failed: ${failure.reason}. Session revoked`,
              unavailable ? "check_unavailable" : failure.code.toLowerCase()
            );
          }
          return run(s, sql, analysis);
        }
        const adminRouter = express.Router();
        adminRouter.post("/agents/:agent/suspend", async (req, res) => {
          const agent = req.params.agent;
          if (!policies.has(agent)) return res.status(404).json({ code: "AGENT_NOT_RECOGNIZED", reason: `Agent "${agent}" is not registered in Warden` });
          suspended.add(agent);
          const open = [...sessions.values()].filter((s) => s.agent === agent && s.status === "active");
          audit("agent_suspended", { agent, detail: `${open.length} session(s) closed` });
          await Promise.all(open.map((s) => endSession(s, "kill_switch")));
          res.json({ agent, suspended: true, closed_sessions: open.map((s) => s.id) });
        });
        adminRouter.get("/audit", (req, res) => res.json({ events: auditLog }));
        return { adminRouter, reset, sessions, mcpSessions, suspended, auditLog, openMcpSession, getMcpSession, closeMcpSession, listDatabases, runQuery };
      }
      module.exports = { createBroker, CHECKS };
    }
  });

  // src/idp.js
  var require_idp = __commonJS({
    "src/idp.js"(exports, module) {
      "use strict";
      var crypto = require_crypto();
      var express = require_express();
      var DEMO_CLIENTS = { "it-ops-agent": "demo-secret-it-ops", "rogue-agent": "demo-secret-rogue" };
      var TOKEN_TTL_SECONDS = 3600;
      var digest = (value) => crypto.createHash("sha256").update(String(value)).digest();
      var safeEqual = (a, b) => crypto.timingSafeEqual(digest(a), digest(b));
      function createIdp({ clients = DEMO_CLIENTS, now = () => /* @__PURE__ */ new Date() } = {}) {
        const tokens = /* @__PURE__ */ new Map();
        const router = express.Router();
        router.post("/token", (req, res) => {
          const { grant_type: grantType, client_id: clientId, client_secret: secret } = req.body;
          if (grantType !== "client_credentials") return res.status(400).json({ error: "unsupported_grant_type" });
          if (typeof clientId !== "string" || !Object.hasOwn(clients, clientId) || !safeEqual(clients[clientId], secret)) {
            return res.status(401).json({ error: "invalid_client" });
          }
          const accessToken = `at_${crypto.randomBytes(16).toString("hex")}`;
          tokens.set(accessToken, { client_id: clientId, expires: now().getTime() + TOKEN_TTL_SECONDS * 1e3 });
          res.json({ access_token: accessToken, token_type: "Bearer", expires_in: TOKEN_TTL_SECONDS });
        });
        function validate(accessToken) {
          const entry = tokens.get(accessToken);
          return entry && now().getTime() < entry.expires ? { client_id: entry.client_id } : null;
        }
        return { router, validate };
      }
      module.exports = { createIdp, DEMO_CLIENTS };
    }
  });

  // src/mcp.js
  var require_mcp = __commonJS({
    "src/mcp.js"(exports, module) {
      "use strict";
      var express = require_express();
      var SERVER_NAME = "postgres";
      var PROTOCOL_VERSION = "2025-06-18";
      var TOOLS = [
        {
          name: "list_databases",
          description: "List the databases this agent may query.",
          inputSchema: { type: "object", properties: {}, additionalProperties: false }
        },
        {
          name: "run_query",
          description: "Run a SQL statement on a database. Access is granted just in time and only while an ITSM incident justifies it. Reads are allowed; a write needs the incident to have a write policy covering that table and statement.",
          inputSchema: {
            type: "object",
            properties: {
              database: { type: "string", description: "Database name, for example orders-prod" },
              sql: { type: "string", description: "The SQL statement to run" },
              incident: { type: "string", description: "ITSM incident number that justifies the access, for example INC0012345 (proposed extension)" }
            },
            required: ["database", "sql", "incident"],
            additionalProperties: false
          }
        }
      ];
      var rpcResult = (id, result) => ({ jsonrpc: "2.0", id, result });
      var rpcError = (id, code, message) => ({ jsonrpc: "2.0", id, error: { code, message } });
      var isText = (v) => typeof v === "string" && v.trim() !== "";
      function toolResult(outcome) {
        const { ok, ...data } = outcome;
        const done = data.kind === "write" ? `${data.rows_affected} row(s) changed` : JSON.stringify(data.rows ?? data.databases);
        const text = ok ? done : `${data.code}: ${data.reason}`;
        return { content: [{ type: "text", text }], structuredContent: data, isError: !ok };
      }
      function createMcp({ broker, idp }) {
        const router = express.Router();
        function authenticate(req, res) {
          const match = /^Bearer (.+)$/.exec(req.get("authorization") || "");
          const identity = match && idp.validate(match[1]);
          if (!identity) {
            res.set("WWW-Authenticate", 'Bearer error="invalid_token"').status(401).json({ error: "invalid_token", error_description: "Missing, invalid or expired access token" });
            return null;
          }
          return identity;
        }
        function sessionOf(req, res, identity, id = null) {
          const sessionId = req.get("mcp-session-id");
          if (!sessionId) {
            res.status(400).json(rpcError(id, -32600, "Missing Mcp-Session-Id header. Send initialize first"));
            return null;
          }
          const session = broker.getMcpSession(sessionId, identity.client_id);
          if (!session) {
            res.status(404).json(rpcError(id, -32600, "Unknown or closed MCP session. Send initialize to start a new one"));
            return null;
          }
          return session;
        }
        const guarded = (handler) => (req, res) => {
          if (req.params.server !== SERVER_NAME) return res.status(404).json({ error: "unknown_mcp_server" });
          const identity = authenticate(req, res);
          if (identity) return handler(req, res, identity);
        };
        router.post("/:server", guarded(async (req, res, identity) => {
          const msg = req.body;
          if (Array.isArray(msg) || typeof msg.method !== "string" || msg.jsonrpc !== "2.0") {
            return res.status(400).json(rpcError(msg && msg.id !== void 0 ? msg.id : null, -32600, "Invalid Request: expected one JSON-RPC 2.0 request object"));
          }
          const { id, method } = msg;
          if (method === "initialize") {
            const session2 = broker.openMcpSession(identity.client_id);
            res.set("Mcp-Session-Id", session2.id);
            return res.json(rpcResult(id, {
              protocolVersion: PROTOCOL_VERSION,
              capabilities: { tools: { listChanged: false } },
              serverInfo: { name: "warden-mcp", title: "Warden access gateway (mock)", version: "0.1.0" }
            }));
          }
          const session = sessionOf(req, res, identity, id ?? null);
          if (!session) return;
          if (id === void 0) return res.status(202).end();
          switch (method) {
            case "ping":
              return res.json(rpcResult(id, {}));
            case "tools/list":
              return res.json(rpcResult(id, { tools: TOOLS }));
            case "tools/call": {
              const { name, arguments: args = {} } = msg.params || {};
              if (!TOOLS.some((t) => t.name === name)) return res.json(rpcError(id, -32602, `Unknown tool: ${name}`));
              if (name === "list_databases") return res.json(rpcResult(id, toolResult(broker.listDatabases(session))));
              if (![args.database, args.sql, args.incident].every(isText)) {
                return res.json(rpcError(id, -32602, "Invalid arguments: database, sql and incident are required strings"));
              }
              return res.json(rpcResult(id, toolResult(await broker.runQuery(session, args))));
            }
            default:
              return res.json(rpcError(id, -32601, `Method not found: ${method}`));
          }
        }));
        router.delete("/:server", guarded(async (req, res, identity) => {
          const session = sessionOf(req, res, identity);
          if (!session) return;
          await broker.closeMcpSession(session);
          res.status(204).end();
        }));
        router.get("/:server", (req, res) => res.set("Allow", "POST, DELETE").status(405).json({ error: "method_not_allowed" }));
        return { router };
      }
      module.exports = { createMcp, rpcError, SERVER_NAME, TOOLS };
    }
  });

  // src/app.js
  var require_app = __commonJS({
    "src/app.js"(exports, module) {
      "use strict";
      var path = require_stub();
      var express = require_express();
      var { loadPolicy } = require_policy();
      var { createItsm } = require_itsm();
      var { createItsmClient } = require_itsm_client();
      var { createBroker } = require_broker();
      var { createIdp } = require_idp();
      var { createMockDb } = require_mockdb();
      var { createMcp, rpcError } = require_mcp();
      function createApp2({ policy: policy2 = path.join("/", "..", "policy.json"), incidents, idpClients, itsmBaseUrl, itsmTimeoutMs, now } = {}) {
        const app2 = express();
        app2.use(express.json());
        app2.use((req, res, next) => {
          req.body ??= {};
          next();
        });
        const itsm = createItsm({ seed: incidents, now });
        const db = createMockDb();
        const broker = createBroker({
          policies: loadPolicy(policy2),
          db,
          itsmClient: createItsmClient(itsmBaseUrl, { timeoutMs: itsmTimeoutMs }),
          now
        });
        const idp = createIdp({ clients: idpClients, now });
        app2.use("/itsm", itsm.router);
        app2.use("/idp", idp.router);
        app2.use("/mcp", createMcp({ broker, idp }).router);
        app2.use("/warden", broker.adminRouter);
        app2.post("/demo/reset", (req, res) => {
          itsm.reset();
          broker.reset();
          db.reset();
          res.json({ ok: true });
        });
        app2.get("/demo/db/:database/:table", (req, res) => {
          const rows = db.snapshot(req.params.database, req.params.table);
          if (!rows) return res.status(404).json({ error: "No such table" });
          res.json({ database: req.params.database, table: req.params.table, rows });
        });
        app2.get("/demo/itsm-calls", (req, res) => res.json({ calls: itsm.getCalls() }));
        app2.post("/demo/itsm-outage", (req, res) => {
          itsm.setDown(req.body.down);
          res.json({ down: Boolean(req.body.down) });
        });
        app2.use(express.static(path.join("/", "..", "public")));
        app2.use((err, req, res, next) => {
          if (err.type === "entity.parse.failed") {
            if (req.originalUrl.startsWith("/mcp")) return res.status(400).json(rpcError(null, -32700, "Parse error"));
            return res.status(400).json({ code: "BAD_REQUEST", reason: "Body is not valid JSON" });
          }
          console.error(err);
          res.status(500).json({ code: "INTERNAL_ERROR", reason: "Unexpected error in the mock" });
        });
        app2.locals.itsm = itsm;
        app2.locals.broker = broker;
        app2.locals.db = db;
        return app2;
      }
      async function start(options = {}, port = 3e3) {
        let base;
        const app2 = createApp2({ itsmBaseUrl: () => base, ...options });
        const server = await new Promise((resolve, reject) => {
          const s = app2.listen(port, "127.0.0.1", () => resolve(s));
          s.on("error", reject);
        });
        base = `http://127.0.0.1:${server.address().port}`;
        return { app: app2, server, base };
      }
      module.exports = { createApp: createApp2, start };
    }
  });

  // web/fetch-shim.js
  var require_fetch_shim = __commonJS({
    "web/fetch-shim.js"(exports, module) {
      "use strict";
      var ROUTED = /^\/(mcp|idp|itsm|warden|demo)(\/|$)/;
      function installFetch2(app2, scope = globalThis) {
        const nativeFetch = scope.fetch.bind(scope);
        const base = scope.location ? scope.location.href : "http://localhost/";
        scope.fetch = async (input, init = {}) => {
          const request = typeof input === "string" || input instanceof URL ? null : input;
          const url = new URL(request ? request.url : String(input), base);
          if (!ROUTED.test(url.pathname)) return nativeFetch(input, init);
          const headers = {};
          new Headers(init.headers || request && request.headers || {}).forEach((value, name) => {
            headers[name] = value;
          });
          const method = init.method || request && request.method || "GET";
          const body = typeof init.body === "string" ? init.body : void 0;
          const out = await app2.dispatch({ method, url: url.pathname + url.search, headers, body });
          const noBody = out.body === null || [101, 204, 205, 304].includes(out.status);
          return new Response(noBody ? null : out.body, { status: out.status, headers: out.headers });
        };
      }
      module.exports = { installFetch: installFetch2 };
    }
  });

  // policy.json
  var require_policy2 = __commonJS({
    "policy.json"(exports, module) {
      module.exports = {
        agents: [
          {
            agent: "IT Ops Agent",
            client_id: "it-ops-agent",
            owner: "DB Ops",
            assignment_group: "DB Ops",
            allowed_databases: [
              "orders-prod"
            ],
            access: "read",
            max_duration_minutes: 30,
            allowed_priorities: [
              "P1",
              "P2"
            ],
            required_ticket_type: "INC",
            write_scopes: {
              INC0012349: {
                database: "orders-prod",
                tables: [
                  "orders"
                ],
                statements: [
                  "UPDATE"
                ]
              }
            }
          }
        ]
      };
    }
  });

  // web/entry.js
  var { createApp } = require_app();
  var { installFetch } = require_fetch_shim();
  var policy = require_policy2();
  var app = createApp({ policy, itsmBaseUrl: () => "" });
  installFetch(app);
})();
