'use strict';

// A very small stand-in for Express, just enough for this app's routes to run inside a browser page.
// It supports what the app uses: routers and mounting, :params, use/get/post/delete, async handlers,
// error handlers, express.json(), and the request and response fields the handlers read.

class Req {
  constructor(method, url, headers, rawBody) {
    this.method = method.toUpperCase();
    this.url = url; // path and query, relative to the router being run
    this.originalUrl = url;
    this.baseUrl = '';
    this.headers = headers; // lower-case names
    this.rawBody = rawBody;
    this.params = {};
    this.body = undefined;
    this.route = undefined;
  }

  get path() { return this.url.split('?')[0]; }

  get(name) { return this.headers[String(name).toLowerCase()]; }
}

class Res {
  constructor() {
    this.statusCode = 200;
    this.headers = {};
    this.body = null;
    this.finished = false;
    this.finishListeners = [];
    this.done = new Promise((resolve) => { this.resolve = resolve; });
  }

  status(code) { this.statusCode = code; return this; }

  set(name, value) { this.headers[String(name).toLowerCase()] = String(value); return this; }

  get(name) { return this.headers[String(name).toLowerCase()]; }

  json(body) {
    this.set('content-type', 'application/json; charset=utf-8');
    return this.end(JSON.stringify(body));
  }

  end(body) {
    if (this.finished) return this;
    this.finished = true;
    this.body = body === undefined ? null : body;
    for (const fn of this.finishListeners) fn(); // before the caller sees the response, so logs are in order
    this.resolve({ status: this.statusCode, headers: this.headers, body: this.body });
    return this;
  }

  on(event, fn) {
    if (event === 'finish') this.finishListeners.push(fn);
    return this;
  }
}

// '/incidents/:number/state' -> a matcher that also returns the named parts.
function compile(pattern) {
  const names = [];
  const source = pattern.replace(/\/+$/, '').split('/').map((segment) => {
    if (segment.startsWith(':')) { names.push(segment.slice(1)); return '([^/]+)'; }
    return segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }).join('/');
  return { names, regex: new RegExp(`^${source}/?$`, 'i') };
}

function Router() {
  const stack = []; // each layer: { type: 'use' | 'route', handlers, ... }

  function handle(req, res, done) {
    const baseUrl = req.baseUrl;
    const url = req.url;
    const query = url.includes('?') ? url.slice(url.indexOf('?')) : '';
    const pathname = url.split('?')[0];
    let index = 0;

    // Runs one layer's handlers in order. While an error is travelling only error handlers (four
    // arguments) run, and otherwise only normal ones. A thrown error or a rejected promise becomes next(err).
    function runChain(handlers, i, err) {
      if (i >= handlers.length) return next(err);
      const fn = handlers[i];
      if (err ? fn.length !== 4 : fn.length === 4) return runChain(handlers, i + 1, err);
      const after = (nextErr) => runChain(handlers, i + 1, nextErr);
      try {
        const out = err ? fn(err, req, res, after) : fn(req, res, after);
        if (out && typeof out.then === 'function') out.catch(after);
      } catch (thrown) {
        after(thrown);
      }
    }

    function next(err) {
      req.baseUrl = baseUrl; // leaving a mounted layer: put the path back
      req.url = url;
      while (index < stack.length) {
        const layer = stack[index++];

        if (layer.type === 'use') {
          const prefix = layer.prefix === '/' ? '' : layer.prefix.replace(/\/$/, '');
          if (prefix && pathname !== prefix && !pathname.startsWith(`${prefix}/`)) continue;
          req.baseUrl = baseUrl + prefix;
          req.url = (pathname.slice(prefix.length) || '/') + query;
          return runChain(layer.handlers, 0, err);
        }

        const match = layer.regex.exec(pathname);
        if (layer.method !== req.method || !match) continue;
        req.params = {};
        layer.names.forEach((name, i) => { req.params[name] = decodeURIComponent(match[i + 1]); });
        req.route = { path: layer.pattern };
        return runChain(layer.handlers, 0, err);
      }
      return done(err);
    }

    next();
  }

  const router = (req, res, done) => handle(req, res, done);
  router.use = (...args) => {
    const prefix = typeof args[0] === 'string' ? args.shift() : '/';
    stack.push({ type: 'use', prefix, handlers: args });
    return router;
  };
  for (const method of ['get', 'post', 'delete']) {
    router[method] = (pattern, ...handlers) => {
      stack.push({ type: 'route', method: method.toUpperCase(), pattern, ...compile(pattern), handlers });
      return router;
    };
  }
  return router;
}

function express() {
  const app = Router();
  app.locals = {};
  // Runs one request through the app and resolves with { status, headers, body }.
  app.dispatch = ({ method, url, headers, body }) => {
    const req = new Req(method, url, headers, body);
    const res = new Res();
    app(req, res, (err) => {
      if (err) {
        console.error(err);
        res.status(err.status || 500).end('Internal Server Error');
      } else {
        res.status(404).end(`Cannot ${req.method} ${req.originalUrl}`);
      }
    });
    return res.done;
  };
  return app;
}

express.Router = Router;

// Mirrors express.json(): parses a JSON body, and passes the same error type on bad input.
express.json = () => (req, res, next) => {
  if (!req.rawBody) return next();
  try {
    const parsed = JSON.parse(req.rawBody);
    if (parsed === null || typeof parsed !== 'object') throw new Error('not an object or array');
    req.body = parsed;
    return next();
  } catch {
    const err = new Error('Invalid JSON');
    err.type = 'entity.parse.failed';
    err.status = 400;
    return next(err);
  }
};

express.static = () => (req, res, next) => next(); // the page is served by GitHub Pages, not by the app

module.exports = express;
