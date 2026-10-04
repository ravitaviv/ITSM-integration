'use strict';

// Sends the page's API calls to the in-browser app instead of the network. Calls to the app's own routes are
// answered by `app`; everything else (fonts, for example) goes to the real fetch. The app's ITSM client uses
// fetch too, so the gateway still reaches the mock ITSM with an HTTP-style call, as it does on the Node server.
const ROUTED = /^\/(mcp|idp|itsm|warden|demo)(\/|$)/;

function installFetch(app, scope = globalThis) {
  const nativeFetch = scope.fetch.bind(scope);
  const base = scope.location ? scope.location.href : 'http://localhost/';

  scope.fetch = async (input, init = {}) => {
    const request = typeof input === 'string' || input instanceof URL ? null : input;
    const url = new URL(request ? request.url : String(input), base);
    if (!ROUTED.test(url.pathname)) return nativeFetch(input, init);

    const headers = {};
    new Headers(init.headers || (request && request.headers) || {}).forEach((value, name) => { headers[name] = value; });
    const method = init.method || (request && request.method) || 'GET';
    const body = typeof init.body === 'string' ? init.body : undefined;

    const out = await app.dispatch({ method, url: url.pathname + url.search, headers, body });
    const noBody = out.body === null || [101, 204, 205, 304].includes(out.status);
    return new Response(noBody ? null : out.body, { status: out.status, headers: out.headers });
  };
}

module.exports = { installFetch };
