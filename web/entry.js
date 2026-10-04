'use strict';

// Entry point of the browser build: the same app as the Node server, started inside the page.
const { createApp } = require('../src/app');
const { installFetch } = require('./fetch-shim');
const policy = require('../policy.json');

// The ITSM client calls the mock ITSM through fetch; with an empty base the call stays inside the page.
const app = createApp({ policy, itsmBaseUrl: () => '' });
installFetch(app);
