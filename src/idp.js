'use strict';
const crypto = require('node:crypto');
const express = require('express');

// Mock of the customer's identity provider (Okta, Entra ID and so on). Warden does not issue the agent's
// credentials: the agent authenticates here with OAuth client credentials and presents the access token to
// the Warden gateway. "rogue-agent" is a valid client at the IdP that Warden has never registered.
// These are demo-only values.
const DEMO_CLIENTS = { 'it-ops-agent': 'demo-secret-it-ops', 'rogue-agent': 'demo-secret-rogue' };
const TOKEN_TTL_SECONDS = 3600;

const digest = (value) => crypto.createHash('sha256').update(String(value)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(digest(a), digest(b));

function createIdp({ clients = DEMO_CLIENTS, now = () => new Date() } = {}) {
  const tokens = new Map(); // access_token -> { client_id, expires }
  const router = express.Router();

  // JSON body for brevity; a real token endpoint takes application/x-www-form-urlencoded.
  router.post('/token', (req, res) => {
    const { grant_type: grantType, client_id: clientId, client_secret: secret } = req.body;
    if (grantType !== 'client_credentials') return res.status(400).json({ error: 'unsupported_grant_type' });
    if (typeof clientId !== 'string' || !Object.hasOwn(clients, clientId) || !safeEqual(clients[clientId], secret)) {
      return res.status(401).json({ error: 'invalid_client' });
    }
    const accessToken = `at_${crypto.randomBytes(16).toString('hex')}`;
    tokens.set(accessToken, { client_id: clientId, expires: now().getTime() + TOKEN_TTL_SECONDS * 1000 });
    res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: TOKEN_TTL_SECONDS });
  });

  // Used by the gateway to validate a bearer token. Returns { client_id } or null.
  function validate(accessToken) {
    const entry = tokens.get(accessToken);
    return entry && now().getTime() < entry.expires ? { client_id: entry.client_id } : null;
  }

  return { router, validate };
}

module.exports = { createIdp, DEMO_CLIENTS };
