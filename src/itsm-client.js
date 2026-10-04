'use strict';

class ItsmUnavailableError extends Error {}

// HTTP client the broker uses to reach ITSM. Anything that stops us getting a
// trustworthy answer (network error, timeout, 5xx, unreadable body) becomes ItsmUnavailableError,
// which the broker treats as "fail closed".
function createItsmClient(baseUrl, { timeoutMs = 2000 } = {}) {
  const base = () => (typeof baseUrl === 'function' ? baseUrl() : baseUrl);

  async function call(path, init = {}) {
    try {
      return await fetch(`${base()}/itsm${path}`, {
        ...init,
        headers: { 'content-type': 'application/json', 'x-caller': 'warden-broker' },
        signal: AbortSignal.timeout(timeoutMs),
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
        throw new ItsmUnavailableError('ITSM returned an unreadable response');
      }
    },

    async addWorkNote(number, text, author) {
      const res = await call(`/incidents/${encodeURIComponent(number)}/work_notes`, {
        method: 'POST',
        body: JSON.stringify({ work_notes: text, author }),
      });
      if (!res.ok) throw new ItsmUnavailableError(`ITSM returned ${res.status}`);
    },
  };
}

module.exports = { createItsmClient, ItsmUnavailableError };
