'use strict';

// Stands in for node:fs and node:path in the browser build. The policy is bundled into the page, so nothing
// is read from disk, and the static-file path the Node server builds is never used.
module.exports = {
  readFileSync() { throw new Error('Reading files is not available in the browser build'); },
  join: (...parts) => parts.filter(Boolean).join('/'),
};
