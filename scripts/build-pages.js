'use strict';
// Builds the static version of the app into docs/, ready for GitHub Pages: the same server code, bundled to run
// inside the page, plus the page itself. Run it with `npm run build:pages` and commit docs/.
const fs = require('node:fs');
const path = require('node:path');
const esbuild = require('esbuild');

const root = path.join(__dirname, '..');
const shim = (name) => path.join(root, 'web', 'shims', name);

// Express and the Node-only modules are swapped for browser versions; nothing in src/ changes.
const browserShims = {
  name: 'browser-shims',
  setup(build) {
    build.onResolve({ filter: /^node:crypto$/ }, () => ({ path: shim('crypto.js') }));
    build.onResolve({ filter: /^node:(fs|path)$/ }, () => ({ path: shim('stub.js') }));
    build.onResolve({ filter: /^express$/ }, () => ({ path: shim('express.js') }));
  },
};

const bundleOptions = {
  entryPoints: [path.join(root, 'web', 'entry.js')],
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: 'es2022',
  define: { __dirname: '"/"' },
  plugins: [browserShims],
  logLevel: 'warning',
};

async function buildPages() {
  const docs = path.join(root, 'docs');
  fs.mkdirSync(docs, { recursive: true });
  await esbuild.build({ ...bundleOptions, outfile: path.join(docs, 'app.bundle.js') });

  // The page is the same file the Node server serves, with the bundle loaded before its own script.
  const page = fs.readFileSync(path.join(root, 'public', 'index.html'), 'utf8');
  const at = page.indexOf('<script>');
  if (at < 0) throw new Error('public/index.html has no inline script to load the bundle before');
  fs.writeFileSync(path.join(docs, 'index.html'), `${page.slice(0, at)}<script src="app.bundle.js"></script>\n${page.slice(at)}`);
  fs.writeFileSync(path.join(docs, '.nojekyll'), ''); // serve the files as they are
}

if (require.main === module) {
  buildPages().then(() => console.log('Built docs/ (index.html, app.bundle.js)'));
}

module.exports = { bundleOptions, buildPages };
