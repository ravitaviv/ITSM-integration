'use strict';
const { start } = require('./src/app');

const port = Number(process.env.PORT) || 3000;

start({}, port).then(({ base }) => {
  console.log(`Incident-justified agent access (mock) on ${base}`);
}).catch((err) => {
  console.error(err.code === 'EADDRINUSE' ? `Port ${port} is in use. Set PORT to another value.` : err);
  process.exit(1);
});
