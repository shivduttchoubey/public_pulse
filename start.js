/**
 * PUBLIC PULSE — Start Script
 * Launches both backend services concurrently
 */

const { spawn } = require('child_process');
const path = require('path');
const http = require('http');
const fs = require('fs');

function startService(name, dir, script) {
  const proc = spawn('node', [script], {
    cwd: path.join(__dirname, dir),
    stdio: 'pipe',
  });

  proc.stdout.on('data', d => process.stdout.write(`\x1b[36m[${name}]\x1b[0m ${d}`));
  proc.stderr.on('data', d => process.stderr.write(`\x1b[31m[${name} ERR]\x1b[0m ${d}`));
  proc.on('exit', code => console.log(`\x1b[33m[${name}]\x1b[0m Exited with code ${code}`));
  
  return proc;
}

// Start a tiny static server for the frontend
function startFrontend() {
  const server = http.createServer((req, res) => {
    const filePath = path.join(__dirname, 'frontend/public', req.url === '/' ? 'index.html' : req.url);
    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(404);
        res.end('Not found');
        return;
      }
      const ext = path.extname(filePath);
      const types = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css' };
      res.writeHead(200, { 'Content-Type': types[ext] || 'text/plain' });
      res.end(data);
    });
  });
  
  server.listen(3000, () => {
    console.log('\x1b[32m[FRONTEND]\x1b[0m Dashboard running on http://localhost:3000');
  });
}

console.log('\x1b[1m\x1b[36m');
console.log('╔═══════════════════════════════════════╗');
console.log('║       PUBLIC PULSE — PoC v1.0         ║');
console.log('║  Decentralizing IT Trust via ZKP      ║');
console.log('╚═══════════════════════════════════════╝');
console.log('\x1b[0m');

startService('INFRA-SIM',  'infra-sim',  'index.js');

setTimeout(() => {
  startService('MIDDLEWARE', 'middleware', 'index.js');
}, 1000);

setTimeout(() => {
  startFrontend();
  console.log('\n\x1b[1m🚀 All services started!\x1b[0m');
  console.log('   Frontend:    \x1b[32mhttp://localhost:3000\x1b[0m');
  console.log('   Middleware:  \x1b[36mhttp://localhost:3002\x1b[0m');
  console.log('   Infra-Sim:   \x1b[35mhttp://localhost:3001\x1b[0m (internal)\n');
}, 2000);
