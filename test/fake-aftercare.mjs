// A stand-in for Aftercare's POST /ingest/vulns, for the CI tests
// (.github/workflows/test.yml). Answers like the real one: 401 for a wrong
// token, 400 for a report that breaks the contract (contract.mjs), 204
// otherwise. Each request is appended to <log file> as one JSON line, so a
// later step can check what the action actually sent.
//
//   node test/fake-aftercare.mjs <port> <expected token> <log file>
import { appendFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { problems } from './contract.mjs';

const [port, token, log] = process.argv.slice(2);

createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', () => {
    let status = 204, report = null, why = [];
    if (req.method !== 'POST' || req.url !== '/ingest/vulns') status = 404;
    else if (req.headers.authorization !== `Bearer ${token}`) status = 401;
    else if (!(req.headers['content-type'] ?? '').startsWith('application/json')) status = 400;
    else {
      try { report = JSON.parse(body); why = problems(report); } catch { why = ['not JSON']; }
      if (why.length) status = 400;
    }
    appendFileSync(log, JSON.stringify({ status, why, report }) + '\n');
    res.writeHead(status, status === 204 ? {} : { 'content-type': 'application/json' });
    res.end(status === 204 ? undefined : JSON.stringify({ error: status === 401 ? 'unauthorised' : 'bad request', why }));
  });
}).listen(Number(port), '127.0.0.1', () => console.log(`fake Aftercare on 127.0.0.1:${port}`));
