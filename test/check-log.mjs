// Checks what the fake Aftercare received during a CI run, against what each
// test case expects (.github/workflows/test.yml).
//
//   node test/check-log.mjs <log file> <expectation> ...
//
// Each expectation is "<http status>:<report status>:<minimum findings>"
// (report status and findings are ignored for a 401), in the order the
// requests were made. Also checks every accepted report passed the contract.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const [log, ...expected] = process.argv.slice(2);
const got = readFileSync(log, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
assert.equal(got.length, expected.length, `expected ${expected.length} requests, got ${got.length}`);
expected.forEach((e, i) => {
  const [http, status, min] = e.split(':');
  const r = got[i];
  assert.equal(String(r.status), http, `request ${i + 1}: HTTP ${r.status} (${r.why.join('; ')})`);
  if (http === '204') {
    assert.equal(r.report.status, status, `request ${i + 1}: status`);
    assert.ok(r.report.findings.length >= Number(min), `request ${i + 1}: ${r.report.findings.length} findings, wanted ${min}+`);
  }
  console.log(`request ${i + 1}: HTTP ${r.status}${r.report ? `, ${r.report.status}, ${r.report.findings.length} findings` : ''}`);
});
