// The report contract, as Aftercare checks it (fredo app/src/ingest.ts).
// Returns a list of problems; empty means Aftercare would accept it. Used by
// the unit tests and by fake-aftercare.mjs, the stand-in server CI posts to.
const STATUSES = ['clear', 'vulnerable', 'error'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];
const REPORT_FIELDS = ['commit', 'findings', 'run_url', 'status'];
const FINDING_FIELDS = ['cvss', 'direct', 'ecosystem', 'fixed_in', 'id', 'package', 'severity', 'title', 'version'];

const text = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max;
const sameKeys = (o, keys) => JSON.stringify(Object.keys(o).sort()) === JSON.stringify(keys);
const https = (v) => { try { return typeof v === 'string' && v.length <= 512 && new URL(v).protocol === 'https:'; } catch { return false; } };

export function problems(report) {
  const out = [];
  if (typeof report !== 'object' || report === null || Array.isArray(report)) return ['not an object'];
  if (!sameKeys(report, REPORT_FIELDS)) out.push(`fields: ${Object.keys(report).join(', ')}`);
  if (!STATUSES.includes(report.status)) out.push(`status: ${report.status}`);
  if (!https(report.run_url)) out.push(`run_url: ${report.run_url}`);
  if (!/^[0-9a-f]{7,64}$/.test(String(report.commit))) out.push(`commit: ${report.commit}`);
  if (!Array.isArray(report.findings) || report.findings.length > 500) return [...out, 'findings: not a list of at most 500'];
  if ((report.status === 'vulnerable') !== (report.findings.length > 0)) out.push(`status ${report.status} with ${report.findings.length} findings`);
  const seen = new Set();
  for (const f of report.findings) {
    const where = `finding ${f?.id}`;
    if (typeof f !== 'object' || f === null || !sameKeys(f, FINDING_FIELDS)) { out.push(`${where}: fields`); continue; }
    if (!/^[!-~]{1,64}$/.test(String(f.id))) out.push(`${where}: id`);
    if (!text(f.package, 214)) out.push(`${where}: package`);
    if (!text(f.version, 64)) out.push(`${where}: version`);
    if (!(f.fixed_in === null || text(f.fixed_in, 64))) out.push(`${where}: fixed_in`);
    if (!SEVERITIES.includes(f.severity)) out.push(`${where}: severity`);
    if (!(f.cvss === null || (typeof f.cvss === 'number' && Number.isFinite(f.cvss) && f.cvss >= 0 && f.cvss <= 10))) out.push(`${where}: cvss`);
    if (!text(f.title, 300)) out.push(`${where}: title`);
    if (!(f.direct === null || typeof f.direct === 'boolean')) out.push(`${where}: direct`);
    if (!/^[a-z0-9.:-]{1,32}$/.test(String(f.ecosystem))) out.push(`${where}: ecosystem`);
    const key = JSON.stringify([f.id, f.package, f.version]);
    if (seen.has(key)) out.push(`${where}: duplicate`);
    seen.add(key);
  }
  return out;
}
