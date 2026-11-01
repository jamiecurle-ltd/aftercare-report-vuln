// Builds the report for Aftercare's POST /ingest/vulns from OSV-Scanner's
// JSON, and prints it. Aftercare never parses tool output, so all the
// interpretation happens here. CONTRACT.md describes the report.
//
//   node build.mjs <dir> <run url> <commit>
//
// <dir> holds what report.sh wrote:
//   osv.json, osv.exit       OSV-Scanner's result and exit code (required)
//   lockfiles.txt            the lockfiles scanned, one per line
//   hex-retired.txt          `mix hex.audit` output (only with hex-retired)
//   mix-deps-tree.txt        `mix deps.tree --format plain` (when mix exists)
//
// OSV alone decides the status: if it didn't run (no exit code of 0 or 1, or
// no result), the report is 'error' with no findings, never 'clear', and
// Aftercare keeps showing the last known findings.
//
// Plain Node, no dependencies, nothing newer than Node 20.
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

// Compares versions numerically: "1.2.10" is [1, 2, 10]. A pre-release
// ("1.2.3-rc.1") comes before its release, as in semver.
const ver = (v) => v.split('-')[0].split('.').map((n) => Number.parseInt(n, 10) || 0);
export function compare(a, b) {
  const x = ver(a), y = ver(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
  return Number(!a.includes('-')) - Number(!b.includes('-'));
}

// CVSS score -> the contract's severity names.
const severity = (cvss) => cvss == null ? 'unknown'
  : cvss >= 9 ? 'critical' : cvss >= 7 ? 'high' : cvss >= 4 ? 'medium' : cvss > 0 ? 'low' : 'unknown';

// Whitespace collapsed; '' if nothing is left.
const clean = (s) => (typeof s === 'string' ? s.replace(/\s+/g, ' ').trim() : '');

// --- Which dependencies are direct ------------------------------------------
// OSV doesn't say, so it's worked out per ecosystem where we can; anything
// else is null ("can't tell"), which the contract allows.

// npm: the root package's own dependencies in package-lock.json.
export function npmDirect(lock) {
  const root = lock?.packages?.[''] ?? {};
  return new Set(Object.keys({ ...root.dependencies, ...root.devDependencies, ...root.optionalDependencies }));
}

// Hex: the top level of `mix deps.tree --format plain`, whose lines start
// "|-- name" or "`-- name" with no indent.
export function hexDirect(tree) {
  return new Set(tree.split('\n').map((l) => /^[|`]-- ([a-z0-9_]+) /.exec(l)?.[1]).filter(Boolean));
}

// --- Retired Hex packages ---------------------------------------------------
// From `mix hex.audit` (Hex 2.4):
//   Retired:
//     hackney 1.6.4 - (invalid) optional message
// The section ends at a blank line. Its "Advisories:" section is OSV's data,
// already in the scan.
export function retiredPackages(text) {
  const out = [];
  let inSection = false;
  for (const line of text.split('\n')) {
    if (line === 'Retired:') { inSection = true; continue; }
    if (!inSection) continue;
    const m = /^ {2}([a-z0-9_]+) (\S+) - (.*)$/.exec(line);
    if (!m) break;
    out.push({ package: m[1], version: m[2], reason: clean(m[3]) });
  }
  return out;
}

// --- The report -----------------------------------------------------------------
// inputs: { osv, direct: { npm?: Set, hex?: Set }, retired?: [...] }
export function buildReport({ osv, direct = {}, retired = [] }, runUrl, commit) {
  if (!osv) return { status: 'error', run_url: runUrl, commit, findings: [] };
  const isDirect = (ecosystem, name) => (direct[ecosystem] ? direct[ecosystem].has(name) : null);
  const findings = new Map();
  const add = (f) => findings.set(JSON.stringify([f.id, f.package, f.version]), f);

  for (const result of osv.results ?? []) {
    for (const { package: pkg, vulnerabilities = [], groups = [] } of result.packages ?? []) {
      const ecosystem = pkg.ecosystem.toLowerCase().replace(/[^a-z0-9.:-]/g, '-').slice(0, 32);
      // A group is one advisory under all its names (GHSA, CVE, EEF, ...): one finding.
      for (const group of groups) {
        const vuln = vulnerabilities.find((v) => group.ids.includes(v.id));
        const id = group.ids.find((i) => i.startsWith('GHSA-')) ?? group.ids[0];
        const score = Number.parseFloat(group.max_severity);
        const cvss = Number.isFinite(score) ? score : null;
        // The lowest fixed version above the installed one. Only version
        // ranges: a GIT range's "fixed" is a commit hash.
        const fixes = (vuln?.affected ?? [])
          .filter((a) => a.package?.name === pkg.name)
          .flatMap((a) => (a.ranges ?? []).filter((r) => r.type === 'SEMVER' || r.type === 'ECOSYSTEM')
            .flatMap((r) => (r.events ?? []).map((e) => e.fixed).filter(Boolean)))
          .filter((f) => compare(f, pkg.version) > 0)
          .sort(compare);
        add({
          id: id.slice(0, 64),
          package: pkg.name.slice(0, 214),
          version: pkg.version.slice(0, 64),
          fixed_in: fixes[0]?.slice(0, 64) ?? null,
          severity: severity(cvss),
          cvss,
          title: (clean(vuln?.summary) || clean(vuln?.details) || id).slice(0, 300),
          direct: isDirect(ecosystem, pkg.name),
          ecosystem,
        });
      }
    }
  }

  // Retired packages: not a vulnerability as such, but the author says stop
  // using that version. Severity unknown, so it shows as needing a look.
  for (const r of retired) {
    add({
      id: `RETIRED-${r.package}`.slice(0, 64),
      package: r.package,
      version: r.version.slice(0, 64),
      fixed_in: null,
      severity: 'unknown',
      cvss: null,
      title: `Retired by its author: ${r.reason}`.slice(0, 300),
      direct: isDirect('hex', r.package),
      ecosystem: 'hex',
    });
  }

  const list = [...findings.values()].sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0));
  return { status: list.length ? 'vulnerable' : 'clear', run_url: runUrl, commit, findings: list };
}

// Reads what report.sh wrote into <dir>.
export function readDir(dir) {
  const file = (f) => join(dir, f);
  const text = (f) => (existsSync(file(f)) ? readFileSync(file(f), 'utf8') : null);
  const json = (f) => { try { return JSON.parse(readFileSync(file(f), 'utf8')); } catch { return null; } };

  const code = text('osv.exit')?.trim();
  const osv = code === '0' || code === '1' ? json('osv.json') : null;

  const direct = {};
  for (const lockfile of (text('lockfiles.txt') ?? '').split('\n').filter(Boolean)) {
    if (lockfile.endsWith('package-lock.json')) {
      const lock = json(lockfile.startsWith('/') ? lockfile : join(process.cwd(), lockfile));
      if (lock) direct.npm = new Set([...(direct.npm ?? []), ...npmDirect(lock)]);
    }
  }
  const tree = text('mix-deps-tree.txt');
  if (tree) direct.hex = hexDirect(tree);

  const hexAudit = text('hex-retired.txt');
  return { osv, direct, retired: hexAudit ? retiredPackages(hexAudit) : [] };
}

// Run as a script (not when the tests import it).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [dir, runUrl, commit] = process.argv.slice(2);
  console.log(JSON.stringify(buildReport(readDir(dir), runUrl, commit)));
}
