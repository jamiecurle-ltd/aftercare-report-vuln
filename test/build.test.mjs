// Unit tests for build.mjs. Run with `node --test test/`.
//
// The fixtures are real OSV-Scanner output (captured 2026-11-01):
//   npm/  a package-lock.json with vulnerable lodash 4.17.20 (direct) and
//         minimist 1.2.5 (transitive)
//   hex/  a mix.lock with retired hackney 1.6.4 and vulnerable
//         ssl_verify_fun 1.1.7, with that project's `mix hex.audit` output,
//         and a real app's `mix deps.tree`
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { buildReport, compare, hexDirect, npmDirect, readDir, retiredPackages } from '../build.mjs';
import { problems } from './contract.mjs';

const fixture = (f) => readFileSync(new URL(`fixtures/${f}`, import.meta.url), 'utf8');
const RUN = 'https://github.com/example/app/actions/runs/1';
const COMMIT = 'a'.repeat(40);

const npm = { osv: JSON.parse(fixture('npm/osv.json')), direct: { npm: npmDirect(JSON.parse(fixture('npm/package-lock.json'))) } };
const hex = {
  osv: JSON.parse(fixture('hex/osv.json')),
  direct: { hex: hexDirect(fixture('hex/mix-deps-tree.txt')) },
  retired: retiredPackages(fixture('hex/hex-audit.txt')),
};

describe('npm', () => {
  const report = buildReport(npm, RUN, COMMIT);

  it('builds a report Aftercare accepts', () => {
    assert.deepEqual(problems(report), []);
    assert.equal(report.status, 'vulnerable');
  });

  it('one finding per advisory, worst first', () => {
    assert.equal(report.findings.length, 6);
    assert.deepEqual(report.findings[0], {
      id: 'GHSA-xvch-5gv4-984h', package: 'minimist', version: '1.2.5', fixed_in: '1.2.6', severity: 'critical',
      cvss: 9.8, title: 'Prototype Pollution in minimist', direct: false, ecosystem: 'npm',
    });
    const scores = report.findings.map((f) => f.cvss);
    assert.deepEqual(scores, [...scores].sort((a, b) => b - a));
  });

  it('knows direct from transitive', () => {
    const direct = Object.fromEntries(report.findings.map((f) => [f.package, f.direct]));
    assert.deepEqual(direct, { lodash: true, minimist: false });
  });
});

describe('hex', () => {
  const report = buildReport(hex, RUN, COMMIT);
  const ids = report.findings.map((f) => f.id);

  it('builds a report Aftercare accepts', () => {
    assert.deepEqual(problems(report), []);
  });

  it("OSV's advisories, by GHSA id where there is one, plus the retired package", () => {
    assert.equal(report.findings.length, 8);
    assert.equal(report.findings[0].package, 'ssl_verify_fun');
    assert.ok(ids.includes('GHSA-gp9c-pm5m-5cxr') && !ids.includes('EEF-CVE-2026-47071'));
    assert.deepEqual(report.findings.find((f) => f.id === 'RETIRED-hackney'), {
      id: 'RETIRED-hackney', package: 'hackney', version: '1.6.4', fixed_in: null, severity: 'unknown',
      cvss: null, title: 'Retired by its author: (invalid)', direct: false, ecosystem: 'hex',
    });
  });

  it("says 'can't tell' (null) for direct when there's no deps tree", () => {
    const r = buildReport({ osv: hex.osv }, RUN, COMMIT);
    assert.ok(r.findings.every((f) => f.direct === null));
    assert.deepEqual(problems(r), []);
  });
});

describe('status', () => {
  it("'error', with no findings, when OSV didn't run", () => {
    const r = buildReport({ osv: null }, RUN, COMMIT);
    assert.deepEqual(r, { status: 'error', run_url: RUN, commit: COMMIT, findings: [] });
    assert.deepEqual(problems(r), []);
  });

  it("'clear' when nothing is found", () => {
    assert.deepEqual(buildReport({ osv: { results: [] } }, RUN, COMMIT), { status: 'clear', run_url: RUN, commit: COMMIT, findings: [] });
  });
});

describe('edge cases', () => {
  const single = (version, vuln, ecosystem = 'npm') => ({
    osv: { results: [{ packages: [{
      package: { name: 'pkg', version, ecosystem },
      vulnerabilities: [{ id: 'GHSA-aaaa-bbbb-cccc', ...vuln }],
      groups: [{ ids: ['GHSA-aaaa-bbbb-cccc'], max_severity: '5.0' }],
    }] }] },
  });
  const ranges = (...r) => ({ affected: [{ package: { name: 'pkg' }, ranges: r.map(({ type, fixed }) => ({ type, events: [{ introduced: '0' }, { fixed }] })) }] });
  const only = (input) => buildReport(input, RUN, COMMIT).findings[0];

  it("ignores a GIT range's commit hash as a fixed version", () => {
    assert.equal(only(single('1.0.0', { summary: 's', ...ranges({ type: 'GIT', fixed: '9f86d081884c7d659a2f' }) })).fixed_in, null);
    assert.equal(only(single('1.0.0', { summary: 's', ...ranges({ type: 'GIT', fixed: '1234abcd' }, { type: 'SEMVER', fixed: '1.0.1' }) })).fixed_in, '1.0.1');
  });

  it('orders a pre-release before its release', () => {
    assert.equal(only(single('1.2.3-beta.1', { summary: 's', ...ranges({ type: 'ECOSYSTEM', fixed: '1.2.3' }) })).fixed_in, '1.2.3');
    assert.ok(compare('1.2.10', '1.2.9') > 0 && compare('1.2.3-rc.1', '1.2.3') < 0);
  });

  it('falls back to the details, then the id, for a blank summary', () => {
    assert.equal(only(single('1.0.0', { summary: '  \n ', details: 'From the details' })).title, 'From the details');
    assert.equal(only(single('1.0.0', { summary: ' ' })).title, 'GHSA-aaaa-bbbb-cccc');
  });

  it("puts OSV's ecosystem names in the contract's form", () => {
    for (const [osvName, ours] of [['PyPI', 'pypi'], ['crates.io', 'crates.io'], ['Debian:12', 'debian:12'], ['Some Thing', 'some-thing']]) {
      const r = buildReport(single('1.0.0', { summary: 's' }, osvName), RUN, COMMIT);
      assert.equal(r.findings[0].ecosystem, ours);
      assert.deepEqual(problems(r), []);
    }
  });

  it('reads only the Retired section of hex.audit', () => {
    assert.deepEqual(retiredPackages('Retired:\n  a_pkg 2.0.0 - (security) Do not use\n  b 1.0.0-rc.1 - (other)\n\nAdvisories:\n  c 1.0.0 - X\n'),
      [{ package: 'a_pkg', version: '2.0.0', reason: '(security) Do not use' }, { package: 'b', version: '1.0.0-rc.1', reason: '(other)' }]);
    assert.deepEqual(retiredPackages('No retired or security advisory packages found\n'), []);
  });
});

// Forgejo's runner runs actions from /var/run/act/..., and /var/run is a
// symlink to /run. Run that way, build.mjs once printed nothing at all.
describe('run as a script', () => {
  it('prints the report when run through a symlinked directory', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'aftercare-'));
    try {
      mkdirSync(join(tmp, 'real'));
      cpSync(new URL('../build.mjs', import.meta.url), join(tmp, 'real', 'build.mjs'));
      symlinkSync(join(tmp, 'real'), join(tmp, 'link'));
      mkdirSync(join(tmp, 'out'));
      writeFileSync(join(tmp, 'out', 'osv.exit'), '0\n');
      writeFileSync(join(tmp, 'out', 'osv.json'), '{"results":[]}');
      const out = execFileSync(process.execPath, [join(tmp, 'link', 'build.mjs'), join(tmp, 'out'), RUN, COMMIT], { encoding: 'utf8' });
      assert.deepEqual(JSON.parse(out), { status: 'clear', run_url: RUN, commit: COMMIT, findings: [] });
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// readDir reads report.sh's files from <dir>, but the lockfile from where the
// caller named it. It once looked for the lockfile inside <dir>, so every npm
// finding said "can't tell" (null) for direct.
describe('readDir', () => {
  it('finds the npm lockfile relative to the working directory', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'aftercare-'));
    try {
      writeFileSync(join(tmp, 'osv.exit'), '1\n');
      writeFileSync(join(tmp, 'osv.json'), fixture('npm/osv.json'));
      writeFileSync(join(tmp, 'lockfiles.txt'), 'test/fixtures/npm/package-lock.json\n');
      const cwd = process.cwd();
      process.chdir(new URL('..', import.meta.url).pathname);
      let report;
      try { report = buildReport(readDir(tmp), RUN, COMMIT); } finally { process.chdir(cwd); }
      const direct = Object.fromEntries(report.findings.map((f) => [f.package, f.direct]));
      assert.deepEqual(direct, { lodash: true, minimist: false });
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
