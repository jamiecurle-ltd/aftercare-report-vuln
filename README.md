# aftercare-report-vuln

A GitHub/Forgejo Action that checks your locked dependencies for known
vulnerabilities and reports them to [Aftercare](https://aftercare.jamiecurle.ltd),
the dashboard where [jamiecurle.ltd](https://jamiecurle.ltd) looks after your
sites. Add it to a nightly workflow and your sites' vulnerabilities column
stays current, including advisories published after your last push.

```yaml
- name: Report to Aftercare
  if: ${{ !cancelled() }}
  uses: jamiecurle-ltd/aftercare-report-vuln@<commit sha> # v1
  with:
    token: ${{ secrets.AFTERCARE_TOKEN }}
    lockfile: mix.lock
```

On Forgejo, use the full URL:
`uses: https://github.com/jamiecurle-ltd/aftercare-report-vuln@<commit sha> # v1`.

## For code owners: what it does

It's one shell script (`report.sh`) and one Node script (`build.mjs`), with no
dependencies, both short enough to read before you adopt it.

1. It downloads [OSV-Scanner](https://github.com/google/osv-scanner) at a fixed
   version, and checks its SHA-256 before running it.
2. It scans the lockfiles you name. OSV-Scanner reads them locally and asks
   [osv.dev](https://osv.dev) about the package names and versions in them.
3. It sends a report to Aftercare: for each advisory, the package, its version,
   the advisory's id, title and severity, and the fixed version. It also sends
   the commit SHA and a link to the workflow run. **Nothing else leaves your
   CI: no source code, no other files, no environment.**
   [CONTRACT.md](CONTRACT.md) is the exact format.

It only reads. It never changes your code, lockfiles or dependencies, and it
needs no permissions on your repository.

**The token** is issued by jamiecurle.ltd for this one repository. It can only
report this repository's dependency audit: it can't read anything from
Aftercare or report for anyone else. Keep it in a secret. If it leaks, ask for
a new one, and the old one stops working at once.

**Failures are visible.** If the scan can't run, Aftercare is told the audit
failed, never that it's clear. If Aftercare refuses the report, the step
fails. Aftercare also flags a repository that hasn't reported in 36 hours.
Put the step last, with `if: ${{ !cancelled() }}`, so it runs even when an
earlier audit step failed, and so a failure here doesn't stop your own checks.

## Inputs

| Input | Required | |
|---|---|---|
| `token` | yes | This repository's Aftercare token, from a secret. |
| `lockfile` | yes | The lockfile(s) to scan, one per line: `mix.lock`, `package-lock.json`, `poetry.lock`, `composer.lock`, `Gemfile.lock`, `go.sum`, `Cargo.lock`, and [anything else OSV-Scanner reads](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/). |
| `hex-retired` | no | Elixir: also report retired Hex packages, from `mix hex.audit`. Needs Elixir set up and `mix deps.get` run before this step. Default `false`. |
| `url` | no | Aftercare's address. Only for testing. |
| `run-url`, `commit` | no | Defaults to this run and its commit. |

**Needs:** bash, curl and Node 20 or newer on the runner, Linux (x64 or arm64)
or macOS. GitHub's hosted runners have all of them. A Forgejo `docker` runner
needs them in its image, e.g. `apt-get install -y nodejs curl ca-certificates`.

**Direct or transitive:** worked out from `package-lock.json` for npm, and from
`mix deps.tree` for Elixir when mix is available. For other ecosystems the
report says it can't tell.

## Examples

A nightly workflow for an Elixir app, on GitHub:

```yaml
name: Audit
on:
  schedule:
    - cron: "17 6 * * *"
  workflow_dispatch:
permissions:
  contents: read
jobs:
  audit:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha> # v7
      - uses: erlef/setup-beam@<sha> # v1
        with:
          version-file: .tool-versions
          version-type: strict
      - run: mix deps.get
      - name: Report to Aftercare
        if: ${{ !cancelled() }}
        uses: jamiecurle-ltd/aftercare-report-vuln@<sha> # v1
        with:
          token: ${{ secrets.AFTERCARE_TOKEN }}
          lockfile: mix.lock
          hex-retired: true
```

A Node app is the same without the Elixir steps, and `lockfile: package-lock.json`.

## Development

```sh
node --test test/build.test.mjs
```

CI (`.github/workflows/test.yml`) runs the unit tests on Node 20 and 24. It
then runs the action itself (`uses: ./`) on Linux x64, Linux arm64 and macOS,
and with Elixir for `hex-retired`, against `test/fake-aftercare.mjs`. That
stand-in Aftercare checks every report against the contract and the token, as
the real one does. The fixtures are real OSV-Scanner output; most of their
size is advisory text.

To update OSV-Scanner, change `OSV_VERSION` and all four checksums in
`report.sh` from the release's `osv-scanner_SHA256SUMS` file.

The Aftercare side lives in the fredo repository (`app/src/ingest.ts`), which
holds the authoritative version of [CONTRACT.md](CONTRACT.md)'s rules.
