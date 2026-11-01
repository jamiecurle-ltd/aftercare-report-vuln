# The report

What this action sends to Aftercare. Aftercare checks every rule here and
refuses anything else, so a repository can't send it anything unexpected.
`test/contract.mjs` checks the same rules in this repo's tests.

```
POST https://aftercare.jamiecurle.ltd/ingest/vulns
Authorization: Bearer <the repository's token>
Content-Type: application/json
```

```json
{
  "status": "vulnerable",
  "run_url": "https://github.com/example/app/actions/runs/123",
  "commit": "<the 40-character SHA scanned>",
  "findings": [
    {
      "id": "GHSA-xvch-5gv4-984h",
      "package": "minimist",
      "version": "1.2.5",
      "fixed_in": "1.2.6",
      "severity": "critical",
      "cvss": 9.8,
      "title": "Prototype Pollution in minimist",
      "direct": false,
      "ecosystem": "npm"
    }
  ]
}
```

## Rules

- **Exact fields.** A missing or unknown field, at the top or in a finding, is
  refused.
- **`status`:**
  - `clear`: the scan ran and found nothing. `findings` is empty.
  - `vulnerable`: at least one finding.
  - `error`: the scan couldn't run. `findings` is empty, and Aftercare keeps
    showing the last known findings, marked as from a failing audit.
- **`run_url`:** https, at most 512 characters.
- **`commit`:** 7 to 64 lower-case hex characters.
- **`findings`:** at most 500. The whole body is at most 64 KB, which in
  practice is reached at about 200 findings.
- **Each finding:**
  - **`id`:** the advisory, preferring its GHSA id. Printable ASCII, no
    spaces, at most 64 characters. A retired Hex package is
    `RETIRED-<package>`.
  - **`package`:** at most 214 characters. **`version`:** at most 64.
    **`title`:** at most 300.
  - **`fixed_in`:** the lowest fixed version above the installed one, or
    `null` if there isn't one yet. Taken only from version ranges, never a
    commit hash.
  - **`severity`:** from the CVSS score. 9.0 and above is `critical`,
    7.0–8.9 `high`, 4.0–6.9 `medium`, 0.1–3.9 `low`, and with no score,
    `unknown`.
  - **`cvss`:** a number from 0 to 10, or `null`.
  - **`direct`:** `true` or `false`, or `null` when it can't be told.
  - **`ecosystem`:** OSV's name, lower-cased, using only `a-z 0-9 . : -`
    (`npm`, `hex`, `pypi`, `crates.io`, `debian:12`).
- **No duplicates:** the same `id`, `package` and `version` appears at most
  once.

## Responses

- **204:** stored. It replaces the repository's previous report.
- **400:** the report broke a rule above.
- **401:** the token is missing, wrong or revoked. All of these get the same
  answer.

If no `clear` or `vulnerable` report arrives for 36 hours, Aftercare marks the
repository stale.
