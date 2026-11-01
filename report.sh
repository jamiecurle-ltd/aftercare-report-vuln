#!/usr/bin/env bash
# The action's one step (action.yml). Scans the lockfiles with OSV-Scanner,
# builds the report (build.mjs) and POSTs it to Aftercare.
#
# Everything comes in through the environment, set by action.yml from its
# inputs: AFTERCARE_TOKEN, LOCKFILES (one per line), AFTERCARE_URL,
# HEX_RETIRED (true/false), and RUN_URL / COMMIT (default: this run).
# Runs from the caller's working directory, so lockfile paths are theirs.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
: "${AFTERCARE_TOKEN:?the token input is required}" "${LOCKFILES:?the lockfile input is required}"
url="${AFTERCARE_URL:-https://aftercare.jamiecurle.ltd}/ingest/vulns"
commit="${COMMIT:-${GITHUB_SHA:-}}"
# Forgejo numbers runs in its URLs; GitHub uses the run id.
if [[ -n ${FORGEJO_ACTIONS:-}${GITEA_ACTIONS:-} ]]; then run="${GITHUB_RUN_NUMBER:-}"; else run="${GITHUB_RUN_ID:-}"; fi
run_url="${RUN_URL:-${GITHUB_SERVER_URL:-}/${GITHUB_REPOSITORY:-}/actions/runs/${run}}"

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT

# OSV-Scanner, pinned by version and checksum. From the release's
# osv-scanner_SHA256SUMS file: update all four together.
OSV_VERSION=v2.7.0
case "$(uname -s)-$(uname -m)" in
  Linux-aarch64|Linux-arm64) PLATFORM=linux_arm64;  SHA=4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7 ;;
  Linux-x86_64)              PLATFORM=linux_amd64;  SHA=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b ;;
  Darwin-arm64)              PLATFORM=darwin_arm64; SHA=d4926ef8da134332543be276dff157e4c170f99ad91fc48e89448a8816bdf70b ;;
  Darwin-x86_64)             PLATFORM=darwin_amd64; SHA=e82c5df7ab0a42dff29a1cd0660711447b56b4c0483ff66ad8634df10fd81a45 ;;
  *) PLATFORM="" ;;
esac

args=()
while IFS= read -r lockfile; do
  lockfile="${lockfile#"${lockfile%%[![:space:]]*}"}"; lockfile="${lockfile%"${lockfile##*[![:space:]]}"}" # trim
  [[ -z $lockfile ]] && continue
  if [[ ! -f $lockfile ]]; then echo "::warning::lockfile not found: $lockfile"; continue; fi
  args+=("--lockfile=$lockfile")
  echo "$lockfile" >> "$dir/lockfiles.txt"
done <<< "$LOCKFILES"

osv="$dir/osv-scanner"
if [[ -z $PLATFORM ]]; then
  echo "::warning::OSV-Scanner has no build for $(uname -s)-$(uname -m): reporting an error"
elif [[ ${#args[@]} -eq 0 ]]; then
  echo "::warning::no lockfiles to scan: reporting an error"
elif curl -fsSL -o "$osv" "https://github.com/google/osv-scanner/releases/download/${OSV_VERSION}/osv-scanner_${PLATFORM}" \
  && { echo "${SHA}  ${osv}" | sha256sum -c - >/dev/null 2>&1 || echo "${SHA}  ${osv}" | shasum -a 256 -c - >/dev/null 2>&1; }; then
  chmod +x "$osv"
  # Exit 0: nothing found. 1: something found. Anything else: it didn't run,
  # and build.mjs reports 'error'.
  "$osv" scan source "${args[@]}" --format json --output-file "$dir/osv.json" 2>&1 | tail -5
  echo "${PIPESTATUS[0]}" > "$dir/osv.exit"
else
  echo "::warning::OSV-Scanner download failed, or its checksum didn't match: reporting an error"
fi

# Hex extras, when there's a mix.lock and mix to ask. Mix runs in the
# lock's own directory (its project), wherever the workflow is.
mix_lock=$(grep -m1 'mix.lock$' "$dir/lockfiles.txt" 2>/dev/null)
if [[ -n $mix_lock ]] && command -v mix >/dev/null 2>&1; then
  project=$(dirname "$mix_lock")
  (cd "$project" && mix deps.tree --format plain) > "$dir/mix-deps-tree.txt" 2>/dev/null || rm -f "$dir/mix-deps-tree.txt"
  if [[ ${HEX_RETIRED:-false} == true ]]; then
    (cd "$project" && mix hex.audit) > "$dir/hex-retired.txt" 2>&1 || true
  fi
elif [[ ${HEX_RETIRED:-false} == true ]]; then
  echo "::warning::hex-retired needs a mix.lock and mix on the PATH: skipping retired packages"
fi

payload=$(node "$here/build.mjs" "$dir" "$run_url" "$commit") || exit 1
echo "Reporting to Aftercare: $(node -e 'const r = JSON.parse(process.argv[1]); console.log(r.status + ",", r.findings.length, "findings")' "$payload")"

# The token goes in a header read from a file descriptor, so it never appears
# on a command line (printf is a shell builtin, not a process).
curl --fail-with-body -sS -X POST "$url" \
  -H "content-type: application/json" \
  -H @<(printf 'authorization: Bearer %s\n' "$AFTERCARE_TOKEN") \
  --data-binary "$payload"
