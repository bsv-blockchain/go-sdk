#!/usr/bin/env bash
# Refresh the pinned ts-stack conformance vector snapshot used by internal/conformance.
#
# Usage: scripts/sync-conformance-vectors.sh [path-to-ts-stack-checkout]
#
# The ts-stack checkout defaults to ../ts-stack. The snapshot records the
# source commit in internal/conformance/testdata/SOURCE.json so reviewers can
# diff the corpus against upstream.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ts_stack="${1:-${repo_root}/../ts-stack}"
src="${ts_stack}/conformance/vectors"
dst="${repo_root}/internal/conformance/testdata/vectors"

if [[ ! -d "${src}" ]]; then
	echo "ts-stack conformance vectors not found at ${src}" >&2
	exit 1
fi

commit="$(git -C "${ts_stack}" rev-parse HEAD)"
if [[ -n "$(git -C "${ts_stack}" status --porcelain -- conformance/vectors)" ]]; then
	echo "refusing to snapshot: ${src} has uncommitted changes" >&2
	exit 1
fi

mkdir -p "${dst}"
rsync -a --delete --exclude README.md --exclude .DS_Store "${src}/" "${dst}/"

# Upstream files do not always end with a newline; the repo's pre-commit eof
# check requires one.
find "${dst}" -type f -name '*.json' -print0 | while IFS= read -r -d '' f; do
	if [[ -s "${f}" && -n "$(tail -c1 "${f}")" ]]; then
		printf '\n' >>"${f}"
	fi
done

cat >"${repo_root}/internal/conformance/testdata/SOURCE.json" <<EOF
{
  "repository": "https://github.com/bsv-blockchain/ts-stack",
  "path": "conformance/vectors",
  "commit": "${commit}"
}
EOF

echo "synced $(find "${dst}" -type f -name '*.json' | wc -l | tr -d ' ') vector files from ts-stack@${commit}"
