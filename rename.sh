#!/usr/bin/env bash
# Renames the internal package "sentinel" to "hardenforge" inside the current git repo.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
[ -d src/sentinel ] || { echo "src/sentinel not found - already renamed?"; exit 1; }

git mv src/sentinel src/hardenforge
sed -i '/The Python package is still called/d' README.md

files=$(git ls-files | xargs -r grep -Il -iE 'sentinel' || true)
if [ -n "$files" ]; then
  # shellcheck disable=SC2086
  sed -i 's/SentinelHardener AI/HardenForge/g; s/SentinelHardener/HardenForge/g; s/SENTINELHARDENER · BENCHMARK COMPLIANCE/HARDENFORGE · COMPLIANCE AUDIT/g; s/SENTINELHARDENER/HARDENFORGE/g; s/SENTINEL_/HARDENFORGE_/g; s/sentinel/hardenforge/g; s/Sentinel/HardenForge/g' $files
fi

if git ls-files | xargs -r grep -Iil 'sentinel' >/dev/null; then
  echo "WARNING: 'sentinel' still found in:"; git ls-files | xargs -r grep -Iil 'sentinel'
else
  echo "OK: no 'sentinel' left."
fi
git add -A
git status --short
echo "Next: git commit -m 'Rename package from sentinel to hardenforge' && git push"
