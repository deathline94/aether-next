#!/usr/bin/env bash
# POSIX entry point for the invariant gate harness.
# Logic lives once in scripts/verify-invariants.mjs — see the ps1 wrapper's note.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec node "$here/verify-invariants.mjs" "$@"
