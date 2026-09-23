#!/usr/bin/env bash
# Flatten the artifacts the build jobs uploaded into one release directory and
# write the checksum manifest that goes with them.
#
# This logic used to live inline in build.yml's "Pack + checksums" step, which is
# why nothing tested it: a shell body pasted into YAML cannot be executed by
# anyone until a release runs it, and a release runs once per tag. The step was in
# fact broken — it wrote a `.sha256` sidecar per payload and then generated the
# manifest with `sha256sum ./*`, which globs the sidecars too, so the manifest
# listed 2N lines for N payloads while the count immediately below it demanded N.
# The publish job could therefore never pass, on every branch and every tag, and
# the only evidence anyone had that the manifest was "verified" was a comment.
#
# Three rules now keep that from coming back:
#   1. The manifest is generated from the payload list, never from a glob of the
#      directory afterwards, so a sidecar cannot enter it by accident.
#   2. Manifest and directory are compared *both ways* — a payload with no
#      manifest line and a manifest line with no payload are both errors, and so
#      is a duplicate line, because `sha256sum -c` reports only the last verdict
#      it reads for a repeated name.
#   3. The manifest and the sidecars are verified separately. A sidecar is an
#      independent statement of one payload's digest; checking only the manifest
#      ships a corrupt sidecar, checking only the sidecars leaves the file people
#      actually diff unwatched.
#
# Usage:
#   pack-checksums.sh [--src DIR] [--out DIR]     # pack + checksum + verify
#   pack-checksums.sh --verify-only DIR           # re-verify a directory as-is
set -euo pipefail

MODE=pack
SRC=dist
OUT=out

die() {
  echo "::error::pack-checksums: $*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --src) [ $# -ge 2 ] || die "--src needs a directory"; SRC=$2; shift 2 ;;
    --out) [ $# -ge 2 ] || die "--out needs a directory"; OUT=$2; shift 2 ;;
    --verify-only)
      MODE=verify
      [ $# -ge 2 ] || die "--verify-only needs a directory"
      OUT=$2
      shift 2
      ;;
    -h | --help)
      sed -n '2,32p' "$0"
      exit 0
      ;;
    *) die "unknown argument '$1' (want --src, --out, --verify-only)" ;;
  esac
done

# The payload extensions are the contract between the build jobs and the release:
# anything else in `dist/` is job scaffolding and must not reach a user.
PAYLOAD_GLOBS=(-name '*.exe' -o -name '*.zip' -o -name '*.apk')

# Every payload in the current directory, as `./name`, sorted, one per line. The
# manifest's own name and the sidecars are excluded by rule, not by hoping that
# they happen to be absent.
list_payloads() {
  local f
  for f in ./*; do
    [ -f "$f" ] || continue
    case "$f" in
    ./SHA256SUMS.txt) continue ;;
    ./*.sha256) continue ;;
    esac
    printf '%s\n' "$f"
  done | LC_ALL=C sort
}

# The names the manifest claims, as they are written in it, sorted. A `sha256sum`
# built for Windows marks binary mode with a leading `*` on the name; the digest is
# the same either way, so the name is normalised before it is compared.
list_manifest() {
  awk 'NF >= 2 { name = $2; sub(/^\*/, "", name); print name }' SHA256SUMS.txt | LC_ALL=C sort
}

# ── pack ─────────────────────────────────────────────────────────────────────
if [ "$MODE" = pack ]; then
  [ -d "$SRC" ] || die "no $SRC/ to pack (download-artifact writes the payloads there)"
  mkdir -p "$OUT"

  # Flattening `dist/**` used to be `cp -v {} out/`, which silently overwrote when
  # two payloads share a basename; refuse instead of shipping the last one visited.
  find "$SRC" -type f \( "${PAYLOAD_GLOBS[@]}" \) | LC_ALL=C sort >"$SRC.pack-list"
  while IFS= read -r f; do
    b="$(basename "$f")"
    if [ -e "$OUT/$b" ]; then
      die "two artifacts flatten to $OUT/$b - existing file vs '$f'"
    fi
    cp -v "$f" "$OUT/$b"
  done <"$SRC.pack-list"
  rm -f "$SRC.pack-list"
fi

[ -d "$OUT" ] || die "$OUT/ does not exist"
cd "$OUT"

mapfile -t PAYLOADS < <(list_payloads)
[ ${#PAYLOADS[@]} -gt 0 ] ||
  die "$OUT/ holds no payload: refusing to publish an empty manifest"

if [ "$MODE" = pack ]; then
  # One sidecar per payload, and the manifest over the same explicit list. `./name`
  # rather than `*` because a basename beginning with a dash would otherwise be
  # read as an option by sha256sum.
  : >SHA256SUMS.txt
  for f in "${PAYLOADS[@]}"; do
    sha256sum "$f" | tee "$f.sha256" >>SHA256SUMS.txt
  done
fi

test -s SHA256SUMS.txt || die "$OUT/SHA256SUMS.txt is missing or empty"

# ── verify ───────────────────────────────────────────────────────────────────
# Manifest and directory must describe exactly the same set of files.
mapfile -t ON_DISK < <(list_payloads)
mapfile -t IN_MANIFEST < <(list_manifest)
if [ "$(printf '%s\n' "${ON_DISK[@]}")" != "$(printf '%s\n' "${IN_MANIFEST[@]}")" ]; then
  diff -u <(printf '%s\n' "${ON_DISK[@]}") <(printf '%s\n' "${IN_MANIFEST[@]}") |
    sed 's/^/  /' >&2 || true
  die "SHA256SUMS.txt and $OUT/ disagree (left: on disk, right: in the manifest)"
fi

# Every payload named exactly once, and no line pointing at something else.
for f in "${ON_DISK[@]}"; do
  hits=$(awk -v n="$f" '{ g = $2; sub(/^\*/, "", g); if (g == n) c += 1 } END { print c + 0 }' SHA256SUMS.txt)
  [ "$hits" = "1" ] || die "$f appears $hits time(s) in SHA256SUMS.txt, expected exactly once"
done
lines=$(grep -c . SHA256SUMS.txt)
[ "$lines" = "${#ON_DISK[@]}" ] ||
  die "SHA256SUMS.txt lists $lines digest line(s) for ${#ON_DISK[@]} payload(s)"

# Sidecars: present, one per payload, each correct on its own terms.
for f in "${ON_DISK[@]}"; do
  [ -f "$f.sha256" ] || die "$f has no $f.sha256 sidecar"
  sha256sum -c --quiet "$f.sha256" || die "$f.sha256 does not verify against $f"
done
sidecars=$(find . -maxdepth 1 -name '*.sha256' | wc -l)
[ "$sidecars" = "${#ON_DISK[@]}" ] ||
  die "$sidecars per-file .sha256 sidecars for ${#ON_DISK[@]} payload(s)"

# The manifest as a whole, over the bytes a user will download.
sha256sum -c --quiet SHA256SUMS.txt || die "SHA256SUMS.txt does not verify"

echo "pack-checksums: ${#ON_DISK[@]} payload(s), $lines manifest line(s), $sidecars sidecar(s) - all verified"

# ── release metadata (the publish step's outputs) ────────────────────────────
[ "$MODE" = pack ] || exit 0

REF=${GITHUB_REF:-refs/heads/main}
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  if [ "${REF#refs/tags/}" != "$REF" ]; then
    {
      echo "tag=${GITHUB_REF_NAME:-${REF##*/}}"
      echo "title=${GITHUB_REF_NAME:-${REF##*/}}"
      echo "prerelease=false"
    } >>"$GITHUB_OUTPUT"
  else
    {
      echo "tag=latest"
      echo "title=Latest build"
      echo "prerelease=true"
    } >>"$GITHUB_OUTPUT"
  fi
else
  echo "pack-checksums: GITHUB_OUTPUT is unset, skipping the tag/title/prerelease outputs"
fi
