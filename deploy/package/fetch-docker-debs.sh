#!/usr/bin/env bash
# =============================================================================
#  Fetch Docker Engine packages for the offline bundle  (INTERNAL — release engineer)
#
#      ./deploy/package/fetch-docker-debs.sh <dest-dir> [codename ...]
#
#  Default codenames: jammy noble — Ubuntu 22.04 and 24.04, the two releases the
#  installer accepts. For each one this reads Docker's own apt index, picks the
#  newest stable version of the four packages install.sh needs (docker-ce,
#  docker-ce-cli, containerd.io, docker-compose-plugin), downloads them, verifies
#  every file against the SHA256 the index publishes, and writes
#  <dest>/<codename>/SHA256SUMS and VERSIONS beside them.
#
#  WHY
#
#  The offline archive promised "no network needed" and did not deliver it: the
#  one thing every step depends on — Docker — had to come from the internet, via
#  `curl get.docker.com | sh`. The first real install (2026-09-17) stalled there,
#  on a host with a stale cdrom apt source. With these packages in the bundle,
#  install.sh provisions Docker with dpkg and the archive is offline in fact.
#
#  Runs on the RELEASE ENGINEER's machine, which has internet. Never shipped.
# =============================================================================
set -euo pipefail

DEST="${1:?usage: $0 <dest-dir> [codename ...]}"; shift || true
CODENAMES=("$@")
[[ ${#CODENAMES[@]} -gt 0 ]] || CODENAMES=(jammy noble)

BASE="https://download.docker.com/linux/ubuntu"
PKGS=(docker-ce docker-ce-cli containerd.io docker-compose-plugin)

if [[ -t 1 ]]; then G=$'\e[92m'; R=$'\e[0m'; RED=$'\e[91m'; else G=''; R=''; RED=''; fi
die() { printf '  %s✗ %s%s\n' "$RED" "$*" "$R" >&2; exit 1; }
command -v curl >/dev/null || die "curl is required"
command -v sha256sum >/dev/null || die "sha256sum is required"

# Newest version of one package from a Debian Packages index: TAB-separated
# "version filename sha256". Stanzas are blank-line separated; `sort -V` orders
# Debian versions well enough within one epoch, which is all one index has.
newest() { # newest PACKAGE <<< "$INDEX"
  awk -v p="$1" 'BEGIN { RS = ""; FS = "\n" }
    { pk = ""; v = ""; f = ""; s = ""
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^Package: /)  pk = substr($i, 10)
        if ($i ~ /^Version: /)  v  = substr($i, 10)
        if ($i ~ /^Filename: /) f  = substr($i, 11)
        if ($i ~ /^SHA256: /)   s  = substr($i, 9)
      }
      if (pk == p && v != "" && f != "" && s != "") print v "\t" f "\t" s }' \
    | sort -t $'\t' -k1,1V | tail -1
}

for cn in "${CODENAMES[@]}"; do
  printf '  fetching Docker Engine for Ubuntu %s…\n' "$cn"
  INDEX="$(curl -fsSL --max-time 60 --retry 3 "$BASE/dists/$cn/stable/binary-amd64/Packages")" \
    || die "cannot read Docker's package index for $cn"
  OUT="$DEST/$cn"
  mkdir -p "$OUT"
  : > "$OUT/SHA256SUMS"; : > "$OUT/VERSIONS"
  for p in "${PKGS[@]}"; do
    line="$(newest "$p" <<<"$INDEX")"
    [[ -n "$line" ]] || die "no '$p' in Docker's $cn index"
    ver="${line%%$'\t'*}"; rest="${line#*$'\t'}"; file="${rest%%$'\t'*}"; sha="${rest#*$'\t'}"
    name="$(basename "$file")"
    if [[ ! -f "$OUT/$name" ]]; then
      curl -fsSL --max-time 900 --retry 3 --retry-delay 5 -o "$OUT/$name.part" "$BASE/$file" \
        || die "download failed: $BASE/$file"
      mv "$OUT/$name.part" "$OUT/$name"
    fi
    printf '%s  %s\n' "$sha" "$name" >> "$OUT/SHA256SUMS"
    printf '%s %s\n' "$p" "$ver" >> "$OUT/VERSIONS"
  done
  # Stale files from an earlier fetch of a different version would otherwise ride
  # along unverified and dpkg -i would install whichever it met first.
  find "$OUT" -maxdepth 1 -name '*.deb' | while read -r f; do
    grep -qF "  $(basename "$f")" "$OUT/SHA256SUMS" || rm -f "$f"
  done
  ( cd "$OUT" && sha256sum -c --quiet SHA256SUMS ) || die "checksum mismatch in $OUT — refusing to ship it"
  printf '  %s✓%s %s: %s (%s)\n' "$G" "$R" "$cn" \
    "$(awk '$1 == "docker-ce" {print "docker-ce " $2}' "$OUT/VERSIONS")" "$(du -sh "$OUT" | cut -f1)"
done
