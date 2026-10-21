#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Paul Borile
#
# check-all-containers.sh — run a cenziadah integrity check on the main process of
# every running Docker container, against the baseline "<container>-czd.json" in the
# current directory (as produced by baseline-all-containers.sh).
#
# Intended for cron / periodic monitoring on the HOST:
#     sudo ./scripts/check-all-containers.sh || logger -t cenziadah "INTEGRITY ALERT"
#
# Exit status: 0 if every checked container is clean; non-zero if ANY container has
# active findings, is missing a baseline, or could not be checked. Per-container
# results are printed; non-clean reports are shown in full.
set -u

# Resolve the cenziadah binary: explicit $CENZIADAH, else one on PATH (production),
# else ./bin/cenziadah (dev checkout).
if [ -n "${CENZIADAH:-}" ]; then
  :
elif command -v cenziadah >/dev/null 2>&1; then
  CENZIADAH="$(command -v cenziadah)"
else
  CENZIADAH="./bin/cenziadah"
fi

die() { echo "error: $*" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || die "docker not found in PATH"
command -v "$CENZIADAH" >/dev/null 2>&1 || [ -x "$CENZIADAH" ] || die "cenziadah not found/executable: $CENZIADAH"

mapfile -t CIDS < <(docker ps -q)
if [ "${#CIDS[@]}" -eq 0 ]; then
  echo "no running containers found"
  exit 0
fi

problems=0
clean=0
for cid in "${CIDS[@]}"; do
  name=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's#^/##')
  pid=$(docker inspect --format '{{.State.Pid}}' "$cid" 2>/dev/null)
  [ -z "$name" ] && name="$cid"
  base="${name}-czd.json"

  if [ -z "$pid" ] || [ "$pid" = "0" ]; then
    echo "SKIP  $name: no host pid" >&2; problems=$((problems+1)); continue
  fi
  if [ ! -f "$base" ]; then
    echo "NOBASE $name: missing baseline $base (run baseline-all-containers.sh)" >&2
    problems=$((problems+1)); continue
  fi

  # cenziadah exit codes: 0 clean, 1 findings at/above threshold, 2 operational.
  report=$("$CENZIADAH" check --pid "$pid" --baseline "$base" 2>&1)
  rc=$?
  case "$rc" in
    0) echo "CLEAN $name (pid $pid)"; clean=$((clean+1)) ;;
    1) echo "ALERT $name (pid $pid): active findings"; echo "$report" | sed 's/^/        /'; problems=$((problems+1)) ;;
    *) echo "ERROR $name (pid $pid): $report" >&2; problems=$((problems+1)) ;;
  esac
done

echo "checked: $clean clean, $problems problem(s)"
[ "$problems" -eq 0 ]
