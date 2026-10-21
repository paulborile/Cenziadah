#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Paul Borile
#
# baseline-all-containers.sh — snapshot the main process of every running Docker
# container, producing one cenziadah baseline per container in the CURRENT directory
# named "<container>-czd.json".
#
# Run this AFTER a stack restart, once the containers have settled, e.g.:
#     docker compose up -d && sleep 5 && sudo ./scripts/baseline-all-containers.sh
#
# cenziadah runs on the HOST (not inside the containers): it needs host /proc and
# CAP_SYS_PTRACE, so this script must run as root (or the binary must have
# cap_sys_ptrace,cap_dac_read_search). It targets each container's main process by
# its HOST pid (docker inspect .State.Pid).
#
# Exit status: 0 if every container was baselined; non-zero if any failed (each
# failure is warned, the rest still run).
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
command -v "$CENZIADAH" >/dev/null 2>&1 || [ -x "$CENZIADAH" ] || die "cenziadah not found/executable: $CENZIADAH (set CENZIADAH=/path, or put cenziadah on PATH)"

# Warn early if we almost certainly lack the privilege to read other procs' memory.
if [ "$(id -u)" -ne 0 ] && [ -f "$CENZIADAH" ] && ! getcap "$CENZIADAH" 2>/dev/null | grep -q cap_sys_ptrace; then
  echo "warning: not root and $CENZIADAH lacks cap_sys_ptrace; snapshots will likely fail" >&2
fi

mapfile -t CIDS < <(docker ps -q)
if [ "${#CIDS[@]}" -eq 0 ]; then
  echo "no running containers found"
  exit 0
fi

failed=0
done=0
for cid in "${CIDS[@]}"; do
  name=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's#^/##')
  pid=$(docker inspect --format '{{.State.Pid}}' "$cid" 2>/dev/null)

  if [ -z "$name" ]; then name="$cid"; fi
  if [ -z "$pid" ] || [ "$pid" = "0" ]; then
    echo "SKIP  $name: no host pid (not running?)" >&2
    failed=$((failed+1))
    continue
  fi

  out="${name}-czd.json"
  if "$CENZIADAH" snapshot --pid "$pid" -o "$out" >/dev/null 2>&1; then
    # A 0-module baseline means no library .text could be resolved/digested — the
    # silent-failure case (e.g. unresolved container paths). Treat it as a failure
    # so module integrity isn't quietly left unarmed.
    mods=$(grep -c '"disk_text_sha256"' "$out" 2>/dev/null)
    mods=${mods:-0}
    if [ "$mods" -eq 0 ]; then
      echo "WARN  $name (pid $pid) -> $out  [0 modules — module integrity NOT armed]" >&2
      failed=$((failed+1))
    else
      echo "OK    $name (pid $pid) -> $out  [$mods modules]"
      done=$((done+1))
    fi
  else
    echo "FAIL  $name (pid $pid): snapshot failed" >&2
    failed=$((failed+1))
  fi
done

echo "baselined $done container(s); $failed failure(s)"
[ "$failed" -eq 0 ]
