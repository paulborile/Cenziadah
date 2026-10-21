#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Paul Borile
#
# deb: postinst configure [<old-version>]   rpm: %post <1=install|2=upgrade>
# The service is never enabled or started automatically: at start cenziadah
# learns its baseline from the host's current state, so the admin chooses when.
set -e
have_systemd() { command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; }

first_install=no
case "$1" in
    configure) [ -z "$2" ] && first_install=yes ;;
    1) first_install=yes ;;
esac

if have_systemd; then
    systemctl daemon-reload || true
    if [ "$first_install" = no ] && systemctl is-active --quiet cenziadah-watch.service; then
        # upgrade: restart only if it was running (it re-learns its baseline),
        # and say so loudly if it does not come back (e.g. a bad option in
        # /etc/default/cenziadah): the host would be unmonitored.
        if ! systemctl try-restart cenziadah-watch.service; then
            cat >&2 <<'MSG'
WARNING: cenziadah-watch failed to restart; this host is NOT monitored.
  Check the options:  /usr/bin/cenziadah watch --check-config <CENZIADAH_ARGS from /etc/default/cenziadah>
  Details:            journalctl -u cenziadah-watch -n 20
MSG
        fi
    fi
fi

if [ "$first_install" = yes ]; then
    cat <<'MSG'
cenziadah installed. To start monitoring:
  1. edit /etc/default/cenziadah (e.g. add --mail-to you@example.com)
  2. systemctl enable --now cenziadah-watch
Events: journalctl -u cenziadah-watch -o cat
MSG
fi
exit 0
