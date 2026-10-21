#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Paul Borile
#
# deb: prerm remove|upgrade|...   rpm: %preun <0=remove|1=upgrade>
# Stop and disable only on removal, not on upgrade.
set -e
case "$1" in
    remove|purge|0)
        if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            systemctl disable --now cenziadah-watch.service >/dev/null 2>&1 || true
        fi
        ;;
esac
exit 0
