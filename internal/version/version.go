// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Package version reports build identity for cenziadah. Values are injected at
// build time via -ldflags (see the Makefile); when built without them (e.g. plain
// `go build`/`go install`), it falls back to Go's embedded VCS stamp so the commit
// is still reported.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Version is the semantic version (SemVer: vMAJOR.MINOR.PATCH). It is the single
// source of truth for the released version and is bumped here per SemVer rules.
// Commit/Date are build identifiers shown alongside it, injected via -ldflags; they
// are NOT the version.
const Version = "v0.8.2"

// Injected at build time with -ldflags "-X .../internal/version.Commit=... ".
var (
	Commit = "" // git short sha (build identifier)
	Date   = "" // build date, RFC3339 (build identifier)
)

// Info returns the user-facing version string: semantic version, build date and Go
// version (no commit). This is what `cenziadah version` / `--version` prints.
func Info() string {
	_, _, d := resolve()
	return fmt.Sprintf("cenziadah %s (built %s, %s)", Version, d, runtime.Version())
}

// Full returns the version plus all build identifiers including the commit. Used
// where exact-build provenance matters, e.g. recording which build produced a
// baseline.
func Full() string {
	_, c, d := resolve()
	return fmt.Sprintf("cenziadah %s (commit %s, built %s, %s)", Version, c, d, runtime.Version())
}

// resolve fills in any fields not set by ldflags from the embedded build info.
func resolve() (ver, commit, date string) {
	ver, commit, date = Version, Commit, Date
	if commit == "" || date == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					if commit == "" {
						commit = s.Value
						if len(commit) > 12 {
							commit = commit[:12]
						}
					}
				case "vcs.time":
					if date == "" {
						date = s.Value
					}
				case "vcs.modified":
					if s.Value == "true" {
						commit += "-dirty"
					}
				}
			}
		}
	}
	if commit == "" {
		commit = "unknown"
	}
	if date == "" {
		date = "unknown"
	}
	return
}
