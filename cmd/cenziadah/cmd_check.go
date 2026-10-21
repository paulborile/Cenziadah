// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/paulborile/cenziadah/internal/baseline"
	"github.com/paulborile/cenziadah/internal/engine"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/report"
)

func cmdCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	pid := fs.Int("pid", 0, "target process id")
	name := fs.String("name", "", "target process name (comm or argv[0])")
	basePath := fs.String("baseline", "", "known-good snapshot to diff against (optional)")
	asJSON := fs.Bool("json", false, "emit JSON instead of text")
	threshold := fs.String("fail-at", "high", "min severity that sets exit code 1: info|low|medium|high|critical")
	if err := fs.Parse(args); err != nil {
		return exitOpError
	}

	target, err := engine.ResolvePID(*pid, *name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cenziadah: %v\n", err)
		return exitOpError
	}

	var base *model.Snapshot
	if *basePath != "" {
		base, err = baseline.Load(*basePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cenziadah: %v\n", err)
			return exitOpError
		}
		// Note the baseline's provenance so a version/tool mismatch is visible when
		// diagnosing unexpected results.
		if base.ToolVersion != "" && !*asJSON {
			fmt.Fprintf(os.Stderr, "cenziadah: baseline created by %s\n", base.ToolVersion)
		}
	}

	tgt, err := engine.Collect(target, true, base)
	if err != nil {
		if tgt == nil || engine.IsPermission(err) && tgt.Mem == nil {
			// No memory access: fall back to a degraded check that runs every
			// detector EXCEPT module integrity. Warn, but still inspect maps, fds,
			// sockets and the process tree (fail safe, not blind).
			if tgt == nil {
				return reportCollectError(err)
			}
			fmt.Fprintln(os.Stderr, "cenziadah: warning: no memory access (needs CAP_SYS_PTRACE); running without module-integrity check")
		} else {
			return reportCollectError(err)
		}
	}
	if tgt.Mem != nil {
		defer tgt.Mem.Close()
	}

	rep := engine.Run(tgt, engine.AllDetectors())

	if *asJSON {
		if err := report.JSON(os.Stdout, rep); err != nil {
			return exitOpError
		}
	} else {
		report.Text(os.Stdout, rep)
	}

	if rep.MaxSeverity() >= parseSeverity(*threshold) && len(rep.Active()) > 0 {
		return exitFinding
	}
	return exitClean
}

func parseSeverity(s string) model.Severity {
	switch s {
	case "info":
		return model.SevInfo
	case "low":
		return model.SevLow
	case "medium":
		return model.SevMedium
	case "critical":
		return model.SevCritical
	default:
		return model.SevHigh
	}
}
