// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Package detector holds the Detector interface and the per-technique detectors.
// Each detector is a black box: it receives an already-populated *Target (parsed
// procfs structs) and emits []model.Finding. Because the target is plain data,
// every detector is unit-testable with synthetic fixtures and no root.
package detector

import (
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/procfs"
)

// Target is the already-collected, read-only view of a process that detectors
// inspect. The engine populates it once (via procfs) and hands the same snapshot
// to every detector, so detectors never touch /proc themselves.
type Target struct {
	Desc     model.TargetDesc
	Regions  []procfs.Region
	FDs      []procfs.FD
	Sockets  []procfs.Socket
	Children []procfs.Child

	// Mem is an open handle for detectors that must read process memory
	// (module integrity). May be nil in unit tests that don't need it.
	Mem *procfs.Mem

	// InteractiveShell: the target is a legitimate interactive terminal shell
	// (set by the all-process scanner only: terminal-shell shape AND launched
	// the expected way). Its new children are commands a person typed.
	InteractiveShell bool

	// ScheduledJob, when set, names the root-configured job (a cron job) this
	// process belongs to: started by it, or descended from it. What it starts is
	// the job's own work. Set by the all-process scanner.
	ScheduledJob string

	// Baseline is the known-good reference, or nil for a baseline-less check
	// (only absolute detectors run in that case).
	Baseline *model.Snapshot
}

// Detector inspects a Target and reports findings.
type Detector interface {
	// Name is a short stable identifier used in logs and --detectors selection.
	Name() string
	// Inspect runs the detection and returns findings (including any it chose to
	// mark Suppressed). It returns an error only for operational failures, not
	// for "found something" — findings are the normal output.
	Inspect(t *Target) ([]model.Finding, error)
}
