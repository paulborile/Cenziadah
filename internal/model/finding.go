// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Package model holds the core data primitives that flow through cenziadah:
// Findings (what detectors emit), Snapshots (the known-good baseline), and the
// assembled Report. It has ZERO dependencies on any other internal package so
// every other package can speak this shared vocabulary without import cycles.
package model

import "time"

// Severity ranks how serious a Finding is.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

// String renders a Severity for human output.
func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "INFO"
	case SevLow:
		return "LOW"
	case SevMedium:
		return "MEDIUM"
	case SevHigh:
		return "HIGH"
	case SevCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Technique identifies which detector produced a Finding and what class of
// tampering it represents. New detectors add new constants here; existing ones
// never change, so stored incidents stay interpretable.
type Technique string

const (
	TechMapsRWX            Technique = "maps.rwx"
	TechMapsAnonExec       Technique = "maps.anon_exec"
	TechMapsDeletedBacking Technique = "maps.deleted_backing"
	TechModuleTextMismatch Technique = "module.text_mismatch"
	TechModuleBuildIDDiff  Technique = "module.build_id_diff"
	TechUnexpectedChild    Technique = "proctree.unexpected_child"
	TechSensitiveFD        Technique = "fd.sensitive_path"
	TechUnexpectedDest     Technique = "net.unexpected_dest"
)

// Finding is the unit of output. A detector emits one per anomaly it sees.
//
// Suppressed is first-class on purpose: a detector never silently drops a flag.
// When something looks anomalous but matches a known-good allow-list (e.g. an
// ART JIT region), it is recorded with Suppressed=true and a SuppressReason so
// the decision stays auditable rather than invisible.
type Finding struct {
	Technique      Technique      `json:"technique"`
	Severity       Severity       `json:"severity"`
	PID            int            `json:"pid"`
	Title          string         `json:"title"`
	Detail         string         `json:"detail,omitempty"`
	Evidence       map[string]any `json:"evidence,omitempty"`
	Suppressed     bool           `json:"suppressed,omitempty"`
	SuppressReason string         `json:"suppress_reason,omitempty"`
}

// Report is the full result of one check: the target it inspected, when, and
// every Finding produced (including suppressed ones, for auditability).
type Report struct {
	Target    TargetDesc `json:"target"`
	CheckedAt time.Time  `json:"checked_at"`
	Findings  []Finding  `json:"findings"`
	// Degraded, when set, says why some detectors could not run (e.g. no
	// /proc/<pid>/mem access), so a clean result is not mistaken for a full one.
	Degraded string `json:"degraded,omitempty"`
	// Baseline says what the verdict was measured against (all-process mode;
	// empty for a single-process check).
	Baseline BaselineState `json:"baseline,omitempty"`
}

// BaselineState is how a process relates to the known-good baseline.
type BaselineState string

const (
	// BaselineChecked: compared against a baseline learned in an earlier sweep.
	// The verdict is a real one.
	BaselineChecked BaselineState = "checked"
	// BaselineNew: the baseline was learned in this very sweep (at start, or a
	// trusted program auto-learned), so the comparison is trivially clean; the
	// first real check is the next sweep.
	BaselineNew BaselineState = "new"
	// BaselineNone: no baseline; only the baseline-less detectors ran (weaker).
	BaselineNone BaselineState = "none"
	// BaselineKnown: not inspected yet (too young), but its program already has
	// a baseline. Used for skipped processes only.
	BaselineKnown BaselineState = "known"
)

// Active returns the findings that were NOT suppressed — the ones that should
// drive exit codes and incident capture.
func (r Report) Active() []Finding {
	out := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if !f.Suppressed {
			out = append(out, f)
		}
	}
	return out
}

// MaxSeverity returns the highest severity among active (non-suppressed)
// findings, or SevInfo if there are none.
func (r Report) MaxSeverity() Severity {
	max := SevInfo
	for _, f := range r.Findings {
		if f.Suppressed {
			continue
		}
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}
