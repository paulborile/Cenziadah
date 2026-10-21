// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Package report renders a model.Report for human (text) and machine (JSON)
// consumption.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/paulborile/cenziadah/internal/model"
)

// Text writes a human-readable report. Active (non-suppressed) findings are shown
// first, highest severity first; suppressed findings are summarized at the end so
// the suppression decisions remain visible and auditable.
func Text(w io.Writer, r model.Report) {
	fmt.Fprintf(w, "cenziadah report for pid %d (%s)\n", r.Target.PID, r.Target.Name)
	if r.Target.Exe != "" {
		fmt.Fprintf(w, "  exe: %s\n", r.Target.Exe)
	}
	fmt.Fprintf(w, "  checked: %s\n\n", r.CheckedAt.Format("2006-01-02 15:04:05"))

	active := r.Active()
	sort.SliceStable(active, func(i, j int) bool { return active[i].Severity > active[j].Severity })

	if len(active) == 0 {
		fmt.Fprintln(w, "CLEAN — no active findings.")
	} else {
		fmt.Fprintf(w, "%d finding(s):\n", len(active))
		for _, f := range active {
			fmt.Fprintf(w, "  [%s] %s (%s)\n", f.Severity, f.Title, f.Technique)
			if f.Detail != "" {
				fmt.Fprintf(w, "         %s\n", f.Detail)
			}
		}
	}

	var suppressed int
	for _, f := range r.Findings {
		if f.Suppressed {
			suppressed++
		}
	}
	if suppressed > 0 {
		fmt.Fprintf(w, "\n(%d finding(s) suppressed as known-good: ART/JIT or baseline)\n", suppressed)
	}
}

// JSON writes the full report (including suppressed findings) as JSON.
func JSON(w io.Writer, r model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
