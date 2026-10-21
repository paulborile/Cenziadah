// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package model

import "time"

// EventKind says whether a finding appeared or went away between two sweeps.
type EventKind string

const (
	EventNew      EventKind = "new"
	EventResolved EventKind = "resolved"
	// EventLearned is a finding that was already present when a baseline was
	// learned from the running host, and so was accepted as normal. Reported once
	// so a pre-existing compromise is not silently absorbed.
	EventLearned EventKind = "learned"
)

// Event is a change in a process's active findings between two consecutive
// sweeps. Continuous monitoring emits events, not full reports, so a steady state
// produces no output.
type Event struct {
	Kind    EventKind  `json:"kind"`
	At      time.Time  `json:"at"`
	Target  TargetDesc `json:"target"`
	Finding Finding    `json:"finding"`
	// Version is the cenziadah version that reported the event (set on output),
	// so an alert read later says which detection logic produced it.
	Version string `json:"version,omitempty"`
}
