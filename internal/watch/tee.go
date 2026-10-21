// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package watch

import (
	"github.com/paulborile/cenziadah/internal/baseline"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/scan"
)

// Tee fans the loop's output out to several sinks (e.g. the log and e-mail),
// in order.
func Tee(sinks ...Sink) Sink { return tee(sinks) }

type tee []Sink

func (t tee) Learning() {
	for _, s := range t {
		s.Learning()
	}
}

func (t tee) Learned(set *baseline.Set, res scan.Result) {
	for _, s := range t {
		s.Learned(set, res)
	}
}

func (t tee) Sweep(n int, res scan.Result, events []model.Event) {
	for _, s := range t {
		s.Sweep(n, res, events)
	}
}

func (t tee) Error(err error) {
	for _, s := range t {
		s.Error(err)
	}
}

// Warn forwards a warning to the sinks that take warnings (Warner).
func (t tee) Warn(msg string) {
	for _, s := range t {
		if w, ok := s.(Warner); ok {
			w.Warn(msg)
		}
	}
}
