// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package detector

import (
	"fmt"

	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/procfs"
	"github.com/paulborile/cenziadah/internal/redact"
)

// ProcTree flags child processes of the target that are not in the baseline's
// allow-list. A web server or messaging app spawning a shell or unknown binary is
// a textbook post-exploitation IoC. With no baseline, any child is reported at a
// lower severity (informational) since we have no notion of "expected".
type ProcTree struct{}

func (ProcTree) Name() string { return "proctree" }

func (ProcTree) Inspect(t *Target) ([]model.Finding, error) {
	allowed := map[string]struct{}{}
	if t.Baseline != nil {
		for _, c := range t.Baseline.Children {
			allowed[c.Exe] = struct{}{}
		}
	}

	var findings []model.Finding
	for _, c := range t.Children {
		_, ok := allowed[c.Exe]
		f := model.Finding{
			Technique: model.TechUnexpectedChild,
			Severity:  model.SevHigh,
			PID:       t.Desc.PID,
			Title:     "unexpected child process",
			Detail:    childDetail(c),
			Evidence: map[string]any{
				"child_pid": c.PID,
				"exe":       c.Exe,
				"cmdline":   c.Cmdline,
			},
		}
		switch {
		case ok:
			f.Suppressed = true
			f.SuppressReason = "child exe present in baseline allow-list"
		case c.PreExisting:
			// Its exe may be unreadable (setuid helpers hide /proc/<pid>/exe), so
			// it cannot be allow-listed by path; it is accepted as this exact
			// process instead. A new child, such as an exploit's shell, is not.
			f.Suppressed = true
			f.SuppressReason = "child was already running when the baseline was learned"
		case c.Expected != "":
			f.Suppressed = true
			f.SuppressReason = c.Expected
		case c.Sibling:
			// Installed next to the parent's own binary in a dedicated root-only
			// directory (see engine.siblingCandidate): part of the same suite.
			f.Suppressed = true
			f.SuppressReason = "child program installed next to the parent's (same root-only package directory)"
		case t.ScheduledJob != "":
			f.Suppressed = true
			f.SuppressReason = "part of " + t.ScheduledJob
		case t.InteractiveShell:
			// A shell spawned by a compromised process is flagged on THAT process
			// (an unexpected child there); what is typed into it, or into any
			// user's terminal, is not a finding of its own.
			f.Suppressed = true
			f.SuppressReason = "child of an interactive terminal shell (a command someone typed)"
		case c.Exe == "" && c.Exited && (procfs.IsShell(c.Name) || procfs.IsInterpreter(c.Name)):
			// Its exe is gone but its name says a shell or interpreter ran: the
			// classic exploit one-shot (sh -c id). Keep the alert. (A process can
			// rename itself, so this only catches the unsubtle case.)
			f.Title = "shell/interpreter child ran and exited (exe no longer readable)"
		case c.Exe == "" && c.Exited:
			// Gone (or a zombie) before even the sweep's process table could read
			// its exe, and not named like a shell: nothing to judge (e.g. postfix's
			// short-lived workers). Recorded, not alerted; a child that is alive
			// with a hidden exe still alerts.
			f.Severity = model.SevInfo
			f.Title = "child exited before it could be identified"
		default:
			f.Severity, f.Title = childRisk(c, t.Baseline != nil)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// maxDetailCmd caps the command line in a finding's detail (an agent's or a
// script's `sh -c` can be many KB); the evidence keeps it whole.
const maxDetailCmd = 512

// childDetail describes a child for a finding. When the exe is unknown (the
// child exited) its process name is the only clue left, so it is included.
// The command line is redacted BEFORE it is cut, so no half secret survives.
func childDetail(c procfs.Child) string {
	d := fmt.Sprintf("pid=%d exe=%s cmd=%q", c.PID, c.Exe, redact.Truncate(redact.Text(c.Cmdline), maxDetailCmd))
	if c.Exe == "" && c.Name != "" {
		d += fmt.Sprintf(" comm=%s", c.Name)
	}
	if c.Exited {
		d += " (exited)"
	}
	return d
}

// childRisk grades a child that no rule explains by WHAT it is, not merely by
// "never seen before": a single learning sweep cannot have seen every program a
// service legitimately starts on demand, but the post-exploitation shape is
// always the same.
//   - shell / interpreter / network tool (sh, python, curl, nc, ...) or a
//     program that is not package-installed (from /tmp, a web root, home), or
//     an alive child whose exe is hidden: HIGH, the webshell / RCE signal;
//   - an ordinary package-installed program never seen as this parent's child:
//     LOW, recorded and kept in the history but not an alert.
//
// Without a baseline (a program first seen after start) nothing was ever
// "expected": the risky shapes are MEDIUM and the rest INFO.
func childRisk(c procfs.Child, haveBaseline bool) (model.Severity, string) {
	risky := procfs.IsRiskyProgram(c.Exe) || (c.Exe == "" && procfs.IsRiskyProgram(c.Name))
	var sev model.Severity
	var title string
	switch {
	case risky:
		sev, title = model.SevHigh, "unexpected shell/interpreter/network-tool child"
	case c.Exe == "":
		sev, title = model.SevHigh, "unexpected child with a hidden executable"
	case !c.Trusted:
		sev, title = model.SevHigh, "unexpected child from a non-package location (not root-owned, or a writable directory)"
	default:
		sev, title = model.SevLow, "new child program (package-installed, not seen at learn time)"
	}
	if !haveBaseline {
		if sev == model.SevHigh {
			sev = model.SevMedium
		} else {
			sev = model.SevInfo
		}
	}
	return sev, title
}
