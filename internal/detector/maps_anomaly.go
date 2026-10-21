// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package detector

import (
	"fmt"
	"strings"

	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/procfs"
)

// MapsAnomaly flags executable-memory anomalies in /proc/<pid>/maps:
//   - rwx mappings (W^X violation)
//   - anonymous executable mappings (exec code not backed by a file)
//   - executable mappings whose backing file was deleted
//
// ART's JIT legitimately produces rwx/anon-exec regions, so those are SUPPRESSED
// (not dropped) when their backing matches a known ART pattern, and — when a
// baseline is present — anything already present in the baseline is suppressed as
// expected noise. This is the primary defense against ART false positives.
type MapsAnomaly struct{}

func (MapsAnomaly) Name() string { return "maps" }

// artBackings are substrings of backing names that ART/Dalvik legitimately maps
// executable. Matching regions are suppressed with a reason, never silently hidden.
var artBackings = []string{
	"memfd:jit-cache", "dalvik-", "/dev/ashmem", ".oat", ".art", ".vdex", ".odex",
	"[anon:dalvik", "anon:libart",
}

func (MapsAnomaly) Inspect(t *Target) ([]model.Finding, error) {
	var findings []model.Finding

	// Build a set of baseline region shapes to suppress expected executable noise.
	type shapeKey struct {
		perm    string
		backing string
	}
	baseShapes := map[shapeKey]struct{}{}
	if t.Baseline != nil {
		for _, rs := range t.Baseline.Regions {
			baseShapes[shapeKey{string(rs.Perm), labelClass(rs.Backing)}] = struct{}{}
		}
	}

	for _, r := range t.Regions {
		if !r.Exec {
			continue // only executable mappings are interesting here
		}

		var tech model.Technique
		var title string
		sev := model.SevHigh

		switch {
		case r.Write:
			tech, title = model.TechMapsRWX, "writable+executable (rwx) mapping"
			sev = model.SevCritical
		case r.Deleted:
			tech, title = model.TechMapsDeletedBacking, "executable mapping with deleted backing file"
			sev = model.SevHigh
		case !r.FileBacked():
			tech, title = model.TechMapsAnonExec, "anonymous executable mapping (code not backed by a file)"
			sev = model.SevHigh
		default:
			continue // normal file-backed r-x code
		}

		f := model.Finding{
			Technique: tech,
			Severity:  sev,
			PID:       t.Desc.PID,
			Title:     title,
			Detail:    fmt.Sprintf("%#x-%#x %s %s", r.Start, r.End, r.Perms(), backingLabel(r)),
			Evidence: map[string]any{
				"start":   fmt.Sprintf("%#x", r.Start),
				"end":     fmt.Sprintf("%#x", r.End),
				"perms":   r.Perms(),
				"backing": backingLabel(r),
				"size":    r.Size(),
			},
		}

		// Suppression 1: known ART/JIT backing.
		if reason := artSuppress(r); reason != "" {
			f.Suppressed = true
			f.SuppressReason = reason
		}
		// Suppression 1b: deleted because a package upgrade replaced the file
		// after the process started (see procfs.AnnotateReplaced).
		if !f.Suppressed && tech == model.TechMapsDeletedBacking && r.ReplacedOnDisk {
			f.Suppressed = true
			f.SuppressReason = "backing file replaced on disk after the process started (package upgrade); restart the process to load the new version"
		}
		// Suppression 2: present in the known-good baseline (same shape).
		if !f.Suppressed && t.Baseline != nil {
			if _, ok := baseShapes[shapeKey{r.Perms(), shapeClass(r)}]; ok {
				f.Suppressed = true
				f.SuppressReason = "matches baseline region shape"
			}
		}

		findings = append(findings, f)
	}
	return findings, nil
}

// kernelExec are backing names for kernel-provided executable mappings present in
// every process (not injection).
var kernelExec = []string{"[vdso]", "[vsyscall]", "[vvar]", "[uprobes]"}

// artSuppress returns a non-empty reason if the region looks like legitimate
// executable memory we must not flag: ART/JIT caches or kernel pseudo-mappings.
func artSuppress(r procfs.Region) string {
	name := backingLabel(r)
	for _, pat := range kernelExec {
		if name == pat {
			return "kernel-provided mapping: " + pat
		}
	}
	for _, pat := range artBackings {
		if strings.Contains(name, pat) {
			return "ART/JIT backing: " + pat
		}
	}
	return ""
}

// backingLabel renders the region's backing in a stable form for evidence and
// shape comparison: the file path, a pseudo name, or "[anon]"/"(deleted)".
// shapeClass is the backing a region is matched against the baseline by. Every
// anonymous region is one class, whatever its label: "[anon:<name>]" names are
// chosen by the process itself (an implant can call itself "v8"), and a
// NotBrkHeap "[heap]" label only says where it was placed. The brk heap, the
// stack and file-backed mappings keep their own labels.
func shapeClass(r procfs.Region) string {
	if r.Anonymous() {
		return "[anon]"
	}
	return backingLabel(r)
}

// labelClass is shapeClass for a baseline's stored backing label.
func labelClass(label string) string {
	if label == "[anon]" || strings.HasPrefix(label, "[anon:") {
		return "[anon]"
	}
	return label
}

func backingLabel(r procfs.Region) string {
	if r.NotBrkHeap {
		return "[anon] (kernel label [heap]: placed over the unused brk start)"
	}
	if r.Deleted {
		if r.Path != "" {
			return r.Path + " (deleted)"
		}
		return "(deleted)"
	}
	if r.Path == "" {
		return "[anon]"
	}
	return r.Path
}
