// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package detector

import (
	"fmt"
	"time"

	"github.com/paulborile/cenziadah/internal/elfref"
	"github.com/paulborile/cenziadah/internal/model"
	"github.com/paulborile/cenziadah/internal/procfs"
)

// defaultReadBuf is the streaming window size for .text comparison. The tool's
// footprint is bounded by this, not by the module size (memory-budget NFR).
const defaultReadBuf = 1 << 20 // 1 MiB

// ModuleIntegrity compares the in-memory .text of file-backed executable modules
// against their on-disk ELF. It proceeds identity-first (GNU build-id), then
// streams a chunk-by-chunk byte comparison of .text through a fixed-size buffer,
// skipping relocation sites. A mismatch is an inline hook / patch (Critical).
type ModuleIntegrity struct {
	// ReadBuf overrides the streaming window size; 0 uses defaultReadBuf.
	ReadBuf int
	// Cache, when set, reuses .text digests across processes in one scan cycle
	// (see TextCache for why that is safe). nil reads memory every time.
	Cache *TextCache
	// OpenModule, when set, opens the on-disk ELF for a region (an all-process
	// sweep shares one parse of libc across processes). nil uses elfref.Open.
	OpenModule func(hostPath string, r procfs.Region) (*elfref.Module, error)
	// ReplacedSince, when set, replaces procfs.ReplacedSince (tests).
	ReplacedSince func(pid int, path string, since time.Time) bool
}

// EvidenceUpgraded marks a build-id finding that is a package upgrade (see
// inspect); the scanner then replaces the module's baseline entry.
const EvidenceUpgraded = "upgraded"

func (ModuleIntegrity) Name() string { return "module" }

func (m ModuleIntegrity) Inspect(t *Target) ([]model.Finding, error) {
	if t.Mem == nil {
		return nil, nil // no memory handle (e.g. snapshot-only context)
	}
	return m.inspect(t, t.Mem)
}

// inspect is the testable core: it takes an explicit memReader.
func (m ModuleIntegrity) inspect(t *Target, mem MemReader) ([]model.Finding, error) {
	bufSize := m.ReadBuf
	if bufSize <= 0 {
		bufSize = defaultReadBuf
	}
	buf := make([]byte, bufSize) // reused streaming window for the .text digest

	// Allow-list of module paths to check; from baseline when present, else every
	// distinct file-backed executable mapping.
	allow := map[string]bool{}
	if t.Baseline != nil {
		for _, md := range t.Baseline.Modules {
			allow[md.Path] = true
		}
	}

	var findings []model.Finding
	seen := map[string]bool{}

	for _, r := range t.Regions {
		if !r.Exec || !r.FileBacked() {
			continue
		}
		if t.Baseline != nil && !allow[r.Path] {
			continue
		}
		if seen[r.Path] {
			continue
		}
		seen[r.Path] = true

		if !procfs.IsELFCodeLib(r.Path) {
			continue // Android artifact (.oat/.apk/...), not plain ELF code
		}
		// Resolve the maps backing path (target's mount namespace) to a host path.
		hostPath, ok := procfs.ResolveBackingPath(t.Desc.PID, r.Path)
		if !ok {
			continue // backing not reachable from host
		}
		mod, err := m.open(hostPath, r)
		if err != nil {
			continue // unreadable/odd backing; not our job to flag here
		}

		// Identity first: compare build-id against baseline if we have one.
		if t.Baseline != nil {
			if bid := baselineBuildID(t.Baseline, r.Path); bid != "" && mod.BuildID != "" && bid != mod.BuildID {
				f := model.Finding{
					Technique: model.TechModuleBuildIDDiff,
					Severity:  model.SevCritical,
					PID:       t.Desc.PID,
					Title:     "loaded module build-id differs from baseline",
					Detail:    fmt.Sprintf("%s: baseline=%s loaded=%s", r.Path, bid, mod.BuildID),
					Evidence:  map[string]any{"path": r.Path, "baseline_build_id": bid, "loaded_build_id": mod.BuildID},
				}
				// A library replaced in place by a package upgrade after the
				// baseline was learned (same path, new build-id: Ubuntu point
				// releases keep the file name) is the new version, not an
				// implant: only root can replace a root-owned file in a
				// root-only directory. A user-writable one still alerts.
				if m.replacedSince(t.Desc.PID, r.Path, t.Baseline.CreatedAt) {
					f.Suppressed = true
					f.SuppressReason = "library upgraded on disk after the baseline was learned (root-owned file and directory); its baseline entry is replaced with the new version"
					f.Evidence[EvidenceUpgraded] = true
				}
				findings = append(findings, f)
				continue // identity mismatch; byte diff is meaningless
			}
		}

		if f, ok := m.checkText(t, mem, r, mod, buf); ok {
			findings = append(findings, f)
		}
	}
	return findings, nil
}

// checkText digests the module's live in-memory .text and compares it to the
// known-good in-memory digest recorded in the baseline. They must match exactly;
// any difference is a patch applied after the baseline — an inline hook.
//
// This compares memory-against-baseline-memory, NOT memory-against-disk, because an
// ART/JIT-hosted process legitimately patches library .text at load (function-entry
// instrumentation), so memory never equals disk on a clean process. The baseline
// captures that legitimate patched state once; the check flags only new changes.
//
// With no baseline, or no recorded memory digest for this module, there is no
// reference to compare against, so checkText reports nothing (identity/build-id is
// handled separately above).
func (m ModuleIntegrity) checkText(t *Target, mem MemReader, r procfs.Region, mod *elfref.Module, buf []byte) (model.Finding, bool) {
	if t.Baseline == nil {
		return model.Finding{}, false
	}
	want := baselineMemText(t.Baseline, r.Path)
	if want == "" {
		return model.Finding{}, false // baseline has no memory digest for this module
	}
	got, ok := m.Cache.Digest(mem, r, mod, buf)
	if !ok {
		return model.Finding{}, false // memory unreadable/race: no opinion
	}
	if got == want {
		return model.Finding{}, false // clean
	}
	return model.Finding{
		Technique: model.TechModuleTextMismatch,
		Severity:  model.SevCritical,
		PID:       t.Desc.PID,
		Title:     "in-memory .text changed since baseline (inline hook/patch)",
		Detail:    fmt.Sprintf("%s: live .text digest differs from baseline", r.Path),
		Evidence: map[string]any{
			"path":          r.Path,
			"baseline_text": want,
			"live_text":     got,
		},
	}, true
}

func (m ModuleIntegrity) replacedSince(pid int, path string, since time.Time) bool {
	if m.ReplacedSince != nil {
		return m.ReplacedSince(pid, path, since)
	}
	return procfs.ReplacedSince(pid, path, since)
}

func (m ModuleIntegrity) open(hostPath string, r procfs.Region) (*elfref.Module, error) {
	if m.OpenModule != nil {
		return m.OpenModule(hostPath, r)
	}
	return elfref.Open(hostPath)
}

func baselineMemText(sn *model.Snapshot, path string) string {
	for _, md := range sn.Modules {
		if md.Path == path {
			return md.MemTextSHA
		}
	}
	return ""
}

func baselineBuildID(s *model.Snapshot, path string) string {
	for _, md := range s.Modules {
		if md.Path == path {
			return md.BuildID
		}
	}
	return ""
}
