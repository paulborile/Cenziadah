// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package engine

import (
	"fmt"
	"sync"
	"syscall"

	"github.com/paulborile/cenziadah/internal/detector"
	"github.com/paulborile/cenziadah/internal/elfref"
	"github.com/paulborile/cenziadah/internal/procfs"
)

// SweepCache holds the caches shared by every process of every sweep: on-disk
// ELF modules (libc is parsed once, not once per process per sweep) and
// in-memory .text digests (detector.TextCache). Create it once per scanner and
// bracket every sweep with BeginSweep/EndSweep.
//
// A module is keyed by the identity of the file itself, from stat(2) on the
// path it resolves to: device, inode, size, mtime and ctime. The same library
// seen through /proc/<pid>/root of any process is one entry; a file replaced
// (new inode) or written in place (new mtime/ctime; ctime cannot be set back
// without root) is a new entry, parsed again. Entries no sweep used are dropped.
type SweepCache struct {
	Text *detector.TextCache
	// DiskDigests makes snapshots record each module's on-disk .text digest. No
	// detector reads it yet (it anchors future on-disk tamper checks) and it costs
	// a full read + hash of every library, so in-memory baselines leave it off.
	DiskDigests bool

	mu   sync.Mutex
	gen  uint64
	mods map[string]*modEntry // by file stamp
}

type modEntry struct {
	mod      *elfref.Module
	err      error
	diskSHA  string
	diskDone bool
	gen      uint64 // last sweep that used it
}

// NewSweepCache returns empty caches.
func NewSweepCache() *SweepCache {
	return &SweepCache{Text: detector.NewTextCache(), mods: make(map[string]*modEntry)}
}

// BeginSweep starts a sweep (statistics restart).
func (c *SweepCache) BeginSweep() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.gen++
	c.mu.Unlock()
	c.Text.BeginSweep()
}

// EndSweep drops what the sweep did not use: modules of programs that exited or
// files that changed, and their digests.
func (c *SweepCache) EndSweep() {
	if c == nil {
		return
	}
	c.mu.Lock()
	for k, e := range c.mods {
		if e.gen != c.gen {
			delete(c.mods, k)
		}
	}
	c.mu.Unlock()
	c.Text.EndSweep()
}

// Modules is the number of cached modules.
func (c *SweepCache) Modules() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.mods)
}

// OpenModule returns the parsed on-disk ELF behind region r (resolved to
// hostPath), parsing each file version once. A nil cache, or a file that
// cannot be stat'ed, always parses. Errors are cached too, so an unreadable
// file is not retried for every process.
func (c *SweepCache) OpenModule(hostPath string, r procfs.Region) (*elfref.Module, error) {
	e := c.entry(hostPath)
	if e == nil {
		return elfref.Open(hostPath)
	}
	return e.mod, e.err
}

// diskDigest returns the masked on-disk .text digest of mod, computed once per
// file version.
func (c *SweepCache) diskDigest(hostPath string, r procfs.Region, mod *elfref.Module) string {
	e := c.entry(hostPath)
	if e == nil || e.mod != mod {
		return diskTextDigest(mod)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !e.diskDone {
		e.diskSHA, e.diskDone = diskTextDigest(mod), true
	}
	return e.diskSHA
}

// entry returns the cache slot for the file at hostPath, parsing it on first
// use; nil when the file cannot be stat'ed.
func (c *SweepCache) entry(hostPath string) *modEntry {
	if c == nil {
		return nil
	}
	stamp, ok := fileStamp(hostPath)
	if !ok {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.mods[stamp]; ok {
		e.gen = c.gen
		if e.mod != nil {
			// Same file (same stamp), but the path it was first parsed through
			// (/proc/<pid>/root/...) dies with that process; keep a live one for
			// Module.RawReaderAt.
			e.mod.Path = hostPath
		}
		return e
	}
	e := &modEntry{gen: c.gen}
	e.mod, e.err = elfref.Open(hostPath)
	if e.mod != nil {
		e.mod.Stamp = stamp
	}
	c.mods[stamp] = e
	return e
}

// fileStamp names one version of one file: device, inode, size, mtime, ctime.
func fileStamp(p string) (string, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return "", false
	}
	return fmt.Sprintf("%d:%d:%d:%d.%d:%d.%d", st.Dev, st.Ino, st.Size,
		st.Mtim.Sec, st.Mtim.Nsec, st.Ctim.Sec, st.Ctim.Nsec), true
}

// textCache returns the digest cache, or nil for a nil SweepCache.
func (c *SweepCache) textCache() *detector.TextCache {
	if c == nil {
		return nil
	}
	return c.Text
}
