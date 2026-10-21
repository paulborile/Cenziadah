// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Package procfs is the ONLY package that touches the kernel's /proc interface.
// It parses /proc/<pid>/{maps,mem,fd,net,status,stat} into plain structs so that
// every detector can be unit-tested against synthetic fixtures with no root and
// no live process. It wraps the one thing we do not control: the /proc format.
package procfs

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
)

// Region is one line of /proc/<pid>/maps: a single virtual memory mapping.
type Region struct {
	Start   uint64 // start virtual address
	End     uint64 // end virtual address (exclusive)
	Read    bool
	Write   bool
	Exec    bool
	Private bool   // 'p' (vs shared 's')
	Offset  uint64 // offset into the backing file
	Dev     string
	Inode   uint64
	Path    string // backing: file path, "[heap]", "[anon]", "memfd:...", or "" for anon
	Deleted bool   // backing file was unlinked while mapped (" (deleted)" suffix)

	// AnonKB is the smaps "Anonymous:" size: pages copied-on-write into private
	// memory. Only meaningful when AnonKnown is true (smaps was read); the zero
	// value means "unknown", never "clean".
	AnonKB    uint64
	AnonKnown bool

	// ReplacedOnDisk: the deleted backing file was replaced by a package-managed
	// file after the process started (an upgrade, not an implant). Set by
	// AnnotateReplaced; false means unknown or not replaced.
	ReplacedOnDisk bool

	// NotBrkHeap: labelled "[heap]" by the kernel only because it overlaps
	// the (unused) brk range; it is an anonymous mmap, not the brk heap. Set by
	// AnnotateBrk.
	NotBrkHeap bool
}

// Anonymous reports whether the mapping is anonymous memory: no backing, an
// "[anon:<name>]" mapping (the name is set by the process itself, so it carries
// no trust), or a NotBrkHeap region. The brk heap, stack and file-backed or
// memfd mappings are not.
func (r Region) Anonymous() bool {
	return !r.Deleted && (r.Path == "" || strings.HasPrefix(r.Path, "[anon:") || r.NotBrkHeap)
}

// Size returns the byte length of the mapping.
func (r Region) Size() uint64 { return r.End - r.Start }

// FileBacked reports whether the mapping is backed by a real file on disk
// (as opposed to anonymous memory or a pseudo-file like [heap] or memfd:).
func (r Region) FileBacked() bool {
	if r.Path == "" || r.Deleted {
		return false
	}
	// Pseudo mappings start with '[' ([heap],[stack],[vdso],...) or are memfd/anon.
	if strings.HasPrefix(r.Path, "[") {
		return false
	}
	if strings.HasPrefix(r.Path, "anon_inode:") || strings.HasPrefix(r.Path, "memfd:") {
		return false
	}
	return true
}

// Perms renders the rwx permission triplet, e.g. "r-x".
func (r Region) Perms() string {
	b := []byte("---")
	if r.Read {
		b[0] = 'r'
	}
	if r.Write {
		b[1] = 'w'
	}
	if r.Exec {
		b[2] = 'x'
	}
	return string(b)
}

// ReadMaps parses /proc/<pid>/maps for the given pid.
func ReadMaps(pid int) ([]Region, error) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/maps")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseMaps(f)
}

// parseMaps is separated from ReadMaps so tests can feed a fixture reader.
func parseMaps(r io.Reader) ([]Region, error) {
	var regions []Region
	sc := bufio.NewScanner(r)
	// maps lines can be long (full paths); give the scanner a generous buffer.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		reg, ok := parseMapLine(sc.Text())
		if ok {
			regions = append(regions, reg)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return regions, nil
}

// parseMapLine parses a single maps line. Format:
//
//	address           perms offset  dev   inode      pathname
//	7f...-7f... r-xp 00000000 08:01 1234  /lib/x.so (deleted)
func parseMapLine(line string) (Region, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return Region{}, false
	}
	dash := strings.IndexByte(fields[0], '-')
	if dash < 0 {
		return Region{}, false
	}
	start, err1 := strconv.ParseUint(fields[0][:dash], 16, 64)
	end, err2 := strconv.ParseUint(fields[0][dash+1:], 16, 64)
	if err1 != nil || err2 != nil {
		return Region{}, false
	}
	perms := fields[1]
	if len(perms) < 4 {
		return Region{}, false
	}
	off, _ := strconv.ParseUint(fields[2], 16, 64)
	inode, _ := strconv.ParseUint(fields[4], 10, 64)

	reg := Region{
		Start:   start,
		End:     end,
		Read:    perms[0] == 'r',
		Write:   perms[1] == 'w',
		Exec:    perms[2] == 'x',
		Private: perms[3] == 'p',
		Offset:  off,
		Dev:     fields[3],
		Inode:   inode,
	}

	// Everything after the 5th field is the pathname, which may itself contain
	// spaces and a trailing " (deleted)".
	if len(fields) >= 6 {
		idx := indexNthField(line, 5)
		if idx >= 0 {
			path := strings.TrimSpace(line[idx:])
			if strings.HasSuffix(path, " (deleted)") {
				reg.Deleted = true
				path = strings.TrimSuffix(path, " (deleted)")
			}
			reg.Path = path
		}
	}
	return reg, true
}

// indexNthField returns the byte index where the nth (0-based) whitespace-
// separated field begins, so the pathname (which may contain spaces) can be
// taken as the remainder of the line verbatim.
func indexNthField(line string, n int) int {
	i := 0
	field := 0
	for i < len(line) {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			return -1
		}
		if field == n {
			return i
		}
		for i < len(line) && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		field++
	}
	return -1
}
