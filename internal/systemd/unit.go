// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

// Package systemd reads system service unit files (root-owned only) so the
// processes systemd starts for a unit can be recognised as that unit's
// configured work: e.g. apt-daily.service running
// `/bin/sh /usr/lib/apt/apt.systemd.daily update`. It is a platform layer over
// the unit-file format; nothing else parses unit files.
package systemd

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// unitDirs are the system unit search paths, highest precedence first.
var unitDirs = []string{
	"/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system",
	"/usr/lib/systemd/system", "/lib/systemd/system",
}

const maxUnitFile = 256 << 10

// Unit is what matters about a service unit here.
type Unit struct {
	Name    string
	Oneshot bool     // Type=oneshot: a batch job, its whole process tree is its work
	Execs   []string // command lines of ExecStart/ExecStartPre/Post/ExecReload/ExecStop... (normalized)
}

// Load reads unit name (e.g. "apt-daily.service" or "getty@tty1.service") from
// the system unit directories under root, applying drop-ins. Only files that
// are root-owned and not group/world-writable are read (trusted, nil = default
// check). It returns false when no trusted unit file exists.
func Load(root, name string, trusted func(string) bool) (Unit, bool) {
	if trusted == nil {
		trusted = rootOnlyFile
	}
	file, instance := name, ""
	if at := strings.IndexByte(name, '@'); at >= 0 && strings.HasSuffix(name, ".service") {
		instance = strings.TrimSuffix(name[at+1:], ".service")
		file = name[:at+1] + ".service" // template: foo@.service
	}
	u := Unit{Name: name}
	st := &state{instance: instance}
	found := false
	for _, d := range unitDirs {
		for _, f := range []string{name, file} {
			p := filepath.Join(root, d, f)
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && trusted(p) {
				st.parse(p)
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		return u, false
	}
	// drop-ins: <name>.d/*.conf and <template>.d/*.conf, in all dirs, by file name
	var dropins []string
	seen := map[string]bool{}
	for _, d := range unitDirs {
		for _, f := range []string{file, name} {
			matches, _ := filepath.Glob(filepath.Join(root, d, f+".d", "*.conf"))
			for _, m := range matches {
				if base := filepath.Base(m); !seen[base] && trusted(m) {
					seen[base] = true
					dropins = append(dropins, m)
				}
			}
		}
	}
	sort.Slice(dropins, func(i, j int) bool { return filepath.Base(dropins[i]) < filepath.Base(dropins[j]) })
	for _, p := range dropins {
		st.parse(p)
	}
	u.Oneshot = st.typ == "oneshot"
	for _, k := range []string{"ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost"} {
		u.Execs = append(u.Execs, st.exec[k]...)
	}
	return u, true
}

type state struct {
	instance string
	typ      string
	exec     map[string][]string
}

func (s *state) parse(p string) {
	f, err := os.Open(p)
	if err != nil {
		return
	}
	defer f.Close()
	if s.exec == nil {
		s.exec = map[string][]string{}
	}
	sc := bufio.NewScanner(io.LimitReader(f, maxUnitFile))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	section, pending := "", ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasSuffix(line, "\\") { // continuation
			pending += strings.TrimSuffix(line, "\\") + " "
			continue
		}
		line, pending = pending+line, ""
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			section = strings.Trim(line, "[]")
			continue
		}
		if section != "Service" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch {
		case k == "Type":
			s.typ = v
		case strings.HasPrefix(k, "Exec"):
			if v == "" {
				s.exec[k] = nil // an empty assignment resets the list (drop-in override)
				continue
			}
			s.exec[k] = append(s.exec[k], s.normalize(v))
		}
	}
}

// normalize turns an Exec*= value into the command line /proc shows: special
// prefixes dropped (- @ : + !), %i/%I expanded, quotes removed, whitespace
// collapsed.
func (s *state) normalize(v string) string {
	v = strings.TrimLeft(v, "-@:+!")
	v = strings.NewReplacer("%i", s.instance, "%I", s.instance, `"`, "", "'", "").Replace(v)
	return strings.Join(strings.Fields(v), " ")
}

// Matches reports whether a process command line is one of the unit's
// configured commands: exactly, or a script started through its interpreter
// (the kernel puts "/bin/sh" in front of `ExecStart=/path/script args`), in which
// case interpreter must be true (the process is a shell or interpreter).
func (u Unit) Matches(cmdline string, interpreter bool) bool {
	cmdline = strings.Join(strings.Fields(cmdline), " ")
	for _, e := range u.Execs {
		if cmdline == e {
			return true
		}
		if interpreter && strings.HasSuffix(cmdline, " "+e) && !strings.Contains(strings.TrimSuffix(cmdline, " "+e), " ") {
			return true
		}
	}
	return false
}

func rootOnlyFile(p string) bool {
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		return false
	}
	return st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Uid == 0 && st.Mode&(syscall.S_IWGRP|syscall.S_IWOTH) == 0
}
