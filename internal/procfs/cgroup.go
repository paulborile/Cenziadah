// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"bufio"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
)

// SystemUnit returns the systemd system service a process belongs to, from its
// cgroup (e.g. "apt-daily.service" for /system.slice/apt-daily.service), or ""
// when it is not in a system service (init.scope, user sessions, containers).
// systemd places every service's processes in that service's cgroup, and a
// non-root process cannot move itself into another service's cgroup, so this is
// a statement made by systemd, not by the process. User units
// (/user.slice/.../user@1000.service/...) are excluded: users control them.
func SystemUnit(pid int) string {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return ""
	}
	defer f.Close()
	return parseSystemUnit(f)
}

func parseSystemUnit(r io.Reader) string {
	sc := bufio.NewScanner(r)
	var v1 string
	for sc.Scan() {
		line := sc.Text()
		// cgroup v2: "0::/system.slice/x.service"; v1: "1:name=systemd:/system.slice/x.service"
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case parts[0] == "0" && parts[1] == "":
			return unitFromPath(parts[2])
		case parts[1] == "name=systemd":
			v1 = unitFromPath(parts[2])
		}
	}
	return v1
}

func unitFromPath(p string) string {
	if !strings.HasPrefix(p, "/system.slice/") {
		return ""
	}
	// the service is the first component under system.slice (nested slices are
	// rare; a service may have sub-cgroups, e.g. .../x.service/payload)
	rest := strings.TrimPrefix(p, "/system.slice/")
	name := strings.SplitN(rest, "/", 2)[0]
	if !strings.HasSuffix(name, ".service") || path.Clean(name) != name {
		return ""
	}
	return name
}
