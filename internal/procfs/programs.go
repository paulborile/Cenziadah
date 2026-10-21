// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import "path"

// shells are command interpreters, by executable (or process) name.
var shells = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true, "fish": true,
	"ksh": true, "mksh": true, "ksh93": true, "tcsh": true, "csh": true, "ash": true,
}

// IsShell reports whether nameOrPath (an exe path or a process name) is a shell.
func IsShell(nameOrPath string) bool {
	return shells[path.Base(TrimDeleted(nameOrPath))]
}

// interpreterPrefixes are program names (or name prefixes, for versioned
// binaries like python3.12) that run arbitrary code from their arguments.
var interpreterPrefixes = []string{
	"python", "perl", "ruby", "node", "nodejs", "php", "lua", "luajit", "tclsh", "wish",
	"java", "busybox", "env", "awk", "gawk", "mawk", "expect", "socat", "nc", "ncat",
}

// IsInterpreter reports whether nameOrPath runs arbitrary code from its
// arguments (python3.12, perl, node, env, nc, ...).
func IsInterpreter(nameOrPath string) bool {
	base := path.Base(TrimDeleted(nameOrPath))
	for _, p := range interpreterPrefixes {
		if base == p || (len(base) > len(p) && base[:len(p)] == p && isVersionSuffix(base[len(p):])) {
			return true
		}
	}
	return false
}

// networkTools move data or open shells across the network: what an attacker
// runs right after getting code execution (download a payload, call home).
var networkTools = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true, "socat": true,
	"telnet": true, "ftp": true, "tftp": true, "ssh": true, "scp": true, "sftp": true,
}

// IsNetworkTool reports whether nameOrPath is a download / remote-shell tool.
func IsNetworkTool(nameOrPath string) bool {
	return networkTools[path.Base(TrimDeleted(nameOrPath))]
}

// IsRiskyProgram reports whether nameOrPath is a shell, an interpreter or a
// network tool: the programs a compromised service starts to run attacker
// commands. A service starting one of these is the webshell / RCE signal.
func IsRiskyProgram(nameOrPath string) bool {
	return IsShell(nameOrPath) || IsInterpreter(nameOrPath) || IsNetworkTool(nameOrPath)
}

// isVersionSuffix accepts "3", "3.12", "-3.12", "5.3": what follows an
// interpreter name in versioned binaries (python3.12, php8.2, lua5.4).
func isVersionSuffix(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' && r != '-' {
			return false
		}
	}
	return true
}
