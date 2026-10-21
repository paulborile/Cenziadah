// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"os"
	"strconv"
	"strings"
)

// ResolveBackingPath maps a path as it appears in /proc/<pid>/maps (which is in the
// TARGET's mount namespace) to a path readable from the host. Needed because
// containers (e.g. waydroid) share the PID namespace but not the mount namespace,
// so maps paths like "/system/lib64/libfoo.so" or "/data/.../libwhatsapp.so" do not
// exist at those paths on the host.
//
// It returns the first candidate that exists, trying in order:
//  1. /proc/<pid>/root/<path> — the kernel's view into the target's own mount
//     namespace; the most correct, handles overlays/binds exactly as the process
//     sees them (requires privilege, which we already need for /proc/<pid>/mem)
//  2. the path as-is, only if the process shares our mount namespace
//  3. waydroid host mount points, as a fallback when /proc/<pid>/root is unavailable
//
// It returns ("", false) if no candidate exists/readable.
func ResolveBackingPath(pid int, path string) (string, bool) {
	if path == "" || !strings.HasPrefix(path, "/") {
		return "", false
	}
	// /proc/<pid>/root/<path> resolves in the TARGET's own mount namespace (Docker,
	// podman, waydroid, or the host), so it always names the exact file the process
	// mapped. We prefer it over the bare host path first, because a container path
	// like /usr/lib/libssl.so may ALSO exist on the host as a different version —
	// digesting the host copy would produce false mismatches. The bare path is tried
	// next (host-native processes, and the rare case /proc/<pid>/root is unreadable),
	// then waydroid host mount points as a last resort.
	procRoot := "/proc/" + strconv.Itoa(pid) + "/root" + path
	if isRegularFile(procRoot) {
		return procRoot, true
	}
	// The bare host path names the same file ONLY if the process verifiably
	// shares our mount namespace. Otherwise (a container, or a process that is
	// exiting and whose root and namespace can no longer be read) the host file
	// at that path is a different file: comparing it produced false CRITICAL
	// "build-id differs" alerts for a retiring Apache worker in a container,
	// whose libc was checked against the host's libc.
	if SameMountNamespace(pid) && isRegularFile(path) {
		return path, true
	}
	for _, c := range []string{
		"/var/lib/waydroid/rootfs" + path,
		"/var/lib/waydroid" + path, // e.g. /data/... -> /var/lib/waydroid/data/...
	} {
		if isRegularFile(c) {
			return c, true
		}
	}
	return "", false
}

// SameMountNamespace reports whether pid verifiably shares cenziadah's own
// mount namespace (its /proc/<pid>/ns/mnt names the same namespace as ours).
// It is false when that cannot be read: the process exited, or no privilege.
func SameMountNamespace(pid int) bool {
	theirs, err1 := os.Readlink("/proc/" + strconv.Itoa(pid) + "/ns/mnt")
	ours, err2 := os.Readlink("/proc/self/ns/mnt")
	return err1 == nil && err2 == nil && theirs == ours
}

func isRegularFile(p string) bool {
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	return fi.Mode().IsRegular()
}

// IsELFCodeLib reports whether a maps backing path names something worth doing
// module-integrity on: a real ELF shared object or executable. It filters out
// Android runtime artifacts (.oat/.art/.vdex/.odex/.dex) and archives (.apk/.jar)
// that are not plain ELF code and would only produce parse-failure noise.
func IsELFCodeLib(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range []string{".oat", ".art", ".vdex", ".odex", ".dex", ".apk", ".jar", ".zip"} {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	// Accept .so (optionally versioned like libc.so.6) and extension-less executables.
	return true
}
