// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import (
	"path"
	"strconv"
	"strings"
	"syscall"
)

// androidSystemUID is Android's "system" user, which owns installed APKs.
const androidSystemUID = 1000

// IsAppProcess reports whether exe is Android's app runtime (app_process,
// app_process32/64): every Android app runs as one, told apart by its name.
func IsAppProcess(exe string) bool {
	return strings.HasPrefix(path.Base(TrimDeleted(exe)), "app_process")
}

// AppInstallDir is AppInstall for a live process: it reads pid's status,
// cmdline and maps. "" if pid is not an Android app or anything is unreadable.
func AppInstallDir(pid int) string {
	st, err := ReadStatus(pid)
	if err != nil {
		return ""
	}
	cmd, err := Cmdline(pid)
	if err != nil {
		return ""
	}
	regions, err := ReadMaps(pid)
	if err != nil {
		return ""
	}
	return AppInstall(pid, st.UID, cmd, regions)
}

// AppInstall returns the install directory of the Android app process pid runs
// (e.g. /data/app/~~StwvKV7_QjIGHT2FPXOdwQ==/com.whatsapp-2h44F8j3UivBperIXvjQ2g==),
// found as the directory of its OWN base.apk among its mapped regions; "" if
// there is none or it cannot be trusted.
//
// PackageManager creates a fresh, randomly named directory for every install
// and update, so the directory names the installed version of the app. It is
// trusted only when it, everything up to /data/app, and base.apk are owned by
// root or Android's system user and not world-writable, as seen in pid's own
// mount namespace, and the app itself does not run as root or system: an app
// cannot then create a directory there to fake an update of itself.
func AppInstall(pid, uid int, cmdline string, regions []Region) string {
	if uid == 0 || uid == androidSystemUID {
		return ""
	}
	pkg, _, _ := strings.Cut(strings.SplitN(cmdline, " ", 2)[0], ":") // "com.x:remote" -> "com.x"
	paths := make([]string, 0, len(regions))
	for _, r := range regions {
		paths = append(paths, r.Path)
	}
	dir := appInstallFromPaths(paths, pkg)
	if dir == "" {
		return ""
	}
	root := "/proc/" + strconv.Itoa(pid) + "/root"
	if !systemOwned(root+dir+"/base.apk", syscall.S_IFREG) {
		return ""
	}
	for d := dir; d != "/data"; d = path.Dir(d) {
		if !systemOwned(root+d, syscall.S_IFDIR) {
			return ""
		}
	}
	return dir
}

// appInstallFromPaths finds pkg's install directory among mapped paths: the
// directory of /data/app/[~~<rand>/]<pkg>-<rand>/base.apk. Other apps' APKs
// mapped into the process (WebView, Play services) do not match.
func appInstallFromPaths(paths []string, pkg string) string {
	if pkg == "" || strings.ContainsAny(pkg, "/-") {
		return ""
	}
	for _, p := range paths {
		if p != path.Clean(p) || path.Base(p) != "base.apk" || !strings.HasPrefix(p, "/data/app/") {
			continue
		}
		dir := path.Dir(p)
		if rand, ok := strings.CutPrefix(path.Base(dir), pkg+"-"); !ok || rand == "" {
			continue
		}
		parent := path.Dir(dir)
		if parent == "/data/app" || (path.Dir(parent) == "/data/app" && strings.HasPrefix(path.Base(parent), "~~")) {
			return dir
		}
	}
	return ""
}

// systemOwned: p is of file type typ, owned by root or Android's system user,
// and not world-writable.
func systemOwned(p string, typ uint32) bool {
	var st syscall.Stat_t
	if err := syscall.Stat(p, &st); err != nil {
		return false
	}
	return st.Mode&syscall.S_IFMT == typ && (st.Uid == 0 || st.Uid == androidSystemUID) && st.Mode&syscall.S_IWOTH == 0
}
