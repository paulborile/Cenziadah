// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Paul Borile

package procfs

import "testing"

func TestIsAppProcess(t *testing.T) {
	for exe, want := range map[string]bool{
		"/system/bin/app_process64": true, "/system/bin/app_process32": true,
		"/system/bin/app_process": true, "/system/bin/app_process64 (deleted)": true,
		"/usr/bin/bash": false, "": false,
	} {
		if got := IsAppProcess(exe); got != want {
			t.Errorf("IsAppProcess(%q) = %v, want %v", exe, got, want)
		}
	}
}

func TestAppInstallFromPaths(t *testing.T) {
	const wa = "/data/app/~~StwvKV7_QjIGHT2FPXOdwQ==/com.whatsapp-2h44F8j3UivBperIXvjQ2g=="
	webview := "/data/app/~~x==/com.google.android.webview-y==/base.apk"
	for _, c := range []struct {
		paths []string
		pkg   string
		want  string
		why   string
	}{
		{[]string{webview, wa + "/base.apk", wa + "/oat/x86_64/base.odex"}, "com.whatsapp", wa, "own apk among others"},
		{[]string{"/data/app/com.whatsapp-1/base.apk"}, "com.whatsapp", "/data/app/com.whatsapp-1", "legacy layout without ~~"},
		{[]string{webview}, "com.whatsapp", "", "only another app's apk"},
		{[]string{"/data/app/~~a==/com.whatsapp.w4b-b==/base.apk"}, "com.whatsapp", "", "different package, same prefix"},
		{[]string{"/data/app/~~a==/com.whatsapp-/base.apk"}, "com.whatsapp", "", "no random suffix"},
		{[]string{"/data/app/x/../~~a==/com.whatsapp-b==/base.apk"}, "com.whatsapp", "", "unclean path"},
		{[]string{"/data/app/x/y/com.whatsapp-b==/base.apk"}, "com.whatsapp", "", "too deep"},
		{[]string{"/data/data/com.whatsapp/files/com.whatsapp-b==/base.apk"}, "com.whatsapp", "", "app-writable data dir"},
		{[]string{wa + "/split_config.apk"}, "com.whatsapp", "", "not base.apk"},
		{[]string{wa + "/base.apk"}, "", "", "no package name"},
	} {
		if got := appInstallFromPaths(c.paths, c.pkg); got != c.want {
			t.Errorf("%s: appInstallFromPaths(%q) = %q, want %q", c.why, c.pkg, got, c.want)
		}
	}
}

func TestAppInstallRejectsSystemUIDs(t *testing.T) {
	r := []Region{{Path: "/data/app/~~a==/com.x-b==/base.apk"}}
	for _, uid := range []int{0, androidSystemUID} {
		if got := AppInstall(1, uid, "com.x", r); got != "" {
			t.Errorf("uid %d: AppInstall = %q, want \"\" (such an app could forge its install dir)", uid, got)
		}
	}
}
