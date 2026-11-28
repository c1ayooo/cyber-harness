package tool

import (
	"runtime"
	"strings"
)

// posixDrivePath converts an MSYS-style absolute path (/c/Windows/System32/
// curl.exe) into its native form (C:\Windows\System32\curl.exe).
//
// The embedded shell keeps POSIX syntax while external programs are native, so
// a model that types an absolute POSIX path for an executable got
// "executable file not found" even though the file was right there (observed on
// 2026-11-20: CURL=/c/WINDOWS/system32/curl.exe). Only the program name is
// translated — ordinary arguments keep whatever spelling the caller used, so
// this cannot rewrite a URL or a data value.
func posixDrivePath(p string) (string, bool) {
	if runtime.GOOS != "windows" || len(p) < 3 || p[0] != '/' || p[2] != '/' {
		return "", false
	}
	drive := p[1]
	if !(drive >= 'a' && drive <= 'z') && !(drive >= 'A' && drive <= 'Z') {
		return "", false
	}
	rest := strings.ReplaceAll(p[3:], "/", `\`)
	return strings.ToUpper(string(drive)) + `:\` + rest, true
}
