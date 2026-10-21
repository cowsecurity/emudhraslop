package platform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Only ordinary local drive paths are accepted. Device namespaces, network
// shares, alternate streams and DOS device names are not scan inputs.
func ValidPath(path string) bool {
	if len(path) < 3 || len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path[1] != ':' || strings.ContainsAny(path, "\x00\n\r/") || strings.Contains(path[2:], ":") {
		return false
	}
	if (path[0] < 'A' || path[0] > 'Z') && (path[0] < 'a' || path[0] > 'z') {
		return false
	}
	for _, part := range strings.Split(path[3:], `\`) {
		name := strings.ToUpper(strings.TrimRight(strings.SplitN(part, ".", 2)[0], " "))
		if strings.TrimRight(part, " .") != part || name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" || name == "CONIN$" || name == "CONOUT$" || name == "COM¹" || name == "COM²" || name == "COM³" || name == "LPT¹" || name == "LPT²" || name == "LPT³" || (len(name) == 4 && (strings.HasPrefix(name, "COM") || strings.HasPrefix(name, "LPT")) && name[3] >= '0' && name[3] <= '9') {
			return false
		}
	}
	return true
}

func OpenRead(path string) (*os.File, error) {
	if !ValidPath(path) {
		return nil, errors.New("ordinary local file path required")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !ValidPath(resolved) {
		return nil, errors.New("local file cannot be resolved")
	}
	p, err := syscall.UTF16PtrFromString(resolved)
	if err != nil {
		return nil, err
	}
	// Opening the final component itself prevents replacement by a named pipe
	// symlink. Directory access is needed for bounded CApath fingerprinting.
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), resolved)
	info, err := f.Stat()
	kind, typeErr := syscall.GetFileType(h)
	if err != nil || typeErr != nil || kind != syscall.FILE_TYPE_DISK || info.Mode()&os.ModeSymlink != 0 {
		f.Close()
		return nil, errors.New("ordinary local disk file required")
	}
	return f, nil
}
