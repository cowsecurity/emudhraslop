//go:build !windows

package platform

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func ValidPath(path string) bool {
	return len(path) <= 4096 && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsAny(path, "\x00\n\r")
}

func OpenRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
