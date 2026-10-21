package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsRejectsDeviceNetworkAndStreamPaths(t *testing.T) {
	for _, path := range []string{`\\.\pipe\test`, `\\server\share\file`, `\\?\C:\file`, `C:\file:secret`, `C:\NUL`, `C:\CON.txt`, `C:\COM1`, `C:\dir.\file`, `C:\dir\file `, `C:relative`, `C:/file`} {
		if ValidPath(path) {
			t.Fatalf("unsafe path accepted: %q", path)
		}
		if f, err := OpenRead(path); err == nil {
			f.Close()
			t.Fatal("unsafe path opened")
		}
	}
}
func TestWindowsLocalRegularFileReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ordinary.pem")
	if err := os.WriteFile(path, []byte("public fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := OpenRead(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("regular file was not opened")
	}
}
