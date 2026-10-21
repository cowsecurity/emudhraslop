package probe

import (
	"github.com/cowsecurity/emudhraslop/internal/model"
	"os"
)

// Windows probes run only as the current non-elevated token; there is no Unix
// identity dropping or root reader copying data into another account here.
func nativeDropsIdentity(model.Target) bool { return false }
func nativeTemp(model.Target) (string, func(), error) {
	dir, err := os.MkdirTemp("", "emudhraslop-native-")
	return dir, func() { _ = os.RemoveAll(dir) }, err
}
func nativeWrite(_ model.Target, path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}
func nativeCache(_ model.Target, dir string) error { return os.Mkdir(dir, 0700) }
