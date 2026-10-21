package platform

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unicode/utf16"
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

func TestWindowsOptionalFileAbsenceIsDistinctFromUnsafePaths(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{filepath.Join(root, "pyvenv.cfg"), filepath.Join(root, "missing", "pyvenv.cfg")} {
		file, err := OpenRead(path)
		if file != nil {
			file.Close()
			t.Fatal("missing file opened")
		}
		if !os.IsNotExist(err) {
			t.Fatalf("missing optional file lost its error class: %v", err)
		}
	}
	for _, path := range []string{`\\server\share\pyvenv.cfg`, `C:\NUL`, `C:\dir\file:stream`} {
		file, err := OpenRead(path)
		if file != nil {
			file.Close()
			t.Fatal("unsafe path opened")
		}
		if err == nil || os.IsNotExist(err) {
			t.Fatal("unsafe path disguised as missing optional configuration")
		}
	}
}

// Mount points can be created in an owned directory by a standard account;
// unlike symbolic links, these tests need no developer-mode privilege.
func junction(t *testing.T, path, target string) error {
	t.Helper()
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_WRITE, 7, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	encoded := utf16.Encode([]rune(target))
	buffer := make([]byte, 16+(len(encoded)+1)*4)
	binary.LittleEndian.PutUint32(buffer, 0xa0000003) // IO_REPARSE_TAG_MOUNT_POINT
	binary.LittleEndian.PutUint16(buffer[4:], uint16(len(buffer)-8))
	binary.LittleEndian.PutUint16(buffer[10:], uint16(len(encoded)*2))
	binary.LittleEndian.PutUint16(buffer[12:], uint16((len(encoded)+1)*2))
	binary.LittleEndian.PutUint16(buffer[14:], uint16(len(encoded)*2))
	for i, code := range encoded {
		binary.LittleEndian.PutUint16(buffer[16+i*2:], code)
		binary.LittleEndian.PutUint16(buffer[16+(len(encoded)+1+i)*2:], code)
	}
	var returned uint32
	return syscall.DeviceIoControl(h, 0x900a4, &buffer[0], uint32(len(buffer)), nil, 0, &returned, nil) // FSCTL_SET_REPARSE_POINT
}

func TestWindowsAncestorJunctionRejectedBeforeDestinationLookup(t *testing.T) {
	for _, target := range []string{`\??\C:\emudhraslop-destination-must-not-be-looked-up`, `\??\UNC\emudhraslop-does-not-exist.invalid\share`} {
		t.Run(target, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "junction")
			if err := junction(t, path, target); err != nil {
				t.Fatalf("cannot create adversarial junction: %v", err)
			}
			// The destination and child do not exist. ErrReparse specifically
			// proves failure occurred before a destination not-found/network error.
			f, err := OpenRead(filepath.Join(path, "roots.pem"))
			if f != nil {
				f.Close()
			}
			if !errors.Is(err, ErrReparse) {
				t.Fatalf("ancestor not rejected at reparse boundary: %v", err)
			}
		})
	}
}
