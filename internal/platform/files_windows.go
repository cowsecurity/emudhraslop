package platform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
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

var ntOpenFile = syscall.NewLazyDLL("ntdll.dll").NewProc("NtOpenFile")
var queryDosDevice = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryDosDeviceW")

type unicodeString struct {
	Length, MaximumLength uint16
	Buffer                *uint16
}
type objectAttributes struct {
	Length                                       uint32
	RootDirectory                                syscall.Handle
	ObjectName                                   *unicodeString
	Attributes                                   uint32
	SecurityDescriptor, SecurityQualityOfService uintptr
}
type ioStatusBlock struct{ Status, Information uintptr }

func OpenRead(path string) (*os.File, error) {
	if !ValidPath(path) {
		return nil, errors.New("ordinary local file path required")
	}
	native, err := localVolumePath(path)
	if err != nil {
		return nil, err
	}
	encoded, err := syscall.UTF16FromString(native)
	if err != nil {
		return nil, err
	}
	name := unicodeString{Length: uint16((len(encoded) - 1) * 2), MaximumLength: uint16(len(encoded) * 2), Buffer: &encoded[0]}
	attrs := objectAttributes{Length: uint32(unsafe.Sizeof(objectAttributes{})), ObjectName: &name, Attributes: 0x40 | 0x1000} // CASE_INSENSITIVE | DONT_REPARSE
	var handle syscall.Handle
	var status ioStatusBlock
	// Kernel path parsing rejects every reparse component atomically. A chain of
	// userspace ancestor checks would still permit a junction-swap race. These
	// flags allow regular files/directories and open the final reparse point
	// itself, which is rejected below, without following its destination.
	result, _, _ := ntOpenFile.Call(uintptr(unsafe.Pointer(&handle)), syscall.GENERIC_READ|0x100000, uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&status)), syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, 0x20|0x4000|0x200000)
	if uint32(result) == 0xc000050b {
		return nil, ErrReparse
	} // STATUS_REPARSE_POINT_ENCOUNTERED
	// Preserve absence of an optional configuration file without weakening the
	// no-reparse boundary or treating permission/volume errors as absence.
	// MS-ERREF: STATUS_OBJECT_NAME_NOT_FOUND / STATUS_OBJECT_PATH_NOT_FOUND.
	if uint32(result) == 0xc0000034 || uint32(result) == 0xc000003a {
		return nil, os.ErrNotExist
	}
	if uint32(result) != 0 {
		return nil, errors.New("local file cannot be opened without reparsing")
	}
	var info syscall.ByHandleFileInformation
	err = syscall.GetFileInformationByHandle(handle, &info)
	kind, typeErr := syscall.GetFileType(handle)
	if err != nil || typeErr != nil || kind != syscall.FILE_TYPE_DISK || info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		syscall.CloseHandle(handle)
		if info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return nil, ErrReparse
		}
		return nil, errors.New("ordinary local disk file required")
	}
	return os.NewFile(uintptr(handle), path), nil
}

// Query the DOS alias without opening it, then address the stable local volume
// directly. Mapped network drives and SUBST aliases are unsupported; a caller
// cannot redirect a drive-letter lookup into SMB after validation.
func localVolumePath(path string) (string, error) {
	drive, _ := syscall.UTF16PtrFromString(path[:2])
	buffer := make([]uint16, 1024)
	n, _, _ := queryDosDevice.Call(uintptr(unsafe.Pointer(drive)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if n == 0 || n >= uintptr(len(buffer)) {
		return "", errors.New("local volume mapping unavailable")
	}
	target := syscall.UTF16ToString(buffer)
	const prefix = `\Device\HarddiskVolume`
	suffix, ok := strings.CutPrefix(target, prefix)
	if !ok || suffix == "" {
		return "", ErrNonlocal
	}
	for _, digit := range suffix {
		if digit < '0' || digit > '9' {
			return "", ErrNonlocal
		}
	}
	return target + path[2:], nil
}
