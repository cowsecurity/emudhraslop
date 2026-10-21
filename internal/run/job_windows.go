package run

import (
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var createJob = kernel32.NewProc("CreateJobObjectW")
var setJob = kernel32.NewProc("SetInformationJobObject")
var assignJob = kernel32.NewProc("AssignProcessToJobObject")
var stopJob = kernel32.NewProc("TerminateJobObject")
var firstThread = kernel32.NewProc("Thread32First")
var nextThread = kernel32.NewProc("Thread32Next")
var openThread = kernel32.NewProc("OpenThread")
var resumeThread = kernel32.NewProc("ResumeThread")
var getWindowsDirectory = kernel32.NewProc("GetWindowsDirectoryW")

// Layout follows JOBOBJECT_EXTENDED_LIMIT_INFORMATION on Windows amd64/arm64.
type jobLimits struct {
	ProcessTime, JobTime                                       int64
	Flags                                                      uint32
	MinWorkingSet, MaxWorkingSet                               uintptr
	ActiveProcesses                                            uint32
	Affinity                                                   uintptr
	PriorityClass, SchedulingClass                             uint32
	IO                                                         [6]uint64
	ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory uintptr
}
type threadEntry struct {
	Size, Usage, ID, OwnerPID   uint32
	BasePriority, DeltaPriority int32
	Flags                       uint32
}

func newJob() (syscall.Handle, error) {
	h, _, err := createJob.Call(0, 0)
	if h == 0 {
		return 0, err
	}
	limits := jobLimits{Flags: 0x2000 | 0x8, ActiveProcesses: 8} // KILL_ON_JOB_CLOSE | ACTIVE_PROCESS
	// Probe scripts need no fan-out; permit a small bounded helper tree.
	ok, _, err := setJob.Call(h, 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
	if ok == 0 {
		syscall.CloseHandle(syscall.Handle(h))
		return 0, err
	}
	return syscall.Handle(h), nil
}
func terminateJob(job syscall.Handle) error {
	ok, _, err := stopJob.Call(uintptr(job), 1)
	if ok == 0 {
		return err
	}
	return nil
}
func attachAndResume(job syscall.Handle, pid uint32) error {
	process, err := syscall.OpenProcess(0x0100|0x0001, false, pid) // SET_QUOTA | TERMINATE
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(process)
	ok, _, err := assignJob.Call(uintptr(job), uintptr(process))
	if ok == 0 {
		return err
	}
	snapshot, err := syscall.CreateToolhelp32Snapshot(0x4, 0) // TH32CS_SNAPTHREAD
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(snapshot)
	entry := threadEntry{Size: uint32(unsafe.Sizeof(threadEntry{}))}
	ok, _, _ = firstThread.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&entry)))
	// Bound system-wide iteration; exceeding this fails closed, never truncates
	// a scan result into a successful process launch.
	for count := 0; ok != 0 && count < 65536; count++ {
		if entry.OwnerPID == pid {
			thread, _, e := openThread.Call(0x0002, 0, uintptr(entry.ID)) // SUSPEND_RESUME
			if thread == 0 {
				return e
			}
			previous, _, e := resumeThread.Call(thread)
			syscall.CloseHandle(syscall.Handle(thread))
			if previous == 0xffffffff || previous != 1 {
				return errors.New("unexpected suspended thread state")
			}
			_ = e
			return nil
		}
		ok, _, _ = nextThread.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&entry)))
	}
	return errors.New("suspended primary thread unavailable")
}
func systemWindowsDirectory() (string, error) {
	b := make([]uint16, 32768)
	n, _, err := getWindowsDirectory.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if n == 0 || n >= uintptr(len(b)) {
		return "", err
	}
	return syscall.UTF16ToString(b[:n]), nil
}
func stringsExe(path string) bool { return strings.EqualFold(filepath.Ext(path), ".exe") }
