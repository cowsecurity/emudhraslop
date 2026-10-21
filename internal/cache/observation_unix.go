//go:build !windows

package cache

import (
	"io"
	"os"
	"syscall"
)

func readObservation(path string) ([]byte, error) {
	if err := inspect(path, true); err != nil {
		return nil, ErrInvalid
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !private(before, false) || before.Size() > maxReportBytes {
		return nil, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(file, maxReportBytes+1))
	if err != nil || len(data) > maxReportBytes {
		return nil, ErrInvalid
	}
	after, err := file.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !private(after, false) || !os.SameFile(before, current) ||
		before.Size() != int64(len(data)) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) ||
		!current.ModTime().Equal(after.ModTime()) || inspect(path, true) != nil {
		return nil, ErrInvalid
	}
	return data, nil
}
