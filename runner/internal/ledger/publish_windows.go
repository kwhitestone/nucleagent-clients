//go:build windows

package ledger

import "golang.org/x/sys/windows"

func publish(staged, destination string) error {
	src, err := windows.UTF16PtrFromString(staged)
	if err != nil {
		return err
	}
	dst, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(src, dst, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
