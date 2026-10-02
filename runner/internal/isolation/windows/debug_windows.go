//go:build windows

package isolation

import (
	"encoding/binary"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Diagnostic only, x64 PEB NtGlobalFlag. This enables loader messages in a
// disposable suspended child; it does not change token/ACL/job policy.
func loaderSnaps(process windows.Handle) error {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return fmt.Errorf("loader tracing requires x64")
	}
	var info windows.PROCESS_BASIC_INFORMATION
	if err := windows.NtQueryInformationProcess(process, 0, unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), nil); err != nil {
		return err
	}
	var flags [4]byte
	addr := uintptr(unsafe.Pointer(info.PebBaseAddress)) + 0xbc
	if err := windows.ReadProcessMemory(process, addr, &flags[0], 4, nil); err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(flags[:], binary.LittleEndian.Uint32(flags[:])|2)
	return windows.WriteProcessMemory(process, addr, &flags[0], 4, nil)
}

func debugWait(process windows.Handle, result *ProbeResult) error {
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	wait := kernel.NewProc("WaitForDebugEventEx")
	cont := kernel.NewProc("ContinueDebugEvent")
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var ev struct {
			Code, PID, TID, Padding uint32
			Data                    [160]byte
		}
		r, _, err := wait.Call(uintptr(unsafe.Pointer(&ev)), 1000)
		if r == 0 {
			if err == windows.ERROR_SEM_TIMEOUT {
				continue
			}
			return err
		}
		status := uint32(0x10002)
		switch ev.Code {
		case 1:
			code := binary.LittleEndian.Uint32(ev.Data[:4])
			result.LoaderTrace = append(result.LoaderTrace, fmt.Sprintf("exception 0x%08x", code))
			if code != 0x80000003 {
				status = 0x80010001
			}
		case 3, 6:
			h := windows.Handle(binary.LittleEndian.Uint64(ev.Data[:8]))
			if h != 0 {
				var path [32768]uint16
				if n, err := windows.GetFinalPathNameByHandle(h, &path[0], uint32(len(path)), 0); err == nil {
					result.LoaderTrace = append(result.LoaderTrace, "image "+windows.UTF16ToString(path[:n]))
				}
				windows.CloseHandle(h)
			}
		case 8:
			addr := uintptr(binary.LittleEndian.Uint64(ev.Data[:8]))
			wide := binary.LittleEndian.Uint16(ev.Data[8:10]) != 0
			n := int(binary.LittleEndian.Uint16(ev.Data[10:12]))
			if wide {
				n *= 2
			}
			if n > 0 && n < 65536 {
				b := make([]byte, n)
				if err := windows.ReadProcessMemory(process, addr, &b[0], uintptr(n), nil); err == nil {
					if wide {
						u := make([]uint16, n/2)
						for i := range u {
							u[i] = binary.LittleEndian.Uint16(b[i*2:])
						}
						result.LoaderTrace = append(result.LoaderTrace, windows.UTF16ToString(u))
					} else {
						result.LoaderTrace = append(result.LoaderTrace, string(b))
					}
				}
			}
		}
		r, _, err = cont.Call(uintptr(ev.PID), uintptr(ev.TID), uintptr(status))
		if r == 0 {
			return err
		}
		if ev.Code == 5 {
			return nil
		}
	}
	result.TimedOut = true
	return fmt.Errorf("debug probe timed out")
}
