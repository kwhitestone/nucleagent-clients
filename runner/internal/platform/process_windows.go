//go:build windows

package platform

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

func Start(s Spec) (*Process, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if err := validateWindowsTask(s); err != nil {
		return nil, errors.Join(ErrIsolationUnavailable, err)
	}
	desk, err := newTaskDesktop()
	if err != nil {
		return nil, errors.Join(ErrIsolationUnavailable, err)
	}
	owned := false
	defer func() {
		if !owned {
			_ = desk.close()
		}
	}()
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !owned {
			windows.CloseHandle(job)
		}
	}()
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_JOB_MEMORY
	limits.BasicLimitInformation.ActiveProcessLimit = 64
	limits.JobMemoryLimit = 2 << 30
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return nil, err
	}
	// Rate is a percentage of total host CPU, capped at two logical cores.
	rate := uint32(20000 / runtime.NumCPU())
	if rate > 10000 {
		rate = 10000
	}
	if rate < 1 {
		rate = 1
	}
	cpu := struct {
		ControlFlags uint32
		CpuRate      uint32
	}{1 | 4, rate}
	if _, err = windows.SetInformationJobObject(job, 15, uintptr(unsafe.Pointer(&cpu)), uint32(unsafe.Sizeof(cpu))); err != nil {
		return nil, err
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return nil, err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		return nil, err
	}
	files := []*os.File{inR, inW, outR, outW, errR, errW}
	defer func() {
		if !owned {
			for _, f := range files {
				f.Close()
			}
		}
	}()
	var handles []windows.Handle
	defer func() {
		for _, h := range handles {
			windows.CloseHandle(h)
		}
	}()
	for _, f := range []*os.File{inR, outW, errW} {
		var h windows.Handle
		if err = windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(f.Fd()), windows.CurrentProcess(), &h, 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return nil, err
		}
		handles = append(handles, h)
	}
	attrs, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return nil, err
	}
	defer attrs.Delete()
	if err = attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return nil, err
	}
	// Atomic membership prevents an orphan between process creation and Job assignment.
	if err = attrs.Update(0x0002000d, unsafe.Pointer(&job), unsafe.Sizeof(job)); err != nil {
		return nil, err
	}
	si := windows.StartupInfoEx{}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdInput = handles[0]
	si.StdOutput = handles[1]
	si.StdErr = handles[2]
	si.ProcThreadAttributeList = attrs.List()
	si.Desktop, _ = windows.UTF16PtrFromString(desk.name)
	argv := []string{windows.EscapeArg(s.Executable)}
	for _, a := range s.Args {
		argv = append(argv, windows.EscapeArg(a))
	}
	command, err := windows.UTF16PtrFromString(strings.Join(argv, " "))
	if err != nil {
		return nil, err
	}
	app, _ := windows.UTF16PtrFromString(s.Executable)
	cwd, _ := windows.UTF16PtrFromString(s.Directory)
	env := append([]string(nil), s.Env...)
	sort.Slice(env, func(i, j int) bool { return strings.ToUpper(env[i]) < strings.ToUpper(env[j]) })
	block := utf16.Encode([]rune(strings.Join(env, "\x00") + "\x00\x00"))
	pi := windows.ProcessInformation{}
	// CREATE_NO_WINDOW is required for nested Codex sandbox console commands;
	// DETACHED_PROCESS hung command/exec in the native composition acceptance.
	if err = windows.CreateProcess(app, command, nil, nil, true, windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW|windows.CREATE_UNICODE_ENVIRONMENT|windows.EXTENDED_STARTUPINFO_PRESENT, &block[0], cwd, &si.StartupInfo, &pi); err != nil {
		return nil, err
	}
	defer windows.CloseHandle(pi.Thread)
	abort := func() { windows.TerminateProcess(pi.Process, 1); windows.CloseHandle(pi.Process) }
	var inJob int32
	r, _, checkErr := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob").Call(uintptr(pi.Process), uintptr(job), uintptr(unsafe.Pointer(&inJob)))
	if r == 0 || inJob == 0 {
		err = fmt.Errorf("worker Job verification: %v", checkErr)
		abort()
		return nil, err
	}
	if _, err = windows.ResumeThread(pi.Thread); err != nil {
		abort()
		return nil, err
	}
	inR.Close()
	outW.Close()
	errW.Close()
	p := &Process{Stdin: inW, Stdout: outR, Stderr: errR, PID: int(pi.ProcessId), done: make(chan struct{})}
	var mu sync.Mutex
	closed := false
	p.terminate = func() error {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			return nil
		}
		return windows.TerminateJobObject(job, 1)
	}
	owned = true
	go func() {
		_, waitErr := windows.WaitForSingleObject(pi.Process, windows.INFINITE)
		var code uint32
		if waitErr == nil {
			waitErr = windows.GetExitCodeProcess(pi.Process, &code)
		}
		if waitErr != nil {
			p.err = waitErr
		} else if code != 0 {
			p.err = fmt.Errorf("worker exited with status %d", code)
		}
		mu.Lock()
		cleanupErr := windows.TerminateJobObject(job, 1)
		// Wait for all descendants before releasing desktop or acknowledging cleanup.
		until := time.Now().Add(4 * time.Second)
		for {
			var accounting jobAccounting
			e := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil)
			if e != nil {
				cleanupErr = errors.Join(cleanupErr, e)
				break
			}
			if accounting.ActiveProcesses == 0 {
				break
			}
			if time.Now().After(until) {
				cleanupErr = errors.Join(cleanupErr, errors.New("Job descendants still active"))
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		cleanupErr = errors.Join(cleanupErr, windows.CloseHandle(job), desk.close())
		p.cleanupErr = cleanupErr
		closed = true
		mu.Unlock()
		windows.CloseHandle(pi.Process)
		close(p.done)
	}()
	return p, nil
}

func PrivateDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := rejectReparsePath(dir); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe private directory")
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
