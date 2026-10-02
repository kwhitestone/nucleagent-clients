//go:build darwin || linux

package platform

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

func Start(s Spec) (*Process, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	cmd := exec.Command(s.Executable, s.Args...)
	cmd.Dir = s.Directory
	cmd.Env = s.Env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	inR, in, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	out, outW, err := os.Pipe()
	if err != nil {
		in.Close()
		inR.Close()
		return nil, err
	}
	stderr, errW, err := os.Pipe()
	if err != nil {
		in.Close()
		inR.Close()
		out.Close()
		outW.Close()
		return nil, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW
	if err = cmd.Start(); err != nil {
		in.Close()
		inR.Close()
		out.Close()
		outW.Close()
		stderr.Close()
		errW.Close()
		return nil, err
	}
	inR.Close()
	outW.Close()
	errW.Close()
	p := &Process{Stdin: in, Stdout: out, Stderr: stderr, PID: cmd.Process.Pid, done: make(chan struct{})}
	var stop sync.Once
	var stopErr error
	p.terminate = func() error {
		stop.Do(func() {
			stopErr = syscall.Kill(-p.PID, syscall.SIGKILL)
			if errors.Is(stopErr, syscall.ESRCH) {
				stopErr = nil
			}
		})
		return stopErr
	}
	go func() { p.err = cmd.Wait(); _ = p.terminate(); close(p.done) }()
	return p, nil
}

func PrivateDirectory(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe private directory")
	}
	return os.Chmod(dir, 0700)
}
