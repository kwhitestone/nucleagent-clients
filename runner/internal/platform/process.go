// Package platform owns native worker lifetime and private filesystem policy.
package platform

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"
)

type Spec struct {
	Executable string
	Args, Env  []string
	Directory  string
}
type Process struct {
	Stdin     io.WriteCloser
	Stdout    io.ReadCloser
	Stderr    io.ReadCloser
	PID       int
	done      chan struct{}
	err       error
	terminate func() error
}

func (s Spec) validate() error {
	if !filepath.IsAbs(s.Executable) || !filepath.IsAbs(s.Directory) || len(s.Env) == 0 {
		return errors.New("worker requires absolute paths and an explicit environment")
	}
	for _, v := range append(append([]string{s.Executable, s.Directory}, s.Args...), s.Env...) {
		if strings.ContainsRune(v, 0) {
			return errors.New("NUL in worker specification")
		}
	}
	return nil
}
func (p *Process) Done() <-chan struct{} { return p.done }
func (p *Process) Wait() error           { <-p.done; return p.err }
func (p *Process) Stop(ctx context.Context) error {
	_ = p.Stdin.Close()
	if err := p.terminate(); err != nil {
		return err
	}
	select {
	case <-p.done:
		return nil
	case <-ctx.Done():
		return errors.New("worker cleanup timed out")
	}
}
func (p *Process) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := p.Stop(ctx)
	p.Stdout.Close()
	p.Stderr.Close()
	return err
}
