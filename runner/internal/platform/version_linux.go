//go:build linux

package platform

import "errors"

func minimumOS() error { return errors.New("Linux is fixture-only") }
