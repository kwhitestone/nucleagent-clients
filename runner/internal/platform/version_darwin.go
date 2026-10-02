//go:build darwin

package platform

import (
	"errors"
	"golang.org/x/sys/unix"
	"strconv"
	"strings"
)

func minimumOS() error {
	version, err := unix.Sysctl("kern.osproductversion")
	if err != nil {
		return err
	}
	major, err := strconv.Atoi(strings.Split(version, ".")[0])
	if err != nil || major < 15 {
		return errors.New("macOS 15 or later required")
	}
	return nil
}
