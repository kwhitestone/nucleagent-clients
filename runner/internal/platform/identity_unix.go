//go:build darwin || linux

package platform

import "os"

func elevatedIdentity() (bool, error) { return os.Geteuid() == 0, nil }
