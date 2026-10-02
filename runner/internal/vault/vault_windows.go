//go:build windows

package vault

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func blob(data []byte) *windows.DataBlob {
	return &windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
}
func (s *Store) write(raw []byte) error {
	var encrypted windows.DataBlob
	entropy := []byte(s.service)
	if err := windows.CryptProtectData(blob(raw), nil, blob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &encrypted); err != nil {
		return errors.New("Windows device credential protection failed")
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(encrypted.Data))))
	f, err := os.CreateTemp(s.root, "credential-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(unsafe.Slice(encrypted.Data, int(encrypted.Size)))
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(s.root, "device.dpapi"))
}
func (s *Store) read() ([]byte, error) {
	path := filepath.Join(s.root, "device.dpapi")
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 65536 {
		return nil, errors.New("unsafe device credential file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("empty device credential")
	}
	var decrypted windows.DataBlob
	entropy := []byte(s.service)
	if err = windows.CryptUnprotectData(blob(data), nil, blob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &decrypted); err != nil {
		return nil, errors.New("Windows device credential could not be decrypted")
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(decrypted.Data))))
	view := unsafe.Slice(decrypted.Data, int(decrypted.Size))
	raw := append([]byte(nil), view...)
	clear(view)
	return raw, nil
}
func (s *Store) remove() error {
	err := os.Remove(filepath.Join(s.root, "device.dpapi"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
