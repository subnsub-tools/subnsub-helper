//go:build !unix

package main

import (
	"errors"
	"os"
)

type portsPin struct{}

func portsPinOpen(int) (*portsPin, error) { return &portsPin{}, nil }

func (k *portsPin) exact() bool { return false }

func (k *portsPin) signal(bool) error { return errors.ErrUnsupported }

func (k *portsPin) close() {}

func portsOpenRegular(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, errNotRegular
	}
	return f, nil
}
