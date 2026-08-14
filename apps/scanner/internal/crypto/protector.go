package crypto

import "errors"

var ErrUnsupported = errors.New("data protection is unsupported on this platform")

type Protector interface {
	Protect([]byte) ([]byte, error)
	Unprotect([]byte) ([]byte, error)
}

type UnsupportedProtector struct{}

func (UnsupportedProtector) Protect([]byte) ([]byte, error) {
	return nil, ErrUnsupported
}

func (UnsupportedProtector) Unprotect([]byte) ([]byte, error) {
	return nil, ErrUnsupported
}
