//go:build !windows

package crypto

func NewProtector() Protector {
	return UnsupportedProtector{}
}
