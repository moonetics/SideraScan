//go:build !windows

package windowchrome

// ApplyFrameless is a no-op fallback on non-Windows platforms.
func ApplyFrameless(_ string) bool {
	return false
}

// BeginDrag is a no-op fallback on non-Windows platforms.
func BeginDrag(_ string) bool {
	return false
}

// MoveBy is a no-op fallback on non-Windows platforms.
func MoveBy(_ string, _ float32, _ float32) bool {
	return false
}
