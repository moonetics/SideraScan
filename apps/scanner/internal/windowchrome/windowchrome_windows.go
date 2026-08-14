//go:build windows

package windowchrome

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	gwlStyle        = ^uintptr(15) // -16
	htCaption       = 2
	wmNCLButtonDown = 0x00A1

	swpNoSize       = 0x0001
	swpNoMove       = 0x0002
	swpNoZOrder     = 0x0004
	swpFrameChanged = 0x0020

	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsThickFrame  = 0x00040000
	wsMinimizeBox = 0x00020000
	wsMaximizeBox = 0x00010000
)

var (
	user32                       = syscall.NewLazyDLL("user32.dll")
	procFindWindowW              = user32.NewProc("FindWindowW")
	procEnumWindows              = user32.NewProc("EnumWindows")
	procGetWindowThreadProcessID = user32.NewProc("GetWindowThreadProcessId")
	procIsWindowVisible          = user32.NewProc("IsWindowVisible")
	procGetWindowLongPtr         = user32.NewProc("GetWindowLongPtrW")
	procSetWindowLongPtr         = user32.NewProc("SetWindowLongPtrW")
	procSetWindowPos             = user32.NewProc("SetWindowPos")
	procGetWindowRect            = user32.NewProc("GetWindowRect")
	procReleaseCapture           = user32.NewProc("ReleaseCapture")
	procSendMessageW             = user32.NewProc("SendMessageW")
)

type rect struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

// ApplyFrameless removes native Windows decorations for the scanner window.
func ApplyFrameless(title string) bool {
	hwnd := findScannerWindow(title)
	if hwnd == 0 {
		return false
	}

	style, _, _ := procGetWindowLongPtr.Call(hwnd, gwlStyle)
	if style == 0 {
		return false
	}

	style &^= wsCaption | wsSysMenu | wsThickFrame | wsMinimizeBox | wsMaximizeBox
	procSetWindowLongPtr.Call(hwnd, gwlStyle, style)
	procSetWindowPos.Call(hwnd, 0, 0, 0, 0, 0, swpNoMove|swpNoSize|swpNoZOrder|swpFrameChanged)
	return true
}

// BeginDrag asks Windows to move the frameless window as if its caption was dragged.
func BeginDrag(title string) bool {
	hwnd := findScannerWindow(title)
	if hwnd == 0 {
		return false
	}

	procReleaseCapture.Call()
	procSendMessageW.Call(hwnd, wmNCLButtonDown, htCaption, 0)
	return true
}

// MoveBy moves the scanner window by a pointer drag delta.
func MoveBy(title string, dx float32, dy float32) bool {
	hwnd := findScannerWindow(title)
	if hwnd == 0 {
		return false
	}

	var bounds rect
	ok, _, _ := procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&bounds)))
	if ok == 0 {
		return false
	}

	x := int(bounds.Left + int32(dx))
	y := int(bounds.Top + int32(dy))
	procSetWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), 0, 0, swpNoSize|swpNoZOrder)
	return true
}

func findWindow(title string) uintptr {
	titlePtr, err := syscall.UTF16PtrFromString(title)
	if err != nil {
		return 0
	}
	hwnd, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(titlePtr)))
	return hwnd
}

func findScannerWindow(title string) uintptr {
	if hwnd := findWindow(title); hwnd != 0 {
		return hwnd
	}

	currentPID := uint32(os.Getpid())
	var found uintptr
	callback := syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		visible, _, _ := procIsWindowVisible.Call(hwnd)
		if visible == 0 {
			return 1
		}

		var pid uint32
		procGetWindowThreadProcessID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if pid == currentPID {
			found = hwnd
			return 0
		}
		return 1
	})
	procEnumWindows.Call(callback, 0)
	return found
}
