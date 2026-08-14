//go:build windows

package windows

import "testing"

func TestHiddenSysProcAttrUsesNoWindowFlags(t *testing.T) {
	attr := hiddenSysProcAttr()
	if attr == nil {
		t.Fatal("expected sys proc attr")
	}
	if !attr.HideWindow {
		t.Fatal("expected hidden window")
	}
	if attr.CreationFlags&createNoWindow == 0 {
		t.Fatalf("expected CREATE_NO_WINDOW flag, got %d", attr.CreationFlags)
	}
}
