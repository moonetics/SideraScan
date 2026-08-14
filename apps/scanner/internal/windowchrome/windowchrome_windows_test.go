//go:build windows

package windowchrome

import "testing"

func TestMissingWindowIsSafe(t *testing.T) {
	title := "SideraScan missing window test"
	if ApplyFrameless(title) {
		t.Fatal("expected ApplyFrameless to return false for missing window")
	}
	if BeginDrag(title) {
		t.Fatal("expected BeginDrag to return false for missing window")
	}
	if MoveBy(title, 12, 8) {
		t.Fatal("expected MoveBy to return false for missing window")
	}
}
