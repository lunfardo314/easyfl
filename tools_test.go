package easyfl

import "testing"

func TestLibrary_ToYAML(t *testing.T) {
	lib := NewBase()
	lib.PrintLibraryStats()
	yamlData := lib.ToYAML()
	t.Logf("----------------------------\n%s", string(yamlData))
}
