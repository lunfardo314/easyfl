package easyfl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLibrary_ToYAML(t *testing.T) {
	lib := NewBase()
	lib.PrintLibraryStats()
	yamlData := lib.ToYAML()
	t.Logf("----------------------------\n%s", string(yamlData))

	_, err := ReadLibraryFromYAML(yamlData)
	require.NoError(t, err)
}
