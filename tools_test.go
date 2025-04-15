package easyfl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLibrary_ToYAML_no_compiled(t *testing.T) {
	lib := NewBase()
	lib.PrintLibraryStats()
	yamlData := lib.ToYAML("base library", false)
	t.Logf("----------------------------\n%s", string(yamlData))

	_, err := ReadLibraryFromYAML(yamlData)
	require.NoError(t, err)
}

func TestLibrary_ToYAML_compiled(t *testing.T) {
	lib := NewBase()
	lib.PrintLibraryStats()
	// not compiled
	yamlData := lib.ToYAML("base library", false)
	//t.Logf("------------- NOT COMPILED\n%s", string(yamlData))

	notCompiled, err := ReadLibraryFromYAML(yamlData)
	require.NoError(t, err)
	_, err = notCompiled.Compile()
	require.NoError(t, err)
	yamlData = lib.ToYAML("base library", true)
	t.Logf("------------- COMPILED\n%s", string(yamlData))
}

func TestLibrary_ToYAML_validate_compiled(t *testing.T) {
	lib := NewBase()
	lib.PrintLibraryStats()
	// not compiled
	yamlData := lib.ToYAML("base library", true)
	t.Logf("------------- COMPILED (%d bytes)\n%s", len(yamlData), string(yamlData))
	compiled, err := ReadLibraryFromYAML(yamlData)
	require.NoError(t, err)
	err = compiled.ValidateCompiled()
	require.NoError(t, err)
}

func TestLibrary_ToYAML_embed(t *testing.T) {
	lib := NewBase()
	lib.PrintLibraryStats()
	// not compiled
	yamlData := lib.ToYAML("base library", true)
	t.Logf("------------- COMPILED (%d bytes)\n%s", len(yamlData), string(yamlData))
	compiled, err := ReadLibraryFromYAML(yamlData)
	require.NoError(t, err)
	err = compiled.ValidateCompiled()
	require.NoError(t, err)
	lib1, err := compiled.Compile()
	require.NoError(t, err)
	err = lib1.Embed(BaseEmbeddingMap(lib1))
	require.NoError(t, err)
}
