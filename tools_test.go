package easyfl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLibrary_ToYAML_not_compiled(t *testing.T) {
	lib := NewBase()
	lib.PrintLibraryStats()
	yamlData := lib.ToYAML("base library", true)
	t.Logf("----------------------------\n%s", string(yamlData))

	_, err := ReadLibraryFromYAML(yamlData)
	require.NoError(t, err)

	//os.WriteFile("base.yaml", yamlData, 0644)
}

func TestLibrary_base_compiled(t *testing.T) {
	lib := NewBase()
	lib.PrintLibraryStats()
	yamlData := lib.ToYAML("base library", true)
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

func TestLibrary_ToYAML_upgrade(t *testing.T) {
	lib := NewBase()
	lib.PrintLibraryStats()

	yamlData := `
functions:
   -
     sym: newfun
     source: concat(0x, 0x111111, 2)
   -
     sym: newfun2
     source: add(5,7)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)

	err = lib.Upgrade(fromYaml)
	require.NoError(t, err)

	lib.MustEqual("newfun", "0x11111102")
	lib.MustEqual("newfun2", "uint8Bytes(12)")
	back := lib.ToYAML("upgraded library", true)
	t.Logf("------------- UPGRADED (%d bytes)\n%s", len(back), string(back))
}

func TestLibrary_base_compiled_const(t *testing.T) {
	libFromYAML, err := ReadLibraryFromYAML([]byte(baseLibraryDefinitions))
	require.NoError(t, err)
	err = libFromYAML.ValidateCompiled()
	require.NoError(t, err)
	lib, err := libFromYAML.Compile()
	require.NoError(t, err)
	err = lib.Embed(BaseEmbeddingMap(lib))
	require.NoError(t, err)
	lib.MustEqual("concat(1,2)", "0x0102")

}
