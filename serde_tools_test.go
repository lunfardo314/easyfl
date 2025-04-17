package easyfl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLibrary_ToYAML_not_compiled(t *testing.T) {
	lib := NewBase()
	lib.PrintLibraryStats()
	yamlData := lib.ToYAML(false, "# ------------- base library for testing")
	t.Logf("----------------------------\n%s", string(yamlData))

	_, err := ReadLibraryFromYAML(yamlData)
	require.NoError(t, err)

	//os.WriteFile("base.yaml", yamlData, 0644)
}

func TestLibrary_base_compiled(t *testing.T) {
	lib := NewBase()
	lib.PrintLibraryStats()
	yamlData := lib.ToYAML(true, "# ------------- base library for testing")
	t.Logf("----------------------------\n%s", string(yamlData))

	_, err := ReadLibraryFromYAML(yamlData)
	require.NoError(t, err)
}

func TestLibrary_ToYAML_validate(t *testing.T) {
	lib := NewBase()
	lib.PrintLibraryStats()
	// not compiled
	yamlData := lib.ToYAML(true, "# ------------- base library for testing")
	t.Logf("----------------------------\n%s", string(yamlData))

	compiled, err := ReadLibraryFromYAML(yamlData)
	require.NoError(t, err)
	err = compiled.ValidateCompiled()
	require.NoError(t, err)
}

func TestLibrary_ToYAML_upgrade(t *testing.T) {
	lib := NewBase()
	lib.PrintLibraryStats()

	yamlData := `
functions:
  -
    description: "some description"
    sym: newfun
    source: concat(0x, 0x111111, 2)
  -
    description: none
    sym: newfun2
    source: add(5,7)
  -
   sym: long-source
   source: > 
     if(
       equal($0,$1),
       blake2b($0),
       blake2b(concat($0,$1))
     )
  -
    sym: dummy
    source: add(5,7)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)

	err = lib.Upgrade(fromYaml)
	require.NoError(t, err)

	lib.MustEqual("newfun", "0x11111102")
	lib.MustEqual("newfun2", "uint8Bytes(12)")
	back := lib.ToYAML(true, "upgraded library")
	t.Logf("------------- UPGRADED (%d bytes)\n%s", len(back), string(back))
}
