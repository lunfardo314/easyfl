package easyfl

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLibraryRenewYAML(t *testing.T) {
	lib := NewLibrary[any]()
	fromYAML, err := ReadLibraryFromYAML([]byte(baseLibraryDefinitions))
	require.NoError(t, err)
	err = lib.Upgrade(fromYAML)
	require.NoError(t, err)
	yamlData := lib.ToYAML(true, "# Base EasyFL library")
	t.Logf("size of the YAML file: %d bytes", len(yamlData))
	err = os.WriteFile("library.yaml", yamlData, 0644)
	require.NoError(t, err)
}

func TestLibrary_ToYAML_not_compiled(t *testing.T) {
	lib := NewBaseLibrary[any]()
	lib.PrintLibraryStats()
	yamlData := lib.ToYAML(false, "# ------------- base library for testing")
	t.Logf("----------------------------\n%s", string(yamlData))

	_, err := ReadLibraryFromYAML(yamlData)
	require.NoError(t, err)

	//os.WriteFile("base.yaml", yamlData, 0644)
}

func TestLibrary_base_compiled(t *testing.T) {
	lib := NewBaseLibrary[any]()
	lib.PrintLibraryStats()
	yamlData := lib.ToYAML(true, "# ------------- base library for testing")
	t.Logf("----------------------------\n%s", string(yamlData))

	_, err := ReadLibraryFromYAML(yamlData)
	require.NoError(t, err)
}

func TestLibrary_ToYAML_validate(t *testing.T) {
	lib := NewBaseLibrary[any]()
	lib.PrintLibraryStats()
	// not compiled
	yamlData := lib.ToYAML(true, "# ------------- base library for testing")
	t.Logf("----------------------------\n%s", string(yamlData))

	compiled, err := ReadLibraryFromYAML(yamlData)
	require.NoError(t, err)
	err = ValidateCompiled[any](compiled)
	require.NoError(t, err)
}

func TestLibrary_ToYAML_upgrade(t *testing.T) {
	lib := NewBaseLibrary[any]()
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
  -
    sym: "@dummy"
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

// Test adding new extended function (replace: false, default)
func TestUpgrade_AddNewExtended_Success(t *testing.T) {
	lib := NewBaseLibrary[any]()

	yamlData := `
functions:
  -
    sym: myNewFunc
    numArgs: 2
    source: add($0, $1)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)

	err = lib.Upgrade(fromYaml)
	require.NoError(t, err)

	// Verify function works
	lib.MustEqual("myNewFunc(3, 5)", "uint8Bytes(8)")
}

// Test adding function that already exists (replace: false) - should fail
func TestUpgrade_AddExisting_Fail(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// Try to add "add" which already exists in base library
	yamlData := `
functions:
  -
    sym: add
    numArgs: 2
    source: sub($0, $1)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)

	err = lib.Upgrade(fromYaml)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}

// Test replacing existing extended function (replace: true) - should succeed
func TestUpgrade_ReplaceExtended_Success(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// First add a function
	yamlData := `
functions:
  -
    sym: myFunc
    numArgs: 2
    source: add($0, $1)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml)
	require.NoError(t, err)

	// Get funCode before replacement
	fi, err := lib.functionByName("myFunc")
	require.NoError(t, err)
	funCodeBefore := fi.FunCode

	// Verify original behavior
	lib.MustEqual("myFunc(3, 5)", "uint8Bytes(8)")

	// Now replace it with different implementation
	yamlReplace := `
functions:
  -
    sym: myFunc
    numArgs: 2
    replace: true
    source: mul($0, $1)
`
	fromYamlReplace, err := ReadLibraryFromYAML([]byte(yamlReplace))
	require.NoError(t, err)
	err = lib.Upgrade(fromYamlReplace)
	require.NoError(t, err)

	// Verify new behavior
	lib.MustEqual("myFunc(3, 5)", "uint8Bytes(15)")

	// Verify funCode is preserved
	fi, err = lib.functionByName("myFunc")
	require.NoError(t, err)
	require.Equal(t, funCodeBefore, fi.FunCode, "funCode should be preserved after replacement")
}

// Test replacing non-existent function (replace: true) - should fail
func TestUpgrade_ReplaceNonExistent_Fail(t *testing.T) {
	lib := NewBaseLibrary[any]()

	yamlData := `
functions:
  -
    sym: nonExistentFunc
    numArgs: 2
    replace: true
    source: add($0, $1)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)

	err = lib.Upgrade(fromYaml)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not exist")
}

// Test replacing embedded function with new embedded_as
func TestUpgrade_ReplaceEmbedded_Success(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// Get funCode of "add" before replacement
	fi, err := lib.functionByName("add")
	require.NoError(t, err)
	funCodeBefore := fi.FunCode

	// Replace "add" with "mul" implementation
	yamlData := `
functions:
  -
    sym: add
    numArgs: 2
    embedded_as: mul
    short: true
    replace: true
    description: "add now does multiplication"
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)

	err = lib.Upgrade(fromYaml, EmbeddedFunctions[any](lib))
	require.NoError(t, err)

	// Now "add" should behave like "mul"
	lib.MustEqual("add(3, 5)", "uint8Bytes(15)")

	// Verify funCode is preserved
	fi, err = lib.functionByName("add")
	require.NoError(t, err)
	require.Equal(t, funCodeBefore, fi.FunCode, "funCode should be preserved after replacement")
}

// Test replacing extended function as embedded - should fail
func TestUpgrade_ReplaceExtendedAsEmbedded_Fail(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// "lessOrEqualThan" is an extended function in base library
	yamlData := `
functions:
  -
    sym: lessOrEqualThan
    numArgs: 2
    embedded_as: add
    short: true
    replace: true
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)

	err = lib.Upgrade(fromYaml, EmbeddedFunctions[any](lib))
	require.Error(t, err)
	require.Contains(t, err.Error(), "not embedded")
}

// Test replacing embedded function as extended - should fail
func TestUpgrade_ReplaceEmbeddedAsExtended_Fail(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// "add" is an embedded function in base library
	yamlData := `
functions:
  -
    sym: add
    numArgs: 2
    replace: true
    source: mul($0, $1)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)

	err = lib.Upgrade(fromYaml)
	require.Error(t, err)
	require.Contains(t, err.Error(), "embedded, not extended")
}

// Test multiple operations in single upgrade: add new and replace existing
func TestUpgrade_MixedAddAndReplace(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// First add a function to replace later
	yamlSetup := `
functions:
  -
    sym: funcToReplace
    numArgs: 1
    source: add($0, 1)
`
	fromYamlSetup, err := ReadLibraryFromYAML([]byte(yamlSetup))
	require.NoError(t, err)
	err = lib.Upgrade(fromYamlSetup)
	require.NoError(t, err)

	// Get funCode before
	fi, err := lib.functionByName("funcToReplace")
	require.NoError(t, err)
	funCodeBefore := fi.FunCode

	// Now do mixed upgrade: add new + replace existing
	yamlMixed := `
functions:
  -
    sym: brandNewFunc
    numArgs: 1
    source: mul($0, 2)
  -
    sym: funcToReplace
    numArgs: 1
    replace: true
    source: mul($0, 10)
`
	fromYamlMixed, err := ReadLibraryFromYAML([]byte(yamlMixed))
	require.NoError(t, err)
	err = lib.Upgrade(fromYamlMixed)
	require.NoError(t, err)

	// Verify new function
	lib.MustEqual("brandNewFunc(5)", "uint8Bytes(10)")

	// Verify replaced function
	lib.MustEqual("funcToReplace(5)", "uint8Bytes(50)")

	// Verify funCode preserved
	fi, err = lib.functionByName("funcToReplace")
	require.NoError(t, err)
	require.Equal(t, funCodeBefore, fi.FunCode)
}

// Test that explicit replace: false behaves same as omitted
func TestUpgrade_ExplicitReplaceFalse(t *testing.T) {
	lib := NewBaseLibrary[any]()

	yamlData := `
functions:
  -
    sym: add
    numArgs: 2
    replace: false
    source: sub($0, $1)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)

	err = lib.Upgrade(fromYaml)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}
