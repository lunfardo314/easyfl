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
    embedded_as: evalMulUint
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
    embedded_as: evalAddUint
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

// Test replacing extended function with different numArgs - should fail for backward compatible serde
func TestUpgrade_ReplaceExtended_NumArgsMismatch_Fail(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// First add a function with 2 args
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

	// Try to replace with different numArgs (1 instead of 2) - should fail
	yamlReplace := `
functions:
  -
    sym: myFunc
    numArgs: 1
    replace: true
    source: mul($0, 2)
`
	fromYamlReplace, err := ReadLibraryFromYAML([]byte(yamlReplace))
	require.NoError(t, err)
	err = lib.Upgrade(fromYamlReplace)
	require.Error(t, err)
	require.Contains(t, err.Error(), "numArgs mismatch")
}

// Test replacing embedded function with different numArgs - should fail for backward compatible serde
func TestUpgrade_ReplaceEmbedded_NumArgsMismatch_Fail(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// "add" has numArgs: 2 in base library
	// Try to replace with different numArgs (3 instead of 2) - should fail
	yamlData := `
functions:
  -
    sym: add
    numArgs: 3
    embedded_as: evalConcat
    short: true
    replace: true
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)

	err = lib.Upgrade(fromYaml, EmbeddedFunctions[any](lib))
	require.Error(t, err)
	require.Contains(t, err.Error(), "numArgs mismatch")
}

// Test adding an immutable extended function
func TestUpgrade_AddImmutableExtended_Success(t *testing.T) {
	lib := NewBaseLibrary[any]()

	yamlData := `
functions:
  -
    sym: immutableFunc
    numArgs: 2
    immutable: true
    source: add($0, $1)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)

	err = lib.Upgrade(fromYaml)
	require.NoError(t, err)

	// Verify function works
	lib.MustEqual("immutableFunc(3, 5)", "uint8Bytes(8)")

	// Verify immutable flag is set by checking YAML output
	yamlOutput := lib.ToYAML(true)
	require.Contains(t, string(yamlOutput), "immutable: true")
}

// Test replacing an immutable extended function - should fail
func TestUpgrade_ReplaceImmutableExtended_Fail(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// First add an immutable function
	yamlData := `
functions:
  -
    sym: immutableFunc
    numArgs: 2
    immutable: true
    source: add($0, $1)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml)
	require.NoError(t, err)

	// Try to replace the immutable function - should fail
	yamlReplace := `
functions:
  -
    sym: immutableFunc
    numArgs: 2
    replace: true
    source: mul($0, $1)
`
	fromYamlReplace, err := ReadLibraryFromYAML([]byte(yamlReplace))
	require.NoError(t, err)
	err = lib.Upgrade(fromYamlReplace)
	require.Error(t, err)
	require.Contains(t, err.Error(), "immutable")
}

// Test adding an immutable embedded function
func TestUpgrade_AddImmutableEmbedded_Success(t *testing.T) {
	lib := NewBaseLibrary[any]()

	yamlData := `
functions:
  -
    sym: immutableEmbedded
    numArgs: 2
    embedded_as: evalAddUint
    immutable: true
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)

	err = lib.Upgrade(fromYaml, EmbeddedFunctions[any](lib))
	require.NoError(t, err)

	// Verify function works
	lib.MustEqual("immutableEmbedded(3, 5)", "uint8Bytes(8)")
}

// Test replacing an immutable embedded function - should fail
func TestUpgrade_ReplaceImmutableEmbedded_Fail(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// First add an immutable embedded function
	yamlData := `
functions:
  -
    sym: immutableEmbedded
    numArgs: 2
    embedded_as: evalAddUint
    immutable: true
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml, EmbeddedFunctions[any](lib))
	require.NoError(t, err)

	// Try to replace the immutable embedded function - should fail
	yamlReplace := `
functions:
  -
    sym: immutableEmbedded
    numArgs: 2
    embedded_as: evalMulUint
    replace: true
`
	fromYamlReplace, err := ReadLibraryFromYAML([]byte(yamlReplace))
	require.NoError(t, err)
	err = lib.Upgrade(fromYamlReplace, EmbeddedFunctions[any](lib))
	require.Error(t, err)
	require.Contains(t, err.Error(), "immutable")
}

// Test that immutable flag affects library hash
func TestUpgrade_ImmutableAffectsHash(t *testing.T) {
	// Create two libraries with same function, one immutable, one not
	lib1 := NewBaseLibrary[any]()
	lib2 := NewBaseLibrary[any]()

	// Add non-immutable function to lib1
	yaml1 := `
functions:
  -
    sym: testFunc
    numArgs: 2
    source: add($0, $1)
`
	fromYaml1, err := ReadLibraryFromYAML([]byte(yaml1))
	require.NoError(t, err)
	err = lib1.Upgrade(fromYaml1)
	require.NoError(t, err)

	// Add immutable function to lib2
	yaml2 := `
functions:
  -
    sym: testFunc
    numArgs: 2
    immutable: true
    source: add($0, $1)
`
	fromYaml2, err := ReadLibraryFromYAML([]byte(yaml2))
	require.NoError(t, err)
	err = lib2.Upgrade(fromYaml2)
	require.NoError(t, err)

	// Hashes should be different
	hash1 := lib1.LibraryHash()
	hash2 := lib2.LibraryHash()
	require.NotEqual(t, hash1, hash2, "library hashes should differ when immutable flag differs")
}

// Test that non-immutable function can still be replaced
func TestUpgrade_NonImmutableCanBeReplaced(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// Add a non-immutable function (immutable: false is the default)
	yamlData := `
functions:
  -
    sym: mutableFunc
    numArgs: 2
    source: add($0, $1)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml)
	require.NoError(t, err)

	// Verify original behavior
	lib.MustEqual("mutableFunc(3, 5)", "uint8Bytes(8)")

	// Replace the function - should succeed
	yamlReplace := `
functions:
  -
    sym: mutableFunc
    numArgs: 2
    replace: true
    source: mul($0, $1)
`
	fromYamlReplace, err := ReadLibraryFromYAML([]byte(yamlReplace))
	require.NoError(t, err)
	err = lib.Upgrade(fromYamlReplace)
	require.NoError(t, err)

	// Verify new behavior
	lib.MustEqual("mutableFunc(3, 5)", "uint8Bytes(15)")
}
