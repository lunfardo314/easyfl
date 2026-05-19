package easyfl

import (
	"testing"

	"github.com/lunfardo314/easyfl/compose"
	"github.com/stretchr/testify/require"
)

// TestLibrary_ValidateCompiled exercises compose.ValidateCompiled on the round-tripped
// base library JSON: parse → re-build → assert hash + bytecodes match.
func TestLibrary_ValidateCompiled(t *testing.T) {
	lib := NewBaseLibrary[any]()
	jsonData := ToJSON(lib, true, true)

	compiled, err := ReadLibraryFromJSON(jsonData)
	require.NoError(t, err)
	require.NoError(t, compose.ValidateCompiled[any](compiled))
}

// TestLibrary_Upgrade_Mixed exercises a multi-function upgrade.
func TestLibrary_Upgrade_Mixed(t *testing.T) {
	lib := NewBaseLibrary[any]()

	jsonData := `{
	  "functions": [
	    {"sym": "newfun", "description": "some description", "numArgs": 0, "source": "concat(0x, 0x111111, 2)"},
	    {"sym": "newfun2", "description": "none", "numArgs": 0, "source": "add(5,7)"},
	    {"sym": "long-source", "numArgs": 2, "source": "if(equal($0,$1), concat($0), concat($0,$1))"},
	    {"sym": "dummy", "numArgs": 0, "source": "add(5,7)"},
	    {"sym": "@dummy", "numArgs": 0, "source": "add(5,7)"}
	  ]
	}`
	require.NoError(t, UpgradeFromJSON(lib, []byte(jsonData)))

	lib.MustEqual("newfun", "0x11111102")
	lib.MustEqual("newfun2", "uint8Bytes(12)")
	back := ToJSON(lib, true, true)
	t.Logf("------------- UPGRADED (%d bytes)\n%s", len(back), string(back))
}

// Test adding function that already exists (replace: false) - should fail
func TestUpgrade_AddExisting_Fail(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// Try to add "add" which already exists in base library
	err := UpgradeFromJSON(lib, []byte(`{
	  "functions": [
	    {"sym": "add", "numArgs": 2, "source": "sub($0, $1)"}
	  ]
	}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}

// Test replacing embedded function with new embedded_as
func TestUpgrade_ReplaceEmbedded_Success(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// Get funCode of "add" before replacement
	fi, err := lib.FunctionByName("add")
	require.NoError(t, err)
	funCodeBefore := fi.FunCode

	// Replace "add" with "mul" implementation
	require.NoError(t, UpgradeFromJSON(lib, []byte(`{
	  "functions": [
	    {"sym": "add", "numArgs": 2, "embeddedAs": "evalMulUint", "short": true, "replace": true, "description": "add now does multiplication"}
	  ]
	}`), EmbeddedFunctions[any](lib)))

	// Now "add" should behave like "mul"
	lib.MustEqual("add(3, 5)", "uint8Bytes(15)")

	// Verify funCode is preserved
	fi, err = lib.FunctionByName("add")
	require.NoError(t, err)
	require.Equal(t, funCodeBefore, fi.FunCode, "funCode should be preserved after replacement")
}

// Test replacing extended function as embedded - should fail
func TestUpgrade_ReplaceExtendedAsEmbedded_Fail(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// "lessOrEqualThan" is an extended function in base library
	err := UpgradeFromJSON(lib, []byte(`{
	  "functions": [
	    {"sym": "lessOrEqualThan", "numArgs": 2, "embeddedAs": "evalAddUint", "short": true, "replace": true}
	  ]
	}`), EmbeddedFunctions[any](lib))
	require.Error(t, err)
	require.Contains(t, err.Error(), "not embedded")
}

// Test replacing embedded function as extended - should fail
func TestUpgrade_ReplaceEmbeddedAsExtended_Fail(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// "add" is an embedded function in base library
	err := UpgradeFromJSON(lib, []byte(`{
	  "functions": [
	    {"sym": "add", "numArgs": 2, "replace": true, "source": "mul($0, $1)"}
	  ]
	}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "embedded, not extended")
}

// Test multiple operations in single upgrade: add new and replace existing
func TestUpgrade_MixedAddAndReplace(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// First add a function to replace later
	require.NoError(t, UpgradeFromJSON(lib, []byte(`{
	  "functions": [
	    {"sym": "funcToReplace", "numArgs": 1, "source": "add($0, 1)"}
	  ]
	}`)))

	// Get funCode before
	fi, err := lib.FunctionByName("funcToReplace")
	require.NoError(t, err)
	funCodeBefore := fi.FunCode

	// Now do mixed upgrade: add new + replace existing
	require.NoError(t, UpgradeFromJSON(lib, []byte(`{
	  "functions": [
	    {"sym": "brandNewFunc", "numArgs": 1, "source": "mul($0, 2)"},
	    {"sym": "funcToReplace", "numArgs": 1, "replace": true, "source": "mul($0, 10)"}
	  ]
	}`)))

	// Verify new function
	lib.MustEqual("brandNewFunc(5)", "uint8Bytes(10)")

	// Verify replaced function
	lib.MustEqual("funcToReplace(5)", "uint8Bytes(50)")

	// Verify funCode preserved
	fi, err = lib.FunctionByName("funcToReplace")
	require.NoError(t, err)
	require.Equal(t, funCodeBefore, fi.FunCode)
}

// Test that explicit replace: false behaves same as omitted
func TestUpgrade_ExplicitReplaceFalse(t *testing.T) {
	lib := NewBaseLibrary[any]()

	err := UpgradeFromJSON(lib, []byte(`{
	  "functions": [
	    {"sym": "add", "numArgs": 2, "replace": false, "source": "sub($0, $1)"}
	  ]
	}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}

// Test replacing extended function with different numArgs - should fail for backward compatible serde
func TestUpgrade_ReplaceExtended_NumArgsMismatch_Fail(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// First add a function with 2 args
	require.NoError(t, UpgradeFromJSON(lib, []byte(`{
	  "functions": [
	    {"sym": "myFunc", "numArgs": 2, "source": "add($0, $1)"}
	  ]
	}`)))

	// Try to replace with different numArgs (1 instead of 2) - should fail
	err := UpgradeFromJSON(lib, []byte(`{
	  "functions": [
	    {"sym": "myFunc", "numArgs": 1, "replace": true, "source": "mul($0, 2)"}
	  ]
	}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "numArgs mismatch")
}

// Test replacing embedded function with different numArgs - should fail for backward compatible serde
func TestUpgrade_ReplaceEmbedded_NumArgsMismatch_Fail(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// "add" has numArgs: 2 in base library
	// Try to replace with different numArgs (3 instead of 2) - should fail
	err := UpgradeFromJSON(lib, []byte(`{
	  "functions": [
	    {"sym": "add", "numArgs": 3, "embeddedAs": "evalConcat", "short": true, "replace": true}
	  ]
	}`), EmbeddedFunctions[any](lib))
	require.Error(t, err)
	require.Contains(t, err.Error(), "numArgs mismatch")
}

// Test adding an immutable extended function
func TestUpgrade_AddImmutableExtended_Success(t *testing.T) {
	lib := NewBaseLibrary[any]()

	require.NoError(t, UpgradeFromJSON(lib, []byte(`{
	  "functions": [
	    {"sym": "immutableFunc", "numArgs": 2, "immutable": true, "source": "add($0, $1)"}
	  ]
	}`)))

	// Verify function works
	lib.MustEqual("immutableFunc(3, 5)", "uint8Bytes(8)")

	// Verify immutable flag is set by checking JSON output
	jsonOutput := ToJSON(lib, true, true)
	require.Contains(t, string(jsonOutput), `"immutable": true`)
}

// Test adding an immutable embedded function
func TestUpgrade_AddImmutableEmbedded_Success(t *testing.T) {
	lib := NewBaseLibrary[any]()

	require.NoError(t, UpgradeFromJSON(lib, []byte(`{
	  "functions": [
	    {"sym": "immutableEmbedded", "numArgs": 2, "embeddedAs": "evalAddUint", "immutable": true}
	  ]
	}`), EmbeddedFunctions[any](lib)))

	// Verify function works
	lib.MustEqual("immutableEmbedded(3, 5)", "uint8Bytes(8)")
}

// Test replacing an immutable embedded function - should fail
func TestUpgrade_ReplaceImmutableEmbedded_Fail(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// First add an immutable embedded function
	require.NoError(t, UpgradeFromJSON(lib, []byte(`{
	  "functions": [
	    {"sym": "immutableEmbedded", "numArgs": 2, "embeddedAs": "evalAddUint", "immutable": true}
	  ]
	}`), EmbeddedFunctions[any](lib)))

	// Try to replace the immutable embedded function - should fail
	err := UpgradeFromJSON(lib, []byte(`{
	  "functions": [
	    {"sym": "immutableEmbedded", "numArgs": 2, "embeddedAs": "evalMulUint", "replace": true}
	  ]
	}`), EmbeddedFunctions[any](lib))
	require.Error(t, err)
	require.Contains(t, err.Error(), "immutable")
}

// Test that immutable flag affects library hash
func TestUpgrade_ImmutableAffectsHash(t *testing.T) {
	lib1 := NewBaseLibrary[any]()
	lib2 := NewBaseLibrary[any]()

	// Add non-immutable function to lib1
	require.NoError(t, UpgradeFromJSON(lib1, []byte(`{
	  "functions": [
	    {"sym": "testFunc", "numArgs": 2, "source": "add($0, $1)"}
	  ]
	}`)))

	// Add immutable function to lib2
	require.NoError(t, UpgradeFromJSON(lib2, []byte(`{
	  "functions": [
	    {"sym": "testFunc", "numArgs": 2, "immutable": true, "source": "add($0, $1)"}
	  ]
	}`)))

	// Hashes should be different
	require.NotEqual(t, lib1.LibraryHash(), lib2.LibraryHash(),
		"library hashes should differ when immutable flag differs")
}

// Test that non-immutable function can still be replaced
func TestUpgrade_NonImmutableCanBeReplaced(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// Add a non-immutable function (immutable: false is the default)
	require.NoError(t, UpgradeFromJSON(lib, []byte(`{
	  "functions": [
	    {"sym": "mutableFunc", "numArgs": 2, "source": "add($0, $1)"}
	  ]
	}`)))

	// Verify original behavior
	lib.MustEqual("mutableFunc(3, 5)", "uint8Bytes(8)")

	// Replace the function - should succeed
	require.NoError(t, UpgradeFromJSON(lib, []byte(`{
	  "functions": [
	    {"sym": "mutableFunc", "numArgs": 2, "replace": true, "source": "mul($0, $1)"}
	  ]
	}`)))

	// Verify new behavior
	lib.MustEqual("mutableFunc(3, 5)", "uint8Bytes(15)")
}

// Test that vararg functions are correctly serialized to JSON
func TestToJSON_VarargExtended(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// Add a vararg function
	_, err := lib.ExtendVarargErr("myVararg", "$$")
	require.NoError(t, err)

	jsonData := ToJSON(lib, true, true)
	t.Logf("JSON output:\n%s", string(jsonData))

	require.Contains(t, string(jsonData), `"numArgs": -1`)
	require.Contains(t, string(jsonData), `"sym": "myVararg"`)
}
