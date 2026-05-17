package easyfl

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// JSON ↔ YAML cross-format hash equality: starting from the same base library,
// serializing through either carrier must yield identical LibraryHash.
func TestJSON_BaseLib_HashMatchesYAML(t *testing.T) {
	libYAML := NewBaseLibrary[any]()
	hashYAML := libYAML.LibraryHash()

	jsonData := libYAML.ToJSON(true, true)
	libJSON, err := NewLibraryFromJSON[any](jsonData, func(lib *Library[any]) func(sym string) EmbeddedFunction[any] {
		return EmbeddedFunctions[any](lib)
	})
	require.NoError(t, err)

	hashJSON := libJSON.LibraryHash()
	require.Equal(t, hashYAML, hashJSON, "base library hash must be format-independent")
}

// Compact and indented JSON must round-trip to libraries with equal hashes.
func TestJSON_CompactVsIndent(t *testing.T) {
	base := NewBaseLibrary[any]()
	hashBase := base.LibraryHash()

	for _, indent := range []bool{false, true} {
		data := base.ToJSON(true, indent)
		lib, err := NewLibraryFromJSON[any](data, func(lib *Library[any]) func(sym string) EmbeddedFunction[any] {
			return EmbeddedFunctions[any](lib)
		})
		require.NoError(t, err, "indent=%v", indent)
		require.Equal(t, hashBase, lib.LibraryHash(), "indent=%v: hash differs", indent)
	}
}

// Compact JSON: single line, no trailing newline, strictly smaller than
// indented JSON of the same library.
func TestJSON_CompactVsIndentShape(t *testing.T) {
	base := NewBaseLibrary[any]()
	compact := base.ToJSON(true, false)
	require.NotContains(t, string(compact), "\n", "compact JSON must contain no newlines")
	require.False(t, strings.HasSuffix(string(compact), "\n"), "compact JSON must not end with newline")

	indented := base.ToJSON(true, true)
	require.Contains(t, string(indented), "\n", "indented JSON must contain newlines")
	require.True(t, strings.HasSuffix(string(indented), "\n"), "indented JSON must end with newline")
	require.Less(t, len(compact), len(indented), "compact JSON must be smaller than indented")
}

// Compiled JSON should be valid JSON parseable by a third-party parser
// (here: encoding/json into a map).
func TestJSON_BaseLib_IsValidJSON(t *testing.T) {
	base := NewBaseLibrary[any]()
	data := base.ToJSON(true, true)

	var generic map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &generic))
	require.Contains(t, generic, "hash")
	require.Contains(t, generic, "functions")
	require.Equal(t, hex.EncodeToString(func() []byte { h := base.LibraryHash(); return h[:] }()), generic["hash"])
}

// Non-compiled output drops hash and funCode/bytecode.
func TestJSON_NonCompiled_DropsRuntimeFields(t *testing.T) {
	base := NewBaseLibrary[any]()
	data := base.ToJSON(false, true)

	var parsed LibraryFromJSON
	require.NoError(t, json.Unmarshal(data, &parsed))
	require.Empty(t, parsed.Hash, "non-compiled output must omit hash")
	for _, f := range parsed.Functions {
		require.Zero(t, f.FunCode, "function %s: non-compiled output must omit funCode", f.Sym)
		require.Empty(t, f.Bytecode, "function %s: non-compiled output must omit bytecode", f.Sym)
	}
}

// Wrong hash in JSON must fail validation in NewLibraryFromJSON.
func TestJSON_HashMismatch_Fails(t *testing.T) {
	base := NewBaseLibrary[any]()
	data := base.ToJSON(true, true)

	var parsed LibraryFromJSON
	require.NoError(t, json.Unmarshal(data, &parsed))
	parsed.Hash = strings.Repeat("aa", 32)
	tampered, err := json.Marshal(&parsed)
	require.NoError(t, err)

	_, err = NewLibraryFromJSON[any](tampered, func(lib *Library[any]) func(sym string) EmbeddedFunction[any] {
		return EmbeddedFunctions[any](lib)
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "hashes do not match")
}

// Inline upgrade via JSON — add a new extended function.
func TestJSON_Upgrade_AddNewExtended(t *testing.T) {
	lib := NewBaseLibrary[any]()

	jsonData := `{
	  "functions": [
	    {"sym": "myNewFunc", "numArgs": 2, "source": "add($0, $1)"}
	  ]
	}`
	require.NoError(t, lib.UpgradeFromJSON([]byte(jsonData)))
	lib.MustEqual("myNewFunc(3, 5)", "uint8Bytes(8)")
}

// Replace flag must error when function does not exist.
func TestJSON_Upgrade_ReplaceNonExistent_Fail(t *testing.T) {
	lib := NewBaseLibrary[any]()

	jsonData := `{
	  "functions": [
	    {"sym": "nonExistentFunc", "numArgs": 2, "replace": true, "source": "add($0, $1)"}
	  ]
	}`
	err := lib.UpgradeFromJSON([]byte(jsonData))
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not exist")
}

// Replace an existing extended function — funCode is preserved.
func TestJSON_Upgrade_ReplaceExtended(t *testing.T) {
	lib := NewBaseLibrary[any]()
	require.NoError(t, lib.UpgradeFromJSON([]byte(`{
	  "functions": [
	    {"sym": "myFunc", "numArgs": 2, "source": "add($0, $1)"}
	  ]
	}`)))
	fi, err := lib.functionByName("myFunc")
	require.NoError(t, err)
	funCodeBefore := fi.FunCode

	require.NoError(t, lib.UpgradeFromJSON([]byte(`{
	  "functions": [
	    {"sym": "myFunc", "numArgs": 2, "replace": true, "source": "mul($0, $1)"}
	  ]
	}`)))

	lib.MustEqual("myFunc(3, 5)", "uint8Bytes(15)")
	fi, err = lib.functionByName("myFunc")
	require.NoError(t, err)
	require.Equal(t, funCodeBefore, fi.FunCode)
}

// Immutable flag is honored.
func TestJSON_Upgrade_ImmutableCannotBeReplaced(t *testing.T) {
	lib := NewBaseLibrary[any]()
	require.NoError(t, lib.UpgradeFromJSON([]byte(`{
	  "functions": [
	    {"sym": "lockedFunc", "numArgs": 2, "immutable": true, "source": "add($0, $1)"}
	  ]
	}`)))

	err := lib.UpgradeFromJSON([]byte(`{
	  "functions": [
	    {"sym": "lockedFunc", "numArgs": 2, "replace": true, "source": "mul($0, $1)"}
	  ]
	}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "immutable")
}

// Vararg encoding round-trips via JSON.
func TestJSON_Upgrade_Vararg(t *testing.T) {
	lib := NewBaseLibrary[any]()
	require.NoError(t, lib.UpgradeFromJSON([]byte(`{
	  "functions": [
	    {"sym": "varargCount", "numArgs": -1, "source": "$$"}
	  ]
	}`)))

	for _, tc := range []struct {
		expr string
		want byte
	}{
		{"varargCount()", 0},
		{"varargCount(1)", 1},
		{"varargCount(1, 2, 3)", 3},
	} {
		got, err := lib.EvalFromSource(nil, tc.expr)
		require.NoError(t, err, tc.expr)
		require.Equal(t, []byte{tc.want}, got, tc.expr)
	}
}

// VersionData containing JSON-meaningful characters (quotes, backslashes) must
// round-trip. This was the original failure mode that motivated yamlEscapeString;
// encoding/json handles the escaping natively so the test should just pass.
func TestJSON_VersionDataEscaping(t *testing.T) {
	lib := NewBaseLibrary[any]()
	embedded := `{"txValidation":"txLayoutValidator","key":"value with \"quotes\" and \\ backslash"}`
	lib.VersionData = []byte(embedded)

	data := lib.ToJSON(true, true)
	parsed, err := ReadLibraryFromJSON(data)
	require.NoError(t, err)
	require.Equal(t, embedded, parsed.VersionData)
}

// IntroduceUpdateJSONMulti accumulates from multiple JSON sources before commit.
func TestJSON_IntroduceMulti(t *testing.T) {
	lib := NewBaseLibrary[any]()
	src1 := []byte(`{"functions":[{"sym":"f1","numArgs":1,"source":"add($0, 1)"}]}`)
	src2 := []byte(`{"functions":[{"sym":"f2","numArgs":1,"source":"mul($0, 2)"}]}`)

	require.NoError(t, lib.IntroduceUpdateJSONMulti(nil, src1, src2))
	require.NoError(t, lib.CommitUpdate())

	lib.MustEqual("f1(5)", "uint8Bytes(6)")
	lib.MustEqual("f2(5)", "uint8Bytes(10)")
}