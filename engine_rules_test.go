package easyfl

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// chainScript builds a local script of functions f0..fk where each level uses
// the previous one twice through `pattern` (with %[1]s the previous name).
func chainScript(base, pattern string, k int) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "func f0 : %s\n", base)
	for i := 1; i <= k; i++ {
		fmt.Fprintf(&sb, "func f%d : %s\n", i, fmt.Sprintf(pattern, fmt.Sprintf("f%d", i-1)))
	}
	return sb.String()
}

func compileScript(t *testing.T, lib *Library[any], source string) (*LocalScript[any], map[string]int) {
	bin, idx, err := lib.CompileLocalScriptWithIndex(source)
	require.NoError(t, err)
	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)
	return s, idx
}

// TestEngineRules_CallDepth: arguments are evaluated lazily inside the callee,
// so `fk($0) = f(k-1)(f(k-1)($0))` doubles the call depth per level. At k=30
// the Go stack would pass its limit, a fatal error no recover catches (do not
// run this without the rule). With MaxCallDepth the evaluation fails cleanly.
func TestEngineRules_CallDepth(t *testing.T) {
	lib := NewBaseLibrary[any]()
	lib.SetEngineRules(EngineRules{MaxCallDepth: 10_000})
	glb := lib.NewGlobalDataNoTrace(nil)
	s, idx := compileScript(t, lib, chainScript("not(not($0))", "%[1]s(%[1]s($0))", 30))

	_, err := s.Eval(glb, idx["f30"], []byte{0x01})
	require.ErrorContains(t, err, "call depth exceeds limit")

	// a shallow level stays under the limit and evaluates
	got, err := s.Eval(glb, idx["f5"], []byte{0x01})
	require.NoError(t, err)
	require.Equal(t, []byte{0xff}, got, "not(not(x)) is true for non-empty x")
}

// TestEngineRules_MaxCalls: separate call sites re-evaluate the callee, so
// `fk($0) = and(f(k-1)($0), f(k-1)($0))` makes 2^k calls at depth k: no deep
// stack, only time. With MaxCalls the evaluation stops after the limit.
func TestEngineRules_MaxCalls(t *testing.T) {
	lib := NewBaseLibrary[any]()
	lib.SetEngineRules(EngineRules{MaxCalls: 1_000_000})
	glb := lib.NewGlobalDataNoTrace(nil)
	s, idx := compileScript(t, lib, chainScript("$0", "and(%[1]s($0),%[1]s($0))", 40))

	_, err := s.Eval(glb, idx["f40"], []byte{0x01})
	require.ErrorContains(t, err, "number of calls exceeds limit")

	got, err := s.Eval(glb, idx["f10"], []byte{0x01})
	require.NoError(t, err)
	require.NotEmpty(t, got)
}

// TestEngineRules_ZeroValueIsHistoric: without rules nothing is limited, so a
// library whose host does not enable them evaluates exactly as before.
func TestEngineRules_ZeroValueIsHistoric(t *testing.T) {
	lib := NewBaseLibrary[any]()
	require.Equal(t, EngineRules{}, lib.EngineRules())
	s, idx := compileScript(t, lib, chainScript("$0", "and(%[1]s($0),%[1]s($0))", 12))
	_, err := s.Eval(lib.NewGlobalDataNoTrace(nil), idx["f12"], []byte{0x01})
	require.NoError(t, err)
}

// TestEngineRules_ParseBytecodeCharged: parseBytecode charges the length of
// the bytecode it parses, so re-parsing a large argument at many call sites
// counts as the work it is, not as one call per site.
func TestEngineRules_ParseBytecodeCharged(t *testing.T) {
	lib := NewBaseLibrary[any]()
	lib.SetEngineRules(EngineRules{MaxCalls: 5_000})
	code, _, err := lib.ExpressionSourceToBytecode(fmt.Sprintf("concat(0x%s)", strings.Repeat("00", 2000)))
	require.NoError(t, err)

	src := fmt.Sprintf("parseBytecode(0x%s, 0x)", hex.EncodeToString(code))
	_, err = lib.EvalFromSource(lib.NewGlobalDataNoTrace(nil), src)
	require.NoError(t, err, "one parse of ~2 KB fits")

	src = fmt.Sprintf("and(%s)", strings.Repeat(src+",", 4)+src)
	_, err = lib.EvalFromSource(lib.NewGlobalDataNoTrace(nil), src)
	require.ErrorContains(t, err, "number of calls exceeds limit")
}

// longCallLiteral finds a 64-byte inline-data literal whose first two bytes,
// read as a long call prefix, name a function of the library. Its first byte
// (data, 64 bytes) also carries the long-call bit.
func longCallLiteral(t *testing.T, lib *Library[any]) ([]byte, string) {
	for b := 0; b < 256; b++ {
		payload := append([]byte{byte(b)}, bytes.Repeat([]byte{0xaa}, 63)...)
		lit := InlineDataBytecode(payload)
		require.Equal(t, byte(0xc0), lit[0])
		if name, err := lib.FunctionNameByCallPrefix(lit); err == nil && !strings.HasPrefix(name, "$") {
			return lit, name
		}
	}
	t.Fatal("no literal reads as a call")
	return nil, ""
}

// TestEngineRules_StrictCallPrefix: parseBytecode with prefix arguments took an
// inline-data literal for a call to the function its first two bytes encode,
// so a ledger rule requiring "a call to f at this position" accepted a
// literal. With Strict it is refused.
func TestEngineRules_StrictCallPrefix(t *testing.T) {
	lib := NewBaseLibrary[any]()
	lit, name := longCallLiteral(t, lib)
	src := fmt.Sprintf("parseBytecode(0x%s, 0x, #%s)", hex.EncodeToString(lit), name)

	_, err := lib.EvalFromSource(lib.NewGlobalDataNoTrace(nil), src)
	require.NoError(t, err, "historic behaviour: the literal passes as %s", name)

	lib.SetEngineRules(EngineRules{Strict: true})
	_, err = lib.EvalFromSource(lib.NewGlobalDataNoTrace(nil), src)
	require.ErrorContains(t, err, "inline data is not a call prefix")
}

// TestEngineRules_StrictInlineData: the long inline-data form under 127 bytes
// evaluated with its length bytes inside the value. With Strict it is refused.
func TestEngineRules_StrictInlineData(t *testing.T) {
	lib := NewBaseLibrary[any]()
	code := []byte{0xff, 0x00, 0x03, 0x61, 0x62, 0x63}
	got, err := lib.EvalFromBytecode(lib.NewGlobalDataNoTrace(nil), code)
	require.NoError(t, err)
	require.Equal(t, []byte{0x00, 0x03, 0x61, 0x62, 0x63}, got, "historic behaviour")

	lib.SetEngineRules(EngineRules{Strict: true})
	_, err = lib.EvalFromBytecode(lib.NewGlobalDataNoTrace(nil), code)
	require.ErrorContains(t, err, "non-canonical inline data")

	// the canonical forms still parse
	for _, n := range []int{0, 1, 126, 127, 300} {
		data := bytes.Repeat([]byte{0x5a}, n)
		got, err = lib.EvalFromBytecode(lib.NewGlobalDataNoTrace(nil), InlineDataBytecode(data))
		require.NoError(t, err)
		require.Equal(t, len(data), len(got))
	}
}

// TestEngineRules_StrictBuiltins: selectCaseByIndex read only the low byte of
// its index, and byte(data, 255) failed on byte-arithmetic wrap. With Strict
// both give the documented result.
func TestEngineRules_StrictBuiltins(t *testing.T) {
	lib := NewBaseLibrary[any]()
	glb := lib.NewGlobalDataNoTrace(nil)
	long := "0x" + strings.Repeat("00", 255) + "7f"

	got, err := lib.EvalFromSource(glb, "selectCaseByIndex(0x0100, 0xaa, 0xbb)")
	require.NoError(t, err)
	require.Equal(t, []byte{0xaa}, got, "historic: index 256 selects case 0")
	_, err = lib.EvalFromSource(glb, fmt.Sprintf("byte(%s, 255)", long))
	require.Error(t, err, "historic: byte(x, 255) fails")

	lib.SetEngineRules(EngineRules{Strict: true})
	glb = lib.NewGlobalDataNoTrace(nil)
	got, err = lib.EvalFromSource(glb, "selectCaseByIndex(0x0100, 0xaa, 0xbb)")
	require.NoError(t, err)
	require.Empty(t, got)
	got, err = lib.EvalFromSource(glb, "selectCaseByIndex(1, 0xaa, 0xbb)")
	require.NoError(t, err)
	require.Equal(t, []byte{0xbb}, got)
	got, err = lib.EvalFromSource(glb, fmt.Sprintf("byte(%s, 255)", long))
	require.NoError(t, err)
	require.Equal(t, []byte{0x7f}, got)
}

// TestEngineRules_Clone: a cloned library keeps its rules.
func TestEngineRules_Clone(t *testing.T) {
	lib := NewBaseLibrary[any]()
	r := EngineRules{MaxCallDepth: 7, MaxCalls: 9, Strict: true}
	lib.SetEngineRules(r)
	require.Equal(t, r, lib.Clone().EngineRules())
}
