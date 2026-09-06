package easyfl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLocalScript_ConcatAmplificationBounded is the regression for the audit
// FEFL-1 finding. A composed doubling `fk = f(k-1)(f(k-1)($0))` squares the
// output size at each level (double-exponential in the number of functions),
// so a handful of tiny functions reach a multi-gigabyte result and a fatal,
// unrecoverable Go OOM. The per-evaluation result-size cap must turn that into
// a clean, catchable error instead. Caching does not help: it bounds the number
// of evaluations, never the size of the materialized result.
func TestLocalScript_ConcatAmplificationBounded(t *testing.T) {
	lib := NewBaseLibrary[any]()
	// f0 -> 2 bytes, f1 -> 4, f2 -> 16, f3 -> 256, f4 -> 65536, f5 -> 2^32.
	const source = `
 func f0 : concat($0,$0)
 func f1 : f0(f0($0))
 func f2 : f1(f1($0))
 func f3 : f2(f2($0))
 func f4 : f3(f3($0))
 func f5 : f4(f4($0))
`
	bin, idx, err := lib.CompileLocalScriptWithIndex(source)
	require.NoError(t, err)
	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)

	// f5 would materialize 2^32 bytes uncapped; the default 128 KB cap stops it
	// at the first intermediate result that crosses the limit.
	_, err = s.Eval(nil, idx["f5"], []byte{0x41})
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds limit")

	// A small composition stays well under the cap and evaluates normally.
	got, err := s.Eval(nil, idx["f2"], []byte{0x41}) // 2^4 = 16 bytes
	require.NoError(t, err)
	require.Len(t, got, 16)
}

// TestSetMaxEvalResultSize checks the configurable cap directly: lowering it
// rejects an oversized result, and a result under the limit still evaluates.
func TestSetMaxEvalResultSize(t *testing.T) {
	defer SetMaxEvalResultSize(DefaultMaxEvalResultSize) // restore for other tests
	lib := NewBaseLibrary[any]()

	SetMaxEvalResultSize(4)
	_, err := lib.EvalFromSource(nil, "concat(0x01020304, 0x0506)") // 6 bytes > 4
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds limit")

	got, err := lib.EvalFromSource(nil, "concat(0x0102, 0x03)") // 3 bytes <= 4
	require.NoError(t, err)
	require.Equal(t, []byte{0x01, 0x02, 0x03}, got)
}
