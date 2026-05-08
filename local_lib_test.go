package easyfl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Smoke tests for Phase A. The full Phase C suite will replace this file.

// TestLocalScriptSingleFn verifies the simplest end-to-end path: compile a
// one-function local script, decode it, evaluate the function.
func TestLocalScriptSingleFn(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `func only : concat($0, $1)`
	bin, err := lib.CompileLocalScript(source)
	require.NoError(t, err)

	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)
	require.Equal(t, 1, s.NumFunctions())

	got, err := s.Eval(nil, 0, []byte{0xaa}, []byte{0xbb})
	require.NoError(t, err)
	require.Equal(t, []byte{0xaa, 0xbb}, got)
}

// TestLocalScriptIntraScriptCall verifies that a function can call another
// function in the same script. The callee is no-deps so Kahn's puts it
// at wire-index 0; the caller follows at wire-index 1.
func TestLocalScriptIntraScriptCall(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `
 func leaf : concat($0, 0xaa)
 func caller : leaf($0)
`
	bin, err := lib.CompileLocalScript(source)
	require.NoError(t, err)

	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)
	require.Equal(t, 2, s.NumFunctions())

	// leaf at wire-index 0 (no deps), caller at wire-index 1 (deps on leaf).
	gotLeaf, err := s.Eval(nil, 0, []byte{0x42})
	require.NoError(t, err)
	require.Equal(t, []byte{0x42, 0xaa}, gotLeaf)

	gotCaller, err := s.Eval(nil, 1, []byte{0x42})
	require.NoError(t, err)
	require.Equal(t, []byte{0x42, 0xaa}, gotCaller)
}

// TestLocalScriptForwardReference confirms source-order freedom: caller is
// defined in source before its callee.
func TestLocalScriptForwardReference(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `
 func caller : callee($0)
 func callee : concat($0, 0xaa)
`
	bin, err := lib.CompileLocalScript(source)
	require.NoError(t, err)

	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)
	require.Equal(t, 2, s.NumFunctions())

	// Whichever wire index ends up being which, evaluating each idx with
	// {0x42} should return {0x42, 0xaa}: callee returns it directly, caller
	// returns whatever callee returned.
	for idx := 0; idx < 2; idx++ {
		got, err := s.Eval(nil, idx, []byte{0x42})
		require.NoError(t, err)
		require.Equal(t, []byte{0x42, 0xaa}, got, "idx=%d", idx)
	}
}

// TestLocalScriptCycleRejected verifies that a -> b -> a is rejected at compile.
func TestLocalScriptCycleRejected(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `
 func a : b($0)
 func b : a($0)
`
	_, err := lib.CompileLocalScript(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "recursion")
}

// TestLocalScriptVarargRejected verifies the vararg ban.
func TestLocalScriptVarargRejected(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `func_vararg foo : concat($0)`
	_, err := lib.CompileLocalScript(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "vararg")
}

// TestLocalScriptDuplicateRejected verifies duplicate-symbol rejection.
func TestLocalScriptDuplicateRejected(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `
 func a : 1
 func a : 2
`
	_, err := lib.CompileLocalScript(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate")
}

// TestLocalScriptBadMagicRejected exercises the decoder's magic check.
func TestLocalScriptBadMagicRejected(t *testing.T) {
	lib := NewBaseLibrary[any]()
	bad := []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	_, err := lib.LocalScriptFromBytes(bad)
	require.Error(t, err)
	require.Contains(t, err.Error(), "magic")
}

// TestLocalScriptEmpty verifies that an empty source compiles to a valid bin.
func TestLocalScriptEmpty(t *testing.T) {
	lib := NewBaseLibrary[any]()
	bin, err := lib.CompileLocalScript("")
	require.NoError(t, err)

	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)
	require.Equal(t, 0, s.NumFunctions())
}

// BenchmarkLocalScriptIntraCall measures end-to-end cost of a local-script
// eval that performs one intra-script call per top-level invocation. Used as
// a sanity check after Phase B's slicepool sharing.
func BenchmarkLocalScriptIntraCall(b *testing.B) {
	lib := NewBaseLibrary[any]()
	const source = `
 func leaf : concat($0, 0xaa)
 func caller : leaf($0)
`
	bin, err := lib.CompileLocalScript(source)
	if err != nil {
		b.Fatal(err)
	}
	s, err := lib.LocalScriptFromBytes(bin)
	if err != nil {
		b.Fatal(err)
	}
	arg := []byte{0x42}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Eval(nil, 1, arg); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLocalScriptDeepCall stresses nested intra-script calls. After
// Phase B (parent slicepool reuse) the per-call slicepool New/Dispose and
// defensive copy are gone, so allocs/op should scale roughly linearly with
// call depth instead of paying that overhead at every level.
func BenchmarkLocalScriptDeepCall(b *testing.B) {
	lib := NewBaseLibrary[any]()
	// 6 layers: f0 is the leaf, f5 wraps f4 which wraps f3 ... down to f0.
	const source = `
 func f0 : concat($0, 0xaa)
 func f1 : f0($0)
 func f2 : f1($0)
 func f3 : f2($0)
 func f4 : f3($0)
 func f5 : f4($0)
`
	bin, err := lib.CompileLocalScript(source)
	if err != nil {
		b.Fatal(err)
	}
	s, err := lib.LocalScriptFromBytes(bin)
	if err != nil {
		b.Fatal(err)
	}
	// Find f5 by arity (not topologically first; toposort puts f0 at idx 0).
	// f5 is the only function whose body still contains a non-leaf reference
	// after all rewrites; we identify it by being the last in the chain. The
	// simplest stable lookup is by walking funByName: f5 is not present after
	// decode (synthetic syms only), so just use the last index.
	leafIdx := s.NumFunctions() - 1
	arg := []byte{0x42}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Eval(nil, leafIdx, arg); err != nil {
			b.Fatal(err)
		}
	}
}

// TestLocalScriptNotInLocalScriptFlag verifies that a global function flagged
// notInLocalScript is rejected when used inside a local script body.
func TestLocalScriptNotInLocalScriptFlag(t *testing.T) {
	lib := NewBaseLibrary[any]()
	// Add an extended function and flag it.
	require.NoError(t, lib.ExtendMany(`func forbidden : concat($0, 0x99)`))
	fd, ok := lib.funByName["forbidden"]
	require.True(t, ok)
	fd.notInLocalScript = true

	// Local script that calls it should fail to compile.
	_, err := lib.CompileLocalScript(`func bad : forbidden($0)`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not allowed inside a local script")

	// A local script that doesn't reference it should still compile fine.
	_, err = lib.CompileLocalScript(`func good : concat($0, 0xaa)`)
	require.NoError(t, err)
}
