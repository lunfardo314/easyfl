package easyfl

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Phase-C test suite for the local-script feature. Covers compile, wire
// format, cycle detection, forward references, the notInLocalScript flag,
// evaluation, and decompile. Plus the Phase-B benchmarks at the bottom.

// =============================================================================
// Compile & wire format
// =============================================================================

func TestLocalScript_EmptyRoundTrip(t *testing.T) {
	lib := NewBaseLibrary[any]()
	bin, err := lib.CompileLocalScript("")
	require.NoError(t, err)

	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)
	require.Equal(t, 0, s.NumFunctions())
}

func TestLocalScript_SingleFnNoParams(t *testing.T) {
	lib := NewBaseLibrary[any]()
	bin, err := lib.CompileLocalScript(`func only : 0xdeadbeef`)
	require.NoError(t, err)

	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)
	require.Equal(t, 1, s.NumFunctions())

	got, err := s.Eval(nil, 0)
	require.NoError(t, err)
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, got)
}

func TestLocalScript_SingleFnWithParams(t *testing.T) {
	lib := NewBaseLibrary[any]()
	bin, err := lib.CompileLocalScript(`func only : concat($0, $1)`)
	require.NoError(t, err)

	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)

	got, err := s.Eval(nil, 0, []byte{0xaa}, []byte{0xbb})
	require.NoError(t, err)
	require.Equal(t, []byte{0xaa, 0xbb}, got)
}

// TestLocalScript_NonTopologicalSourceOrder confirms source-order freedom
// even with a non-trivial dependency graph: top depends on left and right;
// both depend on leaf; source declares them top, left, leaf, right (mixed).
func TestLocalScript_NonTopologicalSourceOrder(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `
 func top   : concat(left($0), right($0))
 func left  : leaf($0)
 func leaf  : concat($0, 0xaa)
 func right : leaf($0)
`
	bin, err := lib.CompileLocalScript(source)
	require.NoError(t, err)
	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)
	require.Equal(t, 4, s.NumFunctions())

	// Try every wire index with a 1-byte arg; whichever is `top` returns
	// 4 bytes (leaf||leaf), whichever are left/right return 2 bytes, and
	// leaf returns 2 bytes. Any error means the dependency graph wasn't
	// resolved correctly.
	arg := []byte{0x42}
	for i := 0; i < s.NumFunctions(); i++ {
		got, err := s.Eval(nil, i, arg)
		require.NoError(t, err, "idx=%d", i)
		require.Contains(t, [][]byte{
			{0x42, 0xaa},
			{0x42, 0xaa, 0x42, 0xaa},
		}, got, "idx=%d", i)
	}
}

func TestLocalScript_BadMagic(t *testing.T) {
	lib := NewBaseLibrary[any]()
	// 7 bytes: magic[2] + version + n[2] + bodyLen[2]. Bytes long enough to
	// pass the truncation check; bad magic must surface as a "magic" error.
	bad := []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	_, err := lib.LocalScriptFromBytes(bad)
	require.Error(t, err)
	require.Contains(t, err.Error(), "magic")
}

func TestLocalScript_BadVersion(t *testing.T) {
	lib := NewBaseLibrary[any]()
	bin, err := lib.CompileLocalScript(`func f : 0`)
	require.NoError(t, err)
	tampered := append([]byte(nil), bin...)
	tampered[2] = 0xff // version byte
	_, err = lib.LocalScriptFromBytes(tampered)
	require.Error(t, err)
	require.Contains(t, err.Error(), "version")
}

func TestLocalScript_TruncatedHeader(t *testing.T) {
	lib := NewBaseLibrary[any]()
	bin, err := lib.CompileLocalScript(`func f : 0`)
	require.NoError(t, err)

	// Header for n=1 is 5 + 3*1 + 2 = 10 bytes; truncating to 6 must fail.
	_, err = lib.LocalScriptFromBytes(bin[:6])
	require.Error(t, err)
	require.Contains(t, err.Error(), "truncated")
}

func TestLocalScript_TruncatedBody(t *testing.T) {
	lib := NewBaseLibrary[any]()
	bin, err := lib.CompileLocalScript(`func f : 0`)
	require.NoError(t, err)

	// Drop the last byte of the body.
	_, err = lib.LocalScriptFromBytes(bin[:len(bin)-1])
	require.Error(t, err)
	require.Contains(t, err.Error(), "bodyLen")
}

func TestLocalScript_BadOffset(t *testing.T) {
	lib := NewBaseLibrary[any]()
	bin, err := lib.CompileLocalScript(`func f : 0`)
	require.NoError(t, err)

	// Header for n=1 is magic[2] + version[1] + n[2] + arity[1] + offsets[2]
	// + bodyLen[2] = 10 bytes. offsets[0] sits at [6:8], bodyLen at [8:10].
	// Tamper offsets[0] to point past bodyLen.
	tampered := append([]byte(nil), bin...)
	bodyLen := binary.BigEndian.Uint16(tampered[8:10])
	binary.BigEndian.PutUint16(tampered[6:8], bodyLen+1)
	_, err = lib.LocalScriptFromBytes(tampered)
	require.Error(t, err)
	require.Contains(t, err.Error(), "offsets")
}

func TestLocalScript_256FunctionsOK(t *testing.T) {
	lib := NewBaseLibrary[any]()

	var b strings.Builder
	for i := 0; i < 256; i++ {
		fmt.Fprintf(&b, "func f%d : %d\n", i, i)
	}
	bin, err := lib.CompileLocalScript(b.String())
	require.NoError(t, err)

	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)
	require.Equal(t, 256, s.NumFunctions())
}

func TestLocalScript_257FunctionsRejected(t *testing.T) {
	lib := NewBaseLibrary[any]()

	var b strings.Builder
	for i := 0; i < 257; i++ {
		fmt.Fprintf(&b, "func f%d : %d\n", i, i&0xff)
	}
	_, err := lib.CompileLocalScript(b.String())
	require.Error(t, err)
	require.Contains(t, err.Error(), "too many functions")
}

func TestLocalScript_15ParamsOK(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `func f : concat($0,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	bin, err := lib.CompileLocalScript(source)
	require.NoError(t, err)

	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)

	args := make([][]byte, 15)
	want := make([]byte, 15)
	for i := range args {
		args[i] = []byte{byte(i + 1)}
		want[i] = byte(i + 1)
	}
	got, err := s.Eval(nil, 0, args...)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestLocalScript_16ParamsRejected(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `func f : concat($0,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`
	_, err := lib.CompileLocalScript(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "max 15")
}

func TestLocalScript_VarargRejected(t *testing.T) {
	lib := NewBaseLibrary[any]()
	_, err := lib.CompileLocalScript(`func_vararg foo : concat($0)`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "vararg")
}

func TestLocalScript_DuplicateRejected(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `
 func a : 1
 func a : 2
`
	_, err := lib.CompileLocalScript(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "duplicate")
}

// =============================================================================
// Cycles & forward references
// =============================================================================

func TestLocalScript_DirectRecursionRejected(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `
 func a : b($0)
 func b : a($0)
`
	_, err := lib.CompileLocalScript(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "recursion")
	// Cycle must include both names.
	require.Contains(t, err.Error(), "a")
	require.Contains(t, err.Error(), "b")
}

func TestLocalScript_IndirectRecursionRejected(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `
 func a : b($0)
 func b : c($0)
 func c : a($0)
`
	_, err := lib.CompileLocalScript(source)
	require.Error(t, err)
	require.Contains(t, err.Error(), "recursion")
	require.Contains(t, err.Error(), "a")
	require.Contains(t, err.Error(), "b")
	require.Contains(t, err.Error(), "c")
}

func TestLocalScript_ForwardReferenceAccepted(t *testing.T) {
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

	// Both indices invoked with {0x42} return {0x42, 0xaa}.
	for idx := 0; idx < 2; idx++ {
		got, err := s.Eval(nil, idx, []byte{0x42})
		require.NoError(t, err, "idx=%d", idx)
		require.Equal(t, []byte{0x42, 0xaa}, got, "idx=%d", idx)
	}
}

func TestLocalScript_DiamondDependencyAccepted(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `
 func leaf  : concat($0, 0xaa)
 func left  : leaf($0)
 func right : leaf($0)
 func top   : concat(left($0), right($0))
`
	bin, err := lib.CompileLocalScript(source)
	require.NoError(t, err)

	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)
	require.Equal(t, 4, s.NumFunctions())

	// Identify `top` by output length: it's the only one returning 4 bytes.
	arg := []byte{0x42}
	got4 := 0
	for i := 0; i < s.NumFunctions(); i++ {
		out, err := s.Eval(nil, i, arg)
		require.NoError(t, err, "idx=%d", i)
		if len(out) == 4 {
			got4++
			require.Equal(t, []byte{0x42, 0xaa, 0x42, 0xaa}, out)
		} else {
			require.Equal(t, []byte{0x42, 0xaa}, out)
		}
	}
	require.Equal(t, 1, got4, "exactly one fn (top) should produce 4 bytes")
}

// =============================================================================
// notInLocalScript flag
// =============================================================================

func TestLocalScript_NotInLocalScript_CompileReject(t *testing.T) {
	lib := NewBaseLibrary[any]()
	require.NoError(t, lib.ExtendMany(`func forbidden : concat($0, 0x99)`))
	fd, ok := lib.funByName["forbidden"]
	require.True(t, ok)
	fd.notInLocalScript = true

	_, err := lib.CompileLocalScript(`func bad : forbidden($0)`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not allowed inside a local script")
	require.Contains(t, err.Error(), "forbidden")
}

func TestLocalScript_NotInLocalScript_DecodeReject(t *testing.T) {
	lib := NewBaseLibrary[any]()
	require.NoError(t, lib.ExtendMany(`func forbidden : concat($0, 0x99)`))

	// Compile a script that uses `forbidden` BEFORE flipping the flag.
	bin, err := lib.CompileLocalScript(`func bad : forbidden($0)`)
	require.NoError(t, err)

	// Flip the flag retroactively. Decoding the previously-compiled bin must
	// now fail (defense-in-depth on the decoder).
	fd, ok := lib.funByName["forbidden"]
	require.True(t, ok)
	fd.notInLocalScript = true

	_, err = lib.LocalScriptFromBytes(bin)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not allowed inside a local script")
}

func TestLocalScript_NotInLocalScript_GlobalUseAllowed(t *testing.T) {
	lib := NewBaseLibrary[any]()
	require.NoError(t, lib.ExtendMany(`func forbidden : concat($0, 0x99)`))
	fd, ok := lib.funByName["forbidden"]
	require.True(t, ok)
	fd.notInLocalScript = true

	// Calling `forbidden` from a top-level / extended-fn body still works.
	require.NoError(t, lib.ExtendMany(`func usesForbidden : forbidden($0)`))
	got, err := lib.EvalFromSource(nil, `usesForbidden(0x42)`)
	require.NoError(t, err)
	require.Equal(t, []byte{0x42, 0x99}, got)
}

// =============================================================================
// Evaluation edge cases
// =============================================================================

func TestLocalScript_OutOfBoundsIdx(t *testing.T) {
	lib := NewBaseLibrary[any]()
	bin, err := lib.CompileLocalScript(`func f : 0`)
	require.NoError(t, err)
	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)

	_, err = s.Function(7)
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of bounds")

	_, err = s.Eval(nil, 7)
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of bounds")

	_, err = s.Function(-1)
	require.Error(t, err)

	_, err = s.Arity(7)
	require.Error(t, err)
}

func TestLocalScript_WrongArity(t *testing.T) {
	lib := NewBaseLibrary[any]()
	bin, err := lib.CompileLocalScript(`func f : concat($0, $1)`)
	require.NoError(t, err)
	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)

	// Declared arity is 2.
	ar, err := s.Arity(0)
	require.NoError(t, err)
	require.Equal(t, 2, ar)

	// Too few args.
	_, err = s.Eval(nil, 0, []byte{0x01})
	require.Error(t, err)
	require.Contains(t, err.Error(), "expects 2 args")

	// Too many args.
	_, err = s.Eval(nil, 0, []byte{0x01}, []byte{0x02}, []byte{0x03})
	require.Error(t, err)
	require.Contains(t, err.Error(), "expects 2 args")
}

func TestLocalScript_IntraScriptCall(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `
 func leaf   : concat($0, 0xaa)
 func caller : leaf($0)
`
	bin, err := lib.CompileLocalScript(source)
	require.NoError(t, err)
	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)

	// leaf at wire-idx 0 (no deps), caller at wire-idx 1.
	gotLeaf, err := s.Eval(nil, 0, []byte{0x42})
	require.NoError(t, err)
	require.Equal(t, []byte{0x42, 0xaa}, gotLeaf)

	gotCaller, err := s.Eval(nil, 1, []byte{0x42})
	require.NoError(t, err)
	require.Equal(t, []byte{0x42, 0xaa}, gotCaller)
}

// =============================================================================
// Decompile
// =============================================================================

// TestLocalScript_DecompileSane verifies that the bytecode of a local-script
// function, decompiled with the script in scope, produces a source string
// referencing the synthetic local symbol of the callee.
func TestLocalScript_DecompileSane(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `
 func leaf   : concat($0, 0xaa)
 func caller : leaf($0)
`
	bin, err := lib.CompileLocalScript(source)
	require.NoError(t, err)
	s, err := lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)

	// Take caller (wire-idx 1) and recover its bytecode by re-encoding its
	// expression. Then DecompileBytecode with the script in scope.
	expr, err := s.Function(1)
	require.NoError(t, err)
	bc := ExpressionToBytecode(expr)

	src, err := lib.DecompileBytecode(bc, s)
	require.NoError(t, err)

	// Synthetic local symbols are "script#0" / "script#1" / ...
	// Caller's body is `leaf($0)` which is `script#0($0)` after decode.
	require.Contains(t, src, "script#0")

	// And without the script in scope, the local-call prefix can't be
	// resolved, so DecompileBytecode should fail.
	_, err = lib.DecompileBytecode(bc)
	require.Error(t, err)
}

// =============================================================================
// Benchmarks (Phase B carry-over)
// =============================================================================

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

func BenchmarkLocalScriptDeepCall(b *testing.B) {
	lib := NewBaseLibrary[any]()
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
