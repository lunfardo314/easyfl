package easyfl

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
)

// Phase-C test suite for the local-script feature. Covers compile, wire
// format, cycle detection, forward references, the call-site validation
// hook, evaluation, and decompile. Plus the Phase-B benchmarks at the
// bottom.

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
// LocalScriptCallSiteCheck (compile- and decode-time hook)
// =============================================================================

// TestLocalScriptCheck_FiresPerCallSite verifies that the hook is invoked
// once per non-trivial call expression, in preorder, and not for inline
// data or parameter references.
func TestLocalScriptCheck_FiresPerCallSite(t *testing.T) {
	lib := NewBaseLibrary[any]()
	type call struct {
		caller string
		callee string
	}
	var seen []call
	check := func(callerSym string, callee *Expression[any]) error {
		seen = append(seen, call{callerSym, callee.FunctionName})
		return nil
	}
	const source = `
func f : concat($0, 0xaa)
func g : f(concat($0, 0xbb))
`
	_, _, err := lib.CompileLocalScriptWithCheck(source, check)
	require.NoError(t, err)
	// f's body: concat($0, 0xaa) — one call ("concat"); $0 and 0xaa are
	// param ref / inline data and skipped.
	// g's body: f(concat($0, 0xbb)) — two calls ("f", "concat"); both args
	// of the inner concat are skipped.
	calleeNames := func() []string {
		out := make([]string, len(seen))
		for i, c := range seen {
			out[i] = c.callee
		}
		return out
	}()
	require.ElementsMatch(t, []string{"concat", "f", "concat"}, calleeNames)
}

// TestLocalScriptCheck_RejectByCallee shows the hook in its simplest mode:
// the host bans a specific callee at compile time. (This is the use case
// the legacy notInLocalScript flag covered before it was removed.)
func TestLocalScriptCheck_RejectByCallee(t *testing.T) {
	lib := NewBaseLibrary[any]()
	require.NoError(t, lib.ExtendMany(`func dangerous : concat($0, 0xff)`))

	check := func(_ string, callee *Expression[any]) error {
		if callee.FunctionName == "dangerous" {
			return fmt.Errorf("call to %q is not allowed", callee.FunctionName)
		}
		return nil
	}
	_, _, err := lib.CompileLocalScriptWithCheck(`func bad : dangerous($0)`, check)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not allowed")
	require.Contains(t, err.Error(), "dangerous")
}

// TestLocalScriptCheck_InspectsLiteralArg shows the callRedeemer-style use
// case: the hook reads a literal argument (would be a 32-byte hash in the
// real callRedeemer scenario) and decides based on its value.
func TestLocalScriptCheck_InspectsLiteralArg(t *testing.T) {
	lib := NewBaseLibrary[any]()
	pinned := map[string]bool{
		"\x9f\x3a": true, // arbitrary "known binary" stand-in
	}
	check := func(_ string, callee *Expression[any]) error {
		if callee.FunctionName != "concat" {
			return nil
		}
		if len(callee.Args) == 0 {
			return nil
		}
		first := callee.Args[0]
		if !first.IsInlineData() {
			return fmt.Errorf("first arg of concat must be a literal")
		}
		lit := string(first.InlineData())
		if !pinned[lit] {
			return fmt.Errorf("first arg of concat (%x) is not pinned", lit)
		}
		return nil
	}

	// Allowed: concat's first arg is the pinned literal 0x9f3a.
	_, _, err := lib.CompileLocalScriptWithCheck(`func ok : concat(0x9f3a, $0)`, check)
	require.NoError(t, err)

	// Rejected: concat's first arg is some other literal.
	_, _, err = lib.CompileLocalScriptWithCheck(`func bad : concat(0x1234, $0)`, check)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not pinned")

	// Rejected: concat's first arg is not a literal (it's another call).
	_, _, err = lib.CompileLocalScriptWithCheck(
		`func bad : concat(concat($0, 0x9f3a), $1)`, check)
	require.Error(t, err)
	require.Contains(t, err.Error(), "must be a literal")
}

// TestLocalScriptCheck_DecodeTime shows the hook running on a binary the
// caller did not compile themselves (defense-in-depth).
func TestLocalScriptCheck_DecodeTime(t *testing.T) {
	lib := NewBaseLibrary[any]()
	require.NoError(t, lib.ExtendMany(`func dangerous : concat($0, 0xff)`))

	// Compile a binary that uses `dangerous` (no flag flipped here).
	bin, err := lib.CompileLocalScript(`func bad : dangerous($0)`)
	require.NoError(t, err)

	check := func(_ string, callee *Expression[any]) error {
		if callee.FunctionName == "dangerous" {
			return fmt.Errorf("call to %q is not allowed", callee.FunctionName)
		}
		return nil
	}
	_, err = lib.LocalScriptFromBytesWithCheck(bin, check)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not allowed")

	// Same bin, no check: still decodes (host's choice to validate).
	_, err = lib.LocalScriptFromBytes(bin)
	require.NoError(t, err)
}

// TestLocalScriptCheck_CallRedeemerPattern is the worked example of the
// full chess-covenant pattern (chess_script.md §9.6): the host registers
// a `callRedeemer(hash, fnIdx, ...args)` global, pins the binaries it
// is willing to dispatch into, and uses the call-site check to enforce —
// at compile time — that every callRedeemer site has:
//
//   1. callee name "callRedeemer"
//   2. arg[0] is a 32-byte literal whose value hashes to a known binary
//   3. arg[1] is a 1-byte literal in range of the pinned binary's fns
//   4. the remaining args match that fn's declared arity
//
// All of (1)–(4) come out of the existing hook + Expression helpers; the
// host doesn't need any easyfl change.
func TestLocalScriptCheck_CallRedeemerPattern(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// --- Build a "library" local script that the consumer will pin. ---
	libBin, libIdx, err := lib.CompileLocalScriptWithIndex(`
func helper2 : concat($0, $1)
func helper3 : concat($0, $1, $2)
`)
	require.NoError(t, err)
	libScript, err := lib.LocalScriptFromBytes(libBin)
	require.NoError(t, err)
	libHash := blake2bSum32(libBin)

	// --- Register a vararg `callRedeemer` global so the consumer source
	//     parses. The body is irrelevant; only the call-site check
	//     inspects callRedeemer call structure at compile time. ---
	require.NoError(t, lib.ExtendMany(`func_vararg callRedeemer : $0`))

	// --- Host's call-site check: enforce the pattern above. ---
	pinned := map[[32]byte]*LocalScript[any]{libHash: libScript}
	check := func(_ string, callee *Expression[any]) error {
		if callee.FunctionName != "callRedeemer" {
			return nil
		}
		if len(callee.Args) < 2 {
			return fmt.Errorf("callRedeemer needs at least hash + fnIdx")
		}
		// (2) hash literal
		h := callee.Args[0]
		if !h.IsInlineData() {
			return fmt.Errorf("callRedeemer arg 0 must be a 32-byte literal hash")
		}
		hashBytes := h.InlineData()
		if len(hashBytes) != 32 {
			return fmt.Errorf("callRedeemer arg 0 must be 32 bytes, got %d", len(hashBytes))
		}
		var key [32]byte
		copy(key[:], hashBytes)
		dep, ok := pinned[key]
		if !ok {
			return fmt.Errorf("callRedeemer hash %x is not pinned", key)
		}
		// (3) fnIdx literal in range
		f := callee.Args[1]
		if !f.IsInlineData() {
			return fmt.Errorf("callRedeemer arg 1 must be a 1-byte literal fnIdx")
		}
		idxBytes := f.InlineData()
		if len(idxBytes) != 1 {
			return fmt.Errorf("callRedeemer arg 1 must be 1 byte, got %d", len(idxBytes))
		}
		idx := int(idxBytes[0])
		if idx < 0 || idx >= dep.NumFunctions() {
			return fmt.Errorf("callRedeemer fnIdx %d out of range (dep has %d fns)",
				idx, dep.NumFunctions())
		}
		// (4) arity match
		arity, err := dep.Arity(idx)
		if err != nil {
			return err
		}
		nForwarded := len(callee.Args) - 2
		if nForwarded != arity {
			return fmt.Errorf("callRedeemer to fn#%d: expected %d forwarded args, got %d",
				idx, arity, nForwarded)
		}
		return nil
	}

	// --- Helpers for assembling source ---
	helper2Wire := libIdx["helper2"]
	helper3Wire := libIdx["helper3"]
	hashLit := fmt.Sprintf("0x%x", libHash[:])
	bytesLit := func(b byte) string { return fmt.Sprintf("0x%02x", b) }

	// --- (a) Valid: pinned hash, valid idx, arity matches. ---
	src := fmt.Sprintf(`func ok : callRedeemer(%s, %s, $0, $1)`,
		hashLit, bytesLit(byte(helper2Wire)))
	_, _, err = lib.CompileLocalScriptWithCheck(src, check)
	require.NoError(t, err, "valid callRedeemer must be accepted")

	// --- (b) Different valid call: helper3 with 3 args. ---
	src = fmt.Sprintf(`func ok : callRedeemer(%s, %s, $0, $1, $2)`,
		hashLit, bytesLit(byte(helper3Wire)))
	_, _, err = lib.CompileLocalScriptWithCheck(src, check)
	require.NoError(t, err)

	// --- (c) Reject: hash is a valid 32-byte literal but not pinned. ---
	wrongHash := "0x" + strings.Repeat("00", 32)
	src = fmt.Sprintf(`func bad : callRedeemer(%s, %s, $0, $1)`,
		wrongHash, bytesLit(byte(helper2Wire)))
	_, _, err = lib.CompileLocalScriptWithCheck(src, check)
	require.Error(t, err)
	require.Contains(t, err.Error(), "is not pinned")

	// --- (d) Reject: hash literal is not 32 bytes. ---
	src = fmt.Sprintf(`func bad : callRedeemer(0xdeadbeef, %s, $0, $1)`,
		bytesLit(byte(helper2Wire)))
	_, _, err = lib.CompileLocalScriptWithCheck(src, check)
	require.Error(t, err)
	require.Contains(t, err.Error(), "must be 32 bytes")

	// --- (e) Reject: hash arg is not a literal at all. ---
	src = fmt.Sprintf(`func bad : callRedeemer(concat($0, %s), %s, $1, $2)`,
		hashLit, bytesLit(byte(helper2Wire)))
	_, _, err = lib.CompileLocalScriptWithCheck(src, check)
	require.Error(t, err)
	require.Contains(t, err.Error(), "must be a 32-byte literal hash")

	// --- (f) Reject: fnIdx out of range for the pinned binary. ---
	oob := byte(libScript.NumFunctions())
	src = fmt.Sprintf(`func bad : callRedeemer(%s, %s, $0, $1)`,
		hashLit, bytesLit(oob))
	_, _, err = lib.CompileLocalScriptWithCheck(src, check)
	require.Error(t, err)
	require.Contains(t, err.Error(), "out of range")

	// --- (g) Reject: arity mismatch (helper2 expects 2 forwarded args). ---
	src = fmt.Sprintf(`func bad : callRedeemer(%s, %s, $0, $1, $2)`,
		hashLit, bytesLit(byte(helper2Wire)))
	_, _, err = lib.CompileLocalScriptWithCheck(src, check)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected 2 forwarded args, got 3")

	// --- (h) Decode-time defense: a bin compiled WITHOUT the check (or
	//     compiled in a different process / pinned set) is still loadable
	//     under LocalScriptFromBytesWithCheck for re-validation. ---
	src = fmt.Sprintf(`func ok : callRedeemer(%s, %s, $0, $1)`,
		hashLit, bytesLit(byte(helper2Wire)))
	bin, err := lib.CompileLocalScript(src)
	require.NoError(t, err)
	_, err = lib.LocalScriptFromBytesWithCheck(bin, check)
	require.NoError(t, err)
	// And: same bin re-checked under a different pinned set fails.
	otherCheck := func(_ string, callee *Expression[any]) error {
		if callee.FunctionName == "callRedeemer" {
			return fmt.Errorf("callRedeemer not pinned in this context")
		}
		return nil
	}
	_, err = lib.LocalScriptFromBytesWithCheck(bin, otherCheck)
	require.Error(t, err)
}

// blake2bSum32 returns blake2b-256 of data as a 32-byte array.
func blake2bSum32(data []byte) [32]byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// TestLocalScriptCheck_NilIsNoop confirms a nil hook is the same as the
// non-Check entry point.
func TestLocalScriptCheck_NilIsNoop(t *testing.T) {
	lib := NewBaseLibrary[any]()
	bin1, idx1, err := lib.CompileLocalScriptWithCheck(`func f : concat($0, 0xaa)`, nil)
	require.NoError(t, err)
	bin2, idx2, err := lib.CompileLocalScriptWithIndex(`func f : concat($0, 0xaa)`)
	require.NoError(t, err)
	require.Equal(t, bin2, bin1)
	require.Equal(t, idx2, idx1)
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
