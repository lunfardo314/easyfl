package easyfl

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
)

const formula1 = "func unlockBlock: concat(concat(0x0000, slice(0x01020304050607, 2, 5)))"

func TestCompile(t *testing.T) {
	t.Run("1", func(t *testing.T) {
		ret, err := parseFunctions(formula1)
		require.NoError(t, err)
		require.NotNil(t, ret)
	})
	t.Run("3", func(t *testing.T) {
		ret, err := parseFunctions(formula1)
		require.NoError(t, err)
		require.EqualValues(t, 1, len(ret))

		code, numParams, err := ExpressionSourceToBinary(ret[0].SourceCode)
		require.NoError(t, err)
		require.EqualValues(t, 0, numParams)
		t.Logf("code len: %d", len(code))
	})
	t.Run("4", func(t *testing.T) {
		parsed, err := parseFunctions(formula1)
		require.NoError(t, err)
		require.EqualValues(t, 1, len(parsed))

		code, numParams, err := ExpressionSourceToBinary(parsed[0].SourceCode)
		require.NoError(t, err)
		require.EqualValues(t, 0, numParams)
		t.Logf("code len: %d", len(code))

		f, err := ExpressionFromBinary(code)
		require.NoError(t, err)
		require.NotNil(t, f)
	})
}

func TestEval(t *testing.T) {
	t.Run("1", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "125")
		require.NoError(t, err)
		require.EqualValues(t, []byte{125}, ret)
	})
	t.Run("2", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "sum8(125, 6)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{131}, ret)
	})
	t.Run("3", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "$0", []byte{222})
		require.NoError(t, err)
		require.EqualValues(t, []byte{222}, ret)
	})
	t.Run("4", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "concat($0,$1)", []byte{222}, []byte{111})
		require.NoError(t, err)
		require.EqualValues(t, []byte{222, 111}, ret)
	})
	t.Run("5", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "concat($0,concat($1,$0))", []byte{222}, []byte{111})
		require.NoError(t, err)
		require.EqualValues(t, []byte{222, 111, 222}, ret)
	})
	t.Run("6", func(t *testing.T) {
		ret, err := EvalFromSource(nil,
			"concat(concat(slice($2,1,1), byte($2,0)), slice(concat(concat($0,$1),concat($1,$0)),1,2))",
			[]byte{222}, []byte{111}, []byte{123, 234})
		require.NoError(t, err)
		require.EqualValues(t, []byte{234, 123, 111, 111}, ret)
	})
	t.Run("7", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "len8($1)", nil, []byte("123456789"))
		require.NoError(t, err)
		require.EqualValues(t, []byte{9}, ret)
	})
	t.Run("8", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "concat(1,2,3,4,5)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{1, 2, 3, 4, 5}, ret)
	})
	t.Run("9", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "slice(concat(concat(1,2),concat(3,4,5)),2,3)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{3, 4}, ret)
	})
	t.Run("10", func(t *testing.T) {
		tr := NewGlobalDataTracePrint(nil)
		ret, err := EvalFromSource(tr, "if(equal(len8($0),3), 0x01, 0x05)", []byte("abc"))
		require.NoError(t, err)
		require.EqualValues(t, []byte{1}, ret)
	})
	t.Run("11", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "if(equal(len8($0),3), 0x01, 0x05)", []byte("abcdef"))
		require.NoError(t, err)
		require.EqualValues(t, []byte{5}, ret)
	})
	const longer = `
			if(
				not(equal(len8($0),5)),   // comment 1
				0x01,
				// comment without code
				0x0506     // comment2
			)`
	t.Run("12", func(t *testing.T) {
		ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), longer, []byte("abcdef"))
		require.NoError(t, err)
		require.EqualValues(t, []byte{1}, ret)
	})
	t.Run("14", func(t *testing.T) {
		ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), longer, []byte("abcde"))
		require.NoError(t, err)
		require.EqualValues(t, []byte{5, 6}, ret)
	})
	t.Run("15", func(t *testing.T) {
		ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), "nil")
		require.NoError(t, err)
		require.True(t, len(ret) == 0)
	})
	t.Run("16", func(t *testing.T) {
		ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), "concat")
		require.NoError(t, err)
		require.True(t, len(ret) == 0)
	})
	t.Run("17", func(t *testing.T) {
		ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), "u16/256")
		require.NoError(t, err)
		require.EqualValues(t, []byte{1, 0}, ret)
	})
	t.Run("18", func(t *testing.T) {
		ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), "u32/70000")
		require.NoError(t, err)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], 70000)
		require.EqualValues(t, b[:], ret)
	})
	t.Run("19", func(t *testing.T) {
		ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), "u64/10000000000")
		require.NoError(t, err)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], 10000000000)
		require.EqualValues(t, b[:], ret)
	})
	t.Run("20", func(t *testing.T) {
		ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), "isZero(0x000000)")
		require.NoError(t, err)
		require.True(t, len(ret) != 0)
	})
	t.Run("21", func(t *testing.T) {
		ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), "isZero(0x003000)")
		require.NoError(t, err)
		require.True(t, len(ret) == 0)
	})
	t.Run("21", func(t *testing.T) {
		ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), "sum8_16($0, $1)", []byte{160}, []byte{160})
		require.NoError(t, err)
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], 320)
		require.EqualValues(t, b[:], ret)
	})
	t.Run("22", func(t *testing.T) {
		_, err := EvalFromSource(NewGlobalDataTracePrint(nil), "sum8($0, $1)", []byte{160}, []byte{160})
		RequireErrorWith(t, err, "arithmetic overflow")
	})
	var blake2bInvokedNum int
	EmbedLong("blake2b-test", 1, func(par *CallParams) []byte {
		a0 := par.Arg(0)
		h := blake2b.Sum256(a0)
		blake2bInvokedNum++
		par.Trace("blake2b-test:: %v -> %v", a0, h[:])
		return h[:]
	})
	t.Run("23", func(t *testing.T) {
		blake2bInvokedNum = 0
		ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), "blake2b-test($0)", []byte{1, 2, 3})
		require.NoError(t, err)
		h := blake2b.Sum256([]byte{0x01, 0x02, 0x03})
		require.EqualValues(t, h[:], ret)
		require.EqualValues(t, blake2bInvokedNum, 1)

		ret, err = EvalFromSource(NewGlobalDataTracePrint(nil), "blake2b-test($0)", nil)
		require.NoError(t, err)
		h = blake2b.Sum256(nil)
		require.EqualValues(t, h[:], ret)
		require.EqualValues(t, blake2bInvokedNum, 2)
	})
	t.Run("24", func(t *testing.T) {
		blake2bInvokedNum = 0
		h2 := blake2b.Sum256([]byte{2})
		h3 := blake2b.Sum256([]byte{3})

		ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), "if($0,blake2b-test($1),blake2b-test($2))",
			[]byte{1}, []byte{2}, []byte{3})
		require.NoError(t, err)
		require.EqualValues(t, h2[:], ret)
		require.EqualValues(t, blake2bInvokedNum, 1)

		ret, err = EvalFromSource(NewGlobalDataTracePrint(nil), "if($0,blake2b-test($1),blake2b-test($2))",
			nil, []byte{2}, []byte{3})
		require.NoError(t, err)
		require.EqualValues(t, h3[:], ret)
		require.EqualValues(t, blake2bInvokedNum, 2)
	})
}

func TestExtendLib(t *testing.T) {
	t.Run("ext-2", func(t *testing.T) {
		_, err := ExtendErr("nil1", "concat()")
		require.NoError(t, err)
	})
	t.Run("ext-3", func(t *testing.T) {
		_, err := ExtendErr("cat2", "concat($0, $1)")
		require.NoError(t, err)
		ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), "cat2(1,2)")
		require.EqualValues(t, []byte{1, 2}, ret)
	})
	const complex = `
		concat(
			concat($0,$1),
			concat($0,$2)
		)
	`
	_, err := ExtendErr("complex", complex)
	require.NoError(t, err)

	d := func(i byte) []byte { return []byte{i} }
	compl := func(d0, d1, d2 []byte) []byte {
		c0 := Concat(d0, d1)
		c1 := Concat(d0, d2)
		c3 := Concat(c0, c1)
		return c3
	}
	t.Run("ext-4", func(t *testing.T) {
		ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), "complex(0,1,2)")
		require.NoError(t, err)
		require.EqualValues(t, compl(d(0), d(1), d(2)), ret)
	})
	t.Run("ext-5", func(t *testing.T) {
		ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), "complex(0,1,complex(2,1,0))")
		require.NoError(t, err)
		exp := compl(d(0), d(1), compl(d(2), d(1), d(0)))
		require.EqualValues(t, exp, ret)
	})
	t.Run("eval from binary", func(t *testing.T) {
		source := "concat($2, $1, $0)"
		_, arity, code, err := CompileExpression(source)
		require.NoError(t, err)
		require.EqualValues(t, 3, arity)
		t.Logf("compiled binary code of '%s' is %d-bytes long", source, len(code))
		ret, err := EvalFromBinary(NewGlobalDataTracePrint(nil), code, []byte{1}, []byte{2}, []byte{3})
		require.NoError(t, err)
		require.EqualValues(t, []byte{3, 2, 1}, ret)
	})
	t.Run("always panics", func(t *testing.T) {
		_, err := EvalFromSource(NewGlobalDataTracePrint(nil), "byte(0,1)")
		require.Error(t, err)
	})
	t.Run("never panics", func(t *testing.T) {
		_, err := EvalFromSource(NewGlobalDataTracePrint(nil), "if(concat,byte(0,1),0x01)")
		require.NoError(t, err)
	})

}

func num(n any) []byte {
	switch n := n.(type) {
	case byte:
		return []byte{n}
	case uint16:
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], n)
		return b[:]
	case uint32:
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], n)
		return b[:]
	case uint64:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], n)
		return b[:]
	case int:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		return b[:]
	}
	panic("wrong type")
}

func TestComparison(t *testing.T) {
	runTest := func(s string, a0, a1 []byte) bool {
		fmt.Printf("---- runTest: '%s'\n", s)
		ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), s, a0, a1)
		require.NoError(t, err)
		if len(ret) == 0 {
			return false
		}
		return true
	}
	t.Run("lessThan", func(t *testing.T) {
		res := runTest("lessThan($0,$1)", num(1), num(5))
		require.True(t, res)
		res = runTest("lessThan($0,$1)", num(10), num(5))
		require.False(t, res)
		res = runTest("lessThan($0,$1)", num(100), num(100))
		require.False(t, res)
		res = runTest("lessThan($0,$1)", num(1000), num(100000000))
		require.True(t, res)
		res = runTest("lessThan($0,$1)", num(100000000), num(100000000))
		require.False(t, res)
		res = runTest("lessThan($0,$1)", num(uint16(100)), num(uint16(150)))
		require.True(t, res)
		res = runTest("lessThan($0,$1)", num(uint32(100)), num(uint32(150)))
		require.True(t, res)
	})
	t.Run("lessThanOrEqual", func(t *testing.T) {
		res := runTest("lessOrEqualThan($0,$1)", num(1), num(5))
		require.True(t, res)
		res = runTest("lessOrEqualThan($0,$1)", num(10), num(5))
		require.False(t, res)
		res = runTest("lessOrEqualThan($0,$1)", num(100), num(100))
		require.True(t, res)
		res = runTest("lessOrEqualThan($0,$1)", num(1000), num(100000000))
		require.True(t, res)
		res = runTest("lessOrEqualThan($0,$1)", num(100000000), num(100000000))
		require.True(t, res)
		res = runTest("lessOrEqualThan($0,$1)", num(uint16(100)), num(uint16(150)))
		require.True(t, res)
		res = runTest("lessOrEqualThan($0,$1)", num(uint32(100)), num(uint32(150)))
		require.True(t, res)
	})
}

func TestSigED25519(t *testing.T) {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	pubKey, privKey, err := ed25519.GenerateKey(rnd)
	require.NoError(t, err)

	const msg = "message to be signed"

	t.Run("validSignatureED25519-ok", func(t *testing.T) {
		signature := ed25519.Sign(privKey, []byte(msg))
		res, err := EvalFromSource(NewGlobalDataTracePrint(nil), "validSignatureED25519($0,$1,$2)", []byte(msg), signature, pubKey)
		require.NoError(t, err)

		require.True(t, len(res) > 0)
	})
	t.Run("validSignatureED25519-wrong-msg", func(t *testing.T) {
		signature := ed25519.Sign(privKey, []byte(msg))
		res, err := EvalFromSource(NewGlobalDataTracePrint(nil), "validSignatureED25519($0,$1,$2)", []byte(msg+"klmn"), signature, pubKey)
		require.NoError(t, err)

		require.True(t, len(res) == 0)
	})
	t.Run("validSignatureED25519-wrong-sig", func(t *testing.T) {
		signature := ed25519.Sign(privKey, []byte(msg))
		signature[5]++
		res, err := EvalFromSource(NewGlobalDataTracePrint(nil), "validSignatureED25519($0,$1,$2)", []byte(msg), signature, pubKey)
		require.NoError(t, err)

		require.True(t, len(res) == 0)
	})
	t.Run("validSignatureED25519-wrong-pubkey", func(t *testing.T) {
		signature := ed25519.Sign(privKey, []byte(msg))
		pk := Concat([]byte(pubKey))
		pk[3]++
		res, err := EvalFromSource(NewGlobalDataTracePrint(nil), "validSignatureED25519($0,$1,$2)", []byte(msg), signature, pk)
		require.NoError(t, err)

		require.True(t, len(res) == 0)
	})
	t.Run("validSignatureED25519-wrong-pubkey", func(t *testing.T) {
		_, err := EvalFromSource(NewGlobalDataTracePrint(nil), "validSignatureED25519($0,$1,$2)", nil, nil, nil)
		RequireErrorWith(t, err, "bad public key length")
	})
}

func TestTracing(t *testing.T) {
	t.Run("no panic 0", func(t *testing.T) {
		tr := NewGlobalDataLog(nil)
		ret, err := EvalFromSource(tr, "slice(concat(concat(1,2),concat(3,4,5)),2,3)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{3, 4}, ret)
		tr.PrintLog()
	})
	t.Run("with panic 1", func(t *testing.T) {
		tr := NewGlobalDataLog(nil)
		_, err := EvalFromSource(tr, "slice(0x0102,2,3)")
		require.Error(t, err)
		tr.PrintLog()
	})
	t.Run("no panic 2", func(t *testing.T) {
		tr := NewGlobalDataLog(nil)
		_, err := EvalFromSource(tr, "slice(tail(0x0102030405,2),1,2)")
		require.NoError(t, err)
		tr.PrintLog()
	})
	t.Run("with panic 3", func(t *testing.T) {
		tr := NewGlobalDataLog(nil)
		_, err := EvalFromSource(tr, "slice(tail(0x0102030405,2),1,5)")
		require.Error(t, err)
		tr.PrintLog()
	})
	t.Run("no panic 4", func(t *testing.T) {
		tr := NewGlobalDataLog(nil)
		_, err := EvalFromSource(tr, "equal(slice(tail(0x0102030405,2),1,2), slice(tail(0x0102030405,2),2,2))")
		require.NoError(t, err)
		tr.PrintLog()
	})
	t.Run("no panic 5", func(t *testing.T) {
		tr := NewGlobalDataLog(nil)
		_, err := EvalFromSource(tr, "equal(len8(slice(tail(0x0102030405,2),1,2)), 2)")
		require.NoError(t, err)
		tr.PrintLog()
	})
	t.Run("no panic 6", func(t *testing.T) {
		tr := NewGlobalDataLog(nil)
		_, err := EvalFromSource(tr, "equal(len16(slice(tail(0x0102030405,2),1,2)), u16/2)")
		require.NoError(t, err)
		tr.PrintLog()
	})
	t.Run("no trace", func(t *testing.T) {
		tr := NewGlobalDataNoTrace(nil)
		_, err := EvalFromSource(tr, "equal(len16(slice(tail(0x0102030405,2),1,2)), u16/2)")
		require.NoError(t, err)
	})
	t.Run("trace print", func(t *testing.T) {
		tr := NewGlobalDataTracePrint(nil)
		_, err := EvalFromSource(tr, "equal(len16(slice(tail(0x0102030405,2),1,2)), u16/2)")
		require.NoError(t, err)
	})
	t.Run("trace if", func(t *testing.T) {
		tr := NewGlobalDataLog(nil)
		_, err := EvalFromSource(tr, "if(nil,0x1234,0x5678)")
		require.NoError(t, err)
		tr.PrintLog()
	})
	t.Run("trace not", func(t *testing.T) {
		tr := NewGlobalDataTracePrint(nil)
		_, err := EvalFromSource(tr, "not(not(not($0)))", []byte{10})
		require.NoError(t, err)
	})
	t.Run("trace concat", func(t *testing.T) {
		tr := NewGlobalDataTracePrint(nil)
		_, err := EvalFromSource(tr, "concat($0,concat($0,$0))", []byte{10})
		require.NoError(t, err)
		tr = NewGlobalDataTracePrint(nil)
		_, err = EvalFromSource(tr, "concat(concat())")
		require.NoError(t, err)
	})
}

func TestArithmetics(t *testing.T) {
	runTest := func(s string, a0, a1, exp []byte) {
		name := fmt.Sprintf("%s: %s, %s -> %s", s, Fmt(a0), Fmt(a1), Fmt(exp))
		t.Run(name, func(t *testing.T) {
			ret, err := EvalFromSource(NewGlobalDataTracePrint(nil), s, a0, a1)
			require.NoError(t, err)
			require.EqualValues(t, exp, ret)
		})
	}
	runTest("mul8_16($0,$1)", num(byte(1)), num(byte(1)), num(uint16(1)))
	runTest("mul8_16($0,$1)", num(byte(10)), num(byte(1)), num(uint16(10)))
	runTest("mul8_16($0,$1)", num(byte(11)), num(byte(11)), num(uint16(121)))
	runTest("mul8_16($0,$1)", num(byte(255)), num(byte(255)), num(uint16(255*255)))

	runTest("mul16_32($0,$1)", num(uint16(1)), num(uint16(1)), num(uint32(1)))
	runTest("mul16_32($0,$1)", num(uint16(11)), num(uint16(11)), num(uint32(121)))
	runTest("mul16_32($0,$1)", num(uint16(255)), num(uint16(255)), num(uint32(255*255)))
	runTest("mul16_32($0,$1)", num(uint16(255*255)), num(uint16(255*255)), num(uint32(255*255*255*255)))
}

func init() {
	Extend("fun1par", "$0")
	Extend("fun2par", "concat($0,$1)")
}

func TestParseBin(t *testing.T) {

	t.Run("1", func(t *testing.T) {
		_, _, bin, err := CompileExpression("fun1par(0x00)")
		require.NoError(t, err)
		t.Logf("code: %s", Fmt(bin))
		res, err := EvalFromBinary(NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
	})
	t.Run("call 2 param", func(t *testing.T) {
		_, _, bin, err := CompileExpression("fun2par(0x01, 0x02)")
		require.NoError(t, err)
		t.Logf("code: %s", Fmt(bin))
		res, err := EvalFromBinary(NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
	})
	t.Run("fun 2 param", func(t *testing.T) {
		_, _, bin, err := CompileExpression("fun2par($0, $1)")
		require.NoError(t, err)
		t.Logf("code: %s", Fmt(bin))
		res, err := EvalFromBinary(NewGlobalDataTracePrint(nil), bin, []byte{1}, []byte{2})
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
	})
	t.Run("2", func(t *testing.T) {
		addrStr := fmt.Sprintf("fun1par(0x%s)", strings.Repeat("00", 32))
		_, _, bin, err := CompileExpression(addrStr)
		require.NoError(t, err)
		t.Logf("code: %s", Fmt(bin))
		res, err := EvalFromBinary(NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
	})
	t.Run("3", func(t *testing.T) {
		_, _, bin, err := CompileExpression("slice(0,0,0)")
		require.NoError(t, err)
		t.Logf("code: %s", Fmt(bin))
		res, err := EvalFromBinary(NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
	})
	t.Run("4", func(t *testing.T) {
		_, _, bin, err := CompileExpression("0")
		require.NoError(t, err)
		t.Logf("code: %s", Fmt(bin))
		res, err := EvalFromBinary(NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
	})
	t.Run("bin code cannot be nil", func(t *testing.T) {
		_, err := EvalFromBinary(NewGlobalDataTracePrint(nil), nil)
		require.Error(t, err)
	})
	t.Run("0-parameter bin code never starts from 0", func(t *testing.T) {
		bin := []byte{0}
		t.Logf("code: %s", Fmt(bin))
		_, err := EvalFromBinary(NewGlobalDataTracePrint(nil), bin)
		require.Error(t, err)

		bin = []byte{0, 0}
		t.Logf("code: %s", Fmt(bin))
		_, err = EvalFromBinary(NewGlobalDataTracePrint(nil), bin)
		require.Error(t, err)
	})
	t.Run("0-started code require 1 parameter", func(t *testing.T) {
		bin := []byte{0}
		t.Logf("code: %s", Fmt(bin))
		res, err := EvalFromBinary(NewGlobalDataTracePrint(nil), bin, []byte{10})
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
		require.EqualValues(t, []byte{10}, res)
	})
	t.Run("0-parameter bin code never starts from 1", func(t *testing.T) {
		bin := []byte{1}
		t.Logf("code: %s", Fmt(bin))
		_, err := EvalFromBinary(NewGlobalDataTracePrint(nil), bin)
		require.Error(t, err)

		bin = []byte{0, 0}
		t.Logf("code: %s", Fmt(bin))
		_, err = EvalFromBinary(NewGlobalDataTracePrint(nil), bin)
		require.Error(t, err)
	})
	t.Run("1-started code require 2 parameters", func(t *testing.T) {
		bin := []byte{1}
		t.Logf("code: %s", Fmt(bin))
		res, err := EvalFromBinary(NewGlobalDataTracePrint(nil), bin, []byte{10}, []byte{11})
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
		require.EqualValues(t, []byte{11}, res)
	})
	t.Run("nil code is 0x80", func(t *testing.T) {
		bin := []byte{0x80}
		t.Logf("code: %s", Fmt(bin))
		res, err := EvalFromBinary(NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		require.True(t, len(res) == 0)
		t.Logf("result: %s", Fmt(res))
	})
	t.Run("fun prefix1", func(t *testing.T) {
		prefix, err := FunctionCallPrefixByName("fun1par", 1)
		require.NoError(t, err)
		t.Logf("fun1par prefix: %s", Fmt(prefix))

		_, _, binCode, err := CompileExpression("fun1par(0xeeff)")
		require.NoError(t, err)
		t.Logf("fun1par(0xeeff) code: %s", Fmt(binCode))
		require.True(t, bytes.HasPrefix(binCode, prefix))

		prefix, err = FunctionCallPrefixByName("fun2par", 2)
		require.NoError(t, err)
		t.Logf("fun2par prefix: %s", Fmt(prefix))

		_, _, binCode, err = CompileExpression("fun2par(0xeeff, 0x1122)")
		require.NoError(t, err)
		t.Logf("fun2par(0xeeff, 0x1122) code: %s", Fmt(binCode))
		require.True(t, bytes.HasPrefix(binCode, prefix))
	})
}

func TestInlineCode(t *testing.T) {
	t.Run("1", func(t *testing.T) {
		_, _, bin1, err := CompileExpression("concat(0,1)")
		require.NoError(t, err)
		_, _, bin2, err := CompileExpression("concat(concat(0,1),2)")
		require.NoError(t, err)
		_, _, bin3, err := CompileExpression(fmt.Sprintf("concat(x/%s,2)", hex.EncodeToString(bin1)))
		require.NoError(t, err)
		require.EqualValues(t, bin2, bin3)

		t.Logf("code with inline: %s", Fmt(bin3))
		res, err := EvalFromBinary(NewGlobalDataTracePrint(nil), bin3)
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
		require.EqualValues(t, []byte{0, 1, 2}, res)
	})
	t.Run("2", func(t *testing.T) {
		_, _, bin1, err := CompileExpression("$0")
		require.NoError(t, err)
		_, _, bin2, err := CompileExpression("concat($0,2)")
		require.NoError(t, err)
		_, _, bin3, err := CompileExpression(fmt.Sprintf("concat(x/%s,2)", hex.EncodeToString(bin1)))
		require.NoError(t, err)
		require.EqualValues(t, bin2, bin3)

		t.Logf("code with inline: %s", Fmt(bin3))
		res, err := EvalFromBinary(NewGlobalDataTracePrint(nil), bin3, []byte{0, 1})
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
		require.EqualValues(t, []byte{0, 1, 2}, res)
	})
	t.Run("3", func(t *testing.T) {
		_, _, bin1, err := CompileExpression("fun1par(0)")
		require.NoError(t, err)
		_, _, bin2, err := CompileExpression("fun2par(fun1par(0),$0)")
		require.NoError(t, err)
		_, _, bin3, err := CompileExpression(fmt.Sprintf("fun2par(x/%s,$0)", hex.EncodeToString(bin1)))
		require.NoError(t, err)
		require.EqualValues(t, bin2, bin3)

		t.Logf("code with inline: %s", Fmt(bin3))
		res, err := EvalFromBinary(NewGlobalDataTracePrint(nil), bin3, []byte{2})
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
		require.EqualValues(t, []byte{0, 2}, res)
	})
}

func TestDecompile(t *testing.T) {
	t.Run("bin-expr 1", func(t *testing.T) {
		const formula = "concat(0,1)"
		_, _, bin, err := CompileExpression(formula)
		require.NoError(t, err)
		f, err := ExpressionFromBinary(bin)
		require.NoError(t, err)
		binBack := ExpressionToBinary(f)
		require.EqualValues(t, bin, binBack)
		formulaBack, err := DecompileBinary(bin)
		require.NoError(t, err)
		t.Logf("orig: '%s'", formula)
		t.Logf("decompiled: '%s'", formulaBack)

		_, _, binBack1, err := CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack1)

		sym, _, args, err := ParseBinaryOneLevel(bin)
		require.NoError(t, err)

		formulaBack2 := ComposeOneLevel(sym, args)
		t.Logf("decompiled by level 1: '%s'", formulaBack2)

		_, _, binBack2, err := CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack2)
	})
	t.Run("bin-expr 2", func(t *testing.T) {
		const formula = "slice(concat($0,1),1,1)"
		_, _, bin, err := CompileExpression(formula)
		require.NoError(t, err)
		f, err := ExpressionFromBinary(bin)
		require.NoError(t, err)
		binBack := ExpressionToBinary(f)
		require.EqualValues(t, bin, binBack)
		formulaBack, err := DecompileBinary(bin)
		require.NoError(t, err)
		t.Logf("orig: '%s'", formula)
		t.Logf("decompiled: '%s'", formulaBack)
		_, _, binBack1, err := CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack1)

		sym, _, args, err := ParseBinaryOneLevel(bin)
		require.NoError(t, err)

		formulaBack2 := ComposeOneLevel(sym, args)
		t.Logf("decompiled by level 1: '%s'", formulaBack2)

		_, _, binBack2, err := CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack2)
	})
	t.Run("bin-expr 3", func(t *testing.T) {
		const formula = "fun2par(fun1par(0x0102),concat($0,$1))"
		_, _, bin, err := CompileExpression(formula)
		require.NoError(t, err)
		f, err := ExpressionFromBinary(bin)
		require.NoError(t, err)
		binBack := ExpressionToBinary(f)
		require.EqualValues(t, bin, binBack)
		formulaBack, err := DecompileBinary(bin)
		require.NoError(t, err)
		t.Logf("orig: '%s'", formula)
		t.Logf("decompiled: '%s'", formulaBack)
		_, _, binBack1, err := CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack1)

		sym, _, args, err := ParseBinaryOneLevel(bin)
		require.NoError(t, err)

		formulaBack2 := ComposeOneLevel(sym, args)
		t.Logf("decompiled by level 1: '%s'", formulaBack2)

		_, _, binBack2, err := CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack2)
	})
	t.Run("bin-expr 4", func(t *testing.T) {
		const formula = "concat(u64/1337)"
		_, _, bin, err := CompileExpression(formula)
		require.NoError(t, err)
		f, err := ExpressionFromBinary(bin)
		require.NoError(t, err)
		binBack := ExpressionToBinary(f)
		require.EqualValues(t, bin, binBack)
		formulaBack, err := DecompileBinary(bin)
		require.NoError(t, err)
		t.Logf("orig: '%s'", formula)
		t.Logf("decompiled: '%s'", formulaBack)

		_, _, binBack1, err := CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack1)

		sym, _, args, err := ParseBinaryOneLevel(bin, 1)
		require.NoError(t, err)
		require.EqualValues(t, 1337, binary.BigEndian.Uint64(StripDataPrefix(args[0])))

		formulaBack2 := ComposeOneLevel(sym, args)
		t.Logf("decompiled by level 1: '%s'", formulaBack2)

		_, _, binBack2, err := CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack2)
	})
	t.Run("bin-expr 5", func(t *testing.T) {
		const formula = "concat(u64/1337, 123, concat(1,2,3), tail(0x00010203, 1))"
		_, _, bin, err := CompileExpression(formula)
		require.NoError(t, err)
		f, err := ExpressionFromBinary(bin)
		require.NoError(t, err)
		binBack := ExpressionToBinary(f)
		require.EqualValues(t, bin, binBack)
		formulaBack, err := DecompileBinary(bin)
		require.NoError(t, err)
		t.Logf("orig: '%s'", formula)
		t.Logf("decompiled: '%s'", formulaBack)

		_, _, binBack1, err := CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack1)

		sym, prefix, args, err := ParseBinaryOneLevel(bin, 4)
		require.NoError(t, err)
		require.EqualValues(t, 1337, binary.BigEndian.Uint64(StripDataPrefix(args[0])))

		formulaBack2 := ComposeOneLevel(sym, args)
		t.Logf("decompiled by level 1: '%s'", formulaBack2)

		_, _, binBack2, err := CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack2)

		pieces := make([]interface{}, len(args)+1)
		pieces[0] = prefix
		for i := range args {
			pieces[i+1] = args[i]
		}
		// concatenation of decomposed binary is equal to the original
		require.EqualValues(t, bin, Concat(pieces...))
	})
}
