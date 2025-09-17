package easyfl

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/lunfardo314/easyfl/easyfl_util"
	"github.com/lunfardo314/easyfl/slicepool"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
)

func init() {
	slicepool.Disable()
}

const formula1 = "func unlockBlock: concat(concat(0x0000, slice(0x01020304050607, 2, 5)))"

func TestAux(t *testing.T) {
	t.Logf("MaxInt: %d", math.MaxInt)
	t.Logf("MaxInt64: %d", math.MaxInt64)
}

func TestInit(t *testing.T) {
	lib := NewBaseLibrary[any]()
	lib.PrintLibraryStats()
}

func TestLiterals(t *testing.T) {
	lib := NewBaseLibrary[any]()

	lib.MustEqual("0", "0x00")
	lib.MustEqual("255", "0xff")
	lib.MustError("500", "integer constant value must be uint8")

	lib.MustEqual("u16/0", "0x0000")
	lib.MustEqual("u16/1024", "0x0400")
	lib.MustError("u16/100000", "wrong u16 constant")

	lib.MustEqual("u32/0", "0x00000000")
	lib.MustEqual("u32/100000", "0x000186a0")
	lib.MustError("u32/5000000000", "wrong u32 constant")

	lib.MustEqual("u64/0", "0x0000000000000000")
	lib.MustEqual("u64/100000000000", "0x000000174876e800")
	lib.MustError("u64/999999999999999999999999999", "value out of range")

	lib.MustEqual("z8/0", "0x")
	lib.MustEqual("z8/0", "false")
	lib.MustEqual("z8/255", "255")
	lib.MustError("z8/300", "wrong z1 constant")

	lib.MustEqual("z16/0", "0x")
	lib.MustEqual("z16/0", "false")
	lib.MustEqual("z16/1024", "0x0400")
	lib.MustEqual("z16/255", "255")
	lib.MustError("z16/100000", "wrong z16 constant")

	lib.MustEqual("z32/0", "0x")
	lib.MustEqual("z32/255", "0xff")
	lib.MustEqual("z32/100000", "0x0186a0")
	lib.MustError("z32/5000000000", "wrong z32 constant")

	lib.MustEqual("z64/0", "0x")
	lib.MustEqual("z64/1024", "0x0400")
	lib.MustEqual("z64/1024", "u16/1024")
	lib.MustEqual("z64/100000000000", "0x174876e800")
	lib.MustError("u64/999999999999999999999999999", "value out of range")
}

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

		code, numParams, err := NewBaseLibrary[any]().ExpressionSourceToBytecode(ret[0].SourceCode)
		require.NoError(t, err)
		require.EqualValues(t, 0, numParams)
		t.Logf("code len: %d", len(code))
	})
	t.Run("4", func(t *testing.T) {
		parsed, err := parseFunctions(formula1)
		require.NoError(t, err)
		require.EqualValues(t, 1, len(parsed))

		lib := NewBaseLibrary[any]()
		code, numParams, err := lib.ExpressionSourceToBytecode(parsed[0].SourceCode)
		require.NoError(t, err)
		require.EqualValues(t, 0, numParams)
		t.Logf("code len: %d", len(code))

		f, err := lib.ExpressionFromBytecode(code)
		require.NoError(t, err)
		require.NotNil(t, f)
	})
	t.Run("fun call literal 1", func(t *testing.T) {
		lib := NewBaseLibrary[any]()
		prefix, err := lib.EvalFromSource(nil, "#concat")
		require.NoError(t, err)
		_, _, code, err := lib.CompileExpression("concat")
		require.NoError(t, err)
		prefix1, err := lib.ParsePrefixBytecode(code)
		require.NoError(t, err)
		require.True(t, bytes.Equal(prefix, prefix1))
	})
	t.Run("fun call literal 2", func(t *testing.T) {
		lib := NewBaseLibrary[any]()
		prefix, err := lib.EvalFromSource(nil, "#tail")
		require.NoError(t, err)
		_, _, code, err := lib.CompileExpression("tail(0x010203, 2)")
		require.NoError(t, err)
		prefix1, err := lib.ParsePrefixBytecode(code)
		require.NoError(t, err)
		require.True(t, bytes.Equal(prefix, prefix1))
	})
	t.Run("fail call binary", func(t *testing.T) {
		lib := NewBaseLibrary[any]()
		_, _, code, err := lib.CompileExpression("!!!ciao!")
		require.NoError(t, err)
		t.Logf("!!!ciao! code = %s", easyfl_util.Fmt(code))
		_, err = lib.EvalFromBytecode(nil, code)
		easyfl_util.RequireErrorWith(t, err, "SCRIPT FAIL: 'ciao!'")

		src := fmt.Sprintf("x/%s", hex.EncodeToString(code))
		_, err = lib.EvalFromSource(nil, src)
		easyfl_util.RequireErrorWith(t, err, "SCRIPT FAIL: 'ciao!'")
	})
}

func TestEval(t *testing.T) {
	lib := NewBaseLibrary[any]()
	t.Run("1", func(t *testing.T) {
		ret, err := lib.EvalFromSource(nil, "125")
		require.NoError(t, err)
		require.EqualValues(t, []byte{125}, ret)
	})
	t.Run("2", func(t *testing.T) {
		ret, err := lib.EvalFromSource(nil, "add(125, 6)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{0, 0, 0, 0, 0, 0, 0, 131}, ret)
	})
	t.Run("3", func(t *testing.T) {
		ret, err := lib.EvalFromSource(nil, "$0", []byte{222})
		require.NoError(t, err)
		require.EqualValues(t, []byte{222}, ret)
	})
	t.Run("4", func(t *testing.T) {
		ret, err := lib.EvalFromSource(nil, "concat($0,$1)", []byte{222}, []byte{111})
		require.NoError(t, err)
		require.EqualValues(t, []byte{222, 111}, ret)
	})
	t.Run("5", func(t *testing.T) {
		ret, err := lib.EvalFromSource(nil, "concat($0,concat($1,$0))", []byte{222}, []byte{111})
		require.NoError(t, err)
		require.EqualValues(t, []byte{222, 111, 222}, ret)
	})
	t.Run("6", func(t *testing.T) {
		ret, err := lib.EvalFromSource(nil,
			"concat(concat(slice($2,1,1), byte($2,0)), slice(concat(concat($0,$1),concat($1,$0)),1,2))",
			[]byte{222}, []byte{111}, []byte{123, 234})
		require.NoError(t, err)
		require.EqualValues(t, []byte{234, 123, 111, 111}, ret)
	})
	t.Run("7", func(t *testing.T) {
		ret, err := lib.EvalFromSource(nil, "len($1)", nil, []byte("123456789"))
		require.NoError(t, err)
		require.EqualValues(t, []byte{0, 0, 0, 0, 0, 0, 0, 9}, ret)
	})
	t.Run("8", func(t *testing.T) {
		ret, err := lib.EvalFromSource(nil, "concat(1,2,3,4,5)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{1, 2, 3, 4, 5}, ret)
	})
	t.Run("9", func(t *testing.T) {
		ret, err := lib.EvalFromSource(nil, "slice(concat(concat(1,2),concat(3,4,5)),2,3)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{3, 4}, ret)
	})
	t.Run("10", func(t *testing.T) {
		tr := lib.NewGlobalDataTracePrint(nil)
		ret, err := lib.EvalFromSource(tr, "if(equal(len($0),u64/3), 0x01, 0x05)", []byte("abc"))
		require.NoError(t, err)
		require.EqualValues(t, []byte{1}, ret)
	})
	t.Run("11", func(t *testing.T) {
		ret, err := lib.EvalFromSource(nil, "if(equal(len($0),u64/3), 0x01, 0x05)", []byte("abcdef"))
		require.NoError(t, err)
		require.EqualValues(t, []byte{5}, ret)
	})
	const longer = `
			if(
				not(equal(len($0),u64/5)),   // comment 1
				0x01,
				// comment without code
				0x0506     // comment2
			)`
	t.Run("12", func(t *testing.T) {
		ret, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), longer, []byte("abcdef"))
		require.NoError(t, err)
		require.EqualValues(t, []byte{1}, ret)
	})
	t.Run("14", func(t *testing.T) {
		ret, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), longer, []byte("abcde"))
		require.NoError(t, err)
		require.EqualValues(t, []byte{5, 6}, ret)
	})
	t.Run("15", func(t *testing.T) {
		ret, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "nil")
		require.NoError(t, err)
		require.True(t, len(ret) == 0)
	})
	t.Run("16", func(t *testing.T) {
		ret, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "concat")
		require.NoError(t, err)
		require.True(t, len(ret) == 0)
	})
	t.Run("17", func(t *testing.T) {
		ret, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "u16/256")
		require.NoError(t, err)
		require.EqualValues(t, []byte{1, 0}, ret)
	})
	t.Run("18", func(t *testing.T) {
		ret, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "u32/70000")
		require.NoError(t, err)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], 70000)
		require.EqualValues(t, b[:], ret)
	})
	t.Run("19", func(t *testing.T) {
		ret, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "u64/10000000000")
		require.NoError(t, err)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], 10000000000)
		require.EqualValues(t, b[:], ret)
	})
	t.Run("20", func(t *testing.T) {
		ret, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "isZero(0x000000)")
		require.NoError(t, err)
		require.True(t, len(ret) != 0)
	})
	t.Run("21", func(t *testing.T) {
		ret, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "isZero(0x003000)")
		require.NoError(t, err)
		require.True(t, len(ret) == 0)
	})
	t.Run("21", func(t *testing.T) {
		ret, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "add($0, $1)", []byte{160}, []byte{160})
		require.NoError(t, err)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], 320)
		require.EqualValues(t, b[:], ret)
	})
	var blake2bInvokedNum int
	lib.embedLong("blake2b-test", 1, func(par *CallParams[any]) []byte {
		a0 := par.Arg(0)
		h := blake2b.Sum256(a0)
		blake2bInvokedNum++
		par.Trace("blake2b-test:: %v -> %v", a0, h[:])
		return h[:]
	})
	t.Run("23", func(t *testing.T) {
		blake2bInvokedNum = 0
		ret, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "blake2b-test($0)", []byte{1, 2, 3})
		require.NoError(t, err)
		h := blake2b.Sum256([]byte{0x01, 0x02, 0x03})
		require.EqualValues(t, h[:], ret)
		require.EqualValues(t, blake2bInvokedNum, 1)

		ret, err = lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "blake2b-test($0)", nil)
		require.NoError(t, err)
		h = blake2b.Sum256(nil)
		require.EqualValues(t, h[:], ret)
		require.EqualValues(t, blake2bInvokedNum, 2)
	})
	t.Run("24", func(t *testing.T) {
		blake2bInvokedNum = 0
		h2 := blake2b.Sum256([]byte{2})
		h3 := blake2b.Sum256([]byte{3})

		ret, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "if($0,blake2b-test($1),blake2b-test($2))",
			[]byte{1}, []byte{2}, []byte{3})
		require.NoError(t, err)
		require.EqualValues(t, h2[:], ret)
		require.EqualValues(t, blake2bInvokedNum, 1)

		ret, err = lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "if($0,blake2b-test($1),blake2b-test($2))",
			nil, []byte{2}, []byte{3})
		require.NoError(t, err)
		require.EqualValues(t, h3[:], ret)
		require.EqualValues(t, blake2bInvokedNum, 2)
	})
}

func TestExtendLib(t *testing.T) {
	lib := NewBaseLibrary[any]()
	t.Run("ext-2", func(t *testing.T) {
		_, err := lib.ExtendErr("nil1", "concat()")
		require.NoError(t, err)
	})
	t.Run("ext-3", func(t *testing.T) {
		_, err := lib.ExtendErr("cat2", "concat($0, $1)")
		require.NoError(t, err)
		ret, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "cat2(1,2)")
		require.EqualValues(t, []byte{1, 2}, ret)
	})
	const complicated = `
		concat(
			concat($0,$1),
			concat($0,$2)
		)
	`
	_, err := lib.ExtendErr("complicated", complicated)
	require.NoError(t, err)

	d := func(i byte) []byte { return []byte{i} }
	compl := func(d0, d1, d2 []byte) []byte {
		c0 := easyfl_util.Concat(d0, d1)
		c1 := easyfl_util.Concat(d0, d2)
		c3 := easyfl_util.Concat(c0, c1)
		return c3
	}
	t.Run("ext-4", func(t *testing.T) {
		ret, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "complicated(0,1,2)")
		require.NoError(t, err)
		require.EqualValues(t, compl(d(0), d(1), d(2)), ret)
	})
	t.Run("ext-5", func(t *testing.T) {
		ret, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "complicated(0,1,complicated(2,1,0))")
		require.NoError(t, err)
		exp := compl(d(0), d(1), compl(d(2), d(1), d(0)))
		require.EqualValues(t, exp, ret)
	})
	t.Run("eval from bytecode", func(t *testing.T) {
		source := "concat($2, $1, $0)"
		_, arity, code, err := lib.CompileExpression(source)
		require.NoError(t, err)
		require.EqualValues(t, 3, arity)
		t.Logf("compiled bytecode of '%s' is %d-bytes long", source, len(code))
		ret, err := lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), code, []byte{1}, []byte{2}, []byte{3})
		require.NoError(t, err)
		require.EqualValues(t, []byte{3, 2, 1}, ret)
	})
	t.Run("always panics", func(t *testing.T) {
		_, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "byte(0,1)")
		require.Error(t, err)
	})
	t.Run("never panics", func(t *testing.T) {
		_, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "if(concat,byte(0,1),0x01)")
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
	lib := NewBaseLibrary[any]()
	runTest := func(s string, a0, a1 []byte) bool {
		t.Logf("---- runTest: '%s'\n", s)
		ret, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), s, a0, a1)
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
	lib := NewBaseLibrary[any]()
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	pubKey, privKey, err := ed25519.GenerateKey(rnd)
	require.NoError(t, err)

	const msg = "message to be signed"

	t.Run("validSignatureED25519-ok", func(t *testing.T) {
		signature := ed25519.Sign(privKey, []byte(msg))
		res, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "validSignatureED25519($0,$1,$2)", []byte(msg), signature, pubKey)
		require.NoError(t, err)

		require.True(t, len(res) > 0)
	})
	t.Run("validSignatureED25519-wrong-msg", func(t *testing.T) {
		signature := ed25519.Sign(privKey, []byte(msg))
		res, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "validSignatureED25519($0,$1,$2)", []byte(msg+"klmn"), signature, pubKey)
		require.NoError(t, err)

		require.True(t, len(res) == 0)
	})
	t.Run("validSignatureED25519-wrong-sig", func(t *testing.T) {
		signature := ed25519.Sign(privKey, []byte(msg))
		signature[5]++
		res, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "validSignatureED25519($0,$1,$2)", []byte(msg), signature, pubKey)
		require.NoError(t, err)

		require.True(t, len(res) == 0)
	})
	t.Run("validSignatureED25519-wrong-pubkey", func(t *testing.T) {
		signature := ed25519.Sign(privKey, []byte(msg))
		pk := easyfl_util.Concat([]byte(pubKey))
		pk[3]++
		res, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "validSignatureED25519($0,$1,$2)", []byte(msg), signature, pk)
		require.NoError(t, err)

		require.True(t, len(res) == 0)
	})
	t.Run("validSignatureED25519-wrong-pubkey", func(t *testing.T) {
		_, err := lib.EvalFromSource(lib.NewGlobalDataTracePrint(nil), "validSignatureED25519($0,$1,$2)", nil, nil, nil)
		easyfl_util.RequireErrorWith(t, err, "bad public key length")
	})
}

func TestTracing(t *testing.T) {
	lib := NewBaseLibrary[any]()
	t.Run("no panic 0", func(t *testing.T) {
		tr := lib.NewGlobalDataLog(nil)
		ret, err := lib.EvalFromSource(tr, "slice(concat(concat(1,2),concat(3,4,5)),2,3)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{3, 4}, ret)
		tr.PrintLog()
	})
	t.Run("with panic 1", func(t *testing.T) {
		tr := lib.NewGlobalDataLog(nil)
		_, err := lib.EvalFromSource(tr, "slice(0x0102,2,3)")
		require.Error(t, err)
		tr.PrintLog()
	})
	t.Run("no panic 2", func(t *testing.T) {
		tr := lib.NewGlobalDataLog(nil)
		_, err := lib.EvalFromSource(tr, "slice(tail(0x0102030405,2),1,2)")
		require.NoError(t, err)
		tr.PrintLog()
	})
	t.Run("with panic 3", func(t *testing.T) {
		tr := lib.NewGlobalDataLog(nil)
		_, err := lib.EvalFromSource(tr, "slice(tail(0x0102030405,2),1,5)")
		require.Error(t, err)
		tr.PrintLog()
	})
	t.Run("no panic 4", func(t *testing.T) {
		tr := lib.NewGlobalDataLog(nil)
		_, err := lib.EvalFromSource(tr, "equal(slice(tail(0x0102030405,2),1,2), slice(tail(0x0102030405,2),2,2))")
		require.NoError(t, err)
		tr.PrintLog()
	})
	t.Run("no panic 5", func(t *testing.T) {
		tr := lib.NewGlobalDataLog(nil)
		_, err := lib.EvalFromSource(tr, "equal(len(slice(tail(0x0102030405,2),1,2)), u64/2)")
		require.NoError(t, err)
		tr.PrintLog()
	})
	t.Run("no panic 6", func(t *testing.T) {
		tr := lib.NewGlobalDataLog(nil)
		_, err := lib.EvalFromSource(tr, "equal(len(slice(tail(0x0102030405,2),1,2)), u64/2)")
		require.NoError(t, err)
		tr.PrintLog()
	})
	t.Run("no trace", func(t *testing.T) {
		tr := lib.NewGlobalDataNoTrace(nil)
		_, err := lib.EvalFromSource(tr, "equal(len(slice(tail(0x0102030405,2),1,2)), u64/2)")
		require.NoError(t, err)
	})
	t.Run("trace print", func(t *testing.T) {
		tr := lib.NewGlobalDataTracePrint(nil)
		_, err := lib.EvalFromSource(tr, "equal(len(slice(tail(0x0102030405,2),1,2)), u64/2)")
		require.NoError(t, err)
	})
	t.Run("trace if", func(t *testing.T) {
		tr := lib.NewGlobalDataLog(nil)
		_, err := lib.EvalFromSource(tr, "if(nil,0x1234,0x5678)")
		require.NoError(t, err)
		tr.PrintLog()
	})
	t.Run("trace not", func(t *testing.T) {
		tr := lib.NewGlobalDataTracePrint(nil)
		_, err := lib.EvalFromSource(tr, "not(not(not($0)))", []byte{10})
		require.NoError(t, err)
	})
	t.Run("trace concat", func(t *testing.T) {
		tr := lib.NewGlobalDataTracePrint(nil)
		_, err := lib.EvalFromSource(tr, "concat($0,concat($0,$0))", []byte{10})
		require.NoError(t, err)
		tr = lib.NewGlobalDataTracePrint(nil)
		_, err = lib.EvalFromSource(tr, "concat(concat())")
		require.NoError(t, err)
	})
	t.Run("trace caching", func(t *testing.T) {
		lib.extend("c6", "concat($0, $0, $0, $0, $0, $0)")
		var counter int
		lib.embedShort("prn", 0, func(_ *CallParams[any]) []byte {
			counter++
			fmt.Printf("counter incremented\n")
			return []byte{1}
		})
		tr := lib.NewGlobalDataTracePrint(nil)
		res, err := lib.EvalFromSource(tr, "c6(c6(prn))")
		require.NoError(t, err)
		require.EqualValues(t, bytes.Repeat([]byte{1}, 36), res)
		require.EqualValues(t, 1, counter)
	})
}

func TestParseBin(t *testing.T) {
	lib := NewBaseLibrary[any]()
	lib.extend("fun1par", "$0")
	lib.extend("fun2par", "concat($0,$1)")

	t.Run("1", func(t *testing.T) {
		_, _, bin, err := lib.CompileExpression("fun1par(0x00)")
		require.NoError(t, err)
		t.Logf("code: %s", easyfl_util.Fmt(bin))
		res, err := lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		t.Logf("result: %s", easyfl_util.Fmt(res))
	})
	t.Run("call 2 param", func(t *testing.T) {
		_, _, bin, err := lib.CompileExpression("fun2par(0x01, 0x02)")
		require.NoError(t, err)
		t.Logf("code: %s", easyfl_util.Fmt(bin))
		res, err := lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		t.Logf("result: %s", easyfl_util.Fmt(res))
	})
	t.Run("fun 2 param", func(t *testing.T) {
		_, _, bin, err := lib.CompileExpression("fun2par($0, $1)")
		require.NoError(t, err)
		t.Logf("code: %s", easyfl_util.Fmt(bin))
		res, err := lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), bin, []byte{1}, []byte{2})
		require.NoError(t, err)
		t.Logf("result: %s", easyfl_util.Fmt(res))
	})
	t.Run("2", func(t *testing.T) {
		addrStr := fmt.Sprintf("fun1par(0x%s)", strings.Repeat("00", 32))
		_, _, bin, err := lib.CompileExpression(addrStr)
		require.NoError(t, err)
		t.Logf("code: %s", easyfl_util.Fmt(bin))
		res, err := lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		t.Logf("result: %s", easyfl_util.Fmt(res))
	})
	t.Run("3", func(t *testing.T) {
		_, _, bin, err := lib.CompileExpression("slice(0,0,0)")
		require.NoError(t, err)
		t.Logf("code: %s", easyfl_util.Fmt(bin))
		res, err := lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		t.Logf("result: %s", easyfl_util.Fmt(res))
	})
	t.Run("4", func(t *testing.T) {
		_, _, bin, err := lib.CompileExpression("0")
		require.NoError(t, err)
		t.Logf("code: %s", easyfl_util.Fmt(bin))
		res, err := lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		t.Logf("result: %s", easyfl_util.Fmt(res))
	})
	t.Run("bin code cannot be nil", func(t *testing.T) {
		_, err := lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), nil)
		require.Error(t, err)
	})
	t.Run("0-parameter bin code never starts from 0", func(t *testing.T) {
		bin := []byte{0}
		t.Logf("code: %s", easyfl_util.Fmt(bin))
		_, err := lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), bin)
		require.Error(t, err)

		bin = []byte{0, 0}
		t.Logf("code: %s", easyfl_util.Fmt(bin))
		_, err = lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), bin)
		require.Error(t, err)
	})
	t.Run("0-started code require 1 parameter", func(t *testing.T) {
		bin := []byte{0}
		t.Logf("code: %s", easyfl_util.Fmt(bin))
		res, err := lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), bin, []byte{10})
		require.NoError(t, err)
		t.Logf("result: %s", easyfl_util.Fmt(res))
		require.EqualValues(t, []byte{10}, res)
	})
	t.Run("0-parameter bin code never starts from 1", func(t *testing.T) {
		bin := []byte{1}
		t.Logf("code: %s", easyfl_util.Fmt(bin))
		_, err := lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), bin)
		require.Error(t, err)

		bin = []byte{0, 0}
		t.Logf("code: %s", easyfl_util.Fmt(bin))
		_, err = lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), bin)
		require.Error(t, err)
	})
	t.Run("1-started code require 2 parameters", func(t *testing.T) {
		bin := []byte{1}
		t.Logf("code: %s", easyfl_util.Fmt(bin))
		res, err := lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), bin, []byte{10}, []byte{11})
		require.NoError(t, err)
		t.Logf("result: %s", easyfl_util.Fmt(res))
		require.EqualValues(t, []byte{11}, res)
	})
	t.Run("nil code is 0x80", func(t *testing.T) {
		bin := []byte{0x80}
		t.Logf("code: %s", easyfl_util.Fmt(bin))
		res, err := lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		require.True(t, len(res) == 0)
		t.Logf("result: %s", easyfl_util.Fmt(res))
	})
	t.Run("fun prefix1", func(t *testing.T) {
		prefix, err := lib.FunctionCallPrefixByName("fun1par", 1)
		require.NoError(t, err)
		t.Logf("fun1par prefix: %s", easyfl_util.Fmt(prefix))

		_, _, binCode, err := lib.CompileExpression("fun1par(0xeeff)")
		require.NoError(t, err)
		t.Logf("fun1par(0xeeff) code: %s", easyfl_util.Fmt(binCode))
		require.True(t, bytes.HasPrefix(binCode, prefix))

		prefix, err = lib.FunctionCallPrefixByName("fun2par", 2)
		require.NoError(t, err)
		t.Logf("fun2par prefix: %s", easyfl_util.Fmt(prefix))

		_, _, binCode, err = lib.CompileExpression("fun2par(0xeeff, 0x1122)")
		require.NoError(t, err)
		t.Logf("fun2par(0xeeff, 0x1122) code: %s", easyfl_util.Fmt(binCode))
		require.True(t, bytes.HasPrefix(binCode, prefix))
	})
}

func TestInlineCode(t *testing.T) {
	lib := NewBaseLibrary[any]()
	lib.extend("fun1par", "$0")
	lib.extend("fun2par", "concat($0,$1)")
	t.Run("1", func(t *testing.T) {
		_, _, bin1, err := lib.CompileExpression("concat(0,1)")
		require.NoError(t, err)
		_, _, bin2, err := lib.CompileExpression("concat(concat(0,1),2)")
		require.NoError(t, err)
		_, _, bin3, err := lib.CompileExpression(fmt.Sprintf("concat(x/%s,2)", hex.EncodeToString(bin1)))
		require.NoError(t, err)
		require.EqualValues(t, bin2, bin3)

		t.Logf("code with inline: %s", easyfl_util.Fmt(bin3))
		res, err := lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), bin3)
		require.NoError(t, err)
		t.Logf("result: %s", easyfl_util.Fmt(res))
		require.EqualValues(t, []byte{0, 1, 2}, res)
	})
	t.Run("2", func(t *testing.T) {
		_, _, bin1, err := lib.CompileExpression("$0")
		require.NoError(t, err)
		_, _, bin2, err := lib.CompileExpression("concat($0,2)")
		require.NoError(t, err)
		_, _, bin3, err := lib.CompileExpression(fmt.Sprintf("concat(x/%s,2)", hex.EncodeToString(bin1)))
		require.NoError(t, err)
		require.EqualValues(t, bin2, bin3)

		t.Logf("code with inline: %s", easyfl_util.Fmt(bin3))
		res, err := lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), bin3, []byte{0, 1})
		require.NoError(t, err)
		t.Logf("result: %s", easyfl_util.Fmt(res))
		require.EqualValues(t, []byte{0, 1, 2}, res)
	})
	t.Run("3", func(t *testing.T) {
		_, _, bin1, err := lib.CompileExpression("fun1par(0)")
		require.NoError(t, err)
		_, _, bin2, err := lib.CompileExpression("fun2par(fun1par(0),$0)")
		require.NoError(t, err)
		_, _, bin3, err := lib.CompileExpression(fmt.Sprintf("fun2par(x/%s,$0)", hex.EncodeToString(bin1)))
		require.NoError(t, err)
		require.EqualValues(t, bin2, bin3)

		t.Logf("code with inline: %s", easyfl_util.Fmt(bin3))
		res, err := lib.EvalFromBytecode(lib.NewGlobalDataTracePrint(nil), bin3, []byte{2})
		require.NoError(t, err)
		t.Logf("result: %s", easyfl_util.Fmt(res))
		require.EqualValues(t, []byte{0, 2}, res)
	})
	t.Run("too long inline", func(t *testing.T) {
		data := strings.Repeat("f", MaxSourceSize-1)
		src := fmt.Sprintf("0x%s", data)
		_, _, _, err := lib.CompileExpression(src)
		easyfl_util.RequireErrorWith(t, err, "source is too long")
	})
	t.Run("long inline", func(t *testing.T) {
		data := strings.Repeat("f", MaxSourceSize-2)
		src := fmt.Sprintf("0x%s", data)
		_, _, _, err := lib.CompileExpression(src)
		require.NoError(t, err)
	})
	t.Run("inline 126-127", func(t *testing.T) {
		data126 := strings.Repeat("f", 126*2)
		src126 := fmt.Sprintf("0x%s", data126)
		_, _, code126, err := lib.CompileExpression(src126)
		require.NoError(t, err)
		require.EqualValues(t, 126+1, len(code126))

		data127 := strings.Repeat("f", 127*2)
		src127 := fmt.Sprintf("0x%s", data127)
		_, _, code127, err := lib.CompileExpression(src127)
		require.NoError(t, err)
		require.EqualValues(t, 127+3, len(code127))

	})
	t.Run("concat long inline", func(t *testing.T) {
		data1 := strings.Repeat("1", 10*1024)
		data2 := strings.Repeat("2", 5*1024)
		data3 := strings.Repeat("3", 7*1024)
		src := fmt.Sprintf("concat(0x%s,0x%s,0x%s)", data1, data2, data3)
		//t.Logf("source: %s", src)
		res, err := lib.EvalFromSource(nil, src)
		require.NoError(t, err)
		require.EqualValues(t, (10+5+7)*1024/2, len(res))
	})
	t.Run("or long inline", func(t *testing.T) {
		data1 := strings.Repeat("1", 10*1024)
		data2 := strings.Repeat("2", 5*1024)
		data3 := strings.Repeat("3", 7*1024)
		src := fmt.Sprintf("or(0x%s,0x%s,0x%s)", data1, data2, data3)
		//t.Logf("source: %s", src)
		lib.MustTrue(src)
	})

}

func TestDecompile(t *testing.T) {
	lib := NewBaseLibrary[any]()
	lib.extend("fun1par", "$0")
	lib.extend("fun2par", "concat($0,$1)")
	t.Run("bin-expr 1", func(t *testing.T) {
		const formula = "concat(0,1)"
		_, _, bin, err := lib.CompileExpression(formula)
		require.NoError(t, err)
		f, err := lib.ExpressionFromBytecode(bin)
		require.NoError(t, err)
		binBack := ExpressionToBytecode(f)
		require.EqualValues(t, bin, binBack)
		formulaBack, err := lib.DecompileBytecode(bin)
		require.NoError(t, err)
		t.Logf("orig: '%s'", formula)
		t.Logf("decompiled: '%s'", formulaBack)

		_, _, binBack1, err := lib.CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack1)

		sym, _, args, err := lib.ParseBytecodeOneLevel(bin)
		require.NoError(t, err)

		formulaBack2 := ComposeBytecodeOneLevel(sym, args)
		t.Logf("decompiled by level 1: '%s'", formulaBack2)

		_, _, binBack2, err := lib.CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack2)
	})
	t.Run("bin-expr 2", func(t *testing.T) {
		const formula = "slice(concat($0,1),1,1)"
		_, _, bin, err := lib.CompileExpression(formula)
		require.NoError(t, err)
		f, err := lib.ExpressionFromBytecode(bin)
		require.NoError(t, err)
		binBack := ExpressionToBytecode(f)
		require.EqualValues(t, bin, binBack)
		formulaBack, err := lib.DecompileBytecode(bin)
		require.NoError(t, err)
		t.Logf("orig: '%s'", formula)
		t.Logf("decompiled: '%s'", formulaBack)
		_, _, binBack1, err := lib.CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack1)

		sym, _, args, err := lib.ParseBytecodeOneLevel(bin)
		require.NoError(t, err)

		formulaBack2 := ComposeBytecodeOneLevel(sym, args)
		t.Logf("decompiled by level 1: '%s'", formulaBack2)

		_, _, binBack2, err := lib.CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack2)
	})
	t.Run("bin-expr 3", func(t *testing.T) {
		const formula = "fun2par(fun1par(0x0102),concat($0,$1))"
		_, _, bin, err := lib.CompileExpression(formula)
		require.NoError(t, err)
		f, err := lib.ExpressionFromBytecode(bin)
		require.NoError(t, err)
		binBack := ExpressionToBytecode(f)
		require.EqualValues(t, bin, binBack)
		formulaBack, err := lib.DecompileBytecode(bin)
		require.NoError(t, err)
		t.Logf("orig: '%s'", formula)
		t.Logf("decompiled: '%s'", formulaBack)
		_, _, binBack1, err := lib.CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack1)

		sym, _, args, err := lib.ParseBytecodeOneLevel(bin)
		require.NoError(t, err)

		formulaBack2 := ComposeBytecodeOneLevel(sym, args)
		t.Logf("decompiled by level 1: '%s'", formulaBack2)

		_, _, binBack2, err := lib.CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack2)
	})
	t.Run("bin-expr 4", func(t *testing.T) {
		const formula = "concat(u64/1337)"
		_, _, bin, err := lib.CompileExpression(formula)
		require.NoError(t, err)
		f, err := lib.ExpressionFromBytecode(bin)
		require.NoError(t, err)
		binBack := ExpressionToBytecode(f)
		require.EqualValues(t, bin, binBack)
		formulaBack, err := lib.DecompileBytecode(bin)
		require.NoError(t, err)
		t.Logf("orig: '%s'", formula)
		t.Logf("decompiled: '%s'", formulaBack)

		_, _, binBack1, err := lib.CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack1)

		sym, _, args, err := lib.ParseBytecodeOneLevel(bin, 1)
		require.NoError(t, err)
		require.EqualValues(t, 1337, binary.BigEndian.Uint64(StripDataPrefix(args[0])))

		formulaBack2 := ComposeBytecodeOneLevel(sym, args)
		t.Logf("decompiled by level 1: '%s'", formulaBack2)

		_, _, binBack2, err := lib.CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack2)
	})
	t.Run("bin-expr 5", func(t *testing.T) {
		const formula = "concat(u64/1337, 123, concat(1,2,3), tail(0x00010203, 1))"
		_, _, bin, err := lib.CompileExpression(formula)
		require.NoError(t, err)
		f, err := lib.ExpressionFromBytecode(bin)
		require.NoError(t, err)
		binBack := ExpressionToBytecode(f)
		require.EqualValues(t, bin, binBack)
		formulaBack, err := lib.DecompileBytecode(bin)
		require.NoError(t, err)
		t.Logf("orig: '%s'", formula)
		t.Logf("decompiled: '%s'", formulaBack)

		_, _, binBack1, err := lib.CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack1)

		sym, prefix, args, err := lib.ParseBytecodeOneLevel(bin, 4)
		require.NoError(t, err)
		require.EqualValues(t, 1337, binary.BigEndian.Uint64(StripDataPrefix(args[0])))

		formulaBack2 := ComposeBytecodeOneLevel(sym, args)
		t.Logf("decompiled by level 1: '%s'", formulaBack2)

		_, _, binBack2, err := lib.CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack2)

		pieces := make([]interface{}, len(args)+1)
		pieces[0] = prefix
		for i := range args {
			pieces[i+1] = args[i]
		}
		// concatenation of decomposed bytecode is equal to the original
		require.EqualValues(t, bin, easyfl_util.Concat(pieces...))
	})
	t.Run("bin-expr 6", func(t *testing.T) {
		const formula = "0x010203"
		_, _, bin, err := lib.CompileExpression(formula)
		require.NoError(t, err)
		f, err := lib.ExpressionFromBytecode(bin)
		require.NoError(t, err)
		binBack := ExpressionToBytecode(f)
		require.EqualValues(t, bin, binBack)
		formulaBack, err := lib.DecompileBytecode(bin)
		require.NoError(t, err)
		t.Logf("orig: '%s'", formula)
		t.Logf("decompiled: '%s'", formulaBack)

		_, _, binBack1, err := lib.CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack1)

		sym, prefix, args, err := lib.ParseBytecodeOneLevel(bin, 0)
		require.NoError(t, err)
		require.True(t, HasInlineDataPrefix(prefix))
		t.Logf("sym = %s", sym)
		_, _, binBack2, err := lib.CompileExpression(formulaBack)
		require.NoError(t, err)
		require.EqualValues(t, bin, binBack2)

		pieces := make([]interface{}, len(args)+1)
		pieces[0] = prefix
		for i := range args {
			pieces[i+1] = args[i]
		}
		// concatenation of decomposed bytecode is equal to the original
		require.EqualValues(t, bin, easyfl_util.Concat(pieces...))

	})
	t.Run("nils", func(t *testing.T) {
		const src = "or(nil, 0x)"
		_, _, code, err := lib.CompileExpression(src)
		require.NoError(t, err)
		srcBack, err := lib.DecompileBytecode(code)
		require.NoError(t, err)
		t.Logf("\n    original: %s\n    decompiled: '%s'", src, srcBack)
		require.EqualValues(t, "or(0x,0x)", srcBack)
	})
}

func TestLocalLibrary(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `
 func fun1 : concat($0, $1)
 func fun2 : concat(fun1($0,2),fun1(3,4))
 func fun3 : fun2($0)
 func fun4 : 0x010203	
`
	libData, err := lib.CompileLocalLibrary(source)
	require.NoError(t, err)

	t.Run("1", func(t *testing.T) {
		require.NoError(t, err)
		require.EqualValues(t, 4, len(libData))

		_, err = lib.LocalLibraryFromBytes(libData)
		require.NoError(t, err)
		_, err = lib.LocalLibraryFromBytes(libData[:3])
		require.NoError(t, err)
		_, err = lib.LocalLibraryFromBytes(libData[:2])
		require.NoError(t, err)
		_, err = lib.LocalLibraryFromBytes(libData[:1])
		require.NoError(t, err)
		_, err = lib.LocalLibraryFromBytes(libData[:0]) // empty library is valid
		require.NoError(t, err)
	})
	t.Run("2", func(t *testing.T) {
		require.NoError(t, err)
		lib.MustEvalFromLibrary(nil, libData, 0, []byte{1}, []byte{2})
		lib.MustEvalFromLibrary(nil, libData, 1, []byte{5})
		lib.MustEvalFromLibrary(nil, libData, 2, []byte{1})
		lib.MustEvalFromLibrary(nil, libData, 3)
		err = easyfl_util.CatchPanicOrError(func() error {
			lib.MustEvalFromLibrary(nil, libData, 4, []byte{1})
			return nil
		})
		easyfl_util.RequireErrorWith(t, err, "function index is out of library bounds")
	})
	t.Run("3", func(t *testing.T) {
		res, err := lib.EvalFromLibrary(nil, libData, 0, []byte{1}, []byte{2})
		require.NoError(t, err)
		require.EqualValues(t, []byte{1, 2}, res)

		res, err = lib.EvalFromLibrary(nil, libData, 1, []byte{5})
		require.NoError(t, err)
		require.EqualValues(t, []byte{5, 2, 3, 4}, res)

		res, err = lib.EvalFromLibrary(nil, libData, 2, []byte{5})
		require.NoError(t, err)
		require.EqualValues(t, []byte{5, 2, 3, 4}, res)

		res, err = lib.EvalFromLibrary(nil, libData, 3)
		require.NoError(t, err)
		require.EqualValues(t, []byte{1, 2, 3}, res)

		res, err = lib.EvalFromLibrary(nil, libData, 2)
		easyfl_util.RequireErrorWith(t, err, "index out of range")

		_, err = lib.EvalFromLibrary(nil, libData, 4, []byte{5})
		easyfl_util.RequireErrorWith(t, err, "function index is out of library bounds")
	})

}

func TestParseDataArgument(t *testing.T) {
	lib := NewBaseLibrary[any]()
	t.Run("1", func(t *testing.T) {
		runSrc := func(src string) {
			_, _, code, err := lib.CompileExpression(src)
			require.NoError(t, err)
			t.Logf("src: %s\ncode: %s", src, easyfl_util.Fmt(code))

			prefix, err := lib.EvalFromSource(nil, fmt.Sprintf("parseBytecode(0x%s,0x)", hex.EncodeToString(code)))
			require.NoError(t, err)
			t.Logf("prefix: %s", easyfl_util.Fmt(prefix))

			_, _, _, sym, err := lib.parseCallPrefix(prefix)
			require.NoError(t, err)
			t.Logf("sym: %s", sym)
			require.EqualValues(t, "concat", sym)
		}
		runSrc("concat")
		runSrc("concat(0x010203030201)")
		runSrc("concat(0x010203030201, 0x112233)")

		srcPrefix := "#concat"
		_, _, codeScrPrefix, err := lib.CompileExpression(srcPrefix)
		require.NoError(t, err)
		t.Logf("src: %s\ncode: %s", srcPrefix, easyfl_util.Fmt(codeScrPrefix))
	})
	t.Run("2", func(t *testing.T) {
		runSrc := func(src string, prefixFun string, nArg byte, expected string) {
			_, _, code, err := lib.CompileExpression(src)
			require.NoError(t, err)
			t.Logf("src: %s\ncode: %s", src, easyfl_util.Fmt(code))
			srcToEval := fmt.Sprintf("parseInlineData(parseBytecode(0x%s, %d, #%s))", hex.EncodeToString(code), nArg, prefixFun)
			lib.MustEqual(srcToEval, expected)
		}
		runSrcFail := func(src string, prefixFun string, nArg byte, expectedErr ...string) {
			_, _, code, err := lib.CompileExpression(src)
			require.NoError(t, err)
			t.Logf("src: %s\ncode: %s", src, easyfl_util.Fmt(code))
			srcToEval := fmt.Sprintf("parseInlineData(parseBytecode(0x%s, %d, #%s))", hex.EncodeToString(code), nArg, prefixFun)
			lib.MustError(srcToEval, expectedErr...)
		}

		runSrc("concat(0x010203030201)", "concat", 0, "0x010203030201")
		runSrc("concat(0x010203030201, 0x112233)", "concat", 1, "0x112233")
		runSrc("concat(0x010203030201, 0x112233, 0x445566)", "concat", 2, "0x445566")
		runSrc("slice(0x010203030201, 1, 1)", "slice", 2, "1")

		runSrcFail("slice(0x010203030201, 1, 1)", "slice", 3, "wrong parameter index")
		runSrcFail("slice(0x010203030201, 1, 1)", "concat", 2, "unexpected call prefix")
		runSrcFail("concat", "concat", 0, "wrong parameter index")

	})
	t.Run("parseNumArgs", func(t *testing.T) {
		runNumArgs := func(src string, expectedNumArgs int) {
			_, _, bytecode, err := lib.CompileExpression(src)
			require.NoError(t, err)
			t.Logf("src: %s\nbytecode: %s", src, easyfl_util.Fmt(bytecode))
			srcToEval := fmt.Sprintf("parseNumArgs(0x%s)", hex.EncodeToString(bytecode))
			lib.MustEqual(srcToEval, fmt.Sprintf("%d", expectedNumArgs))
		}
		runNumArgs("concat", 0)
		runNumArgs("concat(1)", 1)
		runNumArgs("concat(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)", 15)
		runNumArgs("or(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)", 15)
		runNumArgs("if(1,2,3)", 3)
		runNumArgs("nil", 0)
		runNumArgs("0x11223344", 0)
	})
}

func TestCases(t *testing.T) {
	lib := NewBaseLibrary[any]()
	t.Run("1", func(t *testing.T) {
		const src = `firstCaseIndex(
			equal($0, 1),
			equal($0, 2),
			equal($0, 3),
			equal($0, 4),
			equal($0, 0xffff),
		)
`
		expr, n, _, err := lib.CompileExpression(src)
		require.NoError(t, err)
		require.EqualValues(t, 1, n)

		res := EvalExpression(nil, expr, []byte{3})
		require.EqualValues(t, []byte{2}, res)

		res = EvalExpression(nil, expr, []byte{4})
		require.EqualValues(t, []byte{3}, res)

		res = EvalExpression(nil, expr, []byte{0})
		require.True(t, len(res) == 0)

		res = EvalExpression(nil, expr, []byte{7})
		require.True(t, len(res) == 0)

		res = EvalExpression(nil, expr, []byte{0xff, 0xff})
		require.EqualValues(t, []byte{4}, res)
	})
	t.Run("2", func(t *testing.T) {
		const src = "firstEqualIndex($0, 1, 2, 3, 4, 0xffff)"

		expr, n, _, err := lib.CompileExpression(src)
		require.NoError(t, err)
		require.EqualValues(t, 1, n)

		res := EvalExpression(nil, expr, []byte{3})
		require.EqualValues(t, []byte{2}, res)

		res = EvalExpression(nil, expr, []byte{4})
		require.EqualValues(t, []byte{3}, res)

		res = EvalExpression(nil, expr, []byte{0})
		require.True(t, len(res) == 0)

		res = EvalExpression(nil, expr, []byte{7})
		require.True(t, len(res) == 0)

		res = EvalExpression(nil, expr, []byte{0xff, 0xff})
		require.EqualValues(t, []byte{4}, res)
	})
	t.Run("3", func(t *testing.T) {
		const src = "selectCaseByIndex($0, 1, 0x1234, add(5,3), true)"

		expr, n, _, err := lib.CompileExpression(src)
		require.NoError(t, err)
		require.EqualValues(t, 1, n)

		res := EvalExpression(nil, expr, []byte{0})
		require.EqualValues(t, []byte{1}, res)

		res = EvalExpression(nil, expr, []byte{1})
		require.EqualValues(t, []byte{0x12, 0x34}, res)

		res = EvalExpression(nil, expr, []byte{2})
		require.EqualValues(t, []byte{0, 0, 0, 0, 0, 0, 0, 8}, res)

		res = EvalExpression(nil, expr, []byte{3})
		require.EqualValues(t, []byte{0xff}, res)

		res = EvalExpression(nil, expr, []byte{4})
		require.True(t, len(res) == 0)

		res = EvalExpression(nil, expr, []byte{0, 0})
		require.True(t, len(res) == 0)
	})
}

func TestEmbed(t *testing.T) {
	lib := NewBaseLibrary[any]()
	t.Run("main", func(t *testing.T) {
		lib.MustEqual("concat", "0x")
		lib.MustEqual("concat(1,2)", "0x0102")
		lib.MustEqual("concat(1,2,3,4)", "concat(concat(1,2),concat(3,4))")

		lib.MustError("fail(100)", "SCRIPT FAIL: error #100")
		lib.MustError("!!!hello,_world!", "hello, world!")
		lib.MustError("!!!fail_error_message_31415", "31415")

		lib.MustEqual("slice(0x010203,1,2)", "0x0203")

		lib.MustEqual("byte(0x010203, 2)", "3")

		lib.MustEqual("tail(0x010203, 2)", "3")

		lib.MustTrue("hasPrefix(0xf10203,0xf1)")

		lib.MustEqual("repeat(1,5)", "0x0101010101")

		lib.MustTrue("equal(len(nil), u64/0)")

		lib.MustEqual("not(1)", "0x")

		lib.MustTrue("and")
		lib.MustTrue("not(and(concat))")

		lib.MustTrue("not(or)")
		lib.MustTrue("not(or(concat))")
		lib.MustTrue("or(1)")

		lib.MustTrue("isZero(0)")
		lib.MustTrue("isZero(repeat(0,100))")
		lib.MustTrue("not(isZero(0x0000000003))")
	})
	t.Run("arithmetics", func(t *testing.T) {
		lib.MustTrue("isZero(uint8Bytes(0x))")
		lib.MustTrue("equal(uint8Bytes(0x), u64/0)")
		lib.MustEqual("uint8Bytes(1)", "u64/1")
		lib.MustEqual("uint8Bytes(u16/1)", "u64/1")

		lib.MustEqual("add(5,6)", "add(10,1)")
		lib.MustEqual("add(5,6)", "u64/11")
		lib.MustEqual("add(0, 0)", "u64/0")
		lib.MustEqual("add(u16/1337, 0)", "u64/1337")
		lib.MustEqual("add(nil, 0)", "u64/0")
		lib.MustEqual("add(0, 0)", "u64/0")
		lib.MustEqual("add(0x, 0x)", "u64/0")
		lib.MustError("add(0xfffffffffffffff0, 0xffffffffffff0000)", "overflow in addition")
		lib.MustError("add(0xfffffffffffffff0, 0x10)", "overflow in addition")

		lib.MustEqual("sub(6,6)", "u64/0")
		lib.MustEqual("sub(6,5)", "u64/1")
		lib.MustEqual("sub(0, 0)", "u64/0")
		lib.MustEqual("sub(u16/1337, 0)", "u64/1337")
		lib.MustEqual("sub(nil, 0)", "u64/0")
		lib.MustError("sub(10, 100)", "underflow in subtraction")

		lib.MustEqual("mul(5,6)", "mul(15,2)")
		lib.MustEqual("mul(5,6)", "u64/30")
		lib.MustEqual("mul(u16/1337, 0)", "u64/0")
		lib.MustEqual("mul(0, u32/1337133700)", "u64/0")
		lib.MustEqual("mul(nil, 5)", "u64/0")

		lib.MustEqual("div(100,100)", "u64/1")
		lib.MustEqual("div(100,110)", "u64/0")
		lib.MustEqual("div(u32/10000,u16/10000)", "u64/1")
		lib.MustEqual("div(0, u32/1337133700)", "u64/0")
		lib.MustError("div(u32/1337133700, 0)", "divide by zero")
		lib.MustEqual("div(nil, 5)", "u64/0")

		lib.MustEqual("mod(100,100)", "u64/0")
		lib.MustEqual("mod(107,100)", "u64/7")
		lib.MustEqual("mod(u32/10100,u16/10000)", "u64/100")
		lib.MustEqual("mod(0, u32/1337133700)", "u64/0")
		lib.MustError("mod(u32/1337133700, 0)", "divide by zero")
		lib.MustEqual("mod(nil, 5)", "u64/0")
		lib.MustEqual("add(mul(div(u32/27, u16/4), 4), mod(u32/27, 4))", "u64/27")
	})
	t.Run("bitwiseAndCmp", func(t *testing.T) {
		// comparison lexicographical (equivalent to bigendian for binary integers)
		lib.MustTrue("lessThan(1,2)")
		lib.MustTrue("not(lessThan(2,1))")
		lib.MustTrue("not(lessThan(2,2))")
		// bitwise
		//lib.embedShort("bitwiseOR", 2, evalBitwiseOR)
		lib.MustEqual("bitwiseOR(0x01, 0x80)", "0x81")
		//lib.embedShort("bitwiseAND", 2, evalBitwiseAND)
		lib.MustEqual("bitwiseAND(0x03, 0xf2)", "0x02")
		lib.MustEqual("bitwiseAND(0x0102, 0xff00)", "0x0100")
		//lib.embedShort("bitwiseNOT", 1, evalBitwiseNOT)
		lib.MustEqual("bitwiseNOT(0x00ff)", "0xff00")
		//lib.embedShort("bitwiseXOR", 2, evalBitwiseXOR)
		lib.MustEqual("bitwiseXOR(0x1234, 0x1234)", "0x0000")
		lib.MustEqual("bitwiseXOR(0x1234, 0xffff)", "bitwiseNOT(0x1234)")
		// other

		//lib.embedLong("lshift64", 2, evalLShift64)
		lib.MustEqual("lshift64(u64/3, u64/2)", "u64/12")
		lib.MustTrue("isZero(lshift64(u64/2001, u64/64))")
		lib.MustTrue("equal(lshift64(u64/2001, u64/4), mul(u64/2001, u16/16))")
		lib.MustEqual("lshift64(u64/2001, nil)", "u64/2001")

		//lib.embedLong("rshift64", 2, evalRShift64)
		lib.MustEqual("rshift64(u64/15, u64/2)", "u64/3")
		lib.MustTrue("isZero(rshift64(0xffffffffffffffff, u64/64))")
		lib.MustTrue("equal(rshift64(u64/2001, u64/3), div(u64/2001, 8))")
		lib.MustEqual("rshift64(u64/2001, nil)", "u64/2001")

	})
	t.Run("base crypto", func(t *testing.T) {
		h := blake2b.Sum256([]byte{1})
		lib.MustEqual("len(blake2b(1))", "u64/32")
		lib.MustEqual("blake2b(1)", fmt.Sprintf("0x%s", hex.EncodeToString(h[:])))
	})
	t.Run("bytecode manipulation", func(t *testing.T) {
		_, _, binCode, err := lib.CompileExpression("slice(0x01020304,1,2)")
		easyfl_util.AssertNoError(err)
		src := fmt.Sprintf("parseInlineData(parseBytecode(0x%s, %d, #slice))", hex.EncodeToString(binCode), 0)
		lib.MustEqual(src, "0x01020304")
		src = fmt.Sprintf("parseInlineData(parseBytecode(0x%s, %d, #slice))", hex.EncodeToString(binCode), 1)
		lib.MustEqual(src, "1")
		src = fmt.Sprintf("parseInlineData(parseBytecode(0x%s, %d, #slice))", hex.EncodeToString(binCode), 2)
		lib.MustEqual(src, "2")
		src = fmt.Sprintf("parseBytecode(0x%s, 0x)", hex.EncodeToString(binCode))
		lib.MustEqual(src, "#slice")
	})
}

func TestManyParams(t *testing.T) {
	lib := NewBaseLibrary[any]()

	t.Run("1", func(t *testing.T) {
		lib.MustEqual("concat(0, 1,2,3,4,5,6,7)", "0x0001020304050607")
	})
	t.Run("2", func(t *testing.T) {
		lib.MustEqual("concat(0,1,2,3,4,5,6,7,8,9,10,11,12,13)", "0x000102030405060708090a0b0c0d")
	})
	t.Run("3", func(t *testing.T) {
		lib.MustEqual("concat(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14)", "0x000102030405060708090a0b0c0d0e")
	})
	t.Run("4", func(t *testing.T) {
		lib.MustError("concat(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)", "can't be more than 15 parameters")
	})
	t.Run("5", func(t *testing.T) {
		_, nParam, _, err := lib.CompileExpression("concat")
		require.NoError(t, err)
		require.EqualValues(t, 0, nParam)
	})
	t.Run("6", func(t *testing.T) {
		_, nParam, _, err := lib.CompileExpression("concat($0,$1,$2,$3)")
		require.NoError(t, err)
		require.EqualValues(t, 4, nParam)
	})
	t.Run("7", func(t *testing.T) {
		_, nParam, _, err := lib.CompileExpression("concat($3)")
		require.NoError(t, err)
		require.EqualValues(t, 4, nParam)
	})
	t.Run("8", func(t *testing.T) {
		_, nParam, _, err := lib.CompileExpression("concat($14)")
		require.NoError(t, err)
		require.EqualValues(t, 15, nParam)
	})
	t.Run("9", func(t *testing.T) {
		_, nParam, _, err := lib.CompileExpression("concat($0, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)")
		require.NoError(t, err)
		require.EqualValues(t, 15, nParam)
	})
	t.Run("10", func(t *testing.T) {
		lib.MustError("concat($15)", "wrong eval parameter reference")
	})

}

func TestParseInlineDataArgumentAnyPrefix(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const src = "concat(1,2,3,4)"
	_, _, bytecode, err := lib.CompileExpression(src)
	require.NoError(t, err)
	src2 := fmt.Sprintf("parseInlineData(parseBytecode(0x%s, 0))", hex.EncodeToString(bytecode))
	lib.MustEqual(src2, "1")
	src2 = fmt.Sprintf("parseInlineData(parseBytecode(0x%s, 1))", hex.EncodeToString(bytecode))
	lib.MustEqual(src2, "2")
	src2 = fmt.Sprintf("parseInlineData(parseBytecode(0x%s, 3))", hex.EncodeToString(bytecode))
	lib.MustEqual(src2, "4")

	const src1 = "or(1,2,3,4)"
	_, _, bytecode, err = lib.CompileExpression(src1)
	require.NoError(t, err)
	src2 = fmt.Sprintf("parseInlineData(parseBytecode(0x%s, 0))", hex.EncodeToString(bytecode))
	lib.MustEqual(src2, "1")
	src2 = fmt.Sprintf("parseInlineData(parseBytecode(0x%s, 1))", hex.EncodeToString(bytecode))
	lib.MustEqual(src2, "2")
	src2 = fmt.Sprintf("parseInlineData(parseBytecode(0x%s, 3))", hex.EncodeToString(bytecode))
	lib.MustEqual(src2, "4")
}
