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

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
)

const formula1 = "func unlockBlock: concat(concat(0x0000, slice(0x01020304050607, 2, 5)))"

func TestAux(t *testing.T) {
	t.Logf("MaxInt: %d", math.MaxInt)
	t.Logf("MaxInt64: %d", math.MaxInt64)
}

func TestInit(t *testing.T) {
	NewBase().PrintLibraryStats()
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

		code, numParams, err := NewBase().ExpressionSourceToBytecode(ret[0].SourceCode)
		require.NoError(t, err)
		require.EqualValues(t, 0, numParams)
		t.Logf("code len: %d", len(code))
	})
	t.Run("4", func(t *testing.T) {
		parsed, err := parseFunctions(formula1)
		require.NoError(t, err)
		require.EqualValues(t, 1, len(parsed))

		lib := NewBase()
		code, numParams, err := lib.ExpressionSourceToBytecode(parsed[0].SourceCode)
		require.NoError(t, err)
		require.EqualValues(t, 0, numParams)
		t.Logf("code len: %d", len(code))

		f, err := lib.ExpressionFromBytecode(code)
		require.NoError(t, err)
		require.NotNil(t, f)
	})
	t.Run("fun call literal 1", func(t *testing.T) {
		lib := NewBase()
		prefix, err := lib.EvalFromSource(nil, "#concat")
		require.NoError(t, err)
		_, _, code, err := lib.CompileExpression("concat")
		require.NoError(t, err)
		prefix1, err := lib.ParseBytecodePrefix(code)
		require.NoError(t, err)
		require.True(t, bytes.Equal(prefix, prefix1))
	})
	t.Run("fun call literal 2", func(t *testing.T) {
		lib := NewBase()
		prefix, err := lib.EvalFromSource(nil, "#tail")
		require.NoError(t, err)
		_, _, code, err := lib.CompileExpression("tail(0x010203, 2)")
		require.NoError(t, err)
		prefix1, err := lib.ParseBytecodePrefix(code)
		require.NoError(t, err)
		require.True(t, bytes.Equal(prefix, prefix1))
	})
	t.Run("fail call binary", func(t *testing.T) {
		lib := NewBase()
		_, _, code, err := lib.CompileExpression("!!!ciao!")
		require.NoError(t, err)
		t.Logf("!!!ciao! code = %s", Fmt(code))
		_, err = lib.EvalFromBytecode(nil, code)
		RequireErrorWith(t, err, "SCRIPT FAIL: 'ciao!'")

		src := fmt.Sprintf("x/%s", hex.EncodeToString(code))
		_, err = lib.EvalFromSource(nil, src)
		RequireErrorWith(t, err, "SCRIPT FAIL: 'ciao!'")
	})
}

func TestEval(t *testing.T) {
	lib := NewBase()
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
		tr := NewGlobalDataTracePrint(nil)
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
		ret, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), longer, []byte("abcdef"))
		require.NoError(t, err)
		require.EqualValues(t, []byte{1}, ret)
	})
	t.Run("14", func(t *testing.T) {
		ret, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), longer, []byte("abcde"))
		require.NoError(t, err)
		require.EqualValues(t, []byte{5, 6}, ret)
	})
	t.Run("15", func(t *testing.T) {
		ret, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "nil")
		require.NoError(t, err)
		require.True(t, len(ret) == 0)
	})
	t.Run("16", func(t *testing.T) {
		ret, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "concat")
		require.NoError(t, err)
		require.True(t, len(ret) == 0)
	})
	t.Run("17", func(t *testing.T) {
		ret, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "u16/256")
		require.NoError(t, err)
		require.EqualValues(t, []byte{1, 0}, ret)
	})
	t.Run("18", func(t *testing.T) {
		ret, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "u32/70000")
		require.NoError(t, err)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], 70000)
		require.EqualValues(t, b[:], ret)
	})
	t.Run("19", func(t *testing.T) {
		ret, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "u64/10000000000")
		require.NoError(t, err)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], 10000000000)
		require.EqualValues(t, b[:], ret)
	})
	t.Run("20", func(t *testing.T) {
		ret, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "isZero(0x000000)")
		require.NoError(t, err)
		require.True(t, len(ret) != 0)
	})
	t.Run("21", func(t *testing.T) {
		ret, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "isZero(0x003000)")
		require.NoError(t, err)
		require.True(t, len(ret) == 0)
	})
	t.Run("21", func(t *testing.T) {
		ret, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "add($0, $1)", []byte{160}, []byte{160})
		require.NoError(t, err)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], 320)
		require.EqualValues(t, b[:], ret)
	})
	var blake2bInvokedNum int
	lib.embedLong("blake2b-test", 1, func(par *CallParams) []byte {
		a0 := par.Arg(0)
		h := blake2b.Sum256(a0)
		blake2bInvokedNum++
		par.Trace("blake2b-test:: %v -> %v", a0, h[:])
		return h[:]
	})
	t.Run("23", func(t *testing.T) {
		blake2bInvokedNum = 0
		ret, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "blake2b-test($0)", []byte{1, 2, 3})
		require.NoError(t, err)
		h := blake2b.Sum256([]byte{0x01, 0x02, 0x03})
		require.EqualValues(t, h[:], ret)
		require.EqualValues(t, blake2bInvokedNum, 1)

		ret, err = lib.EvalFromSource(NewGlobalDataTracePrint(nil), "blake2b-test($0)", nil)
		require.NoError(t, err)
		h = blake2b.Sum256(nil)
		require.EqualValues(t, h[:], ret)
		require.EqualValues(t, blake2bInvokedNum, 2)
	})
	t.Run("24", func(t *testing.T) {
		blake2bInvokedNum = 0
		h2 := blake2b.Sum256([]byte{2})
		h3 := blake2b.Sum256([]byte{3})

		ret, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "if($0,blake2b-test($1),blake2b-test($2))",
			[]byte{1}, []byte{2}, []byte{3})
		require.NoError(t, err)
		require.EqualValues(t, h2[:], ret)
		require.EqualValues(t, blake2bInvokedNum, 1)

		ret, err = lib.EvalFromSource(NewGlobalDataTracePrint(nil), "if($0,blake2b-test($1),blake2b-test($2))",
			nil, []byte{2}, []byte{3})
		require.NoError(t, err)
		require.EqualValues(t, h3[:], ret)
		require.EqualValues(t, blake2bInvokedNum, 2)
	})
}

func TestExtendLib(t *testing.T) {
	lib := NewBase()
	t.Run("ext-2", func(t *testing.T) {
		_, err := lib.ExtendErr("nil1", "concat()")
		require.NoError(t, err)
	})
	t.Run("ext-3", func(t *testing.T) {
		_, err := lib.ExtendErr("cat2", "concat($0, $1)")
		require.NoError(t, err)
		ret, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "cat2(1,2)")
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
		c0 := concat(d0, d1)
		c1 := concat(d0, d2)
		c3 := concat(c0, c1)
		return c3
	}
	t.Run("ext-4", func(t *testing.T) {
		ret, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "complicated(0,1,2)")
		require.NoError(t, err)
		require.EqualValues(t, compl(d(0), d(1), d(2)), ret)
	})
	t.Run("ext-5", func(t *testing.T) {
		ret, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "complicated(0,1,complicated(2,1,0))")
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
		ret, err := lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), code, []byte{1}, []byte{2}, []byte{3})
		require.NoError(t, err)
		require.EqualValues(t, []byte{3, 2, 1}, ret)
	})
	t.Run("always panics", func(t *testing.T) {
		_, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "byte(0,1)")
		require.Error(t, err)
	})
	t.Run("never panics", func(t *testing.T) {
		_, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "if(concat,byte(0,1),0x01)")
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
	lib := NewBase()
	runTest := func(s string, a0, a1 []byte) bool {
		fmt.Printf("---- runTest: '%s'\n", s)
		ret, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), s, a0, a1)
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
	lib := NewBase()
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	pubKey, privKey, err := ed25519.GenerateKey(rnd)
	require.NoError(t, err)

	const msg = "message to be signed"

	t.Run("validSignatureED25519-ok", func(t *testing.T) {
		signature := ed25519.Sign(privKey, []byte(msg))
		res, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "validSignatureED25519($0,$1,$2)", []byte(msg), signature, pubKey)
		require.NoError(t, err)

		require.True(t, len(res) > 0)
	})
	t.Run("validSignatureED25519-wrong-msg", func(t *testing.T) {
		signature := ed25519.Sign(privKey, []byte(msg))
		res, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "validSignatureED25519($0,$1,$2)", []byte(msg+"klmn"), signature, pubKey)
		require.NoError(t, err)

		require.True(t, len(res) == 0)
	})
	t.Run("validSignatureED25519-wrong-sig", func(t *testing.T) {
		signature := ed25519.Sign(privKey, []byte(msg))
		signature[5]++
		res, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "validSignatureED25519($0,$1,$2)", []byte(msg), signature, pubKey)
		require.NoError(t, err)

		require.True(t, len(res) == 0)
	})
	t.Run("validSignatureED25519-wrong-pubkey", func(t *testing.T) {
		signature := ed25519.Sign(privKey, []byte(msg))
		pk := concat([]byte(pubKey))
		pk[3]++
		res, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "validSignatureED25519($0,$1,$2)", []byte(msg), signature, pk)
		require.NoError(t, err)

		require.True(t, len(res) == 0)
	})
	t.Run("validSignatureED25519-wrong-pubkey", func(t *testing.T) {
		_, err := lib.EvalFromSource(NewGlobalDataTracePrint(nil), "validSignatureED25519($0,$1,$2)", nil, nil, nil)
		RequireErrorWith(t, err, "bad public key length")
	})
}

func TestTracing(t *testing.T) {
	lib := NewBase()
	t.Run("no panic 0", func(t *testing.T) {
		tr := NewGlobalDataLog(nil)
		ret, err := lib.EvalFromSource(tr, "slice(concat(concat(1,2),concat(3,4,5)),2,3)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{3, 4}, ret)
		tr.PrintLog()
	})
	t.Run("with panic 1", func(t *testing.T) {
		tr := NewGlobalDataLog(nil)
		_, err := lib.EvalFromSource(tr, "slice(0x0102,2,3)")
		require.Error(t, err)
		tr.PrintLog()
	})
	t.Run("no panic 2", func(t *testing.T) {
		tr := NewGlobalDataLog(nil)
		_, err := lib.EvalFromSource(tr, "slice(tail(0x0102030405,2),1,2)")
		require.NoError(t, err)
		tr.PrintLog()
	})
	t.Run("with panic 3", func(t *testing.T) {
		tr := NewGlobalDataLog(nil)
		_, err := lib.EvalFromSource(tr, "slice(tail(0x0102030405,2),1,5)")
		require.Error(t, err)
		tr.PrintLog()
	})
	t.Run("no panic 4", func(t *testing.T) {
		tr := NewGlobalDataLog(nil)
		_, err := lib.EvalFromSource(tr, "equal(slice(tail(0x0102030405,2),1,2), slice(tail(0x0102030405,2),2,2))")
		require.NoError(t, err)
		tr.PrintLog()
	})
	t.Run("no panic 5", func(t *testing.T) {
		tr := NewGlobalDataLog(nil)
		_, err := lib.EvalFromSource(tr, "equal(len(slice(tail(0x0102030405,2),1,2)), u64/2)")
		require.NoError(t, err)
		tr.PrintLog()
	})
	t.Run("no panic 6", func(t *testing.T) {
		tr := NewGlobalDataLog(nil)
		_, err := lib.EvalFromSource(tr, "equal(len(slice(tail(0x0102030405,2),1,2)), u64/2)")
		require.NoError(t, err)
		tr.PrintLog()
	})
	t.Run("no trace", func(t *testing.T) {
		tr := NewGlobalDataNoTrace(nil)
		_, err := lib.EvalFromSource(tr, "equal(len(slice(tail(0x0102030405,2),1,2)), u64/2)")
		require.NoError(t, err)
	})
	t.Run("trace print", func(t *testing.T) {
		tr := NewGlobalDataTracePrint(nil)
		_, err := lib.EvalFromSource(tr, "equal(len(slice(tail(0x0102030405,2),1,2)), u64/2)")
		require.NoError(t, err)
	})
	t.Run("trace if", func(t *testing.T) {
		tr := NewGlobalDataLog(nil)
		_, err := lib.EvalFromSource(tr, "if(nil,0x1234,0x5678)")
		require.NoError(t, err)
		tr.PrintLog()
	})
	t.Run("trace not", func(t *testing.T) {
		tr := NewGlobalDataTracePrint(nil)
		_, err := lib.EvalFromSource(tr, "not(not(not($0)))", []byte{10})
		require.NoError(t, err)
	})
	t.Run("trace concat", func(t *testing.T) {
		tr := NewGlobalDataTracePrint(nil)
		_, err := lib.EvalFromSource(tr, "concat($0,concat($0,$0))", []byte{10})
		require.NoError(t, err)
		tr = NewGlobalDataTracePrint(nil)
		_, err = lib.EvalFromSource(tr, "concat(concat())")
		require.NoError(t, err)
	})
	t.Run("trace caching", func(t *testing.T) {
		lib.extend("c6", "concat($0, $0, $0, $0, $0, $0)")
		var counter int
		lib.embedShort("prn", 0, func(_ *CallParams) []byte {
			counter++
			fmt.Printf("counter incremented\n")
			return []byte{1}
		})
		tr := NewGlobalDataTracePrint(nil)
		res, err := lib.EvalFromSource(tr, "c6(c6(prn))")
		require.NoError(t, err)
		require.EqualValues(t, bytes.Repeat([]byte{1}, 36), res)
		require.EqualValues(t, 1, counter)
	})
}

func TestParseBin(t *testing.T) {
	lib := NewBase()
	lib.extend("fun1par", "$0")
	lib.extend("fun2par", "concat($0,$1)")

	t.Run("1", func(t *testing.T) {
		_, _, bin, err := lib.CompileExpression("fun1par(0x00)")
		require.NoError(t, err)
		t.Logf("code: %s", Fmt(bin))
		res, err := lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
	})
	t.Run("call 2 param", func(t *testing.T) {
		_, _, bin, err := lib.CompileExpression("fun2par(0x01, 0x02)")
		require.NoError(t, err)
		t.Logf("code: %s", Fmt(bin))
		res, err := lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
	})
	t.Run("fun 2 param", func(t *testing.T) {
		_, _, bin, err := lib.CompileExpression("fun2par($0, $1)")
		require.NoError(t, err)
		t.Logf("code: %s", Fmt(bin))
		res, err := lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), bin, []byte{1}, []byte{2})
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
	})
	t.Run("2", func(t *testing.T) {
		addrStr := fmt.Sprintf("fun1par(0x%s)", strings.Repeat("00", 32))
		_, _, bin, err := lib.CompileExpression(addrStr)
		require.NoError(t, err)
		t.Logf("code: %s", Fmt(bin))
		res, err := lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
	})
	t.Run("3", func(t *testing.T) {
		_, _, bin, err := lib.CompileExpression("slice(0,0,0)")
		require.NoError(t, err)
		t.Logf("code: %s", Fmt(bin))
		res, err := lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
	})
	t.Run("4", func(t *testing.T) {
		_, _, bin, err := lib.CompileExpression("0")
		require.NoError(t, err)
		t.Logf("code: %s", Fmt(bin))
		res, err := lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
	})
	t.Run("bin code cannot be nil", func(t *testing.T) {
		_, err := lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), nil)
		require.Error(t, err)
	})
	t.Run("0-parameter bin code never starts from 0", func(t *testing.T) {
		bin := []byte{0}
		t.Logf("code: %s", Fmt(bin))
		_, err := lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), bin)
		require.Error(t, err)

		bin = []byte{0, 0}
		t.Logf("code: %s", Fmt(bin))
		_, err = lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), bin)
		require.Error(t, err)
	})
	t.Run("0-started code require 1 parameter", func(t *testing.T) {
		bin := []byte{0}
		t.Logf("code: %s", Fmt(bin))
		res, err := lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), bin, []byte{10})
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
		require.EqualValues(t, []byte{10}, res)
	})
	t.Run("0-parameter bin code never starts from 1", func(t *testing.T) {
		bin := []byte{1}
		t.Logf("code: %s", Fmt(bin))
		_, err := lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), bin)
		require.Error(t, err)

		bin = []byte{0, 0}
		t.Logf("code: %s", Fmt(bin))
		_, err = lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), bin)
		require.Error(t, err)
	})
	t.Run("1-started code require 2 parameters", func(t *testing.T) {
		bin := []byte{1}
		t.Logf("code: %s", Fmt(bin))
		res, err := lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), bin, []byte{10}, []byte{11})
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
		require.EqualValues(t, []byte{11}, res)
	})
	t.Run("nil code is 0x80", func(t *testing.T) {
		bin := []byte{0x80}
		t.Logf("code: %s", Fmt(bin))
		res, err := lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), bin)
		require.NoError(t, err)
		require.True(t, len(res) == 0)
		t.Logf("result: %s", Fmt(res))
	})
	t.Run("fun prefix1", func(t *testing.T) {
		prefix, err := lib.FunctionCallPrefixByName("fun1par", 1)
		require.NoError(t, err)
		t.Logf("fun1par prefix: %s", Fmt(prefix))

		_, _, binCode, err := lib.CompileExpression("fun1par(0xeeff)")
		require.NoError(t, err)
		t.Logf("fun1par(0xeeff) code: %s", Fmt(binCode))
		require.True(t, bytes.HasPrefix(binCode, prefix))

		prefix, err = lib.FunctionCallPrefixByName("fun2par", 2)
		require.NoError(t, err)
		t.Logf("fun2par prefix: %s", Fmt(prefix))

		_, _, binCode, err = lib.CompileExpression("fun2par(0xeeff, 0x1122)")
		require.NoError(t, err)
		t.Logf("fun2par(0xeeff, 0x1122) code: %s", Fmt(binCode))
		require.True(t, bytes.HasPrefix(binCode, prefix))
	})
}

func TestInlineCode(t *testing.T) {
	lib := NewBase()
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

		t.Logf("code with inline: %s", Fmt(bin3))
		res, err := lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), bin3)
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
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

		t.Logf("code with inline: %s", Fmt(bin3))
		res, err := lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), bin3, []byte{0, 1})
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
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

		t.Logf("code with inline: %s", Fmt(bin3))
		res, err := lib.EvalFromBytecode(NewGlobalDataTracePrint(nil), bin3, []byte{2})
		require.NoError(t, err)
		t.Logf("result: %s", Fmt(res))
		require.EqualValues(t, []byte{0, 2}, res)
	})
}

func TestDecompile(t *testing.T) {
	lib := NewBase()
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
		require.EqualValues(t, bin, concat(pieces...))
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
		require.True(t, IsDataPrefix(prefix))
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
		require.EqualValues(t, bin, concat(pieces...))

	})
}

func TestLocalLibrary(t *testing.T) {
	lib := NewBase()
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
		err = CatchPanicOrError(func() error {
			lib.MustEvalFromLibrary(nil, libData, 4, []byte{1})
			return nil
		})
		RequireErrorWith(t, err, "function index is out of library bounds")
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
		RequireErrorWith(t, err, "index out of range")

		_, err = lib.EvalFromLibrary(nil, libData, 4, []byte{5})
		RequireErrorWith(t, err, "function index is out of library bounds")
	})

}

func TestBytecodeParams(t *testing.T) {
	lib := NewBase()
	t.Run("1", func(t *testing.T) {
		const src = "concat(1,2)"
		_, _, code, err := lib.CompileExpression(src)
		require.NoError(t, err)

		src1 := fmt.Sprintf("bytecode(%s)", src)
		expr1, nPar, code1, err := lib.CompileExpression(src1)
		require.NoError(t, err)
		require.EqualValues(t, 0, nPar)
		t.Logf("compile '%s' -> %s", src1, Fmt(code1))

		res := EvalExpression(nil, expr1)
		t.Logf("Result: '%s'", Fmt(res))

		require.EqualValues(t, code, res)

		decompiled1, err := lib.DecompileBytecode(code1)
		require.NoError(t, err)
		t.Logf("decompiled1: '%s'", decompiled1)

		decompiled, err := lib.DecompileBytecode(code)
		require.NoError(t, err)
		t.Logf("decompiled: '%s'", decompiled)
	})
	t.Run("2", func(t *testing.T) {
		const src = "and(concat(1,2), if(1,2,3))"
		_, _, code, err := lib.CompileExpression(src)
		require.NoError(t, err)

		src1 := fmt.Sprintf("bytecode(%s)", src)
		expr1, nPar, code1, err := lib.CompileExpression(src1)
		require.NoError(t, err)
		require.EqualValues(t, 0, nPar)
		t.Logf("compile '%s' -> %s", src1, Fmt(code1))

		res := EvalExpression(nil, expr1)
		t.Logf("Result: '%s'", Fmt(res))

		require.EqualValues(t, code, res)

		decompiled1, err := lib.DecompileBytecode(code1)
		require.NoError(t, err)
		t.Logf("decompiled: '%s'", decompiled1)

		decompiled, err := lib.DecompileBytecode(code)
		require.NoError(t, err)
		t.Logf("decompiled: '%s'", decompiled)
	})
	t.Run("3", func(t *testing.T) {
		const src = "concat($0,$$0)"

		expr, n, code, err := lib.CompileExpression(src)
		require.NoError(t, err)
		require.EqualValues(t, 1, n)
		t.Logf("code: %s", Fmt(code))

		res := EvalExpression(nil, expr, []byte{0xff})
		t.Logf("eval: %s", Fmt(res))
		require.EqualValues(t, []byte{0xff, 0x81, 0xff}, res)
	})
	t.Run("3-1", func(t *testing.T) {
		const src = "concat(1,$$0, $$1, $$2)"

		expr, n, code, err := lib.CompileExpression(src)
		require.NoError(t, err)
		require.EqualValues(t, 3, n)
		t.Logf("code: %s", Fmt(code))

		res := EvalExpression(nil, expr, []byte{0xff}, []byte{0xff}, []byte{0xff})
		t.Logf("eval: %s", Fmt(res))
		require.EqualValues(t, hex.EncodeToString(res), "0181ff81ff81ff")
	})
	t.Run("4", func(t *testing.T) {
		res, err := lib.EvalFromSource(nil, "concat(42,41)")
		require.NoError(t, err)

		require.EqualValues(t, res, []byte{42, 41})

		res1, err := lib.EvalFromSource(nil, "eval(bytecode(concat(42,41)))")
		require.NoError(t, err)
		require.EqualValues(t, res, res1)
	})
	t.Run("5", func(t *testing.T) {
		sources := []string{"123", "0x", "u64/1234567890", "concat(1,2,3)", "lessOrEqualThan(1,2)", "lessOrEqualThan(2, 1)",
			"lessOrEqualThan(0xabcdef123456, 0xabcdef123000)", "concat(1,concat(2,3), concat)", "nil"}
		for _, src := range sources {
			lib.MustEqual(src, fmt.Sprintf("eval(bytecode(%s))", src))
		}
	})
	t.Run("6", func(t *testing.T) {
		const src = "lessOrEqualThan(0xabcdef123456,0xabcdef123000)"
		t.Logf("orig: %s", src)
		srcBytecode := fmt.Sprintf("bytecode(%s)", src)
		code, err := lib.EvalFromSource(nil, srcBytecode)
		require.NoError(t, err)
		t.Logf("code: %s", Fmt(code))
		decomp, err := lib.DecompileBytecode(code)
		require.NoError(t, err)
		t.Logf("decompile: %s", decomp)
		require.EqualValues(t, src, decomp)

		srcParse := fmt.Sprintf("eval(parseArgumentBytecode(0x%s,#lessOrEqualThan, 1))", hex.EncodeToString(code))
		lib.MustEqual(srcParse, "0xabcdef123000")
	})
	t.Run("7", func(t *testing.T) {
		const src = "lessOrEqualThan(0xabcdef123456,0xabcdef123000)"
		t.Logf("orig: %s", src)
		srcBytecode := fmt.Sprintf("bytecode(%s)", src)
		code, err := lib.EvalFromSource(nil, srcBytecode)
		require.NoError(t, err)
		t.Logf("code: %s", Fmt(code))
		decomp, err := lib.DecompileBytecode(code)
		require.NoError(t, err)
		t.Logf("decompile: %s", decomp)
		require.EqualValues(t, src, decomp)

		prefix, err := lib.EvalFromSource(nil, fmt.Sprintf("parsePrefixBytecode(0x%x)", code))
		require.NoError(t, err)
		arg0, err := lib.EvalFromSource(nil, fmt.Sprintf("parseArgumentBytecode(0x%x, #lessOrEqualThan, 0)", code))
		require.NoError(t, err)
		arg1, err := lib.EvalFromSource(nil, fmt.Sprintf("parseArgumentBytecode(0x%x, #lessOrEqualThan, 1)", code))
		require.NoError(t, err)
		require.EqualValues(t, code, concat(prefix, arg0, arg1))

	})
}
