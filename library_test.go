package easyfl

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"testing"

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
	}, "blake2b-test")
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
