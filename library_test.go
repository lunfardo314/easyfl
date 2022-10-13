package easyfl

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/lunfardo314/easyutxo"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
)

const formula1 = "func unlockBlock: concat(concat(0x0000, slice(0x01020304050607, 2, 5)))"

func TestCompile(t *testing.T) {
	t.Run("1", func(t *testing.T) {
		ret, err := ParseFunctions(formula1)
		require.NoError(t, err)
		require.NotNil(t, ret)
	})
	t.Run("3", func(t *testing.T) {
		ret, err := ParseFunctions(formula1)
		require.NoError(t, err)
		require.EqualValues(t, 1, len(ret))

		code, numParams, err := ExpressionSourceToBinary(ret[0].SourceCode)
		require.NoError(t, err)
		require.EqualValues(t, 0, numParams)
		t.Logf("code len: %d", len(code))
	})
	t.Run("4", func(t *testing.T) {
		parsed, err := ParseFunctions(formula1)
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
		ret, err := EvalFromSource(nil, "if(equal(len8($0),3), 0x01, 0x05)", []byte("abc"))
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
		ret, err := EvalFromSource(nil, longer, []byte("abcdef"))
		require.NoError(t, err)
		require.EqualValues(t, []byte{1}, ret)
	})
	t.Run("14", func(t *testing.T) {
		ret, err := EvalFromSource(nil, longer, []byte("abcde"))
		require.NoError(t, err)
		require.EqualValues(t, []byte{5, 6}, ret)
	})
	t.Run("15", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "nil")
		require.NoError(t, err)
		require.True(t, len(ret) == 0)
	})
	t.Run("16", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "concat")
		require.NoError(t, err)
		require.True(t, len(ret) == 0)
	})
	t.Run("17", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "u16/256")
		require.NoError(t, err)
		require.EqualValues(t, []byte{1, 0}, ret)
	})
	t.Run("18", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "u32/70000")
		require.NoError(t, err)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], 70000)
		require.EqualValues(t, b[:], ret)
	})
	t.Run("19", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "u64/10000000000")
		require.NoError(t, err)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], 10000000000)
		require.EqualValues(t, b[:], ret)
	})
	t.Run("20", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "isZero(0x000000)")
		require.NoError(t, err)
		require.True(t, len(ret) != 0)
	})
	t.Run("21", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "isZero(0x003000)")
		require.NoError(t, err)
		require.True(t, len(ret) == 0)
	})
	t.Run("21", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "sum8_16($0, $1)", []byte{160}, []byte{160})
		require.NoError(t, err)
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], 320)
		require.EqualValues(t, b[:], ret)
	})
	t.Run("22", func(t *testing.T) {
		_, err := EvalFromSource(nil, "sum8($0, $1)", []byte{160}, []byte{160})
		easyutxo.RequireErrorWith(t, err, "arithmetic overflow")
	})
	var blake2bInvokedNum int
	EmbedLong("blake2b-test", 1, func(par *CallParams) []byte {
		h := blake2b.Sum256(par.Arg(0))
		blake2bInvokedNum++
		return h[:]
	})
	t.Run("23", func(t *testing.T) {
		blake2bInvokedNum = 0
		ret, err := EvalFromSource(nil, "blake2b-test($0)", []byte{1, 2, 3})
		require.NoError(t, err)
		h := blake2b.Sum256([]byte{0x01, 0x02, 0x03})
		require.EqualValues(t, h[:], ret)
		require.EqualValues(t, blake2bInvokedNum, 1)

		ret, err = EvalFromSource(nil, "blake2b-test($0)", nil)
		require.NoError(t, err)
		h = blake2b.Sum256(nil)
		require.EqualValues(t, h[:], ret)
		require.EqualValues(t, blake2bInvokedNum, 2)
	})
	t.Run("24", func(t *testing.T) {
		blake2bInvokedNum = 0
		h2 := blake2b.Sum256([]byte{2})
		h3 := blake2b.Sum256([]byte{3})

		ret, err := EvalFromSource(nil, "if($0,blake2b-test($1),blake2b-test($2))",
			[]byte{1}, []byte{2}, []byte{3})
		require.NoError(t, err)
		require.EqualValues(t, h2[:], ret)
		require.EqualValues(t, blake2bInvokedNum, 1)

		ret, err = EvalFromSource(nil, "if($0,blake2b-test($1),blake2b-test($2))",
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
		ret, err := EvalFromSource(nil, "cat2(1,2)")
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
		c0 := easyutxo.Concat(d0, d1)
		c1 := easyutxo.Concat(d0, d2)
		c3 := easyutxo.Concat(c0, c1)
		return c3
	}
	t.Run("ext-4", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "complex(0,1,2)")
		require.NoError(t, err)
		require.EqualValues(t, compl(d(0), d(1), d(2)), ret)
	})
	t.Run("ext-5", func(t *testing.T) {
		ret, err := EvalFromSource(nil, "complex(0,1,complex(2,1,0))")
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
		ret, err := EvalFromBinary(nil, code, []byte{1}, []byte{2}, []byte{3})
		require.NoError(t, err)
		require.EqualValues(t, []byte{3, 2, 1}, ret)
	})
	t.Run("always panics", func(t *testing.T) {
		_, err := EvalFromSource(nil, "byte(0,1)")
		require.Error(t, err)
	})
	t.Run("never panics", func(t *testing.T) {
		_, err := EvalFromSource(nil, "if(concat,byte(0,1),0x01)")
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
		ret, err := EvalFromSource(nil, s, a0, a1)
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
		res, err := EvalFromSource(nil, "validSignatureED25519($0,$1,$2)", []byte(msg), signature, pubKey)
		require.NoError(t, err)

		require.True(t, len(res) > 0)
	})
	t.Run("validSignatureED25519-wrong-msg", func(t *testing.T) {
		signature := ed25519.Sign(privKey, []byte(msg))
		res, err := EvalFromSource(nil, "validSignatureED25519($0,$1,$2)", []byte(msg+"klmn"), signature, pubKey)
		require.NoError(t, err)

		require.True(t, len(res) == 0)
	})
	t.Run("validSignatureED25519-wrong-sig", func(t *testing.T) {
		signature := ed25519.Sign(privKey, []byte(msg))
		signature[5]++
		res, err := EvalFromSource(nil, "validSignatureED25519($0,$1,$2)", []byte(msg), signature, pubKey)
		require.NoError(t, err)

		require.True(t, len(res) == 0)
	})
	t.Run("validSignatureED25519-wrong-pubkey", func(t *testing.T) {
		signature := ed25519.Sign(privKey, []byte(msg))
		pk := easyutxo.Concat([]byte(pubKey))
		pk[3]++
		res, err := EvalFromSource(nil, "validSignatureED25519($0,$1,$2)", []byte(msg), signature, pk)
		require.NoError(t, err)

		require.True(t, len(res) == 0)
	})
	t.Run("validSignatureED25519-wrong-pubkey", func(t *testing.T) {
		_, err := EvalFromSource(nil, "validSignatureED25519($0,$1,$2)", nil, nil, nil)
		easyutxo.RequireErrorWith(t, err, "bad public key length")
	})
}
