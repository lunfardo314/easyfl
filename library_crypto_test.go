package easyfl

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/lunfardo314/easyfl/easyfl_util"
	"github.com/stretchr/testify/require"
)

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
		}, "prn")
		tr := lib.NewGlobalDataTracePrint(nil)
		res, err := lib.EvalFromSource(tr, "c6(c6(prn))")
		require.NoError(t, err)
		require.EqualValues(t, bytes.Repeat([]byte{1}, 36), res)
		require.EqualValues(t, 1, counter)
	})
}
