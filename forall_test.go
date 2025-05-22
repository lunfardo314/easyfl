package easyfl

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestForAll(t *testing.T) {
	lib := NewBaseLibrary()
	t.Run("1", func(t *testing.T) {
		_, _, code, err := lib.CompileExpression("$0")
		require.NoError(t, err)
		source := fmt.Sprintf("forAll(0, 0x%s)", hex.EncodeToString(code))
		lib.MustTrue(source)
	})
	t.Run("2", func(t *testing.T) {
		_, _, code, err := lib.CompileExpression("$0")
		require.NoError(t, err)
		source := fmt.Sprintf("forAll(concat(0,1,2,3,4), 0x%s)", hex.EncodeToString(code))
		lib.MustTrue(source)
	})
	t.Run("3", func(t *testing.T) {
		_, _, code, err := lib.CompileExpression("equal($0, 1)")
		require.NoError(t, err)
		source := fmt.Sprintf("forAll(concat(1,1,1,1), 0x%s)", hex.EncodeToString(code))
		lib.MustTrue(source)
		source = fmt.Sprintf("not(forAll(concat(2,1,1), 0x%s))", hex.EncodeToString(code))
		lib.MustTrue(source)
		source = fmt.Sprintf("not(forAll(concat(1,1,1,5), 0x%s))", hex.EncodeToString(code))
		lib.MustTrue(source)
		source = fmt.Sprintf("forAll(0x, 0x%s)", hex.EncodeToString(code))
		lib.MustTrue(source)
	})
	t.Run("4", func(t *testing.T) {
		_, _, code, err := lib.CompileExpression("equal($0, 1)")
		require.NoError(t, err)
		source := fmt.Sprintf("forAll(0x, 0x%s)", hex.EncodeToString(code))
		lib.MustTrue(source)
	})
	t.Run("5", func(t *testing.T) {
		_, _, code, err := lib.CompileExpression("isZero(mod($0, 2))")
		require.NoError(t, err)
		source := fmt.Sprintf("forAll(concat(2,4, 16, 96), 0x%s)", hex.EncodeToString(code))
		lib.MustTrue(source)
		source = fmt.Sprintf("not(forAll(concat(2,4, 99, 16, 96), 0x%s))", hex.EncodeToString(code))
		lib.MustTrue(source)
	})
	t.Run("range", func(t *testing.T) {
		lib.MustEqual("range(0, 7)", "concat(0, 1, 2, 3, 4, 5, 6, 7)")
		lib.MustEqual("range(5, 13)", "0x05060708090a0b0c0d")
		lib.MustEqual("range(13, 5)", "0x")
		lib.MustEqual("range(15, 15)", "0x0f")
	})
	t.Run("6", func(t *testing.T) {
		_, _, code, err := lib.CompileExpression("lessThan($0, 25)")
		require.NoError(t, err)
		source := fmt.Sprintf("forAll(range(5,24), 0x%s)", hex.EncodeToString(code))
		lib.MustTrue(source)
		source = fmt.Sprintf("not(forAll(range(10,255), 0x%s))", hex.EncodeToString(code))
		lib.MustTrue(source)
	})
	t.Run("inline 1", func(t *testing.T) {
		const srcExtend = "func _forAll : forAll($0, $$1)"
		err := lib.ExtendMany(srcExtend)
		require.NoError(t, err)

		res, err := lib.EvalFromSourceNoArgs(nil, "_forAll(range(5,24), lessThan($0, 25))")
		require.NoError(t, err)
		require.True(t, len(res) > 0)

		res, err = lib.EvalFromSourceNoArgs(nil, "_forAll(range(5,99), lessThan($0, 25))")
		require.NoError(t, err)
		require.True(t, len(res) == 0)
	})
	t.Run("inline 2", func(t *testing.T) {
		res, err := lib.EvalFromSourceNoArgs(nil, "forAll(range(5,24), bytecode(lessThan($0, 25)))")
		require.NoError(t, err)
		require.True(t, len(res) > 0)

		res, err = lib.EvalFromSourceNoArgs(nil, "forAll(range(5,99), bytecode(lessThan($0, 25)))")
		require.NoError(t, err)
		require.True(t, len(res) == 0)
	})
}

// TODO refactor eval function to varargs

func TestSumAll(t *testing.T) {
	lib := NewBaseLibrary()
	t.Run("1", func(t *testing.T) {
		const srcExtend = `
func sumAll0 :
if(
  equal(len($0), u64/0),
  u64/0,
  if(
     equal(len($0), u64/1),
     uint8Bytes(eval($$1)),
     0xffffffffffffffff
  )
)
`
		err := lib.ExtendMany(srcExtend)
		require.NoError(t, err)
	})
}

const forAllFiniteSource = `
// $0 range slice
// $1 function to evaluate
func forAllFinite :
or(
   // empty
  equal(len($0), u64/0),
  and(
     // 1 element
     equal(len($0), u64/1), 
     eval($1, $0)
  ),
  and(
  )
)
`

func TestForAllExtended(t *testing.T) {
	lib := NewBaseLibrary()
	lib.MustExtendMany(forAllFiniteSource)
}
