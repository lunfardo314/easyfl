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
func split2Prefix : slice($0, 0, div(len($0),2))
func split2Suffix : tail($0, add(div(len($0),2),1))

// $0 - elements
// $1 predicate bytecode
func forAll4 :
or(
   // empty
  equal(len($0), u64/0),
  and(
     // 1 element
     equal(len($0), u64/1), 
     eval($1, $0)
  ),
  and(
     // 2 elements
     equal(len($0), u64/2), 
     eval($1, byte($0,0)),
     eval($1, byte($0,1))
  ),
  and(
     // 3 elements
     equal(len($0), u64/3), 
     eval($1, byte($0,0)),
     eval($1, byte($0,1)),
     eval($1, byte($0,2))
  ),
  and(
     // 4 elements
     equal(len($0), u64/4), 
     eval($1, byte($0,0)),
     eval($1, byte($0,1)),
     eval($1, byte($0,2)),
     eval($1, byte($0,3))
  ),
  !!!forAllUpTo4_no_more_4_elements
)

// up to 8 elements
func forAllFinite6 :
if(
  lessOrEqualThan(len($0), u64/4),
  forAll4($0, $1),
  and(
    forAll4(split2Prefix($0), $1),
    forAll4(split2Suffix($0), $1),
  )
)

// up to 16 elements
func forAllFinite5 :
if(
  lessOrEqualThan(len($0), u64/4),
  forAll4($0, $1),
  and(
    forAllFinite6(split2Prefix($0), $1),
    forAllFinite6(split2Suffix($0), $1),
  )
)

// up to 32 elements
func forAllFinite4 :
if(
  lessOrEqualThan(len($0), u64/4),
  forAll4($0, $1),
  and(
    forAllFinite5(split2Prefix($0), $1),
    forAllFinite5(split2Suffix($0), $1),
  )
)

// up to 64 elements
func forAllFinite3 :
if(
  lessOrEqualThan(len($0), u64/4),
  forAll4($0, $1),
  and(
    forAllFinite4(split2Prefix($0), $1),
    forAllFinite4(split2Suffix($0), $1),
  )
)

// up to 128 elements
func forAllFinite2 :
if(
  lessOrEqualThan(len($0), u64/4),
  forAll4($0, $1),
  and(
    forAllFinite3(split2Prefix($0), $1),
    forAllFinite3(split2Suffix($0), $1),
  )
)

// up to 256 elements
func forAllFinite1 :
if(
  lessOrEqualThan(len($0), u64/4),
  forAll4($0, $1),
  and(
    forAllFinite2(split2Prefix($0), $1),
    forAllFinite2(split2Suffix($0), $1),
  )
)

// $0 range slice
// $1 function to evaluate
func forAllFinite : 
and(
   require(lessOrEqualThan(len($0), u64/256), !!!forAllFinite_no_more_256_elements),
   forAllFinite1($0, $1)
)
`

func TestForAllExtended(t *testing.T) {
	lib := NewBaseLibrary()
	lib.MustExtendMany(forAllFiniteSource)

	lib.MustTrue("forAllFinite(0x,0x)")
	lib.MustTrue("forAllFinite(0x,1)")
	_, _, code, err := lib.CompileExpression("equal($0,1)")
	require.NoError(t, err)
	lib.MustTrue("forAllFinite(1,0x%s)", hex.EncodeToString(code))
	_, _, code, err = lib.CompileExpression("isZero(div($0,2))")
	require.NoError(t, err)
	lib.MustTrue("forAllFinite(0x02040610,0x%s)", hex.EncodeToString(code))
}
