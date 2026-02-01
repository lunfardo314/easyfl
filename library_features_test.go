package easyfl

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/lunfardo314/easyfl/easyfl_util"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"
)

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

func TestArityLiteral(t *testing.T) {
	lib := NewBaseLibrary[any]()

	t.Run("$$ with no args", func(t *testing.T) {
		// Test $$ with no arguments - returns 0 (empty varScope)
		ret, err := lib.EvalFromSource(nil, "$$")
		require.NoError(t, err)
		require.EqualValues(t, []byte{0}, ret)
	})

	t.Run("$$ in fixed-arg extended function", func(t *testing.T) {
		// Define an extended function that uses $$ but also references $0
		// This makes it a 1-arg function
		lib.extend("arityPlus", "concat($$, $0)")

		// Call with 1 argument - $$ should return 1
		ret, err := lib.EvalFromSource(nil, "arityPlus(0x42)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{1, 0x42}, ret)
	})

	t.Run("$$ in extended function with 2 args", func(t *testing.T) {
		// Define an extended function with 2 args
		lib.extend("arityConcat", "concat($$, $0, $1)")

		// Call with 2 arguments - $$ should return 2
		ret, err := lib.EvalFromSource(nil, "arityConcat(0x01, 0x02)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{2, 0x01, 0x02}, ret)
	})

	t.Run("$$ in extended function with 3 args nested", func(t *testing.T) {
		// Define an extended function with 3 args
		lib.extend("arityConcat3", "concat($$, $0, concat($1, $2))")

		// Call with 3 arguments - $$ should return 3
		ret, err := lib.EvalFromSource(nil, "arityConcat3(1, 2, 3)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{3, 1, 2, 3}, ret)
	})

	t.Run("$$ in extended function with 2 args nested", func(t *testing.T) {
		// Define an extended function with 2 args
		lib.extend("arityConcat2nested", "concat($$, $0, concat($1, $1))")

		// Call with 2 arguments - $$ should return 2
		ret, err := lib.EvalFromSource(nil, "arityConcat2nested(1, 2)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{2, 1, 2, 2}, ret)
	})

	t.Run("$$ compiles correctly", func(t *testing.T) {
		// Verify $$ compiles to the $$ function call
		_, numParams, code, err := lib.CompileExpression("$$")
		require.NoError(t, err)
		require.EqualValues(t, 0, numParams)
		t.Logf("$$ bytecode: %s", easyfl_util.Fmt(code))

		// Decompile should show "$$"
		src, err := lib.DecompileBytecode(code)
		require.NoError(t, err)
		require.EqualValues(t, "$$", src)
	})

	t.Run("$$ via EvalExpression directly", func(t *testing.T) {
		// Use EvalExpression directly to bypass the arg count check
		// This simulates what vararg functions will do
		f, _, _, err := lib.CompileExpression("$$")
		require.NoError(t, err)

		// With 3 args in varScope
		ret := EvalExpression[any](nil, f, []byte{1}, []byte{2}, []byte{3})
		require.EqualValues(t, []byte{3}, ret)

		// With 5 args in varScope
		ret = EvalExpression[any](nil, f, []byte{1}, []byte{2}, []byte{3}, []byte{4}, []byte{5})
		require.EqualValues(t, []byte{5}, ret)
	})
}

func TestVarargExtendedFunctions(t *testing.T) {
	lib := NewBaseLibrary[any]()

	t.Run("func_vararg parsing", func(t *testing.T) {
		// Test that func_vararg is correctly parsed
		err := lib.ExtendMany(`
func_vararg countArgs: $$
`)
		require.NoError(t, err)

		// Call with different numbers of arguments
		ret, err := lib.EvalFromSource(nil, "countArgs()")
		require.NoError(t, err)
		require.EqualValues(t, []byte{0}, ret)

		ret, err = lib.EvalFromSource(nil, "countArgs(1)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{1}, ret)

		ret, err = lib.EvalFromSource(nil, "countArgs(1, 2, 3)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{3}, ret)

		ret, err = lib.EvalFromSource(nil, "countArgs(1, 2, 3, 4, 5)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{5}, ret)
	})

	t.Run("vararg function returns first arg or nil", func(t *testing.T) {
		lib2 := NewBaseLibrary[any]()
		// Define a vararg function that returns the first arg if present, else nil
		// Note: $$ returns 0x00 when no args (which is truthy since non-empty),
		// so we need to use not(isZero($$)) to check if there are args
		err := lib2.ExtendMany(`
func_vararg firstOrNil: if(not(isZero($$)), $0, nil)
`)
		require.NoError(t, err)

		// With no args - returns nil (isZero(0x00) is true, so not() makes it false, we get nil)
		ret, err := lib2.EvalFromSource(nil, "firstOrNil()")
		require.NoError(t, err)
		require.EqualValues(t, []byte{}, ret)

		// With one arg - returns that arg
		ret, err = lib2.EvalFromSource(nil, "firstOrNil(0x42)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{0x42}, ret)

		// With multiple args - still returns first
		ret, err = lib2.EvalFromSource(nil, "firstOrNil(0xAB, 0xCD, 0xEF)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{0xAB}, ret)
	})

	t.Run("vararg sum function", func(t *testing.T) {
		lib3 := NewBaseLibrary[any]()
		// Define a vararg function that sums up to 4 arguments
		err := lib3.ExtendMany(`
func_vararg sum4: selectCaseByIndex($$,
   u64/0,
   uint8Bytes($0),
   add($0,$1),
   add($0,add($1,$2)),
   add(add($0,$1),add($2,$3))
)
`)
		require.NoError(t, err)

		// No args - returns 0
		ret, err := lib3.EvalFromSource(nil, "sum4()")
		require.NoError(t, err)
		require.EqualValues(t, make([]byte, 8), ret)

		// One arg
		ret, err = lib3.EvalFromSource(nil, "sum4(u64/5)")
		require.NoError(t, err)
		var expected [8]byte
		binary.BigEndian.PutUint64(expected[:], 5)
		require.EqualValues(t, expected[:], ret)

		// Two args: 10 + 20 = 30
		ret, err = lib3.EvalFromSource(nil, "sum4(u64/10, u64/20)")
		require.NoError(t, err)
		binary.BigEndian.PutUint64(expected[:], 30)
		require.EqualValues(t, expected[:], ret)

		// Three args: 1 + 2 + 3 = 6
		ret, err = lib3.EvalFromSource(nil, "sum4(u64/1, u64/2, u64/3)")
		require.NoError(t, err)
		binary.BigEndian.PutUint64(expected[:], 6)
		require.EqualValues(t, expected[:], ret)

		// Four args: 1 + 2 + 3 + 4 = 10
		ret, err = lib3.EvalFromSource(nil, "sum4(u64/1, u64/2, u64/3, u64/4)")
		require.NoError(t, err)
		binary.BigEndian.PutUint64(expected[:], 10)
		require.EqualValues(t, expected[:], ret)
	})

	t.Run("mixed func and func_vararg", func(t *testing.T) {
		lib4 := NewBaseLibrary[any]()
		// Test that both regular and vararg functions can coexist
		err := lib4.ExtendMany(`
func regular: concat($0, $1)
func_vararg varargFn: $$
`)
		require.NoError(t, err)

		// Regular function works as expected
		ret, err := lib4.EvalFromSource(nil, "regular(0x01, 0x02)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{0x01, 0x02}, ret)

		// Vararg function works as expected
		ret, err = lib4.EvalFromSource(nil, "varargFn(0x01, 0x02, 0x03)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{3}, ret)
	})

	t.Run("vararg accessing $i beyond arity panics", func(t *testing.T) {
		lib5 := NewBaseLibrary[any]()
		// Define a vararg function that unconditionally accesses $2
		err := lib5.ExtendMany(`
func_vararg needsThree: $2
`)
		require.NoError(t, err)

		// With 3+ args it should work
		ret, err := lib5.EvalFromSource(nil, "needsThree(0x01, 0x02, 0x03)")
		require.NoError(t, err)
		require.EqualValues(t, []byte{0x03}, ret)

		// With fewer args it should panic
		lib5.MustError("needsThree(0x01, 0x02)", "")
		lib5.MustError("needsThree(0x01)", "")
		lib5.MustError("needsThree()", "")
	})
}
