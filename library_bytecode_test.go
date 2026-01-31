package easyfl

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/lunfardo314/easyfl/easyfl_util"
	"github.com/stretchr/testify/require"
)

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

	src2 = fmt.Sprintf("parseInlineDataArgument(0x%s, 0)", hex.EncodeToString(bytecode))
	lib.MustEqual(src2, "1")
	src2 = fmt.Sprintf("parseInlineDataArgument(0x%s, 0, #or)", hex.EncodeToString(bytecode))
	lib.MustEqual(src2, "1")
	src2 = fmt.Sprintf("parseInlineDataArgument(0x%s, 0, #add)", hex.EncodeToString(bytecode))
	lib.MustError(src2, "unexpected call prefix 'or'")

	src2 = fmt.Sprintf("parseInlineDataArgument(0x%s, 1)", hex.EncodeToString(bytecode))
	lib.MustEqual(src2, "2")
	src2 = fmt.Sprintf("parseInlineDataArgument(0x%s, 1, #sub, #and, #or)", hex.EncodeToString(bytecode))
	lib.MustEqual(src2, "2")
	src2 = fmt.Sprintf("parseInlineDataArgument(0x%s, 1, #sub)", hex.EncodeToString(bytecode))
	lib.MustError(src2, "unexpected call prefix 'or'")

	src2 = fmt.Sprintf("parseInlineDataArgument(0x%s, 3)", hex.EncodeToString(bytecode))
	lib.MustEqual(src2, "4")
}
