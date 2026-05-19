package embed

import (
	"bytes"
	"encoding/binary"
	"math"

	"github.com/lunfardo314/easyfl/engine"
	"github.com/lunfardo314/easyfl/easyfl_util"
	"github.com/lunfardo314/easyfl/slicepool"
	"github.com/lunfardo314/easyfl/tuples"
)

// list of standard embedded functions
// TODO
//  - certain function could be optimized.
//  - do we need short end long embedding?

func unboundEmbeddedFunctions[T any]() map[string]engine.EmbeddedFunction[T] {
	return map[string]engine.EmbeddedFunction[T]{
		// short base
		"evalArity":     evalArity[T],
		"evalFail":      evalFail[T],
		"evalSlice":     evalSlice[T],
		"evalByte":      evalByte[T],
		"evalTail":      evalTail[T],
		"evalEqual":     evalEqual[T],
		"evalHasPrefix": evalHasPrefix[T],
		"evalLen":       evalLen[T],
		"evalNot":       evalNot[T],
		"evalIf":        evalIf[T],
		"evalIsZero":    evalIsZero[T],
		// long base
		"evalConcat":            evalConcat[T],
		"evalAnd":               evalAnd[T],
		"evalOr":                evalOr[T],
		"evalRepeat":            evalRepeat[T],
		"evalFirstCaseIndex":    evalFirstCaseIndex[T],
		"evalFirstEqualIndex":   evalFirstEqualIndex[T],
		"evalSelectCaseByIndex": evalSelectCaseByIndex[T],
		// arithmetics short
		"evalAddUint":    evalAddUint[T],
		"evalSubUint":    evalSubUint[T],
		"evalMulUint":    evalMulUint[T],
		"evalDivUint":    evalDivUint[T],
		"evalModuloUint": evalModuloUint[T],
		"evalUint8Bytes": evalUint8Bytes[T],
		// bitwise and compare short
		"evalLessThan":   evalLessThan[T],
		"evalBitwiseOR":  evalBitwiseOR[T],
		"evalBitwiseAND": evalBitwiseAND[T],
		"evalBitwiseNOT": evalBitwiseNOT[T],
		"evalBitwiseXOR": evalBitwiseXOR[T],
		// bitwise long
		"evalLShift64": evalLShift64[T],
		"evalRShift64": evalRShift64[T],
		// tuples
		"evalAtTuple8": evalAtTuple8[T],
		"evalTupleLen": evalNumElementsOfTuple[T],
	}
}
func Resolver[T any](targetLib *engine.Library[T]) func(sym string) engine.EmbeddedFunction[T] {
	embTyped := unboundEmbeddedFunctions[T]()
	return func(sym string) engine.EmbeddedFunction[T] {
		if ret, found := embTyped[sym]; found {
			return ret
		}
		// function bound to a particular target library
		switch sym {
		case "evalParseBytecode":
			return targetLib.EvalParseBytecode
		case "evalParseInlineData":
			return targetLib.EvalParseInlineData
		case "evalParseInlineDataArgument":
			return targetLib.EvalParseInlineDataArgument
		case "evalParseNumArgs":
			return targetLib.EvalParseNumArgs
		}
		return nil
	}
}

// -----------------------------------------------------------------

// evalArity returns the number of arguments in the enclosing function's var scope.
// This is the embedded function for the $$ literal.
func evalArity[T any](par *engine.CallParams[T]) []byte {
	arity := par.VarScopeArity()
	return par.AllocData(arity)
}

func evalFail[T any](par *engine.CallParams[T]) []byte {
	c := par.Arg(0)
	if len(c) == 1 {
		par.TracePanic("SCRIPT FAIL: error #%d", c[0])
	}
	par.TracePanic("SCRIPT FAIL: '%s'", string(c))
	return nil
}

// slices first argument 'from' 'to' inclusive 'to'
func evalSlice[T any](par *engine.CallParams[T]) []byte {
	data := par.Arg(0)
	from := par.Arg(1)
	to := par.Arg(2)
	if len(from) != 1 || len(to) != 1 {
		par.TracePanic("slice:: data: %s, from: %s, to: %s -- wrong bound values", easyfl_util.FmtLazy(data), easyfl_util.FmtLazy(from), easyfl_util.FmtLazy(to))
	}
	if from[0] > to[0] {
		par.TracePanic("slice:: data: %s, from: %s, to: %s -- wrong slice bounds. ", easyfl_util.Fmt(data), easyfl_util.Fmt(from), easyfl_util.Fmt(to))
	}
	upper := int(to[0]) + 1
	if upper > len(data) {
		par.TracePanic("slice:: data: %s, from: %s, to: %s -- slice out of bounds. ", easyfl_util.Fmt(data), easyfl_util.Fmt(from), easyfl_util.Fmt(to))
	}
	ret := data[from[0]:upper]
	return ret
}

func evalByte[T any](par *engine.CallParams[T]) []byte {
	data := par.Arg(0)
	idx := par.Arg(1)
	if len(idx) != 1 || int(idx[0]) >= len(data) {
		par.TracePanic("byte:: data: %s, idx: %s -- wrong index value", easyfl_util.FmtLazy(data), easyfl_util.FmtLazy(idx))
	}
	ret := data[idx[0] : idx[0]+1]
	return ret
}

func evalTail[T any](par *engine.CallParams[T]) []byte {
	data := par.Arg(0)
	from := par.Arg(1)
	if len(from) != 1 || int(from[0]) >= len(data) {
		par.TracePanic("tail:: data: %s, from: %s -- index out of bounds. ", easyfl_util.FmtLazy(data), easyfl_util.FmtLazy(from))
	}
	ret := data[from[0]:]
	return ret
}

func evalEqual[T any](par *engine.CallParams[T]) []byte {
	var ret []byte
	p0 := par.Arg(0)
	p1 := par.Arg(1)
	if bytes.Equal(p0, p1) {
		ret = par.AllocData(0xff)
	}
	return ret
}

func evalHasPrefix[T any](par *engine.CallParams[T]) []byte {
	var ret []byte
	data := par.Arg(0)
	prefix := par.Arg(1)
	if bytes.HasPrefix(data, prefix) {
		ret = par.AllocData(0xff)
	}
	return ret
}

func evalRepeat[T any](par *engine.CallParams[T]) []byte {
	fragment := par.Arg(0)
	n := par.Arg(1)
	if len(n) != 1 {
		par.TracePanic("evalRepeat: count must be 1-byte long")
	}
	ret := par.AllocData(bytes.Repeat(fragment, int(n[0]))...)
	return ret
}

func evalLen[T any](par *engine.CallParams[T]) []byte {
	data := par.Arg(0)
	ret := par.Alloc(8)
	binary.BigEndian.PutUint64(ret, uint64(len(data)))
	return ret
}

func evalIf[T any](par *engine.CallParams[T]) []byte {
	cond := par.Arg(0)
	if len(cond) != 0 {
		yes := par.Arg(1)
		return yes
	}
	no := par.Arg(2)
	return no
}

// evalFirstCaseIndex evaluates and returns first argument with not-nil value
func evalFirstCaseIndex[T any](par *engine.CallParams[T]) []byte {
	for i := byte(0); i < par.Arity(); i++ {
		if c := par.Arg(i); len(c) > 0 {
			return par.AllocData(i)
		}
	}
	return nil
}

func evalFirstEqualIndex[T any](par *engine.CallParams[T]) []byte {
	if par.Arity() == 0 {
		return nil
	}

	v := par.Arg(0)
	for i := byte(1); i < par.Arity(); i++ {
		if bytes.Equal(v, par.Arg(i)) {
			return par.AllocData(i - 1)
		}
	}
	return nil
}

func evalSelectCaseByIndex[T any](par *engine.CallParams[T]) []byte {
	if par.Arity() == 0 {
		par.TracePanic("evalSelectCaseByIndex: must be at least 1 argument")
	}
	idx, err := easyfl_util.Uint64FromBytes(par.Arg(0))
	if err != nil {
		par.TracePanic("evalSelectCaseByIndex: invalid argument")
		return nil
	}
	if byte(idx)+1 >= par.Arity() {
		return nil
	}
	return par.Arg(byte(idx) + 1)
}

func evalIsZero[T any](par *engine.CallParams[T]) []byte {
	arg := par.Arg(0)
	if easyfl_util.IsZero(arg) {
		return par.AllocData(0xff)
	}
	return nil
}

func evalNot[T any](par *engine.CallParams[T]) []byte {
	arg := par.Arg(0)
	if len(arg) == 0 {
		return par.AllocData(0xff)
	}
	return nil
}

func evalConcat[T any](par *engine.CallParams[T]) []byte {
	var args [engine.MaxParameters][]byte
	a := args[:par.Arity()]
	totalSize := 0
	for i := range a {
		a[i] = par.Arg(byte(i))
		totalSize += len(a[i])
	}

	ret := par.Alloc(uint16(totalSize))[:0]
	for i := range a {
		ret = append(ret, a[i]...)
	}
	return ret
}

func evalAnd[T any](par *engine.CallParams[T]) []byte {
	for i := byte(0); i < par.Arity(); i++ {
		if len(par.Arg(i)) == 0 {
			return nil
		}
	}
	return par.AllocData(0xff)
}

func evalOr[T any](par *engine.CallParams[T]) []byte {
	for i := byte(0); i < par.Arity(); i++ {
		if len(par.Arg(i)) != 0 {
			return par.AllocData(0xff)
		}
	}
	return nil
}

func ensure8Bytes(spool *slicepool.SlicePool, data []byte) ([]byte, bool) {
	if len(data) == 8 {
		return data, true
	}
	if len(data) > 8 {
		return nil, false
	}
	ret := spool.Alloc(8)
	copy(ret[8-len(data):], data)
	return ret, true
}

// Must2ArithmeticOperands makes uint64 from both params (big-endian)
// Parameters must have with size <= 8. They are padded with 0 in upper bytes, if necessary
func Must2ArithmeticOperands[T any](par *engine.CallParams[T], name string) (op0 uint64, op1 uint64) {
	var err error
	a0 := par.Arg(0)
	if op0, err = easyfl_util.Uint64FromBytes(a0); err != nil {
		par.TracePanic("%s::Must2ArithmeticOperands op0=%s", name, easyfl_util.Fmt(a0))
		return
	}
	a1 := par.Arg(1)
	if op1, err = easyfl_util.Uint64FromBytes(a1); err != nil {
		par.TracePanic("%s::Must2ArithmeticOperands op0=%s", name, easyfl_util.Fmt(a1))
		return
	}
	return
}

func evalAddUint[T any](par *engine.CallParams[T]) []byte {
	a0, a1 := Must2ArithmeticOperands(par, "addUint")
	if a0 > math.MaxUint64-a1 {
		par.TracePanic("evalAddUint:: %d + %d -> overflow in addition", a0, a1)
	}
	ret := par.Alloc(8)
	binary.BigEndian.PutUint64(ret, a0+a1)
	return ret
}

func evalSubUint[T any](par *engine.CallParams[T]) []byte {
	a0, a1 := Must2ArithmeticOperands(par, "subUint")
	if a0 < a1 {
		par.TracePanic("evalSubUint:: %d - %d -> underflow in subtraction", a0, a1)
	}
	ret := par.Alloc(8)
	binary.BigEndian.PutUint64(ret, a0-a1)
	return ret
}

func evalMulUint[T any](par *engine.CallParams[T]) []byte {
	a0, a1 := Must2ArithmeticOperands(par, "mulUint")
	if a0 == 0 || a1 == 0 {
		return par.Alloc(8)
	}
	if a0 > math.MaxUint64/a1-1 {
		par.TracePanic("evalMulUint:: %d * %d -> overflow in multiplication", a0, a1)
	}
	ret := par.Alloc(8)
	binary.BigEndian.PutUint64(ret, a0*a1)
	return ret
}

func evalDivUint[T any](par *engine.CallParams[T]) []byte {
	a0, a1 := Must2ArithmeticOperands(par, "divUint")
	if a1 == 0 {
		par.TracePanic("evalDivUint:: %d / %d -> divide by zero", a0, a1)
	}
	ret := par.Alloc(8)
	binary.BigEndian.PutUint64(ret, a0/a1)
	return ret
}

func evalModuloUint[T any](par *engine.CallParams[T]) []byte {
	a0, a1 := Must2ArithmeticOperands(par, "moduloUint")
	if a1 == 0 {
		par.TracePanic("evalModuloUint:: %d / %d -> divide by zero", a0, a1)
	}
	ret := par.Alloc(8)
	binary.BigEndian.PutUint64(ret, a0%a1)
	return ret
}

func evalUint8Bytes[T any](par *engine.CallParams[T]) []byte {
	ret, ok := ensure8Bytes(par.Spool(), par.Arg(0))
	if !ok {
		par.TracePanic("%s:: wrong size of parameter", "uint64Bytes")
	}
	return ret
}

// lexicographical comparison of two slices of equal length
func evalLessThan[T any](par *engine.CallParams[T]) []byte {
	a0 := par.Arg(0)
	a1 := par.Arg(1)

	if len(a0) != len(a1) {
		par.TracePanic("lessThan: operands must be equal length. %s, %s", easyfl_util.FmtLazy(a0), easyfl_util.FmtLazy(a1))
	}
	for i := range a0 {
		switch {
		case a0[i] < a1[i]:
			return par.AllocData(0xff) // true
		case a0[i] > a1[i]:
			return nil //false
		}
	}
	return nil // equal -> false
}

func evalBitwiseAND[T any](par *engine.CallParams[T]) []byte {
	a0 := par.Arg(0)
	a1 := par.Arg(1)
	if len(a0) != len(a1) {
		par.TracePanic("evalBitwiseAND: equal length arguments expected: %s -- %s", easyfl_util.FmtLazy(a0), easyfl_util.FmtLazy(a1))
	}
	ret := par.Alloc(uint16(len(a0))) // true

	for i := range a0 {
		ret[i] = a0[i] & a1[i]
	}
	return ret
}

func evalBitwiseOR[T any](par *engine.CallParams[T]) []byte {
	a0 := par.Arg(0)
	a1 := par.Arg(1)
	if len(a0) != len(a1) {
		par.TracePanic("evalBitwiseOR: equal length arguments expected: %s -- %s", easyfl_util.FmtLazy(a0), easyfl_util.FmtLazy(a1))
	}
	ret := par.Alloc(uint16(len(a0))) // true
	for i := range a0 {
		ret[i] = a0[i] | a1[i]
	}
	return ret
}

func evalBitwiseXOR[T any](par *engine.CallParams[T]) []byte {
	a0 := par.Arg(0)
	a1 := par.Arg(1)
	if len(a0) != len(a1) {
		par.TracePanic("evalBitwiseXOR: equal length arguments expected: %s -- %s", easyfl_util.FmtLazy(a0), easyfl_util.FmtLazy(a1))
	}
	ret := par.Alloc(uint16(len(a0))) // true
	for i := range a0 {
		ret[i] = a0[i] ^ a1[i]
	}
	return ret
}

func evalBitwiseNOT[T any](par *engine.CallParams[T]) []byte {
	a0 := par.Arg(0)
	ret := par.Alloc(uint16(len(a0))) // true
	for i := range a0 {
		ret[i] = ^a0[i]
	}
	return ret
}

func evalLShift64[T any](par *engine.CallParams[T]) []byte {
	a0, a1 := Must2ArithmeticOperands(par, "lshift64")
	ret := par.Alloc(8) // true
	binary.BigEndian.PutUint64(ret, a0<<a1)
	return ret
}

func evalRShift64[T any](par *engine.CallParams[T]) []byte {
	a0, a1 := Must2ArithmeticOperands(par, "lshift64")
	ret := par.Alloc(8) // true
	binary.BigEndian.PutUint64(ret, a0>>a1)
	return ret
}

func evalAtTuple8[T any](par *engine.CallParams[T]) []byte {
	arr, err := tuples.TupleFromBytes(par.Arg(0))
	if err != nil {
		par.TracePanic("evalAtTuple8: %v", err)
	}
	idx := par.Arg(1)
	if len(idx) != 1 {
		par.TracePanic("evalAtTuple8: 1-byte value expected")
	}
	ret, err := arr.At(int(idx[0]))
	if err != nil {
		par.TracePanic("evalAtTuple8: %v", err)
	}
	return ret
}

func evalNumElementsOfTuple[T any](par *engine.CallParams[T]) []byte {
	arr, err := tuples.TupleFromBytes(par.Arg(0))
	if err != nil {
		par.TracePanic("evalNumElementsOfTuple: %v", err)
	}
	ret := par.Alloc(8)
	binary.BigEndian.PutUint64(ret, uint64(arr.NumElements()))
	return ret
}

