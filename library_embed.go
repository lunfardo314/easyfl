package easyfl

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"math"
	"reflect"

	"github.com/lunfardo314/easyfl/easyfl_util"
	"github.com/lunfardo314/easyfl/slicepool"
	"github.com/lunfardo314/easyfl/tuples"
	"golang.org/x/crypto/blake2b"
)

// list of standard embedded functions
// TODO
//  - certain function could be optimized.
//  - do we need short end long embedding?

var unboundEmbeddedFunctions = map[string]EmbeddedFunction{
	// short base
	"fail":      evalFail,
	"slice":     evalSlice,
	"byte":      evalByte,
	"tail":      evalTail,
	"equal":     evalEqual,
	"hasPrefix": evalHasPrefix,
	"len":       evalLen,
	"not":       evalNot,
	"if":        evalIf,
	"isZero":    evalIsZero,
	// long base
	"concat":            evalConcat,
	"and":               evalAnd,
	"or":                evalOr,
	"repeat":            evalRepeat,
	"firstCaseIndex":    evalFirstCaseIndex,
	"firstEqualIndex":   evalFirstEqualIndex,
	"selectCaseByIndex": evalSelectCaseByIndex,
	// arithmetics short
	"add":        evalAddUint,
	"sub":        evalSubUint,
	"mul":        evalMulUint,
	"div":        evalDivUint,
	"mod":        evalModuloUint,
	"uint8Bytes": evalUint8Bytes,
	// bitwise and compare short
	"lessThan":   evalLessThan,
	"bitwiseOR":  evalBitwiseOR,
	"bitwiseAND": evalBitwiseAND,
	"bitwiseNOT": evalBitwiseNOT,
	"bitwiseXOR": evalBitwiseXOR,
	// bitwise long
	"lshift64": evalLShift64,
	"rshift64": evalRShift64,
	// base crypto
	"validSignatureED25519": evalValidSigED25519,
	"blake2b":               evalBlake2b,
	// tuples
	"atTuple8": evalAtTuple8,
	"tupleLen": evalNumElementsOfTuple,
}

func EmbeddedFunctions(targetLib *Library) func(sym string) EmbeddedFunction {
	return func(sym string) EmbeddedFunction {
		if ret, found := unboundEmbeddedFunctions[sym]; found {
			return ret
		}
		// function bound to a particular target library
		switch sym {
		case "parseArgumentBytecode":
			return targetLib.evalParseArgumentBytecode
		case "parsePrefixBytecode":
			return targetLib.evalParsePrefixBytecode
		case "parseInlineData":
			return targetLib.evalParseInlineData
		case "callLocalLibrary":
			return targetLib.evalCallLocalLibrary
		}
		return nil
	}
}

// evalCallLocalLibrary not tested here, only in Proxima
func (lib *Library) evalCallLocalLibrary(ctx *CallParams) []byte {
	// arg 0 - local library binary (as a lazy array)
	// arg 1 - 1-byte index of then function in the library
	// arg 2 ... arg 15 optional arguments
	arr, err := tuples.TupleFromBytes(ctx.Arg(0))
	if err != nil {
		ctx.TracePanic("evalCallLocalLibrary: %v", err)
	}
	libData := arr.Parsed()
	idx := ctx.Arg(1)
	if len(idx) != 1 || int(idx[0]) >= len(libData) {
		ctx.TracePanic("evalCallLocalLibrary: wrong function index")
	}
	ret := lib.CallLocalLibrary(ctx.Slice(2, ctx.Arity()), libData, int(idx[0]))
	ctx.Trace("evalCallLocalLibrary: lib#%d -> 0x%s", idx[0], hex.EncodeToString(ret))
	return ret
}

// -----------------------------------------------------------------

func isNil(p interface{}) bool {
	return p == nil || (reflect.ValueOf(p).Kind() == reflect.Ptr && reflect.ValueOf(p).IsNil())
}

func evalFail(par *CallParams) []byte {
	c := par.Arg(0)
	if len(c) == 1 {
		par.TracePanic("SCRIPT FAIL: error #%d", c[0])
	}
	par.TracePanic("SCRIPT FAIL: '%s'", string(c))
	return nil
}

// slices first argument 'from' 'to' inclusive 'to'
func evalSlice(par *CallParams) []byte {
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
	par.Trace("slice:: data: %s, from: %s, to: %s -> %s", easyfl_util.FmtLazy(data), easyfl_util.FmtLazy(from), easyfl_util.FmtLazy(to), easyfl_util.FmtLazy(ret))
	return ret
}

func evalByte(par *CallParams) []byte {
	data := par.Arg(0)
	idx := par.Arg(1)
	if len(idx) != 1 || int(idx[0]) >= len(data) {
		par.TracePanic("byte:: data: %s, idx: %s -- wrong index value", easyfl_util.FmtLazy(data), easyfl_util.FmtLazy(idx))
	}
	ret := data[idx[0] : idx[0]+1]
	par.Trace("byte:: data: %s, idx: %s -> %s", easyfl_util.FmtLazy(data), easyfl_util.FmtLazy(idx), easyfl_util.FmtLazy(ret))
	return ret
}

func evalTail(par *CallParams) []byte {
	data := par.Arg(0)
	from := par.Arg(1)
	if len(from) != 1 || int(from[0]) >= len(data) {
		par.TracePanic("tail:: data: %s, from: %s -- index out of bounds. ", easyfl_util.FmtLazy(data), easyfl_util.FmtLazy(from))
	}
	ret := data[from[0]:]
	par.Trace("tail:: data: %s, from: %s -> %s", easyfl_util.FmtLazy(data), easyfl_util.FmtLazy(from), easyfl_util.FmtLazy(ret))
	return ret
}

func evalEqual(par *CallParams) []byte {
	var ret []byte
	p0 := par.Arg(0)
	p1 := par.Arg(1)
	if bytes.Equal(p0, p1) {
		ret = par.AllocData(0xff)
	}
	par.Trace("equal:: %s, %s -> %s", easyfl_util.FmtLazy(p0), easyfl_util.FmtLazy(p1), easyfl_util.FmtLazy(ret))
	return ret
}

func evalHasPrefix(par *CallParams) []byte {
	var ret []byte
	data := par.Arg(0)
	prefix := par.Arg(1)
	if bytes.HasPrefix(data, prefix) {
		ret = par.AllocData(0xff)
	}
	par.Trace("hasPrefix:: %s, %s -> %s", easyfl_util.FmtLazy(data), easyfl_util.FmtLazy(prefix), easyfl_util.FmtLazy(ret))
	return ret
}

func evalRepeat(par *CallParams) []byte {
	fragment := par.Arg(0)
	n := par.Arg(1)
	if len(n) != 1 {
		par.TracePanic("evalRepeat: count must be 1-byte long")
	}
	ret := bytes.Repeat(fragment, int(n[0]))
	par.Trace("hasPrefix:: %s, %s -> %s", easyfl_util.FmtLazy(fragment), easyfl_util.FmtLazy(n), easyfl_util.FmtLazy(ret))
	return ret
}

func evalLen(par *CallParams) []byte {
	data := par.Arg(0)
	ret := par.Alloc(8)
	binary.BigEndian.PutUint64(ret, uint64(len(data)))
	par.Trace("len:: %s -> %s", easyfl_util.FmtLazy(data), easyfl_util.FmtLazy(ret[:]))
	return ret[:]
}

func evalIf(par *CallParams) []byte {
	cond := par.Arg(0)
	if len(cond) != 0 {
		yes := par.Arg(1)
		par.Trace("if:: %s -> %s", easyfl_util.FmtLazy(cond), easyfl_util.FmtLazy(yes))
		return yes
	}
	no := par.Arg(2)
	par.Trace("if:: %s -> %s", easyfl_util.FmtLazy(cond), easyfl_util.FmtLazy(no))
	return no
}

// evalFirstCaseIndex evaluates and returns first argument with not-nil value
func evalFirstCaseIndex(par *CallParams) []byte {
	for i := byte(0); i < par.Arity(); i++ {
		if c := par.Arg(i); len(c) > 0 {
			par.Trace("firstCaseIndex:: -> %d", i)
			return par.AllocData(i)
		}
	}
	par.Trace("firstCaseIndex:: -> nil")
	return nil
}

func evalFirstEqualIndex(par *CallParams) []byte {
	if par.Arity() == 0 {
		return nil
	}

	v := par.Arg(0)
	for i := byte(1); i < par.Arity(); i++ {
		if bytes.Equal(v, par.Arg(i)) {
			par.Trace("firstEqualIndex:: -> %d", i)
			return par.AllocData(i - 1)
		}
	}
	par.Trace("firstEqualIndex:: -> nil")
	return nil
}

func evalSelectCaseByIndex(par *CallParams) []byte {
	if par.Arity() == 0 {
		par.TracePanic("evalSelectCaseByIndex: must be at least 1 argument")
	}
	idx := par.Arg(0)
	if len(idx) != 1 || idx[0]+1 >= par.Arity() {
		return nil
	}
	return par.Arg(idx[0] + 1)
}

func evalIsZero(par *CallParams) []byte {
	arg := par.Arg(0)
	for _, b := range arg {
		if b != 0 {
			par.Trace("isZero:: %s -> nil", easyfl_util.FmtLazy(arg))
			return nil
		}
	}
	par.Trace("isZero:: %s -> true", easyfl_util.FmtLazy(arg))
	return par.AllocData(0xff)
}

func evalNot(par *CallParams) []byte {
	arg := par.Arg(0)
	if len(arg) == 0 {
		par.Trace("not:: %s -> true", easyfl_util.FmtLazy(arg))
		return par.AllocData(0xff)
	}
	par.Trace("not:: %s -> nil", easyfl_util.FmtLazy(arg))
	return nil
}

func evalConcat(par *CallParams) []byte {
	var args [MaxParameters][]byte
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
	par.Trace("concat:: %d params -> %s", par.Arity(), easyfl_util.FmtLazy(ret))
	return ret
}

func evalAnd(par *CallParams) []byte {
	for i := byte(0); i < par.Arity(); i++ {
		if len(par.Arg(i)) == 0 {
			par.Trace("and:: param %d nil -> nil", i)
			return nil
		}
	}
	par.Trace("and:: %d params -> true", par.Arity)
	return par.AllocData(0xff)
}

func evalOr(par *CallParams) []byte {
	for i := byte(0); i < par.Arity(); i++ {
		if len(par.Arg(i)) != 0 {
			par.Trace("or:: param %d -> true", i)
			return par.AllocData(0xff)
		}
	}
	par.Trace("or:: %d params -> nil", par.Arity)
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
func Must2ArithmeticOperands(par *CallParams, name string) (op0 uint64, op1 uint64) {
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

func evalAddUint(par *CallParams) []byte {
	a0, a1 := Must2ArithmeticOperands(par, "addUint")
	if a0 > math.MaxUint64-a1 {
		par.TracePanic("evalAddUint:: %d + %d -> overflow in addition", a0, a1)
	}
	ret := par.Alloc(8)
	binary.BigEndian.PutUint64(ret, a0+a1)
	return ret
}

func evalSubUint(par *CallParams) []byte {
	a0, a1 := Must2ArithmeticOperands(par, "subUint")
	if a0 < a1 {
		par.TracePanic("evalSubUint:: %d - %d -> underflow in subtraction", a0, a1)
	}
	ret := par.Alloc(8)
	binary.BigEndian.PutUint64(ret, a0-a1)
	return ret
}

func evalMulUint(par *CallParams) []byte {
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

func evalDivUint(par *CallParams) []byte {
	a0, a1 := Must2ArithmeticOperands(par, "divUint")
	if a1 == 0 {
		par.TracePanic("evalDivUint:: %d / %d -> divide by zero", a0, a1)
	}
	ret := par.Alloc(8)
	binary.BigEndian.PutUint64(ret, a0/a1)
	return ret
}

func evalModuloUint(par *CallParams) []byte {
	a0, a1 := Must2ArithmeticOperands(par, "moduloUint")
	if a1 == 0 {
		par.TracePanic("evalModuloUint:: %d / %d -> divide by zero", a0, a1)
	}
	ret := par.Alloc(8)
	binary.BigEndian.PutUint64(ret, a0%a1)
	return ret
}

func evalUint8Bytes(par *CallParams) []byte {
	ret, ok := ensure8Bytes(par.ctx.spool, par.Arg(0))
	if !ok {
		par.TracePanic("%s:: wrong size of parameter", "uint64Bytes")
	}
	return ret
}

// lexicographical comparison of two slices of equal length
func evalLessThan(par *CallParams) []byte {
	a0 := par.Arg(0)
	a1 := par.Arg(1)

	if len(a0) != len(a1) {
		par.TracePanic("lessThan: operands must be equal length. %s, %s", easyfl_util.FmtLazy(a0), easyfl_util.FmtLazy(a1))
	}
	for i := range a0 {
		switch {
		case a0[i] < a1[i]:
			par.Trace("lessThan: %s, %s -> true", easyfl_util.Fmt(a0), easyfl_util.Fmt(a1))
			return par.AllocData(0xff) // true
		case a0[i] > a1[i]:
			par.Trace("lessThan: %s, %s -> false", easyfl_util.Fmt(a0), easyfl_util.Fmt(a1))
			return nil //false
		}
	}
	par.Trace("lessThan: %s, %s -> false", easyfl_util.FmtLazy(a0), easyfl_util.FmtLazy(a1))
	return nil // equal -> false
}

func evalValidSigED25519(par *CallParams) []byte {
	msg := par.Arg(0)
	signature := par.Arg(1)
	pubKey := par.Arg(2)

	if ed25519.Verify(pubKey, msg, signature) {
		par.Trace("ValidSigED25519: msg=%s, sig=%s, pubKey=%s -> true",
			easyfl_util.FmtLazy(msg), easyfl_util.FmtLazy(signature), easyfl_util.FmtLazy(pubKey))
		return par.AllocData(0xff) // true
	}
	par.Trace("ValidSigED25519: msg=%s, sig=%s, pubKey=%s -> false",
		easyfl_util.FmtLazy(msg), easyfl_util.FmtLazy(signature), easyfl_util.FmtLazy(pubKey))
	return nil
}

func evalBlake2b(par *CallParams) []byte {
	var buf bytes.Buffer
	for i := byte(0); i < par.Arity(); i++ {
		buf.Write(par.Arg(i))
	}
	ret := blake2b.Sum256(buf.Bytes())
	par.Trace("blake2b: %d params -> %s", par.Arity(), easyfl_util.FmtLazy(ret[:]))
	return par.AllocData(ret[:]...) // true
}

func evalBitwiseAND(par *CallParams) []byte {
	a0 := par.Arg(0)
	a1 := par.Arg(1)
	if len(a0) != len(a1) {
		par.TracePanic("evalBitwiseAND: equal length arguments expected: %s -- %s", easyfl_util.FmtLazy(a0), easyfl_util.FmtLazy(a1))
	}
	ret := par.Alloc(uint16(len(a0))) // true

	for i := range a0 {
		ret[i] = a0[i] & a1[i]
	}
	par.Trace("evalBitwiseAND: %s, %s -> %s", easyfl_util.FmtLazy(a0), easyfl_util.FmtLazy(a1), easyfl_util.FmtLazy(ret))
	return ret
}

func evalBitwiseOR(par *CallParams) []byte {
	a0 := par.Arg(0)
	a1 := par.Arg(1)
	if len(a0) != len(a1) {
		par.TracePanic("evalBitwiseOR: equal length arguments expected: %s -- %s", easyfl_util.FmtLazy(a0), easyfl_util.FmtLazy(a1))
	}
	ret := par.Alloc(uint16(len(a0))) // true
	for i := range a0 {
		ret[i] = a0[i] | a1[i]
	}
	par.Trace("evalBitwiseOR: %s, %s -> %s", easyfl_util.FmtLazy(a0), easyfl_util.FmtLazy(a1), easyfl_util.FmtLazy(ret))
	return ret
}

func evalBitwiseXOR(par *CallParams) []byte {
	a0 := par.Arg(0)
	a1 := par.Arg(1)
	if len(a0) != len(a1) {
		par.TracePanic("evalBitwiseXOR: equal length arguments expected: %s -- %s", easyfl_util.FmtLazy(a0), easyfl_util.FmtLazy(a1))
	}
	ret := par.Alloc(uint16(len(a0))) // true
	for i := range a0 {
		ret[i] = a0[i] ^ a1[i]
	}
	par.Trace("evalBitwiseXOR: %s, %s -> %s", easyfl_util.FmtLazy(a0), easyfl_util.FmtLazy(a1), easyfl_util.FmtLazy(ret))
	return ret
}

func evalBitwiseNOT(par *CallParams) []byte {
	a0 := par.Arg(0)
	ret := par.Alloc(uint16(len(a0))) // true
	for i := range a0 {
		ret[i] = ^a0[i]
	}
	par.Trace("evalBitwiseNOT: %s -> %s", easyfl_util.FmtLazy(a0), easyfl_util.FmtLazy(ret))
	return ret
}

func evalLShift64(par *CallParams) []byte {
	a0, a1 := Must2ArithmeticOperands(par, "lshift64")
	ret := par.Alloc(8) // true
	binary.BigEndian.PutUint64(ret, a0<<a1)
	return ret
}

func evalRShift64(par *CallParams) []byte {
	a0, a1 := Must2ArithmeticOperands(par, "lshift64")
	ret := par.Alloc(8) // true
	binary.BigEndian.PutUint64(ret, a0>>a1)
	return ret
}

func evalAtTuple8(par *CallParams) []byte {
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

func evalNumElementsOfTuple(par *CallParams) []byte {
	arr, err := tuples.TupleFromBytes(par.Arg(0))
	if err != nil {
		par.TracePanic("evalNumElementsOfTuple: %v", err)
	}
	ret := par.Alloc(8)
	binary.BigEndian.PutUint64(ret, uint64(arr.NumElements()))
	return ret
}

func (lib *Library) evalParseInlineData(par *CallParams) []byte {
	dataBytecode := par.Arg(0)
	if !HasInlineDataPrefix(dataBytecode) {
		par.TracePanic("evalParseInlineData: not an inline data function call: %s", easyfl_util.FmtLazy(dataBytecode))
	}
	return dataBytecode[1:]
}

// evalParseArgumentBytecode takes bytecode of the argument as is.
// Note: data prefix is not stripped. To get the data, it must be evaluated
func (lib *Library) evalParseArgumentBytecode(par *CallParams) []byte {
	a0 := par.Arg(0)
	sym, prefix, args, err := lib.ParseBytecodeOneLevel(a0)
	if err != nil {
		par.TracePanic("evalParseArgumentBytecode:: %v", err)
	}
	expectedPrefix := par.Arg(1)
	_, _, _, symExpectedPrefix, err := lib.parseCallPrefix(expectedPrefix)
	if err != nil {
		par.TracePanic("evalParseArgumentBytecode: can't parse prefix '%s': %v", easyfl_util.FmtLazy(expectedPrefix), err)
	}

	if sym != symExpectedPrefix {
		par.TracePanic("evalParseArgumentBytecode: unexpected function prefix. Expected '%s'('%s'), got '%s'('%s')",
			easyfl_util.FmtLazy(expectedPrefix), symExpectedPrefix, easyfl_util.FmtLazy(prefix), sym)
	}
	idx := par.Arg(2)
	if len(idx) != 1 || len(args) <= int(idx[0]) {
		par.TracePanic("evalParseArgumentBytecode: wrong parameter index")
	}
	ret := args[idx[0]]
	par.Trace("unwrapBytecodeArg:: %s, %s, %s -> %s", easyfl_util.FmtLazy(a0), easyfl_util.FmtLazy(expectedPrefix), easyfl_util.FmtLazy(idx), easyfl_util.FmtLazy(ret))
	return ret
}

func (lib *Library) evalParsePrefixBytecode(par *CallParams) []byte {
	code := par.Arg(0)
	prefix, err := lib.ParsePrefixBytecode(code)
	if err != nil {
		par.TracePanic("evalParsePrefixBytecode: %v", err)
	}
	par.Trace("parseBytecodePrefix::%s -> %s", easyfl_util.FmtLazy(code), easyfl_util.FmtLazy(prefix))
	return prefix
}
