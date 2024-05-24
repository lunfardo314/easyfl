package easyfl

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"

	"golang.org/x/crypto/blake2b"
)

// list of standard embedded functions
// TODO
//  - certain function could be optimized.
//  - do we need short end long embedding?

var (
	embedShortBase = []*EmbeddedFunctionData{
		{"fail", 1, evalFail},
		{"slice", 3, evalSlice},
		{"byte", 2, evalByte},
		{"tail", 2, evalTail},
		{"equal", 2, evalEqual},
		{"hasPrefix", 2, evalHasPrefix},
		{"len", 1, evalLen},
		{"not", 1, evalNot},
		{"if", 3, evalIf},
		{"isZero", 1, evalIsZero},
	}
	embedLongBase = []*EmbeddedFunctionData{
		{"concat", -1, evalConcat},
		{"and", -1, evalAnd},
		{"or", -1, evalOr},
		{"repeat", 2, evalRepeat},
	}
	embedArithmeticsShort = []*EmbeddedFunctionData{
		{"add", 2, evalAddUint},
		{"sub", 2, evalSubUint},
		{"mul", 2, evalMulUint},
		{"div", 2, evalDivUint},
		{"mod", 2, evalModuloUint},
		{"equalUint", 2, evalEqualUint},
	}
	embedBitwiseAndCmpShort = []*EmbeddedFunctionData{
		{"lessThan", 2, evalLessThan},
		{"bitwiseOR", 2, evalBitwiseOR},
		{"bitwiseAND", 2, evalBitwiseAND},
		{"bitwiseNOT", 1, evalBitwiseNOT},
		{"bitwiseXOR", 2, evalBitwiseXOR},
	}
	embedBitwiseAndCmpLong = []*EmbeddedFunctionData{
		{"lshift64", 2, evalLShift64},
		{"rshift64", 2, evalRShift64},
	}
	embedBaseCrypto = []*EmbeddedFunctionData{
		{"validSignatureED25519", 3, evalValidSigED25519},
		{"blake2b", -1, evalBlake2b},
	}
	embedBytecodeManipulation = func(lib *Library) []*EmbeddedFunctionData {
		return []*EmbeddedFunctionData{
			{"unwrapBytecodeArg", 3, lib.evalUnwrapBytecodeArg},
			{"parseBytecodePrefix", 1, lib.evalParseBytecodePrefix},
			{"evalBytecodeArg", 3, lib.evalEvalBytecodeArg},
		}
	}
)

// embedding functions with inline tests

func (lib *Library) embedMain() {
	lib.UpgradeWithEmbeddedShort(embedShortBase...)
	lib.UpgradeWthEmbeddedLong(embedLongBase...)

	// inline tests
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
}

func (lib *Library) embedArithmetics() {
	lib.UpgradeWithEmbeddedShort(embedArithmeticsShort...)

	lib.MustEqual("add(5,6)", "add(10,1)")
	lib.MustEqual("add(5,6)", "u64/11")
	lib.MustEqual("add(0, 0)", "u64/0")
	lib.MustEqual("add(u16/1337, 0)", "u64/1337")
	lib.MustError("add(nil, 0)", "wrong size of parameters")

	lib.MustEqual("sub(6,6)", "u64/0")
	lib.MustEqual("sub(6,5)", "u64/1")
	lib.MustEqual("sub(0, 0)", "u64/0")
	lib.MustEqual("sub(u16/1337, 0)", "u64/1337")
	lib.MustError("sub(nil, 0)", "wrong size of parameters")
	lib.MustError("sub(10, 100)", "underflow in subtraction")

	lib.MustEqual("mul(5,6)", "mul(15,2)")
	lib.MustEqual("mul(5,6)", "u64/30")
	lib.MustEqual("mul(u16/1337, 0)", "u64/0")
	lib.MustEqual("mul(0, u32/1337133700)", "u64/0")
	lib.MustError("mul(nil, 5)", "wrong size of parameters")

	lib.MustEqual("div(100,100)", "u64/1")
	lib.MustEqual("div(100,110)", "u64/0")
	lib.MustEqual("div(u32/10000,u16/10000)", "u64/1")
	lib.MustEqual("div(0, u32/1337133700)", "u64/0")
	lib.MustError("div(u32/1337133700, 0)", "integer divide by zero")
	lib.MustError("div(nil, 5)", "wrong size of parameters")

	lib.MustEqual("mod(100,100)", "u64/0")
	lib.MustEqual("mod(107,100)", "u64/7")
	lib.MustEqual("mod(u32/10100,u16/10000)", "u64/100")
	lib.MustEqual("mod(0, u32/1337133700)", "u64/0")
	lib.MustError("mod(u32/1337133700, 0)", "integer divide by zero")
	lib.MustError("mod(nil, 5)", "wrong size of parameters")
	lib.MustEqual("add(mul(div(u32/27, u16/4), 4), mod(u32/27, 4))", "u64/27")

	lib.MustTrue("equalUint(100,100)")
	lib.MustTrue("equalUint(100,u32/100)")
	lib.MustTrue("not(equalUint(100,u32/1337))")
	lib.MustError("equalUint(nil, 5)", "wrong size of parameters")
}

func (lib *Library) embedBitwiseAndCmp() {
	lib.UpgradeWithEmbeddedShort(embedBitwiseAndCmpShort...)
	lib.UpgradeWthEmbeddedLong(embedBitwiseAndCmpLong...)

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
	lib.MustError("lshift64(u64/2001, nil)", "wrong size of parameters")

	//lib.embedLong("rshift64", 2, evalRShift64)
	lib.MustEqual("rshift64(u64/15, u64/2)", "u64/3")
	lib.MustTrue("isZero(rshift64(0xffffffffffffffff, u64/64))")
	lib.MustTrue("equal(rshift64(u64/2001, u64/3), div(u64/2001, 8))")
	lib.MustError("rshift64(u64/2001, nil)", "wrong size of parameters")
}

func (lib *Library) embedBaseCrypto() {
	lib.UpgradeWthEmbeddedLong(embedBaseCrypto...)

	h := blake2b.Sum256([]byte{1})
	lib.MustEqual("len(blake2b(1))", "u64/32")
	lib.MustEqual("blake2b(1)", fmt.Sprintf("0x%s", hex.EncodeToString(h[:])))
}

func (lib *Library) embedBytecodeManipulation() {
	// code parsing
	// $0 - EasyFL bytecode
	// $1 - expected call prefix (#-literal)
	// $2 - number of the parameter to return
	// Panics if the bytecode is not the valid call of the specified function or number of the parameter is out of bounds
	// Returns code of the argument if it is a call function, or data is it is a constant
	//lib.embedLong("unwrapBytecodeArg", 3, lib.evalUnwrapBytecodeArg)
	//lib.embedLong("parseBytecodePrefix", 1, lib.evalParseBytecodePrefix)
	//lib.embedLong("evalBytecodeArg", 3, lib.evalEvalBytecodeArg)
	lib.UpgradeWthEmbeddedLong(embedBytecodeManipulation(lib)...)

	_, _, binCode, err := lib.CompileExpression("slice(0x01020304,1,2)")
	AssertNoError(err)
	src := fmt.Sprintf("unwrapBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 0)
	lib.MustEqual(src, "0x01020304")
	src = fmt.Sprintf("unwrapBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 1)
	lib.MustEqual(src, "1")
	src = fmt.Sprintf("unwrapBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 2)
	lib.MustEqual(src, "2")
	src = fmt.Sprintf("parseBytecodePrefix(0x%s)", hex.EncodeToString(binCode))
	lib.MustEqual(src, "#slice")

	src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 0)
	lib.MustEqual(src, "0x01020304")
	src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 1)
	lib.MustEqual(src, "1")
	src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 2)
	lib.MustEqual(src, "2")

	_, _, binCode, err = lib.CompileExpression("slice(concat(1,2,concat(3,4)),1,2)")
	AssertNoError(err)
	src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 0)
	lib.MustEqual(src, "0x01020304")
	src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 1)
	lib.MustEqual(src, "1")
	src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 2)
	lib.MustEqual(src, "2")

	_, _, binCode, err = lib.CompileExpression("slice(concat(1,concat(2,3),4),byte(0x020301, 2),add(1,1))")
	AssertNoError(err)
	src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 0)
	lib.MustEqual(src, "0x01020304")
	src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 1)
	lib.MustEqual(src, "1")
	src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 2)
	lib.MustEqual(src, "u64/2")
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
		par.TracePanic("slice:: data: %s, from: %s, to: %s -- wrong bound values", Fmt(data), Fmt(from), Fmt(to))
	}
	if from[0] > to[0] {
		par.TracePanic("slice:: data: %s, from: %s, to: %s -- wrong slice bounds. ", Fmt(data), Fmt(from), Fmt(to))
	}
	upper := int(to[0]) + 1
	if upper > len(data) {
		par.TracePanic("slice:: data: %s, from: %s, to: %s -- slice out of bounds. ", Fmt(data), Fmt(from), Fmt(to))
	}
	ret := data[from[0]:upper]
	par.Trace("slice:: data: %s, from: %s, to: %s -> %s", Fmt(data), Fmt(from), Fmt(to), Fmt(ret))
	return ret
}

func evalByte(par *CallParams) []byte {
	data := par.Arg(0)
	idx := par.Arg(1)
	if len(idx) != 1 || int(idx[0]) >= len(data) {
		par.TracePanic("byte:: data: %s, idx: %s -- wrong index value", Fmt(data), Fmt(idx))
	}
	ret := data[idx[0] : idx[0]+1]
	par.Trace("byte:: data: %s, idx: %s -> %s", Fmt(data), Fmt(idx), Fmt(ret))
	return ret
}

func evalTail(par *CallParams) []byte {
	data := par.Arg(0)
	from := par.Arg(1)
	if len(from) != 1 || int(from[0]) >= len(data) {
		par.TracePanic("tail:: data: %s, from: %s -- index out of bounds. ", Fmt(data), Fmt(from))
	}
	ret := data[from[0]:]
	par.Trace("tail:: data: %s, from: %s -> %s", Fmt(data), Fmt(from), Fmt(ret))
	return ret
}

func evalEqual(par *CallParams) []byte {
	var ret []byte
	p0 := par.Arg(0)
	p1 := par.Arg(1)
	if bytes.Equal(p0, p1) {
		ret = []byte{0xff}
	}
	par.Trace("equal:: %s, %s -> %s", Fmt(p0), Fmt(p1), Fmt(ret))
	return ret
}

func evalHasPrefix(par *CallParams) []byte {
	var ret []byte
	data := par.Arg(0)
	prefix := par.Arg(1)
	if bytes.HasPrefix(data, prefix) {
		ret = []byte{0xff}
	}
	par.Trace("hasPrefix:: %s, %s -> %s", Fmt(data), Fmt(prefix), Fmt(ret))
	return ret
}

func evalRepeat(par *CallParams) []byte {
	fragment := par.Arg(0)
	n := par.Arg(1)
	if len(n) != 1 {
		par.TracePanic("evalRepeat: count must 1-byte long")
	}
	ret := bytes.Repeat(fragment, int(n[0]))
	par.Trace("hasPrefix:: %s, %s -> %s", Fmt(fragment), Fmt(n), Fmt(ret))
	return ret
}

func evalLen(par *CallParams) []byte {
	data := par.Arg(0)
	var ret [8]byte
	binary.BigEndian.PutUint64(ret[:], uint64(len(data)))
	par.Trace("len:: %s -> %s", Fmt(data), Fmt(ret[:]))
	return ret[:]
}

func evalIf(par *CallParams) []byte {
	cond := par.Arg(0)
	if len(cond) != 0 {
		yes := par.Arg(1)
		par.Trace("if:: %s -> %s", Fmt(cond), Fmt(yes))
		return yes
	}
	no := par.Arg(2)
	par.Trace("if:: %s -> %s", Fmt(cond), Fmt(no))
	return no
}

func evalIsZero(par *CallParams) []byte {
	arg := par.Arg(0)
	for _, b := range arg {
		if b != 0 {
			par.Trace("isZero:: %s -> nil", Fmt(arg))
			return nil
		}
	}
	par.Trace("isZero:: %s -> true", Fmt(arg))
	return []byte{0xff}
}

func evalNot(par *CallParams) []byte {
	arg := par.Arg(0)
	if len(arg) == 0 {
		par.Trace("not:: %s -> true", Fmt(arg))
		return []byte{0xff}
	}
	par.Trace("not:: %s -> nil", Fmt(arg))
	return nil
}

func evalConcat(par *CallParams) []byte {
	var buf bytes.Buffer
	for i := byte(0); i < par.Arity(); i++ {
		buf.Write(par.Arg(i))
	}
	ret := buf.Bytes()
	par.Trace("Concat:: %d params -> %s", par.Arity(), Fmt(ret))
	return ret
}

func evalAnd(par *CallParams) []byte {
	for i := byte(0); i < par.Arity(); i++ {
		if len(par.Arg(i)) == 0 {
			par.Trace("and:: param %d nil -> nil", i)
			return nil
		}
	}
	par.Trace("and:: %d params -> true", par.Arity())
	return []byte{0xff}
}

func evalOr(par *CallParams) []byte {
	for i := byte(0); i < par.Arity(); i++ {
		if len(par.Arg(i)) != 0 {
			par.Trace("or:: param %d -> true", i)
			return []byte{0xff}
		}
	}
	par.Trace("or:: %d params -> nil", par.Arity())
	return nil
}

// mustArithmeticArgs makes uint64 from both params (bigendian)
// Parameters must be not nil with size <= 8. They are padded with 0 in upper bytes, if necessary
func mustArithmeticArgs(par *CallParams, name string) (uint64, uint64) {
	a0 := par.Arg(0)
	a1 := par.Arg(1)
	if len(a0) == 0 || len(a1) == 0 || len(a0) > 8 || len(a1) > 8 {
		par.TracePanic("%s:: wrong size of parameters", name)
	}
	var a0b, a1b [8]byte
	copy(a0b[8-len(a0):], a0)
	copy(a1b[8-len(a1):], a1)
	return binary.BigEndian.Uint64(a0b[:]), binary.BigEndian.Uint64(a1b[:])
}

func evalAddUint(par *CallParams) []byte {
	a0, a1 := mustArithmeticArgs(par, "addUint")
	var ret [8]byte
	binary.BigEndian.PutUint64(ret[:], a0+a1)
	return ret[:]
}

func evalSubUint(par *CallParams) []byte {
	a0, a1 := mustArithmeticArgs(par, "subUint")
	if a0 < a1 {
		par.TracePanic("evalSubUint:: %d - %d -> underflow in subtraction", a0, a1)
	}
	var ret [8]byte
	binary.BigEndian.PutUint64(ret[:], a0-a1)
	return ret[:]
}

func evalMulUint(par *CallParams) []byte {
	a0, a1 := mustArithmeticArgs(par, "mulUint")
	var ret [8]byte
	binary.BigEndian.PutUint64(ret[:], a0*a1)
	return ret[:]
}

func evalDivUint(par *CallParams) []byte {
	a0, a1 := mustArithmeticArgs(par, "divUint")
	var ret [8]byte
	binary.BigEndian.PutUint64(ret[:], a0/a1)
	return ret[:]
}

func evalModuloUint(par *CallParams) []byte {
	a0, a1 := mustArithmeticArgs(par, "moduloUint")
	var ret [8]byte
	binary.BigEndian.PutUint64(ret[:], a0%a1)
	return ret[:]
}

func evalEqualUint(par *CallParams) []byte {
	a0, a1 := mustArithmeticArgs(par, "equalUint")
	if a0 == a1 {
		return []byte{0xff}
	}
	return nil
}

// lexicographical comparison of two slices of equal length
func evalLessThan(par *CallParams) []byte {
	a0 := par.Arg(0)
	a1 := par.Arg(1)
	if len(a0) != len(a1) {
		par.TracePanic("lessThan: operands must be equal length. %s, %s", Fmt(a0), Fmt(a1))
	}
	for i := range a0 {
		switch {
		case a0[i] < a1[i]:
			par.Trace("lessThan: %s, %s -> true", Fmt(a0), Fmt(a1))
			return []byte{0xff} // true
		case a0[i] > a1[i]:
			par.Trace("lessThan: %s, %s -> false", Fmt(a0), Fmt(a1))
			return nil //false
		}
	}
	par.Trace("lessThan: %s, %s -> false", Fmt(a0), Fmt(a1))
	return nil // equal -> false
}

func evalValidSigED25519(par *CallParams) []byte {
	msg := par.Arg(0)
	signature := par.Arg(1)
	pubKey := par.Arg(2)

	if ed25519.Verify(pubKey, msg, signature) {
		par.Trace("ValidSigED25519: msg=%s, sig=%s, pubKey=%s -> true",
			Fmt(msg), Fmt(signature), Fmt(pubKey))
		return []byte{0xff}
	}
	par.Trace("ValidSigED25519: msg=%s, sig=%s, pubKey=%s -> false",
		Fmt(msg), Fmt(signature), Fmt(pubKey))
	return nil
}

func evalBlake2b(par *CallParams) []byte {
	var buf bytes.Buffer
	for i := byte(0); i < par.Arity(); i++ {
		buf.Write(par.Arg(i))
	}
	ret := blake2b.Sum256(buf.Bytes())
	par.Trace("blake2b: %d params -> %s", par.Arity(), Fmt(ret[:]))
	return ret[:]
}

func evalBitwiseAND(par *CallParams) []byte {
	a0 := par.Arg(0)
	a1 := par.Arg(1)
	if len(a0) != len(a1) {
		par.TracePanic("evalBitwiseAND: equal length arguments expected: %s -- %s", Fmt(a0), Fmt(a1))
	}
	ret := make([]byte, len(a0))
	for i := range a0 {
		ret[i] = a0[i] & a1[i]
	}
	par.Trace("evalBitwiseAND: %s, %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret))
	return ret
}

func evalBitwiseOR(par *CallParams) []byte {
	a0 := par.Arg(0)
	a1 := par.Arg(1)
	if len(a0) != len(a1) {
		par.TracePanic("evalBitwiseOR: equal length arguments expected: %s -- %s", Fmt(a0), Fmt(a1))
	}
	ret := make([]byte, len(a0))
	for i := range a0 {
		ret[i] = a0[i] | a1[i]
	}
	par.Trace("evalBitwiseOR: %s, %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret))
	return ret
}

func evalBitwiseXOR(par *CallParams) []byte {
	a0 := par.Arg(0)
	a1 := par.Arg(1)
	if len(a0) != len(a1) {
		par.TracePanic("evalBitwiseXOR: equal length arguments expected: %s -- %s", Fmt(a0), Fmt(a1))
	}
	ret := make([]byte, len(a0))
	for i := range a0 {
		ret[i] = a0[i] ^ a1[i]
	}
	par.Trace("evalBitwiseXOR: %s, %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret))
	return ret
}

func evalBitwiseNOT(par *CallParams) []byte {
	a0 := par.Arg(0)
	ret := make([]byte, len(a0))
	for i := range a0 {
		ret[i] = ^a0[i]
	}
	par.Trace("evalBitwiseNOT: %s -> %s", Fmt(a0), Fmt(ret))
	return ret
}

func evalLShift64(par *CallParams) []byte {
	a0, a1 := mustArithmeticArgs(par, "lshift64")
	var ret [8]byte
	binary.BigEndian.PutUint64(ret[:], a0<<a1)
	return ret[:]
}

func evalRShift64(par *CallParams) []byte {
	a0, a1 := mustArithmeticArgs(par, "lshift64")
	var ret [8]byte
	binary.BigEndian.PutUint64(ret[:], a0>>a1)
	return ret[:]
}

func (lib *Library) evalUnwrapBytecodeArg(par *CallParams) []byte {
	a0 := par.Arg(0)
	_, prefix, args, err := lib.ParseBytecodeOneLevel(a0)
	if err != nil {
		par.TracePanic("evalUnwrapBytecodeArg:: %v", err)
	}
	expectedPrefix := par.Arg(1)
	idx := par.Arg(2)
	if !bytes.Equal(prefix, expectedPrefix) {
		_, _, _, symPrefix, err := lib.parseCallPrefix(prefix)
		if err != nil {
			par.TracePanic("evalUnwrapBytecodeArg: can't parse prefix '%s': %v", Fmt(prefix), err)
		}
		_, _, _, symExpectedPrefix, err := lib.parseCallPrefix(expectedPrefix)
		if err != nil {
			par.TracePanic("evalUnwrapBytecodeArg: can't parse expected prefix '%s': %v", Fmt(expectedPrefix), err)
		}
		par.TracePanic("evalUnwrapBytecodeArg: unexpected function prefix. Expected '%s'('%s'), got '%s'('%s')",
			Fmt(expectedPrefix), symExpectedPrefix, Fmt(prefix), symPrefix)
	}
	if len(idx) != 1 || len(args) <= int(idx[0]) {
		par.TracePanic("evalUnwrapBytecodeArg: wrong parameter index")
	}
	ret := StripDataPrefix(args[idx[0]])
	par.Trace("unwrapBytecodeArg:: %s, %s, %s -> %s", Fmt(a0), Fmt(expectedPrefix), Fmt(idx), Fmt(ret))
	return ret
}

func (lib *Library) evalParseBytecodePrefix(par *CallParams) []byte {
	code := par.Arg(0)
	prefix, err := lib.ParseBytecodePrefix(code)
	if err != nil {
		par.TracePanic("evalParseBytecodePrefix: %v", err)
	}
	par.Trace("parseBytecodePrefix::%s -> %s", Fmt(code), Fmt(prefix))
	return prefix
}

func (lib *Library) evalEvalBytecodeArg(par *CallParams) []byte {
	a0 := par.Arg(0)
	_, prefix, args, err := lib.ParseBytecodeOneLevel(a0)
	if err != nil {
		par.TracePanic("evalUnwrapBytecodeArg:: %v", err)
	}
	expectedPrefix := par.Arg(1)
	idx := par.Arg(2)
	if !bytes.Equal(prefix, expectedPrefix) {
		_, _, _, symPrefix, err := lib.parseCallPrefix(prefix)
		if err != nil {
			par.TracePanic("evalEvalBytecodeArg: can't parse prefix '%s': %v", Fmt(prefix), err)
		}
		_, _, _, symExpectedPrefix, err := lib.parseCallPrefix(expectedPrefix)
		if err != nil {
			par.TracePanic("evalEvalBytecodeArg: can't parse expected prefix '%s': %v", Fmt(expectedPrefix), err)
		}
		par.TracePanic("evalEvalBytecodeArg: unexpected function prefix. Expected '%s'('%s'), got '%s'('%s')",
			Fmt(expectedPrefix), symExpectedPrefix, Fmt(prefix), symPrefix)
	}
	if len(idx) != 1 || len(args) <= int(idx[0]) {
		par.TracePanic("evalUnwrapBytecodeArg: wrong parameter index")
	}

	ret, err := lib.EvalFromBytecode(par.ctx.glb, args[idx[0]])
	if err != nil {
		par.TracePanic("evaldBytecodeArg:: %s, %s, %s", Fmt(a0), Fmt(expectedPrefix), Fmt(idx))
	}

	par.Trace("evaldBytecodeArg:: %s, %s, %s -> %s", Fmt(a0), Fmt(expectedPrefix), Fmt(idx), Fmt(ret))
	return ret
}
