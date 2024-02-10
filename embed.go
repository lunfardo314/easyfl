package easyfl

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"math"
	"reflect"

	"golang.org/x/crypto/blake2b"
)

func isNil(p interface{}) bool {
	return p == nil || (reflect.ValueOf(p).Kind() == reflect.Ptr && reflect.ValueOf(p).IsNil())
}

func evalId(par *CallParams) []byte {
	return par.Arg(0)
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

func evalLen8(par *CallParams) []byte {
	arg := par.Arg(0)
	sz := len(arg)
	if sz > math.MaxUint8 {
		par.TracePanic("len8:: size of the data > 255: %s", Fmt(arg))
	}
	ret := []byte{byte(sz)}
	par.Trace("len8:: %s -> %s", Fmt(arg), Fmt(ret))
	return ret
}

func evalLen16(par *CallParams) []byte {
	data := par.Arg(0)
	if len(data) > math.MaxUint16 {
		par.TracePanic("len16:: size of the data > uint16: %s", Fmt(data))
	}
	var ret [2]byte
	binary.BigEndian.PutUint16(ret[:], uint16(len(data)))
	par.Trace("len16:: %s -> %s", Fmt(data), Fmt(ret[:]))
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

func mustArithmArgs(par *CallParams, bytesSize int, name string) ([]byte, []byte) {
	a0 := par.Arg(0)
	a1 := par.Arg(1)
	if len(a0) != bytesSize || len(a1) != bytesSize {
		par.TracePanic("%s:: %d-bytes size parameters expected", name, bytesSize)
	}
	return a0, a1
}

func evalSum8_16(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 1, "sum8_16")
	sum := uint16(a0[0]) + uint16(a1[0])
	ret := make([]byte, 2)
	binary.BigEndian.PutUint16(ret, sum)
	return ret
}

func evalMustSum8(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 1, "sum8")
	sum := int(a0[0]) + int(a1[0])
	if sum > 255 {
		par.TracePanic("_mustSum8:: %s, %s -> arithmetic overflow", Fmt(a0), Fmt(a1))
	}
	ret := []byte{byte(sum)}
	par.Trace("sum8:: %s, %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret))
	return ret
}

func evalSum16_32(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 2, "sum16_32")
	sum := uint32(binary.BigEndian.Uint16(a0)) + uint32(binary.BigEndian.Uint16(a1))
	ret := make([]byte, 4)
	binary.BigEndian.PutUint32(ret, sum)
	par.Trace("sum16_32:: %s, %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret))
	return ret
}

func evalMustSum16(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 2, "sum_16")
	sum := uint32(binary.BigEndian.Uint16(a0)) + uint32(binary.BigEndian.Uint16(a1))
	if sum > math.MaxUint16 {
		par.TracePanic("_mustSum16: %s, %s -> arithmetic overflow", Fmt(a0), Fmt(a1))
	}
	ret := make([]byte, 2)
	binary.BigEndian.PutUint16(ret, uint16(sum))
	par.Trace("sum16:: %s, %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret))
	return ret
}

func evalSum32_64(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 4, "sum32_64")
	sum := uint64(binary.BigEndian.Uint32(a0)) + uint64(binary.BigEndian.Uint32(a1))
	ret := make([]byte, 8)
	binary.BigEndian.PutUint64(ret, sum)
	par.Trace("sum32_64:: %s, %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret))
	return ret
}

func evalMustSum32(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 4, "sum32")
	sum := uint64(binary.BigEndian.Uint32(a0)) + uint64(binary.BigEndian.Uint32(a1))
	if sum > math.MaxUint32 {
		par.TracePanic("_mustSum32:: %s, %s -> arithmetic overflow", Fmt(a0), Fmt(a1))
	}
	ret := make([]byte, 4)
	binary.BigEndian.PutUint32(ret, uint32(sum))
	par.Trace("sum32:: %s, %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret))
	return ret
}

func evalMustSum64(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 8, "sum64")
	s0 := binary.BigEndian.Uint64(a0)
	s1 := binary.BigEndian.Uint64(a1)
	if s0 > math.MaxUint64-s1 {
		par.TracePanic("_mustSum64: arithmetic overflow")
	}
	ret := make([]byte, 8)
	binary.BigEndian.PutUint64(ret, s0+s1)
	par.Trace("sum64:: %s, %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret))
	return ret
}

func evalMustSub8(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 1, "sub8")
	if a0[0] < a1[0] {
		par.TracePanic("mustSub8:: %s - %s -> underflow in subtraction", Fmt(a0), Fmt(a1))
	}
	ret := []byte{a0[0] - a1[0]}
	par.Trace("sub8:: %s, %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret))
	return ret
}

func evalMustSub32(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 4, "sub32")
	op0 := binary.BigEndian.Uint32(a0)
	op1 := binary.BigEndian.Uint32(a1)
	if op0 < op1 {
		par.TracePanic("mustSub32:: %s - %s -> underflow in subtraction", Fmt(a0), Fmt(a1))
	}
	ret := make([]byte, 4)
	binary.BigEndian.PutUint32(ret, op0-op1)
	par.Trace("sub32:: %s - %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret))
	return ret
}

func evalMustSub64(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 8, "sub64")
	op0 := binary.BigEndian.Uint64(a0)
	op1 := binary.BigEndian.Uint64(a1)
	if op0 < op1 {
		par.TracePanic("mustSub64:: %s - %s -> underflow in subtraction", Fmt(a0), Fmt(a1))
	}
	ret := make([]byte, 8)
	binary.BigEndian.PutUint64(ret, op0-op1)
	par.Trace("sub64:: %s - %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret))
	return ret
}

func evalMul8_16(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 1, "mul8_16")
	var ret [2]byte
	binary.BigEndian.PutUint16(ret[:], uint16(a0[0])*uint16(a1[0]))
	par.Trace("mul8_16:: %s, %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret[:]))
	return ret[:]
}

func evalMul16_32(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 2, "mul16_32")
	var ret [4]byte
	op0 := binary.BigEndian.Uint16(a0)
	op1 := binary.BigEndian.Uint16(a1)
	binary.BigEndian.PutUint32(ret[:], uint32(op0)*uint32(op1))
	par.Trace("mul16_32:: %s, %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret[:]))
	return ret[:]
}

func evalDiv64(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 8, "div64")
	var ret [8]byte
	op0 := binary.BigEndian.Uint64(a0)
	op1 := binary.BigEndian.Uint64(a1)
	binary.BigEndian.PutUint64(ret[:], op0/op1)
	par.Trace("div64:: %s / %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret[:]))
	return ret[:]
}

func evalMul64(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 8, "mul64")
	var ret [8]byte
	op0 := binary.BigEndian.Uint64(a0)
	op1 := binary.BigEndian.Uint64(a1)
	// safe arithmetics
	if op1 != 0 && op0 >= math.MaxUint64/op1 {
		par.TracePanic("mul64:: %s * %s -> overflow in multiplication", Fmt(a0), Fmt(a1))
	}
	binary.BigEndian.PutUint64(ret[:], op0*op1)
	par.Trace("mul64:: %s * %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret[:]))
	return ret[:]
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

	ret, err := lib.EvalFromBinary(par.ctx.glb, args[idx[0]])
	if err != nil {
		par.TracePanic("evaldBytecodeArg:: %s, %s, %s", Fmt(a0), Fmt(expectedPrefix), Fmt(idx))
	}

	par.Trace("evaldBytecodeArg:: %s, %s, %s -> %s", Fmt(a0), Fmt(expectedPrefix), Fmt(idx), Fmt(ret))
	return ret
}
