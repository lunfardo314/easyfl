package easyfl

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
)

type funDescriptor struct {
	sym               string
	funCode           uint16
	requiredNumParams int
	evalFun           EvalFunction
	contextDependent  bool
}

type libraryData struct {
	funByName    map[string]*funDescriptor
	funByFunCode map[uint16]*funDescriptor
}

var (
	theLibrary = &libraryData{
		funByName:    make(map[string]*funDescriptor),
		funByFunCode: make(map[uint16]*funDescriptor),
	}
	numEmbeddedShort = EmbeddedReservedUntil + 1
	numEmbeddedLong  int
	numExtended      int
)

const traceYN = false

func init() {
	// basic
	// 'slice' inclusive the end. Expects 1-byte slices at $1 and $2
	EmbedShort("slice", 3, evalSlice)
	// 'tail' takes from $1 to the end
	EmbedShort("tail", 2, evalTail)
	EmbedShort("equal", 2, evalEqual)
	// 'len8' returns length up until 255 (256 and more panics)
	EmbedShort("len8", 1, evalLen8)
	EmbedShort("len16", 1, evalLen16)
	EmbedShort("not", 1, evalNot)
	EmbedShort("if", 3, evalIf)
	EmbedShort("isZero", 1, evalIsZero)
	// stateless varargs
	// 'concat' concatenates variable number of arguments. concat() is empty byte array
	EmbedLong("concat", -1, evalConcat)
	EmbedLong("and", -1, evalAnd)
	EmbedLong("or", -1, evalOr)

	// safe arithmetics
	EmbedShort("sum8", 2, evalMustSum8)
	EmbedShort("sum8_16", 2, evalSum8_16)
	EmbedShort("sum16", 2, evalMustSum16)
	EmbedShort("sum16_32", 2, evalSum16_32)
	EmbedShort("sum32", 2, evalMustSum32)
	EmbedShort("sum32_64", 2, evalSum32_64)
	EmbedShort("sum64", 2, evalMustSum64)
	EmbedShort("sub8", 2, evalMustSub8)
	// comparison
	EmbedShort("lessThan", 2, evalLessThan)
	Extend("lessOrEqualThan", "or(lessThan($0,$1),equal($0,$1))")
	Extend("greaterThan", "not(lessOrEqualThan($0,$1))")
	Extend("greaterOrEqualThan", "not(lessThan($0,$1))")
	// other
	Extend("nil", "or")
	Extend("byte", "slice($0, $1, $1)")

	EmbedLong("validSignatureED25519", 3, evalValidSigED25519)
	EmbedLong("blake2b", -1, evalBlake2b)

}

func PrintLibraryStats() {
	fmt.Printf(`EasyFL function library:
    number of short embedded: %d out of max %d
    number of long embedded: %d out of max %d
    number of extended: %d out of max %d
`,
		numEmbeddedShort, MaxNumEmbeddedShort, numEmbeddedLong, MaxNumEmbeddedLong, numExtended, MaxNumExtended)
}

// EmbedShort embeds short-callable function inti the library
// contextDependent is not used currently, it is intended for caching of values TODO
func EmbedShort(sym string, requiredNumPar int, evalFun EvalFunction, contextDependent ...bool) byte {
	if numEmbeddedShort >= MaxNumEmbeddedShort {
		panic("too many embedded short functions")
	}
	mustUniqueName(sym)
	if requiredNumPar > 15 {
		panic("can't be more than 15 parameters")
	}
	if traceYN {
		evalFun = wrapWithTracing(evalFun, sym)
	}
	var ctxDept bool
	if len(contextDependent) > 0 {
		ctxDept = contextDependent[0]
	}
	dscr := &funDescriptor{
		sym:               sym,
		funCode:           uint16(numEmbeddedShort),
		requiredNumParams: requiredNumPar,
		evalFun:           evalFun,
		contextDependent:  ctxDept,
	}
	theLibrary.funByName[sym] = dscr
	theLibrary.funByFunCode[dscr.funCode] = dscr
	numEmbeddedShort++

	return byte(dscr.funCode)
}

func EmbedLong(sym string, requiredNumPar int, evalFun EvalFunction) uint16 {
	if numEmbeddedLong >= MaxNumEmbeddedLong {
		panic("too many embedded long functions")
	}
	mustUniqueName(sym)
	if requiredNumPar > 15 {
		panic("can't be more than 15 parameters")
	}
	if traceYN {
		evalFun = wrapWithTracing(evalFun, sym)
	}
	dscr := &funDescriptor{
		sym:               sym,
		funCode:           uint16(numEmbeddedLong + FirstEmbeddedLongFun),
		requiredNumParams: requiredNumPar,
		evalFun:           evalFun,
	}
	theLibrary.funByName[sym] = dscr
	theLibrary.funByFunCode[dscr.funCode] = dscr
	numEmbeddedLong++

	return dscr.funCode
}

func Extend(sym string, source string) uint16 {
	ret, err := ExtendErr(sym, source)
	if err != nil {
		panic(err)
	}
	return ret
}

func makeEvalFunForExpressions(expr *Expression) EvalFunction {
	return func(par *CallParams) []byte {
		varScope := make([]*Call, len(par.args))
		for i := range varScope {
			p := NewCallParams(par.ctx, par.args[i].Args)
			varScope[i] = NewCall(par.args[i].EvalFunc, p)
		}
		nextCtx := NewEvalContext(varScope, par.ctx.glb, par.ctx.prev)
		nextParams := NewCallParams(nextCtx, expr.Args)
		call := NewCall(expr.EvalFunc, nextParams)
		return call.Eval()
	}
}

func evalParamFun(paramNr byte) EvalFunction {
	return func(par *CallParams) []byte {
		return par.ctx.varScope[paramNr].Eval()
	}
}

func ExtendErr(sym string, source string) (uint16, error) {
	f, numParam, _, err := CompileExpression(source)
	if err != nil {
		return 0, fmt.Errorf("error while compiling '%s': %v", sym, err)
	}

	if numExtended >= MaxNumExtended {
		panic("too many extended functions")
	}
	if existsFunction(sym) {
		return 0, errors.New("repeating symbol '" + sym + "'")
	}
	if numParam > 15 {
		return 0, errors.New("can't be more than 15 parameters")
	}
	evalFun := makeEvalFunForExpressions(f)
	if traceYN {
		evalFun = wrapWithTracing(evalFun, sym)
	}
	dscr := &funDescriptor{
		sym:               sym,
		funCode:           uint16(numExtended + FirstExtendedFun),
		requiredNumParams: numParam,
		evalFun:           evalFun,
	}
	theLibrary.funByName[sym] = dscr
	theLibrary.funByFunCode[dscr.funCode] = dscr
	numExtended++
	return dscr.funCode, nil

}

func wrapWithTracing(f EvalFunction, msg string) EvalFunction {
	return func(par *CallParams) []byte {
		fmt.Printf("EvalFunction '%s' - IN\n", msg)
		ret := f(par)
		fmt.Printf("EvalFunction '%s' - OUT: %v\n", msg, ret)
		return ret
	}
}

func mustUniqueName(sym string) {
	if existsFunction(sym) {
		panic("repeating symbol '" + sym + "'")
	}
}

func ExtendMany(source string) error {
	parsed, err := ParseFunctions(source)
	if err != nil {
		return err
	}
	for _, pf := range parsed {
		if _, err = ExtendErr(pf.Sym, pf.SourceCode); err != nil {
			return err
		}
	}
	return nil
}

func MustExtendMany(source string) {
	if err := ExtendMany(source); err != nil {
		panic(err)
	}
}

func existsFunction(sym string) bool {
	_, found := theLibrary.funByName[sym]
	return found
}

func functionByName(sym string) (*funInfo, error) {
	fd, found := theLibrary.funByName[sym]
	if !found {
		return nil, fmt.Errorf("no such function in the library: '%s'", sym)
	}
	ret := &funInfo{
		Sym:       sym,
		FunCode:   fd.funCode,
		NumParams: fd.requiredNumParams,
	}
	switch {
	case fd.funCode < FirstEmbeddedLongFun:
		ret.IsEmbedded = true
		ret.IsShort = true
	case fd.funCode < FirstExtendedFun:
		ret.IsEmbedded = true
		ret.IsShort = false
	}
	return ret, nil
}

func functionByCode(funCode uint16) (EvalFunction, int, error) {
	var libData *funDescriptor
	libData = theLibrary.funByFunCode[funCode]
	if libData == nil {
		return nil, 0, fmt.Errorf("wrong function code %d", funCode)
	}
	return libData.evalFun, libData.requiredNumParams, nil
}

// slices first argument 'from' 'to' inclusive 'to'
func evalSlice(par *CallParams) []byte {
	data := par.Arg(0)
	from := par.Arg(1)
	to := par.Arg(2)
	if from[0] > to[0] {
		panic("wrong slice bounds")
	}
	upper := int(to[0]) + 1
	if upper > len(data) {
		panic("slice out of bounds")
	}
	return data[from[0]:upper]
}

func evalTail(par *CallParams) []byte {
	data := par.Arg(0)
	from := par.Arg(1)
	return data[from[0]:]
}

func evalEqual(par *CallParams) []byte {
	if bytes.Equal(par.Arg(0), par.Arg(1)) {
		return []byte{0xff}
	}
	return nil
}

func evalLen8(par *CallParams) []byte {
	sz := len(par.Arg(0))
	if sz > math.MaxUint8 {
		panic("len8: size of the data > 255")
	}
	return []byte{byte(sz)}
}

func evalLen16(par *CallParams) []byte {
	data := par.Arg(0)
	if len(data) > math.MaxUint16 {
		panic("len16: size of the data > uint16")
	}
	var ret [2]byte
	binary.BigEndian.PutUint16(ret[:], uint16(len(data)))
	return ret[:]
}

func evalIf(par *CallParams) []byte {
	cond := par.Arg(0)
	if len(cond) != 0 {
		// true
		return par.Arg(1)
	}
	return par.Arg(2)
}

func evalIsZero(par *CallParams) []byte {
	for _, b := range par.Arg(0) {
		if b != 0 {
			return nil
		}
	}
	return []byte{0xff}
}

func evalNot(par *CallParams) []byte {
	if len(par.Arg(0)) == 0 {
		return []byte{0xff}
	}
	return nil
}

func evalConcat(par *CallParams) []byte {
	var buf bytes.Buffer
	for i := byte(0); i < par.Arity(); i++ {
		buf.Write(par.Arg(i))
	}
	return buf.Bytes()
}

func evalAnd(par *CallParams) []byte {
	for i := byte(0); i < par.Arity(); i++ {
		if len(par.Arg(i)) == 0 {
			return nil
		}
	}
	return []byte{0xff}
}

func evalOr(par *CallParams) []byte {
	for i := byte(0); i < par.Arity(); i++ {
		if len(par.Arg(i)) != 0 {
			return []byte{0xff}
		}
	}
	return nil
}

func mustArithmArgs(par *CallParams, bytesSize int) ([]byte, []byte) {
	a0 := par.Arg(0)
	a1 := par.Arg(1)
	if len(a0) != bytesSize || len(a1) != bytesSize {
		panic(fmt.Errorf("%d-bytes size parameters expected", bytesSize))
	}
	return a0, a1
}

func evalSum8_16(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 1)
	sum := uint16(a0[0]) + uint16(a1[0])
	ret := make([]byte, 2)
	binary.BigEndian.PutUint16(ret, sum)
	return ret
}

func evalMustSum8(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 1)
	sum := int(a0[0]) + int(a1[0])
	if sum > 255 {
		panic("_mustSum8: arithmetic overflow")
	}
	return []byte{byte(sum)}
}

func evalSum16_32(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 2)
	sum := uint32(binary.BigEndian.Uint16(a0)) + uint32(binary.BigEndian.Uint16(a1))
	ret := make([]byte, 4)
	binary.BigEndian.PutUint32(ret, sum)
	return ret
}

func evalMustSum16(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 2)
	sum := uint32(binary.BigEndian.Uint16(a0)) + uint32(binary.BigEndian.Uint16(a1))
	if sum > math.MaxUint16 {
		panic("_mustSum16: arithmetic overflow")
	}
	ret := make([]byte, 2)
	binary.BigEndian.PutUint16(ret, uint16(sum))
	return ret
}

func evalSum32_64(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 4)
	sum := uint64(binary.BigEndian.Uint32(a0)) + uint64(binary.BigEndian.Uint32(a1))
	ret := make([]byte, 8)
	binary.BigEndian.PutUint64(ret, sum)
	return ret
}

func evalMustSum32(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 4)
	sum := uint64(binary.BigEndian.Uint32(a0)) + uint64(binary.BigEndian.Uint32(a1))
	if sum > math.MaxUint32 {
		panic("_mustSum32: arithmetic overflow")
	}
	ret := make([]byte, 4)
	binary.BigEndian.PutUint32(ret, uint32(sum))
	return ret
}

func evalMustSum64(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 8)
	s0 := binary.BigEndian.Uint64(a0)
	s1 := binary.BigEndian.Uint64(a1)
	if s0 > math.MaxUint64-s1 {
		panic("_mustSum64: arithmetic overflow")
	}
	ret := make([]byte, 8)
	binary.BigEndian.PutUint64(ret, s0+s1)
	return ret
}

func evalMustSub8(par *CallParams) []byte {
	a0, a1 := mustArithmArgs(par, 1)
	if a0[0] < a1[0] {
		panic("_mustSub8: underflow in subtraction")
	}
	return []byte{a0[0] - a1[0]}
}

// lexicographical comparison of two slices of equal length
func evalLessThan(par *CallParams) []byte {
	a0 := par.Arg(0)
	a1 := par.Arg(1)
	if len(a0) != len(a1) {
		panic("evalLessThan: operands must be equal length")
	}
	for i := range a0 {
		if a0[i] < a1[i] {
			return []byte{0xff} // true
		}
	}
	return nil
}

func evalValidSigED25519(ctx *CallParams) []byte {
	msg := ctx.Arg(0)
	signature := ctx.Arg(1)
	pubKey := ctx.Arg(2)

	if ed25519.Verify(pubKey, msg, signature) {
		return []byte{0xff}
	}
	return nil
}

func evalBlake2b(ctx *CallParams) []byte {
	var buf bytes.Buffer
	for i := byte(0); i < ctx.Arity(); i++ {
		buf.Write(ctx.Arg(i))
	}
	ret := blake2b.Sum256(buf.Bytes())
	return ret[:]
}
