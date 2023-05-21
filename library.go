package easyfl

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"reflect"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
)

const (
	EmbeddedReservedUntil = 15
	MaxNumEmbeddedShort   = 64
	FirstEmbeddedLongFun  = MaxNumEmbeddedShort
	MaxNumEmbeddedLong    = 256
	FirstExtendedFun      = FirstEmbeddedLongFun + MaxNumEmbeddedLong
	MaxGlobalFunCode      = 1022
	FirstLocalFunCode     = 1023 // functions in local libraries uses extra byte for local function codes
	MaxNumExtended        = MaxGlobalFunCode - FirstExtendedFun

	MaxParameters = 15
)

type (
	Expression struct {
		// for evaluation
		Args     []*Expression
		EvalFunc EvalFunction
		// for code parsing
		FunctionName string
		CallPrefix   []byte
	}

	EvalFunction func(glb *CallParams) []byte

	funDescriptor struct {
		sym               string
		funCode           uint16
		requiredNumParams int
		evalFun           EvalFunction
		locallyDependent  bool
	}

	funInfo struct {
		Sym        string
		FunCode    uint16
		IsEmbedded bool
		IsShort    bool
		IsLocal    bool
		NumParams  int
	}
)

var (
	globalFunByName    = make(map[string]*funDescriptor)
	globalFunByFunCode = make(map[uint16]*funDescriptor)
	numEmbeddedShort   = EmbeddedReservedUntil + 1
	numEmbeddedLong    int
	numExtended        int
)

const traceYN = false

/*
EasyFL runtime defines a standard library. It is always compiled at startup, in the `init` function.
The library is constructed by function calls:
- 'EmbedShort' adds an embedded function to the library with the short opcode 1-byte long.
Maximum number of short embedded functions is 64
- 'EmbedLong' is the same as 'EmbedShort', only it embeds function with 2 byte long byte code.
Maximum number of embedded function is 256
- 'Extend' adds function defined as a EasyFL expression. Maximum number of extended functions is 702

The 'init' function also includes inline tests with function call 'MustTrue', 'MustEqual', 'MustError'.

'init' panics if library extensions fail or any of inline test fail

The target environment, such as 'EasyUTXO' extends the standard library by using the same function in its 'init'

*/

func init() {
	// basic
	EmbedShort("id", 1, evalId)
	{
		MustEqual("id(0x010203)", "0x010203")
		MustError("id")
	}

	// 'fail' function panics engine. Literal starting with !!! is a call to 'fail' with the message
	EmbedShort("fail", 1, evalFail)
	{
		MustError("fail(100)", "SCRIPT FAIL: error #100")
		MustError("!!!hello,_world!", "hello, world!")
		MustError("!!!fail_error_message_31415", "31415")
	}
	// 'slice' inclusive the end. Expects 1-byte slices at $1 and $2
	EmbedShort("slice", 3, evalSlice)
	{
		MustEqual("slice(0x010203,1,2)", "0x0203")
	}
	// 'byte' takes 1-byte long slice at index
	EmbedShort("byte", 2, evalByte)
	{
		MustEqual("byte(0x010203, 2)", "3")
	}
	// 'tail' takes from $1 to the end
	EmbedShort("tail", 2, evalTail)
	{
		MustEqual("tail(0x010203, 2)", "3")
	}
	EmbedShort("equal", 2, evalEqual)
	EmbedShort("hasPrefix", 2, evalHasPrefix)
	{
		MustTrue("hasPrefix(0xf10203,0xf1)")
	}
	EmbedShort("repeat", 2, evalRepeat)
	{
		MustEqual("repeat(1,5)", "0x0101010101")
	}
	// 'len8' returns length up until 255 (256 and more panics)
	EmbedShort("len8", 1, evalLen8)
	EmbedShort("len16", 1, evalLen16)
	EmbedShort("not", 1, evalNot)
	EmbedShort("if", 3, evalIf)

	// returns false if at least one byte is not 0
	EmbedShort("isZero", 1, evalIsZero)
	{
		MustTrue("isZero(0)")
		MustTrue("isZero(repeat(0,100))")
		MustTrue("not(isZero(0x0000000003))")
	}
	// stateless varargs
	// 'Concat' concatenates variable number of arguments. Concat() is empty byte array
	EmbedLong("concat", -1, evalConcat)
	{
		MustEqual("concat(1,2)", "0x0102")
		MustEqual("concat(1,2,3,4)", "concat(concat(1,2),concat(3,4))")
	}
	EmbedLong("and", -1, evalAnd)
	{
		MustTrue("and")
		MustTrue("not(and(concat))")
	}
	EmbedLong("or", -1, evalOr)
	{
		MustTrue("not(or)")
		MustTrue("not(or(concat))")
		MustTrue("or(1)")
	}
	Extend("nil", "or")
	{
		MustEqual("concat", "nil")
		MustTrue("not(nil)")
	}
	Extend("equiv", "or(and($0,$1), and(not($0),not($1)))")
	{
		MustTrue("equiv(nil, nil)")
		MustTrue("equiv(2, 100)")
		MustTrue("not(equiv(nil, 0))")
	}
	// safe arithmetics
	EmbedShort("sum8", 2, evalMustSum8)
	{
		MustEqual("sum8(5,6)", "sum8(10,1)")
		MustEqual("sum8(5,6)", "11")
	}
	EmbedShort("sum8_16", 2, evalSum8_16)
	{
		MustEqual("sum8_16(5,6)", "sum8_16(10,1)")
		MustEqual("sum8_16(5,6)", "u16/11")
	}
	EmbedShort("sum16", 2, evalMustSum16)
	{
		MustEqual("sum16(u16/5,u16/6)", "sum16(u16/10,u16/1)")
		MustEqual("sum16(u16/5,u16/6)", "u16/11")
	}
	EmbedShort("sum16_32", 2, evalSum16_32)
	EmbedShort("sum32", 2, evalMustSum32)
	EmbedShort("sum32_64", 2, evalSum32_64)
	EmbedShort("sum64", 2, evalMustSum64)
	EmbedShort("sub8", 2, evalMustSub8)
	EmbedShort("mul8_16", 2, evalMul8_16)
	EmbedShort("mul16_32", 2, evalMul16_32)

	// bitwise
	EmbedShort("bitwiseOR", 2, evalBitwiseOR)
	{
		MustEqual("bitwiseOR(0x01, 0x80)", "0x81")
	}
	EmbedShort("bitwiseAND", 2, evalBitwiseAND)
	{
		MustEqual("bitwiseAND(0x03, 0xf2)", "0x02")
		MustEqual("bitwiseAND(0x0102, 0xff00)", "0x0100")
	}
	EmbedShort("bitwiseNOT", 1, evalBitwiseNOT)
	{
		MustEqual("bitwiseNOT(0x00ff)", "0xff00")
	}
	EmbedShort("bitwiseXOR", 2, evalBitwiseXOR)
	{
		MustEqual("bitwiseXOR(0x1234, 0x1234)", "0x0000")
		MustEqual("bitwiseXOR(0x1234, 0xffff)", "bitwiseNOT(0x1234)")
	}
	// comparison
	EmbedShort("lessThan", 2, evalLessThan)
	{
		MustTrue("lessThan(1,2)")
		MustTrue("not(lessThan(2,1))")
		MustTrue("not(lessThan(2,2))")
	}

	Extend("lessOrEqualThan", "or(lessThan($0,$1),equal($0,$1))")
	Extend("greaterThan", "not(lessOrEqualThan($0,$1))")
	Extend("greaterOrEqualThan", "not(lessThan($0,$1))")
	// other

	EmbedLong("validSignatureED25519", 3, evalValidSigED25519)

	EmbedLong("blake2b", -1, evalBlake2b)
	h := blake2b.Sum256([]byte{1})
	{
		MustEqual("len8(blake2b(1))", "32")
		MustEqual("blake2b(1)", fmt.Sprintf("0x%s", hex.EncodeToString(h[:])))
	}
	// code parsing
	// $0 - binary EasyFL code
	// $1 - expected call prefix (#-literal)
	// $2 - number of the parameter to return
	// Panics if the binary code is not the valid call of the specified function or number of the parameter is out of bounds
	// Returns code of the argument if it is a call function, or data is it is a constant
	EmbedLong("parseBytecodeArg", 3, evalParseBytecodeArg)
	EmbedLong("parseBytecodePrefix", 1, evalParseBytecodePrefix)
	EmbedLong("evalBytecodeArg", 3, evalEvalBytecodeArg)
	{
		_, _, binCode, err := CompileExpression("slice(0x01020304,1,2)")
		AssertNoError(err)
		src := fmt.Sprintf("parseBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 0)
		MustEqual(src, "0x01020304")
		src = fmt.Sprintf("parseBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 1)
		MustEqual(src, "1")
		src = fmt.Sprintf("parseBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 2)
		MustEqual(src, "2")
		src = fmt.Sprintf("parseBytecodePrefix(0x%s)", hex.EncodeToString(binCode))
		MustEqual(src, "#slice")

		src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 0)
		MustEqual(src, "0x01020304")
		src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 1)
		MustEqual(src, "1")
		src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 2)
		MustEqual(src, "2")

		_, _, binCode, err = CompileExpression("slice(concat(1,2,concat(3,4)),1,2)")
		AssertNoError(err)
		src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 0)
		MustEqual(src, "0x01020304")
		src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 1)
		MustEqual(src, "1")
		src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 2)
		MustEqual(src, "2")

		_, _, binCode, err = CompileExpression("slice(concat(1,concat(2,3),4),byte(0x020301, 2),sum8(1,1))")
		AssertNoError(err)
		src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 0)
		MustEqual(src, "0x01020304")
		src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 1)
		MustEqual(src, "1")
		src = fmt.Sprintf("evalBytecodeArg(0x%s, #slice, %d)", hex.EncodeToString(binCode), 2)
		MustEqual(src, "2")
	}
	Extend("false", "or")
	Extend("true", "and")

	Extend("require", "or($0,$1)")
	{
		MustError("require(nil, !!!requirement_failed)", "requirement failed")
		MustEqual("require(true, !!!something_wrong)", "true")
	}
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
// locallyDependent is not used currently, it is intended for caching of values TODO
func EmbedShort(sym string, requiredNumPar int, evalFun EvalFunction, contextDependent ...bool) byte {
	Assert(numEmbeddedShort < MaxNumEmbeddedShort, "too many embedded short functions")
	Assert(!existsFunction(sym), "!existsFunction(sym)")
	Assert(requiredNumPar <= 15, "can't be more than 15 parameters")

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
		locallyDependent:  ctxDept,
	}
	globalFunByName[sym] = dscr
	globalFunByFunCode[dscr.funCode] = dscr
	numEmbeddedShort++

	{
		// sanity check
		if requiredNumPar < 0 {
			requiredNumPar = 1
		}
		codeBytes, err := FunctionCallPrefixByName(sym, byte(requiredNumPar))
		AssertNoError(err)
		Assert(len(codeBytes) == 1, "expected short code")
	}
	return byte(dscr.funCode)
}

func EmbedLong(sym string, requiredNumPar int, evalFun EvalFunction) uint16 {
	Assert(numEmbeddedLong < MaxNumEmbeddedLong, "too many embedded long functions")
	Assert(!existsFunction(sym), "!existsFunction(sym)")
	Assert(requiredNumPar <= 15, "can't be more than 15 parameters")
	if traceYN {
		evalFun = wrapWithTracing(evalFun, sym)
	}
	dscr := &funDescriptor{
		sym:               sym,
		funCode:           uint16(numEmbeddedLong + FirstEmbeddedLongFun),
		requiredNumParams: requiredNumPar,
		evalFun:           evalFun,
	}
	globalFunByName[sym] = dscr
	globalFunByFunCode[dscr.funCode] = dscr
	numEmbeddedLong++

	{
		// sanity check
		if requiredNumPar < 0 {
			requiredNumPar = 1
		}
		codeBytes, err := FunctionCallPrefixByName(sym, byte(requiredNumPar))
		AssertNoError(err)
		Assert(len(codeBytes) == 2, "expected long code")
	}
	return dscr.funCode
}

func Extend(sym string, source string) uint16 {
	ret, err := ExtendErr(sym, source)
	if err != nil {
		panic(err)
	}
	return ret
}

func makeEvalFunForExpression(sym string, expr *Expression) EvalFunction {
	return func(par *CallParams) []byte {
		varScope := make([]*call, len(par.args))
		for i := range varScope {
			varScope[i] = newCall(par.args[i].EvalFunc, par.args[i].Args, par.ctx)
		}
		ret := evalExpression(par.ctx.glb, expr, varScope)
		par.Trace("'%s':: %d params -> %s", sym, par.Arity(), Fmt(ret))
		return ret
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

	Assert(numExtended < MaxNumExtended, "too many extended functions")

	if existsFunction(sym) {
		return 0, errors.New("repeating symbol '" + sym + "'")
	}
	if numParam > 15 {
		return 0, errors.New("can't be more than 15 parameters")
	}
	evalFun := makeEvalFunForExpression(sym, f)
	if traceYN {
		evalFun = wrapWithTracing(evalFun, sym)
	}
	dscr := &funDescriptor{
		sym:               sym,
		funCode:           uint16(numExtended + FirstExtendedFun),
		requiredNumParams: numParam,
		evalFun:           evalFun,
	}
	globalFunByName[sym] = dscr
	globalFunByFunCode[dscr.funCode] = dscr
	numExtended++

	{
		// sanity check
		codeBytes, err := FunctionCallPrefixByName(sym, byte(numParam))
		AssertNoError(err)
		Assert(len(codeBytes) == 2, "expected long code")
	}

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

func ExtendMany(source string) error {
	parsed, err := parseFunctions(source)
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

func existsFunction(sym string, localLib ...*LocalLibrary) bool {
	if _, found := globalFunByName[sym]; found {
		return true
	}
	if len(localLib) == 0 {
		return false
	}
	_, found := localLib[0].funByName[sym]
	return found
}

func functionByName(sym string, localLib ...*LocalLibrary) (*funInfo, error) {
	fd, found := globalFunByName[sym]
	ret := &funInfo{
		Sym: sym,
	}
	if found {
		ret.FunCode = fd.funCode
		ret.NumParams = fd.requiredNumParams
		switch {
		case fd.funCode < FirstEmbeddedLongFun:
			ret.IsEmbedded = true
			ret.IsShort = true
		case fd.funCode < FirstExtendedFun:
			ret.IsEmbedded = true
			ret.IsShort = false
		}
	} else {
		if len(localLib) > 0 {
			if fdLoc, foundLocal := localLib[0].funByName[sym]; foundLocal {
				ret.FunCode = fdLoc.funCode
				ret.NumParams = fdLoc.requiredNumParams
				ret.IsLocal = true
			} else {
				ret = nil
			}
		} else {
			ret = nil
		}
	}
	if ret == nil {
		return nil, fmt.Errorf("no such function in the library: '%s'", sym)
	}
	return ret, nil
}

func functionByCode(funCode uint16, localLib ...*LocalLibrary) (EvalFunction, int, string, error) {
	if funCode < FirstLocalFunCode {
		libData := globalFunByFunCode[funCode]
		if libData != nil {
			return libData.evalFun, libData.requiredNumParams, libData.sym, nil
		}
	}
	funCodeLocal := funCode - FirstLocalFunCode
	if len(localLib) == 0 || int(funCodeLocal) >= len(localLib[0].funByFunCode) {
		return nil, 0, "", fmt.Errorf("wrong function code %d", funCode)
	}

	libData := localLib[0].funByFunCode[byte(funCodeLocal)]
	if libData == nil {
		return nil, 0, "", fmt.Errorf("wrong local function code %d", funCode)
	}
	sym := fmt.Sprintf("lib#%d)", funCodeLocal)
	return libData.evalFun, libData.requiredNumParams, sym, nil
}

func (fi *funInfo) callPrefix(numArgs byte) ([]byte, error) {
	var ret []byte
	if fi.IsShort {
		Assert(fi.FunCode > 15, "internal inconsistency: fi.FunCode must be > 15")
		ret = []byte{byte(fi.FunCode)}
	} else {
		if fi.NumParams < 0 {
			// vararg function
			if numArgs > 15 {
				return nil, fmt.Errorf("internal inconsistency: number of arguments must be <= 15")
			}
		} else {
			if int(numArgs) != fi.NumParams {
				return nil, fmt.Errorf("wrong number of arguments")
			}
		}
		firstByte := FirstByteLongCallMask | (numArgs << 2)
		if !fi.IsLocal {
			// normal long function call 2 bytes
			u16 := (uint16(firstByte) << 8) | fi.FunCode
			ret = make([]byte, 2)
			binary.BigEndian.PutUint16(ret, u16)
		} else {
			Assert(fi.FunCode <= FirstLocalFunCode+255 && FirstLocalFunCode <= fi.FunCode, "fi.FunCode <= FirstLocalFunCode+255 && FirstLocalFunCode <= fi.FunCode")
			// local function call 3 bytes
			u16 := (uint16(firstByte) << 8) | FirstLocalFunCode
			ret = make([]byte, 3)
			binary.BigEndian.PutUint16(ret[:2], u16)
			ret[2] = byte(fi.FunCode - FirstLocalFunCode)
		}
	}
	return ret, nil
}

func FunctionCallPrefixByName(sym string, numArgs byte) ([]byte, error) {
	fi, err := functionByName(sym)
	if err != nil {
		return nil, err
	}
	return fi.callPrefix(numArgs)
}

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
		par.TracePanic("_mustSub8:: %s, %s -> underflow in subtraction", Fmt(a0), Fmt(a1))
	}
	ret := []byte{a0[0] - a1[0]}
	par.Trace("sub8:: %s, %s -> %s", Fmt(a0), Fmt(a1), Fmt(ret))
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

func evalParseBytecodeArg(par *CallParams) []byte {
	a0 := par.Arg(0)
	_, prefix, args, err := ParseBytecodeOneLevel(a0)
	if err != nil {
		par.TracePanic("evalParseBytecodeArg:: %v", err)
	}
	expectedPrefix := par.Arg(1)
	idx := par.Arg(2)
	if !bytes.Equal(prefix, expectedPrefix) {
		par.TracePanic("evalParseBytecodeArg: unexpected function prefix. Expected '%s', got '%s'", Fmt(expectedPrefix), Fmt(prefix))
	}
	if len(idx) != 1 || len(args) <= int(idx[0]) {
		par.TracePanic("evalParseBytecodeArg: wrong parameter index")
	}
	ret := StripDataPrefix(args[idx[0]])
	par.Trace("parseBytecodeArg:: %s, %s, %s -> %s", Fmt(a0), Fmt(expectedPrefix), Fmt(idx), Fmt(ret))
	return ret
}

func evalParseBytecodePrefix(par *CallParams) []byte {
	code := par.Arg(0)
	prefix, err := ParseBytecodePrefix(code)
	if err != nil {
		par.TracePanic("evalParseBytecodePrefix: %v", err)
	}
	par.Trace("parseBytecodePrefix::%s -> %s", Fmt(code), Fmt(prefix))
	return prefix
}

func evalEvalBytecodeArg(par *CallParams) []byte {
	a0 := par.Arg(0)
	_, prefix, args, err := ParseBytecodeOneLevel(a0)
	if err != nil {
		par.TracePanic("evalParseBytecodeArg:: %v", err)
	}
	expectedPrefix := par.Arg(1)
	idx := par.Arg(2)
	if !bytes.Equal(prefix, expectedPrefix) {
		par.TracePanic("evalParseBytecodeArg: unexpected function prefix. Expected '%s', got '%s'", Fmt(expectedPrefix), Fmt(prefix))
	}
	if len(idx) != 1 || len(args) <= int(idx[0]) {
		par.TracePanic("evalParseBytecodeArg: wrong parameter index")
	}

	ret, err := EvalFromBinary(par.ctx.glb, args[idx[0]])
	if err != nil {
		par.TracePanic("evaldBytecodeArg:: %s, %s, %s", Fmt(a0), Fmt(expectedPrefix), Fmt(idx))
	}

	par.Trace("evaldBytecodeArg:: %s, %s, %s -> %s", Fmt(a0), Fmt(expectedPrefix), Fmt(idx), Fmt(ret))
	return ret
}
