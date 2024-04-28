package easyfl

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"

	"golang.org/x/crypto/blake2b"
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
		bytecode          []byte
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

	Library struct {
		funByName        map[string]*funDescriptor
		funByFunCode     map[uint16]*funDescriptor
		numEmbeddedShort int
		numEmbeddedLong  int
		numExtended      int
	}
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

func NewBase() *Library {
	ret := newLibrary()
	ret.init()
	return ret
}

func (lib *Library) init() {
	// basic
	lib.EmbedShort("id", 1, evalId)
	{
		lib.MustEqual("id(0x010203)", "0x010203")
		lib.MustError("id")
	}

	// 'fail' function panics engine. Literal starting with !!! is a call to 'fail' with the message
	lib.EmbedShort("fail", 1, evalFail)
	{
		lib.MustError("fail(100)", "SCRIPT FAIL: error #100")
		lib.MustError("!!!hello,_world!", "hello, world!")
		lib.MustError("!!!fail_error_message_31415", "31415")
	}
	// 'slice' inclusive the end. Expects 1-byte slices at $1 and $2
	lib.EmbedShort("slice", 3, evalSlice)
	{
		lib.MustEqual("slice(0x010203,1,2)", "0x0203")
	}
	// 'byte' takes 1-byte long slice at index
	lib.EmbedShort("byte", 2, evalByte)
	{
		lib.MustEqual("byte(0x010203, 2)", "3")
	}
	// 'tail' takes from $1 to the end
	lib.EmbedShort("tail", 2, evalTail)
	{
		lib.MustEqual("tail(0x010203, 2)", "3")
	}
	lib.EmbedShort("equal", 2, evalEqual)
	lib.EmbedShort("hasPrefix", 2, evalHasPrefix)
	{
		lib.MustTrue("hasPrefix(0xf10203,0xf1)")
	}
	lib.EmbedShort("repeat", 2, evalRepeat)
	{
		lib.MustEqual("repeat(1,5)", "0x0101010101")
	}
	// 'len8' returns length up until 255 (256 and more panics)
	lib.EmbedShort("len8", 1, evalLen8)
	lib.EmbedShort("len16", 1, evalLen16)
	lib.EmbedShort("not", 1, evalNot)
	lib.EmbedShort("if", 3, evalIf)

	// returns false if at least one byte is not 0
	lib.EmbedShort("isZero", 1, evalIsZero)
	{
		lib.MustTrue("isZero(0)")
		lib.MustTrue("isZero(repeat(0,100))")
		lib.MustTrue("not(isZero(0x0000000003))")
	}
	// stateless varargs
	// 'Concat' concatenates variable number of arguments. Concat() is empty byte array
	lib.EmbedLong("concat", -1, evalConcat)
	{
		lib.MustEqual("concat(1,2)", "0x0102")
		lib.MustEqual("concat(1,2,3,4)", "concat(concat(1,2),concat(3,4))")
	}
	lib.EmbedLong("and", -1, evalAnd)
	{
		lib.MustTrue("and")
		lib.MustTrue("not(and(concat))")
	}
	lib.EmbedLong("or", -1, evalOr)
	{
		lib.MustTrue("not(or)")
		lib.MustTrue("not(or(concat))")
		lib.MustTrue("or(1)")
	}
	lib.Extend("nil", "or")
	{
		lib.MustEqual("concat", "nil")
		lib.MustTrue("not(nil)")
	}
	lib.Extend("equiv", "or(and($0,$1), and(not($0),not($1)))")
	{
		lib.MustTrue("equiv(nil, nil)")
		lib.MustTrue("equiv(2, 100)")
		lib.MustTrue("not(equiv(nil, 0))")
	}
	// safe arithmetics
	lib.EmbedShort("add", 2, evalAddUint)
	{
		lib.MustEqual("add(5,6)", "add(10,1)")
		lib.MustEqual("add(5,6)", "u64/11")
		lib.MustEqual("add(0, 0)", "u64/0")
		lib.MustEqual("add(u16/1337, 0)", "u64/1337")
		lib.MustError("add(nil, 0)", "wrong size of parameters")
	}
	lib.EmbedShort("sub", 2, evalSubUint)
	{
		lib.MustEqual("sub(6,6)", "u64/0")
		lib.MustEqual("sub(6,5)", "u64/1")
		lib.MustEqual("sub(0, 0)", "u64/0")
		lib.MustEqual("sub(u16/1337, 0)", "u64/1337")
		lib.MustError("sub(nil, 0)", "wrong size of parameters")
		lib.MustError("sub(10, 100)", "underflow in subtraction")
	}
	lib.EmbedShort("mul", 2, evalMulUint)
	{
		lib.MustEqual("mul(5,6)", "mul(15,2)")
		lib.MustEqual("mul(5,6)", "u64/30")
		lib.MustEqual("mul(u16/1337, 0)", "u64/0")
		lib.MustEqual("mul(0, u32/1337133700)", "u64/0")
		lib.MustError("mul(nil, 5)", "wrong size of parameters")
	}
	lib.EmbedShort("div", 2, evalDivUint)
	{
		lib.MustEqual("div(100,100)", "u64/1")
		lib.MustEqual("div(100,110)", "u64/0")
		lib.MustEqual("div(u32/10000,u16/10000)", "u64/1")
		lib.MustEqual("div(0, u32/1337133700)", "u64/0")
		lib.MustError("div(u32/1337133700, 0)", "integer divide by zero")
		lib.MustError("div(nil, 5)", "wrong size of parameters")
	}
	lib.EmbedShort("mod", 2, evalModuloUint)
	{
		lib.MustEqual("mod(100,100)", "u64/0")
		lib.MustEqual("mod(107,100)", "u64/7")
		lib.MustEqual("mod(u32/10100,u16/10000)", "u64/100")
		lib.MustEqual("mod(0, u32/1337133700)", "u64/0")
		lib.MustError("mod(u32/1337133700, 0)", "integer divide by zero")
		lib.MustError("mod(nil, 5)", "wrong size of parameters")
		lib.MustEqual("add(mul(div(u32/27, u16/4), 4), mod(u32/27, 4))", "u64/27")
	}
	lib.EmbedShort("equalUint", 2, evalEqualUint)
	{
		lib.MustTrue("equalUint(100,100)")
		lib.MustTrue("equalUint(100,u32/100)")
		lib.MustTrue("not(equalUint(100,u32/1337))")
		lib.MustError("equalUint(nil, 5)", "wrong size of parameters")
	}

	// bitwise
	lib.EmbedShort("bitwiseOR", 2, evalBitwiseOR)
	{
		lib.MustEqual("bitwiseOR(0x01, 0x80)", "0x81")
	}
	lib.EmbedShort("bitwiseAND", 2, evalBitwiseAND)
	{
		lib.MustEqual("bitwiseAND(0x03, 0xf2)", "0x02")
		lib.MustEqual("bitwiseAND(0x0102, 0xff00)", "0x0100")
	}
	lib.EmbedShort("bitwiseNOT", 1, evalBitwiseNOT)
	{
		lib.MustEqual("bitwiseNOT(0x00ff)", "0xff00")
	}
	lib.EmbedShort("bitwiseXOR", 2, evalBitwiseXOR)
	{
		lib.MustEqual("bitwiseXOR(0x1234, 0x1234)", "0x0000")
		lib.MustEqual("bitwiseXOR(0x1234, 0xffff)", "bitwiseNOT(0x1234)")
	}
	// comparison
	lib.EmbedShort("lessThan", 2, evalLessThan)
	{
		lib.MustTrue("lessThan(1,2)")
		lib.MustTrue("not(lessThan(2,1))")
		lib.MustTrue("not(lessThan(2,2))")
	}

	lib.Extend("lessOrEqualThan", "or(lessThan($0,$1),equal($0,$1))")
	lib.Extend("greaterThan", "not(lessOrEqualThan($0,$1))")
	lib.Extend("greaterOrEqualThan", "not(lessThan($0,$1))")
	// other

	lib.EmbedLong("lshift64", 2, evalLShift64)
	{
		lib.MustEqual("lshift64(u64/3, u64/2)", "u64/12")
		lib.MustTrue("isZero(lshift64(u64/2001, u64/64))")
		lib.MustTrue("equal(lshift64(u64/2001, u64/4), mul(u64/2001, u16/16))")
		lib.MustError("lshift64(u64/2001, nil)", "wrong size of parameters")
	}

	lib.EmbedLong("rshift64", 2, evalRShift64)
	{
		lib.MustEqual("rshift64(u64/15, u64/2)", "u64/3")
		lib.MustTrue("isZero(rshift64(0xffffffffffffffff, u64/64))")
		lib.MustTrue("equal(rshift64(u64/2001, u64/3), div(u64/2001, 8))")
		lib.MustError("rshift64(u64/2001, nil)", "wrong size of parameters")
	}

	lib.EmbedLong("validSignatureED25519", 3, evalValidSigED25519)

	lib.EmbedLong("blake2b", -1, evalBlake2b)
	h := blake2b.Sum256([]byte{1})
	{
		lib.MustEqual("len8(blake2b(1))", "32")
		lib.MustEqual("blake2b(1)", fmt.Sprintf("0x%s", hex.EncodeToString(h[:])))
	}
	// code parsing
	// $0 - binary EasyFL code
	// $1 - expected call prefix (#-literal)
	// $2 - number of the parameter to return
	// Panics if the binary code is not the valid call of the specified function or number of the parameter is out of bounds
	// Returns code of the argument if it is a call function, or data is it is a constant
	lib.EmbedLong("unwrapBytecodeArg", 3, lib.evalUnwrapBytecodeArg)
	lib.EmbedLong("parseBytecodePrefix", 1, lib.evalParseBytecodePrefix)
	lib.EmbedLong("evalBytecodeArg", 3, lib.evalEvalBytecodeArg)
	{
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
	lib.Extend("false", "or")
	lib.Extend("true", "and")

	lib.Extend("require", "or($0,$1)")
	{
		lib.MustError("require(nil, !!!requirement_failed)", "requirement failed")
		lib.MustEqual("require(true, !!!something_wrong)", "true")
	}
}

func newLibrary() *Library {
	return &Library{
		funByName:        make(map[string]*funDescriptor),
		funByFunCode:     make(map[uint16]*funDescriptor),
		numEmbeddedShort: EmbeddedReservedUntil + 1,
	}
}

func (lib *Library) PrintLibraryStats() {
	h := lib.LibraryHash()
	fmt.Printf(`EasyFL function library (hash: %s):
    number of short embedded: %d out of max %d
    number of long embedded: %d out of max %d
    number of extended: %d out of max %d
`,
		hex.EncodeToString(h[:]), lib.numEmbeddedShort, MaxNumEmbeddedShort, lib.numEmbeddedLong, MaxNumEmbeddedLong, lib.numExtended, MaxNumExtended)
}

// EmbedShort embeds short-callable function inti the library
// locallyDependent is not used currently, it is intended for caching of values TODO
func (lib *Library) EmbedShort(sym string, requiredNumPar int, evalFun EvalFunction, contextDependent ...bool) byte {
	Assert(lib.numEmbeddedShort < MaxNumEmbeddedShort, "too many embedded short functions")
	Assert(!lib.existsFunction(sym), "!existsFunction(sym)")
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
		funCode:           uint16(lib.numEmbeddedShort),
		requiredNumParams: requiredNumPar,
		evalFun:           evalFun,
		locallyDependent:  ctxDept,
	}
	lib.funByName[sym] = dscr
	lib.funByFunCode[dscr.funCode] = dscr
	lib.numEmbeddedShort++

	{
		// sanity check
		if requiredNumPar < 0 {
			requiredNumPar = 1
		}
		codeBytes, err := lib.FunctionCallPrefixByName(sym, byte(requiredNumPar))
		AssertNoError(err)
		Assert(len(codeBytes) == 1, "expected short code")
	}
	return byte(dscr.funCode)
}

func (lib *Library) EmbedLong(sym string, requiredNumPar int, evalFun EvalFunction) uint16 {
	Assert(lib.numEmbeddedLong < MaxNumEmbeddedLong, "too many embedded long functions")
	Assert(!lib.existsFunction(sym), "!existsFunction(sym)")
	Assert(requiredNumPar <= 15, "can't be more than 15 parameters")
	if traceYN {
		evalFun = wrapWithTracing(evalFun, sym)
	}
	dscr := &funDescriptor{
		sym:               sym,
		funCode:           uint16(lib.numEmbeddedLong + FirstEmbeddedLongFun),
		requiredNumParams: requiredNumPar,
		evalFun:           evalFun,
	}
	lib.funByName[sym] = dscr
	lib.funByFunCode[dscr.funCode] = dscr
	lib.numEmbeddedLong++

	{
		// sanity check
		if requiredNumPar < 0 {
			requiredNumPar = 1
		}
		codeBytes, err := lib.FunctionCallPrefixByName(sym, byte(requiredNumPar))
		AssertNoError(err)
		Assert(len(codeBytes) == 2, "expected long code")
	}
	return dscr.funCode
}

func (lib *Library) Extend(sym string, source string) uint16 {
	ret, err := lib.ExtendErr(sym, source)
	if err != nil {
		panic(err)
	}
	return ret
}

func (lib *Library) Extendf(sym string, template string, args ...any) uint16 {
	ret, err := lib.ExtendErr(sym, fmt.Sprintf(template, args...))
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

func (lib *Library) ExtendErr(sym string, source string) (uint16, error) {
	f, numParam, bytecode, err := lib.CompileExpression(source)
	if err != nil {
		return 0, fmt.Errorf("error while compiling '%s': %v", sym, err)
	}

	Assert(lib.numExtended < MaxNumExtended, "too many extended functions")

	if lib.existsFunction(sym) {
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
		funCode:           uint16(lib.numExtended + FirstExtendedFun),
		bytecode:          bytecode,
		requiredNumParams: numParam,
		evalFun:           evalFun,
	}
	lib.funByName[sym] = dscr
	lib.funByFunCode[dscr.funCode] = dscr
	lib.numExtended++

	{
		// sanity check
		codeBytes, err := lib.FunctionCallPrefixByName(sym, byte(numParam))
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

func (lib *Library) ExtendMany(source string) error {
	parsed, err := parseFunctions(source)
	if err != nil {
		return err
	}
	for _, pf := range parsed {
		if _, err = lib.ExtendErr(pf.Sym, pf.SourceCode); err != nil {
			return err
		}
	}
	return nil
}

func (lib *Library) MustExtendMany(source string) {
	if err := lib.ExtendMany(source); err != nil {
		panic(err)
	}
}

// LibraryHash returns hash of the library code and locks library against modifications.
// It is used for consistency checking and compatibility check
// Should not be invoked from func init()
func (lib *Library) LibraryHash() [32]byte {
	ret := blake2b.Sum256(lib.libraryBytes())
	return ret
}

func (lib *Library) libraryBytes() []byte {
	var buf bytes.Buffer

	funCodes := make([]uint16, 0, len(lib.funByFunCode))
	for funCode := range lib.funByFunCode {
		funCodes = append(funCodes, funCode)
	}
	sort.Slice(funCodes, func(i, j int) bool {
		return funCodes[i] < funCodes[j]
	})
	for _, fc := range funCodes {
		lib.funByFunCode[fc].write(&buf)
	}
	return buf.Bytes()
}

func (fd *funDescriptor) write(w io.Writer) {
	_, _ = w.Write([]byte(fd.sym))
	var funCodeBin [2]byte
	binary.BigEndian.PutUint16(funCodeBin[:], fd.funCode)
	_, _ = w.Write(funCodeBin[:])
	_, _ = w.Write(fd.bytecode)
}

func (lib *Library) existsFunction(sym string, localLib ...*LocalLibrary) bool {
	if _, found := lib.funByName[sym]; found {
		return true
	}
	if len(localLib) == 0 {
		return false
	}
	_, found := localLib[0].funByName[sym]
	return found
}

func (lib *Library) functionByName(sym string, localLib ...*LocalLibrary) (*funInfo, error) {
	fd, found := lib.funByName[sym]
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

func (lib *Library) functionByCode(funCode uint16, localLib ...*LocalLibrary) (EvalFunction, int, string, error) {
	if funCode < FirstLocalFunCode {
		libData := lib.funByFunCode[funCode]
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

func (lib *Library) FunctionCallPrefixByName(sym string, numArgs byte) ([]byte, error) {
	fi, err := lib.functionByName(sym)
	if err != nil {
		return nil, err
	}
	return fi.callPrefix(numArgs)
}
