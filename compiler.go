package easyfl

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"go/token"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode"

	"github.com/lunfardo314/easyfl/easyfl_util"
	"github.com/lunfardo314/easyfl/slicepool"
)

// funParsed is an interim representation of the source code
type funParsed struct {
	Sym        string
	SourceCode string
}

// parsedExpression interim representation of the parsed expression
type parsedExpression struct {
	sym    string
	params []*parsedExpression
}

// parseFunctions parses many function definitions
func parseFunctions(s string) ([]*funParsed, error) {
	lines := splitLinesStripComments(s)
	ret, err := parseDefs(lines)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func splitLinesStripComments(s string) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "//")
		lines = append(lines, strings.TrimSpace(line))
	}
	return lines
}

func parseDefs(lines []string) ([]*funParsed, error) {
	ret := make([]*funParsed, 0)
	var current *funParsed
	for lineno, line := range lines {
		if strings.HasPrefix(line, "func ") {
			if current != nil {
				current.SourceCode = stripSpaces(current.SourceCode)
				ret = append(ret, current)
			}
			sym, body, found := strings.Cut(strings.TrimPrefix(line, "func "), ":")
			if !found {
				return nil, fmt.Errorf("':' expectected @ line %d", lineno)
			}
			current = &funParsed{
				Sym:        strings.TrimSpace(sym),
				SourceCode: body,
			}
			if !token.IsIdentifier(current.Sym) {
				return nil, fmt.Errorf("'%s' is not an identifier", sym)
			}
		} else {
			if len(stripSpaces(line)) == 0 {
				continue
			}
			if current == nil {
				return nil, fmt.Errorf("unexpectected symbols @ line %d", lineno)
			}
			current.SourceCode += line
		}
	}
	if current != nil {
		current.SourceCode = stripSpaces(current.SourceCode)
		ret = append(ret, current)
	}
	return ret, nil
}

func stripSpaces(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			// if the character is a space, drop it
			return -1
		}
		// else keep it in the string
		return r
	}, str)
}

func parseExpression(s string) (*parsedExpression, error) {
	name, rest, foundOpen := strings.Cut(s, "(")
	f := &parsedExpression{
		sym:    name,
		params: make([]*parsedExpression, 0),
	}
	if !foundOpen {
		if strings.Contains(rest, ")") || strings.Contains(rest, ",") {
			return nil, fmt.Errorf("unexpected ')': '%s'", s)
		}
		return f, nil
	}
	spl, err := splitArgs(rest)
	if err != nil {
		return nil, err
	}
	var ff *parsedExpression
	for _, _call := range spl {
		if ff, err = parseExpression(_call); err != nil {
			return nil, err
		}
		f.params = append(f.params, ff)
	}
	if len(f.params) > MaxParameters {
		return nil, fmt.Errorf("can't be more than %d parameters", MaxParameters)
	}
	return f, nil
}

// parseArgs expects ','-delimited list of calls, which ends with ')'
func splitArgs(argsStr string) ([]string, error) {
	ret := make([]string, 0)
	var buf bytes.Buffer
	level := 0
	for _, c := range []byte(argsStr) {
		if level < 0 {
			return nil, fmt.Errorf("unbalanced paranthesis: '%s'", argsStr)
		}
		switch c {
		case ',':
			if level == 0 {
				p := make([]byte, len(buf.Bytes()))
				copy(p, buf.Bytes())
				ret = append(ret, string(p))
				buf.Reset()
			} else {
				buf.WriteByte(c)
			}
		case '(':
			buf.WriteByte(c)
			level++
		case ')':
			level--
			if level >= 0 {
				buf.WriteByte(c)
			}
		default:
			buf.WriteByte(c)
		}
	}
	if level != -1 {
		return nil, fmt.Errorf("unclosed '(': '%s'", argsStr)
	}
	if len(buf.Bytes()) > 0 {
		p := make([]byte, len(buf.Bytes()))
		copy(p, buf.Bytes())
		ret = append(ret, string(p))
	}
	return ret, nil
}

// Byte serialization of the formula:
//
// prefix[0] || prefix[1] || suffix
// prefix[0] bits
// - bit 7 (FirstByteDataMask) : 0 is library function, 1 is inline data
// - if inline data: bits 6-0 is size of the inline data, 0-127
// - if library function:
//  - if bit 6 (FirstByteLongCallMask) is 0, it is inline parameter only byte prefix[0] is used
//  - bits 5-0 are interpreted inline (values 0-63) call to short embedded function with fixed arity
//    some values are used, some are reserved
//  - if bit 6 (FirstByteLongCallMask) is 1, it is long call.
//  -- bits 5-2 are interpreted as arity of the long call (values 0-15)
//  -- the prefix[0] byte is extended with prefix[1] the prefix 1-2 is interpreted as uint16 bigendian
//  -- bits 9-0 of uint16 is the long code of the called function (values 0-1023)

const (
	FirstByteDataMask          = byte(0x01) << 7
	FirstByteDataLenMask       = ^FirstByteDataMask
	FirstByteLongCallMask      = byte(0x01) << 6
	FirstByteLongCallArityMask = byte(0x0f) << 2
	Uint16LongCallCodeMask     = ^(uint16(FirstByteDataMask|FirstByteLongCallMask|FirstByteLongCallArityMask) << 8)
)

// bytecodeFromParsedExpression takes parsed expression and generates bytecode of it
func (f *parsedExpression) bytecodeFromParsedExpression(lib *Library, w io.Writer, localLib ...*LocalLibrary) (int, error) {
	numArgs := 0
	if len(f.params) == 0 {
		isLiteral, nArgs, err := parseLiteral(lib, f.sym, w)
		if err != nil {
			return 0, err
		}
		if isLiteral {
			return nArgs, nil
		}
	}
	// either has arguments or not literal
	// try if it is a short call
	fi, err := lib.functionByName(f.sym, localLib...)
	if err != nil {
		return 0, err
	}
	if fi.NumParams >= 0 && fi.NumParams != len(f.params) {
		return 0, fmt.Errorf("%d arguments required, got %d: '%s'", fi.NumParams, len(f.params), f.sym)
	}

	callBytes, err := fi.callPrefix(byte(len(f.params)))
	if err != nil {
		return 0, err
	}
	// write call bytes
	if _, err = w.Write(callBytes); err != nil {
		return 0, err
	}
	// generate code for call parameters
	var n int
	for _, ff := range f.params {
		if n, err = ff.bytecodeFromParsedExpression(lib, w, localLib...); err != nil {
			return 0, err
		}
		if n > numArgs {
			numArgs = n
		}
	}
	return numArgs, nil
}

func writeDataWithPrefix(w io.Writer, data []byte) error {
	if len(data) > 127 {
		return errors.New("too long inline data")
	}
	_, err := w.Write([]byte{FirstByteDataMask | byte(len(data))})
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func mustDataWithPrefix(data []byte) []byte {
	var buf bytes.Buffer
	err := writeDataWithPrefix(&buf, data)
	easyfl_util.AssertNoError(err)
	return buf.Bytes()
}

func parseLiteral(lib *Library, sym string, w io.Writer) (bool, int, error) {
	// write bytecode data
	n, err := strconv.Atoi(sym)
	itIsANumber := err == nil

	var b, funCallPrefix []byte
	var un uint64
	var fi *funInfo

	switch {
	case itIsANumber:
		if n < 0 || n >= 256 {
			return false, 0, fmt.Errorf("integer constant value must be uint8: %s", sym)
		}
		// it is a 1 byte value
		if err = writeDataWithPrefix(w, []byte{byte(n)}); err != nil {
			return false, 0, err
		}
		return true, 0, nil
	case strings.HasPrefix(sym, "$$"):
		// bytecode parameter reference function
		n, err = strconv.Atoi(sym[2:])
		if err != nil {
			return false, 0, err
		}
		if n < 0 || n > MaxParameters {
			return false, 0, fmt.Errorf("wrong bytecode parameter reference '%s'", sym)
		}
		if _, err = w.Write([]byte{BytecodeParameterFlag | byte(n)}); err != nil {
			return false, 0, err
		}
		return true, n + 1, nil
	case strings.HasPrefix(sym, "$"):
		// eval parameter reference function
		n, err = strconv.Atoi(sym[1:])
		if err != nil {
			return false, 0, err
		}
		if n < 0 || n > MaxParameters {
			return false, 0, fmt.Errorf("wrong eval parameter reference '%s'", sym)
		}
		if _, err = w.Write([]byte{byte(n)}); err != nil {
			return false, 0, err
		}
		return true, n + 1, nil
	case sym == "nil":
		if _, err = w.Write([]byte{FirstByteDataMask}); err != nil {
			return false, 0, err
		}
		return true, 0, nil
	case strings.HasPrefix(sym, "0x"):
		// it is hexadecimal constant
		if b, err = hex.DecodeString(sym[2:]); err != nil {
			return false, 0, fmt.Errorf("%v: '%s'", err, sym)
		}
		if len(b) > 127 {
			return false, 0, fmt.Errorf("hexadecimal constant can't be longer than 127 bytes: '%s'", sym)
		}
		if err = writeDataWithPrefix(w, b); err != nil {
			return false, 0, err
		}
		return true, 0, nil
	case strings.HasPrefix(sym, "x/"):
		// it is an inline bytecode
		if b, err = hex.DecodeString(sym[2:]); err != nil {
			return false, 0, fmt.Errorf("%v: '%s'", err, sym)
		}
		// write the code as is
		if _, err = w.Write(b); err != nil {
			return false, 0, err
		}
		return true, 0, nil
	case strings.HasPrefix(sym, "u16/"):
		// it is u16 constant big endian
		n, err = strconv.Atoi(strings.TrimPrefix(sym, "u16/"))
		if err != nil {
			return false, 0, fmt.Errorf("%v: '%s'", err, sym)
		}
		if n < 0 || n > math.MaxUint16 {
			return false, 0, fmt.Errorf("wrong u16 constant: '%s'", sym)
		}
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(n))
		if err = writeDataWithPrefix(w, b[:]); err != nil {
			return false, 0, err
		}
		return true, 0, nil
	case strings.HasPrefix(sym, "u32/"):
		// it is u16 constant big endian
		n, err = strconv.Atoi(strings.TrimPrefix(sym, "u32/"))
		if err != nil {
			return false, 0, fmt.Errorf("%v: '%s'", err, sym)
		}
		if n < 0 || n > math.MaxUint32 {
			return false, 0, fmt.Errorf("wrong u32 constant: '%s'", sym)
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(n))
		if err = writeDataWithPrefix(w, b[:]); err != nil {
			return false, 0, err
		}
		return true, 0, nil
	case strings.HasPrefix(sym, "u64/"):
		// it is u16 constant big endian
		if un, err = strconv.ParseUint(strings.TrimPrefix(sym, "u64/"), 10, 64); err != nil {
			return false, 0, fmt.Errorf("%v: '%s'", err, sym)
		}
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], un)
		if err = writeDataWithPrefix(w, b[:]); err != nil {
			return false, 0, err
		}
		return true, 0, nil
	case strings.HasPrefix(sym, "z16/"):
		// it is u16 constant big endian
		n, err = strconv.Atoi(strings.TrimPrefix(sym, "z16/"))
		if err != nil {
			return false, 0, fmt.Errorf("%v: '%s'", err, sym)
		}
		if n < 0 || n > math.MaxUint16 {
			return false, 0, fmt.Errorf("wrong z16 constant: '%s'", sym)
		}
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(n))
		if err = writeDataWithPrefix(w, easyfl_util.TrimLeadingZeroBytes(b[:])); err != nil {
			return false, 0, err
		}
		return true, 0, nil
	case strings.HasPrefix(sym, "z32/"):
		// it is u16 constant big endian
		n, err = strconv.Atoi(strings.TrimPrefix(sym, "z32/"))
		if err != nil {
			return false, 0, fmt.Errorf("%v: '%s'", err, sym)
		}
		if n < 0 || n > math.MaxUint32 {
			return false, 0, fmt.Errorf("wrong z32 constant: '%s'", sym)
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(n))
		if err = writeDataWithPrefix(w, easyfl_util.TrimLeadingZeroBytes(b[:])); err != nil {
			return false, 0, err
		}
		return true, 0, nil
	case strings.HasPrefix(sym, "z64/"):
		// it is u16 constant big endian
		if un, err = strconv.ParseUint(strings.TrimPrefix(sym, "z64/"), 10, 64); err != nil {
			return false, 0, fmt.Errorf("%v: '%s'", err, sym)
		}
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], un)
		if err = writeDataWithPrefix(w, easyfl_util.TrimLeadingZeroBytes(b[:])); err != nil {
			return false, 0, err
		}
		return true, 0, nil
	case strings.HasPrefix(sym, "#"):
		// function call prefix literal
		funName := strings.TrimPrefix(sym, "#")
		if fi, err = lib.functionByName(funName); err != nil {
			return false, 0, err
		}
		numArgs := fi.NumParams
		if numArgs < 0 {
			numArgs = 0
		}
		if funCallPrefix, err = fi.callPrefix(byte(numArgs)); err != nil {
			return false, 0, err
		}
		if _, err = w.Write([]byte{FirstByteDataMask | byte(len(funCallPrefix))}); err != nil {
			return false, 0, err
		}
		if _, err = w.Write(funCallPrefix); err != nil {
			return false, 0, err
		}
		return true, 0, nil
	case strings.HasPrefix(sym, "!!!"):
		// 'fail' literal
		msg := strings.TrimPrefix(sym, "!!!")
		msgData := []byte(strings.Replace(msg, "_", " ", -1))
		if len(msgData) > 127 {
			return false, 0, fmt.Errorf("fail message can't be longer than 127 bytes: '%s'", sym)
		}
		fi, err = lib.functionByName("fail")
		easyfl_util.AssertNoError(err)
		funCallPrefix, err = fi.callPrefix(1)
		easyfl_util.AssertNoError(err)
		if _, err = w.Write(funCallPrefix); err != nil {
			return false, 0, err
		}
		if _, err = w.Write([]byte{FirstByteDataMask | byte(len(msgData))}); err != nil {
			return false, 0, err
		}
		if _, err = w.Write(msgData); err != nil {
			return false, 0, err
		}
		return true, 0, nil
	}
	return false, 0, nil
}

// ExpressionSourceToBytecode compiles expression from source form into the canonical bytecode representation
func (lib *Library) ExpressionSourceToBytecode(formulaSource string, localLib ...*LocalLibrary) ([]byte, int, error) {
	f, err := parseExpression(formulaSource)
	if err != nil {
		return nil, 0, err
	}

	var buf bytes.Buffer
	numArgs, err := f.bytecodeFromParsedExpression(lib, &buf, localLib...)
	if err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), numArgs, nil
}

// ExpressionFromBytecode creates evaluation form of the expression from its canonical representation
func (lib *Library) ExpressionFromBytecode(code []byte, localLib ...*LocalLibrary) (*Expression, error) {
	ret, remaining, _, err := lib.expressionFromBytecode(code, localLib...)
	if err != nil {
		return nil, err
	}
	if len(remaining) != 0 {
		return nil, fmt.Errorf("ExpressionFromBytecode: not all bytes have been consumed in %s. Remaining: %s",
			easyfl_util.Fmt(code), easyfl_util.Fmt(remaining))
	}
	return ret, nil
}

// ExpressionToBytecode converts evaluation form of the expression into the canonical bytecode form
func ExpressionToBytecode(f *Expression) []byte {
	var buf bytes.Buffer
	easyfl_util.AssertNoError(writeExpressionBytecode(&buf, f))
	return buf.Bytes()
}

// ExpressionToSource converts evaluation form of the expression into the source form (decompiles)
func ExpressionToSource(f *Expression) string {
	var buf bytes.Buffer
	easyfl_util.AssertNoError(writeExpressionSource(&buf, f))
	return string(buf.Bytes())
}

func writeExpressionBytecode(w io.Writer, expr *Expression) error {
	if _, err := w.Write(expr.CallPrefix); err != nil {
		return err
	}
	for _, arg := range expr.Args {
		if err := writeExpressionBytecode(w, arg); err != nil {
			return err
		}
	}
	return nil
}

func writeExpressionSource(w io.Writer, f *Expression) error {
	if _, err := w.Write([]byte(f.FunctionName)); err != nil {
		return err
	}
	if len(f.Args) > 0 {
		if _, err := w.Write([]byte{'('}); err != nil {
			return err
		}
	}
	first := true
	for _, arg := range f.Args {
		if !first {
			if _, err := w.Write([]byte{','}); err != nil {
				return err
			}
		}
		if err := writeExpressionSource(w, arg); err != nil {
			return err
		}
		first = false
	}
	if len(f.Args) > 0 {
		if _, err := w.Write([]byte{')'}); err != nil {
			return err
		}
	}
	return nil
}

// expressionFromBytecode parses bytecode into the executable expression tree
func (lib *Library) expressionFromBytecode(bytecode []byte, localLib ...*LocalLibrary) (*Expression, []byte, byte, error) {
	if len(bytecode) == 0 {
		return nil, nil, 0xff, io.EOF
	}

	dataPrefix, itIsData, err := ParseBytecodeInlineDataPrefix(bytecode)
	if err != nil {
		return nil, nil, 0xff, err
	}
	if itIsData {
		var sym string
		switch len(dataPrefix[1:]) {
		case 0:
			sym = "nil"
		case 1:
			sym = fmt.Sprintf("%d", dataPrefix[1])
		default:
			sym = fmt.Sprintf("0x%s", hex.EncodeToString(dataPrefix[1:]))
		}
		ret := newExpression(sym, dataPrefix, 0)
		ret.EvalFunc = dataFunction(dataPrefix[1:])
		return ret, bytecode[len(dataPrefix):], 0xff, nil
	}
	maxParameterNumber := byte(0xff)

	// function call expected
	callPrefix, evalFun, arity, sym, err := lib.parseCallPrefix(bytecode, localLib...)
	if err != nil {
		return nil, nil, 0xff, err
	}
	if len(callPrefix) == 1 && callPrefix[0] < LastEmbeddedReserved {
		// it is a parameter function call
		maxParameterNumber = callPrefix[0] & (^BytecodeParameterFlag)
	}
	if len(callPrefix) == 1 && arity < 0 {
		return nil, nil, 0xff, fmt.Errorf("EasyFL: short embedded with vararg is not allowed")
	}
	easyfl_util.Assertf(arity >= 0, "EasyFL: arity >= 0")

	ret := newExpression(sym, callPrefix, arity)

	bytecode = bytecode[len(callPrefix):]
	// collect call Args
	var p *Expression
	var m byte
	for i := 0; i < arity; i++ {
		p, bytecode, m, err = lib.expressionFromBytecode(bytecode, localLib...)
		if err != nil {
			return nil, nil, 0xff, err
		}
		if m != 0xff {
			if maxParameterNumber == 0xff || m > maxParameterNumber {
				maxParameterNumber = m
			}
		}
		ret.Args[i] = p
	}
	ret.EvalFunc = evalFun
	return ret, bytecode, maxParameterNumber, nil
}

// CompileExpression compiles from sources directly into the evaluation form
func (lib *Library) CompileExpression(source string, localLib ...*LocalLibrary) (*Expression, int, []byte, error) {
	src := strings.Join(splitLinesStripComments(source), "")
	bytecode, numParams, err := lib.ExpressionSourceToBytecode(stripSpaces(src), localLib...)
	if err != nil {
		return nil, 0, nil, err
	}
	ret, err := lib.ExpressionFromBytecode(bytecode, localLib...)
	if err != nil {
		return nil, 0, nil, err
	}
	return ret, numParams, bytecode, nil
}

// DecompileBytecode decompiles canonical bytecode into source. Symbols are restored wherever possible
func (lib *Library) DecompileBytecode(code []byte) (string, error) {
	f, err := lib.ExpressionFromBytecode(code)
	if err != nil {
		return "", err
	}
	return ExpressionToSource(f), nil
}

func dataFunction(data []byte) EvalFunction {
	d := data
	return EvalFunction{
		EmbeddedFunction: func(par *CallParams) []byte {
			par.Trace("-> %s", easyfl_util.Fmt(d))
			return data
		},
		bytecode: mustDataWithPrefix(data),
	}
}

// parseCallPrefix returns:
// - call prefix
// - eval function
// - call arity
// - symbol
// - error or nil
func (lib *Library) parseCallPrefix(code []byte, localLib ...*LocalLibrary) ([]byte, EvalFunction, int, string, error) {
	if len(code) == 0 || IsDataPrefix(code) {
		return nil, EvalFunction{}, 0, "", fmt.Errorf("parseCallPrefix: not a function call")
	}

	var evalFun EvalFunction
	var embeddedFun EmbeddedFunction
	var numParams, arity int
	var err error
	var callPrefix []byte
	var sym string

	if code[0]&FirstByteLongCallMask == 0 {
		// short call
		if code[0] <= LastEmbeddedReserved {
			// this is param reference
			if code[0]&BytecodeParameterFlag == 0 {
				// eval param reference
				evalFun = EvalFunction{
					EmbeddedFunction: evalEvalParamFun(code[0]),
				}
				sym = fmt.Sprintf("$%d", code[0])
			} else {
				// bytecode param reference
				paramNr := code[0] & (^BytecodeParameterFlag)
				evalFun = EvalFunction{
					EmbeddedFunction: evalBytecodeParamFun(paramNr),
				}
				sym = fmt.Sprintf("$$%d", paramNr)
			}
		} else {
			embeddedFun, arity, sym, err = lib.functionByCode(uint16(code[0]))
			if err != nil {
				return nil, EvalFunction{}, 0, sym, err
			}
			evalFun = EvalFunction{
				EmbeddedFunction: embeddedFun,
				bytecode:         code,
			}
		}
		callPrefix = code[:1]
	} else {
		// long call
		if len(code) < 2 {
			return nil, EvalFunction{}, 0, "", io.EOF
		}
		arity = int((code[0] & FirstByteLongCallArityMask) >> 2)
		t := binary.BigEndian.Uint16(code[:2])
		idx := t & Uint16LongCallCodeMask
		if idx > FirstLocalFunCode {
			return nil, EvalFunction{}, 0, "", fmt.Errorf("wrong call prefix")
		}
		callPrefix = code[:2]
		if idx == FirstLocalFunCode {
			// it is a local library call
			if len(localLib) == 0 {
				return nil, EvalFunction{}, 0, "", fmt.Errorf("local library not provided")
			}
			if len(code) < 3 {
				return nil, EvalFunction{}, 0, "", io.EOF
			}
			idx = uint16(FirstLocalFunCode) + uint16(code[2])
			callPrefix = code[:3]
		}
		embeddedFun, numParams, sym, err = lib.functionByCode(idx, localLib...)
		if err != nil {
			return nil, EvalFunction{}, 0, "", err
		}
		if numParams > 0 && numParams != arity {
			return nil, EvalFunction{}, 0, "", fmt.Errorf("wrong number of call args")
		}
		evalFun = EvalFunction{
			EmbeddedFunction: embeddedFun,
			bytecode:         code,
		}
	}
	return callPrefix, evalFun, arity, sym, nil
}

// ParseBytecodeInlineDataPrefix attempts to parse beginning of the code as inline data
// Function used is binary code analysis
// Returns:
// - parsed data including the 1-byte prefix, if it is data, otherwise nil
// - true if it is data, false if not (it is a function call)
// - EOF if not enough data
func ParseBytecodeInlineDataPrefix(code []byte) ([]byte, bool, error) {
	if !IsDataPrefix(code) {
		// not data
		return nil, false, nil
	}
	// it is data
	size := int(code[0] & FirstByteDataLenMask)
	if len(code) < size+1 {
		// too short
		return nil, false, io.EOF
	}
	return code[0 : 1+size], true, nil
}

func IsDataPrefix(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	return data[0]&FirstByteDataMask != 0
}

// StripDataPrefix if the first byte is a data prefix, strips it. Usually used for the data prefix returned by ParseBytecodeInlineDataPrefix
func StripDataPrefix(data []byte) []byte {
	if IsDataPrefix(data) {
		// if it is data, skip the prefix
		return data[1:]
	}
	// no change otherwise
	return data
}

// ParsePrefixBytecode tries to parse first 1, 2 or 3 bytes as a prefix, which contains
// all information about the function call (if it is not inline data)
// Returns:
// 1 byte for short call
// 2 bytes for long calls
// 3 bytes for local library call
func (lib *Library) ParsePrefixBytecode(code []byte) ([]byte, error) {
	callPrefix, _, _, _, err := lib.parseCallPrefix(code)
	if err != nil {
		return nil, err
	}
	return callPrefix, nil
}

// ParseBytecodeOneLevel parses bytecode of the function. Returns:
// - if it is inline data, it returns its prefix
// - if it is a function call, it returns pref, arg1, ... argN, where
// -- perf is call prefix
// -- argi is a canonical bytecode of the argument i
// Note, that argi is a canonical form of some expression too and the original expression is a concatenation
// of its on-level parsed form.
// To have next level, the argument can be parsed one level again
func (lib *Library) ParseBytecodeOneLevel(code []byte, expectedNumArgs ...int) (string, []byte, [][]byte, error) {
	f, err := lib.ExpressionFromBytecode(code)

	if err != nil {
		return "", nil, nil, err
	}
	if len(expectedNumArgs) > 0 && len(f.Args) != expectedNumArgs[0] {
		return "", nil, nil, fmt.Errorf("ParseBytecodeOneLevel (sym = %s): unexpected number of 1st level call arguments: expected %d, got %d",
			f.FunctionName, expectedNumArgs[0], len(f.Args))
	}
	args := make([][]byte, len(f.Args))

	prefix := f.CallPrefix
	for i, arg := range f.Args {
		var buf bytes.Buffer
		if err = writeExpressionBytecode(&buf, arg); err != nil {
			return "", nil, nil, err
		}
		args[i] = buf.Bytes()
	}
	return f.FunctionName, prefix, args, nil
}

// ComposeBytecodeOneLevel creates a source form of the one-level parsed expression. The nested function calls
// take a form of 'x/....' source literals
func ComposeBytecodeOneLevel(sym string, args [][]byte) string {
	ret := sym
	first := true
	if len(args) > 0 {
		ret += "("
	}
	for _, arg := range args {
		if !first {
			ret += ","
		}
		if len(arg) == 0 {
			ret += "nil"
		} else {
			if arg[0]&FirstByteDataMask != 0 {
				// it is data
				if len(arg) == 2 {
					// one byte constant
					ret += fmt.Sprintf("%d", arg[1])
				} else {
					ret += fmt.Sprintf("0x%s", hex.EncodeToString(arg[1:]))
				}
			} else {
				// it is a function call
				ret += fmt.Sprintf("x/%s", hex.EncodeToString(arg))
			}
		}
		first = false
	}
	if len(args) > 0 {
		ret += ")"
	}
	return ret
}

func makeEmbeddedFunForExpression(sym string, expr *Expression) EmbeddedFunction {
	return func(par *CallParams) []byte {
		varScope := newVarScope(len(par.args))

		for i := range varScope {
			varScope[i] = newCall(par.args[i].EvalFunc, par.args[i].Args, par.ctx)
		}
		defer disposeVarScope(varScope)

		spool := slicepool.New()
		retp := evalExpression(par.ctx.glb, spool, expr, varScope)
		ret := make([]byte, len(retp))
		copy(ret, retp)
		spool.Dispose()

		par.Trace("'%s':: %d params -> %s", sym, par.Arity(), easyfl_util.Fmt(ret))
		return ret
	}
}
