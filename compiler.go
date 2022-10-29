package easyfl

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode"
)

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
	for _, call := range spl {
		ff, err := parseExpression(call)
		if err != nil {
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

// binaryFromParsedExpression takes parsed expression and generates binary code of it
func (f *parsedExpression) binaryFromParsedExpression(w io.Writer) (int, error) {
	numArgs := 0
	if len(f.params) == 0 {
		// parameter reference
		if strings.HasPrefix(f.sym, "$") {
			n, err := strconv.Atoi(f.sym[1:])
			if err != nil {
				return 0, err
			}
			if n < 0 || n > MaxParameters {
				return 0, fmt.Errorf("wrong argument reference '%s'", f.sym)
			}
			if numArgs < n+1 {
				numArgs = n + 1
			}
			if _, err = w.Write([]byte{byte(n)}); err != nil {
				return 0, err
			}
			return numArgs, nil
		}
		// write inline data
		n, err := strconv.Atoi(f.sym)
		if err == nil {
			// it is a number
			if n < 0 || n >= 256 {
				return 0, fmt.Errorf("integer constant value not uint8: %s", f.sym)
			}
			// it is a 1 byte value
			if _, err = w.Write([]byte{FirstByteDataMask | byte(1), byte(n)}); err != nil {
				return 0, err
			}
			return 0, nil
		}
		if strings.HasPrefix(f.sym, "0x") {
			// it is hexadecimal constant
			b, err := hex.DecodeString(f.sym[2:])
			if err != nil {
				return 0, fmt.Errorf("%v: '%s'", err, f.sym)
			}
			if len(b) > 127 {
				return 0, fmt.Errorf("hexadecimal constant longer than 127 bytes: '%s'", f.sym)
			}
			if _, err = w.Write([]byte{FirstByteDataMask | byte(len(b))}); err != nil {
				return 0, err
			}
			if _, err = w.Write(b); err != nil {
				return 0, err
			}
			return 0, nil
		}
		if strings.HasPrefix(f.sym, "x/") {
			// it is an inline binary executable code
			b, err := hex.DecodeString(f.sym[2:])
			if err != nil {
				return 0, fmt.Errorf("%v: '%s'", err, f.sym)
			}
			// write the code as is
			if _, err = w.Write(b); err != nil {
				return 0, err
			}
			return 0, nil
		}
		if strings.HasPrefix(f.sym, "u16/") {
			// it is u16 constant big endian
			n, err = strconv.Atoi(strings.TrimPrefix(f.sym, "u16/"))
			if err != nil {
				return 0, fmt.Errorf("%v: '%s'", err, f.sym)
			}
			if n < 0 || n > math.MaxUint16 {
				return 0, fmt.Errorf("wrong u16 constant: '%s'", f.sym)
			}
			b := make([]byte, 2)
			binary.BigEndian.PutUint16(b, uint16(n))
			if _, err = w.Write([]byte{FirstByteDataMask | byte(2)}); err != nil {
				return 0, err
			}
			if _, err = w.Write(b); err != nil {
				return 0, err
			}
			return 0, nil
		}
		if strings.HasPrefix(f.sym, "u32/") {
			// it is u16 constant big endian
			n, err = strconv.Atoi(strings.TrimPrefix(f.sym, "u32/"))
			if err != nil {
				return 0, fmt.Errorf("%v: '%s'", err, f.sym)
			}
			if n < 0 || n > math.MaxUint32 {
				return 0, fmt.Errorf("wrong u32 constant: '%s'", f.sym)
			}
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, uint32(n))
			if _, err = w.Write([]byte{FirstByteDataMask | byte(4)}); err != nil {
				return 0, err
			}
			if _, err = w.Write(b); err != nil {
				return 0, err
			}
			return 0, nil
		}
		if strings.HasPrefix(f.sym, "u64/") {
			// it is u16 constant big endian
			un, err := strconv.ParseUint(strings.TrimPrefix(f.sym, "u64/"), 10, 64)
			if err != nil {
				return 0, fmt.Errorf("%v: '%s'", err, f.sym)
			}
			b := make([]byte, 8)
			binary.BigEndian.PutUint64(b, un)
			if _, err = w.Write([]byte{FirstByteDataMask | byte(8)}); err != nil {
				return 0, err
			}
			if _, err = w.Write(b); err != nil {
				return 0, err
			}
			return 0, nil
		}
		// TODO other types of literals
	}
	// either has arguments or not literal
	// try if it is a short call
	fi, err := functionByName(f.sym)
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
	for _, ff := range f.params {
		n, err := ff.binaryFromParsedExpression(w)
		if err != nil {
			return 0, err
		}
		if n > numArgs {
			numArgs = n
		}
	}
	return numArgs, nil
}

// ExpressionSourceToBinary compile expression from source form into binary for embedding into transaction
func ExpressionSourceToBinary(formulaSource string) ([]byte, int, error) {
	f, err := parseExpression(formulaSource)
	if err != nil {
		return nil, 0, err
	}

	var buf bytes.Buffer
	numArgs, err := f.binaryFromParsedExpression(&buf)
	if err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), numArgs, nil
}

// ExpressionFromBinary creates evaluation form of the expression
func ExpressionFromBinary(code []byte) (*Expression, error) {
	ret, remaining, err := expressionFromBinary(code)
	if err != nil {
		return nil, err
	}
	if len(remaining) != 0 {
		return nil, fmt.Errorf("not all bytes have been consumed")
	}
	return ret, nil
}

func ExpressionToBinary(f *Expression) []byte {
	var buf bytes.Buffer
	AssertNoError(writeExpressionBinary(&buf, f))
	return buf.Bytes()
}

func ExpressionToSource(f *Expression) string {
	var buf bytes.Buffer
	AssertNoError(writeExpressionSource(&buf, f))
	return string(buf.Bytes())
}

func writeExpressionBinary(w io.Writer, expr *Expression) error {
	if _, err := w.Write(expr.CallPrefix); err != nil {
		return err
	}
	for _, arg := range expr.Args {
		if err := writeExpressionBinary(w, arg); err != nil {
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

// expressionFromBinary parses executable code into the executable expression tree
func expressionFromBinary(code []byte) (*Expression, []byte, error) {
	if len(code) == 0 {
		return nil, nil, io.EOF
	}
	dataPrefix, itIsData, err := ParseInlineDataPrefix(code)
	if err != nil {
		return nil, nil, err
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
		ret := &Expression{
			EvalFunc:     dataFunction(dataPrefix[1:]),
			FunctionName: sym,
			CallPrefix:   dataPrefix,
		}
		return ret, code[len(dataPrefix):], nil
	}
	// function call expected
	callPrefix, evalFun, arity, sym, err := parseCallPrefix(code)
	if err != nil {
		return nil, nil, err
	}
	ret := &Expression{
		Args:         make([]*Expression, 0),
		EvalFunc:     nil,
		FunctionName: sym,
		CallPrefix:   callPrefix,
	}

	code = code[len(callPrefix):]
	// collect call Args
	var p *Expression
	for i := 0; i < arity; i++ {
		p, code, err = expressionFromBinary(code)
		if err != nil {
			return nil, nil, err
		}
		ret.Args = append(ret.Args, p)
	}
	ret.EvalFunc = evalFun
	return ret, code, nil
}

// CompileExpression compiles from sources directly into the evaluation form
func CompileExpression(source string) (*Expression, int, []byte, error) {
	src := strings.Join(splitLinesStripComments(source), "")
	code, numParams, err := ExpressionSourceToBinary(stripSpaces(src))
	if err != nil {
		return nil, 0, nil, err
	}
	ret, err := ExpressionFromBinary(code)
	if err != nil {
		return nil, 0, nil, err
	}
	return ret, numParams, code, nil
}

func DecompileBinary(code []byte) (string, error) {
	f, err := ExpressionFromBinary(code)
	if err != nil {
		return "", err
	}
	return ExpressionToSource(f), nil
}

func dataFunction(data []byte) EvalFunction {
	d := data
	return func(par *CallParams) []byte {
		par.Trace("-> %s", Fmt(d))
		return data
	}
}

func dataCalls(glb GlobalData, data ...[]byte) []*Call {
	ret := make([]*Call, len(data))
	for i, d := range data {
		ret[i] = NewCall(dataFunction(d), NewCallParams(NewEvalContext(nil, glb), nil))
	}
	return ret
}

func parseCallPrefix(code []byte) ([]byte, EvalFunction, int, string, error) {
	if len(code) == 0 || code[0]&FirstByteDataMask != 0 {
		return nil, nil, 0, "", fmt.Errorf("parseCallPrefix: not a function call")
	}

	var evalFun EvalFunction
	var numParams, arity int
	var err error
	var callPrefix []byte
	var sym string

	if code[0]&FirstByteLongCallMask == 0 {
		// short call
		if code[0] < EmbeddedReservedUntil {
			// param reference
			evalFun = evalParamFun(code[0])
			sym = fmt.Sprintf("$%d", code[0])
		} else {
			evalFun, arity, sym, err = functionByCode(uint16(code[0]))
			if err != nil {
				return nil, nil, 0, sym, err
			}
		}
		callPrefix = code[:1]
	} else {
		// long call
		if len(code) < 2 {
			return nil, nil, 0, "", io.EOF
		}
		arity = int((code[0] & FirstByteLongCallArityMask) >> 2)
		t := binary.BigEndian.Uint16(code[:2])
		idx := t & Uint16LongCallCodeMask
		evalFun, numParams, sym, err = functionByCode(idx)
		if err != nil {
			return nil, nil, 0, "", err
		}
		if numParams > 0 && numParams != arity {
			return nil, nil, 0, "", fmt.Errorf("wrong number of call args")
		}
		callPrefix = code[:2]
	}
	return callPrefix, evalFun, arity, sym, nil
}

// ParseInlineDataPrefix attempts to parse beginning of the code as inline data
// Function is for binary code analysis
// Returns:
// - parsed data with the 1 byte prefix or nil
// - true if success, false if not
// - EOF if not enough data
func ParseInlineDataPrefix(code []byte) ([]byte, bool, error) {
	if code[0]&FirstByteDataMask == 0 {
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

func ParseCallPrefixFromBinary(code []byte) ([]byte, error) {
	callPrefix, _, _, _, err := parseCallPrefix(code)
	if err != nil {
		return nil, err
	}
	return callPrefix, nil
}

func DecompileBinaryOneLevel(code []byte) (string, []byte, [][]byte, error) {
	f, err := ExpressionFromBinary(code)
	if err != nil {
		return "", nil, nil, err
	}
	args := make([][]byte, len(f.Args))
	prefix := f.CallPrefix

	for i, arg := range f.Args {
		var buf bytes.Buffer
		if err = writeExpressionBinary(&buf, arg); err != nil {
			return "", nil, nil, err
		}
		args[i] = buf.Bytes()
	}
	return f.FunctionName, prefix, args, nil
}

func ComposeOneLevel(sym string, args [][]byte) string {
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
