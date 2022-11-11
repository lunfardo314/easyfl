package easyfl

import (
	"errors"
	"fmt"
)

type (
	LocalLibrary struct {
		funByName    map[string]*funDescriptor
		funByFunCode []*funDescriptor // code of the function respective to the baseline of numExtended+FirstExtendedFun+1
	}
)

func NewLocalLibrary() *LocalLibrary {
	return &LocalLibrary{
		funByName:    make(map[string]*funDescriptor),
		funByFunCode: make([]*funDescriptor, 0),
	}
}

func CompileLocalLibrary(source string) ([][]byte, error) {
	lib := NewLocalLibrary()
	ret := make([][]byte, 0)
	parsed, err := parseFunctions(source)
	if err != nil {
		return nil, err
	}
	for _, pf := range parsed {
		f, numParam, binCode, err := CompileExpression(pf.SourceCode, lib)
		if err != nil {
			return nil, fmt.Errorf("error while compiling '%s': %v", pf.Sym, err)
		}

		Assert(len(lib.funByName) <= 255, "a local library can contain uo to 255 functions")

		if existsFunction(pf.Sym, lib) {
			return nil, errors.New("repeating symbol '" + pf.Sym + "'")
		}
		if numParam > 15 {
			return nil, errors.New("can't be more than 15 parameters")
		}
		evalFun := makeEvalFunForExpression(pf.Sym, f)
		if traceYN {
			evalFun = wrapWithTracing(evalFun, pf.Sym)
		}
		funCode := FirstLocalFunCode + uint16(len(lib.funByName))
		dscr := &funDescriptor{
			sym:               pf.Sym,
			funCode:           funCode,
			requiredNumParams: numParam,
			evalFun:           evalFun,
		}
		lib.funByName[pf.Sym] = dscr
		lib.funByFunCode = append(lib.funByFunCode, dscr)
		ret = append(ret, binCode)
	}
	return ret, nil
}

func LocalLibraryFromBytes(bin [][]byte) (*LocalLibrary, error) {
	if len(bin) > 255 {
		return nil, fmt.Errorf("local library can contain up to 255 elements")
	}
	ret := NewLocalLibrary()

	for i, data := range bin {
		expr, remaining, maxParam, err := expressionFromBinary(data, ret)
		if err != nil {
			return nil, err
		}
		if len(remaining) != 0 {
			return nil, fmt.Errorf("not all bytes have been consumed")
		}
		sym := fmt.Sprintf("lib#%d", i)
		numParams := 0
		if maxParam != 0xff {
			numParams = int(maxParam) + 1
		}
		Assert(numParams <= 15, "numParams <= 15")
		dscr := &funDescriptor{
			sym:               sym,
			funCode:           uint16(FirstLocalFunCode + i),
			requiredNumParams: numParams,
			evalFun:           makeEvalFunForExpression(sym, expr),
		}
		ret.funByFunCode = append(ret.funByFunCode, dscr)
	}
	return ret, nil
}
