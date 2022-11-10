package easyfl

import (
	"errors"
	"fmt"
)

type (
	LocalLibrary struct {
		funByName    map[string]*funLocal
		funByFunCode map[byte]*funLocal // code of the function respective to the baseline of numExtended+FirstExtendedFun+1
	}

	funLocal struct {
		sym               string
		funCode           uint16 // always equal to FirstLocalFunCode + local code 1 byte
		requiredNumParams int
		evalFun           EvalFunction
		binCode           []byte
	}
)

func NewLocalLibrary() *LocalLibrary {
	return &LocalLibrary{
		funByName:    make(map[string]*funLocal),
		funByFunCode: make(map[byte]*funLocal),
	}
}

func CompileToLocalLibrary(source string) (*LocalLibrary, error) {
	lib := NewLocalLibrary()
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
		funcCodeByte := byte(len(lib.funByName))
		funCode := FirstLocalFunCode + uint16(len(lib.funByName))
		dscr := &funLocal{
			sym:               pf.Sym,
			funCode:           funCode,
			requiredNumParams: numParam,
			evalFun:           evalFun,
			binCode:           binCode,
		}
		lib.funByFunCode[funcCodeByte] = dscr
		lib.funByName[pf.Sym] = dscr
	}
	return lib, nil
}

func (lib *LocalLibrary) Bytes() [][]byte {
	ret := make([][]byte, 0)
	for i := 0; i < 256; i++ {
		dscr, ok := lib.funByFunCode[byte(i)]
		if !ok {
			continue
		}
		ret = append(ret, dscr.binCode)
	}
	return ret
}

func LocalLibraryFromBytes(bin [][]byte) (*LocalLibrary, error) {
	if len(bin) > 255 {
		return nil, fmt.Errorf("local library can contain up to 255 elements")
	}
	ret := NewLocalLibrary()

	for i, data := range bin {
		expr, err := ExpressionFromBinary(data, ret)
		if err != nil {
			return nil, err
		}

		ret.funByFunCode[byte(i)] = &funLocal{
			sym:               "",
			funCode:           uint16(FirstLocalFunCode + i),
			requiredNumParams: len(expr.Args),
			evalFun:           expr.EvalFunc,
			binCode:           data,
		}
	}
	return ret, nil
}
