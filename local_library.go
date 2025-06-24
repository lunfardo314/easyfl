package easyfl

import (
	"errors"
	"fmt"

	"github.com/lunfardo314/easyfl/easyfl_util"
	"github.com/lunfardo314/easyfl/tuples"
)

type (
	LocalLibrary[T any] struct {
		funByName    map[string]*funDescriptor[T]
		funByFunCode []*funDescriptor[T] // code of the function respective to the baseline of numExtended+FirstExtended+1
	}
)

func NewLocalLibrary[T any]() *LocalLibrary[T] {
	return &LocalLibrary[T]{
		funByName:    make(map[string]*funDescriptor[T]),
		funByFunCode: make([]*funDescriptor[T], 0),
	}
}

func (lib *Library[T]) CompileLocalLibrary(source string) ([][]byte, error) {
	libLoc := NewLocalLibrary[T]()
	ret := make([][]byte, 0)
	parsed, err := parseFunctions(source)
	if err != nil {
		return nil, err
	}
	for _, pf := range parsed {
		f, numParam, binCode, err := lib.CompileExpression(pf.SourceCode, libLoc)
		if err != nil {
			return nil, fmt.Errorf("error while compiling '%s': %v", pf.Sym, err)
		}

		easyfl_util.Assertf(len(lib.funByName) <= 255, "a local library can contain up to 255 functions")

		if lib.existsFunction(pf.Sym, libLoc) {
			return nil, errors.New("repeating symbol '" + pf.Sym + "'")
		}
		if numParam > 15 {
			return nil, errors.New("can't be more than 15 parameters")
		}
		embeddedFun := makeEmbeddedFunForExpression(pf.Sym, f)
		if traceYN {
			embeddedFun = wrapWithTracing(embeddedFun, pf.Sym)
		}
		funCode := FirstLocalFunCode + uint16(len(libLoc.funByName))
		dscr := &funDescriptor[T]{
			sym:               pf.Sym,
			funCode:           funCode,
			requiredNumParams: numParam,
			embeddedFun:       embeddedFun,
		}
		libLoc.funByName[pf.Sym] = dscr
		libLoc.funByFunCode = append(libLoc.funByFunCode, dscr)
		ret = append(ret, binCode)
	}
	return ret, nil
}

// CompileLocalLibraryToTuple compiles local library and serializes it as lazy array
func (lib *Library[T]) CompileLocalLibraryToTuple(source string) ([]byte, error) {
	libBin, err := lib.CompileLocalLibrary(source)
	if err != nil {
		return nil, err
	}
	ret := tuples.MakeTupleFromDataElements(libBin...)
	return ret.Bytes(), nil
}

func (lib *Library[T]) LocalLibraryFromBytes(bin [][]byte) (*LocalLibrary[T], error) {
	if len(bin) > 255 {
		return nil, fmt.Errorf("local library can contain up to 255 elements")
	}
	ret := NewLocalLibrary[T]()

	for i, data := range bin {
		expr, remaining, maxParam, err := lib.expressionFromBytecode(data, ret)
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
		easyfl_util.Assertf(numParams <= 15, "numParams <= 15")
		dscr := &funDescriptor[T]{
			sym:               sym,
			funCode:           uint16(FirstLocalFunCode + i),
			requiredNumParams: numParams,
			embeddedFun:       makeEmbeddedFunForExpression(sym, expr),
		}
		ret.funByFunCode = append(ret.funByFunCode, dscr)
	}
	return ret, nil
}
