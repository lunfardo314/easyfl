package easyfl

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/lunfardo314/easyfl/easyfl_util"
)

func NewLibrary[T any]() *Library[T] {
	return newLibrary[T]()
}

func NewLibraryFromYAML[T any](yamlData []byte, embedFun ...func(lib *Library[T]) func(sym string) EmbeddedFunction[T]) (*Library[T], error) {
	lib := NewLibrary[T]()
	fromYAML, err := ReadLibraryFromYAML(yamlData)
	if err != nil {
		return nil, err
	}
	if len(embedFun) > 0 {
		if err = lib.Upgrade(fromYAML, embedFun[0](lib)); err != nil {
			return nil, err
		}
	} else {
		if err = lib.Upgrade(fromYAML); err != nil {
			return nil, err
		}
	}
	// if library is compiled, check consistency
	hashCalculated := lib.LibraryHash()
	if len(fromYAML.Hash) > 0 && fromYAML.Hash != hex.EncodeToString(hashCalculated[:]) {
		return nil, fmt.Errorf("NewLibraryFromYAML: provided and calculated hashes does not match")
	}
	return lib, nil
}

func NewBaseLibrary[T any]() *Library[T] {
	lib, err := NewLibraryFromYAML[T]([]byte(baseLibraryDefinitions), func(lib *Library[T]) func(sym string) EmbeddedFunction[T] {
		return EmbeddedFunctions[T](lib)
	})
	easyfl_util.AssertNoError(err)

	return lib
}

func newLibrary[T any]() *Library[T] {
	return &Library[T]{
		funByName:        make(map[string]*funDescriptor[T]),
		funByFunCode:     make(map[uint16]*funDescriptor[T]),
		numEmbeddedShort: FirstEmbeddedShort,
	}
}

func (lib *Library[T]) PrintLibraryStats() {
	h := lib.LibraryHash()
	fmt.Printf(`EasyFL function library (hash: %s):
    number of short embedded: %d out of max %d, remain free %d 
    number of long embedded: %d out of max %d, remain free %d
    number of extended: %d out of max %d, remain free %d
`,
		hex.EncodeToString(h[:]),
		lib.numEmbeddedShort, MaxNumEmbeddedAndReservedShort, MaxNumEmbeddedAndReservedShort-lib.numEmbeddedShort,
		lib.numEmbeddedLong, MaxNumEmbeddedLong, MaxNumEmbeddedLong-lib.numEmbeddedLong,
		lib.numExtended, MaxNumExtendedGlobal, MaxNumExtendedGlobal-lib.numExtended,
	)
}

func (lib *Library[T]) addDescriptor(fd *funDescriptor[T]) {
	lib.funByName[fd.sym] = fd
	lib.funByFunCode[fd.funCode] = fd
	isEmbedded, isShort := fd.isEmbeddedOrShort()
	if isEmbedded {
		if isShort {
			lib.numEmbeddedShort++
		} else {
			lib.numEmbeddedLong++
		}
	} else {
		lib.numExtended++
	}
}

// embedShort embeds short-callable function into the library
func (lib *Library[T]) embedShort(sym string, requiredNumPar int, embeddedFun EmbeddedFunction[T], embeddedAs string, description ...string) byte {
	ret, err := lib.embedShortErr(sym, requiredNumPar, embeddedFun, embeddedAs, description...)
	easyfl_util.AssertNoError(err)
	return ret
}

func (lib *Library[T]) embedShortErr(sym string, requiredNumPar int, embeddedFun EmbeddedFunction[T], embeddedAs string, description ...string) (byte, error) {
	if lib.numEmbeddedShort >= MaxNumEmbeddedAndReservedShort {
		return 0, fmt.Errorf("EasyFL: too many embedded short functions")
	}
	if lib.existsFunction(sym) {
		return 0, fmt.Errorf("EasyFL: repeating function '%s'", sym)
	}
	if requiredNumPar > 15 {
		return 0, fmt.Errorf("EasyFL: can't be more than 15 parameters")
	}
	if requiredNumPar < 0 {
		return 0, fmt.Errorf("EasyFL: short embedded vararg functions are not allowed")
	}
	if traceYN {
		embeddedFun = wrapWithTracing[T](embeddedFun, sym)
	}
	dscr := &funDescriptor[T]{
		sym:               sym,
		funCode:           lib.numEmbeddedShort,
		requiredNumParams: requiredNumPar,
		embeddedFun:       embeddedFun,
		embeddedAs:        embeddedAs,
	}
	if len(description) > 0 {
		dscr.description = description[0]
	}
	lib.addDescriptor(dscr)
	{
		codeBytes, err := lib.FunctionCallPrefixByName(sym, byte(requiredNumPar))
		easyfl_util.AssertNoError(err)
		easyfl_util.Assertf(len(codeBytes) == 1, "expected short code")
	}
	return byte(dscr.funCode), nil
}

func (lib *Library[T]) embedLong(sym string, requiredNumPar int, embeddedFun EmbeddedFunction[T], embeddedAs string, description ...string) uint16 {
	ret, err := lib.embedLongErr(sym, requiredNumPar, embeddedFun, embeddedAs, description...)
	easyfl_util.AssertNoError(err)
	return ret
}

func (lib *Library[T]) embedLongErr(sym string, requiredNumPar int, embeddedFun EmbeddedFunction[T], embeddedAs string, description ...string) (uint16, error) {
	if lib.numEmbeddedLong > MaxNumEmbeddedLong {
		return 0, fmt.Errorf("EasyFL: too many embedded long functions")
	}
	if lib.existsFunction(sym) {
		return 0, fmt.Errorf("EasyFL: repeating function '%s'", sym)
	}
	if requiredNumPar > 15 {
		return 0, fmt.Errorf("EasyFL: can't be more than 15 parameters")
	}

	if traceYN {
		embeddedFun = wrapWithTracing(embeddedFun, sym)
	}
	dscr := &funDescriptor[T]{
		sym:               sym,
		funCode:           lib.numEmbeddedLong + FirstEmbeddedLong,
		requiredNumParams: requiredNumPar,
		embeddedFun:       embeddedFun,
		embeddedAs:        embeddedAs,
	}
	if len(description) > 0 {
		dscr.description = description[0]
	}
	lib.addDescriptor(dscr)

	{
		// sanity check
		if requiredNumPar < 0 {
			requiredNumPar = 1
		}
		codeBytes, err := lib.FunctionCallPrefixByName(sym, byte(requiredNumPar))
		easyfl_util.AssertNoError(err)
		easyfl_util.Assertf(len(codeBytes) == 2, "expected long code")
	}
	return dscr.funCode, nil
}

// extend extends library with the compiled bytecode
func (lib *Library[T]) extend(sym string, source string, description ...string) uint16 {
	ret, err := lib.ExtendErr(sym, source, description...)
	if err != nil {
		panic(err)
	}
	return ret
}

// replaceEmbedded replaces an existing embedded function's implementation while preserving its funCode
func (lib *Library[T]) replaceEmbedded(sym string, requiredNumPar int, embeddedFun EmbeddedFunction[T], embeddedAs string, description string) error {
	fd, found := lib.funByName[sym]
	if !found {
		return fmt.Errorf("replaceEmbedded: function '%s' not found", sym)
	}
	if fd.embeddedAs == "" {
		return fmt.Errorf("replaceEmbedded: function '%s' is not embedded", sym)
	}
	if requiredNumPar > 15 {
		return fmt.Errorf("replaceEmbedded: can't be more than 15 parameters")
	}
	if traceYN {
		embeddedFun = wrapWithTracing(embeddedFun, sym)
	}
	// Update the descriptor in place, preserving funCode
	fd.requiredNumParams = requiredNumPar
	fd.embeddedFun = embeddedFun
	fd.embeddedAs = embeddedAs
	fd.description = description
	return nil
}

// replaceExtended replaces an existing extended function's implementation while preserving its funCode
func (lib *Library[T]) replaceExtended(sym string, source string, description string) error {
	fd, found := lib.funByName[sym]
	if !found {
		return fmt.Errorf("replaceExtended: function '%s' not found", sym)
	}
	if fd.embeddedAs != "" {
		return fmt.Errorf("replaceExtended: function '%s' is embedded, not extended", sym)
	}

	f, numParam, bytecode, err := lib.CompileExpression(source)
	if err != nil {
		return fmt.Errorf("replaceExtended: error while compiling '%s': %v", sym, err)
	}
	if numParam > 15 {
		return fmt.Errorf("replaceExtended: can't be more than 15 parameters")
	}

	embeddedFun := makeEmbeddedFunForExpression(sym, f)
	if traceYN {
		embeddedFun = wrapWithTracing(embeddedFun, sym)
	}
	// Update the descriptor in place, preserving funCode
	fd.bytecode = bytecode
	fd.requiredNumParams = numParam
	fd.embeddedFun = embeddedFun
	fd.source = source
	fd.description = description
	return nil
}

func evalEvalParamFun[T any](paramNr byte) EmbeddedFunction[T] {
	return func(par *CallParams[T]) []byte {
		return par.EvalParam(paramNr)
	}
}

func (lib *Library[T]) ExtendErr(sym string, source string, description ...string) (uint16, error) {
	f, numParam, bytecode, err := lib.CompileExpression(source)
	if err != nil {
		return 0, fmt.Errorf("error while compiling '%s': %v", sym, err)
	}

	easyfl_util.Assertf(lib.numExtended < MaxNumExtendedGlobal, "too many extended functions")

	if lib.existsFunction(sym) {
		return 0, errors.New("repeating symbol '" + sym + "'")
	}
	if numParam > 15 {
		return 0, errors.New("can't be more than 15 parameters")
	}
	embeddedFun := makeEmbeddedFunForExpression(sym, f)
	if traceYN {
		embeddedFun = wrapWithTracing(embeddedFun, sym)
	}
	dscr := &funDescriptor[T]{
		sym:               sym,
		funCode:           lib.numExtended + FirstExtended,
		bytecode:          bytecode,
		requiredNumParams: numParam,
		embeddedFun:       embeddedFun,
		source:            source,
	}
	if len(description) > 0 {
		dscr.description = description[0]
	}
	lib.addDescriptor(dscr)

	{
		// sanity check
		codeBytes, err := lib.FunctionCallPrefixByName(sym, byte(numParam))
		easyfl_util.AssertNoError(err)
		easyfl_util.Assertf(len(codeBytes) == 2, "expected long code")
	}

	return dscr.funCode, nil

}

func wrapWithTracing[T any](f EmbeddedFunction[T], msg string) EmbeddedFunction[T] {
	return func(par *CallParams[T]) []byte {
		fmt.Printf("EvalFunction '%s' - IN\n", msg)
		ret := f(par)
		fmt.Printf("EvalFunction '%s' - OUT: %v\n", msg, ret)
		return ret
	}
}

func (lib *Library[T]) ExtendMany(source string) error {
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

func (lib *Library[T]) MustExtendMany(source string) {
	if err := lib.ExtendMany(source); err != nil {
		panic(err)
	}
}

// LibraryHash returns hash of the library code and locks library against modifications.
// It is used for consistency checking and compatibility check

func (lib *Library[T]) existsFunction(sym string, localLib ...*LocalLibrary[T]) bool {
	if _, found := lib.funByName[sym]; found {
		return true
	}
	if len(localLib) == 0 {
		return false
	}
	_, found := localLib[0].funByName[sym]
	return found
}

func (lib *Library[T]) functionByName(sym string, localLib ...*LocalLibrary[T]) (*funInfo, error) {
	fd, found := lib.funByName[sym]
	ret := &funInfo{
		Sym: sym,
	}
	if found {
		ret.FunCode = fd.funCode
		ret.NumParams = fd.requiredNumParams
		ret.IsEmbedded, ret.IsShort = fd.isEmbeddedOrShort()
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

func (fd *funDescriptor[T]) isEmbeddedOrShort() (isEmbedded bool, isShort bool) {
	switch {
	case fd.funCode < FirstEmbeddedLong:
		isEmbedded = true
		isShort = true
	case fd.funCode < FirstExtended:
		isEmbedded = true
		isShort = false
	}
	return
}

func (lib *Library[T]) functionByCode(funCode uint16, localLib ...*LocalLibrary[T]) (EmbeddedFunction[T], int, string, error) {
	if funCode < FirstLocalFunCode {
		libData := lib.funByFunCode[funCode]
		if libData != nil {
			return libData.embeddedFun, libData.requiredNumParams, libData.sym, nil
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
	return libData.embeddedFun, libData.requiredNumParams, sym, nil
}

func (fi *funInfo) callPrefix(numArgs byte) ([]byte, error) {
	var ret []byte
	if fi.IsShort {
		easyfl_util.Assertf(fi.FunCode > LastEmbeddedReserved, "internal inconsistency: fi.FunCode must be > %d", LastEmbeddedReserved)
		ret = []byte{byte(fi.FunCode)}
	} else {
		if fi.NumParams < 0 {
			// vararg function
			if numArgs > MaxParameters {
				return nil, fmt.Errorf("internal inconsistency: number of arguments must be <= %d", MaxParameters)
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
			//ret = make([]byte, 2)
			ret = makeSmallByteArray(2)
			binary.BigEndian.PutUint16(ret, u16)
		} else {
			easyfl_util.Assertf(fi.FunCode <= FirstLocalFunCode+255 && FirstLocalFunCode <= fi.FunCode, "fi.FunCode <= FirstLocalFunCode+255 && FirstLocalFunCode <= fi.FunCode")
			// local function call 3 bytes
			u16 := (uint16(firstByte) << 8) | FirstLocalFunCode
			//ret = make([]byte, 3)
			ret = makeSmallByteArray(3)
			binary.BigEndian.PutUint16(ret[:2], u16)
			ret[2] = byte(fi.FunCode - FirstLocalFunCode)
		}
	}
	return ret, nil
}

func (lib *Library[T]) FunctionCallPrefixByName(sym string, numArgs byte) ([]byte, error) {
	fi, err := lib.functionByName(sym)
	if err != nil {
		return nil, err
	}
	return fi.callPrefix(numArgs)
}

func (lib *Library[T]) NumFunctions() uint16 {
	return lib.numEmbeddedShort + lib.numEmbeddedLong + lib.numExtended
}

func (lib *Library[T]) FunctionNameByCallPrefix(prefix []byte, localLib ...*LocalLibrary[T]) (sym string, err error) {
	if prefix[0]&FirstByteLongCallMask == 0 {
		// short call
		if prefix[0] <= LastEmbeddedReserved {
			// this is a param reference
			// eval param reference
			sym = fmt.Sprintf("$%d", prefix[0])
		} else {
			if _, _, sym, err = lib.functionByCode(uint16(prefix[0])); err != nil {
				return
			}
		}
	} else {
		// long call
		if len(prefix) < 2 {
			err = io.ErrUnexpectedEOF
			return
		}
		t := binary.BigEndian.Uint16(prefix[:2])
		idx := t & Uint16LongCallCodeMask
		if idx > FirstLocalFunCode {
			err = fmt.Errorf("wrong call prefix")
			return
		}
		if idx == FirstLocalFunCode {
			// it is a local library call
			if len(localLib) == 0 {
				err = fmt.Errorf("local library not provided")
				return
			}
			if len(prefix) < 3 {
				err = io.ErrUnexpectedEOF
				return
			}
			idx = uint16(FirstLocalFunCode) + uint16(prefix[2])
		}

		if _, _, sym, err = lib.functionByCode(idx, localLib...); err != nil {
			return
		}
	}
	return
}
