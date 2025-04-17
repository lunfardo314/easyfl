package easyfl

import (
	"sync"

	"github.com/lunfardo314/easyfl/easyfl_util"
)

const (

	// ---- embedded parameter access codes

	FirstEmbeddedReserved = 0x00
	// MaxParameters maximum number of parameters in the function definition and the call.
	MaxParameters         = 0x08
	LastEmbeddedReserved  = FirstEmbeddedReserved + 2*MaxParameters - 1 // 15 reserved for parameter access 2 x 8
	BytecodeParameterFlag = byte(0x08)

	// ----- embedded short

	FirstEmbeddedShort             = LastEmbeddedReserved + 1
	LastEmbeddedShort              = 0x3f // 63
	MaxNumEmbeddedAndReservedShort = LastEmbeddedShort + 1

	// ---- embedded long codes

	FirstEmbeddedLong  = LastEmbeddedShort + 1 // 64
	MaxNumEmbeddedLong = 0xff
	LastEmbeddedLong   = FirstEmbeddedLong + MaxNumEmbeddedLong - 1

	// ---- extended codes

	FirstExtended        = LastEmbeddedLong + 1
	LastGlobalFunCode    = 1022 // biggest global function code. All the rest are local
	MaxNumExtendedGlobal = LastGlobalFunCode - FirstExtended
	FirstLocalFunCode    = LastGlobalFunCode + 1 // functions in local libraries uses extra byte for local function codes
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

	EmbeddedFunction func(glb *CallParams) []byte
	EvalFunction     struct {
		EmbeddedFunction
		bytecode []byte
	}

	funDescriptor struct {
		// source name of the function
		sym string
		// code of the function
		funCode uint16
		// nil for embedded functions
		bytecode []byte
		// number of parameters (from 0 up to 15) or -1 for vararg
		requiredNumParams int
		// for embedded functions it is hardcoded function, for extended functions is
		// interpreter closure of the bytecode
		embeddedFun EmbeddedFunction
		// only needed for generating YAML
		source string
		// any text
		description string
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
		numEmbeddedShort uint16
		numEmbeddedLong  uint16
		numExtended      uint16
	}

	EmbeddedFunctionData struct {
		Sym            string
		RequiredNumPar int
		EmbeddedFun    EmbeddedFunction
		Description    string
	}

	ExtendedFunctionData struct {
		Sym         string
		Source      string
		Description string
	}
)

const traceYN = false

var (
	expressionArrayPool [15]sync.Pool
	expressionPool      sync.Pool
)

func newArgArray(argNum int) (ret []*Expression) {
	easyfl_util.Assertf(argNum <= MaxParameters, "size<=MaxParameters")
	if argNum > 0 {
		if retAny := expressionArrayPool[argNum].Get(); retAny != nil {
			ret = retAny.([]*Expression)
		} else {
			ret = make([]*Expression, argNum)
		}
	}
	return ret
}

func disposeArgArray(argArr []*Expression) {
	for i := range argArr {
		disposeExpression(argArr[i])
		argArr[i] = nil
	}
	expressionArrayPool[len(argArr)].Put(argArr)
}

func newExpression(funName string, callPrefix []byte, numArg int) (ret *Expression) {
	if retAny := expressionPool.Get(); retAny != nil {
		ret = retAny.(*Expression)
	} else {
		ret = &Expression{}
	}
	ret.FunctionName = funName
	ret.CallPrefix = callPrefix
	ret.Args = newArgArray(numArg)
	return
}

func disposeExpression(expr *Expression) {
	disposeArgArray(expr.Args)
	*expr = Expression{}
	expressionPool.Put(expr)
}

// TODO optimize heap allocations with these small slices

//const smallByteArrayMax = 64
//
//var smallByteArrayPool [smallByteArrayMax]sync.Pool

func makeSmallByteArray(sz int) []byte {
	return make([]byte, sz)
	//if sz == 0 {
	//	return nil
	//}
	//if sz > smallByteArrayMax {
	//	return make([]byte, sz)
	//}
	//if retAny := smallByteArrayPool[sz-1].Get(); retAny != nil {
	//	return retAny.([]byte)
	//}
	//return make([]byte, sz)
}

// disposeSmallByteArray does not make zeroes
func disposeSmallByteArray(arr []byte) {
	//if len(arr) == 0 || len(arr) > smallByteArrayMax {
	//	return
	//}
	//smallByteArrayPool[len(arr)-1].Put(arr)
}

func nulls(data []byte) []byte {
	for i := range data {
		data[i] = 0
	}
	return data
}
