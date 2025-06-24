package easyfl

import (
	"sync"

	"github.com/lunfardo314/easyfl/easyfl_util"
)

const (

	// ---- embedded parameter access codes

	FirstEmbeddedReserved = 0x00
	// MaxParameters maximum number of parameters in the function definition and the call.
	MaxParameters        = 0x0f
	LastEmbeddedReserved = FirstEmbeddedReserved + MaxParameters - 1

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
	Expression[T any] struct {
		// for evaluation
		Args     []*Expression[T]
		EvalFunc EvalFunction[T]
		// for code parsing
		FunctionName string
		CallPrefix   []byte
	}

	EmbeddedFunction[T any] func(glb *CallParams[T]) []byte
	EvalFunction[T any]     struct {
		EmbeddedFunction[T]
		bytecode []byte
	}

	funDescriptor[T any] struct {
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
		embeddedFun EmbeddedFunction[T]
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

	// Library type parameter T is type of the data context

	Library[T any] struct {
		funByName        map[string]*funDescriptor[T]
		funByFunCode     map[uint16]*funDescriptor[T]
		numEmbeddedShort uint16
		numEmbeddedLong  uint16
		numExtended      uint16
	}
)

const traceYN = false

var (
	expressionArrayPool [MaxParameters + 1]sync.Pool
	expressionPool      sync.Pool
)

func newArgArray[T any](argNum int) (ret []*Expression[T]) {
	easyfl_util.Assertf(argNum <= MaxParameters, "size<=MaxParameters")
	if argNum > 0 {
		if retAny := expressionArrayPool[argNum].Get(); retAny != nil {
			ret = retAny.([]*Expression[T])
		} else {
			ret = make([]*Expression[T], argNum)
		}
	}
	return ret
}

func disposeArgArray[T any](argArr []*Expression[T]) {
	for i := range argArr {
		disposeExpression(argArr[i])
		argArr[i] = nil
	}
	expressionArrayPool[len(argArr)].Put(argArr)
}

func newExpression[T any](funName string, callPrefix []byte, numArg int) (ret *Expression[T]) {
	if retAny := expressionPool.Get(); retAny != nil {
		ret = retAny.(*Expression[T])
	} else {
		ret = &Expression[T]{}
	}
	ret.FunctionName = funName
	ret.CallPrefix = callPrefix
	ret.Args = newArgArray[T](numArg)
	return
}

func disposeExpression[T any](expr *Expression[T]) {
	disposeArgArray(expr.Args)
	*expr = Expression[T]{}
	expressionPool.Put(expr)
}

// TODO optimize heap allocation for small objects

func makeSmallByteArray(sz int) []byte {
	return make([]byte, sz)
}
