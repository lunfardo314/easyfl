package easyfl

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"github.com/lunfardo314/easyfl/easyfl_util"
	"github.com/lunfardo314/easyfl/slicepool"
)

// GlobalData represents the data to be evaluated. It is wrapped into the interface which offers some tracing options
// Type parameter T is type of data provided in the eval context
type GlobalData[T any] interface {
	Data() T              // return data being evaluated. It is interpreted by the transaction host
	Trace() bool          // should return true if tracing enabled
	PutTrace(string)      // hook for tracing messages. Called only if enabled
	Library() *Library[T] // returns library
}

// evalContext is the structure through which the EasyFL script accesses data structure it is validating
type evalContext[T any] struct {
	glb      GlobalData[T]
	spool    *slicepool.SlicePool
	varScope []*call[T]
}

// CallParams is a structure through which the function accesses its evaluation context and call arguments
type CallParams[T any] struct {
	*evalContext[T]
	args []*Expression[T]
}

// call is EvalFunction with params
type call[T any] struct {
	f      EvalFunction[T]
	params *CallParams[T]
	cache  []byte
	cached bool
}

func newEvalContext[T any](varScope []*call[T], glb GlobalData[T], spool *slicepool.SlicePool) *evalContext[T] {
	return &evalContext[T]{
		varScope: varScope,
		spool:    spool,
		glb:      glb,
	}
}

var (
	callPool     sync.Pool
	varScopePool [MaxParameters + 1]sync.Pool
)

func newCall[T any](f EvalFunction[T], args []*Expression[T], ctx *evalContext[T]) (ret *call[T]) {
	if retAny := callPool.Get(); retAny != nil {
		ret = retAny.(*call[T])
	} else {
		ret = &call[T]{}
	}
	*ret = call[T]{
		f: f,
		params: &CallParams[T]{
			evalContext: ctx,
			args:        args,
		},
	}
	return
}

func disposeCall[T any](c *call[T]) {
	*c = call[T]{}
	callPool.Put(c)
}

func newVarScope[T any](sz int) []*call[T] {
	if sz == 0 {
		return nil
	}
	easyfl_util.Assertf(sz <= MaxParameters, "sz <= MaxParameters")
	if retAny := varScopePool[sz-1].Get(); retAny != nil {
		return retAny.([]*call[T])
	}
	return make([]*call[T], sz)
}

func disposeVarScope[T any](vs []*call[T]) {
	if len(vs) == 0 {
		return
	}
	for i := range vs {
		disposeCall(vs[i])
		vs[i] = nil
	}
	varScopePool[len(vs)-1].Put(vs)
}

// Eval evaluates the expression by calling it eval function with the parameter
func (c *call[T]) Eval() []byte {
	if c.cached {
		return c.cache
	}
	c.cache = c.f.EmbeddedFunction(c.params)
	c.cached = true
	return c.cache
}

// DataContext accesses the data context inside the embedded function
func (p *CallParams[T]) DataContext() T {
	return p.glb.Data()
}

// Slice makes CallParams with the slice of arguments
func (p *CallParams[T]) Slice(from, to byte) *CallParams[T] {
	return &CallParams[T]{
		evalContext: p.evalContext,
		args:        p.args[from:to],
	}
}

// Arity return actual number of call parameters
func (p *CallParams[T]) Arity() byte {
	return byte(len(p.args))
}

func (ctx *evalContext[T]) eval(f *Expression[T]) []byte {
	c := newCall(f.EvalFunc, f.Args, ctx)
	defer disposeCall(c)

	return c.Eval()
}

// Arg evaluates argument if the call inside embedded function
func (p *CallParams[T]) Arg(n byte) []byte {
	if traceYN {
		fmt.Printf("Arg(%d) -- IN\n", n)
	}
	ret := p.evalContext.eval(p.args[n])

	if traceYN {
		fmt.Printf("Arg(%d) -- OUT ret: %v\n", n, ret)
	}
	return ret
}

func (p *CallParams[T]) Trace(format string, args ...any) {
	if isNil(p.glb) || !p.glb.Trace() {
		return
	}
	p.glb.PutTrace(fmt.Sprintf(format, easyfl_util.EvalLazyArgs(args...)...))
}

func (p *CallParams[T]) TracePanic(format string, args ...any) {
	p.Trace("panic: "+format, args...)
	panic(fmt.Sprintf("panic: "+format, easyfl_util.EvalLazyArgs(args...)...))
}

func (p *CallParams[T]) Assertf(cond bool, format string, args ...any) {
	if !cond {
		p.TracePanic(format, args...)
	}
}

func (p *CallParams[T]) Alloc(size uint16) []byte {
	return p.spool.Alloc(size)
}

func (p *CallParams[T]) AllocData(data ...byte) []byte {
	return p.spool.AllocData(data...)
}

func (p *CallParams[T]) EvalParam(paramNr byte) []byte {
	return p.varScope[paramNr].Eval()
}

func (p *CallParams[T]) GetBytecode(paramNr byte) []byte {
	return p.varScope[paramNr].f.bytecode
}

func evalExpression[T any](glb GlobalData[T], spool *slicepool.SlicePool, f *Expression[T], varScope []*call[T]) []byte {
	return newEvalContext(varScope, glb, spool).eval(f)
}

// EvalExpression evaluates the expression, in the context of any data context and given values of parameters
func EvalExpression[T any](glb GlobalData[T], f *Expression[T], args ...[]byte) []byte {
	argsForData := make([]*call[T], len(args))

	spool := slicepool.New()
	ctx := newEvalContext(nil, glb, spool)
	for i, d := range args {
		argsForData[i] = newCall[T](dataFunction[T](d), nil, ctx)
	}
	retp := evalExpression(glb, spool, f, argsForData)
	ret := make([]byte, len(retp))
	copy(ret, retp)
	spool.Dispose()

	return ret
}

// EvalExpressionWithSlicePool evaluates expression, in the context of any data context and given values of parameters
// It must be provided slice pool for allocation of interim  data
func EvalExpressionWithSlicePool[T any](glb GlobalData[T], spool *slicepool.SlicePool, f *Expression[T], args ...[]byte) []byte {
	argsForData := make([]*call[T], len(args))

	ctx := newEvalContext(nil, glb, spool)
	for i, d := range args {
		argsForData[i] = newCall[T](dataFunction[T](d), nil, ctx)
	}
	retp := evalExpression(glb, spool, f, argsForData)
	ret := make([]byte, len(retp))
	copy(ret, retp)

	return ret
}

// EvalFromSource compiles the source of the expression and evaluates it
// Never panics
func (lib *Library[T]) EvalFromSource(glb GlobalData[T], source string, args ...[]byte) ([]byte, error) {
	var ret []byte
	err := easyfl_util.CatchPanicOrError(func() error {
		f, requiredNumArgs, _, err := lib.CompileExpression(source)
		if err != nil {
			return err
		}
		if requiredNumArgs != len(args) {
			return fmt.Errorf("required number of parameters is %d, got %d", requiredNumArgs, len(args))
		}
		ret = EvalExpression[T](glb, f, args...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// MustEvalFromSource evaluates the source of the expression and panics on any error
func (lib *Library[T]) MustEvalFromSource(glb GlobalData[T], source string, args ...[]byte) []byte {
	ret, err := lib.EvalFromSource(glb, source, args...)
	if err != nil {
		panic(err)
	}
	return ret
}

// MustEvalFromBytecode interprets expression in the bytecode form. Will panic on any compile and runtime error
func (lib *Library[T]) MustEvalFromBytecode(glb GlobalData[T], code []byte, args ...[]byte) []byte {
	expr, err := lib.ExpressionFromBytecode(code)
	if err != nil {
		panic(err)
	}
	defer disposeExpression(expr)

	return EvalExpression(glb, expr, args...)
}

func (lib *Library[T]) MustEvalFromBytecodeWithSlicePool(glb GlobalData[T], spool *slicepool.SlicePool, code []byte, args ...[]byte) []byte {
	expr, err := lib.ExpressionFromBytecode(code)
	if err != nil {
		panic(err)
	}
	defer disposeExpression(expr)

	return EvalExpressionWithSlicePool(glb, spool, expr, args...)
}

// EvalFromBytecode evaluates the expression, never panics but return an error
func (lib *Library[T]) EvalFromBytecode(glb GlobalData[T], code []byte, args ...[]byte) ([]byte, error) {
	var ret []byte
	err := easyfl_util.CatchPanicOrError(func() error {
		ret = lib.MustEvalFromBytecode(glb, code, args...)
		return nil
	})
	return ret, err
}

// EvalFromBytecodeWithSlicePool evaluates expression, never panics but return an error
func (lib *Library[T]) EvalFromBytecodeWithSlicePool(glb GlobalData[T], spool *slicepool.SlicePool, code []byte, args ...[]byte) ([]byte, error) {
	var ret []byte
	err := easyfl_util.CatchPanicOrError(func() error {
		ret = lib.MustEvalFromBytecodeWithSlicePool(glb, spool, code, args...)
		return nil
	})
	return ret, err
}

func (lib *Library[T]) expressionFromLibrary(libraryBin [][]byte, funIndex int) (*Expression[T], error) {
	libLoc, err := lib.LocalLibraryFromBytes(libraryBin[:funIndex])
	if err != nil {
		return nil, err
	}
	expr, err := lib.ExpressionFromBytecode(libraryBin[funIndex], libLoc)
	if err != nil {
		return nil, err
	}
	return expr, nil
}

func (lib *Library[T]) MustEvalFromLibrary(glb GlobalData[T], libraryBin [][]byte, funIndex int, args ...[]byte) []byte {
	if funIndex < 0 || funIndex >= len(libraryBin) {
		panic("function index is out of library bounds")
	}
	if funIndex == 0 {
		return lib.MustEvalFromBytecode(glb, libraryBin[0], args...)
	}
	expr, err := lib.expressionFromLibrary(libraryBin, funIndex)
	if err != nil {
		panic(err)
	}
	defer disposeExpression(expr)

	return EvalExpression(glb, expr, args...)
}

func (lib *Library[T]) EvalFromLibrary(glb GlobalData[T], libraryBin [][]byte, funIndex int, args ...[]byte) ([]byte, error) {
	var ret []byte
	err := easyfl_util.CatchPanicOrError(func() error {
		ret = lib.MustEvalFromLibrary(glb, libraryBin, funIndex, args...)
		return nil
	})
	return ret, err
}

// CallLocalLibrary to be called from the extension outside the easyfl.
func (lib *Library[T]) CallLocalLibrary(ctx *CallParams[T], libBin [][]byte, idx int) []byte {
	if idx < 0 || idx >= len(libBin) {
		panic("function index is out of library bounds")
	}
	expr, err := lib.expressionFromLibrary(libBin, idx)
	if err != nil {
		ctx.TracePanic("error while parsing local library: %v", err)
	}
	varScope := make([]*call[T], len(ctx.args))
	for i := range varScope {
		varScope[i] = newCall(ctx.args[i].EvalFunc, ctx.args[i].Args, ctx.evalContext)
	}

	spool := slicepool.New()
	retp := evalExpression(ctx.glb, spool, expr, varScope)
	ret := make([]byte, len(retp))
	copy(ret, retp)
	spool.Dispose()

	ctx.Trace("'lib#%d':: %d params -> %s", idx, ctx.Arity(), easyfl_util.Fmt(ret))
	return ret
}

func (lib *Library[T]) MustEqual(source1, source2 string) {
	res1, err := lib.EvalFromSource(nil, source1)
	easyfl_util.Assertf(err == nil, "expression '%s' resulted in error: '%v'", source1, err)
	res2, err := lib.EvalFromSource(nil, source2)
	easyfl_util.Assertf(err == nil, "expression '%s' resulted in error: '%v'", source2, err)
	easyfl_util.Assertf(bytes.Equal(res1, res2), "must be equal %s and %s: %s != %s", source1, source2, easyfl_util.Fmt(res1), easyfl_util.Fmt(res2))
	easyfl_util.Assertf(err == nil, "expression '%s' resulted in error: '%v'", source2, err)
	easyfl_util.Assertf(bytes.Equal(res1, res2), "must be equal %s and %s: %s != %s", source1, source2,
		func() string { return easyfl_util.Fmt(res1) }, func() string { return easyfl_util.Fmt(res2) })
}

func (lib *Library[T]) MustTrue(source string) {
	res, err := lib.EvalFromSource(nil, source)
	easyfl_util.Assertf(err == nil, "expression '%s' resulted in error: '%v'", source, err)
	easyfl_util.Assertf(len(res) > 0, "expression '%s' must be true", res)
}

func (lib *Library[T]) MustError(source string, mustContain ...string) {
	_, err := lib.EvalFromSource(nil, source)
	easyfl_util.Assertf(err != nil, "expression '%s' is expected to return an error", source)
	if len(mustContain) > 0 {
		easyfl_util.Assertf(strings.Contains(err.Error(), mustContain[0]), fmt.Sprintf("error must contain '%s' (instead got '%s')", mustContain[0], err.Error()))
	}
}
