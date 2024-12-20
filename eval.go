package easyfl

import (
	"bytes"
	"fmt"
	"strings"
)

// GlobalData represents the data to be evaluated. It is wrapped into the interface
// which offers some tracing options
type GlobalData interface {
	Data() interface{} // return data being evaluated. It is interpreted by the transaction host
	Trace() bool       // should return true if tracing enabled
	PutTrace(string)   // hook for tracing messages. Called only if enabled
}

// evalContext is the structure through which the EasyFL script accesses data structure it is validating
type evalContext struct {
	glb      GlobalData
	varScope []*call
}

// CallParams is a structure through which the function accesses its evaluation context and call arguments
type CallParams struct {
	ctx  *evalContext
	args []*Expression
}

// call is EvalFunction with params
type call struct {
	f      EvalFunction
	params *CallParams
	cache  []byte
	cached bool
}

func newEvalContext(varScope []*call, glb GlobalData) *evalContext {
	return &evalContext{
		varScope: varScope,
		glb:      glb,
	}
}

func newCallParams(ctx *evalContext, args []*Expression) *CallParams {
	return &CallParams{
		ctx:  ctx,
		args: args,
	}
}

func newCall(f EvalFunction, args []*Expression, ctx *evalContext) *call {
	return &call{
		f:      f,
		params: newCallParams(ctx, args),
	}
}

// Eval evaluates the expression by calling it eval function with the parameter
func (c *call) Eval() []byte {
	if c.cached {
		return c.cache
	}
	c.cache = c.f.EmbeddedFunction(c.params)
	c.cached = true
	return c.cache
}

// DataContext accesses the data context inside the embedded function
func (p *CallParams) DataContext() interface{} {
	return p.ctx.glb.Data()
}

// Slice makes CallParams with the slice of arguments
func (p *CallParams) Slice(from, to byte) *CallParams {
	return &CallParams{
		ctx:  p.ctx,
		args: p.args[from:to],
	}
}

// Arity return actual number of call parameters
func (p *CallParams) Arity() byte {
	return byte(len(p.args))
}

func (ctx *evalContext) eval(f *Expression) []byte {
	return newCall(f.EvalFunc, f.Args, ctx).Eval()
}

// Arg evaluates argument if the call inside embedded function
func (p *CallParams) Arg(n byte) []byte {
	if traceYN {
		fmt.Printf("Arg(%d) -- IN\n", n)
	}
	ret := p.ctx.eval(p.args[n])

	if traceYN {
		fmt.Printf("Arg(%d) -- OUT ret: %v\n", n, ret)
	}
	return ret
}

func (p *CallParams) Trace(format string, args ...interface{}) {
	if isNil(p.ctx.glb) || !p.ctx.glb.Trace() {
		return
	}
	p.ctx.glb.PutTrace(fmt.Sprintf(format, args...))
}

func (p *CallParams) TracePanic(format string, args ...interface{}) {
	p.Trace("panic: "+format, args...)
	panic(fmt.Sprintf("panic: "+format, args...))
}

func (p *CallParams) EvalParam(paramNr byte) []byte {
	return p.ctx.varScope[paramNr].Eval()
}

func (p *CallParams) GetBytecode(paramNr byte) []byte {
	return p.ctx.varScope[paramNr].f.bytecode
}

func evalExpression(glb GlobalData, f *Expression, varScope []*call) []byte {
	return newEvalContext(varScope, glb).eval(f)
}

// EvalExpression evaluates expression, in the context of any data context and given values of parameters
func EvalExpression(glb GlobalData, f *Expression, args ...[]byte) []byte {
	argsForData := make([]*call, len(args))
	ctx := newEvalContext(nil, glb)
	for i, d := range args {
		argsForData[i] = newCall(dataFunction(d), nil, ctx)
	}
	return evalExpression(glb, f, argsForData)
}

// EvalFromSource compiles source of the expression and evaluates it
// Never panics
func (lib *Library) EvalFromSource(glb GlobalData, source string, args ...[]byte) ([]byte, error) {
	var ret []byte
	err := CatchPanicOrError(func() error {
		f, requiredNumArgs, _, err := lib.CompileExpression(source)
		if err != nil {
			return err
		}
		if requiredNumArgs != len(args) {
			return fmt.Errorf("required number of parameters is %d, got %d", requiredNumArgs, len(args))
		}
		ret = EvalExpression(glb, f, args...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// MustEvalFromSource evaluates the source of the expression and panics on any error
func (lib *Library) MustEvalFromSource(glb GlobalData, source string, args ...[]byte) []byte {
	ret, err := lib.EvalFromSource(glb, source, args...)
	if err != nil {
		panic(err)
	}
	return ret
}

// MustEvalFromBytecode interprets expression in the bytecode form. Will panic on any compile and runtime error
func (lib *Library) MustEvalFromBytecode(glb GlobalData, code []byte, args ...[]byte) []byte {
	expr, err := lib.ExpressionFromBytecode(code)
	if err != nil {
		panic(err)
	}
	defer disposeExpression(expr)

	return EvalExpression(glb, expr, args...)
}

// EvalFromBytecode evaluates expression, never panics but return an error
func (lib *Library) EvalFromBytecode(glb GlobalData, code []byte, args ...[]byte) ([]byte, error) {
	var ret []byte
	err := CatchPanicOrError(func() error {
		ret = lib.MustEvalFromBytecode(glb, code, args...)
		return nil
	})
	return ret, err
}

func (lib *Library) expressionFromLibrary(libraryBin [][]byte, funIndex int) (*Expression, error) {
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

func (lib *Library) MustEvalFromLibrary(glb GlobalData, libraryBin [][]byte, funIndex int, args ...[]byte) []byte {
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

func (lib *Library) EvalFromLibrary(glb GlobalData, libraryBin [][]byte, funIndex int, args ...[]byte) ([]byte, error) {
	var ret []byte
	err := CatchPanicOrError(func() error {
		ret = lib.MustEvalFromLibrary(glb, libraryBin, funIndex, args...)
		return nil
	})
	return ret, err
}

// CallLocalLibrary to be called from the extension outside the easyfl.
func (lib *Library) CallLocalLibrary(ctx *CallParams, libBin [][]byte, idx int) []byte {
	if idx < 0 || idx >= len(libBin) {
		panic("function index is out of library bounds")
	}
	expr, err := lib.expressionFromLibrary(libBin, idx)
	if err != nil {
		ctx.TracePanic("error while parsing local library: %v", err)
	}
	varScope := make([]*call, len(ctx.args))
	for i := range varScope {
		varScope[i] = newCall(ctx.args[i].EvalFunc, ctx.args[i].Args, ctx.ctx)
	}
	ret := evalExpression(ctx.ctx.glb, expr, varScope)
	ctx.Trace("'lib#%d':: %d params -> %s", idx, ctx.Arity(), Fmt(ret))
	return ret
}

func (lib *Library) MustEqual(source1, source2 string) {
	res1, err := lib.EvalFromSource(nil, source1)
	Assertf(err == nil, "expression '%s' resulted in error: '%v'", source1, err)
	res2, err := lib.EvalFromSource(nil, source2)
	Assertf(err == nil, "expression '%s' resulted in error: '%v'", source2, err)
	Assertf(bytes.Equal(res1, res2), "must be equal %s and %s: %s != %s", source1, source2, Fmt(res1), Fmt(res2))
}

func (lib *Library) MustTrue(source string) {
	res, err := lib.EvalFromSource(nil, source)
	Assertf(err == nil, "expression '%s' resulted in error: '%v'", source, err)
	Assertf(len(res) > 0, "expression '%s' must be true", res)
}

func (lib *Library) MustError(source string, mustContain ...string) {
	_, err := lib.EvalFromSource(nil, source)
	Assertf(err != nil, "expression '%s' is expected to return an error", source)
	if len(mustContain) > 0 {
		Assertf(strings.Contains(err.Error(), mustContain[0]), fmt.Sprintf("error must contain '%s' (instead got %s)", mustContain[0], err.Error()))
	}
}
