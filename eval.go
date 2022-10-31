package easyfl

import (
	"fmt"
)

// GlobalData represents the data to be evaluated. It is wrapped into the interface
// which offers some tracing options
type GlobalData interface {
	Data() interface{} // return data being evaluated. It is interpreted by the transaction host
	Trace() bool       // should return true if tracing enabled
	PutTrace(string)   // hook for tracing messages. Called only if enabled
}

// EvalContext is the structure through which the EasyFL script accesses data structure it is validating
type EvalContext struct {
	glb      GlobalData
	varScope []*Call
}

// CallParams is a structure through which the function accesses its evaluation context and call arguments
type CallParams struct {
	ctx  *EvalContext
	args []*Expression
}

// Call is EvalFunction with params
type Call struct {
	f      EvalFunction
	params *CallParams
}

func newEvalContext(varScope []*Call, glb GlobalData) *EvalContext {
	return &EvalContext{
		varScope: varScope,
		glb:      glb,
	}
}

func newCallParams(ctx *EvalContext, args []*Expression) *CallParams {
	return &CallParams{
		ctx:  ctx,
		args: args,
	}
}

func newCall(f EvalFunction, args []*Expression, ctx *EvalContext) *Call {
	return &Call{
		f:      f,
		params: newCallParams(ctx, args),
	}
}

// Eval evaluates the expression by calling it eval function with the parameter
func (c *Call) Eval() []byte {
	return c.f(c.params)
}

// DataContext accesses the data context inside the embedded function
func (p *CallParams) DataContext() interface{} {
	return p.ctx.glb.Data()
}

// Arity return actual number of call parameters
func (p *CallParams) Arity() byte {
	return byte(len(p.args))
}

func (ctx *EvalContext) eval(f *Expression) []byte {
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

// evalParam used by $0-$15 functions
func (p *CallParams) evalParam(n byte) []byte {
	if traceYN {
		fmt.Printf("evalParam $%d -- IN\n", n)
	}

	ret := p.ctx.varScope[n].Eval()

	if traceYN {
		fmt.Printf("evalParam $%d -- OUT, ret: %v\n", n, ret)
	}
	return ret
}

func (ctx *EvalContext) DataContext() interface{} {
	return ctx.glb.Data()
}

func evalExpression(glb GlobalData, f *Expression, varScope []*Call) []byte {
	return newEvalContext(varScope, glb).eval(f)
}

// EvalExpression evaluates expression, in the context of any data context and given values of parameters
func EvalExpression(glb GlobalData, f *Expression, args ...[]byte) []byte {
	argsForData := make([]*Call, len(args))
	ctx := newEvalContext(nil, glb)
	for i, d := range args {
		argsForData[i] = newCall(dataFunction(d), nil, ctx)
	}
	return evalExpression(glb, f, argsForData)
}

// EvalFromSource compiles source of the expression and evaluates it
// Never panics
func EvalFromSource(glb GlobalData, source string, args ...[]byte) ([]byte, error) {
	var ret []byte
	err := CatchPanicOrError(func() error {
		f, requiredNumArgs, _, err := CompileExpression(source)
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
func MustEvalFromSource(glb GlobalData, source string, args ...[]byte) []byte {
	ret, err := EvalFromSource(glb, source, args...)
	if err != nil {
		panic(err)
	}
	return ret
}

// MustEvalFromBinary interprets expression in the binary form. Will panic on any compile and runtime error
func MustEvalFromBinary(glb GlobalData, code []byte, args ...[]byte) []byte {
	expr, err := ExpressionFromBinary(code)
	if err != nil {
		panic(err)
	}
	return EvalExpression(glb, expr, args...)
}

// EvalFromBinary evaluates expression, never panics but return an error
func EvalFromBinary(glb GlobalData, code []byte, args ...[]byte) ([]byte, error) {
	var ret []byte
	err := CatchPanicOrError(func() error {
		ret = MustEvalFromBinary(glb, code, args...)
		return nil
	})
	return ret, err
}
