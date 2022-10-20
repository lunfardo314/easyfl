package easyfl

import (
	"fmt"
)

// GlobalData represents the data to be evaluated. It is wrapped into the interface
// which offers some tracing options
type GlobalData interface {
	Data() interface{} // return data being evaluated. It is interpreted by the transaction host
	Trace() bool       // should return if the caller wants tracing of evaluation
	PutTrace(string)   // hook for tracing messages. Called only if Trace() =  true
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

func NewEvalContext(varScope []*Call, glb GlobalData) *EvalContext {
	return &EvalContext{
		varScope: varScope,
		glb:      glb,
	}
}

func NewCallParams(ctx *EvalContext, args []*Expression) *CallParams {
	return &CallParams{
		ctx:  ctx,
		args: args,
	}
}

func NewCall(f EvalFunction, params *CallParams) *Call {
	return &Call{
		f:      f,
		params: params,
	}
}

// Eval evaluates the expression by calling it eval function with the parameter
func (c *Call) Eval() []byte {
	return c.f(c.params)
}

// DataContext accesses the data context inside the embedded function
func (ctx *CallParams) DataContext() interface{} {
	return ctx.ctx.glb
}

// Arity return actual number of call parameters
func (ctx *CallParams) Arity() byte {
	return byte(len(ctx.args))
}

// Arg evaluates argument if the call inside embedded function
func (ctx *CallParams) Arg(n byte) []byte {
	if traceYN {
		fmt.Printf("Arg(%d) -- IN\n", n)
	}
	call := NewCall(ctx.args[n].EvalFunc, NewCallParams(ctx.ctx, ctx.args[n].Args))
	ret := call.Eval()

	if traceYN {
		fmt.Printf("Arg(%d) -- OUT ret: %v\n", n, ret)
	}
	return ret
}

// evalParam used by $0-$15 functions
func (ctx *CallParams) evalParam(n byte) []byte {
	if traceYN {
		fmt.Printf("evalParam $%d -- IN\n", n)
	}

	ret := ctx.ctx.varScope[n].Eval()

	if traceYN {
		fmt.Printf("evalParam $%d -- OUT, ret: %v\n", n, ret)
	}
	return ret
}

func (ctx *EvalContext) DataContext() interface{} {
	return ctx.glb
}

func evalExpression(glb GlobalData, f *Expression, varScope []*Call) []byte {
	ctx := NewEvalContext(varScope, glb)
	par := NewCallParams(ctx, f.Args)
	call := NewCall(f.EvalFunc, par)
	return call.Eval()
}

// EvalExpression evaluates expression, in the context of any data context and given values of parameters
func EvalExpression(glb GlobalData, f *Expression, args ...[]byte) []byte {
	argsForData := dataCalls(args...)
	return evalExpression(glb, f, argsForData)
}

// EvalFromSource compiles source of the expression and evaluates it
// Never panics
func EvalFromSource(glb GlobalData, source string, args ...[]byte) ([]byte, error) {
	var ret []byte
	err := catchPanicOrError(func() error {
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
	err := catchPanicOrError(func() error {
		ret = MustEvalFromBinary(glb, code, args...)
		return nil
	})
	return ret, err
}
