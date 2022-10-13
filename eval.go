package easyfl

import (
	"fmt"

	"github.com/lunfardo314/easyutxo"
)

// EvalContext is the structure through which the EasyFL script accesses data structure it is validating
type EvalContext struct {
	glb      interface{}
	varScope []*Call
	prev     *EvalContext
}

// CallParams is a structure through which the function accesses its evaluation context and call arguments
type CallParams struct {
	ctx  *EvalContext
	args []*Expression
}

type Call struct {
	f      EvalFunction
	params *CallParams
}

func NewEvalContext(varScope []*Call, glb interface{}, prev *EvalContext) *EvalContext {
	return &EvalContext{
		varScope: varScope,
		glb:      glb,
		prev:     prev,
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

func (c *Call) Eval() []byte {
	return c.f(c.params)
}

func (ctx *CallParams) DataContext() interface{} {
	return ctx.ctx.glb
}

func (ctx *CallParams) Arity() byte {
	return byte(len(ctx.args))
}

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

func evalExpression(glb interface{}, f *Expression, varScope []*Call) []byte {
	ctx := NewEvalContext(varScope, glb, nil)
	par := NewCallParams(ctx, f.Args)
	call := NewCall(f.EvalFunc, par)
	return call.Eval()
}

func EvalExpression(glb interface{}, f *Expression, args ...[]byte) []byte {
	argsForData := dataCalls(args...)
	return evalExpression(glb, f, argsForData)
}

func EvalFromSource(glb interface{}, source string, args ...[]byte) ([]byte, error) {
	var ret []byte
	err := easyutxo.CatchPanicOrError(func() error {
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

func MustEvalFromSource(glb interface{}, source string, args ...[]byte) []byte {
	ret, err := EvalFromSource(glb, source, args...)
	if err != nil {
		panic(err)
	}
	return ret
}

func MustEvalFromBinary(glb interface{}, code []byte, args ...[]byte) []byte {
	expr, err := ExpressionFromBinary(code)
	if err != nil {
		panic(err)
	}
	return EvalExpression(glb, expr, args...)
}

func EvalFromBinary(glb interface{}, code []byte, args ...[]byte) ([]byte, error) {
	var ret []byte
	err := easyutxo.CatchPanicOrError(func() error {
		ret = MustEvalFromBinary(glb, code, args...)
		return nil
	})
	return ret, err
}
