package engine

// Library-bound embedded function implementations. These differ from the
// rest of the embedded built-ins (which live in easyfl/embed) by needing
// access to library-internal state (function lookup, bytecode parsing,
// prefix matching). They live in engine alongside Library so they can
// reach unexported helpers like matchesPrefixes.
//
// The names are exported (EvalParse*) so easyfl/embed's resolver can wire
// them into the embedded function table by reference.

import (
	"encoding/hex"
	"fmt"

	"github.com/lunfardo314/easyfl/easyfl_util"
)

// EvalParseInlineData implements `parseInlineData(bin)`: panics if bin
// is not a recognised inline-data bytecode, otherwise returns the raw
// payload (data prefix stripped).
func (lib *Library[T]) EvalParseInlineData(par *CallParams[T]) []byte {
	dataBytecode := par.Arg(0)
	if !HasInlineDataPrefix(dataBytecode) {
		deco, err := lib.DecompileBytecode(dataBytecode)
		if err != nil {
			deco = err.Error()
		}
		par.TracePanic("evalParseInlineData: not an inline data function: %s (got decompiled='%v')",
			easyfl_util.FmtLazy(dataBytecode), deco)
	}
	return StripDataPrefix(dataBytecode)
}

// EvalParseBytecode implements `parseBytecode(bytecode, idx, prefix...)`.
//   - arg0: bytecode of a top-level call.
//   - arg1: 1-byte argument index (which child to return), or empty to
//     return the call-prefix.
//   - arg2..: zero or more enforced call-prefix alternatives; if any are
//     present, the bytecode's prefix must match one of them or the call
//     panics.
func (lib *Library[T]) EvalParseBytecode(par *CallParams[T]) (ret []byte) {
	par.Require(par.Arity() >= 2, "evalParseBytecode: wrong number of arguments")
	a0 := par.Arg(0)
	sym, prefix, args, err := lib.ParseBytecodeOneLevel(a0)
	if err != nil {
		err = fmt.Errorf("evalParseBytecode: %v", err)
	}
	par.RequireNoError(err)

	a1 := par.Arg(1)
	if len(a1) == 0 {
		ret = prefix
	} else {
		par.Require(len(a1) == 1, "evalParseBytecode: expected argument1 length 1 byte")
		par.Require(int(a1[0]) < len(args), "evalParseBytecode: wrong parameter index: number of params %d, got index %d", len(args), a1[0])
		ret = args[a1[0]]
	}
	if par.Arity() == 2 {
		return
	}
	for i := byte(2); i < par.Arity(); i++ {
		match, err := lib.matchesPrefixes(prefix, par.Arg(i))
		par.RequireNoError(err)
		if match {
			return
		}
	}
	par.Require(false, "evalParseBytecode: unexpected call prefix '%s'", sym)
	return
}

// EvalParseInlineDataArgument is the inline-data variant of EvalParseBytecode:
// returns the argument as inline-data payload (panics if the bytecode at
// that position isn't an inline-data call).
func (lib *Library[T]) EvalParseInlineDataArgument(par *CallParams[T]) (ret []byte) {
	ret = lib.EvalParseBytecode(par)
	par.Require(HasInlineDataPrefix(ret), "evalParseInlineDataArgument: not an inline data function")
	return StripDataPrefix(ret)
}

// EvalParseNumArgs implements `parseNumArgs(bytecode)`: returns the
// number of arguments the top-level call in bytecode would take.
func (lib *Library[T]) EvalParseNumArgs(par *CallParams[T]) []byte {
	bytecode := par.Arg(0)
	nargs, err := lib.ParseNumArgs(bytecode)
	if err != nil {
		par.TracePanic("evalParseNumArgs(0x%s): %v", hex.EncodeToString(bytecode), err)
	}
	easyfl_util.Assertf(nargs <= MaxParameters, "nargs<=MaxParameters")
	return par.AllocData(byte(nargs))
}
