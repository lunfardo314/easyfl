package engine

import "fmt"

// EngineRules are evaluation rules a host switches on per library. Each of them
// rejects programs the engine used to accept, so for a ledger they are a
// validity change: the host enables them on the library versions that activate
// them, not retroactively. The zero value is the engine's historic behaviour.
//
// They are not part of the library hash, like the Go bodies of embedded
// functions: the host must set the same rules on the same library version on
// every node.
type EngineRules struct {
	// MaxCallDepth bounds the nesting of calls in one evaluation, nested local
	// script evaluations included. Arguments are evaluated lazily inside the
	// callee, so the Go stack can grow exponentially with the bytecode size,
	// and a Go stack overflow is a fatal error no recover catches. 0: unlimited.
	MaxCallDepth int
	// MaxCalls bounds the number of calls in one evaluation, plus what
	// builtins charge for work proportional to their input (CallParams.Charge).
	// Separate call sites re-evaluate a callee, so the number of calls can be
	// exponential in the bytecode size. 0: unlimited.
	MaxCalls int
	// Strict enables the encoding and builtin fixes of the 2026-11 audit:
	//   - parseBytecode with prefix arguments: an inline-data literal is never
	//     taken for a call (its first byte also carries the long-call bit);
	//   - inline data in the long form (0xff) must be at least 127 bytes, so
	//     each value has one encoding;
	//   - selectCaseByIndex compares the whole index instead of its low byte;
	//   - byte(data, 255) returns the byte instead of failing.
	Strict bool
}

// SetEngineRules sets the evaluation rules of the library. Call it before the
// library evaluates anything; it is not synchronised with evaluation.
func (lib *Library[T]) SetEngineRules(r EngineRules) {
	lib.rules = r
}

// EngineRules returns the evaluation rules of the library.
func (lib *Library[T]) EngineRules() EngineRules {
	return lib.rules
}

// evalBudget is the running cost of one evaluation, shared by every nested
// evaluation context of it, nested local scripts included.
type evalBudget struct {
	rules EngineRules
	depth int
	calls int
}

func newEvalBudget[T any](glb GlobalData[T]) *evalBudget {
	ret := &evalBudget{}
	if glb != nil {
		if lib := glb.Library(); lib != nil {
			ret.rules = lib.rules
		}
	}
	return ret
}

func (b *evalBudget) enter() {
	b.depth++
	if b.rules.MaxCallDepth > 0 && b.depth > b.rules.MaxCallDepth {
		panic(fmt.Errorf("easyfl eval: call depth exceeds limit %d", b.rules.MaxCallDepth))
	}
	b.charge(1)
}

func (b *evalBudget) leave() {
	b.depth--
}

func (b *evalBudget) charge(units int) {
	b.calls += units
	if b.rules.MaxCalls > 0 && b.calls > b.rules.MaxCalls {
		panic(fmt.Errorf("easyfl eval: number of calls exceeds limit %d", b.rules.MaxCalls))
	}
}
