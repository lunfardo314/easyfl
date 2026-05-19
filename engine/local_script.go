package engine

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/lunfardo314/easyfl/slicepool"
)

// Local scripts are self-contained, serialized bundles of EasyFL functions.
// See claude/local_script.md for the design.

// MaxLocalScriptFunctions is the maximum number of functions in a single
// local script. The wire format encodes the function index as a single byte.
const MaxLocalScriptFunctions = 256

// Wire-format constants. See claude/local_script.md §4.
//
//	LocalScriptBin :=
//	    magic[2]              // 0x45 0x53  ('ES')
//	    version[1]            // 0x02
//	    n[2]                  // BE uint16, number of functions, 0..256
//	    arity[n]              // 1 byte each, declared arity 0..15
//	    flags[n]              // 1 byte each, per-fn flag bits (bit 0 = private)
//	    offsets[n*2]          // BE uint16, byte offset of each fn's bytecode within `body`
//	    bodyLen[2]            // BE uint16
//	    body[bodyLen]         // concatenated function bytecodes
//
// Header total: 5 + 4*n + 2 = 7 + 4*n bytes.
//
// Version 0x02 added the flags[n] array for the private-entry-point feature
// (see compileLocalScript and (*LocalScript[T]).Eval). v1 bins are rejected;
// no backward compatibility is maintained at this stage.
const (
	localScriptMagic0  = 0x45 // 'E'
	localScriptMagic1  = 0x53 // 'S'
	localScriptVersion = 0x02
)

// Per-function flag bits in the `flags[n]` header array.
const (
	// localScriptFlagPrivate marks a function that cannot be invoked via
	// (*LocalScript[T]).Eval (or transitively via callRedeemer). Set
	// automatically at compile time for any source-level function whose name
	// starts with an underscore. Internal helpers carry an `_` prefix; the
	// public API does not.
	localScriptFlagPrivate byte = 1 << 0
)

// LocalScriptBin is the canonical wire form of a local script.
type LocalScriptBin []byte

// LocalScript is the executable form of a local script. Construct one with
// Library[T].LocalScriptFromBytes. Opaque except for the methods below.
//
// Field shapes (funByName / funByFunCode) are intentionally compatible with
// the resolution paths in library.go and compiler.go that previously took a
// *LocalLibrary[T].
type LocalScript[T any] struct {
	bin          LocalScriptBin
	funByName    map[string]*funDescriptor[T]
	funByFunCode []*funDescriptor[T] // index = local index (0..n-1)
	expressions  []*Expression[T]    // expression tree per function index
}

// CompileLocalScript compiles EasyFL source containing one or more function
// definitions into a LocalScriptBin. Source order is free; cycles, vararg
// locals, and over-arity definitions are rejected.
//
// Cross-script composition (e.g. a `callRedeemer(hash, fnIdx, ...)` pattern
// where the host registers callRedeemer as a vararg global) is structurally
// recursion-free without any runtime check: the callee is identified by
// content hash, and a hash can only exist after the callee binary is
// compiled — so the dependency graph between binaries is a DAG by
// construction, the same way the function-reference graph inside the
// library is a DAG. easyfl therefore imposes no per-call restriction.
//
// Hosts that want to *declare* which other scripts a binary is willing to
// call (an "import list" — useful for catching typos at compile time and
// for verifying call-site structure such as fnIdx-in-range and arity
// match) can use CompileLocalScriptWithCheck. Such a declaration is a
// compile-time precaution, not a safety property; safety comes from the
// hash-by-content rule above.
func (lib *Library[T]) CompileLocalScript(source string) (LocalScriptBin, error) {
	bin, _, err := lib.CompileLocalScriptWithIndex(source)
	return bin, err
}

// CompileLocalScriptWithIndex is like CompileLocalScript but additionally
// returns a map from source-level function names to their wire indices in
// the resulting LocalScriptBin. Useful for hosts and tests that want to
// invoke a specific function by source name; the decoded *LocalScript[T]
// uses synthetic "script#i" symbols and has no knowledge of source names.
func (lib *Library[T]) CompileLocalScriptWithIndex(source string) (LocalScriptBin, map[string]int, error) {
	return lib.compileLocalScript(source, nil)
}

// compileLocalScript is the shared implementation of
// CompileLocalScriptWithIndex (check == nil) and CompileLocalScriptWithCheck.
// When check is non-nil it is invoked once per non-trivial call site after
// cycle / forbidden-funCode checks but before bytecode is encoded —
// callers see source-level names for both the calling function and any
// local callees.
func (lib *Library[T]) compileLocalScript(source string, check LocalScriptCallSiteCheck[T]) (LocalScriptBin, map[string]int, error) {
	// ---- Phase 1: parse
	parsed, err := ParseFunctions(source)
	if err != nil {
		return nil, nil, err
	}
	if len(parsed) > MaxLocalScriptFunctions {
		return nil, nil, fmt.Errorf("local script: too many functions: %d (max %d)", len(parsed), MaxLocalScriptFunctions)
	}
	seen := make(map[string]bool, len(parsed))
	for _, p := range parsed {
		if p.IsVararg {
			return nil, nil, fmt.Errorf("local script: vararg local functions are not allowed (in '%s')", p.Sym)
		}
		if seen[p.Sym] {
			return nil, nil, fmt.Errorf("local script: duplicate symbol '%s'", p.Sym)
		}
		seen[p.Sym] = true
	}

	// ---- Phase 2: introduce stubs in a fresh compile-time scope.
	// Privacy is decided at this point: any source-level function whose name
	// starts with '_' is private and will refuse to be dispatched at runtime.
	scope := &LocalScript[T]{
		funByName:    make(map[string]*funDescriptor[T], len(parsed)),
		funByFunCode: make([]*funDescriptor[T], 0, len(parsed)),
	}
	for i, p := range parsed {
		d := &funDescriptor[T]{
			sym:               p.Sym,
			funCode:           uint16(FirstLocalFunCode) + uint16(i),
			requiredNumParams: -1, // temporary; set in Phase 2.5
			private:           strings.HasPrefix(p.Sym, "_"),
		}
		scope.funByName[p.Sym] = d
		scope.funByFunCode = append(scope.funByFunCode, d)
	}

	// ---- Phase 2.5: count params from source so #fnName references resolve
	for i, p := range parsed {
		n, err := CountParametersFromSource(p.SourceCode)
		if err != nil {
			return nil, nil, fmt.Errorf("local script: counting params for '%s': %v", p.Sym, err)
		}
		if n > MaxParameters {
			return nil, nil, fmt.Errorf("local script: function '%s' has %d params, max %d", p.Sym, n, MaxParameters)
		}
		scope.funByFunCode[i].requiredNumParams = n
	}

	// ---- Phase 3: compile bodies to bytecode against the scope
	bytecodes := make([][]byte, len(parsed))
	for i, p := range parsed {
		src, err := preprocessSource(p.SourceCode)
		if err != nil {
			return nil, nil, fmt.Errorf("local script: preprocess '%s': %v", p.Sym, err)
		}
		bc, n, err := lib.ExpressionSourceToBytecode(src, scope)
		if err != nil {
			return nil, nil, fmt.Errorf("local script: compile '%s': %v", p.Sym, err)
		}
		if n != scope.funByFunCode[i].requiredNumParams {
			return nil, nil, fmt.Errorf("local script: function '%s': declared %d params, body uses %d",
				p.Sym, scope.funByFunCode[i].requiredNumParams, n)
		}
		bytecodes[i] = bc
	}

	// ---- Phase 4: cycle detection on intra-script call graph
	if err := checkLocalScriptCycles(scope, bytecodes); err != nil {
		return nil, nil, err
	}

	// ---- Phase 5: user-supplied call-site check (if any)
	// Decode each pre-toposort bytecode into an Expression tree using the
	// source-name scope, then walk for the user check. Source-level names
	// are visible for both the caller and any local callees. Typical use
	// is to enforce a declared import list (e.g. "callRedeemer's first
	// argument must hash to one of these pinned binaries"); see the
	// LocalScriptCallSiteCheck doc for the full rationale.
	if check != nil {
		for i, bc := range bytecodes {
			expr, err := lib.ExpressionFromBytecode(bc, scope)
			if err != nil {
				return nil, nil, fmt.Errorf("local script: rebuilding expression for check in '%s': %v",
					scope.funByFunCode[i].sym, err)
			}
			if err := walkExpressionCalls(scope.funByFunCode[i].sym, expr, check); err != nil {
				return nil, nil, err
			}
		}
	}

	// ---- Phase 6: topological sort + encode in dependency order
	order, err := topologicalSortLocal(bytecodes)
	if err != nil {
		return nil, nil, err
	}
	bin, err := encodeLocalScript(scope, bytecodes, order)
	if err != nil {
		return nil, nil, err
	}

	// Build sym → wire-index map. order[wireIdx] = oldIdx (source-position).
	symIndex := make(map[string]int, len(parsed))
	for wireIdx, oldIdx := range order {
		symIndex[parsed[oldIdx].Sym] = wireIdx
	}
	return bin, symIndex, nil
}

// LocalScriptCallSiteCheck is a per-call-site validation hook invoked by
// CompileLocalScriptWithCheck and LocalScriptFromBytesWithCheck. For every
// non-trivial call expression encountered while walking each function body
// (excluding inline-data literals and $0..$14 parameter references) the
// hook receives the source-level name of the calling function plus the
// Expression node representing the call. Returning a non-nil error fails
// the operation with that error.
//
// The hook is **not** a safety mechanism. Cross-script composition via a
// host-registered `callRedeemer(hash, fnIdx, ...)` global is recursion-
// free by construction: hashes only exist after the callee is compiled,
// so the dependency graph is a DAG, and a host that dispatches by hash
// cannot be tricked into calling itself. The same property removed the
// need for the legacy notInLocalScript flag.
//
// What the hook *is* useful for is a compile-time **declaration** of a
// binary's dependencies — an import list. The host registers a check
// that, for each `callRedeemer(...)` site, verifies:
//
//   1. The first argument is a 32-byte literal hash.
//   2. That hash is in the binary's declared import set.
//   3. The fnIdx literal is in range of the imported binary's functions.
//   4. The number of forwarded args matches the imported function's arity.
//
// All four are catch-typos-early checks; none of them are required for
// safety. A binary compiled without a check is no less sound than one
// compiled with — the check just turns a "bad call rejected at execution
// time" failure into a "bad call rejected at compile time" failure, and
// makes the import set visible to readers of the source.
type LocalScriptCallSiteCheck[T any] func(callerSym string, callee *Expression[T]) error

// IsInlineData reports whether the expression is an inline-data literal
// (the high bit of CallPrefix[0] is set per the bytecode format). Inline
// data has its full payload embedded in CallPrefix.
func (e *Expression[T]) IsInlineData() bool {
	return len(e.CallPrefix) > 0 && e.CallPrefix[0]&FirstByteDataMask != 0
}

// InlineData returns the literal bytes for an inline-data expression, or
// nil if the expression is not inline data. Both the short form
// (`0x80|len + payload`) and the long form (`0xff + len[2] + payload`)
// are decoded.
func (e *Expression[T]) InlineData() []byte {
	if !e.IsInlineData() {
		return nil
	}
	if e.CallPrefix[0] == 0xff {
		if len(e.CallPrefix) < 3 {
			return nil
		}
		return e.CallPrefix[3:]
	}
	return e.CallPrefix[1:]
}

// IsParameterRef reports whether the expression is a $0..$14 parameter
// reference (a single-byte short call with funCode in the reserved range).
func (e *Expression[T]) IsParameterRef() bool {
	if e.IsInlineData() || len(e.CallPrefix) != 1 {
		return false
	}
	return uint16(e.CallPrefix[0]) <= LastEmbeddedReserved
}

// walkExpressionCalls invokes cb once per non-trivial call site (not inline
// data, not parameter ref) found in expr, in preorder.
func walkExpressionCalls[T any](callerSym string, expr *Expression[T], cb LocalScriptCallSiteCheck[T]) error {
	if cb == nil {
		return nil
	}
	if !expr.IsInlineData() && !expr.IsParameterRef() {
		if err := cb(callerSym, expr); err != nil {
			return err
		}
	}
	for _, arg := range expr.Args {
		if err := walkExpressionCalls(callerSym, arg, cb); err != nil {
			return err
		}
	}
	return nil
}

// CompileLocalScriptWithCheck is like CompileLocalScriptWithIndex but
// additionally invokes `check` for every non-trivial call site in the
// compiled bodies. Returning a non-nil error from `check` fails
// compilation.
//
// Local-call call-sites carry their source-level name in the callee's
// FunctionName when invoked from this entry point (the parent script's
// scope is used to decode). Caller-symbol names are the source-level
// function names from the script.
//
// Typical use is to declare which other binaries the script is willing
// to call into — an "import list" expressed at the call-site level.
// Recursion is impossible regardless (calls dispatch by content hash,
// which forms a DAG by construction); the check is a compile-time
// precaution that catches unknown hashes, out-of-range fnIdx values, and
// arity mismatches early. A `check == nil` is equivalent to
// CompileLocalScriptWithIndex and is just as sound — only less helpful
// to the source author.
func (lib *Library[T]) CompileLocalScriptWithCheck(source string, check LocalScriptCallSiteCheck[T]) (LocalScriptBin, map[string]int, error) {
	return lib.compileLocalScript(source, check)
}

// LocalScriptFromBytesWithCheck is like LocalScriptFromBytes but also
// invokes `check` for every non-trivial call site in the decoded bodies.
// Caller-symbol names are the synthesised "script#i" form used at decode
// time.
//
// Useful when a binary travels across an import-set boundary (compiled
// against import set A, decoded for execution against import set B): the
// caller can re-run its declaration against the imported binary it
// actually has on hand. As at compile time, this is a precaution, not a
// soundness gate.
func (lib *Library[T]) LocalScriptFromBytesWithCheck(bin LocalScriptBin, check LocalScriptCallSiteCheck[T]) (*LocalScript[T], error) {
	s, err := lib.LocalScriptFromBytes(bin)
	if err != nil {
		return nil, err
	}
	if check == nil {
		return s, nil
	}
	for i := 0; i < s.NumFunctions(); i++ {
		if err := walkExpressionCalls(s.funByFunCode[i].sym, s.expressions[i], check); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// LocalScriptFromBytes parses a LocalScriptBin into the executable form.
// Decoded scripts use synthesised "script#i" symbols (the original source
// names aren't on the wire), but per-fn privacy survives serialisation via
// the flags[n] header array — see compileLocalScript for the encoding.
func (lib *Library[T]) LocalScriptFromBytes(bin LocalScriptBin) (*LocalScript[T], error) {
	arities, flags, bodies, err := parseLocalScriptHeader(bin)
	if err != nil {
		return nil, err
	}
	n := len(arities)
	ret := &LocalScript[T]{
		bin:          append(LocalScriptBin(nil), bin...),
		funByName:    make(map[string]*funDescriptor[T], n),
		funByFunCode: make([]*funDescriptor[T], 0, n),
		expressions:  make([]*Expression[T], 0, n),
	}

	// Stub-introduce so each fn can reference earlier ones during expression building.
	for i, ar := range arities {
		sym := fmt.Sprintf("script#%d", i)
		d := &funDescriptor[T]{
			sym:               sym,
			funCode:           uint16(FirstLocalFunCode) + uint16(i),
			requiredNumParams: int(ar),
			private:           flags[i]&localScriptFlagPrivate != 0,
		}
		ret.funByName[sym] = d
		ret.funByFunCode = append(ret.funByFunCode, d)
	}

	// Build expression trees in array order; the encoder writes dependencies first,
	// so each fn finds its dependencies as already bound.
	for i, bc := range bodies {
		expr, err := lib.ExpressionFromBytecode(bc, ret)
		if err != nil {
			return nil, fmt.Errorf("local script: building expression for '%s': %v", ret.funByFunCode[i].sym, err)
		}
		ret.expressions = append(ret.expressions, expr)
		ret.funByFunCode[i].embeddedFun = makeEmbeddedFunForExpression(ret.funByFunCode[i].sym, expr)
	}
	return ret, nil
}

// === methods on *LocalScript[T] ===

// Bytes returns the wire form of the script.
func (s *LocalScript[T]) Bytes() LocalScriptBin { return s.bin }

// NumFunctions returns the number of functions in the script.
func (s *LocalScript[T]) NumFunctions() int { return len(s.funByFunCode) }

// Arity returns the declared arity of function idx.
func (s *LocalScript[T]) Arity(idx int) (int, error) {
	if idx < 0 || idx >= len(s.funByFunCode) {
		return 0, fmt.Errorf("local script: function index %d out of bounds (n=%d)", idx, len(s.funByFunCode))
	}
	return s.funByFunCode[idx].requiredNumParams, nil
}

// IsPrivate reports whether function idx is private. Private functions are
// internal helpers (source-level name starts with '_'); Eval refuses to
// dispatch them. Indices out of range count as "not private".
func (s *LocalScript[T]) IsPrivate(idx int) bool {
	if idx < 0 || idx >= len(s.funByFunCode) {
		return false
	}
	return s.funByFunCode[idx].private
}

// Function returns the expression tree for function idx.
func (s *LocalScript[T]) Function(idx int) (*Expression[T], error) {
	if idx < 0 || idx >= len(s.expressions) {
		return nil, fmt.Errorf("local script: function index %d out of bounds (n=%d)", idx, len(s.expressions))
	}
	return s.expressions[idx], nil
}

// Eval evaluates function idx of the script with the given args, in the given
// data context. Returns the function's result as bytes, or an error (caught
// from any panic during evaluation). Creates and disposes its own slice pool,
// so the returned slice survives this call.
//
// For nested dispatch (one script invoked from inside another's evaluation),
// prefer EvalInPool — it threads the caller's slice pool through, avoiding
// the per-Eval pool creation + segment churn + result copy-out.
//
// Privacy gate: attempts to invoke a private function (source-level name
// starts with '_') return an error before any evaluation runs. Hosts that
// dispatch into a script — most notably callRedeemer in proxima — surface
// this as a script-validation failure on the consuming transaction.
func (s *LocalScript[T]) Eval(glb GlobalData[T], idx int, args ...[]byte) ([]byte, error) {
	expr, err := s.checkAndGetExpression(idx, len(args))
	if err != nil {
		return nil, err
	}
	var ret []byte
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("local script: eval #%d: %v", idx, r)
		}
	}()
	ret = EvalExpression(glb, expr, args...)
	return ret, err
}

// EvalInPool is the nested-dispatch variant of Eval. The caller supplies
// the slice pool the outer evaluation is using; this call's allocations
// land in that pool, and the returned slice references pool-owned memory
// (no defensive copy-out). The caller must keep the pool alive for the
// duration of any downstream consumption of the returned slice.
//
// Used by proxima's callRedeemer to thread the parent eval's spool down
// into the redeemed script, eliminating per-redeemer pool creation and
// result copy-out — which dominate allocations in deeply nested covenant
// validators.
func (s *LocalScript[T]) EvalInPool(glb GlobalData[T], spool *slicepool.SlicePool, idx int, args ...[]byte) ([]byte, error) {
	expr, err := s.checkAndGetExpression(idx, len(args))
	if err != nil {
		return nil, err
	}
	var ret []byte
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("local script: eval #%d: %v", idx, r)
		}
	}()
	ret = EvalExpressionInPool(glb, spool, expr, args...)
	return ret, err
}

// checkAndGetExpression validates idx (range + privacy + arity) and
// returns the expression tree to evaluate. Shared between Eval and
// EvalInPool so dispatch rules stay in one place.
func (s *LocalScript[T]) checkAndGetExpression(idx, gotArgs int) (*Expression[T], error) {
	if idx < 0 || idx >= len(s.funByFunCode) {
		return nil, fmt.Errorf("local script: function index %d out of bounds (n=%d)", idx, len(s.funByFunCode))
	}
	if s.funByFunCode[idx].private {
		return nil, fmt.Errorf("local script: function #%d is private and cannot be invoked", idx)
	}
	declared := s.funByFunCode[idx].requiredNumParams
	if declared >= 0 && declared != gotArgs {
		return nil, fmt.Errorf("local script: function #%d expects %d args, got %d", idx, declared, gotArgs)
	}
	return s.Function(idx)
}

// === wire format ===

// parseLocalScriptHeader validates the wire format and returns the per-fn
// declared arities, per-fn flag bytes, and per-fn bytecode slices (slices
// are views into bin).
func parseLocalScriptHeader(bin LocalScriptBin) (arities, flags []byte, bodies [][]byte, err error) {
	const fixed = 2 + 1 + 2 + 2 // magic + version + n + bodyLen
	if len(bin) < fixed {
		return nil, nil, nil, fmt.Errorf("local script: truncated header")
	}
	if bin[0] != localScriptMagic0 || bin[1] != localScriptMagic1 {
		return nil, nil, nil, fmt.Errorf("local script: bad magic")
	}
	if bin[2] != localScriptVersion {
		return nil, nil, nil, fmt.Errorf("local script: unsupported version 0x%02x", bin[2])
	}
	n := int(binary.BigEndian.Uint16(bin[3:5]))
	if n > MaxLocalScriptFunctions {
		return nil, nil, nil, fmt.Errorf("local script: too many functions: %d (max %d)", n, MaxLocalScriptFunctions)
	}
	headerLen := 5 + 4*n + 2 // magic+version + n + arity[n] + flags[n] + offsets[n*2] + bodyLen
	if len(bin) < headerLen {
		return nil, nil, nil, fmt.Errorf("local script: truncated header (need %d, got %d)", headerLen, len(bin))
	}
	arities = make([]byte, n)
	copy(arities, bin[5:5+n])
	for i, ar := range arities {
		if ar > MaxParameters {
			return nil, nil, nil, fmt.Errorf("local script: function #%d has arity %d (max %d)", i, ar, MaxParameters)
		}
	}
	flags = make([]byte, n)
	copy(flags, bin[5+n:5+2*n])

	offsetsBase := 5 + 2*n
	offsets := make([]int, n)
	for i := 0; i < n; i++ {
		offsets[i] = int(binary.BigEndian.Uint16(bin[offsetsBase+2*i : offsetsBase+2*i+2]))
	}
	bodyLen := int(binary.BigEndian.Uint16(bin[offsetsBase+2*n : offsetsBase+2*n+2]))
	if len(bin) != headerLen+bodyLen {
		return nil, nil, nil, fmt.Errorf("local script: bad bodyLen (header says %d, total wire %d)", bodyLen, len(bin))
	}
	body := bin[headerLen:]
	bodies = make([][]byte, n)
	for i := 0; i < n; i++ {
		start := offsets[i]
		end := bodyLen
		if i+1 < n {
			end = offsets[i+1]
		}
		if start > end || end > bodyLen {
			return nil, nil, nil, fmt.Errorf("local script: bad offsets at #%d (start=%d end=%d bodyLen=%d)",
				i, start, end, bodyLen)
		}
		bodies[i] = body[start:end]
	}
	return arities, flags, bodies, nil
}

// encodeLocalScript writes bytecodes in the given topological order and
// reassigns local indices so they match the on-wire order. Call sites in the
// bodies are rewritten to use the new indices.
func encodeLocalScript[T any](
	scope *LocalScript[T],
	bytecodes [][]byte,
	order []int,
) (LocalScriptBin, error) {
	n := len(order)
	if n != len(bytecodes) {
		return nil, fmt.Errorf("local script: encoder: %d bytecodes vs %d order entries", len(bytecodes), n)
	}
	// newIndex[oldIdx] = newIdx
	newIndex := make([]int, n)
	for newIdx, oldIdx := range order {
		newIndex[oldIdx] = newIdx
	}
	// Rewrite each body's local-call prefixes to use the new indices.
	rewritten := make([][]byte, n)
	totalBody := 0
	for newIdx, oldIdx := range order {
		bc := bytecodes[oldIdx]
		nbc, err := rewriteLocalIndices(bc, newIndex)
		if err != nil {
			return nil, fmt.Errorf("local script: rewriting indices for '%s': %v", scope.funByFunCode[oldIdx].sym, err)
		}
		rewritten[newIdx] = nbc
		totalBody += len(nbc)
	}
	if totalBody > 0xffff {
		return nil, fmt.Errorf("local script: body too large: %d bytes (max 65535)", totalBody)
	}

	headerLen := 5 + 4*n + 2
	out := make([]byte, headerLen+totalBody)
	out[0] = localScriptMagic0
	out[1] = localScriptMagic1
	out[2] = localScriptVersion
	binary.BigEndian.PutUint16(out[3:5], uint16(n))

	// arity[n] in NEW order
	for newIdx, oldIdx := range order {
		out[5+newIdx] = byte(scope.funByFunCode[oldIdx].requiredNumParams)
	}

	// flags[n] in NEW order. Bit 0 = private. See localScriptFlagPrivate.
	for newIdx, oldIdx := range order {
		var f byte
		if scope.funByFunCode[oldIdx].private {
			f |= localScriptFlagPrivate
		}
		out[5+n+newIdx] = f
	}

	// offsets[n*2]
	offsetsBase := 5 + 2*n
	off := 0
	for i := 0; i < n; i++ {
		binary.BigEndian.PutUint16(out[offsetsBase+2*i:offsetsBase+2*i+2], uint16(off))
		off += len(rewritten[i])
	}

	// bodyLen[2]
	binary.BigEndian.PutUint16(out[offsetsBase+2*n:offsetsBase+2*n+2], uint16(totalBody))

	// body
	body := out[headerLen:]
	pos := 0
	for _, bc := range rewritten {
		copy(body[pos:], bc)
		pos += len(bc)
	}
	return out, nil
}

// === bytecode walking and intra-script analysis ===

// walkBytecode is a preorder walker over a bytecode buffer. For each call
// site it invokes visit(funCode, isLocal, localIdxOffset). For non-local
// calls localIdxOffset is -1; for a local call it points to the third byte
// of the prefix in `bc` (the local index byte).
func walkBytecode(bc []byte, visit func(funCode uint16, isLocal bool, localIdxOffset int) error) error {
	pos := 0
	for pos < len(bc) {
		b := bc[pos]
		switch {
		case b&FirstByteDataMask != 0:
			// inline data
			if b == 0xff {
				if pos+3 > len(bc) {
					return io.ErrUnexpectedEOF
				}
				dataLen := int(binary.BigEndian.Uint16(bc[pos+1 : pos+3]))
				pos += 3 + dataLen
			} else {
				dataLen := int(b & FirstByteShortDataLenMask)
				pos += 1 + dataLen
			}
			if pos > len(bc) {
				return io.ErrUnexpectedEOF
			}
		case b&FirstByteLongCallMask == 0:
			// short call: 1 byte
			if err := visit(uint16(b), false, -1); err != nil {
				return err
			}
			pos++
		default:
			// long call: 2+ bytes
			if pos+2 > len(bc) {
				return io.ErrUnexpectedEOF
			}
			u16 := binary.BigEndian.Uint16(bc[pos : pos+2])
			funCode := u16 & Uint16LongCallCodeMask
			if funCode == FirstLocalFunCode {
				if pos+3 > len(bc) {
					return io.ErrUnexpectedEOF
				}
				if err := visit(funCode, true, pos+2); err != nil {
					return err
				}
				pos += 3
			} else {
				if err := visit(funCode, false, -1); err != nil {
					return err
				}
				pos += 2
			}
		}
	}
	return nil
}

// rewriteLocalIndices walks bc, finding every 3-byte local-call prefix, and
// rewrites its third byte using the newIndex mapping. Returns a copy of bc
// with the rewritten indices.
func rewriteLocalIndices(bc []byte, newIndex []int) ([]byte, error) {
	out := append([]byte(nil), bc...)
	err := walkBytecode(out, func(_ uint16, isLocal bool, localIdxOffset int) error {
		if !isLocal {
			return nil
		}
		oldIdx := int(out[localIdxOffset])
		if oldIdx >= len(newIndex) {
			return fmt.Errorf("local index %d out of range (n=%d)", oldIdx, len(newIndex))
		}
		out[localIdxOffset] = byte(newIndex[oldIdx])
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// extractReferencedLocalIndices returns the local indices referenced by the
// given bytecode (deduplicated, in first-appearance order).
func extractReferencedLocalIndices(bc []byte) ([]int, error) {
	var out []int
	seen := make(map[int]struct{})
	err := walkBytecode(bc, func(_ uint16, isLocal bool, localIdxOffset int) error {
		if !isLocal {
			return nil
		}
		idx := int(bc[localIdxOffset])
		if _, ok := seen[idx]; !ok {
			seen[idx] = struct{}{}
			out = append(out, idx)
		}
		return nil
	})
	return out, err
}

// checkLocalScriptCycles runs three-color DFS over the intra-script call
// graph and returns an error naming the cycle if one is found.
func checkLocalScriptCycles[T any](scope *LocalScript[T], bytecodes [][]byte) error {
	const (
		colorWhite = 0
		colorGray  = 1
		colorBlack = 2
	)
	n := len(bytecodes)
	colors := make([]int, n)
	path := make([]string, 0, n)

	var dfs func(i int) error
	dfs = func(i int) error {
		switch colors[i] {
		case colorBlack:
			return nil
		case colorGray:
			cycle := append([]string(nil), path...)
			cycle = append(cycle, scope.funByFunCode[i].sym)
			return fmt.Errorf("local script: recursion: %s", strings.Join(cycle, " -> "))
		}
		colors[i] = colorGray
		path = append(path, scope.funByFunCode[i].sym)
		refs, err := extractReferencedLocalIndices(bytecodes[i])
		if err != nil {
			return fmt.Errorf("local script: walking bytecode of '%s': %v", scope.funByFunCode[i].sym, err)
		}
		for _, ref := range refs {
			if ref >= n {
				return fmt.Errorf("local script: invalid local reference #%d in '%s'", ref, scope.funByFunCode[i].sym)
			}
			if err := dfs(ref); err != nil {
				return err
			}
		}
		path = path[:len(path)-1]
		colors[i] = colorBlack
		return nil
	}

	for i := 0; i < n; i++ {
		if err := dfs(i); err != nil {
			return err
		}
	}
	return nil
}

// topologicalSortLocal returns intra-script indices in dependency-first order.
// Caller must run cycle detection first; if a cycle remains, this returns an
// error rather than producing a partial order.
func topologicalSortLocal(bytecodes [][]byte) ([]int, error) {
	n := len(bytecodes)
	revDeps := make([][]int, n)
	inDeg := make([]int, n)
	for i := 0; i < n; i++ {
		refs, err := extractReferencedLocalIndices(bytecodes[i])
		if err != nil {
			return nil, err
		}
		seen := make(map[int]struct{}, len(refs))
		for _, r := range refs {
			if r == i || r >= n {
				continue
			}
			if _, ok := seen[r]; ok {
				continue
			}
			seen[r] = struct{}{}
			revDeps[r] = append(revDeps[r], i)
			inDeg[i]++
		}
	}
	queue := make([]int, 0, n)
	for i := 0; i < n; i++ {
		if inDeg[i] == 0 {
			queue = append(queue, i)
		}
	}
	out := make([]int, 0, n)
	for len(queue) > 0 {
		i := queue[0]
		queue = queue[1:]
		out = append(out, i)
		for _, d := range revDeps[i] {
			inDeg[d]--
			if inDeg[d] == 0 {
				queue = append(queue, d)
			}
		}
	}
	if len(out) != n {
		return nil, fmt.Errorf("local script: cycle detected during topological sort")
	}
	return out, nil
}

