package easyfl

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
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
//	    version[1]            // 0x01
//	    n[2]                  // BE uint16, number of functions, 0..256
//	    arity[n]              // 1 byte each, declared arity 0..15
//	    offsets[n*2]          // BE uint16, byte offset of each fn's bytecode within `body`
//	    bodyLen[2]            // BE uint16
//	    body[bodyLen]         // concatenated function bytecodes
//
// Header total: 5 + 3*n + 2 = 7 + 3*n bytes.
const (
	localScriptMagic0  = 0x45 // 'E'
	localScriptMagic1  = 0x53 // 'S'
	localScriptVersion = 0x01
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
// locals, references to globals flagged notInLocalScript, and over-arity
// definitions are rejected.
func (lib *Library[T]) CompileLocalScript(source string) (LocalScriptBin, error) {
	// ---- Phase 1: parse
	parsed, err := parseFunctions(source)
	if err != nil {
		return nil, err
	}
	if len(parsed) > MaxLocalScriptFunctions {
		return nil, fmt.Errorf("local script: too many functions: %d (max %d)", len(parsed), MaxLocalScriptFunctions)
	}
	seen := make(map[string]bool, len(parsed))
	for _, p := range parsed {
		if p.IsVararg {
			return nil, fmt.Errorf("local script: vararg local functions are not allowed (in '%s')", p.Sym)
		}
		if seen[p.Sym] {
			return nil, fmt.Errorf("local script: duplicate symbol '%s'", p.Sym)
		}
		seen[p.Sym] = true
	}

	// ---- Phase 2: introduce stubs in a fresh compile-time scope
	scope := &LocalScript[T]{
		funByName:    make(map[string]*funDescriptor[T], len(parsed)),
		funByFunCode: make([]*funDescriptor[T], 0, len(parsed)),
	}
	for i, p := range parsed {
		d := &funDescriptor[T]{
			sym:               p.Sym,
			funCode:           uint16(FirstLocalFunCode) + uint16(i),
			requiredNumParams: -1, // temporary; set in Phase 2.5
		}
		scope.funByName[p.Sym] = d
		scope.funByFunCode = append(scope.funByFunCode, d)
	}

	// ---- Phase 2.5: count params from source so #fnName references resolve
	for i, p := range parsed {
		n, err := countParametersFromSource(p.SourceCode)
		if err != nil {
			return nil, fmt.Errorf("local script: counting params for '%s': %v", p.Sym, err)
		}
		if n > MaxParameters {
			return nil, fmt.Errorf("local script: function '%s' has %d params, max %d", p.Sym, n, MaxParameters)
		}
		scope.funByFunCode[i].requiredNumParams = n
	}

	// ---- Phase 3: compile bodies to bytecode against the scope
	bytecodes := make([][]byte, len(parsed))
	for i, p := range parsed {
		src, err := preprocessSource(p.SourceCode)
		if err != nil {
			return nil, fmt.Errorf("local script: preprocess '%s': %v", p.Sym, err)
		}
		bc, n, err := lib.ExpressionSourceToBytecode(src, scope)
		if err != nil {
			return nil, fmt.Errorf("local script: compile '%s': %v", p.Sym, err)
		}
		if n != scope.funByFunCode[i].requiredNumParams {
			return nil, fmt.Errorf("local script: function '%s': declared %d params, body uses %d",
				p.Sym, scope.funByFunCode[i].requiredNumParams, n)
		}
		bytecodes[i] = bc
	}

	// ---- Phase 4: cycle detection on intra-script call graph
	if err := checkLocalScriptCycles(scope, bytecodes); err != nil {
		return nil, err
	}

	// ---- Phase 5: forbidden-funCode check (refs to globals flagged notInLocalScript)
	for i, bc := range bytecodes {
		if err := checkForbiddenGlobalRefs(lib, scope.funByFunCode[i].sym, bc); err != nil {
			return nil, err
		}
	}

	// ---- Phase 6: topological sort + encode in dependency order
	order, err := topologicalSortLocal(bytecodes)
	if err != nil {
		return nil, err
	}
	return encodeLocalScript(scope, bytecodes, order)
}

// LocalScriptFromBytes parses a LocalScriptBin into the executable form.
func (lib *Library[T]) LocalScriptFromBytes(bin LocalScriptBin) (*LocalScript[T], error) {
	arities, bodies, err := parseLocalScriptHeader(bin)
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
		}
		ret.funByName[sym] = d
		ret.funByFunCode = append(ret.funByFunCode, d)
	}

	// Defense-in-depth: forbidden-funCode check on every body.
	for i, bc := range bodies {
		if err := checkForbiddenGlobalRefs(lib, ret.funByFunCode[i].sym, bc); err != nil {
			return nil, err
		}
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

// Function returns the expression tree for function idx.
func (s *LocalScript[T]) Function(idx int) (*Expression[T], error) {
	if idx < 0 || idx >= len(s.expressions) {
		return nil, fmt.Errorf("local script: function index %d out of bounds (n=%d)", idx, len(s.expressions))
	}
	return s.expressions[idx], nil
}

// Eval evaluates function idx of the script with the given args, in the given
// data context. Returns the function's result as bytes, or an error (caught
// from any panic during evaluation).
func (s *LocalScript[T]) Eval(glb GlobalData[T], idx int, args ...[]byte) ([]byte, error) {
	expr, err := s.Function(idx)
	if err != nil {
		return nil, err
	}
	declared := s.funByFunCode[idx].requiredNumParams
	if declared >= 0 && declared != len(args) {
		return nil, fmt.Errorf("local script: function #%d expects %d args, got %d", idx, declared, len(args))
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

// === wire format ===

// parseLocalScriptHeader validates the wire format and returns the per-fn
// declared arities and per-fn bytecode slices (slices are views into bin).
func parseLocalScriptHeader(bin LocalScriptBin) ([]byte, [][]byte, error) {
	const fixed = 2 + 1 + 2 + 2 // magic + version + n + bodyLen
	if len(bin) < fixed {
		return nil, nil, fmt.Errorf("local script: truncated header")
	}
	if bin[0] != localScriptMagic0 || bin[1] != localScriptMagic1 {
		return nil, nil, fmt.Errorf("local script: bad magic")
	}
	if bin[2] != localScriptVersion {
		return nil, nil, fmt.Errorf("local script: unsupported version 0x%02x", bin[2])
	}
	n := int(binary.BigEndian.Uint16(bin[3:5]))
	if n > MaxLocalScriptFunctions {
		return nil, nil, fmt.Errorf("local script: too many functions: %d (max %d)", n, MaxLocalScriptFunctions)
	}
	headerLen := 5 + 3*n + 2
	if len(bin) < headerLen {
		return nil, nil, fmt.Errorf("local script: truncated header (need %d, got %d)", headerLen, len(bin))
	}
	arities := make([]byte, n)
	copy(arities, bin[5:5+n])
	for i, ar := range arities {
		if ar > MaxParameters {
			return nil, nil, fmt.Errorf("local script: function #%d has arity %d (max %d)", i, ar, MaxParameters)
		}
	}
	offsetsBase := 5 + n
	offsets := make([]int, n)
	for i := 0; i < n; i++ {
		offsets[i] = int(binary.BigEndian.Uint16(bin[offsetsBase+2*i : offsetsBase+2*i+2]))
	}
	bodyLen := int(binary.BigEndian.Uint16(bin[offsetsBase+2*n : offsetsBase+2*n+2]))
	if len(bin) != headerLen+bodyLen {
		return nil, nil, fmt.Errorf("local script: bad bodyLen (header says %d, total wire %d)", bodyLen, len(bin))
	}
	body := bin[headerLen:]
	bodies := make([][]byte, n)
	for i := 0; i < n; i++ {
		start := offsets[i]
		end := bodyLen
		if i+1 < n {
			end = offsets[i+1]
		}
		if start > end || end > bodyLen {
			return nil, nil, fmt.Errorf("local script: bad offsets at #%d (start=%d end=%d bodyLen=%d)",
				i, start, end, bodyLen)
		}
		bodies[i] = body[start:end]
	}
	return arities, bodies, nil
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

	headerLen := 5 + 3*n + 2
	out := make([]byte, headerLen+totalBody)
	out[0] = localScriptMagic0
	out[1] = localScriptMagic1
	out[2] = localScriptVersion
	binary.BigEndian.PutUint16(out[3:5], uint16(n))

	// arity[n] in NEW order
	for newIdx, oldIdx := range order {
		out[5+newIdx] = byte(scope.funByFunCode[oldIdx].requiredNumParams)
	}

	// offsets[n*2]
	offsetsBase := 5 + n
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

// checkForbiddenGlobalRefs walks bc and rejects any reference to a global
// function whose descriptor has notInLocalScript = true.
func checkForbiddenGlobalRefs[T any](lib *Library[T], sym string, bc []byte) error {
	return walkBytecode(bc, func(funCode uint16, isLocal bool, _ int) error {
		if isLocal {
			return nil
		}
		if funCode <= LastEmbeddedReserved {
			// parameter reference — not a function call
			return nil
		}
		fd, ok := lib.funByFunCode[funCode]
		if !ok {
			// unknown global: handled elsewhere; no opinion here
			return nil
		}
		if fd.notInLocalScript {
			return fmt.Errorf("local script: function '%s' is not allowed inside a local script (used in '%s')", fd.sym, sym)
		}
		return nil
	})
}
