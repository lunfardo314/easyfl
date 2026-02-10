package easyfl

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// extractReferencedFunCodes walks bytecode linearly and returns all
// referenced global function codes (excluding parameter references and local calls).
// Bytecode is a preorder serialization, so a linear scan finds all call sites.
func extractReferencedFunCodes(bytecode []byte) ([]uint16, error) {
	var refs []uint16
	seen := make(map[uint16]struct{})
	pos := 0
	for pos < len(bytecode) {
		b := bytecode[pos]
		if b&FirstByteDataMask != 0 {
			// inline data
			if b == 0xff {
				if pos+3 > len(bytecode) {
					return nil, fmt.Errorf("extractReferencedFunCodes: unexpected end of bytecode at pos %d", pos)
				}
				dataLen := int(binary.BigEndian.Uint16(bytecode[pos+1 : pos+3]))
				pos += 3 + dataLen
			} else {
				dataLen := int(b & FirstByteShortDataLenMask)
				pos += 1 + dataLen
			}
		} else if b&FirstByteLongCallMask == 0 {
			// short call: 1 byte
			funCode := uint16(b)
			if funCode >= FirstEmbeddedShort {
				if _, ok := seen[funCode]; !ok {
					refs = append(refs, funCode)
					seen[funCode] = struct{}{}
				}
			}
			// parameter references (0..14) are not recorded
			pos++
		} else {
			// long call: 2+ bytes
			if pos+2 > len(bytecode) {
				return nil, fmt.Errorf("extractReferencedFunCodes: unexpected end of bytecode at pos %d", pos)
			}
			u16 := binary.BigEndian.Uint16(bytecode[pos : pos+2])
			funCode := u16 & Uint16LongCallCodeMask
			if funCode == FirstLocalFunCode {
				// local library call: 3 byte prefix, skip
				pos += 3
			} else {
				if _, ok := seen[funCode]; !ok {
					refs = append(refs, funCode)
					seen[funCode] = struct{}{}
				}
				pos += 2
			}
		}
	}
	return refs, nil
}

// checkForCycles performs DFS cycle detection starting from the given function codes.
// It traverses into all reachable extended functions. Embedded functions (funCode < FirstExtended)
// are leaf nodes and cannot participate in cycles.
func checkForCycles[T any](lib *Library[T], startFunCodes []uint16) error {
	const (
		colorWhite = 0 // unvisited
		colorGray  = 1 // on current DFS path
		colorBlack = 2 // fully explored
	)

	colors := make(map[uint16]int)
	path := make([]string, 0) // function names on current path, for error reporting

	var dfs func(fc uint16) error
	dfs = func(fc uint16) error {
		if fc < FirstExtended {
			return nil // embedded function: leaf node
		}
		switch colors[fc] {
		case colorBlack:
			return nil
		case colorGray:
			// cycle detected
			fd := lib.funByFunCode[fc]
			cycleName := fmt.Sprintf("%d", fc)
			if fd != nil {
				cycleName = fd.sym
			}
			path = append(path, cycleName)
			return fmt.Errorf("recursion detected in call graph: %s", strings.Join(path, " -> "))
		}

		fd := lib.funByFunCode[fc]
		if fd == nil || fd.bytecode == nil {
			// no bytecode: embedded or unresolvable, treat as leaf
			colors[fc] = colorBlack
			return nil
		}

		name := fd.sym
		colors[fc] = colorGray
		path = append(path, name)

		refs, err := extractReferencedFunCodes(fd.bytecode)
		if err != nil {
			return fmt.Errorf("checkForCycles: error extracting refs from '%s': %v", name, err)
		}
		for _, ref := range refs {
			if err := dfs(ref); err != nil {
				return err
			}
		}

		path = path[:len(path)-1]
		colors[fc] = colorBlack
		return nil
	}

	for _, fc := range startFunCodes {
		if err := dfs(fc); err != nil {
			return err
		}
	}
	return nil
}

// topologicalSortPartialOrder sorts funCodes so that dependencies come before dependents.
// Uses Kahn's algorithm (BFS-based topological sort) which correctly handles partial orders.
// The input must be acyclic (call checkForCycles first).
//
// NOTE: sort.Slice cannot be used here. A dependency graph defines a partial order, not a
// strict weak ordering. sort.Slice requires transitivity of incomparability: if A is
// incomparable with B, and B is incomparable with C, then A must be incomparable with C.
// Dependency graphs violate this: an unrelated function E can be incomparable with both
// a dependency D and its dependent F, while D < F. This causes sort.Slice to produce
// incorrect orderings where a function is placed before its own dependencies.
func topologicalSortPartialOrder[T any](lib *Library[T], funCodes []uint16) ([]uint16, error) {
	inSet := make(map[uint16]bool, len(funCodes))
	for _, fc := range funCodes {
		inSet[fc] = true
	}

	// Build direct dependency graph (only within the given set)
	// directDeps[fc] = set of functions that fc depends on (within batch)
	// dependents[fc] = set of functions that depend on fc (within batch)
	directDeps := make(map[uint16]map[uint16]bool, len(funCodes))
	dependents := make(map[uint16]map[uint16]bool, len(funCodes))
	inDegree := make(map[uint16]int, len(funCodes))

	for _, fc := range funCodes {
		directDeps[fc] = make(map[uint16]bool)
		dependents[fc] = make(map[uint16]bool)
	}

	for _, fc := range funCodes {
		fd := lib.funByFunCode[fc]
		if fd != nil && fd.bytecode != nil {
			refs, err := extractReferencedFunCodes(fd.bytecode)
			if err != nil {
				return nil, err
			}
			for _, ref := range refs {
				if inSet[ref] && ref != fc && !directDeps[fc][ref] {
					directDeps[fc][ref] = true
					dependents[ref][fc] = true
					inDegree[fc]++
				}
			}
		}
	}

	// Kahn's algorithm: start with nodes that have no in-batch dependencies
	var queue []uint16
	for _, fc := range funCodes {
		if inDegree[fc] == 0 {
			queue = append(queue, fc)
		}
	}

	var result []uint16
	for len(queue) > 0 {
		fc := queue[0]
		queue = queue[1:]
		result = append(result, fc)

		for dep := range dependents[fc] {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				queue = append(queue, dep)
			}
		}
	}

	if len(result) != len(funCodes) {
		return nil, fmt.Errorf("topological sort: cycle detected (processed %d of %d)", len(result), len(funCodes))
	}

	return result, nil
}
