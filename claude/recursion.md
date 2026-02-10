# Recursion prevention in extended functions

## Requirement
Extended EasyFL functions are defined as open EasyFL functions.
It is crucial to prevent recursive calls directly or indirectly.
I.e. call tree of any function call must end at embedded functions as terminals

## Previous solution
Previously, recursion was prevented by ensuring that function codes (opcodes) in the function definition must be strongly smaller
than the opcode of the calling function.

It was implemented so that when adding extended functions to the library, opcodes of the added function are increasing and called
functions must already exist in the library.

### The problem
That implementation made it impossible to upgrade existing extended function with new formula that uses new functions.
This was a big limitation to the upgradability of the library.

## Implemented solution

### Overview
The `Upgrade()` method in `serde_tools.go` was restructured into a multi-phase process that:
- Eliminates ordering constraints between functions in an upgrade batch
- Allows forward references (function A can call function D even if D is listed after A in the YAML)
- Explicitly checks for recursion via call graph analysis (DFS cycle detection)

### Multi-phase `Upgrade()` architecture
- **Phase 0**: Embedded functions are processed immediately (they are leaf nodes with Go implementations, no EasyFL dependencies)
- **Phase 1 (Introduction)**: Stub descriptors are registered for all new/replaced extended functions with `requiredNumParams = -1` (temporary vararg). This makes all function names resolvable without requiring a specific ordering.
- **Phase 2 (Bytecode generation)**: All pending functions are compiled to bytecode via `ExpressionSourceToBytecode()`. Source is preprocessed via `preprocessSource()`. Actual `numParams` is determined from compilation and set on the descriptors. For replaced functions, `numParams` must match the original (backward compatibility).
- **Phase 3 (Validation)**: `checkForCycles()` performs DFS with three-color marking (white/gray/black) starting from all involved function codes. It traverses into all reachable extended functions (not just the batch), since cycles can span existing functions. Embedded functions (`funCode < FirstExtended`) are leaf nodes.
- **Phase 4 (Bind)**: `topologicalSortPartialOrder()` sorts the pending functions using `sort.Slice` with a partial order predicate based on transitive dependency closure. Functions are then compiled to expression trees via `ExpressionFromBytecode()` in dependency-first order, ensuring each function's dependencies already have their `embeddedFun` set.

### Clone() for safe upgrades
`Library.Clone()` creates a deep copy of the library with hash verification. The safe upgrade pattern is:
```go
clone := lib.Clone()
if err := clone.Upgrade(fromYAML, ...); err != nil {
    // discard clone, original is untouched
    return err
}
lib = clone // adopt the upgraded library
```
No rollback logic is needed inside `Upgrade()`.

### Shared batch-add logic (`addExtendedBatch`)
The multi-phase logic (phases 1-4) was extracted from `Upgrade()` into a shared `addExtendedBatch()` method on `Library[T]`. Both `Upgrade()` and `ExtendMany()` now use this same code path:

- **`Upgrade()`** retains Phase 0 (embedded function processing + replace/existence validation), then delegates extended functions to `addExtendedBatch()`.
- **`ExtendMany()`** validates no duplicate/existing names, builds a `[]pendingExtendedFunc` slice from parsed source, and calls `addExtendedBatch()`. This gives `ExtendMany` forward-reference support and cycle detection — previously it required dependency order (no forward references).

The `pendingExtendedFunc` struct and `addExtendedBatch()` method live in `library.go`. Error messages from `addExtendedBatch` use neutral wording; callers wrap with their own context prefix (e.g. `"Upgrade: "`, `"ExtendMany: "`).

The previously unused `replaceExtended()` method was removed — its functionality is subsumed by `addExtendedBatch` with `isReplace=true`.

### Staged update API (`IntroduceUpdateYAML`, `IntroduceUpdateMany`, `CommitUpdate`)
A staged API allows accumulating functions from multiple sources (YAML + plain EasyFL code) into a single batch before resolving. This enables cross-source forward references and a single cycle check across all sources.

**`Library[T].pendingBatch`** (`types.go`): A `[]pendingExtendedFunc` field on the library struct serves as the staging area.

**`IntroduceUpdateYAML(fromYAML, embed...)`** (`serde_tools.go`):
- Sets `VersionData` if non-empty
- For each YAML function: validates replace/existence against both the library and `pendingBatch`
- Embedded functions (`EmbeddedAs != ""`): processed immediately (embedShort/embedLong/replaceEmbedded + immutable flag)
- Extended functions: appended to `lib.pendingBatch`

**`IntroduceUpdateMany(source)`** (`library.go`):
- Parses with `parseFunctions(source)`
- Validates no duplicates within the call, against the library, and against `pendingBatch`
- Appends all parsed functions to `lib.pendingBatch`

**`CommitUpdate()`** (`library.go`):
- Calls `lib.addExtendedBatch(lib.pendingBatch)`
- Clears `lib.pendingBatch` (on both success and error)
- Returns `nil` when `pendingBatch` is empty

**Rewritten callers:**
- `Upgrade()` is now `IntroduceUpdateYAML` + `CommitUpdate`
- `ExtendMany()` is now `IntroduceUpdateMany` + `CommitUpdate`

**Variadic versions:**
- `IntroduceUpdateYAMLMulti(embed func(sym string) EmbeddedFunction[T], fromYAMLs ...*LibraryFromYAML)` (`serde_tools.go`) — processes multiple YAML definitions sequentially into the same pendingBatch. `embed` resolver may be nil when no embedded functions need resolving.
- `IntroduceUpdateManyMulti(sources ...string)` (`library.go`) — processes multiple EasyFL source strings sequentially into the same pendingBatch. No resolver needed since plain EasyFL source only defines extended functions.

**`Clone()`** asserts that `pendingBatch` is empty — cloning mid-update is not supported.

**Helper: `isPendingSym(sym)`** scans `lib.pendingBatch` for a matching symbol. Used by both introduce methods to detect cross-batch duplicates.

### Key files
- `recursion.go` — `extractReferencedFunCodes()` (bytecode walker), `checkForCycles()` (DFS cycle detection), `topologicalSortPartialOrder()` (sort.Slice with partial order)
- `library.go` — `pendingExtendedFunc` struct, `addExtendedBatch()` (shared multi-phase logic), `isPendingSym()`, `IntroduceUpdateMany()`, `CommitUpdate()`, `Clone()` method, rewritten `ExtendMany()`
- `compiler.go` — `preprocessSource()` helper (strips comments and whitespace)
- `serde_tools.go` — `IntroduceUpdateYAML()`, simplified `Upgrade()` as introduce+commit
- `recursion_test.go` — tests for forward references, self/mutual/indirect recursion detection, replace-induced cycles, diamond dependencies, clone correctness, backward compatibility, `ExtendMany` forward references and cycle detection, cross-source forward references, cross-source cycles, cross-batch duplicate detection, empty commit

### Key design decisions
- **Temporary vararg stubs**: During Phase 1, stubs use `requiredNumParams = -1` so `ExpressionSourceToBytecode` doesn't fail on arity checks. Actual arity validation happens in Phase 4 when `ExpressionFromBytecode` checks the call prefix arity against the now-correct `numParams`.
- **Topological sort via `sort.Slice`**: Transitive dependency closure is computed, then used as the `less` predicate. This is a strict weak ordering on the DAG.
- **Bytecode is a preorder serialization**: A linear scan of bytecode extracts all function call sites without recursive tree traversal.

## Remaining goals
- Incorporate these changes in the `proxima` repo where `easyfl` is a dependency
