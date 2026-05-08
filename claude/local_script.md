# Local scripts — design & redesign spec (easyfl side)

## 1. Purpose & terminology

A *local script* is a self-contained, serialized bundle of EasyFL functions
that can be compiled, decoded into an executable form, and evaluated against
any `GlobalData[T]` context. The feature was previously called "local
library"; renamed to **local script** to avoid overload with the global
`Library[T]`.

**Scope of this document.** Only the easyfl side: pure-Go APIs for compile,
decode, and evaluate, plus a host-controlled hook that lets the global
library declare which of its functions cannot appear inside a local
script. There are *no* EasyFL script-callable builtins for local scripts
in this repo. The host (Proxima) provides the script-callable surface;
see `local_script_proxima.md` (a companion doc intended to migrate to
the Proxima repo).

## 2. Status

The current implementation (`local_library.go`, `local_lib_test.go`,
`evalCallLocalLibrary` in `library_embed.go`, the helpers in `eval.go`)
is pre-production and **not** yet used by Proxima. This spec drives a
ground-up redesign. **Backward compatibility is not a constraint**:
rename, re-shape and re-encode freely.

## 3. Properties the easyfl piece must guarantee

1. **Self-contained.** A script decodes and evaluates against the global
   `Library[T]` alone. No external symbols.
2. **Acyclic.** Calls inside a script form a DAG; recursion (direct or
   indirect) is rejected at compile time. Source order is **free** —
   function `a` may reference `b` defined later in the source.
3. **Deterministic compile.** Same source compiled against the same
   `*Library[T]` yields byte-equal output.
4. **No script-level invocation primitive at the easyfl level.** A
   script body has only one cross-fn mechanism: the existing 3-byte
   intra-script direct dispatch. Cross-script invocation is a host
   concern.
5. **Pure.** No global mutable state in easyfl. No caches, no
   tx-scoped sets, no hash registry — those belong to the host.
6. **Host-controlled exclusion.** The global library can declare that
   particular global functions are forbidden inside local scripts;
   easyfl's compiler and decoder enforce that.

## 4. Wire format (`LocalScriptBin`)

Replace the current `tuples.Tuple` envelope with a flat header:

```
LocalScriptBin :=
    magic[2]              // 0x45 0x53  ('ES' = "EasyFL Script")
    version[1]            // 0x01
    n[1]                  // number of functions, 0..255 → up to 256 fns
    arity[n]              // 1 byte each, declared arity 0..15
    offsets[n*2]          // big-endian uint16, byte offset of each fn's
                          //   bytecode within `body`
    bodyLen[2]            // big-endian uint16
    body[bodyLen]         // concatenated function bytecodes
```

### Why a flat header

- **Validation before compile.** The decoder bounds-checks `n`, every
  `offsets[i]`, `bodyLen` and the per-fn slice extents *before* it
  begins parsing any expression tree. Today a malformed script is
  detected only when `expressionFromBytecode` happens to fail.
- **Declared arity is preserved.** No more "infer arity from
  `max($N) + 1`".
- **Magic + version.** Lets us evolve the format unambiguously. The
  magic also makes a `LocalScriptBin` byte-distinguishable from raw
  bytecode or a `tuples.Tuple` blob, which matters for hosts that
  accept multiple binary kinds at the same input slot.
- **Single ownership of the bytes.** `LocalScriptBin` is just `[]byte`;
  the executable `*LocalScript[T]` keeps a reference, no copies.

### Capacity (single source of truth)

```go
const MaxLocalScriptFunctions = 256
```

All compile, decode and call paths must use this constant.

## 5. Compilation

Multi-phase pipeline modelled on the global `addExtendedBatch` (see
`recursion.md`). Source order is free: the DAG is enforced by explicit
cycle detection, not by ordering.

```go
func (lib *Library[T]) CompileLocalScript(source string) (LocalScriptBin, error)
```

### Phases

- **Phase 1 (parse).** `parseFunctions(source)` produces ordered
  `(sym, body, isVararg)` records. *Vararg local fns are rejected* —
  local call prefixes carry an explicit arity field, so vararg has no
  place here.
- **Phase 2 (introduce stubs).** Every fn is registered in a fresh
  compile-time `LocalScript[T]` table with `requiredNumParams = -1`,
  so any source can reference any other regardless of order.
- **Phase 2.5 (count params).** For each fn, run
  `countParametersFromSource` (already exists in `compiler.go`) to set
  `requiredNumParams`. Needed so that `#fnName` literals resolve with
  the right arity even in cross-references.
- **Phase 3 (compile to bytecode).** Each fn's source is compiled by
  `ExpressionSourceToBytecode(src, scriptScope)`. Parameter count
  returned by the compiler must match the count from Phase 2.5;
  mismatch → error.
- **Phase 4 (cycle detection).** A local-call extractor analogous to
  `extractReferencedFunCodes` (in `recursion.go`) walks each fn's
  bytecode, picking up the *local* indices behind every 3-byte
  `callPrefix == FirstLocalFunCode` site. DFS with three-color
  marking finds any cycle.
- **Phase 5 (forbidden-funCode check).** During the same scan as
  Phase 4, `extractReferencedFunCodes` is run over each fn's
  bytecode; for each global funCode referenced, look up the
  funDescriptor and reject if its `notInLocalScript` flag is set
  (§7). This is what enforces a host's "this builtin can't be used
  inside a local script" rule.
- **Phase 6 (encode).** Topologically sort by intra-script dependency
  (Kahn's, same as global `topologicalSortPartialOrder`) and serialize
  bytecodes in dependency order. The on-wire ordering is therefore
  topological, while the user's source order is free.

### Error vocabulary

All compile-time conditions return `error`. No `Assertf` on user input.
Standard messages:

- `local script: too many functions: %d (max %d)`
- `local script: duplicate symbol '%s'`
- `local script: function '%s' has %d params, max %d`
- `local script: vararg local functions are not allowed`
- `local script: recursion: %s -> ... -> %s`
- `local script: unknown symbol '%s'`
- `local script: function '%s' is not allowed inside a local script`

## 6. Decoder

```go
func (lib *Library[T]) LocalScriptFromBytes(bin LocalScriptBin) (*LocalScript[T], error)
```

Steps:

1. Validate magic + version.
2. Validate `n`, every `offsets[i]`, `bodyLen` and that each fn's slice
   stays inside `body`.
3. Walk each fn's bytecode and reject any reference to a flagged
   funCode (the same Phase-5 check as compile, applied at decode for
   defense in depth — a bin produced by some other tool can't sneak
   in a forbidden builtin).
4. Build expression trees for fn `0..n-1`, in order. Because the wire
   ordering is already topological (§5 Phase 6), each fn sees all its
   dependencies as already bound when its tree is constructed.
5. Populate `funByName` (`script#0`, `script#1`, …) and `funByFunCode`
   on the resulting `*LocalScript[T]`.
6. Store `bin` on the `*LocalScript[T]`.

## 7. Host-controlled exclusion of global functions

Global library functions can be marked **not callable from inside a
local script**. The mark is a per-funDescriptor flag carried alongside
`embeddedFun`, `embeddedAs`, etc.:

```go
type funDescriptor[T any] struct {
    // ... existing fields ...
    notInLocalScript bool
}
```

How a host sets it:

- **YAML.** A new boolean field on each function entry. Defaults to
  `false`. `ReadLibraryFromYAML` populates `funDescriptor.notInLocalScript`.
- **Programmatic.** The `embedShort` / `embedLong` APIs (and any
  successor used by hosts to register Go-implemented builtins) gain
  an option to set the flag, e.g. via a variadic option list or a
  small option struct. Concrete API choice deferred to implementation
  time; the requirement is that the flag can be set when registering
  a function.

What easyfl enforces:

- Phase 5 of compile (§5) and step 3 of decode (§6) reject any local
  script whose body references a flagged funCode.
- The flag is purely about *appearing inside a local script's
  bytecode*. Calls to flagged functions from global / extended fn
  bodies are unaffected.

The flag is the *only* way easyfl learns about host-specific bans;
easyfl itself does not name `callRedeemer` or anything similar.

## 8. Evaluation API

The executable form `*LocalScript[T]` is what easyfl hands to the host.
It is opaque except for these accessors:

```go
type LocalScript[T any] struct { /* opaque */ }

func (s *LocalScript[T]) Bytes()              LocalScriptBin
func (s *LocalScript[T]) NumFunctions()     int
func (s *LocalScript[T]) Arity(idx int)     (int, error)
func (s *LocalScript[T]) Function(idx int)  (*Expression[T], error)
func (s *LocalScript[T]) Eval(
    glb GlobalData[T], idx int, args ...[]byte,
) ([]byte, error)
```

`Eval` is a thin convenience wrapper around `EvalExpression(glb,
s.Function(idx), args...)`. It is the canonical entry point used by
both tests and the host.

There is **no** `Hash()` method, **no** `EvalLocalScriptCall(bin, hash,
idx, args)` form, and **no** `HashLocalScript` helper. Hashing is the
host's concern: if the host wants a cache key, it calls blake2b on the
bin itself.

## 9. Why no script-level builtins, no hashing, no cache

The previous spec drafts proposed an in-easyfl `callRedeemerBase` (or
`callLocalLibrary`) builtin plus a `redeem` constraint plus a
hash-keyed cache. All three have been moved out: every meaningful
operation on a local script — *committing to* a script in a
transaction, *invoking* a script from a script, *caching* compiled
scripts across transactions, *naming* the hash for those purposes —
fundamentally depends on transaction context, which easyfl has no
model of.

Pushing those concerns into easyfl forced ugly compromises:

- A script-callable verifier had to redo work the tx framework had
  already done, *or* a `redeem` constraint with a special arg-shape
  contract had to leak through easyfl.
- A cache in easyfl is global mutable state; even if hung off
  `*Library[T]` it has nothing to do with what easyfl actually does
  (compile / decode / evaluate).
- Hashing as a public API in easyfl would suggest easyfl owns the
  identity scheme, which it does not.

The clean split: easyfl is a pure language + library + compile-time
gate (the `notInLocalScript` flag). Hosts attach whatever
side-effecting machinery they need on top. easyfl just lets them.

## 10. API surface (final)

Public:

```go
// types
type LocalScriptBin []byte
type LocalScript[T any]                              // opaque executable

// compile / decode
func (lib *Library[T]) CompileLocalScript(source string) (LocalScriptBin, error)
func (lib *Library[T]) LocalScriptFromBytes(bin LocalScriptBin) (*LocalScript[T], error)

// methods on *LocalScript[T]
func (s *LocalScript[T]) Bytes()              LocalScriptBin
func (s *LocalScript[T]) NumFunctions()     int
func (s *LocalScript[T]) Arity(idx int)     (int, error)
func (s *LocalScript[T]) Function(idx int)  (*Expression[T], error)
func (s *LocalScript[T]) Eval(
    glb GlobalData[T], idx int, args ...[]byte,
) ([]byte, error)
```

Hooks for hosts:

- A boolean field `notInLocalScript` on each function entry in YAML.
- An option on the programmatic embed APIs to set the same flag.

Internal:

- `extractReferencedLocalIndices(bytecode []byte) []byte` — sister of
  `extractReferencedFunCodes` for the cycle detector.

Removed (no compatibility shims):

- `callLocalLibrary` script builtin and its evaluator.
- `CompileLocalLibraryToTuple`.
- `Library.CallLocalLibrary`.
- `Library.MustEvalFromLocalLibrary`, `Library.EvalFromLocalLibrary`.
- `Library.expressionFromLocalLibrary`.
- The `funIndex == 0` short-circuit.
- `lib#%d)` symbol typo (`library.go:569`).
- The `callLocalLibrary` entry in `library.yaml`.

## 11. File layout

| File | Contents |
| --- | --- |
| `local_script.go` *(rename of `local_library.go`)* | wire format constants, encoder, decoder, validator, `CompileLocalScript`, `LocalScript[T]`, cycle detector, intra-script index extractor, the forbidden-funCode check, `Eval` and accessors. |
| `library_embed.go` | drop the `evalCallLocalLibrary` binding. |
| `library.yaml` | remove the `callLocalLibrary` entry; add the `notInLocalScript` boolean field on function entries (defaulting to `false`). |
| `library_yaml.go` | parse the new `notInLocalScript` field into `funDescriptor`. |
| `eval.go` | drop all local-script helpers. |
| `local_script_test.go` *(rename of `local_lib_test.go`)* | the new pure-Go test suite (§13 Phase C). |

## 12. Phases

### Phase A — Wire format, compile, decode
1. Constants & types (§4).
2. Encoder + decoder + validator.
3. Multi-phase compile pipeline with cycle detection (§5).
4. The forbidden-funCode check, plumbed via a new `notInLocalScript`
   field on `funDescriptor`, exposed in YAML and on the embed APIs.

### Phase B — Executable form & evaluation
1. `*LocalScript[T]` accessors and `Eval`.
2. Allocation cleanup in the call setup (one varScope alloc per call,
   no per-call `slicepool.New`).
3. Remove obsolete script-builtin wiring from `library.yaml` and
   `library_embed.go`.

### Phase C — Tests (pure Go, no tx context)
A new `local_script_test.go` (replacing `local_lib_test.go`):

**Compile & wire format**
- Empty script round-trip.
- Single fn, no params / with params.
- Multi-fn with **non-topological** source order.
- Bad magic / bad version / truncated body / bad offsets — all
  rejected with the documented errors.
- 256 fns OK, 257 fns rejected.
- 15 params OK, 16 params rejected.
- Vararg local — rejected.

**Cycles & forward references**
- `a → b → a` direct recursion → rejected with cycle path in error.
- `a → b → c → a` indirect → rejected.
- Forward reference (`a` defined before `b` but calls `b`) — accepted.
- Diamond dependency — accepted.

**Forbidden-funCode flag**
- A test library is built with one extra extended function flagged
  `notInLocalScript`. A local script that references that function
  is rejected at compile and at decode.
- Same library, same function, used from a global / extended fn body
  — succeeds.

**Evaluation**
- Compile → decode → `Eval(glb, idx, args)` returns expected bytes
  for each fn.
- Out-of-bounds idx → error from `Function`/`Eval`.
- Wrong arity → error.
- Intra-script call from one local fn to another (3-byte prefix path)
  evaluated end-to-end.

**Decompile**
- `lib.DecompileBytecode` on a local-script bytecode (with a
  `*LocalScript[T]` in scope) produces sane source.

### Phase D — None at the easyfl level
The covenant PoC and any `redeemScript` / `callRedeemer` work happens
in the Proxima repo. See `local_script_proxima.md`.

## 13. Out of scope (easyfl side)

- Script-callable invocation primitives (`redeemScript`,
  `callRedeemer`, anything similar).
- Hashing API and any concept of script identity beyond byte-equality
  of bins.
- Caching of compiled `*LocalScript[T]` — pure-Go callers cache
  themselves; the host has its own cache.
- Tx-scoped state, paths, constraint indices, unlock parameters.
- Cross-script named imports.
- Runtime mutation of a `*LocalScript[T]` after decode.
- Allowing forward references across **separate** scripts (each
  script is self-contained).
