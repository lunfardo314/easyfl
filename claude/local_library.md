# Local libraries — design & redesign spec

## 1. Purpose

A *local library* is a self-contained, serialized bundle of EasyFL functions
that travels with input data (typically as a UTXO redeemer) and is invoked
dynamically from a global-library script. The feature is the basis for UTXO
programmability with redeemers: the spending transaction supplies the
bundle, and a global script dispatches into it.

## 2. Status of this document

The current implementation (`local_library.go`, `local_lib_test.go`,
`evalCallLocalLibrary` in `library_embed.go`, the helpers in `eval.go`) is
pre-production and **not** yet used by Proxima. This spec drives a
ground-up redesign. **Backward compatibility is not a constraint**: rename,
re-shape and re-encode freely.

## 3. Properties the design must guarantee

1. **Self-contained.** A bundle decodes and evaluates against the global
   library alone. No external symbols.
2. **Acyclic.** Calls inside a bundle form a DAG; recursion (direct or
   indirect) is rejected at compile time, exactly as for global extended
   functions. Source order is **free** — function `a` may reference `b`
   defined later in the source.
3. **Deterministic identity.** Every bundle has a canonical wire form and
   a fixed-size content hash (32-byte blake2b). The hash is the redeemer
   commitment.
4. **Commitment verification happens once per transaction.** Not per
   invocation. The tx-level constraint framework runs a `redeem(hash,
   bin)` script that performs the hash check; subsequent script-level
   invocations rely on this commitment having been established.
5. **Cacheable.** A `*LocalLibrary[T]` (the executable form) is built
   once per unique hash and reused for all invocations across the
   process lifetime.
6. **Bounded.** Bundle invocations cannot trigger unbounded stack growth
   or re-entrancy.
7. **Cheap intra-bundle dispatch.** A call from one local fn to another
   in the same bundle is a direct 3-byte prefix dispatch — not a
   recursive script-level invocation.
8. **easyfl stays pure.** The easyfl library knows nothing about
   transaction tree paths, unlock parameters, or constraint indices.
   Hosts (e.g. Proxima) wrap easyfl primitives with their own thin
   builtins that fetch bytes from the tx tree.

## 4. Wire format (`LocalLibraryBin`)

Replace the current `tuples.Tuple` envelope with a flat header:

```
LocalLibraryBin :=
    magic[2]              // 0x45 0x4C  ('EL')
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
  begins parsing any expression tree. Today a malformed bundle is
  detected only when `expressionFromBytecode` happens to fail.
- **Declared arity is preserved.** No more "infer arity from
  `max($N) + 1`".
- **Magic + version.** Lets us evolve the format unambiguously.
- **Single ownership of the bytes.** `LocalLibraryBin` is just `[]byte`;
  the executable `LocalLibrary[T]` keeps a reference, no copies.

### Capacity (single source of truth)

```go
const MaxLocalLibraryFunctions = 256
```

All compile, decode and call paths must use this constant.

## 5. Compilation

Compilation is a multi-phase pipeline modelled on the global
`addExtendedBatch` (see `recursion.md`). Source order is free: the DAG is
enforced by explicit cycle detection, not by ordering.

```go
func (lib *Library[T]) CompileLocalLibrary(source string) (LocalLibraryBin, error)
```

### Phases

- **Phase 1 (parse).** `parseFunctions(source)` produces ordered
  `(sym, body, isVararg)` records. *Vararg local fns are rejected* —
  local call prefixes carry an explicit arity field, so vararg has no
  place here.
- **Phase 2 (introduce stubs).** Every fn is registered in a fresh
  `LocalLibrary[T]` with `requiredNumParams = -1`, so any source can
  reference any other regardless of order.
- **Phase 2.5 (count params).** For each fn, run
  `countParametersFromSource` (already exists in `compiler.go`) to set
  `requiredNumParams`. Needed so that `#fnName` literals resolve with
  the right arity even in cross-references.
- **Phase 3 (compile to bytecode).** Each fn's source is compiled by
  `ExpressionSourceToBytecode(src, localLib)`. Parameter count returned
  by the compiler must match the count from Phase 2.5; mismatch →
  error.
- **Phase 4 (cycle detection).** A local-call extractor analogous to
  `extractReferencedFunCodes` (in `recursion.go`) walks each fn's
  bytecode, picking up the *local* indices behind every 3-byte
  `callPrefix == FirstLocalFunCode` site. DFS with three-color marking
  finds any cycle. Embedded / extended global calls do not need to be
  followed (they are guaranteed acyclic by the global library
  invariants).
- **Phase 5 (forbid script-level local-lib invocation inside a
  bundle).** During the same scan as Phase 4, reject any bundle whose
  body references the funCode of `callRedeemerBase` (or any future
  script-level local-lib invocation builtin). Rationale in §10.
- **Phase 6 (encode).** Topologically sort by intra-bundle dependency
  (Kahn's, same as global `topologicalSortPartialOrder`) and serialize
  bytecodes in dependency order. The on-wire ordering is therefore
  topological, while the user's source order is free.

### Error vocabulary

All compile-time conditions return `error`. No `Assertf` on user input.
Standard messages:

- `local library: too many functions: %d (max %d)`
- `local library: duplicate symbol '%s'`
- `local library: function '%s' has %d params, max %d`
- `local library: vararg local functions are not allowed`
- `local library: recursion: %s -> ... -> %s`
- `local library: 'callRedeemerBase' is not allowed inside a local function`
- `local library: unknown symbol '%s'`

## 6. The decoder

```go
func (lib *Library[T]) LocalLibraryFromBytes(bin LocalLibraryBin) (*LocalLibrary[T], error)
```

Steps:

1. Validate magic + version.
2. Validate `n`, every `offsets[i]`, `bodyLen` and that each fn's slice
   stays inside `body`.
3. Build expression trees for fn `0..n-1`, in order. Because the wire
   ordering is already topological (§5 Phase 6), each fn sees all its
   dependencies as already bound when its tree is constructed.
4. Populate **both** `funByName` (`lib#0`, `lib#1`, …) and
   `funByFunCode` on the resulting `*LocalLibrary[T]`. The current code
   leaves `funByName` empty after decode; that's a usability sharp
   edge and is removed.
5. Store `bin` (or just its hash) on the `*LocalLibrary[T]`.

## 7. Commitment & invocation

Three pieces, layered cleanly:

- `redeem(hash, bin)` — global-library function. Performs the
  blake2b-check. Lives at a tx-level constraint slot. Runs **once per
  transaction**.
- `callRedeemerBase(hash, redeemBytecode, idx, args…)` — pure-easyfl
  script builtin. Receives the bytecode of a `redeem(hash, bin)` call
  as bytes, parses it structurally, dispatches into the bundle.
  Performs no hashing.
- *(host-level, not in easyfl)* `callRedeemer(hash, constraintIdx,
  idx, args…)` — Proxima's thin wrapper. Fetches the constraint
  bytecode at `constraintIdx` and forwards to `callRedeemerBase`.
  `constraintIdx` typically comes from an unlock parameter in the
  consumed UTXO context.

The easyfl spec covers only `redeem` and `callRedeemerBase`. The
Proxima wrapper is sketched here only to make the layering clear.

### 7.1 The `redeem(hash, bin)` constraint

A new global-library function:

```
redeem(<32-byte-hash-literal>, <inline-data-bin-literal>) -> non-empty if valid
```

Semantics: `equal(blake2b(bin), hash)`. Both arguments **must be inline
data literals** in the bytecode (no sub-expressions). Enforced at
evaluation time:

- Argument 0 must be inline data, exactly 32 bytes — the committed
  hash.
- Argument 1 must be inline data — the bundle bytes.

`redeem` is placed in the spending transaction's constraint tree at a
known position. The transaction-validation framework evaluates all
constraints in the tree, so `redeem` runs **once per transaction**. If
it fails, the entire spend fails. If it succeeds, the bundle bytes at
that constraint are committed-to by the supplied hash for the rest of
the validation.

Why both args must be inline literals:

- `callRedeemerBase` (§7.2) extracts them by structural parsing,
  without evaluating any sub-expressions and without needing a
  GlobalData context.
- The committed hash and the bundle bytes are *facts* about the
  transaction, not values that the redeemer can dynamically vary at
  call time.

### 7.2 The `callRedeemerBase` builtin

The pure-easyfl script-callable primitive:

```
callRedeemerBase(<32-byte-hash>, <redeemBytecode>, <idx>, args…)   // numArgs = -1
```

Arguments:

- `hash` — the committed hash that the calling script expects (typically
  a 32-byte literal baked into a UTXO validator script).
- `redeemBytecode` — bytes that **must** decode as a `redeem(_, _)`
  call. Where these bytes come from is the host's concern: a Proxima
  wrapper fetches them from a tx-tree constraint slot; tests can pass
  them inline.
- `idx` — 1 byte, which function in the bundle to invoke.
- `args…` — pass-through arguments for the local fn.

Evaluation steps (no blake2b on the hot path):

1. Evaluate arg 0 → `expectedHash` (must be 32 bytes).
2. Evaluate arg 1 → `redeemBytecode`.
3. Structurally parse `redeemBytecode`:
   - The leading call prefix must be the call prefix of `redeem`. If
     not, panic: `"callRedeemerBase: not a redeem call"`.
   - Argument 0 of the call must be inline data, exactly 32 bytes;
     extract it as `committedHash`. If shape wrong, panic.
   - Argument 1 of the call must be inline data; extract it as `bin`.
     If shape wrong, panic.
4. Memcmp `committedHash` against `expectedHash`. Mismatch → panic
   `"callRedeemerBase: hash mismatch"`.
5. Look up `committedHash` in the cache.
   - Hit: use the cached `*LocalLibrary[T]`.
   - Miss: `LocalLibraryFromBytes(bin)` → `Put(committedHash, ll)`.
6. Dispatch into `ll[idx]` with `args…`.

Chain of trust:

- The tx framework evaluated `redeem(committedHash, bin)` at its known
  constraint slot, which performed `blake2b(bin) == committedHash`.
  (Once per tx.)
- `callRedeemerBase` does a structural memcmp confirming
  "the bytecode I was just handed is `redeem(expectedHash, _)`". The
  `expectedHash` is the script's baked-in commitment.
- The cache key is `committedHash`, which the structural check just
  proved equals `expectedHash`. So the cached library is the one whose
  bytes hashed to that key.

No blake2b is computed in this path. The structural check is a small
constant amount of work (parse one call prefix, confirm two
inline-data shapes, one 32-byte memcmp).

### 7.3 The Proxima wrapper (informative)

In Proxima's library extension the easyfl primitive is wrapped into a
thin host-level builtin:

```
callRedeemer(<hash>, <constraintIdx>, <idx>, args…) :=
    callRedeemerBase(<hash>, <fetchConstraintBytecode(constraintIdx)>, <idx>, args…)
```

`constraintIdx` typically comes from an unlock parameter in the
consumed UTXO context, which is what makes the binding flexible: the
spender chooses which slot of the spending transaction holds the
redeemer. `fetchConstraintBytecode` is whatever Proxima already uses
to read constraint bytes by index.

This is intentionally *not* part of easyfl: paths, indices and tx-tree
layout belong to the host.

### 7.4 The cache

A pluggable interface lives on `Library[T]`:

```go
type LocalLibraryCache[T any] interface {
    Get(LocalLibraryHash) (*LocalLibrary[T], bool)
    Put(LocalLibraryHash, *LocalLibrary[T])
}

func (lib *Library[T]) WithLocalLibraryCache(c LocalLibraryCache[T]) *Library[T]
```

Default: a thread-safe LRU (size configurable, e.g. 1024).

Cache invariant: `cache[H] == ll` ⇒ `ll` was produced by
`LocalLibraryFromBytes(bin)` for some `bin` with `blake2b(bin) == H`.
The invariant holds because every `Put` happens after the on-chain
`redeem` constraint witnessed `blake2b(bin) == H` and after the
structural check inside `callRedeemerBase` confirmed the binding.

### 7.5 Why this layering

Three concerns separated:

| Concern | Where | Cost |
| --- | --- | --- |
| Hash & commitment verification | `redeem(hash, bin)` constraint | One blake2b per tx |
| Identity binding (caller commits to hash H) | Script literal in caller + structural check in `callRedeemerBase` | One memcmp per call site |
| Decode (wire bytes → expression trees) | `LocalLibraryFromBytes`, cached by hash | One decode per unique bundle, process-wide |
| Dispatch | `callRedeemerBase` body + the local lib's expression eval | Per call |

Compared to "verify on every call":

- Hashing 1 KB with blake2b is ~µs but ≫ a memcmp.
- More importantly, the design **proves** commitment is verified — by
  the structure of the constraint tree — rather than relying on every
  caller remembering to verify. There is no script-level path that
  bypasses commitment.

## 8. Go-level surface

`callRedeemerBase` is the only script-level builtin for invoking a
local library. There is no script-callable `callLocalLibrary`. The Go
entry point exists for host code, tests, and benchmarks:

```go
func (lib *Library[T]) EvalLocalLibraryCall(
    glb GlobalData[T],
    bin LocalLibraryBin,
    hash LocalLibraryHash,    // expected hash, or zero to skip the check
    idx int,
    args ...[]byte,
) ([]byte, error)
```

If `hash` is non-zero, this entry point computes `blake2b(bin)` and
verifies it. If `hash` is zero, it computes the hash itself and uses
it as the cache key without verification (test-only use). It then
proceeds the same way as `callRedeemerBase` from step 5 onward.

Internal helper (not exposed):

```go
func (lib *Library[T]) evalLocalCall(
    ctx *evalContext[T],
    ll *LocalLibrary[T],
    idx int,
    args []*Expression[T],
) []byte
```

Used by both `EvalLocalLibraryCall` and `evalCallRedeemerBase` so the
dispatch logic exists in exactly one place.

## 9. Intra-bundle vs cross-bundle dispatch

Two distinct kinds of "calling a local function":

| Kind | Encoding | Cost | Allowed where |
| --- | --- | --- | --- |
| Intra-bundle | Direct 3-byte prefix `0x40\|arity<<2  0x03  0xFF  idx` | Inline dispatch | Anywhere — global script bodies *and* local fn bodies |
| Cross-bundle | `callRedeemerBase(hash, redeemBytecode, idx, …)` | One structural check + cache lookup + dispatch | **Only** in global / extended fn bodies; **forbidden** in local fn bodies |

The current implementation already supports the intra-bundle direct
prefix — `parseCallPrefix` handles it (`compiler.go:783-797`). The
redesign just makes the boundary explicit and rejects cross-bundle
calls from inside a bundle.

## 10. Why `callRedeemerBase` is forbidden inside a local function

Compile-time reject (Phase 5 of §5).

### Rationale

- **Static recursion bound = 2.** Global → 1 layer of local → embedded
  terminals. No depth counter, no re-entrancy detection, no stack
  guards. Simple cost-and-safety story for covenant authors.
- **No bundle-pair trampolines.** With a hash-keyed cache plus nested
  invocations, two bundles could volley calls between each other
  forever (or up to a depth limit). Forbidding the construct removes
  the entire class.
- **Composability stays at the right layer.** When two bundles need to
  cooperate, the *global* validator script chooses which bundle to
  dispatch into. Each invocation is a clean, top-level
  `callRedeemerBase`.
- **Cleaner cost model.** A covenant's worst-case cost is the global
  script's worst case plus, for each call site, one bundle dispatch.
  No multiplicative blow-up under attack.

### Considered alternative (rejected)

Allow `callRedeemerBase` inside a bundle, with a hard depth limit
(e.g. 4) on `evalContext`. Rejected because the bound is arbitrary,
adds a knob, complicates auditing, and an adversary always runs at
limit-1.

If a future requirement breaks this assumption, lifting the
restriction is a localized change. Adding it later, after covenants
in the wild rely on nesting, is much harder.

## 11. Safety beyond the recursion ban

- Wire-format validation (§6) before any expression-tree work.
- `MaxLocalLibraryFunctions = 256` enforced everywhere.
- `MaxParameters = 15` per local function (existing global cap).
- `redeem` arg-shape check: arg 0 must be inline data of exactly 32
  bytes; arg 1 must be inline data. Anything else → constraint
  evaluation fails.
- `callRedeemerBase` structural checks (§7.2 steps 3-4); any mismatch
  → panic with a documented message.
- Out-of-bounds idx → panic
  `"local library: function index %d out of bounds (n=%d)"`.

## 12. API surface (final)

Public:

```go
// types
type LocalLibraryBin  []byte                // the wire form (§4)
type LocalLibraryHash [32]byte
type LocalLibrary[T any]                    // executable form (opaque)

// hashing
func HashLocalLibrary(bin LocalLibraryBin) LocalLibraryHash

// compile / decode
func (lib *Library[T]) CompileLocalLibrary(source string) (LocalLibraryBin, error)
func (lib *Library[T]) LocalLibraryFromBytes(bin LocalLibraryBin) (*LocalLibrary[T], error)

// cache plumbing
type LocalLibraryCache[T any] interface { ... }
func (lib *Library[T]) WithLocalLibraryCache(c LocalLibraryCache[T]) *Library[T]

// Go-level eval entry point (host code, tests, benchmarks)
func (lib *Library[T]) EvalLocalLibraryCall(
    glb GlobalData[T], bin LocalLibraryBin, hash LocalLibraryHash,
    idx int, args ...[]byte,
) ([]byte, error)
```

Internal (lowercased):

- `evalRedeem` — embedded function bound to the `redeem` symbol
  (§7.1). Asserts arg shapes and returns `equal(blake2b(bin), hash)`.
- `evalCallRedeemerBase` — embedded function bound to the
  `callRedeemerBase` symbol (§7.2).
- `extractReferencedLocalIndices(bytecode []byte) []byte` — sister of
  `extractReferencedFunCodes` for the cycle detector.

Removed (no compatibility shims):

- `callLocalLibrary` (script-level builtin) — replaced by
  `callRedeemerBase`.
- `CompileLocalLibraryToTuple` — bundle bytes are the natural unit.
- `Library.CallLocalLibrary` — replaced by the Go-level
  `EvalLocalLibraryCall`.
- `Library.MustEvalFromLocalLibrary`, `Library.EvalFromLocalLibrary` —
  replaced by `EvalLocalLibraryCall`.
- `Library.expressionFromLocalLibrary` — folded into the decoder.
- The `funIndex == 0` short-circuit — gone.
- `lib#%d)` symbol typo (`library.go:569`) — gone.

## 13. File layout

| File | Contents |
| --- | --- |
| `local_library.go` | wire format constants, encoder, decoder, validator, `CompileLocalLibrary`, `LocalLibrary[T]`, hash, cycle detector, intra-bundle index extractor. |
| `local_library_eval.go` *(new)* | `EvalLocalLibraryCall`, the cache plumbing, `evalRedeem`, `evalCallRedeemerBase`, the shared dispatch helper. |
| `library_embed.go` | binds `redeem` and `callRedeemerBase` symbols to their embedded implementations. |
| `library.yaml` | adds `redeem` (numArgs = 2) and `callRedeemerBase` (numArgs = -1) entries; removes `callLocalLibrary`. |
| `eval.go` | no local-library helpers. |

## 14. Phases

### Phase A — Compile + decode + wire format
1. Constants & types (§4).
2. Encoder + decoder + validator.
3. Multi-phase compile pipeline with cycle detection (§5).
4. Phase-5 ban on `callRedeemerBase` inside a bundle.
5. Hashing.

### Phase B — `redeem`, `callRedeemerBase`, cache, Go-level eval
1. Default LRU `LocalLibraryCache[T]`.
2. Implement `evalRedeem` (arg-shape checks + blake2b).
3. Implement `evalCallRedeemerBase` (structural extraction + cache + dispatch).
4. `EvalLocalLibraryCall` Go entry point sharing the dispatch helper.
5. Allocation cleanup in the call setup.
6. Update `library.yaml` (add `redeem`, `callRedeemerBase`; remove
   `callLocalLibrary`).

### Phase C — Tests
A new `local_library_test.go` (replacing `local_lib_test.go`) covering:

**Compile & wire format**
- Empty bundle round-trip.
- Single fn, no params / with params.
- Multi-fn with **non-topological** source order — relies on the new
  pipeline.
- Bad magic / bad version / truncated body / bad offsets — all
  rejected with the documented errors.
- 256 fns OK, 257 fns rejected.
- 15 params OK, 16 params rejected.
- Vararg local — rejected.

**Cycles & forward references**
- `a → b → a` direct recursion → rejected.
- `a → b → c → a` indirect → rejected.
- Forward reference (`a` defined before `b` but calls `b`) — accepted.
- Diamond dependency — accepted.

**`callRedeemerBase` ban inside a bundle**
- Local fn body that calls `callRedeemerBase` → compile error.
- Global fn calling into the bundle works fine.

**`redeem` constraint**
- `redeem(<32 bytes>, <bin>)` succeeds when `blake2b(bin) ==` arg 0.
- `redeem` with a 31-byte arg 0 → fail.
- `redeem` with arg 0 not inline data → fail.
- `redeem` with arg 1 not inline data → fail.
- `redeem(<32 bytes>, <bin>)` with mismatched hash → fail.

**`callRedeemerBase` semantics**
- Happy path: pass an inline-literal `redeem(hash, bin)` bytecode and
  call. Returns the right value.
- `redeemBytecode` is not a `redeem(_,_)` call → panic
  `"callRedeemerBase: not a redeem call"`.
- `redeemBytecode` is `redeem(otherHash, _)` → panic
  `"callRedeemerBase: hash mismatch"`.
- `redeemBytecode`'s arg 0 is not inline data / wrong length → panic.
- `redeemBytecode`'s arg 1 is not inline data → panic.
- Cache: two consecutive `callRedeemerBase` calls on the same bundle
  decode it exactly once (instrumented test cache).
- Different bundles → independent cache entries.

**Eval semantics**
- Out-of-bounds idx → panic with the documented message.
- Wrong arity to a local fn → panic.
- Intra-bundle call from one local fn to another (3-byte prefix path).

**Trace + decompile**
- `lib.DecompileBytecode` of a global script using `callRedeemerBase`
  produces a sane source string.

**Bench**
- Cold vs warm `callRedeemerBase` invocation. Document the ratio.
- Intra-bundle dispatch vs `callRedeemerBase`-with-cache-hit.
  Document.

### Phase D — Covenant PoC
Stub awaiting requirements. Likely scenarios the design supports
cleanly:

- *Predicate redeemer.* A bundle whose fn 0 is the spending predicate;
  the validator script calls `callRedeemerBase(<expected hash>,
  <redeem bytecode>, 0, …)` (or its Proxima `callRedeemer` wrapper).
- *State-machine UTXO.* The output commits to a hash; the redeemer
  carries the bundle implementing each transition; idx selects the
  transition.
- *Multi-input dispatch.* Two inputs each carry a bundle; the global
  script invokes both via `callRedeemerBase` and combines results —
  composability lives at the global level, not nested inside a
  bundle.

## 15. Out of scope

- Allowing forward references across **separate** bundles (each bundle
  is self-contained).
- Cross-bundle named imports.
- Runtime mutation of a `*LocalLibrary[T]` after decode.
- Allowing `callRedeemerBase` inside a bundle (see §10; revisit only
  with a concrete requirement).
- Bundles whose bytes are produced by a sub-expression of `redeem`
  rather than supplied as an inline-data literal (see §7.1).
- Anything related to tx-tree paths, constraint indices, or unlock
  parameters — those are host concerns; see §7.3 for how Proxima
  wraps.
