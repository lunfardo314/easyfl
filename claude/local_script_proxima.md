# Local scripts — Proxima-side spec

> **Note.** This document is intended to migrate to the Proxima repo as
> part of adopting the easyfl local-script feature. It is parked here
> while the easyfl-side rewrite (`claude/local_script.md`) is in
> progress, since the two designs are co-developed.

## 1. Context

The easyfl library exposes only Go-level primitives for local scripts:
compile, decode, evaluate (see `claude/local_script.md`). It does *not*
expose hashing, caching, or any script-callable builtin for local
scripts. easyfl additionally provides one host hook:
`funDescriptor.notInLocalScript`, which lets the host mark global
functions as forbidden inside local-script bodies — easyfl's compiler
and decoder enforce the mark.

Anything tx-coupled — committing to a script in a transaction,
invoking a script from a script, caching compiled scripts across
transactions — is the host's responsibility. Proxima provides two
script-level builtins:

- `redeemScript(<bin>)` — a tx-level constraint that commits to a
  local script in the spending transaction.
- `callRedeemer(<hash>, <idx>, args…)` — an invocation that dispatches
  into a previously-redeemed script.

The two are coupled by:

- a **library-level** cache of compiled scripts (lives on the
  `*Library[T]`),
- a **tx-scoped** list of script-hash commitments redeemed in the
  current tx (lives on the per-tx evaluation context).

This design deliberately introduces *impure* per-tx state. That's a
real departure from strict functional tx semantics. Justification:
amortizing the hash-and-decode cost across many `callRedeemer`
invocations, and making covenant authoring straightforward. See §8.

## 2. State

### 2.1 Library-level compiled-script cache

A compiled local script depends on the global library that resolved its
funCodes — different libraries produce different `*easyfl.LocalScript[T]`
values for the same source. The cache therefore lives on the
`*easyfl.Library[T]` (or, equivalently, on a Proxima wrapper that owns
exactly one `*Library[T]`):

```go
type CompiledScriptCache interface {
    Get(hash [32]byte) (*easyfl.LocalScript[T], bool)
    Put(hash [32]byte, s *easyfl.LocalScript[T])
}
```

Default implementation: thread-safe, unbounded `sync.Map`-style cache
over the lifetime of the `*Library[T]`. Operators can swap in an LRU
or persistent cache.

**Eviction-during-tx safety.** A `callRedeemer` running inside a tx
needs the compiled form for its hash. If the library cache used a
small LRU, eviction between `redeemScript(bin)` and a later
`callRedeemer(hash,…)` could leave the call without a backing
script, even though the hash is in the tx-scope commitment list. Two
acceptable strategies:

- **Unbounded cache.** Default. Memory bound is the working set of
  unique scripts seen since process start.
- **Refcounted LRU.** The cache pins entries that have a non-zero
  per-tx refcount; `redeemScript` increments on entry, the tx context
  decrements at tx end. Only entries with refcount 0 are eligible for
  eviction.

The choice is purely an implementation detail of the cache impl;
neither `redeemScript` nor `callRedeemer` semantics depend on which
strategy is used.

Cache invariant: `cache[H] == s` ⇒ `blake2b(s.Bytes()) == H`. Holds
because every `Put` happens after `redeemScript` witnessed
`blake2b(bin) == H`.

### 2.2 Tx-scope commitment list

The per-tx evaluation context holds the list of script-hash
**commitments** redeemed in this tx — just hashes:

```go
type TxContext interface {
    // existing GlobalData[T] surface ...
    IsScriptRedeemed(h [32]byte) bool
    AddRedeemedScript(h [32]byte)
}
```

Lifetime: one transaction validation. Populated by `redeemScript`.
Read by `callRedeemer`. Cleared at tx end.

The compiled form lives in the library cache, not here. `callRedeemer`
fetches it from the cache after confirming the hash is in the
commitment list.

The list is the binding piece: presence in the tx commits the spender
to the script. If the spender's transaction did not redeem hash `H`,
no `callRedeemer(H,…)` succeeds — even if the library cache happens
to contain `H` from earlier transactions.

## 3. The `redeemScript(<bin>)` constraint

Signature: 1 argument, returns non-empty (truthy) on success.

Semantics:

1. Evaluate arg 0 → `bin` (bytes).
2. Compute `h = blake2b(bin)`.
3. If `lib.cache.Get(h)` hits, take that `*easyfl.LocalScript[T]`.
   Otherwise call `lib.LocalScriptFromBytes(bin)`; on success
   `lib.cache.Put(h, s)`. On failure, panic with the easyfl error
   wrapped in `"redeemScript: invalid script: %v"`.
4. `txContext.AddRedeemedScript(h)`.
5. Return non-empty (e.g. `0x01`) so the constraint is truthy.

Properties:

- Hashing: **once per tx, per unique script**.
- Decoding: **once per `*Library[T]`, per unique hash** (assuming
  the cache doesn't evict — see §2.1).
- Idempotent within a tx: redeeming the same hash twice is a no-op
  for the commitment list (a set), and the cache `Put` overwrites
  the same entry.
- The constraint is the *only* way for a hash to enter the tx-scope
  commitment list. There is no script-callable backdoor.

## 4. The `callRedeemer(<hash>, <idx>, args…)` builtin

Signature: vararg (`numArgs = -1`); the first two args are required.

Semantics:

1. Evaluate arg 0 → `h` (must be 32 bytes; otherwise panic
   `"callRedeemer: hash must be 32 bytes"`).
2. Evaluate arg 1 → `idxBytes` (must be exactly 1 byte; otherwise
   panic `"callRedeemer: idx must be 1 byte"`). Let
   `idx = int(idxBytes[0])`.
3. If `!txContext.IsScriptRedeemed(h)`, panic
   `"callRedeemer: script %x is not redeemed"`.
4. Look up `s = lib.cache.Get(h)`. With the eviction-safety
   strategy from §2.1 in force, this is guaranteed to hit. (If a
   non-default cache is configured and somehow misses, panic
   `"callRedeemer: compiled script %x missing from cache (cache
   misconfigured)"` — this is an operator error, not a script
   error.)
5. Bounds-check `idx` against `s.NumFunctions()`; out-of-range →
   panic.
6. Pass through args 2..N as the local fn's args. Return
   `s.Eval(glb, idx, evaluatedArgs…)`.

Properties:

- No hashing.
- No decoding.
- Library cache is consulted, but the **commitment list** is what
  authoritatively gates the call.

## 5. Compile-time ban on `callRedeemer` inside a local script

Enforced at the **easyfl** level, via the `notInLocalScript` flag on
the funDescriptor. Proxima sets the flag when it registers
`callRedeemer` (and `redeemScript`, which also has no business inside
a local script body). easyfl's compile and decode paths reject any
local-script bytecode that references a flagged funCode.

Where the flag is set:

- In Proxima's library-extension YAML, on the `callRedeemer` and
  `redeemScript` entries: `notInLocalScript: true`.
- Or, equivalently, in the Go code that registers them
  programmatically.

Proxima needs *no* compile wrapper. `easyfl.CompileLocalScript` is
the only entry; the ban is enforced by the easyfl compiler, given a
properly-flagged library.

Error message (from easyfl): `"local script: function 'callRedeemer'
is not allowed inside a local script"`.

Rationale (unchanged from previous drafts):

- **Static recursion bound = 2.** Global → 1 layer of local →
  embedded terminals.
- **No bundle-pair trampolines.**
- **Composability stays at the right layer.**
- **Cleaner cost model.**

If a future requirement breaks this assumption, lifting the
restriction is a localized change: drop `notInLocalScript: true` on
`callRedeemer` and add a depth counter on the tx context. Adding the
restriction later, after covenants in the wild rely on nesting, is
much harder.

## 6. Validation ordering

Happens naturally: Proxima's tx framework already evaluates tx-level
constraints **before** any UTXO unlocks. Since `redeemScript` is a
tx-level constraint and `callRedeemer` is invoked from UTXO unlock
scripts (and from extended global functions called by them), the
commitment list is already populated by the time any `callRedeemer`
runs.

No two-pass strategy or special slot ordering is needed.

## 7. Public Proxima API

```go
// per-tx context (extends easyfl.GlobalData[T])
type TxContext interface {
    // existing surface ...
    IsScriptRedeemed(h [32]byte) bool
    AddRedeemedScript(h [32]byte)
}

// library-level cache plumbing (defaults to unbounded)
type CompiledScriptCache interface {
    Get(hash [32]byte) (*easyfl.LocalScript[T], bool)
    Put(hash [32]byte, s *easyfl.LocalScript[T])
}
func (px *ProximaLib[T]) WithCompiledScriptCache(c CompiledScriptCache) *ProximaLib[T]
```

Script-callable builtins are wired through Proxima's library
extension. Both have `notInLocalScript: true` so easyfl rejects their
appearance inside any local script body.

## 8. Trade-off: this is impure on purpose

Strict functional tx semantics would require every script invocation
to carry, in its arguments, everything it needs — no implicit
per-tx state. With that model, `callRedeemer` would have to be passed
the script bytes directly and re-verify on every call.

We accept the impurity because:

1. **Performance.** Hashing 1 KB of bin with blake2b on every call
   is ~µs but adds up across hot paths (state-machine UTXOs that
   invoke the same script many times per tx). With the
   redeemed-set-of-hashes model, the hash runs once per tx per
   unique script.
2. **UX.** Covenant authors write the natural `callRedeemer(<hash>,
   idx, args…)` and don't need to thread the script bytes around.
3. **Determinism is preserved.** The "impurity" is bounded to a
   single tx evaluation. Within one tx, given the same inputs, the
   same constraints fire in the same order, populating the same
   commitment list, producing the same `callRedeemer` results.
4. **Auditability.** A covenant author reads the validator script
   and sees exactly which hashes it expects to be redeemed.
5. **Clean failure mode.** A `callRedeemer` for an un-redeemed hash
   fails loudly with `"script %x is not redeemed"`; no silent
   fallback.

What's *not* OK and is explicitly rejected:

- Letting `callRedeemer` *cause* a script to be redeemed implicitly
  (adding to the list as a side effect of a call). That would break
  the commit-then-invoke separation.
- Sharing the commitment list across transactions. Each tx starts
  with an empty list.
- Letting the library cache be consulted by `callRedeemer` to
  bypass the commitment list. The cache is purely a decode
  optimization for `redeemScript`; the commitment list is the
  binding.

## 9. Test plan (Proxima-side)

Lives in the Proxima repo when this doc moves there. Sketch:

**`redeemScript` semantics**
- Valid bin → success, hash present in tx commitment list, compiled
  form reachable through the library cache.
- Invalid bin (bad magic, bad offsets, …) → fail with wrapped
  easyfl error.
- Same script redeemed twice in one tx → second is a no-op on the
  commitment list.
- Cache: two transactions redeeming the same hash decode the
  script exactly once (instrumented test cache).
- Different transactions, different hashes → independent decodes.

**`callRedeemer` semantics**
- Happy path: `redeemScript(bin)` followed by `callRedeemer(hash,
  idx, args…)` returns expected bytes.
- `callRedeemer` for an un-redeemed hash → fail
  `"script %x is not redeemed"`.
- `hash` not 32 bytes → fail.
- `idx` not 1 byte → fail.
- `idx` out of range → fail.
- Wrong arity to a local fn → fail.
- Cross-input dispatch: tx with two inputs, each redeems a script,
  one validator calls into both.

**Compile-time ban**
- Local-script body referencing `callRedeemer` → easyfl compile
  error.
- Local-script body referencing `redeemScript` → easyfl compile
  error.
- Local-script body invoking another local fn via the 3-byte direct
  prefix → fine.

**Validation ordering**
- A constraint that uses `callRedeemer` resolves correctly as long
  as `redeemScript` runs first; verify by exercising the natural
  tx-level-before-UTXO order.

**Determinism**
- Replaying the same tx produces the same outputs and the same
  commitment list.

## 10. Phases (Proxima-side)

### Phase P1 — Plumbing
1. `TxContext.IsScriptRedeemed` / `AddRedeemedScript` on the per-tx
   `GlobalData[T]` impl.
2. Default `CompiledScriptCache` (unbounded) on the Proxima
   `*Library[T]` wrapper. Optional refcounted-LRU later.

### Phase P2 — Builtins
1. `redeemScript` constraint, with `notInLocalScript: true` in YAML.
2. `callRedeemer` builtin, with `notInLocalScript: true` in YAML.

### Phase P3 — Tests
The Proxima-side test plan above.

### Phase P4 — Covenant PoC
The covenant PoC promised in the original task. Likely shapes:

- *Predicate redeemer.* Validator script:
  `callRedeemer(<expected-hash>, 0)` invokes the redeemer's
  predicate function.
- *State-machine UTXO.* Output commits to a hash; the redeemer's
  bundle implements each transition; idx selects the transition.
- *Multi-input dispatch.* Multiple inputs each redeem their own
  script; a coordinating validator calls into all of them and
  combines the results.

## 11. Out of scope

- Cross-tx persistence of the commitment list (each tx starts
  empty).
- Caching at finer granularity than the script (no per-fn caching).
- Allowing `callRedeemer` inside a local script (see §5; revisit
  only with a concrete requirement).
- Letting the commitment list be modified by anything other than
  `redeemScript`.
- Sharing scripts between consensus nodes via the cache (cache is
  process-local; persistence is a separate concern handled outside
  this design).
