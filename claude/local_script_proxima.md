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
`LocalScriptCallSiteCheck` — a per-call-site validation callback fired
by `CompileLocalScriptWithCheck` and `LocalScriptFromBytesWithCheck` on
every non-trivial call expression in the body (skipping inline-data
literals and `$0..$14` parameter references). The host (Proxima)
supplies the callback; easyfl just walks the calls and lets the host
accept or reject each one. This is the mechanism that pins call-site
shape rules (e.g. "first arg of `callRedeemer` must be a 32-byte
literal") into local-script bytecode at compile and at decode.

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

Signature: 1 argument, returns non-empty (truthy) on success. The
argument **must** be inline-data (compile-time enforced — see §5);
formula args are rejected.

Semantics:

1. Read arg 0 → `bin` (the literal script bytes). No evaluation is
   needed: the inline-data rule guarantees `bin` is the constant
   payload of the call site.
2. Compute `h = blake2b(bin)`.
3. If `lib.cache.Get(h)` hits, take that `*easyfl.LocalScript[T]`.
   Otherwise call `lib.LocalScriptFromBytesWithCheck(bin, hostCheck)`;
   on success `lib.cache.Put(h, s)`. On failure, panic with the
   easyfl error wrapped in `"redeemScript: invalid script: %v"`.
   `hostCheck` is the same `LocalScriptCallSiteCheck` Proxima uses at
   compile time (§5), re-run at decode for defense in depth.
4. `txContext.AddRedeemedScript(h)`.
5. Return non-empty (e.g. `0x01`) so the constraint is truthy.

Properties:

- Hashing: **once per tx, per unique script**.
- Decoding: **once per `*Library[T]`, per unique hash** (assuming
  the cache doesn't evict — see §2.1).
- Idempotent within a tx: redeeming the same hash twice is a no-op
  for the commitment list (a set), and the cache `Put` overwrites
  the same entry.
- **First arg is inline-data only.** Together with the call-site
  hook (§5) this guarantees that the constraint is the *only* way
  for a hash to enter the tx-scope commitment list, and that the
  set of committed scripts is statically readable from the spending
  tx's bytecode. There is no script-callable backdoor: a runtime-
  computed `bin` would let any caller inject arbitrary scripts into
  the commitment list (even from inside a redeemed script's body),
  which the inline-data rule rules out.

## 4. The `callRedeemer(<hash>, <idx>, args…)` builtin

Signature: vararg (`numArgs = -1`); the first two args are required.
`<hash>` **must** be inline-data (compile-time enforced — see §5);
formula args are rejected.

Semantics:

1. Read arg 0 → `h` (the literal hash bytes). The inline-data rule
   makes runtime size validation unnecessary — a non-32-byte literal
   is rejected at compile time by the call-site hook, and even if a
   shorter or longer literal slipped through it would simply miss
   the commitment list (which only ever contains 32-byte hashes).
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
- **First arg is inline-data only.** The dispatch graph is therefore
  statically visible: a reader of any script bytecode can enumerate
  exactly which hashes it can call into. A formula hash would let
  the unlock pick among the redeemed set at runtime based on
  witness data — pinning the literal removes that.

## 5. Compile-time call-site validation via the easyfl hook

`callRedeemer` and `redeemScript` are registered as ordinary global
builtins. There is no `notInLocalScript` flag (it was removed from
easyfl: composition across local scripts via `callRedeemer` is
**recursion-free by construction** — a hash exists only after the
callee binary is finalized, so the dependency graph between binaries
is a DAG, the same way function references inside the global library
are a DAG). The chess covenant pattern (`chessValidator` /
`chessGame`) relies on a local script *being able* to call into
another local script; a blanket ban would have killed it.

What Proxima still needs to enforce — call-site shape, not call-site
existence — lives in a `LocalScriptCallSiteCheck` that easyfl runs at
compile and at decode of every local script.

### 5.1 What the host check enforces

For each non-trivial call expression in a local-script body:

- **`callRedeemer(<hash>, <fnIdx>, args…)`**
  1. `arg[0].IsInlineData() && len(arg[0].InlineData()) == 32` —
     the hash is a 32-byte literal, statically visible in the
     bytecode.
  2. *(Optional, with a pinned import set.)* The literal is in the
     covenant author's declared import set. Then `arg[1]` (the
     `fnIdx` byte) can be range-checked against the pinned binary's
     `NumFunctions()` and the forwarded-arg count against its
     `Arity(fnIdx)`. This is not a safety check — it's a typo-catch
     that promotes "unknown hash rejected at execution time" to
     "unknown hash rejected at compile time" and makes the import
     set visible to readers of the source.

- **`redeemScript(<bin>)`**
  1. `arg[0].IsInlineData()` — the script bytes are a literal.

`redeemScript` is a tx-level constraint and doesn't normally appear
inside a local script body, but enforcing the inline-data rule here
too is defense in depth: a redeemed script body must not be able to
call `redeemScript(<formula>)` and inject runtime-computed scripts
into the commitment list.

### 5.2 Where the hook is attached

- **Local scripts.** Compiled via
  `lib.CompileLocalScriptWithCheck(source, hostCheck)` and decoded via
  `lib.LocalScriptFromBytesWithCheck(bin, hostCheck)`. Any binary
  passing through Proxima's host code uses the `*WithCheck` entry
  points; bare `CompileLocalScript` / `LocalScriptFromBytes` are
  reserved for pure-easyfl tests and tooling.
- **Extended / constraint scripts.** These are not local scripts and
  the hook above does not fire on them. The same inline-data rule on
  `redeemScript` and `callRedeemer` must therefore be re-enforced in
  Proxima's compile pipeline for ordinary expressions — a small
  post-compile bytecode walk (or wrapper around easyfl's expression
  compiler) that rejects any non-literal first arg to either builtin.

### 5.3 Why inline-data is the load-bearing rule

`redeemScript` and `callRedeemer` are the two ends of the
commit-then-invoke separation (§3, §4). Allowing a formula in either
position breaks it:

- **`redeemScript(<formula>)` would let any caller commit a
  *runtime-computed* script.** A static reader of the spending tx
  could not enumerate which scripts the tx commits to; the
  commitment list would be determined only after the formula
  evaluates, possibly steered by witness data. Auditability gone.
- **`callRedeemer(<formula>, …)` would let an unlock pick among the
  redeemed set at runtime.** Even with the commitment list pinned,
  a dynamic hash arg drags tx-context state into the dispatch
  decision. Pinning the literal keeps the dispatch graph statically
  visible.

In both cases, the inline-data rule is what makes "the commitment
list is the exact set of scripts the spender vouches for, and the
dispatch graph between them is statically visible" an auditable
property of any tx, instead of a runtime accident.

### 5.4 Static recursion bound

With cross-script recursion ruled out by content-addressable
identity, the static depth bound is whatever the import-set DAG
admits. `chessValidator → chessGame → tournamentRedeemer → …` is
allowed up to whatever depth covenant authors choose to compile.
Each binary is type/arity-checked against the binaries it pins
(when a pinned import set is declared), so depth is not a
soundness issue.

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

// host-supplied call-site check, passed to easyfl's
// CompileLocalScriptWithCheck / LocalScriptFromBytesWithCheck.
func (px *ProximaLib[T]) LocalScriptCheck() easyfl.LocalScriptCallSiteCheck[T]
```

`LocalScriptCheck` returns the default Proxima check that enforces the
rules in §5.1 (inline-data on `callRedeemer`'s hash and on
`redeemScript`'s bin). Covenant authors who want a *pinned* import
set can compose the default with their own per-script check.

Script-callable builtins are wired through Proxima's library
extension as ordinary globals — no special flags. The inline-data
rule is enforced by the call-site check above (inside local scripts)
and by Proxima's expression-compile pipeline (everywhere else); see
§5.2.

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
- `idx` not 1 byte → fail.
- `idx` out of range → fail.
- Wrong arity to a local fn → fail.
- Cross-input dispatch: tx with two inputs, each redeems a script,
  one validator calls into both.

**Call-site hook enforcement (replaces the old compile-time ban)**
- Local-script body with `callRedeemer(<formula>, …)` → rejected at
  `CompileLocalScriptWithCheck`.
- Local-script body with `callRedeemer(<literal-of-wrong-size>, …)`
  → rejected.
- Local-script body with `callRedeemer(<literal>, …)` where the
  literal is in the pinned import set → accepted; out-of-range
  `fnIdx` and arity mismatches against the pinned binary →
  rejected.
- Local-script body with `redeemScript(<formula>)` → rejected
  (defense-in-depth even though it shouldn't appear here).
- Cross-script composition (`chessValidator` ← `chessGame` pattern):
  a local script that calls another local script via `callRedeemer`
  with a literal hash → accepted, evaluates correctly through the
  commit-then-invoke pipeline.
- Decode-time revalidation: a binary compiled against pinned set A
  decoded via `LocalScriptFromBytesWithCheck` against pinned set B
  → rejected if any call site falls outside B.
- Constraint script (not a local script) with
  `redeemScript(<formula>)` or `callRedeemer(<formula>, …)` →
  rejected by Proxima's expression-compile wrapper.

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
1. `redeemScript` constraint registered as an ordinary global; bin
   arg uses `lib.LocalScriptFromBytesWithCheck(bin, hostCheck)`
   under the hood.
2. `callRedeemer` builtin registered as an ordinary global.
3. `LocalScriptCallSiteCheck` (the `hostCheck` above) implementing
   §5.1: inline-data on the hash arg of `callRedeemer` and the bin
   arg of `redeemScript`, plus optional pinned-import-set
   range/arity checks.
4. Expression-compile wrapper for non-local-script easyfl
   expressions that re-applies the inline-data rule (§5.2).

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
- Allowing a *formula* in `redeemScript`'s bin arg or `callRedeemer`'s
  hash arg — both are inline-data only by design (§5.3); revisit only
  with a concrete requirement that demonstrably preserves the
  static-commitment / static-dispatch property.
- Letting the commitment list be modified by anything other than
  `redeemScript`.
- Sharing scripts between consensus nodes via the cache (cache is
  process-local; persistence is a separate concern handled outside
  this design).
