# EasyFL — TinyGo / WASM Compatibility Analysis

## Goal

Compile a **subset** of EasyFL to WebAssembly via TinyGo so it can run in browsers
and other environments without the full Go runtime. Full functionality
(YAML serde, crypto embedded functions, optimized allocators) remains available
only for the **Proxima backend** build, which keeps using the standard Go toolchain.

## Scope decisions (input to planning)

| Concern | WASM subset | Proxima backend |
|---|---|---|
| Source compiler / bytecode evaluator | required | required |
| YAML library serde (`gopkg.in/yaml.v3`) | **dropped** | kept |
| Crypto embedded fns (`blake2b`, `ed25519`) | **moved out** to host (Proxima) | provided by Proxima |
| `slicepool` optimized allocator | **simplified** to pure `make`/`append` | kept |
| `reflect` (one isolated call) | **removed** | n/a (also removed) |

## Audit findings

### Blockers (under TinyGo)

#### B1. `gopkg.in/yaml.v3` — `serde_tools.go:15`

Used by `yaml.Unmarshal(data, &fromYAML)` at `serde_tools.go:278` and by the
struct tags on `LibraryFromYAML` / `FuncDescriptorYAMLAble`. The library relies
heavily on `reflect` for struct-tag-driven unmarshal; TinyGo's `reflect` cannot
handle this and the package may not compile at all.

Affected surface in `serde_tools.go`:

- `LibraryFromYAML`, `FuncDescriptorYAMLAble` (types)
- `(*Library).ToYAML()` (line 121) — writes a YAML representation
- `ReadLibraryFromYAML([]byte)` (line 276) — parses YAML
- `(*Library).introduceFromParsedYAML(...)` (line 287)
- `(*Library).IntroduceUpdateYAML(...)` (line 360)
- `(*Library).IntroduceUpdateYAMLMulti(...)` (line 371)
- `(*Library).Upgrade(...)` (line 397) — takes `*LibraryFromYAML`
- `(*Library).UpgradeFromYAML(...)` (line 407)
- `ValidateCompiled[T]` (line 415)

#### B2. `reflect` — `library_embed.go:10, 93`

Single isolated use:

```go
func isNil(p interface{}) bool {
    return p == nil || (reflect.ValueOf(p).Kind() == reflect.Ptr && reflect.ValueOf(p).IsNil())
}
```

Trivial to replace. Used only to guard typed-nil `GlobalData[T]` values.

#### B3. Crypto embedded functions — `library_embed.go`

Two embedded functions hardcoded into the core embedded-function table at
`library_embed.go:62-63`:

```go
"evalValidSignatureED25519": evalValidSigED25519[T],   // line 422-435
"evalBlake2b":               evalBlake2b[T],            // line 437-445
```

Imports at `library_embed.go:5, 15`:

```go
"crypto/ed25519"
"golang.org/x/crypto/blake2b"
```

These will move out of core. The embedded-function lookup is already pluggable
(`EmbeddedFunctions[T]` returns a `func(sym string) EmbeddedFunction[T]`), so
extracting them is mostly mechanical.

Also: `serde_tools.go:49` uses `blake2b.Sum256` for `LibraryHash()`. Since the
library hash is part of YAML serde validation (also being dropped from WASM),
this comes out together.

### Risks (compile under TinyGo but worth attention)

#### R1. `sync.Pool` / `sync.Mutex` / `sync.RWMutex`

- `eval.go:52-53` — `callPool`, `varScopePool` (per-arity pool of `[]*call[T]`)
- `types.go:112-113` — `expressionArrayPool`, `expressionPool`
- `slicepool/slicepool.go` — entire pool implementation
- `tuples/tree.go:20` — `subtreeMutex sync.RWMutex` (lazy subtree deserialization)

Under TinyGo / single-threaded WASM these are stubs / no-ops. Code is correct
but pools provide no reuse — net cost is allocation churn plus a tiny code-size
overhead. Per scope decision, slicepool simplifies to direct allocation; the
other `sync.Pool` sites in `eval.go` and `types.go` should be treated the same.

#### R2. `fmt` usage

Heavy in `compiler.go`, `eval.go`, `recursion.go`, `trace.go`, embedded
function error reporting via `par.TracePanic(...)`. Works under TinyGo but adds
significant binary size to WASM output (likely the dominant size contributor
once YAML and crypto are gone).

Mitigation options (deferred): swap `fmt.Errorf` for static error strings on
hot paths; conditionally compile out `Trace` formatting on WASM builds.

#### R3. Pure-Go crypto under TinyGo (only relevant if we *kept* it)

Not a concern given the scope decision to move crypto out, but for reference:
`golang.org/x/crypto/blake2b` and `crypto/ed25519` should work under TinyGo
0.31+ but need verification; blake2b has an asm fast path that TinyGo bypasses.

### Clean — no concerns

Verified via grep across non-test files:

- No goroutines (`go func`)
- No `os` / `net` / `syscall` / `os/exec` / `os/signal`
- No `unsafe`
- No `cgo`
- No `runtime.*` calls
- `compiler.go` uses `go/token.IsIdentifier` (small, pure, supported)
- `bufio.Scanner` with `MaxScanTokenSize` constant — fine
- `encoding/binary`, `encoding/hex`, `strings`, `strconv`, `math` — fine

## Per-file summary

| File | Imports of concern | Action for WASM subset |
|---|---|---|
| `library.go` | none | keep |
| `compiler.go` | none | keep |
| `eval.go` | `sync.Pool` (callPool, varScopePool); `slicepool` | replace pools with direct alloc |
| `types.go` | `sync.Pool` (expr arrays) | replace pools with direct alloc |
| `library_embed.go` | `reflect`, `crypto/ed25519`, `blake2b` | remove reflect; move crypto out |
| `serde_tools.go` | `yaml.v3`, `blake2b` | exclude entire file from WASM build |
| `library_yaml.go` | `//go:embed library.yaml` (string only) | exclude or keep as string asset |
| `local_script.go` | none | keep |
| `recursion.go` | none | keep |
| `trace.go` | `fmt` only | keep |
| `slicepool/` | `sync.Pool`, `sync.Mutex` | replace with direct-alloc shim |
| `tuples/` | `sync.RWMutex` in tree.go | acceptable (no-op under WASM); keep |
| `easyfl_util/` | none | keep |
| `chess/`, `claude/` | demos, inherit parent | not part of WASM build |

## Locked-in design decisions

These decisions were taken before detailed planning began and serve as the
foundation for the refactor:

1. **WASM scope: compile + evaluate.** The WASM build includes both the source
   compiler and the bytecode evaluator. It does **not** include library
   construction at runtime (no `Extend()` flows exposed in WASM hosts) — the
   library is constructed once at startup and treated as read-only thereafter.

2. **Library loading: deferred.** The WASM subset is designed around an
   abstract loader interface; the concrete on-the-wire format (binary
   snapshot vs. programmatic construction) is picked during implementation.
   Core must not depend on YAML.

3. **Factoring: sub-package split (Option B), with a localized build tag for
   slicepool.** YAML serde and crypto embedded functions move to dedicated
   sub-packages (`easyfl/serde`, `easyfl/embed/crypto`). The root `easyfl`
   package becomes the TinyGo-clean subset. The `easyfl/slicepool` sub-package
   stays in place but ships two build-tagged implementations of the same
   public API (see decision 4 below). Proxima updates its imports for the
   YAML and crypto pieces; the slicepool import path is unchanged.

4. **Slicepool: two implementations of the same API, selected by build tag.**
   The current `nil == pure allocation` pattern is fine — no Go-interface
   abstraction in core. Public eval signatures keep `*slicepool.SlicePool` as
   they are today. The `easyfl/slicepool` sub-package contains two files:
   - `slicepool.go` with `//go:build !tinygo` — current segment-based
     `sync.Pool`-backed implementation, used by Proxima.
   - `slicepool_tinygo.go` with `//go:build tinygo` — pure-allocation shim
     exposing the same `*SlicePool` type and method set (`New`, `Alloc`,
     `AllocData`, `Dispose`). No `sync.Pool`, no `sync.Mutex`, no segments.
     Methods just call `make`/`copy`.

   This is the **only build tag in the project**. Caller code in core (eval,
   compiler, embedded functions) is unchanged. The WASM binary contains no
   pooling machinery.

5. **Tracing / `fmt`: keep as-is for now.** No API divergence in this refactor.
   Binary size will be measured once the WASM build is functional; if `fmt` is
   the dominant cost, trace stripping can land as a follow-up.

## Target package layout

```
easyfl/                    (TinyGo-clean core, ~minimal deps)
├── library.go             — Library[T], function registry
├── compiler.go            — source → bytecode
├── eval.go                — bytecode → result, takes Allocator
├── types.go               — Expression[T], CallParams[T]
├── library_embed.go       — non-crypto embedded fns; reflect removed
├── local_script.go
├── recursion.go
├── trace.go
├── allocator.go           — NEW: Allocator interface + pure-alloc default
└── …

easyfl/serde/              — YAML + LibraryHash; depends on easyfl + blake2b + yaml.v3
├── yaml.go                — moved from serde_tools.go + library_yaml.go
└── hash.go                — LibraryHash, ValidateCompiled

easyfl/embed/crypto/       — crypto embedded fns; Proxima wires these in
├── blake2b.go             — evalBlake2b + registration helper
└── ed25519.go             — evalValidSigED25519 + registration helper

easyfl/slicepool/          — two implementations of the same API, build-tagged
├── slicepool.go             — //go:build !tinygo  — optimized segment pool
└── slicepool_tinygo.go      — //go:build tinygo   — pure-alloc shim

easyfl/tuples/             — kept as-is (sync.RWMutex is no-op under WASM, acceptable)
easyfl/easyfl_util/        — kept as-is
easyfl/chess/, claude/     — demo packages; not in WASM build
```

Sub-packages import the core. The core imports nothing from the sub-packages,
so the WASM build can compile core in isolation.

## Remaining open items (to resolve during detailed planning)

- ~~Slicepool TinyGo shim — exact API.~~ **Resolved.** Audit of all
  callsites confirms production code only uses `New()`, `Alloc()`,
  `AllocData()`, `Dispose()`, and the `*SlicePool` type. `Disable()` is
  test-only and called from `library_test.go:18` — that test file already
  imports `blake2b` and exercises YAML, so it is excluded from the TinyGo
  build by the YAML/crypto sub-package split, independent of slicepool.
  The TinyGo shim is exactly:

  ```go
  //go:build tinygo

  package slicepool

  type SlicePool struct{}

  func New() *SlicePool                              { return nil }
  func (p *SlicePool) Alloc(size uint16) []byte      { return make([]byte, size) }
  func (p *SlicePool) AllocData(data ...byte) []byte { ret := make([]byte, len(data)); copy(ret, data); return ret }
  func (p *SlicePool) Dispose()                      {}
  ```

  `slicepool/slicepool_test.go` gets `//go:build !tinygo` since it exercises
  the optimized segment allocator's internals.
- **Where `LibraryHash()` lives.** It's used by `serde_tools.go:128` when
  writing compiled YAML — naturally moves to `easyfl/serde`. But Proxima may
  use it independently of YAML; need to confirm callers in the Proxima repo
  before relocating.
- **Embedded function registration API.** `EmbeddedFunctions[T]` returns a
  `func(sym string) EmbeddedFunction[T]`. After the split, the core's
  factory will not return crypto symbols. Proxima needs a clean way to chain
  the core factory with the crypto factory from `easyfl/embed/crypto`.
  Likely a `Chain(...func(sym string) EmbeddedFunction[T])` helper in core.
- **`isNil()` replacement.** Confirm all callers of `isNil()` to determine
  whether `p == nil` suffices, or a generic-typed `T` constraint is needed.
- **WASM entrypoint.** Where does the `//go:build wasm` package with
  `main()` live? Likely a new `easyfl/wasm/` directory, but out of scope for
  the core refactor itself.

## Verification plan (once refactor lands)

1. `tinygo build -target=wasm -o easyfl.wasm ./...` from a thin WASM entrypoint
   package.
2. Binary-size budget check.
3. Round-trip test: compile a non-trivial expression from source → bytecode →
   evaluate, in WASM, with results matching the standard-Go build.
4. Conformance: run the existing `library_test.go` cases that don't depend on
   YAML/crypto against the WASM build.
