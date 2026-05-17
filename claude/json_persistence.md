# EasyFL — Replace YAML with JSON as the persistent library format

## Goal

Drop YAML entirely as EasyFL's persistent library format and replace it with
JSON. The same JSON serializer covers three roles:

| Role | Form | Producer | Consumer |
|---|---|---|---|
| Embedded base library (in-repo, on-disk) | pretty JSON | `TestLibraryRenew` regenerator | `//go:embed library.json` |
| Proxima HTTP API (`/library`, snapshot manifests) | compact JSON | Proxima API handler | Wallet/UI; other nodes |
| State storage (chain snapshot / state record) | compact JSON | Proxima ledger | Proxima ledger |

EasyFL itself stays **compression-agnostic**. Proxima may gzip the compact
JSON bytes when storing snapshots or sending them on the wire — that wrapping
lives in Proxima, not in `easyfl`. Wallet/browser frontends (the eventual
TinyGo/WASM consumer) receive raw JSON.

## Why JSON

- **Standard library.** `encoding/json` ships with Go and works under TinyGo;
  `gopkg.in/yaml.v3` does not. This removes the only blocking dependency for
  a TinyGo-clean wallet build, even before the broader WASM refactor lands.
- **Single third-party dep removed.** `go.mod` loses `gopkg.in/yaml.v3`.
- **Browser-native.** Frontend transaction builders parse JSON natively;
  no `js-yaml` polyfill.
- **Canonical-by-construction.** `encoding/json` emits struct fields in
  declaration order and map keys sorted alphabetically — deterministic bytes
  without extra effort. (We don't currently rely on this for hashing — see
  "Hash invariance" below — but it's a nice property for storage.)
- **No semantic loss.** The existing `LibraryFromYAML` / `FuncDescriptorYAMLAble`
  schema is flat, scalar-only, and has zero YAML-specific features. It maps
  to JSON 1:1.

## Scope

**In scope** (this refactor):

- New JSON serde alongside the existing YAML serde, sharing data structures.
- Regenerate `library.json` from current `library.yaml`; verify hashes match.
- Switch `NewBaseLibrary` and all internal call sites to JSON.
- Remove YAML serde, `library.yaml`, `library_yaml.go`, and the `yaml.v3` dep.
- Update tests (`serde_tools_test.go`, `library_test.go`) to use JSON.

**Out of scope** (deferred):

- Compression (gzip, etc.) — Proxima's concern.
- TinyGo/WASM build — separate effort, tracked in `tinygo_wasm.md`.
  This JSON migration is a prerequisite step but does not itself produce a
  WASM build.
- Schema versioning / migration story — no field renames, no data-model
  changes; today's library YAMLs map mechanically to tomorrow's JSON.
- Proxima-side changes — coordinated in a follow-up PR in the Proxima repo
  once this lands.

## Locked-in decisions (from clarifying questions)

1. **Two forms, both JSON.** Compact = `json.Marshal` (single line, no
   whitespace, no trailing newline). Pretty = `json.MarshalIndent` with a
   small indent and a trailing newline. No third encoding.
2. **Compression is not EasyFL's job.** Proxima wraps the compact JSON bytes
   with gzip wherever it wants to (state, snapshot files, API responses).
   EasyFL's serde produces and consumes plain JSON bytes only.
3. **Full YAML cutover.** No legacy YAML reader is kept. Proxima's import
   sites must switch in lockstep with this change.
4. **Flat `functions` array.** Sorted by `funCode` in compiled form; sorted
   by `sym` in non-compiled form (matches current YAML ordering). No section
   grouping, no `_section` field, no comments (JSON has no comment syntax).
   Section information is derivable from `funCode` ranges.

## Hash invariance

`(*Library[T]).LibraryHash()` is computed from `libraryBytes()` — a
deterministic binary serialization defined in `serde_tools.go:65`. That
serialization is **not** YAML- or JSON-specific; it walks `funByFunCode` in
funCode order and writes `funCode | numParams | sym | bytecode | embeddedAs |
immutable` for each entry, prefixed by counts and `VersionData`.

**Consequence:** changing the textual carrier (YAML → JSON) does not change
`LibraryHash()`. The current base library hash
`5ef6911bad2b4ec3dfac171d8f02bf28cd066e4684ebb091a1b1059a3c2c3bb0` carries
over verbatim into `library.json`.

This is a hard invariant of the refactor. The verification plan checks it.

## JSON schema

```json
{
  "hash": "5ef6911bad2b4ec3dfac171d8f02bf28cd066e4684ebb091a1b1059a3c2c3bb0",
  "versionData": "...",
  "functions": [
    {
      "sym": "fail",
      "description": "fails with parameter as panic message ...",
      "funCode": 15,
      "numArgs": 1,
      "embeddedAs": "evalFail",
      "short": true
    },
    {
      "sym": "lessOrEqualThan",
      "description": "...",
      "funCode": 320,
      "numArgs": 2,
      "source": "...",
      "bytecode": "..."
    }
  ]
}
```

### Field naming

camelCase across the board (`numArgs`, `embeddedAs`, `funCode`, `versionData`).
Reasons: matches Go field names byte-for-byte after `json` tag generation,
matches the conventions of likely JS/TS consumers in the wallet, and removes
the awkward inconsistency of today's YAML (`numArgs` camelCase but
`embedded_as`/`version_data` snake_case).

### `omitempty` policy

- `hash` — omit when empty (non-compiled library).
- `versionData` — omit when empty string.
- `description` — omit when empty.
- `funCode` — omit when zero (non-compiled output; compiled output always has
  nonzero funCodes).
- `embeddedAs` — omit for extended functions.
- `short`, `replace`, `immutable` — omit when false (matches current YAML).
- `source`, `bytecode` — omit when empty (embedded functions have no source;
  non-compiled output has no bytecode).
- `numArgs` — **always emitted**, including zero and `-1` (vararg). Required
  for correct unmarshal of explicit vararg.

## API surface

### Renames

| Today (YAML) | After (JSON) |
|---|---|
| `LibraryFromYAML` | `LibraryFromJSON` |
| `FuncDescriptorYAMLAble` | `FuncDescriptorJSON` |
| `ReadLibraryFromYAML` | `ReadLibraryFromJSON` |
| `(*Library).ToYAML(compiled bool, prefix ...string)` | `(*Library).ToJSON(compiled, indent bool)` |
| `(*Library).UpgradeFromYAML` | `(*Library).UpgradeFromJSON` |
| `(*Library).IntroduceUpdateYAML` | `(*Library).IntroduceUpdateJSON` |
| `(*Library).IntroduceUpdateYAMLMulti` | `(*Library).IntroduceUpdateJSONMulti` |
| `NewLibraryFromYAML` | `NewLibraryFromJSON` |
| `ValidateCompiled[T]` | `ValidateCompiled[T]` (signature unchanged; takes `*LibraryFromJSON`) |

### New signature notes

- `ToJSON(compiled, indent bool) []byte`
  - `compiled=true` includes `hash`, `funCode`, and `bytecode` fields.
  - `indent=true` → `MarshalIndent(..., "", "  ")` + trailing `\n` for
    diff-friendliness.
  - `indent=false` → `Marshal` (compact), no trailing newline. Canonical for
    storage and on-the-wire.
  - The `prefix ...string` parameter is dropped — no comment carrier in JSON.
- `(*Library).Upgrade(fromJSON *LibraryFromJSON, embed ...)` — same shape as
  today's `Upgrade(*LibraryFromYAML, ...)`; just the parameter type is
  renamed.

### Files

| File | Action |
|---|---|
| `serde_tools.go` | YAML helpers (`prn`, `yamlEscapeString`, `prnFuncDescription`, `ToYAML`, `ReadLibraryFromYAML`, `IntroduceUpdate*`, `UpgradeFromYAML`, `mustFunYAMLAbleByName`) removed. Replaced by their JSON counterparts. `libraryBytes` / `write` / `LibraryHash` and `introduceFromParsedYAML` (renamed to `introduceFromParsed`) are kept as-is — they are format-agnostic. |
| `library_yaml.go` | Renamed to `library_json.go`. `//go:embed library.yaml` → `//go:embed library.json`. |
| `library.yaml` | Deleted. |
| `library.json` | New file. Generated from the current base library; see Phase 2. |
| `library.go` | `NewBaseLibrary` calls `NewLibraryFromJSON`. `NewLibraryFromYAML` removed. |
| `serde_tools_test.go` | Updated to test JSON. `TestYamlEscapeString` deleted (no JSON equivalent needed — `encoding/json` handles escaping). The `TestLibraryRenewYAML` regenerator becomes `TestLibraryRenewJSON`. |
| `library_test.go` | Two tests use inline YAML strings (`library_test.go:496, 549`). Convert to inline JSON literals. |
| `go.mod` / `go.sum` | Remove `gopkg.in/yaml.v3`. |

## Phased plan

The phases are designed to keep the tree green at every step.

**Status:** Phases 1–3 complete (commits `443337c`, `8c3dae6`, `2fa5f48`,
`ec81984` on `develop`). Phase 4 is a coordinated PR in
`lunfardo314/proxima`, not yet started.

### Phase 1 — Add JSON serde alongside YAML (no behavior change) — DONE (443337c)

1. Add `json:` tags to `LibraryFromYAML` / `FuncDescriptorYAMLAble` structs.
   Keep the existing `yaml:` tags. Field types are unchanged.
2. Add `ReadLibraryFromJSON`, `(*Library).ToJSON`, `(*Library).UpgradeFromJSON`,
   `(*Library).IntroduceUpdateJSON`, `(*Library).IntroduceUpdateJSONMulti`,
   `NewLibraryFromJSON` in a new file `serde_json.go` (keeps the diff
   reviewable; will collapse into `serde_tools.go` in Phase 3).
3. Refactor `introduceFromParsedYAML` → `introduceFromParsed` (drop the YAML
   suffix; it never read YAML, it read a parsed struct).
4. Add tests that mirror `serde_tools_test.go` 1:1 against the JSON API.
   Round-trip: load YAML → ToJSON → ReadLibraryFromJSON → hash equality.

Exit criterion: both YAML and JSON serde paths produce libraries with
identical `LibraryHash()` for the same logical content. All existing tests
pass; new JSON tests pass.

### Phase 2 — Generate and embed `library.json` — DONE (8c3dae6, 2fa5f48)

1. Add a one-shot test `TestLibraryRenewJSON` (parallel to `TestLibraryRenewYAML`)
   that loads the current `library.yaml`, runs `lib.ToJSON(true, true)`, and
   writes `library.json` to disk.
2. Run it. Commit the generated `library.json`.
3. Verify by hand: `library.json`'s `hash` field equals the value in
   `library.yaml`.
4. In a separate commit, swap `library_yaml.go`'s `//go:embed library.yaml`
   for `//go:embed library.json`, rename the file to `library_json.go`, and
   point `NewBaseLibrary` to `NewLibraryFromJSON`.
5. Run the full suite. `library.yaml` is still on disk but no longer
   referenced.

Exit criterion: `NewBaseLibrary` loads from JSON. Hash unchanged. All tests
green.

### Phase 3 — Remove YAML — DONE (ec81984)

1. Delete YAML-specific code in `serde_tools.go`: `ToYAML`,
   `ReadLibraryFromYAML`, `UpgradeFromYAML`, `IntroduceUpdateYAML`,
   `IntroduceUpdateYAMLMulti`, `mustFunYAMLAbleByName`, `prn`,
   `yamlEscapeString`, `prnFuncDescription`, `ident`/`ident2`/`ident3`.
2. Remove `yaml:` tags. Rename types `LibraryFromYAML` → `LibraryFromJSON`,
   `FuncDescriptorYAMLAble` → `FuncDescriptorJSON`. Rename
   `serde_tools_test.go` symbols accordingly.
3. Remove `gopkg.in/yaml.v3` import in `serde_tools.go`.
4. Run `go mod tidy`. `gopkg.in/yaml.v3` should drop from `go.mod` /
   `go.sum`.
5. Delete `library.yaml`. Delete the YAML regenerator test.
6. Update `library_test.go:496, 549` inline YAML strings → JSON.
7. Collapse `serde_json.go` into `serde_tools.go` (or rename to
   `serde_tools.go` outright if the YAML deletion left it empty).

Exit criterion: `grep -i yaml` returns nothing in non-comment Go source. No
`yaml.v3` dep. Full suite green.

### Phase 4 — Downstream (Proxima) — PENDING

Not part of this PR. Coordinated PR in `lunfardo314/proxima`:

- `easyfl.NewLibraryFromYAML(…)` → `easyfl.NewLibraryFromJSON(…)`.
- Any Proxima API endpoint that previously served `ToYAML(...)` switches to
  `ToJSON(true, true)` for human-facing endpoints and `ToJSON(true, false)`
  for snapshot blobs and state.
- Add gzip wrapping in the Proxima layer if/where current YAML payloads were
  large enough to justify it.

## Verification — results

### Phase 1 (DONE)
- `TestJSON_BaseLib_RoundTripHash` (originally `TestJSON_BaseLib_HashMatchesYAML`):
  base lib → `ToJSON` → `NewLibraryFromJSON` → hash equality. Passes.
- `TestJSON_CompactVsIndent`, `TestJSON_CompactVsIndentShape`: both forms parse
  to equal hashes; compact has no newlines, indented has trailing newline.
- 13 new JSON tests in `serde_json_test.go` mirror upgrade semantics.

### Phase 2 (DONE)
- `library.json` top-level `"hash"` =
  `5ef6911bad2b4ec3dfac171d8f02bf28cd066e4684ebb091a1b1059a3c2c3bb0`,
  unchanged from the deleted `library.yaml`.
- `NewBaseLibrary()` produces the same hash before and after the consumer
  switch.

### Phase 3 (DONE)
- `go build ./...` and `go test ./...` clean.
- `go mod why gopkg.in/yaml.v3` shows only the transitive path through
  `github.com/stretchr/testify`; easyfl no longer imports it directly.
- `grep -i yaml` in `*.go` returns nothing — exit criterion met.

## Open items — resolutions

1. **Indent width.** Chose two spaces. `library.json` is 380 lines (vs.
   361 for the old `library.yaml`).
2. **`description` on embedded functions.** Left inline, one per function.
   Readable; revisit only if reviewers complain.
3. **`numArgs: -1` vararg encoding.** JSON numbers handle `-1` natively.
   `TestJSON_Upgrade_Vararg` and `TestToJSON_VarargExtended` cover it.
4. **`hash` location in pretty output.** `LibraryFromJSON.Hash` is the first
   declared field, so `MarshalIndent` puts it at the top of `library.json`
   — diff-friendly.
5. **Public API breakage.** Hard rename in phase 3; no deprecation window.
   Proxima must update imports in lockstep (phase 4 PR).

## Non-goals (explicitly)

- Not changing the bytecode format, function-code layout, or `Library[T]`
  generic API.
- Not changing `LibraryHash()` semantics or the bytes it digests.
- Not adding gzip, brotli, or any other transport encoding to EasyFL.
- Not introducing a schema version field. If a future incompatible change
  is needed, add `"schemaVersion": 1` then; today's single schema is
  implicit version 0.