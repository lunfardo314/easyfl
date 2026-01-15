# Change Log

## Add immutable flag for functions

**Commit:** 5854ef5bcf8c853db6c4d3a6c8e2dced2abac48b
**Date:** 2026-01-15 20:45:28 +0200

### Changes Made

**1. `types.go`** - Added `immutable` field to `funDescriptor`:
```go
immutable bool  // if true, function cannot be replaced/modified in upgrades
```

**2. `serde_tools.go`** - Multiple updates:
- Added `Immutable` field to `FuncDescriptorYAMLAble` struct with YAML tag `yaml:"immutable,omitempty"`
- Updated `mustFunYAMLAbleByName` to include immutable in output
- Updated `prnFuncDescription` to print `immutable: true` when set
- Updated `funDescriptor.write()` to include immutable byte in library hash
- Updated `Upgrade()` to set the immutable flag when adding functions from YAML

**3. `library.go`** - Updated replace functions:
- `replaceEmbedded()` returns error if function is immutable
- `replaceExtended()` returns error if function is immutable

**4. `library_yaml.go`** - Updated base library hash (changed due to new byte in hash calculation)

### Tests Added (in `serde_tools_test.go`):
- `TestUpgrade_AddImmutableExtended_Success` - Adding immutable extended function works
- `TestUpgrade_ReplaceImmutableExtended_Fail` - Replacing immutable extended function fails
- `TestUpgrade_AddImmutableEmbedded_Success` - Adding immutable embedded function works
- `TestUpgrade_ReplaceImmutableEmbedded_Fail` - Replacing immutable embedded function fails
- `TestUpgrade_ImmutableAffectsHash` - Immutable flag affects library hash
- `TestUpgrade_NonImmutableCanBeReplaced` - Non-immutable functions can still be replaced

### YAML Usage Example:
```yaml
functions:
  -
    sym: myImmutableFunc
    numArgs: 2
    immutable: true
    source: add($0, $1)
```
