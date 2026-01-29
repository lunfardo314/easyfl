# Refactoring: `embedded_as` field for embedded function resolution

## Goal

Add an additional mapping level for embedded function resolution to support versioned implementations.

## Current Behavior

Function symbol name is directly resolved to Go implementation via `EmbeddedFunctions[T]()` resolver:

```
symbol name (e.g., "add") --> Go implementation
```

## Proposed Change

Add an `embedded_as` field to function descriptors that serves as a stable key for implementation lookup:

```
symbol name --> embedded_as key --> Go implementation (via resolver)
```

## Changes Required

1. **`funDescriptor` struct** (`types.go`): Add `embeddedAs string` field

2. **YAML schema** (`library_yaml.go`):
   - Add `embedded_as` field to function definitions
   - Remove `embedded` flag (becomes redundant)
   - Absence of `embedded_as` key means function is not embedded (i.e., it's an extended function defined in EasyFL source)

3. **Resolver function**: Modify to use `embedded_as` value instead of symbol name for lookup

## Benefits

- **Version upgrades**: Upgrade an embedded function to a new implementation while keeping the old version available in previous library versions
- **Implementation sharing**: Multiple EasyFL functions can share the same Go implementation
- **Decoupling**: Function names in the library are decoupled from implementation identifiers
- **Flexibility**: Different resolvers can provide different behaviors for the same `embedded_as` keys
