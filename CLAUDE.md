# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Context

EasyFL is part of the [Proxima project](https://github.com/lunfardo314/proxima), but the language and interpreter are independent and can be used in other projects.

## Documentation

- Full language documentation: https://lunfardo314.github.io/#/txdocs/easyfl
- Usage in Proxima ledger: https://lunfardo314.github.io/#/ledgerdocs/library

## Commit Preferences

Do not include "Generated with Claude Code" or "Co-Authored-By: Claude" in commit messages.

## Build and Test Commands

```bash
# Run all tests
go test ./...

# Run a specific test
go test -run TestName

# Run tests with verbose output
go test -v ./...

# Run tests in a specific package
go test ./tuples/...
```

## Architecture Overview

EasyFL (Easy Formula/Functional Language) is a simple, non-Turing complete functional programming language designed for UTXO ledger programmability. It operates in three forms:

1. **Source form** - Human-readable ASCII expressions
2. **Bytecode form** - Compact canonical representation for storage/embedding
3. **Execution form** - Internal tree structure for evaluation

### Core Components

**Library[T any]** (`library.go`, `types.go`)
- Generic type parameter T represents the data context type passed during evaluation
- Contains function registry with embedded (Go-implemented) and extended (EasyFL-defined) functions
- Functions are categorized as:
  - **Short embedded** (1-byte call prefix, codes 16-63)
  - **Long embedded** (2-byte call prefix, codes 64-319)
  - **Extended** (2-byte call prefix, compiled from EasyFL source)
  - **Local** (3-byte call prefix, for inline libraries)

**Compiler** (`compiler.go`)
- `CompileExpression()` - Source to execution form + bytecode
- `ExpressionSourceToBytecode()` - Source to bytecode only
- `ExpressionFromBytecode()` - Bytecode to execution form
- `DecompileBytecode()` - Bytecode back to source
- Literals: `$0`-`$14` (params), `nil`, hex (`0x...`), integers, `u16/`, `u32/`, `u64/`, `z8/`-`z64/` (trimmed)

**Evaluator** (`eval.go`)
- `EvalExpression()` - Evaluate with data context and args
- `EvalFromSource()` / `EvalFromBytecode()` - Compile-and-eval helpers
- `CallParams[T]` - Function call context with `Arg(n)`, `DataContext()`, `Trace()`

**Embedded Functions** (`library_embed.go`)
- Core functions: `concat`, `slice`, `byte`, `tail`, `equal`, `if`, `and`, `or`, `not`
- Arithmetic: `add`, `sub`, `mul`, `div`, `mod` (all 8-byte big-endian)
- Crypto: `blake2b`, `validSignatureED25519`
- Bytecode manipulation: `parseBytecode`, `parseInlineData`, `parseNumArgs`
- Tuples: `atTuple8`, `tupleLen`

**LocalLibrary** (`local_library.go`)
- Compile multiple functions as inline bytecode array
- Functions can reference each other and earlier definitions
- Used for embedding reusable function sets in data structures

**Tuples Package** (`tuples/`)
- Binary serialization for arrays of byte slices
- `Tuple` (immutable) and `TupleEditable` (mutable)
- Supports nested tree structures via `Tree` type

### Bytecode Format

```
First byte determines format:
- Bit 7 set: inline data (bits 0-6 = length, or 0xFF + 2-byte length)
- Bit 7 clear, bit 6 clear: short call (1 byte)
- Bit 7 clear, bit 6 set: long call (2 bytes, bits 2-5 = arity)
```

### Key Constraints

- Maximum 15 parameters per function (`$0` to `$14`)
- Maximum source size: ~64KB (bufio.MaxScanTokenSize)
- Maximum data size: 65535 bytes
- Local libraries: up to 255 functions

### Testing Patterns

The test file (`library_test.go`) shows common patterns:
- `lib.MustEqual(src1, src2)` - Assert two expressions evaluate equally
- `lib.MustTrue(src)` - Assert expression is truthy (non-empty)
- `lib.MustError(src, msg)` - Assert expression panics with message
- `NewGlobalDataTracePrint(nil)` / `NewGlobalDataLog(nil)` - Tracing helpers
