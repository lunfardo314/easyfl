## Refactoring: Add Variable Argument Support for Extended Functions

## Current Behavior

Extended functions are defined as EasyFL formulas. The formulas are parametrized using `$0`, `$1`, etc. to reference evaluated arguments of the function call.

Currently, EasyFL formulas only allow definition of functions with a fixed number of arguments. The maximum index `i` in `$i` used in the formula defines the fixed number of arguments in the call as `i+1`.

That fixed number `numArgs` is stored in the function descriptor and in YAML.

For embedded functions, `numArgs = -1` indicates variable arguments; however, for extended functions this is not currently allowed.

## Goal

Enable definition of variable argument functions in EasyFL for extended functions.

## Design Decisions (Clarified)

1. **`$$` literal scope**: The `$$` literal works in both vararg and fixed-argument functions, returning the actual argument count in all cases.

2. **YAML format**: Vararg extended functions use `numArgs: -1` in YAML, consistent with embedded vararg functions.

## Guidelines and Semantics

- `numArgs` in the descriptor and YAML remains with the same semantics. `numArgs = -1` becomes possible for extended functions.
- New syntax `func_vararg <name> : <formula>` indicates that `<name>` and `<formula>` should be treated as a variable-argument function.
- The language syntax does not change, but parsing does not enforce a fixed number of arguments for vararg extended function calls. That is, `f(a,b)` and `f(a,b,c)` are both valid for a vararg extended function call.
- In the defining formula, access to parameter `$i` that does not exist in the call results in a panic.
- To handle this situation in the formula, we introduce the predefined literal `$$` which returns a one-byte value of the actual number of arguments in the call.

### Example 1
Function `foo` returns the number of arguments as a one-byte value:
```
func_vararg foo: $$
```
So, `foo(5)` returns `0x01`, `foo(6,7,8)` returns `0x03`.

### Example 2
Function `add4` returns the sum of up to 4 arguments:
```
func_vararg add4: selectCaseByIndex($$,
   u64/0,                      // no args
   uint8Bytes($0),             // 1 arg
   add($0,$1),                 // 2 args
   add($0,add($1,$2)),         // 3 args
   add(add($0,$1),add($2,$3)), // 4 args
   !!!max_4_arguments_allowed  // more than 4 args
)
```

Note: The EasyFL definitions above have not been tested and may contain errors.

## Implementation Plan

### Tasks
1. [x] Add `$$` literal parsing in compiler (returns arity at runtime)
2. [x] Add `func_vararg` keyword parsing for defining vararg extended functions
3. [x] Modify compiler to allow `numArgs = -1` for extended functions
4. [x] Modify YAML parsing to support `numArgs = -1` for extended functions
5. [x] Implement runtime behavior: `$$` returns arity, `$i` beyond arity panics
6. [x] Write tests for vararg extended functions
7. [x] Update this file with implementation details

## Implementation Details

### Files Modified

1. **compiler.go**
   - Added `IsVararg` field to `funParsed` struct
   - Modified `parseDefs` to recognize `func_vararg` prefix
   - Added `$$` literal parsing that compiles to `arity` function call

2. **library.go**
   - Added `ExtendVarargErr` method for adding vararg extended functions with `numArgs = -1`
   - Modified `ExtendMany` to dispatch to `ExtendVarargErr` when `IsVararg` flag is set

3. **library_embed.go**
   - Added `evalArity` function that returns `VarScopeArity()` as a single byte
   - The `$$` embedded function is defined in `library.yaml` with short code 36

4. **eval.go**
   - Added `VarScopeArity()` method to `CallParams` that returns the length of the var scope

5. **serde_tools.go**
   - Modified `Upgrade` to call `ExtendVarargErr` when `NumArgs == -1` for extended functions
   - YAML serialization/deserialization already supports `-1` for numArgs

### Key Behaviors

- `$$` is both the literal syntax and the function name (short embedded, code 36)
- `$$` returns a 1-byte value with the actual argument count
- Decompilation shows `$$` (not a separate `arity` function)
- **Important**: `$$` returns `0x00` when no args (which is truthy since non-empty). To check for zero args, use `isZero($$)` or `not(isZero($$))` for the inverse
- Accessing `$i` beyond the actual arity causes a panic (existing behavior)
- Vararg functions can be called with any number of arguments (0 to 15)

### Usage Examples

```easyfl
// Returns argument count
func_vararg countArgs: $$

// Returns first arg if present, else nil
func_vararg firstOrNil: if(not(isZero($$)), $0, nil)

// Sum up to 4 arguments
func_vararg sum4: selectCaseByIndex($$,
   u64/0,                      // no args
   uint8Bytes($0),             // 1 arg
   add($0,$1),                 // 2 args
   add($0,add($1,$2)),         // 3 args
   add(add($0,$1),add($2,$3))  // 4 args
)
```

### YAML Format

Vararg extended functions use `numArgs: -1`:
```yaml
functions:
  -
    sym: myVarargFunc
    numArgs: -1
    source: $$
```

## Progress Tracking

### Session 1
- [x] Read and understand the codebase structure
- [x] Clarified design decisions with user
- [x] Added `$$` literal and `arity` embedded function

### Session 2
- [x] Added `func_vararg` keyword parsing
- [x] Added `ExtendVarargErr` method
- [x] Modified YAML parsing for vararg extended functions
- [x] Added comprehensive tests
- [x] All tests passing
