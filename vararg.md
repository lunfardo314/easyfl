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
1. [ ] Add `$$` literal parsing in compiler (returns arity at runtime)
2. [ ] Add `func_vararg` keyword parsing for defining vararg extended functions
3. [ ] Modify compiler to allow `numArgs = -1` for extended functions
4. [ ] Modify YAML parsing to support `numArgs = -1` for extended functions
5. [ ] Implement runtime behavior: `$$` returns arity, `$i` beyond arity panics
6. [ ] Write tests for vararg extended functions
7. [ ] Update this file with implementation details

## Progress Tracking

### Session 1
- [x] Read and understand the codebase structure
- [x] Clarified design decisions with user
- [ ] Implementation in progress...
