package easyfl

const baseLibraryDefinitions = `
# EasyFL library
compiled: true
description: "base library"
hash: 2f7fdd6218061b4d9092e8a83e8e7cbce2a4604f6f3b9f18a4471673e55f29b2
functions:
# BEGIN EMBEDDED function definitions
#    function codes (opcodes) from 0 to 15 are reserved for predefined inline functions
# BEGIN SHORT EMBEDDED function definitions
#    function codes (opcodes) from 16 to 63 are reserved for 'SHORT EMBEDDED function codes'
   -
      sym: fail
      description: "fails with parameter as panic message, where '_' is replaced with space"
      funCode: 16
      numArgs: 1
      embedded: true
      short: true
   -
      sym: slice
      description: "slice($0,$1,$2) takes a slice of $0, from $1 to $2 inclusive. $1 and $2 must be 1-byte long"
      funCode: 17
      numArgs: 3
      embedded: true
      short: true
   -
      sym: byte
      description: "byte($0,$1) takes byte $1 of $0, returns 1-byte long slice. $1 must be 1-byte long"
      funCode: 18
      numArgs: 2
      embedded: true
      short: true
   -
      sym: tail
      description: "tail($0,$1) returns slice of $0 from $1 to the end"
      funCode: 19
      numArgs: 2
      embedded: true
      short: true
   -
      sym: equal
      description: "equal($0,$1) returns non-empty value if $0 and $1 are equal slices"
      funCode: 20
      numArgs: 2
      embedded: true
      short: true
   -
      sym: hasPrefix
      description: "hasPrefix($0,$1) returns non-empty value if $0 has $1 as prefix"
      funCode: 21
      numArgs: 2
      embedded: true
      short: true
   -
      sym: len
      description: "len($0)returns uint64 big-endian 8 bytes of the length of $0"
      funCode: 22
      numArgs: 1
      embedded: true
      short: true
   -
      sym: not
      description: "not($0) returns 0x if $0 is not empty, and non-empty value if $0 is empty"
      funCode: 23
      numArgs: 1
      embedded: true
      short: true
   -
      sym: if
      description: "if($0,$1,$2) returns eval value of $1 if $0 is non-empty and eval value of $1 otherwise"
      funCode: 24
      numArgs: 3
      embedded: true
      short: true
   -
      sym: isZero
      description: "isZero($0) returns 0x if $0 contains at least one non-zero byte"
      funCode: 25
      numArgs: 1
      embedded: true
      short: true
   -
      sym: add
      description: "add($0,$1) returns $0 + $1 as big-endian uint64. $0 and $1 is expanded to 8 bytes by adding leading 0-s"
      funCode: 26
      numArgs: 2
      embedded: true
      short: true
   -
      sym: sub
      description: "sub($0,$1) returns $0 - $1 as big-endian uint64 or panics with 'underflow' if $0<$1. $0 and $1 is expanded to 8 bytes by adding leading 0-s"
      funCode: 27
      numArgs: 2
      embedded: true
      short: true
   -
      sym: mul
      description: "mul($0,$1) returns $0 x $1 as big-endian uint64. $0 and $1 is expanded to 8 bytes by adding leading 0-s"
      funCode: 28
      numArgs: 2
      embedded: true
      short: true
   -
      sym: div
      description: "div($0,$1) returns $0 / $1 (integer division) as big-endian uint64 or panics if $1 is 0. $0 and $1 is expanded to 8 bytes by adding leading 0-s"
      funCode: 29
      numArgs: 2
      embedded: true
      short: true
   -
      sym: mod
      description: "mod($0,$1) returns $0 mod $1 as big-endian uint64 or panics if $1 is 0. $0 and $1 is expanded to 8 bytes by adding leading 0-s"
      funCode: 30
      numArgs: 2
      embedded: true
      short: true
   -
      sym: uint8Bytes
      description: " expands $0 with leading 0-s up to 8 bytes"
      funCode: 31
      numArgs: 1
      embedded: true
      short: true
   -
      sym: lessThan
      description: "returns non-empty value of $0 < $1 lexicographically, otherwise returns 0x. Operands must be of equal length"
      funCode: 32
      numArgs: 2
      embedded: true
      short: true
   -
      sym: bitwiseOR
      description: "bitwise OR operation on $0 and $1, which must have equal length"
      funCode: 33
      numArgs: 2
      embedded: true
      short: true
   -
      sym: bitwiseAND
      description: "bitwise AND operation on $0 and $1, which must have equal length"
      funCode: 34
      numArgs: 2
      embedded: true
      short: true
   -
      sym: bitwiseNOT
      description: "bitwise inversion of $0"
      funCode: 35
      numArgs: 1
      embedded: true
      short: true
   -
      sym: bitwiseXOR
      description: "bitwise XOR operation on $0 and $1, which must have equal length"
      funCode: 36
      numArgs: 2
      embedded: true
      short: true
# END SHORT EMBEDDED function definitions
# BEGIN LONG EMBEDDED function definitions
#    function codes (opcodes) from 64 to 318 are reserved for 'LONG EMBEDDED function codes'
   -
      sym: concat
      description: "concatenates variable number of arguments"
      funCode: 64
      numArgs: -1
      embedded: true
   -
      sym: and
      description: "returns non-empty value if all arguments are not empty, otherwise returns 0x"
      funCode: 65
      numArgs: -1
      embedded: true
   -
      sym: or
      description: "returns empty value 0x if all arguments are 0x (empty), otherwise returns non-empty value"
      funCode: 66
      numArgs: -1
      embedded: true
   -
      sym: repeat
      description: "repeat($0,$1) repeats $0 number of times $1. $1 must be 1-byte long"
      funCode: 67
      numArgs: 2
      embedded: true
   -
      sym: firstCaseIndex
      description: "evaluates one-by-one and returns first argument with non-empty value"
      funCode: 68
      numArgs: -1
      embedded: true
   -
      sym: firstEqualIndex
      description: "firstEqualIndex($0,$1,..$n) evaluates $0 and returns (i-1) of the parameter $i which is equal to $0"
      funCode: 69
      numArgs: -1
      embedded: true
   -
      sym: selectCaseByIndex
      description: "selectCaseByIndex($0,$1, ..$n) return value if the parameter based on the value of $0+1"
      funCode: 70
      numArgs: -1
      embedded: true
   -
      sym: lshift64
      description: "lshift64($0,$1) returns $0<<$1, where both arguments ar expanded to big-endian uint64 bytes by adding leading 0-s"
      funCode: 71
      numArgs: 2
      embedded: true
   -
      sym: rshift64
      description: "lshift64($0,$1) returns $0>>$1, where both arguments ar expanded to big-endian uint64 bytes by adding leading 0-s"
      funCode: 72
      numArgs: 2
      embedded: true
   -
      sym: validSignatureED25519
      description: "validSignatureED25519($0,$1,$2) returns non-empty value if $1 represents valid ED25519 signature of message $0 and  public key $2"
      funCode: 73
      numArgs: 3
      embedded: true
   -
      sym: blake2b
      description: "returns 32 bytes of the blake2b hash of the argument"
      funCode: 74
      numArgs: -1
      embedded: true
   -
      sym: parseArgumentBytecode
      description: "parseArgumentBytecode($0,$1,$2) treats $0 as bytecode. It check if its call prefix is equal to $1 and takes bytecode argument with index $2"
      funCode: 75
      numArgs: 3
      embedded: true
   -
      sym: parsePrefixBytecode
      description: "treats $0 as bytecode. Returns its call prefix"
      funCode: 76
      numArgs: 1
      embedded: true
   -
      sym: eval
      description: "evaluates $0 as bytecode without open parameters (as closed formula)"
      funCode: 77
      numArgs: 1
      embedded: true
# END LONG embedded function definitions
# BEGIN EXTENDED function definitions (defined by EasyFL formulas)
#    function codes (opcodes) from 319 and up to maximum 1022 are reserved for 'EXTENDED function codes'
   -
      sym: false
      description: "returns 0x"
      funCode: 319
      numArgs: 0
      bytecode: 80
      source: >
         0x
   -
      sym: true
      description: "returns non-empty value"
      funCode: 320
      numArgs: 0
      bytecode: 81ff
      source: >
         0xff
   -
      sym: require
      description: "equivalent to or($0,$1). Useful in context like require(<cond>, !!!fail_condition_not_satisfied)"
      funCode: 321
      numArgs: 2
      bytecode: 48420001
      source: >
         or($0,$1)
   -
      sym: lessOrEqualThan
      description: "returns $0<=$1. Requires operands must be equal length"
      funCode: 322
      numArgs: 2
      bytecode: 4842200001140001
      source: >
         or(lessThan($0,$1),equal($0,$1))
   -
      sym: greaterThan
      description: "returns $0>$1. Requires operands must be equal length"
      funCode: 323
      numArgs: 2
      bytecode: 1749420001
      source: >
         not(lessOrEqualThan($0,$1))
   -
      sym: greaterOrEqualThan
      description: "returns $0>=$1. Requires operands must be equal length"
      funCode: 324
      numArgs: 2
      bytecode: 17200001
      source: >
         not(lessThan($0,$1))
   -
      sym: bytecode
      description: "returns bytecode of the operand, i.e. arguments is compiled instead of evaluated"
      funCode: 325
      numArgs: 1
      bytecode: 08
      source: >
         $$0
   -
      sym: evalArgumentBytecode
      description: "in bytecode $0, parses argument with index $2, enforces call prefix is equal to $1"
      funCode: 326
      numArgs: 3
      bytecode: 444d4c4b000102
      source: >
         eval(parseArgumentBytecode($0,$1,$2))
   -
      sym: lessThanUint
      description: "returns $0<$1 for arguments of any size <= 8. Each of arguments ar expanded fit leading 0-s up to 8 bytes and compare lexicographically"
      funCode: 327
      numArgs: 2
      bytecode: 201f001f01
      source: >
         lessThan(uint8Bytes($0), uint8Bytes($1))
   -
      sym: equalUint
      description: "returns $0==$1 preliminary expanding each operand with leading 0-s to 8 bytes"
      funCode: 328
      numArgs: 2
      bytecode: 141f001f01
      source: >
         equal(uint8Bytes($0), uint8Bytes($1))
   -
      sym: max
      description: "returns bigger one out of 2 operands of equal size"
      funCode: 329
      numArgs: 2
      bytecode: 182000010100
      source: >
         if(lessThan($0,$1),$1,$0)
   -
      sym: min
      description: "returns smaller one out of 2 operands of equal size"
      funCode: 330
      numArgs: 2
      bytecode: 182000010001
      source: >
         if(lessThan($0,$1),$0,$1)
# END EXTENDED function definitions
# END all function definitions
`
