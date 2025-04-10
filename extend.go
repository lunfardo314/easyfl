package easyfl

var extendWithUtilityFunctions = []*ExtendedFunctionData{
	{"false", "0x"},
	{"true", "0xff"},
	{"require", "or($0,$1)"},
	{"lessOrEqualThan", "or(lessThan($0,$1),equal($0,$1))"},
	{"greaterThan", "not(lessOrEqualThan($0,$1))"},
	{"greaterOrEqualThan", "not(lessThan($0,$1))"},
	{"bytecode", "$$0"},
	{"evalArgumentBytecode", "eval(parseArgumentBytecode($0,$1,$2))"},
	{"lessThanUint", "lessThan(uint8Bytes($0), uint8Bytes($1))"},
	{"equalUint", "equal(uint8Bytes($0), uint8Bytes($1))"},
	{"max", "if(lessThan($0,$1),$1,$0)"},
	{"min", "if(lessThan($0,$1),$0,$1)"},
}

func (lib *Library) extendBase() {
	lib.UpgradeWithExtensions(extendWithUtilityFunctions...)

	lib.MustError("require(nil, !!!requirement_failed)", "requirement failed")
	lib.MustEqual("require(true, !!!something_wrong)", "true")

	lib.MustTrue("equal(0x,0x)")
	lib.MustTrue("equalUint(0x,0x)")
	lib.MustTrue("equalUint(100,100)")
	lib.MustTrue("equalUint(100,u32/100)")
	lib.MustTrue("not(equalUint(100,u32/1337))")
	lib.MustTrue("not(equalUint(nil, 5))")

	lib.MustTrue("lessThanUint(10,u32/100)")
	lib.MustTrue("not(lessThanUint(100,100))")
	lib.MustTrue("not(lessThanUint(u16/100,u64/100))")
	lib.MustTrue("lessThanUint(0,u64/1)")
	lib.MustTrue("lessThanUint(nil, 5)")

	lib.MustEqual("max(1,100)", "100")
	lib.MustEqual("max(100,1)", "100")

	lib.MustEqual("min(1,100)", "1")
	lib.MustEqual("min(100,1)", "1")

	lib.MustEqual("max(u32/1,u32/100)", "u32/100")
	lib.MustEqual("max(u32/100,u32/1)", "u32/100")

	lib.MustEqual("min(u32/1,u32/100)", "u32/1")
	lib.MustEqual("min(u32/100,u32/1)", "u32/1")

}
