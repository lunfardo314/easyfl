package easyfl

var extendWithUtilityFunctions = []*ExtendedFunctionData{
	{"false", "0x", "TBD"},
	{"true", "0xff", "TBD"},
	{"require", "or($0,$1)", "TBD"},
	{"lessOrEqualThan", "or(lessThan($0,$1),equal($0,$1))", "TBD"},
	{"greaterThan", "not(lessOrEqualThan($0,$1))", "TBD"},
	{"greaterOrEqualThan", "not(lessThan($0,$1))", "TBD"},
	{"bytecode", "$$0", "TBD"},
	{"evalArgumentBytecode", "eval(parseArgumentBytecode($0,$1,$2))", "TBD"},
	{"lessThanUint", "lessThan(uint8Bytes($0), uint8Bytes($1))", "TBD"},
	{"equalUint", "equal(uint8Bytes($0), uint8Bytes($1))", "TBD"},
	{"max", "if(lessThan($0,$1),$1,$0)", "TBD"},
	{"min", "if(lessThan($0,$1),$0,$1)", "TBD"},
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
