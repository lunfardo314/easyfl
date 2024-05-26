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
	{"lessThanUint", "lessThan(uint64Bytes($0), uint64Bytes($1))"},
	{"equalUint", "equal(uint64Bytes($0), uint64Bytes($1))"},
}

func (lib *Library) extendBase() {
	lib.UpgradeWithExtensions(extendWithUtilityFunctions...)

	lib.MustError("require(nil, !!!requirement_failed)", "requirement failed")
	lib.MustEqual("require(true, !!!something_wrong)", "true")

	lib.MustTrue("equalUint(100,100)")
	lib.MustTrue("equalUint(100,u32/100)")
	lib.MustTrue("not(equalUint(100,u32/1337))")
	lib.MustError("equalUint(nil, 5)", "wrong size of parameter")

	lib.MustTrue("lessThanUint(10,u32/100)")
	lib.MustTrue("not(lessThanUint(100,100))")
	lib.MustTrue("not(lessThanUint(u16/100,u64/100))")
	lib.MustTrue("lessThanUint(0,u64/1)")
	lib.MustError("lessThanUint(nil, 5)", "wrong size of parameter")
}
