package easyfl

var extendWithUtilityFunctions = []*ExtendFunction{
	{"false", "0x"},
	{"true", "0xff"},
	{"require", "or($0,$1)"},
	{"lessOrEqualThan", "or(lessThan($0,$1),equal($0,$1))"},
	{"greaterThan", "not(lessOrEqualThan($0,$1))"},
	{"greaterOrEqualThan", "not(lessThan($0,$1))"},
}

func (lib *Library) extendBase() {
	lib.Extend(extendWithUtilityFunctions...)

	lib.MustError("require(nil, !!!requirement_failed)", "requirement failed")
	lib.MustEqual("require(true, !!!something_wrong)", "true")
}
