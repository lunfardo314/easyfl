package easyfl

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUpgrade_ForwardRef_ReplaceCallsNew tests that a replaced function can reference
// a new function added in the same batch, regardless of YAML ordering.
func TestUpgrade_ForwardRef_ReplaceCallsNew(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// First add a function that we'll later replace
	yaml1 := `
functions:
  -
    sym: funcA
    numArgs: 2
    source: add($0, $1)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yaml1))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml)
	require.NoError(t, err)
	lib.MustEqual("funcA(3, 5)", "uint8Bytes(8)")

	// Now upgrade: replace funcA to call new funcD. funcA listed BEFORE funcD (forward ref).
	yaml2 := `
functions:
  -
    sym: funcA
    numArgs: 2
    replace: true
    source: funcD($0, $1)
  -
    sym: funcD
    numArgs: 2
    source: mul($0, $1)
`
	fromYaml, err = ReadLibraryFromYAML([]byte(yaml2))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml)
	require.NoError(t, err)

	// funcA now delegates to funcD (mul)
	lib.MustEqual("funcA(3, 5)", "uint8Bytes(15)")
	lib.MustEqual("funcD(3, 5)", "uint8Bytes(15)")
}

// TestUpgrade_ForwardRef_NewCallsNew tests that new functions can reference each other
// regardless of YAML ordering.
func TestUpgrade_ForwardRef_NewCallsNew(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// funcE calls funcF, but funcE is listed first
	yamlData := `
functions:
  -
    sym: funcE
    numArgs: 2
    source: funcF($0, $1)
  -
    sym: funcF
    numArgs: 2
    source: add($0, $1)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml)
	require.NoError(t, err)

	lib.MustEqual("funcE(3, 5)", "uint8Bytes(8)")
	lib.MustEqual("funcF(3, 5)", "uint8Bytes(8)")
}

// TestUpgrade_SelfRecursion tests that a function calling itself is detected.
func TestUpgrade_SelfRecursion(t *testing.T) {
	lib := NewBaseLibrary[any]()

	yamlData := `
functions:
  -
    sym: selfRec
    numArgs: 1
    source: selfRec($0)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml)
	require.Error(t, err)
	require.Contains(t, err.Error(), "recursion detected")
}

// TestUpgrade_MutualRecursion tests that A→B, B→A is detected.
func TestUpgrade_MutualRecursion(t *testing.T) {
	lib := NewBaseLibrary[any]()

	yamlData := `
functions:
  -
    sym: mutA
    numArgs: 1
    source: mutB($0)
  -
    sym: mutB
    numArgs: 1
    source: mutA($0)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml)
	require.Error(t, err)
	require.Contains(t, err.Error(), "recursion detected")
}

// TestUpgrade_IndirectCycle tests that A→B→C→A is detected.
func TestUpgrade_IndirectCycle(t *testing.T) {
	lib := NewBaseLibrary[any]()

	yamlData := `
functions:
  -
    sym: cycA
    numArgs: 1
    source: cycB($0)
  -
    sym: cycB
    numArgs: 1
    source: cycC($0)
  -
    sym: cycC
    numArgs: 1
    source: cycA($0)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml)
	require.Error(t, err)
	require.Contains(t, err.Error(), "recursion detected")
}

// TestUpgrade_ReplaceInducedCycle tests that replacing B to call A creates a cycle
// when existing A already calls B.
func TestUpgrade_ReplaceInducedCycle(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// Add A that calls B
	yaml1 := `
functions:
  -
    sym: depB
    numArgs: 1
    source: byte($0, 0)
  -
    sym: depA
    numArgs: 1
    source: depB($0)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yaml1))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml)
	require.NoError(t, err)

	// Now replace B to call A — creates cycle A→B→A
	yaml2 := `
functions:
  -
    sym: depB
    numArgs: 1
    replace: true
    source: depA($0)
`
	fromYaml, err = ReadLibraryFromYAML([]byte(yaml2))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml)
	require.Error(t, err)
	require.Contains(t, err.Error(), "recursion detected")
}

// TestUpgrade_DiamondDependency tests that A→B, A→C, B→D, C→D (diamond, no cycle) succeeds.
func TestUpgrade_DiamondDependency(t *testing.T) {
	lib := NewBaseLibrary[any]()

	yamlData := `
functions:
  -
    sym: diamA
    numArgs: 1
    source: add(diamB($0), diamC($0))
  -
    sym: diamB
    numArgs: 1
    source: diamD($0)
  -
    sym: diamC
    numArgs: 1
    source: diamD($0)
  -
    sym: diamD
    numArgs: 1
    source: byte($0, 0)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml)
	require.NoError(t, err)

	// diamA(0x0102) should compute byte(0x0102, 0) for both paths, then add them
	lib.MustEqual("diamD(0x0102)", "1")
	lib.MustEqual("diamB(0x0102)", "1")
	lib.MustEqual("diamC(0x0102)", "1")
	lib.MustEqual("diamA(0x0102)", "uint8Bytes(2)")
}

// TestClone_Basic tests that Clone produces an independent copy.
func TestClone_Basic(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// Add a function to the original
	yaml1 := `
functions:
  -
    sym: origFunc
    numArgs: 2
    source: add($0, $1)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yaml1))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml)
	require.NoError(t, err)

	origHash := lib.LibraryHash()
	origNumFuncs := lib.NumFunctions()

	// Clone and modify the clone
	clone := lib.Clone()
	yaml2 := `
functions:
  -
    sym: cloneFunc
    numArgs: 2
    source: mul($0, $1)
`
	fromYaml, err = ReadLibraryFromYAML([]byte(yaml2))
	require.NoError(t, err)
	err = clone.Upgrade(fromYaml)
	require.NoError(t, err)

	// Original is unchanged
	require.Equal(t, origHash, lib.LibraryHash())
	require.Equal(t, origNumFuncs, lib.NumFunctions())

	// Clone has the new function
	require.NotEqual(t, origHash, clone.LibraryHash())
	require.Equal(t, origNumFuncs+1, clone.NumFunctions())

	// Both work independently
	lib.MustEqual("origFunc(3, 5)", "uint8Bytes(8)")
	clone.MustEqual("origFunc(3, 5)", "uint8Bytes(8)")
	clone.MustEqual("cloneFunc(3, 5)", "uint8Bytes(15)")
}

// TestClone_DiscardOnError tests the pattern: clone, upgrade with error, discard clone.
func TestClone_DiscardOnError(t *testing.T) {
	lib := NewBaseLibrary[any]()

	yaml1 := `
functions:
  -
    sym: stableFunc
    numArgs: 1
    source: byte($0, 0)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yaml1))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml)
	require.NoError(t, err)

	origHash := lib.LibraryHash()

	// Clone and attempt upgrade with recursion
	clone := lib.Clone()
	yamlBad := `
functions:
  -
    sym: badA
    numArgs: 1
    source: badB($0)
  -
    sym: badB
    numArgs: 1
    source: badA($0)
`
	fromYaml, err = ReadLibraryFromYAML([]byte(yamlBad))
	require.NoError(t, err)
	err = clone.Upgrade(fromYaml)
	require.Error(t, err) // cycle detected

	// Original is completely untouched
	require.Equal(t, origHash, lib.LibraryHash())
	lib.MustEqual("stableFunc(0x0102)", "1")
}

// TestUpgrade_BackwardCompatible_NoForwardRefs tests that existing upgrade patterns
// without forward references still work.
func TestUpgrade_BackwardCompatible_NoForwardRefs(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// Sequential dependency: funcX uses base lib, funcY uses funcX
	yamlData := `
functions:
  -
    sym: funcX
    numArgs: 2
    source: add($0, $1)
  -
    sym: funcY
    numArgs: 2
    source: funcX($0, $1)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml)
	require.NoError(t, err)

	lib.MustEqual("funcX(3, 5)", "uint8Bytes(8)")
	lib.MustEqual("funcY(3, 5)", "uint8Bytes(8)")
}

// TestUpgrade_MixedEmbeddedAndExtended_ForwardRef tests that embedded functions
// are processed correctly alongside extended functions with forward references.
func TestUpgrade_MixedEmbeddedAndExtended_ForwardRef(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// Mix: one embedded replacement + two extended with forward ref
	yamlData := `
functions:
  -
    sym: add
    numArgs: 2
    embedded_as: "evalAddUint"
    short: true
    replace: true
  -
    sym: fwdCaller
    numArgs: 2
    source: fwdTarget($0, $1)
  -
    sym: fwdTarget
    numArgs: 2
    source: add($0, $1)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml, EmbeddedFunctions[any](lib))
	require.NoError(t, err)

	lib.MustEqual("fwdCaller(3, 5)", "uint8Bytes(8)")
	lib.MustEqual("fwdTarget(3, 5)", "uint8Bytes(8)")
}

// TestExtractReferencedFunCodes tests the bytecode walking utility.
func TestExtractReferencedFunCodes(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// Compile "add($0, $1)" and extract references
	_, _, bytecode, err := lib.CompileExpression("add($0, $1)")
	require.NoError(t, err)

	refs, err := extractReferencedFunCodes(bytecode)
	require.NoError(t, err)
	require.NotEmpty(t, refs)

	// "add" should be among the references
	addFi, err := lib.functionByName("add")
	require.NoError(t, err)
	found := false
	for _, r := range refs {
		if r == addFi.FunCode {
			found = true
			break
		}
	}
	require.True(t, found, "expected 'add' funCode %d in refs %v", addFi.FunCode, refs)
}

// TestCheckForCycles_NoExtended tests cycle check on a library with only embedded functions.
func TestCheckForCycles_NoExtended(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// No extended functions to check — should be fine
	err := checkForCycles(lib, nil)
	require.NoError(t, err)
}

// TestUpgrade_VarargForwardRef tests that vararg functions work with forward references.
func TestUpgrade_VarargForwardRef(t *testing.T) {
	lib := NewBaseLibrary[any]()

	yamlData := `
functions:
  -
    sym: varCaller
    numArgs: 2
    source: varTarget($0, $1)
  -
    sym: varTarget
    numArgs: -1
    source: add($0, $1)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)
	err = lib.Upgrade(fromYaml)
	require.NoError(t, err)

	lib.MustEqual("varCaller(3, 5)", "uint8Bytes(8)")
}

// TestExtendMany_ForwardReference tests that ExtendMany supports forward references
// (funcA calls funcB, but funcA is defined first).
func TestExtendMany_ForwardReference(t *testing.T) {
	lib := NewBaseLibrary[any]()

	err := lib.ExtendMany(`
func fwdA : fwdB($0, $1)
func fwdB : add($0, $1)
`)
	require.NoError(t, err)

	lib.MustEqual("fwdA(3, 5)", "uint8Bytes(8)")
	lib.MustEqual("fwdB(3, 5)", "uint8Bytes(8)")
}

// TestExtendMany_CycleDetection tests that ExtendMany detects mutual recursion.
func TestExtendMany_CycleDetection(t *testing.T) {
	lib := NewBaseLibrary[any]()

	err := lib.ExtendMany(`
func cycX : cycY($0)
func cycY : cycX($0)
`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "recursion detected")
}

// TestIntroduceCommit_CrossSourceForwardRef tests that functions from YAML and plain
// EasyFL code can reference each other when committed together.
func TestIntroduceCommit_CrossSourceForwardRef(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// YAML adds funcA that calls funcB (which doesn't exist yet)
	err := lib.IntroduceUpdateYAML([]byte(`
functions:
  -
    sym: funcA
    numArgs: 2
    source: funcB($0, $1)
`))
	require.NoError(t, err)

	// Plain code adds funcB
	err = lib.IntroduceUpdateMany(`
func funcB : add($0, $1)
`)
	require.NoError(t, err)

	// CommitUpdate resolves both together
	err = lib.CommitUpdate()
	require.NoError(t, err)

	lib.MustEqual("funcA(3, 5)", "uint8Bytes(8)")
	lib.MustEqual("funcB(3, 5)", "uint8Bytes(8)")
}

// TestIntroduceCommit_CrossSourceCycle tests that cross-source cycles are detected.
func TestIntroduceCommit_CrossSourceCycle(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// YAML adds funcA→funcB
	err := lib.IntroduceUpdateYAML([]byte(`
functions:
  -
    sym: funcA
    numArgs: 1
    source: funcB($0)
`))
	require.NoError(t, err)

	// Plain code adds funcB→funcA (cycle)
	err = lib.IntroduceUpdateMany(`
func funcB : funcA($0)
`)
	require.NoError(t, err)

	// CommitUpdate should detect the cycle
	err = lib.CommitUpdate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "recursion detected")
}

// TestIntroduceCommit_DuplicateAcrossBatches tests that the same symbol in YAML
// and plain code is detected as a duplicate.
func TestIntroduceCommit_DuplicateAcrossBatches(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// YAML adds funcDup
	err := lib.IntroduceUpdateYAML([]byte(`
functions:
  -
    sym: funcDup
    numArgs: 1
    source: byte($0, 0)
`))
	require.NoError(t, err)

	// Plain code also tries to add funcDup — should fail
	err = lib.IntroduceUpdateMany(`
func funcDup : byte($0, 0)
`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already in pending batch")
}

// TestIntroduceCommit_EmptyCommit tests that CommitUpdate with no pending returns nil.
func TestIntroduceCommit_EmptyCommit(t *testing.T) {
	lib := NewBaseLibrary[any]()
	err := lib.CommitUpdate()
	require.NoError(t, err)
}

// TestIntroduceMulti_YAMLAndSources tests the variadic IntroduceUpdateYAMLMulti
// and IntroduceUpdateManyMulti with cross-source forward references.
func TestIntroduceMulti_YAMLAndSources(t *testing.T) {
	lib := NewBaseLibrary[any]()

	yaml1 := []byte(`
functions:
  -
    sym: mFuncA
    numArgs: 2
    source: mFuncC($0, $1)
`)
	yaml2 := []byte(`
functions:
  -
    sym: mFuncB
    numArgs: 2
    source: mFuncA($0, $1)
`)

	// Introduce two YAML sources at once (nil resolver — no embedded)
	err := lib.IntroduceUpdateYAMLMulti(nil, yaml1, yaml2)
	require.NoError(t, err)

	// Introduce two plain EasyFL sources at once
	src1 := `func mFuncC : add($0, $1)`
	src2 := `func mFuncD : mFuncB($0, $1)`
	err = lib.IntroduceUpdateManyMulti(src1, src2)
	require.NoError(t, err)

	err = lib.CommitUpdate()
	require.NoError(t, err)

	// mFuncA→mFuncC→add, mFuncB→mFuncA→mFuncC→add, mFuncD→mFuncB→...
	lib.MustEqual("mFuncC(3, 5)", "uint8Bytes(8)")
	lib.MustEqual("mFuncA(3, 5)", "uint8Bytes(8)")
	lib.MustEqual("mFuncB(3, 5)", "uint8Bytes(8)")
	lib.MustEqual("mFuncD(3, 5)", "uint8Bytes(8)")
}

// TestTopoSort_CrossSourceDepWithManyUnrelated tests the scenario that originally triggered
// the sort.Slice bug: a function in source1 depends on a function in sourceN (last source),
// with many unrelated functions defined in between. The previous sort.Slice-based topological
// sort would incorrectly place the dependent before its dependency due to the partial order
// comparator violating the strict weak ordering requirement (transitivity of incomparability).
func TestTopoSort_CrossSourceDepWithManyUnrelated(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// Source 1: defines "caller" which depends on "helper" (not yet defined)
	src1 := `func caller : helper($0, $1)`

	// Sources 2..N: many unrelated functions that neither depend on "caller" nor "helper".
	// These are the functions that break sort.Slice by being incomparable with both endpoints.
	var unrelatedSources []string
	for i := 0; i < 50; i++ {
		unrelatedSources = append(unrelatedSources,
			fmt.Sprintf("func unrel%d : add($0, $1)", i))
	}

	// Last source: defines "helper"
	srcLast := `func helper : mul($0, $1)`

	// Stage all sources
	err := lib.IntroduceUpdateMany(src1)
	require.NoError(t, err)
	for _, s := range unrelatedSources {
		err = lib.IntroduceUpdateMany(s)
		require.NoError(t, err)
	}
	err = lib.IntroduceUpdateMany(srcLast)
	require.NoError(t, err)

	// Commit — the topological sort must place "helper" before "caller"
	err = lib.CommitUpdate()
	require.NoError(t, err)

	// Verify both functions work correctly
	lib.MustEqual("helper(3, 5)", "uint8Bytes(15)")
	lib.MustEqual("caller(3, 5)", "uint8Bytes(15)")
}

// TestTopoSort_DeepChainReversed tests a deep dependency chain where functions are
// introduced in reverse order: A→B→C→D→E, but A is defined first and E last.
func TestTopoSort_DeepChainReversed(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// A calls B, B calls C, C calls D, D calls E — all defined in forward (wrong) order
	err := lib.ExtendMany(`
func chainA : chainB($0, $1)
func chainB : chainC($0, $1)
func chainC : chainD($0, $1)
func chainD : chainE($0, $1)
func chainE : add($0, $1)
`)
	require.NoError(t, err)

	lib.MustEqual("chainE(3, 5)", "uint8Bytes(8)")
	lib.MustEqual("chainD(3, 5)", "uint8Bytes(8)")
	lib.MustEqual("chainC(3, 5)", "uint8Bytes(8)")
	lib.MustEqual("chainB(3, 5)", "uint8Bytes(8)")
	lib.MustEqual("chainA(3, 5)", "uint8Bytes(8)")
}

// TestTopoSort_MultipleSourcesReverseOrder tests that IntroduceUpdateManyMulti correctly
// handles the case where the first source references functions from the last source.
// This is the pattern that occurs in Proxima's def_upgrade0.go: sigLock (first source)
// references selfRequireEnoughStorageDeposit (last source).
func TestTopoSort_MultipleSourcesReverseOrder(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// Source 1: defines "outer" that calls "inner" (defined in source 3)
	src1 := `func outer : add(inner($0), $1)`
	// Source 2: unrelated function
	src2 := `func middle : byte($0, 0)`
	// Source 3: defines "inner" that "outer" depends on
	src3 := `func inner : mul($0, 2)`

	err := lib.IntroduceUpdateManyMulti(src1, src2, src3)
	require.NoError(t, err)

	err = lib.CommitUpdate()
	require.NoError(t, err)

	// inner(3) = 3*2 = 6, outer(3, 5) = inner(3) + 5 = 6 + 5 = 11
	lib.MustEqual("inner(3)", "uint8Bytes(6)")
	lib.MustEqual("outer(3, 5)", "uint8Bytes(11)")
	lib.MustEqual("middle(0x0102)", "1")
}

// TestTopoSort_IndependentFunctionsNoOrder tests that independent functions
// (no dependencies between them) can be compiled in any order without error.
func TestTopoSort_IndependentFunctionsNoOrder(t *testing.T) {
	lib := NewBaseLibrary[any]()

	err := lib.ExtendMany(`
func indA : add($0, $1)
func indB : mul($0, $1)
func indC : sub($0, $1)
func indD : byte($0, 0)
`)
	require.NoError(t, err)

	lib.MustEqual("indA(3, 5)", "uint8Bytes(8)")
	lib.MustEqual("indB(3, 5)", "uint8Bytes(15)")
}

// TestTopoSort_DiamondWithUnrelated tests a diamond dependency pattern with many
// unrelated functions in between, stressing the topological sort correctness.
func TestTopoSort_DiamondWithUnrelated(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// Build sources: top→left, top→right, left→bottom, right→bottom
	// with unrelated functions interleaved
	srcTop := `func diaTop : add(diaLeft($0), diaRight($0))`
	srcLeft := `func diaLeft : diaBot($0)`
	srcRight := `func diaRight : diaBot($0)`
	srcBot := `func diaBot : byte($0, 0)`

	// Introduce in worst-case order: top first, bottom last, with unrelated in between
	err := lib.IntroduceUpdateMany(srcTop)
	require.NoError(t, err)

	for i := 0; i < 20; i++ {
		err = lib.IntroduceUpdateMany(fmt.Sprintf("func noise%d : add($0, $1)", i))
		require.NoError(t, err)
	}

	err = lib.IntroduceUpdateMany(srcLeft)
	require.NoError(t, err)

	for i := 20; i < 40; i++ {
		err = lib.IntroduceUpdateMany(fmt.Sprintf("func noise%d : add($0, $1)", i))
		require.NoError(t, err)
	}

	err = lib.IntroduceUpdateMany(srcRight)
	require.NoError(t, err)
	err = lib.IntroduceUpdateMany(srcBot)
	require.NoError(t, err)

	err = lib.CommitUpdate()
	require.NoError(t, err)

	// diaBot(0x0102) = byte(0x0102, 0) = 1
	// diaLeft = diaRight = diaBot = 1
	// diaTop = 1 + 1 = 2
	lib.MustEqual("diaBot(0x0102)", "1")
	lib.MustEqual("diaLeft(0x0102)", "1")
	lib.MustEqual("diaRight(0x0102)", "1")
	lib.MustEqual("diaTop(0x0102)", "uint8Bytes(2)")
}

// TestHashPrefixForwardRef tests that #funcName bytecode prefix references resolve
// with the correct arity even when the referenced function is defined in a later source.
// This was a bug: Phase 1 registered all functions with requiredNumParams=-1, and Phase 2
// compiled sequentially. When an earlier function used #laterFunc, the arity was 0 instead
// of the actual value, causing the call prefix to differ from the runtime bytecode.
func TestHashPrefixForwardRef(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// earlyChecker uses #lateTarget to check if bytecode has lateTarget's prefix.
	// earlyChecker is listed FIRST so it's compiled before lateTarget in Phase 2.
	// lateTarget has 3 params — without the fix, #lateTarget would resolve with arity 0.
	err := lib.ExtendMany(`
func earlyChecker : equal(parseBytecode($0, 0x), #lateTarget)
func lateTarget : concat($0, $1, $2)
`)
	require.NoError(t, err)

	// Compile lateTarget(0x01, 0x02, 0x03) to get its actual bytecode
	_, _, code, err := lib.CompileExpression("lateTarget(0x01, 0x02, 0x03)")
	require.NoError(t, err)

	// earlyChecker should return 0xff (true) when given lateTarget bytecode
	src := fmt.Sprintf("earlyChecker(0x%s)", hex.EncodeToString(code))
	result, err := lib.EvalFromSource(nil, src)
	require.NoError(t, err)
	require.Equal(t, []byte{0xff}, result, "earlyChecker should recognize lateTarget prefix via #lateTarget")
}

// TestHashPrefixForwardRef_MultiSource tests #funcName across separate sources
// committed together (the pattern used by Proxima's IntroduceUpdateManyMulti).
func TestHashPrefixForwardRef_MultiSource(t *testing.T) {
	lib := NewBaseLibrary[any]()

	// Source 1 (compiled first) references #targetFunc from source 2
	err := lib.IntroduceUpdateMany(`
func checker : equal(parseBytecode($0, 0x), #targetFunc)
`)
	require.NoError(t, err)

	// Source 2 defines targetFunc with 4 params
	err = lib.IntroduceUpdateMany(`
func targetFunc : concat($0, concat($1, concat($2, $3)))
`)
	require.NoError(t, err)

	err = lib.CommitUpdate()
	require.NoError(t, err)

	// Compile targetFunc call to get its bytecode
	_, _, code, err := lib.CompileExpression("targetFunc(0x01, 0x02, 0x03, 0x04)")
	require.NoError(t, err)

	// checker should recognize the prefix
	src := fmt.Sprintf("checker(0x%s)", hex.EncodeToString(code))
	result, err := lib.EvalFromSource(nil, src)
	require.NoError(t, err)
	require.Equal(t, []byte{0xff}, result, "checker should recognize targetFunc prefix across sources")
}

// TestCountParametersFromSource tests the parameter count pre-scanner.
func TestCountParametersFromSource(t *testing.T) {
	tests := []struct {
		source   string
		expected int
	}{
		{"add($0, $1)", 2},
		{"byte($0, 0)", 1},
		{"concat($0, $1, $2)", 3},
		{"concat($0, concat($1, concat($2, $3)))", 4},
		{"0x0102", 0},
		{"nil", 0},
		{"add(1, 2)", 0},
		// $15 = param index 15, so 16 params
		{"add($0, $15)", 16},
	}
	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			n, err := countParametersFromSource(tt.source)
			require.NoError(t, err)
			require.Equal(t, tt.expected, n, "source: %s", tt.source)
		})
	}
}
