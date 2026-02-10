package easyfl

import (
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
	yamlData := `
functions:
  -
    sym: funcA
    numArgs: 2
    source: funcB($0, $1)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)
	err = lib.IntroduceUpdateYAML(fromYaml)
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
	yamlData := `
functions:
  -
    sym: funcA
    numArgs: 1
    source: funcB($0)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)
	err = lib.IntroduceUpdateYAML(fromYaml)
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
	yamlData := `
functions:
  -
    sym: funcDup
    numArgs: 1
    source: byte($0, 0)
`
	fromYaml, err := ReadLibraryFromYAML([]byte(yamlData))
	require.NoError(t, err)
	err = lib.IntroduceUpdateYAML(fromYaml)
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
