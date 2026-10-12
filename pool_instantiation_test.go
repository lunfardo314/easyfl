package easyfl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type otherContext struct{}

// TestPoolsAcrossInstantiations is the regression for the shared object pools:
// they are package-level, hence shared by libraries of every context type, so
// evaluating or parsing on one library after another of a different type took
// an object of the wrong type from a pool and panicked. Both orders are run,
// with an extended function so that variable scopes are pooled too.
func TestPoolsAcrossInstantiations(t *testing.T) {
	libA := NewBaseLibrary[any]()
	libB := NewBaseLibrary[*otherContext]()
	libA.Extend("double", "concat($0,$0)")
	libB.Extend("double", "concat($0,$0)")

	const source = "double(concat(0x01, 0x02))"
	_, _, codeA, err := libA.CompileExpression(source)
	require.NoError(t, err)
	_, _, codeB, err := libB.CompileExpression(source)
	require.NoError(t, err)
	expected := []byte{1, 2, 1, 2}

	for i := 0; i < 3; i++ {
		// evaluation on one library returns objects to the pools ...
		require.Equal(t, expected, libA.MustEvalFromBytecode(nil, codeA))
		// ... which the other library then takes, both parsing and evaluating
		_, _, _, err = libB.ParseBytecodeOneLevel(codeB)
		require.NoError(t, err)
		require.Equal(t, expected, libB.MustEvalFromBytecode(nil, codeB))
		res, err := libA.EvalFromSource(nil, source)
		require.NoError(t, err)
		require.Equal(t, expected, res)
		_, _, _, err = libA.ParseBytecodeOneLevel(codeA)
		require.NoError(t, err)
	}
}
