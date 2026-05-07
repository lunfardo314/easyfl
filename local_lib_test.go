package easyfl

import (
	"testing"

	"github.com/lunfardo314/easyfl/easyfl_util"
	"github.com/stretchr/testify/require"
)

func TestLocalLibrary(t *testing.T) {
	lib := NewBaseLibrary[any]()
	const source = `
 func fun1 : concat($0, $1)
 func fun2 : concat(fun1($0,2),fun1(3,4))
 func fun3 : fun2($0)
 func fun4 : 0x010203
`
	libData, err := lib.CompileLocalLibrary(source)
	require.NoError(t, err)

	t.Run("1", func(t *testing.T) {
		require.NoError(t, err)
		require.EqualValues(t, 4, len(libData))

		_, err = lib.LocalLibraryFromBytes(libData)
		require.NoError(t, err)
		_, err = lib.LocalLibraryFromBytes(libData[:3])
		require.NoError(t, err)
		_, err = lib.LocalLibraryFromBytes(libData[:2])
		require.NoError(t, err)
		_, err = lib.LocalLibraryFromBytes(libData[:1])
		require.NoError(t, err)
		_, err = lib.LocalLibraryFromBytes(libData[:0]) // empty library is valid
		require.NoError(t, err)
	})
	t.Run("2", func(t *testing.T) {
		require.NoError(t, err)
		lib.MustEvalFromLocalLibrary(nil, libData, 0, []byte{1}, []byte{2})
		lib.MustEvalFromLocalLibrary(nil, libData, 1, []byte{5})
		lib.MustEvalFromLocalLibrary(nil, libData, 2, []byte{1})
		lib.MustEvalFromLocalLibrary(nil, libData, 3)
		err = easyfl_util.CatchPanicOrError(func() error {
			lib.MustEvalFromLocalLibrary(nil, libData, 4, []byte{1})
			return nil
		})
		easyfl_util.RequireErrorWith(t, err, "function index is out of library bounds")
	})
	t.Run("3", func(t *testing.T) {
		res, err := lib.EvalFromLocalLibrary(nil, libData, 0, []byte{1}, []byte{2})
		require.NoError(t, err)
		require.EqualValues(t, []byte{1, 2}, res)

		res, err = lib.EvalFromLocalLibrary(nil, libData, 1, []byte{5})
		require.NoError(t, err)
		require.EqualValues(t, []byte{5, 2, 3, 4}, res)

		res, err = lib.EvalFromLocalLibrary(nil, libData, 2, []byte{5})
		require.NoError(t, err)
		require.EqualValues(t, []byte{5, 2, 3, 4}, res)

		res, err = lib.EvalFromLocalLibrary(nil, libData, 3)
		require.NoError(t, err)
		require.EqualValues(t, []byte{1, 2, 3}, res)

		res, err = lib.EvalFromLocalLibrary(nil, libData, 2)
		easyfl_util.RequireErrorWith(t, err, "index out of range")

		_, err = lib.EvalFromLocalLibrary(nil, libData, 4, []byte{5})
		easyfl_util.RequireErrorWith(t, err, "function index is out of library bounds")
	})

}
