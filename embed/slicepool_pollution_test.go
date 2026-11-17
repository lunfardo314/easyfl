package embed_test

import (
	"testing"

	"github.com/lunfardo314/easyfl"
	"github.com/lunfardo314/easyfl/slicepool"
	"github.com/stretchr/testify/require"
)

// oversizeConcat concatenates exactly 65536 bytes: 2 x 128 x 255 + 2 x 128.
// One byte past slicepool.MaxAllocSize, so uint16(totalSize) wraps to 0.
const oversizeConcat = `concat(repeat(repeat(0xff,128),255),repeat(repeat(0xff,128),255),repeat(0xff,128),repeat(0xff,128))`

// Kept outside the root package: its tests disable the slice pool, which would
// make both tests below pass without exercising pooled memory.

// TestConcatOversizeDoesNotPolluteSharedPool is the regression for a concat
// whose total size wraps the uint16 allocation size to 0: append then wrote the
// result over the rest of the pool segment, and every later allocation from the
// same pool started non-zero. Hosts share one pool across all constraints of a
// transaction, so uint8Bytes of a short value evaluated afterwards widened with
// garbage instead of zeros and arithmetic checks could be made to pass.
func TestConcatOversizeDoesNotPolluteSharedPool(t *testing.T) {
	lib := easyfl.NewBaseLibrary[any]()
	spool := slicepool.New()
	defer spool.Dispose()

	code, _, err := lib.ExpressionSourceToBytecode("len(" + oversizeConcat + ")")
	require.NoError(t, err)
	_, err = lib.EvalFromBytecodeWithSlicePool(nil, spool, code)
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds limit")

	// A later evaluation in the same pool must still widen with zeros.
	code, _, err = lib.ExpressionSourceToBytecode("uint8Bytes(0x01)")
	require.NoError(t, err)
	got, err := lib.EvalFromBytecodeWithSlicePool(nil, spool, code)
	require.NoError(t, err)
	require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 1}, got)
}

// TestSlicePoolAllocIsCapped checks the pool's own guard, independent of any
// builtin: an append past an allocation must reallocate, not write into memory
// the next Alloc hands out and callers rely on being zero.
func TestSlicePoolAllocIsCapped(t *testing.T) {
	spool := slicepool.New()
	defer spool.Dispose()

	buf := spool.Alloc(0)
	require.Equal(t, 0, cap(buf))
	_ = append(buf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)

	require.Equal(t, make([]byte, 8), spool.Alloc(8))
}
