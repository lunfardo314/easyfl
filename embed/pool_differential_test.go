package embed_test

import (
	"bytes"
	"testing"

	"github.com/lunfardo314/easyfl"
	"github.com/lunfardo314/easyfl/slicepool"
	"github.com/stretchr/testify/require"
)

// differentialSources are evaluated one after another in one shared pool, as a host
// evaluates all constraints of a transaction. Sizes sit around the 2046-byte segment and
// the 65535-byte allocation limit, where an allocation can wrap or spill.
var differentialSources = []string{
	// first, in a fresh pool: exactly 65536 bytes, a 16-byte piece first. It fits into the
	// segment's spare capacity, so with a wrapped allocation append writes it into pooled
	// memory before reallocating for the large pieces; len takes 8 of those bytes and the
	// uint8Bytes after it the other 8
	"len(concat(repeat(0xff,16),repeat(repeat(0xaa,128),249),repeat(repeat(0xaa,128),249),repeat(repeat(0xaa,8),222)))",
	"uint8Bytes(0x01)",
	"concat(repeat(0xaa,255),repeat(0xbb,255))",
	"len(concat(repeat(repeat(0xff,128),255),repeat(repeat(0xff,128),255),repeat(0xff,128),repeat(0xff,127)))",
	"add(uint8Bytes(0x0102),uint8Bytes(0x03))",
	"bitwiseAND(repeat(0xff,255),repeat(0x0f,255))",
	"bitwiseNOT(repeat(repeat(0xf0,128),255))",
	"concat(repeat(0x11,200),repeat(0x22,200),repeat(0x33,200),repeat(0x44,200),repeat(0x55,200),repeat(0x66,200),repeat(0x77,200),repeat(0x88,200),repeat(0x99,200),repeat(0xaa,200),repeat(0xbb,47))",
	"uint8Bytes(0x01)",
	"equalUint(0x,u64/0)",
	"sub(uint8Bytes(0x0100),uint8Bytes(0x01))",
}

type evalResult struct {
	res []byte
	err bool
}

func evalIn(lib *easyfl.Library[any], spool *slicepool.SlicePool, code []byte) evalResult {
	res, err := lib.EvalFromBytecodeWithSlicePool(nil, spool, code)
	return evalResult{res: bytes.Clone(res), err: err != nil}
}

// TestPoolDifferential evaluates the same programs in one shared pool and each in a fresh,
// unpooled evaluation, and requires identical results. A builtin writing past its
// allocation, or relying on pooled memory being zero, makes a later program in the shared
// pool differ from its unpooled run.
func TestPoolDifferential(t *testing.T) {
	lib := easyfl.NewBaseLibrary[any]()
	codes := make([][]byte, len(differentialSources))
	for i, src := range differentialSources {
		code, _, err := lib.ExpressionSourceToBytecode(src)
		require.NoError(t, err, src)
		codes[i] = code
	}
	shared := slicepool.New()
	defer shared.Dispose()
	for i, code := range codes {
		require.Equal(t, evalIn(lib, nil, code), evalIn(lib, shared, code), differentialSources[i])
	}
}

// FuzzPoolDifferential runs arbitrary bytecode a, then bytecode b in the same pool, and
// requires b to give the same result as an unpooled evaluation of b alone: no program can
// change what a later program in the same pool computes.
func FuzzPoolDifferential(f *testing.F) {
	lib := easyfl.NewBaseLibrary[any]()
	for i, src := range differentialSources {
		a, _, err := lib.ExpressionSourceToBytecode(src)
		require.NoError(f, err)
		b, _, err := lib.ExpressionSourceToBytecode(differentialSources[(i+1)%len(differentialSources)])
		require.NoError(f, err)
		f.Add(a, b)
	}
	f.Fuzz(func(t *testing.T, a, b []byte) {
		if _, err := lib.ExpressionFromBytecode(a); err != nil {
			return
		}
		if _, err := lib.ExpressionFromBytecode(b); err != nil {
			return
		}
		shared := slicepool.New()
		defer shared.Dispose()
		_ = evalIn(lib, shared, a)
		require.Equal(t, evalIn(lib, nil, b), evalIn(lib, shared, b))
	})
}
