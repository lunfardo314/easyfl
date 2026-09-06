package tuples

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDecodeTruncatedNoPanic is the regression for the decoder crash
// (audit finding FTX-1 / FEFL-2): a tuple whose length prefix declares
// elements the body is too short to hold must return an error, never index
// out of range. This decoder runs on untrusted transaction bytes arriving
// over gossip and the API, so a panic here is a remote node crash.
func TestDecodeTruncatedNoPanic(t *testing.T) {
	cases := [][]byte{
		{0x40, 0x01},             // 1 element, 1-byte lengths, empty body
		{0x80, 0x01, 0x00},       // 1 element, 2-byte lengths, truncated body
		{0xC0, 0x01, 0x00, 0x00}, // 1 element, 4-byte lengths, truncated body
		{0x40, 0x02, 0x01},       // 2 elements, only one length byte present
	}
	for _, data := range cases {
		_, err := TreeFromBytesReadOnly(data)
		require.Error(t, err, "input %x must error, not panic", data)
	}
}

// FuzzTreeFromBytesReadOnly asserts the invariant that matters for a
// network-facing decoder: whatever bytes arrive, it returns cleanly and
// never panics.
func FuzzTreeFromBytesReadOnly(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		{0x00, 0x00},
		{0x40, 0x01},
		{0x80, 0x01, 0x00},
		{0xC0, 0x01, 0x00, 0x00},
		{0x40, 0x02, 0x01},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// The only assertion is "does not panic". A returned error is fine.
		_, _ = TreeFromBytesReadOnly(data)
	})
}
