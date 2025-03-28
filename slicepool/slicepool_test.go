package slicepool

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func init() {
	Disable()
}

func TestSlicePool(t *testing.T) {
	sp := New()

	data := []string{"a", "ab", "abcd", "dddddddddddddddd", "eeeeeeee", strings.Repeat("-", 2000)}
	dataBack := []string{}
	for _, d := range data {
		db := sp.Alloc(uint16(len(d)))
		copy(db, d)
		dataBack = append(dataBack, string(db))
	}
	for i := range dataBack {
		require.EqualValues(t, dataBack[i], data[i])
	}

	const (
		numStrings = 1000
		maxStrlen  = 2000
	)
	sp.Dispose()
	sp = New()

	data = []string{}
	dataBack = []string{}
	for i := 0; i < numStrings; i++ {
		s := String(rand.Intn(maxStrlen))
		data = append(data, s)
		db := sp.Alloc(uint16(len(s)))
		copy(db, s)
		dataBack = append(dataBack, string(db))
	}
	for i := range dataBack {
		require.EqualValues(t, dataBack[i], data[i])
	}
	sp.Dispose()

}

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func String(length int) string {
	return StringWithCharset(length, charset)
}
