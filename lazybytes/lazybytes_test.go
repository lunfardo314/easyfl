package lazybytes

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

const howMany = 250

var data [][]byte

func init() {
	data = make([][]byte, howMany)
	for i := range data {
		data[i] = make([]byte, 2)
		binary.BigEndian.PutUint16(data[i], uint16(i))
	}
}

func TestLazyArraySemantics(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		_, err := ArrayFromBytesReadOnly(nil)
		require.Error(t, err)
		//require.EqualValues(t, 0, len(ls.Bytes()))
		//require.Panics(t, func() {
		//	ls.NumElementsAtPath()
		//})
	})
	t.Run("empty", func(t *testing.T) {
		ls := EmptyArray()
		require.EqualValues(t, []byte{0, 0}, ls.Bytes())

		require.EqualValues(t, 0, ls.NumElements())
	})
	t.Run("serialize all nil", func(t *testing.T) {
		ls := EmptyArray()
		ls.MustPush(nil)
		ls.MustPush(nil)
		ls.MustPush(nil)
		require.EqualValues(t, 3, ls.NumElements())
		lsBin := ls.Bytes()
		require.EqualValues(t, []byte{byte(dataLenBytes0), 3}, lsBin)
		lsBack, err := ArrayFromBytesReadOnly(lsBin)
		require.NoError(t, err)
		require.EqualValues(t, 3, ls.NumElements())
		lsBack.ForEach(func(i int, d []byte) bool {
			require.EqualValues(t, 0, len(d))
			return true
		})
	})
	t.Run("serialize some nil", func(t *testing.T) {
		ls := EmptyArray()
		ls.MustPush(nil)
		ls.MustPush(nil)
		ls.MustPush([]byte("ab"))
		ls.MustPush(nil)
		ls.MustPush([]byte("1234567890"))
		require.EqualValues(t, 5, ls.NumElements())
		lsBin := ls.Bytes()
		lsBack, err := ArrayFromBytesReadOnly(lsBin)
		require.NoError(t, err)
		require.EqualValues(t, 5, lsBack.NumElements())
		require.EqualValues(t, 0, len(lsBack.MustAt(0)))
		require.EqualValues(t, 0, len(lsBack.MustAt(1)))
		require.EqualValues(t, []byte("ab"), lsBack.MustAt(2))
		require.EqualValues(t, 0, len(lsBack.MustAt(3)))
		require.EqualValues(t, []byte("1234567890"), lsBack.MustAt(4))
	})
	t.Run("deserialize rubbish", func(t *testing.T) {
		ls := EmptyArray()
		ls.MustPush(data[17])
		lsBin := ls.Bytes()
		lsBack, err := ArrayFromBytesReadOnly(lsBin)
		require.NoError(t, err)
		require.True(t, bytes.Equal(lsBin, lsBack.Bytes()))

		require.NotPanics(t, func() {
			require.EqualValues(t, data[17], ls.MakeReadOnly().MustAt(0))
		})
		lsBinWrong := append(lsBin, 1, 2, 3)
		_, err = ArrayFromBytesReadOnly(lsBinWrong)
		require.Error(t, err)
	})
	t.Run("push+boundaries", func(t *testing.T) {
		ls := EmptyArray(1000)
		require.NotPanics(t, func() {
			ls.MustPush(data[17])
		})
		require.EqualValues(t, data[17], ls.MakeReadOnly().MustAt(0))
		require.EqualValues(t, 1, ls.NumElements())
		ser := ls.Bytes()
		lsBack, err := ArrayFromBytesReadOnly(ser)
		require.NoError(t, err)
		require.EqualValues(t, 1, lsBack.NumElements())
		require.EqualValues(t, ls.MakeReadOnly().MustAt(0), lsBack.MustAt(0))
		require.Panics(t, func() {
			ls.MakeReadOnly().MustAt(1)
		})
		require.Panics(t, func() {
			lsBack.MustAt(100)
		})
	})
	t.Run("too long", func(t *testing.T) {
		require.NotPanics(t, func() {
			ls := EmptyArray()
			ls.MustPush(bytes.Repeat(data[0], 256))
		})
		require.NotPanics(t, func() {
			ls := EmptyArray()
			ls.MustPush(bytes.Repeat(data[0], 257))
		})
		require.NotPanics(t, func() {
			ls := EmptyArray()
			for i := 0; i < 255; i++ {
				ls.MustPush(data[0])
			}
		})
		require.Panics(t, func() {
			ls := EmptyArray(300)
			for i := 0; i < 301; i++ {
				ls.MustPush(data[0])
			}
		})
		require.Panics(t, func() {
			ls := EmptyArray()
			for i := 0; i < math.MaxUint16+1; i++ {
				ls.MustPush(data[0])
			}
		})
	})
	t.Run("serialize prefix", func(t *testing.T) {
		da, err := ArrayFromBytesReadOnly([]byte{byte(dataLenBytes0), 0})
		require.NoError(t, err)
		bin := da.Bytes()
		daBack, err := ArrayFromBytesReadOnly(bin)
		require.NoError(t, err)
		require.EqualValues(t, 0, daBack.NumElements())
		require.EqualValues(t, bin, daBack.Bytes())

		da, err = ArrayFromBytesReadOnly(emptyArrayPrefix.Bytes())
		require.NoError(t, err)
		bin = da.Bytes()
		daBack, err = ArrayFromBytesReadOnly(bin)
		require.NoError(t, err)
		require.EqualValues(t, 0, daBack.NumElements())
		require.EqualValues(t, bin, daBack.Bytes())

		da, err = ArrayFromBytesReadOnly([]byte{byte(dataLenBytes0), 17})
		require.NoError(t, err)
		bin = da.Bytes()
		daBack, err = ArrayFromBytesReadOnly(bin)
		require.NoError(t, err)
		require.EqualValues(t, 17, daBack.NumElements())
		for i := 0; i < 17; i++ {
			require.EqualValues(t, 0, len(daBack.MustAt(i)))
		}
		require.Panics(t, func() {
			daBack.MustAt(18)
		})
	})
	t.Run("serialize short", func(t *testing.T) {
		ls := EmptyArray()
		for i := 0; i < 100; i++ {
			ls.MustPush(bytes.Repeat(data[0], 100))
		}
		lsBack, err := ArrayFromBytesReadOnly(ls.Bytes())
		require.NoError(t, err)
		require.EqualValues(t, ls.NumElements(), lsBack.NumElements())
		for i := 0; i < 100; i++ {
			require.EqualValues(t, ls.MakeReadOnly().MustAt(i), lsBack.MustAt(i))
		}
	})
	t.Run("serialization long 1", func(t *testing.T) {
		ls := EmptyArray()
		for i := 0; i < 100; i++ {
			ls.MustPush(bytes.Repeat(data[0], 2000))
		}
		daBytes := ls.Bytes()
		daBack, err := ArrayFromBytesReadOnly(daBytes)
		require.NoError(t, err)
		require.EqualValues(t, ls.NumElements(), daBack.NumElements())
		for i := 0; i < 100; i++ {
			require.EqualValues(t, ls.MakeReadOnly().MustAt(i), daBack.MustAt(i))
		}
	})
	t.Run("serialization long 2", func(t *testing.T) {
		ls1 := EmptyArray()
		for i := 0; i < 100; i++ {
			ls1.MustPush(bytes.Repeat(data[0], 2000))
		}
		ls2 := EmptyArray()
		for i := 0; i < 100; i++ {
			ls2.MustPush(bytes.Repeat(data[0], 2000))
		}
		for i := 0; i < 100; i++ {
			require.EqualValues(t, ls1.MakeReadOnly().MustAt(i), ls2.MakeReadOnly().MustAt(i))
		}
		require.EqualValues(t, ls1.NumElements(), ls2.NumElements())
		require.EqualValues(t, ls1.Bytes(), ls2.Bytes())
	})
}

func TestTreeSemantics(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		_, err := TreeFromBytesReadOnly(nil)
		require.Error(t, err)
	})
	t.Run("empty array error", func(t *testing.T) {
		st, err := TreeFromBytesReadOnly(EmptyArray().Bytes())
		require.NoError(t, err)
		_, err = st.BytesAtPath(Path(1))
		require.Error(t, err)
	})
	t.Run("rubbish panic", func(t *testing.T) {
		_, err := TreeFromBytesReadOnly([]byte("0123456789"))
		require.Error(t, err)
	})
	t.Run("level 1-1", func(t *testing.T) {
		sa := EmptyArray()
		for i := 0; i < howMany; i++ {
			sa.MustPush(data[i])
		}
		st, err := TreeFromBytesReadOnly(sa.Bytes())
		require.NoError(t, err)
		t.Logf("ser len = %d bytes (%d x uint16)", len(sa.Bytes()), howMany)
		for i := 0; i < howMany; i++ {
			var tmp []byte
			tmp, err = st.BytesAtPath(Path(byte(i)))
			require.NoError(t, err)
			require.EqualValues(t, uint16(i), binary.BigEndian.Uint16(tmp))
		}
		_, err = st.BytesAtPath(Path(howMany))
		require.Error(t, err)
	})
	t.Run("tree from trees", func(t *testing.T) {
		sa1 := EmptyArray()
		for i := 0; i < 2; i++ {
			sa1.MustPush(data[i])
		}
		st1, err := TreeFromBytesReadOnly(sa1.Bytes())
		require.NoError(t, err)

		sa2 := EmptyArray()
		for i := 2 - 1; i >= 0; i-- {
			sa2.MustPush(data[i])
		}
		st2, err := TreeFromBytesReadOnly(sa2.Bytes())

		tr := TreeFromTreesReadOnly(st1, st2)
		require.NoError(t, err)

		tr1 := MakeArrayReadOnly(sa1, st2).AsTree()
		require.EqualValues(t, tr.Bytes(), tr1.Bytes())
	})
}

func BenchmarkAt(b *testing.B) {
	arr := EmptyArray()
	for i := 0; i < 100; i++ {
		arr.MustPush(bytes.Repeat([]byte{1}, i))
	}
	arrReadOnly := arr.MakeReadOnly()
	for i := 0; i < b.N; i++ {
		arrReadOnly.MustAt(10)
	}
}
