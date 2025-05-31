package tuples

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/rand"
	"sync"
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

func TestTupleSemantics(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		_, err := TupleFromBytes(nil)
		require.Error(t, err)
	})
	t.Run("empty", func(t *testing.T) {
		ls := EmptyTupleEditable()
		require.EqualValues(t, []byte{0, 0}, ls.Bytes())

		require.EqualValues(t, 0, ls.NumElements())
	})
	t.Run("serialize all nil", func(t *testing.T) {
		ls := EmptyTupleEditable()
		ls.MustPush(nil)
		ls.MustPush(nil)
		ls.MustPush(nil)
		require.EqualValues(t, 3, ls.NumElements())
		lsBin := ls.Bytes()
		require.EqualValues(t, []byte{byte(dataLenBytes0), 3}, lsBin)
		lsBack, err := TupleFromBytes(lsBin)
		require.NoError(t, err)
		require.EqualValues(t, 3, ls.NumElements())
		lsBack.ForEach(func(i int, d []byte) bool {
			require.EqualValues(t, 0, len(d))
			return true
		})
	})
	t.Run("serialize some nil", func(t *testing.T) {
		ls := EmptyTupleEditable()
		ls.MustPush(nil)
		ls.MustPush(nil)
		ls.MustPush([]byte("ab"))
		ls.MustPush(nil)
		ls.MustPush([]byte("1234567890"))
		require.EqualValues(t, 5, ls.NumElements())
		lsBin := ls.Bytes()
		lsBack, err := TupleFromBytes(lsBin)
		require.NoError(t, err)
		require.EqualValues(t, 5, lsBack.NumElements())
		require.EqualValues(t, 0, len(lsBack.MustAt(0)))
		require.EqualValues(t, 0, len(lsBack.MustAt(1)))
		require.EqualValues(t, []byte("ab"), lsBack.MustAt(2))
		require.EqualValues(t, 0, len(lsBack.MustAt(3)))
		require.EqualValues(t, []byte("1234567890"), lsBack.MustAt(4))
	})
	t.Run("deserialize rubbish", func(t *testing.T) {
		ls := EmptyTupleEditable()
		ls.MustPush(data[17])
		lsBin := ls.Bytes()
		lsBack, err := TupleFromBytes(lsBin)
		require.NoError(t, err)
		require.True(t, bytes.Equal(lsBin, lsBack.Bytes()))

		require.NotPanics(t, func() {
			require.EqualValues(t, data[17], ls.Tuple().MustAt(0))
		})
		lsBinWrong := append(lsBin, 1, 2, 3)
		_, err = TupleFromBytes(lsBinWrong)
		require.Error(t, err)
	})
	t.Run("push+boundaries", func(t *testing.T) {
		ls := EmptyTupleEditable(1000)
		require.NotPanics(t, func() {
			ls.MustPush(data[17])
		})
		require.EqualValues(t, data[17], ls.Tuple().MustAt(0))
		require.EqualValues(t, 1, ls.NumElements())
		ser := ls.Bytes()
		lsBack, err := TupleFromBytes(ser)
		require.NoError(t, err)
		require.EqualValues(t, 1, lsBack.NumElements())
		require.EqualValues(t, ls.Tuple().MustAt(0), lsBack.MustAt(0))
		require.Panics(t, func() {
			ls.Tuple().MustAt(1)
		})
		require.Panics(t, func() {
			lsBack.MustAt(100)
		})
	})
	t.Run("too long", func(t *testing.T) {
		require.NotPanics(t, func() {
			ls := EmptyTupleEditable()
			ls.MustPush(bytes.Repeat(data[0], 256))
		})
		require.NotPanics(t, func() {
			ls := EmptyTupleEditable()
			ls.MustPush(bytes.Repeat(data[0], 257))
		})
		require.NotPanics(t, func() {
			ls := EmptyTupleEditable()
			for i := 0; i < 255; i++ {
				ls.MustPush(data[0])
			}
		})
		require.Panics(t, func() {
			ls := EmptyTupleEditable(300)
			for i := 0; i < 301; i++ {
				ls.MustPush(data[0])
			}
		})
		require.Panics(t, func() {
			ls := EmptyTupleEditable()
			for i := 0; i < math.MaxUint16+1; i++ {
				ls.MustPush(data[0])
			}
		})
	})
	t.Run("serialize prefix", func(t *testing.T) {
		da, err := TupleFromBytes([]byte{byte(dataLenBytes0), 0})
		require.NoError(t, err)
		bin := da.Bytes()
		daBack, err := TupleFromBytes(bin)
		require.NoError(t, err)
		require.EqualValues(t, 0, daBack.NumElements())
		require.EqualValues(t, bin, daBack.Bytes())

		da, err = TupleFromBytes(emptyTuplePrefix.Bytes())
		require.NoError(t, err)
		bin = da.Bytes()
		daBack, err = TupleFromBytes(bin)
		require.NoError(t, err)
		require.EqualValues(t, 0, daBack.NumElements())
		require.EqualValues(t, bin, daBack.Bytes())

		da, err = TupleFromBytes([]byte{byte(dataLenBytes0), 17})
		require.NoError(t, err)
		bin = da.Bytes()
		daBack, err = TupleFromBytes(bin)
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
		ls := EmptyTupleEditable()
		for i := 0; i < 100; i++ {
			ls.MustPush(bytes.Repeat(data[0], 100))
		}
		lsBack, err := TupleFromBytes(ls.Bytes())
		require.NoError(t, err)
		require.EqualValues(t, ls.NumElements(), lsBack.NumElements())
		for i := 0; i < 100; i++ {
			require.EqualValues(t, ls.Tuple().MustAt(i), lsBack.MustAt(i))
		}
	})
	t.Run("serialization long 1", func(t *testing.T) {
		ls := EmptyTupleEditable()
		for i := 0; i < 100; i++ {
			ls.MustPush(bytes.Repeat(data[0], 2000))
		}
		daBytes := ls.Bytes()
		daBack, err := TupleFromBytes(daBytes)
		require.NoError(t, err)
		require.EqualValues(t, ls.NumElements(), daBack.NumElements())
		for i := 0; i < 100; i++ {
			require.EqualValues(t, ls.Tuple().MustAt(i), daBack.MustAt(i))
		}
	})
	t.Run("serialization long 2", func(t *testing.T) {
		ls1 := EmptyTupleEditable()
		for i := 0; i < 100; i++ {
			ls1.MustPush(bytes.Repeat(data[0], 2000))
		}
		ls2 := EmptyTupleEditable()
		for i := 0; i < 100; i++ {
			ls2.MustPush(bytes.Repeat(data[0], 2000))
		}
		for i := 0; i < 100; i++ {
			require.EqualValues(t, ls1.Tuple().MustAt(i), ls2.Tuple().MustAt(i))
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
		st, err := TreeFromBytesReadOnly(EmptyTupleEditable().Bytes())
		require.NoError(t, err)
		_, err = st.BytesAtPath(Path(1))
		require.Error(t, err)
	})
	t.Run("rubbish panic", func(t *testing.T) {
		_, err := TreeFromBytesReadOnly([]byte("0123456789"))
		require.Error(t, err)
	})
	t.Run("level 1-1", func(t *testing.T) {
		sa := EmptyTupleEditable()
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
		sa1 := EmptyTupleEditable()
		for i := 0; i < 2; i++ {
			sa1.MustPush(data[i])
		}
		st1, err := TreeFromBytesReadOnly(sa1.Bytes())
		require.NoError(t, err)

		sa2 := EmptyTupleEditable()
		for i := 2 - 1; i >= 0; i-- {
			sa2.MustPush(data[i])
		}
		st2, err := TreeFromBytesReadOnly(sa2.Bytes())

		tr := TreeFromTreesReadOnly(st1, st2)
		require.NoError(t, err)

		tr1 := MakeTupleFromSerializableElements(sa1, st2).AsTree()
		require.EqualValues(t, tr.Bytes(), tr1.Bytes())
	})
}

func TestTreeConcurrency(t *testing.T) {
	treeBytes := buildTree(7)
	tree, err := TreeFromBytesReadOnly(treeBytes)
	require.NoError(t, err)
	routine := func(wg *sync.WaitGroup) {
		for i := 0; i < 1000; i++ {
			_, _ = tree.BytesAtPath(randomPath(8))
		}
		wg.Done()
	}

	const nRoutines = 100
	var wg sync.WaitGroup
	wg.Add(nRoutines)
	for i := 0; i < nRoutines; i++ {
		go routine(&wg)
	}
	wg.Wait()
}

func randomArray(n int) []byte {
	arr := EmptyTupleEditable(n)
	for i := 0; i < n; i++ {
		arr.MustPushUint64(rand.Uint64())
	}
	return arr.Bytes()
}

func randomPath(depth int) []byte {
	ret := make([]byte, depth)
	for i := 0; i < depth; i++ {
		ret[i] = byte(rand.Intn(2))
	}
	return ret
}

// builds a tree with 2^n leaves
func buildTree(n int, leaves ...[]byte) []byte {
	if n == 0 {
		return randomArray(7)
	}
	return MakeTupleFromDataElements(buildTree(n-1), buildTree(n-1)).Bytes()
}

func BenchmarkAt(b *testing.B) {
	arr := EmptyTupleEditable()
	for i := 0; i < 100; i++ {
		arr.MustPush(bytes.Repeat([]byte{1}, i))
	}
	arrReadOnly := arr.Tuple()
	for i := 0; i < b.N; i++ {
		arrReadOnly.MustAt(10)
	}
}

func BenchmarkAtPath(b *testing.B) {
	treeBytes := buildTree(7)
	tree, _ := TreeFromBytesReadOnly(treeBytes)
	for i := 0; i < b.N; i++ {
		_, _ = tree.BytesAtPath(randomPath(8))
	}
}
