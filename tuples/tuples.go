// Package tuples is a way to treat byte data as serialized arrays or, recursively, as trees of byte slices
// It is used for fast, safe and uniform serialization/deserialization
package tuples

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/lunfardo314/easyfl/easyfl_util"
)

type (
	TupleEditable struct {
		elements       [][]byte
		maxNumElements int
	}

	_slice struct {
		from uint32
		to   uint32
	}
	Tuple struct {
		bytes        []byte
		index        []_slice
		numSizeBytes byte
	}
)

type lenPrefixType uint16

// a prefix of the serialized tuple is two bytes interpreted as uint16 big-endian
// The highest 2 bits are interpreted as 4 possible dataLenBytes (0, 1, 2 and 4 bytes)
// The rest is interpreted as uint16 as the number of elements in the array. Max 2^14-1 =
// 0 byte with ArrayMaxData code, the number of bits reserved for element data length
// 1 byte is the number of elements in the array
const (
	dataLenBytes0  = uint16(0x00) << 14
	dataLenBytes8  = uint16(0x01) << 14
	dataLenBytes16 = uint16(0x02) << 14
	dataLenBytes32 = uint16(0x03) << 14

	dataLenMask  = uint16(0x03) << 14
	tupleLenMask = ^dataLenMask
	maxTupleLen  = int(tupleLenMask) // 16383

	emptyTuplePrefix = lenPrefixType(0)
)

func (dl lenPrefixType) dataLenBytes() int {
	m := uint16(dl) & dataLenMask
	switch m {
	case dataLenBytes0:
		return 0
	case dataLenBytes8:
		return 1
	case dataLenBytes16:
		return 2
	case dataLenBytes32:
		return 4
	}
	panic("very bad")
}

func (dl lenPrefixType) numElements() int {
	s := uint16(dl) & tupleLenMask
	return int(s)
}

func (dl lenPrefixType) Bytes() []byte {
	ret := make([]byte, 2)
	binary.BigEndian.PutUint16(ret, uint16(dl))
	return ret
}

func TupleFromBytes(data []byte, maxNumElements ...int) (*Tuple, error) {
	mx := maxTupleLen
	if len(maxNumElements) > 0 {
		mx = maxNumElements[0]
	}
	index, dlBytes, err := parseArray(data, mx)
	if err != nil {
		return nil, fmt.Errorf("TupleFromBytes: %v", err)
	}
	return &Tuple{
		bytes:        data,
		index:        index,
		numSizeBytes: dlBytes,
	}, nil
}

func TupleFromBytesEditable(data []byte, maxNumElements ...int) (*TupleEditable, error) {
	mx := maxTupleLen
	if len(maxNumElements) > 0 {
		mx = maxNumElements[0]
	}
	arr, err := TupleFromBytes(data, mx)
	if err != nil {
		return nil, fmt.Errorf("ArrayFromBytesEditable: %v", err)
	}
	elements := make([][]byte, arr.NumElements())
	arr.ForEach(func(i int, d []byte) bool {
		elements[i] = d
		return true
	})
	return &TupleEditable{
		elements:       elements,
		maxNumElements: mx,
	}, nil
}

// EmptyTupleEditable by default mutable
func EmptyTupleEditable(maxNumElements ...int) *TupleEditable {
	mx := maxTupleLen
	if len(maxNumElements) > 0 {
		mx = maxNumElements[0]
	}
	return &TupleEditable{
		elements:       make([][]byte, 0, mx),
		maxNumElements: mx,
	}
}

func MakeTupleFromDataElements(element ...[]byte) *Tuple {
	ret := EmptyTupleEditable(len(element))
	for _, el := range element {
		ret.MustPush(el)
	}
	return ret.Tuple()
}

func MakeTupleFromSerializableElements(element ...any) *Tuple {
	ret := EmptyTupleEditable(len(element))
	for _, el := range element {
		if el == nil {
			ret.MustPush(nil)
			continue
		}
		switch e := el.(type) {
		case []byte:
			ret.MustPush(e)
		case interface{ Bytes() []byte }:
			ret.MustPush(e.Bytes())
		default:
			panic(fmt.Errorf("MakeTupleFromSerializableElements: only '[]byte' and 'interface{Bytes() []byte}' types are allowed as arguments. Got %T", el))
		}
	}
	return ret.Tuple()
}

func (a *TupleEditable) Tuple() *Tuple {
	ret, err := TupleFromBytes(a.Bytes())
	easyfl_util.AssertNoError(err)
	return ret
}

func (a *TupleEditable) MustPush(data []byte) int {
	easyfl_util.Assertf(len(a.elements) < a.maxNumElements, "TupleEditable.MustPush: too many elements")
	a.elements = append(a.elements, data)
	return len(a.elements) - 1
}

func (a *TupleEditable) MustPushUint32(v uint32) int {
	var vBin [4]byte
	binary.BigEndian.PutUint32(vBin[:], v)
	return a.MustPush(vBin[:])
}

func (a *TupleEditable) MustPushUint64(v uint64) int {
	var vBin [8]byte
	binary.BigEndian.PutUint64(vBin[:], v)
	return a.MustPush(vBin[:])
}

// MustPutAtIdx puts data at index, panics if the array has no element at that index
func (a *TupleEditable) MustPutAtIdx(idx byte, data []byte) {
	a.elements[idx] = data
}

// MustPutAtIdxWithPadding puts data at index, pads elements with nils if necessary
func (a *TupleEditable) MustPutAtIdxWithPadding(idx byte, data []byte) {
	for int(idx) >= a.NumElements() {
		a.MustPush(nil)
	}
	a.MustPutAtIdx(idx, data)
}

func (a *Tuple) MustAt(idx int) []byte {
	if a.numSizeBytes == 0 {
		prefix := lenPrefixType(binary.BigEndian.Uint16(a.bytes[:2]))
		easyfl_util.Assertf(idx+1 <= prefix.numElements(), "Tuple.MustAt: index %d is out of range. Num elements: %d", idx, prefix.numElements())
		return nil
	}
	easyfl_util.Assertf(idx >= 0 && idx < a.NumElements(), "Tuple.MustAt: index %d is out of range. Num elements: %d", idx, a.NumElements())
	return a.bytes[a.index[idx].from:a.index[idx].to]
}

func (a *Tuple) ForEach(fun func(i int, data []byte) bool) {
	for i := 0; i < a.NumElements(); i++ {
		if !fun(i, a.MustAt(i)) {
			return
		}
	}
}

func (a *Tuple) At(idx int) ([]byte, error) {
	if idx >= a.NumElements() {
		return nil, fmt.Errorf("Tuple.At(%d): index is out of range. Num elements: %d", idx, a.NumElements())
	}
	return a.MustAt(idx), nil
}

func (a *Tuple) String() string {
	ret := make([]string, a.NumElements())
	for i := range ret {
		ret[i] = easyfl_util.Fmt(a.MustAt(i))
	}
	return fmt.Sprintf("[%s]", strings.Join(ret, ","))
}

func (a *Tuple) Parsed() [][]byte {
	ret := make([][]byte, a.NumElements())
	a.ForEach(func(i int, data []byte) bool {
		ret[i] = data
		return true
	})
	return ret
}

func (a *TupleEditable) NumElements() int {
	return len(a.elements)
}

func (a *Tuple) NumElements() int {
	prefix := lenPrefixType(binary.BigEndian.Uint16(a.bytes[:2]))
	return prefix.numElements()
}

func (a *Tuple) Bytes() []byte {
	return a.bytes
}

func (a *TupleEditable) Bytes() []byte {
	var buf bytes.Buffer
	err := encodeArray(a.elements, &buf)
	easyfl_util.AssertNoError(err)
	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())
	return ret
}

func (a *Tuple) AsTree() *Tree {
	return &Tree{
		sa:       a,
		subtrees: make(map[byte]*Tree),
	}
}

func calcLenPrefix(data [][]byte) (lenPrefixType, error) {
	if len(data) > maxTupleLen {
		return 0, errors.New("too long data")
	}
	if len(data) == 0 {
		return emptyTuplePrefix, nil
	}
	var dl uint16
	var t uint16
	for _, d := range data {
		t = dataLenBytes0
		switch {
		case len(d) > math.MaxUint32:
			return 0, errors.New("data can't be longer that MaxInt32")
		case len(d) > math.MaxUint16:
			t = dataLenBytes32
		case len(d) > math.MaxUint8:
			t = dataLenBytes16
		case len(d) > 0:
			t = dataLenBytes8
		}
		if dl < t {
			dl = t
		}
	}
	return lenPrefixType(dl | uint16(len(data))), nil
}

func writeData(data [][]byte, numDataLenBytes int, w io.Writer) error {
	if numDataLenBytes == 0 {
		return nil // all empty
	}
	for _, d := range data {
		switch numDataLenBytes {
		case 1:
			if _, err := w.Write([]byte{byte(len(d))}); err != nil {
				return err
			}
		case 2:
			var b [2]byte
			binary.BigEndian.PutUint16(b[:], uint16(len(d)))
			if _, err := w.Write(b[:]); err != nil {
				return err
			}
		case 4:
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(len(d)))
			if _, err := w.Write(b[:]); err != nil {
				return err
			}
		}
		if _, err := w.Write(d); err != nil {
			return err
		}
	}
	return nil
}

// decodeData forms index of elements in the data
func decodeData(data []byte, numDataLenBytes int, n int) ([]_slice, error) {
	if numDataLenBytes == 0 {
		return nil, nil
	}
	ret := make([]_slice, n)

	from := uint32(2)
	var sz, to uint32

	for i := range ret {
		switch numDataLenBytes {
		case 1:
			sz = uint32(data[from])
		case 2:
			sz = uint32(binary.BigEndian.Uint16(data[from : from+2]))
		case 4:
			sz = binary.BigEndian.Uint32(data[from : from+4])
		default:
			panic("wrong lenPrefixType value")
		}
		from += uint32(numDataLenBytes)
		to = from + sz
		if to > uint32(len(data)) {
			return nil, errors.New("serialization error: unexpected EOF")
		}
		ret[i] = _slice{
			from: from,
			to:   to,
		}
		from = to
	}
	if int(to) != len(data) {
		return nil, errors.New("serialization error: not all bytes were consumed")
	}
	return ret, nil
}

func encodeArray(data [][]byte, w io.Writer) error {
	prefix, err := calcLenPrefix(data)
	if err != nil {
		return err
	}
	if _, err = w.Write(prefix.Bytes()); err != nil {
		return err
	}
	return writeData(data, prefix.dataLenBytes(), w)
}

func parseArray(data []byte, maxNumElements int) ([]_slice, byte, error) {
	if len(data) < 2 {
		return nil, 0, errors.New("unexpected EOF")
	}
	prefix := lenPrefixType(binary.BigEndian.Uint16(data[:2]))
	if prefix.numElements() > maxNumElements {
		return nil, 0, fmt.Errorf("parseArray: number of elements in the prefix %d is larger than maxNumElements %d ",
			prefix.numElements(), maxNumElements)
	}
	dlBytes := prefix.dataLenBytes()
	arr, err := decodeData(data, dlBytes, prefix.numElements())
	if err != nil {
		return nil, 0, fmt.Errorf("parseArray: %v", err)
	}
	return arr, byte(dlBytes), nil
}
