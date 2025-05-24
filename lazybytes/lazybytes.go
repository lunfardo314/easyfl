// Package lazybytes is a way to treat byte data as serialized arrays or, recursively, as trees of byte slices
// It is used for fast, safe and uniform serialization/deserialization in 'lazy' way: the bytes are only deserialized
// when there's a need to access element of the array or a tree
// The read-only lazy array and tree are thread safe. Non-read only are not thread safe
// It is used for the (de)serialization of Proxima transactions into the tree form, where every element (a byte slice)
// can be accessed with a path of indices (bytes)
package lazybytes

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"

	"github.com/lunfardo314/easyfl/easyfl_util"
)

// TODO rewrite and optimize package
//  - []uint16 index instead of [][]byte in 'parsed'
//  - take into account that almost all lazy arrays are readonly nad with max 256 elements
//  - get rid of mutex in the readonly mode
//  - get rid of unnecessary functions

// ArrayEditable can be interpreted two ways:
// - as byte slice
// - as a serialized append-only array of up to 255 byte slices
// Serialization cached and optimized by analyzing the maximum length of the data element
// if readOnly == false NOT THREAD_SAFE!!!
// if readOnly == true, it is thread safe

type (
	ArrayEditable struct {
		elements       [][]byte
		maxNumElements int
	}

	_slice struct {
		from uint32
		to   uint32
	}
	ArrayReadOnly struct {
		bytes        []byte
		index        []_slice
		numSizeBytes byte
	}
)

type lenPrefixType uint16

// a prefix of the serialized slice array is two bytes interpreted as uint16 big-endian
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
	arrayLenMask = ^dataLenMask
	maxArrayLen  = int(arrayLenMask) // 16383

	emptyArrayPrefix = lenPrefixType(0)
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
	s := uint16(dl) & arrayLenMask
	return int(s)
}

func (dl lenPrefixType) Bytes() []byte {
	ret := make([]byte, 2)
	binary.BigEndian.PutUint16(ret, uint16(dl))
	return ret
}

func ArrayFromBytesReadOnly(data []byte, maxNumElements ...int) (*ArrayReadOnly, error) {
	mx := maxArrayLen
	if len(maxNumElements) > 0 {
		mx = maxNumElements[0]
	}
	index, dlBytes, err := parseArray(data, mx)
	if err != nil {
		return nil, fmt.Errorf("ArrayFromBytesReadOnly: %v", err)
	}
	return &ArrayReadOnly{
		bytes:        data,
		index:        index,
		numSizeBytes: dlBytes,
	}, nil
}

func ArrayFromBytesEditable(data []byte, maxNumElements ...int) (*ArrayEditable, error) {
	mx := maxArrayLen
	if len(maxNumElements) > 0 {
		mx = maxNumElements[0]
	}
	arr, err := ArrayFromBytesReadOnly(data, mx)
	if err != nil {
		return nil, fmt.Errorf("ArrayFromBytesEditable: %v", err)
	}
	elements := make([][]byte, arr.NumElements())
	arr.ForEach(func(i int, d []byte) bool {
		elements[i] = d
		return true
	})
	return &ArrayEditable{
		elements:       elements,
		maxNumElements: mx,
	}, nil
}

// EmptyArray by default mutable
func EmptyArray(maxNumElements ...int) *ArrayEditable {
	mx := maxArrayLen
	if len(maxNumElements) > 0 {
		mx = maxNumElements[0]
	}
	return &ArrayEditable{
		elements:       make([][]byte, 0, mx),
		maxNumElements: mx,
	}
}

func MakeArrayFromDataReadOnly(element ...[]byte) *ArrayReadOnly {
	ret := EmptyArray(len(element))
	for _, el := range element {
		ret.MustPush(el)
	}
	return ret.MakeReadOnly()
}

func MakeArrayReadOnly(element ...any) *ArrayReadOnly {
	ret := EmptyArray(len(element))
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
			panic(fmt.Errorf("lazyarray.Make: only '[]byte' and 'interface{Bytes() []byte}' types are allowed as arguments. Got %T", el))
		}
	}
	return ret.MakeReadOnly()
}

func (a *ArrayEditable) MakeReadOnly() *ArrayReadOnly {
	ret, err := ArrayFromBytesReadOnly(a.Bytes())
	easyfl_util.AssertNoError(err)
	return ret
}

func (a *ArrayEditable) MustPush(data []byte) int {
	easyfl_util.Assertf(len(a.elements) < a.maxNumElements, "ArrayEditable.MustPush: too many elements")
	a.elements = append(a.elements, data)
	return len(a.elements) - 1
}

func (a *ArrayEditable) PushUint32(v uint32) int {
	var vBin [4]byte
	binary.BigEndian.PutUint32(vBin[:], v)
	return a.MustPush(vBin[:])
}

func (a *ArrayEditable) PushUint64(v uint64) int {
	var vBin [8]byte
	binary.BigEndian.PutUint64(vBin[:], v)
	return a.MustPush(vBin[:])
}

// MustPutAtIdx puts data at index, panics if the array has no element at that index
func (a *ArrayEditable) MustPutAtIdx(idx byte, data []byte) {
	a.elements[idx] = data
}

// PutAtIdxWithPadding puts data at index, pads elements with nils if necessary
func (a *ArrayEditable) PutAtIdxWithPadding(idx byte, data []byte) {
	for int(idx) >= a.NumElements() {
		a.MustPush(nil)
	}
	a.MustPutAtIdx(idx, data)
}

func (a *ArrayReadOnly) MustAt(idx int) []byte {
	if a.numSizeBytes == 0 {
		prefix := lenPrefixType(binary.BigEndian.Uint16(a.bytes[:2]))
		easyfl_util.Assertf(idx+1 <= prefix.numElements(), "ArrayReadOnly.MustAt: index %d is out of range. Num elements: %d", idx, prefix.numElements())
		return nil
	}
	easyfl_util.Assertf(idx >= 0 && idx < a.NumElements(), "ArrayReadOnly.MustAt: index %d is out of range. Num elements: %d", idx, a.NumElements())
	return a.bytes[a.index[idx].from:a.index[idx].to]
}

func (a *ArrayReadOnly) ForEach(fun func(i int, data []byte) bool) {
	for i := 0; i < a.NumElements(); i++ {
		if !fun(i, a.MustAt(i)) {
			return
		}
	}
}

func (a *ArrayReadOnly) At(idx int) ([]byte, error) {
	if idx >= a.NumElements() {
		return nil, fmt.Errorf("ArrayReadOnly.At(%d): index is out of range. Num elements: %d", idx, a.NumElements())
	}
	return a.MustAt(idx), nil
}

func (a *ArrayReadOnly) String() string {
	ret := make([]string, a.NumElements())
	for i := range ret {
		ret[i] = easyfl_util.Fmt(a.MustAt(i))
	}
	return fmt.Sprintf("[%s]", strings.Join(ret, ","))
}

func (a *ArrayReadOnly) Parsed() [][]byte {
	ret := make([][]byte, a.NumElements())
	a.ForEach(func(i int, data []byte) bool {
		ret[i] = data
		return true
	})
	return ret
}

func (a *ArrayEditable) NumElements() int {
	return len(a.elements)
}

func (a *ArrayReadOnly) NumElements() int {
	prefix := lenPrefixType(binary.BigEndian.Uint16(a.bytes[:2]))
	return prefix.numElements()
}

func (a *ArrayReadOnly) Bytes() []byte {
	return a.bytes
}

func (a *ArrayEditable) Bytes() []byte {
	var buf bytes.Buffer
	err := encodeArray(a.elements, &buf)
	easyfl_util.AssertNoError(err)
	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())
	return ret
}

func (a *ArrayReadOnly) AsTree() *Tree {
	return &Tree{
		sa:       a,
		subtrees: make(map[byte]*Tree),
	}
}

func calcLenPrefix(data [][]byte) (lenPrefixType, error) {
	if len(data) > maxArrayLen {
		return 0, errors.New("too long data")
	}
	if len(data) == 0 {
		return emptyArrayPrefix, nil
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

//------------------------------------------------------------------------------

// Tree is a read-only interface to ArrayEditable, which is interpreted as a tree
type Tree struct {
	// bytes
	sa *ArrayReadOnly
	// cache of parsed subtrees
	subtrees     map[byte]*Tree
	subtreeMutex sync.RWMutex
}

type TreePath []byte

// MaxElementsLazyTree each node of the tree can have maximum 256 elements
const MaxElementsLazyTree = 256

func TreeFromBytesReadOnly(data []byte) (*Tree, error) {
	arr, err := ArrayFromBytesReadOnly(data, MaxElementsLazyTree)
	if err != nil {
		return nil, fmt.Errorf("TreeFromBytesReadOnly: %v", err)
	}
	return &Tree{
		sa:       arr,
		subtrees: make(map[byte]*Tree),
	}, nil
}

func TreeFromTreesReadOnly(trees ...*Tree) *Tree {
	easyfl_util.Assertf(len(trees) <= MaxElementsLazyTree, "can't be more than %d tree node elements", MaxElementsLazyTree)

	sa := EmptyArray(MaxElementsLazyTree)
	m := make(map[byte]*Tree)
	for i, tr := range trees {
		sa.MustPush(tr.Bytes())
		m[byte(i)] = tr
	}

	return &Tree{
		sa:       sa.MakeReadOnly(),
		subtrees: m,
	}
}

func Path(p ...any) TreePath {
	return easyfl_util.Concat(p...)
}

func (p TreePath) Bytes() []byte {
	return p
}

func (p TreePath) String() string {
	return fmt.Sprintf("%v", []byte(p))
}

func (p TreePath) Hex() string {
	return hex.EncodeToString(p.Bytes())
}

// Bytes recursively update bytes in the tree from leaves
func (st *Tree) Bytes() []byte {
	return st.sa.Bytes()
}

// takes from the cache or creates a subtree
func (st *Tree) getSubtree(idx byte) (*Tree, error) {
	st.subtreeMutex.RLock()
	defer st.subtreeMutex.RUnlock()

	ret, ok := st.subtrees[idx]
	if ok {
		return ret, nil
	}
	bin, err := st.sa.At(int(idx))
	if err != nil {
		return nil, fmt.Errorf("getSubtree: %v", err)
	}
	ret, err = TreeFromBytesReadOnly(bin)
	if err != nil {
		return nil, fmt.Errorf("getSubtree: %v", err)
	}
	st.subtrees[idx] = ret
	return ret, nil
}

func (st *Tree) Subtree(path TreePath) (*Tree, error) {
	if len(path) == 0 {
		return st, nil
	}
	subtree, err := st.getSubtree(path[0])
	if err != nil {
		return nil, err
	}
	if len(path) == 1 {
		return subtree, nil
	}
	ret, err := subtree.Subtree(path[1:])
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// BytesAtPath returns serialized for of the element at path
func (st *Tree) BytesAtPath(path TreePath) ([]byte, error) {
	if len(path) == 0 {
		return st.Bytes(), nil
	}
	if len(path) == 1 {
		return st.sa.At(int(path[0]))
	}
	subtree, err := st.getSubtree(path[0])
	if err != nil {
		return nil, err
	}
	return subtree.BytesAtPath(path[1:])
}

// NumElements returns the size of the array at the end of the path
func (st *Tree) NumElements(path TreePath) (int, error) {
	s, err := st.Subtree(path)
	if err != nil {
		return 0, err
	}
	return s.sa.NumElements(), nil
}

func (st *Tree) ForEach(fun func(i byte, data []byte) bool, path TreePath) error {
	sub, err := st.Subtree(path)
	if err != nil {
		return err
	}
	sub.sa.ForEach(func(i int, data []byte) bool {
		return fun(byte(i), data)
	})
	return nil
}

func (st *Tree) ForEachIndex(fun func(i byte) bool, path TreePath) error {
	n, err := st.NumElements(path)
	if err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		if !fun(byte(i)) {
			return nil
		}
	}
	return nil
}
