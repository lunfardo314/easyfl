package tuples

import (
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/lunfardo314/easyfl/easyfl_util"
)

// Tree is a read-only interface to Tuple, which is interpreted as a tree
// It is deserialized in a lazy way, i.e. subtrees are deserialized into tuples
// only when accessed
type Tree struct {
	// bytes
	sa *Tuple
	// cache of parsed subtrees
	subtrees map[byte]*Tree
	// to protect lazy deserialization in multithread situations
	subtreeMutex sync.RWMutex
}

type TreePath []byte

// MaxElementsTree each node of the tree can have maximum of 256 elements
const MaxElementsTree = 256

func TreeFromBytesReadOnly(data []byte) (*Tree, error) {
	arr, err := TupleFromBytes(data, MaxElementsTree)
	if err != nil {
		return nil, fmt.Errorf("TreeFromBytesReadOnly: %v", err)
	}
	return &Tree{
		sa:       arr,
		subtrees: make(map[byte]*Tree),
	}, nil
}

func TreeFromTreesReadOnly(trees ...*Tree) *Tree {
	easyfl_util.Assertf(len(trees) <= MaxElementsTree, "can't be more than %d tree node elements", MaxElementsTree)

	sa := EmptyTupleEditable(MaxElementsTree)
	m := make(map[byte]*Tree)
	for i, tr := range trees {
		sa.MustPush(tr.Bytes())
		m[byte(i)] = tr
	}

	return &Tree{
		sa:       sa.Tuple(),
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

func (st *Tree) _getCachedSubtree(idx byte) *Tree {
	st.subtreeMutex.RLock()
	defer st.subtreeMutex.RUnlock()

	return st.subtrees[idx]
}

// takes from the cache or creates a subtree
func (st *Tree) getSubtree(idx byte) (*Tree, error) {
	if ret := st._getCachedSubtree(idx); ret != nil {
		return ret, nil
	}

	st.subtreeMutex.Lock()
	defer st.subtreeMutex.Unlock()

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

// BytesAtPath returns serialized for of the element at 'path'
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

func (st *Tree) MustBytesAtPath(path TreePath) []byte {
	ret, err := st.BytesAtPath(path)
	easyfl_util.AssertNoError(err)
	return ret
}

// NumElementsAtPath returns the size of the array at the end of the path
func (st *Tree) NumElementsAtPath(path TreePath) (int, error) {
	s, err := st.Subtree(path)
	if err != nil {
		return 0, err
	}
	return s.sa.NumElements(), nil
}

func (st *Tree) MustNumElementsAtPath(path TreePath) int {
	ret, err := st.NumElementsAtPath(path)
	easyfl_util.AssertNoError(err)
	return ret
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
	n, err := st.NumElementsAtPath(path)
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
