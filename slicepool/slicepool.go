// Package slicepool implements optimized heap allocation mechanism performance and GC-wise
// One slice pool can be imagined as one heap of byte slices, where each slice is allocated and never garbage collected.
// With each call Alloc memory occupied by pool only grows util pool is disposed.
// Dispose pool means all memory occupied by slices in pool is returned to sync pools and nullified.
// So, it is not memory safe mechanism because after pool is disposed, slices allocated in it should not be used
//
// In EasyFL all interim byte slices which occur during evaluation of the expression
// will be allocated in the slice pool incrementally. When evaluation is finished, final value is copied into
// the slice allocated with make([]byte, ..) and whole pool is disposed in one operation
package slicepool

import "sync"

const segmentSize = 1022

type (
	segment struct {
		array   [segmentSize]byte
		allocAt uint16
	}
	SlicePool struct {
		mutex sync.Mutex
		segs  []*segment
	}
)

var (
	mpools      sync.Pool
	segments    sync.Pool
	disableOnce sync.Once
	enabled     = true
)

func Disable() {
	disableOnce.Do(func() {
		enabled = false
	})
}

func New() (ret *SlicePool) {
	if !enabled {
		return nil
	}
	if p := mpools.Get(); p != nil {
		ret = p.(*SlicePool)
	} else {
		ret = &SlicePool{
			segs: make([]*segment, 0),
		}
	}
	return
}

// Dispose not thread safe!
func (p *SlicePool) Dispose() {
	if p == nil {
		return
	}
	for i := range p.segs {
		p.segs[i].dispose()
		p.segs[i] = nil
	}
	p.segs = p.segs[:0]
	mpools.Put(p)
}

// Alloc thread safe
func (p *SlicePool) Alloc(size uint16) (ret []byte) {
	if p == nil {
		return make([]byte, size)
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	if size > segmentSize {
		return make([]byte, size)
	}
	var seg *segment
	for i := range p.segs {
		if p.segs[i].allocAt+size < segmentSize {
			seg = p.segs[i]
			break
		}
	}
	if seg == nil {
		if s := segments.Get(); s != nil {
			seg = s.(*segment)
		} else {
			seg = new(segment)
		}
		p.segs = append(p.segs, seg)
	}
	ret = seg.array[seg.allocAt : seg.allocAt+size]
	seg.allocAt += size
	return
}

func (p *SlicePool) AllocData(data ...byte) (ret []byte) {
	ret = p.Alloc(uint16(len(data)))
	copy(ret, data)
	return
}

func (s *segment) dispose() {
	*s = segment{}
	segments.Put(s)
}
