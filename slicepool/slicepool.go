package slicepool

import "sync"

const segmentSize = 1022

type (
	segment struct {
		array   [segmentSize]byte
		allocAt uint16
	}
	SlicePool []*segment
)

var (
	mpools   sync.Pool
	segments sync.Pool
)

func New() (ret *SlicePool) {
	if p := mpools.Get(); p != nil {
		ret = p.(*SlicePool)
	} else {
		ret = new(SlicePool)
	}
	return
}

func (p SlicePool) Dispose() {
	for i := range p {
		p[i].dispose()
		p[i] = nil
	}
	mpools.Put(p[:0])
}

func (p SlicePool) Alloc(size uint16) (ret []byte) {
	if size > segmentSize {
		return make([]byte, size)
	}
	var seg *segment
	for i := range p {
		if p[i].allocAt+size < segmentSize {
			seg = p[i]
			break
		}
	}
	if seg == nil {
		if s := segments.Get(); s != nil {
			seg = s.(*segment)
		} else {
			seg = new(segment)
		}
		p = append(p, seg)
	}
	ret = seg.array[seg.allocAt : seg.allocAt+size]
	seg.allocAt += size
	return
}

func (s *segment) dispose() {
	*s = segment{}
	segments.Put(s)
}
