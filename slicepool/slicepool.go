package slicepool

import "sync"

const segmentSize = 1022

type (
	segment struct {
		array   [segmentSize]byte
		allocAt uint16
	}
	SlicePool struct {
		segs []*segment
	}
)

var (
	mpools   sync.Pool
	segments sync.Pool
)

func New() (ret *SlicePool) {
	if p := mpools.Get(); p != nil {
		ret = p.(*SlicePool)
	} else {
		ret = &SlicePool{
			segs: make([]*segment, 0),
		}
	}
	return
}

func (p *SlicePool) Dispose() {
	for i := range p.segs {
		p.segs[i].dispose()
		p.segs[i] = nil
	}
	p.segs = p.segs[:0]
	mpools.Put(p)
}

func (p *SlicePool) Alloc(size uint16) (ret []byte) {
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

func (s *segment) dispose() {
	*s = segment{}
	segments.Put(s)
}
