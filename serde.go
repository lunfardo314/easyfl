package easyfl

import (
	"bytes"
	"encoding/binary"
	"io"
	"sort"

	"golang.org/x/crypto/blake2b"
)

func (lib *Library) LibraryHash() [32]byte {
	ret := blake2b.Sum256(lib.libraryBytes())
	return ret
}

func (lib *Library) libraryBytes() []byte {
	var buf bytes.Buffer

	lib.write(&buf)
	return buf.Bytes()
}

// currently only serialization is implemented. Deserialization is not.
// Serialization is only used for calculating library hash, to support library upgrades

func (lib *Library) write(w io.Writer) {
	_ = binary.Write(w, binary.BigEndian, lib.numEmbeddedShort)
	_ = binary.Write(w, binary.BigEndian, lib.numEmbeddedLong)
	_ = binary.Write(w, binary.BigEndian, lib.numExtended)

	funCodes := make([]uint16, 0, len(lib.funByFunCode))
	for funCode := range lib.funByFunCode {
		funCodes = append(funCodes, funCode)
	}
	sort.Slice(funCodes, func(i, j int) bool {
		return funCodes[i] < funCodes[j]
	})
	for _, fc := range funCodes {
		lib.funByFunCode[fc].write(w)
	}
}

func (fd *funDescriptor) write(w io.Writer) {
	// fun code
	_ = binary.Write(w, binary.BigEndian, fd.funCode)

	// required number of parameters
	np := byte(fd.requiredNumParams)
	if fd.requiredNumParams < 0 {
		np = 0xff
	}
	_ = binary.Write(w, binary.BigEndian, np)

	// function name
	Assert(len(fd.sym) < 256, "EasyFL: len(fd.sym)<256")
	_, _ = w.Write([]byte{byte(len(fd.sym))})
	_, _ = w.Write([]byte(fd.sym))
	Assert(len(fd.bytecode) < 256*256, "EasyFL: len(fd.bytecode)<256*256")
	// bytecode (nil for embedded)
	_ = binary.Write(w, binary.BigEndian, uint16(len(fd.bytecode)))
	_, _ = w.Write(fd.bytecode)
}
