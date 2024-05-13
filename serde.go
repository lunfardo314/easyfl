package easyfl

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

func (lib *Library) read(r io.Reader) (err error) {
	var numEmbeddedShort, numEmbeddedLong, numExtended uint16
	if err = binary.Read(r, binary.BigEndian, &numEmbeddedShort); err != nil {
		return err
	}
	if err = binary.Read(r, binary.BigEndian, &numEmbeddedLong); err != nil {
		return err
	}
	if err = binary.Read(r, binary.BigEndian, &numExtended); err != nil {
		return err
	}
	expected := numEmbeddedShort + numEmbeddedLong + numExtended

	for lib.NumFunctions() < expected {
		fd := funDescriptor{}
		if err = fd.read(r, lib); err != nil {
			return
		}
		lib.addDescriptor(&fd)
	}
	return nil
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

func (fd *funDescriptor) read(r io.Reader, lib *Library) (err error) {
	// fun code
	if err = binary.Read(r, binary.BigEndian, &fd.funCode); err != nil {
		return err
	}
	// required number of parameters
	var np byte
	if err = binary.Read(r, binary.BigEndian, &np); err != nil {
		return err
	}
	fd.requiredNumParams = int(np)
	if np == 0xff {
		fd.requiredNumParams = -1
	}
	// function name
	var size byte
	if err = binary.Read(r, binary.BigEndian, &size); err != nil {
		return err
	}
	buf := make([]byte, size)
	if _, err = r.Read(buf); err != nil {
		return err
	}
	fd.sym = string(buf)
	// bytecode
	if err = binary.Read(r, binary.BigEndian, &size); err != nil {
		return err
	}
	if size > 0 {
		// extension
		fd.bytecode = make([]byte, size)
		if _, err = r.Read(fd.bytecode); err != nil {
			return err
		}
		if fd.evalFun, err = lib.evalFunctionForBytecode(fd.sym, fd.bytecode); err != nil {
			return err
		}
	} else {
		// embedded
		var sym string
		if fd.evalFun, fd.requiredNumParams, sym, err = lib.functionByCode(fd.funCode); err != nil {
			return fmt.Errorf("can't find embedded function '%s' with code %d: %w", fd.sym, fd.funCode, err)
		}
		if sym != fd.sym {
			return fmt.Errorf("embedded function with code %d: expected name '%s', got '%s'", fd.funCode, fd.sym, sym)
		}
	}
	return nil
}
