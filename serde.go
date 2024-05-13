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

	funCodes := make([]uint16, 0, len(lib.funByFunCode))
	for funCode := range lib.funByFunCode {
		funCodes = append(funCodes, funCode)
	}
	sort.Slice(funCodes, func(i, j int) bool {
		return funCodes[i] < funCodes[j]
	})
	for _, fc := range funCodes {
		lib.funByFunCode[fc].write(&buf)
	}
	return buf.Bytes()
}

func (fd *funDescriptor) write(w io.Writer) {
	var uint16Bin [2]byte
	// fun code
	binary.BigEndian.PutUint16(uint16Bin[:], fd.funCode)
	_, _ = w.Write(uint16Bin[:]) // 2 bytes
	// function name
	Assert(len(fd.sym) < 256, "EasyFL: len(fd.sym)<256")
	_, _ = w.Write([]byte{byte(len(fd.sym))})
	_, _ = w.Write([]byte(fd.sym))
	Assert(len(fd.bytecode) < 256*256, "EasyFL: len(fd.bytecode)<256*256")
	// bytecode (nil for embedded)
	binary.BigEndian.PutUint16(uint16Bin[:], uint16(len(fd.bytecode)))
	_, _ = w.Write(uint16Bin[:]) // 2 bytes
	_, _ = w.Write(fd.bytecode)
}

func (fd *funDescriptor) read(r io.Reader, lib *Library) error {
	var uint16Bin [2]byte
	var err error
	// fun code
	if _, err = r.Read(uint16Bin[:]); err != nil {
		return err
	}
	fd.funCode = binary.BigEndian.Uint16(uint16Bin[:])
	// function name
	var size1 [1]byte
	if _, err = r.Read(size1[:]); err != nil {
		return err
	}
	buf := make([]byte, size1[0])
	if _, err = r.Read(buf); err != nil {
		return err
	}
	fd.sym = string(buf)
	// bytecode
	if _, err = r.Read(uint16Bin[:]); err != nil {
		return err
	}
	lenBytecode := binary.BigEndian.Uint16(uint16Bin[:])
	if lenBytecode > 0 {
		// extension
		fd.bytecode = make([]byte, lenBytecode)
		if _, err = r.Read(fd.bytecode); err != nil {
			return err
		}
		if fd.evalFun, err = lib.evalFunctionForBytecode(fd.sym, fd.bytecode); err != nil {
			return err
		}
	} else {
		// embedded
		var fi *funInfo
		if fi, err = lib.functionByName(fd.sym); err != nil {
			return err
		}
		if fd.evalFun, fd.requiredNumParams, _, err = lib.functionByCode(fi.FunCode); err != nil {
			return fmt.Errorf("can't find embedded function '%s' with code %d: %w", fi.Sym, fi.FunCode, err)
		}
	}
	return nil
}
