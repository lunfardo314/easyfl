package easyfl

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
)

type (
	LibraryYAMLAble struct {
		Hash string `yaml:"hash"`
	}

	FuncDescriptor struct {
		Sym      string `yaml:"sym"`
		FunCode  uint16 `yaml:"funCode"`
		Embedded bool   `yaml:"embedded"`
		Short    bool   `yaml:"short"`
		NumArgs  int    `yaml:"numArgs"`
		Source   string `yaml:"source"`
		Bytecode string `yaml:"bytecode"`
	}
)

func (lib *Library) ToYAML() []byte {
	var buf bytes.Buffer

	prn(&buf, "# EasyFL library\n")
	prn(&buf, "name: base\n")
	h := lib.LibraryHash()
	prn(&buf, "hash: %s\n", hex.EncodeToString(h[:]))
	prn(&buf, "num_embedded_short: %d\n", lib.numEmbeddedShort)
	prn(&buf, "num_embedded_long: %d\n", lib.numEmbeddedLong)
	prn(&buf, "num_extended: %d\n", lib.numExtended)

	embedded := make([]*FuncDescriptor, 0)
	for sym := range lib.funByName {
		dscr := lib.findByName(sym)
		if !dscr.Embedded {
			continue
		}
		embedded = append(embedded, dscr)
	}
	sort.Slice(embedded, func(i, j int) bool {
		return embedded[i].FunCode < embedded[j].FunCode
	})

	prn(&buf, "functions:\n")

	prn(&buf, "# ------------ embedded functions\n")
	for _, dscr := range embedded {
		prnFuncDescription(&buf, dscr)
	}

	extended := make([]*FuncDescriptor, 0)
	for sym := range lib.funByName {
		dscr := lib.findByName(sym)
		if dscr.Embedded {
			continue
		}
		extended = append(extended, dscr)
	}
	sort.Slice(extended, func(i, j int) bool {
		return extended[i].FunCode < extended[j].FunCode
	})

	prn(&buf, "# ------------ extended functions\n")
	for _, dscr := range extended {
		prnFuncDescription(&buf, dscr)
	}

	return buf.Bytes()
}

const (
	ident  = "   "
	ident2 = ident + ident
)

func prn(w io.Writer, format string, a ...any) {
	_, err := fmt.Fprintf(w, format, a...)
	AssertNoError(err)
}

func prnFuncDescription(w io.Writer, f *FuncDescriptor) {
	var b2 [2]byte
	binary.BigEndian.PutUint16(b2[:], f.FunCode)
	inShort := "extended"
	if f.Embedded {
		if f.Short {
			inShort = "embedded short"
		} else {
			inShort = "embedded long"
		}
	}
	argsStr := fmt.Sprintf("args: %d", f.NumArgs)
	if f.NumArgs < 0 {
		argsStr = "varargs"
	}
	prn(w, "# func '%s', funCode: %d (hex 0x%s), %s, %s)\n", f.Sym, f.FunCode, hex.EncodeToString(b2[:]), inShort, argsStr)
	prn(w, ident+"-\n")
	prn(w, ident2+"funCode: %d\n", f.FunCode)
	prn(w, ident2+"sym: %s\n", f.Sym)
	prn(w, ident2+"numArgs: %d\n", f.NumArgs)
	if f.Embedded {
		prn(w, ident2+"embedded: true\n")
	}
	if f.Short {
		prn(w, ident2+"short: true\n")
	}
	if !f.Embedded {
		prn(w, ident2+"bytecode: %s\n", f.Bytecode)
	}
}

func (lib *Library) findByName(sym string) *FuncDescriptor {
	fi, err := lib.functionByName(sym)
	AssertNoError(err)
	dscr := lib.funByFunCode[fi.FunCode]

	return &FuncDescriptor{
		Sym:      dscr.sym,
		FunCode:  dscr.funCode,
		Embedded: fi.IsEmbedded,
		Short:    fi.IsShort,
		NumArgs:  dscr.requiredNumParams,
		Source:   "",
		Bytecode: hex.EncodeToString(dscr.bytecode),
	}

}
