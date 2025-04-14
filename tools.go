package easyfl

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type (
	LibraryFromYAML struct {
		Name      string                   `yaml:"name"`
		Hash      string                   `yaml:"hash"`
		Functions []FuncDescriptorYAMLable `yaml:"functions"`
	}

	FuncDescriptorYAMLable struct {
		Digest   string `yaml:"digest,omitempty"`
		Sym      string `yaml:"sym"`
		FunCode  uint16 `yaml:"funCode"`
		Embedded bool   `yaml:"embedded,omitempty"`
		Short    bool   `yaml:"short,omitempty"`
		NumArgs  int    `yaml:"numArgs"`
		Source   string `yaml:"source,omitempty"`
		Bytecode string `yaml:"bytecode,omitempty"`
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

	numEmbeddedShort := 0
	numEmbeddedLong := 0
	numExtended := 0

	functions := make([]*FuncDescriptorYAMLable, 0)
	for sym, fd := range lib.funByName {
		functions = append(functions, lib.funYAMLAbleByName(sym))
		isEmbedded, isShort := fd.isEmbeddedOrShort()
		if isEmbedded {
			if isShort {
				numEmbeddedShort++
			} else {
				numEmbeddedLong++
			}
		} else {
			numExtended++
		}
	}
	Assertf(numEmbeddedLong+numEmbeddedShort+numExtended == len(lib.funByName), "numEmbeddedLong+numEmbeddedShort+numExtended==len(lib.funByName)")
	Assertf(int(lib.numEmbeddedShort)-FirstEmbeddedShort == numEmbeddedShort, "int(lib.numEmbeddedShort)==numEmbeddedShort")
	Assertf(int(lib.numEmbeddedLong) == numEmbeddedLong, "int(lib.numEmbeddedLong)==numEmbeddedLong")
	Assertf(int(lib.numExtended) == numExtended, "int(lib.numExtended)==numExtended")

	sort.Slice(functions, func(i, j int) bool {
		return functions[i].FunCode < functions[j].FunCode
	})

	prn(&buf, "functions:\n")

	for _, dscr := range functions {
		prnFuncDescription(&buf, dscr)
	}

	return buf.Bytes()
}

const (
	ident  = "   "
	ident2 = ident + ident
	ident3 = ident + ident + ident
)

func prn(w io.Writer, format string, a ...any) {
	_, err := fmt.Fprintf(w, format, a...)
	AssertNoError(err)
}

func prnFuncDescription(w io.Writer, f *FuncDescriptorYAMLable) {
	prn(w, ident+"-\n")
	prn(w, ident2+"digest: \"%s\"\n", f.Digest)
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
		prn(w, ident2+"source: >\n%s\n", ident3+strings.Replace(f.Source, "\n", ident3+"\n", -1))
	}
}

func (lib *Library) funYAMLAbleByName(sym string) *FuncDescriptorYAMLable {
	fi, err := lib.functionByName(sym)
	AssertNoError(err)
	dscr := lib.funByFunCode[fi.FunCode]

	var b2 [2]byte
	binary.BigEndian.PutUint16(b2[:], fi.FunCode)
	inShort := "extended"
	if fi.IsEmbedded {
		if fi.IsShort {
			inShort = "embedded short"
		} else {
			inShort = "embedded long"
		}
	}
	argsStr := fmt.Sprintf("args: %d", fi.NumParams)
	if fi.NumParams < 0 {
		argsStr = "varargs"
	}

	return &FuncDescriptorYAMLable{
		Digest:   fmt.Sprintf("name: '%s', funCode: %d (hex 0x%s), %s, %s", fi.Sym, fi.FunCode, hex.EncodeToString(b2[:]), inShort, argsStr),
		Sym:      dscr.sym,
		FunCode:  dscr.funCode,
		Embedded: fi.IsEmbedded,
		Short:    fi.IsShort,
		NumArgs:  dscr.requiredNumParams,
		Source:   dscr.source,
		Bytecode: hex.EncodeToString(dscr.bytecode),
	}
}

func ReadLibraryFromYAML(data []byte) (*Library, error) {
	fromYAML := &LibraryFromYAML{}
	err := yaml.Unmarshal(data, &fromYAML)
	if err != nil {
		return nil, err
	}
	ret := &Library{
		funByName:    make(map[string]*funDescriptor),
		funByFunCode: make(map[uint16]*funDescriptor),
	}

	numEmbeddedShort := 0
	numEmbeddedLong := 0
	numExtended := 0

	for _, dscr := range fromYAML.Functions {
		if _, already := ret.funByName[dscr.Sym]; already {
			return nil, fmt.Errorf("duplicate function name '%s', code: %d", dscr.Sym, dscr.FunCode)
		}
		fd := &funDescriptor{
			sym:               dscr.Sym,
			funCode:           dscr.FunCode,
			bytecode:          nil,
			requiredNumParams: dscr.NumArgs,
			embeddedFun:       nil,
			source:            dscr.Source,
		}
		fd.bytecode, err = hex.DecodeString(dscr.Bytecode)
		if err != nil {
			return nil, fmt.Errorf("error while decoding bytecode fun name: '%s': %v", dscr.Sym, err)
		}

		ret.funByName[dscr.Sym] = fd

		if _, already := ret.funByFunCode[dscr.FunCode]; already {
			return nil, fmt.Errorf("duplicate function code %d, name: %s", dscr.FunCode, dscr.Sym)
		}
		ret.funByFunCode[dscr.FunCode] = fd
		isEmbedded, isShort := fd.isEmbeddedOrShort()
		if isEmbedded {
			if isShort {
				numEmbeddedShort++
			} else {
				numEmbeddedLong++
			}
		} else {
			numExtended++
		}
	}
	ret.numEmbeddedShort = uint16(numEmbeddedShort) + FirstEmbeddedShort
	ret.numEmbeddedLong = uint16(numEmbeddedLong)
	ret.numExtended = uint16(numExtended)
	return ret, nil
}

func (lib *Library) Embed(m map[string]*EmbeddedFunctionData) error {
	for _, fd := range lib.funByFunCode {
		if isEmbedded, _ := fd.isEmbeddedOrShort(); isEmbedded {
			e, ok := m[fd.sym]
			if !ok {
				return fmt.Errorf("embedded fun '%s' not found", fd.sym)
			}
			if fd.requiredNumParams != e.RequiredNumPar {
				return fmt.Errorf("embedded fun '%s': inconsistent number of params", fd.sym)
			}
			fd.embeddedFun = e.EmbeddedFun
		}
	}
	return nil
}

func (lib *Library) ValidateExtended() error {
	extended := make([]*funDescriptor, 0)
	for _, fd := range lib.funByFunCode {
		if isEmbedded, _ := fd.isEmbeddedOrShort(); !isEmbedded {
			extended = append(extended, fd)
		}
	}
	sort.Slice(extended, func(i, j int) bool {
		return extended[i].funCode < extended[j].funCode
	})
	for _, fd := range extended {
		_, numArgs, bytecode, err := lib.CompileExpression(fd.source)
		if err != nil {
			return fmt.Errorf("error while compiling function name: '%s', source: `%s`: %v", fd.sym, fd.source, err)
		}
		if numArgs != fd.requiredNumParams {
			return fmt.Errorf("error while compiling function. Inconsistent number of args. name: '%s', source: `%s`", fd.sym, fd.source)
		}
		if !bytes.Equal(fd.bytecode, bytecode) {
			return fmt.Errorf("error while compiling function. Compiled bytecode != provided one. name: '%s', source: `%s`", fd.sym, fd.source)
		}
	}
	return nil
}
