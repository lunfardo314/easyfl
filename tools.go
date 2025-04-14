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
		Name             string                   `yaml:"name"`
		Hash             string                   `yaml:"hash"`
		NumEmbeddedShort uint16                   `yaml:"num_embedded_short"`
		NumEmbeddedLong  uint16                   `yaml:"num_embedded_long"`
		NumExtended      uint16                   `yaml:"num_extended"`
		Functions        []FuncDescriptorYAMLable `yaml:"functions"`
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

	embedded := make([]*FuncDescriptorYAMLable, 0)
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

	extended := make([]*FuncDescriptorYAMLable, 0)
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

func (lib *Library) findByName(sym string) *FuncDescriptorYAMLable {
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
	isSorted := sort.SliceIsSorted(fromYAML.Functions, func(i, j int) bool {
		return fromYAML.Functions[i].FunCode < fromYAML.Functions[j].FunCode
	})
	if !isSorted {
		return nil, fmt.Errorf("function descriptions in the .YAML file must be sorted ascending by 'funCode'")
	}
	ret := &Library{
		funByName:        make(map[string]*funDescriptor),
		funByFunCode:     make(map[uint16]*funDescriptor),
		numEmbeddedShort: fromYAML.NumEmbeddedShort,
		numEmbeddedLong:  fromYAML.NumEmbeddedLong,
		numExtended:      fromYAML.NumExtended,
	}
	return ret, nil
}
