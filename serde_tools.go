package easyfl

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/lunfardo314/easyfl/easyfl_util"
	"golang.org/x/crypto/blake2b"
	"gopkg.in/yaml.v3"
)

type (
	// LibraryFromYAML is parsed YAML description of a library
	LibraryFromYAML struct {
		Hash      string                   `yaml:"hash,omitempty"` // if Hash != "", library is compiled
		Functions []FuncDescriptorYAMLAble `yaml:"functions"`
	}

	// FuncDescriptorYAMLAble contains all information about embed ior extended function
	// Mandatory fields:
	// - for compiled library: Sym, FunCode, NumArgs. Bytecode and Source only for extended functions
	// - for not compiled library Sym, NumArgs. Source only for extended functions
	FuncDescriptorYAMLAble struct {
		Sym         string `yaml:"sym"`
		FunCode     uint16 `yaml:"funCode,omitempty"`
		NumArgs     int    `yaml:"numArgs"`
		Embedded    bool   `yaml:"embedded,omitempty"`
		Short       bool   `yaml:"short,omitempty"`
		Source      string `yaml:"source,omitempty"`
		Bytecode    string `yaml:"bytecode,omitempty"`
		Description string `yaml:"description,omitempty"`
	}
)

// LibraryHash returns hash of the library bytes. used for consistency checking
func (lib *Library) LibraryHash() [32]byte {
	ret := blake2b.Sum256(lib.libraryBytes())
	return ret
}

// libraryBytes is serialized compiled library essence. Data includes names (sym), fun codes, num args and bytecodes
// in the order of its appearance. I.e. hash does not depend on source and description
func (lib *Library) libraryBytes() []byte {
	var buf bytes.Buffer

	lib.write(&buf)
	return buf.Bytes()
}

// currently only serialization is implemented.
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
	easyfl_util.Assertf(len(fd.sym) < 256, "EasyFL: len(fd.sym)<256")
	_, _ = w.Write([]byte{byte(len(fd.sym))})
	_, _ = w.Write([]byte(fd.sym))
	easyfl_util.Assertf(len(fd.bytecode) < 256*256, "EasyFL: len(fd.bytecode)<256*256")
	// bytecode (will be nil for embedded)
	_ = binary.Write(w, binary.BigEndian, uint16(len(fd.bytecode)))
	_, _ = w.Write(fd.bytecode)
}

// ToYAML generates YAML data. Prefix is added at the beginning, usually it is a comment
// If compiled = true, it also adds hash of the library and each function descriptor contain funCode and compiled bytecode (whenever relevant)
func (lib *Library) ToYAML(compiled bool, prefix ...string) []byte {
	var buf bytes.Buffer

	if len(prefix) > 0 {
		prn(&buf, "%s\n", prefix[0])
	}
	if compiled {
		h := lib.LibraryHash()
		prn(&buf, "hash: %s\n", hex.EncodeToString(h[:]))
	}

	functions := make([]*FuncDescriptorYAMLAble, 0)
	for sym := range lib.funByName {
		functions = append(functions, lib.mustFunYAMLAbleByName(sym))
	}

	if compiled {
		// sort by funCodes
		sort.Slice(functions, func(i, j int) bool {
			return functions[i].FunCode < functions[j].FunCode
		})
	} else {
		// sort by name
		sort.Slice(functions, func(i, j int) bool {
			return functions[i].Sym < functions[j].Sym
		})
	}

	prn(&buf, "functions:\n")

	prn(&buf, "# BEGIN EMBEDDED function definitions\n")
	if compiled {
		prn(&buf, "#    function codes (opcodes) from %d to %d are reserved for predefined parameter access functions $i\n", FirstEmbeddedReserved, LastEmbeddedReserved)
	}
	prn(&buf, "# BEGIN SHORT EMBEDDED function definitions\n")
	if compiled {
		prn(&buf, "#    function codes (opcodes) from %d to %d are reserved for 'SHORT EMBEDDED function codes'\n", FirstEmbeddedShort, LastEmbeddedShort)
	}
	for _, dscr := range functions {
		if dscr.Embedded && dscr.Short {
			prnFuncDescription(&buf, dscr, compiled)
		}
	}
	prn(&buf, "# END SHORT EMBEDDED function definitions\n")

	prn(&buf, "# BEGIN LONG EMBEDDED function definitions\n")
	if compiled {
		prn(&buf, "#    function codes (opcodes) from %d to %d are reserved for 'LONG EMBEDDED function codes'\n", FirstEmbeddedLong, LastEmbeddedLong)
	}
	for _, dscr := range functions {
		if dscr.Embedded && !dscr.Short {
			prnFuncDescription(&buf, dscr, compiled)
		}
	}
	prn(&buf, "# END LONG EMBEDDED function definitions\n")

	prn(&buf, "# BEGIN EXTENDED function definitions (defined by EasyFL formulas)\n")
	if compiled {
		prn(&buf, "#    function codes (opcodes) from %d and up to maximum %d are reserved for 'EXTENDED function codes'\n", FirstExtended, LastGlobalFunCode)
	}
	for _, dscr := range functions {
		if !dscr.Embedded {
			prnFuncDescription(&buf, dscr, compiled)
		}
	}
	prn(&buf, "# END EXTENDED function definitions (defined by EasyFL formulas)\n")
	prn(&buf, "# END all function definitions\n")

	return buf.Bytes()
}

const (
	ident  = "   "
	ident2 = ident + ident
	ident3 = ident + ident + ident
)

func prn(w io.Writer, format string, a ...any) {
	_, err := fmt.Fprintf(w, format, a...)
	easyfl_util.AssertNoError(err)
}

func prnFuncDescription(w io.Writer, f *FuncDescriptorYAMLAble, compiled bool) {
	prn(w, ident+"-\n")
	prn(w, ident2+"sym: \"%s\"\n", f.Sym)
	if f.Description != "" {
		prn(w, ident2+"description: \"%s\"\n", f.Description)
	}
	if compiled {
		prn(w, ident2+"funCode: %d\n", f.FunCode)
	}
	prn(w, ident2+"numArgs: %d\n", f.NumArgs)
	if f.Embedded {
		prn(w, ident2+"embedded: true\n")
	}
	if f.Short {
		prn(w, ident2+"short: true\n")
	}
	if !f.Embedded {
		if compiled {
			prn(w, ident2+"bytecode: %s\n", f.Bytecode)
		}
		prn(w, ident2+"source: >\n%s\n", ident3+strings.Replace(f.Source, "\n", "\n"+ident3, -1))
	}
}

func (lib *Library) mustFunYAMLAbleByName(sym string) *FuncDescriptorYAMLAble {
	fi, err := lib.functionByName(sym)
	easyfl_util.AssertNoError(err)
	d := lib.funByFunCode[fi.FunCode]
	return &FuncDescriptorYAMLAble{
		Description: d.description,
		Sym:         d.sym,
		FunCode:     d.funCode,
		Embedded:    fi.IsEmbedded,
		Short:       fi.IsShort,
		NumArgs:     d.requiredNumParams,
		Source:      d.source,
		Bytecode:    hex.EncodeToString(d.bytecode),
	}
}

// ReadLibraryFromYAML parses YAML
func ReadLibraryFromYAML(data []byte) (*LibraryFromYAML, error) {
	fromYAML := &LibraryFromYAML{}
	err := yaml.Unmarshal(data, &fromYAML)
	if err != nil {
		return nil, err
	}
	return fromYAML, nil
}

// Upgrade add functions to the library from YAMLAble. It ignores compiled part, compiles and assigns fun codes
// If embedding functions are available, embeds them and enforces consistency
// NOTE: if embedded functions are not provided, library is not ready for use, however its consistency
// has been checked, and it can be serialized to YAML
func (lib *Library) Upgrade(fromYAML *LibraryFromYAML, embed ...func(sym string) EmbeddedFunction) error {
	var err error
	var ef EmbeddedFunction

	for _, d := range fromYAML.Functions {
		if d.Embedded {
			if len(embed) > 0 {
				if ef = embed[0](d.Sym); ef == nil {
					return fmt.Errorf("missing embedded function: '%s'", d.Sym)
				}
			}
			if d.Short {
				if _, err = lib.embedShortErr(d.Sym, d.NumArgs, ef, d.Description); err != nil {
					return err
				}
			} else {
				if _, err = lib.embedLongErr(d.Sym, d.NumArgs, ef, d.Description); err != nil {
					return err
				}
			}
		} else {
			if _, err = lib.ExtendErr(d.Sym, d.Source, d.Description); err != nil {
				return err
			}
		}
	}
	return nil
}

func (lib *Library) UpgradeFromYAML(yamlData []byte, embed ...func(sym string) EmbeddedFunction) error {
	fromYAML, err := ReadLibraryFromYAML(yamlData)
	if err != nil {
		return err
	}
	return lib.Upgrade(fromYAML, embed...)
}

func (libYAML *LibraryFromYAML) ValidateCompiled() error {
	hashProvidedBin, err := hex.DecodeString(libYAML.Hash)
	if err != nil || len(hashProvidedBin) != sha256.Size {
		return fmt.Errorf("ValidateCompiled: not compiled or wrong hash string")
	}
	lib := NewLibrary()
	if err = lib.Upgrade(libYAML); err != nil {
		return err
	}

	for _, d := range libYAML.Functions {
		if !d.Embedded {
			fd, found := lib.funByFunCode[d.FunCode]
			easyfl_util.Assertf(found, "ValidateCompiled: func code %d (name: '%s') not found", d.FunCode, d.Sym)
			easyfl_util.Assertf(fd.sym == d.Sym, "ValidateCompiled: func code %d is wrong (conflicting function names '%s' and '%s')", d.FunCode, d.Sym, fd.sym)

			compiledBytecode := hex.EncodeToString(fd.bytecode)
			if d.Bytecode != compiledBytecode {
				return fmt.Errorf("ValidateCompiled: func code %d, function name '%s'. Conflicting bytecodes: compiled: '%s' != provided '%s'",
					d.FunCode, d.Sym, compiledBytecode, d.Bytecode)
			}
		}
	}

	hashCompiled := lib.LibraryHash()
	if hex.EncodeToString(hashCompiled[:]) != libYAML.Hash {
		return fmt.Errorf("ValidateCompiled: library hash does not match: compiled %s != provided %s", hex.EncodeToString(hashCompiled[:]), libYAML.Hash)
	}
	return nil
}
