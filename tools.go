package easyfl

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type (
	LibraryFromYAML struct {
		Description string                   `yaml:"description"`
		Compiled    bool                     `yaml:"compiled"`
		Hash        string                   `yaml:"hash"`
		Functions   []FuncDescriptorYAMLAble `yaml:"functions"`
	}

	FuncDescriptorYAMLAble struct {
		Description string `yaml:"description,omitempty"`
		Sym         string `yaml:"sym"`
		NumArgs     int    `yaml:"numArgs"`
		Embedded    bool   `yaml:"embedded,omitempty"`
		Short       bool   `yaml:"short,omitempty"`
		FunCode     uint16 `yaml:"funCode,omitempty"`
		Source      string `yaml:"source,omitempty"`
		Bytecode    string `yaml:"bytecode,omitempty"`
	}
)

func (lib *Library) ToYAML(description string, compiled bool) []byte {
	var buf bytes.Buffer

	prn(&buf, "# EasyFL library\n")
	prn(&buf, "compiled: %v\n", compiled)
	prn(&buf, "description: \"%s\"\n", description)
	if compiled {
		h := lib.LibraryHash()
		prn(&buf, "hash: %s\n", hex.EncodeToString(h[:]))
	}

	functions := make([]*FuncDescriptorYAMLAble, 0)
	for sym := range lib.funByName {
		functions = append(functions, lib.funYAMLAbleByName(sym))
	}

	sort.Slice(functions, func(i, j int) bool {
		return functions[i].FunCode < functions[j].FunCode
	})

	prn(&buf, "functions:\n")
	if compiled {
		prn(&buf, "# BEGIN EMBEDDED function definitions\n")
		prn(&buf, "#    function codes (opcodes) from %d to %d are reserved for predefined inline functions\n", FirstEmbeddedReserved, LastEmbeddedReserved)
		prn(&buf, "# BEGIN SHORT EMBEDDED function definitions\n")
		prn(&buf, "#    function codes (opcodes) from %d to %d are reserved for 'SHORT EMBEDDED function codes'\n", FirstEmbeddedShort, LastEmbeddedShort)
	}
	for _, dscr := range functions {
		if compiled {
			if dscr.FunCode == FirstEmbeddedLong {
				prn(&buf, "# END SHORT EMBEDDED function definitions\n")
				prn(&buf, "# BEGIN LONG EMBEDDED function definitions\n")
				prn(&buf, "#    function codes (opcodes) from %d to %d are reserved for 'LONG EMBEDDED function codes'\n", FirstEmbeddedLong, LastEmbeddedLong)
			}
			if dscr.FunCode == FirstExtended {
				prn(&buf, "# END LONG embedded function definitions\n")
				prn(&buf, "# BEGIN EXTENDED function definitions (defined by EasyFL formulas)\n")
				prn(&buf, "#    function codes (opcodes) from %d and up to maximum %d are reserved for 'EXTENDED function codes'\n", FirstExtended, LastGlobalFunCode)
			}
		}
		prnFuncDescription(&buf, dscr, compiled)
	}
	prn(&buf, "# END EXTENDED function definitions\n")
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
	AssertNoError(err)
}

func prnFuncDescription(w io.Writer, f *FuncDescriptorYAMLAble, compiled bool) {
	prn(w, ident+"-\n")
	prn(w, ident2+"sym: %s\n", f.Sym)
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
		prn(w, ident2+"source: >\n%s\n", ident3+strings.Replace(f.Source, "\n", ident3+"\n", -1))
	}
}

func (lib *Library) funYAMLAbleByName(sym string) *FuncDescriptorYAMLAble {
	fi, err := lib.functionByName(sym)
	AssertNoError(err)
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

// CompileToYAML compiles, assigns funcodes and converts to compiled YAML
func (libYAML *LibraryFromYAML) CompileToYAML(dscr string) ([]byte, error) {
	if libYAML.Compiled {
		return nil, fmt.Errorf("CompileToYAML: already finalized")
	}
	lib, err := libYAML.Compile()
	if err != nil {
		return nil, err
	}
	return lib.ToYAML(dscr, true), nil
}

// Compile makes library, ignores compiled part, compiles and assigns funcodes but does not embed hardcoded functions
func (libYAML *LibraryFromYAML) Compile() (*Library, error) {
	ret := newLibrary()

	err := ret.Upgrade(libYAML)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// TODO provide embedded functions at the moment of compilation

func (lib *Library) Upgrade(fromYAML *LibraryFromYAML) error {
	var err error

	for _, d := range fromYAML.Functions {
		if d.Embedded {
			if d.Short {
				if _, err = lib.embedShortErr(d.Sym, d.NumArgs, nil, d.Description); err != nil {
					return err
				}
			} else {
				if _, err = lib.embedLongErr(d.Sym, d.NumArgs, nil, d.Description); err != nil {
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

func (libYAML *LibraryFromYAML) ValidateCompiled() error {
	if !libYAML.Compiled {
		return fmt.Errorf("ValidateCompiled: not compiled")
	}
	lib, err := libYAML.Compile()
	if err != nil {
		return err
	}

	for _, d := range libYAML.Functions {
		if !d.Embedded {
			fd, found := lib.funByFunCode[d.FunCode]
			if !found {
				return fmt.Errorf("ValidateCompiled: func code %d (name: '%s') not found", d.FunCode, d.Sym)
			}
			if fd.sym != d.Sym {
				return fmt.Errorf("ValidateCompiled: func code %d is wrong (conflicting function names '%s' and '%s')", d.FunCode, d.Sym, fd.sym)
			}
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
