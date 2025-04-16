package easyfl

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type (
	LibraryFromYAML struct {
		Hash      string                   `yaml:"hash"` // if Hash != "", library is compiled
		Functions []FuncDescriptorYAMLAble `yaml:"functions"`
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
		prn(&buf, "#    function codes (opcodes) from %d to %d are reserved for predefined parameter access functions $i and $$i\n", FirstEmbeddedReserved, LastEmbeddedReserved)
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

func (lib *Library) mustFunYAMLAbleByName(sym string) *FuncDescriptorYAMLAble {
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

func (lib *Library) UpgradeFromYAML(yamlData []byte, embed ...map[string]EmbeddedFunction) error {
	libFromYAML, err := ReadLibraryFromYAML(yamlData)
	if err != nil {
		return err
	}
	return lib.Upgrade(libFromYAML, embed...)
}

// Upgrade add functions to the library from YAMLAble. It ignores compiled part, compiles and assigns fun codes
// If embedding functions are available, embeds them and enforces consistency
// NOTE: if embedded functions are not provided, library is not ready for use, however its consistency
// has been checked, and it can be serialized to YAML
func (lib *Library) Upgrade(fromYAML *LibraryFromYAML, embed ...map[string]EmbeddedFunction) error {
	var err error

	var em map[string]EmbeddedFunction
	if len(embed) > 0 {
		em = embed[0]
	}
	var ef EmbeddedFunction
	var found bool

	for _, d := range fromYAML.Functions {
		if d.Embedded {
			if em != nil {
				if ef, found = em[d.Sym]; !found {
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

func (libYAML *LibraryFromYAML) ValidateCompiled() error {
	hashProvidedBin, err := hex.DecodeString(libYAML.Hash)
	if err != nil || len(hashProvidedBin) != sha256.Size {
		return fmt.Errorf("ValidateCompiled: not compiled or wrong hash string")
	}
	lib := New()
	if err = lib.Upgrade(libYAML); err != nil {
		return err
	}

	for _, d := range libYAML.Functions {
		if !d.Embedded {
			fd, found := lib.funByFunCode[d.FunCode]
			Assertf(found, "ValidateCompiled: func code %d (name: '%s') not found", d.FunCode, d.Sym)
			Assertf(fd.sym == d.Sym, "ValidateCompiled: func code %d is wrong (conflicting function names '%s' and '%s')", d.FunCode, d.Sym, fd.sym)

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
