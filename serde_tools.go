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
		Hash        string                   `yaml:"hash,omitempty"`         // if Hash != "", library is compiled
		VersionData string                   `yaml:"version_data,omitempty"` // optional version data as string
		Functions   []FuncDescriptorYAMLAble `yaml:"functions"`
	}

	// FuncDescriptorYAMLAble contains all information about embedded or extended function
	// Mandatory fields:
	// - for compiled library: Sym, FunCode, NumArgs. Bytecode and Source only for extended functions
	// - for not compiled library Sym, NumArgs. Source only for extended functions
	// EmbeddedAs is the key for resolving Go implementation. If empty, function is extended (not embedded)
	// Replace: if true, function must exist in target library and will be replaced; if false/absent, function must not exist
	// Immutable: if true, function cannot be replaced/modified in upgrades
	FuncDescriptorYAMLAble struct {
		Sym         string `yaml:"sym"`
		FunCode     uint16 `yaml:"funCode,omitempty"`
		NumArgs     int    `yaml:"numArgs"`
		EmbeddedAs  string `yaml:"embedded_as,omitempty"`
		Short       bool   `yaml:"short,omitempty"`
		Replace     bool   `yaml:"replace,omitempty"`
		Immutable   bool   `yaml:"immutable,omitempty"`
		Source      string `yaml:"source,omitempty"`
		Bytecode    string `yaml:"bytecode,omitempty"`
		Description string `yaml:"description,omitempty"`
	}
)

// LibraryHash returns hash of the library bytes. used for consistency checking
func (lib *Library[T]) LibraryHash() [32]byte {
	ret := blake2b.Sum256(lib.libraryBytes())
	return ret
}

// libraryBytes is serialized compiled library essence. Data includes names (sym), fun codes, num args and bytecodes
// in the order of its appearance. I.e. hash does not depend on source and description
func (lib *Library[T]) libraryBytes() []byte {
	var buf bytes.Buffer

	lib.write(&buf)
	return buf.Bytes()
}

// currently only serialization is implemented.
// Serialization is only used for calculating library hash, to support library upgrades

func (lib *Library[T]) write(w io.Writer) {
	_ = binary.Write(w, binary.BigEndian, lib.numEmbeddedShort)
	_ = binary.Write(w, binary.BigEndian, lib.numEmbeddedLong)
	_ = binary.Write(w, binary.BigEndian, lib.numExtended)

	// include VersionData in hash
	_ = binary.Write(w, binary.BigEndian, uint16(len(lib.VersionData)))
	_, _ = w.Write(lib.VersionData)

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

func (fd *funDescriptor[T]) write(w io.Writer) {
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

	// embeddedAs key (empty for extended functions)
	easyfl_util.Assertf(len(fd.embeddedAs) < 256, "EasyFL: len(fd.embeddedAs)<256")
	_, _ = w.Write([]byte{byte(len(fd.embeddedAs))})
	_, _ = w.Write([]byte(fd.embeddedAs))

	// immutable flag
	immutableByte := byte(0)
	if fd.immutable {
		immutableByte = 1
	}
	_, _ = w.Write([]byte{immutableByte})
}

// ToYAML generates YAML data. Prefix is added at the beginning, usually it is a comment
// If compiled = true, it also adds hash of the library and each function descriptor contain funCode and compiled bytecode (whenever relevant)
func (lib *Library[T]) ToYAML(compiled bool, prefix ...string) []byte {
	var buf bytes.Buffer

	if len(prefix) > 0 {
		prn(&buf, "%s\n", prefix[0])
	}
	if compiled {
		h := lib.LibraryHash()
		prn(&buf, "hash: %s\n", hex.EncodeToString(h[:]))
	}
	if len(lib.VersionData) > 0 {
		prn(&buf, "version_data: \"%s\"\n", yamlEscapeString(string(lib.VersionData)))
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
		if dscr.EmbeddedAs != "" && dscr.Short {
			prnFuncDescription(&buf, dscr, compiled)
		}
	}
	prn(&buf, "# END SHORT EMBEDDED function definitions\n")

	prn(&buf, "# BEGIN LONG EMBEDDED function definitions\n")
	if compiled {
		prn(&buf, "#    function codes (opcodes) from %d to %d are reserved for 'LONG EMBEDDED function codes'\n", FirstEmbeddedLong, LastEmbeddedLong)
	}
	for _, dscr := range functions {
		if dscr.EmbeddedAs != "" && !dscr.Short {
			prnFuncDescription(&buf, dscr, compiled)
		}
	}
	prn(&buf, "# END LONG EMBEDDED function definitions\n")

	prn(&buf, "# BEGIN EXTENDED function definitions (defined by EasyFL formulas)\n")
	if compiled {
		prn(&buf, "#    function codes (opcodes) from %d and up to maximum %d are reserved for 'EXTENDED function codes'\n", FirstExtended, LastGlobalFunCode)
	}
	for _, dscr := range functions {
		if dscr.EmbeddedAs == "" {
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

// yamlEscapeString escapes a string for use in YAML double-quoted format.
// It escapes backslashes, double quotes, and control characters.
func yamlEscapeString(s string) string {
	var buf strings.Builder
	buf.Grow(len(s) + 10) // pre-allocate with some extra space for escapes

	for _, r := range s {
		switch r {
		case '\\':
			buf.WriteString("\\\\")
		case '"':
			buf.WriteString("\\\"")
		case '\n':
			buf.WriteString("\\n")
		case '\r':
			buf.WriteString("\\r")
		case '\t':
			buf.WriteString("\\t")
		default:
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

func prnFuncDescription(w io.Writer, f *FuncDescriptorYAMLAble, compiled bool) {
	prn(w, ident+"-\n")
	prn(w, ident2+"sym: \"%s\"\n", yamlEscapeString(f.Sym))
	if f.Description != "" {
		prn(w, ident2+"description: \"%s\"\n", yamlEscapeString(f.Description))
	}
	if compiled {
		prn(w, ident2+"funCode: %d\n", f.FunCode)
	}
	prn(w, ident2+"numArgs: %d\n", f.NumArgs)
	if f.EmbeddedAs != "" {
		prn(w, ident2+"embedded_as: \"%s\"\n", yamlEscapeString(f.EmbeddedAs))
	}
	if f.Short {
		prn(w, ident2+"short: true\n")
	}
	if f.Immutable {
		prn(w, ident2+"immutable: true\n")
	}
	if f.EmbeddedAs == "" {
		if compiled {
			prn(w, ident2+"bytecode: %s\n", f.Bytecode)
		}
		prn(w, ident2+"source: >\n%s\n", ident3+strings.Replace(f.Source, "\n", "\n"+ident3, -1))
	}
}

func (lib *Library[T]) mustFunYAMLAbleByName(sym string) *FuncDescriptorYAMLAble {
	fi, err := lib.functionByName(sym)
	easyfl_util.AssertNoError(err)
	d := lib.funByFunCode[fi.FunCode]
	return &FuncDescriptorYAMLAble{
		Description: d.description,
		Sym:         d.sym,
		FunCode:     d.funCode,
		EmbeddedAs:  d.embeddedAs,
		Short:       fi.IsShort,
		Immutable:   d.immutable,
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

// Upgrade adds or replaces functions in the library from YAML definitions.
// It uses a multi-phase approach that allows forward references between extended functions
// within the same upgrade batch and explicitly checks for recursion via call graph analysis.
//
// For safe upgrades, use Clone() first: clone := lib.Clone(); err := clone.Upgrade(...).
// If the upgrade fails, simply discard the clone.
//
// The Replace flag controls behavior:
// - Replace=true: function must exist in library, its definition will be replaced (funCode preserved)
// - Replace=false (default): function must not exist, will be added as new
// The Immutable flag controls whether the function can be replaced in future upgrades
func (lib *Library[T]) Upgrade(fromYAML *LibraryFromYAML, embed ...func(sym string) EmbeddedFunction[T]) error {
	// Update VersionData only if new value is non-empty (after trimming whitespace)
	if vd := strings.TrimSpace(fromYAML.VersionData); vd != "" {
		lib.VersionData = []byte(vd)
	}

	// ---- Phase 0: process embedded functions (leaf nodes, no dependencies on EasyFL functions)
	// Also validate replace/existence flags for all functions upfront
	type pendingExtendedFunc struct {
		sym         string
		source      string
		description string
		isReplace   bool
		isVararg    bool
		immutable   bool
	}
	var pending []pendingExtendedFunc

	for _, d := range fromYAML.Functions {
		exists := lib.existsFunction(d.Sym)

		// Check replace flag consistency
		if d.Replace {
			if !exists {
				return fmt.Errorf("replace=true but function '%s' does not exist in library", d.Sym)
			}
		} else {
			if exists {
				return fmt.Errorf("function '%s' already exists in library (use replace=true to replace)", d.Sym)
			}
		}

		if d.EmbeddedAs != "" {
			// embedded function — process immediately
			var ef EmbeddedFunction[T]
			if len(embed) > 0 {
				if ef = embed[0](d.EmbeddedAs); ef == nil {
					return fmt.Errorf("missing embedded function for key '%s' (sym: '%s')", d.EmbeddedAs, d.Sym)
				}
			}
			if d.Replace {
				if err := lib.replaceEmbedded(d.Sym, d.NumArgs, ef, d.EmbeddedAs, d.Description); err != nil {
					return err
				}
			} else {
				if d.Short {
					if _, err := lib.embedShortErr(d.Sym, d.NumArgs, ef, d.EmbeddedAs, d.Description); err != nil {
						return err
					}
				} else {
					if _, err := lib.embedLongErr(d.Sym, d.NumArgs, ef, d.EmbeddedAs, d.Description); err != nil {
						return err
					}
				}
			}
			// Set immutable flag for embedded
			if d.Immutable {
				if fd, found := lib.funByName[d.Sym]; found {
					fd.immutable = true
				}
			}
		} else {
			// extended function — defer to Phase 1
			pending = append(pending, pendingExtendedFunc{
				sym:         d.Sym,
				source:      d.Source,
				description: d.Description,
				isReplace:   d.Replace,
				isVararg:    d.NumArgs == -1,
				immutable:   d.Immutable,
			})
		}
	}

	if len(pending) == 0 {
		return nil
	}

	// ---- Phase 1: introduce stubs for new extended functions; validate replaced ones
	// Stubs use requiredNumParams = -1 (vararg) so that ExpressionSourceToBytecode
	// does not fail on arity checks. Actual numParams is determined in Phase 2.
	for _, p := range pending {
		if p.isReplace {
			// Validate: exists, not immutable, is extended
			fd := lib.funByName[p.sym]
			if fd.immutable {
				return fmt.Errorf("replaceExtended: function '%s' is immutable and cannot be replaced", p.sym)
			}
			if fd.embeddedAs != "" {
				return fmt.Errorf("replaceExtended: function '%s' is embedded, not extended", p.sym)
			}
		} else {
			// Create stub descriptor
			easyfl_util.Assertf(lib.numExtended < MaxNumExtendedGlobal, "too many extended functions")
			dscr := &funDescriptor[T]{
				sym:               p.sym,
				funCode:           lib.numExtended + FirstExtended,
				requiredNumParams: -1, // temporary vararg
			}
			lib.addDescriptor(dscr)
		}
	}

	// ---- Phase 2: compile all pending functions to bytecode
	// All function names are now resolvable (stubs exist for new, descriptors exist for replaced)
	type compiledInfo struct {
		bytecode []byte
		numParam int
	}
	compiled := make([]compiledInfo, len(pending))
	involvedFunCodes := make([]uint16, len(pending))

	for i, p := range pending {
		src, err := preprocessSource(p.source)
		if err != nil {
			return fmt.Errorf("Upgrade: error preprocessing source for '%s': %v", p.sym, err)
		}
		bytecode, numParam, err := lib.ExpressionSourceToBytecode(src)
		if err != nil {
			return fmt.Errorf("Upgrade: error compiling '%s': %v", p.sym, err)
		}
		if numParam > 15 {
			return fmt.Errorf("Upgrade: can't be more than 15 parameters in '%s'", p.sym)
		}
		compiled[i] = compiledInfo{bytecode: bytecode, numParam: numParam}

		fd := lib.funByName[p.sym]
		involvedFunCodes[i] = fd.funCode

		// Set bytecode on descriptor (needed for cycle check)
		fd.bytecode = bytecode

		// Fix up numParams from compiled result
		if p.isVararg {
			fd.requiredNumParams = -1
		} else if p.isReplace {
			// For replaced functions, numArgs must not change
			if fd.requiredNumParams >= 0 && fd.requiredNumParams != numParam {
				return fmt.Errorf("Upgrade: function '%s' numArgs mismatch: existing %d, new %d (must be equal for backward compatibility)",
					p.sym, fd.requiredNumParams, numParam)
			}
		} else {
			// New function: set actual numParams
			fd.requiredNumParams = numParam
		}
	}

	// ---- Phase 3: check for cycles in the call graph
	if err := checkForCycles(lib, involvedFunCodes); err != nil {
		return fmt.Errorf("Upgrade: %v", err)
	}

	// ---- Phase 4: build expression trees in topological order (dependencies first)
	sorted, err := topologicalSortPartialOrder(lib, involvedFunCodes)
	if err != nil {
		return fmt.Errorf("Upgrade: topological sort failed: %v", err)
	}

	// Map funCode to pending index for lookup
	fcToIdx := make(map[uint16]int, len(involvedFunCodes))
	for i, fc := range involvedFunCodes {
		fcToIdx[fc] = i
	}

	for _, fc := range sorted {
		idx := fcToIdx[fc]
		p := pending[idx]
		c := compiled[idx]
		fd := lib.funByName[p.sym]

		expr, err := lib.ExpressionFromBytecode(c.bytecode)
		if err != nil {
			return fmt.Errorf("Upgrade: error building expression for '%s': %v", p.sym, err)
		}

		embeddedFun := makeEmbeddedFunForExpression(p.sym, expr)
		if traceYN {
			embeddedFun = wrapWithTracing(embeddedFun, p.sym)
		}

		fd.embeddedFun = embeddedFun
		fd.source = p.source
		fd.description = p.description

		// Set immutable flag
		if p.immutable {
			fd.immutable = true
		}
	}
	return nil
}

func (lib *Library[T]) UpgradeFromYAML(yamlData []byte, embed ...func(sym string) EmbeddedFunction[T]) error {
	fromYAML, err := ReadLibraryFromYAML(yamlData)
	if err != nil {
		return err
	}
	return lib.Upgrade(fromYAML, embed...)
}

func ValidateCompiled[T any](libYAML *LibraryFromYAML) error {
	hashProvidedBin, err := hex.DecodeString(libYAML.Hash)
	if err != nil || len(hashProvidedBin) != sha256.Size {
		return fmt.Errorf("ValidateCompiled: not compiled or wrong hash string")
	}
	lib := NewLibrary[T]()
	if err = lib.Upgrade(libYAML); err != nil {
		return err
	}

	for _, d := range libYAML.Functions {
		if d.EmbeddedAs == "" {
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
