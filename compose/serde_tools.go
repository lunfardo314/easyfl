package compose

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/lunfardo314/easyfl/easyfl_util"
	"golang.org/x/crypto/blake2b"
)

type (
	// LibraryFromJSON is a parsed library description (carrier struct for JSON
	// serialization and the Upgrade pipeline).
	LibraryFromJSON struct {
		Hash        string               `json:"hash,omitempty"`        // if Hash != "", library is compiled
		VersionData string               `json:"versionData,omitempty"` // optional version data as string
		Functions   []FuncDescriptorJSON `json:"functions"`
	}

	// FuncDescriptorJSON contains all information about an embedded or extended function.
	// Mandatory fields:
	//   - for a compiled library: Sym, FunCode, NumArgs; plus Bytecode and Source for extended functions
	//   - for a non-compiled library: Sym, NumArgs; plus Source for extended functions
	// EmbeddedAs is the key for resolving the Go implementation. Empty means the function is extended.
	// Replace: if true, function must exist in the target library and will be replaced; if false/absent, function must not exist.
	// Immutable: if true, function cannot be replaced/modified in future upgrades.
	//
	// Field order matches the desired JSON pretty-print layout: sym, description,
	// funCode, numArgs, embeddedAs, short, replace, immutable, source, bytecode.
	FuncDescriptorJSON struct {
		Sym         string `json:"sym"`
		Description string `json:"description,omitempty"`
		FunCode     uint16 `json:"funCode,omitempty"`
		NumArgs     int    `json:"numArgs"`
		EmbeddedAs  string `json:"embeddedAs,omitempty"`
		Short       bool   `json:"short,omitempty"`
		Replace     bool   `json:"replace,omitempty"`
		Immutable   bool   `json:"immutable,omitempty"`
		Source      string `json:"source,omitempty"`
		Bytecode    string `json:"bytecode,omitempty"`
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

func (lib *Library[T]) MustFuncDescriptor(sym string) *FuncDescriptorJSON {
	fi, err := lib.FunctionByName(sym)
	easyfl_util.AssertNoError(err)
	d := lib.funByFunCode[fi.FunCode]
	return &FuncDescriptorJSON{
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

// IntroduceUpdate is the internal implementation that works with an
// already-parsed library description. It stages extended functions for
// CommitUpdate and processes embedded functions immediately.
func (lib *Library[T]) IntroduceUpdate(fromJSON *LibraryFromJSON, embed ...func(sym string) EmbeddedFunction[T]) error {
	// Update VersionData only if new value is non-empty (after trimming whitespace)
	if vd := strings.TrimSpace(fromJSON.VersionData); vd != "" {
		lib.VersionData = []byte(vd)
	}

	for _, d := range fromJSON.Functions {
		exists := lib.existsFunction(d.Sym)

		// Check replace flag consistency against library and pendingBatch
		if d.Replace {
			if !exists {
				return fmt.Errorf("replace=true but function '%s' does not exist in library", d.Sym)
			}
		} else {
			if exists {
				return fmt.Errorf("function '%s' already exists in library (use replace=true to replace)", d.Sym)
			}
			if lib.isPendingSym(d.Sym) {
				return fmt.Errorf("function '%s' already in pending batch", d.Sym)
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
			// Set per-descriptor flags for embedded
			if fd, found := lib.funByName[d.Sym]; found {
				if d.Immutable {
					fd.immutable = true
				}
			}
		} else {
			// extended function — append to pending batch
			lib.pendingBatch = append(lib.pendingBatch, pendingExtendedFunc{
				sym:         d.Sym,
				source:      d.Source,
				description: d.Description,
				isReplace:   d.Replace,
				isVararg:    d.NumArgs == -1,
				immutable:   d.Immutable,
			})
		}
	}
	return nil
}

// Upgrade adds or replaces functions in the library from a parsed library
// description. It uses a multi-phase approach that allows forward references
// between extended functions within the same upgrade batch and explicitly
// checks for recursion via call graph analysis.
//
// For safe upgrades, use Clone() first: clone := lib.Clone(); err := clone.Upgrade(...).
// If the upgrade fails, simply discard the clone.
//
// The Replace flag controls behavior:
//   - Replace=true: function must exist in library, its definition will be replaced (funCode preserved)
//   - Replace=false (default): function must not exist, will be added as new
//
// The Immutable flag controls whether the function can be replaced in future upgrades.
func (lib *Library[T]) Upgrade(fromJSON *LibraryFromJSON, embed ...func(sym string) EmbeddedFunction[T]) error {
	if err := lib.IntroduceUpdate(fromJSON, embed...); err != nil {
		return fmt.Errorf("Upgrade: %v", err)
	}
	if err := lib.CommitUpdate(); err != nil {
		return fmt.Errorf("Upgrade: %v", err)
	}
	return nil
}

// ValidateCompiled checks that a compiled library description (one with a
// non-empty Hash field) is internally consistent: the declared bytecodes,
// funCodes, and top-level hash all reproduce when the library is rebuilt.
func ValidateCompiled[T any](libJSON *LibraryFromJSON) error {
	hashProvidedBin, err := hex.DecodeString(libJSON.Hash)
	if err != nil || len(hashProvidedBin) != blake2b.Size256 {
		return fmt.Errorf("ValidateCompiled: not compiled or wrong hash string")
	}
	lib := NewLibrary[T]()
	if err = lib.Upgrade(libJSON); err != nil {
		return err
	}

	for _, d := range libJSON.Functions {
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
	if hex.EncodeToString(hashCompiled[:]) != libJSON.Hash {
		return fmt.Errorf("ValidateCompiled: library hash does not match: compiled %s != provided %s", hex.EncodeToString(hashCompiled[:]), libJSON.Hash)
	}
	return nil
}
