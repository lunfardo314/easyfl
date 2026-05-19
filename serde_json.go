package easyfl

// JSON serialisation helpers — kept at the easyfl facade rather than
// inside easyfl/engine so the engine sub-package doesn't drag in
// encoding/json. Wallets that want to round-trip lock scripts without
// JSON should import easyfl/engine directly and skip this file.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/lunfardo314/easyfl/engine"
)

// ToJSON serialises a library to JSON.
//   - compiled=true emits funCode/bytecode fields and the top-level hash.
//   - indent=true emits human-readable indented JSON with a trailing newline.
//     indent=false emits compact JSON (canonical for storage and on-the-wire);
//     no trailing newline.
func ToJSON[T any](lib *engine.Library[T], compiled, indent bool) []byte {
	syms := lib.FunctionSymbols()
	out := engine.LibraryFromJSON{
		VersionData: string(lib.VersionData),
		Functions:   make([]engine.FuncDescriptorJSON, 0, len(syms)),
	}
	if compiled {
		h := lib.LibraryHash()
		out.Hash = hex.EncodeToString(h[:])
	}

	for _, sym := range syms {
		d := *lib.MustFuncDescriptor(sym)
		if !compiled {
			d.FunCode = 0
			d.Bytecode = ""
		}
		out.Functions = append(out.Functions, d)
	}

	if compiled {
		sort.Slice(out.Functions, func(i, j int) bool {
			return out.Functions[i].FunCode < out.Functions[j].FunCode
		})
	} else {
		sort.Slice(out.Functions, func(i, j int) bool {
			return out.Functions[i].Sym < out.Functions[j].Sym
		})
	}

	var (
		data []byte
		err  error
	)
	if indent {
		data, err = json.MarshalIndent(&out, "", "  ")
	} else {
		data, err = json.Marshal(&out)
	}
	if err != nil {
		panic(fmt.Errorf("ToJSON: %v", err))
	}
	if indent {
		data = append(data, '\n')
	}
	return data
}

// ReadLibraryFromJSON parses JSON into a *engine.LibraryFromJSON.
func ReadLibraryFromJSON(data []byte) (*engine.LibraryFromJSON, error) {
	ret := &engine.LibraryFromJSON{}
	if err := json.Unmarshal(data, ret); err != nil {
		return nil, err
	}
	return ret, nil
}

// IntroduceUpdateJSON parses raw JSON data and stages extended functions
// for later processing by lib.CommitUpdate. Embedded functions are
// processed immediately.
func IntroduceUpdateJSON[T any](lib *engine.Library[T], jsonData []byte, embed ...func(sym string) engine.EmbeddedFunction[T]) error {
	fromJSON, err := ReadLibraryFromJSON(jsonData)
	if err != nil {
		return err
	}
	return lib.IntroduceUpdate(fromJSON, embed...)
}

// IntroduceUpdateJSONMulti is the variadic form of IntroduceUpdateJSON.
func IntroduceUpdateJSONMulti[T any](lib *engine.Library[T], embed func(sym string) engine.EmbeddedFunction[T], jsonDatas ...[]byte) error {
	for _, jsonData := range jsonDatas {
		if embed != nil {
			if err := IntroduceUpdateJSON(lib, jsonData, embed); err != nil {
				return err
			}
		} else {
			if err := IntroduceUpdateJSON(lib, jsonData); err != nil {
				return err
			}
		}
	}
	return nil
}

// UpgradeFromJSON parses JSON and applies it as a single Upgrade
// (introduce + CommitUpdate).
func UpgradeFromJSON[T any](lib *engine.Library[T], jsonData []byte, embed ...func(sym string) engine.EmbeddedFunction[T]) error {
	fromJSON, err := ReadLibraryFromJSON(jsonData)
	if err != nil {
		return err
	}
	return lib.Upgrade(fromJSON, embed...)
}

// NewLibraryFromJSON constructs a fresh library and upgrades it from JSON.
// If the JSON contains a non-empty "hash" field (i.e. compiled library),
// the computed hash is checked against it.
func NewLibraryFromJSON[T any](jsonData []byte, embedFun ...func(lib *engine.Library[T]) func(sym string) engine.EmbeddedFunction[T]) (*engine.Library[T], error) {
	lib := engine.NewLibrary[T]()
	fromJSON, err := ReadLibraryFromJSON(jsonData)
	if err != nil {
		return nil, err
	}
	if len(embedFun) > 0 {
		if err = lib.Upgrade(fromJSON, embedFun[0](lib)); err != nil {
			return nil, err
		}
	} else {
		if err = lib.Upgrade(fromJSON); err != nil {
			return nil, err
		}
	}
	hashCalculated := lib.LibraryHash()
	if len(fromJSON.Hash) > 0 && fromJSON.Hash != hex.EncodeToString(hashCalculated[:]) {
		return nil, fmt.Errorf("NewLibraryFromJSON: provided and calculated hashes do not match")
	}
	return lib, nil
}
