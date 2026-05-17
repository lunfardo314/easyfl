package easyfl

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// ToJSON serializes the library to JSON.
//   - compiled=true emits funCode/bytecode fields and the top-level hash.
//   - indent=true emits human-readable indented JSON with a trailing newline.
//     indent=false emits compact JSON (canonical for storage and on-the-wire);
//     no trailing newline.
func (lib *Library[T]) ToJSON(compiled, indent bool) []byte {
	out := LibraryFromJSON{
		VersionData: string(lib.VersionData),
		Functions:   make([]FuncDescriptorJSON, 0, len(lib.funByName)),
	}
	if compiled {
		h := lib.LibraryHash()
		out.Hash = hex.EncodeToString(h[:])
	}

	for sym := range lib.funByName {
		d := *lib.mustFuncDescriptor(sym)
		if !compiled {
			// non-compiled output: drop funCode and bytecode (they are runtime artifacts)
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

// ReadLibraryFromJSON parses JSON into a *LibraryFromJSON.
func ReadLibraryFromJSON(data []byte) (*LibraryFromJSON, error) {
	ret := &LibraryFromJSON{}
	if err := json.Unmarshal(data, ret); err != nil {
		return nil, err
	}
	return ret, nil
}

// IntroduceUpdateJSON parses raw JSON data and stages extended functions for
// later processing by CommitUpdate. Embedded functions are processed immediately.
func (lib *Library[T]) IntroduceUpdateJSON(jsonData []byte, embed ...func(sym string) EmbeddedFunction[T]) error {
	fromJSON, err := ReadLibraryFromJSON(jsonData)
	if err != nil {
		return err
	}
	return lib.introduceFromParsed(fromJSON, embed...)
}

// IntroduceUpdateJSONMulti is the variadic form of IntroduceUpdateJSON.
func (lib *Library[T]) IntroduceUpdateJSONMulti(embed func(sym string) EmbeddedFunction[T], jsonDatas ...[]byte) error {
	for _, jsonData := range jsonDatas {
		if embed != nil {
			if err := lib.IntroduceUpdateJSON(jsonData, embed); err != nil {
				return err
			}
		} else {
			if err := lib.IntroduceUpdateJSON(jsonData); err != nil {
				return err
			}
		}
	}
	return nil
}

// UpgradeFromJSON parses JSON and applies it as a single Upgrade
// (introduce + CommitUpdate).
func (lib *Library[T]) UpgradeFromJSON(jsonData []byte, embed ...func(sym string) EmbeddedFunction[T]) error {
	fromJSON, err := ReadLibraryFromJSON(jsonData)
	if err != nil {
		return err
	}
	return lib.Upgrade(fromJSON, embed...)
}

// NewLibraryFromJSON constructs a fresh library and upgrades it from JSON.
// If the JSON contains a non-empty "hash" field (i.e. compiled library), the
// computed hash is checked against it.
func NewLibraryFromJSON[T any](jsonData []byte, embedFun ...func(lib *Library[T]) func(sym string) EmbeddedFunction[T]) (*Library[T], error) {
	lib := NewLibrary[T]()
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
