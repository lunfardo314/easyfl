// Probe entry point for measuring the easyfl WASM binary size under
// TinyGo. Imports the top-level easyfl package and exercises the full
// path — NewBaseLibrary (embedded function bodies registered) + a
// trivial compile. This is the "everything wired" baseline; for a
// wallet-style minimum, import easyfl/compose directly and use
// NewLibrary + Upgrade(LibraryFromJSON). See claude/wasm_easyfl.md.
//
// Build: tinygo build -target=wasm -o /tmp/easyfl.wasm ./wasm/
package main

import "github.com/lunfardo314/easyfl"

func main() {
	lib := easyfl.NewBaseLibrary[any]()
	expr, _, _, err := lib.CompileExpression("concat(0x01, 0x02)")
	if err != nil {
		panic(err)
	}
	_ = expr
}
