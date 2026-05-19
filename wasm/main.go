// Probe entry point for measuring the easyfl WASM binary size under
// TinyGo. Imports the top-level easyfl package so the baseline reflects
// the current (unsplit) state — including embedded function bodies,
// eval engine, JSON serde and LibraryHash.
//
// Build: tinygo build -target=wasm -o /tmp/easyfl.wasm ./wasm/
//
// Phase A of claude/wasm_easyfl.md (lives in the proxima repo).
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
