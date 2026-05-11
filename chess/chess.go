// Package chess exposes the EasyFL chess move validator local-script source
// so downstream packages (e.g. proxima's chess covenant PoC) can compose it
// via callRedeemer without duplicating the source. The design and behaviour
// live in chess_script.md / chess_script.easyfl in this directory.
package chess

import _ "embed"

//go:embed chess_script.easyfl
var ScriptSource string
