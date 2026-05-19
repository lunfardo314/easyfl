// Package easyfl is the top-level facade for the easyfl library.
//
// The compose sub-package holds the minimal compile / decompile / library
// registry surface (no fmt-on-hot-paths, no encoding/json, no embedded
// function bodies). The embed sub-package holds the base library's
// embedded function bodies. The top-level easyfl package wires both
// together (via NewBaseLibrary), provides the JSON serde helpers, and
// re-exports everything as type aliases for backward compatibility
// with existing imports of github.com/lunfardo314/easyfl.
package easyfl

import (
	"github.com/lunfardo314/easyfl/compose"
	"github.com/lunfardo314/easyfl/easyfl_util"
	"github.com/lunfardo314/easyfl/embed"
)

// Type aliases re-export the compose types so existing
// easyfl.<Type> imports keep working unchanged.
type (
	Library[T any]            = compose.Library[T]
	Expression[T any]         = compose.Expression[T]
	EmbeddedFunction[T any]   = compose.EmbeddedFunction[T]
	EvalFunction[T any]       = compose.EvalFunction[T]
	CallParams[T any]         = compose.CallParams[T]
	GlobalData[T any]         = compose.GlobalData[T]
	GlobalDataNoTrace[T any]  = compose.GlobalDataNoTrace[T]
	LocalScript[T any]        = compose.LocalScript[T]
	LocalScriptBin            = compose.LocalScriptBin
	LocalScriptCallSiteCheck[T any] = compose.LocalScriptCallSiteCheck[T]
	LibraryFromJSON           = compose.LibraryFromJSON
	FuncDescriptorJSON        = compose.FuncDescriptorJSON
)

// Re-exported constants and free functions from compose.
const (
	MaxSourceSize                 = compose.MaxSourceSize
	MaxDataSize                   = compose.MaxDataSize
	MaxParameters                 = compose.MaxParameters
	FirstEmbeddedReserved         = compose.FirstEmbeddedReserved
	LastEmbeddedReserved          = compose.LastEmbeddedReserved
	FirstEmbeddedShort            = compose.FirstEmbeddedShort
	LastEmbeddedShort             = compose.LastEmbeddedShort
	MaxNumEmbeddedAndReservedShort = compose.MaxNumEmbeddedAndReservedShort
	FirstEmbeddedLong             = compose.FirstEmbeddedLong
	MaxNumEmbeddedLong            = compose.MaxNumEmbeddedLong
	LastEmbeddedLong              = compose.LastEmbeddedLong
	FirstExtended                 = compose.FirstExtended
	LastGlobalFunCode             = compose.LastGlobalFunCode
	MaxNumExtendedGlobal          = compose.MaxNumExtendedGlobal
	FirstLocalFunCode             = compose.FirstLocalFunCode
)

// NewLibrary returns an empty library. Wallet-style callers that want
// to avoid pulling base embedded function bodies into the build use
// this directly. See package doc for the recommended pattern.
func NewLibrary[T any]() *Library[T] {
	return compose.NewLibrary[T]()
}

// NewBaseLibrary returns the canonical base library: empty library
// + the base library.json descriptors + the base embedded function
// resolver wired in. This is what Proxima uses to construct its
// `ledger` library; the wasm wallet should prefer NewLibrary.
func NewBaseLibrary[T any]() *Library[T] {
	lib, err := NewLibraryFromJSON[T]([]byte(baseLibraryDefinitions),
		func(lib *compose.Library[T]) func(sym string) compose.EmbeddedFunction[T] {
			return embed.Resolver[T](lib)
		})
	easyfl_util.AssertNoError(err)
	return lib
}

// EmbeddedFunctions wraps embed.Resolver for back-compat with callers
// that historically reached for easyfl.EmbeddedFunctions directly.
func EmbeddedFunctions[T any](targetLib *Library[T]) func(sym string) EmbeddedFunction[T] {
	return embed.Resolver[T](targetLib)
}

// HasInlineDataPrefix mirrors compose.HasInlineDataPrefix.
func HasInlineDataPrefix(data []byte) bool { return compose.HasInlineDataPrefix(data) }

// StripDataPrefix mirrors compose.StripDataPrefix.
func StripDataPrefix(data []byte) []byte { return compose.StripDataPrefix(data) }

// ExpressionToBytecode mirrors compose.ExpressionToBytecode.
func ExpressionToBytecode[T any](f *Expression[T]) []byte {
	return compose.ExpressionToBytecode(f)
}

// EvalExpression / EvalExpressionWithSlicePool / EvalExpressionInPool
// are re-exported for callers that import easyfl directly.
func EvalExpression[T any](glb GlobalData[T], f *Expression[T], args ...[]byte) []byte {
	return compose.EvalExpression(glb, f, args...)
}
