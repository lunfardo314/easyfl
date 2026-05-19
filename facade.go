// Package easyfl is the top-level facade for the easyfl library.
//
// The engine sub-package holds Library, Expression, CallParams, the
// eval engine, the source compiler, the decompiler, and library
// construction primitives — i.e. everything except the embedded
// function bodies and the JSON serde. The embed sub-package holds
// the base library's embedded function bodies. The top-level easyfl
// package wires both together (via NewBaseLibrary), provides the JSON
// serde helpers, and re-exports the engine types as aliases so the
// existing easyfl.<Type> imports keep compiling.
//
// Wallet-style callers that want a minimal wasm binary should import
// easyfl/engine directly: they avoid the embedded library.json blob
// and the JSON serde / library-hash machinery.
package easyfl

import (
	"github.com/lunfardo314/easyfl/easyfl_util"
	"github.com/lunfardo314/easyfl/embed"
	"github.com/lunfardo314/easyfl/engine"
	"github.com/lunfardo314/easyfl/slicepool"
)

// Type aliases re-export the engine types so existing
// easyfl.<Type> imports keep working unchanged.
type (
	Library[T any]                  = engine.Library[T]
	Expression[T any]               = engine.Expression[T]
	EmbeddedFunction[T any]         = engine.EmbeddedFunction[T]
	EvalFunction[T any]             = engine.EvalFunction[T]
	CallParams[T any]               = engine.CallParams[T]
	GlobalData[T any]               = engine.GlobalData[T]
	GlobalDataNoTrace[T any]        = engine.GlobalDataNoTrace[T]
	LocalScript[T any]              = engine.LocalScript[T]
	LocalScriptBin                  = engine.LocalScriptBin
	LocalScriptCallSiteCheck[T any] = engine.LocalScriptCallSiteCheck[T]
	LibraryFromJSON                 = engine.LibraryFromJSON
	FuncDescriptorJSON              = engine.FuncDescriptorJSON
)

// Re-exported constants from engine.
const (
	MaxSourceSize                  = engine.MaxSourceSize
	MaxDataSize                    = engine.MaxDataSize
	MaxParameters                  = engine.MaxParameters
	FirstEmbeddedReserved          = engine.FirstEmbeddedReserved
	LastEmbeddedReserved           = engine.LastEmbeddedReserved
	FirstEmbeddedShort             = engine.FirstEmbeddedShort
	LastEmbeddedShort              = engine.LastEmbeddedShort
	MaxNumEmbeddedAndReservedShort = engine.MaxNumEmbeddedAndReservedShort
	FirstEmbeddedLong              = engine.FirstEmbeddedLong
	MaxNumEmbeddedLong             = engine.MaxNumEmbeddedLong
	LastEmbeddedLong               = engine.LastEmbeddedLong
	FirstExtended                  = engine.FirstExtended
	LastGlobalFunCode              = engine.LastGlobalFunCode
	MaxNumExtendedGlobal           = engine.MaxNumExtendedGlobal
	FirstLocalFunCode              = engine.FirstLocalFunCode
)

// NewLibrary returns an empty library. Wallet-style callers that want
// to avoid pulling base embedded function bodies into the build use
// this directly (or, equivalently, engine.NewLibrary).
func NewLibrary[T any]() *Library[T] {
	return engine.NewLibrary[T]()
}

// NewBaseLibrary returns the canonical base library: empty library
// + the base library.json descriptors + the base embedded function
// resolver wired in. This is what Proxima uses to construct its
// `ledger` library; the wasm wallet should prefer NewLibrary.
func NewBaseLibrary[T any]() *Library[T] {
	lib, err := NewLibraryFromJSON[T]([]byte(baseLibraryDefinitions),
		func(lib *engine.Library[T]) func(sym string) engine.EmbeddedFunction[T] {
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

// HasInlineDataPrefix mirrors engine.HasInlineDataPrefix.
func HasInlineDataPrefix(data []byte) bool { return engine.HasInlineDataPrefix(data) }

// StripDataPrefix mirrors engine.StripDataPrefix.
func StripDataPrefix(data []byte) []byte { return engine.StripDataPrefix(data) }

// InlineDataBytecode mirrors engine.InlineDataBytecode.
func InlineDataBytecode(data []byte) []byte { return engine.InlineDataBytecode(data) }

// ExpressionToBytecode mirrors engine.ExpressionToBytecode.
func ExpressionToBytecode[T any](f *Expression[T]) []byte {
	return engine.ExpressionToBytecode(f)
}

// EvalExpression mirrors engine.EvalExpression.
func EvalExpression[T any](glb GlobalData[T], f *Expression[T], args ...[]byte) []byte {
	return engine.EvalExpression(glb, f, args...)
}

// EvalExpressionWithSlicePool mirrors engine.EvalExpressionWithSlicePool.
// The caller's pool is reused for the eval; the result is copied to the
// Go heap before return so it outlives the pool's Dispose.
func EvalExpressionWithSlicePool[T any](glb GlobalData[T], spool *slicepool.SlicePool, f *Expression[T], args ...[]byte) []byte {
	return engine.EvalExpressionWithSlicePool(glb, spool, f, args...)
}

// EvalExpressionInPool mirrors engine.EvalExpressionInPool. Result is
// allocated inside spool; caller must keep the pool alive while reading
// the returned slice.
func EvalExpressionInPool[T any](glb GlobalData[T], spool *slicepool.SlicePool, f *Expression[T], args ...[]byte) []byte {
	return engine.EvalExpressionInPool(glb, spool, f, args...)
}
