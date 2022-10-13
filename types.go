package easyfl

const (
	EmbeddedReservedUntil = 15
	MaxNumEmbeddedShort   = 64
	FirstEmbeddedLongFun  = MaxNumEmbeddedShort
	MaxNumEmbeddedLong    = 256
	FirstExtendedFun      = FirstEmbeddedLongFun + MaxNumEmbeddedLong
	MaxFunCode            = 1023
	MaxNumExtended        = MaxFunCode - FirstExtendedFun

	MaxParameters = 15
)

type funInfo struct {
	Sym        string
	FunCode    uint16
	IsEmbedded bool
	IsShort    bool
	NumParams  int
}

type FunParsed struct {
	Sym        string
	SourceCode string
}

type Expression struct {
	Args     []*Expression
	EvalFunc EvalFunction
}

type EvalFunction func(glb *CallParams) []byte
