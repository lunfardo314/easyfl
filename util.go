package easyfl

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func concat(data ...interface{}) []byte {
	var buf bytes.Buffer
	for _, d := range data {
		switch d := d.(type) {
		case byte:
			buf.WriteByte(d)
		case []byte:
			buf.Write(d)
		case interface{ Bytes() []byte }:
			buf.Write(d.Bytes())
		case int:
			if d < 0 || d > 255 {
				panic("not a 1 byte integer value")
			}
			buf.WriteByte(byte(d))
		default:
			panic("must be 'byte', '[]byte' or 'interface{ Bytes() []byte }'")
		}
	}
	return buf.Bytes()
}

func CatchPanicOrError(f func() error) error {
	var err error
	func() {
		defer func() {
			r := recover()
			if r == nil {
				return
			}
			var ok bool
			if err, ok = r.(error); !ok {
				err = fmt.Errorf("%v", r)
			}
		}()
		err = f()
	}()
	return err
}

func RequireErrorWith(t *testing.T, err error, s string) {
	require.Error(t, err)
	require.Contains(t, err.Error(), s)
}

func Assertf(cond bool, format string, args ...interface{}) {
	if !cond {
		panic(fmt.Errorf("assertion failed:: "+format, evalLazyArgs(args...)...))
	}
}

func evalLazyArgs(args ...any) []any {
	ret := make([]any, len(args))
	for i, arg := range args {
		switch funArg := arg.(type) {
		case func() any:
			ret[i] = funArg()
		case func() string:
			ret[i] = funArg()
		case func() bool:
			ret[i] = funArg()
		case func() int:
			ret[i] = funArg()
		case func() byte:
			ret[i] = funArg()
		case func() uint:
			ret[i] = funArg()
		case func() uint16:
			ret[i] = funArg()
		case func() uint32:
			ret[i] = funArg()
		case func() uint64:
			ret[i] = funArg()
		case func() int16:
			ret[i] = funArg()
		case func() int32:
			ret[i] = funArg()
		case func() int64:
			ret[i] = funArg()
		default:
			ret[i] = arg
		}
	}
	return ret
}

func AssertNoError(err error) {
	Assertf(err == nil, "error: %v", err)
}

func Hex(data []byte) string {
	return fmt.Sprintf("%dx%s", len(data), hex.EncodeToString(data))
}

func Fmt(data []byte) string {
	return Hex(data)
}
