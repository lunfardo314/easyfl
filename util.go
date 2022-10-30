package easyfl

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func Concat(data ...interface{}) []byte {
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

func RequirePanicOrErrorWith(t *testing.T, f func() error, s string) {
	RequireErrorWith(t, CatchPanicOrError(f), s)
}

func Assert(cond bool, format string, args ...interface{}) {
	if !cond {
		panic(fmt.Sprintf("assertion failed:: "+format, args...))
	}
}

func AssertNoError(err error) {
	Assert(err == nil, "error: %v", err)
}

func Hex(data []byte) string {
	return fmt.Sprintf("%dx%s", len(data), hex.EncodeToString(data))
}

func Fmt(data []byte) string {
	return Hex(data)
}
