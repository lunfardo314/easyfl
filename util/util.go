package util

import (
	"bytes"
	"encoding/binary"
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

func Assertf(cond bool, format string, args ...interface{}) {
	if !cond {
		panic(fmt.Errorf("assertion failed:: "+format, EvalLazyArgs(args...)...))
	}
}

func EvalLazyArgs(args ...any) []any {
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

func FmtLazy(data []byte) func() string {
	return func() string {
		return Hex(data)
	}
}

// Uint64FromBytes takes any 8 or less bytes, padds with 0 prefix up to 8 bytes size and makes uin64 big-endian
func Uint64FromBytes(data []byte) (uint64, error) {
	if len(data) > 8 {
		return 0, fmt.Errorf("Uint64FromBytes: can't be more than 8 bytes")
	}
	var paddedData [8]byte
	copy(paddedData[8-len(data):], data)

	return binary.BigEndian.Uint64(paddedData[:]), nil
}

func MustUint64FromBytes(data []byte) uint64 {
	ret, err := Uint64FromBytes(data)
	AssertNoError(err)
	return ret
}

// TrimLeadingZeroBytes returns sub-slice without leading zeroes
func TrimLeadingZeroBytes(data []byte) []byte {
	for i := 0; i < len(data); i++ {
		if data[i] != 0 {
			return data[i:]
		}
	}
	return nil
}

func Uint64To8Bytes(v uint64) (ret [8]byte) {
	binary.BigEndian.PutUint64(ret[:], v)
	return
}

func TrimmedLeadingZeroUint64(v uint64) []byte {
	ret := Uint64To8Bytes(v)
	return TrimLeadingZeroBytes(ret[:])
}

func TrimmedLeadingZeroUint64Hex(v uint64) string {
	return hex.EncodeToString(TrimmedLeadingZeroUint64(v))
}
