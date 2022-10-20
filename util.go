package easyfl

import (
	"bytes"
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
		default:
			panic("must be byte or []byte")
		}
	}
	return buf.Bytes()
}

func catchPanicOrError(f func() error) error {
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

func requireErrorWith(t *testing.T, err error, s string) {
	require.Error(t, err)
	require.Contains(t, err.Error(), s)
}

func requirePanicOrErrorWith(t *testing.T, f func() error, s string) {
	requireErrorWith(t, catchPanicOrError(f), s)
}

func assert(cond bool, format string, args ...interface{}) {
	if !cond {
		panic(fmt.Sprintf("assertion failed:: "+format, args...))
	}
}

func assertNoError(err error) {
	assert(err == nil, "error: %v", err)
}
