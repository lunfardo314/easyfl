// Package testutil holds helpers that depend on testing and stretchr/testify.
// Kept out of the parent easyfl_util package so its imports (testify ->
// net/http -> ...) don't leak into production code or TinyGo wasm builds.
package testutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// RequireErrorWith asserts that err is non-nil and its message contains s.
func RequireErrorWith(t *testing.T, err error, s string) {
	require.Error(t, err)
	require.Contains(t, err.Error(), s)
}
