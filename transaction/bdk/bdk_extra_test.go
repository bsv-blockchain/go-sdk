//go:build cgo && !ios && !android && (darwin || linux) && (amd64 || arm64)

package bdk

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFinalizeValidateBatch exercises the GC finalizer hook directly, which is
// otherwise only invoked non-deterministically by the runtime.
func TestFinalizeValidateBatch(t *testing.T) {
	batch := NewValidateBatch()
	require.NotNil(t, batch)

	finalizeValidateBatch(batch)
	require.True(t, batch.Empty())
}
