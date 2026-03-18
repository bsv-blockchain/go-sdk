package spv

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGullibleHeadersClientCurrentHeight verifies the CurrentHeight method
// returns the expected dummy height without error.
func TestGullibleHeadersClientCurrentHeight(t *testing.T) {
	t.Parallel()

	client := &GullibleHeadersClient{}
	ctx := context.Background()

	height, err := client.CurrentHeight(ctx)
	require.NoError(t, err)
	require.Equal(t, uint32(800000), height)
}

// TestGullibleHeadersClientIsValidRootForHeight verifies that the gullible
// client always returns true regardless of arguments.
func TestGullibleHeadersClientIsValidRootForHeight(t *testing.T) {
	t.Parallel()

	client := &GullibleHeadersClient{}
	ctx := context.Background()

	valid, err := client.IsValidRootForHeight(ctx, nil, 0)
	require.NoError(t, err)
	require.True(t, valid)
}
