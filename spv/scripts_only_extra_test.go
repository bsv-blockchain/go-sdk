package spv

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGullibleHeadersClient_CurrentHeight verifies the CurrentHeight method
// returns the expected dummy height without error.
func TestGullibleHeadersClient_CurrentHeight(t *testing.T) {
	t.Parallel()

	client := &GullibleHeadersClient{}
	ctx := context.Background()

	height, err := client.CurrentHeight(ctx)
	require.NoError(t, err)
	require.Equal(t, uint32(800000), height)
}

// TestGullibleHeadersClient_IsValidRootForHeight verifies that the gullible
// client always returns true regardless of arguments.
func TestGullibleHeadersClient_IsValidRootForHeight(t *testing.T) {
	t.Parallel()

	client := &GullibleHeadersClient{}
	ctx := context.Background()

	valid, err := client.IsValidRootForHeight(ctx, nil, 0)
	require.NoError(t, err)
	require.True(t, valid)
}
