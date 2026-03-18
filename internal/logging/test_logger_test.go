package logging

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewTestLoggerReturnsLogger(t *testing.T) {
	logger := NewTestLogger(t)
	require.NotNil(t, logger)
}

func TestNewTestLoggerIsStructuredLogger(t *testing.T) {
	logger := NewTestLogger(t)
	// The returned value must be a *slog.Logger.
	var _ *slog.Logger = logger
}

func TestNewTestLoggerCanLog(t *testing.T) {
	logger := NewTestLogger(t)
	// Calling log methods must not panic.
	require.NotPanics(t, func() {
		logger.Debug("debug message", "key", "value")
		logger.Info("info message", "key", "value")
		logger.Warn("warn message", "key", "value")
		logger.Error("error message", "key", "value")
	})
}

func TestNewTestLoggerWithSubtest(t *testing.T) {
	t.Run("subtest", func(t *testing.T) {
		logger := NewTestLogger(t)
		require.NotNil(t, logger)
		require.NotPanics(t, func() {
			logger.Info("from subtest")
		})
	})
}

func TestNewTestLoggerWriterOutputLength(t *testing.T) {
	// Verify the underlying testLogger.Write returns correct byte count.
	w := &testLogger{t: t}
	msg := []byte("hello test logger")
	n, err := w.Write(msg)
	require.NoError(t, err)
	require.Equal(t, len(msg), n)
}
