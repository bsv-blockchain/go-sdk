package logging

import (
	"log/slog"
	"testing"
)

type testLogger struct {
	t testing.TB
}

func (w testLogger) Write(p []byte) (n int, err error) {
	w.t.Helper()
	w.t.Log(string(p))
	return len(p), nil
}

func NewTestLogger(t testing.TB) *slog.Logger {
	handler := slog.NewTextHandler(&testLogger{t: t}, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})

	return slog.New(handler)
}
