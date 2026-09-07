package primitives

import (
	"fmt"
	"testing"
)

// Benchmarks for the hash helpers that back txids, sighashes, and merkle
// parents. Inputs are prepared outside the timer and scaled by size.

// BenchmarkSha256d measures the double-SHA256 used pervasively across the SDK.
func BenchmarkSha256d(b *testing.B) {
	for _, size := range []int{32, 256, 1024} {
		b.Run(fmt.Sprintf("bytes=%d", size), func(b *testing.B) {
			msg := make([]byte, size)
			for i := range msg {
				msg[i] = byte(i)
			}

			b.ReportAllocs()
			for b.Loop() {
				_ = Sha256d(msg)
			}
		})
	}
}

// BenchmarkSha256 measures a single SHA-256 pass for comparison against the
// double hash above.
func BenchmarkSha256(b *testing.B) {
	for _, size := range []int{32, 256, 1024} {
		b.Run(fmt.Sprintf("bytes=%d", size), func(b *testing.B) {
			msg := make([]byte, size)
			for i := range msg {
				msg[i] = byte(i)
			}

			b.ReportAllocs()
			for b.Loop() {
				_ = Sha256(msg)
			}
		})
	}
}
