package util_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/util"
)

// Benchmarks for the Writer/Reader wire helpers that back every length prefix,
// count, and string field across wallet/, auth/, overlay/, message/, compat/.
// The buffer is reused across iterations (Buf[:0]) so the measurement isolates
// the per-call encode/decode cost, not buffer growth.

// BenchmarkWriteVarInt measures encoding a varint of each on-wire width.
func BenchmarkWriteVarInt(b *testing.B) {
	cases := []struct {
		name string
		v    uint64
	}{
		{"1byte", 0xfc},
		{"3byte", 0xffff},
		{"5byte", 0xffffffff},
		{"9byte", 0xffffffffffffffff},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			w := util.NewWriter()
			w.WriteVarInt(c.v) // grow Buf once outside the measured reset

			b.ReportAllocs()
			for b.Loop() {
				w.Buf = w.Buf[:0]
				w.WriteVarInt(c.v)
			}
		})
	}
}

// BenchmarkWriteString measures encoding a length-prefixed string.
func BenchmarkWriteString(b *testing.B) {
	for _, n := range []int{8, 64, 256} {
		b.Run(fmt.Sprintf("len=%d", n), func(b *testing.B) {
			s := strings.Repeat("x", n)
			w := util.NewWriter()
			w.WriteString(s)

			b.ReportAllocs()
			for b.Loop() {
				w.Buf = w.Buf[:0]
				w.WriteString(s)
			}
		})
	}
}

// BenchmarkWriteBytesReverse measures the reversed-bytes write (txids/hashes).
func BenchmarkWriteBytesReverse(b *testing.B) {
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}
	w := util.NewWriter()
	w.WriteBytesReverse(data)

	b.ReportAllocs()
	for b.Loop() {
		w.Buf = w.Buf[:0]
		w.WriteBytesReverse(data)
	}
}

// BenchmarkReadVarInt measures decoding a varint of each on-wire width.
func BenchmarkReadVarInt(b *testing.B) {
	cases := []struct {
		name string
		v    uint64
	}{
		{"1byte", 0xfc},
		{"3byte", 0xffff},
		{"5byte", 0xffffffff},
		{"9byte", 0xffffffffffffffff},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			data := util.VarInt(c.v).Bytes()
			r := util.NewReader(data)

			b.ReportAllocs()
			for b.Loop() {
				r.Pos = 0
				if _, err := r.ReadVarInt(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
