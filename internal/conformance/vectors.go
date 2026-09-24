// Package conformance loads the pinned ts-stack cross-language conformance
// corpus (testdata/vectors) and runs it with the same skip semantics as the
// TypeScript reference runner:
//
//   - parity_class "intended" (file or vector level) is a governed skip
//   - "skip": true is a governed skip
//   - everything else (required, best-effort) must be executed
//
// Go-specific gaps must be declared with GoGap, which requires a concrete
// reason, so a missing implementation never passes silently.
package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// EnvVectorsDir overrides the vector root, e.g. to run against a live
// ts-stack checkout instead of the pinned snapshot.
const EnvVectorsDir = "BSV_CONFORMANCE_VECTORS"

// File is one vector file from the corpus.
type File struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	BRC         []string `json:"brc"`
	Version     string   `json:"version"`
	ParityClass string   `json:"parity_class"`
	SkipReason  string   `json:"skip_reason"`
	Vectors     []Vector `json:"vectors"`
}

// Vector is one test case. Input and Expected stay raw so each runner can
// decode them into the shape its domain needs.
type Vector struct {
	ID          string          `json:"id"`
	Description string          `json:"description"`
	Input       json.RawMessage `json:"input"`
	Expected    json.RawMessage `json:"expected"`
	Tags        []string        `json:"tags"`
	ParityClass string          `json:"parity_class"`
	Skip        bool            `json:"skip"`
	SkipReason  string          `json:"skip_reason"`
	Notes       string          `json:"notes"`
}

// DecodeInput unmarshals the vector input into dst, failing the test on error.
func (v Vector) DecodeInput(t testing.TB, dst any) {
	t.Helper()
	if err := json.Unmarshal(v.Input, dst); err != nil {
		t.Fatalf("%s: decode input: %v", v.ID, err)
	}
}

// DecodeExpected unmarshals the vector expectation into dst, failing the test on error.
func (v Vector) DecodeExpected(t testing.TB, dst any) {
	t.Helper()
	if err := json.Unmarshal(v.Expected, dst); err != nil {
		t.Fatalf("%s: decode expected: %v", v.ID, err)
	}
}

// Dir returns the vector root directory.
func Dir() string {
	if dir := os.Getenv(EnvVectorsDir); dir != "" {
		return dir
	}
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		panic("conformance: cannot resolve package directory")
	}
	return filepath.Join(filepath.Dir(self), "testdata", "vectors")
}

// Load reads a vector file by its path relative to the vector root,
// e.g. "auth/brc31-handshake.json".
func Load(t testing.TB, rel string) *File {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(Dir(), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("load %s: %v", rel, err)
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	if len(f.Vectors) == 0 {
		t.Fatalf("%s: no vectors", rel)
	}
	return &f
}

// Run executes fn for every vector in the file as a subtest named by the
// vector ID, applying the reference runner's governed-skip rules first.
func Run(t *testing.T, f *File, fn func(t *testing.T, v Vector)) {
	t.Helper()
	for _, v := range f.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			if parity, reason, skip := governedSkip(f, v); skip {
				t.Skipf("governed skip (%s): %s", parity, reason)
			}
			fn(t, v)
		})
	}
}

// governedSkip reports whether the reference runner skips v: parity_class
// "intended" (vector level, else file level) or an explicit skip flag.
func governedSkip(f *File, v Vector) (parity, reason string, skip bool) {
	parity = v.ParityClass
	if parity == "" {
		parity = f.ParityClass
	}
	if parity == "" {
		parity = "required"
	}
	if parity != "intended" && !v.Skip {
		return parity, "", false
	}
	for _, r := range []string{v.SkipReason, f.SkipReason, v.Notes} {
		if r != "" {
			return parity, r, true
		}
	}
	return parity, "", true
}

// GoGap skips a vector the Go SDK deliberately does not implement. The reason
// must say what is missing and why, so gaps stay reviewable.
func GoGap(t testing.TB, reason string) {
	t.Helper()
	if len(reason) < 20 {
		t.Fatalf("GoGap reason too short to be reviewable: %q", reason)
	}
	t.Skipf("go gap: %s", reason)
}
