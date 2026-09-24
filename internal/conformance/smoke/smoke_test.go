package smoke_test

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/internal/conformance"
)

// TestCorpusLoads proves every pinned vector file parses with the shared loader.
func TestCorpusLoads(t *testing.T) {
	root := conformance.Dir()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		conformance.Load(t, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
