//go:build race

package interpreter

// raceDetector reports whether the tests run under the race detector, which
// slows bulk memory copies several times over.
const raceDetector = true
